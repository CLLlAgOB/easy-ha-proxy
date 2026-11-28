package hostsec

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/tools"
)

const (
	osRestartDropinDefault = "/etc/needrestart/conf.d/easy-ha-proxy-os-security.conf"
	osAptGuardDefault      = "/etc/apt/apt.conf.d/99-easy-ha-proxy-os-security"
	osAptGuardConfig       = "// Managed by easy-ha-proxy OS security.\nAPT::Periodic::Unattended-Upgrade \"0\";\nUnattended-Upgrade::InstallOnShutdown \"false\";\nUnattended-Upgrade::Automatic-Reboot \"false\";\n"
	osRestartConfig        = "# Managed by easy-ha-proxy OS security; deferred services remain visible.\n$nrconf{override_rc}{qr(^(haproxy|docker|containerd|easy-ha-proxy-updated|easy-ha-proxy-updated-job-[0-9a-f]{12}|easy-ha-proxy-backupd)\\.service$)} = 0;\n"
)

var (
	osPreviousRestartConfig = strings.ReplaceAll(osRestartConfig, "|easy-ha-proxy-updated-job-[0-9a-f]{12}", "")
	osRestartDropin         = osRestartDropinDefault
	osAptGuard              = osAptGuardDefault
	unattendedUpgradeBin    = "/usr/bin/unattended-upgrade"
	needrestartBin          = "/usr/sbin/needrestart"
	osModes                 = map[string]bool{"system": true, "notify": true, "auto": true, "window": true, "daily": true}
	osIntervals             = map[int]bool{1: true, 2: true, 4: true, 6: true, 12: true, 24: true}
	osProtectedPackages     = map[string]bool{
		"haproxy": true, "haproxy-awslc": true, "libssl-awslc": true,
		"docker.io": true, "docker-ce": true, "docker-ce-cli": true,
		"containerd": true, "containerd.io": true, "runc": true,
		"docker-buildx-plugin": true, "docker-compose-plugin": true,
	}
	osPkgNameRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*(?::[a-z0-9]+)?$`)
	instBootstrapRe  = regexp.MustCompile(`^Inst (\S+) \((\S+) .+`)
	needrestartSvcRe = regexp.MustCompile(`(?m)^NEEDRESTART-SVC:\s*(\S+)\s*$`)
	needrestartKstRe = regexp.MustCompile(`(?m)^NEEDRESTART-KSTA:\s*([0-9]+)`)
	refreshAptFunc   = func() (map[string]any, error) {
		return tools.RefreshAptMetadata(tools.AptMetadataState, "/etc/apt", 100*time.Second)
	}
)

type osPolicy struct {
	Mode     string
	Interval int
	Start    int
	End      int
}

func (p osPolicy) toMap() map[string]any {
	return map[string]any{"mode": p.Mode, "interval": p.Interval, "start": p.Start, "end": p.End}
}

func validateOSPolicy(raw map[string]any) (osPolicy, error) {
	if raw == nil || len(raw) != 4 {
		return osPolicy{}, secErr("Invalid OS security policy")
	}
	for k := range raw {
		if k != "mode" && k != "interval" && k != "start" && k != "end" {
			return osPolicy{}, secErr("Invalid OS security policy")
		}
	}
	mode, ok := raw["mode"].(string)
	if !ok || !osModes[mode] {
		return osPolicy{}, secErr("Invalid OS security policy")
	}
	interval, ok := strictIntVal(raw["interval"])
	if !ok || !osIntervals[interval] {
		return osPolicy{}, secErr("Invalid OS security check interval")
	}
	start, okS := strictIntVal(raw["start"])
	end, okE := strictIntVal(raw["end"])
	if !okS || !okE || start < 0 || start > 23 || end < 0 || end > 23 || start == end {
		return osPolicy{}, secErr("Invalid OS security installation window")
	}
	return osPolicy{Mode: mode, Interval: interval, Start: start, End: end}, nil
}

func osWindowOpen(p osPolicy, local time.Time) bool {
	h := local.Hour()
	if p.Mode == "daily" {
		return h == p.Start
	}
	if p.Start < p.End {
		return p.Start <= h && h < p.End
	}
	return h >= p.Start || h < p.End
}

func osScheduledInstall(p osPolicy, status map[string]any, local time.Time) bool {
	if p.Mode == "auto" {
		return true
	}
	if (p.Mode != "daily" && p.Mode != "window") || !osWindowOpen(p, local) {
		return false
	}
	if p.Mode != "daily" {
		return true
	}
	last, ok := numVal(status["last_install_at"])
	if !ok || last == 0 {
		return true
	}
	prev := time.Unix(0, int64(last*1e9)).In(local.Location())
	return prev.Format("2006-01-02") != local.Format("2006-01-02")
}

func readNativePolicy() map[string]any {
	code, text, err := runCommand([]string{"/usr/bin/apt-config", "shell",
		"PERIODIC", "APT::Periodic::Unattended-Upgrade",
		"REBOOT", "Unattended-Upgrade::Automatic-Reboot",
		"SHUTDOWN", "Unattended-Upgrade::InstallOnShutdown"},
		cmdOpts{timeout: 5 * time.Second})
	vals := map[string]string{}
	if err == nil && code == 0 {
		vals = parseAptConfigShell(text)
	}
	periodic := vals["PERIODIC"]
	if periodic == "" {
		periodic = "0"
	}
	return map[string]any{
		"periodic": periodic,
		"reboot":   parseAptBool(vals["REBOOT"], false),
		"shutdown": parseAptBool(vals["SHUTDOWN"], false),
	}
}

// InspectOSSettings reads effective Linux APT periodic / timer settings without mutating the host.
func InspectOSSettings() (map[string]any, error) {
	if _, _, err := checkPlatform(); err != nil {
		return nil, err
	}
	_, text, err := runCommand([]string{"/usr/bin/apt-config", "shell",
		"ENABLED", "APT::Periodic::Enable",
		"LISTS", "APT::Periodic::Update-Package-Lists",
		"UPGRADE", "APT::Periodic::Unattended-Upgrade",
		"REBOOT", "Unattended-Upgrade::Automatic-Reboot",
		"SHUTDOWN", "Unattended-Upgrade::InstallOnShutdown"},
		cmdOpts{timeout: 3 * time.Second, check: true})
	if err != nil {
		return nil, err
	}
	values := parseAptConfigShell(text)
	_, timerOut, err := runCommand([]string{"/usr/bin/systemctl", "show", NativeTimerUnit,
		"--property=LoadState,UnitFileState,ActiveState,TimersCalendar,NextElapseUSecRealtime,RandomizedDelayUSec"},
		cmdOpts{timeout: 3 * time.Second, check: true})
	if err != nil {
		return nil, err
	}
	timer := map[string]string{}
	for _, line := range strings.Split(timerOut, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			timer[k] = v
		}
	}
	if ls := timer["LoadState"]; ls != "loaded" && ls != "masked" {
		return nil, secErr("The native APT upgrade timer is not supported")
	}
	enabled := parseAptBool(values["ENABLED"], true)
	meta, _ := readTimerMetadata(NativeTimerUnit)
	var nextRunAt any
	if meta != nil {
		nextRunAt = meta["next_run_at"]
	}
	upgrade := values["UPGRADE"]
	if upgrade == "" {
		upgrade = "0"
	}
	lists := values["LISTS"]
	if lists == "" {
		lists = "0"
	}
	cal := []string{}
	for _, m := range onCalendarRe.FindAllStringSubmatch(timer["TimersCalendar"], -1) {
		cal = append(cal, m[1])
	}
	active := timer["ActiveState"] == "active"
	var timerEnabled any
	if v, ok := timer["UnitFileState"]; ok {
		timerEnabled = v
	}
	return map[string]any{
		"checked_at":          unixSeconds(nowFunc()),
		"periodic_enabled":    enabled,
		"next_run_at":         nextRunAt,
		"upgrade_interval":    upgrade,
		"lists_interval":      lists,
		"automatic_reboot":    parseAptBool(values["REBOOT"], false),
		"install_on_shutdown": parseAptBool(values["SHUTDOWN"], false),
		"timer_enabled":       timerEnabled,
		"timer_active":        active,
		"calendar":            cal,
		"random_delay":        timer["RandomizedDelayUSec"],
		"next_run":            timer["NextElapseUSecRealtime"],
		"automatic_install":   enabled && upgrade != "0" && active,
	}, nil
}

func readNativeTimer() (map[string]any, error) {
	_, text, err := runCommand([]string{"/usr/bin/systemctl", "show", NativeTimerUnit, "--property=LoadState,UnitFileState,ActiveState"},
		cmdOpts{timeout: 60 * time.Second, check: true})
	if err != nil {
		return nil, err
	}
	fields := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			fields[k] = v
		}
	}
	validStates := map[string]bool{
		"enabled": true, "enabled-runtime": true, "disabled": true,
		"masked": true, "masked-runtime": true, "static": true, "indirect": true,
	}
	if (fields["LoadState"] != "loaded" && fields["LoadState"] != "masked") || !validStates[fields["UnitFileState"]] {
		return nil, secErr("The native APT upgrade timer is not supported")
	}
	return map[string]any{"enabled": fields["UnitFileState"], "active": fields["ActiveState"] == "active"}, nil
}

func restoreNativeTimer(baseline map[string]any) error {
	en := strVal(baseline["enabled"])
	if en == "enabled" || en == "enabled-runtime" {
		argv := []string{"/usr/bin/systemctl", "enable"}
		if en == "enabled-runtime" {
			argv = append(argv, "--runtime")
		}
		argv = append(argv, NativeTimerUnit)
		if _, _, err := runCommand(argv, cmdOpts{timeout: 60 * time.Second, check: true}); err != nil {
			return err
		}
	}
	if baseline["active"] == true {
		if _, _, err := runCommand([]string{"/usr/bin/systemctl", "start", NativeTimerUnit}, cmdOpts{timeout: 60 * time.Second, check: true}); err != nil {
			return err
		}
	}
	actual, err := readNativeTimer()
	if err != nil {
		return err
	}
	if actual["enabled"] != baseline["enabled"] || actual["active"] != baseline["active"] {
		return secErr("The native APT timer could not be restored; manual recovery is required")
	}
	return nil
}

func assertNativeIdle() error {
	_, text, err := runCommand([]string{"/usr/bin/systemctl", "show", "apt-daily-upgrade.service", "--property=ActiveState", "--value"},
		cmdOpts{timeout: 60 * time.Second, check: true})
	if err != nil {
		return err
	}
	st := strings.TrimSpace(text)
	if st != "inactive" && st != "failed" {
		return secErr("Native automatic upgrades are active; wait before changing the policy")
	}
	return nil
}

func assertOSManaged(record map[string]any, allowPreviousGuard bool) error {
	policyMap, _ := record["policy"].(map[string]any)
	if strVal(record["phase"]) != "ready" || strVal(policyMap["mode"]) == "system" {
		return secErr("Enable OS security management before installing updates")
	}
	timer, err := readNativeTimer()
	if err != nil {
		return err
	}
	disallowed := map[string]bool{"disabled": true, "masked": true, "masked-runtime": true, "static": true, "indirect": true}
	if timer["active"] == true || !disallowed[strVal(timer["enabled"])] {
		return secErr("Native APT timer settings changed; review the OS security policy")
	}
	if isSymlink(osRestartDropin) || !isRegularFile(osRestartDropin) {
		return secErr("OS security restart protection changed; review the policy")
	}
	rawDropin, err := os.ReadFile(osRestartDropin)
	if err != nil {
		return secErr("OS security restart protection changed; review the policy")
	}
	dropinText := string(rawDropin)
	if dropinText != osRestartConfig && (!allowPreviousGuard || dropinText != osPreviousRestartConfig) {
		return secErr("OS security restart protection changed; review the policy")
	}
	if isSymlink(osAptGuard) || !isRegularFile(osAptGuard) {
		return secErr("OS security APT protection changed; review the policy")
	}
	rawGuard, err := os.ReadFile(osAptGuard)
	if err != nil || string(rawGuard) != osAptGuardConfig {
		return secErr("OS security APT protection changed; review the policy")
	}
	_, eff, err := runCommand([]string{"/usr/bin/apt-config", "shell",
		"PERIODIC", "APT::Periodic::Unattended-Upgrade",
		"SHUTDOWN", "Unattended-Upgrade::InstallOnShutdown",
		"REBOOT", "Unattended-Upgrade::Automatic-Reboot"},
		cmdOpts{timeout: 60 * time.Second, check: true})
	if err != nil {
		return err
	}
	lines := map[string]bool{}
	for _, l := range strings.Split(strings.TrimSpace(eff), "\n") {
		if l != "" {
			lines[l] = true
		}
	}
	if len(lines) != 3 || !lines["PERIODIC='0'"] || !lines["SHUTDOWN='false'"] || !lines["REBOOT='false'"] {
		return secErr("Another APT setting overrides managed OS security protection")
	}
	return assertNativeIdle()
}

func bootstrapOSSecurityTools(distro, codename string, stdout io.Writer) error {
	installed, err := queryInstalledPackages()
	if err != nil {
		return err
	}
	has := map[string]bool{}
	for _, p := range installed {
		has[p.Short] = true
	}
	var missing []string
	for _, name := range []string{"unattended-upgrades", "needrestart"} {
		if !has[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	metadata, err := refreshAptFunc()
	if err != nil {
		return err
	}
	if metadata["fresh"] != true {
		return secErr("%s", strVal(metadata["error"]))
	}
	origins, err := loadPolicyOrigins()
	if err != nil {
		return err
	}
	simArgv := append([]string{"/usr/bin/apt-get", "-s", "--no-install-recommends", "install"}, missing...)
	_, sim, err := runCommand(simArgv, cmdOpts{timeout: 60 * time.Second, check: true})
	if err != nil {
		return err
	}
	var install []string
	for _, line := range strings.Split(sim, "\n") {
		if strings.HasPrefix(line, "Remv ") {
			return secErr("Installing security tools would remove packages")
		}
		if !strings.HasPrefix(line, "Inst ") {
			continue
		}
		m := instBootstrapRe.FindStringSubmatch(line)
		if m == nil || !osPkgNameRe.MatchString(m[1]) {
			return secErr("Installing security tools would change existing packages")
		}
		ok, err := checkOfficialPackageVersion(origins, distro, codename, m[1], m[2])
		if err != nil {
			return err
		}
		if !ok {
			return secErr("Security tools require signed distribution packages")
		}
		install = append(install, m[1]+"="+m[2])
	}
	if len(install) == 0 || len(install) > 100 {
		return secErr("Security-tool installation could not be planned safely")
	}
	instArgv := append([]string{"/usr/bin/apt-get", "-y", "--no-remove", "--no-install-recommends", "--no-upgrade", "install"}, install...)
	_, logOut, err := runCommand(instArgv, cmdOpts{timeout: 1800 * time.Second, env: map[string]string{"NEEDRESTART_MODE": "l"}, check: true, stdout: stdout})
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(stdout, logOut)
	return nil
}

func configureOSSecurity(root string, requested map[string]any, distro, codename string, stdout io.Writer) error {
	pol, err := validateOSPolicy(requested)
	if err != nil {
		return err
	}
	path := filepath.Join(root, "policy.json")
	var old map[string]any
	if lexists(path) {
		old, err = ReadJSON(path)
		if err != nil {
			return err
		}
	}
	if old != nil && strVal(old["phase"]) != "ready" && pol.Mode != "system" {
		return secErr("Restore system management after the interrupted policy change")
	}
	var baseline map[string]any
	if old != nil {
		baseline, _ = old["baseline"].(map[string]any)
	}
	if pol.Mode == "system" {
		if baseline != nil {
			timer, err := readNativeTimer()
			if err != nil {
				return err
			}
			allowed := map[string]bool{"disabled": true, "masked": true, "masked-runtime": true, "static": true, "indirect": true}
			if timer["active"] == true || !allowed[strVal(timer["enabled"])] {
				return secErr("Native APT timer settings changed; refusing to overwrite them")
			}
			cfg := copyMap(old)
			cfg["phase"] = "configuring"
			if err := AtomicWrite(path, cfg, 0o600); err != nil {
				return err
			}
			for _, pair := range []struct {
				p        string
				expected string
				prev     string
			}{
				{osRestartDropin, osRestartConfig, osPreviousRestartConfig},
				{osAptGuard, osAptGuardConfig, ""},
			} {
				if lexists(pair.p) {
					if isSymlink(pair.p) {
						return secErr("OS security protection changed; review the policy")
					}
					raw, rerr := os.ReadFile(pair.p)
					if rerr != nil || (string(raw) != pair.expected && (pair.prev == "" || string(raw) != pair.prev)) {
						return secErr("OS security protection changed; review the policy")
					}
					if err := os.Remove(pair.p); err != nil {
						return err
					}
				}
			}
			if err := restoreNativeTimer(baseline); err != nil {
				rec := copyMap(old)
				rec["phase"] = "recovery_required"
				_ = AtomicWrite(path, rec, 0o600)
				return err
			}
		}
		return AtomicWrite(path, map[string]any{"phase": "ready", "policy": pol.toMap(), "updated_at": unixSeconds(nowFunc())}, 0o600)
	}
	if old != nil {
		oldPol, _ := old["policy"].(map[string]any)
		if strVal(oldPol["mode"]) != "system" && strVal(old["phase"]) == "ready" {
			if err := assertOSManaged(old, true); err != nil {
				return err
			}
		}
	}
	if baseline == nil {
		if lexists(osRestartDropin) || lexists(osAptGuard) {
			return secErr("The OS security configuration already exists outside panel management")
		}
		baseline, err = readNativeTimer()
		if err != nil {
			return err
		}
	}
	journal := map[string]any{"phase": "configuring", "baseline": baseline, "policy": pol.toMap(), "updated_at": unixSeconds(nowFunc())}
	if err := AtomicWrite(path, journal, 0o600); err != nil {
		return err
	}
	applyErr := func() error {
		if _, _, err := runCommand([]string{"/usr/bin/systemctl", "stop", NativeTimerUnit}, cmdOpts{timeout: 60 * time.Second, check: true}); err != nil {
			return err
		}
		cur, err := readNativeTimer()
		if err != nil {
			return err
		}
		if cur["active"] == true {
			return secErr("The native APT timer could not be stopped")
		}
		if err := assertNativeIdle(); err != nil {
			return err
		}
		if en := strVal(cur["enabled"]); en == "enabled" || en == "enabled-runtime" {
			argv := []string{"/usr/bin/systemctl", "disable"}
			if en == "enabled-runtime" {
				argv = append(argv, "--runtime")
			}
			argv = append(argv, NativeTimerUnit)
			if _, _, err := runCommand(argv, cmdOpts{timeout: 60 * time.Second, check: true}); err != nil {
				return err
			}
		}
		if err := AtomicWrite(osRestartDropin, osRestartConfig, 0o644); err != nil {
			return err
		}
		if err := AtomicWrite(osAptGuard, osAptGuardConfig, 0o644); err != nil {
			return err
		}
		if err := bootstrapOSSecurityTools(distro, codename, stdout); err != nil {
			return err
		}
		journal["phase"] = "ready"
		if err := assertOSManaged(journal, false); err != nil {
			return err
		}
		return AtomicWrite(path, journal, 0o600)
	}()
	if applyErr != nil {
		rollbackErr := func() error {
			if old != nil {
				oldPol, _ := old["policy"].(map[string]any)
				if strVal(oldPol["mode"]) != "system" {
					return AtomicWrite(path, old, 0o600)
				}
			}
			for _, pair := range []struct{ p, exp string }{{osRestartDropin, osRestartConfig}, {osAptGuard, osAptGuardConfig}} {
				if isRegularFile(pair.p) && !isSymlink(pair.p) {
					if raw, rerr := os.ReadFile(pair.p); rerr == nil && string(raw) == pair.exp {
						_ = os.Remove(pair.p)
					}
				}
			}
			if err := restoreNativeTimer(baseline); err != nil {
				return err
			}
			fallback := old
			if fallback == nil {
				fallback = map[string]any{"phase": "ready", "policy": map[string]any{"mode": "system", "interval": 4, "start": 3, "end": 5}}
			}
			return AtomicWrite(path, fallback, 0o600)
		}()
		if rollbackErr != nil {
			rec := copyMap(journal)
			rec["phase"] = "recovery_required"
			_ = AtomicWrite(path, rec, 0o600)
		}
		return applyErr
	}
	return nil
}

var buildAptEnvironment = func(dir, distro, codename string) (map[string]string, error) {
	mainConf := filepath.Join(dir, "main.conf")
	var patterns []string
	if distro == "ubuntu" {
		patterns = []string{
			fmt.Sprintf("origin=Ubuntu,archive=%s-security", codename),
			fmt.Sprintf("origin=UbuntuESMApps,archive=%s-apps-security", codename),
			fmt.Sprintf("origin=UbuntuESM,archive=%s-infra-security", codename),
		}
	} else {
		patterns = []string{fmt.Sprintf("origin=Debian,label=Debian-Security,codename=%s-security", codename)}
	}
	var b strings.Builder
	if isRegularFile("/etc/apt/apt.conf") {
		b.WriteString("#include \"/etc/apt/apt.conf\";\n")
	}
	b.WriteString("#clear Unattended-Upgrade::Allowed-Origins;\n#clear Unattended-Upgrade::Origins-Pattern;\n")
	b.WriteString("Unattended-Upgrade::Origins-Pattern { ")
	for i, p := range patterns {
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%q;", p)
	}
	b.WriteString(" };\n")
	protectedNames := make([]string, 0, len(osProtectedPackages))
	for k := range osProtectedPackages {
		protectedNames = append(protectedNames, k)
	}
	sort.Strings(protectedNames)
	b.WriteString("Unattended-Upgrade::Package-Blacklist { ")
	for i, n := range protectedNames {
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "\"^%s(:[a-z0-9]+)?$\";", strings.ReplaceAll(n, ".", "[.]"))
	}
	b.WriteString(" };\n")
	b.WriteString("APT::Get::AllowUnauthenticated \"false\";\nAcquire::AllowInsecureRepositories \"false\";\n")
	b.WriteString("APT::Ignore-Hold \"false\";\nAPT::Get::allow-change-held-packages \"false\";\n")
	for _, opt := range []string{
		"Automatic-Reboot", "Automatic-Reboot-WithUsers", "InstallOnShutdown",
		"Remove-Unused-Dependencies", "Remove-New-Unused-Dependencies",
		"Remove-Unused-Kernel-Packages", "Allow-downgrade", "Allow-APT-Mark-Fallback",
	} {
		fmt.Fprintf(&b, "Unattended-Upgrade::%s \"false\";\n", opt)
	}
	b.WriteString("#clear Binary::unattended-upgrade;\n#clear Binary::unattended-upgrades;\n")
	if err := AtomicWrite(mainConf, b.String(), 0o600); err != nil {
		return nil, err
	}
	initConf := filepath.Join(dir, "initial.conf")
	if err := AtomicWrite(initConf, fmt.Sprintf("Dir::Etc::main \"%s\";\n", mainConf), 0o600); err != nil {
		return nil, err
	}
	return map[string]string{"APT_CONFIG": initConf, "NEEDRESTART_MODE": "a"}, nil
}

// restartStatus inspects pending service restarts and kernel reboot state.
var restartStatus = func() map[string]any {
	reboot := lexists(rebootRequiredPath)
	svcSet := map[string]bool{}
	var errVal any
	var kernelWarn any
	if isRegularFile(needrestartBin) {
		code, text, err := runCommand([]string{needrestartBin, "-b", "-r", "l"}, cmdOpts{timeout: 60 * time.Second})
		if err != nil || code != 0 {
			errVal = "The restart check failed"
		} else {
			for _, m := range needrestartSvcRe.FindAllStringSubmatch(text, -1) {
				svcSet[m[1]] = true
			}
			if km := needrestartKstRe.FindStringSubmatch(text); km != nil {
				if n, nerr := strconv.Atoi(km[1]); nerr == nil && (n == 1 || n == 2 || n == 3) {
					reboot = reboot || n > 1
				} else {
					kernelWarn = "The kernel restart state is unknown"
				}
			} else {
				kernelWarn = "The kernel restart state is unknown"
			}
		}
	} else {
		errVal = "The restart checker is not installed"
	}
	svcs := sortedMapKeys(svcSet)
	if len(svcs) > 100 {
		svcs = svcs[:100]
		svcSet = map[string]bool{}
		for _, s := range svcs {
			svcSet[s] = true
		}
	}
	for _, name := range []string{"haproxy", "docker", "containerd", "easy-ha-proxy-updated", "easy-ha-proxy-backupd"} {
		code, text, err := runCommand([]string{"/usr/bin/systemctl", "show", name + ".service", "--property=MainPID", "--value"},
			cmdOpts{timeout: 60 * time.Second})
		pidStr := strings.TrimSpace(text)
		pid, perr := strconv.Atoi(pidStr)
		if err == nil && code == 0 && perr == nil && pid > 0 {
			procDir := filepath.Join("/proc", pidStr)
			exeLink, eerr := os.Readlink(filepath.Join(procDir, "exe"))
			mapsRaw, merr := os.ReadFile(filepath.Join(procDir, "maps"))
			if eerr != nil || merr != nil {
				errVal = "A running service could not be checked for replaced libraries"
			} else if strings.Contains(exeLink, "(deleted)") || strings.Contains(string(mapsRaw), " (deleted)") {
				svcSet[name+".service"] = true
			}
		}
	}
	return map[string]any{
		"reboot_required": reboot,
		"services":        sortedMapKeys(svcSet),
		"error":           errVal,
		"kernel_warning":  kernelWarn,
		"checked_at":      unixSeconds(nowFunc()),
	}
}

func runOSSecurity(action, root string, requested map[string]any, maintenanceRevision string, stdout io.Writer) (map[string]any, error) {
	distro, codename, err := checkPlatform()
	if err != nil {
		return nil, err
	}
	if err := maintenanceGuard(false); err != nil {
		return nil, err
	}
	if action == "configure" {
		if err := configureOSSecurity(root, requested, distro, codename, stdout); err != nil {
			return nil, err
		}
		statusPath := filepath.Join(root, "status.json")
		status := map[string]any{"state": "unverified"}
		if lexists(statusPath) {
			if s, err := ReadJSON(statusPath); err == nil {
				status = s
			} else {
				return nil, err
			}
		}
		nt, err := readNativeTimer()
		if err != nil {
			return nil, err
		}
		status["native_timer"] = nt
		status["native_policy"] = readNativePolicy()
		if err := AtomicWrite(statusPath, status, 0o600); err != nil {
			return nil, err
		}
		return map[string]any{"message": "OS security policy saved"}, nil
	}

	policyPath := filepath.Join(root, "policy.json")
	policyRec := map[string]any{"phase": "ready", "policy": map[string]any{"mode": "system", "interval": 4, "start": 3, "end": 5}}
	if lexists(policyPath) {
		policyRec, err = ReadJSON(policyPath)
		if err != nil {
			return nil, err
		}
	}
	polMap, _ := policyRec["policy"].(map[string]any)
	pol, err := validateOSPolicy(polMap)
	if err != nil {
		return nil, err
	}
	if action == "install" || action == "cycle" {
		if err := assertOSManaged(policyRec, false); err != nil {
			return nil, err
		}
	} else if strVal(policyRec["phase"]) != "ready" {
		return nil, secErr("Restore system management after the interrupted policy change")
	}
	if pol.Mode != "system" {
		if err := assertOSManaged(policyRec, false); err != nil {
			return nil, err
		}
	}

	statusPath := filepath.Join(root, "status.json")
	previous := map[string]any{}
	if lexists(statusPath) {
		previous, err = ReadJSON(statusPath)
		if err != nil {
			return nil, err
		}
	}
	state := copyMap(previous)
	state["state"] = "checking"
	state["error"] = nil
	state["last_attempt"] = unixSeconds(nowFunc())
	state["platform"] = distro + " " + codename
	doInstall := action == "install" || (action == "cycle" && osScheduledInstall(pol, previous, localTimeFunc()))
	if doInstall {
		state["last_install_attempt"] = unixSeconds(nowFunc())
	}
	if err := AtomicWrite(statusPath, state, 0o600); err != nil {
		return nil, err
	}
	res, runErr := func() (map[string]any, error) {
		_, _ = fmt.Fprintln(stdout, "EHP-PROGRESS phase=checking")
		metadata, err := refreshAptFunc()
		if err != nil {
			return nil, err
		}
		if metadata["fresh"] != true {
			return nil, secErr("%s", strVal(metadata["error"]))
		}
		before, err := querySecurityPackages(distro, codename)
		if err != nil {
			return nil, err
		}
		installNow := action == "install" || (action == "cycle" && osScheduledInstall(pol, previous, localTimeFunc()))
		if installNow {
			state["last_install_attempt"] = unixSeconds(nowFunc())
			if err := AtomicWrite(statusPath, state, 0o600); err != nil {
				return nil, err
			}
			if err := assertOSManaged(policyRec, false); err != nil {
				return nil, err
			}
			if !isRegularFile(unattendedUpgradeBin) {
				return nil, secErr("The security installer is not installed; save the policy again")
			}
			hasEligible := false
			for _, row := range before {
				if !row.Protected && !row.Held {
					hasEligible = true
					break
				}
			}
			if hasEligible {
				if maintenanceRevision != "" {
					if err := requireMWWindow(root, maintenanceRevision, localTimeFunc()); err != nil {
						return nil, err
					}
				}
				_, _ = fmt.Fprintln(stdout, "EHP-PROGRESS phase=playbook")
				tmpDir, err := os.MkdirTemp(root, "os-security-")
				if err != nil {
					return nil, err
				}
				defer os.RemoveAll(tmpDir)
				env, err := buildAptEnvironment(tmpDir, distro, codename)
				if err != nil {
					return nil, err
				}
				_, logOut, err := runCommand([]string{unattendedUpgradeBin, "--verbose", "--minimal-upgrade-steps"},
					cmdOpts{timeout: 5400 * time.Second, env: env, check: true, stdout: stdout})
				if err != nil {
					return nil, err
				}
				_, _ = fmt.Fprintln(stdout, logOut)
			}
		}
		after, err := querySecurityPackages(distro, codename)
		if err != nil {
			return nil, err
		}
		remaining := map[string]securityPackageRow{}
		for _, r := range after {
			remaining[r.Name] = r
		}
		reviewed := map[string]string{}
		if installNow {
			for _, r := range before {
				reviewed[r.Name] = r.Candidate
			}
		} else if prevUnapplied, ok := previous["unapplied_packages"].(map[string]any); ok {
			for k, v := range prevUnapplied {
				reviewed[k] = strVal(v)
			}
		}
		unapplied := map[string]string{}
		for _, r := range after {
			if reviewed[r.Name] == r.Candidate {
				unapplied[r.Name] = r.Candidate
			}
		}
		installedCount := 0
		if installNow {
			for _, r := range before {
				rem, stillThere := remaining[r.Name]
				if !stillThere || CompareVersions(rem.Installed, r.Installed) > 0 {
					installedCount++
				}
			}
		}
		eligibleCount := 0
		for _, r := range after {
			if !r.Protected && !r.Held {
				eligibleCount++
			}
		}
		shown := after
		if len(shown) > 200 {
			shown = shown[:200]
		}
		nt, err := readNativeTimer()
		if err != nil {
			return nil, err
		}
		nowTS := unixSeconds(nowFunc())
		state["state"] = "ready"
		state["error"] = nil
		state["checked_at"] = nowTS
		state["packages"] = shown
		state["package_count"] = len(after)
		state["eligible_count"] = eligibleCount
		state["restart"] = restartStatus()
		state["native_timer"] = nt
		state["installed_count"] = installedCount
		state["native_policy"] = readNativePolicy()
		if installNow {
			state["last_install_at"] = nowTS
		} else if v, ok := previous["last_install_at"]; ok {
			state["last_install_at"] = v
		} else {
			state["last_install_at"] = nil
		}
		state["last_success"] = nowTS
		persisted := copyMap(state)
		persisted["unapplied_packages"] = unapplied
		if err := AtomicWrite(statusPath, persisted, 0o600); err != nil {
			return nil, err
		}
		delete(state, "unapplied_packages")
		msg := "OS security check completed"
		if installNow {
			msg = "OS security installation finished; review remaining updates and restarts"
		}
		out := copyMap(state)
		out["message"] = msg
		return out, nil
	}()
	if runErr != nil {
		failed := copyMap(state)
		failed["state"] = "unknown"
		failed["error"] = truncStr(runErr.Error(), 500)
		_ = AtomicWrite(statusPath, failed, 0o600)
		return nil, runErr
	}
	return res, nil
}

// RunOSSecurityCLI implements "easy-ha-proxy-agent os-security <action> [flags]".
func RunOSSecurityCLI(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		fmt.Fprintln(stderr, "usage: easy-ha-proxy-agent os-security <check|install|cycle|configure|inspect> [flags]")
		return 2
	}
	action := args[0]
	switch action {
	case "check", "install", "cycle", "configure", "inspect":
	default:
		fmt.Fprintf(stderr, "unsupported os-security action: %s\n", action)
		return 2
	}
	fs := flag.NewFlagSet("os-security", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateRoot := fs.String("state-root", DefaultStateRoot, "")
	lockPath := fs.String("maintenance-lock", DefaultLockPath, "")
	mode := fs.String("mode", "", "")
	interval := fs.Int("interval", 4, "")
	start := fs.Int("start", 3, "")
	end := fs.Int("end", 5, "")
	requestID := fs.String("request-id", "", "")
	maintRev := fs.String("maintenance-revision", "", "")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "OS security maintenance must run as root")
		return 2
	}
	syscall.Umask(0o077)
	writeErr := func(err error) int {
		b, _ := json.Marshal(map[string]any{"ok": false, "error": err.Error()})
		fmt.Fprintln(stdout, string(b))
		return 1
	}
	if action == "inspect" {
		res, err := InspectOSSettings()
		if err != nil {
			return writeErr(err)
		}
		res["ok"] = true
		b, _ := json.Marshal(res)
		fmt.Fprintln(stdout, string(b))
		return 0
	}
	_ = syscall.Setpriority(syscall.PRIO_PROCESS, 0, 10)
	if isRegularFile("/usr/bin/ionice") {
		_, _, _ = runCommand([]string{"/usr/bin/ionice", "-c", "2", "-n", "7", "-p", strconv.Itoa(os.Getpid())}, cmdOpts{timeout: 5 * time.Second})
	}
	lock, err := acquireFlock(*lockPath, false)
	if err != nil {
		return writeErr(err)
	}
	defer lock.Close()
	requested := map[string]any{"mode": *mode, "interval": *interval, "start": *start, "end": *end}
	res, err := runOSSecurity(action, *stateRoot, requested, *maintRev, stdout)
	if err != nil {
		return writeErr(err)
	}
	res["ok"] = true
	res["request_id"] = *requestID
	b, _ := json.Marshal(res)
	fmt.Fprintln(stdout, string(b))
	return 0
}

func copyMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func sortedMapKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func truncStr(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max])
}
