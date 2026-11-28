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
)

const (
	nrNativeCheck = `our %nrconf; my $loaded = do $ARGV[0]; die($@ || $!) unless defined $loaded; my $rules = $nrconf{override_rc} || {}; for my $unit (@ARGV[1..$#ARGV]) { print((grep { $unit =~ $_ && !$rules->{$_} } keys %$rules) ? "blocked\n" : "allowed\n"); }`
	nrExclusions  = "$nrconf{override_rc}{qr(^(haproxy|docker|containerd|easy-ha-proxy-updated|easy-ha-proxy-updated-job-[0-9a-f]{12}|easy-ha-proxy-backupd|dbus|dbus-broker|dnsmasq|systemd-networkd|systemd-resolved|systemd-logind|networking|NetworkManager|ModemManager|wpa_supplicant)\\.service$)} = 0;\n"
)

var (
	needrestartConfPath = "/etc/needrestart/needrestart.conf"
	perlBin             = "/usr/bin/perl"
	serviceUnitRe       = regexp.MustCompile(`^[A-Za-z0-9_@.:\-]+\.service$`)
	protectedSvcRe      = regexp.MustCompile(`^(?:haproxy|docker|containerd|easy-ha-proxy-updated|easy-ha-proxy-updated-job-[0-9a-f]{12}|easy-ha-proxy-backupd)\.service$`)
	deferredSvcRe       = regexp.MustCompile(`^(?:dbus(?:-broker)?|dnsmasq|systemd-networkd|systemd-resolved|systemd-logind|networking|NetworkManager|ModemManager|wpa_supplicant|libvirtd|virtlogd|virtlockd|gdm3?|kdm|sddm|lightdm|bird6?|frr|bluetooth)\.service$`)
)

type restartPolicyData struct {
	Enabled   bool
	Time      string
	ID        string
	UpdatedAt float64
}

func readRestartPolicy(root string) (restartPolicyData, error) {
	unified, err := readMWPolicy(root)
	if err != nil {
		return restartPolicyData{}, err
	}
	if unified != nil {
		return restartPolicyData{
			Enabled:   unified.Enabled,
			Time:      fmt.Sprintf("%02d:00", unified.Start),
			ID:        unified.ID,
			UpdatedAt: unified.UpdatedAt,
		}, nil
	}
	p := filepath.Join(root, "restart-policy.json")
	if !lexists(p) {
		return restartPolicyData{Enabled: false, Time: "02:15", ID: "", UpdatedAt: 0}, nil
	}
	val, err := ReadJSON(p)
	if err != nil {
		return restartPolicyData{}, err
	}
	en, okE := boolVal(val["enabled"])
	tm, okT := val["time"].(string)
	upd, okU := numVal(val["updated_at"])
	id := strVal(val["id"])
	if !okE || !okT || !hhmmRe.MatchString(tm) || !hex32Re.MatchString(id) || !okU {
		return restartPolicyData{}, secErr("The service restart policy is invalid")
	}
	return restartPolicyData{Enabled: en, Time: tm, ID: id, UpdatedAt: upd}, nil
}

func lastPackageInstall(root string) (float64, error) {
	statusPath := filepath.Join(root, "status.json")
	status := map[string]any{}
	if lexists(statusPath) {
		if s, err := ReadJSON(statusPath); err == nil {
			status = s
		}
	}
	best := 0.0
	for _, k := range []string{"last_install_at", "last_install_attempt"} {
		if f, ok := numVal(status[k]); ok && f > best {
			best = f
		}
	}
	pkgPath := filepath.Join(root, "package-install.json")
	if lexists(pkgPath) {
		rec, err := ReadJSON(pkgPath)
		if err != nil {
			return 0, err
		}
		att, ok := numVal(rec["last_install_attempt"])
		if !ok || !(att > 0) {
			return 0, secErr("The OS package installation record is invalid")
		}
		if att > best {
			best = att
		}
	}
	return best, nil
}

func dailyWindow(local time.Time, hhmm string) (time.Time, string, error) {
	if !hhmmRe.MatchString(hhmm) {
		return time.Time{}, "", secErr("Invalid automatic reboot time")
	}
	h, _ := strconv.Atoi(hhmm[:2])
	m, _ := strconv.Atoi(hhmm[3:])
	anchor := time.Date(local.Year(), local.Month(), local.Day(), h, m, 0, 0, local.Location())
	if local.Before(anchor) {
		anchor = time.Date(local.Year(), local.Month(), local.Day()-1, h, m, 0, 0, local.Location())
	}
	return anchor, anchor.Format("2006-01-02") + " " + hhmm, nil
}

func restartDone(pol restartPolicyData, status map[string]any, key string, installedAt float64) bool {
	comp, _ := numVal(status["completed_at"])
	return strVal(status["policy_id"]) == pol.ID && strVal(status["window"]) == key &&
		strVal(status["state"]) == "ready" && status["applied"] == true && comp >= installedAt
}

func restartDue(pol restartPolicyData, status map[string]any, local time.Time, bootID string, installedAt float64) (bool, string) {
	anchor, key, err := dailyWindow(local, pol.Time)
	if err != nil {
		return false, ""
	}
	same := strVal(status["policy_id"]) == pol.ID && strVal(status["boot_id"]) == bootID
	retry := 300.0
	if strVal(status["state"]) == "running" {
		retry = 900.0
	}
	ts := unixSeconds(local)
	anc := unixSeconds(anchor)
	lastAtt, _ := numVal(status["last_attempt"])
	ok := pol.Enabled && ts-anc >= 0 && ts-anc < 3600 && pol.UpdatedAt <= anc &&
		!restartDone(pol, status, key, installedAt) && (!same || ts-lastAtt >= retry)
	return ok, key
}

func classifyService(service string, native map[string]bool) string {
	if protectedSvcRe.MatchString(service) {
		return "protected"
	}
	if deferredSvcRe.MatchString(service) || native[service] {
		return "deferred"
	}
	if serviceUnitRe.MatchString(service) || service == "systemd-manager" {
		return "automatic"
	}
	return "unknown"
}

var queryNativeExclusions = func(units []string) map[string]bool {
	var valid []string
	for _, u := range units {
		if serviceUnitRe.MatchString(u) {
			valid = append(valid, u)
		}
	}
	if len(valid) == 0 || !isRegularFile(needrestartConfPath) || !isRegularFile(perlBin) {
		return map[string]bool{}
	}
	argv := append([]string{perlBin, "-e", nrNativeCheck, needrestartConfPath}, valid...)
	code, out, err := runCommand(argv, cmdOpts{timeout: 30 * time.Second})
	if err != nil || code != 0 {
		return map[string]bool{}
	}
	answers := strings.Fields(out)
	if len(answers) != len(valid) {
		return map[string]bool{}
	}
	blocked := map[string]bool{}
	for i, ans := range answers {
		if ans != "blocked" && ans != "allowed" {
			return map[string]bool{}
		}
		if ans == "blocked" {
			blocked[valid[i]] = true
		}
	}
	return blocked
}

func checkedRestart() (map[string]any, error) {
	result := restartStatus()
	if errText := strVal(result["error"]); errText != "" {
		return nil, secErr("%s", errText)
	}
	svcs := stringSlice(result["services"])
	var autos []string
	for _, s := range svcs {
		k := classifyService(s, nil)
		if k == "unknown" {
			return nil, secErr("The restart checker returned an unsupported service")
		}
		if k == "automatic" {
			autos = append(autos, s)
		}
	}
	native := queryNativeExclusions(autos)
	details := make([]map[string]any, 0, len(svcs))
	for _, s := range svcs {
		details = append(details, map[string]any{"service": s, "kind": classifyService(s, native)})
	}
	result["native_excluded"] = sortedMapKeys(native)
	result["details"] = details
	return result, nil
}

func fallbackServices(root string, now *time.Time, freshOverride map[string]any) ([]string, error) {
	pol, err := readRestartPolicy(root)
	if err != nil {
		return nil, err
	}
	p := filepath.Join(root, "restart-status.json")
	if !pol.Enabled || !lexists(p) {
		return []string{}, nil
	}
	status, err := ReadJSON(p)
	if err != nil {
		return nil, err
	}
	local := localTimeFunc()
	if now != nil {
		local = *now
	}
	anchor, key, err := dailyWindow(local, pol.Time)
	if err != nil {
		return nil, err
	}
	bootID, err := readBootID()
	if err != nil {
		return nil, err
	}
	installedAt, err := lastPackageInstall(root)
	if err != nil {
		return nil, err
	}
	comp, _ := numVal(status["completed_at"])
	anc := unixSeconds(anchor)
	nowTS := unixSeconds(local)
	if strVal(status["state"]) != "ready" || status["applied"] != true || status["verified"] != true ||
		strVal(status["policy_id"]) != pol.ID || strVal(status["boot_id"]) != bootID ||
		strVal(status["window"]) != key || pol.UpdatedAt > anc ||
		comp < anc || comp > nowTS || nowTS-comp > 24*3600 || comp < installedAt ||
		strVal(status["kernel_warning"]) != "" ||
		len(stringSlice(status["failed_services"])) > 0 || len(stringSlice(status["unresolved"])) > 0 {
		return []string{}, nil
	}
	deferred := stringSlice(status["deferred"])
	if len(deferred) == 0 {
		return []string{}, nil
	}
	native := map[string]bool{}
	for _, n := range stringSlice(status["native_excluded"]) {
		native[n] = true
	}
	defSet := map[string]bool{}
	for _, s := range deferred {
		k := classifyService(s, native)
		if k != "protected" && k != "deferred" {
			return []string{}, nil
		}
		defSet[s] = true
	}
	fresh := freshOverride
	if fresh == nil {
		fresh, err = checkedRestart()
		if err != nil {
			return nil, err
		}
	}
	svcs := stringSlice(fresh["services"])
	if strVal(fresh["error"]) != "" || strVal(fresh["kernel_warning"]) != "" || len(svcs) == 0 {
		return []string{}, nil
	}
	outSet := map[string]bool{}
	for _, s := range svcs {
		if !defSet[s] {
			return []string{}, nil
		}
		outSet[s] = true
	}
	return sortedMapKeys(outSet), nil
}

func executeServiceRestarts(action, root string, now *time.Time, maintenanceRevision string, stdout io.Writer) (map[string]any, error) {
	if _, _, err := checkPlatform(); err != nil {
		return nil, err
	}
	managed := map[string]any{}
	if p := filepath.Join(root, "policy.json"); lexists(p) {
		var err error
		managed, err = ReadJSON(p)
		if err != nil {
			return nil, err
		}
	}
	if action != "restart-check" {
		if err := assertOSManaged(managed, false); err != nil {
			return nil, err
		}
	}
	pol, err := readRestartPolicy(root)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(root, "restart-status.json")
	previous := map[string]any{}
	if lexists(path) {
		previous, err = ReadJSON(path)
		if err != nil {
			return nil, err
		}
	}
	local := localTimeFunc()
	if now != nil {
		local = *now
	}
	bootID, err := readBootID()
	if err != nil {
		return nil, err
	}
	_, key, err := dailyWindow(local, pol.Time)
	if err != nil {
		return nil, err
	}
	if action == "restart-cycle" {
		inst, err := lastPackageInstall(root)
		if err != nil {
			return nil, err
		}
		if ok, _ := restartDue(pol, previous, local, bootID, inst); !ok {
			return map[string]any{"message": "The service restart window is not due"}, nil
		}
	}
	if action == "restart-check" {
		if err := maintenanceGuard(false); err != nil {
			rec := copyMap(previous)
			rec["check"] = map[string]any{"error": truncStr(err.Error(), 500), "checked_at": unixSeconds(nowFunc())}
			rec["check_boot_id"] = bootID
			_ = AtomicWrite(path, rec, 0o600)
			return nil, err
		}
		fresh, err := checkedRestart()
		if err != nil {
			rec := copyMap(previous)
			rec["check"] = map[string]any{"error": truncStr(err.Error(), 500), "checked_at": unixSeconds(nowFunc())}
			rec["check_boot_id"] = bootID
			_ = AtomicWrite(path, rec, 0o600)
			return nil, err
		}
		rec := copyMap(previous)
		rec["check"] = fresh
		rec["check_boot_id"] = bootID
		if err := AtomicWrite(path, rec, 0o600); err != nil {
			return nil, err
		}
		return map[string]any{"message": "Service restart check completed", "restart": fresh}, nil
	}

	state := map[string]any{
		"state":        "running",
		"last_attempt": unixSeconds(local),
		"policy_id":    pol.ID,
		"boot_id":      bootID,
		"window":       key,
		"applied":      false,
		"verified":     false,
		"error":        nil,
	}
	if err := AtomicWrite(path, state, 0o600); err != nil {
		return nil, err
	}
	runErr := func() error {
		if err := maintenanceGuard(false); err != nil {
			return err
		}
		return withPackageLocks(func() error {
			before, err := checkedRestart()
			if err != nil {
				return err
			}
			nativeBefore := map[string]bool{}
			for _, n := range stringSlice(before["native_excluded"]) {
				nativeBefore[n] = true
			}
			var automatic []string
			for _, u := range stringSlice(before["services"]) {
				if classifyService(u, nativeBefore) == "automatic" {
					automatic = append(automatic, u)
				}
			}
			if len(automatic) > 0 {
				if maintenanceRevision != "" {
					if err := requireMWWindow(root, maintenanceRevision, localTimeFunc()); err != nil {
						return err
					}
				}
				_, _ = fmt.Fprintln(stdout, "EHP-PROGRESS phase=playbook")
				tmpDir, err := os.MkdirTemp(root, "service-restarts-")
				if err != nil {
					return err
				}
				defer os.RemoveAll(tmpDir)
				cfg := filepath.Join(tmpDir, "needrestart.conf")
				body := "my $loaded = do q(/etc/needrestart/needrestart.conf); die($@ || $!) unless defined $loaded;\n" + nrExclusions
				if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
					return err
				}
				_, logOut, err := runCommand([]string{needrestartBin, "-r", "a", "-c", cfg},
					cmdOpts{timeout: 600 * time.Second, env: map[string]string{"NEEDRESTART_MODE": "a"}, check: true, stdout: stdout})
				if err != nil {
					return err
				}
				_, _ = fmt.Fprintln(stdout, logOut)
			}
			after, err := checkedRestart()
			if err != nil {
				return err
			}
			failed := []string{}
			failedSet := map[string]bool{}
			for _, unit := range automatic {
				if unit == "systemd-manager" {
					continue
				}
				code, text, rerr := runCommand([]string{"/usr/bin/systemctl", "show", unit, "--property=ActiveState", "--value"},
					cmdOpts{timeout: 60 * time.Second})
				st := strings.TrimSpace(text)
				if rerr != nil || code != 0 || (st != "active" && st != "reloading") {
					failed = append(failed, unit)
					failedSet[unit] = true
				}
			}
			nativeAfter := map[string]bool{}
			for _, n := range stringSlice(after["native_excluded"]) {
				nativeAfter[n] = true
			}
			afterSvcs := stringSlice(after["services"])
			afterSet := map[string]bool{}
			for _, s := range afterSvcs {
				afterSet[s] = true
			}
			deferred := []string{}
			defSet := map[string]bool{}
			for _, u := range afterSvcs {
				k := classifyService(u, nativeAfter)
				if k == "protected" || k == "deferred" {
					deferred = append(deferred, u)
					defSet[u] = true
				}
			}
			unresolved := []string{}
			for _, u := range afterSvcs {
				if !defSet[u] {
					unresolved = append(unresolved, u)
				}
			}
			sort.Strings(unresolved)
			restarted := []string{}
			for _, u := range automatic {
				if !afterSet[u] && !failedSet[u] {
					restarted = append(restarted, u)
				}
			}
			sort.Strings(restarted)
			kw := after["kernel_warning"]
			if strVal(kw) == "" {
				kw = before["kernel_warning"]
			}
			state["state"] = "ready"
			state["completed_at"] = unixSeconds(nowFunc())
			state["applied"] = true
			state["verified"] = len(failed) == 0 && len(unresolved) == 0
			state["before"] = stringSlice(before["services"])
			state["restart"] = after
			state["restarted"] = restarted
			state["deferred"] = deferred
			state["unresolved"] = unresolved
			state["failed_services"] = failed
			state["kernel_warning"] = kw
			state["native_excluded"] = sortedMapKeys(nativeAfter)
			if err := AtomicWrite(path, state, 0o600); err != nil {
				return err
			}
			if len(failed) > 0 {
				return secErr("Some services did not become active after their restart")
			}
			return nil
		})
	}()
	if runErr != nil {
		failed := copyMap(state)
		failed["state"] = "unknown"
		failed["verified"] = false
		failed["error"] = truncStr(runErr.Error(), 500)
		_ = AtomicWrite(path, failed, 0o600)
		return nil, runErr
	}
	out := copyMap(state)
	out["message"] = "Service restarts finished; review remaining services"
	return out, nil
}

// RunServiceRestartsCLI implements "easy-ha-proxy-agent service-restarts <action> [flags]".
func RunServiceRestartsCLI(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		fmt.Fprintln(stderr, "usage: easy-ha-proxy-agent service-restarts <restart-check|restart|restart-cycle|reboot-reason> [flags]")
		return 2
	}
	action := args[0]
	switch action {
	case "restart-check", "restart", "restart-cycle", "reboot-reason":
	default:
		fmt.Fprintf(stderr, "unsupported service-restarts action: %s\n", action)
		return 2
	}
	fs := flag.NewFlagSet("service-restarts", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateRoot := fs.String("state-root", DefaultStateRoot, "")
	lockPath := fs.String("maintenance-lock", DefaultLockPath, "")
	requestID := fs.String("request-id", "", "")
	maintRev := fs.String("maintenance-revision", "", "")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "Service restarts require root")
		return 2
	}
	syscall.Umask(0o077)
	writeErr := func(err error) int {
		b, _ := json.Marshal(map[string]any{"ok": false, "error": err.Error()})
		fmt.Fprintln(stdout, string(b))
		return 1
	}
	var res map[string]any
	var err error
	if action == "reboot-reason" {
		svcs, serr := fallbackServices(*stateRoot, nil, nil)
		if serr != nil {
			return writeErr(serr)
		}
		res = map[string]any{"services": svcs}
	} else {
		lock, lerr := acquireFlock(*lockPath, false)
		if lerr != nil {
			return writeErr(lerr)
		}
		defer lock.Close()
		res, err = executeServiceRestarts(action, *stateRoot, nil, *maintRev, stdout)
		if err != nil {
			return writeErr(err)
		}
	}
	res["ok"] = true
	res["request_id"] = *requestID
	b, _ := json.Marshal(res)
	fmt.Fprintln(stdout, string(b))
	return 0
}

func stringSlice(v any) []string {
	switch xs := v.(type) {
	case []string:
		return xs
	case []any:
		out := make([]string, 0, len(xs))
		for _, x := range xs {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return []string{}
	}
}
