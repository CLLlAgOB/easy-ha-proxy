package hostsec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/pyx"
)

var (
	guardHAProxyPkgs = map[string]bool{"haproxy": true, "haproxy-awslc": true, "libssl-awslc": true}
	guardRuntimePkgs = map[string]bool{
		"docker-ce": true, "docker-ce-cli": true, "docker.io": true, "docker-ce-rootless-extras": true,
		"containerd": true, "containerd.io": true, "runc": true,
		"moby-engine": true, "moby-cli": true, "moby-containerd": true, "moby-runc": true,
	}
	guardInstRe        = regexp.MustCompile(`^Inst ([a-z0-9][a-z0-9+.-]*(?::[a-z0-9]+)?)(?: \[([^\]]+)\])? \((\S+)(?:\s|\))`)
	guardVerRe         = regexp.MustCompile(`^(?:(\d+):)?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$`)
	guardPrereleaseRe  = regexp.MustCompile(`(?:[~+-])(?:rc|alpha|beta)(?:[.\d-]|$)`)
	guardContainerNmRe = regexp.MustCompile(`^/[A-Za-z0-9][A-Za-z0-9_.-]*$`)
	guardRuntimeFiles  = []string{"/etc/docker/daemon.json", "/opt/authelia/docker-compose.yml", "/opt/haproxy-admin/docker-compose.yml"}
	guardDpkgLockPath  = "/var/lib/dpkg/lock-frontend"
	guardMaintLockPath = DefaultLockPath
	guardSleep         = time.Sleep
)

var guardRun = func(argv []string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := pyx.GroupCommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdin = nil
	cmd.Env = append(os.Environ(), "LC_ALL=C", "DEBIAN_FRONTEND=noninteractive")
	stdout := fullBuffer{limit: 2 << 20}
	stderr := tailBuffer{limit: maxTailBytes}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return "", refusef("Command timed out: %s", filepath.Base(argv[0]))
	}
	if err != nil {
		code := 1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			code = exitErr.ExitCode()
		}
		label := filepath.Base(argv[0])
		if len(argv) > 1 {
			label += " " + argv[1]
		}
		detail := repoURLRe.ReplaceAllString(stderr.String(), "[repository]")
		detail = strings.Join(strings.Fields(detail), " ")
		if len(detail) > 2000 {
			detail = detail[:2000]
		}
		return "", refusef("Command failed: %s (exit %d): %s", label, code, detail)
	}
	if stdout.overflow {
		return "", refusef("Command output exceeds the safety limit: %s", filepath.Base(argv[0]))
	}
	return stdout.buf.String(), nil
}

var guardRunUpgrade = func(argv []string, stdout io.Writer) error {
	rc, output, err := runCommand(argv, cmdOpts{timeout: 90 * time.Minute})
	if stdout != nil && output != "" {
		_, _ = fmt.Fprintln(stdout, output)
	}
	if err != nil {
		return refusef("OS package installation failed; inspect the package-manager state: %v", err)
	}
	if rc != 0 {
		return refusef("OS package installation failed; inspect the package-manager state")
	}
	return nil
}

type patchLineKey struct {
	epoch, major, minor int
	valid               bool
}

func guardPatchLine(version string) patchLineKey {
	if version == "" {
		return patchLineKey{}
	}
	m := guardVerRe.FindStringSubmatch(version)
	if m == nil || guardPrereleaseRe.MatchString(version) {
		return patchLineKey{}
	}
	epoch := 0
	if m[1] != "" {
		epoch, _ = strconv.Atoi(m[1])
	}
	major, _ := strconv.Atoi(m[2])
	minor, _ := strconv.Atoi(m[3])
	return patchLineKey{epoch: epoch, major: major, minor: minor, valid: true}
}

// ValidateOSUpgrade checks dpkg selections and apt-get -s upgrade simulation.
func ValidateOSUpgrade(selections, simulation string, automatic, allowRuntimeChange bool) ([]string, error) {
	for _, line := range strings.Split(selections, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 {
			base, _, _ := strings.Cut(fields[0], ":")
			if guardHAProxyPkgs[base] && fields[1] != "hold" && fields[1] != "deinstall" && fields[1] != "purge" {
				return nil, refusef("HAProxy package protection is missing: %s", fields[0])
			}
		}
	}
	runtimes := []string{}
	for _, line := range strings.Split(simulation, "\n") {
		if strings.HasPrefix(line, "Remv ") {
			return nil, refusef("An OS upgrade must not remove packages")
		}
		if !strings.HasPrefix(line, "Inst ") {
			continue
		}
		m := guardInstRe.FindStringSubmatch(line)
		if m == nil {
			return nil, refusef("An APT package candidate could not be verified")
		}
		pkg, inst, cand := m[1], m[2], m[3]
		name, _, _ := strings.Cut(pkg, ":")
		if guardHAProxyPkgs[name] {
			return nil, refusef("HAProxy packages must be updated separately: %s", pkg)
		}
		if automatic && guardRuntimePkgs[name] {
			plOld := guardPatchLine(inst)
			plNew := guardPatchLine(cand)
			if !plOld.valid || !plNew.valid || (!allowRuntimeChange && plOld != plNew) {
				shownOld := inst
				if shownOld == "" {
					shownOld = "not installed"
				}
				return nil, refusef("Automatic OS installation requires manual review of %s: %s -> %s. Only patch updates within the installed runtime release line are automatic.", pkg, shownOld, cand)
			}
			runtimes = append(runtimes, pkg)
		}
	}
	return runtimes, nil
}

func recordUpgradeAttempt(root string) error {
	return AtomicWrite(filepath.Join(root, "package-install.json"), map[string]any{"last_install_attempt": unixSeconds(nowFunc())}, 0o600)
}

var checkRuntimeConsent = func(root, revision string, deadline float64, reserve float64, requireRuntime bool, localOverride *time.Time) error {
	p := filepath.Join(filepath.Dir(root), "settings.json")
	info, err := os.Lstat(p)
	if err != nil {
		return refusef("Unsafe runtime maintenance consent")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || (requireRootOwner && st.Uid != 0) || info.Size() > maxJSONBytes {
		return refusef("Unsafe runtime maintenance consent")
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return refusef("Unsafe runtime maintenance consent")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var settings map[string]any
	if err := dec.Decode(&settings); err != nil {
		return refusef("Unsafe runtime maintenance consent")
	}
	local := localTimeFunc()
	if localOverride != nil {
		local = *localOverride
	}
	start, okS := strictIntVal(settings["auto_install_start"])
	end, okE := strictIntVal(settings["auto_install_end"])
	if !okS || !okE || start < 0 || start >= 24 || end < 0 || end >= 24 || start == end {
		return refusef("Invalid runtime maintenance window")
	}
	w := computeMWWindow(local, start, end)
	upd, okU := numVal(settings["maintenance_updated_at"])
	ts := unixSeconds(local)
	nowTS := unixSeconds(nowFunc())
	inside := w.OpensAt <= ts && ts < w.ClosesAt && okU && upd > 0 && upd <= w.OpensAt && math.Abs(deadline-w.ClosesAt) < 1
	if !inside || settings["auto_install"] != true || settings["auto_install_unified"] != true ||
		(requireRuntime && settings["auto_install_runtime"] != true) ||
		strVal(settings["maintenance_revision"]) != revision ||
		!(nowTS+reserve < deadline && deadline <= nowTS+86400) {
		return refusef("Runtime maintenance consent was revoked or its window has closed")
	}
	return nil
}

type containerInfo struct {
	ID     string  `json:"id"`
	Name   string  `json:"name"`
	Status string  `json:"status"`
	Paused bool    `json:"paused"`
	Health *string `json:"health"`
}

var inspectContainerState = func(identity string) (containerInfo, error) {
	out, err := guardRun([]string{"/usr/bin/docker", "inspect", "--type", "container", identity})
	if err != nil {
		return containerInfo{}, err
	}
	var records []map[string]any
	if err := json.Unmarshal([]byte(out), &records); err != nil || len(records) != 1 {
		return containerInfo{}, refusef("A container identity could not be verified")
	}
	rec := records[0]
	id := strVal(rec["Id"])
	if !hex64Re.MatchString(id) {
		return containerInfo{}, refusef("A container identity could not be verified")
	}
	state, _ := rec["State"].(map[string]any)
	var healthPtr *string
	if h, ok := state["Health"].(map[string]any); ok {
		s := strVal(h["Status"])
		healthPtr = &s
	}
	return containerInfo{
		ID:     id,
		Name:   strVal(rec["Name"]),
		Status: strVal(state["Status"]),
		Paused: state["Paused"] == true,
		Health: healthPtr,
	}, nil
}

var listRunningContainers = func() ([]containerInfo, error) {
	out, err := guardRun([]string{"/usr/bin/docker", "ps", "--no-trunc", "-q"})
	if err != nil {
		return nil, err
	}
	ids := strings.Fields(out)
	if len(ids) > 256 {
		return nil, refusef("The running container set could not be verified")
	}
	for _, id := range ids {
		if !hex64Re.MatchString(id) {
			return nil, refusef("The running container set could not be verified")
		}
	}
	res := make([]containerInfo, 0, len(ids))
	for _, id := range ids {
		ci, err := inspectContainerState(id)
		if err != nil {
			return nil, err
		}
		if ci.Status != "running" || ci.Paused || (ci.Health != nil && *ci.Health != "healthy") {
			return nil, refusef("Resolve unhealthy, restarting or paused containers before runtime maintenance")
		}
		res = append(res, ci)
	}
	return res, nil
}

func recoveryContainerState(item containerInfo) (containerInfo, error) {
	cur, err := inspectContainerState(item.ID)
	if err != nil {
		if !guardContainerNmRe.MatchString(item.Name) {
			return containerInfo{}, err
		}
		allOut, aerr := guardRun([]string{"/usr/bin/docker", "ps", "-a", "--no-trunc", "--format", "{{.ID}}"})
		if aerr != nil {
			return containerInfo{}, err
		}
		for _, id := range strings.Fields(allOut) {
			if !hex64Re.MatchString(id) || id == item.ID {
				return containerInfo{}, err
			}
		}
		cur, err = inspectContainerState(item.Name)
		if err != nil {
			return containerInfo{}, err
		}
		if cur.Name != item.Name || cur.ID == item.ID || cur.Status != "running" || cur.Paused {
			return containerInfo{}, refusef("Replacement container is not running: %s", item.Name)
		}
		return cur, nil
	}
	if cur.ID == item.ID {
		return cur, nil
	}
	if cur.Name != item.Name {
		return containerInfo{}, refusef("A recovery container identity could not be verified")
	}
	return cur, nil
}

var restoreContainers = func(containers []containerInfo) error {
	deadline := nowFunc().Add(180 * time.Second)
	_, _ = guardRun([]string{"/usr/bin/systemctl", "start", "docker.service"})
	starts := map[string]int{}
	lastErr := map[string]string{}
	for {
		var pending []string
		for _, item := range containers {
			label := item.Name
			if label == "" && len(item.ID) >= 12 {
				label = item.ID[:12]
			}
			cur, err := recoveryContainerState(item)
			if err != nil {
				lastErr[item.ID] = err.Error()
				pending = append(pending, fmt.Sprintf("%s: %v", label, err))
				continue
			}
			if cur.ID == item.ID && (cur.Status == "created" || cur.Status == "exited") && starts[item.ID] < 3 {
				starts[item.ID]++
				if _, serr := guardRun([]string{"/usr/bin/docker", "start", item.ID}); serr != nil {
					lastErr[item.ID] = serr.Error()
					pending = append(pending, fmt.Sprintf("%s: %v", label, serr))
					continue
				}
				cur, err = inspectContainerState(item.ID)
				if err != nil {
					lastErr[item.ID] = err.Error()
					pending = append(pending, fmt.Sprintf("%s: %v", label, err))
					continue
				}
			}
			if cur.Status != "running" || cur.Paused || (cur.Health != nil && *cur.Health != "healthy") {
				healthStr := "None"
				if cur.Health != nil {
					healthStr = *cur.Health
				}
				detail := fmt.Sprintf("%s: status=%s, health=%s, paused=%v", label, cur.Status, healthStr, cur.Paused)
				if prev, ok := lastErr[item.ID]; ok {
					detail += "; last error: " + prev
				}
				pending = append(pending, detail)
			}
		}
		if len(pending) == 0 {
			return nil
		}
		if !nowFunc().Before(deadline) {
			joined := strings.Join(pending, "; ")
			if len(joined) > 8000 {
				joined = joined[:8000]
			}
			return refusef("Some containers did not recover; further runtime updates require operator recovery: %s", joined)
		}
		guardSleep(2 * time.Second)
	}
}

func performRuntimeMaintenance(root, revision string, deadline float64, allowRuntimeChange bool, stdout io.Writer) error {
	journal := filepath.Join(root, "runtime-maintenance.json")
	if lexists(journal) {
		raw, err := os.ReadFile(journal)
		if err != nil {
			return err
		}
		var rec map[string]any
		if err := json.Unmarshal(raw, &rec); err != nil {
			return err
		}
		if ph := strVal(rec["phase"]); ph != "completed" && ph != "recovered" {
			return refusef("Previous runtime maintenance requires recovery before another upgrade")
		}
	}
	if err := checkRuntimeConsent(root, revision, deadline, 0, allowRuntimeChange, nil); err != nil {
		return err
	}
	selections, err := guardRun([]string{"/usr/bin/dpkg", "--get-selections"})
	if err != nil {
		return err
	}
	simulation, err := guardRun([]string{"/usr/bin/apt-get", "-s", "--with-new-pkgs", "upgrade"})
	if err != nil {
		return err
	}
	runtimes, err := ValidateOSUpgrade(selections, simulation, true, allowRuntimeChange)
	if err != nil {
		return err
	}
	if len(runtimes) > 0 && !allowRuntimeChange {
		live, err := guardRun([]string{"/usr/bin/docker", "info", "--format", "{{.LiveRestoreEnabled}}"})
		if err != nil {
			return err
		}
		if strings.ToLower(strings.TrimSpace(live)) != "true" {
			return refusef("Automatic runtime patch updates require Docker live-restore")
		}
	}
	hasChanges := false
	for _, line := range strings.Split(simulation, "\n") {
		if m := guardInstRe.FindStringSubmatch(line); m != nil {
			base, _, _ := strings.Cut(m[1], ":")
			if guardRuntimePkgs[base] && guardPatchLine(m[2]) != guardPatchLine(m[3]) {
				hasChanges = true
				break
			}
		}
	}
	if len(runtimes) > 0 {
		swarm, err := guardRun([]string{"/usr/bin/docker", "info", "--format", "{{.Swarm.LocalNodeState}}"})
		if err != nil {
			return err
		}
		if strings.TrimSpace(swarm) == "active" {
			return refusef("Automatic runtime maintenance does not support Docker Swarm")
		}
	}
	if err := guardRunUpgrade([]string{"/usr/bin/apt-get", "-y", "--download-only", "--with-new-pkgs", "upgrade"}, stdout); err != nil {
		return err
	}
	reserve := 0.0
	if hasChanges {
		reserve = 600.0
	}
	if err := checkRuntimeConsent(root, revision, deadline, reserve, allowRuntimeChange, nil); err != nil {
		return err
	}
	reviewed := filterSimLines(simulation)
	latest, err := guardRun([]string{"/usr/bin/apt-get", "-s", "--with-new-pkgs", "upgrade"})
	if err != nil {
		return err
	}
	if strings.Join(reviewed, "\n") != strings.Join(filterSimLines(latest), "\n") {
		return refusef("APT candidates changed during download; runtime maintenance was deferred")
	}
	var containers []containerInfo
	if len(runtimes) > 0 {
		containers, err = listRunningContainers()
		if err != nil {
			return err
		}
	}
	record := map[string]any{"phase": "prepared", "revision": revision, "containers": containers, "started_at": unixSeconds(nowFunc())}
	if len(runtimes) > 0 {
		backupDir := filepath.Join(root, fmt.Sprintf("runtime-backup-%d", nowFunc().Unix()))
		if err := os.MkdirAll(root, 0o700); err != nil {
			return err
		}
		if err := os.Mkdir(backupDir, 0o700); err != nil {
			return err
		}
		for idx, src := range guardRuntimeFiles {
			if isRegularFile(src) && !isSymlink(src) {
				raw, rerr := os.ReadFile(src)
				if rerr != nil {
					return rerr
				}
				dst := filepath.Join(backupDir, fmt.Sprintf("%d-%s", idx, filepath.Base(src)))
				if err := AtomicWrite(dst, raw, 0o600); err != nil {
					return err
				}
			}
		}
		record["backup"] = backupDir
		if err := AtomicWrite(journal, record, 0o600); err != nil {
			return err
		}
	}
	var failure error
	installStarted := false
	func() {
		defer func() {
			if len(runtimes) == 0 {
				return
			}
			record["phase"] = "restoring"
			_ = AtomicWrite(journal, record, 0o600)
			if rerr := restoreContainers(containers); rerr != nil {
				record["phase"] = "recovery_required"
				record["restored"] = false
				record["error"] = rerr.Error()
				record["completed_at"] = unixSeconds(nowFunc())
				failure = rerr
			} else {
				phase := "completed"
				if failure != nil {
					if installStarted {
						phase = "failed"
					} else {
						phase = "recovered"
					}
					record["error"] = failure.Error()
				}
				record["phase"] = phase
				record["restored"] = true
				record["installation_started"] = installStarted
				record["completed_at"] = unixSeconds(nowFunc())
			}
			_ = AtomicWrite(journal, record, 0o600)
		}()
		if hasChanges {
			record["phase"] = "stopping"
			if err := AtomicWrite(journal, record, 0o600); err != nil {
				failure = err
				return
			}
			if len(containers) > 0 {
				argv := []string{"/usr/bin/docker", "stop", "--time", "60"}
				for _, c := range containers {
					argv = append(argv, c.ID)
				}
				if _, err := guardRun(argv); err != nil {
					failure = err
					return
				}
			}
			still, err := guardRun([]string{"/usr/bin/docker", "ps", "-q"})
			if err != nil {
				failure = err
				return
			}
			if strings.TrimSpace(still) != "" {
				failure = refusef("New containers appeared during maintenance; the upgrade was refused")
				return
			}
		}
		if err := checkRuntimeConsent(root, revision, deadline, 0, allowRuntimeChange, nil); err != nil {
			failure = err
			return
		}
		if err := recordUpgradeAttempt(root); err != nil {
			failure = err
			return
		}
		record["phase"] = "upgrading"
		if len(runtimes) > 0 {
			if err := AtomicWrite(journal, record, 0o600); err != nil {
				failure = err
				return
			}
		}
		installStarted = true
		if err := guardRunUpgrade([]string{"/usr/bin/apt-get", "-y", "--no-remove", "--with-new-pkgs",
			"-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", "upgrade"}, stdout); err != nil {
			failure = err
		}
	}()
	if failure != nil {
		return refusef("%s", failure.Error())
	}
	return nil
}

func filterSimLines(sim string) []string {
	var out []string
	for _, l := range strings.Split(sim, "\n") {
		if strings.HasPrefix(l, "Inst ") || strings.HasPrefix(l, "Remv ") {
			out = append(out, l)
		}
	}
	return out
}

func recoverRuntimeMaintenance(root string) error {
	custody, err := acquireFlock(guardMaintLockPath, false)
	if err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return refusef("Another maintenance operation is active; wait before runtime recovery")
		}
		return err
	}
	defer custody.Close()
	journal := filepath.Join(root, "runtime-maintenance.json")
	raw, err := os.ReadFile(journal)
	if err != nil {
		return err
	}
	var record map[string]any
	if err := json.Unmarshal(raw, &record); err != nil {
		return err
	}
	rawContainers, ok := record["containers"].([]any)
	if !ok || len(rawContainers) > 256 {
		return refusef("Unsafe runtime recovery record")
	}
	containers := make([]containerInfo, 0, len(rawContainers))
	for _, entry := range rawContainers {
		m, ok := entry.(map[string]any)
		if !ok || !hex64Re.MatchString(strVal(m["id"])) {
			return refusef("Unsafe runtime recovery record")
		}
		var hPtr *string
		if hs, ok := m["health"].(string); ok {
			hPtr = &hs
		}
		containers = append(containers, containerInfo{
			ID:     strVal(m["id"]),
			Name:   strVal(m["name"]),
			Status: strVal(m["status"]),
			Paused: m["paused"] == true,
			Health: hPtr,
		})
	}
	dpkgLock, err := os.OpenFile(guardDpkgLockPath, os.O_RDWR|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer dpkgLock.Close()
	fl := unix.Flock_t{Type: unix.F_WRLCK, Whence: io.SeekStart, Start: 0, Len: 0}
	if err := unix.FcntlFlock(dpkgLock.Fd(), unix.F_SETLK, &fl); err != nil {
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EACCES) {
			return refusef("APT is still active; wait before runtime recovery")
		}
		return err
	}
	if err := restoreContainers(containers); err != nil {
		return err
	}
	record["phase"] = "recovered"
	record["restored"] = true
	record["recovered_at"] = unixSeconds(nowFunc())
	return AtomicWrite(journal, record, 0o600)
}

func prepareOSUpgrade(automatic bool, root string) error {
	journal := filepath.Join(root, "runtime-maintenance.json")
	if lexists(journal) {
		raw, err := os.ReadFile(journal)
		if err != nil {
			return err
		}
		var rec map[string]any
		if err := json.Unmarshal(raw, &rec); err != nil {
			return err
		}
		if ph := strVal(rec["phase"]); ph != "completed" && ph != "recovered" {
			return refusef("Runtime recovery is required; run easy-ha-proxy-agent os-upgrade-guard --recover-runtime")
		}
	}
	selections, err := guardRun([]string{"/usr/bin/dpkg", "--get-selections"})
	if err != nil {
		return err
	}
	simulation, err := guardRun([]string{"/usr/bin/apt-get", "-s", "--with-new-pkgs", "upgrade"})
	if err != nil {
		return err
	}
	runtimes, err := ValidateOSUpgrade(selections, simulation, automatic, false)
	if err != nil {
		return err
	}
	if len(runtimes) > 0 {
		live, err := guardRun([]string{"/usr/bin/docker", "--host", "unix:///var/run/docker.sock",
			"info", "--format", "{{.LiveRestoreEnabled}}"})
		if err != nil {
			return err
		}
		if strings.ToLower(strings.TrimSpace(live)) != "true" {
			return refusef("Automatic runtime updates require verified Docker live-restore")
		}
	}
	return recordUpgradeAttempt(root)
}

// RunOSUpgradeGuardCLI implements "easy-ha-proxy-agent os-upgrade-guard [flags]".
func RunOSUpgradeGuardCLI(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("os-upgrade-guard", flag.ContinueOnError)
	fs.SetOutput(stderr)
	automatic := fs.Bool("automatic", false, "")
	stateRoot := fs.String("state-root", DefaultStateRoot, "")
	runtimeMaint := fs.String("runtime-maintenance", "", "")
	maintRev := fs.String("maintenance-revision", "", "")
	maintUntil := fs.Float64("maintenance-until", -1, "")
	recoverRuntime := fs.Bool("recover-runtime", false, "")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "OS upgrade preflight requires root")
		return 2
	}
	var err error
	switch {
	case *recoverRuntime:
		err = recoverRuntimeMaintenance(*stateRoot)
	case *runtimeMaint != "" || *maintRev != "":
		rev := *runtimeMaint
		if rev == "" {
			rev = *maintRev
		}
		if !*automatic || !hex32Re.MatchString(rev) || *maintUntil < 0 {
			err = refusef("Runtime maintenance requires a valid automatic window lease")
		} else {
			err = performRuntimeMaintenance(*stateRoot, rev, *maintUntil, *runtimeMaint != "", stdout)
		}
	default:
		err = prepareOSUpgrade(*automatic, *stateRoot)
	}
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 1
	}
	return 0
}
