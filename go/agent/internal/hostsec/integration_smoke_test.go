//go:build hostsec_smoke

// Disposable signed APT repository & auto-reboot integration test for hostsec.
//
// Never run on a production gateway. Requires root and EHP_SECURITY_DISPOSABLE=1.
// The systemctl reboot command is ALWAYS intercepted in-process.
package hostsec

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func mustExec(t *testing.T, extraEnv []string, argv ...string) string {
	t.Helper()
	cmd := exec.Command(argv[0], argv[1:]...)
	if len(extraEnv) > 0 {
		cmd.Env = append(os.Environ(), extraEnv...)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command %v failed: %v\n%s", argv, err, string(out))
	}
	return strings.TrimSpace(string(out))
}

func buildDebFixture(t *testing.T, root, name, version, arch string) string {
	t.Helper()
	dir := filepath.Join(root, name+"-"+version)
	debDir := filepath.Join(dir, "DEBIAN")
	dataDir := filepath.Join(dir, "usr/share/ehp-os-security-fixture")
	if err := os.MkdirAll(debDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	control := fmt.Sprintf("Package: %s\nVersion: %s\nArchitecture: %s\nMaintainer: Disposable fixture <fixture@example.test>\nDescription: Disposable OS security test\n",
		name, version, arch)
	if err := os.WriteFile(filepath.Join(debDir, "control"), []byte(control), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, name), []byte(version+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(root, name+"-"+version+".deb")
	mustExec(t, nil, "dpkg-deb", "--build", dir, archive)
	return archive
}

func randHex(n int) string {
	b := make([]byte, (n+1)/2)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

// TestDisposableDpkgLockHolder holds an exclusive POSIX lock on /var/lib/dpkg/lock-frontend
// in a child process until stdin closes (pure Go, no Python required).
func TestDisposableDpkgLockHolder(t *testing.T) {
	if os.Getenv("EHP_SECURITY_DISPOSABLE") != "1" || os.Getenv("EHP_SMOKE_LOCK_HOLDER") != "1" {
		t.Skip("lock holder subtest only runs when invoked by TestDisposableOSSecurityAndAutoReboot")
	}
	f, err := os.OpenFile("/var/lib/dpkg/lock-frontend", os.O_RDWR|os.O_CREATE, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	lk := unix.Flock_t{Type: unix.F_WRLCK, Whence: io.SeekStart}
	if err := unix.FcntlFlock(f.Fd(), unix.F_SETLK, &lk); err != nil {
		t.Fatal(err)
	}
	fmt.Println("LOCK_READY")
	_, _ = io.ReadAll(os.Stdin)
}

// TestDisposableAutoRebootWorker is invoked inside systemd-run on Ubuntu runners
// to verify maintenance lock custody with systemctl reboot strictly intercepted.
func TestDisposableAutoRebootWorker(t *testing.T) {
	if os.Getenv("EHP_SECURITY_DISPOSABLE") != "1" || os.Getenv("EHP_SMOKE_REBOOT_WORKER") != "1" {
		t.Skip("worker subtest only runs when invoked by TestDisposableOSSecurityAndAutoReboot")
	}
	root := os.Getenv("EHP_SMOKE_ROOT")
	lock := os.Getenv("EHP_SMOKE_LOCK")
	marker := os.Getenv("EHP_SMOKE_MARKER")
	req := os.Getenv("EHP_SMOKE_REQUIRED")
	unit := os.Getenv("EHP_SMOKE_UNIT")
	outFile := os.Getenv("EHP_SMOKE_OUTPUT")

	reboots := 0
	origRun := runCommand
	runCommand = func(argv []string, opts cmdOpts) (int, string, error) {
		if len(argv) == 2 && argv[0] == "/usr/bin/systemctl" && argv[1] == "reboot" {
			reboots++
			return 0, "No reboot was executed by this disposable fixture.", nil
		}
		return origRun(argv, opts)
	}
	defer func() { runCommand = origRun }()

	res, err := FireAutoReboot(root, lock, marker, req, unit, nil, io.Discard)
	if err != nil {
		t.Fatalf("FireAutoReboot worker error: %v", err)
	}
	payload, _ := json.Marshal(map[string]any{"result": res, "intercepted_reboots": reboots})
	if err := os.WriteFile(outFile, append(payload, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDisposableOSSecurityAndAutoReboot(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("EHP_SECURITY_DISPOSABLE") != "1" {
		t.Fatal("Requires root and EHP_SECURITY_DISPOSABLE=1 on a disposable machine")
	}
	useSystemd := os.Getenv("EHP_SMOKE_SYSTEMD") == "1"
	if !useSystemd {
		if _, err := os.Stat("/.dockerenv"); err != nil {
			t.Fatal("The timer adapter is only for disposable containers")
		}
	}
	unix.Umask(0o022)
	base, err := os.MkdirTemp("", "ehp-disposable-os-security-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base)
	_ = os.Chmod(base, 0o755)

	origRun := runCommand
	defer func() { runCommand = origRun }()
	if !useSystemd {
		_ = os.MkdirAll("/run/systemd/system", 0o755)
		timerEnabled := "enabled"
		timerActive := true
		runCommand = func(argv []string, opts cmdOpts) (int, string, error) {
			if len(argv) == 0 || argv[0] != "/usr/bin/systemctl" {
				return origRun(argv, opts)
			}
			for _, a := range argv {
				switch a {
				case "stop":
					timerActive = false
				case "disable":
					timerEnabled = "disabled"
				case "enable":
					timerEnabled = "enabled"
				case "start":
					timerActive = true
				}
			}
			if len(argv) >= 3 && argv[1] == "show" && argv[2] == NativeTimerUnit {
				act := "inactive"
				if timerActive {
					act = "active"
				}
				return 0, fmt.Sprintf("LoadState=loaded\nUnitFileState=%s\nActiveState=%s\n", timerEnabled, act), nil
			}
			for _, a := range argv {
				if a == "apt-daily-upgrade.service" {
					return 0, "inactive\n", nil
				}
			}
			return 0, "0\n", nil
		}
	}

	distro, codename, err := checkPlatform()
	if err != nil {
		t.Fatal(err)
	}
	arch := mustExec(t, nil, "dpkg", "--print-architecture")
	names := []string{"ehp-security-fixture", "ehp-held-fixture", "ehp-protected-fixture", "ehp-nonsecurity-fixture"}
	osProtectedPackages["ehp-protected-fixture"] = true
	defer delete(osProtectedPackages, "ehp-protected-fixture")

	baseline, err := readNativeTimer()
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(base, "state")
	sourceBackup := filepath.Join(base, "original-sources")
	_ = os.MkdirAll(sourceBackup, 0o755)
	sourceFile := "/etc/apt/sources.list.d/ehp-disposable-security.list"
	extraFile := "/etc/apt/apt.conf.d/98-ehp-disposable-inherited"
	type movedPair struct{ backup, original string }
	var moved []movedPair

	defer func() {
		if polPath := filepath.Join(state, "policy.json"); lexists(polPath) {
			if rec, err := ReadJSON(polPath); err == nil && rec["baseline"] != nil {
				_, _ = runOSSecurity("configure", state, map[string]any{"mode": "system", "interval": 4, "start": 3, "end": 5}, "", io.Discard)
			}
		}
		_ = os.Remove(sourceFile)
		_ = os.Remove(extraFile)
		for _, m := range moved {
			_ = os.Rename(m.backup, m.original)
		}
		_ = exec.Command("apt-mark", "unhold", "ehp-held-fixture").Run()
		cmd := exec.Command("dpkg", append([]string{"--purge"}, names...)...)
		cmd.Env = append(os.Environ(), "NEEDRESTART_MODE=l")
		_ = cmd.Run()
	}()

	for _, name := range names {
		deb := buildDebFixture(t, base, name, "1.0", arch)
		mustExec(t, []string{"NEEDRESTART_MODE=l"}, "dpkg", "-i", deb)
	}
	mustExec(t, nil, "apt-mark", "hold", "ehp-held-fixture")

	candidates := []string{"/etc/apt/sources.list"}
	if entries, err := filepath.Glob("/etc/apt/sources.list.d/*"); err == nil {
		candidates = append(candidates, entries...)
	}
	for _, existing := range candidates {
		fi, err := os.Stat(existing)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		ext := filepath.Ext(existing)
		if filepath.Base(existing) == "sources.list" || ext == ".sources" || ext == ".list" {
			dst := filepath.Join(sourceBackup, filepath.Base(existing))
			if err := os.Rename(existing, dst); err != nil {
				t.Fatal(err)
			}
			moved = append(moved, movedPair{dst, existing})
		}
	}

	gpgHome := filepath.Join(base, "gnupg")
	_ = os.MkdirAll(gpgHome, 0o700)
	gpgBase := []string{"gpg", "--homedir", gpgHome, "--batch", "--pinentry-mode", "loopback", "--passphrase", ""}
	mustExec(t, nil, append(gpgBase, "--quick-generate-key", "Disposable security fixture <fixture@example.test>", "rsa2048", "sign", "0")...)
	keyPath := filepath.Join(base, "key.asc")
	keyOut := mustExec(t, nil, append(gpgBase, "--armor", "--export")...)
	if err := os.WriteFile(keyPath, []byte(keyOut+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	repo := filepath.Join(base, "repo")
	_ = os.MkdirAll(filepath.Join(repo, "pool"), 0o755)
	origin := "Debian"
	if distro == "ubuntu" {
		origin = "Ubuntu"
	}
	for _, spec := range []struct {
		suffix string
		pkgs   []string
		ver    string
	}{
		{"security", names[:3], "2.0"},
		{"updates", names[3:], "9.0"},
	} {
		suite := codename + "-" + spec.suffix
		var records strings.Builder
		for _, name := range spec.pkgs {
			archive := buildDebFixture(t, base, name, spec.ver, arch)
			raw, err := os.ReadFile(archive)
			if err != nil {
				t.Fatal(err)
			}
			outDeb := filepath.Join(repo, "pool", filepath.Base(archive))
			if err := os.WriteFile(outDeb, raw, 0o644); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(raw)
			ctrl := mustExec(t, nil, "dpkg-deb", "-f", outDeb)
			fmt.Fprintf(&records, "%s\nFilename: pool/%s\nSize: %d\nSHA256: %s\n\n",
				ctrl, filepath.Base(outDeb), len(raw), hex.EncodeToString(sum[:]))
		}
		distDir := filepath.Join(repo, "dists", suite)
		idxDir := filepath.Join(distDir, "main", "binary-"+arch)
		_ = os.MkdirAll(idxDir, 0o755)
		pkgBytes := []byte(records.String())
		pkgPath := filepath.Join(idxDir, "Packages")
		if err := os.WriteFile(pkgPath, pkgBytes, 0o644); err != nil {
			t.Fatal(err)
		}
		var gzBuf bytes.Buffer
		gz := gzip.NewWriter(&gzBuf)
		_, _ = gz.Write(pkgBytes)
		_ = gz.Close()
		gzPath := filepath.Join(idxDir, "Packages.gz")
		if err := os.WriteFile(gzPath, gzBuf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		label := origin
		if distro == "debian" && spec.suffix == "security" {
			label = "Debian-Security"
		}
		relCodename := codename
		if distro == "debian" {
			relCodename = suite
		}
		var rel strings.Builder
		fmt.Fprintf(&rel, "Origin: %s\nLabel: %s\nSuite: %s\nCodename: %s\nDate: %s\nArchitectures: %s\nComponents: main\nSHA256:\n",
			origin, label, suite, relCodename, time.Now().UTC().Format(time.RFC1123), arch)
		for _, item := range []struct {
			relPath string
			data    []byte
		}{
			{filepath.Join("main", "binary-"+arch, "Packages"), pkgBytes},
			{filepath.Join("main", "binary-"+arch, "Packages.gz"), gzBuf.Bytes()},
		} {
			s := sha256.Sum256(item.data)
			fmt.Fprintf(&rel, " %s %d %s\n", hex.EncodeToString(s[:]), len(item.data), item.relPath)
		}
		relPath := filepath.Join(distDir, "Release")
		inRelPath := filepath.Join(distDir, "InRelease")
		if err := os.WriteFile(relPath, []byte(rel.String()), 0o644); err != nil {
			t.Fatal(err)
		}
		mustExec(t, nil, append(gpgBase, "--yes", "--clearsign", "--output", inRelPath, relPath)...)
	}

	sourcesTxt := fmt.Sprintf("deb [signed-by=%s] file://%s %s-security main\ndeb [signed-by=%s] file://%s %s-updates main\n",
		keyPath, repo, codename, keyPath, repo, codename)
	if err := os.WriteFile(sourceFile, []byte(sourcesTxt), 0o644); err != nil {
		t.Fatal(err)
	}
	extraTxt := fmt.Sprintf("Unattended-Upgrade::Allowed-Origins { \"%s:%s-updates\"; };\nUnattended-Upgrade::Automatic-Reboot \"true\";\nUnattended-Upgrade::InstallOnShutdown \"true\";\n",
		origin, codename)
	if err := os.WriteFile(extraFile, []byte(extraTxt), 0o644); err != nil {
		t.Fatal(err)
	}

	policy := map[string]any{"mode": "notify", "interval": 4, "start": 3, "end": 5}
	if _, err := runOSSecurity("configure", state, policy, "", io.Discard); err != nil {
		t.Fatalf("configure notify: %v", err)
	}
	live, err := InspectOSSettings()
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if live["automatic_install"] != false || live["automatic_reboot"] != false || live["upgrade_interval"] != "0" {
		t.Fatalf("unexpected live settings: %#v", live)
	}
	check, err := runOSSecurity("check", state, nil, "", io.Discard)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if check["package_count"] != 3 || check["eligible_count"] != 1 {
		t.Fatalf("unexpected check counts: %#v", check)
	}
	np, _ := check["native_policy"].(map[string]any)
	if np["reboot"] != false || np["shutdown"] != false {
		t.Fatalf("unexpected native_policy: %#v", np)
	}
	if _, err := runOSSecurity("cycle", state, nil, "", io.Discard); err != nil {
		t.Fatalf("cycle notify: %v", err)
	}
	if ver := mustExec(t, nil, "dpkg-query", "-W", "-f=${Version}", names[0]); ver != "1.0" {
		t.Fatalf("notify mode installed package: %s", ver)
	}

	// Override NEEDRESTART_MODE to 'l' for the CI runner after asserting production sets 'a'.
	origAptEnv := buildAptEnvironment
	buildAptEnvironment = func(dir, d, c string) (map[string]string, error) {
		env, err := origAptEnv(dir, d, c)
		if err != nil {
			return nil, err
		}
		if env["NEEDRESTART_MODE"] != "a" {
			t.Fatalf("expected NEEDRESTART_MODE=a, got %q", env["NEEDRESTART_MODE"])
		}
		env["NEEDRESTART_MODE"] = "l"
		return env, nil
	}
	defer func() { buildAptEnvironment = origAptEnv }()

	hour := time.Now().In(time.Local).Hour()
	daily := map[string]any{"mode": "daily", "interval": 4, "start": hour, "end": (hour + 1) % 24}
	if _, err := runOSSecurity("configure", state, daily, "", io.Discard); err != nil {
		t.Fatalf("configure daily: %v", err)
	}
	res, err := runOSSecurity("cycle", state, nil, "", io.Discard)
	if err != nil {
		t.Fatalf("cycle daily: %v", err)
	}
	if res["installed_count"] != 1 || res["package_count"] != 2 {
		t.Fatalf("unexpected daily cycle result: %#v", res)
	}
	if ver := mustExec(t, nil, "dpkg-query", "-W", "-f=${Version}", names[0]); ver != "2.0" {
		t.Fatalf("expected security fixture upgraded to 2.0, got %s", ver)
	}
	for _, name := range names[1:] {
		if ver := mustExec(t, nil, "dpkg-query", "-W", "-f=${Version}", name); ver != "1.0" {
			t.Fatalf("package %s unexpectedly changed to %s", name, ver)
		}
	}

	// Auto-reboot smoke (reboot ALWAYS intercepted)
	exerciseAutoRebootSmoke(t, state, base, useSystemd)

	// Return to system management and verify baseline restored
	sysPol := map[string]any{"mode": "system", "interval": 4, "start": 3, "end": 5}
	if _, err := runOSSecurity("configure", state, sysPol, "", io.Discard); err != nil {
		t.Fatalf("configure system: %v", err)
	}
	afterTimer, err := readNativeTimer()
	if err != nil {
		t.Fatal(err)
	}
	if afterTimer["enabled"] != baseline["enabled"] || afterTimer["active"] != baseline["active"] {
		t.Fatalf("native timer not restored: got %#v, want %#v", afterTimer, baseline)
	}
	if lexists(osRestartDropin) || lexists(osAptGuard) {
		t.Fatal("managed drop-in or APT guard was not removed")
	}
}

func exerciseAutoRebootSmoke(t *testing.T, root, base string, useSystemd bool) {
	t.Helper()
	lock := filepath.Join(base, "reboot.lock")
	marker := filepath.Join(base, "reboot.json")
	required := filepath.Join(base, "reboot-required")
	now := time.Now().In(time.Local)
	hhmm := now.Format("15:04")
	_, key, err := dailyWindow(now, hhmm)
	if err != nil {
		t.Fatal(err)
	}
	unit := "easy-ha-proxy-web-reboot-" + randHex(12)
	rev := randHex(32)
	bootID, err := readBootID()
	if err != nil {
		t.Fatal(err)
	}
	policy := map[string]any{
		"enabled": true, "time": hhmm, "id": rev, "updated_at": float64(now.Unix() - 60),
		"attempt": map[string]any{"window": key, "state": "scheduled", "at": float64(now.Unix())},
	}
	owned := map[string]any{
		"unit": unit, "boot_id": bootID,
		"automatic": map[string]any{"policy_revision": rev, "window": key},
	}
	reset := func() {
		if err := AtomicWrite(filepath.Join(root, "reboot-policy.json"), policy, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := AtomicWrite(marker, owned, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(required, []byte("reboot\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	harmless := func() (string, int) {
		reboots := 0
		prevRun := runCommand
		runCommand = func(argv []string, opts cmdOpts) (int, string, error) {
			if len(argv) == 2 && argv[0] == "/usr/bin/systemctl" && argv[1] == "reboot" {
				reboots++
				return 0, "No reboot was executed by this disposable fixture.", nil
			}
			return prevRun(argv, opts)
		}
		defer func() { runCommand = prevRun }()
		r, err := FireAutoReboot(root, lock, marker, required, unit, nil, io.Discard)
		if err != nil {
			t.Fatalf("FireAutoReboot: %v", err)
		}
		return r, reboots
	}

	// 1. Triggered
	reset()
	if r, n := harmless(); r != "triggered" || n != 1 {
		t.Fatalf("expected triggered/1, got %q/%d", r, n)
	}
	_ = os.Remove(marker)

	// 2. Real APT POSIX lock defers reboot
	reset()
	selfBin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	holder := exec.Command(selfBin, "-test.run=^TestDisposableDpkgLockHolder$")
	holder.Env = append(os.Environ(), "EHP_SECURITY_DISPOSABLE=1", "EHP_SMOKE_LOCK_HOLDER=1")
	stdin, err := holder.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := holder.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	n, _ := stdout.Read(buf)
	if !strings.Contains(string(buf[:n]), "LOCK_READY") {
		_ = holder.Process.Kill()
		t.Fatalf("lock holder did not become ready: %q", string(buf[:n]))
	}
	r, reboots := harmless()
	_ = stdin.Close()
	_ = holder.Wait()
	if r != "deferred" || reboots != 0 || lexists(marker) {
		t.Fatalf("expected deferred/0/no-marker with busy dpkg lock, got %q/%d/%v", r, reboots, lexists(marker))
	}

	// 3. Real systemd-run custody test on Ubuntu runners
	if useSystemd {
		reset()
		outFile := filepath.Join(base, "reboot-worker.json")
		held, err := os.OpenFile(lock, os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if err := unix.Flock(int(held.Fd()), unix.LOCK_EX); err != nil {
			_ = held.Close()
			t.Fatal(err)
		}
		defer func() {
			_ = exec.Command("systemctl", "stop", unit+".timer", unit+".service").Run()
			_ = os.Remove(marker)
		}()
		mustExec(t, nil, "systemd-run", "--quiet", "--unit="+unit, "--on-active=1s",
			"--timer-property=AccuracySec=1s", "--timer-property=RemainAfterElapse=no",
			"--property=TimeoutStartSec=30s",
			"--setenv=EHP_SECURITY_DISPOSABLE=1",
			"--setenv=EHP_SMOKE_REBOOT_WORKER=1",
			"--setenv=EHP_SMOKE_ROOT="+root,
			"--setenv=EHP_SMOKE_LOCK="+lock,
			"--setenv=EHP_SMOKE_MARKER="+marker,
			"--setenv=EHP_SMOKE_REQUIRED="+required,
			"--setenv=EHP_SMOKE_UNIT="+unit,
			"--setenv=EHP_SMOKE_OUTPUT="+outFile,
			"--", selfBin, "-test.run=^TestDisposableAutoRebootWorker$")
		time.Sleep(2 * time.Second)
		if lexists(outFile) {
			_ = held.Close()
			t.Fatal("The worker escaped maintenance custody while flock was held")
		}
		_ = held.Close()
		var raw []byte
		for i := 0; i < 100; i++ {
			if b, err := os.ReadFile(outFile); err == nil && len(bytes.TrimSpace(b)) > 0 {
				raw = b
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		var got map[string]any
		if err := json.Unmarshal(bytes.TrimSpace(raw), &got); err != nil || got["result"] != "triggered" || got["intercepted_reboots"] != float64(1) {
			t.Fatalf("unexpected systemd-run worker result: %q (%v)", string(raw), err)
		}
	} else {
		_ = os.Remove(marker)
	}
	policy["enabled"] = false
	_ = AtomicWrite(filepath.Join(root, "reboot-policy.json"), policy, 0o600)
}
