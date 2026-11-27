// Package hostsec implements the root-owned host security and maintenance
// helpers of easy-ha-proxy (os-security, service-restarts, auto-reboot,
// os-upgrade-guard and ssh-protection) in pure Go.
package hostsec

import (
	"bytes"
	"encoding/json"
	"errors"
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
)

const (
	DefaultStateRoot = "/var/lib/easy-ha-proxy/update-web/os-security"
	DefaultLockPath  = "/run/easy-ha-proxy/easy-ha-proxy-backupd.operation.lock"
	DefaultBootPath  = "/proc/sys/kernel/random/boot_id"
	NativeTimerUnit  = "apt-daily-upgrade.timer"
	maxJSONBytes     = 1024 * 1024
	maxTailBytes     = 128 * 1024
	maxRawBytes      = 32 * 1024 * 1024
)

// Paths and hooks as vars so tests can redirect them into temp directories.
var (
	osReleasePath        = "/etc/os-release"
	systemdRunDir        = "/run/systemd/system"
	bootIDPath           = DefaultBootPath
	runGuardDir          = "/run/easy-ha-proxy"
	haproxyMigrationDir  = "/var/lib/easy-ha-proxy/haproxy-package-migration"
	haproxyPendingUIFile = "/opt/haproxy-admin/backups/haproxy/pending_ui_transaction.json"
	haproxyGuardTxFile   = "/var/lib/easy-ha-proxy/haproxy-config-guard/transaction.json"
	rebootRequiredPath   = "/run/reboot-required"
	varRunRebootRequired = "/var/run/reboot-required"
	aptLockPaths         = []string{"/var/lib/dpkg/lock-frontend", "/var/lib/dpkg/lock", "/var/lib/apt/lists/lock", "/var/cache/apt/archives/lock"}
	requireRootOwner     = true
	commandKillGrace     = 120 * time.Second
	nowFunc              = time.Now
	localTimeFunc        = defaultLocalTime
	timerNameRe          = regexp.MustCompile(`^[A-Za-z0-9_.:@-]{1,180}\.timer$`)
	durationPartRe       = regexp.MustCompile(`(\d+(?:\.\d+)?)\s*(us|ms|min|s|h|d)`)
	onCalendarRe         = regexp.MustCompile(`OnCalendar=([^;}]*)`)
	busctlUint64Re       = regexp.MustCompile(`^t\s+([0-9]+)$`)
	repoURLRe            = regexp.MustCompile(`https?://\S+`)
	codenameRe           = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}$`)
	hex32Re              = regexp.MustCompile(`^[0-9a-f]{32}$`)
	hex64Re              = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hhmmRe               = regexp.MustCompile(`^(?:[01][0-9]|2[0-3]):[0-5][0-9]$`)
)

// SecurityError represents a controlled refusal or host-security error.
type SecurityError struct{ Msg string }

func (e *SecurityError) Error() string { return e.Msg }

func secErr(format string, args ...any) error {
	return &SecurityError{Msg: fmt.Sprintf(format, args...)}
}

// UpgradeRefused represents an OS upgrade guard refusal.
type UpgradeRefused struct{ Msg string }

func (e *UpgradeRefused) Error() string { return e.Msg }

func refusef(format string, args ...any) error {
	return &UpgradeRefused{Msg: fmt.Sprintf(format, args...)}
}

func defaultLocalTime() time.Time {
	return nowFunc().In(time.Local)
}

func lexists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

func isRegularFile(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

func isSymlink(p string) bool {
	fi, err := os.Lstat(p)
	return err == nil && fi.Mode()&os.ModeSymlink != 0
}

func isDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

func readBootID() (string, error) {
	raw, err := os.ReadFile(bootIDPath)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

// ReadJSON reads a root-owned, non-symlink JSON object up to 1 MiB.
func ReadJSON(p string) (map[string]any, error) {
	info, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || (requireRootOwner && st.Uid != 0) || st.Nlink != 1 || info.Size() <= 0 || info.Size() > maxJSONBytes {
		return nil, secErr("Unsafe OS security state")
	}
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	ost, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || ost.Dev != st.Dev || ost.Ino != st.Ino {
		return nil, secErr("OS security state changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxJSONBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxJSONBytes {
		return nil, secErr("Unsafe OS security state")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var val any
	if err := dec.Decode(&val); err != nil {
		return nil, secErr("Invalid OS security state")
	}
	m, ok := val.(map[string]any)
	if !ok {
		return nil, secErr("Invalid OS security state")
	}
	return m, nil
}

// AtomicWrite writes a JSON object or raw string atomically with fsync.
func AtomicWrite(p string, value any, mode os.FileMode) error {
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(p)+".*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if os.Geteuid() == 0 {
		if err := tmp.Chown(0, 0); err != nil {
			_ = tmp.Close()
			return err
		}
	}
	var payload []byte
	switch v := value.(type) {
	case string:
		payload = []byte(v)
	case []byte:
		payload = v
	default:
		b, err := json.Marshal(v)
		if err != nil {
			_ = tmp.Close()
			return err
		}
		payload = append(b, '\n')
	}
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, p); err != nil {
		return err
	}
	cleanup = false
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// tailBuffer keeps the last N bytes written to it, bounding memory.
type tailBuffer struct {
	limit int
	buf   []byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if t.limit <= 0 {
		return n, nil
	}
	if len(p) >= t.limit {
		t.buf = append(t.buf[:0], p[len(p)-t.limit:]...)
		return n, nil
	}
	if len(t.buf)+len(p) > t.limit {
		excess := len(t.buf) + len(p) - t.limit
		t.buf = append(t.buf[excess:], p...)
	} else {
		t.buf = append(t.buf, p...)
	}
	return n, nil
}

func (t *tailBuffer) String() string { return string(t.buf) }

// fullBuffer captures complete output up to a cap, for data the caller parses
// (rawOutput). Unlike tailBuffer it keeps the beginning: a truncated tail
// silently drops the first packages of a large apt-cache policy batch.
type fullBuffer struct {
	buf      bytes.Buffer
	limit    int
	overflow bool
}

func (f *fullBuffer) Write(p []byte) (int, error) {
	if f.buf.Len()+len(p) > f.limit {
		f.overflow = true
		if remain := f.limit - f.buf.Len(); remain > 0 {
			f.buf.Write(p[:remain])
		}
		return len(p), nil
	}
	return f.buf.Write(p)
}

type cmdOpts struct {
	timeout   time.Duration
	env       map[string]string
	check     bool
	stdout    io.Writer
	rawOutput bool
}

// runCommand runs argv without a shell, bounded to 128 KiB output tail,
// killing the process group on timeout and redacting URLs.
var runCommand = func(argv []string, opts cmdOpts) (int, string, error) {
	if len(argv) == 0 {
		return 1, "", secErr("Empty command")
	}
	timeout := opts.timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin = nil
	env := append(os.Environ(), "LC_ALL=C", "DEBIAN_FRONTEND=noninteractive")
	for k, v := range opts.env {
		env = append(env, k+"="+v)
	}
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 5 * time.Second
	out := &tailBuffer{limit: maxTailBytes}
	var raw fullBuffer
	if opts.rawOutput {
		// Data the caller parses needs the complete stdout, not a truncated
		// tail shared with stderr; stderr stays a bounded diagnostic tail.
		raw.limit = maxRawBytes
		cmd.Stdout = &raw
		cmd.Stderr = out
	} else {
		cmd.Stdout = out
		cmd.Stderr = out
	}
	if err := cmd.Start(); err != nil {
		return 1, "", err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var waitErr error
	select {
	case waitErr = <-done:
	case <-time.After(timeout):
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(commandKillGrace):
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			<-done
		}
		return 1, "", secErr("OS security command timed out; inspect package-manager state")
	}
	rc := 0
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			rc = exitErr.ExitCode()
		} else {
			return 1, "", waitErr
		}
	}
	if opts.rawOutput {
		if raw.overflow {
			return 1, "", secErr("OS security command output exceeded the %d-byte capture limit", maxRawBytes)
		}
		full := raw.buf.String()
		if opts.check && rc != 0 {
			return rc, full, secErr("OS security command failed: %s", filepath.Base(argv[0]))
		}
		return rc, full, nil
	}
	tail := out.String()
	redacted := repoURLRe.ReplaceAllString(tail, "[repository]")
	if opts.check && rc != 0 {
		if opts.stdout != nil {
			_, _ = fmt.Fprintln(opts.stdout, redacted)
		} else {
			fmt.Println(redacted)
		}
		return rc, redacted, secErr("OS security command failed: %s", filepath.Base(argv[0]))
	}
	return rc, redacted, nil
}

// Platform checks Ubuntu/Debian + codename + systemd.
var checkPlatform = func() (string, string, error) {
	raw, err := os.ReadFile(osReleasePath)
	if err != nil {
		return "", "", err
	}
	release := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			release[k] = strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	distro := release["ID"]
	codename := release["VERSION_CODENAME"]
	if (distro != "ubuntu" && distro != "debian") || !codenameRe.MatchString(codename) {
		return "", "", secErr("OS security updates require Ubuntu or Debian with a supported APT setup")
	}
	if !isDir(systemdRunDir) {
		return "", "", secErr("OS security management requires systemd")
	}
	return distro, codename, nil
}

// acquireFlock acquires a non-blocking or blocking BSD flock on lockPath.
func acquireFlock(lockPath string, blocking bool) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o750); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || (requireRootOwner && st.Uid != 0) {
		_ = f.Close()
		return nil, secErr("Unsafe maintenance lock")
	}
	how := unix.LOCK_EX
	if !blocking {
		how |= unix.LOCK_NB
	}
	if err := unix.Flock(int(f.Fd()), how); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// withPackageLocks holds real POSIX fcntl record locks on the 4 APT lock files
// for the duration of fn (matching Python's fcntl.lockf).
var withPackageLocks = func(fn func() error) error {
	var opened []*os.File
	defer func() {
		for i := len(opened) - 1; i >= 0; i-- {
			_ = opened[i].Close()
		}
	}()
	for _, p := range aptLockPaths {
		if !lexists(p) {
			continue
		}
		f, err := os.OpenFile(p, os.O_RDWR|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		opened = append(opened, f)
		info, err := f.Stat()
		if err != nil {
			return err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || (requireRootOwner && st.Uid != 0) {
			return secErr("Unsafe package-manager lock: %s (expected a root-owned regular file)", p)
		}
		fl := unix.Flock_t{Type: unix.F_WRLCK, Whence: io.SeekStart, Start: 0, Len: 0}
		if err := unix.FcntlFlock(f.Fd(), unix.F_SETLK, &fl); err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EACCES) {
				return secErr("APT is busy; the automatic reboot was deferred")
			}
			return err
		}
	}
	return fn()
}

// maintenanceGuard verifies no conflicting maintenance, HAProxy, or APT operation is active.
var maintenanceGuard = func(allowWebReboot bool) error {
	for _, name := range []string{"easy-ha-proxy-web-reboot.json", "reboot-scheduled", "easy-ha-proxy-backupd-restore.active"} {
		if name == "easy-ha-proxy-web-reboot.json" && allowWebReboot {
			continue
		}
		if lexists(filepath.Join(runGuardDir, name)) {
			return secErr("Another maintenance or reboot operation is pending")
		}
	}
	settled := map[string]bool{"committed": true, "rolled_back": true, "aborted": true, "preparing": true, "prepared": true}
	for _, name := range []string{"last-update.json", "last-migration.json"} {
		p := filepath.Join(haproxyMigrationDir, name)
		if lexists(p) {
			op, err := ReadJSON(p)
			if err != nil {
				return err
			}
			if !settled[strVal(op["phase"])] {
				return secErr("Recover the unfinished HAProxy operation before OS maintenance")
			}
		}
	}
	if lexists(haproxyPendingUIFile) {
		return secErr("Resolve pending HAProxy configuration changes before OS maintenance")
	}
	if lexists(haproxyGuardTxFile) {
		tx, err := ReadJSON(haproxyGuardTxFile)
		if err != nil {
			return err
		}
		if st := strVal(tx["state"]); st != "confirmed" && st != "rolled_back" {
			return secErr("Resolve pending HAProxy configuration changes before OS maintenance")
		}
	}
	code, text, err := runCommand([]string{"/usr/bin/dpkg", "--audit"}, cmdOpts{timeout: 60 * time.Second, check: true})
	if err != nil {
		return err
	}
	if code != 0 || strings.TrimSpace(text) != "" {
		return secErr("The package manager needs recovery before OS security updates")
	}
	for _, p := range aptLockPaths {
		if !lexists(p) {
			continue
		}
		f, err := os.OpenFile(p, os.O_RDWR|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		fl := unix.Flock_t{Type: unix.F_WRLCK, Whence: io.SeekStart, Start: 0, Len: 0}
		lerr := unix.FcntlFlock(f.Fd(), unix.F_SETLK, &fl)
		if lerr == nil {
			ul := unix.Flock_t{Type: unix.F_UNLCK, Whence: io.SeekStart, Start: 0, Len: 0}
			_ = unix.FcntlFlock(f.Fd(), unix.F_SETLK, &ul)
		}
		_ = f.Close()
		if lerr != nil {
			if errors.Is(lerr, syscall.EAGAIN) || errors.Is(lerr, syscall.EACCES) {
				return secErr("APT is busy; retry OS security maintenance later")
			}
			return lerr
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// JSON number / string helpers
// ---------------------------------------------------------------------------

func strVal(v any) string {
	s, _ := v.(string)
	return s
}

func boolVal(v any) (bool, bool) {
	b, ok := v.(bool)
	return b, ok
}

func strictIntVal(v any) (int, bool) {
	switch x := v.(type) {
	case int:
		return x, true
	case int64:
		return int(x), true
	case json.Number:
		s := x.String()
		if strings.ContainsAny(s, ".eE") {
			return 0, false
		}
		n, err := strconv.Atoi(s)
		return n, err == nil
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) || math.Trunc(x) != x {
			return 0, false
		}
		return int(x), true
	default:
		return 0, false
	}
}

func numVal(v any) (float64, bool) {
	switch x := v.(type) {
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case float64:
		return x, !math.IsNaN(x)
	case json.Number:
		f, err := x.Float64()
		return f, err == nil && !math.IsNaN(f)
	default:
		return 0, false
	}
}

func unixSeconds(t time.Time) float64 {
	return float64(t.UnixNano()) / 1e9
}

// ---------------------------------------------------------------------------
// Unified maintenance window (port of installer/maintenance_window.py)
// ---------------------------------------------------------------------------

type mwPolicyData struct {
	Enabled   bool
	Start     int
	End       int
	Runtime   bool
	ID        string
	UpdatedAt float64
}

type mwWindowData struct {
	Key      string
	OpensAt  float64
	ClosesAt float64
}

func parseMWPolicy(settings map[string]any) (*mwPolicyData, error) {
	if settings["auto_install_unified"] != true {
		return nil, nil
	}
	start, okS := strictIntVal(settings["auto_install_start"])
	end, okE := strictIntVal(settings["auto_install_end"])
	updated, okU := numVal(settings["maintenance_updated_at"])
	rev := strVal(settings["maintenance_revision"])
	if !okS || !okE || start < 0 || start >= 24 || end < 0 || end >= 24 || start == end ||
		!hex32Re.MatchString(rev) || !okU || !(updated > 0) || math.IsInf(updated, 0) {
		return nil, errors.New("The unified maintenance policy is invalid")
	}
	return &mwPolicyData{
		Enabled:   settings["auto_install"] == true,
		Start:     start,
		End:       end,
		Runtime:   settings["auto_install_runtime"] == true,
		ID:        rev,
		UpdatedAt: updated,
	}, nil
}

func readMWPolicy(root string) (*mwPolicyData, error) {
	p := filepath.Join(filepath.Dir(root), "settings.json")
	if !lexists(p) {
		return nil, nil
	}
	settings, err := ReadJSON(p)
	if err != nil {
		return nil, err
	}
	return parseMWPolicy(settings)
}

func computeMWWindow(local time.Time, start, end int) mwWindowData {
	day := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, local.Location())
	if local.Hour() < start {
		day = day.AddDate(0, 0, -1)
	}
	opened := time.Date(day.Year(), day.Month(), day.Day(), start, 0, 0, 0, local.Location())
	closeDay := day
	if end <= start {
		closeDay = day.AddDate(0, 0, 1)
	}
	closed := time.Date(closeDay.Year(), closeDay.Month(), closeDay.Day(), end, 0, 0, 0, local.Location())
	return mwWindowData{
		Key:      day.Format("2006-01-02"),
		OpensAt:  unixSeconds(opened),
		ClosesAt: unixSeconds(closed),
	}
}

func currentMWWindow(value *mwPolicyData, local time.Time) *mwWindowData {
	if value == nil {
		return nil
	}
	w := computeMWWindow(local, value.Start, value.End)
	ts := unixSeconds(local)
	if value.Enabled && w.OpensAt <= ts && ts < w.ClosesAt && value.UpdatedAt <= w.OpensAt {
		return &w
	}
	return nil
}

func requireMWWindow(root, revision string, local time.Time) error {
	value, err := readMWPolicy(root)
	if err != nil {
		return err
	}
	if value == nil || value.ID != revision || currentMWWindow(value, local) == nil {
		return errors.New("The unified maintenance window has closed or its consent changed")
	}
	return nil
}

// RequireUnifiedWindow verifies that the unified maintenance window for revision
// is still open and before the deadline (used by haproxy-migrate patch).
func RequireUnifiedWindow(root, revision string, until float64, hasUntil bool) error {
	value, err := readMWPolicy(root)
	if err != nil {
		return err
	}
	if value == nil || value.ID != revision || currentMWWindow(value, localTimeFunc()) == nil ||
		!hasUntil || unixSeconds(nowFunc()) >= until {
		return errors.New("The unified maintenance window closed before HAProxy application")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Timer metadata (port of installer/timer_metadata.py)
// ---------------------------------------------------------------------------

func parseDurationSeconds(text string) any {
	if text == "0" {
		return 0
	}
	if text == "" || strings.TrimSpace(durationPartRe.ReplaceAllString(text, "")) != "" {
		return nil
	}
	units := map[string]float64{"us": 1e-6, "ms": 1e-3, "s": 1, "min": 60, "h": 3600, "d": 86400}
	total := 0.0
	for _, m := range durationPartRe.FindAllStringSubmatch(text, -1) {
		v, err := strconv.ParseFloat(m[1], 64)
		if err != nil {
			return nil
		}
		total += v * units[m[2]]
	}
	return total
}

func dbusEscapeUnit(name string) string {
	var b strings.Builder
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "_%02x", c)
		}
	}
	return b.String()
}

var runShort = func(argv []string) string {
	code, out, err := runCommand(argv, cmdOpts{timeout: 2 * time.Second})
	if err != nil || code != 0 {
		return ""
	}
	return strings.TrimSpace(out)
}

func readTimerMetadata(name string) (map[string]any, error) {
	if !timerNameRe.MatchString(name) {
		return nil, errors.New("Invalid timer name")
	}
	text := runShort([]string{"/usr/bin/systemctl", "show", name,
		"--property=ActiveState,TimersCalendar,NextElapseUSecRealtime,RandomizedDelayUSec,Description"})
	props := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			props[k] = v
		}
	}
	active := props["ActiveState"] == "active"
	nextRun := ""
	if active {
		nextRun = props["NextElapseUSecRealtime"]
	}
	cal := []string{}
	for _, m := range onCalendarRe.FindAllStringSubmatch(props["TimersCalendar"], -1) {
		cal = append(cal, m[1])
	}
	res := map[string]any{
		"unit":                 name,
		"active":               active,
		"description":          props["Description"],
		"next_run":             nextRun,
		"next_run_at":          nil,
		"random_delay_seconds": parseDurationSeconds(props["RandomizedDelayUSec"]),
		"calendar":             cal,
	}
	if active {
		val := runShort([]string{"/usr/bin/busctl", "get-property", "org.freedesktop.systemd1",
			"/org/freedesktop/systemd1/unit/" + dbusEscapeUnit(name),
			"org.freedesktop.systemd1.Timer", "NextElapseUSecRealtime"})
		if m := busctlUint64Re.FindStringSubmatch(val); m != nil {
			if n, err := strconv.ParseUint(m[1], 10, 64); err == nil && n > 0 && n < 1e18 {
				res["next_run_at"] = float64(n) / 1e6
			}
		}
	}
	return res, nil
}
