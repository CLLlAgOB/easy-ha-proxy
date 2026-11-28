// Package haproxymigrate implements explicit, root-only HAProxy provider
// migration, in-branch patching, rollback, and crash recovery.
package haproxymigrate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	DefaultKeyURL = "https://pks.haproxy.com/linux/community/RPM-GPG-KEY-HAProxy"
)

// MigrationError represents a controlled refusal or failure during migration.
type MigrationError struct {
	Msg string
}

func (e *MigrationError) Error() string { return e.Msg }

func migErr(format string, args ...any) error {
	return &MigrationError{Msg: fmt.Sprintf(format, args...)}
}

// RollbackExercise triggers a deliberate post-switch rollback verification.
type RollbackExercise struct {
	Msg string
}

func (e *RollbackExercise) Error() string { return e.Msg }

// Paths collects all filesystem locations managed or inspected by the engine.
type Paths struct {
	Root         string
	Config       string
	Variables    string
	ServerState  string
	Socket       string
	Lock         string
	ControlState string
	Policy       string
	Repository   string
	Priorities   string
	SigningKey   string
	Binary       string
	Source       string
}

// DefaultPaths returns the standard production gateway paths.
func DefaultPaths() Paths {
	return Paths{
		Root:         "/var/lib/easy-ha-proxy/haproxy-package-migration",
		Config:       "/etc/haproxy/haproxy.cfg",
		Variables:    "/etc/easy-ha-proxy/vars.yml",
		ServerState:  "/var/lib/haproxy/server-state",
		Socket:       "/run/haproxy/admin.sock",
		Lock:         "/run/easy-ha-proxy/easy-ha-proxy-backupd.operation.lock",
		ControlState: "/var/lib/easy-ha-proxy/haproxy-config-guard/transaction.json",
		Policy:       "/usr/sbin/policy-rc.d",
		Repository:   "/etc/apt/sources.list.d/easy-ha-proxy-haproxy.list",
		Priorities:   "/etc/apt/preferences.d/easy-ha-proxy-haproxy",
		SigningKey:   "/usr/share/keyrings/easy-ha-proxy-haproxy-community.asc",
		Binary:       "/usr/sbin/haproxy",
		Source:       "/opt/easy-ha-proxy/source",
	}
}

// Package-level vars injectable by unit tests.
var (
	serviceDropinDirs = []string{
		"/etc/systemd/system/haproxy.service.d",
		"/run/systemd/system/haproxy.service.d",
		"/usr/lib/systemd/system/haproxy.service.d",
		"/lib/systemd/system/haproxy.service.d",
	}
	osReleasePath    = "/etc/os-release"
	memInfoPath      = "/proc/meminfo"
	machineIDPath    = "/etc/machine-id"
	haproxyEtcUnit   = "/etc/systemd/system/haproxy.service"
	haproxyUsrUnit   = "/usr/lib/systemd/system/haproxy.service"
	haproxyLibUnit   = "/lib/systemd/system/haproxy.service"
	haproxyConfD     = "/etc/haproxy/conf.d"
	requireRootOwner = true
	nowFunc          = time.Now
	sleepFunc        = time.Sleep
	engineBinaryFunc = os.Executable
)

var (
	hex32Re        = regexp.MustCompile(`^[0-9a-f]{32}$`)
	hex64Re        = regexp.MustCompile(`^[0-9a-f]{64}$`)
	dropinContRe   = regexp.MustCompile(`\\\r?\n\s*`)
	dropinExecRe   = regexp.MustCompile(`^(Exec\w*|Type|RootDirectory|User|Group)\s*=(.*)$`)
	systemctlBadRe = regexp.MustCompile(`\bsystemctl\s+(?:--\S+\s+)*(?:stop|restart|try-restart)\b`)
	haproxyVerRe   = regexp.MustCompile(`HAProxy version (\S+)`)
	memAvailRe     = regexp.MustCompile(`(?m)^MemAvailable:\s+([0-9]+) kB$`)
	poolDebRe      = regexp.MustCompile(`^pool/[A-Za-z0-9_./+~-]+\.deb$`)
	hostnameRe     = regexp.MustCompile(`^[A-Za-z0-9.-]+$`)
)

var (
	pausedUnits = []string{
		"easy-ha-proxy-guardd.service",
		"haproxy-certd.service",
		"haproxy-controld.service",
		"haproxy-state-dump.timer",
		"certbot.timer",
		"snap.certbot.renew.timer",
		"apt-daily.timer",
		"apt-daily-upgrade.timer",
	}
	optionalDependencies = map[string]bool{
		"libjemalloc2":                 true,
		"liblua5.4-0":                  true,
		"libopentracing1":              true,
		"libopentracing-c-wrapper0":    true,
		"libopentracing-c-wrapper0t64": true,
	}
	allowedPackages = map[string]bool{
		"haproxy":                      true,
		"haproxy-awslc":                true,
		"libssl-awslc":                 true,
		"libjemalloc2":                 true,
		"liblua5.4-0":                  true,
		"libopentracing1":              true,
		"libopentracing-c-wrapper0":    true,
		"libopentracing-c-wrapper0t64": true,
	}
)

// CmdResult captures subprocess execution results.
type CmdResult struct {
	Code   int
	Stdout string
	Stderr string
}

// CmdOpts controls subprocess invocation.
type CmdOpts struct {
	Cwd      string
	Check    bool
	Timeout  time.Duration
	EnvExtra map[string]string
}

// Host abstracts privileged system commands so tests and container smoke runs can substitute it.
type Host interface {
	SetLog(path string)
	Command(args []string, opts CmdOpts) (CmdResult, error)
	Active(unit string) bool
	Service(action, unit string) error
	MainPID() (int, error)
	Packages() (map[string]string, error)
	Machine() (string, error)
	WorkerDigest(pid string) (string, error)
	StartSeed(directory, unit string) error
	Watchdog(directory, unit, recoveryBinary string) error
	CancelWatchdog(unit string)
	ControlJournal(defaultPath string) (string, error)
	GuardDatabase() (string, error)
}

// SystemHost is the production Linux/systemd Host implementation.
type SystemHost struct {
	LogPath string
}

func (h *SystemHost) SetLog(path string) { h.LogPath = path }

func (h *SystemHost) Command(args []string, opts CmdOpts) (CmdResult, error) {
	if len(args) == 0 {
		return CmdResult{Code: 1}, migErr("empty command")
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	cmd := exec.Command(args[0], args[1:]...)
	if opts.Cwd != "" {
		cmd.Dir = opts.Cwd
	}
	env := make([]string, 0, len(os.Environ())+2+len(opts.EnvExtra))
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "DEBIAN_FRONTEND=") || strings.HasPrefix(kv, "LC_ALL=") {
			continue
		}
		if opts.EnvExtra != nil {
			k, _, _ := strings.Cut(kv, "=")
			if _, ok := opts.EnvExtra[k]; ok {
				continue
			}
		}
		env = append(env, kv)
	}
	env = append(env, "DEBIAN_FRONTEND=noninteractive", "LC_ALL=C")
	for k, v := range opts.EnvExtra {
		env = append(env, k+"="+v)
	}
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return CmdResult{Code: 1}, err
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
		case <-time.After(10 * time.Second):
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			<-done
		}
		return CmdResult{Code: 1}, migErr("Command timed out: %s", args[0])
	}
	rc := 0
	if waitErr != nil {
		var ee *exec.ExitError
		if errors.As(waitErr, &ee) {
			rc = ee.ExitCode()
		} else {
			return CmdResult{Code: 1}, waitErr
		}
	}
	res := CmdResult{Code: rc, Stdout: stdout.String(), Stderr: stderr.String()}
	if h.LogPath != "" {
		rec, _ := json.Marshal(map[string]any{
			"args": args,
			"rc":   res.Code,
			"out":  res.Stdout,
			"err":  res.Stderr,
		})
		if f, err := os.OpenFile(h.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
			_, _ = f.Write(append(rec, '\n'))
			_ = f.Chmod(0o600)
			_ = f.Close()
		}
	}
	if opts.Check && res.Code != 0 {
		return res, migErr("%s failed with exit %d; see the private transaction log", filepath.Base(args[0]), res.Code)
	}
	return res, nil
}

func (h *SystemHost) Active(unit string) bool {
	res, err := h.Command([]string{"/usr/bin/systemctl", "is-active", "--quiet", unit}, CmdOpts{Check: false})
	return err == nil && res.Code == 0
}

func (h *SystemHost) Service(action, unit string) error {
	if unit == "" {
		unit = "haproxy.service"
	}
	_, err := h.Command([]string{"/usr/bin/systemctl", action, unit}, CmdOpts{Check: true})
	return err
}

func (h *SystemHost) MainPID() (int, error) {
	res, err := h.Command([]string{"/usr/bin/systemctl", "show", "haproxy.service", "--property=MainPID", "--value"}, CmdOpts{Check: true})
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(res.Stdout))
}

func (h *SystemHost) Packages() (map[string]string, error) {
	res, err := h.Command([]string{"/usr/bin/dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${db:Status-Status}\n"}, CmdOpts{Check: true})
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, line := range strings.Split(res.Stdout, "\n") {
		parts := strings.Split(line, "\t")
		if len(parts) == 3 && parts[2] == "installed" {
			name, _, _ := strings.Cut(parts[0], ":")
			out[name] = parts[1]
		}
	}
	return out, nil
}

func (h *SystemHost) Machine() (string, error) {
	raw, err := os.ReadFile(machineIDPath)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func (h *SystemHost) WorkerDigest(pid string) (string, error) {
	n, err := strconv.Atoi(strings.TrimSpace(pid))
	if err != nil || n <= 0 {
		return "", migErr("Invalid worker pid: %s", pid)
	}
	return fileDigest(filepath.Join("/proc", strconv.Itoa(n), "exe"))
}

func collectLibDirs(root string) []string {
	if _, err := os.Stat(root); err != nil {
		return nil
	}
	seen := map[string]bool{}
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		base := d.Name()
		if strings.HasPrefix(base, "lib") && strings.Contains(base, ".so") {
			seen[filepath.Dir(p)] = true
		}
		return nil
	})
	dirs := make([]string, 0, len(seen))
	for d := range seen {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	return dirs
}

func (h *SystemHost) StartSeed(directory, unit string) error {
	argv := []string{
		"/usr/bin/systemd-run", "--quiet", "--collect", "--unit=" + unit,
		"--property=CPUQuota=50%", "--property=MemoryMax=256M",
		"--property=Restart=no", "--property=NoNewPrivileges=yes",
	}
	if dirs := collectLibDirs(filepath.Join(directory, "baseline-libraries")); len(dirs) > 0 {
		argv = append(argv, "--setenv=LD_LIBRARY_PATH="+strings.Join(dirs, ":"))
	}
	argv = append(argv, filepath.Join(directory, "baseline-haproxy"), "-db", "-f", filepath.Join(directory, "seed.cfg"))
	_, err := h.Command(argv, CmdOpts{Check: true})
	return err
}

func (h *SystemHost) Watchdog(directory, unit, recoveryBinary string) error {
	argv := []string{
		"/usr/bin/systemd-run", "--quiet", "--collect", "--unit=" + unit,
		"--on-active=300s", "--timer-property=AccuracySec=1s",
		"--property=Restart=on-failure", "--property=RestartSec=10s",
		filepath.Join(directory, recoveryBinary), "haproxy-migrate", "recover", "--id", filepath.Base(directory),
	}
	_, err := h.Command(argv, CmdOpts{Check: true})
	return err
}

func (h *SystemHost) CancelWatchdog(unit string) {
	_, _ = h.Command([]string{"/usr/bin/systemctl", "stop", unit + ".timer"}, CmdOpts{Check: false})
}

func (h *SystemHost) readServiceEnv(unit string) (map[string]string, error) {
	res, err := h.Command([]string{"/usr/bin/systemctl", "show", unit, "--property=MainPID", "--value"}, CmdOpts{Check: true})
	if err != nil {
		return nil, err
	}
	pid := strings.TrimSpace(res.Stdout)
	raw, err := os.ReadFile(filepath.Join("/proc", pid, "environ"))
	if err != nil {
		return nil, err
	}
	env := map[string]string{}
	for _, entry := range bytes.Split(raw, []byte{0}) {
		if k, v, ok := bytes.Cut(entry, []byte{'='}); ok {
			env[string(k)] = string(v)
		}
	}
	return env, nil
}

func (h *SystemHost) ControlJournal(defaultPath string) (string, error) {
	env, err := h.readServiceEnv("haproxy-controld.service")
	if err != nil {
		return "", err
	}
	if v := env["HAPROXY_CONFIG_TRANSACTION_DIR"]; v != "" {
		return filepath.Join(v, "transaction.json"), nil
	}
	return defaultPath, nil
}

func (h *SystemHost) GuardDatabase() (string, error) {
	env, err := h.readServiceEnv("easy-ha-proxy-guardd.service")
	if err != nil {
		return "", err
	}
	if v := env["GUARDD_DATABASE"]; v != "" {
		return v, nil
	}
	return "/var/lib/easy-ha-proxy/security/security.db", nil
}

// QualifiedServiceDropin validates that a systemd drop-in only uses the
// qualified master-socket ExecStart or the managed state dump ExecStartPre.
func QualifiedServiceDropin(text, configPath string) bool {
	collapsed := dropinContRe.ReplaceAllString(text, " ")
	section := ""
	type kv struct{ k, v string }
	var execution []kv
	for _, raw := range strings.Split(collapsed, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = line
			continue
		}
		if m := dropinExecRe.FindStringSubmatch(line); m != nil {
			if section != "[Service]" {
				return false
			}
			execution = append(execution, kv{m[1], strings.TrimSpace(m[2])})
		}
	}
	if len(execution) == 0 {
		return true
	}
	if len(execution) == 1 && execution[0].k == "ExecStartPre" && execution[0].v == "-/usr/local/sbin/haproxy-state-dump" {
		return true
	}
	if len(execution) != 2 || execution[0].k != "ExecStart" || execution[0].v != "" || execution[1].k != "ExecStart" {
		return false
	}
	cmd, err := shlexSplitStrict(execution[1].v)
	if err != nil {
		return false
	}
	want := []string{
		"/usr/sbin/haproxy", "-Ws", "-S",
		"/run/haproxy/master.sock,mode,660,user,root,group,haproxy",
		"-f", configPath, "-p", "/run/haproxy.pid",
	}
	if len(cmd) != len(want) {
		return false
	}
	for i := range want {
		if cmd[i] != want[i] {
			return false
		}
	}
	return true
}

func shlexSplitStrict(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	inWord := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'':
			inWord = true
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return nil, errors.New("unclosed single quote")
			}
			cur.WriteString(s[i+1 : i+1+j])
			i += j + 1
		case c == '"':
			inWord = true
			closed := false
			for i++; i < len(s); i++ {
				if s[i] == '"' {
					closed = true
					break
				}
				if s[i] == '\\' && i+1 < len(s) && strings.ContainsRune("\\\"$`\n", rune(s[i+1])) {
					i++
				}
				cur.WriteByte(s[i])
			}
			if !closed {
				return nil, errors.New("unclosed double quote")
			}
		case c == '\\':
			if i+1 >= len(s) {
				return nil, errors.New("trailing escape")
			}
			inWord = true
			i++
			cur.WriteByte(s[i])
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			if inWord {
				out = append(out, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			inWord = true
			cur.WriteByte(c)
		}
	}
	if inWord {
		out = append(out, cur.String())
	}
	return out, nil
}

func fileDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func bytesDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func atomicWrite(path string, data []byte, mode os.FileMode, uid, gid int) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
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
		if err := tmp.Chown(uid, gid); err != nil {
			_ = tmp.Close()
			return err
		}
	}
	if _, err := tmp.Write(data); err != nil {
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
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func privateDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || (requireRootOwner && st.Uid != 0) {
		return migErr("Migration state must be a root-owned directory")
	}
	return os.Chmod(path, 0o700)
}

func lexists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

func isSymlink(p string) bool {
	fi, err := os.Lstat(p)
	return err == nil && fi.Mode()&os.ModeSymlink != 0
}

func isRegularFile(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

func freeDiskBytes(path string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, err
	}
	return st.Bavail * uint64(st.Bsize), nil
}

// ParseParagraphs parses RFC822/Debian control paragraphs separated by blank lines.
func ParseParagraphs(data string) []map[string]string {
	var out []map[string]string
	for _, block := range strings.Split(data, "\n\n") {
		rec := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			line = strings.TrimRight(line, "\r")
			if line == "" || line[0] == ' ' || line[0] == '\t' {
				continue
			}
			if k, v, ok := strings.Cut(line, ": "); ok {
				rec[k] = v
			}
		}
		if len(rec) > 0 {
			out = append(out, rec)
		}
	}
	return out
}

// ParseAptPlan parses `apt-get --simulate` output and rejects any package outside allowed.
func ParseAptPlan(text string, allowed map[string]bool) (map[string]bool, error) {
	changed := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "Inst ") || strings.HasPrefix(line, "Remv ") || strings.HasPrefix(line, "Conf ") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			pkg, _, _ := strings.Cut(fields[1], ":")
			if !allowed[pkg] {
				return nil, migErr("APT would change an unrelated package: %s", pkg)
			}
			changed[pkg] = true
		}
	}
	return changed, nil
}

func strVal(v any) string {
	s, _ := v.(string)
	return s
}

func floatVal(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int:
		return float64(x)
	case int64:
		return float64(x)
	case json.Number:
		f, _ := x.Float64()
		return f
	default:
		return 0
	}
}

func intVal(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	case json.Number:
		i, _ := x.Int64()
		return int(i)
	default:
		return 0
	}
}

func unixNowFloat() float64 {
	return float64(nowFunc().UnixNano()) / 1e9
}
