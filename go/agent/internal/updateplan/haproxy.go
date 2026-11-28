package updateplan

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The HAProxy component: installed, running and eligible versions, read
// without changing the host. Only negotiated by brokers that support
// controlled HAProxy patches (--haproxy-status).

const (
	haproxyBinary      = "/usr/sbin/haproxy"
	haproxyLastUpdate  = "/var/lib/easy-ha-proxy/haproxy-package-migration/last-update.json"
	haproxyLastMigrate = "/var/lib/easy-ha-proxy/haproxy-package-migration/last-migration.json"
	haproxyProtection  = "/etc/needrestart/conf.d/easy-ha-proxy-haproxy.conf"
	haproxyAdminSocket = "/run/haproxy/admin.sock"
	guardedRestartLine = `$nrconf{override_rc}{qr(^haproxy\.service$)} = 0;`
)

// haproxyPackages are held out of OS package updates while protected.
var haproxyPackages = map[string]bool{"haproxy": true, "haproxy-awslc": true, "libssl-awslc": true}

var (
	settledPhases    = map[string]bool{"committed": true, "rolled_back": true, "aborted": true, "preparing": true, "prepared": true}
	operationIDRe    = regexp.MustCompile(`^[0-9a-f]{32}$`)
	policyCandidate  = regexp.MustCompile(`(?m)^\s+Candidate:\s*(\S+)`)
	policyRepository = regexp.MustCompile(`(?m)^\s+\d+\s+(?:https?://|file:)`)
	operationKeys    = []string{"id", "kind", "phase", "old_version", "target_packages", "updated_at", "failure",
		"rollback_verified", "target_verified"}

	// The host facts the qualification and runtime checks read; the tests
	// replace them.
	osReleasePath = "/etc/os-release"
	machine       = func() string {
		switch runtime.GOARCH {
		case "arm64":
			return "aarch64"
		case "amd64":
			return "x86_64"
		}
		return runtime.GOARCH
	}
	runtimeReader = haproxyRuntimeState
)

func loadLatestOperation(paths ...string) M {
	type entry struct {
		unsettled bool
		ts        float64
		raw       M
	}
	var candidates []entry
	for _, p := range paths {
		if p == "" {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		var loaded any
		if decoder.Decode(&loaded) != nil {
			continue
		}
		raw, ok := loaded.(M)
		if !ok {
			continue
		}
		id := ""
		if v, has := raw["id"]; has {
			id = pyStr(v)
		}
		if !operationIDRe.MatchString(id) {
			continue
		}
		phase := truthyStr(raw["phase"])
		ts := 0.0
		if n, ok := raw["updated_at"].(json.Number); ok {
			ts, _ = strconv.ParseFloat(string(n), 64)
		}
		candidates = append(candidates, entry{!settledPhases[phase], ts, raw})
	}
	if len(candidates) == 0 {
		return nil
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if a.unsettled != b.unsettled {
			return a.unsettled
		}
		return a.ts > b.ts
	})
	last := candidates[0].raw
	out := M{}
	for _, key := range operationKeys {
		out[key] = last[key]
	}
	return out
}

// haproxyRuntimeState asks the running HAProxy for its version and checks
// that it runs the installed binary and no replaced system library.
func haproxyRuntimeState(binary string) (M, error) {
	conn, err := net.DialTimeout("unix", haproxyAdminSocket, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("show info\n")); err != nil {
		return nil, err
	}
	if unix, ok := conn.(*net.UnixConn); ok {
		_ = unix.CloseWrite()
	}
	var reply []byte
	buf := make([]byte, 16384)
	for {
		n, err := conn.Read(buf)
		reply = append(reply, buf[:n]...)
		if len(reply) > 256*1024 {
			return nil, errors.New("HAProxy runtime reply exceeds the limit")
		}
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return nil, err
			}
			break
		}
	}
	fields := map[string]string{}
	for _, line := range splitLines(string(reply)) {
		if k, v, ok := strings.Cut(line, ": "); ok {
			fields[k] = v
		}
	}
	pidText, ok := fields["Pid"]
	if !ok {
		return nil, errors.New("no Pid in the HAProxy runtime reply")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(pidText))
	if err != nil {
		return nil, err
	}
	version, ok := fields["Version"]
	if !ok {
		return nil, errors.New("no Version in the HAProxy runtime reply")
	}
	process := filepath.Join("/proc", strconv.Itoa(pid))
	maps, err := os.ReadFile(filepath.Join(process, "maps"))
	if err != nil {
		return nil, err
	}
	libraries := map[string]bool{}
	for _, line := range splitLines(string(maps)) {
		columns := splitFields(line, 6)
		if len(columns) == 6 && strings.Contains(columns[1], "x") && strings.HasSuffix(columns[5], " (deleted)") &&
			hasAnyPrefix(columns[5], "/usr/", "/lib/", "/bin/", "/sbin/") {
			libraries[path.Base(strings.TrimSuffix(columns[5], " (deleted)"))] = true
		}
	}
	running, err := fileSHA256(filepath.Join(process, "exe"))
	if err != nil {
		return nil, err
	}
	installed, err := fileSHA256(binary)
	if err != nil {
		return nil, err
	}
	names := []string{}
	for name := range libraries {
		names = append(names, name)
	}
	sort.Strings(names)
	return M{"running_version": version, "binary_matches": running == installed, "replaced_libraries": strList(names)}, nil
}

// splitFields is Python's str.split(None, n-1): at most n fields, the last
// one the rest of the line.
func splitFields(line string, n int) []string {
	out := []string{}
	rest := strings.TrimLeft(line, " \t\n\r\v\f")
	for rest != "" {
		if len(out) == n-1 {
			out = append(out, rest)
			break
		}
		i := strings.IndexAny(rest, " \t\n\r\v\f")
		if i < 0 {
			out = append(out, rest)
			break
		}
		out = append(out, rest[:i])
		rest = strings.TrimLeft(rest[i:], " \t\n\r\v\f")
	}
	return out
}

func hasAnyPrefix(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func hostQualified() bool {
	raw, err := os.ReadFile(osReleasePath)
	if err != nil {
		return false
	}
	release := map[string]string{}
	for _, line := range splitLines(string(raw)) {
		if k, v, ok := strings.Cut(line, "="); ok {
			release[k] = v
		}
	}
	m := machine()
	return strings.Trim(release["ID"], `"`) == "ubuntu" && strings.Trim(release["VERSION_ID"], `"`) == "24.04" &&
		(m == "aarch64" || m == "x86_64")
}

type haproxyPaths struct {
	binary, lastUpdate, lastMigration, protection string
}

func probeHAProxy(runner Runner, paths haproxyPaths, metadata M) M {
	qualified := hostQualified()
	d := M{"installed_version": nil, "running_version": nil, "candidate_version": nil, "branch": nil, "provider": nil,
		"protected": false, "needs_reload": false, "qualified": qualified, "apt": metadata}
	result := func(state, summary string) M {
		return M{"id": "haproxy", "state": state, "actionable": state == "available", "summary": summary,
			"current_version": d["installed_version"], "available_version": d["candidate_version"],
			"installed": d["installed_version"], "available": d["candidate_version"], "details": d}
	}
	if op := loadLatestOperation(paths.lastUpdate, paths.lastMigration); op != nil {
		d["last_operation"] = op
	}
	if !isFile(paths.binary) {
		return result("blocked", "HAProxy is not installed on this host.")
	}
	found := map[string]string{}
	for _, name := range []string{"haproxy", "haproxy-awslc"} {
		response := runner.Run([]string{"dpkg-query", "-W", "-f=${db:Status-Status}\t${Version}", name}, 10*time.Second)
		parts := strings.Split(strings.TrimSpace(response.Stdout), "\t")
		if response.Returncode == 0 && len(parts) == 2 && parts[0] == "installed" {
			found[name] = parts[1]
		}
	}
	if len(found) != 1 {
		return result("unknown", "The installed HAProxy package could not be determined.")
	}
	var name, version string
	for name, version = range found {
	}
	var branch any
	if m := haproxyBranchRe.FindStringSubmatch(version); m != nil {
		branch = m[1]
	}
	provider, source := "Distribution", "APT"
	if qualified {
		provider, source = "Ubuntu", "Ubuntu noble"
	}
	if name == "haproxy-awslc" {
		provider = "HAProxy Technologies"
		if qualified {
			source = "ha34 / Ubuntu noble"
		}
	}
	d["package"], d["installed_version"], d["branch"], d["provider"], d["source"] = name, version, branch, provider, source
	policy := runner.Run([]string{"apt-cache", "policy", name}, 15*time.Second)
	if m := policyCandidate.FindStringSubmatch(policy.Stdout); policy.Returncode == 0 && m != nil && m[1] != "(none)" {
		d["candidate_version"] = m[1]
	}
	if !policyRepository.MatchString(policy.Stdout) {
		d["candidate_version"] = nil
	}
	selections := runner.Run([]string{"dpkg", "--get-selections"}, 10*time.Second)
	held := map[string]bool{}
	for _, line := range splitLines(selections.Stdout) {
		if f := strings.Fields(line); len(f) == 2 && f[1] == "hold" {
			pkg, _, _ := strings.Cut(f[0], ":")
			held[pkg] = true
		}
	}
	required := []string{name}
	if name == "haproxy-awslc" {
		required = append(required, "libssl-awslc")
	}
	allHeld := true
	for _, pkg := range required {
		allHeld = allHeld && held[pkg]
	}
	guarded := false
	if text, err := os.ReadFile(paths.protection); err == nil {
		guarded = strings.Contains(string(text), guardedRestartLine)
	}
	d["protected"] = selections.Returncode == 0 && allHeld && guarded
	state, err := runtimeReader(paths.binary)
	if err != nil {
		return result("unknown", "The running HAProxy version could not be verified.")
	}
	for k, v := range state {
		d[k] = v
	}
	if d["binary_matches"] != true {
		return result("blocked", "The running HAProxy binary differs from the installed package; operator recovery is required.")
	}
	replaced, _ := d["replaced_libraries"].([]any)
	d["needs_reload"] = len(replaced) > 0
	if !qualified {
		d["manual_update"] = "vendor"
		if name == "haproxy" {
			d["manual_update"] = "distribution"
		}
		return result("blocked", "HAProxy is excluded from OS package updates in the panel, including manual installation. "+
			"Controlled updates require Ubuntu 24.04 ARM64 or AMD64. On this platform, update HAProxy separately over SSH "+
			"or the server console and restore package holds afterwards.")
	}
	if metadata["fresh"] != true {
		return result("unknown", "APT metadata is stale or its refresh failed. Check for updates again.")
	}
	candidate, _ := d["candidate_version"].(string)
	if candidate == "" {
		return result("unknown", "No eligible HAProxy package candidate was found.")
	}
	supported := "2.8"
	if name == "haproxy-awslc" {
		supported = "3.4"
	}
	if !strings.HasPrefix(version, supported+".") || !strings.HasPrefix(candidate, supported+".") {
		return result("blocked", "A different HAProxy branch requires a separate migration.")
	}
	if d["protected"] != true {
		return result("blocked", "Enable controlled HAProxy package protection with a host-service update first.")
	}
	newer := runner.Run([]string{"dpkg", "--compare-versions", candidate, "gt", version}, 5*time.Second)
	switch {
	case newer.Returncode == 0:
		return result("available", "A HAProxy patch update is available in the selected branch.")
	case newer.Returncode != 1:
		return result("unknown", "HAProxy package versions could not be compared.")
	case candidate != version:
		return result("blocked", "The eligible HAProxy candidate is older than the installed package.")
	case d["needs_reload"] == true:
		return result("available", "HAProxy must reload to use updated system libraries; the package version is unchanged.")
	}
	return result("current", "Installed and running HAProxy are current in the selected branch.")
}
