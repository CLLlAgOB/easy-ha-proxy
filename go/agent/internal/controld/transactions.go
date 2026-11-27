package controld

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/pyx"
)

// cmdReload is cmd_reload.
func (d *Daemon) cmdReload() (bool, string) {
	d.dumpServerState()
	log.Printf("Executing reload command: %s", d.Opts.SystemctlCmd)
	argv := pyFields(d.Opts.SystemctlCmd)
	if len(argv) == 0 {
		return false, "reload exception: IndexError('list index out of range')"
	}
	res, err := execRaw(argv, nil, haproxyReloadTimeout*time.Second)
	if err != nil {
		if _, ok := err.(*timeoutErr); ok {
			return false, fmt.Sprintf("the reload did not finish within %d seconds and was stopped", haproxyReloadTimeout)
		}
		return false, "reload exception: " + pyReprErr(err)
	}
	if res.rc == 0 {
		msg := res.stdout
		if msg == "" {
			msg = "reloaded"
		}
		return true, pyStrip(msg)
	}
	msg := res.stderr
	if msg == "" {
		msg = fmt.Sprintf("systemctl exit code %d", res.rc)
	}
	return false, pyStrip(msg)
}

func (d *Daemon) haproxyCheckConfigFromB64(value string) (int, string, string, error) {
	raw, err := b64decodeStrict(value)
	if err != nil {
		return 0, "", "", err
	}
	if len(raw) > d.Opts.MaxConfigBytes {
		return 0, "", "", vErr("HAProxy configuration exceeds the allowed size")
	}
	if err := enforceConfigPolicy(raw); err != nil {
		return 0, "", "", err
	}
	tmp, err := os.CreateTemp("", "hapadm-check-*.cfg")
	if err != nil {
		return 0, "", "", err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return 0, "", "", err
	}
	tmp.Close()
	res, err := execRaw([]string{d.Opts.HAProxyBin, "-c", "-f", name}, nil, haproxyCheckTimeout*time.Second)
	if err != nil {
		if _, ok := err.(*timeoutErr); ok {
			return 124, "", fmt.Sprintf("haproxy -c did not finish within %d seconds and was stopped", haproxyCheckTimeout), nil
		}
		return 0, "", "", err
	}
	return res.rc, res.stdout, res.stderr, nil
}

func unfoldHAProxyLines(text string) []string {
	logical := []string{}
	pending := ""
	for _, rawLine := range pySplitlines(text) {
		combined := rawLine
		if pending != "" {
			combined = pending + rawLine
		}
		strippedR := strings.TrimRight(combined, "\r")
		trailing := len(strippedR) - len(strings.TrimRight(strippedR, `\`))
		if trailing%2 == 1 {
			pending = strippedR[:len(strippedR)-1]
			continue
		}
		logical = append(logical, strippedR)
		pending = ""
	}
	if pending != "" {
		logical = append(logical, pending)
	}
	return logical
}

// firstNonEmptyStr is the first value that is not empty.
func firstNonEmptyStr(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func normalizedPrefixPath(raw, allowedPrefix string) bool {
	if raw == "" || !strings.HasPrefix(raw, "/") || strings.Contains(raw, "\x00") {
		return false
	}
	for _, p := range pyPathParts(raw) {
		if p == ".." {
			return false
		}
	}
	normalized := filepath.Clean(raw)
	if strings.HasPrefix(raw, "//") && !strings.HasPrefix(raw, "///") {
		normalized = "/" + normalized
	}
	return strings.HasPrefix(normalized, strings.TrimRight(allowedPrefix, "/")+"/")
}

// policyPathUnder reports whether an absolute file path stays under one of the
// allowed host prefixes (the directory itself or a child, no ".." escape).
func policyPathUnder(raw string, prefixes ...string) bool {
	if raw == "" || !strings.HasPrefix(raw, "/") || strings.Contains(raw, "\x00") {
		return false
	}
	for _, p := range pyPathParts(raw) {
		if p == ".." {
			return false
		}
	}
	normalized := filepath.Clean(raw)
	for _, p := range prefixes {
		base := strings.TrimRight(p, "/")
		if normalized == base || strings.HasPrefix(normalized, base+"/") {
			return true
		}
	}
	return false
}

// policyFilePaths guards file-bearing directives in EVERY section. HAProxy
// starts as UID 0 and opens files / creates Unix sockets before the chroot and
// privilege drop, so a path outside the host-owned directories in any section
// lets a compromised panel container read arbitrary root files (errorfile,
// acl -f, crt, ca-file, return ... file) or overwrite host files (unix bind).
func policyFilePaths(token string, parts []string) error {
	// No path argument may climb out with "..".
	for _, p := range parts[1:] {
		if strings.HasPrefix(p, "/") || strings.HasPrefix(p, "unix@/") {
			for _, part := range pyPathParts(strings.TrimPrefix(p, "unix@")) {
				if part == ".." {
					return vErr("HAProxy file path may not contain '..'")
				}
			}
		}
	}
	switch token {
	case "errorfile":
		if len(parts) >= 3 && !policyPathUnder(parts[2], "/etc/haproxy/") {
			return vErr("HAProxy errorfile must stay under /etc/haproxy")
		}
	case "ca-base", "crt-base":
		if len(parts) >= 2 && strings.HasPrefix(parts[1], "/") &&
			!policyPathUnder(parts[1], "/etc/haproxy/", "/etc/ssl/certs/", "/etc/ssl/private/") {
			return vErr("HAProxy %s must stay under /etc/haproxy or /etc/ssl", token)
		}
	case "bind":
		// Only the bind address can be a Unix socket; crt/ca-file options are
		// file paths checked by the embedded-keyword scan below.
		if len(parts) >= 2 {
			addr := parts[1]
			if strings.HasPrefix(addr, "/") || strings.HasPrefix(addr, "unix@") {
				if !policyPathUnder(strings.TrimPrefix(addr, "unix@"), "/run/haproxy/") {
					return vErr("HAProxy unix bind socket must stay under /run/haproxy")
				}
			}
		}
	}
	// File-bearing keywords also appear as options inside bind/server/
	// default-server/acl/return lines, not only as the leading directive.
	for i, p := range parts {
		switch p {
		case "crt", "ca-file", "crl-file":
			if i+1 < len(parts) && strings.HasPrefix(parts[i+1], "/") &&
				!policyPathUnder(parts[i+1], "/etc/haproxy/", "/etc/ssl/certs/", "/etc/ssl/private/") {
				return vErr("HAProxy %s must stay under /etc/haproxy or /etc/ssl", p)
			}
		case "-f":
			if i+1 < len(parts) && !policyPathUnder(parts[i+1], "/etc/haproxy/") {
				return vErr("HAProxy acl file must stay under /etc/haproxy")
			}
		case "file":
			// "return ... file <path>" reads an arbitrary root file into the
			// response; the template only uses lf-file under /etc/haproxy.
			if token == "http-request" || token == "http-response" {
				return vErr("HAProxy %s ... file is not allowed", token)
			}
		case "lf-file":
			if i+1 < len(parts) && !policyPathUnder(parts[i+1], "/etc/haproxy/") {
				return vErr("HAProxy lf-file must stay under /etc/haproxy")
			}
		}
	}
	return nil
}

var (
	// The lua-prepend-path values haproxy.cfg.j2 writes.
	approvedLuaSearchPaths = map[string]bool{
		"/etc/haproxy/lua/?/http.lua": true,
		"/etc/haproxy/lua/?.lua":      true,
	}
	policyForbidden = map[string]bool{"program": true, "pidfile": true, "module-load": true, "setuid": true, "setgid": true,
		"uid": true, "gid": true, "external-check": true, "external-check-path": true, "external-check-command": true,
		"lua-load-per-thread": true, "setenv": true, "presetenv": true, "ssl-engine": true, "insecure-fork-wanted": true,
		"insecure-setuid-wanted": true}
	policySections = map[string]bool{"defaults": true, "frontend": true, "backend": true, "listen": true, "resolvers": true,
		"mailers": true, "peers": true, "userlist": true, "cache": true, "program": true, "ring": true, "log-forward": true,
		"fcgi-app": true, "crt-store": true, "traces": true, "http-errors": true, "acme": true}
	policyAllowedGlobal = map[string]bool{"log": true, "nbthread": true, "maxconn": true, "chroot": true, "stats": true,
		"user": true, "group": true, "daemon": true, "ca-base": true, "crt-base": true, "ssl-default-bind-ciphersuites": true,
		"ssl-default-bind-ciphers": true, "ssl-default-bind-options": true, "localpeer": true, "lua-prepend-path": true,
		"lua-load": true, "server-state-file": true}
	policyCompatBlocks = map[string]string{".if version_atleast(3.1)": "tune.lua.bool-sample-conversion normal",
		".if !feature(OPENSSL_AWSLC)": "tune.ssl.default-dh-param 2048"}
)

func startsWithSpace(s string) bool {
	r, size := utf8DecodeFirst(s)
	return size > 0 && pySpace(r)
}

func utf8DecodeFirst(s string) (rune, int) {
	for _, r := range s {
		return r, len(string(r))
	}
	return 0, 0
}

// enforceConfigPolicy is _enforce_config_policy.
func enforceConfigPolicy(raw []byte) error {
	if err := utf8Check(raw); err != nil {
		return err
	}
	inGlobal, sawGlobal := false, false
	required := map[string]bool{"user": false, "group": false, "chroot": false}
	conditionalBody, conditionalOpen, bodySeen := "", false, false
	for _, rawLine := range unfoldHAProxyLines(string(raw)) {
		line := pyStrip(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := pyFields(line)
		token := strings.ToLower(parts[0])
		if conditionalOpen {
			if !startsWithSpace(rawLine) {
				return vErr("HAProxy compatibility block must stay inside global")
			}
			if bodySeen {
				if line != ".endif" {
					return vErr("invalid HAProxy compatibility block ending")
				}
				conditionalOpen, bodySeen = false, false
				continue
			}
			if line != conditionalBody {
				return vErr("invalid HAProxy compatibility block body")
			}
			bodySeen = true
		} else if strings.HasPrefix(token, ".") {
			body, ok := policyCompatBlocks[line]
			if !inGlobal || !startsWithSpace(rawLine) || !ok {
				return vErr("unapproved HAProxy conditional directive")
			}
			conditionalBody, conditionalOpen = body, true
			continue
		}
		if policyForbidden[token] {
			return vErr("HAProxy directive '%s' is not allowed", token)
		}
		if token == "option" && len(parts) >= 2 && strings.ToLower(parts[1]) == "external-check" {
			return vErr("HAProxy directive 'option external-check' is not allowed")
		}
		if err := policyFilePaths(token, parts); err != nil {
			return err
		}
		if token == "global" {
			if sawGlobal {
				return vErr("multiple global sections are not allowed")
			}
			inGlobal, sawGlobal = true, true
			continue
		}
		if policySections[token] {
			inGlobal = false
			continue
		}
		if !inGlobal {
			continue
		}
		if !strings.HasPrefix(token, "tune.") && !policyAllowedGlobal[token] {
			return vErr("global directive '%s' is not allowed", token)
		}
		switch {
		case token == "user":
			required["user"] = len(parts) == 2 && parts[1] == "haproxy"
		case token == "group":
			required["group"] = len(parts) == 2 && parts[1] == "haproxy"
		case token == "chroot":
			required["chroot"] = len(parts) == 2 && parts[1] == "/var/lib/haproxy"
		case token == "stats" && len(parts) >= 2 && strings.ToLower(parts[1]) == "socket":
			if len(parts) < 3 || !normalizedPrefixPath(parts[2], "/run/haproxy/") {
				return vErr("HAProxy stats socket must stay under /run/haproxy")
			}
		case token == "lua-load":
			if len(parts) != 2 || parts[1] != "/etc/haproxy/lua/auth-request.lua" {
				return vErr("unapproved HAProxy Lua entry point")
			}
		case token == "lua-prepend-path":
			// Lua splits package.path on ";", so a prefix check would let
			// one value carry further directories; only the template's
			// own entries are accepted, as for lua-load.
			if len(parts) != 2 || !approvedLuaSearchPaths[parts[1]] {
				return vErr("HAProxy Lua search path must stay under /etc/haproxy/lua")
			}
		case token == "server-state-file":
			if len(parts) != 2 || !normalizedPrefixPath(parts[1], "/var/lib/haproxy/") {
				return vErr("HAProxy server state file must stay under /var/lib/haproxy")
			}
		}
	}
	if conditionalOpen {
		return vErr("unclosed HAProxy compatibility block")
	}
	if !sawGlobal || !required["user"] || !required["group"] || !required["chroot"] {
		return vErr("required HAProxy privilege-drop directives are missing")
	}
	return nil
}

// haproxyWriteConfigFromB64 validates and atomically replaces haproxy.cfg.
func (d *Daemon) haproxyWriteConfigFromB64(value string) error {
	raw, err := b64decodeStrict(value)
	if err != nil {
		return err
	}
	if len(raw) == 0 || len(raw) > d.Opts.MaxConfigBytes {
		return vErr("invalid HAProxy configuration size")
	}
	if err := enforceConfigPolicy(raw); err != nil {
		return err
	}
	cfgPath := d.Opts.HAProxyCfgPath
	dir := filepath.Dir(cfgPath)
	if err := os.MkdirAll(dir, 0o777); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".haproxy.cfg.*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()
	res, err := execRaw([]string{d.Opts.HAProxyBin, "-c", "-f", tmpPath}, nil, haproxyCheckTimeout*time.Second)
	if err != nil {
		return err
	}
	if res.rc != 0 {
		detail := res.stderr
		if detail == "" {
			detail = res.stdout
		}
		if detail == "" {
			detail = "validation failed"
		}
		return vErr("HAProxy rejected the configuration: %s", pyStrip(detail))
	}
	var st unix.Stat_t
	if err := unix.Stat(cfgPath, &st); err == nil {
		if err := os.Chown(tmpPath, int(st.Uid), int(st.Gid)); err != nil {
			return err
		}
		if err := unix.Chmod(tmpPath, st.Mode&0o7777); err != nil {
			return &os.PathError{Op: "chmod", Path: tmpPath, Err: err}
		}
	} else if err == unix.ENOENT {
		if err := os.Chmod(tmpPath, 0o640); err != nil {
			return err
		}
	} else {
		return &os.PathError{Op: "stat", Path: cfgPath, Err: err}
	}
	if err := os.Rename(tmpPath, cfgPath); err != nil {
		return err
	}
	keep = true
	fsyncDir(dir)
	return nil
}

// ---------------------------------------------------------------------------
// guarded apply
// ---------------------------------------------------------------------------

var (
	controlPlaneDomainRE = regexp.MustCompile(`^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	controlPlaneACLRE    = regexp.MustCompile(`(?m)^\s*acl\s+(host_admin|host_authelia)\s+hdr\(host\)\s+-i\s+(.+?)\s*$`)
	controlPlanePaths    = map[string]string{"admin": "/api/control-plane-health", "authelia": "/api/health"}
	httpStatusRE         = regexp.MustCompile(`^HTTP/\d(?:\.\d)?\s+(\d{3})(?:\s+.*)?$`)
)

type cpCheck = map[string]any

func decodeControlPlaneChecks(value string) ([]cpCheck, error) {
	raw, err := b64decodeStrict(value)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw) > 16*1024 {
		return nil, vErr("invalid control-plane check payload size")
	}
	if err := utf8Check(raw); err != nil {
		return nil, err
	}
	payload, err := decodeJSONObject(raw)
	if err != nil {
		return nil, err
	}
	items, ok := payload.([]any)
	if !ok || len(items) < 1 || len(items) > 2 {
		return nil, vErr("one or two control-plane checks are required")
	}
	checks := []cpCheck{}
	seen := map[string]bool{}
	for _, it := range items {
		item, ok := it.(map[string]any)
		if !ok {
			return nil, vErr("invalid control-plane check")
		}
		service := strings.ToLower(pyStrip(pyx.StrOr(item["service"])))
		domain := strings.TrimRight(strings.ToLower(pyStrip(pyx.StrOr(item["domain"]))), ".")
		if _, ok := controlPlanePaths[service]; !ok || seen[service] {
			return nil, vErr("invalid or duplicate control-plane service")
		}
		if len(domain) < 1 || len(domain) > 253 || !controlPlaneDomainRE.MatchString(domain) {
			return nil, vErr("invalid control-plane domain for %s", service)
		}
		seen[service] = true
		checks = append(checks, cpCheck{"service": service, "domain": domain, "path": controlPlanePaths[service]})
	}
	if !seen["admin"] {
		return nil, vErr("the HAProxy Admin check is required")
	}
	return checks, nil
}

// checksFromState turns persisted checks back into the probe's shape.
func checksFromState(v []any) []cpCheck {
	out := []cpCheck{}
	for _, it := range v {
		if m, ok := it.(map[string]any); ok {
			out = append(out, m)
		} else {
			out = append(out, cpCheck{})
		}
	}
	return out
}

func controlPlaneDomains(raw []byte) (map[string][]string, error) {
	if err := utf8Check(raw); err != nil {
		return nil, err
	}
	domains := map[string][]string{}
	for _, m := range controlPlaneACLRE.FindAllStringSubmatch(string(raw), -1) {
		set := map[string]bool{}
		for _, v := range pyFields(m[2]) {
			if s := pyStrip(v); s != "" {
				set[strings.TrimRight(strings.ToLower(s), ".")] = true
			}
		}
		values := make([]string, 0, len(set))
		for v := range set {
			values = append(values, v)
		}
		sort.Strings(values)
		if len(values) > 0 {
			domains[m[1]] = values
		}
	}
	return domains, nil
}

func equalDomains(a, b map[string][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		w, ok := b[k]
		if !ok || strings.Join(v, "\x00") != strings.Join(w, "\x00") {
			return false
		}
	}
	return true
}

func validateGuardedControlPlaneTransition(previous, candidate []byte, checks []cpCheck) error {
	active, err := controlPlaneDomains(previous)
	if err != nil {
		return err
	}
	cand, err := controlPlaneDomains(candidate)
	if err != nil {
		return err
	}
	if len(active["host_admin"]) == 0 {
		return vErr("the current config has no protected HAProxy Admin domain")
	}
	if !equalDomains(active, cand) {
		return vErr("protected HAProxy Admin/Authelia domains changed; use the domain migration workflow")
	}
	expected := map[string]string{}
	for _, pair := range [][2]string{{"host_admin", "admin"}, {"host_authelia", "authelia"}} {
		domains := cand[pair[0]]
		if len(domains) > 1 {
			return vErr("multiple protected domains found for %s", pair[1])
		}
		if len(domains) == 1 {
			expected[pair[1]] = domains[0]
		}
	}
	supplied := map[string]string{}
	for _, c := range checks {
		supplied[pyx.Str(c["service"])] = pyx.Str(c["domain"])
	}
	if len(supplied) != len(expected) {
		return vErr("control-plane checks do not match the protected domains")
	}
	for k, v := range expected {
		if supplied[k] != v {
			return vErr("control-plane checks do not match the protected domains")
		}
	}
	return nil
}

func (d *Daemon) createGuardedConfigBackup(raw []byte, candidateSHA string) (string, error) {
	if len(raw) == 0 || len(raw) > d.Opts.MaxConfigBytes {
		return "", vErr("the current HAProxy configuration cannot be backed up")
	}
	dir := d.Opts.ConfigBackupDir
	if err := os.MkdirAll(dir, 0o777); err != nil {
		return "", err
	}
	backup := filepath.Join(dir, "haproxy.cfg.pre-apply."+compactStamp(time.Now())+"."+candidateSHA[:12])
	tmp, err := os.CreateTemp(dir, ".haproxy.cfg.pre-apply.*")
	if err != nil {
		return "", err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return "", err
	}
	tmp.Close()
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		os.Remove(tmpPath)
		return "", err
	}
	if err := os.Rename(tmpPath, backup); err != nil {
		os.Remove(tmpPath)
		return "", err
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "haproxy.cfg.pre-apply.*"))
	type mt struct {
		p string
		t time.Time
	}
	items := []mt{}
	for _, m := range matches {
		if fi, err := os.Stat(m); err == nil {
			items = append(items, mt{m, fi.ModTime()})
		}
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].t.After(items[j].t) })
	keep := d.Opts.GuardedConfigBackups
	if keep < 1 {
		keep = 1
	}
	for i := keep; i < len(items); i++ {
		if err := os.Remove(items[i].p); err != nil {
			log.Printf("Could not remove old HAProxy config backup %s", items[i].p)
		}
	}
	return backup, nil
}

func (d *Daemon) probeControlPlaneService(check cpCheck) map[string]any {
	service, domain, path := pyx.Str(check["service"]), pyx.Str(check["domain"]), pyx.Str(check["path"])
	result := map[string]any{"service": check["service"], "domain": check["domain"], "path": check["path"],
		"ok": false, "status": nil, "failure": ""}
	_ = service
	timeout := time.Duration(d.Opts.ControlPlaneCheckTimeout * float64(time.Second))
	fail := func(msg string) map[string]any {
		result["failure"] = msg
		return result
	}
	conn, err := net.DialTimeout("tcp", "127.0.0.1:443", timeout)
	if err != nil {
		return fail(pyNetErr(err))
	}
	defer conn.Close()
	tc := tls.Client(conn, &tls.Config{ServerName: domain, InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	_ = tc.SetDeadline(time.Now().Add(timeout))
	if err := tc.Handshake(); err != nil {
		return fail(pyNetErr(err))
	}
	request := "GET " + path + " HTTP/1.1\r\nHost: " + domain + "\r\nUser-Agent: easy-ha-proxy-config-guard/1\r\n" +
		"Accept: application/json\r\nConnection: close\r\n\r\n"
	_ = tc.SetDeadline(time.Now().Add(timeout))
	if _, err := tc.Write([]byte(request)); err != nil {
		return fail(pyNetErr(err))
	}
	response := []byte{}
	buf := make([]byte, 2048)
	for !strings.Contains(string(response), "\r\n") && len(response) < 8192 {
		_ = tc.SetDeadline(time.Now().Add(timeout))
		n, err := tc.Read(buf)
		response = append(response, buf[:n]...)
		if err != nil {
			if n == 0 && !isEOFLike(err) {
				return fail(pyNetErr(err))
			}
			break
		}
	}
	statusLine := strings.SplitN(string(response), "\r\n", 2)[0]
	statusLine = strings.ToValidUTF8(statusLine, "�")
	m := httpStatusRE.FindStringSubmatch(statusLine)
	if m == nil || strings.Contains(statusLine, "\n") {
		if statusLine == "" {
			statusLine = "empty"
		}
		return fail("invalid HTTP response: " + statusLine)
	}
	status, _ := strconv.Atoi(m[1])
	result["status"] = status
	result["ok"] = status == 200
	if status != 200 {
		result["failure"] = fmt.Sprintf("expected HTTP 200, received HTTP %d", status)
	}
	return result
}

func isEOFLike(err error) bool {
	return err != nil && (err.Error() == "EOF" || strings.Contains(err.Error(), "close notify"))
}

func allOK(items []map[string]any) bool {
	for _, it := range items {
		if !pyx.Truthy(it["ok"]) {
			return false
		}
	}
	return true
}

func (d *Daemon) runControlPlaneChecks(checks []cpCheck) []map[string]any {
	latest := []map[string]any{}
	attempts := d.Opts.ControlPlaneCheckAttempts
	if attempts > 30 {
		attempts = 30
	}
	if attempts < 1 {
		attempts = 1
	}
	interval := d.Opts.ControlPlaneCheckInterval
	if interval < 0.1 {
		interval = 0.1
	}
	for attempt := 1; attempt <= attempts; attempt++ {
		latest = latest[:0:0]
		for _, c := range checks {
			r := d.probeControlPlaneService(c)
			r["attempt"] = attempt
			latest = append(latest, r)
		}
		if allOK(latest) {
			return latest
		}
		if attempt < attempts {
			time.Sleep(time.Duration(interval * float64(time.Second)))
		}
	}
	return latest
}

func listOfMaps(items []map[string]any) []any {
	out := make([]any, len(items))
	for i, it := range items {
		out[i] = it
	}
	return out
}

func (d *Daemon) restoreGuardedConfig(previousB64 string, checks []cpCheck) map[string]any {
	result := map[string]any{"ok": false, "reload_ok": false, "reload_output": "", "checks": []any{}, "failure": ""}
	if err := d.haproxyWriteConfigFromB64(previousB64); err != nil {
		result["failure"] = "rollback failed: " + pyErr(err)
		return result
	}
	ok, output := d.cmdReload()
	result["reload_ok"], result["reload_output"] = ok, output
	if !ok {
		result["failure"] = "rollback reload failed: " + output
		return result
	}
	rc := d.runControlPlaneChecks(checks)
	result["checks"] = listOfMaps(rc)
	result["ok"] = allOK(rc)
	if !allOK(rc) {
		result["failure"] = "critical services did not recover after rollback"
	}
	return result
}

func failedChecks(items []map[string]any) string {
	failed := []string{}
	for _, it := range items {
		if !pyx.Truthy(it["ok"]) {
			failed = append(failed, fmt.Sprintf("%s (%s): %s", pyx.Str(it["service"]), pyx.Str(it["domain"]), pyx.Str(it["failure"])))
		}
	}
	if len(failed) == 0 {
		return "critical service check failed"
	}
	return strings.Join(failed, "; ")
}

func (d *Daemon) haproxyApplyConfigGuardedLocked(cfgB64, checksB64 string) (map[string]any, error) {
	checks, err := decodeControlPlaneChecks(checksB64)
	if err != nil {
		return nil, err
	}
	candidate, err := b64decodeStrict(cfgB64)
	if err != nil {
		return nil, err
	}
	if len(candidate) == 0 || len(candidate) > d.Opts.MaxConfigBytes {
		return nil, vErr("invalid HAProxy configuration size")
	}
	previous, err := os.ReadFile(d.Opts.HAProxyCfgPath)
	if err != nil {
		return nil, err
	}
	if len(previous) == 0 || len(previous) > d.Opts.MaxConfigBytes {
		return nil, vErr("a valid current HAProxy configuration is required for rollback")
	}
	if err := validateGuardedControlPlaneTransition(previous, candidate, checks); err != nil {
		return nil, err
	}
	candidateSHA, previousSHA := sha256Hex(candidate), sha256Hex(previous)
	backupPath, err := d.createGuardedConfigBackup(previous, candidateSHA)
	if err != nil {
		return nil, err
	}
	previousB64 := b64(previous)
	result := map[string]any{"ok": false, "applied": false, "rolled_back": false, "rollback_ok": nil,
		"candidate_sha256": candidateSHA, "previous_sha256": previousSHA, "backup_path": backupPath,
		"checks": []any{}, "rollback": nil, "reload_output": "", "failure": ""}
	if err := d.haproxyWriteConfigFromB64(cfgB64); err != nil {
		result["failure"] = "guarded apply failed: " + pyErr(err)
	} else {
		ok, output := d.cmdReload()
		result["reload_output"] = output
		if !ok {
			result["failure"] = "HAProxy reload failed: " + output
		} else {
			cr := d.runControlPlaneChecks(checks)
			result["checks"] = listOfMaps(cr)
			if allOK(cr) {
				result["ok"], result["applied"] = true, true
				return result, nil
			}
			result["failure"] = failedChecks(cr)
		}
	}
	rollback := d.restoreGuardedConfig(previousB64, checks)
	result["rolled_back"], result["rollback"], result["rollback_ok"] = true, rollback, pyx.Truthy(rollback["ok"])
	summary := "HAProxy apply failed AND the rollback did not succeed"
	if pyx.Truthy(rollback["ok"]) {
		summary = "HAProxy apply failed and was rolled back"
	}
	d.reportAlert("config.apply_failed", "haproxy", summary, pyx.StrOr(result["failure"]))
	return result, nil
}

func (d *Daemon) haproxyApplyConfigGuarded(cfgB64, checksB64 string) (map[string]any, error) {
	if !d.guarded.TryLock() {
		return nil, rErr("another guarded HAProxy configuration apply is running")
	}
	defer d.guarded.Unlock()
	if err := d.ensureNoActiveConfigTransactionLocked(); err != nil {
		return nil, err
	}
	return d.haproxyApplyConfigGuardedLocked(cfgB64, checksB64)
}

// ---------------------------------------------------------------------------
// transaction state
// ---------------------------------------------------------------------------

func (d *Daemon) transactionStatePath() string {
	return filepath.Join(d.Opts.ConfigTransactionDir, configTransactionState)
}

func (d *Daemon) ensureTransactionDir() (string, error) {
	dir := d.Opts.ConfigTransactionDir
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return "", rErr("HAProxy config transaction path is not a safe directory")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

func (d *Daemon) persistConfigTransaction(state map[string]any) error {
	dir, err := d.ensureTransactionDir()
	if err != nil {
		return err
	}
	raw := pyx.Compact(state, true)
	if len(raw) == 0 || len(raw) > d.Opts.MaxTransactionStateBytes {
		return rErr("HAProxy config transaction state exceeds the size limit")
	}
	tmp, err := os.CreateTemp(dir, ".transaction.*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	tmp.Close()
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, d.transactionStatePath()); err != nil {
		os.Remove(tmpPath)
		return err
	}
	fsyncDir(dir)
	return nil
}

func (d *Daemon) loadConfigTransaction() (map[string]any, error) {
	path := d.transactionStatePath()
	fi, err := os.Lstat(path)
	if err != nil {
		if isNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		return nil, rErr("HAProxy config transaction state is not a regular file")
	}
	if fi.Size() <= 0 || fi.Size() > int64(d.Opts.MaxTransactionStateBytes) {
		return nil, rErr("HAProxy config transaction state has an invalid size")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := utf8Check(raw); err != nil {
		return nil, err
	}
	v, err := decodeJSONObject(raw)
	if err != nil {
		return nil, err
	}
	state, ok := v.(map[string]any)
	if n, isInt := pyx.Int(state["version"]); !ok || !isInt || n != configTransactionVersion || isBool(state["version"]) {
		return nil, rErr("HAProxy config transaction state has an invalid format")
	}
	if id, ok := state["transaction_id"].(string); !ok || id == "" {
		return nil, rErr("HAProxy config transaction state has no transaction id")
	}
	return state, nil
}

func isBool(v any) bool { _, ok := v.(bool); return ok }

func (d *Daemon) ensureNoActiveConfigTransactionLocked() error {
	state, err := d.loadConfigTransaction()
	if err != nil || state == nil {
		return err
	}
	if state["state"] == "pending_confirmation" {
		deadline := pyx.Float(state["deadline_epoch"])
		if deadline != 0 && nowEpoch() >= deadline {
			if _, err := d.rollbackConfigTransactionLocked(state, "confirmation timeout expired before another config write"); err != nil {
				return err
			}
			if state, err = d.loadConfigTransaction(); err != nil {
				return err
			}
		}
	}
	if state != nil {
		if s, ok := state["state"].(string); ok && activeStates[s] {
			return rErr("another HAProxy config transaction is still active")
		}
	}
	return nil
}

func (d *Daemon) haproxyWriteConfigSerialized(cfgB64 string) error {
	if !d.guarded.TryLock() {
		return rErr("another guarded HAProxy configuration operation is running")
	}
	defer d.guarded.Unlock()
	if err := d.ensureNoActiveConfigTransactionLocked(); err != nil {
		return err
	}
	return d.haproxyWriteConfigFromB64(cfgB64)
}

// ---------------------------------------------------------------------------
// sources, admin allow list
// ---------------------------------------------------------------------------

func canonicalAdminAllowlistEntries(value any) ([]string, error) {
	list, ok := value.([]any)
	if !ok || len(list) > adminAllowlistMaxEntries {
		return nil, vErr("admin allow list must contain at most 256 entries")
	}
	result := []string{}
	seen := map[string]bool{}
	for _, raw := range list {
		s, ok := raw.(string)
		if !ok {
			return nil, vErr("admin allow list entries must be strings")
		}
		text := pyStrip(s)
		if text == "" {
			continue
		}
		var canonical string
		var err error
		if strings.Contains(text, "/") {
			canonical, err = pyIPNetwork(text)
		} else {
			canonical, err = pyIPAddress(text)
		}
		if err != nil {
			return nil, vErr("invalid admin allow list entry: %s", pyRepr(text))
		}
		if !seen[canonical] {
			result = append(result, canonical)
			seen[canonical] = true
		}
	}
	return result, nil
}

type sourcesDecoded struct {
	candidate, previous map[string][]byte
	geoip               map[string]any
	adminAllowlist      []string
	hasAdmin            bool
}

func (d *Daemon) decodeConfigTransactionSources(value string) (*sourcesDecoded, error) {
	raw, err := b64decodeStrict(value)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw) > d.Opts.MaxTransactionSourcesPayloadBytes {
		return nil, vErr("invalid config source payload size")
	}
	if err := utf8Check(raw); err != nil {
		return nil, err
	}
	v, err := decodeJSONObject(raw)
	if err != nil {
		return nil, err
	}
	payload, ok := v.(map[string]any)
	_, hasC := payload["candidate"]
	_, hasP := payload["previous"]
	if !ok || !hasC || !hasP {
		return nil, vErr("config sources must contain candidate and previous mappings")
	}
	for k := range payload {
		if k != "candidate" && k != "previous" && k != "geoip_selection" && k != "admin_allowlist" {
			return nil, vErr("config sources contain unsupported transaction fields")
		}
	}
	out := &sourcesDecoded{}
	for _, group := range []string{"candidate", "previous"} {
		mapping, ok := payload[group].(map[string]any)
		if !ok || len(mapping) == 0 {
			return nil, vErr("config source %s mapping is empty", group)
		}
		for name := range mapping {
			if !configSourceFilenames[name] {
				return nil, vErr("config source payload contains an unsupported filename")
			}
		}
		decoded := map[string][]byte{}
		for _, name := range sortedKeys(mapping) {
			encoded, ok := mapping[name].(string)
			if !ok {
				return nil, vErr("invalid encoded content for %s", name)
			}
			content, err := b64decodeStrict(encoded)
			if err != nil {
				return nil, err
			}
			if len(content) > d.Opts.MaxTransactionSourceFileBytes {
				return nil, vErr("config source %s exceeds the size limit", name)
			}
			if strings.Contains(string(content), "\x00") {
				return nil, vErr("config source %s contains a NUL byte", name)
			}
			if err := utf8Check(content); err != nil {
				return nil, err
			}
			decoded[name] = content
		}
		if group == "candidate" {
			out.candidate = decoded
		} else {
			out.previous = decoded
		}
	}
	if len(out.candidate) != len(out.previous) {
		return nil, vErr("candidate and previous config source filenames differ")
	}
	for k := range out.candidate {
		if _, ok := out.previous[k]; !ok {
			return nil, vErr("candidate and previous config source filenames differ")
		}
	}
	if gs, present := payload["geoip_selection"]; present && gs != nil {
		sel, ok := gs.(map[string]any)
		_, hv := sel["version"]
		_, hc := sel["countries"]
		_, he := sel["access_filter_enabled"]
		if !ok || len(sel) != 3 || !hv || !hc || !he {
			return nil, vErr("config GeoIP selection has an invalid format")
		}
		countriesRaw, okC := sel["countries"].([]any)
		enabled, okE := sel["access_filter_enabled"].(bool)
		if n, okV := pyx.Int(sel["version"]); !okV || n != 1 || !okC || !okE || len(countriesRaw) > geoipMaxCountries {
			return nil, vErr("config GeoIP selection has an invalid format")
		}
		countries := []string{}
		for _, c := range countriesRaw {
			s, ok := c.(string)
			if !ok || !isCountryCode(s) {
				return nil, vErr("config GeoIP selection contains an invalid country code")
			}
			countries = append(countries, s)
		}
		if !isSortedUnique(countries) {
			return nil, vErr("config GeoIP selection countries are not canonical")
		}
		if enabled && len(countries) == 0 {
			return nil, vErr("GeoIP filtering cannot be enabled without selected countries")
		}
		out.geoip = map[string]any{"version": 1, "countries": stringsToAny(countries), "access_filter_enabled": enabled}
	}
	if al, present := payload["admin_allowlist"]; present && al != nil {
		entries, err := canonicalAdminAllowlistEntries(al)
		if err != nil {
			return nil, err
		}
		out.adminAllowlist, out.hasAdmin = entries, true
	}
	return out, nil
}

func isSortedUnique(list []string) bool {
	for i := 1; i < len(list); i++ {
		if list[i-1] >= list[i] {
			return false
		}
	}
	return true
}

func stringsToAny(list []string) []any {
	out := make([]any, len(list))
	for i, s := range list {
		out[i] = s
	}
	return out
}

func openDirNoFollow(path string) (int, error) {
	return unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
}

func (d *Daemon) openConfigSourceDirectory() (int, error) {
	fd, err := openDirNoFollow(d.Opts.ConfigSourceDir)
	if err != nil {
		return -1, rErr("HAProxy config source directory is unavailable or unsafe")
	}
	return fd, nil
}

func (d *Daemon) readConfigSourceAt(dirfd int, filename string) ([]byte, *unix.Stat_t, error) {
	if !configSourceFilenames[filename] {
		return nil, nil, vErr("unsupported config source filename")
	}
	fd, err := unix.Openat(dirfd, filename, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, rErr("config source %s is unavailable or unsafe", filename)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, nil, &os.PathError{Op: "fstat", Path: filename, Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, nil, rErr("config source %s is not a regular file", filename)
	}
	limit := d.Opts.MaxTransactionSourceFileBytes
	if st.Size > int64(limit) {
		return nil, nil, rErr("config source %s exceeds the size limit", filename)
	}
	data, err := readAllFD(fd, limit, func() error { return rErr("config source %s exceeds the size limit", filename) })
	if err != nil {
		return nil, nil, err
	}
	return data, &st, nil
}

func readAllFD(fd, limit int, over func() error) ([]byte, error) {
	out := []byte{}
	buf := make([]byte, 65536)
	for {
		n, err := unix.Read(fd, buf)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return nil, err
		}
		if n <= 0 {
			return out, nil
		}
		out = append(out, buf[:n]...)
		if len(out) > limit {
			return nil, over()
		}
	}
}

func (d *Daemon) verifyCandidateConfigSources(candidate map[string][]byte) error {
	fd, err := d.openConfigSourceDirectory()
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	for _, name := range sortedKeys(candidate) {
		current, _, err := d.readConfigSourceAt(fd, name)
		if err != nil {
			return err
		}
		if !compareDigest(string(current), string(candidate[name])) {
			return vErr("live config source %s changed before the transaction", name)
		}
	}
	return nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (d *Daemon) verifyLiveTransactionCandidate(state map[string]any) error {
	expectedCfg := pyx.StrOr(state["candidate_sha256"])
	if !isHex64(expectedCfg) {
		return rErr("persisted candidate config hash is invalid")
	}
	current, err := os.ReadFile(d.Opts.HAProxyCfgPath)
	if err != nil {
		return err
	}
	if len(current) == 0 || len(current) > d.Opts.MaxConfigBytes {
		return rErr("live HAProxy configuration has an invalid size")
	}
	if !compareDigest(sha256Hex(current), expectedCfg) {
		return rErr("live HAProxy configuration changed before confirmation")
	}
	expected, ok := state["candidate_source_sha256"].(map[string]any)
	if !ok || len(expected) == 0 {
		return rErr("persisted candidate config source hashes are invalid")
	}
	for k := range expected {
		if !configSourceFilenames[k] {
			return rErr("persisted candidate config source hashes are invalid")
		}
	}
	fd, err := d.openConfigSourceDirectory()
	if err != nil {
		return err
	}
	for _, name := range sortedKeys(expected) {
		hash := pyx.Str(expected[name])
		if !isHex64(hash) {
			unix.Close(fd)
			return rErr("persisted candidate hash for %s is invalid", name)
		}
		src, _, err := d.readConfigSourceAt(fd, name)
		if err != nil {
			unix.Close(fd)
			return err
		}
		if !compareDigest(sha256Hex(src), hash) {
			unix.Close(fd)
			return rErr("live config source %s changed before confirmation", name)
		}
	}
	unix.Close(fd)
	if err := d.verifyTransactionAdminAllowlistCandidate(state); err != nil {
		return err
	}
	return d.verifyTransactionGeoIPCandidate(state)
}

func (d *Daemon) readCurrentConfigSources() (map[string][]byte, error) {
	fd, err := d.openConfigSourceDirectory()
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	sources := map[string][]byte{}
	for _, name := range sortedKeys(configSourceFilenames) {
		content, _, err := d.readConfigSourceAt(fd, name)
		if err != nil {
			continue
		}
		sources[name] = content
	}
	return sources, nil
}

// ---------------------------------------------------------------------------
// configuration history
// ---------------------------------------------------------------------------

func (d *Daemon) configHistoryEntries() []string {
	dir := d.Opts.ConfigHistoryDir
	if !isDir(dir) {
		return nil
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	names := []string{}
	for _, e := range ents {
		p := filepath.Join(dir, e.Name())
		if isDir(p) && isFile(filepath.Join(p, configHistoryMeta)) {
			names = append(names, e.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	return names
}

func (d *Daemon) recordConfigVersion(state map[string]any) string {
	id, err := d.recordConfigVersionInner(state)
	if err != nil {
		log.Printf("Could not record the configuration version: %s", pyReprErr(err))
		return ""
	}
	return id
}

func (d *Daemon) recordConfigVersionInner(state map[string]any) (string, error) {
	sources, err := d.readCurrentConfigSources()
	if err != nil {
		return "", err
	}
	if len(sources) == 0 {
		return "", nil
	}
	h := []byte{}
	for _, name := range sortedKeys(sources) {
		h = append(h, []byte(name)...)
		h = append(h, 0)
		h = append(h, sources[name]...)
	}
	generation := sha256Hex(h)
	dir := d.Opts.ConfigHistoryDir
	existing := d.configHistoryEntries()
	if len(existing) > 0 {
		if raw, err := os.ReadFile(filepath.Join(dir, existing[0], configHistoryMeta)); err == nil {
			if v, err := pyx.Decode(raw); err == nil {
				if latest, ok := v.(map[string]any); ok && latest["generation"] == generation {
					return pyx.StrOr(latest["id"]), nil
				} else if !ok {
					return "", fmt.Errorf("'%s' object has no attribute 'get'", pyTypeName(v))
				}
			}
		}
	}
	now := time.Now()
	versionID := compactStamp(now) + "." + generation[:12]
	target := filepath.Join(dir, versionID)
	staging := filepath.Join(dir, ".staging."+tokenHex(8))
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	if err := os.Mkdir(staging, 0o750); err != nil {
		return "", err
	}
	fail := func(err error) (string, error) {
		_ = os.RemoveAll(staging)
		return "", err
	}
	for _, name := range sortedKeys(sources) {
		p := filepath.Join(staging, name)
		if err := os.WriteFile(p, sources[name], 0o666); err != nil {
			return fail(err)
		}
		if err := os.Chmod(p, 0o640); err != nil {
			return fail(err)
		}
	}
	parent := ""
	if len(existing) > 0 {
		parent = existing[0]
	}
	if state == nil {
		state = map[string]any{}
	}
	meta := map[string]any{"id": versionID, "ts": now.Unix(), "generation": generation, "parent": parent,
		"files": stringsToAny(sortedKeys(sources)), "transaction_id": firstNonEmptyStr(pyx.StrOr(state["transaction_id"]), pyx.StrOr(state["id"])),
		"cfg_sha256": pyx.StrOr(state["candidate_sha256"])}
	metaRaw, _ := pyx.Encode(meta)
	metaPath := filepath.Join(staging, configHistoryMeta)
	if err := os.WriteFile(metaPath, pyHumanJSON(metaRaw), 0o666); err != nil {
		return fail(err)
	}
	if err := os.Chmod(metaPath, 0o640); err != nil {
		return fail(err)
	}
	if err := os.Rename(staging, target); err != nil {
		return fail(err)
	}
	keep := d.Opts.ConfigHistoryKeep
	if keep < 1 {
		keep = 1
	}
	entries := d.configHistoryEntries()
	for i := keep; i < len(entries); i++ {
		_ = os.RemoveAll(filepath.Join(dir, entries[i]))
	}
	log.Printf("Recorded configuration version %s", versionID)
	return versionID, nil
}

// pyHumanJSON turns Go's compact JSON into json.dumps' default separators.
func pyHumanJSON(raw []byte) []byte {
	raw = []byte(strings.TrimRight(string(raw), "\n"))
	out := make([]byte, 0, len(raw)+len(raw)/8)
	inString, escaped := false, false
	for _, c := range raw {
		out = append(out, c)
		if inString {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case ',', ':':
			out = append(out, ' ')
		}
	}
	return out
}

func pyTypeName(v any) string {
	switch v.(type) {
	case []any:
		return "list"
	case string:
		return "str"
	case json.Number:
		if strings.ContainsAny(v.(json.Number).String(), ".eE") {
			return "float"
		}
		return "int"
	case bool:
		return "bool"
	case nil:
		return "NoneType"
	}
	return "dict"
}

func (d *Daemon) listConfigVersions(limit int) []any {
	if limit > 200 {
		limit = 200
	}
	if limit < 1 {
		limit = 1
	}
	versions := []any{}
	entries := d.configHistoryEntries()
	if len(entries) > limit {
		entries = entries[:limit]
	}
	for _, name := range entries {
		p := filepath.Join(d.Opts.ConfigHistoryDir, name)
		raw, err := os.ReadFile(filepath.Join(p, configHistoryMeta))
		if err != nil || utf8Check(raw) != nil {
			continue
		}
		v, err := pyx.Decode(raw)
		if err != nil {
			continue
		}
		meta, ok := v.(map[string]any)
		if !ok {
			continue
		}
		var total int64
		if ents, err := os.ReadDir(p); err == nil {
			for _, e := range ents {
				if fi, err := os.Stat(filepath.Join(p, e.Name())); err == nil && fi.Mode().IsRegular() {
					total += fi.Size()
				}
			}
		}
		meta["bytes"] = total
		versions = append(versions, meta)
	}
	return versions
}

func (d *Daemon) getConfigVersion(versionID string) (map[string]any, error) {
	name := pyStrip(versionID)
	found := false
	for _, e := range d.configHistoryEntries() {
		if e == name {
			found = true
		}
	}
	if name == "" || !found {
		return nil, vErr("unknown configuration version")
	}
	p := filepath.Join(d.Opts.ConfigHistoryDir, name)
	raw, err := os.ReadFile(filepath.Join(p, configHistoryMeta))
	if err != nil {
		return nil, err
	}
	v, err := decodeJSONObject(raw)
	if err != nil {
		return nil, err
	}
	meta, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("'%s' object does not support item assignment", pyTypeName(v))
	}
	sources := map[string]any{}
	for _, fn := range sortedKeys(configSourceFilenames) {
		c := filepath.Join(p, fn)
		if isFile(c) {
			data, err := os.ReadFile(c)
			if err != nil {
				return nil, err
			}
			sources[fn] = b64(data)
		}
	}
	meta["sources"] = sources
	return meta, nil
}

func (d *Daemon) restoreConfigSources(previous map[string][]byte) ([]string, error) {
	fd, err := d.openConfigSourceDirectory()
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	restored := []string{}
	var dst unix.Stat_t
	if err := unix.Fstat(fd, &dst); err != nil {
		return nil, err
	}
	for _, name := range sortedKeys(previous) {
		content := previous[name]
		if !configSourceFilenames[name] {
			return restored, vErr("unsupported rollback config source filename")
		}
		owner, group, mode := int(dst.Uid), int(dst.Gid), uint32(0o644)
		_, st, err := d.readConfigSourceAt(fd, name)
		if err == nil {
			owner, group, mode = int(st.Uid), int(st.Gid), st.Mode&0o7777
		} else if !isRuntime(err) {
			return restored, err
		}
		temporary := "." + name + ".transaction." + tokenHex(8)
		if err := writeTempAt(fd, temporary, content, mode, owner, group, true); err != nil {
			return restored, err
		}
		if err := unix.Renameat(fd, temporary, fd, name); err != nil {
			_ = unix.Unlinkat(fd, temporary, 0)
			return restored, &os.LinkError{Op: "rename", Old: temporary, New: name, Err: err}
		}
		_ = unix.Fsync(fd)
		restored = append(restored, name)
	}
	return restored, nil
}

// writeTempAt creates name under dirfd exclusively, writes content, sets
// mode and owner (an unprivileged chown failure tolerated when lenient).
func writeTempAt(dirfd int, name string, content []byte, mode uint32, owner, group int, lenient bool) error {
	tfd, err := unix.Openat(dirfd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return &os.PathError{Op: "open", Path: name, Err: err}
	}
	fail := func(err error) error {
		unix.Close(tfd)
		_ = unix.Unlinkat(dirfd, name, 0)
		return err
	}
	for len(content) > 0 {
		n, err := unix.Write(tfd, content)
		if err != nil {
			return fail(err)
		}
		content = content[n:]
	}
	if err := unix.Fsync(tfd); err != nil {
		return fail(err)
	}
	if err := unix.Fchmod(tfd, mode); err != nil {
		return fail(err)
	}
	if err := unix.Fchown(tfd, owner, group); err != nil {
		if !(lenient && (err == unix.EPERM || err == unix.EACCES) && os.Geteuid() != 0) {
			return fail(&os.PathError{Op: "fchown", Path: name, Err: err})
		}
	}
	unix.Close(tfd)
	return nil
}

func (d *Daemon) canonicalAdminAllowlistRaw(entries []string) ([]byte, error) {
	canonical, err := canonicalAdminAllowlistEntries(stringsToAny(entries))
	if err != nil {
		return nil, err
	}
	raw := []byte{}
	if len(canonical) > 0 {
		raw = []byte(strings.Join(canonical, "\n") + "\n")
	}
	if len(raw) > adminAllowlistMaxBytes {
		return nil, vErr("admin allow list exceeds the size limit")
	}
	return raw, nil
}

func (d *Daemon) openAdminAllowlistDirectory() (int, error) {
	p := d.Opts.AdminAllowlistPath
	parts := pyPathParts(p)
	if !strings.HasPrefix(p, "/") || len(parts) == 0 || parts[len(parts)-1] == ".." {
		return -1, rErr("admin allow list path is unsafe")
	}
	fd, err := openDirNoFollow("/" + strings.Join(parts[:len(parts)-1], "/"))
	if err != nil {
		return -1, rErr("admin allow list directory is unavailable or unsafe")
	}
	return fd, nil
}

func (d *Daemon) readAdminAllowlistRaw() (bool, []byte, error) {
	fd, err := d.openAdminAllowlistDirectory()
	if err != nil {
		return false, nil, err
	}
	defer unix.Close(fd)
	name := filepath.Base(d.Opts.AdminAllowlistPath)
	var st unix.Stat_t
	if err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if err == unix.ENOENT {
			return false, []byte{}, nil
		}
		return false, nil, &os.PathError{Op: "stat", Path: name, Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return false, nil, rErr("admin allow list is not a regular file")
	}
	if st.Size > adminAllowlistMaxBytes {
		return false, nil, rErr("admin allow list exceeds the size limit")
	}
	ffd, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return false, nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	defer unix.Close(ffd)
	var cst unix.Stat_t
	if err := unix.Fstat(ffd, &cst); err != nil || cst.Mode&unix.S_IFMT != unix.S_IFREG {
		return false, nil, rErr("admin allow list is not a regular file")
	}
	raw, err := readAllFD(ffd, adminAllowlistMaxBytes, func() error { return rErr("admin allow list exceeds the size limit") })
	if err != nil {
		return false, nil, err
	}
	if strings.Contains(string(raw), "\x00") {
		return false, nil, rErr("admin allow list contains a NUL byte")
	}
	if err := utf8Check(raw); err != nil {
		return false, nil, err
	}
	return true, raw, nil
}

func (d *Daemon) writeAdminAllowlistRaw(raw []byte) error {
	if len(raw) > adminAllowlistMaxBytes || strings.Contains(string(raw), "\x00") {
		return vErr("invalid admin allow list snapshot")
	}
	if err := utf8Check(raw); err != nil {
		return err
	}
	fd, err := d.openAdminAllowlistDirectory()
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	name := filepath.Base(d.Opts.AdminAllowlistPath)
	temporary := ".admin.allow.transaction." + tokenHex(8)
	var dst unix.Stat_t
	if err := unix.Fstat(fd, &dst); err != nil {
		return err
	}
	owner, group, mode := int(dst.Uid), int(dst.Gid), uint32(0o640)
	var st unix.Stat_t
	if err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		if st.Mode&unix.S_IFMT != unix.S_IFREG {
			return rErr("admin allow list is not a regular file")
		}
		owner, group, mode = int(st.Uid), int(st.Gid), st.Mode&0o7777
	} else if err != unix.ENOENT {
		return &os.PathError{Op: "stat", Path: name, Err: err}
	}
	if err := writeTempAt(fd, temporary, raw, mode, owner, group, false); err != nil {
		return err
	}
	if err := unix.Renameat(fd, temporary, fd, name); err != nil {
		_ = unix.Unlinkat(fd, temporary, 0)
		return &os.LinkError{Op: "rename", Old: temporary, New: name, Err: err}
	}
	_ = unix.Fsync(fd)
	return nil
}
