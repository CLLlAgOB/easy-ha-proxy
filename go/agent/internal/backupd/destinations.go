package backupd

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

var (
	destinationNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
	sftpHostRe        = regexp.MustCompile(`^[A-Za-z0-9._:\[\]-]+$`)
	sftpUserRe        = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$`)
	bucketRe          = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,62}$`)
	accessKeyRe       = regexp.MustCompile(`^[A-Za-z0-9/+=_-]{3,128}$`)
	remoteDateRe      = regexp.MustCompile(`^` + regexp.QuoteMeta(remotePrefix) + `(\d{4})(\d{2})(\d{2})`)
	s3KeyRe           = regexp.MustCompile(`<Key>([^<]+)</Key>`)
	shlexSafeRe       = regexp.MustCompile(`^[A-Za-z0-9_@%+=:,./-]+$`)
)

const (
	remotePrefix   = "easy-ha-proxy-"
	sshKeyscan     = "/usr/bin/ssh-keyscan"
	sshKeygen      = "/usr/bin/ssh-keygen"
	s3Algorithm    = "AWS4-HMAC-SHA256"
	s3Service      = "s3"
	s3Unreserved   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	askpassContent = "#!/bin/sh\nexec cat -- \"$EASY_HA_PROXY_SFTP_PASSWORD_FILE\"\n"
)

var destinationTypes = []string{"sftp", "s3"}

var hostKeyFailures = []string{
	"REMOTE HOST IDENTIFICATION HAS CHANGED", "Host key verification failed",
	"host key for", "No matching host key",
}

func keepCount(value any, def, limit int64) (int64, error) {
	if value == nil || value == "" {
		return def, nil
	}
	n, ok := pyInt(value)
	if !ok {
		return 0, bErr("invalid", "a retention count must be a number")
	}
	if n < 0 {
		n = 0
	}
	if n > limit {
		n = limit
	}
	return n, nil
}

func destName(name any) string { return strings.ToLower(strings.TrimSpace(pyStr(name))) }

func (d *Daemon) destinationPath(name any) (string, error) {
	text := destName(name)
	if !destinationNameRe.MatchString(text) {
		return "", bErr("invalid", "the destination name may use a-z, 0-9 and dashes")
	}
	return filepath.Join(d.Opts.DestinationsDir, text+".json"), nil
}

func (d *Daemon) destFile(name, suffix string) string {
	return filepath.Join(d.Opts.DestinationsDir, destName(name)+suffix)
}

func destinationAuth(record map[string]any) string {
	v := pyStr(record["auth"])
	if v == "password" {
		return v
	}
	return "key"
}

func verifyMode(value, def any) (string, error) {
	text := strings.ToLower(strings.TrimSpace(pyStr(value)))
	if text == "auto" || text == "transfer" {
		return text, nil
	}
	if value != nil && text != "" {
		return "", bErr("invalid", "verify must be auto or transfer")
	}
	fallback := strings.ToLower(strings.TrimSpace(pyStr(def)))
	if fallback == "auto" || fallback == "transfer" {
		return fallback, nil
	}
	return "auto", nil
}

func verifyModeLoose(value any) string {
	m, err := verifyMode(value, nil)
	if err != nil {
		return "auto"
	}
	return m
}

func runCapture(timeout time.Duration, stdin []byte, env []string, name string, args ...string) (int, []byte, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	if env != nil {
		cmd.Env = env
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return -1, out.Bytes(), errb.Bytes(), fmt.Errorf("command %q timed out after %s", name, timeout)
	}
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode(), out.Bytes(), errb.Bytes(), nil
		}
		return -1, out.Bytes(), errb.Bytes(), err
	}
	return 0, out.Bytes(), errb.Bytes(), nil
}

// scanHostKey asks the far end for its host keys (trust on first use).
func scanHostKey(host string, port int64) ([]byte, error) {
	_, out, errb, err := runCapture(15*time.Second, nil, nil, sshKeyscan, "-T", "10", "-p",
		strconv.FormatInt(port, 10), "-t", "ed25519,ecdsa,rsa", "--", host)
	if err != nil {
		return nil, bErr("upstream", "cannot read the host key: %v", err)
	}
	lines := []string{}
	for _, line := range strings.Split(strings.ToValidUTF8(string(out), "�"), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.TrimSpace(line) != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	if len(lines) == 0 {
		detail := truncRunes(strings.TrimSpace(string(errb)), 300)
		msg := "the far end did not offer a host key"
		if detail != "" {
			msg += ": " + detail
		}
		return nil, bErr("upstream", "%s", msg)
	}
	sort.Strings(lines)
	return []byte(strings.Join(lines, "\n") + "\n"), nil
}

func hostKeyFingerprints(knownHosts []byte) []string {
	f, err := os.CreateTemp("", "backupd-hostkey-")
	if err != nil {
		return []string{}
	}
	defer func() { _ = os.Remove(f.Name()) }()
	_, _ = f.Write(knownHosts)
	_ = f.Close()
	_, out, _, err := runCapture(15*time.Second, nil, nil, sshKeygen, "-l", "-E", "sha256", "-f", f.Name())
	prints := []string{}
	if err != nil {
		return prints
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.HasPrefix(fields[1], "SHA256:") {
			kind := ""
			last := fields[len(fields)-1]
			if strings.HasPrefix(last, "(") {
				kind = strings.Trim(last, "()")
			}
			prints = append(prints, strings.TrimSpace(kind+" "+fields[1]))
		}
	}
	return prints
}

func (d *Daemon) pinHostKey(name string, knownHosts []byte) ([]string, error) {
	if err := writePrivate(d.destFile(name, ".known_hosts"), knownHosts); err != nil {
		return nil, err
	}
	return hostKeyFingerprints(knownHosts), nil
}

func anyList(v any) []any {
	if l, ok := v.([]any); ok {
		return l
	}
	return nil
}

func (d *Daemon) pinnedFingerprints(record map[string]any) []any {
	stored := anyList(record["host_key_fingerprints"])
	if len(stored) > 0 || record["type"] != "sftp" || !truthy(record["name"]) {
		if stored == nil {
			return []any{}
		}
		return stored
	}
	raw, err := os.ReadFile(d.destFile(pyStr(record["name"]), ".known_hosts"))
	if err != nil {
		return []any{}
	}
	out := []any{}
	for _, p := range hostKeyFingerprints(raw) {
		out = append(out, p)
	}
	return out
}

func hostKeyProblem(stderr []byte) bool {
	text := strings.ToLower(string(stderr))
	for _, marker := range hostKeyFailures {
		if strings.Contains(text, strings.ToLower(marker)) {
			return true
		}
	}
	return false
}

func (d *Daemon) noteHostKeyChange(record map[string]any) string {
	offered := []string{}
	if kh, err := scanHostKey(pyStr(record["host"]), intOr(record["port"], 22)); err == nil {
		offered = hostKeyFingerprints(kh)
	}
	if stored, err := d.loadDestination(record["name"]); err == nil {
		offeredAny := make([]any, len(offered))
		for i, o := range offered {
			offeredAny[i] = o
		}
		stored["host_key_changed"] = map[string]any{"at": utcNow(), "offered": offeredAny}
		if path, err := d.destinationPath(record["name"]); err == nil {
			_ = d.atomicJSON(path, stored, 0o600)
		}
	}
	msg := "the far end presented a different host key than the one pinned, so " +
		"nothing was sent. If the server was reinstalled or its key replaced " +
		"on purpose, trust the new key on the backups page"
	if len(offered) > 0 {
		msg += " (offered: " + strings.Join(offered, ", ") + ")"
	}
	return msg + "."
}

func normalizePrivateKey(material string) []byte {
	text := strings.ReplaceAll(material, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	text = strings.Trim(text, "\n")
	return []byte(text + "\n")
}

// writePrivate replaces a root-only file.
func writePrivate(path string, content []byte) error {
	_ = os.Remove(path)
	return privateFile(path, content)
}

func (d *Daemon) ensureDestinationsDir() error {
	if err := os.MkdirAll(d.Opts.DestinationsDir, 0o700); err != nil {
		return err
	}
	return os.Chmod(d.Opts.DestinationsDir, 0o700)
}

func (d *Daemon) loadDestination(name any) (map[string]any, error) {
	path, err := d.destinationPath(name)
	if err != nil {
		return nil, err
	}
	record, err := d.safeJSONFile(path)
	if err != nil {
		var be *Error
		if errors.As(err, &be) {
			return nil, err
		}
		return nil, bErr("invalid", "cannot read the destination: %v", pyOSError(err))
	}
	if len(record) == 0 {
		return nil, bErr("not_found", "no such destination")
	}
	return record, nil
}

// pyOSError renders an OSError the way str(exc) does.
func pyOSError(err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		if errors.Is(pe.Err, os.ErrNotExist) {
			return fmt.Sprintf("[Errno 2] No such file or directory: '%s'", pe.Path)
		}
		return fmt.Sprintf("%v: '%s'", pe.Err, pe.Path)
	}
	return err.Error()
}

func getOr(record map[string]any, key string, def any) any {
	if v, ok := record[key]; ok {
		return v
	}
	return def
}

func (d *Daemon) publicDestination(record map[string]any) map[string]any {
	var changed any
	if truthy(record["host_key_changed"]) {
		changed = record["host_key_changed"]
	}
	return map[string]any{
		"name": getOr(record, "name", ""), "type": getOr(record, "type", ""),
		"host": getOr(record, "host", ""), "port": getOr(record, "port", 22),
		"user": getOr(record, "user", ""), "path": getOr(record, "path", ""),
		"has_key": truthy(record["key_installed"]), "auth": destinationAuth(record),
		"has_password":          truthy(record["password_installed"]),
		"host_key_pinned":       truthy(record["host_key_pinned"]),
		"host_key_fingerprints": d.pinnedFingerprints(record),
		"host_key_source":       getOr(record, "host_key_source", ""),
		"host_key_changed":      changed,
		"verify":                verifyModeLoose(record["verify"]),
		"endpoint":              getOr(record, "endpoint", ""), "region": getOr(record, "region", ""),
		"bucket": getOr(record, "bucket", ""), "prefix": getOr(record, "prefix", ""),
		"access_key": getOr(record, "access_key", ""), "has_secret": truthy(record["secret_installed"]),
		"allow_insecure": truthy(record["allow_insecure"]),
		"keep_daily":     getOr(record, "keep_daily", 7), "keep_weekly": getOr(record, "keep_weekly", 4),
		"keep_monthly": getOr(record, "keep_monthly", 6), "updated_at": getOr(record, "updated_at", ""),
	}
}

func (d *Daemon) listDestinations() (map[string]any, error) {
	if err := d.ensureDestinationsDir(); err != nil {
		return nil, err
	}
	matches, _ := filepath.Glob(filepath.Join(d.Opts.DestinationsDir, "*.json"))
	sort.Strings(matches)
	items := []map[string]any{}
	for _, path := range matches {
		if rec, err := d.safeJSONFile(path); err == nil {
			items = append(items, d.publicDestination(rec))
		}
	}
	return map[string]any{"ok": true, "destinations": items, "types": destinationTypes}, nil
}

func hasControl(s string) bool {
	for _, r := range s {
		if r < 32 || r == 127 {
			return true
		}
	}
	return false
}

func (d *Daemon) saveDestination(req map[string]any) (map[string]any, error) {
	if err := d.ensureDestinationsDir(); err != nil {
		return nil, err
	}
	name := destName(req["name"])
	pathTarget, err := d.destinationPath(name)
	if err != nil {
		return nil, err
	}
	kind := strings.ToLower(strings.TrimSpace(pyStr(req["type"])))
	if kind != "sftp" && kind != "s3" {
		return nil, bErr("invalid", "unsupported destination type")
	}
	existing := map[string]any{}
	if rec, err := d.loadDestination(name); err == nil {
		existing = rec
	} else {
		var be *Error
		if !errors.As(err, &be) {
			return nil, err
		}
	}
	if kind == "s3" {
		return d.saveS3Destination(req, name, pathTarget, existing)
	}
	host := strings.TrimSpace(pyStr(req["host"]))
	badHost := host == "" || strings.HasPrefix(host, "-") || len([]rune(host)) > 253 || !sftpHostRe.MatchString(host)
	for _, r := range host {
		if unicode.IsSpace(r) || r < 32 || r == 127 {
			badHost = true
		}
	}
	if badHost {
		return nil, bErr("invalid", "a host is required")
	}
	userName := strings.TrimSpace(pyStr(req["user"]))
	if !sftpUserRe.MatchString(userName) {
		return nil, bErr("invalid", "the user name is not valid")
	}
	port := int64(22)
	if truthy(req["port"]) {
		n, ok := pyInt(req["port"])
		if !ok {
			return nil, bErr("invalid", "the port must be a number")
		}
		port = n
	}
	if port < 1 || port > 65535 {
		return nil, bErr("invalid", "the port is out of range")
	}
	remote, err := normalizeRemoteDir(req["path"])
	if err != nil {
		return nil, err
	}
	auth := strings.TrimSpace(pyStr(req["auth"]))
	if auth == "" {
		auth = strings.TrimSpace(pyStr(existing["auth"]))
	}
	if auth == "" {
		auth = "key"
	}
	auth = strings.ToLower(auth)
	if auth != "key" && auth != "password" {
		return nil, bErr("invalid", "auth must be key or password")
	}
	keyInstalled := truthy(existing["key_installed"])
	passwordInstalled := truthy(existing["password_installed"])
	if auth == "key" {
		key := pyStr(req["private_key"])
		if key != "" {
			if !strings.Contains(key, "PRIVATE KEY") {
				return nil, bErr("invalid", "that does not look like a private key")
			}
			if err := writePrivate(d.destFile(name, ".key"), normalizePrivateKey(key)); err != nil {
				return nil, err
			}
			keyInstalled = true
		} else if !keyInstalled {
			return nil, bErr("invalid", "a private key is required")
		}
	} else {
		password := req["password"]
		if truthy(password) {
			s, ok := password.(string)
			if !ok || len([]rune(s)) > 1024 || strings.ContainsAny(s, "\x00\r\n") {
				return nil, bErr("invalid", "the password is not valid")
			}
			if err := writePrivate(d.destFile(name, ".password"), []byte(s)); err != nil {
				return nil, err
			}
			passwordInstalled = true
		} else if !passwordInstalled {
			return nil, bErr("invalid", "a password is required")
		}
	}
	hostKey := strings.TrimSpace(pyStr(req["host_key"]))
	sameEndpoint := existing["host"] == host && intOr(existing["port"], 22) == port
	fingerprints := anyList(existing["host_key_fingerprints"])
	if fingerprints == nil {
		fingerprints = []any{}
	}
	source := pyStr(existing["host_key_source"])
	if source == "" {
		source = "supplied"
	}
	pin := func(kh []byte) error {
		prints, err := d.pinHostKey(name, kh)
		if err != nil {
			return err
		}
		fingerprints = []any{}
		for _, p := range prints {
			fingerprints = append(fingerprints, p)
		}
		return nil
	}
	if hostKey != "" {
		if err := pin([]byte(hostKey + "\n")); err != nil {
			return nil, err
		}
		source = "supplied"
	} else if !(truthy(existing["host_key_pinned"]) && sameEndpoint) {
		kh, err := scanHostKey(host, port)
		if err != nil {
			return nil, err
		}
		if err := pin(kh); err != nil {
			return nil, err
		}
		source = "first-use"
	}
	keepDaily, err := keepCount(req["keep_daily"], 7, 365)
	if err != nil {
		return nil, err
	}
	keepWeekly, err := keepCount(req["keep_weekly"], 4, 260)
	if err != nil {
		return nil, err
	}
	keepMonthly, err := keepCount(req["keep_monthly"], 6, 120)
	if err != nil {
		return nil, err
	}
	verify, err := verifyMode(req["verify"], existing["verify"])
	if err != nil {
		return nil, err
	}
	record := map[string]any{
		"name": name, "type": kind, "host": host, "port": port, "user": userName, "path": remote,
		"auth": auth, "key_installed": keyInstalled, "password_installed": passwordInstalled,
		"host_key_pinned": true, "host_key_fingerprints": fingerprints, "host_key_source": source,
		"keep_daily": keepDaily, "keep_weekly": keepWeekly, "keep_monthly": keepMonthly,
		"verify": verify, "updated_at": utcNow(),
	}
	if err := d.atomicJSON(pathTarget, record, 0o600); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "destination": d.publicDestination(record)}, nil
}

// Python ipaddress.is_reserved for IPv6.
var ipv6Reserved = func() []*net.IPNet {
	out := []*net.IPNet{}
	for _, cidr := range []string{"::/8", "100::/8", "200::/7", "400::/6", "800::/5", "1000::/4",
		"4000::/3", "6000::/3", "8000::/3", "a000::/3", "c000::/3", "e000::/4", "f000::/5",
		"f800::/6", "fe00::/9"} {
		_, n, _ := net.ParseCIDR(cidr)
		out = append(out, n)
	}
	return out
}()

func forbiddenS3IP(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		return v4.IsLoopback() || v4.IsLinkLocalUnicast() || v4.IsLinkLocalMulticast() ||
			v4.IsMulticast() || v4.IsUnspecified() || v4[0] >= 240
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, n := range ipv6Reserved {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func validateS3EndpointHost(hostname string) error {
	host := strings.TrimRight(strings.ToLower(strings.TrimSpace(hostname)), ".")
	if host == "" || len([]rune(host)) > 253 {
		return bErr("invalid", "the endpoint host is not valid")
	}
	for _, r := range host {
		if unicode.IsSpace(r) || r < 32 || r == 127 {
			return bErr("invalid", "the endpoint host is not valid")
		}
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return bErr("invalid", "the S3 endpoint cannot target localhost")
	}
	if ip := net.ParseIP(host); ip != nil && forbiddenS3IP(ip) {
		return bErr("invalid", "the S3 endpoint resolves to a forbidden address")
	}
	return nil
}

func resolveS3Address(ctx context.Context, hostname string) (string, error) {
	if err := validateS3EndpointHost(hostname); err != nil {
		return "", err
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, hostname)
	if err != nil {
		return "", bErr("invalid", "the S3 endpoint host does not resolve: %v", err)
	}
	selected := ""
	for _, a := range addrs {
		if forbiddenS3IP(a.IP) {
			return "", bErr("invalid", "the S3 endpoint resolves to a forbidden address")
		}
		if selected == "" {
			selected = a.IP.String()
		}
	}
	if selected == "" {
		return "", bErr("invalid", "the S3 endpoint host did not resolve to a usable address")
	}
	return selected, nil
}

func (d *Daemon) saveS3Destination(req map[string]any, name, pathTarget string, existing map[string]any) (map[string]any, error) {
	endpoint := strings.TrimRight(strings.TrimSpace(pyStr(req["endpoint"])), "/")
	if hasControl(endpoint) {
		return nil, bErr("invalid", "the endpoint URL is not valid")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" || parsed.Hostname() == "" {
		return nil, bErr("invalid", "the endpoint must be a full https:// URL")
	}
	if parsed.User != nil {
		return nil, bErr("invalid", "the endpoint URL must not include credentials")
	}
	if p := parsed.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n > 65535 {
			return nil, bErr("invalid", "the endpoint port is not valid")
		}
		if n < 1 {
			return nil, bErr("invalid", "the endpoint port is out of range")
		}
	}
	if err := validateS3EndpointHost(parsed.Hostname()); err != nil {
		return nil, err
	}
	allowInsecure := truthy(req["allow_insecure"])
	if parsed.Scheme == "http" && !allowInsecure {
		return nil, bErr("invalid", "the endpoint is plain http; tick 'allow insecure' only for a storage service on a trusted network")
	}
	bucket := strings.TrimSpace(pyStr(req["bucket"]))
	if !bucketRe.MatchString(bucket) {
		return nil, bErr("invalid", "the bucket name is not valid")
	}
	prefix := strings.Trim(strings.TrimSpace(pyStr(req["prefix"])), "/")
	if strings.Contains(prefix, "..") || len([]rune(prefix)) > 256 {
		return nil, bErr("invalid", "the prefix is not valid")
	}
	accessKey := strings.TrimSpace(pyStr(req["access_key"]))
	if !accessKeyRe.MatchString(accessKey) {
		return nil, bErr("invalid", "the access key is not valid")
	}
	if secret := pyStr(req["secret_key"]); secret != "" {
		if err := writePrivate(d.destFile(name, ".secret"), []byte(secret)); err != nil {
			return nil, err
		}
	} else if !truthy(existing["secret_installed"]) {
		return nil, bErr("invalid", "a secret key is required")
	}
	region := strings.TrimSpace(pyStr(req["region"]))
	if region == "" {
		region = "us-east-1"
	}
	region = truncRunes(region, 64)
	keepDaily, err := keepCount(req["keep_daily"], 7, 365)
	if err != nil {
		return nil, err
	}
	keepWeekly, err := keepCount(req["keep_weekly"], 4, 260)
	if err != nil {
		return nil, err
	}
	keepMonthly, err := keepCount(req["keep_monthly"], 6, 120)
	if err != nil {
		return nil, err
	}
	verify, err := verifyMode(req["verify"], existing["verify"])
	if err != nil {
		return nil, err
	}
	record := map[string]any{
		"name": name, "type": "s3", "endpoint": endpoint, "region": region, "bucket": bucket,
		"prefix": prefix, "access_key": accessKey, "secret_installed": true,
		"allow_insecure": allowInsecure, "keep_daily": keepDaily, "keep_weekly": keepWeekly,
		"keep_monthly": keepMonthly, "verify": verify, "updated_at": utcNow(),
	}
	if err := d.atomicJSON(pathTarget, record, 0o600); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "destination": d.publicDestination(record)}, nil
}

func (d *Daemon) deleteDestination(req map[string]any) (map[string]any, error) {
	name := destName(req["name"])
	pathTarget, err := d.destinationPath(name)
	if err != nil {
		return nil, err
	}
	removed := false
	for _, p := range []string{pathTarget, d.destFile(name, ".key"), d.destFile(name, ".known_hosts"),
		d.destFile(name, ".password"), d.destFile(name, ".secret")} {
		if os.Remove(p) == nil {
			removed = true
		}
	}
	return map[string]any{"ok": true, "deleted": removed}, nil
}

func (d *Daemon) sftpBaseCommand(record map[string]any, binary string) []string {
	name := pyStr(record["name"])
	cmd := []string{binary,
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + d.destFile(name, ".known_hosts"),
		"-o", "IdentitiesOnly=yes",
		"-o", "ConnectTimeout=20",
	}
	if destinationAuth(record) == "password" {
		cmd = append(cmd, "-o", "BatchMode=no", "-o", "PubkeyAuthentication=no",
			"-o", "PreferredAuthentications=password,keyboard-interactive",
			"-o", "NumberOfPasswordPrompts=1")
	} else {
		cmd = append(cmd, "-o", "BatchMode=yes", "-i", d.destFile(name, ".key"))
	}
	flag := "-p"
	if strings.HasSuffix(binary, "sftp") {
		flag = "-P"
	}
	return append(cmd, flag, strconv.FormatInt(intOr(record["port"], 22), 10))
}

func (d *Daemon) askpassPath() string { return filepath.Join(d.Opts.DestinationsDir, ".askpass") }

func (d *Daemon) ensureAskpass() error {
	path := d.askpassPath()
	if raw, err := os.ReadFile(path); err == nil && string(raw) == askpassContent {
		return os.Chmod(path, 0o700)
	}
	if err := d.ensureDestinationsDir(); err != nil {
		return err
	}
	if err := writePrivate(path, []byte(askpassContent)); err != nil {
		return err
	}
	return os.Chmod(path, 0o700)
}

func (d *Daemon) sftpEnvironment(record map[string]any) ([]string, error) {
	if destinationAuth(record) != "password" {
		return nil, nil
	}
	if err := d.ensureAskpass(); err != nil {
		return nil, err
	}
	display := os.Getenv("DISPLAY")
	if display == "" {
		display = ":0"
	}
	env := []string{}
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		switch k {
		case "SSH_ASKPASS", "SSH_ASKPASS_REQUIRE", "DISPLAY", "EASY_HA_PROXY_SFTP_PASSWORD_FILE":
			continue
		}
		env = append(env, kv)
	}
	return append(env, "SSH_ASKPASS="+d.askpassPath(), "SSH_ASKPASS_REQUIRE=force", "DISPLAY="+display,
		"EASY_HA_PROXY_SFTP_PASSWORD_FILE="+d.destFile(pyStr(record["name"]), ".password")), nil
}

type procResult struct {
	rc     int
	stdout []byte
	stderr []byte
}

func (d *Daemon) checked(record map[string]any, res procResult) procResult {
	if res.rc != 0 && hostKeyProblem(res.stderr) {
		res.stderr = []byte(d.noteHostKeyChange(record))
	}
	return res
}

func (d *Daemon) runSFTP(record map[string]any, batch string) (procResult, error) {
	env, err := d.sftpEnvironment(record)
	if err != nil {
		return procResult{}, err
	}
	argv := d.sftpBaseCommand(record, "/usr/bin/sftp")
	argv = append(argv, "-b", "-", "--", pyStr(record["user"])+"@"+pyStr(record["host"]))
	rc, out, errb, err := runCapture(time.Duration(d.Opts.SFTPTimeoutSeconds)*time.Second, []byte(batch), env, argv[0], argv[1:]...)
	if err != nil {
		return procResult{}, err
	}
	return d.checked(record, procResult{rc, out, errb}), nil
}

func (d *Daemon) runSSH(record map[string]any, remote []string) (procResult, error) {
	env, err := d.sftpEnvironment(record)
	if err != nil {
		return procResult{}, err
	}
	argv := d.sftpBaseCommand(record, "/usr/bin/ssh")
	argv = append(argv, "--", pyStr(record["user"])+"@"+pyStr(record["host"]))
	argv = append(argv, remote...)
	rc, out, errb, err := runCapture(time.Duration(d.Opts.SFTPTimeoutSeconds)*time.Second, []byte{}, env, argv[0], argv[1:]...)
	if err != nil {
		return procResult{}, err
	}
	return d.checked(record, procResult{rc, out, errb}), nil
}

func (d *Daemon) retrustDestination(req map[string]any) (map[string]any, error) {
	record, err := d.loadDestination(req["name"])
	if err != nil {
		return nil, err
	}
	if record["type"] != "sftp" {
		return nil, bErr("invalid", "only an SFTP destination has a host key")
	}
	kh, err := scanHostKey(pyStr(record["host"]), intOr(record["port"], 22))
	if err != nil {
		return nil, err
	}
	name := pyStr(record["name"])
	prints, err := d.pinHostKey(name, kh)
	if err != nil {
		return nil, err
	}
	printsAny := []any{}
	for _, p := range prints {
		printsAny = append(printsAny, p)
	}
	record["host_key_fingerprints"] = printsAny
	record["host_key_pinned"] = true
	record["host_key_source"] = "trusted-after-change"
	delete(record, "host_key_changed")
	record["updated_at"] = utcNow()
	path, _ := d.destinationPath(name)
	if err := d.atomicJSON(path, record, 0o600); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "destination": d.publicDestination(record)}, nil
}

// normalizeRemoteDir: absolute, relative, or "." for the session's start directory.
func normalizeRemoteDir(value any) (string, error) {
	text := strings.TrimSpace(pyStr(value))
	if text == "" || text == "." || text == "./" {
		return ".", nil
	}
	parts := []string{}
	for _, p := range strings.Split(text, "/") {
		if p != "" && p != "." {
			parts = append(parts, p)
		}
	}
	for _, p := range parts {
		if p == ".." {
			return "", bErr("invalid", "the remote path must be free of '..'")
		}
	}
	if len([]rune(text)) > 512 || hasControl(text) {
		return "", bErr("invalid", "the remote path must be free of '..'")
	}
	joined := strings.Join(parts, "/")
	if strings.HasPrefix(text, "/") {
		return "/" + joined, nil
	}
	if joined == "" {
		return ".", nil
	}
	return joined, nil
}

func remoteJoin(directory, name string) string {
	if directory == "" || directory == "." {
		return name
	}
	return strings.TrimRight(directory, "/") + "/" + name
}

func remoteQuote(value string) (string, error) {
	if hasControl(value) {
		return "", bErr("invalid", "the remote path contains control characters")
	}
	v := strings.ReplaceAll(value, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	return `"` + v + `"`, nil
}

// batch builds an sftp batch from format lines whose %q-style slots are
// remote-quoted paths.
func batchLine(cmd string, paths ...string) (string, error) {
	out := []string{cmd}
	for _, p := range paths {
		q, err := remoteQuote(p)
		if err != nil {
			return "", err
		}
		out = append(out, q)
	}
	return strings.Join(out, " ") + "\n", nil
}

func shlexQuote(s string) string {
	if s == "" {
		return "''"
	}
	if shlexSafeRe.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

func (d *Daemon) verifyRemoteCopy(record map[string]any, remoteFile, expected string, size int64) (bool, string, string, error) {
	mode := strings.ToLower(strings.TrimSpace(pyStr(record["verify"])))
	if mode == "" {
		mode = "auto"
	}
	if mode == "transfer" {
		return true, "transfer", "", nil
	}
	probe, err := d.runSSH(record, []string{"sha256sum", "--", shlexQuote(remoteFile)})
	if err != nil {
		return false, "", "", err
	}
	if probe.rc == 0 {
		answer := strings.Fields(strings.ToValidUTF8(string(probe.stdout), "�"))
		if len(answer) > 0 && sha256Re.MatchString(answer[0]) {
			if answer[0] == expected {
				return true, "remote-hash", "", nil
			}
			return false, "remote-hash", "the far end reports different content", nil
		}
	}
	if size > d.Opts.VerifyDownloadMaxBytes {
		return false, "none", "the far end cannot hash and the archive is too large to re-read", nil
	}
	work, err := os.MkdirTemp("", "backupd-verify-")
	if err != nil {
		return false, "", "", err
	}
	defer os.RemoveAll(work)
	local := filepath.Join(work, "verify.bin")
	line, err := batchLine("get", remoteFile, local)
	if err != nil {
		return false, "", "", err
	}
	res, err := d.runSFTP(record, line)
	if err != nil {
		return false, "", "", err
	}
	if _, serr := os.Stat(local); res.rc != 0 || serr != nil {
		return false, "download", "the copy could not be read back", nil
	}
	actual, err := sha256File(local)
	if err != nil {
		return false, "", "", err
	}
	if actual != expected {
		return false, "download", "the copy read back does not match", nil
	}
	return true, "download", "", nil
}

func (d *Daemon) remoteArchiveName(backupID, archive string) string {
	var created time.Time
	ok := false
	if meta, err := d.safeJSONFile(d.backupMetaPath(backupID)); err == nil {
		created, ok = parseISO(pyStr(meta["created_at"]))
	}
	if !ok {
		if fi, err := os.Stat(archive); err == nil {
			created = fi.ModTime()
		} else {
			created = time.Now()
		}
	}
	return remotePrefix + created.UTC().Format("20060102-150405") + "-" + backupID + ArchiveSuffix
}

func remoteChecksumBody(expected, remoteName string) []byte {
	return []byte(expected + "  " + remoteName + "\n")
}

func archiveNamesFrom(rows []string) []string {
	names := []string{}
	for _, row := range rows {
		candidate := strings.TrimSpace(row)
		if i := strings.LastIndex(candidate, "/"); i >= 0 {
			candidate = candidate[i+1:]
		}
		if strings.HasPrefix(candidate, remotePrefix) && strings.HasSuffix(candidate, ArchiveSuffix) {
			names = append(names, candidate)
		}
	}
	sort.Strings(names)
	return names
}

func (d *Daemon) remoteListing(record map[string]any) []string {
	line, err := batchLine("ls -1", pyStr(record["path"]))
	if err != nil {
		return []string{}
	}
	res, err := d.runSFTP(record, line)
	if err != nil || res.rc != 0 {
		return []string{}
	}
	return archiveNamesFrom(splitLines(strings.ToValidUTF8(string(res.stdout), "�")))
}

// retentionVictims: one per day as dailies, then one per ISO week, then one
// per month; only recognised dated copies can be victims.
func retentionVictims(names []string, record map[string]any) []string {
	sorted := append([]string{}, names...)
	sort.Strings(sorted)
	byDay := map[string]string{}
	dated := map[string]bool{}
	for _, name := range sorted {
		m := remoteDateRe.FindStringSubmatch(name)
		if m == nil {
			continue
		}
		y, _ := strconv.Atoi(m[1])
		mo, _ := strconv.Atoi(m[2])
		dd, _ := strconv.Atoi(m[3])
		t := time.Date(y, time.Month(mo), dd, 0, 0, 0, 0, time.UTC)
		if y < 1 || t.Year() != y || int(t.Month()) != mo || t.Day() != dd {
			continue
		}
		dated[name] = true
		byDay[m[1]+"-"+m[2]+"-"+m[3]] = name
	}
	days := make([]string, 0, len(byDay))
	for day := range byDay {
		days = append(days, day)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(days)))
	keep := map[string]bool{}
	daily := int(intOr(record["keep_daily"], 0))
	for i := 0; i < daily && i < len(days); i++ {
		keep[byDay[days[i]]] = true
	}
	weekly := int(intOr(record["keep_weekly"], 0))
	seenWeeks := map[string]bool{}
	for _, day := range days {
		t, _ := time.Parse("2006-01-02", day)
		y, w := t.ISOWeek()
		token := fmt.Sprintf("%d-%d", y, w)
		if seenWeeks[token] {
			continue
		}
		seenWeeks[token] = true
		if len(seenWeeks) <= weekly {
			keep[byDay[day]] = true
		}
	}
	monthly := int(intOr(record["keep_monthly"], 0))
	seenMonths := map[string]bool{}
	for _, day := range days {
		token := day[:7]
		if seenMonths[token] {
			continue
		}
		seenMonths[token] = true
		if len(seenMonths) <= monthly {
			keep[byDay[day]] = true
		}
	}
	victims := []string{}
	for _, name := range names {
		if dated[name] && !keep[name] {
			victims = append(victims, name)
		}
	}
	return victims
}

// ---------------------------------------------------------------------------
// S3-compatible destinations (SigV4)
// ---------------------------------------------------------------------------

func s3Quote(value string, keepSlash bool) string {
	allowed := s3Unreserved
	if keepSlash {
		allowed += "/"
	}
	var b strings.Builder
	for _, c := range []byte(value) {
		if strings.IndexByte(allowed, c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func s3SigningKey(secret, stamp, region string) []byte {
	key := []byte("AWS4" + secret)
	for _, part := range []string{stamp, region, s3Service, "aws4_request"} {
		key = hmacSHA256(key, part)
	}
	return key
}

func s3Authorization(method, canonicalURI, canonicalQuery string, headers map[string]string,
	payloadSHA, accessKey, secretKey, region, amzDate string) string {
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	var canonicalHeaders strings.Builder
	for _, n := range names {
		canonicalHeaders.WriteString(n + ":" + strings.Join(strings.Fields(headers[n]), " ") + "\n")
	}
	signedHeaders := strings.Join(names, ";")
	canonicalRequest := strings.Join([]string{method, canonicalURI, canonicalQuery,
		canonicalHeaders.String(), signedHeaders, payloadSHA}, "\n")
	stamp := amzDate[:8]
	scope := stamp + "/" + region + "/" + s3Service + "/aws4_request"
	sum := sha256.Sum256([]byte(canonicalRequest))
	toSign := strings.Join([]string{s3Algorithm, amzDate, scope, hex.EncodeToString(sum[:])}, "\n")
	signature := hex.EncodeToString(hmacSHA256(s3SigningKey(secretKey, stamp, region), toSign))
	return fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		s3Algorithm, accessKey, scope, signedHeaders, signature)
}

// idleConn applies the timeout per read/write, like a Python socket timeout.
type idleConn struct {
	net.Conn
	timeout time.Duration
}

func (c *idleConn) Read(b []byte) (int, error) {
	_ = c.Conn.SetDeadline(time.Now().Add(c.timeout))
	return c.Conn.Read(b)
}

func (c *idleConn) Write(b []byte) (int, error) {
	_ = c.Conn.SetDeadline(time.Now().Add(c.timeout))
	return c.Conn.Write(b)
}

func (d *Daemon) s3Request(record map[string]any, method, key string, query map[string]string,
	body io.Reader, bodySHA string, length int64) (int, []byte, error) {
	endpoint, err := url.Parse(pyStr(record["endpoint"]))
	if err != nil || (endpoint.Scheme != "https" && endpoint.Scheme != "http") || endpoint.Hostname() == "" {
		return 0, nil, bErr("invalid", "the endpoint must be http or https")
	}
	if endpoint.User != nil {
		return 0, nil, bErr("invalid", "the endpoint URL must not include credentials")
	}
	if err := validateS3EndpointHost(endpoint.Hostname()); err != nil {
		return 0, nil, err
	}
	if endpoint.Scheme == "http" && !truthy(record["allow_insecure"]) {
		return 0, nil, bErr("invalid", "the endpoint is plain http; enable 'allow insecure' only for a storage service on a trusted network")
	}
	rawSecret, err := os.ReadFile(d.destFile(pyStr(record["name"]), ".secret"))
	if err != nil {
		return 0, nil, err
	}
	secret := strings.TrimSpace(string(rawSecret))
	prefix := strings.Trim(pyStr(record["prefix"]), "/")
	segments := []string{}
	for _, s := range []string{pyStr(record["bucket"]), map[bool]string{true: prefix, false: ""}[key != ""], key} {
		if s != "" {
			segments = append(segments, s)
		}
	}
	canonicalURI := "/" + s3Quote(strings.Join(segments, "/"), true)
	qnames := make([]string, 0, len(query))
	for k := range query {
		qnames = append(qnames, k)
	}
	sort.Strings(qnames)
	qparts := []string{}
	for _, k := range qnames {
		qparts = append(qparts, s3Quote(k, false)+"="+s3Quote(query[k], false))
	}
	canonicalQuery := strings.Join(qparts, "&")
	amzDate := time.Now().UTC().Format("20060102T150405Z")
	payloadSHA := bodySHA
	if payloadSHA == "" {
		empty := sha256.Sum256(nil)
		payloadSHA = hex.EncodeToString(empty[:])
	}
	host := endpoint.Host
	headers := map[string]string{"host": host, "x-amz-content-sha256": payloadSHA, "x-amz-date": amzDate}
	region := pyStr(record["region"])
	if region == "" {
		region = "us-east-1"
	}
	authorization := s3Authorization(method, canonicalURI, canonicalQuery, headers, payloadSHA,
		pyStr(record["access_key"]), secret, region, amzDate)
	secret = ""
	timeout := time.Duration(d.Opts.S3TimeoutSeconds) * time.Second
	port := endpoint.Port()
	if port == "" {
		port = map[string]string{"https": "443", "http": "80"}[endpoint.Scheme]
	}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			pinned, err := resolveS3Address(ctx, endpoint.Hostname())
			if err != nil {
				return nil, err
			}
			dialer := net.Dialer{Timeout: timeout}
			conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(pinned, port))
			if err != nil {
				return nil, err
			}
			return &idleConn{Conn: conn, timeout: timeout}, nil
		},
		TLSClientConfig:    &tls.Config{ServerName: endpoint.Hostname(), MinVersion: tls.VersionTLS12},
		DisableCompression: true,
		DisableKeepAlives:  true,
	}
	defer transport.CloseIdleConnections()
	// Path is the decoded form and RawPath the exact signed one, so the
	// request line carries precisely what was signed.
	target := &url.URL{Scheme: endpoint.Scheme, Host: host, Path: "/" + strings.Join(segments, "/"),
		RawPath: canonicalURI, RawQuery: canonicalQuery}
	reqBody := body
	if reqBody == nil {
		reqBody = http.NoBody
	}
	req, err := http.NewRequest(method, target.String(), reqBody)
	if err != nil {
		return 0, nil, err
	}
	req.URL = target
	req.Host = host
	req.Header.Set("x-amz-content-sha256", payloadSHA)
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("Authorization", authorization)
	req.ContentLength = length
	if body == nil {
		req.ContentLength = 0
	}
	resp, err := (&http.Client{Transport: transport}).Do(req)
	if err != nil {
		var be *Error
		if errors.As(err, &be) {
			return 0, nil, be
		}
		return 0, nil, err
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	return resp.StatusCode, payload, nil
}

func (d *Daemon) s3Listing(record map[string]any) ([]string, error) {
	prefix := strings.Trim(pyStr(record["prefix"]), "/")
	query := map[string]string{"list-type": "2"}
	if prefix != "" {
		query["prefix"] = prefix + "/"
	}
	status, body, err := d.s3Request(record, "GET", "", query, nil, "", 0)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return []string{}, nil
	}
	rows := []string{}
	for _, m := range s3KeyRe.FindAllStringSubmatch(strings.ToValidUTF8(string(body), "�"), -1) {
		rows = append(rows, m[1])
	}
	return archiveNamesFrom(rows), nil
}

func (d *Daemon) s3Upload(record map[string]any, archive, remoteName, expected string) (map[string]any, error) {
	f, err := os.Open(archive)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	size := fi.Size()
	status, body, err := d.s3Request(record, "PUT", remoteName, nil, f, expected, size)
	_ = f.Close()
	if err != nil {
		return nil, err
	}
	if status != 200 && status != 201 {
		detail := truncRunes(strings.TrimSpace(strings.ToValidUTF8(string(body), "�")), 400)
		return nil, bErr("upstream", "the upload failed (%d): %s", status, detail)
	}
	payload := remoteChecksumBody(expected, remoteName)
	sum := sha256.Sum256(payload)
	if _, _, err := d.s3Request(record, "PUT", remoteName+".sha256", nil, bytes.NewReader(payload),
		hex.EncodeToString(sum[:]), int64(len(payload))); err != nil {
		return nil, err
	}
	return map[string]any{"bytes": size, "verified": true, "verified_by": "signed-put"}, nil
}

func (d *Daemon) s3Prune(record map[string]any, victims []string) ([]string, error) {
	removed := []string{}
	for _, name := range victims {
		for _, key := range []string{name, name + ".sha256"} {
			status, _, err := d.s3Request(record, "DELETE", key, nil, nil, "", 0)
			if err != nil {
				return removed, err
			}
			if (status == 200 || status == 204) && key == name {
				removed = append(removed, name)
			}
		}
	}
	return removed, nil
}

// sftpUploadLock keeps publication, verification and retention together per
// remote folder; the last user removes the entry.
func (d *Daemon) sftpUploadLock(record map[string]any) (func(), error) {
	dir, err := normalizeRemoteDir(record["path"])
	if err != nil {
		return nil, err
	}
	port := pyStr(record["port"])
	if port == "" {
		port = "22"
	}
	key := strings.Join([]string{strings.TrimRight(strings.ToLower(pyStr(record["host"])), "."),
		port, pyStr(record["user"]), dir}, "\x00")
	d.uploadMu.Lock()
	lock := d.uploads[key]
	if lock == nil {
		lock = &uploadLock{}
		d.uploads[key] = lock
	}
	lock.users++
	d.uploadMu.Unlock()
	lock.mu.Lock()
	return func() {
		lock.mu.Unlock()
		d.uploadMu.Lock()
		lock.users--
		if lock.users == 0 {
			delete(d.uploads, key)
		}
		d.uploadMu.Unlock()
	}, nil
}

func copyRecord(record map[string]any) map[string]any {
	out := make(map[string]any, len(record))
	for k, v := range record {
		out[k] = v
	}
	return out
}

func (d *Daemon) publishSFTPFile(record map[string]any, staging, final, expected string, size int64) (bool, error) {
	line, err := batchLine("rename", staging, final)
	if err != nil {
		return false, err
	}
	res, err := d.runSFTP(record, line)
	if err != nil {
		return false, err
	}
	if res.rc == 0 {
		return true, nil
	}
	auto := copyRecord(record)
	auto["verify"] = "auto"
	same, _, _, err := d.verifyRemoteCopy(auto, final, expected, size)
	if err != nil {
		return false, err
	}
	if same {
		return false, nil
	}
	detail := truncRunes(strings.TrimSpace(strings.ToValidUTF8(string(res.stderr), "�")), 500)
	return false, bErr("upstream", "the copy could not be published safely; an existing file was kept: %s", detail)
}

func (d *Daemon) uploadSFTPBackup(record map[string]any, backupID, archive, remoteName, expected string, size int64) (response map[string]any, retErr error) {
	remoteDir := pyStr(record["path"])
	remoteFile := remoteJoin(remoteDir, remoteName)
	token := uuidHex()
	staging := remoteFile + "." + token + ".part"
	stagingChecksum := remoteFile + ".sha256." + token + ".part"
	pending := map[string]bool{staging: true, stagingChecksum: true}
	checksumBody := remoteChecksumBody(expected, remoteName)
	response = map[string]any{"ok": true, "backup_id": backupID, "destination": record["name"],
		"bytes": size, "pruned": []string{}}
	destLabel := backupID + "@" + pyStr(record["name"])
	defer func() {
		left := []string{}
		for _, p := range []string{staging, stagingChecksum} {
			if pending[p] {
				left = append(left, p)
			}
		}
		if len(left) == 0 {
			return
		}
		var batch strings.Builder
		for _, p := range left {
			line, err := batchLine("-rm", p)
			if err == nil {
				batch.WriteString(line)
			}
		}
		if _, err := d.runSFTP(record, batch.String()); err != nil {
			log.Printf("Could not clean up temporary upload for %s", pyStr(record["name"]))
		}
	}()
	failed := func(err error) (map[string]any, error) {
		detail := truncRunes(err.Error(), 500)
		d.reportAlert("backup.failed", destLabel, "The off-host copy of the backup failed", detail)
		return nil, bErr("upstream", "the upload failed: %s", detail)
	}
	work, err := os.MkdirTemp("", "backupd-upload-")
	if err != nil {
		return failed(err)
	}
	checksumCopy := filepath.Join(work, remoteName+".sha256")
	if err := os.WriteFile(checksumCopy, checksumBody, 0o600); err != nil {
		_ = os.RemoveAll(work)
		return failed(err)
	}
	var batch strings.Builder
	for _, l := range [][]string{{"-mkdir", remoteDir}, {"put", archive, staging}, {"put", checksumCopy, stagingChecksum}} {
		line, err := batchLine(l[0], l[1:]...)
		if err != nil {
			_ = os.RemoveAll(work)
			return failed(err)
		}
		batch.WriteString(line)
	}
	res, err := d.runSFTP(record, batch.String())
	_ = os.RemoveAll(work)
	if err != nil {
		return failed(err)
	}
	if res.rc != 0 {
		detail := truncRunes(strings.TrimSpace(strings.ToValidUTF8(string(res.stderr), "�")), 500)
		return failed(bErr("upstream", "the upload failed: %s", detail))
	}
	verified, method, detail, err := d.verifyRemoteCopy(record, staging, expected, size)
	if err != nil {
		return failed(err)
	}
	response["verified"] = verified
	response["verified_by"] = method
	if !verified {
		response["ok"] = false
		if detail == "" {
			detail = "the copy could not be verified"
		}
		response["error"] = detail
		d.reportAlert("backup.failed", destLabel, "The off-host copy could not be verified", detail)
		return response, nil
	}
	moved, err := d.publishSFTPFile(record, staging, remoteFile, expected, size)
	if err != nil {
		return failed(err)
	}
	if moved {
		delete(pending, staging)
	}
	sum := sha256.Sum256(checksumBody)
	moved, err = d.publishSFTPFile(record, stagingChecksum, remoteFile+".sha256", hex.EncodeToString(sum[:]), int64(len(checksumBody)))
	if err != nil {
		return failed(err)
	}
	if moved {
		delete(pending, stagingChecksum)
	}
	victims := retentionVictims(d.remoteListing(record), record)
	if len(victims) > 0 {
		var prune strings.Builder
		for _, name := range victims {
			for _, p := range []string{remoteJoin(remoteDir, name), remoteJoin(remoteDir, name+".sha256")} {
				line, err := batchLine("-rm", p)
				if err != nil {
					return failed(err)
				}
				prune.WriteString(line)
			}
		}
		if _, err := d.runSFTP(record, prune.String()); err != nil {
			return failed(err)
		}
		response["pruned"] = victims
	}
	return response, nil
}

func (d *Daemon) uploadBackup(req map[string]any) (map[string]any, error) {
	backupID, err := identifier(req["backup_id"], "backup id")
	if err != nil {
		return nil, err
	}
	record, err := d.loadDestination(req["destination"])
	if err != nil {
		return nil, err
	}
	archive := d.backupArchivePath(backupID)
	checksum := d.backupChecksumPath(backupID)
	fi, err := os.Stat(archive)
	if err != nil || !fi.Mode().IsRegular() {
		return nil, bErr("not_found", "no such backup")
	}
	expected := ""
	if ci, err := os.Stat(checksum); err == nil && ci.Mode().IsRegular() {
		info, err := lstatInfo(checksum)
		if err != nil {
			return nil, err
		}
		expected, err = readChecksumFile(checksum, info)
		if err != nil {
			return nil, err
		}
	}
	if expected == "" {
		if expected, err = sha256File(archive); err != nil {
			return nil, err
		}
	}
	size := fi.Size()
	remoteName := d.remoteArchiveName(backupID, archive)
	if record["type"] == "s3" {
		outcome, err := d.s3Upload(record, archive, remoteName, expected)
		if err != nil {
			return nil, err
		}
		response := map[string]any{"ok": true, "backup_id": backupID, "destination": record["name"], "pruned": []string{}}
		for k, v := range outcome {
			response[k] = v
		}
		listing, err := d.s3Listing(record)
		if err != nil {
			return nil, err
		}
		if victims := retentionVictims(listing, record); len(victims) > 0 {
			pruned, err := d.s3Prune(record, victims)
			if err != nil {
				return nil, err
			}
			response["pruned"] = pruned
		}
		return response, nil
	}
	unlock, err := d.sftpUploadLock(record)
	if err != nil {
		return nil, err
	}
	defer unlock()
	return d.uploadSFTPBackup(record, backupID, archive, remoteName, expected, size)
}

func (d *Daemon) testDestination(req map[string]any) (map[string]any, error) {
	record, err := d.loadDestination(req["name"])
	if err != nil {
		return nil, err
	}
	if record["type"] == "s3" {
		status, body, err := d.s3Request(record, "GET", "", map[string]string{"list-type": "2", "max-keys": "1"}, nil, "", 0)
		if err != nil {
			var be *Error
			if errors.As(err, &be) {
				return map[string]any{"ok": false, "error": be.Msg}, nil
			}
			return nil, err
		}
		if status != 200 {
			return map[string]any{"ok": false, "error": fmt.Sprintf("the storage service answered %d: ", status) +
				truncRunes(strings.TrimSpace(strings.ToValidUTF8(string(body), "�")), 300)}, nil
		}
		return map[string]any{"ok": true, "destination": record["name"]}, nil
	}
	path := pyStr(record["path"])
	marker := remoteJoin(path, ".easy-ha-proxy-write-test")
	work, err := os.MkdirTemp("", "backupd-test-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(work)
	probe := filepath.Join(work, "probe")
	if err := os.WriteFile(probe, []byte(utcNow()+"\n"), 0o600); err != nil {
		return nil, err
	}
	var batch strings.Builder
	for _, l := range [][]string{{"-mkdir", path}, {"put", probe, marker}, {"rm", marker}} {
		line, err := batchLine(l[0], l[1:]...)
		if err != nil {
			return nil, err
		}
		batch.WriteString(line)
	}
	res, err := d.runSFTP(record, batch.String())
	if err != nil {
		return nil, err
	}
	if res.rc != 0 {
		return map[string]any{"ok": false, "error": truncRunes(strings.TrimSpace(strings.ToValidUTF8(string(res.stderr), "�")), 500)}, nil
	}
	if truthy(record["host_key_changed"]) {
		delete(record, "host_key_changed")
		if p, err := d.destinationPath(record["name"]); err == nil {
			if err := d.atomicJSON(p, record, 0o600); err != nil {
				return nil, err
			}
		}
	}
	return map[string]any{"ok": true, "destination": record["name"]}, nil
}
