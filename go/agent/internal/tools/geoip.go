package tools

// The Go port of update_geoip.py: DB-IP Country Lite downloaded, checked and
// turned into per-country CIDR files and allowed.geo (IPv4 and IPv6, as the
// maxminddb reader yields them, collapsed like ipaddress.collapse_addresses),
// published as an immutable release with the same state.json, switched with
// a HAProxy validation, reload and critical-service probe that rolls back,
// and --configure-selection updating vars.yml and selection.json as one
// transaction.

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"easy-ha-proxy/panel/shared/pyyaml"
)

const (
	geoipDatabaseName     = "dbip-country-lite.mmdb"
	geoipAllowedName      = "allowed.geo"
	geoipStateName        = "state.json"
	geoipReleaseFormat    = 1
	geoipMaxCompressed    = 64 * 1024 * 1024
	geoipMaxDatabase      = 128 * 1024 * 1024
	geoipMaxSelection     = 16 * 1024
	geoipMaxTransaction   = 20 * 1024 * 1024
	geoipMinDatabaseNodes = 10000
)

var (
	geoipActiveStates = map[string]bool{"prepared": true, "pending_confirmation": true, "rolling_back": true, "rollback_failed": true}
	geoipControlACL   = regexp.MustCompile(`(?m)^\s*acl\s+(host_admin|host_authelia)\s+hdr\(host\)\s+-i\s+(.+?)\s*$`)
	geoipProbeMarkers = []*regexp.Regexp{
		regexp.MustCompile(`(?m)^\s*acl\s+local_control_plane_probe\s+src\s+127\.0\.0\.1\s*$`),
		regexp.MustCompile(`(?m)^\s*acl\s+admin_control_plane_probe_path\s+path\s+-i\s+/api/control-plane-health\s*$`),
		regexp.MustCompile(`(?m)^\s*acl\s+admin_control_plane_probe\s+var\(txn\.admin_control_plane_probe\)\s+-m\s+bool\s*$`),
		regexp.MustCompile(`(?m)^\s*http-request\s+set-header\s+Remote-User\s+easy-ha-proxy-healthcheck\s+if\s+host_admin\s+admin_control_plane_probe\s*$`),
	}
	geoipControlPaths = map[string][2]string{"host_admin": {"admin", "/api/control-plane-health"}, "host_authelia": {"authelia", "/api/health"}}
	geoipDomainRE     = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	geoipCountryCode  = regexp.MustCompile(`^[A-Z]{2}$`)
	geoipCountryFile  = regexp.MustCompile(`^[A-Z][A-Z]\.cidr$`)
	geoipLegacyFile   = regexp.MustCompile(`^[A-Za-z]{2}\.cidr$`)
	geoipHTTPStatus   = regexp.MustCompile(`^HTTP/\d(?:\.\d)?\s+(\d{3})(?:\s+.*)?$`)
	geoipSafePeriod   = regexp.MustCompile(`[^0-9A-Za-z_-]`)
	geoipMMDBMarker   = []byte("\xab\xcd\xefMaxMind.com")
)

type geoipError struct{ msg string }

func (e *geoipError) Error() string { return e.msg }

func gerr(format string, args ...any) error { return &geoipError{fmt.Sprintf(format, args...)} }

func geoipLog(w io.Writer, msg string) { fmt.Fprintf(w, "[easy-ha-proxy-geoip] %s\n", msg) }

// GeoIPArgs are update_geoip.py's arguments.
type GeoIPArgs struct {
	Directory, BaseURL, SelectionFile, TransactionState, TransactionID string
	VarsFile, HAProxy, HAProxyConfig, Systemctl                        string
	ConfigureSelection, AccessFilterEnabled, ForceDownload, SkipReload bool
	Countries                                                          []string
	Out                                                                io.Writer
	Now                                                                func() time.Time
}

func sha256File(path string) (string, error) {
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

func fileMatchesSHA256(path string, expected any) bool {
	v := strings.ToLower(strings.TrimSpace(pyStrOrEmpty(expected)))
	if len(v) != 64 || strings.Trim(v, "0123456789abcdef") != "" {
		return false
	}
	got, err := sha256File(path)
	return err == nil && got == v
}

func pyStrOrEmpty(v any) string {
	if !pyTruthy(v) {
		return ""
	}
	return pyStrValue(v)
}

func countryACLHashes(release string) (map[string]string, error) {
	ents, err := os.ReadDir(release)
	if err != nil {
		return nil, err
	}
	names := []string{}
	for _, e := range ents {
		if geoipCountryFile.MatchString(e.Name()) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	out := map[string]string{}
	for _, n := range names {
		h, err := sha256File(filepath.Join(release, n))
		if err != nil {
			return nil, err
		}
		out[n] = h
	}
	return out, nil
}

func countryACLsMatch(release string, expected any) bool {
	m, ok := expected.(*pyyaml.Map)
	if !ok {
		return false
	}
	got, err := countryACLHashes(release)
	if err != nil || len(got) != m.Len() {
		return false
	}
	for k, v := range got {
		if m.Value(k) != v {
			return false
		}
	}
	return true
}

func sameHashes(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func readGeoState(path string) *pyyaml.Map {
	raw, err := os.ReadFile(path)
	if err != nil {
		return pyyaml.NewMap()
	}
	v, err := pyyaml.JSONLoads(raw)
	if err != nil {
		return pyyaml.NewMap()
	}
	if m, ok := v.(*pyyaml.Map); ok {
		return m
	}
	return pyyaml.NewMap()
}

func releasePayloadMatches(release, dbSHA, allowedSHA string, countrySHA map[string]string) bool {
	st := readGeoState(filepath.Join(release, geoipStateName))
	if n, ok := st.Value("release_format_version").(int64); !ok || n != geoipReleaseFormat {
		return false
	}
	return strings.ToLower(pyStrOrEmpty(st.Value("database_sha256"))) == dbSHA &&
		strings.ToLower(pyStrOrEmpty(st.Value("allowed_sha256"))) == allowedSHA &&
		fileMatchesSHA256(filepath.Join(release, geoipDatabaseName), dbSHA) &&
		fileMatchesSHA256(filepath.Join(release, geoipAllowedName), allowedSHA) &&
		countryACLsMatch(release, st.Value("country_sha256")) && mapEqualsHashes(st.Value("country_sha256"), countrySHA)
}

func mapEqualsHashes(v any, want map[string]string) bool {
	m, ok := v.(*pyyaml.Map)
	if !ok || m.Len() != len(want) {
		return false
	}
	for k, val := range want {
		if m.Value(k) != val {
			return false
		}
	}
	return true
}

// normalizeCountries is normalize_countries.
func normalizeCountries(values []string) ([]string, error) {
	set := map[string]bool{}
	for _, raw := range values {
		for _, v := range strings.Split(raw, ",") {
			code := strings.ToUpper(strings.TrimSpace(v))
			if code == "" {
				continue
			}
			if !geoipCountryCode.MatchString(code) {
				return nil, gerr("invalid ISO country code: %s", pyRepr(v))
			}
			set[code] = true
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

func loadGeoSelection(path string) ([]string, bool, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, gerr("GeoIP selection file is missing: %s", path)
		}
		return nil, false, err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		return nil, false, gerr("GeoIP selection must be a regular file")
	}
	if fi.Size() <= 0 || fi.Size() > geoipMaxSelection {
		return nil, false, gerr("GeoIP selection has an invalid size")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false, gerr("cannot read GeoIP selection: %v", err)
	}
	v, err := pyyaml.JSONLoads(raw)
	if err != nil {
		return nil, false, gerr("cannot read GeoIP selection: %v", err)
	}
	m, ok := v.(*pyyaml.Map)
	if !ok || m.Len() != 3 || !hasKeys(m, "version", "countries", "access_filter_enabled") {
		return nil, false, gerr("GeoIP selection has an invalid format")
	}
	if n, ok := m.Value("version").(int64); !ok || n != 1 {
		return nil, false, gerr("unsupported GeoIP selection version")
	}
	list, ok := m.Value("countries").([]any)
	strs := []string{}
	for _, c := range list {
		s, isStr := c.(string)
		if !isStr {
			ok = false
			break
		}
		strs = append(strs, s)
	}
	if !ok {
		return nil, false, gerr("GeoIP selection countries must be a list of strings")
	}
	enabled, ok := m.Value("access_filter_enabled").(bool)
	if !ok {
		return nil, false, gerr("GeoIP selection access_filter_enabled must be boolean")
	}
	countries, err := normalizeCountries(strs)
	return countries, enabled, err
}

func hasKeys(m *pyyaml.Map, keys ...string) bool {
	for _, k := range keys {
		if _, ok := m.Get(k); !ok {
			return false
		}
	}
	return true
}

func verifyTransactionAccess(statePath, id string) error {
	if statePath == "" {
		return nil
	}
	fi, err := os.Lstat(statePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		return gerr("HAProxy config transaction state is unsafe")
	}
	if fi.Size() <= 0 || fi.Size() > geoipMaxTransaction {
		return gerr("HAProxy config transaction state has an invalid size")
	}
	raw, err := os.ReadFile(statePath)
	if err != nil {
		return gerr("HAProxy config transaction state is invalid")
	}
	v, err := pyyaml.JSONLoads(raw)
	m, ok := v.(*pyyaml.Map)
	if err != nil || !ok {
		return gerr("HAProxy config transaction state is invalid")
	}
	if s, _ := m.Value("state").(string); !geoipActiveStates[s] {
		return nil
	}
	expected := pyStrOrEmpty(m.Value("transaction_id"))
	if expected != "" && id != "" && expected == id {
		return nil
	}
	return gerr("a HAProxy configuration transaction is active; GeoIP update deferred")
}

func openManagedDir(path string) (int, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, gerr("managed directory is unavailable or unsafe: %s", path)
	}
	return fd, nil
}

func readManaged(path string, maximum int64) ([]byte, error) {
	dfd, err := openManagedDir(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer syscall.Close(dfd)
	ffd, err := openat(dfd, filepath.Base(path), syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		if err == syscall.ENOENT {
			return []byte{}, nil
		}
		return nil, gerr("cannot safely open managed file %s: %s", path, osErrorText(filepath.Base(path), err))
	}
	f := os.NewFile(uintptr(ffd), path)
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, gerr("managed file is not a regular file: %s", path)
	}
	if fi.Size() < 0 || fi.Size() > maximum {
		return nil, gerr("managed file has an invalid size: %s", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, gerr("managed file has an invalid size: %s", path)
	}
	return data, nil
}

func openat(dirfd int, name string, flags int, mode uint32) (int, error) {
	return unix.Openat(dirfd, name, flags, mode)
}

func atomicWriteManaged(path string, content []byte, defaultMode os.FileMode) error {
	dir := filepath.Dir(path)
	dfd, err := openManagedDir(dir)
	if err != nil {
		return err
	}
	syscall.Close(dfd)
	var st syscall.Stat_t
	hasCurrent := false
	if err := syscall.Lstat(path, &st); err == nil {
		if st.Mode&syscall.S_IFMT == syscall.S_IFLNK {
			return gerr("managed file is unavailable or unsafe: %s", path)
		}
		if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
			return gerr("managed file is not a regular file: %s", path)
		}
		hasCurrent = true
	}
	tmp := filepath.Join(dir, fmt.Sprintf(".%s.%d.%d.tmp", filepath.Base(path), os.Getpid(), time.Now().UnixNano()))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	fail := func(err error) error {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if _, err := f.Write(content); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	mode := uint32(defaultMode)
	if hasCurrent {
		mode = st.Mode & 0o7777
	}
	if err := syscall.Fchmod(int(f.Fd()), mode); err != nil {
		return fail(err)
	}
	if hasCurrent {
		if err := syscall.Fchown(int(f.Fd()), int(st.Uid), int(st.Gid)); err != nil && !(err == syscall.EPERM && os.Geteuid() != 0) {
			return fail(err)
		}
	}
	f.Close()
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	fsyncPath(dir)
	return nil
}

func fsyncPath(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
}

func restoreManaged(path string, content []byte, mode os.FileMode) error {
	if len(content) > 0 {
		return atomicWriteManaged(path, content, mode)
	}
	dirFD, err := openManagedDir(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer syscall.Close(dirFD)
	if err := unix.Unlinkat(dirFD, filepath.Base(path), 0); err != nil && !os.IsNotExist(err) {
		return err
	}
	_ = syscall.Fsync(dirFD)
	return nil
}

// selectionJSON is json.dumps(selection, indent=2, sort_keys=True) + "\n".
func selectionJSON(countries []string, enabled bool) []byte {
	var b strings.Builder
	b.WriteString("{\n  \"access_filter_enabled\": ")
	b.WriteString(strconv.FormatBool(enabled))
	b.WriteString(",\n  \"countries\": ")
	if len(countries) == 0 {
		b.WriteString("[]")
	} else {
		b.WriteString("[\n")
		for i, c := range countries {
			b.WriteString("    \"" + c + "\"")
			if i < len(countries)-1 {
				b.WriteString(",")
			}
			b.WriteString("\n")
		}
		b.WriteString("  ]")
	}
	b.WriteString(",\n  \"version\": 1\n}\n")
	return []byte(b.String())
}

func (a *GeoIPArgs) configureSelection() error {
	if a.SelectionFile == "" || a.VarsFile == "" {
		return gerr("--selection-file and --vars-file are required for configuration")
	}
	countries, err := normalizeCountries(a.Countries)
	if err != nil {
		return err
	}
	varsDir := filepath.Dir(a.VarsFile)
	dfd, err := openManagedDir(varsDir)
	if err != nil {
		return err
	}
	lfd, err := openat(dfd, ".vars.yml.lock", syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o640)
	syscall.Close(dfd)
	if err != nil {
		return gerr("cannot safely open the vars.yml lock")
	}
	defer syscall.Close(lfd)
	if err := syscall.Flock(lfd, syscall.LOCK_EX); err != nil {
		return err
	}
	oldVars, err := readManaged(a.VarsFile, 2*1024*1024)
	if err != nil {
		return err
	}
	oldSelection, err := readManaged(a.SelectionFile, geoipMaxSelection)
	if err != nil {
		return err
	}
	if len(oldVars) == 0 {
		return gerr("runtime vars.yml is missing or empty: %s", a.VarsFile)
	}
	if !utf8Valid(oldVars) {
		return gerr("runtime vars.yml is invalid: 'utf-8' codec can't decode the file")
	}
	v, err := pyyaml.Load(oldVars)
	if err != nil {
		return gerr("runtime vars.yml is invalid: %v", err)
	}
	if !pyTruthy(v) {
		v = pyyaml.NewMap()
	}
	values, ok := v.(*pyyaml.Map)
	if !ok {
		return gerr("runtime vars.yml root must be a mapping")
	}
	enabledV, present := values.Get("enable_geoip")
	if !present {
		enabledV = false
	}
	enabled, ok := enabledV.(bool)
	if !ok {
		return gerr("enable_geoip in runtime vars.yml must be boolean")
	}
	prevRaw := values.Value("geoip_country_codes")
	if !pyTruthy(prevRaw) {
		prevRaw = []any{}
	}
	prevList, ok := prevRaw.([]any)
	prevStrs := []string{}
	for _, x := range prevList {
		s, isStr := x.(string)
		if !isStr {
			ok = false
			break
		}
		prevStrs = append(prevStrs, s)
	}
	if !ok {
		return gerr("geoip_country_codes in runtime vars.yml must be a list")
	}
	previous, err := normalizeCountries(prevStrs)
	if err != nil {
		return err
	}
	if len(oldSelection) == 0 {
		oldSelection = selectionJSON(previous, enabled)
	}
	if enabled && len(countries) == 0 {
		return gerr("at least one country is required while global GeoIP filtering is enabled")
	}
	list := make([]any, len(countries))
	for i, c := range countries {
		list[i] = c
	}
	values.Set("geoip_country_codes", list)
	newVarsText, err := pyyaml.Dump(values, pyyaml.Options{AllowUnicode: true, Width: 1000})
	if err != nil {
		return err
	}
	newSelection := selectionJSON(countries, enabled)
	unlock, err := geoipLock(resolveDir(a.Directory))
	if err != nil {
		return err
	}
	defer unlock()
	applyErr := func() error {
		if err := atomicWriteManaged(a.VarsFile, []byte(newVarsText), 0o640); err != nil {
			return err
		}
		if err := atomicWriteManaged(a.SelectionFile, newSelection, 0o644); err != nil {
			return err
		}
		return a.update(true)
	}()
	if applyErr == nil {
		return nil
	}
	rollback := []string{}
	if err := restoreManaged(a.VarsFile, oldVars, 0o640); err != nil {
		rollback = append(rollback, "vars.yml restore failed: "+err.Error())
	}
	if err := restoreManaged(a.SelectionFile, oldSelection, 0o644); err != nil {
		rollback = append(rollback, "selection restore failed: "+err.Error())
	}
	if len(rollback) == 0 && len(oldSelection) > 0 {
		if err := a.update(true); err != nil {
			rollback = append(rollback, "active ACL restore failed: "+err.Error())
		}
	}
	detail := "GeoIP selection update failed: " + applyErr.Error()
	if len(rollback) > 0 {
		detail += "; rollback incomplete: " + strings.Join(rollback, "; ")
	} else {
		detail += "; previous selection and active ACL were restored"
	}
	return gerr("%s", detail)
}

func utf8Valid(b []byte) bool { return strings.ToValidUTF8(string(b), "\x00\x01") == string(b) }

func resolveDir(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	if r, err := filepath.EvalSymlinks(abs); err == nil {
		return r
	}
	return abs
}

func geoipLock(dir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, ".update.lock"), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, gerr("another GeoIP update is already running")
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}

func monthCandidates(now time.Time, count int) []string {
	y, m := now.Year(), int(now.Month())
	out := []string{}
	for i := 0; i < count; i++ {
		out = append(out, fmt.Sprintf("%04d-%02d", y, m))
		m--
		if m == 0 {
			m, y = 12, y-1
		}
	}
	return out
}

func activeRelease(dir string) (string, error) {
	resolved, err := filepath.EvalSymlinks(filepath.Join(dir, "current"))
	if err != nil {
		return "", nil
	}
	releases := resolveDir(filepath.Join(dir, "releases"))
	if resolved != releases && !strings.HasPrefix(resolved, releases+"/") {
		return "", gerr("current GeoIP release points outside releases/")
	}
	return resolved, nil
}

// ---------------------------------------------------------------------------
// MaxMind DB reader
// ---------------------------------------------------------------------------

type mmdb struct {
	data         []byte
	nodeCount    uint64
	recordSize   uint64
	ipVersion    uint64
	treeSize     int
	ipv4Start    uint64
	databaseType string
	buildEpoch   uint64
}

func openMMDBFile(path string) (*mmdb, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, gerr("GeoIP database is missing or unreadable: %s", path)
	}
	defer func() { _ = file.Close() }()
	fi, err := file.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Size() <= 0 || fi.Size() > geoipMaxDatabase {
		return nil, gerr("GeoIP database is not a regular file of an accepted size: %s", path)
	}
	raw, err := io.ReadAll(io.LimitReader(file, geoipMaxDatabase+1))
	if err != nil {
		return nil, gerr("invalid MMDB database %s: %v", path, err)
	}
	if len(raw) > geoipMaxDatabase {
		return nil, gerr("GeoIP database exceeds its size limit: %s", path)
	}
	r, err := parseMMDB(raw)
	if err != nil {
		return nil, gerr("invalid MMDB database %s: %v", path, err)
	}
	if !strings.Contains(strings.ToLower(r.databaseType), "country") || r.nodeCount < geoipMinDatabaseNodes {
		return nil, gerr("unexpected MMDB metadata: type=%s, nodes=%d", pyRepr(r.databaseType), r.nodeCount)
	}
	return r, nil
}

func parseMMDB(raw []byte) (*mmdb, error) {
	idx := bytes.LastIndex(raw, geoipMMDBMarker)
	if idx < 0 {
		return nil, errors.New("Error opening database file. Is this a valid MaxMind DB file?")
	}
	r := &mmdb{data: raw}
	meta, _, err := r.decode(idx+len(geoipMMDBMarker), idx+len(geoipMMDBMarker))
	if err != nil {
		return nil, err
	}
	m, ok := meta.(map[string]any)
	if !ok {
		return nil, errors.New("invalid metadata")
	}
	u := func(k string) uint64 { n, _ := m[k].(uint64); return n }
	r.nodeCount, r.recordSize, r.ipVersion, r.buildEpoch = u("node_count"), u("record_size"), u("ip_version"), u("build_epoch")
	r.databaseType, _ = m["database_type"].(string)
	if r.recordSize != 24 && r.recordSize != 28 && r.recordSize != 32 {
		return nil, fmt.Errorf("Unknown record size: %d", r.recordSize)
	}
	nodeBytes := r.recordSize / 4
	if r.nodeCount == 0 || idx < 16 || r.nodeCount > uint64(idx-16)/nodeBytes {
		return nil, errors.New("truncated search tree")
	}
	if r.ipVersion != 4 && r.ipVersion != 6 {
		return nil, errors.New("unsupported IP version")
	}
	r.treeSize = int(r.nodeCount * nodeBytes)
	r.data = raw[:idx]
	if r.ipVersion == 6 {
		node := uint64(0)
		for i := 0; i < 96 && node < r.nodeCount; i++ {
			node = r.readNode(node, 0)
		}
		r.ipv4Start = node
	}
	return r, nil
}

func (r *mmdb) readNode(node uint64, bit int) uint64 {
	nb := int(r.recordSize / 4)
	off := int(node) * nb
	d := r.data
	switch r.recordSize {
	case 24:
		o := off + bit*3
		return uint64(d[o])<<16 | uint64(d[o+1])<<8 | uint64(d[o+2])
	case 28:
		mid := uint64(d[off+3])
		if bit == 0 {
			return (mid>>4)<<24 | uint64(d[off])<<16 | uint64(d[off+1])<<8 | uint64(d[off+2])
		}
		return (mid&0x0f)<<24 | uint64(d[off+4])<<16 | uint64(d[off+5])<<8 | uint64(d[off+6])
	}
	o := off + bit*4
	return uint64(binary.BigEndian.Uint32(d[o : o+4]))
}

func (r *mmdb) decode(off, base int) (any, int, error) {
	budget := 1 << 20
	return r.decodeAt(off, base, 0, &budget)
}

func (r *mmdb) decodeAt(off, base, depth int, budget *int) (any, int, error) {
	d := r.data
	*budget--
	if depth > 32 || *budget < 0 || off < 0 || off >= len(d) {
		return nil, off, errors.New("unexpected end of data")
	}
	ctrl := d[off]
	off++
	typ := int(ctrl >> 5)
	if typ == 1 {
		size := int((ctrl >> 3) & 0x3)
		if size+1 > len(d)-off {
			return nil, off, errors.New("truncated pointer")
		}
		v := int(ctrl & 0x7)
		var p int
		switch size {
		case 0:
			p = v<<8 | int(d[off])
			off++
		case 1:
			p = (v<<16 | int(d[off])<<8 | int(d[off+1])) + 2048
			off += 2
		case 2:
			p = (v<<24 | int(d[off])<<16 | int(d[off+1])<<8 | int(d[off+2])) + 526336
			off += 3
		default:
			p = int(binary.BigEndian.Uint32(d[off : off+4]))
			off += 4
		}
		if p < 0 || p >= len(d)-base {
			return nil, off, errors.New("pointer outside data section")
		}
		val, _, err := r.decodeAt(base+p, base, depth+1, budget)
		return val, off, err
	}
	if typ == 0 {
		if off == len(d) {
			return nil, off, errors.New("truncated extended type")
		}
		typ = int(d[off]) + 7
		off++
	}
	size := int(ctrl & 0x1f)
	if typ != 14 {
		if size >= 29 && size-28 > len(d)-off {
			return nil, off, errors.New("truncated size")
		}
		switch size {
		case 29:
			size = 29 + int(d[off])
			off++
		case 30:
			size = 285 + int(binary.BigEndian.Uint16(d[off:off+2]))
			off += 2
		case 31:
			size = 65821 + (int(d[off])<<16 | int(d[off+1])<<8 | int(d[off+2]))
			off += 3
		}
	}
	if size > len(d)-off && typ != 7 && typ != 11 && typ != 14 {
		return nil, off, errors.New("unexpected end of data")
	}
	switch typ {
	case 2:
		*budget -= size
		if *budget < 0 {
			return nil, off, errors.New("MMDB decode budget exceeded")
		}
		return string(d[off : off+size]), off + size, nil
	case 3:
		if size != 8 {
			return nil, off, errors.New("invalid double length")
		}
		return math.Float64frombits(binary.BigEndian.Uint64(d[off : off+8])), off + 8, nil
	case 4:
		return d[off : off+size], off + size, nil
	case 5, 6, 9:
		var u uint64
		for i := 0; i < size; i++ {
			u = u<<8 | uint64(d[off+i])
		}
		return u, off + size, nil
	case 10:
		n := new(big.Int).SetBytes(d[off : off+size])
		if n.IsUint64() {
			return n.Uint64(), off + size, nil
		}
		return n, off + size, nil
	case 8:
		var u uint32
		for i := 0; i < size; i++ {
			u = u<<8 | uint32(d[off+i])
		}
		return int64(int32(u)), off + size, nil
	case 7:
		if size > (len(d)-off)/2 || size > *budget/2 {
			return nil, off, errors.New("invalid container length")
		}
		m := make(map[string]any, min(size, 256))
		for i := 0; i < size; i++ {
			k, next, err := r.decodeAt(off, base, depth+1, budget)
			if err != nil {
				return nil, next, err
			}
			v, next2, err := r.decodeAt(next, base, depth+1, budget)
			if err != nil {
				return nil, next2, err
			}
			if ks, ok := k.(string); ok {
				m[ks] = v
			}
			off = next2
		}
		return m, off, nil
	case 11:
		if size > (len(d)-off) || size > *budget {
			return nil, off, errors.New("invalid container length")
		}
		arr := make([]any, size)
		for i := 0; i < size; i++ {
			v, next, err := r.decodeAt(off, base, depth+1, budget)
			if err != nil {
				return nil, next, err
			}
			arr[i] = v
			off = next
		}
		return arr, off, nil
	case 14:
		return size != 0, off, nil
	case 15:
		if size != 4 {
			return nil, off, errors.New("invalid float length")
		}
		return float64(math.Float32frombits(binary.BigEndian.Uint32(d[off : off+4]))), off + 4, nil
	}
	return nil, off + size, nil
}

type mmdbNetwork struct {
	v6     bool
	addr   *big.Int
	prefix int
}

// each is maxminddb Reader.__iter__: networks in tree order, IPv4 subtree
// reported as IPv4, aliases of it skipped.
func (r *mmdb) each(f func(n mmdbNetwork, record any) error) error {
	bits := 32
	if r.ipVersion == 6 {
		bits = 128
	}
	ipv4Max := new(big.Int).SetUint64(math.MaxUint32)
	remaining := r.nodeCount*16 + 1
	var walk func(node uint64, depth int, acc *big.Int) error
	walk = func(node uint64, depth int, acc *big.Int) error {
		if remaining == 0 {
			return errors.New("search tree traversal limit exceeded")
		}
		remaining--
		if depth > bits || (depth == bits && node < r.nodeCount) {
			return errors.New("search tree exceeds address length")
		}
		if acc.Sign() != 0 && node == r.ipv4Start && r.ipVersion == 6 {
			return nil
		}
		if node > r.nodeCount {
			a := new(big.Int).Lsh(acc, uint(bits-depth))
			d := depth
			v6 := bits == 128
			if v6 && depth >= 96 && a.Cmp(ipv4Max) <= 0 {
				d -= 96
				v6 = false
			}
			recordOffset := node - r.nodeCount
			if recordOffset < 16 || recordOffset >= uint64(len(r.data)-r.treeSize) {
				return errors.New("record outside data section")
			}
			ptr := r.treeSize + int(recordOffset)
			rec, _, err := r.decode(ptr, r.treeSize+16)
			if err != nil {
				return err
			}
			return f(mmdbNetwork{v6, a, d}, rec)
		}
		if node < r.nodeCount {
			left := r.readNode(node, 0)
			next := new(big.Int).Lsh(acc, 1)
			if err := walk(left, depth+1, next); err != nil {
				return err
			}
			right := r.readNode(node, 1)
			return walk(right, depth+1, new(big.Int).Or(new(big.Int).Lsh(acc, 1), big.NewInt(1)))
		}
		return nil
	}
	return walk(0, 0, big.NewInt(0))
}

// ---------------------------------------------------------------------------
// networks
// ---------------------------------------------------------------------------

type cidr struct {
	v6     bool
	start  *big.Int
	prefix int
}

func (c cidr) bits() int {
	if c.v6 {
		return 128
	}
	return 32
}

func (c cidr) end() *big.Int {
	size := new(big.Int).Lsh(big.NewInt(1), uint(c.bits()-c.prefix))
	return new(big.Int).Sub(new(big.Int).Add(c.start, size), big.NewInt(1))
}

func (c cidr) String() string {
	b := c.start.FillBytes(make([]byte, c.bits()/8))
	var a netip.Addr
	if c.v6 {
		a = netip.AddrFrom16([16]byte(b))
	} else {
		a = netip.AddrFrom4([4]byte(b))
	}
	return netip.PrefixFrom(a, c.prefix).String()
}

func (c cidr) key() string { return fmt.Sprintf("%t/%s/%d", c.v6, c.start.String(), c.prefix) }

func cidrLess(a, b cidr) bool {
	if a.v6 != b.v6 {
		return !a.v6
	}
	if cmp := a.start.Cmp(b.start); cmp != 0 {
		return cmp < 0
	}
	return a.prefix < b.prefix
}

// collapse is ipaddress.collapse_addresses for one IP version.
func collapse(nets []cidr) []cidr {
	if len(nets) == 0 {
		return nil
	}
	sorted := append([]cidr(nil), nets...)
	sort.Slice(sorted, func(i, j int) bool { return cidrLess(sorted[i], sorted[j]) })
	type rng struct{ lo, hi *big.Int }
	ranges := []rng{}
	for _, n := range sorted {
		lo, hi := n.start, n.end()
		if len(ranges) > 0 {
			last := &ranges[len(ranges)-1]
			if lo.Cmp(new(big.Int).Add(last.hi, big.NewInt(1))) <= 0 {
				if hi.Cmp(last.hi) > 0 {
					last.hi = hi
				}
				continue
			}
		}
		ranges = append(ranges, rng{lo, hi})
	}
	v6, bits := sorted[0].v6, sorted[0].bits()
	out := []cidr{}
	one := big.NewInt(1)
	for _, r := range ranges {
		cur := new(big.Int).Set(r.lo)
		for cur.Cmp(r.hi) <= 0 {
			tz := int(cur.TrailingZeroBits())
			if cur.Sign() == 0 {
				tz = bits
			}
			if tz > bits {
				tz = bits
			}
			span := new(big.Int).Add(new(big.Int).Sub(r.hi, cur), one)
			maxBits := span.BitLen() - 1
			n := tz
			if maxBits < n {
				n = maxBits
			}
			out = append(out, cidr{v6, new(big.Int).Set(cur), bits - n})
			cur.Add(cur, new(big.Int).Lsh(one, uint(n)))
		}
	}
	return out
}

type aclResult struct {
	allowed      []cidr
	perCountry   map[string][]cidr
	counts       *pyyaml.Map
	records      int64
	databaseType string
	buildEpoch   uint64
}

func deriveACL(path string, countries []string) (*aclResult, error) {
	r, err := openMMDBFile(path)
	if err != nil {
		return nil, err
	}
	selected := map[string]map[string]cidr{}
	for _, c := range countries {
		selected[c] = map[string]cidr{}
	}
	versions := map[int]bool{}
	var records int64
	err = r.each(func(n mmdbNetwork, record any) error {
		records++
		bits := 32
		if n.v6 {
			bits = 128
		}
		if n.prefix < 0 || n.prefix > bits {
			return gerr("invalid network in MMDB: %s/%d", n.addr.String(), n.prefix)
		}
		c := cidr{n.v6, n.addr, n.prefix}
		mask := new(big.Int).Lsh(big.NewInt(1), uint(bits-n.prefix))
		c.start = new(big.Int).Sub(n.addr, new(big.Int).Mod(n.addr, mask))
		if n.v6 {
			versions[6] = true
		} else {
			versions[4] = true
		}
		m, ok := record.(map[string]any)
		if !ok {
			return nil
		}
		code := ""
		if country, ok := m["country"].(map[string]any); ok {
			code = strings.ToUpper(strings.TrimSpace(fmt.Sprint(valueOr(country["iso_code"], ""))))
		}
		if set, ok := selected[code]; ok {
			set[c.key()] = c
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if records < geoipMinDatabaseNodes || !(versions[4] && versions[6] && len(versions) == 2) {
		vs := []string{}
		for _, v := range []int{4, 6} {
			if versions[v] {
				vs = append(vs, strconv.Itoa(v))
			}
		}
		return nil, gerr("MMDB coverage validation failed: records=%d, IP versions=[%s]", records, strings.Join(vs, ", "))
	}
	missing := []string{}
	for _, c := range countries {
		if len(selected[c]) == 0 {
			missing = append(missing, c)
		}
	}
	if len(missing) > 0 {
		return nil, gerr("selected countries are absent from the database: %s", strings.Join(missing, ", "))
	}
	res := &aclResult{perCountry: map[string][]cidr{}, counts: pyyaml.NewMap(), records: records,
		databaseType: r.databaseType, buildEpoch: r.buildEpoch}
	all := map[string]cidr{}
	for _, code := range countries {
		var v4, v6 []cidr
		for _, c := range selected[code] {
			if c.v6 {
				v6 = append(v6, c)
			} else {
				v4 = append(v4, c)
			}
		}
		col := append(collapse(v4), collapse(v6)...)
		res.perCountry[code] = col
		var n4, n6 int64
		for _, c := range col {
			all[c.key()] = c
			if c.v6 {
				n6++
			} else {
				n4++
			}
		}
		res.counts.Set(code, omapAny("ipv4", n4, "ipv6", n6))
	}
	for _, c := range all {
		res.allowed = append(res.allowed, c)
	}
	sort.Slice(res.allowed, func(i, j int) bool { return cidrLess(res.allowed[i], res.allowed[j]) })
	return res, nil
}

func valueOr(v, def any) any {
	if v == nil {
		return def
	}
	return v
}

func omapAny(kv ...any) *pyyaml.Map {
	m := pyyaml.NewMap()
	for i := 0; i+1 < len(kv); i += 2 {
		m.Set(kv[i].(string), kv[i+1])
	}
	return m
}

func writeNetworks(path string, nets []cidr) error {
	lines := make([]string, len(nets))
	for i, n := range nets {
		lines[i] = n.String()
	}
	text := strings.Join(lines, "\n")
	if len(lines) > 0 {
		text += "\n"
	}
	return os.WriteFile(path, []byte(text), 0o666)
}

func setReleasePermissions(root string) error {
	gid := -1
	if g, err := user.LookupGroup("haproxy"); err == nil {
		gid, _ = strconv.Atoi(g.Gid)
	}
	return filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		mode := os.FileMode(0o644)
		if fi.IsDir() {
			mode = 0o755
		}
		if err := os.Chmod(p, mode); err != nil {
			return err
		}
		if gid >= 0 {
			if err := os.Chown(p, 0, gid); err != nil && !(errors.Is(err, syscall.EPERM) && os.Geteuid() != 0) {
				return err
			}
		}
		return nil
	})
}

func atomicSymlink(target, link string) error {
	tmp := filepath.Join(filepath.Dir(link), fmt.Sprintf(".%s.%d.tmp", filepath.Base(link), os.Getpid()))
	_ = os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	return os.Rename(tmp, link)
}

type snapshotEntry struct {
	kind    string
	payload []byte
}

func compatibilitySnapshot(dir string) map[string]*snapshotEntry {
	out := map[string]*snapshotEntry{}
	for _, name := range []string{geoipDatabaseName, geoipAllowedName} {
		p := filepath.Join(dir, name)
		if fi, err := os.Lstat(p); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			t, _ := os.Readlink(p)
			out[name] = &snapshotEntry{"symlink", []byte(t)}
		} else if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			b, _ := os.ReadFile(p)
			out[name] = &snapshotEntry{"file", b}
		} else {
			out[name] = nil
		}
	}
	return out
}

func installCompatibilityLinks(dir string) error {
	for _, name := range []string{geoipDatabaseName, geoipAllowedName} {
		if err := atomicSymlink("current/"+name, filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	return nil
}

func removeLegacyCountryFiles(dir string, out io.Writer) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		geoipLog(out, fmt.Sprintf("WARNING: cannot inspect legacy GeoIP country files: %v", err))
		return
	}
	removed := []string{}
	for _, e := range ents {
		if !geoipLegacyFile.MatchString(e.Name()) {
			continue
		}
		p := filepath.Join(dir, e.Name())
		if fi, err := os.Lstat(p); err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
			continue
		}
		if err := os.Remove(p); err != nil {
			geoipLog(out, fmt.Sprintf("WARNING: cannot remove legacy GeoIP file %s: %v", p, err))
			continue
		}
		removed = append(removed, e.Name())
	}
	if len(removed) > 0 {
		sort.Strings(removed)
		geoipLog(out, "Removed legacy flat country files: "+strings.Join(removed, ", "))
	}
}

func restoreCompatibilitySnapshot(dir string, snap map[string]*snapshotEntry) error {
	for _, name := range []string{geoipDatabaseName, geoipAllowedName} {
		p := filepath.Join(dir, name)
		_ = os.Remove(p)
		e := snap[name]
		if e == nil {
			continue
		}
		if e.kind == "symlink" {
			if err := os.Symlink(string(e.payload), p); err != nil {
				return err
			}
			continue
		}
		tmp := filepath.Join(dir, fmt.Sprintf(".%s.%d.restore", name, os.Getpid()))
		if err := os.WriteFile(tmp, e.payload, 0o644); err != nil {
			return err
		}
		_ = os.Chmod(tmp, 0o644)
		if err := os.Rename(tmp, p); err != nil {
			return err
		}
	}
	return nil
}

func geoipCommand(argv []string) (bool, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return false, fmt.Sprintf("Command '%s' timed out after 60 seconds", pyArgList(argv))
	}
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return false, fmt.Sprintf("[Errno 2] No such file or directory: %s", pyRepr(argv[0]))
		}
	}
	parts := []string{}
	for _, s := range []string{out.String(), errb.String()} {
		if t := strings.TrimSpace(s); t != "" {
			parts = append(parts, t)
		}
	}
	return err == nil, strings.Join(parts, "\n")
}

type controlCheck struct{ service, domain, path string }

func controlPlaneChecks(config string) []controlCheck {
	raw, err := os.ReadFile(config)
	if err != nil || !utf8Valid(raw) {
		return nil
	}
	text := string(raw)
	for _, m := range geoipProbeMarkers {
		if !m.MatchString(text) {
			return nil
		}
	}
	out := []controlCheck{}
	for _, m := range geoipControlACL.FindAllStringSubmatch(text, -1) {
		sp := geoipControlPaths[m[1]]
		domains := []string{}
		for _, v := range strings.Fields(m[2]) {
			domains = append(domains, strings.TrimRight(strings.ToLower(v), "."))
		}
		if len(domains) == 1 && len(domains[0]) >= 1 && len(domains[0]) <= 253 && geoipDomainRE.MatchString(domains[0]) {
			out = append(out, controlCheck{sp[0], domains[0], sp[1]})
		}
	}
	return out
}

func geoipProbe(c controlCheck) (bool, string) {
	timeout := 5 * time.Second
	conn, err := net.DialTimeout("tcp", "127.0.0.1:443", timeout)
	if err != nil {
		return false, fmt.Sprintf("%s (%s) failed: %s", c.service, c.domain, netErrText(err))
	}
	defer conn.Close()
	tc := tls.Client(conn, &tls.Config{ServerName: c.domain, InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	_ = tc.SetDeadline(time.Now().Add(timeout))
	if err := tc.Handshake(); err != nil {
		return false, fmt.Sprintf("%s (%s) failed: %s", c.service, c.domain, netErrText(err))
	}
	req := "GET " + c.path + " HTTP/1.1\r\nHost: " + c.domain + "\r\nUser-Agent: easy-ha-proxy-geoip-guard/1\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
	if _, err := tc.Write([]byte(req)); err != nil {
		return false, fmt.Sprintf("%s (%s) failed: %s", c.service, c.domain, netErrText(err))
	}
	resp := []byte{}
	buf := make([]byte, 2048)
	for !bytes.Contains(resp, []byte("\r\n")) && len(resp) < 8192 {
		_ = tc.SetDeadline(time.Now().Add(timeout))
		n, err := tc.Read(buf)
		resp = append(resp, buf[:n]...)
		if err != nil {
			break
		}
	}
	line := strings.SplitN(strings.ToValidUTF8(string(resp), "�"), "\r\n", 2)[0]
	status := 0
	if m := geoipHTTPStatus.FindStringSubmatch(line); m != nil {
		status, _ = strconv.Atoi(m[1])
	}
	shown := "invalid"
	if status != 0 {
		shown = strconv.Itoa(status)
	}
	return status == 200, fmt.Sprintf("%s (%s) returned HTTP %s", c.service, c.domain, shown)
}

func netErrText(err error) string {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timed out"
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		msg := errno.Error()
		if msg != "" {
			msg = strings.ToUpper(msg[:1]) + msg[1:]
		}
		return fmt.Sprintf("[Errno %d] %s", int(errno), msg)
	}
	return err.Error()
}

func verifyControlPlane(config string) (bool, string) {
	checks := controlPlaneChecks(config)
	hasAdmin := false
	for _, c := range checks {
		if c.service == "admin" {
			hasAdmin = true
		}
	}
	if !hasAdmin {
		return true, "guarded HAProxy Admin control-plane probe is unavailable; probe skipped"
	}
	latest := []string{}
	for attempt := 1; attempt <= 5; attempt++ {
		latest = latest[:0]
		all := true
		for _, c := range checks {
			ok, msg := geoipProbe(c)
			all = all && ok
			latest = append(latest, msg)
		}
		if all {
			return true, strings.Join(latest, "; ")
		}
		if attempt < 5 {
			time.Sleep(time.Second)
		}
	}
	return false, strings.Join(latest, "; ")
}

func validateReloadAndProbe(haproxy, systemctl, config string) (bool, string) {
	if ok, out := geoipCommand([]string{haproxy, "-c", "-f", config}); !ok {
		return false, "HAProxy validation failed: " + out
	}
	if ok, out := geoipCommand([]string{systemctl, "reload", "haproxy.service"}); !ok {
		return false, "HAProxy reload failed: " + out
	}
	ok, out := verifyControlPlane(config)
	if !ok {
		return false, "critical service probe failed: " + out
	}
	return true, out
}

func pruneReleases(dir string, keep int) error {
	releases := filepath.Join(dir, "releases")
	protected := map[string]bool{}
	for _, l := range []string{"current", "previous"} {
		if r, err := filepath.EvalSymlinks(filepath.Join(dir, l)); err == nil {
			protected[r] = true
		}
	}
	ents, err := os.ReadDir(releases)
	if err != nil {
		return err
	}
	type cand struct {
		p string
		t int64
	}
	cands := []cand{}
	for _, e := range ents {
		p := filepath.Join(releases, e.Name())
		fi, err := os.Stat(p)
		if err != nil || !fi.IsDir() {
			continue
		}
		cands = append(cands, cand{p, fi.ModTime().UnixNano()})
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].t > cands[j].t })
	retained := 0
	for _, c := range cands {
		if protected[resolveDir(c.p)] || retained < keep {
			retained++
			continue
		}
		if err := os.RemoveAll(c.p); err != nil {
			return err
		}
	}
	return nil
}

const geoipMaxRedirects = 5

var (
	geoipLookupIP = func(ctx context.Context, host string) ([]netip.Addr, error) {
		if addr, err := netip.ParseAddr(host); err == nil {
			return []netip.Addr{addr}, nil
		}
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}
	geoipHTTPTransport http.RoundTripper
	geoipReservedNets  = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("240.0.0.0/4"),
		netip.MustParsePrefix("255.255.255.255/32"),
		netip.MustParsePrefix("64:ff9b::/96"),
		netip.MustParsePrefix("64:ff9b:1::/48"),
		netip.MustParsePrefix("100::/64"),
		netip.MustParsePrefix("2001::/23"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2002::/16"),
		netip.MustParsePrefix("fec0::/10"),
	}
)

func isGeoIPBlockedAddr(raw netip.Addr) bool {
	addr := raw.Unmap()
	if !addr.IsValid() || addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsInterfaceLocalMulticast() ||
		addr.IsUnspecified() || !addr.IsGlobalUnicast() {
		return true
	}
	for _, p := range geoipReservedNets {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func validateGeoIPURL(ctx context.Context, u *url.URL, requireHTTPS bool) error {
	if u == nil {
		return gerr("GeoIP URL is missing")
	}
	scheme := strings.ToLower(u.Scheme)
	if requireHTTPS {
		if scheme != "https" {
			return gerr("GeoIP redirect to non-HTTPS scheme %q is not allowed", u.Scheme)
		}
	} else if scheme != "https" && scheme != "http" {
		return gerr("unsupported GeoIP URL scheme %q", u.Scheme)
	}
	if u.User != nil {
		return gerr("GeoIP URL must not include credentials")
	}
	host := strings.TrimSpace(u.Hostname())
	if host == "" {
		return gerr("GeoIP URL has no host")
	}
	_, err := geoipPublicAddresses(ctx, host)
	return err
}

func geoipPublicAddresses(ctx context.Context, host string) ([]netip.Addr, error) {
	addrs, err := geoipLookupIP(ctx, host)
	if err != nil || len(addrs) == 0 {
		return nil, gerr("cannot resolve GeoIP host %q: %v", host, err)
	}
	for _, addr := range addrs {
		if isGeoIPBlockedAddr(addr) {
			return nil, gerr("GeoIP host %q resolves to disallowed address %s", host, addr)
		}
	}
	return addrs, nil
}

func dialGeoIP(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	addrs, err := geoipPublicAddresses(ctx, host)
	if err != nil {
		return nil, err
	}
	dialer := net.Dialer{Timeout: 10 * time.Second}
	for _, addr := range addrs {
		conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(addr.Unmap().String(), port))
		if dialErr == nil {
			return conn, nil
		}
		err = dialErr
	}
	return nil, err
}

func geoipCheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > geoipMaxRedirects {
		return gerr("too many GeoIP redirects (limit %d)", geoipMaxRedirects)
	}
	if err := validateGeoIPURL(req.Context(), req.URL, true); err != nil {
		return err
	}
	return nil
}

func downloadFile(rawURL, dest string, out io.Writer) error {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return gerr("download failed for %s: %v", rawURL, err)
	}
	transport := geoipHTTPTransport
	if transport == nil {
		pinned := http.DefaultTransport.(*http.Transport).Clone()
		pinned.Proxy = nil
		pinned.DialContext = dialGeoIP
		defer pinned.CloseIdleConnections()
		transport = pinned
	}
	var last error
	for attempt := 1; attempt <= 3; attempt++ {
		err := func() error {
			reqCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			if err := validateGeoIPURL(reqCtx, parsedURL, strings.EqualFold(parsedURL.Scheme, "https")); err != nil {
				return err
			}
			req, err := http.NewRequestWithContext(reqCtx, "GET", rawURL, nil)
			if err != nil {
				return err
			}
			req.Header.Set("User-Agent", "easy-ha-proxy-geoip-updater/1")
			client := &http.Client{
				Timeout:       60 * time.Second,
				Transport:     transport,
				CheckRedirect: geoipCheckRedirect,
			}
			resp, err := client.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode >= 400 {
				return &httpStatusErr{resp.StatusCode, resp.Status}
			}
			f, err := os.Create(dest)
			if err != nil {
				return err
			}
			n, copyErr := io.Copy(f, io.LimitReader(resp.Body, geoipMaxCompressed+1))
			closeErr := f.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
			if n > geoipMaxCompressed {
				return gerr("compressed GeoIP download is too large")
			}
			if n == 0 {
				return gerr("GeoIP download is empty")
			}
			return nil
		}()
		if err == nil {
			return nil
		}
		last = err
		var hs *httpStatusErr
		if errors.As(err, &hs) && hs.code == 404 {
			break
		}
		if attempt < 3 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
	}
	return gerr("download failed for %s: %v", rawURL, last)
}

type httpStatusErr struct {
	code   int
	status string
}

func (e *httpStatusErr) Error() string {
	return fmt.Sprintf("HTTP Error %d: %s", e.code, strings.TrimSpace(strings.TrimPrefix(e.status, strconv.Itoa(e.code))))
}

func decompressDatabase(src, dest string) error {
	f, err := os.Open(src)
	if err != nil {
		return gerr("cannot decompress GeoIP database: %v", err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return gerr("cannot decompress GeoIP database: Not a gzipped file")
	}
	out, err := os.Create(dest)
	if err != nil {
		return gerr("cannot decompress GeoIP database: %v", err)
	}
	defer out.Close()
	n, err := io.Copy(out, io.LimitReader(zr, geoipMaxDatabase+1))
	if err != nil {
		return gerr("cannot decompress GeoIP database: %v", err)
	}
	if n > geoipMaxDatabase {
		return gerr("uncompressed GeoIP database is too large")
	}
	if n == 0 {
		return gerr("uncompressed GeoIP database is empty")
	}
	return nil
}

type downloaded struct {
	path, period, url string
}

func downloadDatabase(baseURL, buildDir string, periods []string, out io.Writer) (*downloaded, error) {
	errs := []string{}
	for _, period := range periods {
		url := strings.TrimRight(baseURL, "/") + "/dbip-country-lite-" + period + ".mmdb.gz"
		archive := filepath.Join(buildDir, period+".mmdb.gz")
		database := filepath.Join(buildDir, period+".mmdb")
		err := func() error {
			defer os.Remove(archive)
			geoipLog(out, "Downloading DB-IP Country Lite "+period)
			if err := downloadFile(url, archive, out); err != nil {
				return err
			}
			if err := decompressDatabase(archive, database); err != nil {
				return err
			}
			_, err := openMMDBFile(database)
			return err
		}()
		if err == nil {
			return &downloaded{database, period, url}, nil
		}
		errs = append(errs, err.Error())
	}
	return nil, gerr("%s", strings.Join(errs, "; "))
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	fi, _ := in.Stat()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fi.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	out.Close()
	return os.Chtimes(dst, fi.ModTime(), fi.ModTime())
}

func isFile(p string) bool { fi, err := os.Stat(p); return err == nil && fi.Mode().IsRegular() }

// stateJSON is json.dumps(state, indent=2, sort_keys=True) + "\n".
func stateJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	s := buf.String()
	var b strings.Builder
	for _, r := range s {
		if r > 0x7e {
			if r > 0xffff {
				r -= 0x10000
				fmt.Fprintf(&b, `\u%04x\u%04x`, 0xd800+(r>>10), 0xdc00+(r&0x3ff))
			} else {
				fmt.Fprintf(&b, `\u%04x`, r)
			}
			continue
		}
		b.WriteRune(r)
	}
	return []byte(b.String()), nil
}

func (a *GeoIPArgs) update(lockHeld bool) error {
	out := a.Out
	if err := verifyTransactionAccess(a.TransactionState, a.TransactionID); err != nil {
		return err
	}
	if err := os.MkdirAll(a.Directory, 0o777); err != nil {
		return err
	}
	dir := resolveDir(a.Directory)
	releases := filepath.Join(dir, "releases")
	if err := os.Mkdir(releases, 0o755); err != nil && !os.IsExist(err) {
		return err
	}
	gid := -1
	if g, err := user.LookupGroup("haproxy"); err == nil {
		gid, _ = strconv.Atoi(g.Gid)
	}
	for _, p := range []string{dir, releases} {
		if err := os.Chmod(p, 0o755); err != nil {
			return err
		}
		if gid >= 0 {
			if err := os.Chown(p, 0, gid); err != nil && !(errors.Is(err, syscall.EPERM) && os.Geteuid() != 0) {
				return err
			}
		}
	}
	if !lockHeld {
		unlock, err := geoipLock(dir)
		if err != nil {
			return err
		}
		defer unlock()
	}
	var countries []string
	var filter bool
	var err error
	if a.SelectionFile != "" {
		countries, filter, err = loadGeoSelection(a.SelectionFile)
	} else {
		countries, err = normalizeCountries(a.Countries)
		filter = a.AccessFilterEnabled
	}
	if err != nil {
		return err
	}
	if filter && len(countries) == 0 {
		return gerr("GeoIP access filtering is enabled but no country codes are selected")
	}
	previous, err := activeRelease(dir)
	if err != nil {
		return err
	}
	current := pyyaml.NewMap()
	if previous != "" {
		current = readGeoState(filepath.Join(previous, geoipStateName))
	}
	currentDB := ""
	if previous != "" {
		currentDB = filepath.Join(previous, geoipDatabaseName)
	}
	if currentDB == "" || !isFile(currentDB) {
		legacy := filepath.Join(dir, geoipDatabaseName)
		if fi, err := os.Lstat(legacy); err == nil && fi.Mode().IsRegular() {
			currentDB = legacy
		}
	}
	previousAllowedPath := filepath.Join(dir, geoipAllowedName)
	if previous != "" {
		previousAllowedPath = filepath.Join(previous, geoipAllowedName)
	}
	previousAllowed, perr := os.ReadFile(previousAllowedPath)
	hasPreviousAllowed := perr == nil
	hashBase := dir
	if previous != "" {
		hashBase = previous
	}
	previousCountrySHA, cerr := countryACLHashes(hashBase)
	now := time.Now
	if a.Now != nil {
		now = a.Now
	}
	periods := monthCandidates(now().UTC(), 3)
	wanted := periods[0]
	dbHashOK := currentDB != "" && isFile(currentDB) && fileMatchesSHA256(currentDB, current.Value("database_sha256"))
	allowedHashOK := previous != "" && isFile(filepath.Join(previous, geoipAllowedName)) &&
		fileMatchesSHA256(filepath.Join(previous, geoipAllowedName), current.Value("allowed_sha256"))
	countryHashOK := previous != "" && countryACLsMatch(previous, current.Value("country_sha256"))
	stateCountries := []string{}
	if l, ok := current.Value("countries").([]any); ok {
		for _, c := range l {
			stateCountries = append(stateCountries, pyStrValue(c))
		}
	}
	sameCountries := strings.Join(stateCountries, ",") == strings.Join(countries, ",") && len(stateCountries) == len(countries)
	formatOK := false
	if n, ok := current.Value("release_format_version").(int64); ok && n == geoipReleaseFormat {
		formatOK = true
	}
	allowedNonEmpty := func() bool {
		fi, err := os.Stat(filepath.Join(previous, geoipAllowedName))
		return err == nil && fi.Size() > 0
	}
	if !a.ForceDownload && previous != "" && currentDB != "" && isFile(currentDB) && isFile(filepath.Join(previous, geoipAllowedName)) &&
		formatOK && current.Value("source_period") == wanted && sameCountries && pyTruthy(current.Value("access_filter_enabled")) == filter &&
		dbHashOK && allowedHashOK && countryHashOK && (!filter || allowedNonEmpty()) {
		if _, err := openMMDBFile(currentDB); err != nil {
			return err
		}
		if err := installCompatibilityLinks(dir); err != nil {
			return err
		}
		removeLegacyCountryFiles(dir, out)
		geoipLog(out, fmt.Sprintf("GeoIP release %s is current; database and country selection are unchanged", filepath.Base(previous)))
		return pruneReleases(dir, 3)
	}
	buildRoot, err := os.MkdirTemp(releases, ".build-")
	if err != nil {
		return err
	}
	defer func() {
		if strings.HasPrefix(filepath.Base(buildRoot), ".build-") {
			_ = os.RemoveAll(buildRoot)
		}
	}()
	reuse := !a.ForceDownload && currentDB != "" && isFile(currentDB) && dbHashOK && current.Value("source_period") == wanted
	sourceURL := pyStrOrEmpty(current.Value("source_url"))
	sourcePeriod := pyStrOrEmpty(current.Value("source_period"))
	if sourcePeriod == "" {
		sourcePeriod = "unknown"
	}
	database := filepath.Join(buildRoot, geoipDatabaseName)
	if reuse {
		if err := copyFile(currentDB, database); err != nil {
			return err
		}
		if _, err := openMMDBFile(database); err != nil {
			return err
		}
		geoipLog(out, "Reusing installed DB-IP Country Lite "+sourcePeriod)
	} else {
		want := []string{wanted}
		if currentDB == "" {
			want = periods
		}
		d, derr := downloadDatabase(a.BaseURL, buildRoot, want, out)
		if derr != nil {
			if currentDB == "" || !isFile(currentDB) || !dbHashOK {
				return derr
			}
			if err := copyFile(currentDB, database); err != nil {
				return err
			}
			if _, err := openMMDBFile(database); err != nil {
				return err
			}
			geoipLog(out, "WARNING: the newest database is unavailable; keeping installed release "+sourcePeriod)
		} else {
			sourcePeriod, sourceURL = d.period, d.url
			if d.path != database {
				if err := os.Rename(d.path, database); err != nil {
					return err
				}
			}
		}
	}
	dbSHA, err := sha256File(database)
	if err != nil {
		return err
	}
	acl, err := deriveACL(database, countries)
	if err != nil {
		return err
	}
	allowedPath := filepath.Join(buildRoot, geoipAllowedName)
	if err := writeNetworks(allowedPath, acl.allowed); err != nil {
		return err
	}
	if !filter && len(countries) == 0 && hasPreviousAllowed && len(previousAllowed) > 0 {
		if err := os.WriteFile(allowedPath, previousAllowed, 0o666); err != nil {
			return err
		}
	}
	allowedContent, err := os.ReadFile(allowedPath)
	if err != nil {
		return err
	}
	allowedSHA := hex.EncodeToString(sha256Sum(allowedContent))
	published := int64(0)
	for _, line := range bytes.Split(allowedContent, []byte("\n")) {
		if len(bytes.TrimSpace(line)) > 0 && !bytes.HasPrefix(bytes.TrimLeft(line, " \t\r\v\f"), []byte("#")) {
			published++
		}
	}
	for _, code := range countries {
		if err := writeNetworks(filepath.Join(buildRoot, code+".cidr"), acl.perCountry[code]); err != nil {
			return err
		}
	}
	countrySHA, err := countryACLHashes(buildRoot)
	if err != nil {
		return err
	}
	aclChanged := !hasPreviousAllowed || !bytes.Equal(previousAllowed, allowedContent) || cerr != nil || !sameHashes(previousCountrySHA, countrySHA)
	cfgHashInput, _ := json.Marshal(nil)
	_ = cfgHashInput
	configHash := hex.EncodeToString(sha256Sum([]byte(configHashJSON(countries, filter, allowedSHA, countrySHA))))
	releaseID := geoipSafePeriod.ReplaceAllString(sourcePeriod, "-") + "-" + dbSHA[:12] + "-" + configHash[:12]
	release := filepath.Join(releases, releaseID)
	countryList := make([]any, len(countries))
	for i, c := range countries {
		countryList[i] = c
	}
	countryShaMap := map[string]any{}
	for k, v := range countrySHA {
		countryShaMap[k] = v
	}
	countsMap := map[string]any{}
	acl.counts.Each(func(k, v any) {
		m := v.(*pyyaml.Map)
		countsMap[k.(string)] = map[string]any{"ipv4": m.Value("ipv4"), "ipv6": m.Value("ipv6")}
	})
	state := map[string]any{
		"release_format_version": geoipReleaseFormat, "provider": "DB-IP Country Lite", "license": "CC BY 4.0",
		"source_url": sourceURL, "source_period": sourcePeriod, "activated_at": pyISO(now().UTC()),
		"database_sha256": dbSHA, "database_type": acl.databaseType, "database_build_epoch": acl.buildEpoch,
		"database_records": acl.records, "countries": countryList, "country_networks": countsMap,
		"allowed_networks": published, "allowed_sha256": allowedSHA, "country_sha256": countryShaMap,
		"access_filter_enabled": filter,
	}
	stateText, err := stateJSON(state)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(buildRoot, geoipStateName), stateText, 0o666); err != nil {
		return err
	}
	if err := setReleasePermissions(buildRoot); err != nil {
		return err
	}
	if _, err := os.Stat(release); err == nil {
		if releasePayloadMatches(release, dbSHA, allowedSHA, countrySHA) {
			_ = os.RemoveAll(buildRoot)
			buildRoot = release
		} else {
			base := fmt.Sprintf("%s-repair-%d-%d", releaseID, os.Getpid(), time.Now().UnixNano())
			releaseID = base
			release = filepath.Join(releases, releaseID)
			for suffix := 1; pathExists(release); suffix++ {
				releaseID = fmt.Sprintf("%s-%d", base, suffix)
				release = filepath.Join(releases, releaseID)
			}
			if err := os.Rename(buildRoot, release); err != nil {
				return err
			}
			buildRoot = release
		}
	} else {
		if err := os.Rename(buildRoot, release); err != nil {
			return err
		}
		buildRoot = release
	}
	oldTarget := ""
	if fi, err := os.Lstat(filepath.Join(dir, "current")); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		oldTarget, _ = os.Readlink(filepath.Join(dir, "current"))
	}
	newTarget := "releases/" + releaseID
	if oldTarget == newTarget {
		if err := installCompatibilityLinks(dir); err != nil {
			return err
		}
		removeLegacyCountryFiles(dir, out)
		geoipLog(out, fmt.Sprintf("GeoIP release %s is already current", releaseID))
		return pruneReleases(dir, 3)
	}
	snap := compatibilitySnapshot(dir)
	if err := atomicSymlink(newTarget, filepath.Join(dir, "current")); err != nil {
		return err
	}
	if err := installCompatibilityLinks(dir); err != nil {
		return err
	}
	active := aclChanged && filter && !a.SkipReload
	if active {
		ok, _ := geoipCommand([]string{a.Systemctl, "is-active", "--quiet", "haproxy.service"})
		active = ok
	}
	if active {
		ok, detail := validateReloadAndProbe(a.HAProxy, a.Systemctl, a.HAProxyConfig)
		if !ok {
			if oldTarget != "" {
				_ = atomicSymlink(oldTarget, filepath.Join(dir, "current"))
				_ = installCompatibilityLinks(dir)
			} else {
				_ = os.Remove(filepath.Join(dir, "current"))
				_ = restoreCompatibilitySnapshot(dir, snap)
			}
			rok, rdetail := validateReloadAndProbe(a.HAProxy, a.Systemctl, a.HAProxyConfig)
			word := "failed"
			if rok {
				word = "succeeded"
			}
			return gerr("new release failed: %s; rollback %s: %s", detail, word, rdetail)
		}
		geoipLog(out, "HAProxy reload and critical-service checks passed: "+detail)
	} else if !aclChanged {
		geoipLog(out, "HAProxy ACL is unchanged; reload is not required")
	}
	if oldTarget != "" && dbHashOK && allowedHashOK && countryHashOK {
		if err := atomicSymlink(oldTarget, filepath.Join(dir, "previous")); err != nil {
			return err
		}
	}
	removeLegacyCountryFiles(dir, out)
	target := "UI lookups only"
	if len(countries) > 0 {
		target = strings.Join(countries, ", ")
	}
	geoipLog(out, fmt.Sprintf("Activated GeoIP release %s: %d networks for %s", releaseID, published, target))
	return pruneReleases(dir, 3)
}

func pathExists(p string) bool { _, err := os.Lstat(p); return err == nil }

func sha256Sum(b []byte) []byte { s := sha256.Sum256(b); return s[:] }

// configHashJSON is json.dumps({...}, sort_keys=True) of the release identity.
func configHashJSON(countries []string, filter bool, allowedSHA string, countrySHA map[string]string) string {
	cs := make([]string, len(countries))
	for i, c := range countries {
		cs[i] = strconv.Quote(c)
	}
	keys := make([]string, 0, len(countrySHA))
	for k := range countrySHA {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = strconv.Quote(k) + ": " + strconv.Quote(countrySHA[k])
	}
	return fmt.Sprintf(`{"access_filter_enabled": %t, "allowed_sha256": %q, "countries": [%s], "country_sha256": {%s}, "release_format_version": %d}`,
		filter, allowedSHA, strings.Join(cs, ", "), strings.Join(parts, ", "), geoipReleaseFormat)
}

// RunUpdateGeoIP is main(): it returns the exit status.
func RunUpdateGeoIP(args []string, stdout io.Writer) int {
	a := &GeoIPArgs{Directory: "/etc/haproxy/geoip", BaseURL: "https://download.db-ip.com/free",
		VarsFile: "/opt/haproxy-admin/config/vars.yml", HAProxy: "/usr/sbin/haproxy", HAProxyConfig: "/etc/haproxy/haproxy.cfg",
		Systemctl: "/usr/bin/systemctl", Out: stdout}
	values := map[string]*string{"--directory": &a.Directory, "--base-url": &a.BaseURL, "--selection-file": &a.SelectionFile,
		"--config-transaction-state": &a.TransactionState, "--config-transaction-id": &a.TransactionID, "--vars-file": &a.VarsFile,
		"--haproxy": &a.HAProxy, "--haproxy-config": &a.HAProxyConfig, "--systemctl": &a.Systemctl}
	flags := map[string]*bool{"--configure-selection": &a.ConfigureSelection, "--access-filter-enabled": &a.AccessFilterEnabled,
		"--force-download": &a.ForceDownload, "--skip-reload": &a.SkipReload}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		name, val, hasVal := strings.Cut(arg, "=")
		if p, ok := values[name]; ok {
			if !hasVal {
				if i+1 >= len(args) {
					fmt.Fprintf(os.Stderr, "update_geoip.py: error: argument %s: expected one argument\n", name)
					return 2
				}
				i++
				val = args[i]
			}
			*p = val
			continue
		}
		if name == "--country" {
			if !hasVal {
				if i+1 >= len(args) {
					fmt.Fprintf(os.Stderr, "update_geoip.py: error: argument --country: expected one argument\n")
					return 2
				}
				i++
				val = args[i]
			}
			a.Countries = append(a.Countries, val)
			continue
		}
		if p, ok := flags[arg]; ok {
			*p = true
			continue
		}
		fmt.Fprintf(os.Stderr, "update_geoip.py: error: unrecognized arguments: %s\n", arg)
		return 2
	}
	var err error
	if a.ConfigureSelection {
		err = a.configureSelection()
	} else {
		err = a.update(false)
	}
	if err != nil {
		var ge *geoipError
		if errors.As(err, &ge) {
			geoipLog(stdout, "ERROR: "+ge.msg)
			return 1
		}
		geoipLog(stdout, "ERROR: "+err.Error())
		return 1
	}
	return 0
}
