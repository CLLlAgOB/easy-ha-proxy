package app

// Port of services_haproxy_config.py: rendering, checking and applying
// haproxy.cfg, and the whole-file operations on the YAML sources.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"easy-ha-proxy/panel/shared/jinja"
	"easy-ha-proxy/panel/shared/pyyaml"
)

// BaseDir is the Flask app's BASE_DIR and working directory.
var BaseDir = func() string {
	if v := os.Getenv("HAPROXY_ADMIN_BASE_DIR"); v != "" {
		return v
	}
	return "/opt/haproxy-admin"
}()

var (
	HAPTemplate      = filepath.Join(BaseDir, "config", "haproxy.cfg.j2")
	HAProxyCfgPath   = "/etc/haproxy/haproxy.cfg"
	WebsitesYAML     = filepath.Join(BaseDir, "config", "websites.yml")
	TCPYAML          = filepath.Join(BaseDir, "config", "tcp.yml")
	UDPYAML          = filepath.Join(BaseDir, "config", "udp.yml")
	ConfigYAML       = filepath.Join(BaseDir, "config", "vars.yml")
	HAProxyBackupDir = filepath.Join(BaseDir, "backups", "haproxy")
	StatePath        = filepath.Join(HAProxyBackupDir, "last_applied_state.json")
	StateWebsites    = filepath.Join(HAProxyBackupDir, "last_applied_websites.yml")
	StateTCP         = filepath.Join(HAProxyBackupDir, "last_applied_tcp.yml")
	StateVars        = filepath.Join(HAProxyBackupDir, "last_applied_vars.yml")
	PendingTxPath    = filepath.Join(HAProxyBackupDir, "pending_ui_transaction.json")
)

const (
	ConfigGenerationHeader = "X-Easy-HAProxy-Config-Generation"
	configGenerationPrefix = "easy-ha-proxy-config-generation-v1|"
	maxYAMLBackups         = 14
	haproxyCheckTimeout    = 30
)

var configSourceOrder = []string{"vars.yml", "websites.yml", "tcp.yml"}

var configGenerationDirectiveRe = regexp.MustCompile(`(?im)^([ \t]*http-request[ \t]+set-header[ \t]+X-Easy-HAProxy-Config-Generation[ \t]+)[0-9a-f]{64}([ \t]+if[ \t]+host_admin[ \t]*)(\r?)$`)

var (
	haproxyControlSocket = func() string {
		for _, k := range []string{"HAPROXY_CONTROL_SOCKET", "HAPROXY_RELOAD_SOCKET"} {
			if v := os.Getenv(k); v != "" {
				return v
			}
		}
		return "/run/easy-ha-proxy/haproxy-controld.sock"
	}()
	haproxyControlTimeout = envInt("HAPROXY_CONTROL_TIMEOUT", 10)
	haproxyGuardedTimeout = envInt("HAPROXY_GUARDED_APPLY_TIMEOUT", 420)
	haproxyConfirmTimeout = envInt("HAPROXY_CONFIG_CONFIRM_TIMEOUT", 120)
	hapCheckCmd           = []string{"/usr/sbin/haproxy", "-c", "-f"}
	txIDRe                = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
	hex64Re               = regexp.MustCompile(`^[0-9a-f]{64}$`)
	isoCountryRe          = regexp.MustCompile(`^[A-Z]{2}$`)
)

// ConfigApplyPreparationError is ConfigApplyPreparationError.
type ConfigApplyPreparationError struct {
	Msg       string
	ErrorCode string
	Details   *Map
}

func (e *ConfigApplyPreparationError) Error() string { return e.Msg }

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// pyB64DecodeStrict is base64.b64decode(s, validate=True).
func pyB64DecodeStrict(s string) ([]byte, error) {
	for _, c := range s {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
			return nil, errors.New("Only base64 data is allowed")
		}
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, errors.New("Incorrect padding")
	}
	return raw, nil
}

func readControldReply(reader io.Reader) ([]byte, error) {
	const maxReply = 32 * 1024 * 1024
	raw, err := io.ReadAll(io.LimitReader(reader, maxReply+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxReply {
		return nil, errors.New("haproxy-controld response is too large")
	}
	return raw, nil
}

func controldRaw(command string, timeout time.Duration) ([]byte, error) {
	conn, err := net.DialTimeout("unix", haproxyControlSocket, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(command + "\n")); err != nil {
		return nil, err
	}
	return readControldReply(conn)
}

// controldJSONRequest is _controld_json_request.
func controldJSONRequest(command string, timeout int) *Map {
	fail := func(msg string) *Map { return newMap("ok", false, "error", msg) }
	if haproxyControlSocket == "" || !fileExists(haproxyControlSocket) {
		return fail("haproxy-controld is unavailable; no configuration was changed")
	}
	if strings.ContainsAny(command, "\n\r") {
		return fail("invalid control command")
	}
	for _, r := range command {
		if r > 127 {
			return fail("haproxy-controld request failed: 'ascii' codec can't encode character")
		}
	}
	raw, err := controldRaw(command, time.Duration(timeout)*time.Second)
	if err != nil {
		return fail("haproxy-controld request failed: " + pyOSError(err))
	}
	response := strings.TrimSpace(strings.ToValidUTF8(string(raw), "�"))
	prefix, payloadB64, found := strings.Cut(response, " ")
	var payload *Map
	var perr string
	switch {
	case !found:
		perr = "not enough values to unpack (expected 2, got 1)"
	case prefix != "OK" && prefix != "ERROR":
		perr = "unexpected response prefix"
	default:
		decoded, err := pyB64DecodeStrict(payloadB64)
		if err != nil {
			perr = err.Error()
			break
		}
		if !utf8.Valid(decoded) {
			perr = "'utf-8' codec can't decode bytes"
			break
		}
		v, err := pyyaml.JSONLoads(decoded)
		if err != nil {
			perr = "Expecting value: line 1 column 1 (char 0)"
			break
		}
		m, ok := asMap(v)
		if !ok {
			perr = "response payload is not an object"
			break
		}
		payload = m
	}
	if perr != "" {
		shown := truncRunes(response, 300)
		if shown == "" {
			shown = "empty"
		}
		return fail(fmt.Sprintf("Invalid haproxy-controld response: %s (%s)", shown, perr))
	}
	if _, ok := payload.Get("ok"); !ok {
		payload.Set("ok", prefix == "OK")
	}
	if prefix == "ERROR" {
		payload.Set("ok", false)
		if _, ok := payload.Get("error"); !ok {
			payload.Set("error", orValue(payload.Value("failure"), "control request failed"))
		}
	}
	return payload
}

func transactionState(result *Map) string {
	return strings.ToLower(orStr(orValue(result.Value("state"), result.Value("status"))))
}

func atomicWriteSnapshot(path string, raw []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o777); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return nil
}

func writePendingTransactionMarker(result *Map, generation string) error {
	txID := orStr(orValue(result.Value("transaction_id"), result.Value("id")))
	if txID == "" {
		return nil
	}
	gen := strings.ToLower(orStr(generation))
	if !hex64Re.MatchString(gen) {
		return &ValueError{"invalid HAProxy configuration generation"}
	}
	marker := newMap("transaction_id", txID, "candidate_sha256", result.Value("candidate_sha256"),
		"confirm_by", orValue(result.Value("confirm_by"), result.Value("deadline")), "config_generation", gen)
	text, err := PyJSON(marker, JSONOpts{EnsureASCII: true, Compact: true})
	if err != nil {
		return err
	}
	return atomicWriteSnapshot(PendingTxPath, []byte(text), 0o600)
}

func clearPendingTransactionMarker() { _ = os.Remove(PendingTxPath) }

func readPendingTransactionMarker() *Map {
	raw, err := os.ReadFile(PendingTxPath)
	if err != nil {
		return pyyaml.NewMap()
	}
	v, err := pyyaml.JSONLoads(raw)
	if err != nil {
		return pyyaml.NewMap()
	}
	if m, ok := asMap(v); ok {
		return m
	}
	return pyyaml.NewMap()
}

// CandidateRequestReachable is candidate_request_reachable.
func CandidateRequestReachable(transactionID, requestGeneration string) bool {
	clean := strings.TrimSpace(transactionID)
	gen := strings.ToLower(strings.TrimSpace(requestGeneration))
	if !txIDRe.MatchString(clean) || !hex64Re.MatchString(gen) {
		return false
	}
	marker := readPendingTransactionMarker()
	markerID := orStr(marker.Value("transaction_id"))
	markerGen := strings.ToLower(orStr(marker.Value("config_generation")))
	if !hex64Re.MatchString(markerGen) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(markerID), []byte(clean)) == 1 &&
		subtle.ConstantTimeCompare([]byte(markerGen), []byte(gen)) == 1
}

// checkCfgViaControld is check_cfg_via_controld (ok=false: fall back).
func checkCfgViaControld(cfgText string) (int, string, string, bool) {
	if haproxyControlSocket == "" || !fileExists(haproxyControlSocket) {
		return 0, "", "", false
	}
	payload := base64.StdEncoding.EncodeToString([]byte(cfgText))
	raw, err := controldRaw("check-config "+payload, time.Duration(haproxyControlTimeout)*time.Second)
	if err != nil {
		return 0, "", "", false
	}
	lines := pySplitlines(strings.ToValidUTF8(string(raw), "�"))
	if len(lines) == 0 {
		return 0, "", "", false
	}
	first := strings.TrimSpace(lines[0])
	if !strings.HasPrefix(first, "OK ") {
		return 1, "", strings.Join(lines, "\n"), true
	}
	rc := 1
	if n, err := strconv.Atoi(strings.TrimSpace(strings.SplitN(first, " ", 2)[1])); err == nil {
		rc = n
	}
	dec := func(i int) string {
		if i >= len(lines) {
			return ""
		}
		s := strings.TrimSpace(lines[i])
		if s == "" {
			return ""
		}
		b, err := pyB64Decode(s)
		if err != nil {
			return ""
		}
		return strings.ToValidUTF8(string(b), "�")
	}
	return rc, dec(1), dec(2), true
}

func criticalControlPlaneChecks(cfgText string) ([]any, error) {
	domains := controlPlaneDomains(cfgText)
	admin := domains["host_admin"]
	if len(admin) != 1 {
		return nil, &ValueError{"The rendered HAProxy configuration must contain exactly one protected HAProxy Admin domain"}
	}
	checks := []any{newMap("service", "admin", "domain", admin[0])}
	auth := domains["host_authelia"]
	if len(auth) > 1 {
		return nil, &ValueError{"The rendered HAProxy configuration contains multiple Authelia domains"}
	}
	if len(auth) == 1 {
		checks = append(checks, newMap("service", "authelia", "domain", auth[0]))
	}
	return checks, nil
}

func formatCheckLine(kind string, check any) string {
	status := get(check, "status")
	outcome := "FAILED"
	if truthy(get(check, "ok")) {
		outcome = "OK"
	}
	var suffix string
	if status != nil {
		suffix = "HTTP " + pyStr(status)
	} else {
		suffix = pyStr(orValue(get(check, "failure"), "no response"))
	}
	return fmt.Sprintf("%s %s (%s): %s — %s", kind, pyStr(get(check, "service")), pyStr(get(check, "domain")), outcome, suffix)
}

func formatGuardDiagnostics(result *Map) string {
	lines := []string{
		"Candidate SHA256: " + pyStr(orValue(result.Value("candidate_sha256"), "unknown")),
		"Previous SHA256: " + pyStr(orValue(result.Value("previous_sha256"), "unknown")),
	}
	if truthy(result.Value("backup_path")) {
		lines = append(lines, "Pre-apply backup: "+pyStr(result.Value("backup_path")))
	}
	if checks, ok := asList(orValue(result.Value("checks"), []any{})); ok {
		for _, c := range checks {
			lines = append(lines, formatCheckLine("Critical check", c))
		}
	}
	if truthy(result.Value("failure")) {
		lines = append(lines, "Apply failure: "+pyStr(result.Value("failure")))
	}
	if truthy(result.Value("rolled_back")) {
		rollback := orValue(result.Value("rollback"), pyyaml.NewMap())
		outcome := "FAILED"
		if truthy(get(rollback, "ok")) {
			outcome = "OK"
		}
		lines = append(lines, "Automatic rollback: "+outcome)
		if truthy(get(rollback, "failure")) {
			lines = append(lines, "Rollback failure: "+pyStr(get(rollback, "failure")))
		}
		if checks, ok := asList(orValue(get(rollback, "checks"), []any{})); ok {
			for _, c := range checks {
				lines = append(lines, formatCheckLine("Rollback check", c))
			}
		}
	}
	return strings.Join(lines, "\n")
}

// GetConfigTransactionStatus is get_config_transaction_status.
func GetConfigTransactionStatus(op *Op, transactionID string) *Map {
	clean := strings.TrimSpace(transactionID)
	if clean != "" && !txIDRe.MatchString(clean) {
		return newMap("ok", false, "error", "invalid configuration transaction id")
	}
	command := "config-transaction-status"
	if clean != "" {
		command += " " + clean
	}
	result := controldJSONRequest(command, haproxyControlTimeout)
	state := transactionState(result)
	if state == "confirmed" || state == "rolled_back" || state == "none" {
		marker := readPendingTransactionMarker()
		markerID := strOrEmpty(marker.Value("transaction_id"))
		resultID := strOrEmpty(orValue(result.Value("transaction_id"), result.Value("id")))
		if markerID == "" || resultID == "" || markerID == resultID {
			if marker.Len() > 0 {
				markBackendSets(op, "a transaction that ended "+state)
			}
			clearPendingTransactionMarker()
		}
	}
	followBackendSets(op, "a status check", result, false)
	return result
}

// ConfigTransactionIsPending is config_transaction_is_pending.
func ConfigTransactionIsPending(op *Op) (bool, string) {
	marker := readPendingTransactionMarker()
	markerID := orStr(marker.Value("transaction_id"))
	result := GetConfigTransactionStatus(op, markerID)
	switch transactionState(result) {
	case "prepared", "pending", "pending_confirmation", "rolling_back":
		return true, "A configuration confirmation is pending"
	case "rollback_failed":
		return true, "Automatic configuration rollback failed; inspect and restore HAProxy from the server console before editing again"
	}
	if markerID != "" && !truthy(result.Value("ok")) {
		return true, "A configuration confirmation may still be pending; haproxy-controld status is unavailable"
	}
	return false, ""
}

type namedPath struct{ name, path string }

func currentConfigSourcePaths() []namedPath {
	return []namedPath{{"vars.yml", ConfigYAML}, {"websites.yml", WebsitesYAML}, {"tcp.yml", TCPYAML}}
}

func appliedConfigSourcePaths() []namedPath {
	return []namedPath{{"vars.yml", StateVars}, {"websites.yml", StateWebsites}, {"tcp.yml", StateTCP}}
}

// Bundle is a source bundle: file name -> exact bytes.
type Bundle map[string][]byte

func readConfigSourceBundle(paths []namedPath, label string) (Bundle, error) {
	b := Bundle{}
	for _, np := range paths {
		raw, err := os.ReadFile(np.path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, valueErr("The %s %s file is missing; no transaction was started", label, np.name)
			}
			return nil, valueErr("The %s %s file cannot be read; no transaction was started", label, np.name)
		}
		if len(raw) > 2*1024*1024 {
			return nil, valueErr("%s exceeds the transaction size limit", np.name)
		}
		if bytes.IndexByte(raw, 0) >= 0 {
			return nil, valueErr("%s contains a NUL byte", np.name)
		}
		if !utf8.Valid(raw) {
			return nil, valueErr("%s is not valid UTF-8", np.name)
		}
		b[np.name] = raw
	}
	return b, nil
}

func bundleComplete(b Bundle) bool {
	if len(b) != len(configSourceOrder) {
		return false
	}
	for _, n := range configSourceOrder {
		if _, ok := b[n]; !ok {
			return false
		}
	}
	return true
}

// ConfigSourceGeneration is config_source_generation.
func ConfigSourceGeneration(b Bundle) (string, error) {
	if !bundleComplete(b) {
		return "", &ValueError{"The configuration source bundle is incomplete"}
	}
	fields := make([]string, 0, 3)
	for _, n := range configSourceOrder {
		fields = append(fields, n+":"+base64.StdEncoding.EncodeToString(b[n]))
	}
	sum := sha256.Sum256([]byte(configGenerationPrefix + strings.Join(fields, "|")))
	return hex.EncodeToString(sum[:]), nil
}

func loadYAMLDoc(raw []byte, invalidMsg string) (any, error) {
	v, err := pyyaml.Load(raw)
	if err != nil {
		return nil, &ValueError{invalidMsg}
	}
	return v, nil
}

func configGeoIPSelection(b Bundle) (*Map, error) {
	if !bundleComplete(b) {
		return nil, &ValueError{"The configuration source bundle is incomplete"}
	}
	v, err := loadYAMLDoc(b["vars.yml"], "The candidate vars.yml is invalid")
	if err != nil {
		return nil, err
	}
	if !truthy(v) {
		v = pyyaml.NewMap()
	}
	variables, ok := asMap(v)
	if !ok {
		return nil, &ValueError{"The candidate vars.yml root must be a mapping"}
	}
	enabledV, has := variables.Get("enable_geoip")
	if !has {
		enabledV = false
	}
	enabled, ok := enabledV.(bool)
	if !ok {
		return nil, &ValueError{"enable_geoip must be boolean"}
	}
	rawCountries := orValue(variables.Value("geoip_country_codes"), []any{})
	list, ok := asList(rawCountries)
	if !ok || len(list) > 249 {
		return nil, &ValueError{"geoip_country_codes must be a list of at most 249 codes"}
	}
	countries := map[string]bool{}
	for _, r := range list {
		s, ok := r.(string)
		if !ok {
			return nil, &ValueError{"GeoIP country codes must be strings"}
		}
		code := strings.ToUpper(strings.TrimSpace(s))
		if !isoCountryRe.MatchString(code) {
			return nil, valueErr("Invalid ISO GeoIP country code: %s", pyRepr(s))
		}
		countries[code] = true
	}
	selected := sortedKeys(countries)
	if enabled && len(selected) == 0 {
		return nil, &ValueError{"Select at least one GeoIP country before enabling GeoIP filtering"}
	}
	w, err := loadYAMLDoc(b["websites.yml"], "The candidate websites.yml is invalid")
	if err != nil {
		return nil, err
	}
	if !truthy(w) {
		w = pyyaml.NewMap()
	}
	websites, ok := asMap(w)
	if !ok {
		return nil, &ValueError{"The candidate websites.yml root must be a mapping"}
	}
	sites, ok := asList(orValue(websites.Value("sites"), []any{}))
	if !ok {
		return nil, &ValueError{"The candidate websites.yml sites value must be a list"}
	}
	for i, s := range sites {
		site, ok := asMap(s)
		if !ok {
			return nil, valueErr("sites[%d] must be an object", i)
		}
		sc := site.Value("geo_countries")
		if l, isList := sc.([]any); sc == nil || (isList && len(l) == 0) {
			continue
		}
		scl, ok := asList(sc)
		if !ok || len(scl) > 249 {
			return nil, valueErr("sites[%d].geo_countries must be a list of at most 249 ISO alpha-2 codes", i)
		}
		norm := map[string]bool{}
		for ci, r := range scl {
			s, ok := r.(string)
			if !ok {
				return nil, valueErr("sites[%d].geo_countries[%d] must be a string", i, ci)
			}
			code := strings.ToUpper(strings.TrimSpace(s))
			if !isoCountryRe.MatchString(code) {
				return nil, valueErr("Invalid site GeoIP country code: %s", pyRepr(s))
			}
			norm[code] = true
		}
		var unavailable []string
		for c := range norm {
			if !countries[c] {
				unavailable = append(unavailable, c)
			}
		}
		sort.Strings(unavailable)
		if len(unavailable) > 0 {
			label := pyStr(orValue(site.Value("domain"), site.Value("name"), int64(i)))
			return nil, valueErr("Site %s uses GeoIP countries not selected globally: %s", pyRepr(label), strings.Join(unavailable, ", "))
		}
	}
	return newMap("version", int64(1), "countries", strList(selected...), "access_filter_enabled", enabled), nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func configAdminAllowlist(b Bundle) ([]any, bool, error) {
	if !bundleComplete(b) {
		return nil, false, &ValueError{"The configuration source bundle is incomplete"}
	}
	v, err := loadYAMLDoc(b["vars.yml"], "The candidate vars.yml is invalid")
	if err != nil {
		return nil, false, err
	}
	if !truthy(v) {
		v = pyyaml.NewMap()
	}
	variables, ok := asMap(v)
	if !ok {
		return nil, false, &ValueError{"The candidate vars.yml root must be a mapping"}
	}
	rawV, has := variables.Get("admin_allowed_ips")
	if !has {
		return nil, false, nil
	}
	list, ok := asList(rawV)
	if !ok || len(list) > 256 {
		return nil, false, &ValueError{"admin_allowed_ips must be a list of at most 256 entries"}
	}
	entries := []any{}
	seen := map[string]bool{}
	for _, r := range list {
		s, ok := r.(string)
		if !ok {
			return nil, false, &ValueError{"admin_allowed_ips entries must be strings"}
		}
		text := strings.TrimSpace(s)
		if text == "" {
			continue
		}
		var canonical string
		if strings.Contains(text, "/") {
			p, ok := pyIPNetwork(text)
			if !ok {
				return nil, false, valueErr("Invalid admin_allowed_ips entry: %s", pyRepr(text))
			}
			canonical = p.String()
		} else {
			a, ok := pyIPAddress(text)
			if !ok {
				return nil, false, valueErr("Invalid admin_allowed_ips entry: %s", pyRepr(text))
			}
			canonical = a.String()
		}
		if !seen[canonical] {
			entries = append(entries, canonical)
			seen[canonical] = true
		}
	}
	return entries, true, nil
}

func sourceBundleSHA256(b Bundle) *Map {
	names := make([]string, 0, len(b))
	for n := range b {
		names = append(names, n)
	}
	sort.Strings(names)
	m := pyyaml.NewMap()
	for _, n := range names {
		sum := sha256.Sum256(b[n])
		m.Set(n, hex.EncodeToString(sum[:]))
	}
	return m
}

func stateSourceHashesMatch(state *Map, b Bundle) bool {
	expected, ok := asMap(state.Value("source_sha256"))
	if !ok {
		return false
	}
	return jinjaEqual(expected, sourceBundleSHA256(b))
}

func stateSpecMatchesSourceBundle(state *Map, b Bundle) bool {
	spec, err := specFromSourceBundle(b)
	if err != nil {
		return false
	}
	sites, has := state.Get("sites")
	if !has {
		sites = []any{}
	}
	tcp, has := state.Get("tcp")
	if !has {
		tcp = []any{}
	}
	cv := orValue(state.Value("config_vars"), pyyaml.NewMap())
	return jinjaEqual(sites, spec.Sites) && jinjaEqual(tcp, spec.TCP) && jinjaEqual(cv, spec.ConfigVars)
}

// pyUTCNowZ is datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z".
func pyUTCNowZ() string {
	t := time.Now().UTC()
	if t.Nanosecond()/1000 == 0 {
		return t.Format("2006-01-02T15:04:05") + "Z"
	}
	return t.Format("2006-01-02T15:04:05.000000") + "Z"
}

func persistAppliedStateBundle(cfgText string, b Bundle) error {
	if !bundleComplete(b) {
		return &ValueError{"The applied configuration source bundle is incomplete"}
	}
	rendered, err := renderHAProxyCfgFromSourceBundle(b, nil)
	if err != nil {
		return err
	}
	if rendered != cfgText {
		return &ValueError{"The configuration sources changed while the safe snapshot was being saved"}
	}
	spec, err := specFromSourceBundle(b)
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(cfgText))
	state := newMap("ts", pyUTCNowZ(), "haproxy_cfg_sha256", hex.EncodeToString(sum[:]),
		"haproxy_cfg_len", int64(len(cfgText)), "source_sha256", sourceBundleSHA256(b),
		"sites", spec.Sites, "tcp", spec.TCP, "config_vars", spec.ConfigVars)
	snap := map[string]string{"vars.yml": StateVars, "websites.yml": StateWebsites, "tcp.yml": StateTCP}
	for _, n := range []string{"vars.yml", "websites.yml", "tcp.yml"} {
		if err := atomicWriteSnapshot(snap[n], b[n], 0o600); err != nil {
			return err
		}
	}
	text, err := PyJSON(state, JSONOpts{Indent: 2})
	if err != nil {
		return err
	}
	return atomicWriteSnapshot(StatePath, []byte(text+"\n"), 0o600)
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func reconcileAppliedStateForCandidate(cfgText string, current, previous Bundle, allowDrift bool, expectedActive string) (Bundle, string, error) {
	active := readFileText(HAProxyCfgPath)
	if active == "" {
		return nil, "", &ValueError{"The active HAProxy configuration is unavailable; no transaction was started"}
	}
	activeSHA := sha256Hex(active)
	state := loadAppliedState()
	if state != nil && previous != nil {
		expected := strOrEmpty(state.Value("haproxy_cfg_sha256"))
		liveMatches := expected == activeSHA
		sourcesMatch := stateSourceHashesMatch(state, previous)
		legacyMatch := stateSpecMatchesSourceBundle(state, previous)
		if liveMatches && (sourcesMatch || legacyMatch) {
			if !sourcesMatch {
				if err := persistAppliedStateBundle(active, previous); err != nil {
					return nil, "", err
				}
				return previous, "legacy_snapshot_metadata", nil
			}
			return previous, "trusted_snapshot", nil
		}
		savedRender, err := renderHAProxyCfgFromSourceBundle(previous, nil)
		if err != nil {
			savedRender = ""
		}
		if savedRender == active {
			if err := persistAppliedStateBundle(active, previous); err != nil {
				return nil, "", err
			}
			return previous, "saved_render", nil
		}
	}
	currentRender, err := renderHAProxyCfgFromSourceBundle(current, nil)
	if err != nil {
		return nil, "", err
	}
	if currentRender == cfgText && currentRender == active {
		if err := persistAppliedStateBundle(active, current); err != nil {
			return nil, "", err
		}
		return current, "current_render", nil
	}
	details := newMap("external_drift_confirmation_required", true, "active_cfg_sha256", activeSHA)
	if allowDrift {
		expected := strings.ToLower(strings.TrimSpace(expectedActive))
		if !hex64Re.MatchString(expected) {
			return nil, "", &ConfigApplyPreparationError{Msg: "Explicit confirmation of the active HAProxy configuration is invalid.", ErrorCode: "haproxy_config_unknown_drift", Details: details}
		}
		if expected != activeSHA {
			return nil, "", &ConfigApplyPreparationError{Msg: "The active HAProxy configuration changed after it was reviewed. Review and confirm the new version before applying.", ErrorCode: "haproxy_config_unknown_drift", Details: details}
		}
		return current, "external_drift_override", nil
	}
	return nil, "", &ConfigApplyPreparationError{Msg: "The active HAProxy configuration contains external changes. Explicit confirmation is required before overwriting it.", ErrorCode: "haproxy_config_unknown_drift", Details: details}
}

func encodeBundle(b Bundle) *Map {
	m := pyyaml.NewMap()
	for _, n := range configSourceOrder {
		m.Set(n, base64.StdEncoding.EncodeToString(b[n]))
	}
	return m
}

func configSourcePayload(cfgText string, allowDrift bool, expectedActive string) (*Map, string, error) {
	current, err := readConfigSourceBundle(currentConfigSourcePaths(), "current")
	if err != nil {
		return nil, "", err
	}
	rendered, err := renderHAProxyCfgFromSourceBundle(current, nil)
	if err != nil {
		return nil, "", err
	}
	if rendered != cfgText {
		return nil, "", &ConfigApplyPreparationError{Msg: "The configuration sources changed while the candidate was being prepared. Validate again before applying.", ErrorCode: "haproxy_config_sources_changed"}
	}
	previous, err := readConfigSourceBundle(appliedConfigSourcePaths(), "safe snapshot")
	if err != nil {
		previous = nil
	}
	previous, baseline, err := reconcileAppliedStateForCandidate(cfgText, current, previous, allowDrift, expectedActive)
	if err != nil {
		return nil, "", err
	}
	geo, err := configGeoIPSelection(current)
	if err != nil {
		return nil, "", err
	}
	payload := newMap("candidate", encodeBundle(current), "previous", encodeBundle(previous), "geoip_selection", geo)
	allow, has, err := configAdminAllowlist(current)
	if err != nil {
		return nil, "", err
	}
	if has {
		payload.Set("admin_allowlist", allow)
	}
	return payload, baseline, nil
}

func configPreparationFailure(err error) *Map {
	code := "config_snapshot_invalid"
	var details *Map
	var pe *ConfigApplyPreparationError
	if errors.As(err, &pe) {
		code = pe.ErrorCode
		details = pe.Details
	}
	f := newMap("ok", false, "error", err.Error(), "error_code", code, "stdout", "", "stderr", err.Error())
	if details != nil {
		details.Each(func(k, v any) { f.Set(k, v) })
	}
	return f
}

func isValueError(err error) bool {
	var ve *ValueError
	var pe *ConfigApplyPreparationError
	return errors.As(err, &ve) || errors.As(err, &pe)
}

// PreflightCfgConfirmation is preflight_cfg_confirmation.
func PreflightCfgConfirmation(cfgText string, allowDrift bool, expectedActive string) (*Map, error) {
	_, baseline, err := configSourcePayload(cfgText, allowDrift, expectedActive)
	if err != nil {
		if isValueError(err) {
			return configPreparationFailure(err), nil
		}
		return nil, err
	}
	return newMap("ok", true, "baseline_source", baseline, "external_drift_overridden", baseline == "external_drift_override"), nil
}

// BeginCfgConfirmation is begin_cfg_confirmation.
func BeginCfgConfirmation(op *Op, cfgText string, confirmTimeout int, allowDrift bool, expectedActive string) (*Map, error) {
	rc, out, errText, err := CheckCfg(cfgText)
	if err != nil {
		return nil, err
	}
	if rc != 0 {
		return newMap("ok", false, "error", "HAProxy configuration validation failed", "stdout", out, "stderr", errText), nil
	}
	var checks []any
	var sources *Map
	var baseline, generation string
	prep := func() error {
		var err error
		if checks, err = criticalControlPlaneChecks(cfgText); err != nil {
			return err
		}
		if sources, baseline, err = configSourcePayload(cfgText, allowDrift, expectedActive); err != nil {
			return err
		}
		if baseline == "external_drift_override" {
			nowSHA := sha256Hex(readFileText(HAProxyCfgPath))
			if nowSHA != expectedActive {
				return &ConfigApplyPreparationError{Msg: "The active HAProxy configuration changed after it was reviewed. Review and confirm the new version before applying.",
					ErrorCode: "haproxy_config_unknown_drift", Details: newMap("external_drift_confirmation_required", true, "active_cfg_sha256", nowSHA)}
			}
		}
		cand, ok := asMap(sources.Value("candidate"))
		if !ok {
			return &ValueError{"The candidate configuration source bundle is missing"}
		}
		b := Bundle{}
		var derr error
		cand.Each(func(k, v any) {
			raw, e := pyB64DecodeStrict(pyStr(v))
			if e != nil {
				derr = &ValueError{e.Error()}
			}
			b[pyStr(k)] = raw
		})
		if derr != nil {
			return derr
		}
		generation, err = ConfigSourceGeneration(b)
		return err
	}
	if err := prep(); err != nil {
		if isValueError(err) {
			return configPreparationFailure(err), nil
		}
		return nil, err
	}
	timeout := confirmTimeout
	if timeout == 0 {
		timeout = haproxyConfirmTimeout
	}
	timeout = max(30, min(timeout, 300))
	cfgB64 := base64.StdEncoding.EncodeToString([]byte(cfgText))
	checksB64 := base64.StdEncoding.EncodeToString([]byte(MustJSON(checks, JSONOpts{Compact: true, EnsureASCII: true})))
	sourcesB64 := base64.StdEncoding.EncodeToString([]byte(MustJSON(sources, JSONOpts{Compact: true, EnsureASCII: true})))
	result := controldJSONRequest(fmt.Sprintf("begin-config-transaction %s %s %s %d", cfgB64, checksB64, sourcesB64, timeout), haproxyGuardedTimeout)
	state := transactionState(result)
	if truthy(result.Value("ok")) && (state == "pending" || state == "pending_confirmation") {
		result.Set("pending_confirmation", true)
		if err := writePendingTransactionMarker(result, generation); err != nil {
			return nil, err
		}
	} else if state == "rolled_back" || truthy(result.Value("rolled_back")) {
		followBackendSets(op, "an apply that was rolled back", result, true)
	}
	result.Set("baseline_source", baseline)
	result.Set("baseline_reconciled", baseline == "legacy_snapshot_metadata" || baseline == "saved_render" || baseline == "current_render")
	result.Set("external_drift_overridden", baseline == "external_drift_override")
	diagSource, ok := asMap(result.Value("safety"))
	if !ok {
		diagSource = result
	}
	diagnostics := formatGuardDiagnostics(diagSource)
	if _, has := result.Get("stdout"); !has {
		if truthy(result.Value("ok")) {
			result.Set("stdout", diagnostics)
		} else {
			result.Set("stdout", "")
		}
	}
	if _, has := result.Get("stderr"); !has {
		if truthy(result.Value("ok")) {
			result.Set("stderr", "")
		} else {
			result.Set("stderr", diagnostics)
		}
	}
	return result, nil
}

// ConfirmCfgTransaction is confirm_cfg_transaction.
func ConfirmCfgTransaction(op *Op, transactionID, candidateSHA string) *Map {
	clean := orStr(transactionID)
	sha := strings.ToLower(orStr(candidateSHA))
	if !txIDRe.MatchString(clean) {
		return newMap("ok", false, "error", "invalid configuration transaction id")
	}
	if !hex64Re.MatchString(sha) {
		return newMap("ok", false, "error", "invalid candidate SHA256")
	}
	result := controldJSONRequest(fmt.Sprintf("confirm-config-transaction %s %s", clean, sha), haproxyGuardedTimeout)
	if truthy(result.Value("ok")) && transactionState(result) == "confirmed" {
		markBackendSets(op, "a confirmed transaction")
		clearPendingTransactionMarker()
		followBackendSets(op, "a confirmed transaction", result, true)
	} else if transactionState(result) == "rolled_back" {
		followBackendSets(op, "a late confirmation that was rolled back", result, true)
	}
	return result
}

// RollbackCfgTransaction is rollback_cfg_transaction.
func RollbackCfgTransaction(op *Op, transactionID string) *Map {
	clean := orStr(transactionID)
	if !txIDRe.MatchString(clean) {
		return newMap("ok", false, "error", "invalid configuration transaction id")
	}
	result := controldJSONRequest("rollback-config-transaction "+clean, haproxyGuardedTimeout)
	if transactionState(result) == "rolled_back" {
		markBackendSets(op, "a transaction rollback")
		clearPendingTransactionMarker()
		followBackendSets(op, "a transaction rollback", result, true)
	}
	return result
}

// UDPListenPortConflict is udp_listen_port_conflict ("" for none).
func UDPListenPortConflict(start, end int64) string {
	if haproxyControlSocket == "" || !fileExists(haproxyControlSocket) {
		return ""
	}
	raw, err := controldRaw(fmt.Sprintf("udp-port-check %d %d", start, end), time.Duration(haproxyControlTimeout)*time.Second)
	if err != nil {
		return ""
	}
	resp := strings.TrimSpace(strings.ToValidUTF8(string(raw), "�"))
	if strings.HasPrefix(resp, "OK busy") {
		parts := strings.Fields(resp)
		busy := strconv.FormatInt(start, 10)
		if len(parts) >= 3 {
			busy = parts[2]
		}
		return fmt.Sprintf("Port %s/udp is already in use on the host", busy)
	}
	return ""
}

// ApplyUDPForwards is apply_udp_forwards.
func ApplyUDPForwards() (bool, *Map, string) {
	result := controldJSONRequest("udp-apply-json", 70)
	if result.Value("ok") == true {
		return true, result, ""
	}
	return false, pyyaml.NewMap(), pyStr(orValue(result.Value("error"), "UDP forwarding apply failed"))
}

// GetUDPRuntimeStatus is get_udp_runtime_status.
func GetUDPRuntimeStatus() *Map {
	result := controldJSONRequest("udp-status", haproxyControlTimeout)
	if result.Value("ok") == true {
		return result
	}
	return newMap("ok", false, "error", pyStr(orValue(result.Value("error"), "UDP forwarding runtime status is unavailable")))
}

// ---- haproxy.cfg rendering ----

type cfgTemplateCache struct {
	mu    sync.Mutex
	env   *jinja.Environment
	mtime time.Time
	size  int64
}

var cfgTemplate cfgTemplateCache

func haproxyCfgEnv() *jinja.Environment {
	cfgTemplate.mu.Lock()
	defer cfgTemplate.mu.Unlock()
	info, err := os.Stat(HAPTemplate)
	if cfgTemplate.env != nil && err == nil && info.ModTime().Equal(cfgTemplate.mtime) && info.Size() == cfgTemplate.size {
		return cfgTemplate.env
	}
	env := jinja.NewEnvironment(func(name string) (string, error) {
		raw, err := os.ReadFile(filepath.Join(filepath.Dir(HAPTemplate), filepath.Base(name)))
		if err != nil {
			return "", fmt.Errorf("haproxy.cfg.j2: %w", err)
		}
		return string(raw), nil
	})
	env.Autoescape = false
	env.TrimBlocks = true
	env.LstripBlocks = true
	env.Filters["regex_replace"] = jinja.RegexReplaceFilter
	env.Filters["combine"] = jinja.CombineFilter
	cfgTemplate.env = env
	if err == nil {
		cfgTemplate.mtime, cfgTemplate.size = info.ModTime(), info.Size()
	}
	return env
}

// loadYAML is _load_yaml: {} for a missing or empty file, a non-mapping
// root wrapped as {"_": data}.
func loadYAML(path string) (*Map, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return pyyaml.NewMap(), nil
		}
		return nil, err
	}
	v, err := pyyaml.Load(raw)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return pyyaml.NewMap(), nil
	}
	if m, ok := asMap(v); ok {
		return m, nil
	}
	return newMap("_", v), nil
}

func loadYAMLBytes(raw []byte, filename string) (*Map, error) {
	if !utf8.Valid(raw) {
		return nil, valueErr("The saved %s snapshot is invalid", filename)
	}
	v, err := pyyaml.Load(raw)
	if err != nil {
		return nil, valueErr("The saved %s snapshot is invalid", filename)
	}
	if v == nil {
		return pyyaml.NewMap(), nil
	}
	if m, ok := asMap(v); ok {
		return m, nil
	}
	return newMap("_", v), nil
}

// Spec is _spec_from_documents.
type Spec struct {
	Sites      any
	TCP        any
	ConfigVars *Map
}

func specFromDocuments(sitesDoc, tcpDoc, configVars *Map) Spec {
	sites, has := sitesDoc.Get("sites")
	if !has {
		sites = []any{}
	}
	if _, ok := asList(sites); !ok {
		sites = []any{}
	}
	tcp := tcpDoc.Value("tcp_proxies")
	if tcp == nil {
		tcp = tcpDoc.Value("tcp")
	}
	if _, ok := asList(tcp); !ok {
		tcp = []any{}
	}
	cv := configVars
	if cv == nil || cv.Len() == 0 {
		cv = pyyaml.NewMap()
	}
	return Spec{Sites: sites, TCP: tcp, ConfigVars: cv}
}

func sourceBundleDocuments(b Bundle) (*Map, *Map, *Map, error) {
	if !bundleComplete(b) {
		return nil, nil, nil, &ValueError{"The configuration source bundle is incomplete"}
	}
	w, err := loadYAMLBytes(b["websites.yml"], "websites.yml")
	if err != nil {
		return nil, nil, nil, err
	}
	t, err := loadYAMLBytes(b["tcp.yml"], "tcp.yml")
	if err != nil {
		return nil, nil, nil, err
	}
	v, err := loadYAMLBytes(b["vars.yml"], "vars.yml")
	if err != nil {
		return nil, nil, nil, err
	}
	return w, t, v, nil
}

func specFromSourceBundle(b Bundle) (Spec, error) {
	w, t, v, err := sourceBundleDocuments(b)
	if err != nil {
		return Spec{}, err
	}
	return specFromDocuments(w, t, v), nil
}

func renderHAProxyCfgFromDocuments(sitesDoc, tcpDoc, configVars *Map, extra map[string]any) (string, error) {
	spec := specFromDocuments(sitesDoc, tcpDoc, configVars)
	ctx := map[string]any{}
	configVars.Each(func(k, v any) { ctx[pyStr(k)] = v })
	ctx["sites"] = spec.Sites
	ctx["tcp_proxies"] = spec.TCP
	ctx["tcp"] = spec.TCP
	ctx["easy_ha_proxy_runtime_vars"] = pyyaml.NewMap()
	ctx["easy_ha_proxy_runtime_websites"] = pyyaml.NewMap()
	ctx["easy_ha_proxy_runtime_tcp"] = pyyaml.NewMap()
	for k, v := range extra {
		ctx[k] = v
	}
	out, err := haproxyCfgEnv().Render(filepath.Base(HAPTemplate), ctx)
	if err != nil {
		return "", &RenderError{err.Error()}
	}
	return out, nil
}

// RenderError is a template failure while rendering haproxy.cfg.
type RenderError struct{ Msg string }

func (e *RenderError) Error() string { return e.Msg }

func renderHAProxyCfgFromSourceBundle(b Bundle, extra map[string]any) (string, error) {
	ctx := map[string]any{}
	for k, v := range extra {
		ctx[k] = v
	}
	gen, err := ConfigSourceGeneration(b)
	if err != nil {
		return "", err
	}
	ctx["easy_ha_proxy_config_generation"] = gen
	w, t, v, err := sourceBundleDocuments(b)
	if err != nil {
		return "", err
	}
	return renderHAProxyCfgFromDocuments(w, t, v, ctx)
}

// RenderHAProxyCfg is render_haproxy_cfg.
func RenderHAProxyCfg(extra map[string]any) (string, error) {
	b, err := readConfigSourceBundle(currentConfigSourcePaths(), "current")
	if err != nil {
		return "", err
	}
	return renderHAProxyCfgFromSourceBundle(b, extra)
}

func readFileText(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.ToValidUTF8(string(raw), "�")
}

func getCurrentSpec() (Spec, error) {
	w, err := loadYAML(WebsitesYAML)
	if err != nil {
		return Spec{}, err
	}
	t, err := loadYAML(TCPYAML)
	if err != nil {
		return Spec{}, err
	}
	v, err := loadYAML(ConfigYAML)
	if err != nil {
		return Spec{}, err
	}
	return specFromDocuments(w, t, v), nil
}

// SaveAppliedStateStrict is save_applied_state_strict.
func SaveAppliedStateStrict(cfgText string) error {
	b, err := readConfigSourceBundle(currentConfigSourcePaths(), "current")
	if err != nil {
		return err
	}
	return persistAppliedStateBundle(cfgText, b)
}

// EnsureAppliedStateBaseline is ensure_applied_state_baseline.
func EnsureAppliedStateBaseline(op *Op, cfgText string) (bool, error) {
	if pending, _ := ConfigTransactionIsPending(op); pending {
		return false, nil
	}
	active := readFileText(HAProxyCfgPath)
	if active == "" || active != cfgText {
		return false, nil
	}
	if state := loadAppliedState(); state != nil {
		current, err := readConfigSourceBundle(currentConfigSourcePaths(), "current")
		if err != nil {
			return false, nil
		}
		if stateSourceHashesMatch(state, current) || !stateSpecMatchesSourceBundle(state, current) {
			return false, nil
		}
	}
	if err := SaveAppliedStateStrict(cfgText); err != nil {
		return false, err
	}
	return true, nil
}

func loadAppliedState() *Map {
	raw, err := os.ReadFile(StatePath)
	if err != nil {
		return nil
	}
	v, err := pyyaml.JSONLoads(raw)
	if err != nil {
		return nil
	}
	m, ok := asMap(v)
	if !ok {
		if v == nil {
			return nil
		}
		return pyyaml.NewMap()
	}
	return m
}

// CheckCfg is check_cfg.
func CheckCfg(cfgText string) (int, string, string, error) {
	if active := readFileText(HAProxyCfgPath); active != "" {
		if err := ValidateControlPlaneTransition(active, cfgText); err != nil {
			return 1, "", err.Error(), nil
		}
	}
	if rc, out, errText, ok := checkCfgViaControld(cfgText); ok {
		return rc, out, errText, nil
	}
	f, err := os.CreateTemp("", "tmp")
	if err != nil {
		return 0, "", "", err
	}
	path := f.Name()
	defer os.Remove(path)
	_, _ = f.WriteString(cfgText)
	f.Close()
	ctx, cancel := context.WithTimeout(context.Background(), haproxyCheckTimeout*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, hapCheckCmd[0], append(hapCheckCmd[1:], path)...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err = cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return 124, "", fmt.Sprintf("haproxy -c did not finish within %d seconds and was stopped", haproxyCheckTimeout), nil
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), out.String(), errb.String(), nil
		}
		return 0, "", "", &OSError{fmt.Sprintf("[Errno 2] No such file or directory: '%s'", hapCheckCmd[0])}
	}
	return 0, out.String(), errb.String(), nil
}

func sourcePath(kind string) (string, bool) {
	switch kind {
	case "websites":
		return WebsitesYAML, true
	case "tcp":
		return TCPYAML, true
	case "vars":
		return ConfigYAML, true
	}
	return "", false
}

// Op carries the source locks one operation holds (Python keeps them in a
// thread-local set; a Go request is one Op).
type Op struct {
	held map[string]*os.File
	// Actor is g.remote_user, for what the operation records.
	Actor string
}

// NewOp starts an operation that holds no locks.
func NewOp() *Op { return &Op{held: map[string]*os.File{}} }

func (op *Op) holdsAny() bool { return op != nil && len(op.held) > 0 }

// Lock is source_lock(kind): re-entrant within the Op; release with the returned func.
func (op *Op) Lock(kind string) (func(), error) {
	if _, ok := op.held[kind]; ok {
		return func() {}, nil
	}
	var path string
	if kind == "udp" {
		path = UDPYAML
	} else {
		p, ok := sourcePath(kind)
		if !ok {
			return nil, fmt.Errorf("KeyError: %s", pyRepr(kind))
		}
		path = p
	}
	lockPath := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".lock")
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o777); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o666)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	op.held[kind] = f
	return func() {
		delete(op.held, kind)
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}

// LockAll takes several locks in order and releases them in reverse.
func (op *Op) LockAll(kinds ...string) (func(), error) {
	var releases []func()
	for _, k := range kinds {
		r, err := op.Lock(k)
		if err != nil {
			for i := len(releases) - 1; i >= 0; i-- {
				releases[i]()
			}
			return nil, err
		}
		releases = append(releases, r)
	}
	return func() {
		for i := len(releases) - 1; i >= 0; i-- {
			releases[i]()
		}
	}, nil
}

// StaleEntry is a site or TCP proxy changed after its form was loaded.
type StaleEntry struct{ Msg string }

func (e *StaleEntry) Error() string { return e.Msg }

// EntryRevision is entry_revision.
func EntryRevision(entry any) string {
	canonical := MustJSON(entry, JSONOpts{SortKeys: true, Compact: true, DefaultStr: true})
	return sha256Hex(canonical)
}

// CheckEntryRevision is check_entry_revision.
func CheckEntryRevision(entry any, expected any, what string) error {
	exp := orStr(expected)
	if exp != "" && entry != nil && EntryRevision(entry) != exp {
		return &StaleEntry{what + " was changed in another session after this page was loaded. Reload the page to see that change, then make yours again."}
	}
	return nil
}

// UpdateYAMLFile is update_yaml_file.
func UpdateYAMLFile(op *Op, kind, content string) (bool, string) {
	if pending, msg := ConfigTransactionIsPending(op); pending {
		return false, msg
	}
	path, ok := sourcePath(kind)
	if !ok {
		return false, "Unknown file type: " + pyRepr(kind)
	}
	release, err := op.Lock(kind)
	if err != nil {
		return false, err.Error()
	}
	defer release()
	return replaceYAMLSource(kind, path, content)
}

func pyStrftimeNow() string { return time.Now().Format("20060102150405") }

func replaceYAMLSource(kind, path, content string, allow ...string) (bool, string) {
	if len(content) > 2*1024*1024 {
		return false, "YAML file exceeds the 2 MB size limit"
	}
	if msg, rootErr := validateYAMLContent(kind, path, content, allow...); rootErr {
		return false, msg
	} else if msg != "" {
		return false, "YAML validation error: " + msg
	}
	backupDir := filepath.Join(BaseDir, "backups")
	if err := os.MkdirAll(backupDir, 0o777); err != nil {
		return false, fmt.Sprintf("Failed to create backup directory %s: %s", backupDir, pyFileError(err, backupDir))
	}
	if info, err := os.Stat(path); err == nil {
		backup := filepath.Join(backupDir, filepath.Base(path)+".bak."+pyStrftimeNow())
		if err := copyFile2(path, backup, info); err != nil {
			return false, fmt.Sprintf("Failed to save backup %s: %s", backup, err.Error())
		}
		rotateBackups(backupDir, filepath.Base(path)+".bak.*", maxYAMLBackups)
	}
	mode := os.FileMode(0o640)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	if err := atomicWriteSnapshot(path, []byte(content), mode); err != nil {
		return false, fmt.Sprintf("Failed to write %s: %s", path, pyOSError(err))
	}
	return true, fmt.Sprintf("File %s updated successfully", filepath.Base(path))
}

// validateYAMLContent returns the validation message, and true when the
// message is the bare "root must be a mapping" answer (not wrapped).
func validateYAMLContent(kind, path, content string, allow ...string) (string, bool) {
	v, err := pyyaml.Load([]byte(content))
	if err != nil {
		return pyYAMLErrorText(err), false
	}
	if !truthy(v) {
		v = pyyaml.NewMap()
	}
	data, ok := asMap(v)
	if !ok {
		return "The YAML root must be a mapping", true
	}
	if err := ValidateConfigData(kind, data); err != nil {
		return err.Error(), false
	}
	if kind == "vars" && fileExists(path) {
		existing, err := loadYAML(path)
		if err != nil {
			return pyYAMLErrorText(err), false
		}
		if err := ValidateProtectedVarsUnchanged(existing, data, allow...); err != nil {
			return err.Error(), false
		}
	}
	return "", false
}

// pyYAMLErrorText is str(yaml.YAMLError) as closely as the Go parser allows.
func pyYAMLErrorText(err error) string { return err.Error() }

// copyFile2 is shutil.copy2: data, permission bits and times.
func copyFile2(src, dst string, info os.FileInfo) error {
	raw, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, raw, info.Mode().Perm()); err != nil {
		return err
	}
	_ = os.Chmod(dst, info.Mode().Perm())
	return os.Chtimes(dst, info.ModTime(), info.ModTime())
}

func rotateBackups(dir, pattern string, keep int) {
	matches, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		return
	}
	type f struct {
		path  string
		mtime time.Time
	}
	var files []f
	for _, m := range matches {
		info, err := os.Stat(m)
		if err != nil {
			return
		}
		files = append(files, f{m, info.ModTime()})
	}
	sort.SliceStable(files, func(i, j int) bool { return files[i].mtime.After(files[j].mtime) })
	for i := keep; i < len(files); i++ {
		_ = os.Remove(files[i].path)
	}
}

func listToDictByName(items any) (*Map, []string) {
	result := pyyaml.NewMap()
	list, _ := asList(items)
	for _, it := range list {
		m, ok := asMap(it)
		if !ok {
			continue
		}
		name := m.Value("name")
		if !truthy(name) {
			continue
		}
		result.Set(pyStr(name), m)
	}
	var names []string
	for _, k := range result.Keys() {
		names = append(names, k.(string))
	}
	return result, names
}

func mapKeyStrings(m *Map) map[string]bool {
	out := map[string]bool{}
	for _, k := range m.Keys() {
		out[pyStr(k)] = true
	}
	return out
}

// GetConfigDiffSummary is get_config_diff_summary.
func GetConfigDiffSummary(rendered *string) (*Map, error) {
	var cfg string
	if rendered == nil {
		r, err := RenderHAProxyCfg(nil)
		if err != nil {
			return nil, err
		}
		cfg = r
	} else {
		cfg = *rendered
	}
	serverDiffers := !ConfigsOperationallyEqual(readFileText(HAProxyCfgPath), cfg)
	applied := loadAppliedState()
	spec, err := getCurrentSpec()
	if err != nil {
		return nil, err
	}
	summary := newMap("server_differs", serverDiffers, "has_applied_state", applied != nil, "source_has_changes", false,
		"has_changes", false, "sites_added", []any{}, "sites_removed", []any{}, "sites_changed", pyyaml.NewMap(),
		"tcp_added", []any{}, "tcp_removed", []any{}, "tcp_changed", pyyaml.NewMap(), "global_changed_keys", []any{})
	if applied == nil || applied.Len() == 0 {
		return summary, nil
	}
	diffEntries := func(curr, old any, withChanges bool) ([]any, []any, *Map) {
		cm, _ := listToDictByName(curr)
		om, _ := listToDictByName(old)
		cn, on := mapKeyStrings(cm), mapKeyStrings(om)
		var added, removed, both []string
		for n := range cn {
			if !on[n] {
				added = append(added, n)
			} else {
				both = append(both, n)
			}
		}
		for n := range on {
			if !cn[n] {
				removed = append(removed, n)
			}
		}
		sort.Strings(added)
		sort.Strings(removed)
		sort.Strings(both)
		changed := pyyaml.NewMap()
		for _, n := range both {
			before := om.Value(n).(*Map)
			after := cm.Value(n).(*Map)
			if jinjaEqual(before, after) {
				continue
			}
			keys := map[string]bool{}
			for _, k := range before.Keys() {
				keys[pyStr(k)] = true
			}
			for _, k := range after.Keys() {
				keys[pyStr(k)] = true
			}
			var changedKeys []string
			for k := range keys {
				if !jinjaEqual(before.Value(k), after.Value(k)) {
					changedKeys = append(changedKeys, k)
				}
			}
			sort.Strings(changedKeys)
			if len(changedKeys) == 0 {
				continue
			}
			entry := newMap("changed_keys", strList(changedKeys...))
			if withChanges {
				changes := pyyaml.NewMap()
				for _, k := range changedKeys {
					changes.Set(k, newMap("before", before.Value(k), "after", after.Value(k)))
				}
				entry.Set("changes", changes)
			}
			changed.Set(n, entry)
		}
		return strList(added...), strList(removed...), changed
	}
	oldSites, has := applied.Get("sites")
	if !has {
		oldSites = []any{}
	}
	sa, sr, sc := diffEntries(spec.Sites, oldSites, true)
	summary.Set("sites_added", sa)
	summary.Set("sites_removed", sr)
	summary.Set("sites_changed", sc)
	oldTCP, has := applied.Get("tcp")
	if !has {
		oldTCP = []any{}
	}
	ta, tr, tc := diffEntries(spec.TCP, oldTCP, false)
	summary.Set("tcp_added", ta)
	summary.Set("tcp_removed", tr)
	summary.Set("tcp_changed", tc)
	currVars := spec.ConfigVars
	oldVars, _ := asMap(orValue(applied.Value("config_vars"), pyyaml.NewMap()))
	if oldVars == nil {
		oldVars = pyyaml.NewMap()
	}
	keys := map[string]bool{}
	for k := range mapKeyStrings(currVars) {
		keys[k] = true
	}
	for k := range mapKeyStrings(oldVars) {
		keys[k] = true
	}
	var global []string
	for _, k := range sortedKeys(keys) {
		if !jinjaEqual(currVars.Value(k), oldVars.Value(k)) {
			global = append(global, k)
		}
	}
	summary.Set("global_changed_keys", strList(global...))
	srcChanges := len(sa) > 0 || len(sr) > 0 || sc.Len() > 0 || len(ta) > 0 || len(tr) > 0 || tc.Len() > 0 || len(global) > 0
	summary.Set("source_has_changes", srcChanges)
	summary.Set("has_changes", serverDiffers || srcChanges)
	return summary, nil
}

// GetHAProxyConfigurationState is get_haproxy_configuration_state.
func GetHAProxyConfigurationState(op *Op) (*Map, error) {
	rendered, err := RenderHAProxyCfg(nil)
	if err != nil {
		return nil, err
	}
	summary, err := GetConfigDiffSummary(&rendered)
	if err != nil {
		return nil, err
	}
	tx := GetConfigTransactionStatus(op, "")
	ts := transactionState(tx)
	pendingStates := map[string]bool{"prepared": true, "pending": true, "pending_confirmation": true, "rolling_back": true}
	settled := map[string]bool{"none": true, "confirmed": true, "rolled_back": true, "expired": true, "failed": true, "cancelled": true}
	if !truthy(summary.Value("has_applied_state")) && !truthy(summary.Value("server_differs")) && settled[ts] {
		if _, err := EnsureAppliedStateBaseline(op, rendered); err != nil {
			return nil, err
		}
		if summary, err = GetConfigDiffSummary(&rendered); err != nil {
			return nil, err
		}
	}
	lenOf := func(key string) int64 {
		switch v := summary.Value(key).(type) {
		case []any:
			return int64(len(v))
		case *Map:
			return int64(v.Len())
		}
		return 0
	}
	siteChanges := lenOf("sites_added") + lenOf("sites_removed") + lenOf("sites_changed")
	tcpChanges := lenOf("tcp_added") + lenOf("tcp_removed") + lenOf("tcp_changed")
	globalChanges := lenOf("global_changed_keys")
	srcChanges := truthy(summary.Value("source_has_changes"))
	renderedDiffers := truthy(summary.Value("server_differs"))
	var publicState, state string
	switch {
	case pendingStates[ts]:
		publicState, state = "pending_confirmation", "pending_confirmation"
	case ts == "rollback_failed":
		publicState, state = "rollback_failed", "rollback_failed"
	case settled[ts]:
		publicState = "idle"
		switch {
		case srcChanges:
			state = "unapplied"
		case renderedDiffers:
			state = "runtime_drift"
		case truthy(summary.Value("has_applied_state")):
			state = "clean"
		default:
			state = "unknown"
		}
	default:
		publicState, state = "unavailable", "unknown"
	}
	return newMap("ok", true, "state", state, "status_available", state != "unknown",
		"pending", srcChanges || renderedDiffers || publicState == "pending_confirmation" || publicState == "rollback_failed",
		"has_applied_state", truthy(summary.Value("has_applied_state")), "source_has_changes", srcChanges,
		"rendered_differs", renderedDiffers, "transaction_state", publicState,
		"changes", newMap("sites", siteChanges, "tcp", tcpChanges, "global", globalChanges, "total", siteChanges+tcpChanges+globalChanges)), nil
}

// RevertToLastAppliedState is revert_to_last_applied_state.
func RevertToLastAppliedState(op *Op) (bool, string) {
	if pending, msg := ConfigTransactionIsPending(op); pending {
		return false, msg
	}
	if !fileExists(StatePath) {
		return false, "No saved applied state; there is nothing to revert"
	}
	anyRestored := false
	var errs []string
	markBackendSets(op, "discarded changes")
	mapping := []struct{ src, dst, label string }{
		{StateWebsites, WebsitesYAML, "websites.yml"},
		{StateTCP, TCPYAML, "tcp.yml"},
		{StateVars, ConfigYAML, "vars.yml"},
	}
	if err := func() error {
		release, err := op.LockAll("websites", "tcp", "vars")
		if err != nil {
			return err
		}
		defer release()
		for _, m := range mapping {
			if !fileExists(m.src) {
				continue
			}
			raw, err := os.ReadFile(m.src)
			if err == nil {
				mode := os.FileMode(0o640)
				if info, e := os.Stat(m.dst); e == nil {
					mode = info.Mode().Perm()
				}
				_ = os.MkdirAll(filepath.Dir(m.dst), 0o777)
				err = atomicWriteSnapshot(m.dst, raw, mode)
			}
			if err != nil {
				errs = append(errs, m.label+": "+pyOSError(err))
				continue
			}
			anyRestored = true
		}
		return nil
	}(); err != nil {
		return false, err.Error()
	}
	note := ""
	if anyRestored {
		note = followBackendSets(op, "discarded changes", nil, true)
	}
	suffix := ""
	if note != "" {
		suffix = " " + note
	}
	if len(errs) > 0 {
		return false, "Failed to revert some files: " + strings.Join(errs, "; ") + suffix
	}
	if !anyRestored {
		return false, "YAML backup files were not found"
	}
	return true, "YAML files reverted to the last applied state" + suffix
}

// GetServerCfgText is get_server_cfg_text.
func GetServerCfgText() string { return readFileText(HAProxyCfgPath) }

func configForOperationalComparison(cfgText string) string {
	return configGenerationDirectiveRe.ReplaceAllString(cfgText, "${1}<config-generation>${2}${3}")
}

// ConfigsOperationallyEqual is configs_operationally_equal.
func ConfigsOperationallyEqual(server, rendered string) bool {
	return configForOperationalComparison(server) == configForOperationalComparison(rendered)
}
