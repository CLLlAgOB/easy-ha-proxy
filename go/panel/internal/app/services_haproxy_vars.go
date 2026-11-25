package app

// Port of services_haproxy_vars.py: the schema-driven vars.yml editor.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"

	"easy-ha-proxy/panel/shared/pyyaml"
)

const (
	maxVarsBytes       = 2 * 1024 * 1024
	hstsDefaultSeconds = 15552000
	intervalPattern    = `^[1-9][0-9]*(?:ms|s|m|h|d)$`
)

var (
	hstsLegacyRe   = regexp.MustCompile(`^([0-9]+)([smhd])$`)
	hstsUnit       = map[string]int64{"s": 1, "m": 60, "h": 3600, "d": 86400}
	listSplitRe    = regexp.MustCompile(`[\n,]+`)
	acmeEmailRe    = regexp.MustCompile(`^[^@\s]{1,64}@[^@\s]{1,253}\.[A-Za-z0-9-]{2,63}$`)
	varsSections   []*Map
	schemaFields   = map[string]*Map{}
	editableFields = map[string]*Map{}
)

type fieldOpt struct {
	help     string
	readonly bool
	options  []string
	min, max any
	pattern  string
	rows     int64
	def      any
}

func vfield(path, label, typ string, o fieldOpt) *Map {
	return newMap("path", path, "label", label, "type", typ, "help", o.help, "readonly", o.readonly,
		"options", strList(o.options...), "minimum", o.min, "maximum", o.max, "pattern", o.pattern,
		"rows", o.rows, "default", o.def)
}

func init() {
	iv := func(path, label string, o fieldOpt) *Map {
		o.pattern = intervalPattern
		return vfield(path, label, "interval", o)
	}
	n := func(v int64) any { return v }
	sec := func(title, desc string, fields ...*Map) *Map {
		list := make([]any, len(fields))
		for i, f := range fields {
			list[i] = f
		}
		return newMap("title", title, "description", desc, "fields", list)
	}
	varsSections = []*Map{
		sec("Frontends and access", "Global switches used directly by the HAProxy template.",
			vfield("enable_http80", "Listen on HTTP port 80", "boolean", fieldOpt{help: "Keep enabled when HTTP redirects or ACME challenges are required."}),
			vfield("admin_ips_enabled", "Restrict the admin frontend by IP list", "boolean", fieldOpt{help: "Configure the list below while this restriction is disabled. Save settings, then validate and apply the HAProxy configuration. When Authelia is enabled, both checks must pass."}),
			vfield("admin_allowed_ips", "Admin frontend allowed IPs and networks", "list", fieldOpt{rows: 4, def: []any{}, help: "Enter one IP address or CIDR network per line. Add the current connection IP before enabling the restriction. These addresses are trusted admin sources and may bypass HAProxy filtering, bans, or rate limits."}),
			vfield("admin_authelia_enabled", "HAProxy Admin authentication via Authelia", "boolean", fieldOpt{readonly: true, help: "Required for the administration control plane and inherited from global Authelia. Use the IP allow list as an additional access gate."}),
			vfield("enable_geoip", "Enable GeoIP filtering subsystem", "boolean", fieldOpt{def: false, help: "Master switch for configured HTTP sites; HAProxy Admin and Authelia are not filtered. Sites are covered only when the default below or their per-site override is enabled."}),
			vfield("site_defaults.enable_geoip", "Apply GeoIP filtering to sites by default", "boolean", fieldOpt{def: true, help: "Affects every HTTP site without an explicit GeoIP override, not only new sites. Warning: when the master switch is on and this default is off, only sites explicitly enabled in their editor are filtered."}),
			vfield("geoip_mode", "GeoIP mode", "choice", fieldOpt{options: []string{"allow", "deny"}, def: "allow"}),
			vfield("haproxy_nbthread", "HAProxy worker threads", "integer", fieldOpt{min: n(1), max: n(256), help: "The installer may recalculate this value during a full stack update."}),
		),
		sec("Default backend", "Defaults inherited by newly created HTTP sites.",
			vfield("site_defaults.balance", "Load-balancing algorithm", "choice", fieldOpt{options: []string{"roundrobin", "leastconn", "source", "first", "random"}}),
			vfield("site_defaults.sticky", "Sticky sessions", "choice", fieldOpt{options: []string{"none", "cookie", "source"}}),
			vfield("site_defaults.backend_port", "Backend port", "integer", fieldOpt{min: n(1), max: n(65535)}),
			vfield("site_defaults.backend_ssl", "Use TLS to the backend", "boolean", fieldOpt{}),
			vfield("site_defaults.backend_ssl_verify", "Verify backend TLS certificate", "boolean", fieldOpt{}),
			vfield("site_defaults.redirect_to_https", "Redirect HTTP to HTTPS", "boolean", fieldOpt{}),
			vfield("site_defaults.maintenance", "Maintenance mode by default", "boolean", fieldOpt{}),
			vfield("site_defaults.hsts", "HSTS max-age", "integer", fieldOpt{min: n(0), max: n(63072000), def: int64(hstsDefaultSeconds), help: "Default: 15552000 seconds (180 days). Set to 0 to disable HSTS."}),
			vfield("site_defaults.compress", "Enable response compression", "boolean", fieldOpt{}),
			vfield("site_defaults.default_favicon", "Serve a neutral favicon", "boolean", fieldOpt{def: true, help: "When a site answers /favicon.ico with 404, the gateway returns a neutral icon instead. A site's own icon always wins."}),
			vfield("site_defaults.certificate_source", "Default certificate source", "choice", fieldOpt{options: []string{"letsencrypt", "internal", "external"}}),
			vfield("site_defaults.le_managed", "Manage Let's Encrypt renewal", "boolean", fieldOpt{}),
		),
		sec("Health checks", "Default checks and request timeout for HTTP sites.",
			vfield("site_defaults.tcp_check", "Enable backend health check", "boolean", fieldOpt{}),
			vfield("site_defaults.health_uri", "Health-check URI", "string", fieldOpt{}),
			vfield("site_defaults.health_status", "Expected HTTP status", "integer", fieldOpt{min: n(100), max: n(599)}),
			iv("site_defaults.http_request_timeout", "HTTP request timeout", fieldOpt{help: "Examples: 500ms, 5s, 2m."}),
			iv("site_defaults.frontend_keepalive_timeout", "Client keep-alive timeout", fieldOpt{def: "30s", help: "How long an idle browser connection is kept for its next request. Default: 30s."}),
		),
		sec("Rate and connection protection", "Default limits inherited by HTTP sites.",
			vfield("site_defaults.ban_policy", "Ban policy", "choice", fieldOpt{options: []string{"legacy", "u02"}, def: "legacy", help: "legacy: HAProxy bans an address itself for too many errors and, where rate_ban is on, for its request rate. u02: an ordinary excess is refused on that site while it lasts (429), signed-in addresses are let through with a warning, and bans come only from adaptive protection or an operator. A new installation starts on u02; a gateway installed earlier stays on legacy until it is switched here."}),
			vfield("site_defaults.max_req_rate", "Maximum request rate", "integer", fieldOpt{min: n(0), max: n(1000000)}),
			iv("site_defaults.rate_window", "Request-rate window", fieldOpt{}),
			vfield("site_defaults.rate_ban", "Ban clients that exceed the request rate", "boolean", fieldOpt{help: "Has no effect under the u02 ban policy."}),
			iv("site_defaults.conn_table_expire", "Connection table expiry", fieldOpt{}),
			iv("site_defaults.conn_rate_window", "Connection-rate window", fieldOpt{}),
			vfield("site_defaults.conn_rate_burst", "Connection burst limit", "integer", fieldOpt{min: n(0), max: n(1000000), def: int64(200), help: "New connections from one address per window, for addresses that are neither whitelisted, admin nor signed in. Default: 200."}),
			vfield("site_defaults.conn_rate_burst_trusted", "Hard connection burst limit", "integer", fieldOpt{min: n(1), max: n(1000000), def: int64(1000), help: "New connections from one address per window for everyone, trusted addresses included. Default: 1000."}),
			vfield("site_defaults.conn_cur_limit", "Concurrent connection limit", "integer", fieldOpt{min: n(1), max: n(1000000), def: int64(500), help: "Open connections from one address, for everyone. Default: 500."}),
			vfield("site_defaults.hard_req_rate", "Hard request limit", "integer", fieldOpt{min: n(1), max: n(1000000), def: int64(1000), help: "Requests from one address across all sites per hard window, for everyone; the excess is refused, nobody is banned. Default: 1000."}),
			iv("site_defaults.hard_req_window", "Hard request window", fieldOpt{def: "10s", help: "Default: 10s."}),
			vfield("site_defaults.err_limit", "Per-site error limit", "integer", fieldOpt{min: n(0), max: n(1000000)}),
			iv("site_defaults.err_window", "Per-site error window", fieldOpt{}),
			vfield("site_defaults.other_err_limit", "Other error limit", "integer", fieldOpt{min: n(0), max: n(1000000)}),
			iv("site_defaults.other_err_window", "Other error window", fieldOpt{}),
			vfield("site_defaults.other_err_exclude_enabled", "Ignore selected harmless errors", "boolean", fieldOpt{}),
		),
		sec("Control plane (read-only)", "Protected domains and host paths are shown for reference. Use the installer migration workflow to change service domains.",
			vfield("root_domain", "Root domain", "string", fieldOpt{readonly: true}),
			vfield("admin_domain", "HAProxy Admin domain", "string", fieldOpt{readonly: true}),
			vfield("aut_domain", "Authelia domain", "string", fieldOpt{readonly: true}),
			vfield("haproxy_certs_dir", "Certificate directory", "string", fieldOpt{readonly: true}),
			vfield("haproxy_socket", "HAProxy runtime socket", "string", fieldOpt{readonly: true}),
			vfield("haproxy_socket_group", "HAProxy socket group", "string", fieldOpt{readonly: true}),
		),
	}
	for _, s := range varsSections {
		for _, f := range s.Value("fields").([]any) {
			fm := f.(*Map)
			path := fm.Value("path").(string)
			schemaFields[path] = fm
			if fm.Value("readonly") != true {
				editableFields[path] = fm
			}
		}
	}
}

func readVarsBytes() ([]byte, error) {
	raw, err := os.ReadFile(ConfigYAML)
	if err != nil {
		if os.IsNotExist(err) {
			return []byte("{}\n"), nil
		}
		return nil, err
	}
	if len(raw) > maxVarsBytes {
		return nil, &ValueError{"vars.yml exceeds the 2 MB size limit"}
	}
	return raw, nil
}

func varsRevision(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func parseVars(raw []byte) (*Map, error) {
	if !utf8.Valid(raw) {
		return nil, valueErr("vars.yml is not valid YAML: 'utf-8' codec can't decode bytes")
	}
	v, err := pyyaml.Load(raw)
	if err != nil {
		return nil, valueErr("vars.yml is not valid YAML: %s", pyYAMLErrorText(err))
	}
	if !truthy(v) {
		v = pyyaml.NewMap()
	}
	data, ok := asMap(v)
	if !ok {
		return nil, &ValueError{"The vars.yml root must be a mapping"}
	}
	if err := ValidateConfigData("vars", data); err != nil {
		return nil, err
	}
	return data, nil
}

func getPath(data *Map, path string) any {
	var cur any = data
	for _, k := range strings.Split(path, ".") {
		m, ok := asMap(cur)
		if !ok {
			return nil
		}
		v, has := m.Get(k)
		if !has {
			return nil
		}
		cur = v
	}
	return cur
}

func setPath(data *Map, path string, value any) {
	keys := strings.Split(path, ".")
	cur := data
	for _, k := range keys[:len(keys)-1] {
		nested, ok := asMap(cur.Value(k))
		if !ok {
			nested = pyyaml.NewMap()
			cur.Set(k, nested)
		}
		cur = nested
	}
	cur.Set(keys[len(keys)-1], value)
}

func displayValue(v any, typ string) any {
	if typ == "list" {
		list, ok := asList(v)
		if !ok {
			if v == nil {
				return ""
			}
			return pyStr(v)
		}
		parts := make([]string, len(list))
		for i, it := range list {
			parts[i] = pyStr(it)
		}
		return strings.Join(parts, "\n")
	}
	return v
}

func normalizeAdminAllowedIPs(value any) ([]any, error) {
	var items []any
	if l, ok := asList(value); ok {
		items = l
	} else {
		for _, s := range listSplitRe.Split(strOrEmpty(value), -1) {
			items = append(items, s)
		}
	}
	if len(items) > 256 {
		return nil, &ValueError{"Admin frontend allowed IPs and networks: at most 256 entries"}
	}
	out := []any{}
	seen := map[string]bool{}
	for _, raw := range items {
		text := strip(raw)
		if text == "" {
			continue
		}
		var parsed string
		if strings.Contains(text, "/") {
			p, ok := pyIPNetwork(text)
			if !ok {
				return nil, valueErr("Admin frontend allowed IPs and networks: invalid IP/network %s", pyRepr(text))
			}
			parsed = p.String()
		} else {
			a, ok := pyIPAddress(text)
			if !ok {
				return nil, valueErr("Admin frontend allowed IPs and networks: invalid IP/network %s", pyRepr(text))
			}
			parsed = a.String()
		}
		if !seen[parsed] {
			out = append(out, parsed)
			seen[parsed] = true
		}
	}
	return out, nil
}

func clientInAdminAllowlist(clientIP string, entries []any) bool {
	addr, ok := pyIPAddress(strings.TrimSpace(clientIP))
	if !ok {
		return false
	}
	for _, e := range entries {
		text := pyStr(e)
		if !strings.Contains(text, "/") {
			bits := 32
			if !addr.Is4() {
				bits = 128
			}
			text = fmt.Sprintf("%s/%d", text, bits)
		}
		p, ok := pyIPNetwork(text)
		if !ok {
			continue
		}
		a := addr
		if p.Addr().Is4() != a.Is4() {
			continue
		}
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ValidateAdminAccessForClient is validate_admin_access_for_client.
func ValidateAdminAccessForClient(data *Map, clientIP string) error {
	if data.Value("admin_ips_enabled") != true {
		return nil
	}
	entries, err := normalizeAdminAllowedIPs(data.Value("admin_allowed_ips"))
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return &ValueError{"Add at least one trusted IP address or network before enabling the admin IP restriction"}
	}
	if !clientInAdminAllowlist(clientIP, entries) {
		return &ValueError{"Add the current connection IP to the admin allow list before enabling or applying this restriction"}
	}
	return nil
}

var _ = netip.Addr{}

func hstsEditorValue(v any) int64 {
	switch x := v.(type) {
	case nil:
		return hstsDefaultSeconds
	case bool:
		if x {
			return 31536000
		}
		return 0
	case int64:
		return x
	}
	text := strings.ToLower(strip(v))
	if n, err := parsePyIntString(text); err == nil {
		return n
	}
	if m := hstsLegacyRe.FindStringSubmatch(text); m != nil {
		n, _ := strconv.ParseInt(m[1], 10, 64)
		return n * hstsUnit[m[2]]
	}
	return hstsDefaultSeconds
}

// GetVarsEditorModel is get_vars_editor_model.
func GetVarsEditorModel() (*Map, error) {
	raw, err := readVarsBytes()
	if err != nil {
		return nil, err
	}
	data, err := parseVars(raw)
	if err != nil {
		return nil, err
	}
	ga, has := data.Get("authelia_enabled")
	if !has {
		ga = true
	}
	globalAuthelia := truthy(ga)
	count := int64(0)
	if l, ok := asList(data.Value("admin_allowed_ips")); ok {
		for _, e := range l {
			if s, ok := e.(string); ok && strings.TrimSpace(s) != "" {
				count++
			}
		}
	}
	sections := []any{}
	for _, s := range varsSections {
		sec := pyyaml.DeepCopy(s).(*Map)
		for _, f := range sec.Value("fields").([]any) {
			field := f.(*Map)
			path := field.Value("path").(string)
			stored := getPath(data, path)
			value := stored
			if path == "admin_authelia_enabled" {
				field.Set("inherited", true)
				field.Set("global_authelia_enabled", globalAuthelia)
				value = globalAuthelia
				field.Set("effective_value", globalAuthelia)
			} else if path == "admin_ips_enabled" {
				field.Set("admin_ip_count", count)
			}
			if value == nil && field.Value("default") != nil {
				value = field.Value("default")
			}
			if path == "site_defaults.hsts" {
				value = hstsEditorValue(value)
			}
			field.Set("value", displayValue(value, field.Value("type").(string)))
			field.Set("present", stored != nil)
		}
		sections = append(sections, sec)
	}
	return newMap("sections", sections, "yaml", string(raw), "revision", varsRevision(raw)), nil
}

func coerceValue(field *Map, value any) (any, error) {
	typ := field.Value("type").(string)
	label := pyStr(field.Value("label"))
	if typ == "integer" && (value == nil || strip(value) == "") && field.Value("default") != nil {
		value = field.Value("default")
	}
	switch typ {
	case "boolean":
		if b, ok := value.(bool); ok {
			return b, nil
		}
		switch strings.ToLower(orStr(value)) {
		case "1", "true", "yes", "on":
			return true, nil
		case "0", "false", "no", "off", "":
			return false, nil
		}
		return nil, valueErr("%s: expected true or false", label)
	case "integer":
		n, err := parsePyIntString(pyStr(value))
		if err != nil || value == nil {
			return nil, valueErr("%s: expected an integer", label)
		}
		if mn, ok := field.Value("minimum").(int64); ok && n < mn {
			return nil, valueErr("%s: minimum value is %d", label, mn)
		}
		if mx, ok := field.Value("maximum").(int64); ok && n > mx {
			return nil, valueErr("%s: maximum value is %d", label, mx)
		}
		return n, nil
	case "list":
		if field.Value("path") == "admin_allowed_ips" {
			return normalizeAdminAllowedIPs(value)
		}
		var items []any
		if l, ok := asList(value); ok {
			items = l
		} else {
			for _, s := range listSplitRe.Split(strOrEmpty(value), -1) {
				items = append(items, s)
			}
		}
		out := []any{}
		for _, it := range items {
			if strip(it) != "" {
				out = append(out, strip(it))
			}
		}
		return out, nil
	}
	text := ""
	if value != nil {
		text = strip(value)
	}
	bad := pyLen(text) > 16384
	for _, r := range text {
		if r < 32 {
			bad = true
		}
	}
	if bad {
		return nil, valueErr("%s: invalid text value", label)
	}
	if typ == "choice" {
		found := false
		for _, o := range field.Value("options").([]any) {
			if o == text {
				found = true
			}
		}
		if !found {
			return nil, valueErr("%s: unsupported value %s", label, pyRepr(text))
		}
	}
	if typ == "interval" && !intervalRe.MatchString(text) {
		return nil, valueErr("%s: use a value such as 500ms, 5s, 2m or 1h", label)
	}
	return text, nil
}

func atomicWriteKeepMode(path string, content []byte) error {
	mode := os.FileMode(0o640)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	if err := atomicWriteSnapshot(path, content, mode); err != nil {
		return err
	}
	if fd, err := syscall.Open(filepath.Dir(path), syscall.O_RDONLY|syscall.O_DIRECTORY, 0); err == nil {
		_ = syscall.Fsync(fd)
		syscall.Close(fd)
	}
	return nil
}

func saveWithRevision(op *Op, content []byte, expected any) (*Map, error) {
	if pending, msg := ConfigTransactionIsPending(op); pending {
		return newMap("ok", false, "pending", true, "error", msg), nil
	}
	exp, ok := expected.(string)
	if !ok || len(exp) != 64 {
		return newMap("ok", false, "conflict", true, "error", "The vars.yml revision is missing or invalid"), nil
	}
	if len(content) == 0 || len(content) > maxVarsBytes {
		return newMap("ok", false, "error", "vars.yml must be between 1 byte and 2 MB"), nil
	}
	release, err := op.Lock("vars")
	if err != nil {
		return nil, err
	}
	defer release()
	current, err := readVarsBytes()
	if err != nil {
		return nil, err
	}
	rev := varsRevision(current)
	if rev != exp {
		return newMap("ok", false, "conflict", true, "error", "vars.yml changed in another session; reload the page before saving", "revision", rev), nil
	}
	existing, err := parseVars(current)
	if err == nil {
		var candidate *Map
		if candidate, err = parseVars(content); err == nil {
			err = ValidateProtectedVarsUnchanged(existing, candidate)
		}
	}
	if err != nil {
		if _, isVE := err.(*ValueError); isVE {
			return newMap("ok", false, "error", err.Error(), "revision", rev), nil
		}
		return nil, err
	}
	if string(content) == string(current) {
		return newMap("ok", true, "unchanged", true, "message", "No vars.yml changes were detected", "revision", rev, "vars_yaml", string(current)), nil
	}
	if err := atomicWriteKeepMode(ConfigYAML, content); err != nil {
		return nil, err
	}
	return newMap("ok", true, "message", "vars.yml was saved. Validate and apply the pending configuration.", "revision", varsRevision(content), "vars_yaml", string(content)), nil
}

func dumpYAMLWide(data any) string {
	out, err := pyyaml.Dump(data, pyyaml.Options{AllowUnicode: true, Width: 1000})
	if err != nil {
		panic(err)
	}
	return out
}

// SaveGuidedVars is save_guided_vars.
func SaveGuidedVars(op *Op, valuesV any, expected any, clientIP string) (*Map, error) {
	values, ok := asMap(valuesV)
	if !ok {
		return newMap("ok", false, "error", "The values payload must be an object"), nil
	}
	var unknown []string
	for _, k := range values.Keys() {
		if _, ok := editableFields[pyStr(k)]; !ok {
			unknown = append(unknown, pyStr(k))
		}
	}
	sort.Strings(unknown)
	if len(unknown) > 0 {
		return newMap("ok", false, "error", "Unsupported or read-only vars.yml fields: "+strings.Join(unknown, ", ")), nil
	}
	raw, err := readVarsBytes()
	if err != nil {
		return nil, err
	}
	rev := varsRevision(raw)
	if !pyEqual(rev, expected) {
		return newMap("ok", false, "conflict", true, "error", "vars.yml changed in another session; reload the page before saving", "revision", rev), nil
	}
	data, err := parseVars(raw)
	if err != nil {
		return nil, err
	}
	changed := []any{}
	var cerr error
	values.Each(func(k, supplied any) {
		if cerr != nil {
			return
		}
		path := pyStr(k)
		parsed, err := coerceValue(editableFields[path], supplied)
		if err != nil {
			cerr = err
			return
		}
		if !pyEqual(getPath(data, path), parsed) {
			setPath(data, path, parsed)
			changed = append(changed, path)
		}
	})
	if cerr != nil {
		return newMap("ok", false, "error", cerr.Error(), "revision", rev), nil
	}
	touched := false
	for _, c := range changed {
		if c == "admin_ips_enabled" || c == "admin_allowed_ips" {
			touched = true
		}
	}
	if touched {
		if err := ValidateAdminAccessForClient(data, clientIP); err != nil {
			return newMap("ok", false, "error", err.Error(), "field_errors", newMap("admin_allowed_ips", err.Error()), "revision", rev), nil
		}
	}
	result, err := saveWithRevision(op, []byte(dumpYAMLWide(data)), expected)
	if err != nil {
		return nil, err
	}
	result.Set("changed_fields", changed)
	return result, nil
}

// SaveRawVars is save_raw_vars.
func SaveRawVars(op *Op, content any, expected any) (*Map, error) {
	s, ok := content.(string)
	if !ok {
		return newMap("ok", false, "error", "The YAML content must be text"), nil
	}
	return saveWithRevision(op, []byte(s), expected)
}

// GetACMEEmail is get_acme_email.
func GetACMEEmail() (*Map, error) {
	raw, err := readVarsBytes()
	if err != nil {
		return nil, err
	}
	data, err := parseVars(raw)
	if err != nil {
		return nil, err
	}
	return newMap("ok", true, "email", strOrEmpty(data.Value("certbot_email")), "revision", varsRevision(raw)), nil
}

// SaveACMEEmail is save_acme_email.
func SaveACMEEmail(op *Op, email any, expected any) (*Map, error) {
	text := ""
	if email != nil {
		text = strip(email)
	}
	if pyLen(text) > 254 || !acmeEmailRe.MatchString(text) {
		return newMap("ok", false, "validation_error", true, "error", "Enter a valid Let's Encrypt account email address"), nil
	}
	raw, err := readVarsBytes()
	if err != nil {
		return nil, err
	}
	rev := varsRevision(raw)
	if !pyEqual(rev, expected) {
		return newMap("ok", false, "conflict", true, "error", "vars.yml changed in another session; reload the page before saving", "revision", rev), nil
	}
	data, err := parseVars(raw)
	if err != nil {
		return nil, err
	}
	if strOrEmpty(data.Value("certbot_email")) == text {
		return newMap("ok", true, "unchanged", true, "message", "The Let's Encrypt email is already up to date", "email", text, "revision", rev), nil
	}
	data.Set("certbot_email", text)
	result, err := saveWithRevision(op, []byte(dumpYAMLWide(data)), expected)
	if err != nil {
		return nil, err
	}
	if truthy(result.Value("ok")) {
		result.Set("email", text)
		result.Set("message", "The Let's Encrypt email was saved. It applies to future certificate registrations and renewals.")
	}
	result.Delete("vars_yaml")
	return result, nil
}
