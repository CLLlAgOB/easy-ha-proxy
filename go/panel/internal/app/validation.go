package app

// Port of validation.py: validation shared by the UI editors and
// whole-file YAML uploads.

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"easy-ha-proxy/panel/shared/pyyaml"
)

var (
	identifierRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	domainBodyRe     = regexp.MustCompile(`^(?:\*\.)?(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$`)
	hostRe           = regexp.MustCompile(`^[A-Za-z0-9_.:%-]{1,253}$`)
	hostnameLabelRe  = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?$`)
	isoAlpha2Re      = regexp.MustCompile(`^[A-Z]{2}$`)
	dnsProfileRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
	caIDRe           = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,119}$`)
	intervalRe       = regexp.MustCompile(`^[1-9][0-9]*(?:ms|s|m|h|d)$`)
	emailRe          = regexp.MustCompile(`^[^@\s]{1,64}@[^@\s]{1,253}\.[A-Za-z0-9-]{2,63}$`)
	controlRe        = regexp.MustCompile(`[\x00-\x1f\x7f]`)
	balanceAlgRe     = regexp.MustCompile(`^([a-z_-]+)(?:\([A-Za-z0-9_.-]{1,64}\))?$`)
	balanceArgRe     = regexp.MustCompile(`^[A-Za-z0-9_.,=/:()-]{1,128}$`)
	haproxyTimeRe    = regexp.MustCompile(`^[0-9]{1,9}(?:us|ms|s|m|h|d)?$`)
	haproxySizeRe    = regexp.MustCompile(`^[1-9][0-9]{0,9}[kmgKMG]?$`)
	cookieNameRe     = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	cookieValueRe    = regexp.MustCompile(`^[A-Za-z0-9_.=;:/-]{1,128}$`)
	alpnRe           = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,32}(?:,[A-Za-z0-9._/-]{1,32}){0,7}$`)
	controlPlaneACL  = regexp.MustCompile(`(?m)^\s*acl\s+(host_admin|host_authelia)\s+hdr\(host\)\s+-i\s+(.+?)\s*$`)
	unsafePathChars  = regexp.MustCompile("[\\s#\"'`]")
	headerNameRe     = regexp.MustCompile(`^[A-Za-z0-9-]{1,128}$`)
	httpMethodRe     = regexp.MustCompile(`^[A-Z][A-Z0-9_-]{0,31}$`)
	httpStatusRe     = regexp.MustCompile(`^[1-5][0-9]{2}$`)
	haproxyNameStrip = regexp.MustCompile(`[^A-Za-z0-9_]`)
)

var balanceValues = map[string]bool{
	"roundrobin": true, "static-rr": true, "leastconn": true, "first": true, "source": true,
	"uri": true, "url_param": true, "hdr": true, "random": true, "rdp-cookie": true,
}

var httpReuseValues = map[string]bool{"never": true, "safe": true, "aggressive": true, "always": true}

var cookieFlags = map[string]bool{"rewrite": true, "insert": true, "prefix": true, "indirect": true, "nocache": true,
	"postonly": true, "preserve": true, "httponly": true, "secure": true, "dynamic": true}

var cookieOptionsWithValue = map[string]bool{"domain": true, "maxidle": true, "maxlife": true, "attr": true}

func valueErr(format string, args ...any) error { return &ValueError{fmt.Sprintf(format, args...)} }

// domainRe is DOMAIN_RE's fullmatch, lookahead included: 1-253 characters
// before an optional final dot.
func domainMatch(text string) bool {
	if strings.ContainsAny(text, "\n") {
		return false
	}
	core := strings.TrimSuffix(text, ".")
	n := pyLen(core)
	if n < 1 || n > 253 {
		return false
	}
	return domainBodyRe.MatchString(text)
}

func validateIdentifier(value any, label string) (string, error) {
	text := orStr(value)
	if !identifierRe.MatchString(text) {
		return "", valueErr("%s: only Latin letters, digits, '.', '_', and '-' are allowed (up to 128 characters)", label)
	}
	return text, nil
}

func validateDomain(value any, label string, allowWildcard bool) (string, error) {
	text := strings.ToLower(orStr(value))
	if !domainMatch(text) {
		return "", valueErr("%s: invalid DNS name", label)
	}
	text = strings.TrimRight(text, ".")
	if strings.HasPrefix(text, "*.") {
		if !allowWildcard {
			return "", valueErr("%s: a wildcard is only allowed among the extra certificate names, and only with DNS-01 validation", label)
		}
		if len(strings.Split(text, ".")) < 3 {
			return "", valueErr("%s: a wildcard needs at least two labels beneath it", label)
		}
	}
	return text, nil
}

// pyIPAddress is ipaddress.ip_address(text).
func pyIPAddress(text string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(text)
	if err != nil {
		return netip.Addr{}, false
	}
	if a.Is4() && strings.Contains(text, ":") {
		return netip.Addr{}, false
	}
	return a, true
}

func validateHost(value any, label string) (string, error) {
	text := orStr(value)
	if !hostRe.MatchString(text) || controlRe.MatchString(text) {
		return "", valueErr("%s: invalid IP address or hostname", label)
	}
	literal := text
	if strings.HasPrefix(literal, "[") && strings.HasSuffix(literal, "]") && len(literal) >= 2 {
		literal = literal[1 : len(literal)-1]
	}
	literal, _, _ = strings.Cut(literal, "%")
	if _, ok := pyIPAddress(literal); ok {
		return text, nil
	}
	if strings.Contains(text, ":") {
		return "", valueErr("%s: invalid IP address or hostname", label)
	}
	allDigits := true
	for _, part := range strings.Split(text, ".") {
		if !pyIsDigit(part) {
			allDigits = false
			break
		}
	}
	if allDigits {
		return "", valueErr("%s: invalid IP address or hostname", label)
	}
	if !domainMatch(text) && !hostnameLabelRe.MatchString(text) {
		return "", valueErr("%s: invalid IP address or hostname", label)
	}
	return text, nil
}

// pyIPNetwork is ipaddress.ip_network(text, strict=False).
func pyIPNetwork(text string) (netip.Prefix, bool) {
	addrText, maskText, _ := strings.Cut(text, "/")
	addr, ok := pyIPAddress(addrText)
	if !ok || addr.Zone() != "" {
		return netip.Prefix{}, false
	}
	bits := addr.BitLen()
	if maskText != "" {
		if isDigits(maskText) {
			n, err := strconv.Atoi(maskText)
			if err != nil || n > addr.BitLen() {
				return netip.Prefix{}, false
			}
			bits = n
		} else if addr.Is4() {
			mask, ok := pyIPAddress(maskText)
			if !ok || !mask.Is4() {
				return netip.Prefix{}, false
			}
			n, ok := maskBits(mask.As4())
			if !ok {
				return netip.Prefix{}, false
			}
			bits = n
		} else {
			return netip.Prefix{}, false
		}
	} else if strings.Contains(text, "/") {
		return netip.Prefix{}, false
	}
	p, err := addr.Prefix(bits)
	if err != nil {
		return netip.Prefix{}, false
	}
	return p, true
}

// maskBits reads a netmask (255.255.255.0) or a hostmask (0.0.0.255).
func maskBits(b [4]byte) (int, bool) {
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	for n := 0; n <= 32; n++ {
		netmask := ^uint32(0) << (32 - n)
		if n == 0 {
			netmask = 0
		}
		if v == netmask {
			return n, true
		}
	}
	for n := 0; n <= 32; n++ {
		host := uint32(0)
		if n < 32 {
			host = ^uint32(0) >> n
		}
		if v == host {
			return n, true
		}
	}
	return 0, false
}

func validateCIDR(value any, label string) (string, error) {
	text := orStr(value)
	if text == "" || controlRe.MatchString(text) || pyLen(text) > 64 {
		return "", valueErr("%s: invalid IP address or network", label)
	}
	if strings.Contains(text, "/") {
		p, ok := pyIPNetwork(text)
		if !ok {
			return "", valueErr("%s: invalid IP address or network (%s)", label, pyRepr(text))
		}
		if p.Bits() == p.Addr().BitLen() {
			return p.Addr().String(), nil
		}
		return p.String(), nil
	}
	a, ok := pyIPAddress(text)
	if !ok {
		return "", valueErr("%s: invalid IP address or network (%s)", label, pyRepr(text))
	}
	return a.String(), nil
}

func validatePort(value any, label string) (int64, error) {
	port, err := pyInt(value)
	if err != nil {
		return 0, valueErr("%s must be a number", label)
	}
	if port < 1 || port > 65535 {
		return 0, valueErr("%s must be between 1 and 65535", label)
	}
	return port, nil
}

func controlPlaneDomains(configText string) map[string][]string {
	domains := map[string][]string{}
	for _, m := range controlPlaneACL.FindAllStringSubmatch(configText, -1) {
		set := map[string]bool{}
		for _, v := range strings.Fields(m[2]) {
			v = strings.TrimRight(strings.ToLower(strings.TrimSpace(v)), ".")
			set[v] = true
		}
		var values []string
		for v := range set {
			values = append(values, v)
		}
		sort.Strings(values)
		if len(values) > 0 {
			domains[m[1]] = values
		}
	}
	return domains
}

// ValidateControlPlaneTransition is validate_control_plane_transition.
func ValidateControlPlaneTransition(active, candidate string) error {
	act := controlPlaneDomains(active)
	if len(act) == 0 {
		return nil
	}
	cand := controlPlaneDomains(candidate)
	labels := map[string]string{"host_admin": "HAProxy Admin", "host_authelia": "Authelia"}
	for _, name := range []string{"host_admin", "host_authelia"} {
		activeDomains, ok := act[name]
		if !ok {
			continue
		}
		candidateDomains := cand[name]
		if strings.Join(candidateDomains, "\x00") == strings.Join(activeDomains, "\x00") && candidateDomains != nil {
			continue
		}
		proposed := "missing"
		if len(candidateDomains) > 0 {
			proposed = strings.Join(candidateDomains, ", ")
		}
		return valueErr("Protected domain %s changed: %s -> %s. The change was blocked. Service domains can only be changed with easy-ha-proxy migrate-domain.",
			labels[name], strings.Join(activeDomains, ", "), proposed)
	}
	return nil
}

// RejectUnsafeScalars is reject_unsafe_scalars.
func RejectUnsafeScalars(value any) error {
	_, err := rejectUnsafe(value, "root", 0, map[any]bool{})
	return err
}

func rejectUnsafe(value any, path string, depth int, seen map[any]bool) (int, error) {
	if depth > 20 {
		return 0, valueErr("%s: structure is too deeply nested", path)
	}
	switch x := value.(type) {
	case string:
		if pyLen(x) > 16384 {
			return 0, valueErr("%s: string is too long", path)
		}
		if controlRe.MatchString(x) {
			return 0, valueErr("%s: control characters and line breaks are forbidden", path)
		}
		return 1, nil
	case *pyyaml.Map:
		if seen[x] {
			return 0, valueErr("%s: YAML aliases are not allowed", path)
		}
		seen[x] = true
		count := 1
		var err error
		for _, k := range x.Keys() {
			ks, ok := k.(string)
			if !ok || controlRe.MatchString(ks) || pyLen(ks) > 128 {
				return 0, valueErr("%s: invalid key", path)
			}
			n, e := rejectUnsafe(x.Value(k), path+"."+ks, depth+1, seen)
			if e != nil {
				return 0, e
			}
			count += n
			if count > 10000 {
				return 0, valueErr("YAML contains too many items")
			}
		}
		return count, err
	case []any:
		if len(x) > 0 {
			key := &x[0]
			if seen[key] {
				return 0, valueErr("%s: YAML aliases are not allowed", path)
			}
			seen[key] = true
		}
		count := 1
		for i, item := range x {
			n, err := rejectUnsafe(item, fmt.Sprintf("%s[%d]", path, i), depth+1, seen)
			if err != nil {
				return 0, err
			}
			count += n
			if count > 10000 {
				return 0, valueErr("YAML contains too many items")
			}
		}
		return count, nil
	case nil, bool, int64, float64:
		return 1, nil
	}
	return 0, valueErr("%s: unsupported value type", path)
}

// fieldText is _field_text: the field's text, or "" (None) when unset or empty.
func fieldText(values *Map, key string) (string, bool) {
	v, ok := values.Get(key)
	if !ok || v == nil {
		return "", false
	}
	t := strip(v)
	return t, t != ""
}

func validateBalance(value, label string) error {
	words := strings.Fields(value)
	m := balanceAlgRe.FindStringSubmatch(words[0])
	ok := m != nil && (balanceValues[m[1]] || m[1] == "hash") && len(words) <= 8
	if ok {
		for _, w := range words[1:] {
			if !balanceArgRe.MatchString(w) {
				ok = false
			}
		}
	}
	if !ok {
		return valueErr("%s: unsupported algorithm", label)
	}
	return nil
}

func validateCookieAttrs(value, label string) error {
	words := strings.Fields(value)
	if len(words) > 24 {
		return valueErr("%s: too many cookie options", label)
	}
	waiting := ""
	for _, w := range words {
		switch {
		case waiting != "":
			if !cookieValueRe.MatchString(w) {
				return valueErr("%s: invalid value for %s", label, waiting)
			}
			waiting = ""
		case cookieOptionsWithValue[w]:
			waiting = w
		case !cookieFlags[w]:
			return valueErr("%s: unknown cookie option %s", label, pyRepr(w))
		}
	}
	if waiting != "" {
		return valueErr("%s: %s needs a value", label, waiting)
	}
	return nil
}

// ValidateBackendTuning is validate_backend_tuning.
func ValidateBackendTuning(values *Map, prefix string) error {
	if t, ok := fieldText(values, "balance"); ok {
		if err := validateBalance(t, prefix+".balance"); err != nil {
			return err
		}
	}
	if t, ok := fieldText(values, "http_reuse"); ok && !httpReuseValues[t] {
		return valueErr("%s.http_reuse: must be never, safe, aggressive or always", prefix)
	}
	for _, key := range []string{"session_timeout", "http_keepalive_timeout"} {
		if t, ok := fieldText(values, key); ok && !haproxyTimeRe.MatchString(t) {
			return valueErr("%s.%s: must be a time such as 30s, 5m or 1h", prefix, key)
		}
	}
	for _, key := range []string{"err_size", "rate_size"} {
		if t, ok := fieldText(values, key); ok && !haproxySizeRe.MatchString(t) {
			return valueErr("%s.%s: must be a size such as 50k or 1m", prefix, key)
		}
	}
	if t, ok := fieldText(values, "cookie_name"); ok && !cookieNameRe.MatchString(t) {
		return valueErr("%s.cookie_name: may use Latin letters, digits, '.', '_' and '-' (up to 64 characters)", prefix)
	}
	if t, ok := fieldText(values, "cookie_attrs"); ok {
		if err := validateCookieAttrs(t, prefix+".cookie_attrs"); err != nil {
			return err
		}
	}
	if t, ok := fieldText(values, "backend_alpn"); ok && !alpnRe.MatchString(t) {
		return valueErr("%s.backend_alpn: must be a comma-separated list of protocols such as h2,http/1.1", prefix)
	}
	return nil
}

func orValue(vals ...any) any {
	for _, v := range vals {
		if truthy(v) {
			return v
		}
	}
	if len(vals) > 0 {
		return vals[len(vals)-1]
	}
	return nil
}

func isBool(v any) bool {
	_, ok := v.(bool)
	return ok
}

func validateSite(siteV any, index int) error {
	site, ok := asMap(siteV)
	if !ok {
		return valueErr("sites[%d] must be an object", index)
	}
	p := fmt.Sprintf("sites[%d]", index)
	if _, err := validateIdentifier(orValue(site.Value("name"), site.Value("domain")), p+".name"); err != nil {
		return err
	}
	if _, err := validateDomain(orValue(site.Value("domain"), site.Value("name")), p+".domain", false); err != nil {
		return err
	}
	return validateSiteFields(site, p)
}

func validateSiteFields(site *Map, p string) error {
	if truthy(site.Value("backend_ip")) {
		if _, err := validateHost(site.Value("backend_ip"), p+".backend_ip"); err != nil {
			return err
		}
	}
	if site.Value("backend_port") != nil {
		if _, err := validatePort(site.Value("backend_port"), p+".backend_port"); err != nil {
			return err
		}
	}
	if gc := site.Value("geo_countries"); gc != nil {
		list, ok := asList(gc)
		if !ok || len(list) > 249 {
			return valueErr("%s.geo_countries must be a list of at most 249 ISO alpha-2 codes", p)
		}
		for ci, c := range list {
			cs, ok := c.(string)
			if !ok || !isoAlpha2Re.MatchString(strings.TrimSpace(cs)) {
				return valueErr("%s.geo_countries[%d] must be an uppercase ISO alpha-2 code", p, ci)
			}
		}
	}
	dnsProfile := site.Value("dns_profile")
	if profile := strip(dnsProfile); profile != "" && !dnsProfileRe.MatchString(strings.ToLower(profile)) {
		return valueErr("%s.dns_profile: may use a-z, 0-9 and dashes", p)
	}
	for _, kv := range []struct {
		key      string
		wildcard bool
	}{{"alt_names", false}, {"cert_alt_names", true}} {
		names := site.Value(kv.key)
		if names == nil {
			continue
		}
		list, ok := asList(names)
		if !ok || len(list) > 100 {
			return valueErr("%s.%s must be a list of at most 100 DNS names", p, kv.key)
		}
		for ni, n := range list {
			if _, err := validateDomain(n, fmt.Sprintf("%s.%s[%d]", p, kv.key, ni), kv.wildcard && truthy(dnsProfile)); err != nil {
				return err
			}
		}
	}
	if ai := site.Value("allow_ips"); ai != nil {
		list, ok := asList(ai)
		if !ok || len(list) > 64 {
			return valueErr("%s.allow_ips must be a list of at most 64 addresses or networks", p)
		}
		for ei, e := range list {
			if _, err := validateCIDR(e, fmt.Sprintf("%s.allow_ips[%d]", p, ei)); err != nil {
				return err
			}
		}
	}
	mtls := site.Value("mtls_mode")
	if mtls != nil && !(mtls == "disabled" || mtls == "optional" || mtls == "required") {
		return valueErr("%s.mtls_mode must be disabled, optional or required", p)
	}
	if mtls == "optional" || mtls == "required" {
		ca := orStr(site.Value("mtls_ca_id"))
		if ca == "" {
			return valueErr("%s.mtls_ca_id is required when client certificates are enabled", p)
		}
		if !caIDRe.MatchString(ca) {
			return valueErr("%s.mtls_ca_id: invalid identifier", p)
		}
	}
	for _, key := range []string{"access_gate", "access_portal_enabled", "alert_enabled"} {
		if v := site.Value(key); v != nil && !isBool(v) {
			return valueErr("%s.%s must be true or false", p, key)
		}
	}
	if v := site.Value("alert_mode"); v != nil && v != "down" && v != "degraded" {
		return valueErr("%s.alert_mode must be down or degraded", p)
	}
	if v := site.Value("alert_after"); v != nil && !intervalRe.MatchString(pyStr(v)) {
		return valueErr("%s.alert_after must be an interval such as 5m or 300s", p)
	}
	if v := site.Value("alert_email"); v != nil {
		email := strip(v)
		if pyLen(email) > 254 || !emailRe.MatchString(email) {
			return valueErr("%s.alert_email must be a valid email", p)
		}
	}
	if v := site.Value("alert_slow_ms"); v != nil {
		n, isInt := v.(int64)
		if !isInt || n < 0 || n > 600000 {
			return valueErr("%s.alert_slow_ms must be a number of milliseconds from 0 to 600000", p)
		}
	}
	servers := []any{}
	if sv := site.Value("servers"); truthy(sv) {
		items, err := iterAny(sv)
		if err != nil {
			return err
		}
		servers = items
	}
	for si, sv := range servers {
		srv, ok := asMap(sv)
		if !ok {
			return valueErr("%s.servers[%d] must be an object", p, si)
		}
		sp := fmt.Sprintf("%s.servers[%d]", p, si)
		if _, err := validateIdentifier(orValue(srv.Value("name"), fmt.Sprintf("srv%d", si+1)), sp+".name"); err != nil {
			return err
		}
		if _, err := validateHost(srv.Value("host"), sp+".host"); err != nil {
			return err
		}
		if _, err := validatePort(srv.Value("port"), sp+".port"); err != nil {
			return err
		}
		if w := srv.Value("weight"); w != nil {
			if isBool(w) {
				return valueErr("%s.weight must be an integer", sp)
			}
			n, err := pyInt(w)
			if err != nil {
				return valueErr("%s.weight must be an integer", sp)
			}
			if n < 0 || n > 256 {
				return valueErr("%s.weight must be between 0 and 256", sp)
			}
		}
	}
	for _, key := range []string{"backend_host", "backend_sni", "verify_host"} {
		v := site.Value(key)
		if v != nil && strip(v) != "" {
			text := strip(v)
			if !hostRe.MatchString(text) || strings.ContainsRune(text, '%') {
				return valueErr("%s.%s: invalid hostname", p, key)
			}
		}
	}
	if v := site.Value("backend_ssl_ca"); v != nil && strip(v) != "" {
		ca := strip(v)
		dotdot := false
		for _, part := range strings.Split(ca, "/") {
			if part == ".." {
				dotdot = true
			}
		}
		if !strings.HasPrefix(ca, "/") || pyLen(ca) > 512 || unsafePathChars.MatchString(ca) || strings.ContainsRune(ca, '\\') || dotdot {
			return valueErr("%s.backend_ssl_ca: invalid CA file path", p)
		}
	}
	if v := site.Value("health_uri"); v != nil && strip(v) != "" {
		u := strip(v)
		if !strings.HasPrefix(u, "/") || pyLen(u) > 512 || unsafePathChars.MatchString(u) || strings.ContainsRune(u, '\\') {
			return valueErr("%s.health_uri: must start with '/' and contain no spaces", p)
		}
	}
	if v := site.Value("health_status"); v != nil && strip(v) != "" {
		if !httpStatusRe.MatchString(strip(v)) {
			return valueErr("%s.health_status: must be an HTTP status code (100-599)", p)
		}
	}
	for _, key := range []string{"err_window", "rate_window"} {
		if t, ok := fieldText(site, key); ok && !haproxyTimeRe.MatchString(t) {
			return valueErr("%s.%s: must be a time such as 20s", p, key)
		}
	}
	if err := validateCounterLimit(site, "err_limit", p); err != nil {
		return err
	}
	if err := validateErrorExclusions(site.Value("err_exclude"), p+".err_exclude", false); err != nil {
		return err
	}
	if v := site.Value("add_headers"); v != nil {
		hdrs, ok := asMap(v)
		if !ok || hdrs.Len() > 64 {
			return valueErr("%s.add_headers must be a mapping of at most 64 headers", p)
		}
		var err error
		hdrs.Each(func(k, hv any) {
			if err != nil {
				return
			}
			name := orStr(k)
			val := ""
			if hv != nil {
				val = pyStr(hv)
			}
			if !headerNameRe.MatchString(name) {
				err = valueErr("%s.add_headers: invalid header name %s", p, pyRepr(name))
				return
			}
			if pyLen(val) > 2048 || strings.ContainsAny(val, "\"\\#%") {
				// HAProxy evaluates log-format %[...] inside a set-header
				// value, so a '%' could read %[env(HAPROXY_ADMIN_PROXY_SECRET)]
				// or another sample fetch into the response header.
				err = valueErr("%s.add_headers[%s]: header value contains unsafe characters", p, pyRepr(name))
			}
		})
		if err != nil {
			return err
		}
	}
	return ValidateBackendTuning(site, p)
}

func validateCounterLimit(fields *Map, key, prefix string) error {
	if raw := fields.Value(key); raw != nil {
		n, err := strconv.ParseInt(strip(raw), 10, 64)
		if err != nil || n < 0 || n > 1_000_000 {
			return valueErr("%s.%s must be an integer from 0 to 1000000", prefix, key)
		}
	}
	return nil
}

func validateErrorExclusions(raw any, label string, exact bool) error {
	if raw == nil {
		return nil
	}
	rules, ok := asList(raw)
	if !ok || len(rules) > 128 {
		return valueErr("%s must be a list of at most 128 rules", label)
	}
	for i, entry := range rules {
		rule, ok := asMap(entry)
		p := fmt.Sprintf("%s[%d]", label, i)
		if !ok {
			return valueErr("%s must be an object", p)
		}
		matches := 0
		for _, key := range []string{"path", "path_beg", "path_reg"} {
			value := rule.Value(key)
			if value == nil || value == "" {
				continue
			}
			text, ok := value.(string)
			if !ok || len(text) > 512 || unsafePathChars.MatchString(text) ||
				exact && key != "path" || strings.HasPrefix(text, "-") || strings.HasPrefix(text, "\\") || strings.HasSuffix(text, "\\") ||
				key != "path_reg" && (!strings.HasPrefix(text, "/") || strings.ContainsRune(text, '\\')) {
				return valueErr("%s.%s must be a single safe path or pattern", p, key)
			}
			matches++
		}
		if matches != 1 {
			return valueErr("%s must specify exactly one path matcher", p)
		}
		if rawMethods := rule.Value("methods"); rawMethods != nil {
			methods, ok := asList(rawMethods)
			if !ok || len(methods) > 32 {
				return valueErr("%s.methods must be a list of at most 32 HTTP methods", p)
			}
			for _, method := range methods {
				text, ok := method.(string)
				if !ok || !httpMethodRe.MatchString(text) {
					return valueErr("%s.methods contains an invalid HTTP method", p)
				}
			}
		}
	}
	return nil
}

func validateSiteDefaults(defaults *Map) error {
	const label = "site_defaults"
	if err := validateSiteFields(defaults, label); err != nil {
		return err
	}
	for _, key := range []string{"auth_ip_expire", "ban_expire", "conn_table_expire", "conn_rate_window", "frontend_client_timeout",
		"frontend_keepalive_timeout", "hard_req_window", "http_request_timeout", "nosni_tcp_window", "other_err_window"} {
		if t, ok := fieldText(defaults, key); ok && !haproxyTimeRe.MatchString(t) {
			return valueErr("%s.%s: must be a time such as 30s", label, key)
		}
	}
	for _, key := range []string{"conn_cur_limit", "conn_rate_burst", "nosni_tcp_limit", "other_err_limit"} {
		if err := validateCounterLimit(defaults, key, label); err != nil {
			return err
		}
	}
	if size, ok := fieldText(defaults, "other_err_size"); ok && !haproxySizeRe.MatchString(size) {
		return valueErr("%s.other_err_size: must be a size such as 50k", label)
	}
	return validateErrorExclusions(defaults.Value("other_err_exclude_exact"), label+".other_err_exclude_exact", true)
}

// iterAny is iter(v) for the values YAML yields.
func iterAny(v any) ([]any, error) {
	switch x := v.(type) {
	case []any:
		return x, nil
	case *Map:
		return x.Keys(), nil
	case string:
		out := []any{}
		for _, r := range x {
			out = append(out, string(r))
		}
		return out, nil
	}
	return nil, &TypeError{fmt.Sprintf("'%s' object is not iterable", pyTypeName(v))}
}

// TypeError mirrors Python's TypeError.
type TypeError struct{ Msg string }

func (e *TypeError) Error() string { return e.Msg }

func pyTypeName(v any) string {
	switch v.(type) {
	case nil:
		return "NoneType"
	case bool:
		return "bool"
	case int64, int:
		return "int"
	case float64:
		return "float"
	case string:
		return "str"
	case []any:
		return "list"
	case *Map:
		return "dict"
	}
	return fmt.Sprintf("%T", v)
}

func validateTCP(proxyV any, index int) error {
	proxy, ok := asMap(proxyV)
	if !ok {
		return valueErr("tcp_proxies[%d] must be an object", index)
	}
	p := fmt.Sprintf("tcp_proxies[%d]", index)
	if _, err := validateIdentifier(proxy.Value("name"), p+".name"); err != nil {
		return err
	}
	if _, err := validateHost(orValue(proxy.Value("bind_ip"), "0.0.0.0"), p+".bind_ip"); err != nil {
		return err
	}
	if _, err := validatePort(proxy.Value("bind_port"), p+".bind_port"); err != nil {
		return err
	}
	balance := strip(orValue(proxy.Value("balance"), "source"))
	if !balanceValues[balance] {
		return valueErr("%s.balance: unsupported algorithm", p)
	}
	if v := proxy.Value("inter"); truthy(v) && !intervalRe.MatchString(pyStr(v)) {
		return valueErr("%s.inter: invalid interval", p)
	}
	if v := proxy.Value("backend_host"); truthy(v) {
		if _, err := validateHost(v, p+".backend_host"); err != nil {
			return err
		}
		if _, err := validatePort(proxy.Value("backend_port"), p+".backend_port"); err != nil {
			return err
		}
	}
	servers := []any{}
	if sv := proxy.Value("servers"); truthy(sv) {
		items, err := iterAny(sv)
		if err != nil {
			return err
		}
		servers = items
	}
	for si, sv := range servers {
		srv, ok := asMap(sv)
		if !ok {
			return valueErr("%s.servers[%d] must be an object", p, si)
		}
		sp := fmt.Sprintf("%s.servers[%d]", p, si)
		if _, err := validateIdentifier(orValue(srv.Value("name"), fmt.Sprintf("srv%d", si+1)), sp+".name"); err != nil {
			return err
		}
		if _, err := validateHost(srv.Value("host"), sp+".host"); err != nil {
			return err
		}
		if _, err := validatePort(srv.Value("port"), sp+".port"); err != nil {
			return err
		}
	}
	return nil
}

// HAProxyName is haproxy_name: the template's san().
func HAProxyName(name any) string {
	return haproxyNameStrip.ReplaceAllString(orStr(name), "_")
}

func routingNames(site *Map) map[string]bool {
	names := []any{site.Value("domain")}
	if alt, ok := asList(site.Value("alt_names")); ok {
		names = append(names, alt...)
	}
	out := map[string]bool{}
	for _, n := range names {
		if orStr(n) != "" {
			out[strings.ToLower(strip(n))] = true
		}
	}
	return out
}

// SiteIdentityConflict is site_identity_conflict ("" for none).
func SiteIdentityConflict(candidate *Map, others []any) string {
	name := orStr(candidate.Value("name"))
	serving := candidate.Value("paused") != true
	routing := routingNames(candidate)
	for _, o := range others {
		other, ok := asMap(o)
		if !ok {
			continue
		}
		otherName := orStr(other.Value("name"))
		if otherName == name {
			return fmt.Sprintf("A site named %s already exists", pyRepr(name))
		}
		if HAProxyName(otherName) == HAProxyName(name) {
			return fmt.Sprintf("Choose another name: %s gives the same HAProxy backend name as the site %s.", pyRepr(name), pyRepr(otherName))
		}
		if serving && other.Value("paused") != true {
			var shared []string
			for n := range routingNames(other) {
				if routing[n] {
					shared = append(shared, n)
				}
			}
			sort.Strings(shared)
			if len(shared) > 0 {
				return fmt.Sprintf("This domain is already served by another site: %s belongs to the site %s.", pyRepr(shared[0]), pyRepr(otherName))
			}
		}
	}
	return ""
}

var anyAddress = map[string]bool{"": true, "*": true, "0.0.0.0": true, "::": true, "[::]": true}

// TCPIdentityConflict is tcp_identity_conflict ("" for none).
func TCPIdentityConflict(candidate *Map, others []any) string {
	name := orStr(candidate.Value("name"))
	address := orStr(candidate.Value("bind_ip"))
	port := orStr(candidate.Value("bind_port"))
	for _, o := range others {
		other, ok := asMap(o)
		if !ok {
			continue
		}
		otherName := orStr(other.Value("name"))
		if otherName == name {
			return fmt.Sprintf("TCP proxy with name=%s already exists", pyRepr(name))
		}
		if HAProxyName(otherName) == HAProxyName(name) {
			return fmt.Sprintf("Choose another name: %s gives the same HAProxy backend name as the TCP proxy %s.", pyRepr(name), pyRepr(otherName))
		}
		otherAddress := orStr(other.Value("bind_ip"))
		if port != "" && orStr(other.Value("bind_port")) == port && (address == otherAddress || anyAddress[address] || anyAddress[otherAddress]) {
			shown := address
			if shown == "" {
				shown = "*"
			}
			return fmt.Sprintf("This listening address is already taken by another TCP proxy: %s:%s belongs to the TCP proxy %s.", shown, port, pyRepr(otherName))
		}
	}
	return ""
}

func noSharedHAProxyNames(entries []any, label string) error {
	seen := map[string]string{}
	for _, e := range entries {
		m, ok := asMap(e)
		if !ok {
			continue
		}
		name := orStr(m.Value("name"))
		key := HAProxyName(name)
		if prev, dup := seen[key]; dup {
			return valueErr("%s: %s and %s give the same HAProxy name", label, pyRepr(name), pyRepr(prev))
		}
		seen[key] = name
	}
	return nil
}

var protectedVarsKeys = []string{"admin_authelia_enabled", "admin_domain", "admin_ips_file", "admin_password",
	"aut_domain", "authelia_enabled", "backend_ssl_verify_ca_file", "haproxy_certs_dir", "haproxy_mtls_dir",
	"haproxy_server_state_file", "haproxy_socket", "haproxy_socket_group", "metrics_export_enabled",
	"metrics_scrape_sources", "root_domain", "whitelist_geo_file", "whitelist_global_file"}

// ValidateProtectedVarsUnchanged is validate_protected_vars_unchanged.
func ValidateProtectedVarsUnchanged(existing, candidate *Map) error {
	for _, key := range protectedVarsKeys {
		if !pyEqual(existing.Value(key), candidate.Value(key)) {
			return valueErr("Protected variable %s cannot be modified from the web interface", pyRepr(key))
		}
	}
	return nil
}

func pyEqual(a, b any) bool { return jinjaEqual(a, b) }

// ValidateConfigData is validate_config_data.
func ValidateConfigData(kind string, data *Map) error {
	if err := RejectUnsafeScalars(data); err != nil {
		return err
	}
	switch kind {
	case "websites":
		sitesV := data.Value("sites")
		if _, has := data.Get("sites"); !has {
			sitesV = []any{}
		}
		sites, ok := asList(sitesV)
		if !ok || len(sites) > 500 {
			return valueErr("sites must be a list of at most 500 items")
		}
		for i, s := range sites {
			if err := validateSite(s, i); err != nil {
				return err
			}
		}
		return noSharedHAProxyNames(sites, "sites")
	case "tcp":
		var pv any = []any{}
		if v, has := data.Get("tcp_proxies"); has {
			pv = v
		} else if v, has := data.Get("tcp"); has {
			pv = v
		}
		proxies, ok := asList(pv)
		if !ok || len(proxies) > 500 {
			return valueErr("tcp_proxies must be a list of at most 500 items")
		}
		for i, p := range proxies {
			if err := validateTCP(p, i); err != nil {
				return err
			}
		}
		return noSharedHAProxyNames(proxies, "tcp_proxies")
	case "vars":
		if v := data.Value("site_defaults"); v != nil {
			d, ok := asMap(v)
			if !ok {
				return valueErr("site_defaults must be a mapping")
			}
			return validateSiteDefaults(d)
		}
	}
	return nil
}
