package app

// Port of services_haproxy_sites.py: websites.yml editing.

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"easy-ha-proxy/panel/shared/jinja"
	"easy-ha-proxy/panel/shared/pyyaml"
)

var (
	mtlsDir         = "/etc/haproxy/mtls"
	allowSplitRe    = regexp.MustCompile(`[,;\s]+`)
	nameListSplitRe = regexp.MustCompile(`[,\s]+`)
	pauseKeys       = []string{"paused", "cert_renewal_paused"}
)

// Hooks the Authelia ACL and access-portal ports fill in.
var (
	autheliaLoadRulesYAML     func() (string, error)
	autheliaSaveRulesFromYAML func(op *Op, text string) (bool, string)
	autheliaConfigdRequest    func(payload *Map) (*Map, error)
	accessPortalDiscard       = func(name string) (string, error) { return "", nil }
)

const gateRuleWarning = "The site is back, but its Authelia login rule could not be added; add a one_factor rule for it on the Authelia access rules page."

func normalizeAllowIPs(value any) ([]any, error) {
	if value == nil || value == "" {
		return []any{}, nil
	}
	if l, ok := value.([]any); ok && len(l) == 0 {
		return []any{}, nil
	}
	if s, ok := value.(string); ok {
		var parts []any
		for _, p := range allowSplitRe.Split(s, -1) {
			if p != "" {
				parts = append(parts, p)
			}
		}
		value = parts
	}
	list, ok := asList(value)
	if !ok {
		if value == nil {
			return []any{}, nil
		}
		return nil, &ValueError{"The access list must be a list of addresses or networks"}
	}
	if len(list) > 64 {
		return nil, &ValueError{"The access list may hold at most 64 addresses"}
	}
	seen := []any{}
	for i, e := range list {
		c, err := validateCIDR(e, fmt.Sprintf("allow_ips[%d]", i))
		if err != nil {
			return nil, err
		}
		dup := false
		for _, s := range seen {
			if s == c {
				dup = true
			}
		}
		if !dup {
			seen = append(seen, c)
		}
	}
	return seen, nil
}

// clientAuthCAIDs is client_auth_ca_ids (nil when unknown).
func clientAuthCAIDs() map[string]bool {
	info, err := os.Stat(mtlsDir)
	if err != nil || !info.IsDir() {
		return nil
	}
	matches, err := filepath.Glob(filepath.Join(mtlsDir, "issuers-*.list"))
	if err != nil {
		return nil
	}
	out := map[string]bool{}
	for _, m := range matches {
		out[strings.TrimPrefix(stem(m), "issuers-")] = true
	}
	return out
}

func emptyCertStatus(state, short, tooltip string) *Map {
	return newMap("state", state, "short", short, "tooltip", tooltip, "haproxy_path", nil, "haproxy_has", false,
		"haproxy_not_after", nil, "haproxy_days_left", nil, "le_path", nil, "le_has", false, "le_not_after", nil, "le_days_left", nil)
}

// CertStatusForSite is get_cert_status_for_site.
func CertStatusForSite(eff *Map) *Map {
	domain := orStr(orValue(eff.Value("domain"), eff.Value("name")))
	if domain == "" {
		return emptyCertStatus("no_domain", "no domain", "Cannot check certificate: the site has no domain.")
	}
	status := CertdStatusForDomain(domain)
	if status.Len() == 0 {
		return emptyCertStatus("unknown", "unknown", "Certificate checking service is unavailable.")
	}
	return status
}

// GetWebsitesList is get_websites_list.
func GetWebsitesList() ([]any, error) {
	data, err := loadYAML(WebsitesYAML)
	if err != nil {
		return nil, err
	}
	list, ok := asList(orValue(data.Value("sites"), []any{}))
	if !ok {
		return []any{}, nil
	}
	return list, nil
}

func siteIsPaused(site any) bool    { return get(site, "paused") == true }
func renewalIsPaused(site any) bool { return get(site, "cert_renewal_paused") == true }

// RenewalPausedDomains is renewal_paused_domains.
func RenewalPausedDomains() []string {
	set := map[string]bool{}
	list, _ := GetWebsitesList()
	for _, s := range list {
		if renewalIsPaused(s) && truthy(get(s, "domain")) {
			set[strings.ToLower(strip(get(s, "domain")))] = true
		}
	}
	return sortedKeys(set)
}

// SetSitePause is set_site_pause.
func SetSitePause(op *Op, name, key string, paused bool) (bool, string) {
	valid := false
	for _, k := range pauseKeys {
		if k == key {
			valid = true
		}
	}
	if !valid {
		return false, "Unknown pause setting " + pyRepr(key)
	}
	release, err := op.Lock("websites")
	if err != nil {
		return false, err.Error()
	}
	defer release()
	list, err := GetWebsitesList()
	if err != nil {
		return false, err.Error()
	}
	for _, s := range list {
		site, ok := asMap(s)
		if !ok || !pyEqual(site.Value("name"), name) {
			continue
		}
		updated := copyMap(site)
		if paused {
			updated.Set(key, true)
		} else {
			updated.Delete(key)
		}
		if key == "paused" && !paused {
			var others []any
			for _, o := range list {
				if m, ok := asMap(o); ok && pyEqual(m.Value("name"), name) {
					continue
				}
				others = append(others, o)
			}
			if c := SiteIdentityConflict(updated, others); c != "" {
				return false, c
			}
		}
		return SaveSiteRaw(op, name, updated)
	}
	return false, fmt.Sprintf("Site %s was not found", pyRepr(name))
}

// SiteRevision is site_revision ("" when absent).
func SiteRevision(name string) string {
	list, _ := GetWebsitesList()
	for _, s := range list {
		if m, ok := asMap(s); ok && orStr(m.Value("name")) == name {
			return EntryRevision(m)
		}
	}
	return ""
}

// SyncRenewalPauses is sync_renewal_pauses.
func SyncRenewalPauses() *Map {
	res, err := CertdSetRenewalPauses(RenewalPausedDomains())
	if err != nil {
		return newMap("ok", false, "error", err.Error())
	}
	return res
}

// ConfiguredGeoIPCountries is get_configured_geoip_countries.
func ConfiguredGeoIPCountries() []string {
	cv, err := loadYAML(ConfigYAML)
	if err != nil {
		return nil
	}
	list, ok := asList(orValue(cv.Value("geoip_country_codes"), []any{}))
	if !ok {
		return []string{}
	}
	set := map[string]bool{}
	for _, v := range list {
		if s, ok := v.(string); ok {
			code := strings.ToUpper(strings.TrimSpace(s))
			if isoCountryRe.MatchString(code) {
				set[code] = true
			}
		}
	}
	return sortedKeys(set)
}

func normalizeSiteGeoCountries(value any) ([]any, error) {
	if value == nil || value == "" {
		return []any{}, nil
	}
	list, ok := asList(value)
	if !ok {
		return nil, &ValueError{"geo_countries must be a list of ISO alpha-2 country codes"}
	}
	if len(list) > 249 {
		return nil, &ValueError{"geo_countries must contain at most 249 country codes"}
	}
	set := map[string]bool{}
	for _, r := range list {
		s, ok := r.(string)
		if !ok {
			return nil, &ValueError{"geo_countries must contain only strings"}
		}
		code := strings.ToUpper(strings.TrimSpace(s))
		if !isoCountryRe.MatchString(code) {
			return nil, valueErr("Invalid GeoIP country code: %s", pyRepr(s))
		}
		set[code] = true
	}
	normalized := sortedKeys(set)
	available := map[string]bool{}
	for _, c := range ConfiguredGeoIPCountries() {
		available[c] = true
	}
	var unavailable []string
	for _, c := range normalized {
		if !available[c] {
			unavailable = append(unavailable, c)
		}
	}
	if len(unavailable) > 0 {
		return nil, &ValueError{"Select these countries on the global GeoIP page first: " + strings.Join(unavailable, ", ")}
	}
	return strList(normalized...), nil
}

func normalizeNameList(value any, label string, limit int) ([]string, error) {
	if value == nil || value == "" {
		return nil, nil
	}
	var items []string
	switch x := value.(type) {
	case string:
		for _, p := range nameListSplitRe.Split(x, -1) {
			if p != "" {
				items = append(items, p)
			}
		}
	case []any:
		for _, r := range x {
			s, ok := r.(string)
			if !ok {
				return nil, valueErr("%s must contain only strings", label)
			}
			if t := strings.TrimSpace(s); t != "" {
				items = append(items, t)
			}
		}
	default:
		return nil, valueErr("%s must be a list of DNS names", label)
	}
	if len(items) > limit {
		return nil, valueErr("%s must contain at most %d names", label, limit)
	}
	return items, nil
}

func normalizeSiteAltNames(value any, domain string) ([]string, error) {
	raw, err := normalizeNameList(value, "alt_names", 100)
	if err != nil {
		return nil, err
	}
	var seen []string
	for _, r := range raw {
		name, err := validateDomain(r, "alt_names", false)
		if err != nil {
			return nil, err
		}
		if name == domain || contains(seen, name) {
			continue
		}
		seen = append(seen, name)
	}
	return seen, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func normalizeSiteCertAltNames(value any, allowWildcard bool, taken []string) ([]string, error) {
	raw, err := normalizeNameList(value, "cert_alt_names", 100)
	if err != nil {
		return nil, err
	}
	var seen []string
	for _, r := range raw {
		name, err := validateDomain(r, "cert_alt_names", allowWildcard)
		if err != nil {
			return nil, err
		}
		if contains(taken, name) || contains(seen, name) {
			continue
		}
		seen = append(seen, name)
	}
	return seen, nil
}

func sitesFromData(data *Map) ([]any, bool) {
	return asList(orValue(data.Value("sites"), []any{}))
}

// AddSiteMinimal is add_site_minimal.
func AddSiteMinimal(op *Op, name, domain, backendIP string, backendPort any, extra *Map) (bool, string) {
	release, err := op.Lock("websites")
	if err != nil {
		return false, err.Error()
	}
	defer release()
	backendIP = strings.TrimSpace(backendIP)
	portText := orStr(backendPort)
	if backendIP == "" && portText == "" {
		cv, err := loadYAML(ConfigYAML)
		if err != nil {
			return false, err.Error()
		}
		if v, has := cv.Get("authelia_enabled"); has && v == false {
			return false, "Enable Authelia before creating a service site"
		}
		data, err := loadYAML(WebsitesYAML)
		if err != nil {
			return false, err.Error()
		}
		sites, ok := sitesFromData(data)
		if !ok {
			sites = []any{}
		}
		gate := newMap("name", name, "domain", domain, "access_gate", true, "authelia_enabled", true, "allow_ips", []any{},
			"tcp_passthrough", false, "zero_trust", false, "redirect_to_https", true, "access_portal_enabled", true)
		startWithDefaultCertificateSource(gate, cv)
		if c := SiteIdentityConflict(gate, sites); c != "" {
			return false, c
		}
		discardAccessPage(name)
		sites = append(sites, gate)
		data.Set("sites", sites)
		ok, msg := UpdateYAMLFile(op, "websites", dumpYAML(data))
		if ok {
			ruleOK, ruleMsg := ensureAccessGateAutheliaRule(op, []string{domain})
			return true, withGateRuleOutcome(msg, domain, ruleOK, ruleMsg)
		}
		return ok, msg
	}
	port, err := parsePyIntString(portText)
	if err != nil {
		return false, "backend_port must be a number"
	}
	if port < 1 || port > 65535 {
		return false, "backend_port must be between 1 and 65535"
	}
	data, err := loadYAML(WebsitesYAML)
	if err != nil {
		return false, err.Error()
	}
	sites, ok := sitesFromData(data)
	if !ok {
		sites = []any{}
	}
	site := newMap("name", name, "domain", domain, "backend_ip", backendIP, "backend_port", port)
	if extra != nil {
		extra.Each(func(k, v any) {
			if v != nil {
				site.Set(k, v)
			}
		})
	}
	if truthy(site.Value("servers")) {
		site.Delete("backend_ip")
		site.Delete("backend_port")
	}
	if cv, err := loadYAML(ConfigYAML); err == nil {
		startWithDefaultCertificateSource(site, cv)
	}
	if c := SiteIdentityConflict(site, sites); c != "" {
		return false, c
	}
	sites = append(sites, site)
	data.Set("sites", sites)
	return UpdateYAMLFile(op, "websites", dumpYAML(data))
}

// startWithDefaultCertificateSource gives a new site without a certificate
// source the installation's default from site_defaults. Certificates are
// issued by the site's own source, and a site without one gets Let's
// Encrypt, which an internal-CA installation cannot use.
func startWithDefaultCertificateSource(site, config *Map) {
	if source, _ := site.Value("certificate_source").(string); validCertificateSource(source) {
		return
	}
	defaults, _ := asMap(orValue(config.Value("site_defaults"), pyyaml.NewMap()))
	if defaults == nil {
		return
	}
	source, _ := defaults.Value("certificate_source").(string)
	if !validCertificateSource(source) {
		return
	}
	site.Set("certificate_source", source)
	site.Set("le_managed", source == "letsencrypt")
}

func validCertificateSource(source string) bool {
	return source == "letsencrypt" || source == "external" || source == "internal"
}

// DeleteSiteByName is delete_site_by_name.
func DeleteSiteByName(op *Op, name string) (bool, string) {
	release, err := op.Lock("websites")
	if err != nil {
		return false, err.Error()
	}
	defer release()
	return deleteSiteByName(op, name)
}

func deleteSiteByName(op *Op, name string) (bool, string) {
	data, err := loadYAML(WebsitesYAML)
	if err != nil {
		return false, err.Error()
	}
	sites, ok := sitesFromData(data)
	if !ok {
		return false, "Invalid websites.yml structure (expected a sites list)"
	}
	newSites := []any{}
	var removed any
	for _, s := range sites {
		if removed == nil && pyEqual(get(s, "name"), name) {
			removed = s
			continue
		}
		newSites = append(newSites, s)
	}
	if removed == nil {
		return false, fmt.Sprintf("Site %s was not found", pyRepr(name))
	}
	data.Set("sites", newSites)
	content := dumpYAML(data)
	kept, err := TrashKeep(op, "site", name, removed, nil)
	if err != nil {
		return false, "The entry could not be kept in the trash, so nothing was deleted: " + err.Error()
	}
	stored := discardAccessPage(name)
	if stored != "" {
		if err := TrashAnnotate(kept, newMap("access_page", stored)); err != nil {
			putAccessPageBack(name, stored)
			TrashDrop(kept)
			return false, "The entry could not be kept in the trash, so nothing was deleted: " + err.Error()
		}
	}
	ok, msg := UpdateYAMLFile(op, "websites", content)
	if !ok {
		if TrashSettle(kept, siteInSource(name)) {
			return false, msg + " The site is gone from websites.yml all the same; it was kept in the trash."
		}
		if stored != "" && !putAccessPageBack(name, stored) {
			return false, msg + " Its access page could not be put back automatically."
		}
		return ok, msg
	}
	TrashCommit(kept)
	return ok, msg + " The site was moved to the trash and can be restored there."
}

func siteInSource(name string) bool {
	list, err := GetWebsitesList()
	if err != nil {
		return false
	}
	for _, s := range list {
		if m, ok := asMap(s); ok && pyEqual(m.Value("name"), name) {
			return true
		}
	}
	return false
}

func putAccessPageBack(name, stored string) bool {
	ok, err := accessPortalRestore(name, stored)
	if err != nil {
		log.Printf("The access page of site %s could not be put back", pyRepr(name))
		return false
	}
	return ok
}

// RestoreSite is restore_site.
func RestoreSite(op *Op, entry, extra *Map) (bool, string, *Map) {
	info := pyyaml.NewMap()
	page := strOrEmpty(get(orValue(extra, pyyaml.NewMap()), "access_page"))
	release, err := op.Lock("websites")
	if err != nil {
		return false, err.Error(), info
	}
	var ok bool
	var msg string
	func() {
		defer release()
		if entry.Value("access_gate") == true {
			cv, _ := loadYAML(ConfigYAML)
			if cv != nil {
				if v, has := cv.Get("authelia_enabled"); has && v == false {
					msg = "Enable Authelia before restoring a service site"
					return
				}
			}
		}
		data, err := loadYAML(WebsitesYAML)
		if err != nil {
			msg = err.Error()
			return
		}
		sites, isList := sitesFromData(data)
		if !isList {
			msg = "Invalid websites.yml structure (expected a sites list)"
			return
		}
		if c := SiteIdentityConflict(entry, sites); c != "" {
			msg = c
			return
		}
		sites = append(sites, entry)
		data.Set("sites", sites)
		ok, msg = UpdateYAMLFile(op, "websites", dumpYAML(data))
		if ok && page != "" {
			info.Set("access_page", TrashRestoreAccessPage(strOrEmpty(entry.Value("name")), page))
		}
	}()
	if !ok {
		return false, msg, info
	}
	if entry.Value("access_gate") == true {
		domain := strOrEmpty(entry.Value("domain"))
		names := []string{domain}
		if alt, isList := asList(orValue(entry.Value("alt_names"), []any{})); isList {
			for _, a := range alt {
				if strip(a) != "" {
					names = append(names, strip(a))
				}
			}
		}
		ruleOK, ruleMsg := ensureAccessGateAutheliaRule(op, names)
		message := withGateRuleOutcome(msg, domain, ruleOK, ruleMsg)
		if !ruleOK {
			info.Set("warning", gateRuleWarning)
		}
		return true, message, info
	}
	return ok, msg, info
}

func discardAccessPage(name string) string {
	stored, err := accessPortalDiscard(name)
	if err != nil {
		log.Printf("The access-page storage of site %s could not be set aside", pyRepr(name))
		return ""
	}
	return stored
}

// SitesAndDefaultsForUI is get_sites_and_defaults_for_ui.
func SitesAndDefaultsForUI() (*Map, []any, error) {
	cv, err := loadYAML(ConfigYAML)
	if err != nil {
		return nil, nil, err
	}
	defaults, ok := asMap(orValue(cv.Value("site_defaults"), pyyaml.NewMap()))
	if !ok {
		defaults = pyyaml.NewMap()
	}
	sites, err := GetWebsitesList()
	if err != nil {
		return nil, nil, err
	}
	var ui []any
	for _, s := range sites {
		effV, err := jinja.CombineFilter(nil, defaults, []any{s}, newMap("recursive", true))
		if err != nil {
			return nil, nil, err
		}
		eff := effV.(*Map)
		ui = append(ui, newMap("raw", s, "effective", eff, "cert", CertStatusForSite(eff)))
	}
	if ui == nil {
		ui = []any{}
	}
	return defaults, ui, nil
}

// SiteRawAndEffective is get_site_raw_and_effective.
func SiteRawAndEffective(name string) (*Map, *Map, *Map, error) {
	cv, err := loadYAML(ConfigYAML)
	if err != nil {
		return nil, nil, nil, err
	}
	defaults, ok := asMap(orValue(cv.Value("site_defaults"), pyyaml.NewMap()))
	if !ok {
		defaults = pyyaml.NewMap()
	}
	data, err := loadYAML(WebsitesYAML)
	if err != nil {
		return nil, nil, nil, err
	}
	sites, ok := sitesFromData(data)
	if !ok {
		sites = []any{}
	}
	for _, s := range sites {
		if pyEqual(get(s, "name"), name) {
			effV, err := jinja.CombineFilter(nil, defaults, []any{s}, newMap("recursive", true))
			if err != nil {
				return nil, nil, nil, err
			}
			raw, _ := asMap(s)
			return defaults, raw, effV.(*Map), nil
		}
	}
	return defaults, nil, nil, nil
}

// SaveSiteFromJSON is save_site_from_json; a StaleEntry error on a stale revision.
func SaveSiteFromJSON(op *Op, siteV any, originalName string, expectedRevision any) (bool, string, error) {
	release, err := op.Lock("websites")
	if err != nil {
		return false, "", err
	}
	defer release()
	site, ok := asMap(siteV)
	if !ok {
		return false, "Invalid site format (expected a JSON object)", nil
	}
	name, err := validateIdentifier(orValue(site.Value("name"), site.Value("domain")), "name")
	if err != nil {
		return false, err.Error(), nil
	}
	domain, err := validateDomain(orValue(site.Value("domain"), name), "domain", false)
	if err != nil {
		return false, err.Error(), nil
	}
	out := copyMap(site)
	out.Set("name", name)
	out.Set("domain", domain)
	geo, err := normalizeSiteGeoCountries(out.Value("geo_countries"))
	if err != nil {
		return false, err.Error(), nil
	}
	if len(geo) > 0 {
		out.Set("geo_countries", geo)
	} else {
		out.Delete("geo_countries")
	}
	source := orStr(out.Value("certificate_source"))
	if source != "letsencrypt" && source != "external" && source != "internal" {
		le, has := out.Get("le_managed")
		if !has {
			le = true
		}
		if truthy(le) {
			source = "letsencrypt"
		} else {
			source = "external"
		}
	}
	out.Set("certificate_source", source)
	out.Set("le_managed", source == "letsencrypt")
	alt, err := normalizeSiteAltNames(out.Value("alt_names"), domain)
	if err != nil {
		return false, err.Error(), nil
	}
	if len(alt) > 0 {
		out.Set("alt_names", strList(alt...))
	} else {
		out.Delete("alt_names")
	}
	dnsProfile := ""
	if source == "letsencrypt" {
		dnsProfile = strings.ToLower(orStr(out.Value("dns_profile")))
		if dnsProfile != "" && !dnsProfileRe.MatchString(dnsProfile) {
			return false, "Invalid DNS provider profile name", nil
		}
	}
	if dnsProfile != "" {
		out.Set("dns_profile", dnsProfile)
	} else {
		out.Delete("dns_profile")
	}
	certAlt, err := normalizeSiteCertAltNames(out.Value("cert_alt_names"), dnsProfile != "", append([]string{domain}, alt...))
	if err != nil {
		return false, err.Error(), nil
	}
	if len(certAlt) > 0 {
		if source == "external" {
			return false, "Extra certificate names do not apply to an external certificate authority", nil
		}
		out.Set("cert_alt_names", strList(certAlt...))
	} else {
		out.Delete("cert_alt_names")
	}
	allow, err := normalizeAllowIPs(out.Value("allow_ips"))
	if err != nil {
		return false, err.Error(), nil
	}
	if len(allow) > 0 {
		out.Set("allow_ips", allow)
	} else {
		out.Delete("allow_ips")
	}
	mtls := strings.ToLower(orStr(orValue(out.Value("mtls_mode"), "disabled")))
	if mtls != "disabled" && mtls != "optional" && mtls != "required" {
		return false, "Client certificate mode must be disabled, optional or required", nil
	}
	if mtls == "disabled" {
		out.Delete("mtls_mode")
		out.Delete("mtls_ca_id")
	} else {
		ca := strings.ToLower(orStr(out.Value("mtls_ca_id")))
		if ca == "" {
			return false, "Select a certificate authority for client certificates", nil
		}
		if !caIDRe.MatchString(ca) {
			return false, "Invalid client certificate authority identifier", nil
		}
		if trusted := clientAuthCAIDs(); trusted != nil && !trusted[ca] {
			return false, fmt.Sprintf("The certificate authority %s is not trusted for client authentication. Enable it on the Certificates page first.", pyRepr(ca)), nil
		}
		out.Set("mtls_mode", mtls)
		out.Set("mtls_ca_id", ca)
	}
	if source == "external" {
		ext := strings.ToLower(orStr(out.Value("external_ca_id")))
		if ext == "" {
			return false, "Select an imported external certificate authority", nil
		}
		bad := pyLen(ext) > 120 || ext == "." || ext == ".."
		for _, r := range ext {
			if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyz0123456789._-", r) {
				bad = true
			}
		}
		if bad {
			return false, "Invalid external certificate authority identifier", nil
		}
		out.Set("external_ca_id", ext)
	} else {
		out.Delete("external_ca_id")
	}
	cv, err := loadYAML(ConfigYAML)
	if err != nil {
		return false, "", err
	}
	if err := ApplyPresetToSite(out, presetsFrom(cv)); err != nil {
		return false, err.Error(), nil
	}
	var cleaned []any
	if servers, ok := asList(out.Value("servers")); ok {
		for i, s := range servers {
			idx := i + 1
			srv, ok := asMap(s)
			if !ok {
				continue
			}
			host := orStr(srv.Value("host"))
			if host == "" {
				continue
			}
			host, err := validateHost(host, fmt.Sprintf("servers[%d].host", idx))
			if err != nil {
				return false, err.Error(), nil
			}
			port, err := validatePort(srv.Value("port"), fmt.Sprintf("servers[%d].port", idx))
			if err != nil {
				return false, err.Error(), nil
			}
			backup := truthy(srv.Value("backup"))
			sname := orStr(srv.Value("name"))
			if sname == "" {
				if backup {
					sname = fmt.Sprintf("backup%d", idx)
				} else {
					sname = fmt.Sprintf("srv%d", idx)
				}
			}
			sname, err = validateIdentifier(sname, fmt.Sprintf("servers[%d].name", idx))
			if err != nil {
				return false, err.Error(), nil
			}
			so := newMap("name", sname, "host", host, "port", port)
			if backup {
				so.Set("backup", true)
			}
			if w, has := srv.Get("weight"); has && w != nil && w != "" {
				if n, err := pyInt(w); err == nil {
					so.Set("weight", n)
				}
			}
			cleaned = append(cleaned, so)
		}
	}
	if len(cleaned) > 0 {
		out.Set("servers", cleaned)
		if len(cleaned) > 1 {
			out.Delete("backend_ip")
			out.Delete("backend_port")
		}
	}
	bip := orStr(out.Value("backend_ip"))
	bport := out.Value("backend_port")
	if bip != "" && bport != nil {
		h, err := validateHost(bip, "backend_ip")
		if err != nil {
			return false, err.Error(), nil
		}
		p, err := validatePort(bport, "backend_port")
		if err != nil {
			return false, err.Error(), nil
		}
		out.Set("backend_ip", h)
		out.Set("backend_port", p)
	} else {
		out.Delete("backend_ip")
		out.Delete("backend_port")
	}
	data, err := loadYAML(WebsitesYAML)
	if err != nil {
		return false, "", err
	}
	sites, ok := sitesFromData(data)
	if !ok {
		return false, "Invalid websites.yml structure (expected a sites list)", nil
	}
	orig := strings.TrimSpace(originalName)
	var previous *Map
	for _, s := range sites {
		if m, ok := asMap(s); ok && orStr(m.Value("name")) == orig {
			previous = m
			break
		}
	}
	prevVal := func(k string) any {
		if previous == nil {
			return nil
		}
		return previous.Value(k)
	}
	if orig != "" {
		var prevEntry any
		if previous != nil && previous.Len() > 0 {
			prevEntry = previous
		}
		if err := CheckEntryRevision(prevEntry, expectedRevision, "This site"); err != nil {
			return false, "", err
		}
	}
	for _, key := range pauseKeys {
		if _, has := site.Get(key); !has {
			if prevVal(key) == true {
				out.Set(key, true)
			}
		} else if site.Value(key) == true {
			out.Set(key, true)
		} else {
			out.Delete(key)
		}
	}
	if _, has := site.Get("access_portal_enabled"); !has && prevVal("access_portal_enabled") == true {
		out.Set("access_portal_enabled", true)
	}
	var others []any
	for _, s := range sites {
		m, isMap := asMap(s)
		if orig == "" || !isMap || orStr(m.Value("name")) != orig {
			others = append(others, s)
		}
	}
	if c := SiteIdentityConflict(out, others); c != "" {
		return false, c, nil
	}
	if orig == "" {
		sites = append(sites, out)
	} else {
		replaced := false
		for i, s := range sites {
			if orStr(get(s, "name")) == orig {
				sites[i] = out
				replaced = true
				break
			}
		}
		if !replaced {
			return false, fmt.Sprintf("Site %s was not found", pyRepr(orig)), nil
		}
	}
	data.Set("sites", sites)
	ok, msg := UpdateYAMLFile(op, "websites", dumpYAML(data))
	if !ok {
		return ok, msg, nil
	}
	if out.Value("access_gate") == true {
		names := []string{domain}
		if alts, isList := asList(orValue(out.Value("alt_names"), []any{})); isList {
			for _, a := range alts {
				if strip(a) != "" {
					names = append(names, strip(a))
				}
			}
		}
		ruleOK, ruleMsg := ensureAccessGateAutheliaRule(op, names)
		return true, withGateRuleOutcome(msg, domain, ruleOK, ruleMsg), nil
	}
	return ok, msg, nil
}

func withGateRuleOutcome(msg, domain string, ruleOK bool, ruleMsg string) string {
	if !ruleOK {
		return fmt.Sprintf("%s Note: the Authelia login rule for the gate could not be added automatically (%s); add a one_factor rule for %s on the Authelia access rules page.", msg, ruleMsg, domain)
	}
	if ruleMsg == "rule added" {
		return msg + " Authelia now has a one_factor access rule for this gate and was restarted to load it; that took effect at once, before the HAProxy apply."
	}
	if strings.HasPrefix(ruleMsg, "rule saved") {
		return fmt.Sprintf("%s The Authelia access rule for this gate was saved, but Authelia could not be restarted to load it; restart it on the Authelia page (%s).", msg, ruleMsg)
	}
	return msg
}

func ensureAccessGateAutheliaRule(op *Op, domains []string) (bool, string) {
	if autheliaLoadRulesYAML == nil || autheliaSaveRulesFromYAML == nil || autheliaConfigdRequest == nil {
		return false, "authelia rules helper unavailable: not ported"
	}
	text, err := autheliaLoadRulesYAML()
	if err != nil {
		return false, "cannot read current rules: " + err.Error()
	}
	v, err := pyyaml.Load([]byte(text))
	if err != nil {
		return false, "cannot read current rules: " + pyYAMLErrorText(err)
	}
	rules, ok := asList(v)
	if !ok || !truthy(v) {
		rules = []any{}
	}
	covered := func(dom string) bool {
		for _, r := range rules {
			rule, ok := asMap(r)
			if !ok {
				continue
			}
			rd := rule.Value("domain")
			names, isList := asList(rd)
			if !isList {
				names = []any{rd}
			}
			for _, n := range names {
				if strings.ToLower(strip(n)) == strings.ToLower(dom) {
					return true
				}
			}
		}
		return false
	}
	var missing []string
	for _, d := range domains {
		if d != "" && !covered(d) {
			missing = append(missing, d)
		}
	}
	if len(missing) == 0 {
		return true, "already present"
	}
	for _, d := range missing {
		rules = append(rules, newMap("domain", d, "policy", "one_factor"))
	}
	ok, msg := autheliaSaveRulesFromYAML(op, dumpYAML(rules))
	if !ok {
		return ok, msg
	}
	restart, err := autheliaConfigdRequest(newMap("action", "restart"))
	if err != nil {
		return true, "rule saved; restart Authelia to activate it (" + err.Error() + ")"
	}
	if !truthy(restart.Value("ok")) {
		return true, "rule saved; restart Authelia to activate it (" + pyStr(orValue(restart.Value("error"), "restart failed")) + ")"
	}
	return true, "rule added"
}

// SaveSiteRaw is save_site_raw.
func SaveSiteRaw(op *Op, name string, newSite *Map) (bool, string) {
	release, err := op.Lock("websites")
	if err != nil {
		return false, err.Error()
	}
	defer release()
	return saveSiteRaw(op, name, newSite)
}

// SaveAccessSiteIdentity is save_access_site_identity; backend is (address, port) or nil.
func SaveAccessSiteIdentity(op *Op, name string, domain any, paused bool, expectedRevision any, del bool, backend []any) (bool, string, error) {
	release, err := op.Lock("websites")
	if err != nil {
		return false, "", err
	}
	defer release()
	_, raw, eff, err := SiteRawAndEffective(name)
	if err != nil {
		return false, "", err
	}
	if raw == nil || eff.Value("access_gate") != true {
		return false, "Access page not found", nil
	}
	if !truthy(expectedRevision) {
		return false, "Reload the service site before saving", nil
	}
	if err := CheckEntryRevision(raw, expectedRevision, "This site"); err != nil {
		return false, "", err
	}
	if del {
		ok, msg := deleteSiteByName(op, name)
		return ok, msg, nil
	}
	d, err := validateDomain(domain, "domain", false)
	if err != nil {
		return false, err.Error(), nil
	}
	updated := copyMap(raw)
	updated.Set("domain", d)
	if paused {
		updated.Set("paused", true)
	} else {
		updated.Delete("paused")
	}
	if backend != nil {
		if !truthy(raw.Value("backend_ip")) || truthy(raw.Value("servers")) {
			return false, "This service site has no single backend of its own to change", nil
		}
		h, err := validateHost(orStr(backend[0]), "backend_ip")
		if err != nil {
			return false, err.Error(), nil
		}
		p, err := validatePort(backend[1], "backend_port")
		if err != nil {
			return false, err.Error(), nil
		}
		updated.Set("backend_ip", h)
		updated.Set("backend_port", p)
	}
	list, _ := GetWebsitesList()
	var others []any
	for _, s := range list {
		if !pyEqual(get(s, "name"), name) {
			others = append(others, s)
		}
	}
	if c := SiteIdentityConflict(updated, others); c != "" {
		return false, c, nil
	}
	ok, message := saveSiteRaw(op, name, updated)
	if ok && !pyEqual(d, raw.Value("domain")) {
		ruleOK, ruleMsg := ensureAccessGateAutheliaRule(op, []string{d})
		message = withGateRuleOutcome(message, d, ruleOK, ruleMsg)
	}
	return ok, message, nil
}

func saveSiteRaw(op *Op, name string, newSite *Map) (bool, string) {
	data, err := loadYAML(WebsitesYAML)
	if err != nil {
		return false, err.Error()
	}
	sites, ok := sitesFromData(data)
	if !ok {
		return false, "Invalid websites.yml structure (expected a sites list)"
	}
	newSites := []any{}
	found := false
	for _, s := range sites {
		if pyEqual(get(s, "name"), name) {
			newSites = append(newSites, newSite)
			found = true
		} else {
			newSites = append(newSites, s)
		}
	}
	if !found {
		return false, fmt.Sprintf("Site %s was not found", pyRepr(name))
	}
	data.Set("sites", newSites)
	return UpdateYAMLFile(op, "websites", dumpYAML(data))
}

// EnsureCertsBeforeApply is ensure_certs_before_apply.
func EnsureCertsBeforeApply() (*Map, error) {
	_, ui, err := SitesAndDefaultsForUI()
	if err != nil {
		return nil, err
	}
	actions := []any{}
	for _, it := range ui {
		item := it.(*Map)
		eff, _ := asMap(orValue(item.Value("effective"), pyyaml.NewMap()))
		raw, _ := asMap(orValue(item.Value("raw"), pyyaml.NewMap()))
		if eff == nil {
			eff = pyyaml.NewMap()
		}
		if raw == nil {
			raw = pyyaml.NewMap()
		}
		if truthy(eff.Value("tcp_passthrough")) || siteIsPaused(raw) || renewalIsPaused(raw) {
			continue
		}
		source, _ := raw.Value("certificate_source").(string)
		if source != "letsencrypt" && source != "external" && source != "internal" {
			le, has := raw.Get("le_managed")
			if !has {
				le = true
			}
			if truthy(le) {
				source = "letsencrypt"
			} else {
				source = "external"
			}
		}
		state := CertStatusForSite(eff).Value("state")
		if state == "missing" || state == "expired" || (source == "internal" && state == "warning") {
			domain := orValue(eff.Value("domain"), eff.Value("name"))
			alts, _ := asList(orValue(eff.Value("alt_names"), []any{}))
			keyTypes := orValue(eff.Value("key_types"), []any{})
			var res *Map
			switch source {
			case "letsencrypt":
				certAlts, _ := asList(orValue(eff.Value("cert_alt_names"), []any{}))
				all := append(append([]any{}, alts...), certAlts...)
				res = CertdIssue(pyStr(domain), all, keyTypes, strOrEmpty(eff.Value("dns_profile")), nil)
			case "internal":
				res = CertdIssueInternal(pyStr(domain), alts)
			default:
				res = newMap("ok", false, "error", "The site uses an external certificate authority, but no valid server certificate is installed. Upload its certificate, chain, and matching private key before applying HAProxy.")
			}
			actions = append(actions, newMap("domain", domain, "result", res))
			if !truthy(res.Value("ok")) {
				return newMap("ok", false, "actions", actions), nil
			}
		}
	}
	actions = append(actions, signInPortalCertsBeforeApply()...)
	return newMap("ok", true, "actions", actions), nil
}

var _ = sort.Strings
