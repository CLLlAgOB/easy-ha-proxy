package app

// Port of routes_geoip.py with services_geoip.py (local GeoIP management
// through haproxy-controld) and routes_audit.py (browsing the change log).

import (
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"easy-ha-proxy/panel/shared/pyyaml"
)

var (
	geoipSchedules  = []string{"daily", "weekly", "monthly"}
	geoipCountryRe  = regexp.MustCompile(`^[A-Z]{2}$`)
	geoipRevisionRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
	auditRangeSecs  = map[string]int64{"1h": 3600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400, "90d": 90 * 86400, "all": 0}
	auditResultList = []string{auditResultSuccess, auditResultFailure, auditResultDenied}
)

func geoipRequest(command string, payload *Map) *Map {
	if payload != nil {
		text, _ := pyyaml.JSONDumps(payload, true, true)
		command += " " + base64.StdEncoding.EncodeToString([]byte(text))
	}
	return controldJSONRequest(command, 360)
}

// normalizeCountries is normalize_countries.
func normalizeCountries(v any) ([]any, error) {
	list, ok := v.([]any)
	if !ok {
		return nil, &ValueError{"countries must be a list"}
	}
	if len(list) > 249 {
		return nil, &ValueError{"at most 249 countries can be selected"}
	}
	set := map[string]bool{}
	for _, raw := range list {
		s, ok := raw.(string)
		if !ok {
			return nil, &ValueError{"country codes must be strings"}
		}
		code := strings.ToUpper(pyStripSpace(s))
		if !geoipCountryRe.MatchString(code) {
			return nil, &ValueError{"invalid ISO country code: " + pyRepr(s)}
		}
		set[code] = true
	}
	return strList(sortedKeys(set)...), nil
}

func runtimeGeoIPConfig() *Map {
	fail := func(msg string) *Map { return newMap("available", false, "error", msg) }
	raw, err := os.ReadFile(ConfigYAML)
	if err != nil {
		return fail("Cannot read runtime vars.yml: " + pyFileError(err, ConfigYAML))
	}
	v, err := pyyaml.Load(raw)
	if err != nil {
		return fail("Cannot read runtime vars.yml: " + err.Error())
	}
	if !truthy(v) {
		v = newMap()
	}
	values, ok := asMap(v)
	if !ok {
		return fail("Runtime vars.yml root is not a mapping")
	}
	enabled, found := values.Get("enable_geoip")
	if !found {
		enabled = false
	}
	mode := strings.ToLower(pyStripSpace(pyStr(orValue(values.Value("geoip_mode"), "allow"))))
	if _, isBool := enabled.(bool); !isBool {
		return fail("enable_geoip must be boolean")
	}
	if mode != "allow" && mode != "deny" {
		return fail("geoip_mode must be allow or deny")
	}
	countries, err := normalizeCountries(orValue(values.Value("geoip_country_codes"), []any{}))
	if err != nil {
		return fail(err.Error())
	}
	return newMap("available", true, "enable_geoip", enabled, "geoip_mode", mode, "countries", countries)
}

func attachRuntimeConfig(result *Map) *Map {
	runtime := runtimeGeoIPConfig()
	result.Set("runtime_config", runtime)
	selection, isMap := asMap(result.Value("selection"))
	inSync := false
	if isMap && truthy(runtime.Value("available")) {
		inSync = pyEqual(selection.Value("countries"), runtime.Value("countries")) &&
			pyEqual(selection.Value("access_filter_enabled"), runtime.Value("enable_geoip"))
	}
	result.Set("runtime_config_in_sync", inSync)
	return result
}

func attachToStatus(result *Map) *Map {
	if status, ok := asMap(result.Value("status")); ok {
		attachRuntimeConfig(status)
	}
	return result
}

func siteGeoIPCountryUsage() (map[string][]string, error) {
	raw, err := os.ReadFile(WebsitesYAML)
	if err != nil {
		return nil, &ValueError{"Cannot read websites.yml GeoIP policies: " + pyFileError(err, WebsitesYAML)}
	}
	v, err := pyyaml.Load(raw)
	if err != nil {
		return nil, &ValueError{"Cannot read websites.yml GeoIP policies: " + err.Error()}
	}
	if !truthy(v) {
		v = newMap()
	}
	websites, ok := asMap(v)
	if !ok {
		return nil, &ValueError{"websites.yml root must be a mapping"}
	}
	sitesV := orValue(websites.Value("sites"), []any{})
	sites, ok := sitesV.([]any)
	if !ok {
		return nil, &ValueError{"websites.yml sites value must be a list"}
	}
	usage := map[string][]string{}
	for i, s := range sites {
		site, ok := asMap(s)
		if !ok {
			return nil, &ValueError{fmt.Sprintf("sites[%d] must be an object", i)}
		}
		rawCountries := site.Value("geo_countries")
		if l, isList := rawCountries.([]any); rawCountries == nil || (isList && len(l) == 0) {
			continue
		}
		codes, err := normalizeCountries(rawCountries)
		if err != nil {
			return nil, &ValueError{fmt.Sprintf("sites[%d].geo_countries: %s", i, err.Error())}
		}
		label := pyStr(orValue(site.Value("domain"), site.Value("name"), fmt.Sprintf("sites[%d]", i)))
		for _, code := range codes {
			usage[code.(string)] = append(usage[code.(string)], label)
		}
	}
	return usage, nil
}

func validationError(msg string) *Map {
	return newMap("ok", false, "validation_error", true, "error", msg)
}

func configureGeoIPCountries(op *Op, values, revision any) *Map {
	if pending, msg := ConfigTransactionIsPending(op); pending {
		return newMap("ok", false, "conflict", true, "error", msg)
	}
	countries, err := normalizeCountries(values)
	if err != nil {
		return validationError(err.Error())
	}
	usage, err := siteGeoIPCountryUsage()
	if err != nil {
		return validationError(err.Error())
	}
	chosen := map[string]bool{}
	for _, c := range countries {
		chosen[c.(string)] = true
	}
	var required []string
	for code := range usage {
		if !chosen[code] {
			required = append(required, code)
		}
	}
	sort.Strings(required)
	if len(required) > 0 {
		parts := make([]string, len(required))
		for i, code := range required {
			labels := append([]string{}, usage[code]...)
			sort.Strings(labels)
			parts[i] = fmt.Sprintf("%s (%s)", code, strings.Join(labels, ", "))
		}
		return validationError("Countries used by per-site GeoIP policies cannot be removed: " + strings.Join(parts, "; "))
	}
	revisionText := strings.ToLower(pyStripSpace(strOrEmpty(revision)))
	if !geoipRevisionRe.MatchString(revisionText) {
		return validationError("the GeoIP selection revision is missing or invalid")
	}
	return attachToStatus(geoipRequest("geoip-configure", newMap("countries", countries, "revision", revisionText)))
}

// geoipAudited is _audited: record the outcome, hand the answer back unchanged.
func (c *Ctx) geoipAudited(action string, result *Map, summary string) *Map {
	ok := truthy(result.Value("ok"))
	entry := AuditEntry{ObjectType: "geoip", Result: recordResult(ok)}
	if ok {
		entry.Summary = summary
	} else {
		entry.Detail = truncRunes(strOrEmpty(result.Value("error")), 500)
	}
	c.RecordRequest(action, entry)
	return result
}

// geoipResponse is _response.
func (c *Ctx) geoipResponse(result *Map) error {
	status := 200
	switch {
	case truthy(result.Value("ok")):
	case truthy(result.Value("conflict")):
		status = 409
	case truthy(result.Value("validation_error")):
		status = 400
	default:
		status = 502
	}
	return c.JSON(status, result)
}

func (a *App) registerGeoIPAudit() {
	a.Handle("routes.haproxy_geoip_status", func(c *Ctx) error {
		return c.geoipResponse(attachRuntimeConfig(geoipRequest("geoip-status", nil)))
	})

	a.Handle("routes.haproxy_geoip_update", func(c *Ctx) error {
		payload, ok := asMap(c.silentJSONMap())
		if ok {
			payload.Each(func(k, _ any) {
				if k != "force" {
					ok = false
				}
			})
		}
		if !ok {
			return c.JSON(400, newMap("ok", false, "error", "invalid request fields"))
		}
		force := truthy(payload.Value("force"))
		result := attachToStatus(geoipRequest("geoip-update", newMap("force", force)))
		return c.geoipResponse(c.geoipAudited("geoip.update", result, "force: "+pyStr(force)))
	})

	a.Handle("routes.haproxy_geoip_countries", func(c *Ctx) error {
		payload, ok := asMap(c.silentJSONMap())
		if !ok || !sameKeys(keySet(payload), "countries", "revision") {
			return c.JSON(400, newMap("ok", false, "error", "countries and revision are required"))
		}
		countries := payload.Value("countries")
		summary := ""
		if list, isList := countries.([]any); isList {
			parts := make([]string, len(list))
			for i, v := range list {
				parts[i] = pyStr(v)
			}
			summary = "countries: " + strings.Join(parts, ", ")
		}
		result := configureGeoIPCountries(c.op(), countries, payload.Value("revision"))
		return c.geoipResponse(c.geoipAudited("geoip.countries", result, summary))
	})

	a.Handle("routes.haproxy_geoip_schedule", func(c *Ctx) error {
		payload, ok := asMap(c.silentJSONMap())
		if !ok || !sameKeys(keySet(payload), "schedule") {
			return c.JSON(400, newMap("ok", false, "error", "schedule is required"))
		}
		schedule := payload.Value("schedule")
		value := strings.ToLower(pyStripSpace(strOrEmpty(schedule)))
		var result *Map
		if pick(geoipSchedules, value, "") == "" {
			result = validationError("schedule must be one of: " + strings.Join(geoipSchedules, ", "))
		} else {
			result = attachToStatus(geoipRequest("geoip-schedule", newMap("schedule", value)))
		}
		return c.geoipResponse(c.geoipAudited("geoip.schedule", result, "schedule: "+pyRepr(schedule)))
	})

	// ---- the change log ----
	clean := func(raw string, allowed []string, limit int) string {
		text := truncRunes(pyStripSpace(raw), limit)
		if allowed != nil && pick(allowed, text, "") == "" {
			return ""
		}
		return text
	}
	a.Handle("routes.api_audit_events", func(c *Ctx) error {
		ranges := []string{"1h", "24h", "7d", "30d", "90d", "all"}
		rangeKey := clean(c.QueryStr("range"), ranges, 120)
		if rangeKey == "" {
			rangeKey = "7d"
		}
		window := auditRangeSecs[rangeKey]
		intArg := func(name string, def int64) int64 {
			raw, has := c.queryOpt(name)
			if !has {
				return def
			}
			n, err := parsePyIntString(raw)
			if err != nil {
				return def
			}
			return n
		}
		limit := intArg("limit", 100)
		offset := intArg("offset", 0)
		var since int64
		if window != 0 {
			since = time.Now().Unix() - window
		}
		payload := Audit().Query(AuditQuery{
			Actor: clean(c.QueryStr("actor"), nil, 120), Action: clean(c.QueryStr("action"), nil, 120),
			ObjectType: clean(c.QueryStr("object_type"), nil, 60), Result: clean(c.QueryStr("result"), auditResultList, 120),
			Since: since, Limit: max(1, min(limit, 500)), Offset: max(0, offset),
		})
		payload.Set("ok", true)
		payload.Set("range", rangeKey)
		return c.JSON(200, payload)
	})
	a.Handle("routes.api_audit_filters", func(c *Ctx) error {
		log := Audit()
		return c.JSON(200, newMap("ok", true, "actors", log.Distinct("actor", 100), "actions", log.Distinct("action", 100),
			"object_types", log.Distinct("object_type", 100), "results", strList(auditResultList...)))
	})
	a.Handle("routes.api_audit_status", func(c *Ctx) error {
		return c.JSON(200, newMap("ok", true, "audit", Audit().Stats()))
	})
}
