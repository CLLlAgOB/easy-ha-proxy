package app

// Page views that only render a template (routes.py, routes_*.py).

import (
	"math"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"easy-ha-proxy/panel/internal/jinja"
	"easy-ha-proxy/panel/internal/pyyaml"
)

func truthy(v any) bool  { return jinja.Truthy(v) }
func pyStr(v any) string { return jinja.Str(v) }

func strList(items ...string) []any {
	out := make([]any, len(items))
	for i, s := range items {
		out[i] = s
	}
	return out
}

func intList(items ...int64) []any {
	out := make([]any, len(items))
	for i, n := range items {
		out[i] = n
	}
	return out
}

// Query is request.args.get(name) (nil when absent).
func (c *Ctx) Query(name string) any {
	vals, ok := c.R.URL.Query()[name]
	if !ok || len(vals) == 0 {
		return nil
	}
	return vals[0]
}

// QueryStr is request.args.get(name, "").
func (c *Ctx) QueryStr(name string) string {
	v := c.Query(name)
	if v == nil {
		return ""
	}
	return v.(string)
}

var (
	monitoringRanges   = strList("1h", "6h", "24h", "7d", "30d", "90d", "1y")
	auditRanges        = strList("1h", "24h", "7d", "30d", "90d", "all")
	securityEventTypes = strList("SCANNER_PATH", "SCANNER_PATH_DECISIVE", "QUERY_INJECTION", "SCANNER_MULTI_CATEGORY",
		"LOW_AND_SLOW_SCANNER", "NOT_FOUND_ENUMERATION", "WIDE_ENUMERATION", "MASS_ENUMERATION", "RECURRING_SCANNER",
		"INVALID_HOST_ACTIVITY", "NOSNI_PROBING", "RATE_EXCEEDED", "ERROR_RATE_EXCEEDED", "LEGACY_HAPROXY_BAN",
		"HARD_FLOOR_EPISODE", "SUBNET_CAMPAIGN")
	dnsProviders = strList("cloudflare", "digitalocean", "route53", "rfc2136")
	liveWindows  = intList(30, 60, 300, 900)
)

const trashMaxKeepDays = 3650

func debugRoutesEnabled() bool {
	switch strings.ToLower(os.Getenv("HAPROXY_ADMIN_DEBUG_ROUTES")) {
	case "1", "true", "yes":
		return true
	}
	return false
}

// validIP is services_security.valid_ip: the canonical address or "".
func validIP(v any) string {
	if v == nil {
		v = "None"
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(pyStr(v)))
	if err != nil || addr.Zone() != "" {
		return ""
	}
	return addr.String()
}

func staticPage(name string, vars map[string]any) HandlerFunc {
	return func(c *Ctx) error { return c.Render(name, vars) }
}

func maxUploadGiB() float64 {
	n := int64(8 * 1024 * 1024 * 1024)
	if v, ok := os.LookupEnv("EASY_HA_PROXY_BACKUP_MAX_UPLOAD_BYTES"); ok {
		if p, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
			n = p
		}
	}
	return pyRound(float64(n)/float64(1024*1024*1024), 1)
}

// pyRound is round(x, ndigits) on a float (half to even on the exact value).
func pyRound(x float64, ndigits int) float64 {
	s := strconv.FormatFloat(x, 'f', ndigits, 64)
	r, _ := strconv.ParseFloat(s, 64)
	if math.IsNaN(r) {
		return x
	}
	return r
}

func (a *App) registerPages() {
	a.Handle("routes.index", func(c *Ctx) error {
		return c.Render("index.html", map[string]any{"is_superadmin": c.Superadmin(), "debug_routes_enabled": debugRoutesEnabled()})
	})
	a.Handle("routes.debug", func(c *Ctx) error {
		if !debugRoutesEnabled() {
			return c.Render("debug_disabled.html", nil)
		}
		return c.Render("debug.html", nil)
	})
	a.Handle("routes.debug_headers", func(c *Ctx) error {
		if !debugRoutesEnabled() {
			return Abort(http.StatusNotFound, "")
		}
		hidden := map[string]bool{"x-easy-ha-proxy-secret": true, "x-easy-haproxy-config-generation": true, "cookie": true, "authorization": true}
		var lines []string
		for _, h := range requestHeaderOrder(c.R) {
			v := h[1]
			if hidden[strings.ToLower(h[0])] {
				v = "[redacted]"
			}
			lines = append(lines, h[0]+": "+v)
		}
		return c.Text(200, "text/plain; charset=utf-8", strings.Join(lines, "\n"))
	})
	a.Handle("routes.haproxy_stats_page", staticPage("haproxy_stats.html", nil))
	a.Handle("routes.monitoring_page", func(c *Ctx) error {
		return c.Render("monitoring.html", map[string]any{"ranges": jinja.Tuple(monitoringRanges), "default_range": "24h", "can_switch_monitors": c.Superadmin()})
	})
	a.Handle("routes.live_activity_page", staticPage("live_activity.html", map[string]any{"windows": jinja.Tuple(liveWindows)}))
	a.Handle("routes.system_health_page", func(c *Ctx) error {
		return c.Render("health.html", map[string]any{"is_superadmin": c.Superadmin()})
	})
	a.Handle("routes.haproxy_backends_page", func(c *Ctx) error {
		return c.Render("haproxy_backends.html", map[string]any{"is_superadmin": c.Superadmin()})
	})
	a.Handle("routes.alerts_page", staticPage("alerts.html", nil))
	a.Handle("routes.audit_page", staticPage("audit.html", map[string]any{"ranges": auditRanges, "default_range": "7d"}))
	a.Handle("routes.adaptive_protection_page", staticPage("adaptive_protection.html", map[string]any{"event_types": jinja.Tuple(securityEventTypes)}))
	a.Handle("routes.adaptive_bans_page", staticPage("adaptive_bans.html", nil))
	a.Handle("routes.adaptive_ban_page", func(c *Ctx) error {
		address := validIP(c.Query("ip"))
		id, err1 := pyIntArg(c.Query("id"))
		ts, err2 := pyIntArg(c.Query("at"))
		if err1 != nil || err2 != nil {
			return Abort(400, "Invalid ban reference")
		}
		const limit = int64(1) << 62
		if !(0 <= id && id <= limit) || !(0 <= ts && ts <= limit) || !(id != 0 || address != "") {
			return Abort(400, "Invalid ban reference")
		}
		ban := newMap("id", id, "ip", address, "ts", ts)
		return c.Render("adaptive_ban_detail.html", map[string]any{"ban": ban})
	})
	a.Handle("routes.detection_rules_page", staticPage("detection_rules.html", nil))
	a.Handle("routes.request_log_page", staticPage("request_log.html", nil))
	a.Handle("routes.config_history_page", staticPage("config_history.html", nil))
	a.Handle("routes.dns_providers_page", staticPage("dns_providers.html", map[string]any{"providers": jinja.Tuple(dnsProviders)}))
	a.Handle("routes.haproxy_geoip_page", staticPage("haproxy_geoip.html", nil))
	a.Handle("routes.trash_page", staticPage("trash.html", map[string]any{"max_keep_days": int64(trashMaxKeepDays)}))
	a.Handle("os_security.page", staticPage("os_security.html", nil))
	a.Handle("ssh_security.page", staticPage("ssh_security.html", nil))
	a.Handle("schedule.page", staticPage("system_schedule.html", nil))
	a.Handle("system_updates.page", staticPage("system_updates.html", nil))
	a.Handle("system_backups.page", func(c *Ctx) error {
		return c.Render("system_backups.html", map[string]any{"max_upload_gib": maxUploadGiB()})
	})
}

// pyIntArg is int(request.args.get(name) or 0).
func pyIntArg(v any) (int64, error) {
	s, _ := v.(string)
	if s == "" {
		return 0, nil
	}
	return strconv.ParseInt(strings.TrimSpace(strings.ReplaceAll(s, "_", "")), 10, 64)
}

func requestHeaderOrder(r *http.Request) [][2]string {
	var out [][2]string
	if r.Host != "" {
		out = append(out, [2]string{"Host", r.Host})
	}
	for k, vals := range r.Header {
		for _, v := range vals {
			out = append(out, [2]string{k, v})
		}
	}
	return out
}

func (a *App) registerAll() {
	a.registerPages()
	a.registerUDPRoutes()
	a.registerTCPRoutes()
	a.registerSiteRoutes()
	a.registerConfigRoutes()
	a.registerSitesPage()
	a.registerSiteEdit()
	a.registerTCPPages()
	a.registerTrashRoutes()
	a.registerBackendPresetRoutes()
	a.registerConfigHistoryRoutes()
	a.registerCertRoutes()
	trashRestorers["udp"] = RestoreUDPForward
}

// newMap builds an ordered dict from key, value pairs.
func newMap(kv ...any) *pyyaml.Map {
	m := pyyaml.NewMap()
	for i := 0; i+1 < len(kv); i += 2 {
		m.Set(kv[i], kv[i+1])
	}
	return m
}
