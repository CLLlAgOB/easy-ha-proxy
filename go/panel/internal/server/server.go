// Package server wires the HTTP routes, middleware chain, static assets,
// and daemon API proxies for the easy-ha-proxy Go web admin panel.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"easy-ha-proxy/panel/internal/audit"
	"easy-ha-proxy/panel/internal/cfgstore"
	"easy-ha-proxy/panel/internal/config"
	"easy-ha-proxy/panel/internal/daemons"
	"easy-ha-proxy/panel/internal/geoip"
	"easy-ha-proxy/panel/internal/haproxy"
	"easy-ha-proxy/panel/internal/i18n"
	"easy-ha-proxy/panel/internal/prometheus"
	"easy-ha-proxy/panel/internal/security"
	"easy-ha-proxy/panel/internal/ui"
)

var (
	monitoringRanges = map[string]struct{}{
		"1h": {}, "6h": {}, "24h": {}, "7d": {}, "30d": {}, "90d": {}, "1y": {},
	}
	monitoringCharts = []string{
		"requests", "traffic", "responses", "latency", "connections",
		"cpu", "memory", "disk", "diskio", "network", "temperature",
		"percentiles", "refusals",
	}
	monitoringChartSet = func() map[string]struct{} {
		m := make(map[string]struct{}, len(monitoringCharts))
		for _, c := range monitoringCharts {
			m[c] = struct{}{}
		}
		return m
	}()
)

// Server holds the configured HTTP handler and dependencies.
type Server struct {
	Cfg      *config.Config
	Pool     *daemons.Pool
	Runtime  *haproxy.Runtime
	GeoIP    *geoip.Reader
	Audit    *audit.Store
	CfgStore *cfgstore.Store
	UI       *ui.Renderer
	Catalog  *i18n.Catalog
	Boundary *security.Boundary
	Prom     *prometheus.Collector
	handler  http.Handler
}

// New constructs a Server with the complete middleware chain and Stage D1 API routes.
func New(cfg *config.Config, pool *daemons.Pool, rt *haproxy.Runtime, cat *i18n.Catalog) *Server {
	if pool == nil {
		pool = daemons.NewPool(cfg)
	}
	if rt == nil {
		rt = haproxy.NewRuntime(cfg.HAProxySocket, cfg.HAProxyCfg, cfg.ExcludeExact, cfg.ExcludePrefix)
	}
	if cat == nil {
		var err error
		cat, err = i18n.LoadDir(cfg.TranslationsDir, cfg.DefaultLanguage)
		if err != nil {
			cat, _ = i18n.LoadDir("", cfg.DefaultLanguage)
		}
	}

	boundary := security.NewBoundary(
		cfg.ProxySecret,
		cfg.SecretKey,
		cfg.SessionSecure,
		cat.TranslateRequest,
	)
	prom := &prometheus.Collector{
		Enabled: cfg.MetricsExportEnabled,
		Token:   cfg.MetricsExportToken,
		Pool:    pool,
		Runtime: rt,
	}

	uiRenderer, _ := ui.NewRenderer(cfg.StaticDir, cfg.ServerTimezone, cat)

	s := &Server{
		Cfg:      cfg,
		Pool:     pool,
		Runtime:  rt,
		GeoIP:    geoip.NewReader(cfg.GeoIPDBPath),
		Audit:    audit.Open(cfg.AuditDatabase),
		CfgStore: cfgstore.New(cfg.ConfigDir, cfg.ConfigBackupDir, cfg.HAProxyCfg),
		UI:       uiRenderer,
		Catalog:  cat,
		Boundary: boundary,
		Prom:     prom,
	}

	mux := http.NewServeMux()
	s.registerRoutes(mux)

	// Middleware order (outermost -> innermost):
	// GzipJSONMiddleware -> BodyLimit -> Boundary (Proxy Secret + RBAC + CSRF + Security Headers) -> Mux.
	var h http.Handler = mux
	h = boundary.Wrap(h)
	h = s.bodyLimitMiddleware(h)
	h = security.GzipJSONMiddleware(h)
	s.handler = h
	return s
}

// Handler returns the root http.Handler.
func (s *Server) Handler() http.Handler {
	return s.handler
}

func (s *Server) bodyLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit := s.Cfg.MaxBodyBytes
		if r.URL.Path == "/system/backups/api/uploads" && s.Cfg.MaxUploadBytes > 0 {
			limit = s.Cfg.MaxUploadBytes
		}
		if limit > 0 && r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) registerRoutes(mux *http.ServeMux) {
	// Control-plane readiness probes and Prometheus exposition.
	mux.HandleFunc("GET /api/control-plane-health", s.handleControlPlaneHealth)
	mux.HandleFunc("GET /api/access-portal-health", s.handleControlPlaneHealth)
	mux.Handle("GET /metrics", s.Prom)

	// Internationalization and static assets.
	mux.HandleFunc("GET /i18n/messages.js", s.Catalog.ServeMessagesJS)
	mux.HandleFunc("POST /language", s.Catalog.ServeSetLanguage(s.Cfg.SessionSecure))
	mux.Handle("GET /static/", s.staticHandler())

	// Health API (routes_health.py).
	mux.HandleFunc("GET /api/health/status", s.handleHealthStatus)
	mux.HandleFunc("GET /api/health/events", s.handleHealthEvents)
	mux.HandleFunc("GET /api/health/logs/systemd", s.handleHealthLogsSystemd)
	mux.HandleFunc("GET /api/health/recent-systemd", s.handleHealthRecentSystemd)
	mux.HandleFunc("GET /api/health/logs/docker", s.handleHealthLogsDocker)
	mux.HandleFunc("GET /api/health/capabilities", s.handleHealthCapabilities)
	mux.HandleFunc("POST /api/health/control", s.handleHealthControl)

	// Alerts API (routes_alerts.py).
	mux.HandleFunc("GET /api/alerts/state", s.handleAlertsState)
	mux.HandleFunc("GET /api/alerts/health", s.handleAlertsHealth)
	mux.HandleFunc("GET /api/alerts/history", s.handleAlertsHistory)
	mux.HandleFunc("GET /api/alerts/portal", s.handleAlertsPortal)
	mux.HandleFunc("POST /api/alerts/config", s.handleAlertsConfig)
	mux.HandleFunc("POST /api/alerts/quieten", s.handleAlertsQuieten)
	mux.HandleFunc("POST /api/alerts/dismiss", s.handleAlertsDismiss)
	mux.HandleFunc("POST /api/alerts/mail/retry", s.handleAlertsMailRetry)
	mux.HandleFunc("POST /api/alerts/history/delete", s.handleAlertsHistoryDelete)
	mux.HandleFunc("POST /api/alerts/test", s.handleAlertsTest)

	// Monitoring API (routes_monitoring.py).
	mux.HandleFunc("GET /api/monitoring/sites", s.handleMonitoringSites)
	mux.HandleFunc("GET /api/monitoring/summary", s.handleMonitoringSummary)
	mux.HandleFunc("GET /api/monitoring/series", s.handleMonitoringSeries)
	mux.HandleFunc("GET /api/monitoring/states", s.handleMonitoringStates)
	mux.HandleFunc("GET /api/monitoring/storage", s.handleMonitoringStorage)
	mux.HandleFunc("GET /api/monitoring/channels", s.handleMonitoringServers)
	mux.HandleFunc("GET /api/monitoring/backends", s.handleMonitoringBackends)
	mux.HandleFunc("GET /api/monitoring/backend-requests", s.handleMonitoringBackends)
	mux.HandleFunc("GET /api/monitoring/attention", s.handleMonitoringAttention)
	mux.HandleFunc("POST /api/monitoring/channels/labels", s.handleMonitoringChannelLabels)
	mux.HandleFunc("POST /api/monitoring/monitors", s.handleMonitoringMonitors)
	mux.HandleFunc("GET /api/monitoring/live", s.handleLiveActivity)
	mux.HandleFunc("GET /api/monitoring/live/decisions", s.handleLiveDecisions)

	// HAProxy Runtime Backends API (routes_runtime.py).
	mux.HandleFunc("GET /api/haproxy/backends", s.handleHAProxyBackends)
	mux.HandleFunc("POST /api/haproxy/backends/state", s.handleHAProxyBackendState)
	mux.HandleFunc("POST /api/haproxy/backends/weight", s.handleHAProxyBackendWeight)

	// Adaptive Security / Guardd API (routes_security.py).
	mux.HandleFunc("GET /api/security/adaptive/health", s.guarddGetProxy("/api/v1/guard/health", 15*time.Second, true))
	mux.HandleFunc("GET /api/security/adaptive/quality", s.guarddGetProxy("/api/v1/guard/quality", 15*time.Second, true))
	mux.HandleFunc("GET /api/security/adaptive/shadow", s.guarddGetProxy("/api/v1/guard/shadow", 15*time.Second, true))
	mux.HandleFunc("GET /api/security/adaptive/rate-warnings", s.guarddGetProxy("/api/v1/guard/rate-warnings", 15*time.Second, true))
	mux.HandleFunc("GET /api/security/adaptive/bans", s.guarddGetProxy("/api/v1/guard/adaptive/bans", 5*time.Second, false))
	mux.HandleFunc("GET /api/security/adaptive/ban", s.guarddGetProxy("/api/v1/guard/adaptive/ban", 5*time.Second, false))
	mux.HandleFunc("GET /api/security/adaptive/ip", s.guarddGetProxy("/api/v1/guard/ip", 15*time.Second, true))
	mux.HandleFunc("GET /api/security/detection-rules", s.guarddGetProxy("/api/v1/guard/signatures", 15*time.Second, true))
	mux.HandleFunc("GET /api/security/detection-rules/context", s.guarddGetProxy("/api/v1/guard/detection-context", 15*time.Second, true))
	mux.HandleFunc("GET /api/security/detection-rules/candidates", s.guarddGetProxy("/api/v1/guard/signatures/candidates", 15*time.Second, true))
	mux.HandleFunc("GET /api/security/traps", s.guarddGetProxy("/api/v1/guard/traps", 15*time.Second, true))
	mux.HandleFunc("GET /api/security/requests", s.guarddGetProxy("/api/v1/guard/requests", 15*time.Second, false))
	mux.HandleFunc("GET /api/security/requests/summary", s.guarddGetProxy("/api/v1/guard/requests/summary", 15*time.Second, false))
	mux.HandleFunc("GET /api/security/requests/status", s.guarddGetProxy("/api/v1/guard/requests/status", 15*time.Second, false))
	mux.HandleFunc("GET /api/security/requests/memory", s.guarddGetProxy("/api/v1/guard/live/memory", 15*time.Second, false))
	mux.HandleFunc("POST /api/security/adaptive/mode", s.guarddSuperadminPostProxy("/api/v1/guard/mode", 30*time.Second))
	mux.HandleFunc("POST /api/security/adaptive/durations", s.guarddSuperadminPostProxy("/api/v1/guard/ban-durations", 15*time.Second))
	mux.HandleFunc("POST /api/security/adaptive/first-step-page", s.guarddSuperadminPostProxy("/api/v1/guard/first-step-page", 15*time.Second))
	mux.HandleFunc("POST /api/security/adaptive/shield", s.guarddSuperadminPostProxy("/api/v1/guard/shield", 15*time.Second))
	mux.HandleFunc("POST /api/security/detection-rules", s.guarddSuperadminPostProxy("/api/v1/guard/signatures", 30*time.Second))
	mux.HandleFunc("POST /api/security/detection-rules/context", s.guarddSuperadminPostProxy("/api/v1/guard/detection-context", 15*time.Second))
	mux.HandleFunc("POST /api/security/detection-rules/preview", s.guarddSuperadminPostProxy("/api/v1/guard/detection-preview", 15*time.Second))
	mux.HandleFunc("POST /api/security/detection-rules/candidates/dismiss", s.guarddSuperadminPostProxy("/api/v1/guard/signatures/candidates/dismiss", 15*time.Second))
	mux.HandleFunc("POST /api/security/traps", s.guarddSuperadminPostProxy("/api/v1/guard/traps", 15*time.Second))
	mux.HandleFunc("POST /api/security/requests/enabled", s.guarddSuperadminPostProxy("/api/v1/guard/requests/enabled", 30*time.Second))
	mux.HandleFunc("POST /api/security/requests/memory", s.guarddSuperadminPostProxy("/api/v1/guard/live/memory", 15*time.Second))

	// Panel info endpoint (for diagnostics and Stage D verification).
	mux.HandleFunc("GET /api/panel/info", s.handlePanelInfo)

	// Stage D2 route groups: dashboard, certificates, config/GeoIP, backups,
	// updates/OS/SSH security, and Authelia daemons.
	s.registerDashboardRoutes(mux)
	s.registerCertRoutes(mux)
	s.registerConfigAndGeoIPRoutes(mux)
	s.registerBackupRoutes(mux)
	s.registerUpdateAndSecurityRoutes(mux)
	s.registerAutheliaRoutes(mux)

	// Stage D3 route groups: audit log, YAML config store, and HTML UI pages.
	s.registerStageD3Routes(mux)
}

func (s *Server) staticHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.Cfg.StaticDir == "" {
			http.NotFound(w, r)
			return
		}
		rel := strings.TrimPrefix(r.URL.Path, "/static/")
		clean := filepath.Clean(filepath.FromSlash(rel))
		if clean == "." || strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
			http.NotFound(w, r)
			return
		}
		full := filepath.Join(s.Cfg.StaticDir, clean)
		info, err := os.Stat(full)
		if err != nil || info.IsDir() {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, full)
	})
}

func (s *Server) writeJSON(w http.ResponseWriter, r *http.Request, status int, payload any) {
	lang := s.Catalog.SelectLanguage(r)
	localized := s.Catalog.LocalizeJSON(lang, payload)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(localized)
}

func (s *Server) readJSONBody(r *http.Request) (map[string]any, error) {
	if r.Body == nil {
		return map[string]any{}, nil
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return map[string]any{}, nil
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, errors.New("a JSON object is required")
	}
	if out == nil {
		return nil, errors.New("a JSON object is required")
	}
	return out, nil
}

func isSuperadmin(r *http.Request) bool {
	id := security.FromContext(r.Context())
	return id != nil && id.IsSuperadmin
}

func remoteUser(r *http.Request) string {
	id := security.FromContext(r.Context())
	if id == nil {
		return ""
	}
	return id.User
}

// ---------------------------------------------------------------------------
// Readiness & Info
// ---------------------------------------------------------------------------

func (s *Server) handleControlPlaneHealth(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, r, http.StatusOK, map[string]any{
		"ok":      true,
		"service": "haproxy-admin",
	})
}

func (s *Server) handlePanelInfo(w http.ResponseWriter, r *http.Request) {
	id := security.FromContext(r.Context())
	csrf := ""
	if id != nil {
		csrf = id.CSRFToken
	}
	s.writeJSON(w, r, http.StatusOK, map[string]any{
		"ok":         true,
		"engine":     "go-panel",
		"version":    config.Version,
		"user":       remoteUser(r),
		"superadmin": isSuperadmin(r),
		"csrf_token": csrf,
		"language":   s.Catalog.SelectLanguage(r),
	})
}

// ---------------------------------------------------------------------------
// Health API (routes_health.py)
// ---------------------------------------------------------------------------

func (s *Server) handleHealthStatus(w http.ResponseWriter, r *http.Request) {
	q := url.Values{}
	if r.URL.Query().Get("refresh") == "1" {
		q.Set("refresh", "1")
	}
	data, _, err := s.Pool.Healthd.GetJSON(r.Context(), "/api/v1/health/status", daemons.RequestOptions{
		Query: q, Timeout: 12 * time.Second, WithToken: true, CheckStatus: true,
	})
	if err != nil {
		s.writeJSON(w, r, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	s.writeJSON(w, r, http.StatusOK, data)
}

func (s *Server) handleHealthEvents(w http.ResponseWriter, r *http.Request) {
	limit := clampInt(r.URL.Query().Get("limit"), 50, 1, 500)
	q := url.Values{"limit": {strconv.Itoa(limit)}}
	data, _, err := s.Pool.Healthd.GetJSON(r.Context(), "/api/v1/health/events", daemons.RequestOptions{
		Query: q, Timeout: 10 * time.Second, WithToken: true, CheckStatus: true,
	})
	if err != nil {
		s.writeJSON(w, r, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	s.writeJSON(w, r, http.StatusOK, data)
}

func (s *Server) handleHealthLogsSystemd(w http.ResponseWriter, r *http.Request) {
	unit := strings.TrimSpace(r.URL.Query().Get("unit"))
	if unit == "" {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "unit is required"})
		return
	}
	tail := parseIntDefault(r.URL.Query().Get("tail"), 200)
	since := parseIntDefault(r.URL.Query().Get("since"), 3600)
	q := url.Values{
		"unit":  {unit},
		"tail":  {strconv.Itoa(tail)},
		"since": {strconv.Itoa(since)},
	}
	data, _, err := s.Pool.Healthd.GetJSON(r.Context(), "/api/v1/health/logs/systemd", daemons.RequestOptions{
		Query: q, Timeout: 20 * time.Second, WithToken: true, CheckStatus: true,
	})
	if err != nil {
		s.writeJSON(w, r, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	s.writeJSON(w, r, http.StatusOK, data)
}

func (s *Server) handleHealthRecentSystemd(w http.ResponseWriter, r *http.Request) {
	limit := clampInt(r.URL.Query().Get("limit"), 50, 1, 500)
	q := url.Values{"limit": {strconv.Itoa(limit)}}
	rawQuery := r.URL.Query()
	if _, hasUnit := rawQuery["unit"]; hasUnit || rawQuery.Has("units") {
		seen := make(map[string]struct{})
		var clean []string
		for _, raw := range append(rawQuery["unit"], rawQuery["units"]...) {
			for _, part := range strings.Split(raw, ",") {
				u := strings.TrimSpace(part)
				if u == "" {
					continue
				}
				if _, dup := seen[u]; !dup {
					seen[u] = struct{}{}
					clean = append(clean, u)
				}
			}
		}
		if len(clean) > 0 {
			for _, u := range clean {
				q.Add("unit", u)
			}
		} else {
			q.Set("units", "")
		}
	}

	data, _, err := s.Pool.Healthd.GetJSON(r.Context(), "/api/v1/health/recent-systemd", daemons.RequestOptions{
		Query: q, Timeout: 20 * time.Second, WithToken: true, CheckStatus: true, AcceptedStatuses: []int{400},
	})
	if err != nil {
		s.writeJSON(w, r, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	status := http.StatusOK
	if okVal, hasOK := data["ok"].(bool); hasOK && !okVal {
		if _, hasInv := data["invalid_units"]; hasInv {
			status = http.StatusBadRequest
		}
	}
	s.writeJSON(w, r, status, data)
}

func (s *Server) handleHealthLogsDocker(w http.ResponseWriter, r *http.Request) {
	container := strings.TrimSpace(r.URL.Query().Get("container"))
	if container == "" {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "container is required"})
		return
	}
	tail := parseIntDefault(r.URL.Query().Get("tail"), 200)
	since := parseIntDefault(r.URL.Query().Get("since"), 3600)
	q := url.Values{
		"container": {container},
		"tail":      {strconv.Itoa(tail)},
		"since":     {strconv.Itoa(since)},
	}
	data, _, err := s.Pool.Healthd.GetJSON(r.Context(), "/api/v1/health/logs/docker", daemons.RequestOptions{
		Query: q, Timeout: 20 * time.Second, WithToken: true, CheckStatus: true,
	})
	if err != nil {
		s.writeJSON(w, r, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	s.writeJSON(w, r, http.StatusOK, data)
}

func (s *Server) handleHealthCapabilities(w http.ResponseWriter, r *http.Request) {
	data, _, err := s.Pool.Healthd.GetJSON(r.Context(), "/api/v1/control/capabilities", daemons.RequestOptions{
		Timeout: 10 * time.Second, WithToken: true, CheckStatus: true,
	})
	if err != nil {
		s.writeJSON(w, r, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	s.writeJSON(w, r, http.StatusOK, data)
}

func (s *Server) handleHealthControl(w http.ResponseWriter, r *http.Request) {
	if !isSuperadmin(r) {
		s.writeJSON(w, r, http.StatusForbidden, map[string]any{"ok": false, "error": "forbidden"})
		return
	}
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	kind := strings.ToLower(strings.TrimSpace(asString(payload["kind"])))
	name := strings.TrimSpace(asString(payload["name"]))
	action := strings.ToLower(strings.TrimSpace(asString(payload["action"])))

	if kind != "systemd" && kind != "docker" {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "kind must be systemd|docker"})
		return
	}
	if name == "" {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "name is required"})
		return
	}
	switch action {
	case "start", "stop", "restart", "reload":
	default:
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "action must be start|stop|restart|reload"})
		return
	}

	caps, _, err := s.Pool.Healthd.GetJSON(r.Context(), "/api/v1/control/capabilities", daemons.RequestOptions{
		Timeout: 10 * time.Second, WithToken: true, CheckStatus: true,
	})
	if err != nil {
		s.writeJSON(w, r, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if okVal, _ := caps["ok"].(bool); !okVal {
		s.writeJSON(w, r, http.StatusBadGateway, map[string]any{"ok": false, "error": "healthd capabilities not ok"})
		return
	}

	allowed := allowedActionsFor(caps, kind, name)
	if _, ok := allowed[action]; !ok {
		list := make([]string, 0, len(allowed))
		for a := range allowed {
			list = append(list, a)
		}
		sort.Strings(list)
		s.writeJSON(w, r, http.StatusForbidden, map[string]any{
			"ok":      false,
			"error":   "action not allowed",
			"allowed": list,
		})
		return
	}

	res, _, err := s.Pool.Healthd.PostJSON(r.Context(), "/api/v1/control", map[string]any{
		"kind": kind, "name": name, "action": action,
	}, daemons.RequestOptions{
		Timeout: 30 * time.Second, WithToken: true, CheckStatus: true,
	})
	if err != nil {
		s.writeJSON(w, r, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if _, hasText := res["text"]; !hasText {
		out := asString(res["stdout"])
		errOut := asString(res["stderr"])
		sep := ""
		if out != "" && errOut != "" {
			sep = "\n"
		}
		res["text"] = strings.TrimSpace(out + sep + errOut)
	}
	status := http.StatusInternalServerError
	if scheduled, _ := res["scheduled"].(bool); scheduled {
		status = http.StatusAccepted
	} else if okVal, _ := res["ok"].(bool); okVal {
		status = http.StatusOK
	}
	s.writeJSON(w, r, status, res)
}

func allowedActionsFor(caps map[string]any, kind, name string) map[string]struct{} {
	allowed := make(map[string]struct{})
	rawMap, _ := caps[kind].(map[string]any)
	addList := func(v any) {
		arr, ok := v.([]any)
		if !ok {
			return
		}
		for _, item := range arr {
			if s, ok := item.(string); ok && s != "" {
				allowed[s] = struct{}{}
			}
		}
	}
	if exact, ok := rawMap[name]; ok {
		addList(exact)
	}
	for pattern, val := range rawMap {
		if pattern == name || (!strings.Contains(pattern, "*") && !strings.Contains(pattern, "?")) {
			continue
		}
		if matched, err := path.Match(pattern, name); err == nil && matched {
			addList(val)
		}
	}
	return allowed
}

// ---------------------------------------------------------------------------
// Alerts API (routes_alerts.py)
// ---------------------------------------------------------------------------

func (s *Server) writeUnavailable(w http.ResponseWriter, r *http.Request, err error) {
	s.writeJSON(w, r, http.StatusServiceUnavailable, map[string]any{
		"ok":          false,
		"unavailable": true,
		"error":       err.Error(),
	})
}

func (s *Server) handleAlertsState(w http.ResponseWriter, r *http.Request) {
	limit := clampInt(r.URL.Query().Get("limit"), 100, 1, 500)
	data, _, err := s.Pool.Alertd.GetJSON(r.Context(), "/api/v1/alerts/state", daemons.RequestOptions{
		Query: url.Values{"limit": {strconv.Itoa(limit)}}, Timeout: 15 * time.Second, CheckStatus: true,
	})
	if err != nil {
		s.writeUnavailable(w, r, err)
		return
	}
	s.writeJSON(w, r, http.StatusOK, data)
}

func (s *Server) handleAlertsHealth(w http.ResponseWriter, r *http.Request) {
	data, _, err := s.Pool.Alertd.GetJSON(r.Context(), "/api/v1/alerts/health", daemons.RequestOptions{
		Timeout: 15 * time.Second, CheckStatus: true,
	})
	if err != nil {
		s.writeUnavailable(w, r, err)
		return
	}
	s.writeJSON(w, r, http.StatusOK, data)
}

func (s *Server) handleAlertsHistory(w http.ResponseWriter, r *http.Request) {
	q := url.Values{
		"limit":  {strconv.Itoa(clampInt(r.URL.Query().Get("limit"), 100, 1, 500))},
		"offset": {strconv.Itoa(clampInt(r.URL.Query().Get("offset"), 0, 0, 1_000_000))},
	}
	for _, k := range []string{"rule", "severity"} {
		if v := strings.TrimSpace(r.URL.Query().Get(k)); v != "" {
			q.Set(k, v)
		}
	}
	data, _, err := s.Pool.Alertd.GetJSON(r.Context(), "/api/v1/alerts/history", daemons.RequestOptions{
		Query: q, Timeout: 15 * time.Second, CheckStatus: true,
	})
	if err != nil {
		s.writeUnavailable(w, r, err)
		return
	}
	s.writeJSON(w, r, http.StatusOK, data)
}

func (s *Server) handleAlertsPortal(w http.ResponseWriter, r *http.Request) {
	data, _, err := s.Pool.Alertd.GetJSON(r.Context(), "/api/v1/alerts/portal", daemons.RequestOptions{
		Timeout: 5 * time.Second, CheckStatus: true,
	})
	if err != nil {
		s.writeUnavailable(w, r, err)
		return
	}
	s.writeJSON(w, r, http.StatusOK, data)
}

func (s *Server) handleAlertsConfig(w http.ResponseWriter, r *http.Request) {
	if !isSuperadmin(r) {
		s.writeJSON(w, r, http.StatusForbidden, map[string]any{"ok": false, "error": "superadmin required"})
		return
	}
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	res, _, err := s.Pool.Alertd.PostJSON(r.Context(), "/api/v1/alerts/config", payload, daemons.RequestOptions{
		Timeout: 15 * time.Second, WithToken: true, CheckStatus: false,
	})
	if err != nil {
		s.writeUnavailable(w, r, err)
		return
	}
	status := http.StatusBadRequest
	if okVal, _ := res["ok"].(bool); okVal {
		status = http.StatusOK
	}
	s.writeJSON(w, r, status, res)
}

func (s *Server) handleAlertsQuieten(w http.ResponseWriter, r *http.Request) {
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	body := map[string]any{
		"rule":    truncStr(strings.TrimSpace(asString(payload["rule"])), 80),
		"subject": truncStr(strings.TrimSpace(asString(payload["subject"])), 200),
		"mode":    asString(payload["mode"]),
		"by":      remoteUser(r),
	}
	if sec, ok := payload["seconds"]; ok {
		body["seconds"] = sec
	}
	res, _, err := s.Pool.Alertd.PostJSON(r.Context(), "/api/v1/alerts/quieten", body, daemons.RequestOptions{
		Timeout: 15 * time.Second, WithToken: true, CheckStatus: false,
	})
	if err != nil {
		s.writeUnavailable(w, r, err)
		return
	}
	status := http.StatusBadRequest
	if okVal, _ := res["ok"].(bool); okVal {
		status = http.StatusOK
	}
	s.writeJSON(w, r, status, res)
}

func (s *Server) handleAlertsDismiss(w http.ResponseWriter, r *http.Request) {
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	body := map[string]any{
		"rule":    truncStr(strings.TrimSpace(asString(payload["rule"])), 80),
		"subject": truncStr(strings.TrimSpace(asString(payload["subject"])), 200),
		"by":      remoteUser(r),
	}
	res, _, err := s.Pool.Alertd.PostJSON(r.Context(), "/api/v1/alerts/dismiss", body, daemons.RequestOptions{
		Timeout: 15 * time.Second, WithToken: true, CheckStatus: false,
	})
	if err != nil {
		s.writeUnavailable(w, r, err)
		return
	}
	status := http.StatusBadRequest
	if okVal, _ := res["ok"].(bool); okVal {
		status = http.StatusOK
	}
	s.writeJSON(w, r, status, res)
}

func (s *Server) handleAlertsMailRetry(w http.ResponseWriter, r *http.Request) {
	res, _, err := s.Pool.Alertd.PostJSON(r.Context(), "/api/v1/alerts/mail/retry", map[string]any{}, daemons.RequestOptions{
		Timeout: 15 * time.Second, WithToken: true, CheckStatus: false,
	})
	if err != nil {
		s.writeUnavailable(w, r, err)
		return
	}
	status := http.StatusBadRequest
	if okVal, _ := res["ok"].(bool); okVal {
		status = http.StatusOK
	}
	s.writeJSON(w, r, status, res)
}

func (s *Server) handleAlertsHistoryDelete(w http.ResponseWriter, r *http.Request) {
	if !isSuperadmin(r) {
		s.writeJSON(w, r, http.StatusForbidden, map[string]any{"ok": false, "error": "superadmin required"})
		return
	}
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	body := map[string]any{}
	if all, _ := payload["all"].(bool); all {
		body["all"] = true
	} else if ids, ok := payload["ids"].([]any); ok {
		if len(ids) > 1000 {
			ids = ids[:1000]
		}
		body["ids"] = ids
	}
	res, _, err := s.Pool.Alertd.PostJSON(r.Context(), "/api/v1/alerts/history/delete", body, daemons.RequestOptions{
		Timeout: 15 * time.Second, WithToken: true, CheckStatus: false,
	})
	if err != nil {
		s.writeUnavailable(w, r, err)
		return
	}
	status := http.StatusBadRequest
	if okVal, _ := res["ok"].(bool); okVal {
		status = http.StatusOK
	}
	s.writeJSON(w, r, status, res)
}

func (s *Server) handleAlertsTest(w http.ResponseWriter, r *http.Request) {
	if !isSuperadmin(r) {
		s.writeJSON(w, r, http.StatusForbidden, map[string]any{"ok": false, "error": "superadmin required"})
		return
	}
	res, _, err := s.Pool.Alertd.PostJSON(r.Context(), "/api/v1/alerts/test", map[string]any{}, daemons.RequestOptions{
		Timeout: 60 * time.Second, WithToken: true, CheckStatus: false,
	})
	if err != nil {
		s.writeUnavailable(w, r, err)
		return
	}
	status := http.StatusBadGateway
	if okVal, _ := res["ok"].(bool); okVal {
		status = http.StatusOK
	}
	s.writeJSON(w, r, status, res)
}

// ---------------------------------------------------------------------------
// Monitoring API (routes_monitoring.py)
// ---------------------------------------------------------------------------

func monitoringWindowQuery(r *http.Request) url.Values {
	q := url.Values{}
	rng := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("range")))
	if _, ok := monitoringRanges[rng]; !ok {
		rng = "24h"
	}
	q.Set("range", rng)
	if site := strings.TrimSpace(r.URL.Query().Get("site")); site != "" && !strings.EqualFold(site, "all") {
		q.Set("site", site)
	}
	since := strings.TrimSpace(r.URL.Query().Get("since"))
	until := strings.TrimSpace(r.URL.Query().Get("until"))
	if since != "" && until != "" {
		if sv, err1 := strconv.ParseInt(since, 10, 64); err1 == nil {
			if uv, err2 := strconv.ParseInt(until, 10, 64); err2 == nil && uv > sv {
				q.Set("since", strconv.FormatInt(sv, 10))
				q.Set("until", strconv.FormatInt(uv, 10))
			}
		}
	}
	return q
}

func (s *Server) handleMonitoringSites(w http.ResponseWriter, r *http.Request) {
	data, _, err := s.Pool.Metricsd.GetJSON(r.Context(), "/api/v1/metrics/sites", daemons.RequestOptions{
		Timeout: 10 * time.Second, CheckStatus: true,
	})
	if err != nil {
		s.writeUnavailable(w, r, err)
		return
	}
	rawSites, _ := data["sites"].([]any)
	sites := make([]map[string]string, 0, len(rawSites))
	for _, item := range rawSites {
		m, _ := item.(map[string]any)
		proxy := strings.TrimSpace(asString(m["proxy"]))
		if proxy == "" {
			continue
		}
		sites = append(sites, map[string]string{
			"proxy": proxy,
			"label": s.Runtime.DisplayName(proxy),
		})
	}
	sort.Slice(sites, func(i, j int) bool {
		return strings.ToLower(sites[i]["label"]) < strings.ToLower(sites[j]["label"])
	})
	s.writeJSON(w, r, http.StatusOK, map[string]any{"ok": true, "sites": sites})
}

func (s *Server) handleMonitoringSummary(w http.ResponseWriter, r *http.Request) {
	data, _, err := s.Pool.Metricsd.GetJSON(r.Context(), "/api/v1/metrics/summary", daemons.RequestOptions{
		Query: monitoringWindowQuery(r), Timeout: 15 * time.Second, CheckStatus: true,
	})
	if err != nil {
		s.writeUnavailable(w, r, err)
		return
	}
	s.writeJSON(w, r, http.StatusOK, data)
}

func (s *Server) handleMonitoringSeries(w http.ResponseWriter, r *http.Request) {
	chart := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("chart")))
	if _, ok := monitoringChartSet[chart]; !ok {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{
			"ok":        false,
			"error":     "unknown chart",
			"available": monitoringCharts,
		})
		return
	}
	q := monitoringWindowQuery(r)
	q.Set("chart", chart)
	comp := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("components")))
	if comp == "0" || comp == "false" || comp == "no" {
		q.Set("components", "0")
	} else {
		q.Set("components", "1")
	}
	data, _, err := s.Pool.Metricsd.GetJSON(r.Context(), "/api/v1/metrics/series", daemons.RequestOptions{
		Query: q, Timeout: 15 * time.Second, CheckStatus: true,
	})
	if err != nil {
		s.writeUnavailable(w, r, err)
		return
	}
	s.writeJSON(w, r, http.StatusOK, data)
}

func (s *Server) handleMonitoringStates(w http.ResponseWriter, r *http.Request) {
	data, _, err := s.Pool.Metricsd.GetJSON(r.Context(), "/api/v1/metrics/states", daemons.RequestOptions{
		Query: monitoringWindowQuery(r), Timeout: 15 * time.Second, CheckStatus: true,
	})
	if err != nil {
		s.writeUnavailable(w, r, err)
		return
	}
	s.writeJSON(w, r, http.StatusOK, data)
}

func (s *Server) handleMonitoringStorage(w http.ResponseWriter, r *http.Request) {
	data, _, err := s.Pool.Metricsd.GetJSON(r.Context(), "/api/v1/metrics/storage", daemons.RequestOptions{
		Timeout: 10 * time.Second, CheckStatus: true,
	})
	if err != nil {
		s.writeUnavailable(w, r, err)
		return
	}
	s.writeJSON(w, r, http.StatusOK, data)
}

func (s *Server) handleMonitoringServers(w http.ResponseWriter, r *http.Request) {
	q := monitoringWindowQuery(r)
	q.Del("site")
	data, _, err := s.Pool.Metricsd.GetJSON(r.Context(), "/api/v1/metrics/servers", daemons.RequestOptions{
		Query: q, Timeout: 15 * time.Second, CheckStatus: true,
	})
	if err != nil {
		s.writeUnavailable(w, r, err)
		return
	}
	s.writeJSON(w, r, http.StatusOK, data)
}

func (s *Server) handleMonitoringBackends(w http.ResponseWriter, r *http.Request) {
	q := monitoringWindowQuery(r)
	q.Del("site")
	data, _, err := s.Pool.Metricsd.GetJSON(r.Context(), "/api/v1/metrics/backends", daemons.RequestOptions{
		Query: q, Timeout: 15 * time.Second, CheckStatus: true,
	})
	if err != nil {
		s.writeUnavailable(w, r, err)
		return
	}
	s.writeJSON(w, r, http.StatusOK, data)
}

func (s *Server) handleMonitoringAttention(w http.ResponseWriter, r *http.Request) {
	data, _, err := s.Pool.Alertd.GetJSON(r.Context(), "/api/v1/alerts/portal", daemons.RequestOptions{
		Timeout: 5 * time.Second, CheckStatus: true,
	})
	if err != nil {
		s.writeJSON(w, r, http.StatusOK, map[string]any{"ok": true, "alerts": []any{}})
		return
	}
	s.writeJSON(w, r, http.StatusOK, data)
}

func (s *Server) handleMonitoringChannelLabels(w http.ResponseWriter, r *http.Request) {
	if !isSuperadmin(r) {
		s.writeJSON(w, r, http.StatusForbidden, map[string]any{"ok": false, "error": "superadmin required"})
		return
	}
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	body := map[string]any{"labels": payload["labels"]}
	if hidden, ok := payload["hidden"]; ok && hidden != nil {
		body["hidden"] = hidden
	}
	res, _, err := s.Pool.Metricsd.PostJSON(r.Context(), "/api/v1/metrics/channel-labels", body, daemons.RequestOptions{
		Timeout: 10 * time.Second, CheckStatus: true, RejectedStatus: 400,
	})
	if err != nil {
		var rej *daemons.RejectedError
		if errors.As(err, &rej) {
			s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": rej.Reason})
			return
		}
		s.writeUnavailable(w, r, err)
		return
	}
	s.writeJSON(w, r, http.StatusOK, res)
}

func (s *Server) handleMonitoringMonitors(w http.ResponseWriter, r *http.Request) {
	if !isSuperadmin(r) {
		s.writeJSON(w, r, http.StatusForbidden, map[string]any{"ok": false, "error": "superadmin required"})
		return
	}
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	res, _, err := s.Pool.Metricsd.PostJSON(r.Context(), "/api/v1/metrics/monitors", map[string]any{
		"monitors": payload["monitors"],
	}, daemons.RequestOptions{
		Timeout: 10 * time.Second, CheckStatus: true, RejectedStatus: 400,
	})
	if err != nil {
		var rej *daemons.RejectedError
		if errors.As(err, &rej) {
			s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": rej.Reason})
			return
		}
		s.writeUnavailable(w, r, err)
		return
	}
	s.writeJSON(w, r, http.StatusOK, res)
}

func (s *Server) handleLiveActivity(w http.ResponseWriter, r *http.Request) {
	data, status, err := s.Pool.Guardd.GetJSON(r.Context(), "/api/v1/guard/live", daemons.RequestOptions{
		Query: r.URL.Query(), Timeout: 15 * time.Second, CheckStatus: false,
	})
	if err != nil {
		s.writeUnavailable(w, r, err)
		return
	}
	if status == 0 {
		status = http.StatusOK
	}
	s.writeJSON(w, r, status, data)
}

func (s *Server) handleLiveDecisions(w http.ResponseWriter, r *http.Request) {
	data, _, err := s.Pool.Guardd.GetJSON(r.Context(), "/api/v1/guard/decisions/feed", daemons.RequestOptions{
		Query: r.URL.Query(), Timeout: 5 * time.Second, CheckStatus: true,
	})
	if err != nil {
		s.writeUnavailable(w, r, err)
		return
	}
	s.writeJSON(w, r, http.StatusOK, data)
}

// ---------------------------------------------------------------------------
// HAProxy Runtime Backends API (routes_runtime.py)
// ---------------------------------------------------------------------------

func (s *Server) handleHAProxyBackends(w http.ResponseWriter, r *http.Request) {
	if !isSuperadmin(r) {
		s.writeJSON(w, r, http.StatusForbidden, map[string]any{"ok": false, "error": "superadmin required"})
		return
	}
	backends, err := s.Runtime.ListBackends(r.Context())
	if err != nil {
		s.writeJSON(w, r, http.StatusBadGateway, map[string]any{"ok": false, "error": "Backend status could not be loaded"})
		return
	}
	s.writeJSON(w, r, http.StatusOK, map[string]any{"ok": true, "backends": backends})
}

func (s *Server) handleHAProxyBackendState(w http.ResponseWriter, r *http.Request) {
	if !isSuperadmin(r) {
		s.writeJSON(w, r, http.StatusForbidden, map[string]any{"ok": false, "error": "superadmin required"})
		return
	}
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	res, err := s.Runtime.SetState(r.Context(), asString(payload["backend"]), asString(payload["server"]), asString(payload["state"]))
	if err != nil {
		var ve *haproxy.ValidationError
		if errors.As(err, &ve) {
			s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": ve.Msg})
			return
		}
		s.writeJSON(w, r, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	s.writeJSON(w, r, http.StatusOK, res)
}

func (s *Server) handleHAProxyBackendWeight(w http.ResponseWriter, r *http.Request) {
	if !isSuperadmin(r) {
		s.writeJSON(w, r, http.StatusForbidden, map[string]any{"ok": false, "error": "superadmin required"})
		return
	}
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	weight, ok := parseWholeNumber(payload["weight"])
	if !ok {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "weight must be a whole number"})
		return
	}
	res, err := s.Runtime.SetWeight(r.Context(), asString(payload["backend"]), asString(payload["server"]), weight)
	if err != nil {
		var ve *haproxy.ValidationError
		if errors.As(err, &ve) {
			s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": ve.Msg})
			return
		}
		s.writeJSON(w, r, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	s.writeJSON(w, r, http.StatusOK, res)
}

// ---------------------------------------------------------------------------
// Adaptive Security / Guardd Proxy Helpers
// ---------------------------------------------------------------------------

func (s *Server) guarddGetProxy(upstreamPath string, timeout time.Duration, checkStatus bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, status, err := s.Pool.Guardd.GetJSON(r.Context(), upstreamPath, daemons.RequestOptions{
			Query: r.URL.Query(), Timeout: timeout, CheckStatus: checkStatus,
		})
		if err != nil {
			s.writeUnavailable(w, r, err)
			return
		}
		if status == 0 {
			status = http.StatusOK
		}
		s.writeJSON(w, r, status, data)
	}
}

func (s *Server) guarddSuperadminPostProxy(upstreamPath string, timeout time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isSuperadmin(r) {
			s.writeJSON(w, r, http.StatusForbidden, map[string]any{"ok": false, "error": "superadmin required"})
			return
		}
		payload, err := s.readJSONBody(r)
		if err != nil {
			s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		data, status, err := s.Pool.Guardd.PostJSON(r.Context(), upstreamPath, payload, daemons.RequestOptions{
			Timeout: timeout, WithToken: true, CheckStatus: false,
		})
		if err != nil {
			s.writeUnavailable(w, r, err)
			return
		}
		if status == 0 {
			status = http.StatusOK
		}
		s.writeJSON(w, r, status, data)
	}
}

// ListenAndServe starts the HTTP server with hardened timeouts and graceful shutdown.
func (s *Server) ListenAndServe(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.Cfg.ListenAddr,
		Handler:           s.handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	case err := <-errCh:
		return err
	}
}

// ---------------------------------------------------------------------------
// Small pure helpers
// ---------------------------------------------------------------------------

func asString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case fmt.Stringer:
		return x.String()
	default:
		return ""
	}
}

func parseIntDefault(raw string, fallback int) int {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return fallback
	}
	return n
}

func clampInt(raw string, fallback, lo, hi int) int {
	n := parseIntDefault(raw, fallback)
	if n < lo {
		return lo
	}
	if n > hi {
		return hi
	}
	return n
}

func truncStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}

func parseWholeNumber(v any) (int, bool) {
	switch x := v.(type) {
	case float64:
		if x != float64(int(x)) {
			return 0, false
		}
		return int(x), true
	case int:
		return x, true
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(x))
		if err != nil {
			return 0, false
		}
		return n, true
	default:
		return 0, false
	}
}
