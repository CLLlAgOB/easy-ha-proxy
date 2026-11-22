package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"easy-ha-proxy/panel/internal/daemons"
)

var isoCountryRe = regexp.MustCompile(`^[A-Z]{2}$`)

var validGeoIPSchedules = map[string]struct{}{
	"daily":   {},
	"weekly":  {},
	"monthly": {},
}

func (s *Server) registerConfigAndGeoIPRoutes(mux *http.ServeMux) {
	// Config versions & history (routes_config_history.py).
	mux.HandleFunc("GET /api/haproxy/config/versions", s.handleConfigVersions)
	mux.HandleFunc("GET /api/haproxy/config/versions/diff", s.handleConfigVersionDiff)
	mux.HandleFunc("POST /api/haproxy/config/versions/restore", s.handleConfigVersionRestore)

	// Guarded HAProxy config transactions (routes_haproxy_config.py).
	mux.HandleFunc("GET /haproxy/config/apply-status", s.handleConfigApplyStatus)
	mux.HandleFunc("POST /haproxy/config/confirm", s.handleConfigConfirm)
	mux.HandleFunc("POST /haproxy/config/rollback-pending", s.handleConfigRollbackPending)

	// Local GeoIP management (routes_geoip.py).
	mux.HandleFunc("GET /haproxy/geoip/status", s.handleGeoIPStatus)
	mux.HandleFunc("POST /haproxy/geoip/update", s.handleGeoIPUpdate)
	mux.HandleFunc("POST /haproxy/geoip/countries", s.handleGeoIPCountries)
	mux.HandleFunc("POST /haproxy/geoip/schedule", s.handleGeoIPSchedule)
}

func (s *Server) controldJSON(ctx context.Context, command string, payload map[string]any, timeout time.Duration) (map[string]any, error) {
	if s.Pool.ControldPath == "" {
		return nil, fmt.Errorf("haproxy-controld socket is not configured")
	}
	line := command
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		line = command + " " + base64.StdEncoding.EncodeToString(raw)
	}
	reply, err := daemons.LineCommand(ctx, s.Pool.ControldPath, line, timeout, 4*1024*1024)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(reply)
	if trimmed == "" {
		return nil, fmt.Errorf("haproxy-controld returned empty response")
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil {
		return nil, fmt.Errorf("haproxy-controld returned invalid JSON: %w", err)
	}
	return parsed, nil
}

func (s *Server) handleConfigVersions(w http.ResponseWriter, r *http.Request) {
	if !isSuperadmin(r) {
		s.writeJSON(w, r, http.StatusForbidden, map[string]any{"ok": false, "error": "superadmin required"})
		return
	}
	limit := clampInt(r.URL.Query().Get("limit"), 50, 1, 200)
	res, err := s.controldJSON(r.Context(), "config-versions "+strconv.Itoa(limit), nil, 15*time.Second)
	if err != nil {
		s.writeUnavailable(w, r, err)
		return
	}
	res["ok"] = true
	s.writeJSON(w, r, http.StatusOK, res)
}

func (s *Server) handleConfigVersionDiff(w http.ResponseWriter, r *http.Request) {
	if !isSuperadmin(r) {
		s.writeJSON(w, r, http.StatusForbidden, map[string]any{"ok": false, "error": "superadmin required"})
		return
	}
	left := strings.TrimSpace(r.URL.Query().Get("left"))
	right := strings.TrimSpace(r.URL.Query().Get("right"))
	if left == "" {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "left version is required"})
		return
	}
	if right == "" {
		right = "applied"
	}
	res, err := s.controldJSON(r.Context(), "config-version-diff", map[string]any{"left": left, "right": right}, 15*time.Second)
	if err != nil {
		s.writeUnavailable(w, r, err)
		return
	}
	status := http.StatusOK
	if okVal, exists := res["ok"].(bool); exists && !okVal {
		status = http.StatusBadRequest
	}
	s.writeJSON(w, r, status, res)
}

func (s *Server) handleConfigVersionRestore(w http.ResponseWriter, r *http.Request) {
	if !isSuperadmin(r) {
		s.writeJSON(w, r, http.StatusForbidden, map[string]any{"ok": false, "error": "superadmin required"})
		return
	}
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	versionID := strings.TrimSpace(asString(payload["version"]))
	if versionID == "" {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "version is required"})
		return
	}
	res, err := s.controldJSON(r.Context(), "restore-config-version", map[string]any{"version": versionID}, 60*time.Second)
	if err != nil {
		s.writeUnavailable(w, r, err)
		return
	}
	status := http.StatusOK
	if okVal, exists := res["ok"].(bool); exists && !okVal {
		status = http.StatusBadRequest
	}
	s.writeJSON(w, r, status, res)
}

func (s *Server) handleConfigApplyStatus(w http.ResponseWriter, r *http.Request) {
	if !isSuperadmin(r) {
		s.writeJSON(w, r, http.StatusForbidden, map[string]any{"ok": false, "error": "superadmin required"})
		return
	}
	res, err := s.controldJSON(r.Context(), "config-transaction-status", nil, 15*time.Second)
	if err != nil {
		s.writeUnavailable(w, r, err)
		return
	}
	s.writeJSON(w, r, http.StatusOK, res)
}

func (s *Server) handleConfigConfirm(w http.ResponseWriter, r *http.Request) {
	if !isSuperadmin(r) {
		s.writeJSON(w, r, http.StatusForbidden, map[string]any{"ok": false, "error": "superadmin required"})
		return
	}
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	token := strings.TrimSpace(asString(payload["token"]))
	if token == "" {
		token = strings.TrimSpace(r.FormValue("token"))
	}
	cmd := "confirm-config-transaction"
	if token != "" {
		cmd += " " + token
	}
	res, err := s.controldJSON(r.Context(), cmd, nil, 30*time.Second)
	if err != nil {
		s.writeUnavailable(w, r, err)
		return
	}
	status := http.StatusOK
	if okVal, exists := res["ok"].(bool); exists && !okVal {
		status = http.StatusBadRequest
	}
	s.writeJSON(w, r, status, res)
}

func (s *Server) handleConfigRollbackPending(w http.ResponseWriter, r *http.Request) {
	if !isSuperadmin(r) {
		s.writeJSON(w, r, http.StatusForbidden, map[string]any{"ok": false, "error": "superadmin required"})
		return
	}
	res, err := s.controldJSON(r.Context(), "rollback-config-transaction", nil, 30*time.Second)
	if err != nil {
		s.writeUnavailable(w, r, err)
		return
	}
	status := http.StatusOK
	if okVal, exists := res["ok"].(bool); exists && !okVal {
		status = http.StatusBadRequest
	}
	s.writeJSON(w, r, status, res)
}

func (s *Server) writeGeoIPResult(w http.ResponseWriter, r *http.Request, res map[string]any) {
	if okVal, _ := res["ok"].(bool); okVal {
		s.writeJSON(w, r, http.StatusOK, res)
		return
	}
	if conflict, _ := res["conflict"].(bool); conflict {
		s.writeJSON(w, r, http.StatusConflict, res)
		return
	}
	if valErr, _ := res["validation_error"].(bool); valErr {
		s.writeJSON(w, r, http.StatusBadRequest, res)
		return
	}
	s.writeJSON(w, r, http.StatusBadGateway, res)
}

func (s *Server) handleGeoIPStatus(w http.ResponseWriter, r *http.Request) {
	res, err := s.controldJSON(r.Context(), "geoip-status", nil, 60*time.Second)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	s.writeGeoIPResult(w, r, res)
}

func (s *Server) handleGeoIPUpdate(w http.ResponseWriter, r *http.Request) {
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	for k := range payload {
		if k != "force" {
			s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid request fields"})
			return
		}
	}
	force, _ := payload["force"].(bool)
	res, err := s.controldJSON(r.Context(), "geoip-update", map[string]any{"force": force}, 360*time.Second)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	s.writeGeoIPResult(w, r, res)
}

func (s *Server) handleGeoIPCountries(w http.ResponseWriter, r *http.Request) {
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if len(payload) != 2 {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "countries and revision are required"})
		return
	}
	rawCountries, hasC := payload["countries"].([]any)
	rev, hasR := payload["revision"]
	if !hasC || !hasR {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "countries and revision are required"})
		return
	}
	if len(rawCountries) > 249 {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "at most 249 countries can be selected"})
		return
	}
	seen := make(map[string]struct{}, len(rawCountries))
	countries := make([]string, 0, len(rawCountries))
	for _, item := range rawCountries {
		code := strings.ToUpper(strings.TrimSpace(asString(item)))
		if !isoCountryRe.MatchString(code) {
			s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid ISO country code"})
			return
		}
		if _, dup := seen[code]; !dup {
			seen[code] = struct{}{}
			countries = append(countries, code)
		}
	}
	sort.Strings(countries)

	res, err := s.controldJSON(r.Context(), "geoip-countries", map[string]any{
		"countries": countries,
		"revision":  rev,
	}, 360*time.Second)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	s.writeGeoIPResult(w, r, res)
}

func (s *Server) handleGeoIPSchedule(w http.ResponseWriter, r *http.Request) {
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if len(payload) != 1 {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "schedule is required"})
		return
	}
	sched := strings.ToLower(strings.TrimSpace(asString(payload["schedule"])))
	if _, ok := validGeoIPSchedules[sched]; !ok {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "schedule must be one of: daily, weekly, monthly"})
		return
	}
	res, err := s.controldJSON(r.Context(), "geoip-schedule", map[string]any{"schedule": sched}, 60*time.Second)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	s.writeGeoIPResult(w, r, res)
}
