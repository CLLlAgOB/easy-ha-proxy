package server

import (
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"easy-ha-proxy/panel/internal/audit"
	"easy-ha-proxy/panel/internal/daemons"
	"easy-ha-proxy/panel/internal/ui"
)

var auditRanges = map[string]int64{
	"1h":  3600,
	"24h": 86400,
	"7d":  7 * 86400,
	"30d": 30 * 86400,
	"90d": 90 * 86400,
	"all": 0,
}

func (s *Server) registerStageD3Routes(mux *http.ServeMux) {
	// Audit log API (routes_audit.py + ssh unblock history).
	mux.HandleFunc("GET /api/audit/events", s.handleAuditEvents)
	mux.HandleFunc("GET /api/audit/filters", s.handleAuditFilters)
	mux.HandleFunc("GET /api/audit/status", s.handleAuditStatus)
	mux.HandleFunc("GET /system/ssh-security/api/unblock-history", s.handleSSHUnblockHistory)

	// HAProxy configuration files, state, check, apply (routes_haproxy_config.py).
	mux.HandleFunc("GET /haproxy/config/state", s.handleConfigState)
	mux.HandleFunc("GET /haproxy/config/preview", s.handleConfigPreview)
	mux.HandleFunc("GET /haproxy/config/download/{kind}", s.handleConfigDownloadKind)
	mux.HandleFunc("GET /haproxy/config/download-cfg/{source}", s.handleConfigDownloadLive)
	mux.HandleFunc("POST /haproxy/config/check", s.handleConfigCheck)
	mux.HandleFunc("POST /haproxy/config/apply", s.handleConfigApply)
	mux.HandleFunc("POST /haproxy/config/vars/raw", s.handleConfigSaveRawKind("vars"))
	mux.HandleFunc("GET /api/haproxy/config/files/{kind}", s.handleConfigFileGet)
	mux.HandleFunc("POST /api/haproxy/config/files/{kind}", s.handleConfigFilePut)

	// HTML UI pages rendered by Go html/template.
	s.registerHTMLPages(mux)
}

func (s *Server) sourceIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		first, _, _ := strings.Cut(xff, ",")
		if clean := strings.TrimSpace(first); clean != "" {
			return clean
		}
	}
	return r.RemoteAddr
}

func (s *Server) recordAudit(r *http.Request, action, objType, objID, result, summary, detail string) {
	if s.Audit == nil {
		return
	}
	s.Audit.Record(remoteUser(r), s.sourceIP(r), action, objType, objID, result, summary, detail, nil, nil)
}

// ---------------------------------------------------------------------------
// Audit API
// ---------------------------------------------------------------------------

func (s *Server) handleAuditEvents(w http.ResponseWriter, r *http.Request) {
	rangeKey := strings.TrimSpace(r.URL.Query().Get("range"))
	window, ok := auditRanges[rangeKey]
	if !ok {
		rangeKey = "7d"
		window = auditRanges["7d"]
	}
	since := int64(0)
	if window > 0 {
		since = time.Now().Unix() - window
	}
	resFilter := strings.TrimSpace(r.URL.Query().Get("result"))
	if resFilter != "" && resFilter != audit.ResultSuccess && resFilter != audit.ResultFailure && resFilter != audit.ResultDenied {
		resFilter = ""
	}
	payload := s.Audit.Query(audit.QueryFilter{
		Actor:      truncStr(strings.TrimSpace(r.URL.Query().Get("actor")), 120),
		Action:     truncStr(strings.TrimSpace(r.URL.Query().Get("action")), 120),
		ObjectType: truncStr(strings.TrimSpace(r.URL.Query().Get("object_type")), 60),
		Result:     resFilter,
		Since:      since,
		Limit:      clampInt(r.URL.Query().Get("limit"), 100, 1, 500),
		Offset:     clampInt(r.URL.Query().Get("offset"), 0, 0, 1_000_000),
	})
	payload["ok"] = true
	payload["range"] = rangeKey
	s.writeJSON(w, r, http.StatusOK, payload)
}

func (s *Server) handleAuditFilters(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, r, http.StatusOK, map[string]any{
		"ok":           true,
		"actors":       s.Audit.Distinct("actor"),
		"actions":      s.Audit.Distinct("action"),
		"object_types": s.Audit.Distinct("object_type"),
		"results":      audit.Results,
	})
}

func (s *Server) handleAuditStatus(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, r, http.StatusOK, map[string]any{
		"ok":    true,
		"audit": s.Audit.Stats(),
	})
}

func (s *Server) handleSSHUnblockHistory(w http.ResponseWriter, r *http.Request) {
	history := s.Audit.Query(audit.QueryFilter{
		Action: "ssh.unban",
		Result: audit.ResultSuccess,
		Limit:  25,
	})
	rawEvents, _ := history["events"].([]audit.Event)
	out := make([]map[string]any, 0, len(rawEvents))
	for _, ev := range rawEvents {
		out = append(out, map[string]any{
			"ts":      ev.TS,
			"actor":   ev.Actor,
			"summary": ev.Summary,
		})
	}
	s.writeJSON(w, r, http.StatusOK, map[string]any{
		"ok":        true,
		"available": history["available"],
		"events":    out,
	})
}

// ---------------------------------------------------------------------------
// HAProxy Configuration Files & Guarded Check/Apply
// ---------------------------------------------------------------------------

func (s *Server) handleConfigState(w http.ResponseWriter, r *http.Request) {
	state := "clean"
	pending := false
	if tx, err := s.controldJSON(r.Context(), "config-transaction-status", nil, 5*time.Second); err == nil {
		if p, _ := tx["pending"].(bool); p {
			state = "pending_confirmation"
			pending = true
		}
	}
	s.writeJSON(w, r, http.StatusOK, map[string]any{
		"ok":      true,
		"state":   state,
		"pending": pending,
		"hashes":  s.CfgStore.SnapshotHashes(),
	})
}

func (s *Server) handleConfigPreview(w http.ResponseWriter, r *http.Request) {
	raw, err := s.CfgStore.ReadLiveHAProxyCfg()
	if err != nil {
		s.writeJSON(w, r, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	s.writeJSON(w, r, http.StatusOK, map[string]any{
		"ok":     true,
		"config": string(raw),
	})
}

func (s *Server) handleConfigDownloadKind(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	raw, filename, _, err := s.CfgStore.Read(kind)
	if err != nil {
		s.writeJSON(w, r, http.StatusNotFound, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func (s *Server) handleConfigDownloadLive(w http.ResponseWriter, r *http.Request) {
	source := strings.ToLower(strings.TrimSpace(r.PathValue("source")))
	if source != "live" && source != "current" {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "unsupported config source"})
		return
	}
	raw, err := s.CfgStore.ReadLiveHAProxyCfg()
	if err != nil {
		s.writeJSON(w, r, http.StatusNotFound, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="haproxy.cfg"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func (s *Server) handleConfigFileGet(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	raw, filename, hash, err := s.CfgStore.Read(kind)
	if err != nil {
		s.writeJSON(w, r, http.StatusNotFound, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	s.writeJSON(w, r, http.StatusOK, map[string]any{
		"ok":       true,
		"kind":     kind,
		"filename": filename,
		"sha256":   hash,
		"content":  string(raw),
	})
}

func (s *Server) handleConfigFilePut(w http.ResponseWriter, r *http.Request) {
	s.saveConfigKind(w, r, r.PathValue("kind"))
}

func (s *Server) handleConfigSaveRawKind(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.saveConfigKind(w, r, kind)
	}
}

func (s *Server) saveConfigKind(w http.ResponseWriter, r *http.Request, kind string) {
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	content := asString(payload["content"])
	if content == "" {
		content = asString(payload["raw"])
	}
	hash, err := s.CfgStore.Write(kind, []byte(content))
	if err != nil {
		s.recordAudit(r, "config.save", "config", kind, audit.ResultFailure, "", err.Error())
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	s.recordAudit(r, "config.save", "config", kind, audit.ResultSuccess, "sha256: "+hash[:12], "")
	s.writeJSON(w, r, http.StatusOK, map[string]any{
		"ok":     true,
		"kind":   kind,
		"sha256": hash,
	})
}

func (s *Server) handleConfigCheck(w http.ResponseWriter, r *http.Request) {
	payload, _ := s.readJSONBody(r)
	cfgText := asString(payload["config"])
	cmd := "check-config"
	if cfgText != "" {
		cmd = "check-config " + base64.StdEncoding.EncodeToString([]byte(cfgText))
	}
	reply, err := daemons.LineCommand(r.Context(), s.Pool.ControldPath, cmd, 30*time.Second, 2*1024*1024)
	if err != nil {
		s.writeUnavailable(w, r, err)
		return
	}
	ok := strings.HasPrefix(strings.TrimSpace(reply), "OK") || strings.Contains(reply, `"ok":true`)
	status := http.StatusOK
	if !ok {
		status = http.StatusBadRequest
	}
	s.writeJSON(w, r, status, map[string]any{
		"ok":     ok,
		"output": strings.TrimSpace(reply),
	})
}

func (s *Server) handleConfigApply(w http.ResponseWriter, r *http.Request) {
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	res, err := s.controldJSON(r.Context(), "begin-config-transaction", payload, 60*time.Second)
	if err != nil {
		s.recordAudit(r, "config.apply", "haproxy", "transaction", audit.ResultFailure, "", err.Error())
		s.writeUnavailable(w, r, err)
		return
	}
	okVal, _ := res["ok"].(bool)
	status := http.StatusBadRequest
	result := audit.ResultFailure
	if okVal {
		status = http.StatusOK
		result = audit.ResultSuccess
	}
	s.recordAudit(r, "config.apply", "haproxy", "transaction", result, asString(res["state"]), asString(res["error"]))
	s.writeJSON(w, r, status, res)
}

// ---------------------------------------------------------------------------
// HTML Admin Pages
// ---------------------------------------------------------------------------

func (s *Server) registerHTMLPages(mux *http.ServeMux) {
	pages := map[string]ui.PageSpec{
		"/":                           {PageID: "routes.index", Title: "Dashboard", HeaderTitle: "Dashboard", Description: "Live HAProxy bans, connections, whitelists, and backends.", APIEndpoint: "/api/tables", Scripts: []string{"js/dashboard.js"}},
		"/monitoring":                 {PageID: "routes.monitoring_page", Title: "Monitoring", HeaderTitle: "Monitoring", Description: "Historical traffic, latency, and host telemetry.", APIEndpoint: "/api/monitoring/summary", Scripts: []string{"js/monitoring_core.js", "js/monitoring.js"}},
		"/monitoring/live":            {PageID: "routes.live_activity_page", Title: "Live activity", HeaderTitle: "Live activity", Description: "Real-time traffic stream and ban decisions.", APIEndpoint: "/api/monitoring/live", Scripts: []string{"js/live_activity_core.js", "js/live_activity.js"}},
		"/system/health":              {PageID: "routes.system_health_page", Title: "System health", HeaderTitle: "System health", Description: "Host systemd services and Docker container health.", APIEndpoint: "/api/health/status", Scripts: []string{"js/health.js"}},
		"/system/alerts":              {PageID: "routes.alerts_page", Title: "Alerts", HeaderTitle: "Alerts", Description: "Active gateway alerts, rules, and notification channels.", APIEndpoint: "/api/alerts/state", Scripts: []string{"js/alerts.js"}},
		"/system/audit":               {PageID: "routes.audit_page", Title: "Audit log", HeaderTitle: "Audit log", Description: "Administrative change history.", APIEndpoint: "/api/audit/events", Scripts: []string{"js/audit.js"}},
		"/security/adaptive":          {PageID: "routes.adaptive_protection", Title: "Adaptive protection", HeaderTitle: "Adaptive protection", Description: "guardd mode, ban ladder, and reputation quality.", APIEndpoint: "/api/security/adaptive/health", Scripts: []string{"js/adaptive_core.js", "js/adaptive_protection.js"}},
		"/security/adaptive/bans":     {PageID: "routes.adaptive_bans", Title: "Adaptive bans", HeaderTitle: "Adaptive bans", Description: "Active and historical adaptive bans.", APIEndpoint: "/api/security/adaptive/bans", Scripts: []string{"js/adaptive_bans.js"}},
		"/security/detection-rules":   {PageID: "routes.detection_rules", Title: "Detection rules", HeaderTitle: "Detection rules", Description: "Scanner signatures, candidates, and trap hosts.", APIEndpoint: "/api/security/detection-rules", Scripts: []string{"js/detection_rules.js"}},
		"/security/requests":          {PageID: "routes.request_log", Title: "Request log", HeaderTitle: "Request log", Description: "Bounded HTTP request log search.", APIEndpoint: "/api/security/requests", Scripts: []string{"js/request_log_core.js", "js/request_log.js"}},
		"/haproxy/backends":           {PageID: "routes.haproxy_backends_page", Title: "HAProxy backends", HeaderTitle: "HAProxy backends", Description: "Runtime Ready / Drain / Maintenance and server weights.", APIEndpoint: "/api/haproxy/backends", Scripts: []string{"js/haproxy_backends.js"}},
		"/haproxy/sites":              {PageID: "routes.haproxy_sites", Title: "Sites", HeaderTitle: "Sites", Description: "HTTP/HTTPS site definitions (websites.yml).", APIEndpoint: "/api/haproxy/config/files/websites", Scripts: []string{"js/haproxy_sites.js"}},
		"/haproxy/tcp":                {PageID: "routes.haproxy_tcp", Title: "TCP forwards", HeaderTitle: "TCP forwards", Description: "TCP stream forwarding rules (tcp.yml).", APIEndpoint: "/api/haproxy/config/files/tcp", Scripts: []string{"js/haproxy_tcp.js"}},
		"/haproxy/udp":                {PageID: "routes.haproxy_udp", Title: "UDP forwards", HeaderTitle: "UDP forwards", Description: "UDP forwarding rules (udp.yml).", APIEndpoint: "/api/haproxy/config/files/udp"},
		"/haproxy/certs":              {PageID: "routes.haproxy_certs", Title: "Certificates", HeaderTitle: "Certificates", Description: "Let's Encrypt, Internal CA, and mTLS certificates.", APIEndpoint: "/api/haproxy/certs", Scripts: []string{"js/haproxy_certs.js"}},
		"/haproxy/certs/dns-providers": {PageID: "routes.dns_providers_page", Title: "DNS providers", HeaderTitle: "DNS providers", Description: "DNS-01 credential profiles managed by certd.", APIEndpoint: "/api/haproxy/dns-providers", Scripts: []string{"js/dns_providers.js"}},
		"/haproxy/certs/delivery":     {PageID: "routes.cert_delivery_page", Title: "Certificate delivery", HeaderTitle: "Certificate delivery", Description: "Automated SFTP/SCP delivery of renewed certificates.", APIEndpoint: "/api/haproxy/cert-delivery", Scripts: []string{"js/cert_delivery.js"}},
		"/haproxy/geoip":              {PageID: "routes.haproxy_geoip_page", Title: "GeoIP", HeaderTitle: "GeoIP", Description: "Local DB-IP country database and filter schedule.", APIEndpoint: "/haproxy/geoip/status", Scripts: []string{"js/geoip.js"}},
		"/haproxy/config":             {PageID: "routes.haproxy_config_page", Title: "HAProxy configuration", HeaderTitle: "HAProxy configuration", Description: "Inspect, check, and transactionally apply HAProxy configuration.", APIEndpoint: "/haproxy/config/state", Scripts: []string{"js/haproxy_config.js"}},
		"/haproxy/config/history":     {PageID: "routes.config_history_page", Title: "Configuration history", HeaderTitle: "Configuration history", Description: "Compare and restore confirmed HAProxy configuration versions.", APIEndpoint: "/api/haproxy/config/versions", Scripts: []string{"js/config_history.js"}},
		"/haproxy/trash":              {PageID: "routes.trash_page", Title: "Trash", HeaderTitle: "Trash", Description: "Recently removed sites and certificates.", APIEndpoint: "/api/haproxy/trash", Scripts: []string{"js/trash.js"}},
		"/authelia/users":             {PageID: "routes.authelia_users", Title: "Authelia users", HeaderTitle: "Authelia users", Description: "User accounts and superadmin roles.", APIEndpoint: "/authelia/api/users", Scripts: []string{"js/authelia_users.js"}},
		"/authelia/bans":              {PageID: "routes.authelia_bans", Title: "Authelia bans", HeaderTitle: "Authelia bans", Description: "Brute-force lockouts managed by authelia-bansd.", APIEndpoint: "/authelia/api/bans", Scripts: []string{"js/authelia_bans.js"}},
		"/authelia/settings/":         {PageID: "authelia_settings.page", Title: "Authelia settings", HeaderTitle: "Authelia settings", Description: "Authentication policy and mail relay settings.", APIEndpoint: "/authelia/settings/notifications/latest", Scripts: []string{"js/authelia_settings.js"}},
		"/system/backups/":            {PageID: "system_backups.page", Title: "System backups", HeaderTitle: "System backups", Description: "Encrypted full backups, off-host destinations, and schedules.", APIEndpoint: "/system/backups/api/status", Scripts: []string{"js/system_backups.js"}},
		"/system/updates/":            {PageID: "system_updates.page", Title: "System updates", HeaderTitle: "System updates", Description: "easy-ha-proxy software updates and HAProxy upgrades.", APIEndpoint: "/system/updates/api/status", Scripts: []string{"js/updates_core.js", "js/system_updates.js"}},
		"/system/os-security/":        {PageID: "os_security.page", Title: "OS security", HeaderTitle: "OS security", Description: "Distribution security updates and reboot policy.", APIEndpoint: "/system/os-security/api/status", Scripts: []string{"js/os_security.js"}},
		"/system/ssh-security/":       {PageID: "ssh_security.page", Title: "SSH security", HeaderTitle: "SSH security", Description: "SSH intrusion protection and ban management.", APIEndpoint: "/system/ssh-security/api/status", Scripts: []string{"js/ssh_security.js"}},
		"/system/schedule/":           {PageID: "schedule.page", Title: "Schedule", HeaderTitle: "Schedule", Description: "Unified maintenance, backup, and GeoIP schedule.", APIEndpoint: "/system/backups/api/schedule", Scripts: []string{"js/schedule_core.js", "js/system_schedule.js"}},
	}

	for routePath, spec := range pages {
		localSpec := spec
		if routePath == "/" {
			mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
				s.UI.Render(w, r, localSpec)
			})
			continue
		}
		mux.HandleFunc("GET "+routePath, func(w http.ResponseWriter, r *http.Request) {
			s.UI.Render(w, r, localSpec)
		})
	}
}
