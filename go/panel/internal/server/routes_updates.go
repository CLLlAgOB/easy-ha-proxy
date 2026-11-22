package server

import (
	"net/http"
	"regexp"
	"strings"
	"time"
)

var (
	bootIDRe       = regexp.MustCompile(`^[0-9a-fA-F-]{8,64}$`)
	autoCheckHours = map[int]struct{}{0: {}, 6: {}, 12: {}, 24: {}, 72: {}, 168: {}}
	osSecModes     = map[string]struct{}{"system": {}, "notify": {}, "auto": {}, "window": {}, "daily": {}}
	osSecIntervals = map[int]struct{}{1: {}, 2: {}, 4: {}, 6: {}, 12: {}, 24: {}}
	sshSecOps      = map[string]struct{}{"install": {}, "enable": {}, "disable": {}}
)

func (s *Server) registerUpdateAndSecurityRoutes(mux *http.ServeMux) {
	// System updates (routes_updates.py).
	mux.HandleFunc("GET /system/updates/api/status", s.handleUpdatesStatus)
	mux.HandleFunc("POST /system/updates/api/check", s.handleUpdatesCheck)
	mux.HandleFunc("POST /system/updates/api/channels", s.handleUpdatesChannels)
	mux.HandleFunc("POST /system/updates/api/settings", s.handleUpdatesSettings)
	mux.HandleFunc("POST /system/updates/api/auto-install", s.handleUpdatesAutoInstall)
	mux.HandleFunc("POST /system/updates/api/apply", s.handleUpdatesApply)
	mux.HandleFunc("POST /system/updates/api/haproxy/migration/start", s.handleHAProxyMigrationStart)
	mux.HandleFunc("POST /system/updates/api/haproxy/migration/prepare", s.handleHAProxyMigrationPrepare)
	mux.HandleFunc("POST /system/updates/api/haproxy/migration/apply", s.handleHAProxyMigrationApply)
	mux.HandleFunc("POST /system/updates/api/reboot", s.handleSystemReboot)
	mux.HandleFunc("POST /system/updates/api/reboot/cancel", s.handleSystemRebootCancel)

	// OS security updates (routes_os_security.py).
	mux.HandleFunc("GET /system/os-security/api/status", s.handleOSSecStatus)
	mux.HandleFunc("POST /system/os-security/api/check", s.handleOSSecCheck)
	mux.HandleFunc("POST /system/os-security/api/policy", s.handleOSSecPolicy)
	mux.HandleFunc("POST /system/os-security/api/install", s.handleOSSecInstall)
	mux.HandleFunc("POST /system/os-security/api/automatic-reboot", s.handleOSSecAutoReboot)
	mux.HandleFunc("POST /system/os-security/api/restart-policy", s.handleOSSecRestartPolicy)
	mux.HandleFunc("POST /system/os-security/api/restart-check", s.handleOSSecRestartCheck)
	mux.HandleFunc("POST /system/os-security/api/restart", s.handleOSSecRestart)

	// SSH security (routes_ssh_security.py).
	mux.HandleFunc("GET /system/ssh-security/api/status", s.handleSSHSecStatus)
	mux.HandleFunc("POST /system/ssh-security/api/connection", s.handleSSHSecConnection)
	mux.HandleFunc("POST /system/ssh-security/api/monitoring", s.handleSSHSecMonitoring)
	mux.HandleFunc("POST /system/ssh-security/api/protection", s.handleSSHSecProtection)
	mux.HandleFunc("POST /system/ssh-security/api/unban", s.handleSSHSecUnban)
}

func (s *Server) callUpdated(w http.ResponseWriter, r *http.Request, payload map[string]any, timeout time.Duration, accepted bool) {
	res, err := s.Pool.Updated.Call(r.Context(), payload, timeout)
	if err != nil {
		s.writeUnavailable(w, r, err)
		return
	}
	okVal, _ := res["ok"].(bool)
	status := http.StatusOK
	if okVal {
		if accepted {
			status = http.StatusAccepted
		}
	} else {
		status = http.StatusBadRequest
		if busy, _ := res["busy"].(bool); busy {
			status = http.StatusConflict
		}
	}
	s.writeJSON(w, r, status, res)
}

func validBootID(raw any) (string, bool) {
	s := strings.TrimSpace(asString(raw))
	return s, bootIDRe.MatchString(s)
}

// ---------------------------------------------------------------------------
// System Updates
// ---------------------------------------------------------------------------

func (s *Server) handleUpdatesStatus(w http.ResponseWriter, r *http.Request) {
	cmd := map[string]any{"action": "status"}
	if raw := strings.TrimSpace(r.URL.Query().Get("job_id")); raw != "" {
		id, ok := validIdentifier(raw)
		if !ok {
			s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid job id"})
			return
		}
		cmd["job_id"] = id
	}
	s.callUpdated(w, r, cmd, 15*time.Second, false)
}

func (s *Server) handleUpdatesCheck(w http.ResponseWriter, r *http.Request) {
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	cmd := map[string]any{"action": "start_check"}
	for _, k := range []string{"release_channel", "image_channel", "source_channel"} {
		if v, ok := payload[k]; ok {
			cmd[k] = asString(v)
		}
	}
	s.callUpdated(w, r, cmd, 15*time.Second, true)
}

func (s *Server) handleUpdatesChannels(w http.ResponseWriter, r *http.Request) {
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	cmd := map[string]any{"action": "set_channels"}
	for _, k := range []string{"release_channel", "image_channel", "source_channel"} {
		if v, ok := payload[k]; ok {
			cmd[k] = asString(v)
		}
	}
	if len(cmd) == 1 {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "select a channel to persist"})
		return
	}
	s.callUpdated(w, r, cmd, 15*time.Second, false)
}

func (s *Server) handleUpdatesSettings(w http.ResponseWriter, r *http.Request) {
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	hours, ok := parseWholeNumber(payload["auto_check_hours"])
	if !ok {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "choose one of the offered check intervals"})
		return
	}
	if _, allowed := autoCheckHours[hours]; !allowed {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "choose one of the offered check intervals"})
		return
	}
	s.callUpdated(w, r, map[string]any{"action": "set_settings", "auto_check_hours": hours}, 15*time.Second, false)
}

func (s *Server) handleUpdatesAutoInstall(w http.ResponseWriter, r *http.Request) {
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	enabled, okE := payload["enabled"].(bool)
	start, okS := parseWholeNumber(payload["start"])
	end, okEnd := parseWholeNumber(payload["end"])
	if !okE {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "enabled must be true or false"})
		return
	}
	if !okS || !okEnd || start < 0 || start > 23 || end < 0 || end > 23 {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "the window is given in whole hours, 0 to 23"})
		return
	}
	if start == end {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "the window must not start and end at the same hour"})
		return
	}
	cmd := map[string]any{
		"action":  "set_auto_install",
		"enabled": enabled,
		"start":   start,
		"end":     end,
	}
	for _, k := range []string{"os", "unified", "runtime"} {
		if v, exists := payload[k]; exists {
			b, ok := v.(bool)
			if !ok {
				s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "enabled must be true or false"})
				return
			}
			cmd[k] = b
		}
	}
	s.callUpdated(w, r, cmd, 15*time.Second, false)
}

func (s *Server) handleUpdatesApply(w http.ResponseWriter, r *http.Request) {
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if asString(payload["confirmation"]) != "UPDATE" {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "type UPDATE to confirm software updates"})
		return
	}
	planID, ok := validIdentifier(asString(payload["plan_id"]))
	if !ok {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid plan id"})
		return
	}
	comps, ok := payload["components"].([]any)
	if !ok || len(comps) == 0 {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "components must be a non-empty list"})
		return
	}
	s.callUpdated(w, r, map[string]any{
		"action":       "start_apply",
		"plan_id":      planID,
		"components":   comps,
		"confirmation": "UPDATE",
	}, 15*time.Second, true)
}

func (s *Server) handleHAProxyMigrationStart(w http.ResponseWriter, r *http.Request) {
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	confirmed, _ := payload["confirmed"].(bool)
	if asString(payload["target_branch"]) != "3.4" || !confirmed {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "Confirm the transition to HAProxy 3.4 LTS"})
		return
	}
	s.callUpdated(w, r, map[string]any{
		"action":        "start_haproxy_transition",
		"target_branch": "3.4",
		"confirmed":     true,
	}, 15*time.Second, true)
}

func (s *Server) handleHAProxyMigrationPrepare(w http.ResponseWriter, r *http.Request) {
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if asString(payload["target_branch"]) != "3.4" {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "Only the qualified HAProxy 3.4 LTS migration is supported"})
		return
	}
	s.callUpdated(w, r, map[string]any{
		"action":        "prepare_haproxy_migration",
		"target_branch": "3.4",
	}, 15*time.Second, true)
}

func (s *Server) handleHAProxyMigrationApply(w http.ResponseWriter, r *http.Request) {
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if asString(payload["confirmation"]) != "MIGRATE 3.4" {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "Type MIGRATE 3.4 to confirm the HAProxy transition"})
		return
	}
	planID, ok := validIdentifier(asString(payload["plan_id"]))
	if !ok {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid migration plan id"})
		return
	}
	s.callUpdated(w, r, map[string]any{
		"action":       "apply_haproxy_migration",
		"plan_id":      planID,
		"confirmation": "MIGRATE 3.4",
	}, 15*time.Second, true)
}

func (s *Server) handleSystemReboot(w http.ResponseWriter, r *http.Request) {
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if asString(payload["confirmation"]) != "REBOOT" {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "type REBOOT to confirm the server reboot"})
		return
	}
	bootID, ok := validBootID(payload["expected_boot_id"])
	if !ok {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid boot id"})
		return
	}
	s.callUpdated(w, r, map[string]any{
		"action":           "reboot",
		"confirmation":     "REBOOT",
		"expected_boot_id": bootID,
		"actor":            remoteUser(r),
	}, 15*time.Second, false)
}

func (s *Server) handleSystemRebootCancel(w http.ResponseWriter, r *http.Request) {
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	bootID, ok := validBootID(payload["expected_boot_id"])
	if !ok {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid boot id"})
		return
	}
	s.callUpdated(w, r, map[string]any{
		"action":           "cancel_reboot",
		"expected_boot_id": bootID,
		"actor":            remoteUser(r),
	}, 15*time.Second, false)
}

// ---------------------------------------------------------------------------
// OS Security Updates (routes_os_security.py)
// ---------------------------------------------------------------------------

func (s *Server) handleOSSecStatus(w http.ResponseWriter, r *http.Request) {
	cmd := map[string]any{"action": "os_security_status"}
	if raw := strings.TrimSpace(r.URL.Query().Get("job_id")); raw != "" {
		id, ok := validIdentifier(raw)
		if !ok {
			s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid job id"})
			return
		}
		cmd["job_id"] = id
	}
	s.callUpdated(w, r, cmd, 15*time.Second, false)
}

func (s *Server) handleOSSecCheck(w http.ResponseWriter, r *http.Request) {
	s.callUpdated(w, r, map[string]any{"action": "os_security_check"}, 15*time.Second, true)
}

func (s *Server) handleOSSecPolicy(w http.ResponseWriter, r *http.Request) {
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	mode := asString(payload["mode"])
	interval, okI := parseWholeNumber(payload["interval"])
	start, okS := parseWholeNumber(payload["start"])
	end, okE := parseWholeNumber(payload["end"])
	_, validMode := osSecModes[mode]
	_, validInt := osSecIntervals[interval]
	if !validMode || !okI || !validInt || !okS || !okE || start < 0 || start > 23 || end < 0 || end > 23 || start == end || asString(payload["confirmation"]) != "SECURITY" {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "Invalid OS security policy or confirmation"})
		return
	}
	s.callUpdated(w, r, map[string]any{
		"action":       "os_security_configure",
		"mode":         mode,
		"interval":     interval,
		"start":        start,
		"end":          end,
		"confirmation": "SECURITY",
	}, 15*time.Second, true)
}

func (s *Server) handleOSSecInstall(w http.ResponseWriter, r *http.Request) {
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if asString(payload["confirmation"]) != "SECURITY" {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "Type SECURITY to confirm OS security management"})
		return
	}
	s.callUpdated(w, r, map[string]any{"action": "os_security_install", "confirmation": "SECURITY"}, 15*time.Second, true)
}

func (s *Server) handleOSSecAutoReboot(w http.ResponseWriter, r *http.Request) {
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	enabled, okE := payload["enabled"].(bool)
	tStr := asString(payload["time"])
	bootID, okB := validBootID(payload["expected_boot_id"])
	if !okE || !hhmmRe.MatchString(tStr) || asString(payload["confirmation"]) != "REBOOT" || !okB {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "Confirm a valid automatic reboot policy"})
		return
	}
	cmd := map[string]any{
		"action":           "set_auto_reboot",
		"enabled":          enabled,
		"time":             tStr,
		"confirmation":     "REBOOT",
		"expected_boot_id": bootID,
		"actor":            remoteUser(r),
	}
	if v, exists := payload["allow_service_reboot"]; exists {
		b, ok := v.(bool)
		if !ok {
			s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "Confirm a valid automatic reboot policy"})
			return
		}
		cmd["allow_service_reboot"] = b
	}
	s.callUpdated(w, r, cmd, 15*time.Second, false)
}

func (s *Server) handleOSSecRestartPolicy(w http.ResponseWriter, r *http.Request) {
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	enabled, okE := payload["enabled"].(bool)
	tStr := asString(payload["time"])
	bootID, okB := validBootID(payload["expected_boot_id"])
	if !okE || !hhmmRe.MatchString(tStr) || asString(payload["confirmation"]) != "SECURITY" || !okB {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "Confirm a valid service restart policy"})
		return
	}
	s.callUpdated(w, r, map[string]any{
		"action":           "set_service_restarts",
		"enabled":          enabled,
		"time":             tStr,
		"confirmation":     "SECURITY",
		"expected_boot_id": bootID,
		"actor":            remoteUser(r),
	}, 15*time.Second, false)
}

func (s *Server) handleOSSecRestartCheck(w http.ResponseWriter, r *http.Request) {
	s.callUpdated(w, r, map[string]any{"action": "os_security_restart_check"}, 15*time.Second, true)
}

func (s *Server) handleOSSecRestart(w http.ResponseWriter, r *http.Request) {
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if asString(payload["confirmation"]) != "SECURITY" {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "Confirm service restarts"})
		return
	}
	s.callUpdated(w, r, map[string]any{"action": "os_security_restart", "confirmation": "SECURITY"}, 15*time.Second, true)
}

// ---------------------------------------------------------------------------
// SSH Security (routes_ssh_security.py)
// ---------------------------------------------------------------------------

func (s *Server) handleSSHSecStatus(w http.ResponseWriter, r *http.Request) {
	cmd := map[string]any{"action": "ssh_protection_status"}
	if raw := strings.TrimSpace(r.URL.Query().Get("job_id")); raw != "" {
		id, ok := validIdentifier(raw)
		if !ok {
			s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid job id"})
			return
		}
		cmd["job_id"] = id
	}
	s.callUpdated(w, r, cmd, 15*time.Second, false)
}

func (s *Server) handleSSHSecConnection(w http.ResponseWriter, r *http.Request) {
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	cmd := map[string]any{
		"action": "ssh_protection_connection",
		"user":   asString(payload["user"]),
		"ip":     asString(payload["ip"]),
	}
	for _, k := range []string{"hostname", "local_address", "port"} {
		if v, exists := payload[k]; exists {
			cmd[k] = v
		}
	}
	s.callUpdated(w, r, cmd, 15*time.Second, false)
}

func (s *Server) handleSSHSecMonitoring(w http.ResponseWriter, r *http.Request) {
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	enabled, ok := payload["enabled"].(bool)
	if !ok {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "Invalid SSH monitoring setting"})
		return
	}
	s.callUpdated(w, r, map[string]any{"action": "ssh_protection_monitor", "enabled": enabled}, 15*time.Second, false)
}

func (s *Server) handleSSHSecProtection(w http.ResponseWriter, r *http.Request) {
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	op := asString(payload["operation"])
	trusted, okT := payload["trusted"].([]any)
	if _, okOp := sshSecOps[op]; !okOp || !okT {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "Invalid SSH protection operation"})
		return
	}
	cmd := map[string]any{
		"action":    "ssh_protection_configure",
		"operation": op,
		"trusted":   trusted,
	}
	if policy, exists := payload["policy"]; exists {
		cmd["policy"] = policy
	}
	s.callUpdated(w, r, cmd, 15*time.Second, true)
}

func (s *Server) handleSSHSecUnban(w http.ResponseWriter, r *http.Request) {
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	ip := strings.TrimSpace(asString(payload["ip"]))
	if ip == "" {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "ip is required"})
		return
	}
	s.callUpdated(w, r, map[string]any{"action": "ssh_protection_unban", "ip": ip}, 15*time.Second, false)
}
