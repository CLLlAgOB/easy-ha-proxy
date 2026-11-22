package server

import (
	"net/http"
	"strings"
	"time"
)

func (s *Server) registerAutheliaRoutes(mux *http.ServeMux) {
	// Authelia usersd JSON API.
	mux.HandleFunc("GET /authelia/api/users", s.handleAutheliaUsersList)
	mux.HandleFunc("POST /authelia/api/users", s.handleAutheliaUserSave)
	mux.HandleFunc("POST /authelia/api/users/{username}/delete", s.handleAutheliaUserDelete)

	// Authelia bansd JSON API.
	mux.HandleFunc("GET /authelia/api/bans", s.handleAutheliaBansList)
	mux.HandleFunc("POST /authelia/api/bans/unban", s.handleAutheliaBansUnban)

	// Authelia settings/notifications (routes_authelia_settings.py).
	mux.HandleFunc("GET /authelia/settings/notifications/latest", s.handleAutheliaNotifLatest)
	mux.HandleFunc("POST /authelia/settings/notifications/latest/reveal", s.handleAutheliaNotifReveal)
	mux.HandleFunc("POST /authelia/settings/notifications/latest/handled", s.handleAutheliaNotifHandled)
}

func (s *Server) handleAutheliaUsersList(w http.ResponseWriter, r *http.Request) {
	res, err := s.Pool.AutheliaUsers.Call(r.Context(), map[string]any{"action": "list"}, 10*time.Second)
	if err != nil {
		s.writeUnavailable(w, r, err)
		return
	}
	s.writeJSON(w, r, http.StatusOK, res)
}

func (s *Server) handleAutheliaUserSave(w http.ResponseWriter, r *http.Request) {
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	action := strings.TrimSpace(asString(payload["action"]))
	if action == "" {
		action = "upsert"
	}
	if action != "create" && action != "update" && action != "upsert" {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "unsupported user action"})
		return
	}
	payload["action"] = action
	res, err := s.Pool.AutheliaUsers.Call(r.Context(), payload, 15*time.Second)
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

func (s *Server) handleAutheliaUserDelete(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.PathValue("username"))
	if username == "" {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "username is required"})
		return
	}
	res, err := s.Pool.AutheliaUsers.Call(r.Context(), map[string]any{
		"action":   "delete",
		"username": username,
	}, 15*time.Second)
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

func (s *Server) handleAutheliaBansList(w http.ResponseWriter, r *http.Request) {
	res, err := s.Pool.AutheliaBans.Call(r.Context(), map[string]any{"action": "list"}, 10*time.Second)
	if err != nil {
		s.writeUnavailable(w, r, err)
		return
	}
	s.writeJSON(w, r, http.StatusOK, res)
}

func (s *Server) handleAutheliaBansUnban(w http.ResponseWriter, r *http.Request) {
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	cmd := map[string]any{"action": "unban"}
	for _, k := range []string{"username", "ip", "id", "kind"} {
		if v, exists := payload[k]; exists {
			cmd[k] = v
		}
	}
	res, err := s.Pool.AutheliaBans.Call(r.Context(), cmd, 15*time.Second)
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

func (s *Server) handleAutheliaNotifLatest(w http.ResponseWriter, r *http.Request) {
	res, err := s.Pool.AutheliaCfg.Call(r.Context(), map[string]any{"action": "notification_latest"}, 10*time.Second)
	if err != nil {
		s.writeUnavailable(w, r, err)
		return
	}
	s.writeJSON(w, r, http.StatusOK, res)
}

func (s *Server) handleAutheliaNotifReveal(w http.ResponseWriter, r *http.Request) {
	res, err := s.Pool.AutheliaCfg.Call(r.Context(), map[string]any{
		"action": "notification_reveal",
		"actor":  remoteUser(r),
	}, 10*time.Second)
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

func (s *Server) handleAutheliaNotifHandled(w http.ResponseWriter, r *http.Request) {
	res, err := s.Pool.AutheliaCfg.Call(r.Context(), map[string]any{
		"action": "notification_handled",
		"actor":  remoteUser(r),
	}, 10*time.Second)
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
