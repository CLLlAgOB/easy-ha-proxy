package server

import (
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"easy-ha-proxy/panel/internal/daemons"
	"easy-ha-proxy/panel/internal/haproxy"
)

func (s *Server) registerDashboardRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/whitelists", s.handleWhitelists)
	mux.HandleFunc("GET /api/tables", s.handleTables)
	mux.HandleFunc("GET /api/tables_raw", s.handleTablesRaw)
	mux.HandleFunc("POST /api/unban", s.handleUnban)
	mux.HandleFunc("POST /api/whitelist", s.handleWhitelistGeo)
	mux.HandleFunc("POST /api/whitelist-global", s.handleWhitelistGlobal)
	mux.HandleFunc("GET /api/attackers", s.handleAttackers)
	mux.HandleFunc("GET /api/connections", s.handleConnections)
	mux.HandleFunc("POST /api/country-batch", s.handleCountryBatch)
	mux.HandleFunc("GET /api/backends", s.handleBackendsStatus)
	mux.HandleFunc("GET /api/ip_auth", s.handleIPAuthTable)
}

func (s *Server) handleWhitelists(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, r, http.StatusOK, map[string]any{
		"geo":    haproxy.ReadWhitelistFile(s.Cfg.WhitelistGeo),
		"global": haproxy.ReadWhitelistFile(s.Cfg.WhitelistGlobal),
	})
}

func (s *Server) handleTables(w http.ResponseWriter, r *http.Request) {
	banTable := s.Cfg.BanTable
	if banTable == "" {
		banTable = "abuse_ban"
	}
	_, entries, err := s.Runtime.ShowTable(r.Context(), banTable)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	res := map[string]any{
		"ok":    true,
		"table": banTable,
		"bans":  entries,
	}
	if r.URL.Query().Get("view") != "bans" {
		if names, err := s.Runtime.ListTableNames(r.Context()); err == nil {
			res["tables"] = names
		}
	}
	s.writeJSON(w, r, http.StatusOK, res)
}

func (s *Server) handleTablesRaw(w http.ResponseWriter, r *http.Request) {
	names, err := s.Runtime.ListTableNames(r.Context())
	if err != nil {
		s.writeJSON(w, r, http.StatusInternalServerError, map[string]any{"error": "Failed to read HAProxy tables"})
		return
	}
	rawTables := make(map[string]string, len(names))
	for _, name := range names {
		raw, _, err := s.Runtime.ShowTable(r.Context(), name)
		if err == nil {
			rawTables[name] = raw
		}
	}
	s.writeJSON(w, r, http.StatusOK, rawTables)
}

func (s *Server) extractIPParam(r *http.Request) string {
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	if strings.HasPrefix(ct, "application/json") {
		if payload, err := s.readJSONBody(r); err == nil {
			return strings.TrimSpace(asString(payload["ip"]))
		}
	}
	return strings.TrimSpace(r.FormValue("ip"))
}

func (s *Server) handleUnban(w http.ResponseWriter, r *http.Request) {
	ip := s.extractIPParam(r)
	if ip == "" {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "IP is required"})
		return
	}
	if _, err := netip.ParseAddr(ip); err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid IP address"})
		return
	}
	banTable := s.Cfg.BanTable
	if banTable == "" {
		banTable = "abuse_ban"
	}
	if err := s.Runtime.ClearTableKey(r.Context(), banTable, ip); err != nil {
		var ve *haproxy.ValidationError
		if errors.As(err, &ve) {
			s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": ve.Msg})
			return
		}
		s.writeJSON(w, r, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	// Best-effort notify guardd to drop its adaptive hold on this address.
	_, _, _ = s.Pool.Guardd.PostJSON(r.Context(), "/api/v1/guard/ban/forget", map[string]any{"ip": ip}, daemons.RequestOptions{
		Timeout: 5 * time.Second, WithToken: true, CheckStatus: false,
	})
	s.writeJSON(w, r, http.StatusOK, map[string]any{"ok": true, "ip": ip})
}

func (s *Server) handleWhitelistGeo(w http.ResponseWriter, r *http.Request) {
	s.handleWhitelistAdd(w, r, s.Cfg.WhitelistGeo)
}

func (s *Server) handleWhitelistGlobal(w http.ResponseWriter, r *http.Request) {
	s.handleWhitelistAdd(w, r, s.Cfg.WhitelistGlobal)
}

func (s *Server) handleWhitelistAdd(w http.ResponseWriter, r *http.Request, targetFile string) {
	ip := s.extractIPParam(r)
	if ip == "" {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "IP is required"})
		return
	}
	if err := s.Runtime.AddToWhitelistFile(r.Context(), targetFile, ip); err != nil {
		var ve *haproxy.ValidationError
		if errors.As(err, &ve) {
			s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": ve.Msg})
			return
		}
		s.writeJSON(w, r, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	s.writeJSON(w, r, http.StatusOK, map[string]any{"ok": true, "ip": ip})
}

func (s *Server) handleAttackers(w http.ResponseWriter, r *http.Request) {
	data, status, err := s.Pool.Guardd.GetJSON(r.Context(), "/api/v1/guard/attackers", daemons.RequestOptions{
		Timeout: 10 * time.Second, CheckStatus: false,
	})
	if err == nil && status == http.StatusOK && data != nil {
		s.writeJSON(w, r, http.StatusOK, data)
		return
	}
	// Fallback to controld `logs-attackers` when guardd live buffer is off.
	if s.Pool.ControldPath != "" {
		raw, cerr := daemons.LineCommand(r.Context(), s.Pool.ControldPath, "logs-attackers", 15*time.Second, 2*1024*1024)
		if cerr == nil && strings.HasPrefix(strings.TrimSpace(raw), "OK") {
			if parsed := decodeControlReply(raw); parsed != nil {
				if _, failed := parsed["error"]; !failed || parsed["code_400"] != nil {
					delete(parsed, "ok")
					s.writeJSON(w, r, http.StatusOK, parsed)
					return
				}
			}
		}
	}
	s.writeJSON(w, r, http.StatusInternalServerError, map[string]any{"error": "Failed to load attack statistics"})
}

func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request) {
	summary, err := s.Runtime.ConnectionsSummary(r.Context())
	if err != nil {
		s.writeJSON(w, r, http.StatusInternalServerError, map[string]any{"error": "Failed to load HAProxy connections"})
		return
	}
	s.writeJSON(w, r, http.StatusOK, summary)
}

func (s *Server) handleCountryBatch(w http.ResponseWriter, r *http.Request) {
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"error": "a JSON object is required"})
		return
	}
	rawIPs, ok := payload["ips"].([]any)
	if !ok {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"error": "ips must be a list"})
		return
	}
	if len(rawIPs) > 512 {
		s.writeJSON(w, r, http.StatusRequestEntityTooLarge, map[string]any{"error": "at most 512 IP addresses are allowed"})
		return
	}
	result := make(map[string]string, len(rawIPs))
	for _, item := range rawIPs {
		ip := strings.TrimSpace(asString(item))
		if _, seen := result[ip]; seen {
			continue
		}
		if _, err := netip.ParseAddr(ip); err != nil {
			result[ip] = ""
			continue
		}
		if s.GeoIP != nil {
			result[ip] = s.GeoIP.CountryCode(ip)
		} else {
			result[ip] = ""
		}
	}
	s.writeJSON(w, r, http.StatusOK, result)
}

func (s *Server) handleBackendsStatus(w http.ResponseWriter, r *http.Request) {
	backends, err := s.Runtime.ListBackends(r.Context())
	if err != nil {
		s.writeJSON(w, r, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	s.writeJSON(w, r, http.StatusOK, map[string]any{"ok": true, "backends": backends})
}

func (s *Server) handleIPAuthTable(w http.ResponseWriter, r *http.Request) {
	_, entries, err := s.Runtime.ShowTable(r.Context(), "ip_auth")
	if err != nil {
		s.writeJSON(w, r, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	s.writeJSON(w, r, http.StatusOK, map[string]any{"ok": true, "entries": entries})
}
