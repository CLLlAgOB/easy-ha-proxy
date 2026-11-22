package server

import (
	"encoding/base64"
	"net/http"
	"regexp"
	"strings"
	"time"

	"easy-ha-proxy/panel/internal/daemons"
)

var (
	dnsProfileRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
	dnsProviders = map[string]struct{}{
		"cloudflare":   {},
		"digitalocean": {},
		"route53":      {},
		"rfc2136":      {},
	}
)

const (
	maxDNSCredentialLen  = 4096
	maxDeliveryKeyLen    = 16384
)

func (s *Server) registerCertRoutes(mux *http.ServeMux) {
	// DNS-01 providers (routes_dns_providers.py).
	mux.HandleFunc("GET /api/haproxy/dns-providers", s.handleDNSProvidersList)
	mux.HandleFunc("POST /api/haproxy/dns-providers/save", s.handleDNSProviderSave)
	mux.HandleFunc("POST /api/haproxy/dns-providers/delete", s.handleDNSProviderDelete)

	// Certificate delivery (routes_cert_delivery.py).
	mux.HandleFunc("GET /api/haproxy/cert-delivery", s.handleCertDeliveryList)
	mux.HandleFunc("POST /api/haproxy/cert-delivery/save", s.handleCertDeliverySave)
	mux.HandleFunc("POST /api/haproxy/cert-delivery/delete", s.handleCertDeliveryDelete)
	mux.HandleFunc("POST /api/haproxy/cert-delivery/test", s.handleCertDeliveryTest)

	// Certificates & CA inspection/import/download.
	mux.HandleFunc("GET /api/haproxy/certs", s.handleCertsList)
	mux.HandleFunc("POST /haproxy/certs/inspect", s.handleCertsMaterial("/api/v1/certs/inspect"))
	mux.HandleFunc("POST /haproxy/certs/import", s.handleCertsMaterial("/api/v1/certs/import"))
	mux.HandleFunc("GET /haproxy/certs/ca/{ca_id}/download", s.handleCADownload)

	// Certificate trash proxy (routes_trash.py).
	mux.HandleFunc("GET /api/haproxy/trash", s.handleTrashList)
	mux.HandleFunc("POST /api/haproxy/trash/settings", s.handleTrashPost("/api/v1/trash/settings"))
	mux.HandleFunc("POST /api/haproxy/trash/restore", s.handleTrashPost("/api/v1/trash/restore"))
	mux.HandleFunc("POST /api/haproxy/trash/delete", s.handleTrashPost("/api/v1/trash/purge"))
	mux.HandleFunc("POST /api/haproxy/trash/empty", s.handleTrashEmpty)
}

func (s *Server) handleDNSProvidersList(w http.ResponseWriter, r *http.Request) {
	if !isSuperadmin(r) {
		s.writeJSON(w, r, http.StatusForbidden, map[string]any{"ok": false, "error": "superadmin required"})
		return
	}
	data, _, err := s.Pool.Certd.PostJSON(r.Context(), "/api/v1/dns-providers/list", map[string]any{}, daemons.RequestOptions{
		Timeout: 15 * time.Second, CheckStatus: false,
	})
	if err != nil {
		s.writeUnavailable(w, r, err)
		return
	}
	s.writeJSON(w, r, http.StatusOK, data)
}

func (s *Server) handleDNSProviderSave(w http.ResponseWriter, r *http.Request) {
	if !isSuperadmin(r) {
		s.writeJSON(w, r, http.StatusForbidden, map[string]any{"ok": false, "error": "superadmin required"})
		return
	}
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	name := strings.ToLower(strings.TrimSpace(asString(payload["name"])))
	provider := strings.ToLower(strings.TrimSpace(asString(payload["provider"])))
	if !dnsProfileRe.MatchString(name) {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "the profile name may use a-z, 0-9 and dashes"})
		return
	}
	if _, ok := dnsProviders[provider]; !ok {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "unsupported provider"})
		return
	}
	supplied, ok := payload["credentials"].(map[string]any)
	if !ok || len(supplied) == 0 {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "credentials are required"})
		return
	}
	creds := make(map[string]string, len(supplied))
	for k, v := range supplied {
		val := asString(v)
		if val == "" {
			continue
		}
		if len(val) > maxDNSCredentialLen {
			s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": k + " is too long"})
			return
		}
		creds[k] = val
	}
	if len(creds) == 0 {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "credentials are required"})
		return
	}

	res, _, err := s.Pool.Certd.PostJSON(r.Context(), "/api/v1/dns-providers/save", map[string]any{
		"name":        name,
		"provider":    provider,
		"credentials": creds,
	}, daemons.RequestOptions{Timeout: 30 * time.Second, CheckStatus: false})
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

func (s *Server) handleDNSProviderDelete(w http.ResponseWriter, r *http.Request) {
	if !isSuperadmin(r) {
		s.writeJSON(w, r, http.StatusForbidden, map[string]any{"ok": false, "error": "superadmin required"})
		return
	}
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	name := strings.ToLower(strings.TrimSpace(asString(payload["name"])))
	if !dnsProfileRe.MatchString(name) {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid profile name"})
		return
	}
	res, _, err := s.Pool.Certd.PostJSON(r.Context(), "/api/v1/dns-providers/delete", map[string]any{"name": name}, daemons.RequestOptions{
		Timeout: 15 * time.Second, CheckStatus: false,
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

func (s *Server) handleCertDeliveryList(w http.ResponseWriter, r *http.Request) {
	if !isSuperadmin(r) {
		s.writeJSON(w, r, http.StatusForbidden, map[string]any{"ok": false, "error": "superadmin required"})
		return
	}
	payload, _, err := s.Pool.Certd.PostJSON(r.Context(), "/api/v1/cert-delivery/list", map[string]any{}, daemons.RequestOptions{
		Timeout: 15 * time.Second, CheckStatus: false,
	})
	if err != nil {
		s.writeUnavailable(w, r, err)
		return
	}
	available := make([]map[string]any, 0)
	if certs, _, err := s.Pool.Certd.GetJSON(r.Context(), "/api/v1/certs/list", daemons.RequestOptions{
		Timeout: 10 * time.Second, CheckStatus: false,
	}); err == nil {
		if leList, ok := certs["letsencrypt"].([]any); ok {
			for _, item := range leList {
				m, _ := item.(map[string]any)
				name := strings.TrimSpace(asString(m["lineage"]))
				if name != "" {
					available = append(available, map[string]any{
						"name":    name,
						"expires": asString(m["not_after"]),
					})
				}
			}
		}
	}
	payload["available"] = available
	s.writeJSON(w, r, http.StatusOK, payload)
}

func (s *Server) handleCertDeliverySave(w http.ResponseWriter, r *http.Request) {
	if !isSuperadmin(r) {
		s.writeJSON(w, r, http.StatusForbidden, map[string]any{"ok": false, "error": "superadmin required"})
		return
	}
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	for _, field := range []string{"private_key", "host_key"} {
		if len(asString(payload[field])) > maxDeliveryKeyLen {
			s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": field + " is too long"})
			return
		}
	}
	res, _, err := s.Pool.Certd.PostJSON(r.Context(), "/api/v1/cert-delivery/save", payload, daemons.RequestOptions{
		Timeout: 30 * time.Second, CheckStatus: false,
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

func (s *Server) handleCertDeliveryDelete(w http.ResponseWriter, r *http.Request) {
	if !isSuperadmin(r) {
		s.writeJSON(w, r, http.StatusForbidden, map[string]any{"ok": false, "error": "superadmin required"})
		return
	}
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	name := strings.ToLower(strings.TrimSpace(asString(payload["name"])))
	res, _, err := s.Pool.Certd.PostJSON(r.Context(), "/api/v1/cert-delivery/delete", map[string]any{"name": name}, daemons.RequestOptions{
		Timeout: 15 * time.Second, CheckStatus: false,
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

func (s *Server) handleCertDeliveryTest(w http.ResponseWriter, r *http.Request) {
	if !isSuperadmin(r) {
		s.writeJSON(w, r, http.StatusForbidden, map[string]any{"ok": false, "error": "superadmin required"})
		return
	}
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	name := strings.ToLower(strings.TrimSpace(asString(payload["name"])))
	res, _, err := s.Pool.Certd.PostJSON(r.Context(), "/api/v1/cert-delivery/test", map[string]any{"name": name}, daemons.RequestOptions{
		Timeout: 90 * time.Second, CheckStatus: false,
	})
	if err != nil {
		s.writeUnavailable(w, r, err)
		return
	}
	s.writeJSON(w, r, http.StatusOK, res)
}

func (s *Server) handleCertsList(w http.ResponseWriter, r *http.Request) {
	if !isSuperadmin(r) {
		s.writeJSON(w, r, http.StatusForbidden, map[string]any{"ok": false, "error": "superadmin required"})
		return
	}
	res, _, err := s.Pool.Certd.GetJSON(r.Context(), "/api/v1/certs/list", daemons.RequestOptions{
		Timeout: 15 * time.Second, CheckStatus: false,
	})
	if err != nil {
		s.writeUnavailable(w, r, err)
		return
	}
	s.writeJSON(w, r, http.StatusOK, res)
}

func (s *Server) handleCertsMaterial(upstream string) http.HandlerFunc {
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
		res, status, err := s.Pool.Certd.PostJSON(r.Context(), upstream, payload, daemons.RequestOptions{
			Timeout: 30 * time.Second, CheckStatus: false,
		})
		if err != nil {
			s.writeUnavailable(w, r, err)
			return
		}
		if status == 0 {
			status = http.StatusOK
		}
		s.writeJSON(w, r, status, res)
	}
}

func (s *Server) handleCADownload(w http.ResponseWriter, r *http.Request) {
	if !isSuperadmin(r) {
		s.writeJSON(w, r, http.StatusForbidden, map[string]any{"ok": false, "error": "superadmin required"})
		return
	}
	caID := strings.TrimSpace(r.PathValue("ca_id"))
	if caID == "" {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "ca_id is required"})
		return
	}
	res, _, err := s.Pool.Certd.PostJSON(r.Context(), "/api/v1/ca/export", map[string]any{"id": caID}, daemons.RequestOptions{
		Timeout: 15 * time.Second, CheckStatus: false,
	})
	if err != nil {
		s.writeUnavailable(w, r, err)
		return
	}
	if okVal, _ := res["ok"].(bool); !okVal {
		s.writeJSON(w, r, http.StatusNotFound, res)
		return
	}
	pemText := asString(res["pem"])
	if pemText == "" {
		if b64 := asString(res["pem_b64"]); b64 != "" {
			if dec, err := base64.StdEncoding.DecodeString(b64); err == nil {
				pemText = string(dec)
			}
		}
	}
	filename := asString(res["filename"])
	if filename == "" {
		filename = caID + ".crt"
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="`+strings.ReplaceAll(filename, `"`, "")+`"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(pemText))
}

func (s *Server) handleTrashList(w http.ResponseWriter, r *http.Request) {
	if !isSuperadmin(r) {
		s.writeJSON(w, r, http.StatusForbidden, map[string]any{"ok": false, "error": "superadmin required"})
		return
	}
	res, _, err := s.Pool.Certd.PostJSON(r.Context(), "/api/v1/trash/list", map[string]any{}, daemons.RequestOptions{
		Timeout: 15 * time.Second, CheckStatus: false,
	})
	if err != nil {
		s.writeUnavailable(w, r, err)
		return
	}
	s.writeJSON(w, r, http.StatusOK, res)
}

func (s *Server) handleTrashPost(upstream string) http.HandlerFunc {
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
		res, _, err := s.Pool.Certd.PostJSON(r.Context(), upstream, payload, daemons.RequestOptions{
			Timeout: 15 * time.Second, CheckStatus: false,
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
}

func (s *Server) handleTrashEmpty(w http.ResponseWriter, r *http.Request) {
	if !isSuperadmin(r) {
		s.writeJSON(w, r, http.StatusForbidden, map[string]any{"ok": false, "error": "superadmin required"})
		return
	}
	res, _, err := s.Pool.Certd.PostJSON(r.Context(), "/api/v1/trash/purge", map[string]any{"all": true}, daemons.RequestOptions{
		Timeout: 30 * time.Second, CheckStatus: false,
	})
	if err != nil {
		s.writeUnavailable(w, r, err)
		return
	}
	s.writeJSON(w, r, http.StatusOK, res)
}
