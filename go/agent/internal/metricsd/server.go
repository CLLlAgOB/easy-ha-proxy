package metricsd

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Server exposes the metricsd HTTP API over an AF_UNIX socket.
type Server struct {
	Collector *Collector
}

// Handler returns the http.Handler for metricsd routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/metrics/health", s.handleHealth)
	mux.HandleFunc("GET /api/v1/metrics/sites", s.handleSites)
	mux.HandleFunc("GET /api/v1/metrics/summary", s.handleSummary)
	mux.HandleFunc("GET /api/v1/metrics/host", s.handleHost)
	mux.HandleFunc("POST /api/v1/metrics/monitors", s.handleSetMonitors)
	return mux
}

// Serve binds and serves over socketPath until ctx is canceled.
func (s *Server) Serve(ctx context.Context, socketPath string) error {
	_ = os.Remove(socketPath)
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o750); err != nil {
		return err
	}
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	defer func() {
		_ = ln.Close()
		_ = os.Remove(socketPath)
	}()

	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	err = srv.Serve(ln)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"backend":   "go-agent",
		"ts":        time.Now().Unix(),
		"collector": s.Collector.Health(),
	})
}

func (s *Server) handleSites(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"sites": s.Collector.Sites(),
	})
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	rangeKey, since, until := ResolveWindow(q, time.Now().Unix())
	site := strings.TrimSpace(q.Get("site"))
	if strings.EqualFold(site, "all") {
		site = ""
	}
	summary := s.Collector.Summary(site, since, until)
	summary["ok"] = true
	summary["range"] = rangeKey
	summary["since"] = since
	summary["until"] = until
	writeJSON(w, http.StatusOK, summary)
}

func (s *Server) handleHost(w http.ResponseWriter, r *http.Request) {
	rangeKey, since, until := ResolveWindow(r.URL.Query(), time.Now().Unix())
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"range":   rangeKey,
		"since":   since,
		"until":   until,
		"samples": s.Collector.HostSamples(since, until),
	})
}

func (s *Server) handleSetMonitors(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var req struct {
		Monitors map[string]bool `json:"monitors"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Monitors) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "monitors must be a non-empty object"})
		return
	}
	updated, errMsg := s.Collector.SetMonitors(req.Monitors)
	if errMsg != "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": errMsg})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "monitors": updated})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
