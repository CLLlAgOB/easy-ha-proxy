package metricsd

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Server exposes the complete metricsd HTTP API over an AF_UNIX socket.
type Server struct {
	Collector *Collector
}

// Handler returns the http.Handler implementing all metricsd routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/metrics/health", s.handleHealth)
	mux.HandleFunc("GET /api/v1/metrics/sites", s.handleSites)
	mux.HandleFunc("GET /api/v1/metrics/summary", s.handleSummary)
	mux.HandleFunc("GET /api/v1/metrics/host", s.handleHost)
	mux.HandleFunc("GET /api/v1/metrics/series", s.handleSeries)
	mux.HandleFunc("GET /api/v1/metrics/servers", s.handleServers)
	mux.HandleFunc("GET /api/v1/metrics/backends", s.handleBackends)
	mux.HandleFunc("GET /api/v1/metrics/states", s.handleStates)
	mux.HandleFunc("GET /api/v1/metrics/storage", s.handleStorage)
	mux.HandleFunc("GET /api/v1/metrics/monitors", s.handleGetMonitors)
	mux.HandleFunc("POST /api/v1/metrics/monitors", s.handleSetMonitors)
	mux.HandleFunc("POST /api/v1/metrics/channel-labels", s.handleChannelLabels)
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
	_ = os.Chmod(socketPath, 0o660)
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

func (s *Server) resolveSite(r *http.Request) string {
	requested := strings.TrimSpace(r.URL.Query().Get("site"))
	if requested == "" || strings.EqualFold(requested, "all") {
		return ""
	}
	for _, entry := range s.Collector.Sites() {
		if entry["proxy"] == requested {
			return requested
		}
	}
	return ""
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	payload := map[string]any{
		"ok":        true,
		"backend":   "go-agent",
		"ts":        time.Now().Unix(),
		"collector": s.Collector.Health(),
	}
	if s.Collector.Store != nil {
		payload["database"] = s.Collector.Store.Stats()
	}
	writeJSON(w, http.StatusOK, payload)
}

func (s *Server) handleSites(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"sites": s.Collector.Sites(),
	})
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	now := time.Now().Unix()
	rangeKey, since, until := ResolveWindow(r.URL.Query(), now)
	site := s.resolveSite(r)
	summary := s.Collector.Summary(site, since, until)
	summary["ok"] = true
	summary["ts"] = until
	summary["range"] = rangeKey
	summary["range_seconds"] = max(int64(1), until-since)
	summary["since"] = since
	summary["until"] = until
	summary["site"] = site
	summary["collector"] = s.Collector.Health()
	if s.Collector.Store != nil {
		summary["storage"] = s.Collector.Store.StorageReport(until)
	}
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

func (s *Server) handleSeries(w http.ResponseWriter, r *http.Request) {
	chart := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("chart")))
	if _, ok := ChartSeries[chart]; !ok {
		avail := make([]string, 0, len(ChartSeries))
		for k := range ChartSeries {
			avail = append(avail, k)
		}
		sort.Strings(avail)
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":        false,
			"error":     "unknown chart",
			"available": avail,
		})
		return
	}
	rangeKey, since, until := ResolveWindow(r.URL.Query(), time.Now().Unix())
	site := s.resolveSite(r)
	payload := s.Collector.Store.Series(chart, site, since, until)
	payload["ok"] = true
	payload["range"] = rangeKey
	payload["since"] = since
	payload["until"] = until
	writeJSON(w, http.StatusOK, payload)
}

func (s *Server) handleServers(w http.ResponseWriter, r *http.Request) {
	rangeKey, since, until := ResolveWindow(r.URL.Query(), time.Now().Unix())
	payload := s.Collector.Store.ServerTotals(since, until)
	labels, hidden := s.Collector.Store.ChannelLabels()
	payload["labels"] = labels
	payload["hidden"] = hidden
	payload["ok"] = true
	payload["range"] = rangeKey
	payload["since"] = since
	payload["until"] = until
	writeJSON(w, http.StatusOK, payload)
}

func (s *Server) handleBackends(w http.ResponseWriter, r *http.Request) {
	rangeKey, since, until := ResolveWindow(r.URL.Query(), time.Now().Unix())
	payload := s.Collector.Store.BackendTotals(since, until)
	payload["ok"] = true
	payload["range"] = rangeKey
	payload["since"] = since
	payload["until"] = until
	writeJSON(w, http.StatusOK, payload)
}

func (s *Server) handleStates(w http.ResponseWriter, r *http.Request) {
	rangeKey, since, until := ResolveWindow(r.URL.Query(), time.Now().Unix())
	payload := s.Collector.Store.StateTimeline(s.resolveSite(r), since, until)
	payload["ok"] = true
	payload["range"] = rangeKey
	payload["since"] = since
	payload["until"] = until
	writeJSON(w, http.StatusOK, payload)
}

func (s *Server) handleStorage(w http.ResponseWriter, _ *http.Request) {
	now := time.Now().Unix()
	st := s.Collector.Store.StorageReport(now)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"ts":      now,
		"path":    st.Path,
		"storage": st,
	})
}

func (s *Server) handleGetMonitors(w http.ResponseWriter, _ *http.Request) {
	health := s.Collector.Health()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"monitors": health["monitors"],
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

func (s *Server) handleChannelLabels(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 65536)
	var raw map[string]any
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil || raw == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "payload must be an object"})
		return
	}
	labelsRaw, ok := raw["labels"].(map[string]any)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "labels must be an object"})
		return
	}
	cleaned, hidden, errMsg := CleanChannelLabels(labelsRaw, raw["hidden"])
	if errMsg != "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": errMsg})
		return
	}
	savedLabels, savedHidden := s.Collector.Store.SetChannelLabels(cleaned, hidden)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"labels": savedLabels,
		"hidden": savedHidden,
	})
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
