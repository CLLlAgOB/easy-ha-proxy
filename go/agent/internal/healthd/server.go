package healthd

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/unixrpc"
)

const maxControlBodyBytes = 8192

// Server exposes the healthd HTTP API over an AF_UNIX socket.
type Server struct {
	Collector    *Collector
	ControlToken string
	SelfUnit     string
	Runner       CmdRunner
}

// Handler returns the http.Handler for healthd routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	mux.HandleFunc("GET /api/v1/status", s.handleStatus)
	mux.HandleFunc("GET /api/v1/health/status", s.handleStatus)
	mux.HandleFunc("GET /api/v1/events", s.handleEvents)
	mux.HandleFunc("GET /api/v1/health/events", s.handleEvents)
	mux.HandleFunc("GET /api/v1/control/capabilities", s.handleCapabilities)
	mux.HandleFunc("POST /api/v1/control", s.handleControl)
	return mux
}

func (s *Server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	allActions := []string{"start", "stop", "restart", "reload"}
	sysCaps := make(map[string][]string)
	for _, u := range s.Collector.cfg.SystemdUnits {
		var acts []string
		for _, a := range allActions {
			if ActionPermitted("systemd", u, a, s.SelfUnit) {
				acts = append(acts, a)
			}
		}
		if len(acts) > 0 {
			sysCaps[u] = acts
		}
	}
	dockCaps := make(map[string][]string)
	for _, c := range s.Collector.cfg.DockerContainers {
		var acts []string
		for _, a := range allActions {
			if ActionPermitted("docker", c, a, s.SelfUnit) {
				acts = append(acts, a)
			}
		}
		if len(acts) > 0 {
			dockCaps[c] = acts
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"systemd": sysCaps,
		"docker":  dockCaps,
	})
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
	grp := strings.TrimSpace(os.Getenv("HEALTHD_SOCKET_GROUP"))
	if grp == "" {
		grp = "hadmin"
	}
	unixrpc.ChownSocket(socketPath, "", grp, 0o660)
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
		"ok":      true,
		"backend": "go-agent",
		"ts":      time.Now().Unix(),
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	force := r.URL.Query().Get("force") == "1"
	snap := s.Collector.Snapshot(r.Context(), force)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"backend":  "go-agent",
		"snapshot": snap,
	})
}

func (s *Server) handleEvents(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"events": s.Collector.Events(),
	})
}

func (s *Server) handleControl(w http.ResponseWriter, r *http.Request) {
	if s.ControlToken == "" {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "control token not configured"})
		return
	}
	if !ConstantTimeTokenOK(strings.TrimSpace(r.Header.Get("X-Healthd-Token")), s.ControlToken) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "unauthorized"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxControlBodyBytes)
	var req struct {
		Kind   string `json:"kind"`
		Name   string `json:"name"`
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid JSON body"})
		return
	}
	kind := strings.ToLower(strings.TrimSpace(req.Kind))
	name := strings.TrimSpace(req.Name)
	action := strings.ToLower(strings.TrimSpace(req.Action))
	if !s.Collector.IsAllowedTarget(r.Context(), kind, name) {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "target not in allowlist"})
		return
	}
	if !ActionPermitted(kind, name, action, s.SelfUnit) {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "action not permitted for target"})
		return
	}
	runner := s.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	var argv []string
	if kind == "systemd" {
		argv = []string{"systemctl", action, name}
	} else {
		argv = []string{"docker", action, name}
	}
	cmdCtx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	rc, _, stderr := runner.Run(cmdCtx, argv...)
	if rc != 0 {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"ok":    false,
			"rc":    rc,
			"error": strings.TrimSpace(stderr),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"kind":   kind,
		"name":   name,
		"action": action,
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
