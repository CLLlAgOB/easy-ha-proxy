package alertd

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/unixrpc"
)

// Server exposes the easy-ha-proxy-alertd AF_UNIX HTTP API.
type Server struct {
	Engine *Engine
	Token  string
}

// Handler returns the http.Handler implementing all 11 alertd endpoints.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/alerts/portal", s.handlePortal)
	mux.HandleFunc("/api/v1/alerts/health", s.handleHealth)
	mux.HandleFunc("/api/v1/alerts/state", s.handleState)
	mux.HandleFunc("/api/v1/alerts/history", s.handleHistory)
	mux.HandleFunc("/api/v1/alerts/notify", s.handleNotify)
	mux.HandleFunc("/api/v1/alerts/config", s.handleConfig)
	mux.HandleFunc("/api/v1/alerts/test", s.handleTest)
	mux.HandleFunc("/api/v1/alerts/quieten", s.handleQuieten)
	mux.HandleFunc("/api/v1/alerts/dismiss", s.handleDismiss)
	mux.HandleFunc("/api/v1/alerts/history/delete", s.handleHistoryDelete)
	mux.HandleFunc("/api/v1/alerts/mail/retry", s.handleMailRetry)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "not found"})
	})
	return mux
}

func (s *Server) authOK(r *http.Request) bool {
	if s.Token == "" {
		return false
	}
	supplied := strings.TrimSpace(r.Header.Get("X-Alertd-Token"))
	return subtle.ConstantTimeCompare([]byte(supplied), []byte(s.Token)) == 1
}

func (s *Server) requirePostAuth(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return false
	}
	if !s.authOK(r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "forbidden"})
		return false
	}
	return true
}

func decodeJSONBody(r *http.Request) map[string]any {
	data, err := io.ReadAll(io.LimitReader(r.Body, 256*1024))
	if err != nil || len(data) == 0 {
		return map[string]any{}
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil || out == nil {
		return map[string]any{}
	}
	return out
}

func writeJSON(w http.ResponseWriter, code int, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

func writeErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrInvalid):
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
	case errors.Is(err, ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": err.Error()})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
	}
}

func queryInt(r *http.Request, key string, def, minV, maxV int) int {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return clampInt(n, minV, maxV)
}

func (s *Server) handlePortal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	out := s.Engine.Portal()
	out["ok"] = true
	out["ts"] = s.Engine.now()
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	out := s.Engine.Health()
	out["ok"] = true
	out["ts"] = s.Engine.now()
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	limit := queryInt(r, "limit", 100, 1, 500)
	out := s.Engine.Snapshot(limit)
	out["ok"] = true
	out["ts"] = s.Engine.now()
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	q := r.URL.Query()
	total, events := s.Engine.store.Events(EventFilter{
		Rule:     strings.TrimSpace(q.Get("rule")),
		Severity: strings.TrimSpace(q.Get("severity")),
		Since:    int64(queryInt(r, "since", 0, 0, 2000000000)),
		Until:    int64(queryInt(r, "until", 0, 0, 2000000000)),
		Limit:    queryInt(r, "limit", 100, 1, 500),
		Offset:   queryInt(r, "offset", 0, 0, 1000000),
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"ts":     s.Engine.now(),
		"total":  total,
		"events": events,
	})
}

func (s *Server) handleNotify(w http.ResponseWriter, r *http.Request) {
	if !s.requirePostAuth(w, r) {
		return
	}
	res, err := s.Engine.Observe(r.Context(), decodeJSONBody(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	res["ok"] = true
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if !s.requirePostAuth(w, r) {
		return
	}
	cfg, err := s.Engine.UpdateConfig(r.Context(), decodeJSONBody(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "config": cfg.Redacted()})
}

func (s *Server) handleTest(w http.ResponseWriter, r *http.Request) {
	if !s.requirePostAuth(w, r) {
		return
	}
	subj := fmt.Sprintf("[%s] easy-ha-proxy alert test", s.Engine.opts.GatewayName)
	body := "This is a test message from easy-ha-proxy.\n\nIf you received it, alert delivery works.\n"
	delivered, errs := s.Engine.Deliver(r.Context(), subj, body, "")
	code := http.StatusBadGateway
	if len(delivered) > 0 {
		code = http.StatusOK
	}
	writeJSON(w, code, map[string]any{
		"ok":        len(delivered) > 0,
		"delivered": delivered,
		"errors":    errs,
	})
}

func (s *Server) handleQuieten(w http.ResponseWriter, r *http.Request) {
	if !s.requirePostAuth(w, r) {
		return
	}
	res, err := s.Engine.Quieten(decodeJSONBody(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	res["ok"] = true
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleDismiss(w http.ResponseWriter, r *http.Request) {
	if !s.requirePostAuth(w, r) {
		return
	}
	res, err := s.Engine.Dismiss(decodeJSONBody(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	res["ok"] = true
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleHistoryDelete(w http.ResponseWriter, r *http.Request) {
	if !s.requirePostAuth(w, r) {
		return
	}
	deleted, err := s.Engine.DeleteHistory(decodeJSONBody(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted": deleted})
}

func (s *Server) handleMailRetry(w http.ResponseWriter, r *http.Request) {
	if !s.requirePostAuth(w, r) {
		return
	}
	res, err := s.Engine.RetryMail(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	res["ok"] = true
	writeJSON(w, http.StatusOK, res)
}

// Run starts the alertd daemon on its AF_UNIX socket and blocks until SIGTERM/SIGINT.
func Run(opts DaemonOptions) error {
	cfg := LoadConfig(opts.ConfigPath)
	store, err := NewStore(opts.DatabasePath)
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()
	engine := NewEngine(opts, cfg, store, nil)
	srv := &Server{Engine: engine, Token: opts.Token}

	ln, err := unixrpc.ListenUnix(opts.SocketPath, "", opts.SocketGroup, 0o660)
	if err != nil {
		return err
	}
	defer func() {
		_ = ln.Close()
		_ = os.Remove(opts.SocketPath)
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		engine.RunLoop(ctx)
	}()
	defer func() {
		stop()
		<-loopDone
	}()

	httpSrv := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 30 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
	}
	log.Printf("easy-ha-proxy-alertd (Go) listening on %s rules=%d enabled=%v", opts.SocketPath, len(Rules), cfg.Enabled)

	return unixrpc.ServeHTTP(ctx, httpSrv, unixrpc.PanelListener(ln), 45*time.Second)
}
