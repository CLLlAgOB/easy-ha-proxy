package certd

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/alerts"
)

// Server exposes the haproxy-certd AF_UNIX HTTP/1.1 API.
type Server struct {
	Manager *Manager
}

// Handler builds the HTTP router for certd endpoints.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/certs/list", s.handleList)
	mux.HandleFunc("/api/v1/certs/status", s.handleStatus)
	mux.HandleFunc("/api/v1/certs/inspect", s.handleInspect)
	mux.HandleFunc("/api/v1/certs/upload", s.handleUpload)
	mux.HandleFunc("/api/v1/certs/delete-haproxy", s.handleDeleteHAProxy)
	mux.HandleFunc("/api/v1/certs/standby", s.handleStandby)
	mux.HandleFunc("/api/v1/certs/dns-providers", s.handleDNSList)
	mux.HandleFunc("/api/v1/certs/dns-providers/save", s.handleDNSSave)
	mux.HandleFunc("/api/v1/certs/dns-providers/delete", s.handleDNSDelete)
	mux.HandleFunc("/api/v1/certs/trash", s.handleTrashList)
	mux.HandleFunc("/api/v1/certs/trash/restore", s.handleTrashRestore)
	mux.HandleFunc("/api/v1/certs/trash/purge", s.handleTrashPurge)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "unknown path"})
	})
	return mux
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	raw, err := json.Marshal(payload)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
	w.Header().Set("Connection", "close")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

func readJSONMap(r *http.Request) (map[string]any, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, DefaultMaxRequestBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > DefaultMaxRequestBytes {
		return nil, errors.New("request body is too large")
	}
	if len(body) == 0 {
		return map[string]any{}, nil
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil || out == nil {
		return map[string]any{}, nil
	}
	return out, nil
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	res, err := s.Manager.ListAll()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	res, err := s.Manager.ListAll()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleInspect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	ct := r.Header.Get("Content-Type")
	var pemBytes []byte
	if strings.HasPrefix(ct, "multipart/form-data") {
		if err := r.ParseMultipartForm(DefaultMaxRequestBytes); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		file, _, err := r.FormFile("file")
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "missing file upload"})
			return
		}
		defer file.Close()
		pemBytes, err = io.ReadAll(io.LimitReader(file, DefaultMaxRequestBytes))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
	} else {
		body, err := readJSONMap(r)
		if err != nil {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		pemStr, _ := body["pem"].(string)
		pemBytes = []byte(pemStr)
	}
	info, err := InspectPEMBytes(pemBytes, s.Manager.now())
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cert": info})
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if err := r.ParseMultipartForm(DefaultMaxRequestBytes); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	file, hdr, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "missing file upload"})
		return
	}
	defer file.Close()
	if name == "" && hdr != nil {
		name = filepath.Base(hdr.Filename)
	}
	data, err := io.ReadAll(io.LimitReader(file, DefaultMaxRequestBytes))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	info, err := s.Manager.UploadPEM(name, data)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cert": info})
}

func (s *Server) handleDeleteHAProxy(w http.ResponseWriter, r *http.Request) {
	body, err := readJSONMap(r)
	if err != nil {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	name, _ := body["name"].(string)
	entry, err := s.Manager.MoveToTrash(name)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "trash": entry})
}

func (s *Server) handleStandby(w http.ResponseWriter, _ *http.Request) {
	certs, err := ListPEMDir(s.Manager.Opts.StandbyDir, s.Manager.now())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "standby": certs})
}

func (s *Server) handleDNSList(w http.ResponseWriter, _ *http.Request) {
	profiles, err := s.Manager.ListDNSProfiles()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "profiles": profiles})
}

func (s *Server) handleDNSSave(w http.ResponseWriter, r *http.Request) {
	body, err := readJSONMap(r)
	if err != nil {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	name, _ := body["name"].(string)
	provider, _ := body["provider"].(string)
	prop := 0
	if n, ok := body["propagation_seconds"].(float64); ok {
		prop = int(n)
	}
	creds := map[string]string{}
	if rawCreds, ok := body["credentials"].(map[string]any); ok {
		for k, v := range rawCreds {
			if str, ok := v.(string); ok {
				creds[k] = str
			}
		}
	}
	prof, err := s.Manager.SaveDNSProfile(name, provider, prop, creds)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "profile": prof})
}

func (s *Server) handleDNSDelete(w http.ResponseWriter, r *http.Request) {
	body, err := readJSONMap(r)
	if err != nil {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	name, _ := body["name"].(string)
	if err := s.Manager.DeleteDNSProfile(name); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted": name})
}

func (s *Server) handleTrashList(w http.ResponseWriter, _ *http.Request) {
	items, err := s.Manager.ListTrash()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "items": items})
}

func (s *Server) handleTrashRestore(w http.ResponseWriter, r *http.Request) {
	body, err := readJSONMap(r)
	if err != nil {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	id, _ := body["id"].(string)
	entry, err := s.Manager.RestoreFromTrash(id)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "restored": entry})
}

func (s *Server) handleTrashPurge(w http.ResponseWriter, r *http.Request) {
	body, err := readJSONMap(r)
	if err != nil {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	id, _ := body["id"].(string)
	n, err := s.Manager.PurgeTrash(id)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "purged": n})
}

// Run binds the certd AF_UNIX socket, starts the expiry watch loop, and serves until SIGTERM/SIGINT.
func Run(opts Options) error {
	mgr := NewManager(opts, alerts.FromEnv())
	srv := &Server{Manager: mgr}

	if err := os.MkdirAll(filepath.Dir(opts.SocketPath), 0o755); err != nil {
		return err
	}
	_ = os.Remove(opts.SocketPath)
	ln, err := net.Listen("unix", opts.SocketPath)
	if err != nil {
		return err
	}
	_ = os.Chmod(opts.SocketPath, 0o660)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	go func() {
		interval := time.Duration(opts.WatchIntervalSec) * time.Second
		if interval <= 0 {
			interval = 6 * time.Hour
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		mgr.CheckExpiringCerts(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				mgr.CheckExpiringCerts(ctx)
			}
		}
	}()

	httpSrv := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 30 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
	}
	log.Printf("haproxy-certd (Go) listening on %s certs=%s", opts.SocketPath, opts.HAProxyCertsDir)

	errCh := make(chan error, 1)
	go func() {
		if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutCtx)
		_ = os.Remove(opts.SocketPath)
		return nil
	case err := <-errCh:
		_ = os.Remove(opts.SocketPath)
		return err
	}
}
