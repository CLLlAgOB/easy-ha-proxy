package healthd

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/unixrpc"
)

// Server is the healthd HTTP API over its Unix socket (HealthHandler).
type Server struct {
	State        *State
	ControlToken string
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	body, _ := json.MarshalIndent(payload, "", "  ")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func clampParam(q url.Values, key string, def, lo, hi int) int {
	raw := q.Get(key)
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return clamp(n, lo, hi)
}

// recentUnits is _parse_recent_systemd_units: nil when no selection was given.
func recentUnits(q url.Values) []string {
	_, hasUnit := q["unit"]
	_, hasUnits := q["units"]
	if !hasUnit && !hasUnits {
		return nil
	}
	selected := []string{}
	seen := map[string]bool{}
	for _, key := range []string{"unit", "units"} {
		for _, raw := range q[key] {
			for _, u := range strings.Split(raw, ",") {
				u = strings.TrimSpace(u)
				if u == "" || seen[u] {
					continue
				}
				seen[u] = true
				selected = append(selected, u)
			}
		}
	}
	return selected
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.get(w, r)
	case http.MethodPost:
		s.post(w, r)
	default:
		writeJSON(w, http.StatusNotImplemented, map[string]any{"ok": false, "error": "unsupported method"})
	}
}

func (s *Server) get(w http.ResponseWriter, r *http.Request) {
	st := s.State
	q := r.URL.Query()
	switch r.URL.Path {
	case "/api/v1/health/ping":
		writeJSON(w, 200, map[string]any{"ok": true, "ts_utc": utcNowISO()})
	case "/api/v1/control/capabilities":
		sys := map[string]any{}
		for _, u := range append(append([]string{}, st.Cfg.SystemdUnits...), st.Cfg.SystemdUnitGlobs...) {
			sys[u] = AllowedActions("systemd", u, st.SelfUnit)
		}
		dock := map[string]any{}
		for _, c := range st.Cfg.DockerContainers {
			dock[c] = AllowedActions("docker", c, st.SelfUnit)
		}
		writeJSON(w, 200, map[string]any{"ok": true, "systemd": sys, "docker": dock})
	case "/api/v1/health/status":
		refresh := q.Get("refresh") == "1"
		writeJSON(w, 200, st.Snapshot(refresh))
	case "/api/v1/health/events":
		limit := clampParam(q, "limit", 50, 1, 500)
		writeJSON(w, 200, map[string]any{"ok": true, "items": st.Events(limit)})
	case "/api/v1/health/logs/systemd":
		unit := strings.TrimSpace(q.Get("unit"))
		tail := clampParam(q, "tail", st.Cfg.LogsDefaultTail, 10, st.Cfg.LogsMaxTail)
		since := clampParam(q, "since", st.Cfg.LogsDefaultSinceSeconds, 60, st.Cfg.LogsMaxSinceSeconds)
		if unit == "" {
			writeJSON(w, 400, map[string]any{"ok": false, "error": "unit is required"})
			return
		}
		mode := strings.ToLower(strings.TrimSpace(q.Get("mode")))
		writeJSON(w, 200, st.LogsSystemd(unit, tail, since, mode, q.Get("reset_cursor") == "1", q.Get("cursor")))
	case "/api/v1/health/recent-systemd":
		limit := clampParam(q, "limit", RecentDefaultLimit, 1, RecentMaxLimit)
		data := st.RecentSystemd(limit, recentUnits(q))
		code := 400
		if ok, _ := data["ok"].(bool); ok {
			code = 200
		}
		writeJSON(w, code, data)
	case "/api/v1/health/logs/docker":
		container := strings.TrimSpace(q.Get("container"))
		tail := clampParam(q, "tail", st.Cfg.LogsDefaultTail, 10, st.Cfg.LogsMaxTail)
		since := clampParam(q, "since", st.Cfg.LogsDefaultSinceSeconds, 60, st.Cfg.LogsMaxSinceSeconds)
		if container == "" {
			writeJSON(w, 400, map[string]any{"ok": false, "error": "container is required"})
			return
		}
		writeJSON(w, 200, st.LogsDocker(container, tail, since))
	default:
		writeJSON(w, 404, map[string]any{"ok": false, "error": "not found"})
	}
}

func (s *Server) post(w http.ResponseWriter, r *http.Request) {
	st := s.State
	if r.URL.Path != "/api/v1/control" {
		writeJSON(w, 404, map[string]any{"ok": false, "error": "not found"})
		return
	}
	token := strings.TrimSpace(r.Header.Get("X-Healthd-Token"))
	if s.ControlToken == "" || subtle.ConstantTimeCompare([]byte(token), []byte(s.ControlToken)) != 1 {
		writeJSON(w, 403, map[string]any{"ok": false, "error": "forbidden"})
		return
	}
	length, _ := strconv.Atoi(strings.TrimSpace(r.Header.Get("Content-Length")))
	if length <= 0 || length > 16384 {
		writeJSON(w, 400, map[string]any{"ok": false, "error": "invalid Content-Length"})
		return
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, int64(length)))
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		var any_ any
		if json.Unmarshal(raw, &any_) == nil {
			writeJSON(w, 400, map[string]any{"ok": false, "error": "payload must be a JSON object"})
			return
		}
		writeJSON(w, 400, map[string]any{"ok": false, "error": fmt.Sprintf("bad json: %v", err)})
		return
	}
	text := func(k string) string {
		v, _ := payload[k].(string)
		return strings.TrimSpace(v)
	}
	kind, name, action := strings.ToLower(text("kind")), text("name"), strings.ToLower(text("action"))
	switch {
	case kind != "systemd" && kind != "docker":
		writeJSON(w, 400, map[string]any{"ok": false, "error": "kind must be systemd|docker"})
		return
	case name == "":
		writeJSON(w, 400, map[string]any{"ok": false, "error": "name is required"})
		return
	case action != "start" && action != "stop" && action != "restart" && action != "reload":
		writeJSON(w, 400, map[string]any{"ok": false, "error": "action must be start|stop|restart|reload"})
		return
	case kind == "systemd" && !st.allowedUnit(name):
		writeJSON(w, 403, map[string]any{"ok": false, "error": "unit not allowed"})
		return
	case kind == "docker" && !st.allowedContainer(name):
		writeJSON(w, 403, map[string]any{"ok": false, "error": "container not allowed"})
		return
	}
	allowed := AllowedActions(kind, name, st.SelfUnit)
	if !contains(allowed, action) {
		sorted := append([]string{}, allowed...)
		sort.Strings(sorted)
		writeJSON(w, 403, map[string]any{"ok": false, "error": "action not allowed", "allowed": sorted})
		return
	}
	var argv []string
	var rc int
	var out, errText string
	if kind == "systemd" {
		argv = []string{"systemctl", action, name}
		if action == "restart" && unitBase(name) == unitBase(st.SelfUnit) {
			go func() {
				time.Sleep(200 * time.Millisecond)
				st.Run(30*time.Second, argv...)
			}()
			st.AddEvent(map[string]any{"ts_utc": utcNowISO(), "kind": "control", "name": kind + ":" + name, "from": "-", "to": action + " scheduled"})
			writeJSON(w, 202, map[string]any{"ok": true, "scheduled": true, "kind": kind, "name": name, "action": action, "cmd": strings.Join(argv, " ")})
			return
		}
		rc, out, errText = st.Run(30*time.Second, argv...)
	} else {
		argv = []string{"docker", action, name}
		rc, out, errText = st.Run(60*time.Second, argv...)
	}
	st.AddEvent(map[string]any{"ts_utc": utcNowISO(), "kind": "control", "name": kind + ":" + name, "from": "-", "to": fmt.Sprintf("%s rc=%d", action, rc)})
	code := 200
	if rc != 0 {
		code = 500
	}
	writeJSON(w, code, map[string]any{"ok": rc == 0, "kind": kind, "name": name, "action": action, "cmd": strings.Join(argv, " "), "rc": rc, "stdout": out, "stderr": errText})
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
	srv := &http.Server{Handler: s, ReadHeaderTimeout: 30 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second}
	go func() {
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shut)
	}()
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
