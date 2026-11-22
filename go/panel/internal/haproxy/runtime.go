// Package haproxy provides HAProxy runtime socket inspection and safe server
// state/weight controls with full parity to services_runtime.py.
package haproxy

import (
	"bufio"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"easy-ha-proxy/panel/internal/daemons"
)

const (
	MinWeight = 0
	MaxWeight = 256
)

var validStates = map[string]struct{}{
	"ready": {},
	"drain": {},
	"maint": {},
}

var defaultProtectedBackends = map[string]struct{}{
	"authelia_backend":  {},
	"be_access_granted": {},
	"be_access_portal":  {},
	"be_maintenance":    {},
}

// ValidationError is a safe user-facing runtime control error (HTTP 400).
type ValidationError struct {
	Msg string
}

func (e *ValidationError) Error() string { return e.Msg }

// ServerEntry describes one HAProxy backend server from `show stat`.
type ServerEntry struct {
	Server      string `json:"server"`
	Address     string `json:"address"`
	Status      string `json:"status"`
	AdminState  string `json:"admin_state"`
	Weight      int    `json:"weight"`
	Sessions    int    `json:"sessions"`
	CheckStatus string `json:"check_status"`
}

// BackendEntry groups operable servers under one HAProxy backend.
type BackendEntry struct {
	Backend string        `json:"backend"`
	Label   string        `json:"label"`
	Servers []ServerEntry `json:"servers"`
}

// Runtime manages HAProxy admin.sock inspection and control.
type Runtime struct {
	SocketPath    string
	ConfigPath    string
	ExcludeExact  map[string]struct{}
	ExcludePrefix []string

	mu            sync.Mutex
	cfgMtime      time.Time
	cfgDisplayMap map[string]string
}

// NewRuntime builds a Runtime controller.
func NewRuntime(socketPath, configPath string, excludeExact, excludePrefix []string) *Runtime {
	exact := make(map[string]struct{}, len(defaultProtectedBackends)+len(excludeExact))
	for k := range defaultProtectedBackends {
		exact[k] = struct{}{}
	}
	for _, k := range excludeExact {
		if s := strings.TrimSpace(k); s != "" {
			exact[s] = struct{}{}
		}
	}
	var prefixes []string
	for _, p := range excludePrefix {
		if s := strings.TrimSpace(p); s != "" {
			prefixes = append(prefixes, s)
		}
	}
	return &Runtime{
		SocketPath:    strings.TrimSpace(socketPath),
		ConfigPath:    strings.TrimSpace(configPath),
		ExcludeExact:  exact,
		ExcludePrefix: prefixes,
	}
}

func (rt *Runtime) isOperable(pxname string) bool {
	if pxname == "" {
		return false
	}
	if _, blocked := rt.ExcludeExact[pxname]; blocked {
		return false
	}
	for _, prefix := range rt.ExcludePrefix {
		if strings.HasPrefix(pxname, prefix) {
			return false
		}
	}
	return true
}

// DisplayName resolves the human-readable backend label from haproxy.cfg
// `# display-name:` tags, falling back to stripping `be_` and replacing `_`.
func (rt *Runtime) DisplayName(pxname string) string {
	names := rt.loadDisplayMap()
	if label, ok := names[pxname]; ok && label != "" {
		return label
	}
	base := strings.TrimPrefix(pxname, "be_")
	return strings.ReplaceAll(base, "_", ".")
}

var (
	backendLineRe = regexp.MustCompile(`^\s*backend\s+(\S+)`)
	displayTagRe  = regexp.MustCompile(`^\s*#\s*display-name:\s*(.+)\s*$`)
)

func (rt *Runtime) loadDisplayMap() map[string]string {
	if rt.ConfigPath == "" {
		return nil
	}
	info, err := os.Stat(rt.ConfigPath)
	if err != nil {
		return nil
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.cfgDisplayMap != nil && info.ModTime().Equal(rt.cfgMtime) {
		return rt.cfgDisplayMap
	}

	f, err := os.Open(rt.ConfigPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	mapping := make(map[string]string)
	scanner := bufio.NewScanner(f)
	current := ""
	for scanner.Scan() {
		line := scanner.Text()
		if m := backendLineRe.FindStringSubmatch(line); m != nil {
			current = strings.TrimSpace(m[1])
			continue
		}
		if current != "" {
			if m := displayTagRe.FindStringSubmatch(line); m != nil {
				if _, exists := mapping[current]; !exists {
					mapping[current] = strings.TrimSpace(m[1])
				}
			}
		}
	}
	rt.cfgMtime = info.ModTime()
	rt.cfgDisplayMap = mapping
	return mapping
}

// ParseShowStat parses HAProxy's CSV `show stat` reply into header-keyed rows.
func ParseShowStat(raw string) []map[string]string {
	var header []string
	var rows []map[string]string

	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			if header == nil {
				trimmed := strings.TrimSpace(strings.TrimPrefix(line, "#"))
				fields, err := csv.NewReader(strings.NewReader(trimmed)).Read()
				if err == nil && len(fields) > 0 {
					for i := range fields {
						fields[i] = strings.TrimSpace(fields[i])
					}
					header = fields
				}
			}
			continue
		}
		if header == nil {
			continue
		}
		r := csv.NewReader(strings.NewReader(line))
		r.FieldsPerRecord = -1
		r.LazyQuotes = true
		fields, err := r.Read()
		if err != nil && !errors.Is(err, io.EOF) {
			continue
		}
		row := make(map[string]string, len(header))
		for i, col := range header {
			if col == "" {
				continue
			}
			if i < len(fields) {
				row[col] = strings.TrimSpace(fields[i])
			} else {
				row[col] = ""
			}
		}
		rows = append(rows, row)
	}
	return rows
}

func adminState(status string) string {
	u := strings.ToUpper(strings.TrimSpace(status))
	if strings.HasPrefix(u, "MAINT") {
		return "maint"
	}
	if strings.HasPrefix(u, "DRAIN") {
		return "drain"
	}
	return "ready"
}

// ListBackends queries HAProxy `show stat` and returns operable backends.
func (rt *Runtime) ListBackends(ctx context.Context) ([]BackendEntry, error) {
	raw, err := daemons.LineCommand(ctx, rt.SocketPath, "show stat", 5*time.Second, 8*1024*1024)
	if err != nil {
		return nil, err
	}
	rows := ParseShowStat(raw)
	grouped := make(map[string][]ServerEntry)
	for _, row := range rows {
		pxname := strings.TrimSpace(row["pxname"])
		svname := strings.TrimSpace(row["svname"])
		if svname == "" || svname == "FRONTEND" || svname == "BACKEND" || !rt.isOperable(pxname) {
			continue
		}
		status := strings.TrimSpace(row["status"])
		grouped[pxname] = append(grouped[pxname], ServerEntry{
			Server:      svname,
			Address:     strings.TrimSpace(row["addr"]),
			Status:      status,
			AdminState:  adminState(status),
			Weight:      parseInt(row["weight"]),
			Sessions:    parseInt(row["scur"]),
			CheckStatus: strings.TrimSpace(row["check_status"]),
		})
	}

	keys := make([]string, 0, len(grouped))
	for k := range grouped {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	backends := make([]BackendEntry, 0, len(keys))
	for _, pxname := range keys {
		servers := grouped[pxname]
		sort.Slice(servers, func(i, j int) bool { return servers[i].Server < servers[j].Server })
		backends = append(backends, BackendEntry{
			Backend: pxname,
			Label:   rt.DisplayName(pxname),
			Servers: servers,
		})
	}
	return backends, nil
}

func (rt *Runtime) resolve(ctx context.Context, backend, server string) (string, string, error) {
	wantBe := strings.TrimSpace(backend)
	wantSrv := strings.TrimSpace(server)
	backends, err := rt.ListBackends(ctx)
	if err != nil {
		return "", "", err
	}
	for _, be := range backends {
		if be.Backend != wantBe {
			continue
		}
		for _, srv := range be.Servers {
			if srv.Server == wantSrv {
				return be.Backend, srv.Server, nil
			}
		}
	}
	return "", "", &ValidationError{Msg: "unknown backend or server"}
}

func (rt *Runtime) runCommand(ctx context.Context, cmd string) error {
	reply, err := daemons.LineCommand(ctx, rt.SocketPath, cmd, 5*time.Second, 64*1024)
	if err != nil {
		return err
	}
	trimmed := strings.TrimSpace(reply)
	if trimmed != "" {
		firstLine := strings.SplitN(trimmed, "\n", 2)[0]
		if len(firstLine) > 200 {
			firstLine = firstLine[:200]
		}
		return &ValidationError{Msg: firstLine}
	}
	return nil
}

// SetState sets a verified server's runtime state to ready, drain, or maint.
func (rt *Runtime) SetState(ctx context.Context, backend, server, state string) (map[string]any, error) {
	wanted := strings.ToLower(strings.TrimSpace(state))
	if _, ok := validStates[wanted]; !ok {
		return nil, &ValidationError{Msg: "state must be one of ready, drain, maint"}
	}
	be, srv, err := rt.resolve(ctx, backend, server)
	if err != nil {
		return nil, err
	}
	if err := rt.runCommand(ctx, fmt.Sprintf("set server %s/%s state %s", be, srv, wanted)); err != nil {
		return nil, err
	}
	return map[string]any{
		"ok":      true,
		"backend": be,
		"server":  srv,
		"state":   wanted,
	}, nil
}

// SetWeight sets a verified server's runtime weight (0..256).
func (rt *Runtime) SetWeight(ctx context.Context, backend, server string, weight int) (map[string]any, error) {
	if weight < MinWeight || weight > MaxWeight {
		return nil, &ValidationError{Msg: fmt.Sprintf("weight must be between %d and %d", MinWeight, MaxWeight)}
	}
	be, srv, err := rt.resolve(ctx, backend, server)
	if err != nil {
		return nil, err
	}
	if err := rt.runCommand(ctx, fmt.Sprintf("set server %s/%s weight %d", be, srv, weight)); err != nil {
		return nil, err
	}
	return map[string]any{
		"ok":      true,
		"backend": be,
		"server":  srv,
		"weight":  weight,
	}, nil
}

func parseInt(raw string) int {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0
	}
	return n
}
