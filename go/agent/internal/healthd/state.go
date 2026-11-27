package healthd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxCursorFiles = 512

var (
	// CursorDir holds journalctl --cursor-file state for "follow" log mode.
	CursorDir             = envOr("HEALTHD_CURSOR_DIR", "/run/haproxy-healthd-cursors")
	logsCacheTTL          = envFloat("HEALTHD_LOGS_CACHE_TTL", 1.0)
	logsCacheMax          = envInt("HEALTHD_LOGS_CACHE_MAX", 256)
	logsCacheMaxValue     = envInt("HEALTHD_LOGS_CACHE_MAX_VALUE_BYTES", 256*1024)
	logsCmdTimeout        = envInt("HEALTHD_LOGS_CMD_TIMEOUT", 12)
	recentExcludedUnits   = []string{"haproxy-healthd.service", "haproxy.service"}
	RecentDefaultLimit    = 50
	RecentMaxLimit        = 500
	systemctlProps        = []string{"LoadState", "ActiveState", "SubState", "Type", "UnitFileState", "Description", "MainPID", "ExecMainPID", "Result", "ExecMainStatus", "ActiveEnterTimestamp", "InactiveEnterTimestamp", "InactiveExitTimestamp"}
	dockerInspectTemplate = strings.Join([]string{
		"Status={{.State.Status}}",
		"Running={{.State.Running}}",
		"Paused={{.State.Paused}}",
		"Restarting={{.State.Restarting}}",
		"OOMKilled={{.State.OOMKilled}}",
		"Dead={{.State.Dead}}",
		"ExitCode={{.State.ExitCode}}",
		"StartedAt={{.State.StartedAt}}",
		"FinishedAt={{.State.FinishedAt}}",
		"Health={{if .State.Health}}{{.State.Health.Status}}{{end}}",
		"Image={{.Config.Image}}",
	}, "\n")
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(os.Getenv(key))); err == nil {
		return n
	}
	return def
}

func envFloat(key string, def float64) float64 {
	if f, err := strconv.ParseFloat(strings.TrimSpace(os.Getenv(key)), 64); err == nil {
		return f
	}
	return def
}

func utcNowISO() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05+00:00")
}

// Runner runs a command and returns (rc, stdout, stderr), like _run_cmd.
type Runner func(timeout time.Duration, argv ...string) (int, string, string)

// RunCmd is the real Runner.
func RunCmd(timeout time.Duration, argv ...string) (int, string, string) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return 124, "", fmt.Sprintf("timeout after %ds", int(timeout.Seconds()))
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), out.String(), errb.String()
		}
		if errors.Is(err, exec.ErrNotFound) {
			return 127, "", "command not found"
		}
		return 1, "", err.Error()
	}
	return 0, out.String(), errb.String()
}

func parseKV(output string) map[string]string {
	data := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok || line == "" {
			continue
		}
		data[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return data
}

func parseIntPtr(s string) any {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return nil
	}
	return n
}

func parseBoolPtr(s string) any {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "1", "yes":
		return true
	case "false", "0", "no":
		return false
	}
	return nil
}

func nullable(m map[string]string, k string) any {
	if v, ok := m[k]; ok {
		return v
	}
	return nil
}

// systemdHealth is _systemd_health: (healthy, display state); healthy nil means unknown.
func systemdHealth(d map[string]string) (any, string) {
	load, active, subState := d["LoadState"], d["ActiveState"], d["SubState"]
	unitType, result := d["Type"], d["Result"]
	status := parseIntPtr(d["ExecMainStatus"])
	switch {
	case load != "" && load != "loaded":
		return false, load
	case active == "failed":
		return false, "failed"
	case unitType == "oneshot" && active == "activating":
		return nil, "running"
	case active == "activating" || active == "deactivating":
		return nil, active
	case active == "active":
		if subState == "exited" {
			return true, "loaded"
		}
		return true, "active"
	case unitType == "oneshot" && active == "inactive":
		exit := strings.TrimSpace(d["InactiveExitTimestamp"])
		if exit == "" || strings.ToLower(exit) == "n/a" {
			return nil, "not-run"
		}
		ok := (result == "" || result == "success") && (status == nil || status == 0)
		if ok {
			return true, "completed"
		}
		return false, "failed"
	case active == "inactive":
		return false, "inactive"
	}
	if active == "" {
		return nil, "?"
	}
	return nil, active
}

func displaySubState(d map[string]string, healthy any, display string) string {
	subState := d["SubState"]
	if d["Type"] != "oneshot" {
		return subState
	}
	result := d["Result"]
	switch {
	case d["ActiveState"] == "activating" || display == "running":
		return "running"
	case display == "completed" && healthy == true:
		return "success"
	case display == "not-run" && healthy == nil:
		return "—"
	case healthy == false:
		if result != "" && result != "success" {
			return result
		}
		if subState != "" {
			return subState
		}
		return "failed"
	}
	return subState
}

// State is _State: a cached snapshot, the event feed and the log readers.
type State struct {
	Cfg      Config
	SelfUnit string
	Run      Runner

	mu             sync.Mutex
	collectMu      sync.Mutex
	cache          map[string]any
	events         []map[string]any
	lastCollect    time.Time
	prevSig        map[string]string
	unitsScanMu    sync.Mutex
	unitsRescan    time.Time
	unitsExpanded  []string
	logs           *ttlCache
	cursorLocks    [64]sync.Mutex
	cursorCreateMu sync.Mutex
}

// NewState builds the state holder; run may be nil for the real commands.
func NewState(cfg Config, selfUnit string, run Runner) *State {
	if run == nil {
		run = RunCmd
	}
	_ = os.MkdirAll(CursorDir, 0o755)
	return &State{
		Cfg:      cfg,
		SelfUnit: selfUnit,
		Run:      run,
		cache:    emptyCache(),
		prevSig:  map[string]string{},
		logs:     newTTLCache(logsCacheTTL, logsCacheMax, logsCacheMaxValue),
	}
}

func emptyCache() map[string]any {
	return map[string]any{
		"ok":      true,
		"ts_utc":  utcNowISO(),
		"systemd": map[string]any{"units": map[string]any{}, "errors": []any{}},
		"docker":  map[string]any{"containers": map[string]any{}, "errors": []any{}, "available": nil},
		"meta":    map[string]any{"cached": false, "cache_age_seconds": nil},
	}
}

func deepCopy(v map[string]any) map[string]any {
	raw, _ := json.Marshal(v)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out
}

func (s *State) allowedUnit(unit string) bool {
	for _, u := range s.Cfg.SystemdUnits {
		if u == unit {
			return true
		}
	}
	for _, g := range s.Cfg.SystemdUnitGlobs {
		if ok, _ := path.Match(g, unit); ok {
			return true
		}
	}
	return false
}

func (s *State) allowedContainer(name string) bool {
	for _, c := range s.Cfg.DockerContainers {
		if c == name {
			return true
		}
	}
	return false
}

// Snapshot returns the cached state, collecting when asked or when stale.
func (s *State) Snapshot(refresh bool) map[string]any {
	ttl := time.Duration(s.Cfg.CacheTTLSeconds) * time.Second
	if refresh || ttl <= 0 {
		return s.ForceRefresh()
	}
	s.mu.Lock()
	units, _ := s.cache["systemd"].(map[string]any)["units"].(map[string]any)
	containers, _ := s.cache["docker"].(map[string]any)["containers"].(map[string]any)
	have := len(units) > 0 || len(containers) > 0
	if have && !s.lastCollect.IsZero() && time.Since(s.lastCollect) < ttl {
		out := deepCopy(s.cache)
		age := int(time.Since(s.lastCollect).Seconds())
		s.mu.Unlock()
		out["meta"] = map[string]any{"cached": true, "cache_age_seconds": age}
		return out
	}
	s.mu.Unlock()
	return s.ForceRefresh()
}

// ForceRefresh collects afresh and records state changes as events.
func (s *State) ForceRefresh() map[string]any {
	// Deferred, as Python's "with self._collect_lock": net/http recovers a
	// panic in the handler, and a lock still held then would block every
	// later health request.
	s.collectMu.Lock()
	defer s.collectMu.Unlock()
	newCache, sig := s.collect()
	now := utcNowISO()
	s.mu.Lock()
	keys := make([]string, 0, len(sig))
	for k := range sig {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		old, ok := s.prevSig[key]
		if !ok || old == sig[key] {
			continue
		}
		kind, name, _ := strings.Cut(key, ":")
		s.appendEvent(map[string]any{"ts_utc": now, "kind": kind, "name": name, "from": old, "to": sig[key]})
	}
	s.prevSig = sig
	s.cache = newCache
	s.lastCollect = time.Now()
	out := deepCopy(s.cache)
	s.mu.Unlock()
	out["meta"] = map[string]any{"cached": false, "cache_age_seconds": 0}
	return out
}

// appendEvent keeps the feed bounded; the caller holds s.mu.
func (s *State) appendEvent(ev map[string]any) {
	s.events = append(s.events, ev)
	if len(s.events) > s.Cfg.EventsMax {
		s.events = s.events[len(s.events)-s.Cfg.EventsMax:]
	}
}

// AddEvent records a control action in the feed.
func (s *State) AddEvent(ev map[string]any) {
	s.mu.Lock()
	s.appendEvent(ev)
	s.mu.Unlock()
}

// Events returns the last `limit` events.
func (s *State) Events(limit int) []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	items := s.events
	if len(items) > limit {
		items = items[len(items)-limit:]
	}
	out := make([]map[string]any, len(items))
	copy(out, items)
	return out
}

func (s *State) expandUnits() []string {
	base := append([]string{}, s.Cfg.SystemdUnits...)
	if len(s.Cfg.SystemdUnitGlobs) == 0 {
		return sortedSet(base)
	}
	s.unitsScanMu.Lock()
	defer s.unitsScanMu.Unlock()
	need := s.unitsRescan.IsZero() || time.Since(s.unitsRescan) >= time.Duration(s.Cfg.UnitsRescanSeconds)*time.Second
	expanded := append([]string{}, s.unitsExpanded...)
	if !need {
		return sortedSet(append(base, expanded...))
	}
	expanded = nil
	rc, out, _ := s.Run(15*time.Second, "systemctl", "list-unit-files", "--type=service", "--no-pager", "--no-legend")
	if rc == 0 {
		for _, line := range strings.Split(out, "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			for _, g := range s.Cfg.SystemdUnitGlobs {
				if ok, _ := path.Match(g, fields[0]); ok {
					expanded = append(expanded, fields[0])
				}
			}
		}
	}
	s.unitsExpanded = sortedSet(expanded)
	s.unitsRescan = time.Now()
	return sortedSet(append(base, expanded...))
}

func sortedSet(items []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, it := range items {
		if !seen[it] {
			seen[it] = true
			out = append(out, it)
		}
	}
	sort.Strings(out)
	return out
}

func (s *State) systemdStatus(unit string) map[string]any {
	argv := []string{"systemctl", "show", unit, "--no-pager"}
	for _, p := range systemctlProps {
		argv = append(argv, "--property", p)
	}
	rc, out, errText := s.Run(12*time.Second, argv...)
	if rc != 0 {
		return map[string]any{"ok": false, "unit": unit, "cmd": strings.Join(argv, " "), "rc": rc, "error": strings.TrimSpace(errText)}
	}
	d := parseKV(out)
	healthy, display := systemdHealth(d)
	return map[string]any{
		"ok":                       true,
		"unit":                     unit,
		"load_state":               nullable(d, "LoadState"),
		"active_state":             nullable(d, "ActiveState"),
		"sub_state":                nullable(d, "SubState"),
		"unit_type":                nullable(d, "Type"),
		"unit_file_state":          nullable(d, "UnitFileState"),
		"description":              nullable(d, "Description"),
		"main_pid":                 nullable(d, "MainPID"),
		"exec_main_pid":            nullable(d, "ExecMainPID"),
		"result":                   nullable(d, "Result"),
		"exec_main_status":         parseIntPtr(d["ExecMainStatus"]),
		"active_enter_timestamp":   nullable(d, "ActiveEnterTimestamp"),
		"inactive_enter_timestamp": nullable(d, "InactiveEnterTimestamp"),
		"inactive_exit_timestamp":  nullable(d, "InactiveExitTimestamp"),
		"healthy":                  healthy,
		"display_state":            display,
		"display_sub_state":        displaySubState(d, healthy, display),
	}
}

func (s *State) dockerStatus(name string) map[string]any {
	argv := []string{"docker", "container", "inspect", "--format", dockerInspectTemplate, name}
	rc, out, errText := s.Run(12*time.Second, argv...)
	if rc != 0 {
		return map[string]any{"ok": false, "name": name, "cmd": strings.Join(argv, " "), "rc": rc, "error": strings.TrimSpace(errText)}
	}
	kv := parseKV(out)
	health := any(nil)
	if kv["Health"] != "" {
		health = kv["Health"]
	}
	return map[string]any{
		"ok":          true,
		"name":        name,
		"status":      nullable(kv, "Status"),
		"running":     parseBoolPtr(kv["Running"]),
		"paused":      parseBoolPtr(kv["Paused"]),
		"restarting":  parseBoolPtr(kv["Restarting"]),
		"oom_killed":  parseBoolPtr(kv["OOMKilled"]),
		"dead":        parseBoolPtr(kv["Dead"]),
		"exit_code":   parseIntPtr(kv["ExitCode"]),
		"started_at":  nullable(kv, "StartedAt"),
		"finished_at": nullable(kv, "FinishedAt"),
		"health":      health,
		"image":       nullable(kv, "Image"),
	}
}

func (s *State) collect() (map[string]any, map[string]string) {
	cache := emptyCache()
	systemd := cache["systemd"].(map[string]any)
	units := systemd["units"].(map[string]any)
	docker := cache["docker"].(map[string]any)
	containers := docker["containers"].(map[string]any)
	sig := map[string]string{}
	toCheck := s.expandUnits()
	if len(s.Cfg.SystemdUnitGlobs) > 0 {
		if rc, _, errText := s.Run(15*time.Second, "systemctl", "list-unit-files", "--type=service", "--no-pager", "--no-legend"); rc != 0 {
			systemd["errors"] = append(systemd["errors"].([]any), map[string]any{"cmd": "systemctl list-unit-files", "rc": rc, "err": strings.TrimSpace(errText)})
		}
	}
	for _, unit := range toCheck {
		if !s.allowedUnit(unit) {
			continue
		}
		info := s.systemdStatus(unit)
		units[unit] = info
		sig["systemd:"+unit] = fmt.Sprintf("%v/%v", orQ(info["active_state"]), orQ(info["sub_state"]))
	}
	rc, _, _ := s.Run(6*time.Second, "docker", "version")
	docker["available"] = rc == 0
	if rc != 0 {
		return cache, sig
	}
	for _, name := range s.Cfg.DockerContainers {
		info := s.dockerStatus(name)
		containers[name] = info
		status := "?"
		if v, ok := info["status"].(string); ok && v != "" {
			status = v
		}
		sig["docker:"+name] = status
	}
	return cache, sig
}

func orQ(v any) any {
	if v == nil {
		return "?"
	}
	return v
}

func sanitizeCursorName(name string) string {
	var b strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		} else if r > 127 {
			// Python's isalnum() keeps letters of any script.
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	out := b.String()
	if len(out) > 180 {
		out = out[:180]
	}
	if out == "" {
		return "unnamed"
	}
	return out
}

func (s *State) cursorLock(key string) *sync.Mutex {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(key))
	return &s.cursorLocks[hash.Sum32()%uint32(len(s.cursorLocks))]
}

// LogsSystemd is get_logs_systemd.
func (s *State) LogsSystemd(unit string, tail, since int, mode string, reset bool, cursor string) map[string]any {
	if !s.allowedUnit(unit) {
		return map[string]any{"ok": false, "error": "unit is not allowed", "unit": unit}
	}
	tail = clamp(tail, 10, s.Cfg.LogsMaxTail)
	since = clamp(since, 60, s.Cfg.LogsMaxSinceSeconds)
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = "tail"
	}
	cursor = strings.TrimSpace(cursor)
	timeout := time.Duration(logsCmdTimeout) * time.Second
	if mode == "follow" {
		if !slices.Contains(s.Cfg.SystemdUnits, unit) && !slices.Contains(s.expandUnits(), unit) {
			return map[string]any{"ok": false, "error": "unit is not installed", "unit": unit}
		}
		cursorFile := filepath.Join(CursorDir, sanitizeCursorName("systemd_"+unit)+".cursor")
		key := fmt.Sprintf("systemd_follow|%s|%d|%d|%v", unit, tail, since, reset)
		if cached := s.logs.get(key); cached != nil {
			cached["cached"] = true
			return cached
		}
		lk := s.cursorLock(cursorFile)
		lk.Lock()
		defer lk.Unlock()
		if reset {
			_ = os.Remove(cursorFile)
		}
		var argv []string
		if info, err := os.Lstat(cursorFile); errors.Is(err, os.ErrNotExist) {
			s.cursorCreateMu.Lock()
			defer s.cursorCreateMu.Unlock()
			entries, err := os.ReadDir(CursorDir)
			if err != nil || len(entries) >= maxCursorFiles {
				return map[string]any{"ok": false, "error": "cannot allocate a log cursor", "unit": unit}
			}
			argv = []string{"journalctl", "-u", unit, "--no-pager", "-q", "-o", "short-iso", "--cursor-file", cursorFile, "--lines", strconv.Itoa(tail), "--since", fmt.Sprintf("-%ds", since)}
		} else if err == nil && info.Mode().IsRegular() {
			argv = []string{"journalctl", "-u", unit, "--no-pager", "-q", "-o", "short-iso", "--cursor-file", cursorFile, "--lines", fmt.Sprintf("+%d", tail)}
		} else {
			return map[string]any{"ok": false, "error": "cannot check the log cursor", "unit": unit}
		}
		rc, out, errText := s.Run(timeout, argv...)
		text := out
		if text == "" {
			text = errText
		}
		resp := map[string]any{"ok": rc == 0, "unit": unit, "mode": "follow", "cursor_file": filepath.Base(cursorFile), "cmd": strings.Join(argv, " "), "rc": rc, "text": text}
		s.logs.put(key, resp)
		return resp
	}
	key := fmt.Sprintf("systemd|%s|%d|%d|%s", unit, tail, since, cursor)
	if cached := s.logs.get(key); cached != nil {
		cached["cached"] = true
		return cached
	}
	argv := []string{"journalctl", "-u", unit, "--no-pager", "-q", "-o", "short-iso", "--show-cursor", "--lines", strconv.Itoa(tail)}
	if cursor != "" {
		argv = append(argv, "--after-cursor", cursor)
	} else {
		argv = append(argv, "--since", fmt.Sprintf("-%ds", since))
	}
	rc, out, errText := s.Run(timeout, argv...)
	cursorOut, textOut := "", out
	if out != "" {
		lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
		last := strings.TrimLeft(lines[len(lines)-1], " \t")
		if strings.HasPrefix(last, "-- cursor:") {
			if _, after, ok := strings.Cut(lines[len(lines)-1], ":"); ok {
				cursorOut = strings.TrimSpace(after)
			}
			textOut = strings.Join(lines[:len(lines)-1], "\n")
			if textOut != "" {
				textOut += "\n"
			}
		}
	}
	if textOut == "" {
		textOut = errText
	}
	resp := map[string]any{"ok": rc == 0, "unit": unit, "mode": "tail", "cmd": strings.Join(argv, " "), "rc": rc, "cursor": cursorOut, "text": textOut}
	s.logs.put(key, resp)
	return resp
}

// RecentSystemd is get_recent_systemd_logs; units nil means the defaults.
func (s *State) RecentSystemd(limit int, units []string) map[string]any {
	limit = clamp(limit, 1, RecentMaxLimit)
	var available []string
	for _, u := range s.expandUnits() {
		if s.allowedUnit(u) {
			available = append(available, u)
		}
	}
	available = sortedSet(available)
	availableSet := map[string]bool{}
	for _, u := range available {
		availableSet[u] = true
	}
	excludedDefault := append([]string{}, recentExcludedUnits...)
	sort.Strings(excludedDefault)
	var selected []string
	var requested any
	if units == nil {
		for _, u := range available {
			if !contains(recentExcludedUnits, u) {
				selected = append(selected, u)
			}
		}
	} else {
		req := []string{}
		seen := map[string]bool{}
		for _, raw := range units {
			u := strings.TrimSpace(raw)
			if u == "" || seen[u] {
				continue
			}
			seen[u] = true
			req = append(req, u)
		}
		var invalid []string
		for _, u := range req {
			if !availableSet[u] {
				invalid = append(invalid, u)
			}
		}
		if len(invalid) > 0 {
			sort.Strings(invalid)
			return map[string]any{"ok": false, "error": "one or more units are not monitored", "invalid_units": invalid, "available_units": nonNil(available), "default_excluded_units": excludedDefault}
		}
		requested = req
		for _, u := range available {
			if seen[u] {
				selected = append(selected, u)
			}
		}
	}
	var excluded []string
	for _, u := range available {
		if !contains(selected, u) {
			excluded = append(excluded, u)
		}
	}
	base := map[string]any{
		"units": nonNil(selected), "available_units": nonNil(available), "requested_units": requested,
		"excluded_units": nonNil(excluded), "default_excluded_units": excludedDefault, "limit": limit,
	}
	if len(selected) == 0 {
		base["ok"] = true
		base["items"] = []any{}
		return base
	}
	key := fmt.Sprintf("systemd_recent|%s|%d", strings.Join(selected, ","), limit)
	if cached := s.logs.get(key); cached != nil {
		cached["cached"] = true
		return cached
	}
	argv := []string{"journalctl"}
	for _, u := range selected {
		argv = append(argv, "-u", u)
	}
	argv = append(argv, "--no-pager", "-q", "-o", "json", "--lines", strconv.Itoa(limit), "--reverse")
	rc, out, errText := s.Run(time.Duration(logsCmdTimeout)*time.Second, argv...)
	items := []any{}
	if rc == 0 {
		for _, line := range strings.Split(out, "\n") {
			var rec map[string]any
			if json.Unmarshal([]byte(line), &rec) != nil {
				continue
			}
			message, ok := rec["MESSAGE"].(string)
			if !ok {
				raw, _ := json.Marshal(rec["MESSAGE"])
				message = string(raw)
			}
			if len([]rune(message)) > 4000 {
				message = string([]rune(message)[:4000])
			}
			ts := ""
			if us, err := strconv.ParseInt(fmt.Sprint(rec["__REALTIME_TIMESTAMP"]), 10, 64); err == nil {
				ts = time.UnixMicro(us).UTC().Format("2006-01-02T15:04:05+00:00")
			}
			var priority any
			if p, err := strconv.Atoi(fmt.Sprint(rec["PRIORITY"])); err == nil {
				priority = p
			}
			unit := "systemd"
			for _, k := range []string{"_SYSTEMD_UNIT", "UNIT", "OBJECT_SYSTEMD_UNIT", "SYSLOG_IDENTIFIER"} {
				if v, ok := rec[k].(string); ok && v != "" {
					unit = v
					break
				}
			}
			items = append(items, map[string]any{"ts_utc": ts, "unit": unit, "raw_message": message, "priority": priority})
		}
	}
	base["ok"] = rc == 0
	base["items"] = items
	base["cmd"] = strings.Join(argv, " ")
	base["rc"] = rc
	if rc == 0 {
		base["error"] = ""
	} else if e := strings.TrimSpace(errText); e != "" {
		base["error"] = e
	} else {
		base["error"] = "journalctl failed"
	}
	s.logs.put(key, base)
	return base
}

// LogsDocker is get_logs_docker.
func (s *State) LogsDocker(container string, tail, since int) map[string]any {
	if !s.allowedContainer(container) {
		return map[string]any{"ok": false, "error": "container is not allowed", "container": container}
	}
	tail = clamp(tail, 10, s.Cfg.LogsMaxTail)
	since = clamp(since, 60, s.Cfg.LogsMaxSinceSeconds)
	key := fmt.Sprintf("docker|%s|%d|%d", container, tail, since)
	if cached := s.logs.get(key); cached != nil {
		cached["cached"] = true
		return cached
	}
	argv := []string{"docker", "logs", "--since", fmt.Sprintf("%ds", since), "--tail", strconv.Itoa(tail), container}
	rc, out, errText := s.Run(time.Duration(logsCmdTimeout)*time.Second, argv...)
	text := out
	if text == "" {
		text = errText
	}
	resp := map[string]any{"ok": rc == 0, "container": container, "cmd": strings.Join(argv, " "), "rc": rc, "text": text}
	s.logs.put(key, resp)
	return resp
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// ttlCache is _TTLCache: a small LRU of recent log answers.
type ttlCache struct {
	ttl     time.Duration
	max     int
	maxVal  int
	mu      sync.Mutex
	order   []string
	entries map[string]ttlEntry
}

type ttlEntry struct {
	at  time.Time
	val map[string]any
}

func newTTLCache(ttlSeconds float64, maxEntries, maxValue int) *ttlCache {
	return &ttlCache{ttl: time.Duration(ttlSeconds * float64(time.Second)), max: maxEntries, maxVal: maxValue, entries: map[string]ttlEntry{}}
}

func (c *ttlCache) get(key string) map[string]any {
	if c.ttl <= 0 || c.max <= 0 {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return nil
	}
	if time.Since(e.at) > c.ttl {
		delete(c.entries, key)
		if i := slices.Index(c.order, key); i >= 0 {
			c.order = slices.Delete(c.order, i, i+1)
		}
		return nil
	}
	out := map[string]any{}
	for k, v := range e.val {
		out[k] = v
	}
	return out
}

func (c *ttlCache) put(key string, val map[string]any) {
	if c.ttl <= 0 || c.max <= 0 {
		return
	}
	raw, err := json.Marshal(val)
	if err != nil || (c.maxVal > 0 && len(raw) > c.maxVal) {
		return
	}
	cp := map[string]any{}
	for k, v := range val {
		cp[k] = v
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.entries[key]; !ok {
		c.order = append(c.order, key)
	}
	c.entries[key] = ttlEntry{at: time.Now(), val: cp}
	for len(c.entries) > c.max && len(c.order) > 0 {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.entries, oldest)
	}
}
