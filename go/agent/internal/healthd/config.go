// Package healthd is a port of haproxy-healthd.py: the state of systemd units
// and Docker containers, their logs, a state-change feed, a guarded control
// API and the per-site availability alerts.
package healthd

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	DefaultSocketPath = "/run/easy-ha-proxy/haproxy-healthd.sock"
	DefaultConfigPath = "/opt/haproxy-admin/healthd.json"
	DefaultHealthUnit = "haproxy-healthd.service"
)

// Config is HealthdConfig: the same keys, defaults and limits as Python.
type Config struct {
	SystemdUnits            []string
	SystemdUnitGlobs        []string
	DockerContainers        []string
	PollIntervalSeconds     int
	EventsMax               int
	CacheTTLSeconds         int
	UnitsRescanSeconds      int
	LogsDefaultTail         int
	LogsMaxTail             int
	LogsDefaultSinceSeconds int
	LogsMaxSinceSeconds     int
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// pyInt mirrors int(raw.get(key) or default): a missing, null, zero or empty
// value takes the default.
func pyInt(m map[string]any, key string, def int) int {
	v, ok := m[key]
	if !ok || v == nil {
		return def
	}
	switch t := v.(type) {
	case float64:
		if t == 0 {
			return def
		}
		return int(t)
	case string:
		if t == "" {
			return def
		}
		n, err := strconv.Atoi(strings.TrimSpace(t))
		if err != nil {
			return def
		}
		return n
	case bool:
		if !t {
			return def
		}
		return 1
	}
	return def
}

func strList(m map[string]any, key string) []string {
	raw, _ := m[key].([]any)
	out := make([]string, 0, len(raw))
	for _, x := range raw {
		out = append(out, fmt.Sprint(x))
	}
	return out
}

func sub(m map[string]any, key string) map[string]any {
	if v, ok := m[key].(map[string]any); ok {
		return v
	}
	return map[string]any{}
}

// LoadConfig reads healthd.json the way _load_config does.
func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("config not found: %s", path)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return Config{}, err
	}
	systemd, docker, logs := sub(raw, "systemd"), sub(raw, "docker"), sub(raw, "logs")
	cfg := Config{
		SystemdUnits:     strList(systemd, "units"),
		SystemdUnitGlobs: strList(systemd, "unit_globs"),
		DockerContainers: strList(docker, "containers"),
	}
	cfg.PollIntervalSeconds = clamp(pyInt(raw, "poll_interval_seconds", 5), 1, 300)
	cfg.EventsMax = clamp(pyInt(raw, "events_max", 200), 10, 2000)
	cfg.CacheTTLSeconds = clamp(pyInt(raw, "cache_ttl_seconds", 15), 0, 3600)
	cfg.UnitsRescanSeconds = clamp(pyInt(raw, "units_rescan_seconds", 60), 5, 3600)
	cfg.LogsMaxTail = clamp(pyInt(logs, "max_tail", 2000), 50, 20000)
	cfg.LogsDefaultTail = clamp(pyInt(logs, "default_tail", 200), 10, cfg.LogsMaxTail)
	cfg.LogsMaxSinceSeconds = clamp(pyInt(logs, "max_since_seconds", 86400), 300, 7*24*3600)
	cfg.LogsDefaultSinceSeconds = clamp(pyInt(logs, "default_since_seconds", 3600), 60, cfg.LogsMaxSinceSeconds)
	return cfg, nil
}

func unitBase(unit string) string {
	return strings.TrimSuffix(strings.TrimSpace(unit), ".service")
}

// AllowedActions is _control_allowed_actions.
func AllowedActions(kind, name, selfUnit string) []string {
	kind = strings.ToLower(strings.TrimSpace(kind))
	nm := strings.TrimSpace(name)
	switch kind {
	case "docker":
		if nm == "haproxy-admin" || nm == "authelia" || nm == "authelia-redis" {
			return []string{"restart"}
		}
		return []string{"start", "stop", "restart"}
	case "systemd":
		base := unitBase(nm)
		switch {
		case base == "haproxy":
			return []string{"reload", "restart"}
		case strings.HasPrefix(base, "authelia"):
			return []string{"start", "stop", "restart"}
		case base == unitBase(selfUnit):
			return []string{"restart"}
		case base == "easy-ha-proxy-backup":
			return []string{}
		}
		return []string{"start", "stop", "restart"}
	}
	return []string{}
}
