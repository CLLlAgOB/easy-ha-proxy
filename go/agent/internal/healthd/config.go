// Package healthd implements the systemd/Docker health & control monitor
// inside the unified easy-ha-proxy-agent binary.
package healthd

import (
	"encoding/json"
	"os"
	"strings"
)

const (
	DefaultSocketPath = "/run/easy-ha-proxy/haproxy-healthd.sock"
	DefaultConfigPath = "/opt/haproxy-admin/healthd.json"
	DefaultHealthUnit = "haproxy-healthd.service"
)

// Config mirrors haproxy-healthd.py's HealthdConfig.
type Config struct {
	SystemdUnits           []string `json:"systemd_units"`
	SystemdUnitGlobs       []string `json:"systemd_unit_globs"`
	DockerContainers       []string `json:"docker_containers"`
	PollIntervalSeconds    int      `json:"poll_interval_seconds"`
	EventsMax              int      `json:"events_max"`
	CacheTTLSeconds        int      `json:"cache_ttl_seconds"`
	UnitsRescanSeconds     int      `json:"units_rescan_seconds"`
	LogsDefaultTail        int      `json:"logs_default_tail"`
	LogsMaxTail            int      `json:"logs_max_tail"`
	LogsDefaultSinceSecond int      `json:"logs_default_since_seconds"`
	LogsMaxSinceSeconds    int      `json:"logs_max_since_seconds"`
}

// DefaultConfig returns safe defaults matching haproxy-healthd.py.
func DefaultConfig() Config {
	return Config{
		SystemdUnits: []string{
			"haproxy.service",
			"haproxy-certd.service",
			"haproxy-controld.service",
			"haproxy-healthd.service",
			"easy-ha-proxy-guardd.service",
			"easy-ha-proxy-metricsd.service",
			"easy-ha-proxy-alertd.service",
			"easy-ha-proxy-backupd.service",
			"easy-ha-proxy-updated.service",
		},
		SystemdUnitGlobs:       []string{"authelia-*.service"},
		DockerContainers:       []string{"haproxy-admin", "authelia", "authelia-redis"},
		PollIntervalSeconds:    15,
		EventsMax:              200,
		CacheTTLSeconds:        5,
		UnitsRescanSeconds:     300,
		LogsDefaultTail:        150,
		LogsMaxTail:            2000,
		LogsDefaultSinceSecond: 3600,
		LogsMaxSinceSeconds:    7 * 86400,
	}
}

// LoadConfig reads healthd.json, falling back to safe defaults on error.
func LoadConfig(path string) Config {
	cfg := DefaultConfig()
	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg
	}
	var parsed Config
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return cfg
	}
	if len(parsed.SystemdUnits) > 0 {
		cfg.SystemdUnits = cleanStrings(parsed.SystemdUnits)
	}
	if parsed.SystemdUnitGlobs != nil {
		cfg.SystemdUnitGlobs = cleanStrings(parsed.SystemdUnitGlobs)
	}
	if parsed.DockerContainers != nil {
		cfg.DockerContainers = cleanStrings(parsed.DockerContainers)
	}
	cfg.PollIntervalSeconds = clampInt(parsed.PollIntervalSeconds, cfg.PollIntervalSeconds, 5, 300)
	cfg.EventsMax = clampInt(parsed.EventsMax, cfg.EventsMax, 20, 5000)
	if parsed.CacheTTLSeconds >= 0 && parsed.CacheTTLSeconds <= 300 {
		cfg.CacheTTLSeconds = parsed.CacheTTLSeconds
	}
	cfg.UnitsRescanSeconds = clampInt(parsed.UnitsRescanSeconds, cfg.UnitsRescanSeconds, 30, 3600)
	cfg.LogsDefaultTail = clampInt(parsed.LogsDefaultTail, cfg.LogsDefaultTail, 10, 5000)
	cfg.LogsMaxTail = clampInt(parsed.LogsMaxTail, cfg.LogsMaxTail, 50, 10000)
	cfg.LogsDefaultSinceSecond = clampInt(parsed.LogsDefaultSinceSecond, cfg.LogsDefaultSinceSecond, 60, 30*86400)
	cfg.LogsMaxSinceSeconds = clampInt(parsed.LogsMaxSinceSeconds, cfg.LogsMaxSinceSeconds, 300, 90*86400)
	return cfg
}

func cleanStrings(items []string) []string {
	out := make([]string, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, s := range items {
		t := strings.TrimSpace(s)
		if t == "" {
			continue
		}
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	return out
}

func clampInt(val, fallback, minV, maxV int) int {
	if val == 0 {
		return fallback
	}
	if val < minV {
		return minV
	}
	if val > maxV {
		return maxV
	}
	return val
}
