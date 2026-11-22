// Package metricsd implements the HAProxy & host metrics collector inside
// the unified easy-ha-proxy-agent binary.
package metricsd

import (
	"encoding/json"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultSocketPath = "/run/easy-ha-proxy/easy-ha-proxy-metricsd.sock"
	DefaultConfigPath = "/opt/haproxy-admin/metricsd.json"
	MaxRangeSeconds   = 365 * 86400
)

var DefaultExcludeExact = []string{"stats", "be_stats"}
var DefaultExcludePrefix = []string{"_"}

// Config mirrors Python `metricsd.runtime.MetricsConfig`.
type Config struct {
	Enabled                     bool     `json:"enabled"`
	PollIntervalSeconds         int      `json:"poll_interval_seconds"`
	HAProxySocket               string   `json:"haproxy_socket"`
	MaintenanceIntervalSeconds  int      `json:"maintenance_interval_seconds"`
	RetentionOneMinuteDays      int      `json:"retention_one_minute_days"`
	RetentionOneMinuteServerHrs int      `json:"retention_one_minute_server_hours"`
	RetentionOneHourDays        int      `json:"retention_one_hour_days"`
	ExcludeExact                []string `json:"exclude_exact"`
	ExcludePrefix               []string `json:"exclude_prefix"`
	AlertErrorRatioPercent      int      `json:"alert_error_ratio_percent"`
	AlertSlowResponseMS         int      `json:"alert_slow_response_ms"`
	AlertMinRequests            int      `json:"alert_min_requests"`
}

// DefaultConfig returns safe defaults matching Python `metricsd`.
func DefaultConfig() Config {
	return Config{
		Enabled:                     true,
		PollIntervalSeconds:         10,
		HAProxySocket:               "/run/haproxy/admin.sock",
		MaintenanceIntervalSeconds:  300,
		RetentionOneMinuteDays:      7,
		RetentionOneMinuteServerHrs: 24,
		RetentionOneHourDays:        365,
		ExcludeExact:                append([]string(nil), DefaultExcludeExact...),
		ExcludePrefix:               append([]string(nil), DefaultExcludePrefix...),
		AlertErrorRatioPercent:      10,
		AlertSlowResponseMS:         3000,
		AlertMinRequests:            20,
	}
}

// Excluded reports whether a proxy name should be omitted from metrics collection.
func (c Config) Excluded(proxy string) bool {
	if proxy == "" {
		return true
	}
	for _, ex := range c.ExcludeExact {
		if proxy == ex {
			return true
		}
	}
	for _, pref := range c.ExcludePrefix {
		if strings.HasPrefix(proxy, pref) {
			return true
		}
	}
	return false
}

// LoadConfig reads metricsd.json, falling back gracefully to defaults.
func LoadConfig(path string) Config {
	cfg := DefaultConfig()
	rawBytes, err := os.ReadFile(path)
	if err != nil {
		return cfg
	}
	var raw map[string]any
	if err := json.Unmarshal(rawBytes, &raw); err != nil {
		return cfg
	}
	if v, ok := raw["enabled"].(bool); ok {
		cfg.Enabled = v
	}
	cfg.PollIntervalSeconds = clampAny(raw["poll_interval_seconds"], cfg.PollIntervalSeconds, 5, 60)
	if s, ok := raw["haproxy_socket"].(string); ok && strings.TrimSpace(s) != "" {
		cfg.HAProxySocket = strings.TrimSpace(s)
	}
	cfg.MaintenanceIntervalSeconds = clampAny(raw["maintenance_interval_seconds"], cfg.MaintenanceIntervalSeconds, 60, 3600)
	if ret, ok := raw["retention"].(map[string]any); ok {
		cfg.RetentionOneMinuteDays = clampAny(ret["one_minute_days"], cfg.RetentionOneMinuteDays, 1, 90)
		cfg.RetentionOneMinuteServerHrs = clampAny(ret["one_minute_server_hours"], cfg.RetentionOneMinuteServerHrs, 1, 2160)
		cfg.RetentionOneHourDays = clampAny(ret["one_hour_days"], cfg.RetentionOneHourDays, 1, 3650)
	}
	if ex, ok := raw["exclude"].(map[string]any); ok {
		if list := toStringSlice(ex["exact"]); len(list) > 0 {
			cfg.ExcludeExact = list
		}
		if list := toStringSlice(ex["prefix"]); len(list) > 0 {
			cfg.ExcludePrefix = list
		}
	}
	if alerts, ok := raw["alerts"].(map[string]any); ok {
		cfg.AlertErrorRatioPercent = clampAny(alerts["error_ratio_percent"], cfg.AlertErrorRatioPercent, 0, 100)
		cfg.AlertSlowResponseMS = clampAny(alerts["slow_response_ms"], cfg.AlertSlowResponseMS, 0, 600000)
		cfg.AlertMinRequests = clampAny(alerts["min_requests"], cfg.AlertMinRequests, 1, 1000000)
	}
	return cfg
}

// ParseSize parses human byte sizes like "256M", "2G", "512K", or raw integer bytes.
func ParseSize(input string) (uint64, bool) {
	s := strings.ToUpper(strings.TrimSpace(input))
	if s == "" {
		return 0, false
	}
	mult := uint64(1)
	switch {
	case strings.HasSuffix(s, "G") || strings.HasSuffix(s, "GB") || strings.HasSuffix(s, "GIB"):
		mult = 1024 * 1024 * 1024
		s = strings.TrimRight(s, "GIB")
	case strings.HasSuffix(s, "M") || strings.HasSuffix(s, "MB") || strings.HasSuffix(s, "MIB"):
		mult = 1024 * 1024
		s = strings.TrimRight(s, "MIB")
	case strings.HasSuffix(s, "K") || strings.HasSuffix(s, "KB") || strings.HasSuffix(s, "KIB"):
		mult = 1024
		s = strings.TrimRight(s, "KIB")
	case strings.HasSuffix(s, "B"):
		s = strings.TrimSuffix(s, "B")
	}
	val, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || val <= 0 {
		return 0, false
	}
	return uint64(val * float64(mult)), true
}

var rangePresets = map[string]int64{
	"1h":  3600,
	"6h":  6 * 3600,
	"24h": 24 * 3600,
	"7d":  7 * 86400,
	"30d": 30 * 86400,
	"90d": 90 * 86400,
	"1y":  365 * 86400,
}

// ResolveWindow mirrors Python `metricsd.constants.resolve_window`, preferring
// explicit (since, until) over preset range keys.
func ResolveWindow(query url.Values, now int64) (rangeKey string, since int64, until int64) {
	if now <= 0 {
		now = time.Now().Unix()
	}
	sRaw := strings.TrimSpace(query.Get("since"))
	uRaw := strings.TrimSpace(query.Get("until"))
	if sRaw != "" && uRaw != "" {
		sVal, sErr := strconv.ParseInt(sRaw, 10, 64)
		uVal, uErr := strconv.ParseInt(uRaw, 10, 64)
		if sErr == nil && uErr == nil && sVal > 0 && uVal > sVal {
			if uVal-sVal > MaxRangeSeconds {
				sVal = uVal - MaxRangeSeconds
			}
			return "custom", sVal, uVal
		}
	}
	key := strings.ToLower(strings.TrimSpace(query.Get("range")))
	span, ok := rangePresets[key]
	if !ok {
		key = "24h"
		span = rangePresets[key]
	}
	return key, now - span, now
}

func clampAny(val any, fallback, minV, maxV int) int {
	var parsed int
	switch t := val.(type) {
	case float64:
		parsed = int(t)
	case int:
		parsed = t
	case string:
		p, err := strconv.Atoi(strings.TrimSpace(t))
		if err != nil {
			return fallback
		}
		parsed = p
	default:
		return fallback
	}
	if parsed < minV {
		return minV
	}
	if parsed > maxV {
		return maxV
	}
	return parsed
}

func toStringSlice(val any) []string {
	arr, ok := val.([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, item := range arr {
		if s, ok := item.(string); ok {
			if t := strings.TrimSpace(s); t != "" {
				out = append(out, t)
			}
		}
	}
	return out
}
