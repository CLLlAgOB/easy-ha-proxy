// Package prometheus renders the optional /metrics exposition with 100% metric
// and dual-gate auth parity to routes_prometheus.py and services_prometheus.py.
package prometheus

import (
	"context"
	"crypto/subtle"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"easy-ha-proxy/panel/internal/daemons"
	"easy-ha-proxy/panel/internal/haproxy"
)

const (
	ContentType    = "text/plain; version=0.0.4; charset=utf-8"
	MaxLabelChars  = 120
)

var labelUnsafeRe = regexp.MustCompile(`[\\"\n\r]`)

func sanitizeLabel(v string) string {
	clean := labelUnsafeRe.ReplaceAllString(v, "")
	if len(clean) > MaxLabelChars {
		return clean[:MaxLabelChars]
	}
	return clean
}

// Sample represents one Prometheus metric sample.
type Sample struct {
	Labels map[string]string
	Value  float64
	Valid  bool
}

func numSample(labels map[string]string, v any) Sample {
	f, ok := toFloat(v)
	return Sample{Labels: labels, Value: f, Valid: ok}
}

func toFloat(v any) (float64, bool) {
	var f float64
	switch x := v.(type) {
	case float64:
		f = x
	case float32:
		f = float64(x)
	case int:
		f = float64(x)
	case int64:
		f = float64(x)
	case uint64:
		f = float64(x)
	case string:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		if err != nil {
			return 0, false
		}
		f = parsed
	default:
		return 0, false
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
}

// Exposition accumulates Prometheus metric families in deterministic order.
type Exposition struct {
	families []string
	seen     map[string]struct{}
}

// NewExposition creates an empty Exposition builder.
func NewExposition() *Exposition {
	return &Exposition{seen: make(map[string]struct{})}
}

// Family appends one metric family if it has at least one valid sample.
func (e *Exposition) Family(name, kind, help string, samples []Sample) {
	var rows []string
	for _, s := range samples {
		if !s.Valid || math.IsNaN(s.Value) || math.IsInf(s.Value, 0) {
			continue
		}
		val := strconv.FormatFloat(s.Value, 'g', -1, 64)
		if len(s.Labels) == 0 {
			rows = append(rows, fmt.Sprintf("%s %s", name, val))
			continue
		}
		keys := make([]string, 0, len(s.Labels))
		for k := range s.Labels {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf(`%s="%s"`, k, sanitizeLabel(s.Labels[k])))
		}
		rows = append(rows, fmt.Sprintf("%s{%s} %s", name, strings.Join(parts, ","), val))
	}
	if len(rows) == 0 {
		return
	}
	if _, dup := e.seen[name]; dup {
		return
	}
	e.seen[name] = struct{}{}
	e.families = append(e.families, fmt.Sprintf("# HELP %s %s\n# TYPE %s %s\n%s", name, help, name, kind, strings.Join(rows, "\n")))
}

// Render returns the complete Prometheus text payload.
func (e *Exposition) Render() string {
	return strings.Join(e.families, "\n") + "\n"
}

// Collector gathers metrics from host daemons and HAProxy runtime.
type Collector struct {
	Enabled bool
	Token   string
	Pool    *daemons.Pool
	Runtime *haproxy.Runtime
	Now     func() time.Time
}

// ServeHTTP serves GET /metrics with the two-lock check (enabled + Bearer token).
func (c *Collector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !c.Enabled {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if !c.tokenOK(r) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	body := c.Collect(r.Context())
	w.Header().Set("Content-Type", ContentType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(body))
}

func (c *Collector) tokenOK(r *http.Request) bool {
	expected := strings.TrimSpace(c.Token)
	if expected == "" {
		return false
	}
	auth := r.Header.Get("Authorization")
	scheme, supplied, ok := strings.Cut(auth, " ")
	if !ok || !strings.EqualFold(scheme, "bearer") {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(supplied)), []byte(expected)) == 1
}

// Collect builds the Prometheus exposition text across all available sources.
func (c *Collector) Collect(ctx context.Context) string {
	exp := NewExposition()
	var availability []Sample

	exp.Family(
		"easy_ha_proxy_build_info",
		"gauge",
		"Always 1; present so a scrape can be distinguished from an empty target.",
		[]Sample{{Value: 1, Valid: true}},
	)

	// 1. HAProxy backend health.
	if c.Runtime != nil {
		backends, err := c.Runtime.ListBackends(ctx)
		if err != nil {
			availability = append(availability, Sample{Labels: map[string]string{"source": "haproxy"}, Value: 0, Valid: true})
		} else {
			availability = append(availability, Sample{Labels: map[string]string{"source": "haproxy"}, Value: 1, Valid: true})
			var total, healthy, sessions []Sample
			for _, be := range backends {
				labels := map[string]string{"backend": sanitizeLabel(be.Backend)}
				up := 0
				sess := 0
				for _, srv := range be.Servers {
					st := strings.ToUpper(srv.Status)
					if strings.HasPrefix(st, "UP") || strings.HasPrefix(st, "NO CHECK") {
						up++
					}
					sess += srv.Sessions
				}
				total = append(total, Sample{Labels: labels, Value: float64(len(be.Servers)), Valid: true})
				healthy = append(healthy, Sample{Labels: labels, Value: float64(up), Valid: true})
				sessions = append(sessions, Sample{Labels: labels, Value: float64(sess), Valid: true})
			}
			exp.Family("easy_ha_proxy_backend_servers_total", "gauge", "Servers configured in the backend.", total)
			exp.Family("easy_ha_proxy_backend_servers_up", "gauge", "Servers currently passing their health check.", healthy)
			exp.Family("easy_ha_proxy_backend_sessions", "gauge", "Sessions currently open across the backend's servers.", sessions)
		}
	}

	// 2. Monitoring storage (metricsd).
	if c.Pool != nil && c.Pool.Metricsd != nil {
		storage, _, err := c.Pool.Metricsd.GetJSON(ctx, "/api/v1/metrics/storage", daemons.RequestOptions{
			Timeout:     5 * time.Second,
			CheckStatus: true,
		})
		if err != nil {
			availability = append(availability, Sample{Labels: map[string]string{"source": "storage"}, Value: 0, Valid: true})
		} else {
			availability = append(availability, Sample{Labels: map[string]string{"source": "storage"}, Value: 1, Valid: true})
			current := strings.ToUpper(asString(storage["state"]))
			var stateSamples []Sample
			for _, st := range []string{"NORMAL", "WARNING", "PRESSURE", "CRITICAL"} {
				v := 0.0
				if st == current {
					v = 1.0
				}
				stateSamples = append(stateSamples, Sample{Labels: map[string]string{"state": st}, Value: v, Valid: true})
			}
			exp.Family("easy_ha_proxy_monitoring_storage_state", "gauge", "1 for the storage state the collector is in.", stateSamples)
			paused := 0.0
			if asBool(storage["writes_paused"]) {
				paused = 1.0
			}
			exp.Family("easy_ha_proxy_monitoring_paused", "gauge", "1 while historical monitoring has stopped writing.", []Sample{{Value: paused, Valid: true}})
			exp.Family("easy_ha_proxy_monitoring_database_bytes", "gauge", "Size of the metrics database on disk.", []Sample{numSample(nil, storage["total_bytes"])})
			exp.Family("easy_ha_proxy_monitoring_filesystem_free_bytes", "gauge", "Free space on the filesystem holding the metrics database.", []Sample{numSample(nil, storage["filesystem_free_bytes"])})
		}
	}

	// 3. Adaptive protection (guardd).
	if c.Pool != nil && c.Pool.Guardd != nil {
		guard, _, err := c.Pool.Guardd.GetJSON(ctx, "/api/v1/guard/health", daemons.RequestOptions{
			Timeout:     5 * time.Second,
			CheckStatus: true,
		})
		if err != nil {
			availability = append(availability, Sample{Labels: map[string]string{"source": "guard"}, Value: 0, Valid: true})
		} else {
			availability = append(availability, Sample{Labels: map[string]string{"source": "guard"}, Value: 1, Valid: true})
			db, _ := guard["database"].(map[string]any)
			if states, ok := guard["states"].(map[string]any); ok {
				keys := make([]string, 0, len(states))
				for k := range states {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				var s []Sample
				for _, k := range keys {
					s = append(s, numSample(map[string]string{"state": sanitizeLabel(k)}, states[k]))
				}
				exp.Family("easy_ha_proxy_guard_addresses", "gauge", "Addresses the engine is tracking, by state. No address is exposed.", s)
			}
			bansActive := guard["bans_active"]
			if bansActive == nil && db != nil {
				bansActive = db["bans_active"]
			}
			exp.Family("easy_ha_proxy_guard_bans_active", "gauge", "Bans the engine currently holds.", []Sample{numSample(nil, bansActive)})
			if db != nil {
				exp.Family("easy_ha_proxy_guard_events_total", "counter", "Security events recorded since the database was created.", []Sample{numSample(nil, db["events"])})
			}
			enforcing := 0.0
			if asString(guard["mode"]) == "enforce" {
				enforcing = 1.0
			}
			exp.Family("easy_ha_proxy_guard_enforcing", "gauge", "1 when the engine is allowed to ban, 0 while it only observes.", []Sample{{Value: enforcing, Valid: true}})
		}
	}

	// 4. Alerts (alertd).
	if c.Pool != nil && c.Pool.Alertd != nil {
		alerts, _, err := c.Pool.Alertd.GetJSON(ctx, "/api/v1/alerts/health", daemons.RequestOptions{
			Timeout:     5 * time.Second,
			CheckStatus: true,
		})
		if err != nil {
			availability = append(availability, Sample{Labels: map[string]string{"source": "alerts"}, Value: 0, Valid: true})
		} else {
			availability = append(availability, Sample{Labels: map[string]string{"source": "alerts"}, Value: 1, Valid: true})
			exp.Family("easy_ha_proxy_alerts_firing", "gauge", "Alerts currently firing.", []Sample{numSample(nil, alerts["firing"])})
			exp.Family("easy_ha_proxy_alerts_pending", "gauge", "Conditions observed but still inside their trigger delay.", []Sample{numSample(nil, alerts["pending"])})
			if chans, ok := alerts["channels"].(map[string]any); ok {
				keys := make([]string, 0, len(chans))
				for k := range chans {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				var s []Sample
				for _, k := range keys {
					v := 0.0
					if asBool(chans[k]) {
						v = 1.0
					}
					s = append(s, Sample{Labels: map[string]string{"channel": sanitizeLabel(k)}, Value: v, Valid: true})
				}
				exp.Family("easy_ha_proxy_alert_channel_ready", "gauge", "1 when a notification channel is configured and usable.", s)
			}
		}
	}

	exp.Family("easy_ha_proxy_source_up", "gauge", "1 when the daemon behind a group of metrics answered this scrape.", availability)
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	exp.Family("easy_ha_proxy_scrape_timestamp_seconds", "gauge", "When this exposition was built.", []Sample{{Value: float64(now().Unix()), Valid: true}})
	return exp.Render()
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func asBool(v any) bool {
	b, _ := v.(bool)
	return b
}
