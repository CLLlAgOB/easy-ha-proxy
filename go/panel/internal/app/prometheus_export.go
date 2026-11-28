package app

// Port of routes_prometheus.py, services_prometheus.py and
// services_prometheus_sources.py: the optional /metrics exposition.

import (
	"crypto/subtle"
	"fmt"
	"log"
	"math"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// What Flask actually sends: Response(mimetype=CONTENT_TYPE) appends a
// charset to a type that already names one.
const promContentType = "text/plain; version=0.0.4; charset=utf-8; charset=utf-8"

var promLabelUnsafe = regexp.MustCompile(`[\\"\n\r]`)

func promLabel(v any) string {
	return truncRunes(promLabelUnsafe.ReplaceAllString(strOrEmpty(v), ""), 120)
}

// promNumber is _number: float(value), or false for what float() refuses
// and for NaN and the infinities.
func promNumber(v any) (float64, bool) {
	if v == nil {
		return 0, false
	}
	f, err := pyFloatStrict(v)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
}

// pyFormatG is format(number, "g").
func pyFormatG(f float64) string {
	s := strconv.FormatFloat(f, 'g', 6, 64)
	if mant, exp, found := strings.Cut(s, "e"); found {
		sign := exp[:1]
		digits := strings.TrimLeft(exp[1:], "0")
		if len(digits) < 2 {
			digits = strings.Repeat("0", 2-len(digits)) + digits
		}
		return mant + "e" + sign + digits
	}
	return s
}

type promSample struct {
	labels map[string]string
	value  any
}

type promExposition struct {
	families []string
}

func (e *promExposition) family(name, kind, help string, samples []promSample) {
	var rows []string
	for _, s := range samples {
		n, ok := promNumber(s.value)
		if !ok {
			continue
		}
		if len(s.labels) > 0 {
			keys := make([]string, 0, len(s.labels))
			for k := range s.labels {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			parts := make([]string, len(keys))
			for i, k := range keys {
				parts[i] = fmt.Sprintf(`%s="%s"`, k, promLabel(s.labels[k]))
			}
			rows = append(rows, fmt.Sprintf("%s{%s} %s", name, strings.Join(parts, ","), pyFormatG(n)))
		} else {
			rows = append(rows, name+" "+pyFormatG(n))
		}
	}
	if len(rows) == 0 {
		return
	}
	e.families = append(e.families, fmt.Sprintf("# HELP %s %s\n# TYPE %s %s\n", name, help, name, kind)+strings.Join(rows, "\n"))
}

func one(v any) []promSample { return []promSample{{nil, v}} }

func labelled(key string, m *Map) []promSample {
	type kv struct {
		k string
		v any
	}
	var items []kv
	if m != nil {
		m.Each(func(k, v any) { items = append(items, kv{pyStr(k), v}) })
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].k < items[j].k })
	out := make([]promSample, len(items))
	for i, it := range items {
		out[i] = promSample{map[string]string{key: promLabel(it.k)}, it.v}
	}
	return out
}

func flag(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// The sources, as services_prometheus_sources.readers().
func promHAProxy() (any, error) { return newMap("backends", listRuntimeBackends()), nil }

func promStorage() (any, error) {
	v, err := metricsdTransport().Get("/api/v1/metrics/storage", HTTPOptions{Timeout: 10 * time.Second})
	if err != nil {
		return nil, err
	}
	m, ok := asMap(v)
	if !ok {
		return nil, noAttr(v, "get")
	}
	if inner, ok := asMap(m.Value("storage")); ok {
		return inner, nil
	}
	return m, nil
}

func promGuard() (any, error) { return guarddGetAny("/api/v1/guard/health", nil, 15*time.Second) }

func promAlerts() (any, error) { return alertdGet("/api/v1/alerts/health", nil, 15*time.Second) }

func promCertificates() (any, error) {
	_, sites, err := SitesAndDefaultsForUI()
	if err != nil {
		return nil, err
	}
	var domains []string
	for _, item := range sites {
		eff := asMapOr(orValue(get(item, "effective"), newMap()))
		domain := pyStripSpace(strOrEmpty(orValue(eff.Value("domain"), eff.Value("name"))))
		if domain != "" && !truthy(eff.Value("tcp_passthrough")) {
			domains = append(domains, domain)
		}
	}
	days := newMap()
	CertdStatusForDomains(domains).Each(func(domain, status any) {
		remaining := get(status, "haproxy_days_left")
		if remaining == nil {
			remaining = get(status, "le_days_left")
		}
		if remaining != nil {
			days.Set(domain, remaining)
		}
	})
	return newMap("days", days), nil
}

func promJobs() (any, error) {
	lastSuccess, lastFailed := newMap(), newMap()
	absorb := func(kind string, payload *Map) {
		job, ok := asMap(orValue(payload.Value("job"), payload.Value("last_job"), newMap()))
		if !ok {
			return
		}
		status := strings.ToLower(strOrEmpty(job.Value("status")))
		lastFailed.Set(kind, status == "failed")
		if status == "completed" {
			if completed := job.Value("completed_at"); completed != nil {
				lastSuccess.Set(kind, completed)
			}
		}
	}
	backup, err := JSONLineRequest(backupdSocketPath(),
		newMap("action", "status"), "full-backup", 5*time.Second, 64*1024, 4*1024*1024)
	if err != nil {
		return nil, err
	}
	absorb("backup", backup)
	update, err := JSONLineRequest(updatedSocketPath(),
		newMap("action", "status"), "software-update", 10*time.Second, 64*1024, 4*1024*1024)
	if err != nil {
		return nil, err
	}
	absorb("update", update)
	return newMap("last_success", lastSuccess, "last_failed", lastFailed), nil
}

// promCollect is collect(): never fails, a scrape is not worth a 500.
func promCollect() string {
	exp := &promExposition{}
	var availability []promSample
	read := func(name string, f func() (any, error)) *Map {
		payload, err := f()
		if err != nil {
			availability = append(availability, promSample{map[string]string{"source": name}, int64(0)})
			return nil
		}
		availability = append(availability, promSample{map[string]string{"source": name}, int64(1)})
		m, _ := asMap(payload)
		return m
	}
	exp.family("easy_ha_proxy_build_info", "gauge", "Always 1; present so a scrape can be distinguished from an empty target.", one(int64(1)))

	if haproxy := read("haproxy", promHAProxy); haproxy != nil {
		var total, healthy, sessions []promSample
		for _, entry := range listOf(haproxy, "backends") {
			m, ok := asMap(entry)
			if !ok || !truthy(m.Value("backend")) {
				continue
			}
			labels := map[string]string{"backend": promLabel(m.Value("backend"))}
			var servers []*Map
			for _, s := range listOf(m, "servers") {
				if sm, ok := asMap(s); ok {
					servers = append(servers, sm)
				}
			}
			var up, sess int64
			for _, s := range servers {
				st := strings.ToUpper(strOrEmpty(s.Value("status")))
				if strings.HasPrefix(st, "UP") || strings.HasPrefix(st, "NO CHECK") {
					up++
				}
				n, _ := intOr0(s.Value("sessions"))
				sess += n
			}
			total = append(total, promSample{labels, int64(len(servers))})
			healthy = append(healthy, promSample{labels, up})
			sessions = append(sessions, promSample{labels, sess})
		}
		exp.family("easy_ha_proxy_backend_servers_total", "gauge", "Servers configured in the backend.", total)
		exp.family("easy_ha_proxy_backend_servers_up", "gauge", "Servers currently passing their health check.", healthy)
		exp.family("easy_ha_proxy_backend_sessions", "gauge", "Sessions currently open across the backend's servers.", sessions)
	}

	if storage := read("storage", promStorage); storage != nil {
		current := strings.ToUpper(strOrEmpty(storage.Value("state")))
		var states []promSample
		for _, s := range []string{"NORMAL", "WARNING", "PRESSURE", "CRITICAL"} {
			states = append(states, promSample{map[string]string{"state": s}, flag(s == current)})
		}
		exp.family("easy_ha_proxy_monitoring_storage_state", "gauge", "1 for the storage state the collector is in.", states)
		exp.family("easy_ha_proxy_monitoring_paused", "gauge", "1 while historical monitoring has stopped writing.", one(flag(truthy(storage.Value("writes_paused")))))
		exp.family("easy_ha_proxy_monitoring_database_bytes", "gauge", "Size of the metrics database on disk.", one(storage.Value("total_bytes")))
		exp.family("easy_ha_proxy_monitoring_filesystem_free_bytes", "gauge", "Free space on the filesystem holding the metrics database.", one(storage.Value("filesystem_free_bytes")))
	}

	if guard := read("guard", promGuard); guard != nil {
		database := asMapOr(orValue(guard.Value("database"), newMap()))
		exp.family("easy_ha_proxy_guard_addresses", "gauge", "Addresses the engine is tracking, by state. No address is exposed.",
			labelled("state", asMapOr(orValue(guard.Value("states"), newMap()))))
		bans, found := guard.Get("bans_active")
		if !found {
			bans = database.Value("bans_active")
		}
		exp.family("easy_ha_proxy_guard_bans_active", "gauge", "Bans the engine currently holds.", one(bans))
		exp.family("easy_ha_proxy_guard_events_total", "counter", "Security events recorded since the database was created.", one(database.Value("events")))
		exp.family("easy_ha_proxy_guard_enforcing", "gauge", "1 when the engine is allowed to ban, 0 while it only observes.",
			one(flag(strOrEmpty(guard.Value("mode")) == "enforce")))
	}

	if alerts := read("alerts", promAlerts); alerts != nil {
		exp.family("easy_ha_proxy_alerts_firing", "gauge", "Alerts currently firing.", one(alerts.Value("firing")))
		exp.family("easy_ha_proxy_alerts_pending", "gauge", "Conditions observed but still inside their trigger delay.", one(alerts.Value("pending")))
		channels := labelled("channel", asMapOr(orValue(alerts.Value("channels"), newMap())))
		for i := range channels {
			channels[i].value = flag(truthy(channels[i].value))
		}
		exp.family("easy_ha_proxy_alert_channel_ready", "gauge", "1 when a notification channel is configured and usable.", channels)
	}

	if certs := read("certificates", promCertificates); certs != nil {
		exp.family("easy_ha_proxy_certificate_days_remaining", "gauge", "Days until the installed certificate expires; negative once expired.",
			labelled("domain", asMapOr(orValue(certs.Value("days"), newMap()))))
	}

	if jobs := read("jobs", promJobs); jobs != nil {
		exp.family("easy_ha_proxy_job_last_success_timestamp_seconds", "gauge", "When each kind of job last completed successfully.",
			labelled("job", asMapOr(orValue(jobs.Value("last_success"), newMap()))))
		failed := labelled("job", asMapOr(orValue(jobs.Value("last_failed"), newMap())))
		for i := range failed {
			failed[i].value = flag(truthy(failed[i].value))
		}
		exp.family("easy_ha_proxy_job_last_failed", "gauge", "1 when the most recent job of that kind failed.", failed)
	}

	exp.family("easy_ha_proxy_source_up", "gauge", "1 when the daemon behind a group of metrics answered this scrape.", availability)
	exp.family("easy_ha_proxy_scrape_timestamp_seconds", "gauge", "When this exposition was built.", one(time.Now().Unix()))
	return strings.Join(exp.families, "\n") + "\n"
}

func metricsEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("METRICS_EXPORT_ENABLED"))) {
	case "1", "true", "yes":
		return true
	}
	return false
}

func (c *Ctx) metricsTokenOK() bool {
	expected := strings.TrimSpace(os.Getenv("METRICS_EXPORT_TOKEN"))
	if expected == "" {
		return false
	}
	scheme, supplied, _ := strings.Cut(c.R.Header.Get("Authorization"), " ")
	if strings.ToLower(scheme) != "bearer" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(pyStripSpace(supplied)), []byte(expected)) == 1
}

func (a *App) registerPrometheus() {
	a.Handle("routes.prometheus_metrics", func(c *Ctx) error {
		// A 404 while disabled: a switched-off endpoint does not confirm itself.
		if !metricsEnabled() {
			return c.Text(404, "text/plain; charset=utf-8", "")
		}
		if !c.metricsTokenOK() {
			c.W.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
			return c.Text(401, "text/plain; charset=utf-8", "")
		}
		var body string
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("prometheus exposition failed: %v", r)
					body = ""
				}
			}()
			body = promCollect()
		}()
		if body == "" {
			return c.Text(503, "text/plain; charset=utf-8", "")
		}
		c.W.Header().Set("Cache-Control", "no-store")
		return c.Text(200, promContentType, body)
	})
}
