package metricsd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"easy-ha-proxy/panel/shared/pyyaml"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/alerts"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/unixrpc"
)

// Server serves the read API over the Unix socket.
type Server struct {
	Collector *Collector
	DB        *Database
}

func (s *Server) sendJSON(w http.ResponseWriter, code int, payload any) {
	body, err := pyyaml.JSONDumps(payload, false, false)
	if err != nil {
		body, _ = pyyaml.JSONDumps(omap("ok", false, "error", err.Error()), false, false)
		code = 500
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(code)
	_, _ = io.WriteString(w, body)
}

func (s *Server) site(query url.Values) (string, error) {
	requested := ""
	if v := query["site"]; len(v) > 0 {
		requested = strings.TrimSpace(v[0])
	}
	if requested == "" || strings.ToLower(requested) == "all" {
		return "", nil
	}
	sites, err := s.DB.sites()
	if err != nil {
		return "", err
	}
	for _, e := range sites {
		if e.(*OMap).Value("proxy") == requested {
			return requested, nil
		}
	}
	return "", nil
}

func orderedMonitors(m map[string]bool) *OMap {
	out := NewOMap()
	for _, n := range append(append([]string{}, gatheredMonitors...), shownMonitors...) {
		out.Set(n, m[n])
	}
	return out
}

func badRequest(msg string) error { return errors.New(msg) }

func readBody(r *http.Request, limit int) ([]byte, error) {
	length, err := strconv.Atoi(strings.TrimSpace(r.Header.Get("Content-Length")))
	if strings.TrimSpace(r.Header.Get("Content-Length")) == "" {
		length, err = 0, nil
	}
	if err != nil {
		return nil, badRequest(fmt.Sprintf("invalid literal for int() with base 10: '%s'", r.Header.Get("Content-Length")))
	}
	if length <= 0 || length > limit {
		return nil, badRequest("invalid Content-Length")
	}
	buf := make([]byte, length)
	n, _ := io.ReadFull(r.Body, buf)
	return []byte(strings.ToValidUTF8(string(buf[:n]), "�")), nil
}

func (s *Server) postChannelLabels(w http.ResponseWriter, r *http.Request) {
	cleaned := NewOMap()
	var hidden any
	err := func() error {
		raw, err := readBody(r, 65536)
		if err != nil {
			return err
		}
		v, err := pyyaml.JSONLoads(raw)
		if err != nil {
			return badRequest(err.Error())
		}
		payload, ok := v.(*pyyaml.Map)
		if !ok {
			return badRequest("payload must be an object")
		}
		labels, ok := payload.Value("labels").(*pyyaml.Map)
		if !ok {
			return badRequest("labels must be an object")
		}
		if labels.Len() > 64 {
			return badRequest("at most 64 labels")
		}
		var lerr error
		labels.Each(func(host, label any) {
			if lerr != nil {
				return
			}
			key := strings.TrimSpace(yamlStr(host))
			text := ""
			if yamlTruthy(label) {
				text = strings.TrimSpace(yamlStr(label))
			}
			if r := []rune(text); len(r) > 60 {
				text = string(r[:60])
			}
			if key == "" || len([]rune(key)) > 255 {
				lerr = badRequest("a host name is missing or too long")
				return
			}
			if text != "" {
				cleaned.Set(key, text)
			}
		})
		if lerr != nil {
			return lerr
		}
		hiddenRaw, present := payload.Get("hidden")
		switch h := hiddenRaw.(type) {
		case nil:
			_ = present
			stored := s.DB.getState(channelHiddenKey, "[]")
			if stored == "" {
				stored = "[]"
			}
			hv, err := pyyaml.JSONLoads([]byte(stored))
			if err != nil {
				return badRequest(err.Error())
			}
			hidden = hv
		case []any:
			if len(h) > 64 {
				return badRequest("at most 64 hidden channels")
			}
			set := map[string]bool{}
			for _, x := range h {
				t := strings.TrimSpace(yamlStr(x))
				if t != "" && len([]rune(t)) <= 255 {
					set[t] = true
				}
			}
			list := make([]string, 0, len(set))
			for k := range set {
				list = append(list, k)
			}
			sort.Strings(list)
			out := make([]any, len(list))
			for i, k := range list {
				out[i] = k
			}
			hidden = out
		default:
			return badRequest("hidden must be a list")
		}
		return nil
	}()
	if err != nil {
		s.sendJSON(w, 400, omap("ok", false, "error", err.Error()))
		return
	}
	labelsText, _ := pyyaml.JSONDumps(cleaned, true, false)
	hiddenText, _ := pyyaml.JSONDumps(hidden, true, false)
	if err := s.DB.setState(channelLabelsKey, labelsText); err != nil {
		s.sendJSON(w, 500, omap("ok", false, "error", err.Error()))
		return
	}
	if err := s.DB.setState(channelHiddenKey, hiddenText); err != nil {
		s.sendJSON(w, 500, omap("ok", false, "error", err.Error()))
		return
	}
	s.sendJSON(w, 200, omap("ok", true, "labels", cleaned, "hidden", hidden))
}

func (s *Server) postMonitors(w http.ResponseWriter, r *http.Request) {
	changes := map[string]bool{}
	err := func() error {
		raw, err := readBody(r, 4096)
		if err != nil {
			return err
		}
		v, err := pyyaml.JSONLoads(raw)
		if err != nil {
			return badRequest(err.Error())
		}
		var obj *pyyaml.Map
		if p, ok := v.(*pyyaml.Map); ok {
			obj, _ = p.Value("monitors").(*pyyaml.Map)
		}
		if obj == nil || obj.Len() == 0 {
			return badRequest("monitors must be a non-empty object")
		}
		defaults := monitorDefaults()
		var verr error
		obj.Each(func(k, val any) {
			if verr != nil {
				return
			}
			name := yamlStr(k)
			if _, ok := defaults[name]; !ok {
				short := name
				if r := []rune(short); len(r) > 40 {
					short = string(r[:40])
				}
				verr = badRequest("unknown monitor: " + short)
				return
			}
			b, ok := val.(bool)
			if !ok {
				verr = badRequest(name + " must be true or false")
				return
			}
			changes[name] = b
		})
		return verr
	}()
	if err != nil {
		s.sendJSON(w, 400, omap("ok", false, "error", err.Error()))
		return
	}
	m, err := s.Collector.setMonitors(changes)
	if err != nil {
		s.sendJSON(w, 500, omap("ok", false, "error", err.Error()))
		return
	}
	s.sendJSON(w, 200, omap("ok", true, "monitors", orderedMonitors(m)))
}

func jsonState(db *Database, key, def string) (any, error) {
	raw := db.getState(key, def)
	if raw == "" {
		raw = def
	}
	return pyyaml.JSONLoads([]byte(raw))
}

// ServeHTTP is MetricsHandler.do_GET / do_POST.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "easy-ha-proxy-metricsd/1.0")
	path := r.URL.Path
	if r.Method == http.MethodPost {
		switch path {
		case "/api/v1/metrics/monitors":
			s.postMonitors(w, r)
		case "/api/v1/metrics/channel-labels":
			s.postChannelLabels(w, r)
		default:
			s.sendJSON(w, 404, omap("ok", false, "error", "unknown path"))
		}
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(501)
		return
	}
	query, _ := url.ParseQuery(r.URL.RawQuery)
	fail := func(err error) { s.sendJSON(w, 500, omap("ok", false, "error", err.Error())) }
	switch path {
	case "/api/v1/metrics/sites":
		sites, err := s.DB.sites()
		if err != nil {
			fail(err)
			return
		}
		s.sendJSON(w, 200, omap("ok", true, "sites", sites))
	case "/api/v1/metrics/series":
		chart := ""
		if v := query["chart"]; len(v) > 0 {
			chart = strings.ToLower(strings.TrimSpace(v[0]))
		}
		if _, ok := chartSeries[chart]; !ok {
			names := make([]string, 0, len(chartSeries))
			for k := range chartSeries {
				names = append(names, k)
			}
			sort.Strings(names)
			avail := make([]any, len(names))
			for i, n := range names {
				avail[i] = n
			}
			s.sendJSON(w, 400, omap("ok", false, "error", "unknown chart", "available", avail))
			return
		}
		key, since, until := resolveWindow(query)
		wanted := "1"
		if v := query["components"]; len(v) > 0 && v[0] != "" {
			wanted = v[0]
		}
		wanted = strings.ToLower(strings.TrimSpace(wanted))
		site, err := s.site(query)
		if err != nil {
			fail(err)
			return
		}
		payload, err := s.DB.series(chart, site, since, until, wanted != "0" && wanted != "false" && wanted != "no")
		if err != nil {
			fail(err)
			return
		}
		payload.Set("ok", true)
		payload.Set("range", key)
		payload.Set("until", until)
		s.sendJSON(w, 200, payload)
	case "/api/v1/metrics/servers":
		key, since, until := resolveWindow(query)
		payload, err := s.DB.serverTotals(since, until)
		if err == nil {
			var labels, hidden any
			if labels, err = jsonState(s.DB, channelLabelsKey, "{}"); err == nil {
				if hidden, err = jsonState(s.DB, channelHiddenKey, "[]"); err == nil {
					payload.Set("labels", labels)
					payload.Set("hidden", hidden)
				}
			}
		}
		if err != nil {
			fail(err)
			return
		}
		payload.Set("ok", true)
		payload.Set("range", key)
		payload.Set("since", since)
		payload.Set("until", until)
		s.sendJSON(w, 200, payload)
	case "/api/v1/metrics/backends":
		key, since, until := resolveWindow(query)
		payload, err := s.DB.backendTotals(since, until)
		if err != nil {
			fail(err)
			return
		}
		payload.Set("ok", true)
		payload.Set("range", key)
		payload.Set("since", since)
		payload.Set("until", until)
		s.sendJSON(w, 200, payload)
	case "/api/v1/metrics/states":
		key, since, until := resolveWindow(query)
		site, err := s.site(query)
		if err != nil {
			fail(err)
			return
		}
		payload, err := s.DB.stateTimeline(site, since, until)
		if err != nil {
			fail(err)
			return
		}
		payload.Set("ok", true)
		payload.Set("range", key)
		payload.Set("since", since)
		payload.Set("until", until)
		s.sendJSON(w, 200, payload)
	case "/api/v1/metrics/summary":
		key, since, until := resolveWindow(query)
		site, err := s.site(query)
		if err != nil {
			fail(err)
			return
		}
		rangeSeconds := maxI(1, until-since)
		payload, err := func() (*OMap, error) {
			totals, err := s.DB.totals(site, since, until)
			if err != nil {
				return nil, err
			}
			conns, err := s.DB.latestGauges(site, until)
			if err != nil {
				return nil, err
			}
			load, err := s.DB.hostLoad(since, until)
			if err != nil {
				return nil, err
			}
			health, err := s.DB.backendHealth()
			if err != nil {
				return nil, err
			}
			monitors, available := s.Collector.monitorSnapshot()
			reqs := totals.Value("requests").(int64)
			return omap("ok", true, "ts", until, "range", key, "range_seconds", rangeSeconds, "since", since, "until", until,
				"site", site, "totals", totals, "requests_per_second", pyRoundN(float64(reqs)/float64(rangeSeconds), 3),
				"connections", conns, "load", load, "health", health, "collector", s.Collector.health(),
				"storage", s.Collector.storage.report(until), "monitors", orderedMonitors(monitors),
				"sensors", s.Collector.sensors(), "log_digests", omap("available", available)), nil
		}()
		if err != nil {
			fail(err)
			return
		}
		s.sendJSON(w, 200, payload)
	case "/api/v1/metrics/monitors":
		monitors, _ := s.Collector.monitorSnapshot()
		s.sendJSON(w, 200, omap("ok", true, "monitors", orderedMonitors(monitors)))
	case "/api/v1/metrics/health":
		stats, err := s.DB.stats()
		if err != nil {
			fail(err)
			return
		}
		s.sendJSON(w, 200, omap("ok", true, "ts", utcNow(), "collector", s.Collector.health(), "database", stats))
	case "/api/v1/metrics/storage":
		now := utcNow()
		s.sendJSON(w, 200, omap("ok", true, "ts", now, "path", s.DB.Path, "storage", s.Collector.storage.report(now)))
	default:
		s.sendJSON(w, 404, omap("ok", false, "error", "not found"))
	}
}

// Main is main(): the collector and the read API until a signal.
func Main() error {
	cfg := LoadConfig(ConfigPath)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if !cfg.Enabled {
		log.Printf("Monitoring is disabled in %s; idling", ConfigPath)
		<-ctx.Done()
		return nil
	}
	db, err := OpenDatabase(DatabasePath)
	if err != nil {
		return err
	}
	defer db.Close()
	var sink alertSink
	if c := alerts.FromEnv(); c.Enabled() {
		sink = c
	}
	col := NewCollector(cfg, db, sink)
	status, _ := col.storage.enforce(utcNow())
	log.Printf("Starting easy-ha-proxy-metricsd: socket=%s db=%s interval=%ds limit=%dMiB reserve=%dMiB storage=%s",
		SocketPath, DatabasePath, cfg.PollIntervalSeconds, status.MaxDatabaseBytes/mib, status.ReservedFreeBytes/mib, status.State)
	col.Start()
	ln, err := unixrpc.ListenUnix(SocketPath, "", SocketGroup, 0o660)
	if err != nil {
		col.Stop()
		return err
	}
	srv := &http.Server{Handler: &Server{Collector: col, DB: db}, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second}
	err = unixrpc.ServeHTTP(ctx, srv, unixrpc.PanelListener(ln), 5*time.Second)
	col.Stop()
	if _, statErr := os.Stat(SocketPath); statErr == nil {
		_ = os.Remove(SocketPath)
	}
	return err
}

// ProbeHost is the probe-host subcommand: one reading of what the collector
// would read from this machine, for checking a build on a host.
func ProbeHost() *OMap {
	out := NewOMap()
	if m := readHostMemory(); m != nil {
		out.Set("memory_used_kib", m.a)
		out.Set("memory_total_kib", m.b)
	} else {
		out.Set("memory_used_kib", nil)
		out.Set("memory_total_kib", nil)
	}
	if used, total, ok := readDiskSpace(diskPath); ok {
		out.Set("disk_used_kib", used)
		out.Set("disk_total_kib", total)
	} else {
		out.Set("disk_used_kib", nil)
		out.Set("disk_total_kib", nil)
	}
	if t, ok := readTemperature(thermalRoot); ok {
		out.Set("temperature_tenths", t)
	} else {
		out.Set("temperature_tenths", nil)
	}
	out.Set("disks", int64(len(readDiskCounters(diskstatsPath, sysBlockRoot))))
	out.Set("network_cards", int64(len(readNetworkCounters(sysNetRoot))))
	return out
}
