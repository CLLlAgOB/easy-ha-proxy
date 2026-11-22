package metricsd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

const (
	GiB = uint64(1024 * 1024 * 1024)
)

// ChartSeries lists all supported chart names for GET /api/v1/metrics/series.
var ChartSeries = map[string]struct{}{
	"requests":    {},
	"errors":      {},
	"latency":     {},
	"bandwidth":   {},
	"connections": {},
	"cpu":         {},
	"memory":      {},
	"load":        {},
	"network":     {},
	"temperature": {},
}

// TrafficBucket aggregates traffic deltas for one (bucketTS, kind, proxy, server).
type TrafficBucket struct {
	TS         int64  `json:"ts"`
	Kind       string `json:"kind"`
	Proxy      string `json:"proxy"`
	Server     string `json:"server"`
	Status     string `json:"status"`
	Requests   uint64 `json:"requests"`
	BytesIn    uint64 `json:"bytes_in"`
	BytesOut   uint64 `json:"bytes_out"`
	Resp2xx    uint64 `json:"resp_2xx"`
	Resp3xx    uint64 `json:"resp_3xx"`
	Resp4xx    uint64 `json:"resp_4xx"`
	Resp5xx    uint64 `json:"resp_5xx"`
	ScurMax    uint64 `json:"scur_max"`
	RtimeSum   uint64 `json:"rtime_sum"`
	RtimeCount uint64 `json:"rtime_count"`
}

// StateChange records one status transition for a backend or server.
type StateChange struct {
	TS     int64  `json:"ts"`
	Kind   string `json:"kind"`
	Proxy  string `json:"proxy"`
	Server string `json:"server"`
	Status string `json:"status"`
}

// StorageStatus summarizes disk budget, retention pressure, and whether writes are paused.
type StorageStatus struct {
	Path               string `json:"path"`
	DatabaseBytes      uint64 `json:"database_bytes"`
	MaxDatabaseBytes   uint64 `json:"max_database_bytes"`
	ReservedFreeBytes  uint64 `json:"reserved_free_bytes"`
	AvailableFreeBytes uint64 `json:"available_free_bytes"`
	TotalFSBytes       uint64 `json:"total_fs_bytes"`
	Pressure           bool   `json:"pressure"`
	Paused             bool   `json:"paused"`
	EffectiveMinDays   int    `json:"effective_one_minute_days"`
	EffectiveHourDays  int    `json:"effective_one_hour_days"`
	CheckedAt          int64  `json:"checked_at"`
}

type bucketKey struct {
	ts     int64
	kind   string
	proxy  string
	server string
}

type metricsSnapshot struct {
	MinuteTraffic []TrafficBucket   `json:"minute_traffic"`
	HourTraffic   []TrafficBucket   `json:"hour_traffic"`
	MinuteHost    []HostSample      `json:"minute_host"`
	HourHost      []HostSample      `json:"hour_host"`
	States        []StateChange     `json:"states"`
	Labels        map[string]string `json:"channel_labels"`
	Hidden        []string          `json:"channel_hidden"`
	Monitors      map[string]bool   `json:"monitors"`
}

// Store persists minute & hour rollups, state transitions, and UI metadata without CGO.
type Store struct {
	mu                 sync.Mutex
	path               string
	cfg                Config
	minuteTraffic      map[bucketKey]*TrafficBucket
	hourTraffic        map[bucketKey]*TrafficBucket
	minuteHost         map[int64]HostSample
	hourHost           map[int64]HostSample
	lastStatus         map[string]string
	states             []StateChange
	labels             map[string]string
	hidden             []string
	monitors           map[string]bool
	storage            StorageStatus
	maxDBBytesOverride uint64
	reserveOverride    uint64
	statFSFn           func(string) (fsStats, error)
}

// NewStore opens or initializes a durable metrics store at path (empty = in-memory).
func NewStore(path string, cfg Config) (*Store, error) {
	s := &Store{
		path:          path,
		cfg:           cfg,
		minuteTraffic: make(map[bucketKey]*TrafficBucket),
		hourTraffic:   make(map[bucketKey]*TrafficBucket),
		minuteHost:    make(map[int64]HostSample),
		hourHost:      make(map[int64]HostSample),
		lastStatus:    make(map[string]string),
		labels:        make(map[string]string),
		hidden:        []string{},
		monitors: map[string]bool{
			"traffic":  true,
			"machine":  true,
			"backends": true,
		},
		statFSFn: statFS,
	}
	s.storage.Path = path
	s.storage.EffectiveMinDays = cfg.RetentionOneMinuteDays
	s.storage.EffectiveHourDays = cfg.RetentionOneHourDays

	if path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return nil, err
		}
		if raw, err := os.ReadFile(path); err == nil && len(raw) > 0 {
			var snap metricsSnapshot
			if json.Unmarshal(raw, &snap) == nil {
				for _, b := range snap.MinuteTraffic {
					cp := b
					s.minuteTraffic[bucketKey{b.TS, b.Kind, b.Proxy, b.Server}] = &cp
				}
				for _, b := range snap.HourTraffic {
					cp := b
					s.hourTraffic[bucketKey{b.TS, b.Kind, b.Proxy, b.Server}] = &cp
				}
				for _, h := range snap.MinuteHost {
					s.minuteHost[h.TS] = h
				}
				for _, h := range snap.HourHost {
					s.hourHost[h.TS] = h
				}
				s.states = snap.States
				if snap.Labels != nil {
					s.labels = snap.Labels
				}
				if snap.Hidden != nil {
					s.hidden = snap.Hidden
				}
				for k, v := range snap.Monitors {
					s.monitors[k] = v
				}
			}
		}
	}
	return s, nil
}

// RecordTraffic merges one DeltaSample into both its 1-minute and 1-hour rollup buckets.
func (s *Store) RecordTraffic(sample DeltaSample) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.storage.Paused {
		return
	}
	minTS := (sample.TS / 60) * 60
	hrTS := (sample.TS / 3600) * 3600
	mergeBucket(s.minuteTraffic, minTS, sample)
	mergeBucket(s.hourTraffic, hrTS, sample)

	if sample.Kind == "backend" || sample.Kind == "server" {
		key := sample.Kind + ":" + sample.Proxy + ":" + sample.Server
		if prev, ok := s.lastStatus[key]; !ok || prev != sample.Status {
			s.lastStatus[key] = sample.Status
			s.states = append(s.states, StateChange{
				TS:     sample.TS,
				Kind:   sample.Kind,
				Proxy:  sample.Proxy,
				Server: sample.Server,
				Status: sample.Status,
			})
			if len(s.states) > 20000 {
				s.states = s.states[len(s.states)-20000:]
			}
		}
	}
}

func mergeBucket(m map[bucketKey]*TrafficBucket, bucketTS int64, sample DeltaSample) {
	k := bucketKey{ts: bucketTS, kind: sample.Kind, proxy: sample.Proxy, server: sample.Server}
	b, ok := m[k]
	if !ok {
		b = &TrafficBucket{
			TS:     bucketTS,
			Kind:   sample.Kind,
			Proxy:  sample.Proxy,
			Server: sample.Server,
		}
		m[k] = b
	}
	b.Status = sample.Status
	b.Requests += sample.Requests
	b.BytesIn += sample.BytesIn
	b.BytesOut += sample.BytesOut
	b.Resp2xx += sample.Resp2xx
	b.Resp3xx += sample.Resp3xx
	b.Resp4xx += sample.Resp4xx
	b.Resp5xx += sample.Resp5xx
	if sample.Scur > b.ScurMax {
		b.ScurMax = sample.Scur
	}
	if sample.RtimeMS > 0 {
		b.RtimeSum += sample.RtimeMS
		b.RtimeCount++
	}
}

// RecordHost stores one host sample into its 1-minute and 1-hour slots.
func (s *Store) RecordHost(hs HostSample) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.storage.Paused {
		return
	}
	minTS := (hs.TS / 60) * 60
	hrTS := (hs.TS / 3600) * 3600
	mh := hs
	mh.TS = minTS
	s.minuteHost[minTS] = mh
	hh := hs
	hh.TS = hrTS
	s.hourHost[hrTS] = hh
}

// EvaluateStorage checks filesystem free space, enforces auto-sized cap/reserve,
// reduces retention under pressure, and pauses writes if free space falls below reserve.
func (s *Store) EvaluateStorage(now int64) StorageStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	dir := "."
	if s.path != "" {
		dir = filepath.Dir(s.path)
	}
	fs, err := s.statFSFn(dir)
	var dbSize uint64
	if s.path != "" {
		if fi, err := os.Stat(s.path); err == nil {
			dbSize = uint64(fi.Size())
		}
	}

	maxDB := s.maxDBBytesOverride
	if maxDB == 0 && err == nil && fs.TotalBytes > 0 {
		tenPct := fs.TotalBytes / 10
		maxDB = min(5*GiB, tenPct)
		if maxDB < 64*1024*1024 {
			maxDB = 64 * 1024 * 1024
		}
	}
	reserve := s.reserveOverride
	if reserve == 0 && err == nil && fs.TotalBytes > 0 {
		tenPct := fs.TotalBytes / 10
		reserve = max(2*GiB, min(tenPct, 10*GiB))
	}

	lowFree := err == nil && reserve > 0 && fs.AvailBytes < reserve
	overCap := maxDB > 0 && dbSize > maxDB
	pressure := lowFree || overCap
	minDays := s.cfg.RetentionOneMinuteDays
	hrDays := s.cfg.RetentionOneHourDays
	if pressure {
		if minDays > 3 {
			minDays = 3
		}
		if hrDays > 90 {
			hrDays = 90
		}
		s.pruneLocked(now, minDays, min(s.cfg.RetentionOneMinuteServerHrs, 12), hrDays)
	}
	paused := lowFree

	s.storage = StorageStatus{
		Path:               s.path,
		DatabaseBytes:      dbSize,
		MaxDatabaseBytes:   maxDB,
		ReservedFreeBytes:  reserve,
		AvailableFreeBytes: fs.AvailBytes,
		TotalFSBytes:       fs.TotalBytes,
		Pressure:           pressure,
		Paused:             paused,
		EffectiveMinDays:   minDays,
		EffectiveHourDays:  hrDays,
		CheckedAt:          now,
	}
	return s.storage
}

// StorageReport returns the latest evaluated StorageStatus.
func (s *Store) StorageReport(now int64) StorageStatus {
	s.mu.Lock()
	checked := s.storage.CheckedAt
	s.mu.Unlock()
	if checked == 0 {
		return s.EvaluateStorage(now)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.storage
}

// Prune enforces configured retention windows and flushes the snapshot to disk.
func (s *Store) Prune(now int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now, s.cfg.RetentionOneMinuteDays, s.cfg.RetentionOneMinuteServerHrs, s.cfg.RetentionOneHourDays)
	s.flushLocked()
}

func (s *Store) pruneLocked(now int64, minDays, srvHours, hrDays int) {
	minCut := now - int64(max(1, minDays))*86400
	srvCut := now - int64(max(1, srvHours))*3600
	hrCut := now - int64(max(1, hrDays))*86400

	for k := range s.minuteTraffic {
		cut := minCut
		if k.kind == "server" {
			cut = srvCut
		}
		if k.ts < cut {
			delete(s.minuteTraffic, k)
		}
	}
	for k := range s.hourTraffic {
		if k.ts < hrCut {
			delete(s.hourTraffic, k)
		}
	}
	for ts := range s.minuteHost {
		if ts < minCut {
			delete(s.minuteHost, ts)
		}
	}
	for ts := range s.hourHost {
		if ts < hrCut {
			delete(s.hourHost, ts)
		}
	}
	keptStates := s.states[:0]
	for _, st := range s.states {
		if st.TS >= minCut {
			keptStates = append(keptStates, st)
		}
	}
	s.states = keptStates
}

// Flush writes an atomic JSON snapshot to disk.
func (s *Store) Flush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flushLocked()
}

func (s *Store) flushLocked() {
	if s.path == "" {
		return
	}
	snap := metricsSnapshot{
		MinuteTraffic: make([]TrafficBucket, 0, len(s.minuteTraffic)),
		HourTraffic:   make([]TrafficBucket, 0, len(s.hourTraffic)),
		MinuteHost:    make([]HostSample, 0, len(s.minuteHost)),
		HourHost:      make([]HostSample, 0, len(s.hourHost)),
		States:        s.states,
		Labels:        s.labels,
		Hidden:        s.hidden,
		Monitors:      s.monitors,
	}
	for _, b := range s.minuteTraffic {
		snap.MinuteTraffic = append(snap.MinuteTraffic, *b)
	}
	for _, b := range s.hourTraffic {
		snap.HourTraffic = append(snap.HourTraffic, *b)
	}
	for _, h := range s.minuteHost {
		snap.MinuteHost = append(snap.MinuteHost, h)
	}
	for _, h := range s.hourHost {
		snap.HourHost = append(snap.HourHost, h)
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".metrics-store.*.tmp")
	if err != nil {
		return
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return
	}
	_ = tmp.Chmod(0o640)
	_ = tmp.Sync()
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return
	}
	_ = os.Rename(tmpName, s.path)
}

// ChannelLabels returns copies of the persisted operator channel labels and hidden list.
func (s *Store) ChannelLabels() (map[string]string, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	labels := make(map[string]string, len(s.labels))
	for k, v := range s.labels {
		labels[k] = v
	}
	hidden := append([]string(nil), s.hidden...)
	return labels, hidden
}

// SetChannelLabels updates channel labels and (when hidden != nil) the hidden host list.
func (s *Store) SetChannelLabels(labels map[string]string, hidden []string) (map[string]string, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.labels = labels
	if hidden != nil {
		s.hidden = hidden
	}
	s.flushLocked()
	cpL := make(map[string]string, len(s.labels))
	for k, v := range s.labels {
		cpL[k] = v
	}
	return cpL, append([]string(nil), s.hidden...)
}

// Series returns chart time-series points over [since, until] (choosing 1m or 1h resolution).
func (s *Store) Series(chart, site string, since, until int64) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	useHourly := until-since > 48*3600
	step := 60
	if useHourly {
		step = 3600
	}

	if chart == "cpu" || chart == "memory" || chart == "load" || chart == "network" || chart == "temperature" {
		src := s.minuteHost
		if useHourly {
			src = s.hourHost
		}
		var list []HostSample
		for ts, hs := range src {
			if ts >= since && ts <= until {
				list = append(list, hs)
			}
		}
		sort.Slice(list, func(i, j int) bool { return list[i].TS < list[j].TS })
		points := make([]map[string]any, 0, len(list))
		for _, hs := range list {
			pt := map[string]any{"ts": hs.TS}
			switch chart {
			case "cpu":
				pt["cpu_percent"] = hs.CPUPercent
			case "memory":
				pt["mem_percent"] = hs.MemPercent
				pt["mem_used_bytes"] = hs.MemUsedBytes
			case "load":
				pt["load1"] = hs.Load1
				pt["load5"] = hs.Load5
				pt["load15"] = hs.Load15
			case "network":
				pt["net_rx_bytes"] = hs.NetRxBytes
				pt["net_tx_bytes"] = hs.NetTxBytes
			case "temperature":
				pt["temp_celsius"] = hs.TempCelsius
			}
			points = append(points, pt)
		}
		return map[string]any{"chart": chart, "resolution": step, "points": points}
	}

	src := s.minuteTraffic
	if useHourly {
		src = s.hourTraffic
	}
	byTS := make(map[int64]*TrafficBucket)
	for _, b := range src {
		if b.TS < since || b.TS > until {
			continue
		}
		if site != "" {
			if b.Kind != "backend" || b.Proxy != site {
				continue
			}
		} else if b.Kind != "frontend" {
			continue
		}
		agg, ok := byTS[b.TS]
		if !ok {
			agg = &TrafficBucket{TS: b.TS}
			byTS[b.TS] = agg
		}
		agg.Requests += b.Requests
		agg.BytesIn += b.BytesIn
		agg.BytesOut += b.BytesOut
		agg.Resp2xx += b.Resp2xx
		agg.Resp3xx += b.Resp3xx
		agg.Resp4xx += b.Resp4xx
		agg.Resp5xx += b.Resp5xx
		agg.ScurMax += b.ScurMax
		agg.RtimeSum += b.RtimeSum
		agg.RtimeCount += b.RtimeCount
	}
	keys := make([]int64, 0, len(byTS))
	for ts := range byTS {
		keys = append(keys, ts)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	points := make([]map[string]any, 0, len(keys))
	for _, ts := range keys {
		b := byTS[ts]
		pt := map[string]any{"ts": ts}
		switch chart {
		case "requests":
			pt["requests"] = b.Requests
		case "errors":
			pt["resp_4xx"] = b.Resp4xx
			pt["resp_5xx"] = b.Resp5xx
		case "latency":
			var avg float64
			if b.RtimeCount > 0 {
				avg = float64(b.RtimeSum) / float64(b.RtimeCount)
			}
			pt["rtime_ms"] = avg
		case "bandwidth":
			pt["bytes_in"] = b.BytesIn
			pt["bytes_out"] = b.BytesOut
		case "connections":
			pt["scur"] = b.ScurMax
		}
		points = append(points, pt)
	}
	return map[string]any{"chart": chart, "site": site, "resolution": step, "points": points}
}

// ServerTotals aggregates per-server totals over [since, until].
func (s *Store) ServerTotals(since, until int64) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	src := s.minuteTraffic
	if until-since > 48*3600 {
		src = s.hourTraffic
	}
	byKey := make(map[string]*TrafficBucket)
	for _, b := range src {
		if b.Kind != "server" || b.TS < since || b.TS > until {
			continue
		}
		k := b.Proxy + "/" + b.Server
		agg, ok := byKey[k]
		if !ok {
			agg = &TrafficBucket{Kind: "server", Proxy: b.Proxy, Server: b.Server}
			byKey[k] = agg
		}
		agg.Status = b.Status
		agg.Requests += b.Requests
		agg.BytesIn += b.BytesIn
		agg.BytesOut += b.BytesOut
		agg.Resp2xx += b.Resp2xx
		agg.Resp3xx += b.Resp3xx
		agg.Resp4xx += b.Resp4xx
		agg.Resp5xx += b.Resp5xx
	}
	list := make([]TrafficBucket, 0, len(byKey))
	for _, v := range byKey {
		list = append(list, *v)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Requests > list[j].Requests })
	return map[string]any{"servers": list}
}

// BackendTotals aggregates per-backend totals over [since, until].
func (s *Store) BackendTotals(since, until int64) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	src := s.minuteTraffic
	if until-since > 48*3600 {
		src = s.hourTraffic
	}
	byKey := make(map[string]*TrafficBucket)
	for _, b := range src {
		if b.Kind != "backend" || b.TS < since || b.TS > until {
			continue
		}
		agg, ok := byKey[b.Proxy]
		if !ok {
			agg = &TrafficBucket{Kind: "backend", Proxy: b.Proxy}
			byKey[b.Proxy] = agg
		}
		agg.Status = b.Status
		agg.Requests += b.Requests
		agg.BytesIn += b.BytesIn
		agg.BytesOut += b.BytesOut
		agg.Resp2xx += b.Resp2xx
		agg.Resp3xx += b.Resp3xx
		agg.Resp4xx += b.Resp4xx
		agg.Resp5xx += b.Resp5xx
		agg.RtimeSum += b.RtimeSum
		agg.RtimeCount += b.RtimeCount
	}
	list := make([]TrafficBucket, 0, len(byKey))
	for _, v := range byKey {
		list = append(list, *v)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Requests > list[j].Requests })
	return map[string]any{"backends": list}
}

// StateTimeline returns backend/server status changes over [since, until].
func (s *Store) StateTimeline(site string, since, until int64) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]StateChange, 0)
	for _, st := range s.states {
		if st.TS < since || st.TS > until {
			continue
		}
		if site != "" && st.Proxy != site {
			continue
		}
		out = append(out, st)
	}
	return map[string]any{"events": out}
}

// LatestBackendMinuteBuckets returns the latest completed minute bucket per backend at minuteTS.
func (s *Store) LatestBackendMinuteBuckets(minuteTS int64) []TrafficBucket {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]TrafficBucket, 0)
	for k, b := range s.minuteTraffic {
		if k.ts == minuteTS && k.kind == "backend" {
			out = append(out, *b)
		}
	}
	return out
}

// Stats returns row counts and file size for /api/v1/metrics/health.
func (s *Store) Stats() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	var size int64
	if s.path != "" {
		if fi, err := os.Stat(s.path); err == nil {
			size = fi.Size()
		}
	}
	return map[string]any{
		"minute_traffic_rows": len(s.minuteTraffic),
		"hour_traffic_rows":   len(s.hourTraffic),
		"minute_host_rows":    len(s.minuteHost),
		"hour_host_rows":      len(s.hourHost),
		"state_events":        len(s.states),
		"database_bytes":      size,
	}
}

// CleanChannelLabels validates POST /api/v1/metrics/channel-labels matching metricsd/api.py.
func CleanChannelLabels(labels map[string]any, hiddenRaw any) (map[string]string, []string, string) {
	if len(labels) > 64 {
		return nil, nil, "at most 64 labels"
	}
	cleaned := make(map[string]string, len(labels))
	for host, rawVal := range labels {
		key := strings.TrimSpace(host)
		if key == "" || len(key) > 255 {
			return nil, nil, "a host name is missing or too long"
		}
		text, _ := rawVal.(string)
		text = strings.TrimSpace(text)
		if len(text) > 60 {
			text = text[:60]
		}
		if text != "" {
			cleaned[key] = text
		}
	}
	if hiddenRaw == nil {
		return cleaned, nil, ""
	}
	list, ok := hiddenRaw.([]any)
	if !ok {
		return nil, nil, "hidden must be a list"
	}
	if len(list) > 64 {
		return nil, nil, "at most 64 hidden channels"
	}
	seen := make(map[string]struct{}, len(list))
	for _, it := range list {
		h, _ := it.(string)
		h = strings.TrimSpace(h)
		if h != "" && len(h) <= 255 {
			seen[h] = struct{}{}
		}
	}
	hidden := make([]string, 0, len(seen))
	for h := range seen {
		hidden = append(hidden, h)
	}
	sort.Strings(hidden)
	return cleaned, hidden, ""
}
