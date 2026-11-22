package metricsd

import (
	"context"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/haproxy"
)

// Counters captures monotonic HAProxy stat counters for delta calculation.
type Counters struct {
	Requests uint64
	BytesIn  uint64
	BytesOut uint64
	Resp2xx  uint64
	Resp3xx  uint64
	Resp4xx  uint64
	Resp5xx  uint64
}

// DeltaSample represents one interval's computed traffic deltas for an object.
type DeltaSample struct {
	TS         int64  `json:"ts"`
	Kind       string `json:"kind"`
	Proxy      string `json:"proxy"`
	Server     string `json:"server"`
	Status     string `json:"status"`
	Scur       uint64 `json:"scur"`
	RtimeMS    uint64 `json:"rtime_ms"`
	Requests   uint64 `json:"requests"`
	BytesIn    uint64 `json:"bytes_in"`
	BytesOut   uint64 `json:"bytes_out"`
	Resp2xx    uint64 `json:"resp_2xx"`
	Resp3xx    uint64 `json:"resp_3xx"`
	Resp4xx    uint64 `json:"resp_4xx"`
	Resp5xx    uint64 `json:"resp_5xx"`
}

// Collector polls HAProxy stats and Linux host metrics, computing reload-safe counter deltas.
type Collector struct {
	cfg    Config
	client *haproxy.Client

	mu          sync.Mutex
	prev        map[haproxy.ObjectKey]Counters
	prevCPU     *CPUTotals
	sites       map[string]string
	recent      []DeltaSample
	recentHost  []HostSample
	monitors    map[string]bool
	pollsTotal  uint64
	pollErrors  uint64
	lastPollTS  int64
	maxSamples  int
}

// NewCollector creates a Collector with sensible bounded memory defaults.
func NewCollector(cfg Config, client *haproxy.Client) *Collector {
	if client == nil {
		client = haproxy.NewClient(cfg.HAProxySocket)
	}
	return &Collector{
		cfg:    cfg,
		client: client,
		prev:   make(map[haproxy.ObjectKey]Counters),
		sites:  make(map[string]string),
		monitors: map[string]bool{
			"traffic":  true,
			"machine":  true,
			"backends": true,
		},
		maxSamples: 10000,
	}
}

// PollOnce collects one round of HAProxy stat deltas and host metrics.
func (c *Collector) PollOnce(ctx context.Context, now int64) error {
	if now <= 0 {
		now = time.Now().Unix()
	}
	rows, err := c.client.ShowStat(ctx)
	if err != nil {
		c.mu.Lock()
		c.pollErrors++
		c.mu.Unlock()
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.pollsTotal++
	c.lastPollTS = now

	if c.monitors["machine"] {
		hs, nextCPU := ReadHostSample(now, c.prevCPU)
		c.prevCPU = nextCPU
		c.recentHost = append(c.recentHost, hs)
		if len(c.recentHost) > 1440 {
			c.recentHost = c.recentHost[len(c.recentHost)-1440:]
		}
	}

	for _, row := range rows {
		key, ok := haproxy.Classify(row)
		if !ok || c.cfg.Excluded(key.Proxy) {
			continue
		}
		if key.Kind == "backend" {
			c.sites[key.Proxy] = row["status"]
		}
		cur := Counters{
			Requests: parseU64(row["req_tot"]),
			BytesIn:  parseU64(row["bin"]),
			BytesOut: parseU64(row["bout"]),
			Resp2xx:  parseU64(row["hrsp_2xx"]),
			Resp3xx:  parseU64(row["hrsp_3xx"]),
			Resp4xx:  parseU64(row["hrsp_4xx"]),
			Resp5xx:  parseU64(row["hrsp_5xx"]),
		}
		if cur.Requests == 0 {
			cur.Requests = parseU64(row["stot"])
		}
		prev, hasPrev := c.prev[key]
		c.prev[key] = cur
		if !hasPrev {
			continue
		}

		sample := DeltaSample{
			TS:       now,
			Kind:     key.Kind,
			Proxy:    key.Proxy,
			Server:   key.Server,
			Status:   row["status"],
			Scur:     parseU64(row["scur"]),
			RtimeMS:  parseU64(row["rtime"]),
			Requests: counterDelta(cur.Requests, prev.Requests),
			BytesIn:  counterDelta(cur.BytesIn, prev.BytesIn),
			BytesOut: counterDelta(cur.BytesOut, prev.BytesOut),
			Resp2xx:  counterDelta(cur.Resp2xx, prev.Resp2xx),
			Resp3xx:  counterDelta(cur.Resp3xx, prev.Resp3xx),
			Resp4xx:  counterDelta(cur.Resp4xx, prev.Resp4xx),
			Resp5xx:  counterDelta(cur.Resp5xx, prev.Resp5xx),
		}
		c.recent = append(c.recent, sample)
		if len(c.recent) > c.maxSamples {
			c.recent = c.recent[len(c.recent)-c.maxSamples:]
		}
	}
	return nil
}

// Sites returns known backend proxies and their last observed status.
func (c *Collector) Sites() []map[string]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	names := make([]string, 0, len(c.sites))
	for name := range c.sites {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]map[string]string, 0, len(names))
	for _, n := range names {
		out = append(out, map[string]string{"proxy": n, "status": c.sites[n]})
	}
	return out
}

// Summary aggregates traffic totals over [since, until] (optionally filtered to one backend site).
func (c *Collector) Summary(site string, since, until int64) map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	var reqs, bin, bout, r2, r3, r4, r5 uint64
	for _, s := range c.recent {
		if s.TS < since || s.TS > until {
			continue
		}
		if site != "" {
			if s.Kind != "backend" || s.Proxy != site {
				continue
			}
		} else if s.Kind != "frontend" {
			continue
		}
		reqs += s.Requests
		bin += s.BytesIn
		bout += s.BytesOut
		r2 += s.Resp2xx
		r3 += s.Resp3xx
		r4 += s.Resp4xx
		r5 += s.Resp5xx
	}
	return map[string]any{
		"requests":  reqs,
		"bytes_in":  bin,
		"bytes_out": bout,
		"resp_2xx":  r2,
		"resp_3xx":  r3,
		"resp_4xx":  r4,
		"resp_5xx":  r5,
	}
}

// HostSamples returns recorded Linux host telemetry inside [since, until].
func (c *Collector) HostSamples(since, until int64) []HostSample {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]HostSample, 0)
	for _, h := range c.recentHost {
		if h.TS >= since && h.TS <= until {
			out = append(out, h)
		}
	}
	return out
}

// SetMonitors updates enabled monitor toggles, rejecting unknown names.
func (c *Collector) SetMonitors(changes map[string]bool) (map[string]bool, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range changes {
		if _, exists := c.monitors[k]; !exists {
			return nil, "unknown monitor: " + k
		}
	}
	for k, v := range changes {
		c.monitors[k] = v
	}
	copyMap := make(map[string]bool, len(c.monitors))
	for k, v := range c.monitors {
		copyMap[k] = v
	}
	return copyMap, ""
}

// Health returns diagnostic stats for /api/v1/metrics/health.
func (c *Collector) Health() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	mon := make(map[string]bool, len(c.monitors))
	for k, v := range c.monitors {
		mon[k] = v
	}
	return map[string]any{
		"polls_total":    c.pollsTotal,
		"poll_errors":    c.pollErrors,
		"last_poll_ts":   c.lastPollTS,
		"tracked_sites":  len(c.sites),
		"cached_samples": len(c.recent),
		"host_samples":   len(c.recentHost),
		"monitors":       mon,
	}
}

// counterDelta computes monotonic delta, gracefully handling HAProxy reload resets.
func counterDelta(cur, prev uint64) uint64 {
	if cur >= prev {
		return cur - prev
	}
	return cur
}

func parseU64(s string) uint64 {
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0
	}
	return v
}
