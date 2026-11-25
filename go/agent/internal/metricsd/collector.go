package metricsd

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"easy-ha-proxy/panel/shared/pyyaml"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/alerts"
)

// alertSink is the part of the alert client metricsd uses.
type alertSink interface {
	Enabled() bool
	Observe(ctx context.Context, obs alerts.Observation) bool
}

func observe(sink alertSink, obs alerts.Observation) {
	if sink == nil || !sink.Enabled() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sink.Observe(ctx, obs)
}

// StorageStatus is one measurement of monitoring storage.
type StorageStatus struct {
	State, Reason                                 string
	TotalBytes, DatabaseBytes, WALBytes, SHMBytes int64
	FilesystemTotalBytes, FilesystemFreeBytes     int64
	MaxDatabaseBytes, ReservedFreeBytes           int64
}

func (s StorageStatus) databaseFraction() float64 {
	if s.MaxDatabaseBytes <= 0 {
		return 0
	}
	return float64(s.TotalBytes) / float64(s.MaxDatabaseBytes)
}

func (s StorageStatus) asDict() *OMap {
	return omap("state", s.State, "reason", s.Reason, "database_bytes", s.DatabaseBytes, "wal_bytes", s.WALBytes,
		"shm_bytes", s.SHMBytes, "total_bytes", s.TotalBytes, "max_database_bytes", s.MaxDatabaseBytes,
		"database_used_fraction", pyRoundN(s.databaseFraction(), 4), "reserved_free_bytes", s.ReservedFreeBytes,
		"filesystem", omap("total_bytes", s.FilesystemTotalBytes, "free_bytes", s.FilesystemFreeBytes))
}

// StorageGuard keeps monitoring inside its budget.
type StorageGuard struct {
	cfg    Config
	db     *Database
	alerts alertSink
	storageState
	// The collector alone mutates storageState. HTTP readers see the last
	// completed enforcement pass without waiting for database maintenance.
	published atomic.Pointer[storageState]
}

type storageState struct {
	state          string
	writesPaused   bool
	pressureLevel  int
	lastCleanup    any
	lastCheckpoint any
	lastPause      any
	lastResume     any
	lastLogged     string
}

func newStorageGuard(cfg Config, db *Database, sink alertSink) *StorageGuard {
	g := &StorageGuard{cfg: cfg, db: db, alerts: sink, storageState: storageState{state: stateNormal}}
	g.publish()
	return g
}

func (g *StorageGuard) publish() {
	state := g.storageState
	g.published.Store(&state)
}

func (g *StorageGuard) resolveLimits(fsTotal int64) (int64, int64) {
	maximum := g.cfg.MaxDatabaseBytes
	if !g.cfg.HasMaxDatabaseBytes {
		maximum = minI(autoMaxDatabaseBytes, int64(float64(fsTotal)*autoMaxDatabaseFrac))
	}
	reserve := g.cfg.ReservedFreeBytes
	if !g.cfg.HasReservedFreeBytes {
		reserve = maxI(autoReserveFloorBytes, minI(int64(float64(fsTotal)*autoReserveFraction), autoReserveCeilBytes))
	}
	return maxI(0, maximum), maxI(0, reserve)
}

func (g *StorageGuard) measure() StorageStatus {
	st := g.db.storage()
	fs := st.Value("filesystem").(*OMap)
	total, free := fs.Value("total_bytes").(int64), fs.Value("free_bytes").(int64)
	maximum, reserve := g.resolveLimits(total)
	used := st.Value("total_bytes").(int64)
	state, reason := stateNormal, "within limits"
	fused, ffree, fmax, fres := float64(used), float64(free), float64(maximum), float64(reserve)
	switch {
	case maximum > 0 && used >= maximum:
		state, reason = stateCritical, "database reached its size limit"
	case reserve > 0 && free <= reserve:
		state, reason = stateCritical, "filesystem hit the free-space reserve"
	case maximum > 0 && fused >= fmax*pressureDatabaseFrac:
		state, reason = statePressure, "database near its size limit"
	case reserve > 0 && ffree < fres*1.25:
		state, reason = statePressure, "filesystem near the free-space reserve"
	case maximum > 0 && fused >= fmax*warningDatabaseFrac:
		state, reason = stateWarning, "database above 80% of its size limit"
	case reserve > 0 && ffree < fres*2:
		state, reason = stateWarning, "filesystem free space below twice the reserve"
	}
	return StorageStatus{State: state, Reason: reason, TotalBytes: used, DatabaseBytes: st.Value("database_bytes").(int64),
		WALBytes: st.Value("wal_bytes").(int64), SHMBytes: st.Value("shm_bytes").(int64), FilesystemTotalBytes: total,
		FilesystemFreeBytes: free, MaxDatabaseBytes: maximum, ReservedFreeBytes: reserve}
}

func (g *StorageGuard) retentionForLevel(level int) *OMap {
	if level < 0 {
		level = 0
	}
	if level > len(retentionLadder)-1 {
		level = len(retentionLadder) - 1
	}
	floors := retentionLadder[level]
	pick := func(configured int64, key string) int64 {
		if v, ok := floors[key]; ok && int64(v) < configured {
			return int64(v)
		}
		return configured
	}
	return omap("minute_days", pick(g.cfg.RetentionOneMinuteDays, "minute_days"),
		"minute_server_hours", pick(g.cfg.RetentionOneMinuteServerHours, "minute_server_hours"),
		"hour_days", pick(g.cfg.RetentionOneHourDays, "hour_days"))
}

func (g *StorageGuard) trim(now int64, level int) map[string]any {
	r := g.retentionForLevel(level)
	deleted, _ := g.db.applyRetention(now-r.Value("minute_days").(int64)*86400, now-r.Value("minute_server_hours").(int64)*3600,
		now-r.Value("hour_days").(int64)*86400)
	if anyDeleted(deleted) {
		g.lastCleanup = now
		g.db.incrementalVacuum(4096)
	}
	return deleted
}

func anyDeleted(m map[string]any) bool {
	for _, v := range m {
		if n, _ := v.(int64); n != 0 {
			return true
		}
	}
	return false
}

func (g *StorageGuard) manageWAL(s StorageStatus, now int64) bool {
	if s.WALBytes < g.cfg.WALSoftLimitBytes {
		return false
	}
	if !g.db.checkpoint(true) {
		g.db.checkpoint(false)
	}
	g.lastCheckpoint = now
	log.Printf("WAL reached %d bytes (soft limit %d); checkpointed", s.WALBytes, g.cfg.WALSoftLimitBytes)
	return true
}

func (g *StorageGuard) resumeMargin(s StorageStatus) int64 {
	floor := resumeMarginFloor
	if s.FilesystemTotalBytes > 0 {
		floor = minI(floor, int64(float64(s.FilesystemTotalBytes)*resumeMarginFSFraction))
	}
	return maxI(floor, int64(float64(s.ReservedFreeBytes)*resumeMarginFraction))
}

func (g *StorageGuard) mayResume(s StorageStatus) bool {
	margin := g.resumeMargin(s)
	space := s.ReservedFreeBytes <= 0 || s.FilesystemFreeBytes > s.ReservedFreeBytes+margin
	budget := s.MaxDatabaseBytes <= 0 || float64(s.TotalBytes) < float64(s.MaxDatabaseBytes)*resumeDatabaseFrac
	return space && budget
}

func deletedJSON(m map[string]any) string {
	return fmt.Sprintf(`{"minutes": %d, "server_minutes": %d, "hours": %d, "events": %d}`,
		m["minutes"], m["server_minutes"], m["hours"], m["events"])
}

func (g *StorageGuard) enforce(now int64) (StorageStatus, []string) {
	status := g.measure()
	actions := []string{}
	if g.manageWAL(status, now) {
		actions = append(actions, "wal_checkpoint")
		status = g.measure()
	}
	if (status.State == statePressure || status.State == stateCritical) && g.cfg.AutoReduceRetention {
		for level := 1; level < len(retentionLadder); level++ {
			_, _ = g.db.rollupHours(now - now%hourSeconds)
			deleted := g.trim(now, level)
			actions = append(actions, fmt.Sprintf("trim_level_%d", level))
			status = g.measure()
			log.Printf("Storage pressure: trimmed at level %d (%s), now %s", level, deletedJSON(deleted), status.State)
			if status.State == stateNormal || status.State == stateWarning {
				break
			}
		}
		g.pressureLevel = minInt(len(retentionLadder)-1, maxInt(g.pressureLevel, 1))
	} else if status.State == stateNormal {
		g.pressureLevel = 0
	}
	if status.State == stateCritical {
		if !g.writesPaused {
			g.writesPaused = true
			g.lastPause = now
			log.Printf("Historical monitoring paused: %s. HAProxy traffic is not affected.", status.Reason)
			actions = append(actions, "paused")
		}
	} else if g.writesPaused && g.mayResume(status) {
		g.writesPaused = false
		g.lastResume = now
		log.Printf("Historical monitoring resumed: %s", status.Reason)
		actions = append(actions, "resumed")
	}
	if status.State != g.lastLogged {
		prev := g.lastLogged
		if prev == "" {
			prev = "unknown"
		}
		log.Printf("Storage state %s -> %s (%s)", prev, status.State, status.Reason)
		g.lastLogged = status.State
	}
	g.state = status.State
	g.publish()
	g.reportToAlerts(status)
	_ = g.db.recordStorageSample(now, status.TotalBytes)
	return status, actions
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (g *StorageGuard) reportToAlerts(s StorageStatus) {
	if g.alerts == nil {
		return
	}
	severity := "warning"
	if s.State == stateCritical {
		severity = "critical"
	}
	observe(g.alerts, alerts.Observation{Rule: "monitoring.storage", Subject: "metrics",
		Active: alerts.BoolPtr(s.State == statePressure || s.State == stateCritical), Severity: severity,
		Summary: "Monitoring storage is " + s.State, Detail: s.Reason})
	observe(g.alerts, alerts.Observation{Rule: "monitoring.paused", Subject: "metrics", Active: alerts.BoolPtr(g.writesPaused),
		Summary: "Historical monitoring is paused; HAProxy traffic is not affected", Detail: s.Reason})
}

func (g *StorageGuard) report(now int64) *OMap {
	state := g.published.Load()
	s := g.measure()
	p := s.asDict()
	p.Set("writes_paused", state.writesPaused)
	p.Set("pressure_level", int64(state.pressureLevel))
	p.Set("effective_retention", g.retentionForLevel(state.pressureLevel))
	p.Set("configured_retention", g.retentionForLevel(0))
	p.Set("wal_soft_limit_bytes", g.cfg.WALSoftLimitBytes)
	p.Set("auto_reduce_retention", g.cfg.AutoReduceRetention)
	p.Set("last_cleanup_ts", state.lastCleanup)
	p.Set("last_checkpoint_ts", state.lastCheckpoint)
	p.Set("last_pause_ts", state.lastPause)
	p.Set("last_resume_ts", state.lastResume)
	p.Set("growth", g.db.storageGrowth(now, s.TotalBytes))
	return p
}

const autheliaBackend = "authelia_backend"

var trafficAlertSkip = map[string]bool{autheliaBackend: true, "be_access_granted": true}
var websitesFile = envDefault("METRICSD_WEBSITES", "/opt/haproxy-admin/config/websites.yml")
var siteIDOther = regexp.MustCompile(`[^A-Za-z0-9_]`)

// siteSlowThresholds is site_slow_thresholds.
func siteSlowThresholds(path string) map[string]int64 {
	raw, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("Cannot read %s for the sites' alert thresholds: %v", path, err)
		}
		return map[string]int64{}
	}
	v, err := pyyaml.Load(raw)
	if err != nil {
		log.Printf("Cannot read %s for the sites' alert thresholds: %v", path, err)
		return map[string]int64{}
	}
	out := map[string]int64{}
	m, ok := v.(*pyyaml.Map)
	if !ok {
		return out
	}
	sites, _ := m.Value("sites").([]any)
	for _, s := range sites {
		site, ok := s.(*pyyaml.Map)
		if !ok || !yamlTruthy(site.Value("name")) {
			continue
		}
		val := site.Value("alert_slow_ms")
		if val == nil {
			continue
		}
		if _, isBool := val.(bool); isBool {
			continue
		}
		var ms int64
		switch x := val.(type) {
		case int64:
			ms = x
		case float64:
			ms = int64(x)
		case string:
			n, ok := pyIntText(x)
			if !ok {
				continue
			}
			ms = n
		default:
			continue
		}
		if ms >= 0 && ms <= 600000 {
			out["be_"+siteIDOther.ReplaceAllString(yamlStr(site.Value("name")), "_")] = ms
		}
	}
	return out
}

func yamlTruthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case string:
		return x != ""
	case bool:
		return x
	case int64:
		return x != 0
	case float64:
		return x != 0
	}
	return true
}

func yamlStr(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		return pyyaml.FloatRepr(x)
	case bool:
		if x {
			return "True"
		}
		return "False"
	}
	return fmt.Sprint(v)
}

type objectKey struct{ kind, proxy, server string }

type missingEntry struct{ first, count int64 }

type cpuPrev struct{ total, idle int64 }

type compPrev struct {
	usage  int64
	moment time.Time
}

// Collector polls HAProxy and the host, accumulates a minute, writes it.
type Collector struct {
	cfg              Config
	db               *Database
	storage          *StorageGuard
	stop             chan struct{}
	stopOnce         sync.Once
	done             chan struct{}
	running          bool
	mu               sync.Mutex
	objectIDs        map[objectKey]int64
	baselines        map[baselineKey]baselineVal
	buckets          map[int64]*Bucket
	bucketTS         int64
	hasBucket        bool
	bucketReported   bool
	lastStates       map[int64]string
	missing          map[int64]missingEntry
	seenSinceStart   map[int64]bool
	addresses        map[int64]string
	cpuPrevious      *cpuPrev
	cgroupRoot       string
	containersDir    string
	componentPrev    map[string]compPrev
	containerNames   map[string]string
	monitors         map[string]bool
	diskPath         string
	diskstatsPath    string
	sysBlockRoot     string
	sysNetRoot       string
	thermalRoot      string
	counterPrevious  map[string]map[string]pair
	websitesPath     string
	thresholdsMTime  *time.Time
	thresholds       map[string]int64
	guarddSocket     string
	digestsAvailable any
	lastDigestPull   time.Time
	lastPollTS       any
	lastFlushTS      any
	lastError        any
	consecutiveFails int64
	pollsTotal       int64
	bucketsWritten   int64
	bucketsDropped   int64
}

// NewCollector builds the collector over an open database.
func NewCollector(cfg Config, db *Database, sink alertSink) *Collector {
	return &Collector{cfg: cfg, db: db, storage: newStorageGuard(cfg, db, sink), stop: make(chan struct{}),
		done: make(chan struct{}), objectIDs: map[objectKey]int64{}, baselines: map[baselineKey]baselineVal{},
		buckets: map[int64]*Bucket{}, lastStates: map[int64]string{}, missing: map[int64]missingEntry{},
		seenSinceStart: map[int64]bool{}, addresses: map[int64]string{}, cgroupRoot: cgroupRoot,
		containersDir: dockerContainersDir, componentPrev: map[string]compPrev{}, containerNames: map[string]string{},
		monitors: monitorDefaults(), diskPath: diskPath, diskstatsPath: diskstatsPath, sysBlockRoot: sysBlockRoot,
		sysNetRoot: sysNetRoot, thermalRoot: thermalRoot, counterPrevious: map[string]map[string]pair{},
		websitesPath: websitesFile, thresholds: map[string]int64{}, guarddSocket: GuarddSocket}
}

func (c *Collector) loadMonitors() {
	raw := c.db.getState(monitorsKey, "{}")
	if raw == "" {
		raw = "{}"
	}
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		v = map[string]any{}
	}
	c.monitors = monitorsFrom(v)
}

func monitorsJSON(m map[string]bool) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%q: %t", k, m[k])
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// setMonitors is set_monitors.
func (c *Collector) setMonitors(changes map[string]bool) (map[string]bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	merged := map[string]any{}
	for k, v := range c.monitors {
		merged[k] = v
	}
	for k, v := range changes {
		merged[k] = v
	}
	m := monitorsFrom(merged)
	if err := c.db.setState(monitorsKey, monitorsJSON(m)); err != nil {
		return nil, err
	}
	c.monitors = m
	if !m["components"] || !m["machine"] {
		c.componentPrev = map[string]compPrev{}
	}
	if !m["machine"] {
		c.cpuPrevious = nil
	}
	for _, n := range []string{"disk", "network"} {
		if !m[n] {
			delete(c.counterPrevious, n)
		}
	}
	return m, nil
}

// Start loads the persisted state and starts the poll loop.
func (c *Collector) Start() {
	c.loadMonitors()
	c.baselines = c.db.loadBaselines()
	c.lastStates = c.db.loadLastStates()
	c.addresses = c.db.loadServerAddresses()
	c.running = true
	go c.run()
}

// Stop ends the loop and flushes the minute in progress.
func (c *Collector) Stop() {
	c.stopOnce.Do(func() { close(c.stop) })
	<-c.done
}

func (c *Collector) run() {
	defer close(c.done)
	defer func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.running = false
	}()
	interval := time.Duration(c.cfg.PollIntervalSeconds) * time.Second
	nextMaintenance := time.Now().Add(time.Duration(c.cfg.MaintenanceIntervalSeconds) * time.Second)
	for {
		select {
		case <-c.stop:
			_, _ = c.flush(true)
			return
		default:
		}
		started := time.Now()
		if _, err := c.poll(); err != nil {
			c.mu.Lock()
			c.consecutiveFails++
			c.lastError = err.Error()
			failures := c.consecutiveFails
			c.mu.Unlock()
			if failures == 1 || failures == 10 || failures%60 == 0 {
				log.Printf("Poll failed (%d in a row): %v", failures, err)
			}
		}
		if time.Since(c.lastDigestPull) >= digestPullSeconds*time.Second {
			c.lastDigestPull = time.Now()
			_, _ = c.pullDigests(utcNow())
		}
		if !time.Now().Before(nextMaintenance) {
			func() {
				defer func() {
					if r := recover(); r != nil {
						log.Printf("Maintenance pass failed: %v", r)
					}
				}()
				if _, err := c.runMaintenance(); err != nil {
					log.Printf("Maintenance pass failed: %v", err)
				}
			}()
			nextMaintenance = time.Now().Add(time.Duration(c.cfg.MaintenanceIntervalSeconds) * time.Second)
		}
		wait := interval - time.Since(started)
		if wait < 500*time.Millisecond {
			wait = 500 * time.Millisecond
		}
		select {
		case <-c.stop:
			_, _ = c.flush(true)
			return
		case <-time.After(wait):
		}
	}
}

func (c *Collector) anyHostMonitor() bool {
	for _, n := range hostMonitors {
		if c.monitors[n] {
			return true
		}
	}
	return false
}

func (c *Collector) poll() (int, error) {
	payload, err := runtimeCommand(c.cfg.HAProxySocket, "show stat")
	if err != nil {
		return 0, err
	}
	rows := parseShowStat(payload)
	now := utcNow()
	if len(rows) == 0 {
		return 0, fmt.Errorf("show stat returned no usable rows")
	}
	bucketTS := now - now%bucketSeconds
	observed := 0
	var pendingTraffic []alerts.Observation
	err = func() error {
		c.mu.Lock()
		defer c.mu.Unlock()
		if !c.hasBucket {
			c.bucketTS, c.hasBucket = bucketTS, true
		} else if bucketTS != c.bucketTS {
			_, obs, ferr := c.flushLocked(c.bucketTS)
			pendingTraffic = obs
			if ferr != nil {
				return ferr
			}
			c.bucketTS = bucketTS
		}
		c.bucketReported = false
		present := map[int64]bool{}
		if err := c.continueRenamed(rows); err != nil {
			return err
		}
		for _, row := range rows {
			kind, proxy, server, ok := classify(row)
			if !ok || c.cfg.Excluded(proxy) {
				continue
			}
			if err := c.observe(kind, proxy, server, row, now); err != nil {
				return err
			}
			observed++
			if kind == "server" || kind == "backend" {
				present[c.objectIDs[objectKey{kind, proxy, server}]] = true
			}
		}
		if err := c.retireMissing(present, now); err != nil {
			return err
		}
		if c.anyHostMonitor() {
			return c.observeHost(now)
		}
		return nil
	}()
	c.sendObservations(pendingTraffic)
	if err != nil {
		return 0, err
	}
	c.reportAuthelia(rows)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pollsTotal++
	c.lastPollTS = now
	c.consecutiveFails = 0
	c.lastError = nil
	return observed, nil
}

func (c *Collector) reportAuthelia(rows []map[string]string) {
	if c.storage.alerts == nil {
		return
	}
	for _, row := range rows {
		if strings.TrimSpace(row["pxname"]) != autheliaBackend || strings.TrimSpace(row["svname"]) != "BACKEND" {
			continue
		}
		status := strings.ToUpper(strings.TrimSpace(row["status"]))
		down := !strings.HasPrefix(status, "UP")
		summary := "Authelia is answering"
		if down {
			summary = "Authelia is not answering: sites behind it cannot sign anyone in"
		}
		shown := status
		if shown == "" {
			shown = "unknown"
		}
		observe(c.storage.alerts, alerts.Observation{Rule: "authelia.unavailable", Subject: "authelia",
			Active: alerts.BoolPtr(down), Summary: summary, Detail: "HAProxy reports " + autheliaBackend + " as " + shown})
		return
	}
}

func (c *Collector) slowThresholds() map[string]int64 {
	var changed *time.Time
	if fi, err := os.Stat(c.websitesPath); err == nil {
		t := fi.ModTime()
		changed = &t
	}
	same := (changed == nil && c.thresholdsMTime == nil) || (changed != nil && c.thresholdsMTime != nil && changed.Equal(*c.thresholdsMTime))
	if !same || (c.thresholdsMTime == nil && changed == nil && c.thresholds == nil) {
		c.thresholdsMTime = changed
		if changed != nil {
			c.thresholds = siteSlowThresholds(c.websitesPath)
		} else {
			c.thresholds = map[string]int64{}
		}
	}
	return c.thresholds
}

func (c *Collector) trafficObservationsLocked(rows map[int64]map[string]int64) []alerts.Observation {
	if c.storage.alerts == nil {
		return nil
	}
	names := map[int64]objectKey{}
	for k, id := range c.objectIDs {
		names[id] = k
	}
	own := c.slowThresholds()
	var obs []alerts.Observation
	for _, id := range sortedIDs(rows) {
		row := rows[id]
		key, ok := names[id]
		if !ok || key.kind != "backend" || trafficAlertSkip[key.proxy] {
			continue
		}
		proxy := key.proxy
		requests := row["requests"]
		enough := requests >= c.cfg.AlertMinRequests
		if c.cfg.AlertErrorRatioPercent > 0 {
			errs := row["resp_5xx"]
			var percent int64
			if requests != 0 {
				percent = floorDiv(errs*100, requests)
			}
			failing := enough && percent >= c.cfg.AlertErrorRatioPercent
			summary, detail := proxy+": server errors back below the threshold", ""
			if failing {
				summary = fmt.Sprintf("%s: %d%% of responses were server errors", proxy, percent)
				detail = fmt.Sprintf("%d of %d responses in the last minute were 5xx (threshold %d%%)", errs, requests, c.cfg.AlertErrorRatioPercent)
			}
			obs = append(obs, alerts.Observation{Rule: "http.error_ratio", Subject: proxy, Active: alerts.BoolPtr(failing), Summary: summary, Detail: detail})
		}
		ownMS, hasOwn := own[proxy]
		threshold := c.cfg.AlertSlowResponseMS
		if hasOwn {
			threshold = ownMS
		}
		if threshold > 0 {
			average := row["response_ms_avg"]
			slow := enough && average >= threshold
			summary, detail := proxy+": response time back below the threshold", ""
			if slow {
				summary = fmt.Sprintf("%s: responses take %d ms on average", proxy, average)
				suffix := ""
				if hasOwn {
					suffix = " for this site"
				}
				detail = fmt.Sprintf("average over the last minute, %d requests (threshold %d ms%s)", requests, threshold, suffix)
			}
			obs = append(obs, alerts.Observation{Rule: "response.slow", Subject: proxy, Active: alerts.BoolPtr(slow), Summary: summary, Detail: detail})
		} else if hasOwn && ownMS == 0 {
			obs = append(obs, alerts.Observation{Rule: "response.slow", Subject: proxy, Active: alerts.BoolPtr(false),
				Summary: proxy + ": slow-response alerts are off for this site"})
		}
	}
	return obs
}

func (c *Collector) sendObservations(obs []alerts.Observation) {
	if c.storage.alerts == nil || len(obs) == 0 {
		return
	}
	for _, o := range obs {
		observe(c.storage.alerts, o)
	}
}

func (c *Collector) observeHost(now int64) error {
	machine := c.monitors["machine"]
	var cpu, busy *int64
	var memory *pair
	if machine {
		cpu = c.readHostCPU()
		busy = c.readHAProxyBusy()
		memory = readHostMemory()
	}
	var disk *pair
	var diskIO, network *pair
	if c.monitors["disk"] {
		if u, t, ok := readDiskSpace(c.diskPath); ok {
			disk = &pair{u, t}
		}
		diskIO = c.counterDelta("disk", readDiskCounters(c.diskstatsPath, c.sysBlockRoot))
	}
	if c.monitors["network"] {
		network = c.counterDelta("network", readNetworkCounters(c.sysNetRoot))
	}
	var temp *int64
	if c.monitors["temperature"] {
		if t, ok := readTemperature(c.thermalRoot); ok {
			temp = &t
		}
	}
	if cpu == nil && busy == nil && memory == nil && disk == nil && diskIO == nil && network == nil && temp == nil {
		return nil
	}
	b, err := c.machineBucket(hostKind, "", "", now)
	if err != nil {
		return err
	}
	b.Samples++
	if cpu != nil {
		b.addGauge("cpu", *cpu)
	}
	if busy != nil {
		b.addGauge("haproxy_busy", *busy)
	}
	if memory != nil {
		b.addGauge("memory", memory.a)
		b.addGauge("memory_total", memory.b)
	}
	if disk != nil {
		b.addGauge("disk_used", disk.a)
		b.addGauge("disk_total", disk.b)
	}
	if diskIO != nil {
		b.addCounter("disk_read", diskIO.a)
		b.addCounter("disk_write", diskIO.b)
	}
	if network != nil {
		b.addCounter("net_rx", network.a)
		b.addCounter("net_tx", network.b)
	}
	if temp != nil {
		b.addGauge("temp", *temp)
	}
	if !machine || !c.monitors["components"] {
		return nil
	}
	return c.observeComponents(now)
}

func (c *Collector) counterDelta(name string, current map[string]pair) *pair {
	previous, had := c.counterPrevious[name]
	if current == nil {
		delete(c.counterPrevious, name)
		return nil
	}
	c.counterPrevious[name] = current
	if !had {
		return nil
	}
	var first, second int64
	for dev, now := range current {
		before, ok := previous[dev]
		if !ok || now.a < before.a || now.b < before.b {
			continue
		}
		first += now.a - before.a
		second += now.b - before.b
	}
	return &pair{first, second}
}

func (c *Collector) sensors() *OMap {
	_, ok := readTemperature(c.thermalRoot)
	return omap("temperature", ok)
}

func (c *Collector) machineBucket(kind, proxy, server string, now int64) (*Bucket, error) {
	key := objectKey{kind, proxy, server}
	id, ok := c.objectIDs[key]
	if !ok {
		var err error
		id, err = c.db.ObjectID(kind, proxy, server, now)
		if err != nil {
			return nil, err
		}
		c.objectIDs[key] = id
	}
	b, ok := c.buckets[id]
	if !ok {
		b = newBucket()
		c.buckets[id] = b
	}
	return b, nil
}

func readHostMemory() *pair {
	raw, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return nil
	}
	values := map[string]int64{}
	for _, line := range strings.Split(string(raw), "\n") {
		name, rest, _ := strings.Cut(line, ":")
		if name == "MemTotal" || name == "MemAvailable" {
			f := strings.Fields(rest)
			if len(f) == 0 {
				return nil
			}
			n, err := strconv.ParseInt(f[0], 10, 64)
			if err != nil {
				return nil
			}
			values[name] = n
			if len(values) == 2 {
				break
			}
		}
	}
	total := values["MemTotal"]
	avail, ok := values["MemAvailable"]
	if total <= 0 || !ok {
		return nil
	}
	return &pair{maxI(0, total-avail), total}
}

type cgroupEntry struct{ name, group, path string }

func (c *Collector) componentCgroups() []cgroupEntry {
	found := []cgroupEntry{}
	type ctr struct{ id, path string }
	containers := []ctr{}
	system := filepath.Join(c.cgroupRoot, "system.slice")
	entries, _ := os.ReadDir(system)
	names := []string{}
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, entry := range names {
		path := filepath.Join(system, entry)
		hasPrefix := false
		for _, p := range componentUnitPrefixes {
			if strings.HasPrefix(entry, p) {
				hasPrefix = true
			}
		}
		switch {
		case engineUnits[entry] != "":
			found = append(found, cgroupEntry{engineUnits[entry], componentEngine, path})
		case strings.HasSuffix(entry, ".service") && hasPrefix:
			found = append(found, cgroupEntry{componentName(strings.TrimSuffix(entry, ".service")), componentService, path})
		case strings.HasPrefix(entry, "docker-") && strings.HasSuffix(entry, ".scope"):
			id := strings.TrimSuffix(strings.TrimPrefix(entry, "docker-"), ".scope")
			if containerIDRE.MatchString(id) {
				containers = append(containers, ctr{id, path})
			}
		}
	}
	dockerDir := filepath.Join(c.cgroupRoot, "docker")
	if dents, err := os.ReadDir(dockerDir); err == nil {
		dn := []string{}
		for _, e := range dents {
			dn = append(dn, e.Name())
		}
		sort.Strings(dn)
		for _, e := range dn {
			if containerIDRE.MatchString(e) {
				containers = append(containers, ctr{e, filepath.Join(dockerDir, e)})
			}
		}
	}
	live := map[string]bool{}
	for _, ct := range containers {
		live[ct.id] = true
		found = append(found, cgroupEntry{c.containerName(ct.id), componentContainer, ct.path})
	}
	for id := range c.containerNames {
		if !live[id] {
			delete(c.containerNames, id)
		}
	}
	if len(found) > maxComponents {
		found = found[:maxComponents]
	}
	return found
}

var containerNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

func (c *Collector) containerName(id string) string {
	if n, ok := c.containerNames[id]; ok {
		return n
	}
	name := id[:12]
	if raw, err := os.ReadFile(filepath.Join(c.containersDir, id, "config.v2.json")); err == nil {
		var v map[string]any
		if json.Unmarshal(raw, &v) == nil {
			rec := ""
			if s, ok := v["Name"].(string); ok {
				rec = strings.TrimLeft(s, "/")
			}
			if containerNameRE.MatchString(rec) {
				name = rec
			}
		}
	}
	c.containerNames[id] = name
	return name
}

func readCgroup(path string) (*int64, *int64) {
	var usage, memory *int64
	if raw, err := os.ReadFile(filepath.Join(path, "cpu.stat")); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(line, "usage_usec ") {
				f := strings.Fields(line)
				if len(f) > 1 {
					if n, err := strconv.ParseInt(f[1], 10, 64); err == nil {
						usage = &n
					}
				}
				break
			}
		}
	}
	if cur, ok := readIntFile(filepath.Join(path, "memory.current")); ok {
		var inactive int64
		valid := true
		if raw, err := os.ReadFile(filepath.Join(path, "memory.stat")); err == nil {
			for _, line := range strings.Split(string(raw), "\n") {
				if strings.HasPrefix(line, "inactive_file ") {
					f := strings.Fields(line)
					if len(f) < 2 {
						valid = false
						break
					}
					n, err := strconv.ParseInt(f[1], 10, 64)
					if err != nil {
						valid = false
					}
					inactive = n
					break
				}
			}
		} else {
			valid = false
		}
		if valid {
			m := floorDiv(maxI(0, cur-inactive), memoryUnit)
			memory = &m
		}
	}
	return usage, memory
}

func (c *Collector) observeComponents(now int64) error {
	moment := time.Now()
	processors := runtime.NumCPU()
	if processors < 1 {
		processors = 1
	}
	type reading struct{ cpu, memory *int64 }
	readings := map[[2]string]*reading{}
	order := [][2]string{}
	seen := map[string]bool{}
	for _, e := range c.componentCgroups() {
		if seen[e.path] {
			continue
		}
		seen[e.path] = true
		usage, memory := readCgroup(e.path)
		if usage == nil && memory == nil {
			continue
		}
		var cpu *int64
		if usage != nil {
			prev, ok := c.componentPrev[e.path]
			c.componentPrev[e.path] = compPrev{*usage, moment}
			if ok {
				used := *usage - prev.usage
				elapsed := moment.Sub(prev.moment).Seconds()
				if used >= 0 && elapsed > 0 {
					v := pyRoundInt(100 * cpuScale * float64(used) / (elapsed * 1e6 * float64(processors)))
					cpu = &v
				}
			}
		}
		key := [2]string{e.name, e.group}
		r, ok := readings[key]
		if !ok {
			r = &reading{}
			readings[key] = r
			order = append(order, key)
		}
		if cpu != nil {
			v := *cpu
			if r.cpu != nil {
				v += *r.cpu
			}
			r.cpu = &v
		}
		if memory != nil {
			v := *memory
			if r.memory != nil {
				v += *r.memory
			}
			r.memory = &v
		}
	}
	for _, key := range order {
		r := readings[key]
		b, err := c.machineBucket(componentKind, key[0], key[1], now)
		if err != nil {
			return err
		}
		b.Samples++
		if r.cpu != nil {
			b.addGauge("cpu", minI(100*cpuScale, *r.cpu))
		}
		if r.memory != nil {
			b.addGauge("memory", *r.memory)
		}
	}
	for p := range c.componentPrev {
		if !seen[p] {
			delete(c.componentPrev, p)
		}
	}
	return nil
}

func (c *Collector) readHostCPU() *int64 {
	raw, err := os.ReadFile("/proc/stat")
	if err != nil {
		return nil
	}
	line, _, _ := strings.Cut(string(raw), "\n")
	f := strings.Fields(line)
	if len(f) < 9 || f[0] != "cpu" {
		return nil
	}
	vals := make([]int64, 8)
	for i := 0; i < 8; i++ {
		n, err := strconv.ParseInt(f[i+1], 10, 64)
		if err != nil {
			return nil
		}
		vals[i] = n
	}
	idle := vals[3] + vals[4]
	var total int64
	for _, v := range vals {
		total += v
	}
	prev := c.cpuPrevious
	c.cpuPrevious = &cpuPrev{total, idle}
	if prev == nil {
		return nil
	}
	td, id := total-prev.total, idle-prev.idle
	if td <= 0 {
		return nil
	}
	busy := maxI(0, td-id)
	v := minI(100*cpuScale, pyRoundInt(100*cpuScale*float64(busy)/float64(td)))
	return &v
}

func (c *Collector) readHAProxyBusy() *int64 {
	payload, err := runtimeCommand(c.cfg.HAProxySocket, "show info")
	if err != nil {
		return nil
	}
	for _, line := range splitLines(payload) {
		name, value, found := strings.Cut(line, ":")
		if found && strings.TrimSpace(name) == "Idle_pct" {
			idle := maxI(0, minI(100, toInt(value)))
			v := (100 - idle) * cpuScale
			return &v
		}
	}
	return nil
}

func (c *Collector) observe(kind, proxy, server string, row map[string]string, now int64) error {
	key := objectKey{kind, proxy, server}
	id, ok := c.objectIDs[key]
	if !ok {
		var err error
		if id, err = c.db.ObjectID(kind, proxy, server, now); err != nil {
			return err
		}
		c.objectIDs[key] = id
	}
	b, ok := c.buckets[id]
	if !ok {
		b = newBucket()
		c.buckets[id] = b
	}
	b.Samples++
	for _, cc := range counterColumns {
		b.addCounter(cc.name, c.delta(id, cc.name, toInt(row[cc.col]), now))
	}
	var other int64
	for _, col := range otherResponseColumns {
		other += toInt(row[col])
	}
	b.addCounter("resp_other", c.delta(id, "resp_other", other, now))
	for _, gc := range gaugeColumns {
		b.addGauge(gc.name, toInt(row[gc.col]))
	}
	if kind == "server" || kind == "backend" {
		if err := c.trackState(id, strings.TrimSpace(row["status"]), now); err != nil {
			return err
		}
	}
	if kind == "server" {
		addr := strings.TrimSpace(row["addr"])
		if addr != "" && c.addresses[id] != addr {
			c.addresses[id] = addr
			if err := c.db.setObjectAddress(id, addr); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Collector) delta(id int64, metric string, current, now int64) int64 {
	key := baselineKey{id, metric}
	prev, ok := c.baselines[key]
	c.baselines[key] = baselineVal{current, now}
	if !ok || current < prev.value {
		return 0
	}
	maxGap := maxI(baselineMaxGapSeconds, 3*c.cfg.PollIntervalSeconds)
	if now-prev.updated > maxGap {
		return 0
	}
	return current - prev.value
}

func (c *Collector) continueRenamed(rows []map[string]string) error {
	names := map[string]map[string]bool{}
	for _, row := range rows {
		kind, proxy, server, ok := classify(row)
		if ok && kind == "server" {
			if names[proxy] == nil {
				names[proxy] = map[string]bool{}
			}
			names[proxy][server] = true
		}
	}
	for _, row := range rows {
		kind, proxy, server, ok := classify(row)
		if !ok || kind != "server" {
			continue
		}
		identity := objectKey{kind, proxy, server}
		if _, known := c.objectIDs[identity]; known {
			continue
		}
		addr := strings.TrimSpace(row["addr"])
		if addr == "" || c.cfg.Excluded(proxy) {
			continue
		}
		if c.db.ObjectExists("server", proxy, server) {
			continue
		}
		id, old, found := c.db.renameCandidate(proxy, addr, names[proxy])
		if !found {
			continue
		}
		if err := c.db.renameServer(id, server); err != nil {
			return err
		}
		delete(c.objectIDs, objectKey{"server", proxy, old})
		c.objectIDs[identity] = id
		log.Printf("Server %s/%s continues as %s (same address %s)", proxy, old, server, addr)
	}
	return nil
}

func (c *Collector) retireMissing(present map[int64]bool, now int64) error {
	for id := range present {
		c.seenSinceStart[id] = true
	}
	for _, id := range sortedIDs(c.lastStates) {
		state := c.lastStates[id]
		if present[id] || state == removedState {
			delete(c.missing, id)
			continue
		}
		m, ok := c.missing[id]
		if !ok {
			m = missingEntry{now, 0}
		}
		m.count++
		if m.count < retireAfterPolls || c.storage.writesPaused {
			c.missing[id] = m
			continue
		}
		delete(c.missing, id)
		first := m.first
		if !c.seenSinceStart[id] {
			last, ok := c.db.lastObserved(id)
			if !ok || last == 0 {
				last = first
			}
			first = minI(now, last)
		}
		c.lastStates[id] = removedState
		if err := c.db.recordStateChange(id, state, removedState, first); err != nil {
			return err
		}
	}
	return nil
}

func (c *Collector) trackState(id int64, status string, now int64) error {
	if status == "" {
		return nil
	}
	state := strings.ToUpper(strings.TrimSpace(strings.SplitN(status, " ", 2)[0]))
	if state == "" {
		return nil
	}
	prev := c.lastStates[id]
	if prev == state || c.storage.writesPaused {
		return nil
	}
	c.lastStates[id] = state
	return c.db.recordStateChange(id, prev, state, now)
}

func (c *Collector) flush(force bool) (int, error) {
	n, pending, err := func() (int, []alerts.Observation, error) {
		c.mu.Lock()
		defer c.mu.Unlock()
		if !c.hasBucket {
			return 0, nil, nil
		}
		now := utcNow()
		current := now - now%bucketSeconds
		if !force && current == c.bucketTS {
			return 0, nil, nil
		}
		n, obs, err := c.flushLocked(c.bucketTS)
		c.bucketTS = current
		return n, obs, err
	}()
	c.sendObservations(pending)
	return n, err
}

func (c *Collector) flushLocked(bucketTS int64) (int, []alerts.Observation, error) {
	if len(c.buckets) == 0 {
		return 0, nil, nil
	}
	rows := map[int64]map[string]int64{}
	for id, b := range c.buckets {
		if b.Samples != 0 {
			rows[id] = b.row()
		}
	}
	if len(rows) == 0 {
		c.buckets = map[int64]*Bucket{}
		c.bucketReported = false
		return 0, nil, nil
	}
	var pending []alerts.Observation
	if !c.bucketReported {
		pending = c.trafficObservationsLocked(rows)
		c.bucketReported = true
	}
	if c.storage.writesPaused {
		c.bucketsDropped += int64(len(rows))
		c.buckets = map[int64]*Bucket{}
		c.bucketReported = false
		return 0, pending, nil
	}
	if err := c.db.writeBuckets(bucketTS, rows, true, c.baselines); err != nil {
		return 0, pending, err
	}
	c.buckets = map[int64]*Bucket{}
	c.bucketReported = false
	c.lastFlushTS = bucketTS
	c.bucketsWritten += int64(len(rows))
	return len(rows), pending, nil
}

// Monitor maps are replaced, never mutated, once they are published.
func (c *Collector) monitorSnapshot() (map[string]bool, any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.monitors, c.digestsAvailable
}

func (c *Collector) pullDigests(now int64) (int, error) {
	monitors, _ := c.monitorSnapshot()
	anyOn := false
	for _, n := range digestMonitors {
		if monitors[n] {
			anyOn = true
		}
	}
	if !anyOn || c.storage.writesPaused {
		return 0, nil
	}
	since := toInt(c.db.getState(digestCursorKey, "0"))
	payload, err := unixGetJSON(c.guarddSocket, fmt.Sprintf("/api/v1/guard/digest?since=%d", since), 10*time.Second)
	c.mu.Lock()
	c.digestsAvailable = err == nil
	c.mu.Unlock()
	if err != nil {
		return 0, err
	}
	bounds, _ := payload["bounds_ms"].([]any)
	if len(bounds) != len(digestBoundsMS) {
		log.Printf("guardd's histogram differs from ours; digests skipped")
		return 0, nil
	}
	for i, b := range bounds {
		if n, ok := pyIntAny(b); !ok || n != digestBoundsMS[i] {
			log.Printf("guardd's histogram differs from ours; digests skipped")
			return 0, nil
		}
	}
	written := 0
	newest := since
	minutes, _ := payload["minutes"].([]any)
	for _, mAny := range minutes {
		minute, ok := mAny.(map[string]any)
		if !ok {
			continue
		}
		ts, ok := pyIntAny(minute["ts"])
		if !ok {
			continue
		}
		if ts <= since {
			continue
		}
		newest = maxI(newest, ts)
		if monitors["percentiles"] {
			rows := map[int64][]int64{}
			backends, _ := minute["backends"].(map[string]any)
			proxies := make([]string, 0, len(backends))
			for p := range backends {
				proxies = append(proxies, p)
			}
			sort.Strings(proxies)
			for _, proxy := range proxies {
				counts, ok := backends[proxy].([]any)
				if !ok || len(counts) != len(histogramColumns) || c.cfg.Excluded(proxy) {
					continue
				}
				name := proxy
				if r := []rune(name); len(r) > 200 {
					name = string(r[:200])
				}
				id, err := c.objectFor("backend", name, now)
				if err != nil {
					return written, err
				}
				vals := make([]int64, len(counts))
				for i, v := range counts {
					n, _ := pyIntAny(v)
					vals[i] = maxI(0, n)
				}
				rows[id] = vals
			}
			if err := c.db.writeLatency(ts, rows); err != nil {
				return written, err
			}
			written += len(rows)
		}
		if monitors["refusals"] {
			refused, _ := minute["refused"].(map[string]any)
			row := map[string]int64{}
			for _, col := range metricColumns {
				row[col] = 0
			}
			row["samples"] = 1
			for _, k := range []string{"geo", "banned", "rate", "other"} {
				var v int64
				if raw, ok := refused[k]; ok {
					v = toInt(pyStrValue(raw))
				}
				row["refused_"+k] = maxI(0, v)
			}
			id, err := c.objectFor(edgeKind, "", now)
			if err != nil {
				return written, err
			}
			if err := c.db.writeBuckets(ts, map[int64]map[string]int64{id: row}, false, nil); err != nil {
				return written, err
			}
			written++
		}
	}
	if newest > since {
		if err := c.db.setState(digestCursorKey, strconv.FormatInt(newest, 10)); err != nil {
			return written, err
		}
	}
	return written, nil
}

func pyStrValue(v any) string {
	switch x := v.(type) {
	case json.Number:
		return x.String()
	case string:
		return x
	case nil:
		return ""
	case bool:
		if x {
			return "True"
		}
		return "False"
	}
	return fmt.Sprint(v)
}

func (c *Collector) objectFor(kind, proxy string, now int64) (int64, error) {
	key := objectKey{kind, proxy, ""}
	if id, ok := c.objectIDs[key]; ok {
		return id, nil
	}
	id, err := c.db.ObjectID(kind, proxy, "", now)
	if err != nil {
		return 0, err
	}
	c.objectIDs[key] = id
	return id, nil
}

func (c *Collector) runMaintenance() (*OMap, error) {
	now := utcNow()
	rolled, err := c.db.rollupHours(now - now%hourSeconds)
	if err != nil {
		return nil, err
	}
	lagged := now - latencyRollupLag
	lr, err := c.db.rollupLatencyHours(lagged - lagged%hourSeconds)
	if err != nil {
		return nil, err
	}
	rolled += lr
	r := c.storage.retentionForLevel(c.storage.pressureLevel)
	deleted, err := c.db.applyRetention(now-r.Value("minute_days").(int64)*86400, now-r.Value("minute_server_hours").(int64)*3600,
		now-r.Value("hour_days").(int64)*86400)
	if err != nil {
		return nil, err
	}
	if anyDeleted(deleted) {
		c.db.incrementalVacuum(256)
	}
	status, actions := c.storage.enforce(now)
	shown := strings.Join(actions, ",")
	if shown == "" {
		shown = "none"
	}
	log.Printf("Maintenance: rolled=%d deleted=%s storage=%s actions=%s", rolled, deletedJSON(deleted), status.State, shown)
	acts := make([]any, len(actions))
	for i, a := range actions {
		acts[i] = a
	}
	return omap("rolled_up", rolled, "deleted", omap("minutes", deleted["minutes"], "server_minutes", deleted["server_minutes"],
		"hours", deleted["hours"], "events", deleted["events"]), "storage_state", status.State, "actions", acts), nil
}

func (c *Collector) health() *OMap {
	c.mu.Lock()
	defer c.mu.Unlock()
	storage := c.storage.published.Load()
	now := utcNow()
	stale := maxI(60, c.cfg.PollIntervalSeconds*6)
	var age any
	degraded := c.lastPollTS == nil
	if c.lastPollTS != nil {
		a := now - c.lastPollTS.(int64)
		age = a
		degraded = a > stale
	}
	return omap("running", c.running, "degraded", degraded, "poll_interval_seconds", c.cfg.PollIntervalSeconds,
		"last_poll_ts", c.lastPollTS, "last_poll_age_seconds", age, "last_flush_ts", c.lastFlushTS,
		"polls_total", c.pollsTotal, "buckets_written", c.bucketsWritten, "buckets_dropped", c.bucketsDropped,
		"writes_paused", storage.writesPaused, "storage_state", storage.state,
		"consecutive_failures", c.consecutiveFails, "last_error", c.lastError)
}

var _ = math.Abs
