// Package metricsd is the Go port of easy-ha-proxy-metricsd (ansible/roles/
// haproxy-admin/files/metricsd/*.py). The Python package is the
// specification: the same metrics.db SQLite schema (v2) and queries, the same
// collector arithmetic, and the same HTTP API on the Unix socket.
package metricsd

import (
	"context"
	"encoding/json"
	"log"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/haproxy"
)

var (
	SocketPath   = envDefault("METRICSD_SOCKET_PATH", "/run/easy-ha-proxy/easy-ha-proxy-metricsd.sock")
	SocketGroup  = envDefault("METRICSD_SOCKET_GROUP", "hadmin")
	ConfigPath   = envDefault("METRICSD_CONFIG", "/opt/haproxy-admin/metricsd.json")
	DatabasePath = envDefault("METRICSD_DATABASE", "/var/lib/easy-ha-proxy/metrics/metrics.db")
	GuarddSocket = envDefault("GUARDD_SOCKET_PATH", "/run/easy-ha-proxy/easy-ha-proxy-guardd.sock")
)

func envDefault(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

const (
	schemaVersion          = 2
	runtimeMaxBytes        = 8 * 1024 * 1024
	runtimeTimeout         = 5 * time.Second
	bucketSeconds          = 60
	hourSeconds            = 3600
	baselineMaxGapSeconds  = 2 * bucketSeconds
	gib                    = int64(1) << 30
	mib                    = int64(1) << 20
	autoMaxDatabaseBytes   = 5 * gib
	autoMaxDatabaseFrac    = 0.10
	autoReserveFloorBytes  = 2 * gib
	autoReserveCeilBytes   = 10 * gib
	autoReserveFraction    = 0.10
	warningDatabaseFrac    = 0.80
	pressureDatabaseFrac   = 0.90
	resumeDatabaseFrac     = 0.95
	resumeMarginFloor      = 512 * mib
	resumeMarginFSFraction = 0.05
	resumeMarginFraction   = 0.10
	defaultWALSoftLimit    = 64 * mib
	stateNormal            = "NORMAL"
	stateWarning           = "WARNING"
	statePressure          = "PRESSURE"
	stateCritical          = "CRITICAL"
	storageSampleInterval  = 3600
	storageSampleRetention = 30 * 86400
	stableGrowthFloor      = 8 * mib
	stableGrowthFraction   = 0.02
	maxChartPoints         = 1500
	maxRangeSeconds        = 365 * 86400
	maxTimelineSpans       = 200
	removedState           = "REMOVED"
	retireAfterPolls       = 3
	absentSpan             = "ABSENT"
	defaultRange           = "24h"
	edgeKind               = "edge"
	digestPullSeconds      = 60
	digestCursorKey        = "digest_cursor"
	latencyRollupLag       = 600
	diskPath               = "/"
	diskstatsPath          = "/proc/diskstats"
	sysBlockRoot           = "/sys/block"
	sysNetRoot             = "/sys/class/net"
	thermalRoot            = "/sys/class/thermal"
	diskstatsSector        = 512
	temperatureLowMilli    = -40000
	temperatureHighMilli   = 150000
	hostKind               = "host"
	componentKind          = "component"
	componentService       = "service"
	componentContainer     = "container"
	componentEngine        = "engine"
	cgroupRoot             = "/sys/fs/cgroup"
	dockerContainersDir    = "/var/lib/docker/containers"
	maxComponents          = 48
	memoryUnit             = 1024
	cpuScale               = 10
)

// retentionLadder is RETENTION_LADDER (level 0 means "as configured").
var retentionLadder = []map[string]int{
	{},
	{"minute_days": 3, "minute_server_hours": 6, "hour_days": 180},
	{"minute_days": 1, "minute_server_hours": 2, "hour_days": 90},
	{"minute_days": 1, "minute_server_hours": 1, "hour_days": 30},
}

var sizeUnits = map[string]int64{"": 1, "b": 1, "k": 1000, "kb": 1000, "kib": 1024, "m": 1000 * 1000, "mb": 1000 * 1000,
	"mib": mib, "g": 1000 * 1000 * 1000, "gb": 1000 * 1000 * 1000, "gib": gib, "t": 1000 * 1000 * 1000 * 1000,
	"tb": 1000 * 1000 * 1000 * 1000, "tib": 1024 * gib}

var sizeRE = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)?)\s*([a-z]*)$`)

var ranges = map[string]int64{"1h": 3600, "6h": 6 * 3600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400,
	"90d": 90 * 86400, "1y": 365 * 86400}

var aggregations = map[string]string{
	"requests": "sum", "sessions": "sum", "bytes_in": "sum", "bytes_out": "sum", "resp_2xx": "sum", "resp_3xx": "sum",
	"resp_4xx": "sum", "resp_5xx": "sum", "resp_other": "sum", "check_failures": "sum", "conn_cur_avg": "wavg",
	"conn_cur_max": "max", "queue_avg": "wavg", "queue_max": "max", "response_ms_avg": "wavg", "response_ms_max": "max",
	"total_ms_avg": "wavg", "connect_ms_avg": "wavg", "queue_ms_avg": "wavg", "cpu_avg": "wavg", "cpu_max": "max",
	"haproxy_busy_avg": "wavg", "haproxy_busy_max": "max", "disk_used_avg": "wavg", "disk_total": "max",
	"disk_read": "sum", "disk_write": "sum", "net_rx": "sum", "net_tx": "sum", "temp_avg": "wavg", "temp_max": "max",
	"refused_geo": "sum", "refused_banned": "sum", "refused_rate": "sum", "refused_other": "sum",
	"memory_avg": "wavg", "memory_max": "max", "memory_total": "max",
}

var chartSeries = map[string][]string{
	"requests":    {"requests"},
	"traffic":     {"bytes_in", "bytes_out"},
	"responses":   {"resp_2xx", "resp_3xx", "resp_4xx", "resp_5xx"},
	"latency":     {"response_ms_avg", "response_ms_max"},
	"connections": {"conn_cur_avg", "conn_cur_max"},
	"cpu":         {"cpu_avg", "cpu_max", "haproxy_busy_avg"},
	"memory":      {"memory_avg", "memory_max", "memory_total"},
	"disk":        {"disk_used_avg", "disk_total"},
	"diskio":      {"disk_read", "disk_write"},
	"network":     {"net_rx", "net_tx"},
	"temperature": {"temp_avg", "temp_max"},
	"percentiles": {"p50", "p95", "p99"},
	"refusals":    {"refused_geo", "refused_banned", "refused_rate", "refused_other"},
}

var hostCharts = map[string]bool{"cpu": true, "memory": true, "disk": true, "diskio": true, "network": true, "temperature": true}

var digestBoundsMS = []int64{5, 10, 25, 50, 75, 100, 150, 200, 300, 500, 750, 1000, 1500, 2000, 3000, 5000, 10000, 30000}

var histogramColumns = func() []string {
	out := make([]string, len(digestBoundsMS)+1)
	for i := range out {
		out[i] = "h" + strconv.Itoa(i)
	}
	return out
}()

var percentiles = []struct {
	name  string
	share float64
}{{"p50", 0.50}, {"p95", 0.95}, {"p99", 0.99}}

var componentColumns = map[string][2]string{"cpu": {"cpu_avg", "cpu_max"}, "memory": {"memory_avg", "memory_max"}}
var componentUnitPrefixes = []string{"haproxy", "easy-ha-proxy-", "authelia-"}
var engineUnits = map[string]string{"docker.service": "dockerd", "containerd.service": "containerd"}

var transientUnits = []*regexp.Regexp{
	regexp.MustCompile(`^(?P<service>.+)-job-[0-9a-f]{6,32}$`),
	regexp.MustCompile(`^(?P<service>easy-ha-proxy-web-reboot)-[0-9a-f]{12}$`),
	regexp.MustCompile(`^(?P<service>easy-ha-proxy-reboot)-[0-9]{14}-[0-9]+-[0-9a-f]{8}$`),
}

// componentName is component_name: a transient unit counts under its service.
func componentName(name string) string {
	for _, re := range transientUnits {
		if m := re.FindStringSubmatch(name); m != nil {
			return m[1]
		}
	}
	return name
}

var containerIDRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

var summaryColumns = []string{"requests", "sessions", "bytes_in", "bytes_out", "resp_2xx", "resp_3xx", "resp_4xx",
	"resp_5xx", "resp_other"}

// aggregateSQL is _aggregate_sql.
func aggregateSQL(column string) string {
	switch aggregations[column] {
	case "sum":
		return "COALESCE(SUM(" + column + "), 0)"
	case "max":
		return "COALESCE(MAX(" + column + "), 0)"
	}
	return "CAST(COALESCE(SUM(" + column + " * samples) / NULLIF(SUM(samples), 0), 0) AS INTEGER)"
}

// pyRound1 is round(x, 1) for a float, ties to even on the exact value.
func pyRound1(x float64) float64 {
	f, _ := strconv.ParseFloat(strconv.FormatFloat(x, 'f', 1, 64), 64)
	return f
}

// pyRoundN is round(x, n).
func pyRoundN(x float64, n int) float64 {
	f, _ := strconv.ParseFloat(strconv.FormatFloat(x, 'f', n, 64), 64)
	return f
}

// pyRoundInt is round(x) to an int (ties to even).
func pyRoundInt(x float64) int64 { return int64(math.RoundToEven(x)) }

// fromStorage is _from_storage.
func fromStorage(chart string, value any) any {
	v, isNull := asInt(value)
	switch chart {
	case "memory":
		return v * memoryUnit
	case "disk":
		if isNull || v == 0 {
			return nil
		}
		return v * memoryUnit
	case "diskio", "network", "refusals":
		return v
	case "temperature":
		if isNull || v == 0 {
			return nil
		}
		return pyRound1(float64(v) / cpuScale)
	}
	return pyRound1(float64(v) / cpuScale)
}

// asInt reads an SQLite value as int(value or 0); isNull is value is None.
func asInt(v any) (int64, bool) {
	switch x := v.(type) {
	case nil:
		return 0, true
	case int64:
		return x, false
	case int:
		return int64(x), false
	case float64:
		return int64(x), false
	case []byte:
		n, _ := strconv.ParseInt(string(x), 10, 64)
		return n, false
	case string:
		n, _ := strconv.ParseInt(x, 10, 64)
		return n, false
	}
	return 0, false
}

func resolveRange(value string) (string, int64) {
	key := strings.ToLower(strings.TrimSpace(value))
	if _, ok := ranges[key]; !ok {
		key = defaultRange
	}
	s := ranges[key]
	if s > maxRangeSeconds {
		s = maxRangeSeconds
	}
	return key, s
}

func utcNow() int64 { return time.Now().Unix() }

// resolveWindow is resolve_window over a parsed query string.
func resolveWindow(query map[string][]string) (string, int64, int64) {
	number := func(name string) (int64, bool) {
		vals := query[name]
		raw := ""
		if len(vals) > 0 {
			raw = vals[0]
		}
		v, ok := pyIntText(raw)
		if !ok || v <= 0 {
			return 0, false
		}
		return v, true
	}
	since, okS := number("since")
	until, okU := number("until")
	if okS && okU && until > since {
		span := until - since
		if span > maxRangeSeconds {
			span = maxRangeSeconds
		}
		return "custom", until - span, until
	}
	raw := ""
	if v := query["range"]; len(v) > 0 {
		raw = v[0]
	}
	key, seconds := resolveRange(raw)
	now := utcNow()
	return key, now - seconds, now
}

// pyIntText is int(str(raw).strip()).
func pyIntText(raw string) (int64, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, false
	}
	t := strings.ReplaceAll(s, "_", "")
	if strings.HasPrefix(s, "_") || strings.HasSuffix(s, "_") || strings.Contains(s, "__") {
		return 0, false
	}
	n, err := strconv.ParseInt(t, 10, 64)
	return n, err == nil
}

// chooseResolution is choose_resolution.
func chooseResolution(rangeSeconds int64) (string, int64) {
	if rangeSeconds <= 86400 {
		return "metric_1m", bucketSeconds
	}
	hours := (rangeSeconds + hourSeconds - 1) / hourSeconds
	step := (hours + maxChartPoints - 1) / maxChartPoints
	if step < 1 {
		step = 1
	}
	return "metric_1h", hourSeconds * step
}

var counterColumns = []struct{ name, col string }{
	{"requests", "req_tot"}, {"sessions", "stot"}, {"bytes_in", "bin"}, {"bytes_out", "bout"},
	{"resp_2xx", "hrsp_2xx"}, {"resp_3xx", "hrsp_3xx"}, {"resp_4xx", "hrsp_4xx"}, {"resp_5xx", "hrsp_5xx"},
	{"check_failures", "chkfail"},
}
var otherResponseColumns = []string{"hrsp_1xx", "hrsp_other"}
var gaugeColumns = []struct{ name, col string }{
	{"conn_cur", "scur"}, {"queue", "qcur"}, {"queue_ms", "qtime"}, {"connect_ms", "ctime"},
	{"response_ms", "rtime"}, {"total_ms", "ttime"},
}

var metricColumns = []string{"samples", "requests", "sessions", "bytes_in", "bytes_out", "resp_2xx", "resp_3xx",
	"resp_4xx", "resp_5xx", "resp_other", "check_failures", "conn_cur_avg", "conn_cur_max", "queue_avg", "queue_max",
	"queue_ms_avg", "connect_ms_avg", "response_ms_avg", "response_ms_max", "total_ms_avg", "cpu_avg", "cpu_max",
	"haproxy_busy_avg", "haproxy_busy_max", "memory_avg", "memory_max", "memory_total", "disk_used_avg", "disk_total",
	"disk_read", "disk_write", "net_rx", "net_tx", "temp_avg", "temp_max", "refused_geo", "refused_banned",
	"refused_rate", "refused_other"}

func rollupColumns(kind string) []string {
	out := []string{}
	for _, c := range metricColumns {
		if aggregations[c] == kind {
			out = append(out, c)
		}
	}
	return out
}

var (
	rollupSum  = rollupColumns("sum")
	rollupMax  = rollupColumns("max")
	rollupWavg = rollupColumns("wavg")
)

var defaultExcludeExact = []string{"be_admin", "be_stats", "be_http_challenge", "be_tls_terminator", "be_maintenance"}
var defaultExcludePrefix = []string{"tbl_"}

// pyIntAny is int(value) for a JSON value (None and junk are not ints).
func pyIntAny(v any) (int64, bool) {
	switch x := v.(type) {
	case bool:
		if x {
			return 1, true
		}
		return 0, true
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return 0, false
		}
		return int64(x), true
	case json.Number:
		if n, err := x.Int64(); err == nil {
			return n, true
		}
		f, err := x.Float64()
		if err != nil {
			return 0, false
		}
		return int64(f), true
	case string:
		return pyIntText(x)
	}
	return 0, false
}

func clampInt(v any, def, lo, hi int64) int64 {
	n, ok := pyIntAny(v)
	if !ok {
		return def
	}
	if n < lo {
		return lo
	}
	if n > hi {
		return hi
	}
	return n
}

// parseSize is parse_size; ok is false for "decide at runtime".
func parseSize(v any, def int64, hasDef bool) (int64, bool) {
	switch x := v.(type) {
	case nil:
		return def, hasDef
	case bool:
		return def, hasDef
	case json.Number:
		f, err := x.Float64()
		if err != nil || f <= 0 {
			return def, hasDef
		}
		return int64(f), true
	case float64:
		if x <= 0 {
			return def, hasDef
		}
		return int64(x), true
	}
	text := strings.ToLower(strings.TrimSpace(pyStr(v)))
	if text == "" || text == "auto" || text == "unlimited" || text == "none" {
		return def, hasDef
	}
	m := sizeRE.FindStringSubmatch(text)
	if m == nil {
		return def, hasDef
	}
	mult, ok := sizeUnits[m[2]]
	if !ok {
		return def, hasDef
	}
	amount, _ := strconv.ParseFloat(m[1], 64)
	parsed := int64(amount * float64(mult))
	if parsed <= 0 {
		return def, hasDef
	}
	return parsed, true
}

func pyStr(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case string:
		return x
	case bool:
		if x {
			return "True"
		}
		return "False"
	case json.Number:
		return x.String()
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// toInt is _to_int for a Runtime API cell.
func toInt(text string) int64 {
	t := strings.TrimSpace(text)
	if t == "" {
		return 0
	}
	if n, err := strconv.ParseInt(t, 10, 64); err == nil {
		return n
	}
	if f, err := strconv.ParseFloat(t, 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
		return int64(f)
	}
	return 0
}

// ---------------------------------------------------------------------------
// configuration (runtime.py)
// ---------------------------------------------------------------------------

// Config is MetricsConfig.
type Config struct {
	Enabled                       bool
	PollIntervalSeconds           int64
	HAProxySocket                 string
	MaintenanceIntervalSeconds    int64
	RetentionOneMinuteDays        int64
	RetentionOneMinuteServerHours int64
	RetentionOneHourDays          int64
	ExcludeExact, ExcludePrefix   []string
	MaxDatabaseBytes              int64
	HasMaxDatabaseBytes           bool
	ReservedFreeBytes             int64
	HasReservedFreeBytes          bool
	AutoReduceRetention           bool
	WALSoftLimitBytes             int64
	AlertErrorRatioPercent        int64
	AlertSlowResponseMS           int64
	AlertMinRequests              int64
}

// Excluded is MetricsConfig.excluded.
func (c Config) Excluded(proxy string) bool {
	if proxy == "" {
		return true
	}
	for _, e := range c.ExcludeExact {
		if proxy == e {
			return true
		}
	}
	for _, p := range c.ExcludePrefix {
		if strings.HasPrefix(proxy, p) {
			return true
		}
	}
	return false
}

func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case json.Number:
		f, _ := x.Float64()
		return f != 0
	case float64:
		return x != 0
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

func getDefault(m map[string]any, key string, def any) any {
	if v, ok := m[key]; ok {
		return v
	}
	return def
}

// LoadConfig is load_config.
func LoadConfig(path string) Config {
	raw := map[string]any{}
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		dec := json.NewDecoder(strings.NewReader(string(data)))
		dec.UseNumber()
		var loaded any
		if derr := dec.Decode(&loaded); derr != nil {
			log.Printf("Cannot read config %s (%v); using defaults", path, derr)
		} else if m, ok := loaded.(map[string]any); ok {
			raw = m
		} else {
			log.Printf("Config %s is not an object; using defaults", path)
		}
	case os.IsNotExist(err):
		log.Printf("Config %s not found; using defaults", path)
	default:
		log.Printf("Cannot read config %s (%v); using defaults", path, err)
	}
	section := func(name string) map[string]any {
		if m, ok := raw[name].(map[string]any); ok {
			return m
		}
		return map[string]any{}
	}
	retention, exclude, storage, alertsCfg := section("retention"), section("exclude"), section("storage"), section("alerts")
	stringTuple := func(v any, fallback []string) []string {
		list, ok := v.([]any)
		if !ok {
			return fallback
		}
		out := []string{}
		for _, it := range list {
			if s := strings.TrimSpace(pyStr(it)); s != "" {
				out = append(out, s)
			}
		}
		if len(out) == 0 {
			return fallback
		}
		return out
	}
	socket := "/run/haproxy/admin.sock"
	if truthy(raw["haproxy_socket"]) {
		socket = strings.TrimSpace(pyStr(raw["haproxy_socket"]))
	}
	c := Config{
		Enabled:                       truthy(getDefault(raw, "enabled", true)),
		PollIntervalSeconds:           clampInt(raw["poll_interval_seconds"], 10, 5, 60),
		HAProxySocket:                 socket,
		MaintenanceIntervalSeconds:    clampInt(raw["maintenance_interval_seconds"], 300, 60, 3600),
		RetentionOneMinuteDays:        clampInt(retention["one_minute_days"], 7, 1, 90),
		RetentionOneMinuteServerHours: clampInt(retention["one_minute_server_hours"], 24, 1, 2160),
		RetentionOneHourDays:          clampInt(retention["one_hour_days"], 365, 1, 3650),
		ExcludeExact:                  stringTuple(exclude["exact"], defaultExcludeExact),
		ExcludePrefix:                 stringTuple(exclude["prefix"], defaultExcludePrefix),
		AutoReduceRetention:           truthy(getDefault(storage, "auto_reduce_retention", true)),
		AlertErrorRatioPercent:        clampInt(alertsCfg["error_ratio_percent"], 10, 0, 100),
		AlertSlowResponseMS:           clampInt(alertsCfg["slow_response_ms"], 3000, 0, 600000),
		AlertMinRequests:              clampInt(alertsCfg["min_requests"], 20, 1, 1000000),
	}
	c.MaxDatabaseBytes, c.HasMaxDatabaseBytes = parseSize(storage["max_database_size"], 0, false)
	c.ReservedFreeBytes, c.HasReservedFreeBytes = parseSize(storage["reserved_free_space"], 0, false)
	c.WALSoftLimitBytes, _ = parseSize(storage["wal_soft_limit"], defaultWALSoftLimit, true)
	if c.WALSoftLimitBytes == 0 {
		c.WALSoftLimitBytes = defaultWALSoftLimit
	}
	return c
}

// runtimeCommand is runtime_command: one Runtime API command, raw reply.
func runtimeCommand(socketPath, command string) (string, error) {
	client := haproxy.NewClient(socketPath)
	client.Timeout = runtimeTimeout
	client.MaxBytes = runtimeMaxBytes
	payload, err := client.Command(context.Background(), command)
	return strings.ToValidUTF8(payload, "�"), err
}

// parseShowStat is parse_show_stat.
func parseShowStat(payload string) []map[string]string {
	lines := []string{}
	for _, l := range splitLines(payload) {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) == 0 || !strings.HasPrefix(lines[0], "#") {
		return nil
	}
	header := []string{}
	for _, cell := range strings.Split(strings.TrimLeft(lines[0], "# "), ",") {
		header = append(header, strings.TrimSpace(cell))
	}
	hasPx, hasSv := false, false
	for _, h := range header {
		hasPx = hasPx || h == "pxname"
		hasSv = hasSv || h == "svname"
	}
	if !hasPx || !hasSv {
		return nil
	}
	rows := []map[string]string{}
	for _, line := range lines[1:] {
		if strings.HasPrefix(line, "#") {
			continue
		}
		cells := strings.Split(line, ",")
		row := map[string]string{}
		for i := 0; i < len(header) && i < len(cells); i++ {
			row[header[i]] = cells[i]
		}
		if row["pxname"] != "" && row["svname"] != "" {
			rows = append(rows, row)
		}
	}
	return rows
}

// classify returns (kind, proxy, server), ok false to skip the row.
func classify(row map[string]string) (string, string, string, bool) {
	proxy, sv := strings.TrimSpace(row["pxname"]), strings.TrimSpace(row["svname"])
	if proxy == "" || sv == "" {
		return "", "", "", false
	}
	switch sv {
	case "FRONTEND":
		return "frontend", proxy, "", true
	case "BACKEND":
		return "backend", proxy, "", true
	}
	return "server", proxy, sv, true
}

// splitLines is str.splitlines().
func splitLines(text string) []string {
	out := []string{}
	start := 0
	rs := []rune(text)
	for i := 0; i < len(rs); i++ {
		switch rs[i] {
		case '\n', '\r', '\v', '\f', 0x1c, 0x1d, 0x1e, 0x85, 0x2028, 0x2029:
			out = append(out, string(rs[start:i]))
			if rs[i] == '\r' && i+1 < len(rs) && rs[i+1] == '\n' {
				i++
			}
			start = i + 1
		}
	}
	if start < len(rs) {
		out = append(out, string(rs[start:]))
	}
	return out
}
