package metricsd

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

var schemaStatements = []string{
	"CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)",
	`
    CREATE TABLE IF NOT EXISTS objects (
        id         INTEGER PRIMARY KEY,
        kind       TEXT    NOT NULL,
        proxy      TEXT    NOT NULL,
        server     TEXT    NOT NULL,
        first_seen INTEGER NOT NULL,
        last_seen  INTEGER NOT NULL,
        UNIQUE (kind, proxy, server)
    )
    `,
	`
    CREATE TABLE IF NOT EXISTS counter_baseline (
        object_id  INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
        metric     TEXT    NOT NULL,
        value      INTEGER NOT NULL,
        updated_ts INTEGER NOT NULL,
        PRIMARY KEY (object_id, metric)
    ) WITHOUT ROWID
    `,
	`
    CREATE TABLE IF NOT EXISTS server_state_events (
        id             INTEGER PRIMARY KEY,
        ts             INTEGER NOT NULL,
        object_id      INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
        previous_state TEXT    NOT NULL,
        state          TEXT    NOT NULL
    )
    `,
	"CREATE INDEX IF NOT EXISTS idx_state_events_ts ON server_state_events (ts)",
	`
    CREATE INDEX IF NOT EXISTS idx_state_events_object
        ON server_state_events (object_id, ts)
    `,
	`
    CREATE TABLE IF NOT EXISTS collector_state (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    `,
	`
    CREATE TABLE IF NOT EXISTS storage_samples (
        ts          INTEGER PRIMARY KEY,
        total_bytes INTEGER NOT NULL
    ) WITHOUT ROWID
    `,
}

const (
	channelLabelsKey = "channel_labels"
	channelHiddenKey = "channel_hidden"
	monitorsKey      = "monitors"
)

var gatheredMonitors = []string{"machine", "components", "disk", "network", "temperature", "percentiles", "refusals"}
var digestMonitors = []string{"percentiles", "refusals"}
var hostMonitors = []string{"machine", "disk", "network", "temperature"}
var shownMonitors = []string{"requests", "traffic", "responses", "latency", "connections", "uplinks", "availability"}

func monitorDefaults() map[string]bool {
	out := map[string]bool{}
	for _, n := range append(append([]string{}, gatheredMonitors...), shownMonitors...) {
		out[n] = true
	}
	return out
}

// monitorsFrom is monitors_from.
func monitorsFrom(raw any) map[string]bool {
	m := monitorDefaults()
	if obj, ok := raw.(map[string]any); ok {
		for name, v := range obj {
			if _, known := m[name]; known {
				if b, ok := v.(bool); ok {
					m[name] = b
				}
			}
		}
	}
	return m
}

func metricTableSQL(name string) string {
	cols := make([]string, len(metricColumns))
	for i, c := range metricColumns {
		cols[i] = c + " INTEGER NOT NULL DEFAULT 0"
	}
	return fmt.Sprintf(`
    CREATE TABLE IF NOT EXISTS %s (
        bucket_ts INTEGER NOT NULL,
        object_id INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
        %s,
        PRIMARY KEY (bucket_ts, object_id)
    ) WITHOUT ROWID
    `, name, strings.Join(cols, ",\n        "))
}

// Bucket is one object's samples for the minute being collected.
type Bucket struct {
	Counters, GaugeSums, GaugeMaxima map[string]int64
	Samples                          int64
}

func newBucket() *Bucket {
	return &Bucket{Counters: map[string]int64{}, GaugeSums: map[string]int64{}, GaugeMaxima: map[string]int64{}}
}

func (b *Bucket) addCounter(name string, delta int64) {
	if delta != 0 {
		b.Counters[name] += delta
	}
}

func (b *Bucket) addGauge(name string, value int64) {
	b.GaugeSums[name] += value
	if cur, ok := b.GaugeMaxima[name]; !ok || value > cur {
		b.GaugeMaxima[name] = value
	}
}

// floorDiv is Python's // for ints.
func floorDiv(a, b int64) int64 {
	q := a / b
	if (a%b != 0) && ((a < 0) != (b < 0)) {
		q--
	}
	return q
}

func (b *Bucket) row() map[string]int64 {
	samples := b.Samples
	if samples < 1 {
		samples = 1
	}
	avg := func(n string) int64 { return floorDiv(b.GaugeSums[n], samples) }
	c, mx := b.Counters, b.GaugeMaxima
	return map[string]int64{
		"samples": b.Samples, "requests": c["requests"], "sessions": c["sessions"], "bytes_in": c["bytes_in"],
		"bytes_out": c["bytes_out"], "resp_2xx": c["resp_2xx"], "resp_3xx": c["resp_3xx"], "resp_4xx": c["resp_4xx"],
		"resp_5xx": c["resp_5xx"], "resp_other": c["resp_other"], "check_failures": c["check_failures"],
		"conn_cur_avg": avg("conn_cur"), "conn_cur_max": mx["conn_cur"], "queue_avg": avg("queue"),
		"queue_max": mx["queue"], "queue_ms_avg": avg("queue_ms"), "connect_ms_avg": avg("connect_ms"),
		"response_ms_avg": avg("response_ms"), "response_ms_max": mx["response_ms"], "total_ms_avg": avg("total_ms"),
		"cpu_avg": avg("cpu"), "cpu_max": mx["cpu"], "haproxy_busy_avg": avg("haproxy_busy"),
		"haproxy_busy_max": mx["haproxy_busy"], "memory_avg": avg("memory"), "memory_max": mx["memory"],
		"memory_total": mx["memory_total"], "disk_used_avg": avg("disk_used"), "disk_total": mx["disk_total"],
		"disk_read": c["disk_read"], "disk_write": c["disk_write"], "net_rx": c["net_rx"], "net_tx": c["net_tx"],
		"temp_avg": avg("temp"), "temp_max": mx["temp"], "refused_geo": c["refused_geo"],
		"refused_banned": c["refused_banned"], "refused_rate": c["refused_rate"], "refused_other": c["refused_other"],
	}
}

// histogramPercentile is histogram_percentile; ok false for None.
func histogramPercentile(counts []int64, share float64) (int64, bool) {
	var total int64
	for _, c := range counts {
		total += c
	}
	if total <= 0 {
		return 0, false
	}
	rank := share * float64(total)
	var seen int64
	for i, count := range counts {
		if count <= 0 {
			continue
		}
		if float64(seen+count) >= rank {
			var lower int64
			if i > 0 {
				lower = digestBoundsMS[i-1]
			}
			if i >= len(digestBoundsMS) {
				return lower, true
			}
			upper := digestBoundsMS[i]
			return pyRoundInt(float64(lower) + float64(upper-lower)*(rank-float64(seen))/float64(count)), true
		}
		seen += count
	}
	return digestBoundsMS[len(digestBoundsMS)-1], true
}

// unixGetJSON is unix_get_json: GET a JSON object over a Unix socket.
func unixGetJSON(socketPath, path string, timeout time.Duration) (map[string]any, error) {
	conn, err := net.DialTimeout("unix", socketPath, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte("GET " + path + " HTTP/1.0\r\nHost: localhost\r\nAccept: application/json\r\n\r\n")); err != nil {
		return nil, err
	}
	raw := []byte{}
	buf := make([]byte, 65536)
	for len(raw) < 16*1024*1024 {
		n, err := conn.Read(buf)
		raw = append(raw, buf[:n]...)
		if err != nil {
			break
		}
	}
	head, body, _ := strings.Cut(string(raw), "\r\n\r\n")
	parts := strings.SplitN(head, " ", 3)
	if len(parts) < 2 || parts[1] != "200" {
		h := head
		if len(h) > 80 {
			h = h[:80]
		}
		return nil, fmt.Errorf("%s: %q", path, h)
	}
	dec := json.NewDecoder(strings.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: not an object", path)
	}
	return m, nil
}

// readDiskSpace is read_disk_space: (used, total) KiB.
func readDiskSpace(path string) (int64, int64, bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, false
	}
	total := int64(st.Blocks) * int64(st.Frsize)
	if total <= 0 {
		return 0, 0, false
	}
	used := (int64(st.Blocks) - int64(st.Bfree)) * int64(st.Frsize)
	return used / memoryUnit, total / memoryUnit, true
}

type pair struct{ a, b int64 }

func readDiskCounters(diskstats, blockRoot string) map[string]pair {
	ents, err := os.ReadDir(blockRoot)
	if err != nil {
		return nil
	}
	disks := map[string]bool{}
	for _, e := range ents {
		if _, err := os.Stat(filepath.Join(blockRoot, e.Name(), "device")); err == nil {
			disks[e.Name()] = true
		}
	}
	raw, err := os.ReadFile(diskstats)
	if err != nil {
		return nil
	}
	out := map[string]pair{}
	for _, line := range splitLines(string(raw)) {
		f := strings.Fields(line)
		if len(f) < 10 || !disks[f[2]] {
			continue
		}
		r, err1 := strconv.ParseInt(f[5], 10, 64)
		w, err2 := strconv.ParseInt(f[9], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		out[f[2]] = pair{r * diskstatsSector, w * diskstatsSector}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func readIntFile(path string) (int64, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	return n, err == nil
}

func readNetworkCounters(netRoot string) map[string]pair {
	ents, err := os.ReadDir(netRoot)
	if err != nil {
		return nil
	}
	out := map[string]pair{}
	for _, e := range ents {
		base := filepath.Join(netRoot, e.Name())
		if _, err := os.Stat(filepath.Join(base, "device")); err != nil {
			continue
		}
		rx, ok1 := readIntFile(filepath.Join(base, "statistics", "rx_bytes"))
		tx, ok2 := readIntFile(filepath.Join(base, "statistics", "tx_bytes"))
		if !ok1 || !ok2 {
			continue
		}
		out[e.Name()] = pair{rx, tx}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func readTemperature(root string) (int64, bool) {
	ents, err := os.ReadDir(root)
	if err != nil {
		return 0, false
	}
	var warmest int64
	found := false
	for _, e := range ents {
		if !strings.HasPrefix(e.Name(), "thermal_zone") {
			continue
		}
		milli, ok := readIntFile(filepath.Join(root, e.Name(), "temp"))
		if !ok || !(temperatureLowMilli < milli && milli < temperatureHighMilli) {
			continue
		}
		v := floorDiv(milli, 100)
		if !found || v > warmest {
			warmest, found = v, true
		}
	}
	return warmest, found
}

type span struct {
	State      string `json:"state"`
	Start, End int64
}

func (s span) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`{"state":%q,"start":%d,"end":%d}`, s.State, s.Start, s.End)), nil
}

func closeSpan(spans *[]span, start, end int64, state string) {
	if end <= start {
		return
	}
	if n := len(*spans); n > 0 && (*spans)[n-1].State == state {
		(*spans)[n-1].End = end
		return
	}
	*spans = append(*spans, span{state, start, end})
}

func compressSpans(spans []span, since, until int64, slices int) []span {
	length := until - since
	if length < 1 {
		length = 1
	}
	result := []span{}
	index := 0
	for number := 0; number < slices; number++ {
		start := since + length*int64(number)/int64(slices)
		end := since + length*int64(number+1)/int64(slices)
		if end <= start {
			continue
		}
		for index < len(spans) && spans[index].End <= start {
			index++
		}
		seconds := map[string]int64{}
		order := []string{}
		worst := map[string]int64{}
		worstOrder := []string{}
		for probe := index; probe < len(spans) && spans[probe].Start < end; probe++ {
			s := spans[probe]
			overlap := minI(end, s.End) - maxI(start, s.Start)
			if overlap <= 0 {
				continue
			}
			group := "OTHER"
			if s.State == "UP" || s.State == absentSpan {
				group = s.State
			}
			if _, ok := seconds[group]; !ok {
				order = append(order, group)
			}
			seconds[group] += overlap
			if group == "OTHER" {
				if _, ok := worst[s.State]; !ok {
					worstOrder = append(worstOrder, s.State)
				}
				worst[s.State] += overlap
			}
		}
		cursor := start
		for _, g := range order {
			name := g
			if g == "OTHER" {
				best := ""
				var bestV int64 = -1
				for _, w := range worstOrder {
					if worst[w] > bestV {
						best, bestV = w, worst[w]
					}
				}
				name = best
			}
			closeSpan(&result, cursor, cursor+seconds[g], name)
			cursor += seconds[g]
		}
	}
	return result
}

func minI(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func maxI(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// ---------------------------------------------------------------------------
// MetricsDatabase
// ---------------------------------------------------------------------------

// Database is MetricsDatabase: one connection guarded by a lock.
type Database struct {
	Path string
	mu   sync.Mutex
	db   *sql.DB
}

// OpenDatabase is MetricsDatabase(path).
func OpenDatabase(path string) (*Database, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o777); err != nil {
		return nil, err
	}
	_, statErr := os.Stat(path)
	fresh := os.IsNotExist(statErr)
	db, err := sql.Open("sqlite", path+"?_txlock=deferred")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	d := &Database{Path: path, db: db}
	pragmas := []string{}
	if fresh {
		pragmas = append(pragmas, "PRAGMA auto_vacuum=INCREMENTAL")
	}
	pragmas = append(pragmas, "PRAGMA journal_mode=WAL", "PRAGMA synchronous=NORMAL", "PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
		// An 8 MiB page cache instead of 2 MiB: a day's CPU or memory chart
		// reads ~33k component rows, and the pure-Go SQLite pays for every
		// page it reads back from the file (measured ~25% faster on a copy
		// of a gateway's 34 MB database). The one connection keeps it.
		"PRAGMA cache_size=-8192")
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			db.Close()
			return nil, err
		}
	}
	if err := d.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return d, nil
}

// tx runs f in one transaction under the lock (Python's "with lock, conn").
func (d *Database) tx(f func(*sql.Tx) error) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	t, err := d.db.Begin()
	if err != nil {
		return err
	}
	if err := f(t); err != nil {
		_ = t.Rollback()
		return err
	}
	return t.Commit()
}

func (d *Database) migrate() error {
	return d.tx(func(t *sql.Tx) error {
		for _, s := range schemaStatements {
			if _, err := t.Exec(s); err != nil {
				return err
			}
		}
		for _, name := range []string{"metric_1m", "metric_1h"} {
			if _, err := t.Exec(metricTableSQL(name)); err != nil {
				return err
			}
		}
		for _, table := range []string{"latency_1m", "latency_1h"} {
			cols := make([]string, len(histogramColumns))
			for i, c := range histogramColumns {
				cols[i] = c + " INTEGER NOT NULL DEFAULT 0"
			}
			q := "CREATE TABLE IF NOT EXISTS " + table + " (bucket_ts INTEGER NOT NULL, " +
				"object_id INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE, " +
				strings.Join(cols, ",\n") + ", PRIMARY KEY (bucket_ts, object_id)) WITHOUT ROWID"
			if _, err := t.Exec(q); err != nil {
				return err
			}
		}
		for _, table := range []string{"metric_1m", "metric_1h"} {
			existing, err := tableColumns(t, table)
			if err != nil {
				return err
			}
			for _, c := range metricColumns {
				if existing[c] {
					continue
				}
				if _, err := t.Exec("ALTER TABLE " + table + " ADD COLUMN " + c + " INTEGER NOT NULL DEFAULT 0"); err != nil {
					return err
				}
				log.Printf("Added metrics column %s.%s", table, c)
			}
		}
		existing, err := tableColumns(t, "objects")
		if err != nil {
			return err
		}
		if !existing["address"] {
			if _, err := t.Exec("ALTER TABLE objects ADD COLUMN address TEXT NOT NULL DEFAULT ''"); err != nil {
				return err
			}
			log.Printf("Added objects.address")
		}
		for _, q := range []string{"CREATE INDEX IF NOT EXISTS idx_metric_1m_object ON metric_1m (object_id, bucket_ts)",
			"CREATE INDEX IF NOT EXISTS idx_metric_1h_object ON metric_1h (object_id, bucket_ts)"} {
			if _, err := t.Exec(q); err != nil {
				return err
			}
		}
		var version sql.NullInt64
		err = t.QueryRow("SELECT version FROM schema_version").Scan(&version)
		if err == sql.ErrNoRows {
			_, err = t.Exec("INSERT INTO schema_version (version) VALUES (?)", schemaVersion)
			return err
		}
		if err != nil {
			return err
		}
		current := version.Int64
		if current > schemaVersion {
			return fmt.Errorf("metrics database schema v%d is newer than the supported v%d", current, schemaVersion)
		}
		for current < schemaVersion {
			current++
			log.Printf("Migrated metrics database to schema v%d", current)
		}
		_, err = t.Exec("UPDATE schema_version SET version = ?", current)
		return err
	})
}

func tableColumns(t *sql.Tx, table string) (map[string]bool, error) {
	rows, err := t.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	cols, _ := rows.Columns()
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		for i, c := range cols {
			if c == "name" {
				out[fmt.Sprint(textOf(vals[i]))] = true
			}
		}
	}
	return out, rows.Err()
}

func textOf(v any) string {
	switch x := v.(type) {
	case []byte:
		return string(x)
	case string:
		return x
	case nil:
		return ""
	}
	return fmt.Sprint(v)
}

// Close closes the connection.
func (d *Database) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	_ = d.db.Close()
}

// queryAll runs a query under the lock and returns rows as []any slices.
func (d *Database) queryAll(q string, args ...any) ([][]any, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return queryRows(d.db, q, args...)
}

type querier interface {
	Query(string, ...any) (*sql.Rows, error)
}

func queryRows(db querier, q string, args ...any) ([][]any, error) {
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	out := [][]any{}
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		for i, v := range vals {
			if b, ok := v.([]byte); ok {
				vals[i] = string(b)
			}
		}
		out = append(out, vals)
	}
	return out, rows.Err()
}

func i64(v any) int64 { n, _ := asInt(v); return n }

// ObjectID is object_id.
func (d *Database) ObjectID(kind, proxy, server string, now int64) (int64, error) {
	var id int64
	err := d.tx(func(t *sql.Tx) error {
		if _, err := t.Exec("INSERT INTO objects (kind, proxy, server, first_seen, last_seen) VALUES (?, ?, ?, ?, ?) "+
			"ON CONFLICT (kind, proxy, server) DO UPDATE SET last_seen = ?", kind, proxy, server, now, now, now); err != nil {
			return err
		}
		return t.QueryRow("SELECT id FROM objects WHERE kind = ? AND proxy = ? AND server = ?", kind, proxy, server).Scan(&id)
	})
	return id, err
}

// ObjectExists is object_exists.
func (d *Database) ObjectExists(kind, proxy, server string) bool {
	rows, err := d.queryAll("SELECT 1 FROM objects WHERE kind = ? AND proxy = ? AND server = ?", kind, proxy, server)
	return err == nil && len(rows) > 0
}

func (d *Database) loadServerAddresses() map[int64]string {
	rows, _ := d.queryAll("SELECT id, address FROM objects WHERE kind = 'server' AND address != ''")
	out := map[int64]string{}
	for _, r := range rows {
		out[i64(r[0])] = textOf(r[1])
	}
	return out
}

func (d *Database) setObjectAddress(id int64, address string) error {
	return d.tx(func(t *sql.Tx) error {
		_, err := t.Exec("UPDATE objects SET address = ? WHERE id = ?", address, id)
		return err
	})
}

func (d *Database) renameCandidate(proxy, address string, present map[string]bool) (int64, string, bool) {
	rows, _ := d.queryAll("SELECT id, server FROM objects WHERE kind = 'server' AND proxy = ? AND address = ?", proxy, address)
	type c struct {
		id     int64
		server string
	}
	cands := []c{}
	for _, r := range rows {
		if s := textOf(r[1]); !present[s] {
			cands = append(cands, c{i64(r[0]), s})
		}
	}
	if len(cands) == 1 {
		return cands[0].id, cands[0].server, true
	}
	return 0, "", false
}

func (d *Database) renameServer(id int64, server string) error {
	return d.tx(func(t *sql.Tx) error {
		_, err := t.Exec("UPDATE objects SET server = ? WHERE id = ?", server, id)
		return err
	})
}

type baselineKey struct {
	id     int64
	metric string
}

type baselineVal struct{ value, updated int64 }

func (d *Database) loadBaselines() map[baselineKey]baselineVal {
	rows, _ := d.queryAll("SELECT object_id, metric, value, updated_ts FROM counter_baseline")
	out := map[baselineKey]baselineVal{}
	for _, r := range rows {
		out[baselineKey{i64(r[0]), textOf(r[1])}] = baselineVal{i64(r[2]), i64(r[3])}
	}
	return out
}

func storeBaselinesTx(t *sql.Tx, b map[baselineKey]baselineVal) error {
	if len(b) == 0 {
		return nil
	}
	stmt, err := t.Prepare("INSERT INTO counter_baseline (object_id, metric, value, updated_ts) VALUES (?, ?, ?, ?) " +
		"ON CONFLICT (object_id, metric) DO UPDATE SET value = excluded.value, updated_ts = excluded.updated_ts")
	if err != nil {
		return err
	}
	defer stmt.Close()
	for k, v := range b {
		if _, err := stmt.Exec(k.id, k.metric, v.value, v.updated); err != nil {
			return err
		}
	}
	return nil
}

func sortedIDs[V any](m map[int64]V) []int64 {
	ids := make([]int64, 0, len(m))
	for k := range m {
		ids = append(ids, k)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

// writeBuckets is write_buckets.
func (d *Database) writeBuckets(bucketTS int64, rows map[int64]map[string]int64, merge bool, baselines map[baselineKey]baselineVal) error {
	if len(rows) == 0 {
		return nil
	}
	cols := append([]string{"bucket_ts", "object_id"}, metricColumns...)
	marks := strings.TrimSuffix(strings.Repeat("?, ", len(cols)), ", ")
	var q string
	if merge {
		updates := []string{"samples = metric_1m.samples + excluded.samples"}
		for _, c := range rollupSum {
			updates = append(updates, c+" = metric_1m."+c+" + excluded."+c)
		}
		for _, c := range rollupMax {
			updates = append(updates, c+" = MAX(metric_1m."+c+", excluded."+c+")")
		}
		for _, c := range rollupWavg {
			updates = append(updates, c+" = CAST(COALESCE((metric_1m."+c+" * metric_1m.samples + excluded."+c+
				" * excluded.samples) / NULLIF(metric_1m.samples + excluded.samples, 0), 0) AS INTEGER)")
		}
		q = "INSERT INTO metric_1m (" + strings.Join(cols, ", ") + ") VALUES (" + marks + ") " +
			"ON CONFLICT (bucket_ts, object_id) DO UPDATE SET " + strings.Join(updates, ", ")
	} else {
		q = "INSERT OR REPLACE INTO metric_1m (" + strings.Join(cols, ", ") + ") VALUES (" + marks + ")"
	}
	return d.tx(func(t *sql.Tx) error {
		stmt, err := t.Prepare(q)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for _, id := range sortedIDs(rows) {
			row := rows[id]
			args := []any{bucketTS, id}
			for _, c := range metricColumns {
				args = append(args, row[c])
			}
			if _, err := stmt.Exec(args...); err != nil {
				return err
			}
		}
		if baselines != nil {
			return storeBaselinesTx(t, baselines)
		}
		return nil
	})
}

func (d *Database) recordStateChange(id int64, previous, state string, now int64) error {
	return d.tx(func(t *sql.Tx) error {
		_, err := t.Exec("INSERT INTO server_state_events (ts, object_id, previous_state, state) VALUES (?, ?, ?, ?)",
			now, id, previous, state)
		return err
	})
}

func (d *Database) lastObserved(id int64) (int64, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	one := func(q string) any {
		rows, err := queryRows(d.db, q, id)
		if err != nil || len(rows) == 0 {
			return nil
		}
		return rows[0][0]
	}
	minute := one("SELECT MAX(bucket_ts) FROM metric_1m WHERE object_id = ?")
	var hour any
	if minute == nil {
		hour = one("SELECT MAX(bucket_ts) FROM metric_1h WHERE object_id = ?")
	}
	event := one("SELECT MAX(ts) FROM server_state_events WHERE object_id = ?")
	cands := []int64{}
	if event != nil {
		cands = append(cands, i64(event))
	}
	if minute != nil {
		cands = append(cands, i64(minute)+bucketSeconds)
	} else if hour != nil {
		cands = append(cands, i64(hour))
	}
	if len(cands) == 0 {
		return 0, false
	}
	best := cands[0]
	for _, c := range cands {
		if c > best {
			best = c
		}
	}
	return best, true
}

func (d *Database) loadLastStates() map[int64]string {
	rows, _ := d.queryAll("SELECT object_id, state FROM server_state_events WHERE id IN (SELECT MAX(id) FROM server_state_events GROUP BY object_id)")
	out := map[int64]string{}
	for _, r := range rows {
		out[i64(r[0])] = textOf(r[1])
	}
	return out
}

func (d *Database) getState(key, def string) string {
	rows, _ := d.queryAll("SELECT value FROM collector_state WHERE key = ?", key)
	if len(rows) == 0 {
		return def
	}
	return textOf(rows[0][0])
}

func (d *Database) setState(key, value string) error {
	return d.tx(func(t *sql.Tx) error {
		_, err := t.Exec("INSERT INTO collector_state (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value", key, value)
		return err
	})
}

func (d *Database) rollupHours(before int64) (int64, error) {
	watermark := toInt(d.getState("rollup_watermark", "0"))
	if before <= watermark {
		return 0, nil
	}
	sums := make([]string, len(rollupSum))
	for i, c := range rollupSum {
		sums[i] = "SUM(" + c + ")"
	}
	projection := []string{fmt.Sprintf("bucket_ts - (bucket_ts %% %d) AS hour_ts", hourSeconds), "object_id", "SUM(samples)", strings.Join(sums, ", ")}
	target := append([]string{"bucket_ts", "object_id", "samples"}, rollupSum...)
	for _, c := range rollupWavg {
		projection = append(projection, "CAST(COALESCE(SUM("+c+" * samples) / NULLIF(SUM(samples), 0), 0) AS INTEGER)")
		target = append(target, c)
	}
	for _, c := range rollupMax {
		projection = append(projection, "MAX("+c+")")
		target = append(target, c)
	}
	var written int64
	err := d.tx(func(t *sql.Tx) error {
		res, err := t.Exec("INSERT OR REPLACE INTO metric_1h ("+strings.Join(target, ", ")+") SELECT "+strings.Join(projection, ", ")+
			" FROM metric_1m WHERE bucket_ts >= ? AND bucket_ts < ? GROUP BY hour_ts, object_id", watermark, before)
		if err != nil {
			return err
		}
		written, _ = res.RowsAffected()
		_, err = t.Exec("INSERT INTO collector_state (key, value) VALUES ('rollup_watermark', ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value", strconv.FormatInt(before, 10))
		return err
	})
	if written < 0 {
		written = 0
	}
	return written, err
}

func (d *Database) writeLatency(bucketTS int64, rows map[int64][]int64) error {
	if len(rows) == 0 {
		return nil
	}
	marks := strings.TrimSuffix(strings.Repeat("?, ", len(histogramColumns)), ", ")
	return d.tx(func(t *sql.Tx) error {
		stmt, err := t.Prepare("INSERT OR REPLACE INTO latency_1m (bucket_ts, object_id, " + strings.Join(histogramColumns, ", ") + ") VALUES (?, ?, " + marks + ")")
		if err != nil {
			return err
		}
		defer stmt.Close()
		for _, id := range sortedIDs(rows) {
			args := []any{bucketTS, id}
			for _, c := range rows[id] {
				args = append(args, c)
			}
			if _, err := stmt.Exec(args...); err != nil {
				return err
			}
		}
		return nil
	})
}

func (d *Database) rollupLatencyHours(before int64) (int64, error) {
	watermark := toInt(d.getState("latency_rollup_watermark", "0"))
	if before <= watermark {
		return 0, nil
	}
	sums := make([]string, len(histogramColumns))
	for i, c := range histogramColumns {
		sums[i] = "SUM(" + c + ")"
	}
	var written int64
	err := d.tx(func(t *sql.Tx) error {
		res, err := t.Exec(fmt.Sprintf("INSERT OR REPLACE INTO latency_1h (bucket_ts, object_id, %s) SELECT bucket_ts - (bucket_ts %% %d) AS hour_ts, object_id, %s FROM latency_1m WHERE bucket_ts >= ? AND bucket_ts < ? GROUP BY hour_ts, object_id",
			strings.Join(histogramColumns, ", "), hourSeconds, strings.Join(sums, ", ")), watermark, before)
		if err != nil {
			return err
		}
		written, _ = res.RowsAffected()
		_, err = t.Exec("INSERT INTO collector_state (key, value) VALUES ('latency_rollup_watermark', ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value", strconv.FormatInt(before, 10))
		return err
	})
	return written, err
}

func (d *Database) applyRetention(minuteCutoff, minuteServerCutoff, hourCutoff int64) (map[string]any, error) {
	out := map[string]any{}
	err := d.tx(func(t *sql.Tx) error {
		exec := func(q string, args ...any) (int64, error) {
			res, err := t.Exec(q, args...)
			if err != nil {
				return 0, err
			}
			n, _ := res.RowsAffected()
			return n, nil
		}
		m1, err := exec("DELETE FROM metric_1m WHERE bucket_ts < ?", minuteCutoff)
		if err != nil {
			return err
		}
		m2, err := exec("DELETE FROM latency_1m WHERE bucket_ts < ?", minuteCutoff)
		if err != nil {
			return err
		}
		if _, err := exec("DELETE FROM latency_1h WHERE bucket_ts < ?", hourCutoff); err != nil {
			return err
		}
		sm, err := exec("DELETE FROM metric_1m WHERE bucket_ts < ? AND object_id IN (SELECT id FROM objects WHERE kind = 'server')", minuteServerCutoff)
		if err != nil {
			return err
		}
		h, err := exec("DELETE FROM metric_1h WHERE bucket_ts < ?", hourCutoff)
		if err != nil {
			return err
		}
		ev, err := exec("DELETE FROM server_state_events WHERE ts < ?", hourCutoff)
		if err != nil {
			return err
		}
		out["minutes"], out["server_minutes"], out["hours"], out["events"] = m1+m2, sm, h, ev
		return nil
	})
	return out, err
}

func (d *Database) incrementalVacuum(pages int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, _ = d.db.Exec(fmt.Sprintf("PRAGMA incremental_vacuum(%d)", pages))
}

func (d *Database) checkpoint(truncate bool) bool {
	mode := "PASSIVE"
	if truncate {
		mode = "TRUNCATE"
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.db.Query("PRAGMA wal_checkpoint(" + mode + ")")
	if err != nil {
		return false
	}
	rows.Close()
	return true
}

func scope(site, alias string) (string, []any) {
	if site == "" {
		return alias + ".kind = 'frontend'", nil
	}
	return alias + ".kind = 'backend' AND " + alias + ".proxy = ?", []any{site}
}

func (d *Database) sites() []any {
	rows, _ := d.queryAll("SELECT proxy, first_seen, last_seen FROM objects WHERE kind = 'backend' ORDER BY proxy")
	out := []any{}
	for _, r := range rows {
		out = append(out, omap("proxy", textOf(r[0]), "first_seen", i64(r[1]), "last_seen", i64(r[2])))
	}
	return out
}

func nullable(v any) any {
	if v == nil {
		return nil
	}
	return i64(v)
}

// series is MetricsDatabase.series.
func (d *Database) series(chart, site string, since, until int64, components bool) (*OMap, error) {
	columns := chartSeries[chart]
	table, step := chooseResolution(maxI(1, until-since))
	if chart == "latency" {
		return d.latencySeries(site, table, step, since, until)
	}
	if chart == "percentiles" {
		return d.percentileSeries(site, table, step, since, until)
	}
	var predicate string
	var params []any
	switch {
	case chart == "refusals":
		predicate = "o.kind = '" + edgeKind + "'"
	case hostCharts[chart]:
		predicate = "o.kind = 'host'"
	default:
		predicate, params = scope(site, "o")
	}
	proj := make([]string, len(columns))
	for i, c := range columns {
		proj[i] = aggregateSQL(c)
	}
	q := fmt.Sprintf("SELECT (m.bucket_ts / %d) * %d AS slot, %s FROM %s m JOIN objects o ON o.id = m.object_id WHERE %s AND m.bucket_ts >= ? AND m.bucket_ts < ? GROUP BY slot ORDER BY slot",
		step, step, strings.Join(proj, ", "), table, predicate)
	rows, err := d.queryAll(q, append(params, since, until)...)
	if err != nil {
		return nil, err
	}
	points := []any{}
	for _, r := range rows {
		points = append(points, i64(r[0]))
	}
	series := NewOMap()
	for i, c := range columns {
		vals := []any{}
		for _, r := range rows {
			if hostCharts[chart] || chart == "refusals" {
				vals = append(vals, fromStorage(chart, r[i+1]))
			} else {
				vals = append(vals, i64(r[i+1]))
			}
		}
		series.Set(c, clip(vals))
	}
	payload := omap("chart", chart, "resolution_seconds", step, "source", table, "points", clip(points), "series", series)
	if _, ok := componentColumns[chart]; ok {
		host := make([]int64, len(rows))
		for i, r := range rows {
			host[i] = i64(r[1])
		}
		if components {
			err = d.addComponents(payload, chart, table, step, since, until, host)
		} else {
			err = d.addComponentGroups(payload, chart, table, step, since, until, host)
		}
		if err != nil {
			return nil, err
		}
	}
	return payload, nil
}

func clip(v []any) []any {
	if len(v) > maxChartPoints {
		return v[:maxChartPoints]
	}
	return v
}

func convertComponent(chart string, v int64) any {
	if chart == "memory" {
		return v * memoryUnit
	}
	return pyRound1(float64(v) / cpuScale)
}

func (d *Database) addComponentGroups(payload *OMap, chart, table string, step, since, until int64, host []int64) error {
	stored := int64(bucketSeconds)
	if table != "metric_1m" {
		stored = hourSeconds
	}
	if step != stored {
		if err := d.addComponents(payload, chart, table, step, since, until, host); err != nil {
			return err
		}
		payload.Delete("components")
		return nil
	}
	average := componentColumns[chart][0]
	value := "CASE WHEN m.samples > 0 THEN COALESCE(m." + average + ", 0) ELSE 0 END"
	d.mu.Lock()
	objRows, err := queryRows(d.db, "SELECT id, proxy FROM objects WHERE kind = 'component'")
	if err != nil {
		d.mu.Unlock()
		return err
	}
	haproxy := []any{}
	for _, r := range objRows {
		if componentName(textOf(r[1])) == "haproxy" {
			haproxy = append(haproxy, i64(r[0]))
		}
	}
	if len(haproxy) == 0 {
		haproxy = []any{int64(-1)}
	}
	marks := strings.TrimSuffix(strings.Repeat("?, ", len(haproxy)), ", ")
	args := append([]any{componentContainer, componentService}, haproxy...)
	args = append(args, since, until)
	rows, err := queryRows(d.db, "SELECT m.bucket_ts, SUM(CASE WHEN o.server = ? THEN "+value+" ELSE 0 END), SUM(CASE WHEN o.server = ? AND o.id NOT IN ("+marks+") THEN "+value+" ELSE 0 END), SUM("+value+") FROM "+table+" m JOIN objects o ON o.id = m.object_id WHERE o.kind = 'component' AND m.bucket_ts >= ? AND m.bucket_ts < ? GROUP BY m.bucket_ts", args...)
	d.mu.Unlock()
	if err != nil {
		return err
	}
	points := payload.Value("points").([]any)
	size := len(points)
	position := map[int64]int{}
	for i, p := range points {
		position[p.(int64)] = i
	}
	containers, helpers, claimed := make([]int64, size), make([]int64, size), make([]int64, size)
	for _, r := range rows {
		idx, ok := position[i64(r[0])]
		if !ok {
			continue
		}
		containers[idx], helpers[idx], claimed[idx] = i64(r[1]), i64(r[2]), i64(r[3])
	}
	d.finishGroups(payload, chart, helpers, containers, claimed, host, size)
	return nil
}

func (d *Database) finishGroups(payload *OMap, chart string, helpers, containers, claimed, host []int64, size int) {
	series := payload.Value("series").(*OMap)
	conv := func(list []int64) []any {
		out := make([]any, len(list))
		for i, v := range list {
			out[i] = convertComponent(chart, v)
		}
		return out
	}
	series.Set("helpers", conv(helpers))
	series.Set("containers", conv(containers))
	other := []any{}
	for i := 0; i < size && i < len(host); i++ {
		other = append(other, fromStorage(chart, maxI(0, host[i]-claimed[i])))
	}
	series.Set("other", other)
}

func (d *Database) latencySeries(site, table string, step, since, until int64) (*OMap, error) {
	predicate, params := "o.kind = 'backend'", []any{}
	if site != "" {
		predicate, params = "o.kind = 'backend' AND o.proxy = ?", []any{site}
	}
	q := fmt.Sprintf("SELECT (m.bucket_ts / %d) * %d AS slot, CAST(ROUND(SUM(m.response_ms_avg * m.requests) * 1.0 / NULLIF(SUM(m.requests), 0)) AS INTEGER), MAX(CASE WHEN m.requests > 0 THEN m.response_ms_max END) FROM %s m JOIN objects o ON o.id = m.object_id WHERE %s AND m.bucket_ts >= ? AND m.bucket_ts < ? GROUP BY slot ORDER BY slot",
		step, step, table, predicate)
	rows, err := d.queryAll(q, append(params, since, until)...)
	if err != nil {
		return nil, err
	}
	if len(rows) > maxChartPoints {
		rows = rows[:maxChartPoints]
	}
	pts, avg, mx := []any{}, []any{}, []any{}
	for _, r := range rows {
		pts = append(pts, i64(r[0]))
		avg = append(avg, nullable(r[1]))
		mx = append(mx, nullable(r[2]))
	}
	return omap("chart", "latency", "resolution_seconds", step, "source", table, "points", pts,
		"series", omap("response_ms_avg", avg, "response_ms_max", mx)), nil
}

func (d *Database) percentileSeries(site, table string, step, since, until int64) (*OMap, error) {
	source := "latency_1h"
	if table == "metric_1m" {
		source = "latency_1m"
	}
	predicate, params := "o.kind = 'backend'", []any{}
	if site != "" {
		predicate, params = "o.kind = 'backend' AND o.proxy = ?", []any{site}
	}
	sums := make([]string, len(histogramColumns))
	for i, c := range histogramColumns {
		sums[i] = "SUM(m." + c + ")"
	}
	q := fmt.Sprintf("SELECT (m.bucket_ts / %d) * %d AS slot, %s FROM %s m JOIN objects o ON o.id = m.object_id WHERE %s AND m.bucket_ts >= ? AND m.bucket_ts < ? GROUP BY slot ORDER BY slot",
		step, step, strings.Join(sums, ", "), source, predicate)
	rows, err := d.queryAll(q, append(params, since, until)...)
	if err != nil {
		return nil, err
	}
	if len(rows) > maxChartPoints {
		rows = rows[:maxChartPoints]
	}
	series := NewOMap()
	lists := map[string][]any{}
	pts := []any{}
	for _, r := range rows {
		pts = append(pts, i64(r[0]))
		counts := make([]int64, len(r)-1)
		for i, v := range r[1:] {
			counts[i] = i64(v)
		}
		for _, p := range percentiles {
			if v, ok := histogramPercentile(counts, p.share); ok {
				lists[p.name] = append(lists[p.name], v)
			} else {
				lists[p.name] = append(lists[p.name], nil)
			}
		}
	}
	for _, p := range percentiles {
		if lists[p.name] == nil {
			lists[p.name] = []any{}
		}
		series.Set(p.name, lists[p.name])
	}
	return omap("chart", "percentiles", "resolution_seconds", step, "source", source, "points", pts, "series", series), nil
}

func (d *Database) addComponents(payload *OMap, chart, table string, step, since, until int64, host []int64) error {
	average, peak := componentColumns[chart][0], componentColumns[chart][1]
	points := payload.Value("points").([]any)
	position := map[int64]int{}
	for i, p := range points {
		position[p.(int64)] = i
	}
	stored := int64(bucketSeconds)
	if table != "metric_1m" {
		stored = hourSeconds
	}
	var selected, grouping string
	if step == stored {
		selected = "m.bucket_ts, o.proxy, o.server, CASE WHEN m.samples > 0 THEN COALESCE(m." + average + ", 0) ELSE 0 END, COALESCE(m." + peak + ", 0)"
	} else {
		selected = fmt.Sprintf("(m.bucket_ts / %d) * %d AS slot, o.proxy, o.server, %s, %s", step, step, aggregateSQL(average), aggregateSQL(peak))
		grouping = " GROUP BY slot, o.id"
	}
	rows, err := d.queryAll("SELECT "+selected+" FROM "+table+" m JOIN objects o ON o.id = m.object_id WHERE o.kind = 'component' AND m.bucket_ts >= ? AND m.bucket_ts < ?"+grouping, since, until)
	if err != nil {
		return err
	}
	size := len(points)
	type entry struct {
		name, group string
		raw         []int64
		highest     int64
	}
	found := map[[2]string]*entry{}
	order := [][2]string{}
	names := map[string]string{}
	for _, r := range rows {
		idx, ok := position[i64(r[0])]
		if !ok {
			continue
		}
		proxy := textOf(r[1])
		name, ok := names[proxy]
		if !ok {
			name = componentName(proxy)
			names[proxy] = name
		}
		key := [2]string{textOf(r[2]), name}
		e, ok := found[key]
		if !ok {
			e = &entry{name: name, group: key[0], raw: make([]int64, size)}
			found[key] = e
			order = append(order, key)
		}
		e.raw[idx] += i64(r[3])
		if h := i64(r[4]); h > e.highest {
			e.highest = h
		}
	}
	helpers, containers, claimed := make([]int64, size), make([]int64, size), make([]int64, size)
	type comp struct {
		om   *OMap
		mean float64
		name string
	}
	comps := []comp{}
	for _, key := range order {
		e := found[key]
		var sum, mx int64
		for i, v := range e.raw {
			claimed[i] += v
			if e.group == componentContainer {
				containers[i] += v
			} else if e.group == componentService && e.name != "haproxy" {
				helpers[i] += v
			}
			sum += v
			if v > mx {
				mx = v
			}
		}
		values := make([]any, size)
		for i, v := range e.raw {
			values[i] = convertComponent(chart, v)
		}
		mean := fromStorage(chart, floorDiv(sum, maxI(1, int64(size))))
		pk := fromStorage(chart, maxI(e.highest, mx))
		om := omap("name", e.name, "group", e.group, "values", values, "mean", mean, "peak", pk)
		comps = append(comps, comp{om, toFloat(mean), e.name})
	}
	sort.SliceStable(comps, func(i, j int) bool {
		if comps[i].mean != comps[j].mean {
			return comps[i].mean > comps[j].mean
		}
		return comps[i].name < comps[j].name
	})
	d.finishGroups(payload, chart, helpers, containers, claimed, host, size)
	list := make([]any, len(comps))
	for i, c := range comps {
		list[i] = c.om
	}
	payload.Set("components", list)
	return nil
}

func toFloat(v any) float64 {
	switch x := v.(type) {
	case int64:
		return float64(x)
	case float64:
		return x
	}
	return 0
}

func (d *Database) hostLoad(since, until int64) (*OMap, error) {
	table, _ := chooseResolution(maxI(1, until-since))
	columns := []string{"cpu_avg", "cpu_max", "haproxy_busy_avg", "haproxy_busy_max", "memory_avg", "memory_max", "memory_total"}
	proj := make([]string, len(columns))
	for i, c := range columns {
		proj[i] = aggregateSQL(c)
	}
	rows, err := d.queryAll("SELECT COUNT(*) AS observed, "+strings.Join(proj, ", ")+" FROM "+table+" m JOIN objects o ON o.id = m.object_id WHERE o.kind = 'host' AND m.bucket_ts >= ? AND m.bucket_ts < ?", since, until)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 || i64(rows[0][0]) == 0 {
		return omap("observed", false), nil
	}
	out := omap("observed", true)
	for i, c := range columns {
		chart := "cpu"
		if strings.HasPrefix(c, "memory") {
			chart = "memory"
		}
		out.Set(c, fromStorage(chart, rows[0][i+1]))
	}
	return out, nil
}

func (d *Database) totals(site string, since, until int64) (*OMap, error) {
	table, _ := chooseResolution(maxI(1, until-since))
	predicate, params := scope(site, "o")
	proj := make([]string, len(summaryColumns))
	for i, c := range summaryColumns {
		proj[i] = aggregateSQL(c)
	}
	rows, err := d.queryAll("SELECT "+strings.Join(proj, ", ")+" FROM "+table+" m JOIN objects o ON o.id = m.object_id WHERE "+predicate+" AND m.bucket_ts >= ? AND m.bucket_ts < ?", append(params, since, until)...)
	if err != nil {
		return nil, err
	}
	out := NewOMap()
	for i, c := range summaryColumns {
		var v int64
		if len(rows) > 0 {
			v = i64(rows[0][i])
		}
		out.Set(c, v)
	}
	return out, nil
}

func (d *Database) serverTotals(since, until int64) (*OMap, error) {
	table, _ := chooseResolution(maxI(1, until-since))
	columns := []string{"bytes_in", "bytes_out", "sessions"}
	proj := make([]string, len(columns))
	for i, c := range columns {
		proj[i] = aggregateSQL(c)
	}
	rows, err := d.queryAll("SELECT o.proxy, o.server, "+strings.Join(proj, ", ")+" FROM "+table+" m JOIN objects o ON o.id = m.object_id WHERE o.kind = 'server' AND m.bucket_ts >= ? AND m.bucket_ts < ? GROUP BY o.proxy, o.server ORDER BY o.proxy, o.server", since, until)
	if err != nil {
		return nil, err
	}
	servers := []any{}
	for _, r := range rows {
		e := omap("proxy", textOf(r[0]), "server", textOf(r[1]))
		for i, c := range columns {
			e.Set(c, i64(r[i+2]))
		}
		servers = append(servers, e)
	}
	return omap("servers", servers), nil
}

var backendTotalColumns = []string{"requests", "resp_2xx", "resp_3xx", "resp_4xx", "resp_5xx", "resp_other", "bytes_in",
	"bytes_out", "sessions", "check_failures"}

func (d *Database) backendTotals(since, until int64) (*OMap, error) {
	table, _ := chooseResolution(maxI(1, until-since))
	proj := make([]string, len(backendTotalColumns))
	for i, c := range backendTotalColumns {
		proj[i] = aggregateSQL(c)
	}
	rows, err := d.queryAll("SELECT o.proxy, "+strings.Join(proj, ", ")+", CAST(ROUND(SUM(m.response_ms_avg * m.requests) * 1.0 / NULLIF(SUM(m.requests), 0)) AS INTEGER), MAX(CASE WHEN m.requests > 0 THEN m.response_ms_max END) FROM "+table+" m JOIN objects o ON o.id = m.object_id WHERE o.kind = 'backend' AND m.bucket_ts >= ? AND m.bucket_ts < ? GROUP BY o.proxy ORDER BY o.proxy", since, until)
	if err != nil {
		return nil, err
	}
	backends := []any{}
	n := len(backendTotalColumns)
	for _, r := range rows {
		e := omap("proxy", textOf(r[0]))
		for i, c := range backendTotalColumns {
			e.Set(c, i64(r[i+1]))
		}
		e.Set("response_ms_avg", nullable(r[n+1]))
		e.Set("response_ms_max", nullable(r[n+2]))
		backends = append(backends, e)
	}
	return omap("backends", backends, "source", table), nil
}

func (d *Database) latestGauges(site string, until int64) (*OMap, error) {
	predicate, params := scope(site, "o")
	inner, innerParams := scope(site, "o2")
	args := append(append(params, innerParams...), until)
	rows, err := d.queryAll("SELECT "+aggregateSQL("conn_cur_avg")+", "+aggregateSQL("conn_cur_max")+" FROM metric_1m m JOIN objects o ON o.id = m.object_id WHERE "+predicate+" AND m.bucket_ts = (  SELECT MAX(m2.bucket_ts) FROM metric_1m m2   JOIN objects o2 ON o2.id = m2.object_id   WHERE "+inner+" AND m2.bucket_ts <= ?)", args...)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return omap("conn_cur_avg", int64(0), "conn_cur_max", int64(0)), nil
	}
	return omap("conn_cur_avg", i64(rows[0][0]), "conn_cur_max", i64(rows[0][1])), nil
}

func (d *Database) backendHealth() (*OMap, error) {
	rows, err := d.queryAll("SELECT o.kind, o.proxy, o.server, e.state, e.ts FROM server_state_events e JOIN objects o ON o.id = e.object_id WHERE e.id IN (SELECT MAX(id) FROM server_state_events GROUP BY object_id) AND e.state != ? ORDER BY o.proxy, o.server", removedState)
	if err != nil {
		return nil, err
	}
	backends, servers := []any{}, []any{}
	var bUp, sUp int64
	for _, r := range rows {
		e := omap("proxy", textOf(r[1]), "server", textOf(r[2]), "state", textOf(r[3]), "since", i64(r[4]))
		if textOf(r[0]) == "backend" {
			backends = append(backends, e)
			if textOf(r[3]) == "UP" {
				bUp++
			}
		} else {
			servers = append(servers, e)
			if textOf(r[3]) == "UP" {
				sUp++
			}
		}
	}
	return omap("backends", backends, "servers", servers, "backends_up", bUp, "backends_total", int64(len(backends)),
		"servers_up", sUp, "servers_total", int64(len(servers))), nil
}

func stateScope(site, alias string) (string, []any) {
	if site == "" {
		return alias + ".kind IN ('backend', 'server')", nil
	}
	return alias + ".kind IN ('backend', 'server') AND " + alias + ".proxy = ?", []any{site}
}

type stateChange struct {
	ts    int64
	state string
}

func (d *Database) stateTimeline(site string, since, until int64) (*OMap, error) {
	predicate, params := stateScope(site, "o")
	d.mu.Lock()
	objects, err := queryRows(d.db, "SELECT o.id, o.kind, o.proxy, o.server FROM objects o WHERE "+predicate+" ORDER BY o.proxy, o.kind DESC, o.server", params...)
	if err != nil {
		d.mu.Unlock()
		return nil, err
	}
	if len(objects) == 0 {
		d.mu.Unlock()
		return omap("objects", []any{}, "truncated", false), nil
	}
	ids := []any{}
	for _, r := range objects {
		ids = append(ids, i64(r[0]))
	}
	marks := strings.TrimSuffix(strings.Repeat("?, ", len(ids)), ", ")
	initialRows, err := queryRows(d.db, "SELECT object_id, state FROM server_state_events WHERE id IN (  SELECT MAX(id) FROM server_state_events   WHERE ts <= ? AND object_id IN ("+marks+")   GROUP BY object_id)", append([]any{since}, ids...)...)
	if err != nil {
		d.mu.Unlock()
		return nil, err
	}
	events, err := queryRows(d.db, "SELECT object_id, ts, state FROM server_state_events WHERE object_id IN ("+marks+") AND ts > ? AND ts <= ? ORDER BY object_id, id", append(ids, since, until)...)
	d.mu.Unlock()
	if err != nil {
		return nil, err
	}
	initial := map[int64]string{}
	for _, r := range initialRows {
		initial[i64(r[0])] = textOf(r[1])
	}
	byObject := map[int64][]stateChange{}
	for _, r := range events {
		id := i64(r[0])
		byObject[id] = append(byObject[id], stateChange{i64(r[1]), textOf(r[2])})
	}
	window := maxI(1, until-since)
	compressed := false
	result := []any{}
	drawn := func(s string) string {
		if s == removedState {
			return absentSpan
		}
		return s
	}
	for _, r := range objects {
		id := i64(r[0])
		changes := byObject[id]
		state, hasState := initial[id]
		if !hasState && len(changes) == 0 {
			continue
		}
		allRemoved := true
		for _, c := range changes {
			if c.state != removedState {
				allRemoved = false
			}
		}
		if (!hasState || state == removedState) && allRemoved {
			continue
		}
		spans := []span{}
		var cursor int64
		var current string
		if !hasState {
			cursor = maxI(since, changes[0].ts)
			closeSpan(&spans, since, cursor, absentSpan)
			current = changes[0].state
		} else {
			cursor, current = since, state
		}
		var removedAt int64
		hasRemoved := false
		for _, c := range changes {
			closeSpan(&spans, cursor, c.ts, drawn(current))
			cursor = maxI(cursor, c.ts)
			current = c.state
			if c.state == removedState {
				removedAt, hasRemoved = c.ts, true
			} else {
				hasRemoved = false
			}
		}
		closeSpan(&spans, cursor, until, drawn(current))
		var absent, downtime int64
		for _, s := range spans {
			if s.State == absentSpan {
				absent += s.End - s.Start
			} else if s.State != "UP" {
				downtime += s.End - s.Start
			}
		}
		present := maxI(1, window-absent)
		if len(spans) > maxTimelineSpans {
			spans = compressSpans(spans, since, until, maxTimelineSpans)
			compressed = true
		}
		transitions := int64(0)
		for _, c := range changes {
			if c.state != removedState {
				transitions++
			}
		}
		avail := float64(present-downtime) / float64(present)
		if avail < 0 {
			avail = 0
		}
		spanList := make([]any, len(spans))
		for i, s := range spans {
			spanList[i] = s
		}
		e := omap("kind", textOf(r[1]), "proxy", textOf(r[2]), "server", textOf(r[3]), "current_state", current,
			"transitions", transitions, "downtime_seconds", downtime, "availability", pyRoundN(avail, 5), "spans", spanList)
		if current == removedState && hasRemoved {
			e.Set("removed_at", removedAt)
		}
		result = append(result, e)
	}
	return omap("objects", result, "truncated", false, "compressed", compressed), nil
}

func (d *Database) recordStorageSample(ts, total int64) error {
	slot := ts - ts%storageSampleInterval
	return d.tx(func(t *sql.Tx) error {
		if _, err := t.Exec("INSERT INTO storage_samples (ts, total_bytes) VALUES (?, ?) ON CONFLICT (ts) DO UPDATE SET total_bytes = excluded.total_bytes", slot, total); err != nil {
			return err
		}
		_, err := t.Exec("DELETE FROM storage_samples WHERE ts < ?", ts-storageSampleRetention)
		return err
	})
}

func (d *Database) storageGrowth(now, current int64) *OMap {
	since := func(seconds int64) any {
		rows, err := d.queryAll("SELECT total_bytes FROM storage_samples WHERE ts <= ? ORDER BY ts DESC LIMIT 1", now-seconds)
		if err != nil || len(rows) == 0 {
			return nil
		}
		return current - i64(rows[0][0])
	}
	day, week := since(86400), since(7*86400)
	trend := "unknown"
	if week != nil {
		w := week.(int64)
		limit := maxI(stableGrowthFloor, int64(float64(current)*stableGrowthFraction))
		aw := w
		if aw < 0 {
			aw = -aw
		}
		switch {
		case aw <= limit:
			trend = "stable"
		case w > 0:
			trend = "growing"
		default:
			trend = "shrinking"
		}
	}
	return omap("last_24h_bytes", day, "last_7d_bytes", week, "trend", trend)
}

func (d *Database) stats() (*OMap, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	one := func(q string) []any {
		rows, err := queryRows(d.db, q)
		if err != nil || len(rows) == 0 {
			return nil
		}
		return rows[0]
	}
	version := one("SELECT version FROM schema_version")
	objects := one("SELECT COUNT(*) AS value FROM objects")
	minutes := one("SELECT COUNT(*) AS value, MIN(bucket_ts) AS oldest, MAX(bucket_ts) AS newest FROM metric_1m")
	hours := one("SELECT COUNT(*) AS value, MIN(bucket_ts) AS oldest, MAX(bucket_ts) AS newest FROM metric_1h")
	events := one("SELECT COUNT(*) AS value FROM server_state_events")
	freelist := one("PRAGMA freelist_count")
	var v, fl int64
	if version != nil {
		v = i64(version[0])
	}
	if freelist != nil {
		fl = i64(freelist[0])
	}
	return omap("schema_version", v, "objects", i64(objects[0]),
		"metric_1m", omap("rows", i64(minutes[0]), "oldest_bucket_ts", nullable(minutes[1]), "newest_bucket_ts", nullable(minutes[2])),
		"metric_1h", omap("rows", i64(hours[0]), "oldest_bucket_ts", nullable(hours[1]), "newest_bucket_ts", nullable(hours[2])),
		"state_events", i64(events[0]), "freelist_pages", fl), nil
}

func fileSize(p string) int64 {
	fi, err := os.Stat(p)
	if err != nil {
		return 0
	}
	return fi.Size()
}

func (d *Database) storage() *OMap {
	db, wal, shm := fileSize(d.Path), fileSize(d.Path+"-wal"), fileSize(d.Path+"-shm")
	fs := omap("total_bytes", int64(0), "free_bytes", int64(0))
	var st syscall.Statfs_t
	if err := syscall.Statfs(filepath.Dir(d.Path), &st); err == nil {
		fs = omap("total_bytes", int64(st.Blocks)*int64(st.Frsize), "free_bytes", int64(st.Bavail)*int64(st.Frsize))
	}
	return omap("database_bytes", db, "wal_bytes", wal, "shm_bytes", shm, "total_bytes", db+wal+shm, "filesystem", fs)
}
