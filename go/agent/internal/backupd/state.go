package backupd

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/alerts"
)

// Daemon is the shared state the Python modules keep in module globals.
type Daemon struct {
	Opts   Options
	Alerts *alerts.Client

	stateMu sync.Mutex // STATE_LOCK

	jobCacheMu sync.Mutex
	jobCache   map[string]jobCacheEntry

	opMu     sync.Mutex // OPERATION_THREAD_LOCK
	uploadMu sync.Mutex // DESTINATION_UPLOAD_LOCKS_GUARD
	uploads  map[string]*uploadLock

	timerMu    sync.Mutex
	timerAt    time.Time
	timerValue map[string]any

	shutdown  chan struct{}
	stop      chan struct{}
	shutOnce  sync.Once
	stopOnce  sync.Once
	transient func() bool
	// helper is the full-backup command: the installed agent's
	// "full-backup"; the tests put a stand-in there.
	helper  []string
	rootUID int // the owner trusted for daemon-written files (root)
	sleep   func(time.Duration)
}

type uploadLock struct {
	mu    sync.Mutex
	users int
}

// NewDaemon builds a daemon over opts without touching the filesystem.
func NewDaemon(opts Options) *Daemon {
	d := &Daemon{
		Opts:     opts,
		Alerts:   alerts.FromEnv(),
		uploads:  map[string]*uploadLock{},
		shutdown: make(chan struct{}),
		stop:     make(chan struct{}),
		sleep:    time.Sleep,
		helper:   []string{"/usr/local/sbin/easy-ha-proxy-agent", "full-backup"},
	}
	d.transient = d.transientJobsSupported
	return d
}

func (d *Daemon) shuttingDown() bool {
	select {
	case <-d.shutdown:
		return true
	default:
		return false
	}
}

func (d *Daemon) requestShutdown() { d.shutOnce.Do(func() { close(d.shutdown) }) }
func (d *Daemon) requestStop()     { d.stopOnce.Do(func() { close(d.stop) }) }

// reportAlert tells the alert engine a job failed; never disturbs the job.
func (d *Daemon) reportAlert(rule, subject, summary, detail string) {
	if d.Alerts == nil || !d.Alerts.Enabled() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	d.Alerts.Observe(ctx, alerts.Observation{Rule: rule, Subject: subject, Summary: summary, Detail: detail})
}

// ---------------------------------------------------------------------------
// Python value semantics
// ---------------------------------------------------------------------------

// pyISO is datetime.isoformat() for an aware UTC datetime.
func pyISO(t time.Time) string {
	t = t.UTC()
	if t.Nanosecond()/1000 == 0 {
		return t.Format("2006-01-02T15:04:05") + "+00:00"
	}
	return t.Format("2006-01-02T15:04:05.000000") + "+00:00"
}

func utcNow() string { return pyISO(time.Now()) }

// parseISO is datetime.fromisoformat for the forms this project writes.
func parseISO(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if strings.HasSuffix(raw, "Z") {
		raw = raw[:len(raw)-1] + "+00:00"
	}
	for _, layout := range []string{
		"2006-01-02T15:04:05.999999999-07:00", "2006-01-02T15:04:05-07:00", "20060102T150405-07:00", "20060102T150405.999999-07:00",
		"2006-01-02 15:04:05.999999999-07:00", "2006-01-02 15:04:05-07:00",
	} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t, true
		}
	}
	for _, layout := range []string{
		"2006-01-02T15:04:05.999999999", "2006-01-02T15:04:05",
		"2006-01-02 15:04:05.999999999", "2006-01-02 15:04:05", "2006-01-02",
	} {
		if t, err := time.ParseInLocation(layout, raw, time.UTC); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// pyStr is str(value or "").
func pyStr(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case json.Number:
		return x.String()
	case bool:
		if x {
			return "True"
		}
		return ""
	case float64:
		if x == 0 {
			return ""
		}
		if x == math.Trunc(x) && math.Abs(x) < 1e16 {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'g', -1, 64)
	case int:
		if x == 0 {
			return ""
		}
		return strconv.Itoa(x)
	case int64:
		if x == 0 {
			return ""
		}
		return strconv.FormatInt(x, 10)
	}
	return fmt.Sprint(v)
}

// truthy is Python's bool(value).
func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case float64:
		return x != 0
	case int:
		return x != 0
	case int64:
		return x != 0
	case json.Number:
		f, _ := x.Float64()
		return f != 0
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

// pyInt is int(value): numbers truncate, strings must be whole numbers.
func pyInt(v any) (int64, bool) {
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
	case int:
		return int64(x), true
	case int64:
		return x, true
	case json.Number:
		if n, err := x.Int64(); err == nil {
			return n, true
		}
		if f, err := x.Float64(); err == nil {
			return int64(f), true
		}
		return 0, false
	case string:
		s := strings.ReplaceAll(strings.TrimSpace(x), "_", "")
		n, err := strconv.ParseInt(s, 10, 64)
		return n, err == nil
	}
	return 0, false
}

// intOr is int(value or default) where an unparseable value yields fallback.
func intOr(v any, def int64) int64 {
	if !truthy(v) {
		return def
	}
	if n, ok := pyInt(v); ok {
		return n
	}
	return def
}

// strictInt is isinstance(value, int) and not isinstance(value, bool).
func strictInt(v any) (int64, bool) {
	switch x := v.(type) {
	case int:
		return int64(x), true
	case int64:
		return x, true
	case json.Number:
		n, err := x.Int64()
		return n, err == nil
	case float64:
		// Requests arrive as float64; a whole number is what was sent.
		if x == math.Trunc(x) && !math.IsInf(x, 0) {
			return int64(x), true
		}
	}
	return 0, false
}

func truncRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n])
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func uuidHex() string { return randomHex(16) }

// encodeJSON is json.dumps(payload, ensure_ascii=False, sort_keys=True).
func encodeJSON(payload any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodeJSON(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// ---------------------------------------------------------------------------
// State files
// ---------------------------------------------------------------------------

func identifier(value any, label string) (string, error) {
	s, ok := value.(string)
	if !ok || !identifierRe.MatchString(s) {
		return "", bErr("invalid", "invalid %s", label)
	}
	return s, nil
}

func requireBool(value any, label string) (bool, error) {
	b, ok := value.(bool)
	if !ok {
		return false, bErr("invalid", "%s must be true or false", label)
	}
	return b, nil
}

func requirePassphrase(value any) (string, error) {
	s, ok := value.(string)
	if !ok || utf8.RuneCountInString(s) < 12 {
		return "", bErr("invalid", "the backup passphrase must contain at least 12 characters")
	}
	if utf8.RuneCountInString(s) > 1024 || strings.ContainsAny(s, "\x00\n\r") {
		return "", bErr("invalid", "the backup passphrase is invalid")
	}
	return s, nil
}

// atomicJSON is atomic_json.
func (d *Daemon) atomicJSON(path string, payload map[string]any, mode os.FileMode) error {
	encoded, err := encodeJSON(payload)
	if err != nil {
		return err
	}
	if len(encoded) > d.Opts.MaxStateBytes {
		return bErr("too_large", "job state is too large")
	}
	dir := filepath.Dir(path)
	temporary := filepath.Join(dir, fmt.Sprintf(".%s.%d.%s.tmp", filepath.Base(path), os.Getpid(), randomHex(6)))
	f, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|oNoFollow, 0o600)
	if err != nil {
		return err
	}
	fail := func(e error) error {
		_ = f.Close()
		_ = os.Remove(temporary)
		return e
	}
	if _, err := f.Write(encoded); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := setOwnerFd(f, 0, d.Opts.AppGroupGID); err != nil {
		return fail(err)
	}
	if err := f.Chmod(mode); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return fsyncDirectory(dir)
}

// safeJSONFile is safe_json_file: root-owned (or ours when unprivileged),
// regular, single-link, bounded, a JSON object. Numbers stay json.Number.
func (d *Daemon) safeJSONFile(path string) (map[string]any, error) {
	expected := 0
	if geteuid() != 0 {
		expected = geteuid()
	}
	info, err := lstatInfo(path)
	if err != nil {
		return nil, err
	}
	name := filepath.Base(path)
	if !info.Mode.IsRegular() || info.Nlink != 1 || info.UID != expected ||
		info.Size <= 0 || info.Size > int64(d.Opts.MaxStateBytes) {
		return nil, bErr("invalid", "unsafe state file: %s", name)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|oNoFollow, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	cur, err := fstatInfo(f)
	if err != nil {
		return nil, err
	}
	if cur.Dev != info.Dev || cur.Ino != info.Ino {
		return nil, bErr("invalid", "state file changed while opening: %s", name)
	}
	// Sized by what is read, not by the cap: listing the jobs reads every job
	// file, and a 1 MiB buffer each time kept the collector busy.
	raw, _ := io.ReadAll(io.LimitReader(f, int64(d.Opts.MaxStateBytes)+1))
	if len(raw) > d.Opts.MaxStateBytes {
		return nil, bErr("invalid", "state file is too large: %s", name)
	}
	v, err := decodeJSON(raw)
	if err != nil {
		return nil, bErr("invalid", "%v", err)
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, bErr("invalid", "invalid state file: %s", name)
	}
	return obj, nil
}

func readFull(f *os.File, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := f.Read(buf[total:])
		total += n
		if err != nil || n == 0 {
			return total, err
		}
	}
	return total, nil
}

func (d *Daemon) statePath(jobID string) (string, error) {
	id, err := identifier(jobID, "job id")
	if err != nil {
		return "", err
	}
	return filepath.Join(d.Opts.JobsDir(), id+".json"), nil
}

func (d *Daemon) newJob(operation string, uploadID any) (map[string]any, error) {
	jobID := uuidHex()
	state := map[string]any{
		"id": jobID, "operation": operation, "status": "queued",
		"created_at": utcNow(), "started_at": nil, "completed_at": nil,
		"upload_id": uploadID, "manifest": nil, "output": nil, "error": nil,
	}
	d.stateMu.Lock()
	defer d.stateMu.Unlock()
	path, _ := d.statePath(jobID)
	if err := d.atomicJSON(path, state, 0o640); err != nil {
		return nil, err
	}
	return state, nil
}

func (d *Daemon) loadJob(jobID string, includeLogs bool) (map[string]any, error) {
	path, err := d.statePath(jobID)
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(path); err != nil {
		return nil, bErr("not_found", "job was not found")
	}
	state, err := d.safeJSONFile(path)
	if err != nil {
		return nil, err
	}
	if state["id"] != jobID {
		return nil, bErr("invalid", "job state identifier does not match")
	}
	return publicJob(state, includeLogs), nil
}

func (d *Daemon) updateJob(jobID string, updates map[string]any) (map[string]any, error) {
	d.stateMu.Lock()
	defer d.stateMu.Unlock()
	path, err := d.statePath(jobID)
	if err != nil {
		return nil, err
	}
	state, err := d.safeJSONFile(path)
	if err != nil {
		return nil, err
	}
	for k, v := range updates {
		state[k] = v
	}
	if err := d.atomicJSON(path, state, 0o640); err != nil {
		return nil, err
	}
	return publicJob(state, true), nil
}

func publicJob(state map[string]any, includeLogs bool) map[string]any {
	var output any
	if out, ok := state["output"].(map[string]any); ok {
		if includeLogs {
			output = out
		} else {
			trimmed := map[string]any{}
			for k, v := range out {
				if k != "stdout" && k != "stderr" {
					trimmed[k] = v
				}
			}
			output = trimmed
		}
	}
	var manifest any
	if m, ok := state["manifest"].(map[string]any); ok {
		manifest = m
	}
	var errText any
	if truthy(state["error"]) {
		errText = truncRunes(pyStr(state["error"]), 4096)
	}
	return map[string]any{
		"id":           pyStr(state["id"]),
		"operation":    pyStr(state["operation"]),
		"status":       pyStr(state["status"]),
		"created_at":   state["created_at"],
		"started_at":   state["started_at"],
		"completed_at": state["completed_at"],
		"upload_id":    state["upload_id"],
		"scope":        state["scope"],
		"manifest":     manifest,
		"output":       output,
		"error":        errText,
	}
}

func sortByCreatedDesc(items []map[string]any) {
	sort.SliceStable(items, func(i, j int) bool {
		return pyStr(items[i]["created_at"]) > pyStr(items[j]["created_at"])
	})
}

// jobCacheEntry is a job file as listJobs last read it, and the lstat it
// was read under. Every write replaces the file by rename, so a changed file
// is a different inode, size or mtime and is read again.
type jobCacheEntry struct {
	sig statInfo
	job map[string]any
}

func deepCopyValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		return deepCopyMap(x)
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = deepCopyValue(item)
		}
		return out
	}
	return v
}

func deepCopyMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = deepCopyValue(v)
	}
	return out
}

func (d *Daemon) listJobs() []map[string]any {
	matches, _ := filepath.Glob(filepath.Join(d.Opts.JobsDir(), "*.json"))
	jobs := []map[string]any{}
	d.jobCacheMu.Lock()
	defer d.jobCacheMu.Unlock()
	if d.jobCache == nil {
		d.jobCache = map[string]jobCacheEntry{}
	}
	seen := map[string]bool{}
	for _, path := range matches {
		jobID := strings.TrimSuffix(filepath.Base(path), ".json")
		if !identifierRe.MatchString(jobID) {
			continue
		}
		sig, statErr := lstatInfo(path)
		if kept, ok := d.jobCache[jobID]; ok && statErr == nil && kept.sig == sig {
			seen[jobID] = true
			jobs = append(jobs, kept.job)
			continue
		}
		job, err := d.loadJob(jobID, false)
		if err != nil {
			log.Printf("Ignoring unsafe job state %s", filepath.Base(path))
			continue
		}
		if statErr == nil {
			seen[jobID] = true
			d.jobCache[jobID] = jobCacheEntry{sig: sig, job: job}
		}
		jobs = append(jobs, job)
	}
	for jobID := range d.jobCache {
		if !seen[jobID] {
			delete(d.jobCache, jobID)
		}
	}
	sortByCreatedDesc(jobs)
	if len(jobs) > d.Opts.ListLimit {
		jobs = jobs[:d.Opts.ListLimit]
	}
	// The cache keeps its own maps: callers get copies they may change.
	for i, job := range jobs {
		jobs[i] = deepCopyMap(job)
	}
	return jobs
}

func activeStatus(s any) bool   { return s == "queued" || s == "running" }
func terminalStatus(s any) bool { return s == "completed" || s == "failed" || s == "interrupted" }

func (d *Daemon) activeJob() map[string]any {
	for _, job := range d.listJobs() {
		if activeStatus(job["status"]) {
			return job
		}
	}
	return nil
}

func (d *Daemon) recoverStaleJobs() {
	for _, job := range d.listJobs() {
		if activeStatus(job["status"]) {
			_, _ = d.updateJob(job["id"].(string), map[string]any{
				"status": "interrupted", "completed_at": utcNow(),
				"error": "the backup daemon restarted before the job completed",
			})
		}
	}
	for _, marker := range []string{d.Opts.RestoreActiveMarker, d.Opts.RestartRequestMarker} {
		_ = os.Remove(marker)
	}
	d.stopOrphanTransientJobs()
}

func (d *Daemon) stopOrphanTransientJobs() {
	if !d.transient() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, systemctlPath, "list-units", "--all", "--plain",
		"--no-legend", "easy-ha-proxy-backupd-job-*.service").Output()
	if err != nil && len(out) == 0 {
		log.Printf("Could not list orphan transient backup jobs")
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && strings.HasPrefix(fields[0], "easy-ha-proxy-backupd-job-") {
			log.Printf("Stopping orphan transient backup job %s", fields[0])
			stopTransientUnit(fields[0])
		}
	}
}

var (
	jobScratchRe   = regexp.MustCompile(`^\.job-[0-9a-f]{12}\.(stdout|stderr|stdin)$`)
	recoveryDirRe  = regexp.MustCompile(`^\.[0-9a-f]{32}\.recovery-source$`)
	workDirRe      = regexp.MustCompile(`^\.work-[0-9a-f]{32}$`)
	uploadCopySufx = ".upload" + ArchiveSuffix
)

// cleanupStaleWorkerArtifacts removes root-owned scratch data left by an
// interrupted daemon process.
func (d *Daemon) cleanupStaleWorkerArtifacts() {
	for _, parent := range []string{d.Opts.JobsDir(), filepath.Dir(d.Opts.SocketPath)} {
		matches, _ := filepath.Glob(filepath.Join(parent, ".job-*.*"))
		for _, path := range matches {
			if !jobScratchRe.MatchString(filepath.Base(path)) {
				continue
			}
			if info, err := lstatInfo(path); err == nil && info.Mode.IsRegular() && info.UID == d.rootUID {
				_ = os.Remove(path)
			}
		}
	}
	matches, _ := filepath.Glob(filepath.Join(d.Opts.JobsDir(), ".*"+uploadCopySufx+"*"))
	for _, path := range matches {
		name := filepath.Base(path)
		jobID := ""
		if strings.HasSuffix(name, uploadCopySufx) {
			jobID = name[1 : len(name)-len(uploadCopySufx)]
		}
		if strings.HasSuffix(name, uploadCopySufx+".sha256") {
			jobID = name[1 : len(name)-len(uploadCopySufx+".sha256")]
		}
		if !identifierRe.MatchString(jobID) {
			continue
		}
		if info, err := lstatInfo(path); err == nil && info.Mode.IsRegular() && info.Nlink == 1 && info.UID == d.rootUID {
			_ = os.Remove(path)
		}
	}
	for _, pair := range []struct {
		dir string
		re  *regexp.Regexp
	}{{d.Opts.JobsDir(), recoveryDirRe}, {d.Opts.BackupsDir(), workDirRe}} {
		entries, _ := os.ReadDir(pair.dir)
		for _, ent := range entries {
			if !pair.re.MatchString(ent.Name()) {
				continue
			}
			path := filepath.Join(pair.dir, ent.Name())
			if info, err := lstatInfo(path); err == nil && info.Mode.IsDir() && info.UID == d.rootUID {
				_ = os.RemoveAll(path)
			}
		}
	}
}

// ensureLayout is ensure_layout.
func (d *Daemon) ensureLayout() error {
	u, err := user.Lookup(d.Opts.AppUser)
	if err != nil {
		return err
	}
	g, err := user.LookupGroup(d.Opts.AppGroup)
	if err != nil {
		return err
	}
	d.Opts.AppUID, _ = strconv.Atoi(u.Uid)
	d.Opts.AppPrimaryGID, _ = strconv.Atoi(u.Gid)
	d.Opts.AppGroupGID, _ = strconv.Atoi(g.Gid)
	for _, p := range []struct{ path, label string }{
		{d.Opts.SocketPath, "socket path"}, {d.Opts.SpoolRoot, "spool root"},
		{d.Opts.SourceDir, "source path"}, {d.Opts.RestoreActiveMarker, "restore marker"},
		{d.Opts.RestartRequestMarker, "restart marker"}, {d.Opts.RebootMarker, "reboot marker"},
		{d.Opts.AssistantRebootMarker, "assistant reboot marker"},
		{d.Opts.OperationLockPath, "operation lock"},
	} {
		if err := ensureAbsolutePath(p.path, p.label); err != nil {
			return err
		}
	}
	for _, dir := range []struct {
		path     string
		uid, gid int
		mode     os.FileMode
	}{
		{d.Opts.SpoolRoot, 0, d.Opts.AppGroupGID, 0o750},
		{d.Opts.JobsDir(), 0, d.Opts.AppGroupGID, 0o750},
		{d.Opts.BackupsDir(), 0, d.Opts.AppGroupGID, 0o750},
		{d.Opts.UploadsDir(), d.Opts.AppUID, d.Opts.AppPrimaryGID, 0o700},
	} {
		if err := ensureDirectory(dir.path, dir.uid, dir.gid, dir.mode); err != nil {
			return err
		}
	}
	parent := filepath.Dir(d.Opts.SocketPath)
	if err := os.MkdirAll(parent, 0o750); err != nil {
		return err
	}
	if err := os.Chown(parent, 0, d.Opts.AppGroupGID); err != nil {
		return err
	}
	return os.Chmod(parent, 0o750)
}

func ensureAbsolutePath(path, label string) error {
	if !filepath.IsAbs(path) {
		return bErr("invalid", "unsafe %s", label)
	}
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		if part == ".." {
			return bErr("invalid", "unsafe %s", label)
		}
	}
	return nil
}

func ensureDirectory(path string, uid, gid int, mode os.FileMode) error {
	if err := ensureAbsolutePath(path, "spool path"); err != nil {
		return err
	}
	if err := os.MkdirAll(path, 0o750); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return bErr("invalid", "spool path is not a real directory: %s", path)
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func isNotExist(err error) bool { return errors.Is(err, os.ErrNotExist) }
