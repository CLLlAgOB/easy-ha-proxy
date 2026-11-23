package updated

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/alerts"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/pyx"
)

// Daemon is the shared state the Python modules keep in module globals.
type Daemon struct {
	Opts   Options
	Alerts *alerts.Client

	stateMu sync.Mutex // STATE_LOCK

	jobCacheMu sync.Mutex
	jobCache   map[string]jobCacheEntry

	opMu sync.Mutex // OPERATION_THREAD_LOCK

	shutdown chan struct{}
	stop     chan struct{}
	shutOnce sync.Once
	stopOnce sync.Once

	autoMu        sync.Mutex
	autoNextAt    float64
	autoRetry     float64
	autoNight     string
	cycleRunning  bool
	metadataFree  bool // METADATA_CONTEXT.unlocked for the running auto check
	buildMu       sync.Mutex
	buildAt       time.Time
	buildValue    map[string]any
	inspectMu     sync.Mutex
	inspectAt     time.Time
	inspectValue  map[string]any
	watchAt       float64
	watchReason   *string
	transient     func() bool
	rootUID       int
	sleep         func(time.Duration)
	now           func() time.Time
	commandRunner func(timeout time.Duration, env []string, argv ...string) (int, string, string, error)
}

// NewDaemon builds a daemon over opts without touching the filesystem.
func NewDaemon(opts Options) *Daemon {
	d := &Daemon{
		Opts: opts, Alerts: alerts.FromEnv(),
		shutdown: make(chan struct{}), stop: make(chan struct{}),
		sleep: time.Sleep, now: time.Now,
	}
	d.transient = d.transientJobsSupported
	d.commandRunner = runCapture
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

func (d *Daemon) alertsOn() bool { return d.Alerts != nil && d.Alerts.Enabled() }

func (d *Daemon) observe(obs alerts.Observation) {
	if !d.alertsOn() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	d.Alerts.Observe(ctx, obs)
}

func (d *Daemon) reportAlert(rule, subject, summary, detail string) {
	d.observe(alerts.Observation{Rule: rule, Subject: subject, Summary: summary, Detail: detail})
}

func level(rule, subject string, active bool, summary, detail string) alerts.Observation {
	return alerts.Observation{Rule: rule, Subject: subject, Active: alerts.BoolPtr(active), Summary: summary, Detail: detail}
}

// availabilityReport: (active, summary, detail), ok=false when unknown.
func availabilityReport(plan map[string]any) (bool, string, string, bool) {
	components := []map[string]any{}
	for _, item := range pyx.List(plan["components"]) {
		if m := pyx.Map(item); m != nil {
			components = append(components, m)
		}
	}
	actionable := []map[string]any{}
	for _, item := range components {
		if item["state"] == "available" && item["actionable"] == true {
			actionable = append(actionable, item)
		}
	}
	if len(actionable) == 0 {
		for _, item := range components {
			if item["state"] == "unknown" {
				return false, "", "", false
			}
		}
		return false, "Software is up to date", "", true
	}
	names := []string{}
	for _, item := range actionable {
		id := pyx.Str(item["id"])
		name, ok := alertComponentNames[id]
		if !ok {
			name = id
		}
		if item["id"] == "haproxy" {
			name += fmt.Sprintf(" %s → %s", orQ(item["installed"]), orQ(item["available"]))
		}
		if item["id"] == "os" {
			if count, ok := pyx.Int(pyx.Map(item["details"])["package_count"]); ok && count > 0 {
				name = fmt.Sprintf("%s (%d)", name, count)
			}
		}
		names = append(names, name)
	}
	summary := "Software updates are available: " + strings.Join(names, ", ")
	lines := []string{}
	var source map[string]any
	for _, item := range actionable {
		if item["id"] == "all" {
			source = item
			break
		}
	}
	changelog := pyx.Map(pyx.Map(source["details"])["changelog"])
	if commits, ok := changelog["commits"].([]any); ok && changelog != nil {
		more := "+"
		if pyx.Truthy(changelog["complete"]) {
			more = ""
		}
		lines = append(lines, fmt.Sprintf("%s%s new change(s):", pyx.Str(changelog["count"]), more))
		for i, c := range commits {
			if i >= alertChangelogLines {
				break
			}
			if cm := pyx.Map(c); cm != nil {
				subject := cm["subject"]
				if !pyx.Truthy(subject) {
					subject = cm["revision"]
				}
				lines = append(lines, "- "+pyx.Str(subject))
			}
		}
		lines = append(lines, "")
	}
	lines = append(lines, "Install them from Software updates in HAProxy Admin.")
	return true, summary, strings.Join(lines, "\n"), true
}

func orQ(v any) string {
	if pyx.Truthy(v) {
		return pyx.Str(v)
	}
	return "?"
}

func (d *Daemon) reportAvailability(plan map[string]any) {
	if !d.alertsOn() {
		return
	}
	active, summary, detail, ok := availabilityReport(plan)
	if !ok {
		return
	}
	d.observe(level(availableRule, availableSubject, active, summary, detail))
}

func identifier(value any, label string) (string, error) {
	s, ok := value.(string)
	if !ok || !identifierRe.MatchString(s) {
		return "", uErr("invalid", "invalid %s", label)
	}
	return s, nil
}

func ensureAbsolute(path, label string) error {
	if !filepath.IsAbs(path) {
		return uErr("invalid", "unsafe %s", label)
	}
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		if part == ".." {
			return uErr("invalid", "unsafe %s", label)
		}
	}
	return nil
}

func ensureDirectory(path string, uid, gid int, mode os.FileMode) error {
	if err := ensureAbsolute(path, "state path"); err != nil {
		return err
	}
	if err := os.MkdirAll(path, 0o750); err != nil {
		return err
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return uErr("invalid", "state path is not a real directory: %s", path)
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

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
	for _, p := range [][2]string{
		{d.Opts.SocketPath, "socket path"}, {d.Opts.StateRoot, "state path"}, {d.Opts.SourceDir, "source path"},
		{d.Opts.ConfigDir, "configuration path"}, {d.Opts.MaintenanceLockPath, "maintenance lock"},
		{d.Opts.ActiveMarker, "active marker"}, {d.Opts.RestartRequestMarker, "restart marker"},
		{d.Opts.RebootMarker, "reboot marker"}, {d.Opts.AssistantRebootMarker, "assistant reboot marker"},
		{d.Opts.HAProxyTransactionMarker, "HAProxy transaction marker"},
		{d.Opts.HAProxyTransactionState, "HAProxy transaction state"},
	} {
		if err := ensureAbsolute(p[0], p[1]); err != nil {
			return err
		}
	}
	if err := ensureDirectory(d.Opts.StateRoot, 0, d.Opts.AppGroupGID, 0o750); err != nil {
		return err
	}
	if err := ensureDirectory(d.Opts.JobsDir(), 0, d.Opts.AppGroupGID, 0o750); err != nil {
		return err
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

// atomicJSON is atomic_json: root:app-group 0640, fsynced.
func (d *Daemon) atomicJSON(path string, payload map[string]any) error {
	encoded, err := pyx.Encode(payload)
	if err != nil {
		return err
	}
	if len(encoded) > d.Opts.MaxStateBytes {
		return uErr("too_large", "update state is too large")
	}
	dir := filepath.Dir(path)
	temporary := filepath.Join(dir, fmt.Sprintf(".%s.%d.%s.tmp", filepath.Base(path), os.Getpid(), pyx.RandomHex(6)))
	f, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|pyx.NoFollow, 0o600)
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
	if err := f.Chown(0, d.Opts.AppGroupGID); err != nil && os.Geteuid() == 0 {
		return fail(err)
	}
	if err := f.Chmod(0o640); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
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
	return pyx.FsyncDir(dir)
}

// safeJSONFile is safe_json_file: root-owned, single link, bounded, an object.
func (d *Daemon) safeJSONFile(path string) (map[string]any, error) {
	info, err := pyx.Lstat(path)
	if err != nil {
		return nil, err
	}
	name := filepath.Base(path)
	if !info.Mode.IsRegular() || info.Nlink != 1 || info.UID != d.rootUID ||
		info.Size <= 0 || info.Size > int64(d.Opts.MaxStateBytes) {
		return nil, uErr("invalid", "unsafe update state file: %s", name)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|pyx.NoFollow, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := pyx.Fstat(f)
	if err != nil {
		return nil, err
	}
	if opened.Dev != info.Dev || opened.Ino != info.Ino {
		return nil, uErr("invalid", "state file changed while opening: %s", name)
	}
	// os.read(fd, MAX_STATE_BYTES + 1): what the file holds, never more than
	// the cap. Sized by what is read, not by the cap: listing the jobs reads
	// every job file, and a 1 MiB buffer each time kept the collector busy.
	raw, err := io.ReadAll(io.LimitReader(f, int64(d.Opts.MaxStateBytes)+1))
	if err != nil {
		return nil, err
	}
	v, err := pyx.Decode(raw)
	if err != nil {
		return nil, uErr("invalid", "%v", err)
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, uErr("invalid", "invalid update state file: %s", name)
	}
	return obj, nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func lexists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func isRegular(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}

func (d *Daemon) statePath(jobID string) (string, error) {
	id, err := identifier(jobID, "job id")
	if err != nil {
		return "", err
	}
	return filepath.Join(d.Opts.JobsDir(), id+".json"), nil
}

func (d *Daemon) newJob(operation string, values map[string]any) (map[string]any, error) {
	jobID := pyx.UUIDHex()
	state := map[string]any{
		"id": jobID, "operation": operation, "status": "queued", "created_at": pyx.UTCNow(),
		"started_at": nil, "completed_at": nil, "components": []any{}, "current_component": nil,
		"plan_id": nil, "output": nil, "result": nil, "error": nil,
	}
	for k, v := range values {
		state[k] = v
	}
	d.stateMu.Lock()
	defer d.stateMu.Unlock()
	path, _ := d.statePath(jobID)
	if err := d.atomicJSON(path, state); err != nil {
		return nil, err
	}
	return state, nil
}

func parseProgress(text string) map[string]any {
	section := text
	if i := strings.LastIndex(text, componentHeading); i >= 0 {
		section = text[i+len(componentHeading):]
	}
	matches := progressRe.FindAllStringSubmatch(section, -1)
	if len(matches) == 0 {
		return nil
	}
	last := matches[len(matches)-1]
	if last[1] != "" {
		if progressPhases[last[1]] {
			return map[string]any{"phase": last[1]}
		}
		return nil
	}
	done, _ := strconv.Atoi(last[2])
	total, _ := strconv.Atoi(last[3])
	task := pyx.TruncRunes(strings.TrimSpace(controlRe.ReplaceAllString(last[4], "")), maxProgressTask)
	return map[string]any{"phase": "playbook", "done": done, "total": total, "task": task}
}

func publicProgress(value any) any {
	m := pyx.Map(value)
	phase, _ := m["phase"].(string)
	if m == nil || !progressPhases[phase] {
		return nil
	}
	result := map[string]any{"phase": phase}
	for _, key := range []string{"done", "total"} {
		if n, ok := pyx.Int(m[key]); ok && n >= 0 && n <= 999999 {
			if _, isBool := m[key].(bool); !isBool {
				result[key] = n
			}
		}
	}
	if task, ok := m["task"].(string); ok && task != "" {
		result["task"] = pyx.TruncRunes(controlRe.ReplaceAllString(task, ""), maxProgressTask)
	}
	return result
}

func publicJob(state map[string]any, includeLog bool) map[string]any {
	var output any
	if out := pyx.Map(state["output"]); out != nil {
		if includeLog {
			output = out
		} else {
			trimmed := map[string]any{}
			for k, v := range out {
				if k != "log" {
					trimmed[k] = v
				}
			}
			output = trimmed
		}
	}
	var components any = []any{}
	if l, ok := state["components"].([]any); ok {
		components = l
	}
	var index any
	if n, ok := pyx.Int(state["component_index"]); ok {
		index = n
	}
	var compStarted any
	if pyx.Truthy(state["component_started_at"]) {
		compStarted = pyx.TruncRunes(pyx.Str(state["component_started_at"]), 40)
	}
	var result any
	if r := pyx.Map(state["result"]); r != nil {
		result = r
	}
	var errText any
	if pyx.Truthy(state["error"]) {
		errText = pyx.TruncRunes(pyx.Str(state["error"]), 4096)
	}
	return map[string]any{
		"id": pyx.StrOr(state["id"]), "operation": pyx.StrOr(state["operation"]),
		"status": pyx.StrOr(state["status"]), "created_at": state["created_at"],
		"started_at": state["started_at"], "completed_at": state["completed_at"],
		"components": components, "current_component": state["current_component"],
		"component_index": index, "component_started_at": compStarted,
		"scheduled": state["scheduled"] == true, "progress": publicProgress(state["progress"]),
		"plan_id": state["plan_id"], "output": output, "result": result, "error": errText,
	}
}

func (d *Daemon) loadJob(jobID string, includeLog bool) (map[string]any, error) {
	path, err := d.statePath(jobID)
	if err != nil {
		return nil, err
	}
	if !exists(path) {
		return nil, uErr("not_found", "update job was not found")
	}
	state, err := d.safeJSONFile(path)
	if err != nil {
		return nil, err
	}
	if state["id"] != jobID {
		return nil, uErr("invalid", "update job identifier does not match")
	}
	return publicJob(state, includeLog), nil
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
	if err := d.atomicJSON(path, state); err != nil {
		return nil, err
	}
	return publicJob(state, true), nil
}

// jobCacheEntry is a job file as listJobs last read it, and the lstat it
// was read under. Every write replaces the file by rename, so a changed file
// is a different inode, size or mtime and is read again.
type jobCacheEntry struct {
	sig pyx.StatInfo
	job map[string]any
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
		stem := strings.TrimSuffix(filepath.Base(path), ".json")
		if !identifierRe.MatchString(stem) {
			continue
		}
		sig, statErr := pyx.Lstat(path)
		if kept, ok := d.jobCache[stem]; ok && statErr == nil && kept.sig == sig {
			seen[stem] = true
			jobs = append(jobs, kept.job)
			continue
		}
		job, err := d.loadJob(stem, false)
		if err != nil {
			log.Printf("Ignoring unsafe update job state %s", filepath.Base(path))
			continue
		}
		if statErr == nil {
			seen[stem] = true
			d.jobCache[stem] = jobCacheEntry{sig: sig, job: job}
		}
		jobs = append(jobs, job)
	}
	for stem := range d.jobCache {
		if !seen[stem] {
			delete(d.jobCache, stem)
		}
	}
	sort.SliceStable(jobs, func(i, j int) bool {
		return pyx.StrOr(jobs[i]["created_at"]) > pyx.StrOr(jobs[j]["created_at"])
	})
	if len(jobs) > d.Opts.ListLimit {
		jobs = jobs[:d.Opts.ListLimit]
	}
	// The cache keeps its own maps: callers get copies they may change.
	for i, job := range jobs {
		jobs[i] = deepCopyMap(job)
	}
	return jobs
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

func activeStatus(s any) bool { return s == "queued" || s == "running" }

func (d *Daemon) activeJob() map[string]any {
	for _, job := range d.listJobs() {
		if activeStatus(job["status"]) {
			return job
		}
	}
	return nil
}

func (d *Daemon) recoverStaleJobs() error {
	if err := d.stopOrphanTransientJobs(); err != nil {
		return err
	}
	for _, job := range d.listJobs() {
		if !activeStatus(job["status"]) {
			continue
		}
		id := job["id"].(string)
		logText := d.readFileTail(filepath.Join(d.Opts.JobsDir(), "."+id+".output"))
		if logText == "" {
			logText = pyx.StrOr(pyx.Map(job["output"])["log"])
		}
		_, _ = d.updateJob(id, map[string]any{
			"status": "interrupted", "completed_at": pyx.UTCNow(),
			"error":  "the update broker restarted before the job completed",
			"output": map[string]any{"log": logText},
		})
	}
	for _, marker := range []string{d.Opts.ActiveMarker, d.Opts.RestartRequestMarker} {
		_ = os.Remove(marker)
	}
	matches, _ := filepath.Glob(filepath.Join(d.Opts.JobsDir(), ".*.output"))
	for _, path := range matches {
		name := filepath.Base(path)
		if !identifierRe.MatchString(strings.TrimSuffix(name[1:], ".output")) {
			continue
		}
		if info, err := pyx.Lstat(path); err == nil && info.Mode.IsRegular() && info.UID == d.rootUID {
			_ = os.Remove(path)
		}
	}
	return nil
}

func (d *Daemon) stopOrphanTransientJobs() error {
	if !d.transient() {
		return nil
	}
	rc, out, _, err := d.commandRunner(30*time.Second, nil, systemctlPath, "list-units", "--all", "--plain",
		"--no-legend", "easy-ha-proxy-updated-job-*.service")
	if err != nil || rc != 0 {
		return uErr("invalid", "Could not inspect surviving update jobs")
	}
	for _, line := range strings.Split(out, "\n") {
		parts := strings.Fields(line)
		if len(parts) == 0 || !strings.HasPrefix(parts[0], "easy-ha-proxy-updated-job-") {
			continue
		}
		unit := parts[0]
		log.Printf("Waiting for surviving update job %s", unit)
		for {
			if d.shuttingDown() {
				return uErr("invalid", "Broker stopped while waiting for surviving update jobs")
			}
			props := d.systemctlProperties(unit, []string{"LoadState", "ActiveState", "SubState", "Job"})
			if props["LoadState"] == "not-found" {
				break
			}
			active := props["ActiveState"]
			if active == "" {
				return uErr("invalid", "Could not inspect surviving update job %s", unit)
			}
			jobField := props["Job"]
			if jobField == "" {
				jobField = "0"
			}
			pending := strings.Fields(jobField)[0] != "0"
			if !pending && (active == "inactive" || active == "failed" || (active == "active" && props["SubState"] == "exited")) {
				break
			}
			d.sleep(500 * time.Millisecond)
		}
		d.stopTransientUnit(unit)
	}
	return nil
}

// sanitizeLog strips control characters and keeps the last MAX_CAPTURE bytes.
func (d *Daemon) sanitizeLog(value string) string {
	clean := strings.ReplaceAll(controlRe.ReplaceAllString(value, ""), "\r", "")
	clean = strings.ToValidUTF8(clean, "�")
	limit := d.Opts.MaxCaptureBytes
	if len(clean) > limit {
		prefix := "[output truncated]\n"
		if limit <= len(prefix) {
			return prefix[:limit]
		}
		tail := clean[len(clean)-(limit-len(prefix)):]
		// Drop an incomplete leading code point to keep the byte cap exact.
		for len(tail) > 0 && !utf8Start(tail[0]) {
			tail = tail[1:]
		}
		clean = prefix + tail
	}
	return clean
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }

func (d *Daemon) readFileTail(path string) string {
	f, err := os.OpenFile(path, os.O_RDONLY|pyx.NoFollow, 0)
	if err != nil {
		return ""
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || fi.Size() <= 0 {
		return ""
	}
	offset := fi.Size() - int64(d.Opts.MaxCaptureBytes*2)
	if offset < 0 {
		offset = 0
	}
	buf := make([]byte, fi.Size()-offset)
	n, _ := f.ReadAt(buf, offset)
	return d.sanitizeLog(strings.ToValidUTF8(string(buf[:n]), "�"))
}

func childEnvironment() []string {
	lang, ok := os.LookupEnv("LANG")
	if !ok {
		lang = "C.UTF-8"
	}
	lcAll, ok := os.LookupEnv("LC_ALL")
	if !ok {
		lcAll = "C.UTF-8"
	}
	return []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG=" + lang, "LC_ALL=" + lcAll, "PYTHONUNBUFFERED=1", "EASY_HA_PROXY_LANGUAGE=en",
		"EASY_HA_PROXY_PROGRESS=1", "EASY_HA_PROXY_REBOOT_DECISION=no",
		"EASY_HA_PROXY_MAINTENANCE_LOCK_HELD=updated",
	}
}

func runCapture(timeout time.Duration, env []string, argv ...string) (int, string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	if env != nil {
		cmd.Env = env
	}
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return -1, out.String(), errb.String(), fmt.Errorf("Command '%s' timed out after %d seconds", argv[0], int(timeout.Seconds()))
	}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode(), out.String(), errb.String(), nil
		}
		return -1, out.String(), errb.String(), err
	}
	return 0, out.String(), errb.String(), nil
}
