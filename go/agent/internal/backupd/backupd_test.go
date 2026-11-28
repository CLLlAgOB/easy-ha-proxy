package backupd

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeHelper stands in for "easy-ha-proxy-agent full-backup"; run as `sh helper ...`.
const fakeHelper = `read pass
case "$1" in
backup)
  f="$3/easy-ha-proxy-full-backup-test.tar.gz.enc"
  printf 'cipher-%s' "$pass" > "$f"
  sum=$(sha256sum "$f" | cut -d' ' -f1)
  echo "$sum  $(basename "$f")" > "$f.sha256"
  echo "progress for $pass"
  echo 'EASY_HA_PROXY_BACKUP_MANIFEST_JSON={"format":"easy-ha-proxy-full-backup","format_version":2,"created_at":"2026-11-22T10:00:00+00:00","payload_expanded_bytes":100,"ssh_included":false,"unknown":1}'
  echo "EASY_HA_PROXY_FULL_BACKUP_FILE=$f"
  ;;
inspect)
  echo 'EASY_HA_PROXY_BACKUP_MANIFEST_JSON={"format":"easy-ha-proxy-full-backup","format_version":2,"created_at":"2026-11-22T10:00:00+00:00","payload_expanded_bytes":100,"ssh_included":false}'
  ;;
restore)
  echo "restore $*"
  [ -f "$2.sha256" ] || { echo "no sidecar" >&2; exit 3; }
  [ -n "$EASY_HA_PROXY_SOURCE_DIR" ] || { echo "no source" >&2; exit 4; }
  ;;
esac
`

func newTestDaemon(t *testing.T) *Daemon {
	t.Helper()
	root := t.TempDir()
	source := filepath.Join(root, "source")
	for _, rel := range []string{"install-local.sh", "installer/easy-ha-proxy", "installer/agent-fetch.sh",
		"ansible/easy-ha-proxy.yml"} {
		p := filepath.Join(source, rel)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte("x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	helper := filepath.Join(root, "full-backup-helper")
	if err := os.WriteFile(helper, []byte(fakeHelper), 0o644); err != nil {
		t.Fatal(err)
	}
	opts := Options{
		SocketPath: filepath.Join(root, "run", "backupd.sock"), SpoolRoot: filepath.Join(root, "spool"),
		SourceDir: source, RestoreActiveMarker: filepath.Join(root, "run", "restore.active"),
		RestartRequestMarker: filepath.Join(root, "run", "restart.requested"),
		RebootMarker:         filepath.Join(root, "run", "reboot.json"), AssistantRebootMarker: filepath.Join(root, "run", "reboot-scheduled"),
		OperationLockPath: filepath.Join(root, "run", "op.lock"), ServiceName: "x.service",
		DestinationsDir: filepath.Join(root, "dest"), SchedulePath: filepath.Join(root, "schedule.json"),
		SchedulePassphrase: filepath.Join(root, "schedule.key"), TimerDropinDir: filepath.Join(root, "timer.d"),
		MaxRequestBytes: 65536, MaxArchiveBytes: 1 << 30, MinFreeBytes: 1, LowSpaceBytes: 1,
		MaxCaptureBytes: 65536, MaxStateBytes: 262144, JobTimeoutSeconds: 60, ListLimit: 50,
		UploadTTLSeconds: 86400, MaxConnections: 4, SFTPTimeoutSeconds: 5, S3TimeoutSeconds: 5,
		ScheduledTimeoutSeconds: 60, VerifyDownloadMaxBytes: 1 << 20,
		AppUID: os.Getuid(), AppPrimaryGID: -1, AppGroupGID: -1,
	}
	for _, dir := range []string{opts.JobsDir(), opts.UploadsDir(), opts.BackupsDir(), filepath.Dir(opts.SocketPath)} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	d := NewDaemon(opts)
	d.Alerts = nil
	d.helper = []string{"/bin/sh", helper}
	d.rootUID = os.Geteuid()
	d.transient = func() bool { return false }
	d.sleep = func(time.Duration) { time.Sleep(10 * time.Millisecond) }
	return d
}

func call(t *testing.T, d *Daemon, req map[string]any) (map[string]any, error) {
	t.Helper()
	return d.Dispatch(context.Background(), req)
}

func mustCall(t *testing.T, d *Daemon, req map[string]any) map[string]any {
	t.Helper()
	out, err := call(t, d, req)
	if err != nil {
		t.Fatalf("%v: %v", req["action"], err)
	}
	return out
}

func waitJob(t *testing.T, d *Daemon, id string) map[string]any {
	t.Helper()
	for i := 0; i < 500; i++ {
		job, err := d.loadJob(id, true)
		if err == nil && terminalStatus(job["status"]) {
			// Give the worker's deferred release a moment.
			time.Sleep(20 * time.Millisecond)
			return job
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("job %s did not finish", id)
	return nil
}

func TestRequestValidation(t *testing.T) {
	d := newTestDaemon(t)
	if _, err := call(t, d, map[string]any{"action": "bogus"}); err == nil || err.Error() != "unknown backup daemon action" {
		t.Fatalf("unknown action: %v", err)
	}
	if _, err := call(t, d, map[string]any{"action": "schedule", "z": 1, "a": 2}); err == nil || err.Error() != "unexpected request fields: a, z" {
		t.Fatalf("fields: %v", err)
	}
	if _, err := call(t, d, map[string]any{"action": "start_backup", "passphrase": "short", "include_ssh": false, "quiesce": true}); err == nil ||
		!strings.Contains(err.Error(), "at least 12 characters") {
		t.Fatalf("passphrase: %v", err)
	}
	if _, err := call(t, d, map[string]any{"action": "start_backup", "passphrase": "long enough passphrase", "include_ssh": "no", "quiesce": true}); err == nil ||
		err.Error() != "include_ssh must be true or false" {
		t.Fatalf("bool: %v", err)
	}
	if _, err := call(t, d, map[string]any{"action": "delete", "kind": "job", "id": strings.Repeat("a", 32), "confirmation": "yes"}); err == nil ||
		err.Error() != "delete confirmation must be exactly DELETE" {
		t.Fatalf("delete: %v", err)
	}
}

func TestScheduledBackupReturnsBeforeArchiveAndTracksDelivery(t *testing.T) {
	d := newTestDaemon(t)
	if err := d.setSchedulePassphrase([]byte("a stored passphrase")); err != nil {
		t.Fatal(err)
	}
	if err := d.atomicJSON(d.Opts.SchedulePath, map[string]any{
		"enabled": true, "destinations": []string{"missing"}, "quiesce": false,
	}, 0o600); err != nil {
		t.Fatal(err)
	}

	gate := make(chan struct{})
	release := true
	t.Cleanup(func() {
		if release {
			close(gate)
		}
	})
	wait := d.sleep
	d.sleep = func(duration time.Duration) {
		if duration == 2*time.Second {
			<-gate
		}
		wait(duration)
	}
	request := map[string]any{"action": "run_scheduled"}
	answers := make(chan map[string]any, 1)
	errs := make(chan error, 1)
	go func() {
		answer, err := d.Dispatch(context.Background(), request)
		answers <- answer
		errs <- err
	}()
	var started map[string]any
	select {
	case started = <-answers:
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("run_scheduled blocked while the backup worker was held")
	}
	jobID, _ := started["job_id"].(string)
	if jobID == "" || started["status"] != "queued" {
		t.Fatalf("start response: %v", started)
	}
	if _, err := call(t, d, request); err == nil || err.Error() != "a scheduled backup is already running" {
		t.Fatalf("duplicate schedule run: %v", err)
	}
	statusRequest := map[string]any{"action": "job_status", "job_id": jobID}
	job := mustCall(t, d, statusRequest)["job"].(map[string]any)
	if job["operation"] != "scheduled_backup" || !activeStatus(job["status"]) {
		t.Fatalf("job while held: %v", job)
	}
	close(gate)
	release = false
	job = waitJob(t, d, jobID)
	output, _ := job["output"].(map[string]any)
	if job["status"] != "failed" || !strings.HasPrefix(pyStr(job["error"]), "missing:") || !truthy(output["backup_id"]) {
		t.Fatalf("delivery outcome: %v", job)
	}
	if got := d.loadSchedule()["last_result"]; got != job["error"] {
		t.Errorf("last schedule result = %q, want %q", got, job["error"])
	}
}

func TestBackupInspectRestoreRoundTrip(t *testing.T) {
	d := newTestDaemon(t)
	pass := "correct horse battery staple"
	started := mustCall(t, d, map[string]any{"action": "start_backup", "passphrase": pass, "include_ssh": false, "quiesce": true})
	job := waitJob(t, d, started["job_id"].(string))
	if job["status"] != "completed" {
		t.Fatalf("backup: %v", job)
	}
	out := job["output"].(map[string]any)
	stdout := out["stdout"].(string)
	if strings.Contains(stdout, pass) || !strings.Contains(stdout, "[REDACTED]") ||
		!strings.Contains(stdout, manifestMarker+"<omitted>") || !strings.Contains(stdout, backupFileMarker+"<stored>") {
		t.Fatalf("output not sanitized: %q", stdout)
	}
	manifest := job["manifest"].(map[string]any)
	if _, leaked := manifest["unknown"]; leaked || manifest["format_version"] == nil {
		t.Fatalf("manifest: %v", manifest)
	}
	backupID := out["backup_id"].(string)
	status := mustCall(t, d, map[string]any{"action": "status"})
	backups := status["backups"].([]map[string]any)
	if len(backups) != 1 || backups[0]["id"] != backupID || backups[0]["created_at"] != "2026-11-22T10:00:00+00:00" {
		t.Fatalf("backups: %v", backups)
	}
	if status["local"].(map[string]any)["count"] != 1 || status["active_job"] != nil {
		t.Fatalf("local/active: %v", status)
	}
	raw, _ := os.ReadFile(d.backupChecksumPath(backupID))
	if !strings.HasSuffix(strings.TrimSpace(string(raw)), backupID+ArchiveSuffix) {
		t.Fatalf("checksum sidecar names the stored archive: %q", raw)
	}

	staged := mustCall(t, d, map[string]any{"action": "stage_backup", "backup_id": backupID})
	uploadID := staged["upload_id"].(string)
	inspected := mustCall(t, d, map[string]any{"action": "start_inspect", "upload_id": uploadID, "passphrase": pass})
	ijob := waitJob(t, d, inspected["job_id"].(string))
	if ijob["status"] != "completed" || ijob["output"].(map[string]any)["sha256"] != backups[0]["sha256"] {
		t.Fatalf("inspect: %v", ijob)
	}
	uploads := mustCall(t, d, map[string]any{"action": "status"})["uploads"].([]map[string]any)
	if len(uploads) != 1 || uploads[0]["staged_backup_id"] != backupID || uploads[0]["inspection_job_id"] != ijob["id"] {
		t.Fatalf("uploads: %v", uploads)
	}
	if _, err := call(t, d, map[string]any{"action": "start_restore", "upload_id": uploadID, "passphrase": pass,
		"inspection_job_id": ijob["id"], "restore_ssh": false, "confirmation": "RESTORE", "scope": "config"}); err != nil {
		t.Fatal(err)
	}
	var rjob map[string]any
	for _, j := range d.listJobs() {
		if j["operation"] == "restore" {
			rjob = waitJob(t, d, j["id"].(string))
		}
	}
	if rjob == nil || rjob["status"] != "completed" || rjob["scope"] != "config" {
		t.Fatalf("restore: %v", rjob)
	}
	if !strings.Contains(rjob["output"].(map[string]any)["stdout"].(string), "--scope config --skip-ssh") {
		t.Fatalf("restore argv: %v", rjob["output"])
	}
	// The worker removes the marker in its deferred cleanup, after the job
	// already reads completed: under -race and a loaded machine that takes
	// longer than waitJob's grace, so wait for it with a deadline.
	markerGone := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if _, err := os.Lstat(d.Opts.RestoreActiveMarker); os.IsNotExist(err) {
			markerGone = true
			break
		}
	}
	if !markerGone {
		t.Fatal("restore marker left behind")
	}
	del := mustCall(t, d, map[string]any{"action": "delete", "kind": "backup", "id": backupID, "confirmation": "DELETE"})
	if files := del["deleted"].(map[string]any)["files"].([]string); len(files) != 3 {
		t.Fatalf("delete: %v", del)
	}
}

func TestBusyAndFailedJob(t *testing.T) {
	d := newTestDaemon(t)
	lock, err := d.acquireOperation()
	if err != nil {
		t.Fatal(err)
	}
	_, err = call(t, d, map[string]any{"action": "start_backup", "passphrase": "long enough passphrase", "include_ssh": false, "quiesce": true})
	if e, ok := err.(interface{ Error() string }); !ok || e.Error() != "another backup operation is already active" {
		t.Fatalf("busy: %v", err)
	}
	d.releaseOperation(lock)
	_ = os.WriteFile(d.helper[1], []byte("echo boom >&2; exit 7\n"), 0o644)
	started := mustCall(t, d, map[string]any{"action": "start_backup", "passphrase": "long enough passphrase", "include_ssh": true, "quiesce": false})
	job := waitJob(t, d, started["job_id"].(string))
	if job["status"] != "failed" || job["error"] != "full backup helper failed: boom" || job["output"].(map[string]any)["returncode"] != float64(7) && job["output"].(map[string]any)["returncode"] != nil {
		if out, ok := job["output"].(map[string]any); !ok || pyStr(out["returncode"]) != "7" {
			t.Fatalf("failed job: %v", job)
		}
	}
}

func TestScheduleAndKeepLocal(t *testing.T) {
	d := newTestDaemon(t)
	s := mustCall(t, d, map[string]any{"action": "schedule"})["schedule"].(map[string]any)
	if s["time"] != "03:20" || s["keep_local"] != int64(3) || s["quiesce"] != true || s["enabled"] != false {
		t.Fatalf("defaults: %v", s)
	}
	if _, err := call(t, d, map[string]any{"action": "schedule_save", "enabled": true}); err == nil ||
		err.Error() != "a stored passphrase is required before the schedule can run" {
		t.Fatalf("enable without passphrase: %v", err)
	}
	if _, err := call(t, d, map[string]any{"action": "schedule_save", "keep_local": 0.0}); err == nil ||
		err.Error() != "the number of backups kept on this server must be between 1 and 50" {
		t.Fatalf("keep_local: %v", err)
	}
	out := mustCall(t, d, map[string]any{"action": "schedule_save", "passphrase": "a stored passphrase", "keep_local": "5"})
	if out["schedule"].(map[string]any)["passphrase_stored"] != true || out["schedule"].(map[string]any)["keep_local"] != int64(5) {
		t.Fatalf("save: %v", out)
	}
	if _, err := call(t, d, map[string]any{"action": "schedule_save", "passphrase": "a replacement passphrase", "time": "29:00"}); err == nil {
		t.Fatal("invalid schedule was accepted")
	}
	if raw, err := os.ReadFile(d.Opts.SchedulePassphrase); err != nil || string(raw) != "a stored passphrase" {
		t.Fatal("invalid schedule changed the stored passphrase")
	}
	if r := mustCall(t, d, map[string]any{"action": "run_scheduled"}); r["skipped"] != "the schedule is off" {
		t.Fatalf("skip: %v", r)
	}
	if _, err := call(t, d, map[string]any{"action": "run_scheduled", "on_demand": true}); err == nil ||
		err.Error() != "choose at least one destination before running it" {
		t.Fatalf("on demand: %v", err)
	}
}

func TestRemoteHelpers(t *testing.T) {
	for in, want := range map[string]string{"": ".", "./": ".", "/": "/", "a//b/./c/": "a/b/c", "/srv//x": "/srv/x"} {
		got, err := normalizeRemoteDir(in)
		if err != nil || got != want {
			t.Fatalf("normalize %q: %q %v", in, got, err)
		}
	}
	if _, err := normalizeRemoteDir("a/../b"); err == nil {
		t.Fatal("dotdot accepted")
	}
	if q, _ := remoteQuote(`a "b"\c`); q != `"a \"b\"\\c"` {
		t.Fatalf("quote: %s", q)
	}
	if shlexQuote("a b'c") != `'a b'"'"'c'` || shlexQuote("plain/path.enc") != "plain/path.enc" {
		t.Fatal("shlex")
	}
	if s3Quote("a b/ü~", true) != "a%20b/%C3%BC~" || s3Quote("a/b", false) != "a%2Fb" {
		t.Fatal("s3 quote")
	}
}

// testdata/python_vectors.json was produced by backupd/destinations.py
// (s3_authorization and retention_victims) so the port is held to it.
func TestPythonVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/python_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Put, Get string
		Names    []string
		Victims  []string
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	put := s3Authorization("PUT", "/bk/gw/easy-ha-proxy-20261122-031000-x.tar.gz.enc", "",
		map[string]string{"host": "s3.example.com:9000", "x-amz-content-sha256": strings.Repeat("a", 64), "x-amz-date": "20261122T031000Z"},
		strings.Repeat("a", 64), "AKIA1", "s3cr3t", "eu-1", "20261122T031000Z")
	get := s3Authorization("GET", "/bk", "list-type=2&prefix=gw%2F",
		map[string]string{"host": "s3.example.com", "x-amz-content-sha256": "e3b0", "x-amz-date": "20261122T031000Z"},
		"e3b0", "AKIA1", "s3cr3t", "us-east-1", "20261122T031000Z")
	if put != v.Put || get != v.Get {
		t.Fatalf("sigv4 differs:\n%s\n%s", put, get)
	}
	got := retentionVictims(v.Names, map[string]any{"keep_daily": 7.0, "keep_weekly": 4.0, "keep_monthly": 6.0})
	if strings.Join(got, ",") != strings.Join(v.Victims, ",") {
		t.Fatalf("retention differs: got %d victims, python %d", len(got), len(v.Victims))
	}
}

func TestCopyRecoverySourceKeepsGitAndSkipsPycache(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "source")
	spool := filepath.Join(root, "spool")
	for _, rel := range []string{
		"install-local.sh",
		"installer/easy-ha-proxy",
		"installer/agent-fetch.sh",
		"installer/__pycache__/easy_ha_proxy.cpython-312.pyc",
		"installer/leftover.pyc",
		"ansible/easy-ha-proxy.yml",
		"ansible/requirements.yml",
		".git/HEAD",
		".git/refs/heads/alpha",
	} {
		p := filepath.Join(src, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("content-"+rel), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(spool, "jobs"), 0o750); err != nil {
		t.Fatal(err)
	}
	d := NewDaemon(Options{SpoolRoot: spool, SourceDir: src})

	dst, err := d.copyRecoverySource(strings.Repeat("a", 32))
	if err != nil {
		t.Fatalf("copyRecoverySource: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, ".git/HEAD")); err != nil {
		t.Fatalf("expected .git/HEAD in recovery source: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, ".git/refs/heads/alpha")); err != nil {
		t.Fatalf("expected .git/refs/heads/alpha in recovery source: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "installer/__pycache__")); !os.IsNotExist(err) {
		t.Fatalf("expected __pycache__ to be skipped, got err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "installer/leftover.pyc")); !os.IsNotExist(err) {
		t.Fatalf("expected .pyc to be skipped, got err=%v", err)
	}
}
