package backupd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/unixrpc"
)

const (
	backupTimerUnit     = "easy-ha-proxy-backup.timer"
	defaultScheduleTime = "03:20"
	defaultKeepLocal    = 3
)

var scheduleTimeRe = regexp.MustCompile(`^([01][0-9]|2[0-3]):([0-5][0-9])$`)

func scheduleTime(value any, def string) (string, error) {
	text := strings.TrimSpace(pyStr(value))
	if text == "" {
		return def, nil
	}
	if !scheduleTimeRe.MatchString(text) {
		return "", bErr("invalid", "the time must be given as HH:MM on a 24-hour clock")
	}
	return text, nil
}

func (d *Daemon) writeTimerTime(value string) error {
	if err := os.MkdirAll(d.Opts.TimerDropinDir, 0o755); err != nil {
		return err
	}
	if err := os.Chmod(d.Opts.TimerDropinDir, 0o755); err != nil {
		return err
	}
	body := strings.Join([]string{
		"# Written by easy-ha-proxy-backupd from the Backups page.",
		"# The empty OnCalendar clears the packaged one; without it",
		"# systemd would keep both and run the backup twice.",
		"[Timer]",
		"OnCalendar=",
		"OnCalendar=*-*-* " + value + ":00",
		"",
	}, "\n")
	target := d.Opts.TimerDropinPath()
	temporary := strings.TrimSuffix(target, ".conf") + ".conf.tmp"
	if err := os.WriteFile(temporary, []byte(body), 0o644); err != nil {
		return err
	}
	if err := os.Chmod(temporary, 0o644); err != nil {
		return err
	}
	if err := os.Rename(temporary, target); err != nil {
		return err
	}
	for _, args := range [][]string{{"daemon-reload"}, {"restart", backupTimerUnit}} {
		rc, _, errb, err := runCapture(60*time.Second, []byte{}, nil, systemctlPath, args...)
		if err != nil || rc != 0 {
			detail := strings.TrimSpace(string(errb))
			if err != nil && detail == "" {
				detail = err.Error()
			}
			return bErr("invalid", "the schedule was saved but the timer could not be updated: %s", truncRunes(detail, 200))
		}
	}
	d.timerMu.Lock()
	d.timerAt = time.Time{}
	d.timerValue = nil
	d.timerMu.Unlock()
	return nil
}

func timerNextRun() string {
	props := systemctlProperties(backupTimerUnit, []string{"NextElapseUSecRealtime", "ActiveState"})
	if props["ActiveState"] != "active" {
		return ""
	}
	return props["NextElapseUSecRealtime"]
}

func (d *Daemon) keepLocalValue(value any, def int64) (int64, error) {
	if value == nil || value == "" {
		return def, nil
	}
	var number int64
	if n, ok := strictInt(value); ok {
		if _, isBool := value.(bool); isBool {
			return 0, bErr("invalid", "the number of backups kept on this server must be a whole number")
		}
		number = n
	} else if s, isStr := value.(string); isStr && isDigits(strings.TrimSpace(s)) {
		number, _ = strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	} else {
		return 0, bErr("invalid", "the number of backups kept on this server must be a whole number")
	}
	if number < 1 || number > int64(d.Opts.ListLimit) {
		return 0, bErr("invalid", "the number of backups kept on this server must be between 1 and %d", d.Opts.ListLimit)
	}
	return number, nil
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func isRegularFile(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}

func (d *Daemon) loadSchedule() map[string]any {
	record, err := d.safeJSONFile(d.Opts.SchedulePath)
	if err != nil {
		record = map[string]any{}
	}
	destinations := []string{}
	for _, item := range anyList(record["destinations"]) {
		if s, ok := item.(string); ok {
			destinations = append(destinations, s)
		}
	}
	quiesce := true
	if v, ok := record["quiesce"]; ok && v == false {
		quiesce = false
	}
	t, err := scheduleTime(record["time"], defaultScheduleTime)
	if err != nil {
		t = defaultScheduleTime
	}
	keep, err := d.keepLocalValue(record["keep_local"], defaultKeepLocal)
	if err != nil {
		keep = defaultKeepLocal
	}
	return map[string]any{
		"enabled":           truthy(record["enabled"]),
		"destinations":      destinations,
		"include_ssh":       truthy(record["include_ssh"]),
		"quiesce":           quiesce,
		"passphrase_stored": isRegularFile(d.Opts.SchedulePassphrase),
		"last_run":          getOr(record, "last_run", ""),
		"last_result":       getOr(record, "last_result", ""),
		"time":              t,
		"next_run":          timerNextRun(),
		"keep_local":        keep,
	}
}

func (d *Daemon) scheduleTimerMetadata() map[string]any {
	copyMap := func(m map[string]any) map[string]any {
		out := map[string]any{}
		for k, v := range m {
			out[k] = v
		}
		return out
	}
	if !d.timerMu.TryLock() {
		return map[string]any{}
	}
	defer d.timerMu.Unlock()
	if !d.timerAt.IsZero() && time.Since(d.timerAt) < 30*time.Second {
		return copyMap(d.timerValue)
	}
	value := backupTimers(runTimerCommand, time.Now())
	d.timerAt = time.Now()
	d.timerValue = value
	return copyMap(value)
}

func (d *Daemon) scheduleStatus() map[string]any {
	schedule := d.loadSchedule()
	for k, v := range d.scheduleTimerMetadata() {
		schedule[k] = v
	}
	return map[string]any{"ok": true, "schedule": schedule}
}

func (d *Daemon) saveSchedule(req map[string]any) (map[string]any, error) {
	current := d.loadSchedule()
	names, present := req["destinations"]
	var list []any
	if !present || names == nil {
		for _, n := range current["destinations"].([]string) {
			list = append(list, n)
		}
	} else {
		l, ok := names.([]any)
		if !ok {
			return nil, bErr("invalid", "destinations must be a list")
		}
		list = l
	}
	chosen := []string{}
	for _, item := range list {
		name := strings.ToLower(strings.TrimSpace(pyStr(item)))
		if _, err := d.loadDestination(name); err != nil {
			return nil, err
		}
		chosen = append(chosen, name)
	}
	passphrase := req["passphrase"]
	if s, ok := passphrase.(string); ok && s != "" {
		p, err := requirePassphrase(s)
		if err != nil {
			return nil, err
		}
		if err := writePrivate(d.Opts.SchedulePassphrase, []byte(p)); err != nil {
			return nil, err
		}
	} else if passphrase == "" {
		_ = os.Remove(d.Opts.SchedulePassphrase)
	}
	enabled := current["enabled"].(bool)
	if v, ok := req["enabled"]; ok && v != nil {
		enabled = truthy(v)
	}
	if enabled && !isRegularFile(d.Opts.SchedulePassphrase) {
		return nil, bErr("invalid", "a stored passphrase is required before the schedule can run")
	}
	if enabled && len(chosen) == 0 {
		return nil, bErr("invalid", "choose at least one destination before enabling the schedule")
	}
	currentTime := current["time"].(string)
	wantedTime, err := scheduleTime(req["time"], currentTime)
	if err != nil {
		return nil, err
	}
	includeSSH := current["include_ssh"].(bool)
	if v, ok := req["include_ssh"]; ok {
		includeSSH = truthy(v)
	}
	quiesce := current["quiesce"].(bool)
	if v, ok := req["quiesce"]; ok {
		quiesce = v != false
	}
	keep, err := d.keepLocalValue(req["keep_local"], current["keep_local"].(int64))
	if err != nil {
		return nil, err
	}
	record := map[string]any{
		"enabled": enabled, "destinations": chosen, "include_ssh": includeSSH, "quiesce": quiesce,
		"last_run": current["last_run"], "last_result": current["last_result"],
		"time": wantedTime, "keep_local": keep,
	}
	if err := d.atomicJSON(d.Opts.SchedulePath, record, 0o600); err != nil {
		return nil, err
	}
	if wantedTime != currentTime {
		if err := d.writeTimerTime(wantedTime); err != nil {
			return nil, err
		}
	}
	return map[string]any{"ok": true, "schedule": d.loadSchedule()}, nil
}

func (d *Daemon) recordScheduleOutcome(result string) {
	record, err := d.safeJSONFile(d.Opts.SchedulePath)
	if err != nil {
		record = map[string]any{}
	}
	record["last_run"] = utcNow()
	record["last_result"] = truncRunes(result, 500)
	_ = d.atomicJSON(d.Opts.SchedulePath, record, 0o600)
}

// runScheduledBackup makes a backup and sends it away, inline: the timer
// wants an exit code.
func (d *Daemon) runScheduledBackup(req map[string]any) (map[string]any, error) {
	schedule := d.loadSchedule()
	onDemand := truthy(req["on_demand"])
	destinations := schedule["destinations"].([]string)
	if !schedule["enabled"].(bool) && !onDemand {
		return map[string]any{"ok": true, "skipped": "the schedule is off"}, nil
	}
	if onDemand && len(destinations) == 0 {
		return nil, bErr("invalid", "choose at least one destination before running it")
	}
	if !schedule["passphrase_stored"].(bool) {
		d.recordScheduleOutcome("no stored passphrase")
		return nil, bErr("invalid", "no stored passphrase")
	}
	raw, err := os.ReadFile(d.Opts.SchedulePassphrase)
	if err != nil {
		return nil, err
	}
	started, err := d.startBackup(map[string]any{
		"action": "start_backup", "passphrase": strings.TrimSpace(string(raw)),
		"include_ssh": schedule["include_ssh"], "quiesce": schedule["quiesce"],
	})
	if err != nil {
		return nil, err
	}
	jobID := started["job_id"].(string)
	deadline := time.Now().Add(time.Duration(d.Opts.ScheduledTimeoutSeconds) * time.Second)
	state := map[string]any{}
	for time.Now().Before(deadline) {
		d.sleep(5 * time.Second)
		if job, err := d.loadJob(jobID, false); err == nil {
			state = job
		} else {
			var be *Error
			if !errors.As(err, &be) {
				return nil, err
			}
		}
		if terminalStatus(state["status"]) {
			break
		}
	}
	if state["status"] != "completed" {
		d.recordScheduleOutcome(fmt.Sprintf("the backup did not complete: %s", pyNone(state["status"])))
		d.reportAlert("backup.failed", jobID, "The scheduled backup did not complete", truncRunes(pyStr(state["error"]), 500))
		return map[string]any{"ok": false, "job_id": jobID, "error": "the backup did not complete"}, nil
	}
	backupID := ""
	if out, ok := state["output"].(map[string]any); ok {
		backupID = pyStr(out["backup_id"])
	}
	uploads := []map[string]any{}
	failures := []string{}
	for _, name := range destinations {
		outcome, err := d.uploadBackup(map[string]any{"action": "upload", "backup_id": backupID, "destination": name})
		if err != nil {
			var be *Error
			if !errors.As(err, &be) {
				return nil, err
			}
			failures = append(failures, name+": "+be.Msg)
			continue
		}
		uploads = append(uploads, outcome)
		if !truthy(outcome["ok"]) {
			failures = append(failures, fmt.Sprintf("%s: %s", name, pyNone(outcome["error"])))
		}
	}
	pruned := []string{}
	if len(uploads) > 0 && len(failures) == 0 {
		lock, err := d.acquireOperation()
		if err != nil {
			log.Printf("Local retention skipped this run: %v", err)
		} else {
			pruned = d.pruneLocalBackups(int(schedule["keep_local"].(int64)))
			d.releaseOperation(lock)
		}
	}
	outcome := fmt.Sprintf("copied to %d destination(s)", len(uploads))
	if len(failures) > 0 {
		outcome = strings.Join(failures, "; ")
	}
	if len(pruned) > 0 {
		outcome += fmt.Sprintf("; removed %d older local backup(s)", len(pruned))
	}
	d.recordScheduleOutcome(outcome)
	storage := d.localStorage(nil)
	if storage["low"].(bool) {
		d.reportAlert("backup.space_low", "local", "Backup storage is running out of space",
			fmt.Sprintf("%v bytes free, below %v; %v local backup(s) use %v bytes",
				storage["free_bytes"], storage["low_space_bytes"], storage["count"], storage["bytes"]))
	}
	return map[string]any{
		"ok": len(failures) == 0, "job_id": jobID, "backup_id": backupID, "uploads": uploads,
		"errors": failures, "pruned": pruned, "local": storage,
	}, nil
}

// pyNone renders a value with str(): a missing one is "None".
func pyNone(v any) string {
	if v == nil {
		return "None"
	}
	if s, ok := v.(string); ok {
		return s
	}
	return pyStr(v)
}

// Dispatch is dispatch() plus handle_connection's exception mapping.
func (d *Daemon) Dispatch(_ context.Context, req map[string]any) (resp map[string]any, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Unhandled backup daemon request error: %v", r)
			resp, err = nil, unixrpc.NewError("internal", "internal backup daemon error")
		}
		if err != nil {
			err = mapError(err)
		}
	}()
	action, _ := req["action"].(string)
	allowed, ok := RequestFields[action]
	if !ok {
		return nil, bErr("invalid", "unknown backup daemon action")
	}
	unexpected := []string{}
	for k := range req {
		if _, ok := allowed[k]; !ok {
			unexpected = append(unexpected, k)
		}
	}
	if len(unexpected) > 0 {
		sort.Strings(unexpected)
		return nil, bErr("invalid", "unexpected request fields: %s", strings.Join(unexpected, ", "))
	}
	switch action {
	case "status":
		return d.statusResponse(req)
	case "stage_backup":
		return d.stageBackup(req)
	case "start_backup":
		return d.startBackup(req)
	case "start_inspect":
		return d.startInspect(req)
	case "start_restore":
		return d.startRestore(req)
	case "destinations":
		return d.listDestinations()
	case "destination_save":
		return d.saveDestination(req)
	case "destination_delete":
		return d.deleteDestination(req)
	case "destination_test":
		return d.testDestination(req)
	case "destination_retrust":
		return d.retrustDestination(req)
	case "upload":
		return d.uploadBackup(req)
	case "schedule":
		return d.scheduleStatus(), nil
	case "schedule_save":
		return d.saveSchedule(req)
	case "run_scheduled":
		return d.runScheduledBackup(req)
	}
	return d.deleteItem(req)
}

func mapError(err error) error {
	var be *Error
	if errors.As(err, &be) {
		return unixrpc.NewError(be.Code, truncRunes(be.Msg, 4096))
	}
	var re *unixrpc.Error
	if errors.As(err, &re) {
		return re
	}
	msg := truncRunes(pyOSError(err), 4096)
	var errno syscall.Errno
	switch {
	case errors.Is(err, os.ErrNotExist):
		return unixrpc.NewError("not_found", msg)
	case errors.As(err, &errno):
		switch errno {
		case syscall.ENOSPC, syscall.Errno(122): // EDQUOT
			return unixrpc.NewError("insufficient_space", msg)
		case syscall.EEXIST, syscall.EBUSY:
			return unixrpc.NewError("conflict", msg)
		case syscall.EFBIG:
			return unixrpc.NewError("too_large", msg)
		}
		return unixrpc.NewError("internal", msg)
	}
	var se *json.SyntaxError
	if errors.As(err, &se) {
		return unixrpc.NewError("invalid", msg)
	}
	var ee *exec.Error
	if errors.As(err, &ee) {
		return unixrpc.NewError("internal", msg)
	}
	log.Printf("Unhandled backup daemon request error: %v", err)
	return unixrpc.NewError("internal", "internal backup daemon error")
}

// Run is serve(): layout, recovery, then the socket until a stop.
func Run(opts Options) error {
	d := NewDaemon(opts)
	if err := d.ensureLayout(); err != nil {
		return fmt.Errorf("cannot start backup daemon: %w", err)
	}
	d.recoverStaleJobs()
	d.cleanupStaleWorkerArtifacts()
	d.expireOrphanedUploads()

	signals := make(chan os.Signal, 2)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		for range signals {
			d.requestShutdown()
			if d.opMu.TryLock() {
				d.opMu.Unlock()
				d.requestStop()
			}
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-d.stop
		cancel()
	}()
	srv := unixrpc.NewServer(d.Opts.AppUID, d.Opts.MaxRequestBytes, 16*1024*1024, d.Opts.MaxConnections, d.Dispatch)
	srv.SocketUser = strconv.Itoa(d.Opts.AppUID)
	srv.SocketGroup = strconv.Itoa(d.Opts.AppPrimaryGID)
	log.Printf("Listening on %s", d.Opts.SocketPath)
	return srv.ListenAndServe(ctx, d.Opts.SocketPath, 0o600)
}
