package backupd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

func (d *Daemon) uploadPath(uploadID string) (string, error) {
	id, err := identifier(uploadID, "upload id")
	if err != nil {
		return "", err
	}
	return filepath.Join(d.Opts.UploadsDir(), id+ArchiveSuffix), nil
}

func (d *Daemon) backupArchivePath(id string) string {
	return filepath.Join(d.Opts.BackupsDir(), id+ArchiveSuffix)
}

func (d *Daemon) backupChecksumPath(id string) string {
	return filepath.Join(d.Opts.BackupsDir(), id+ChecksumSuffix)
}

func (d *Daemon) backupMetaPath(id string) string {
	return filepath.Join(d.Opts.BackupsDir(), id+MetaSuffix)
}

func (d *Daemon) stageRecordPath(uploadID string) string {
	return filepath.Join(d.Opts.JobsDir(), stageRecordPrefix+uploadID+stageRecordSuffix)
}

// safeRegularFile is safe_regular_file. expectedUID < 0 means any owner.
func safeRegularFile(path string, expectedUID int, maximum int64) (statInfo, error) {
	info, err := lstatInfo(path)
	if err != nil {
		return info, err
	}
	name := filepath.Base(path)
	if !info.Mode.IsRegular() || info.Nlink != 1 || (expectedUID >= 0 && info.UID != expectedUID) || info.Size <= 0 {
		return info, bErr("invalid", "unsafe or unsupported file: %s", name)
	}
	if info.Size > maximum {
		return info, bErr("too_large", "file exceeds the configured size limit: %s", name)
	}
	return info, nil
}

func sha256File(path string) (string, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|oNoFollow, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// copyUploadToJob makes the immutable per-job copy a helper reads.
func (d *Daemon) copyUploadToJob(uploadID, jobID string) (string, string, int64, error) {
	source, before, expected, err := d.resolveUploadSource(uploadID)
	if err != nil {
		return "", "", 0, err
	}
	destination := filepath.Join(d.Opts.JobsDir(), "."+jobID+uploadCopySufx)
	src, err := os.OpenFile(source, os.O_RDONLY|oNoFollow, 0)
	if err != nil {
		return "", "", 0, err
	}
	defer src.Close()
	fail := func(e error) (string, string, int64, error) {
		_ = os.Remove(destination)
		return "", "", 0, e
	}
	dst, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL|oNoFollow, 0o600)
	if err != nil {
		return "", "", 0, err
	}
	defer dst.Close()
	opened, err := fstatInfo(src)
	if err != nil {
		return fail(err)
	}
	if opened.Dev != before.Dev || opened.Ino != before.Ino {
		return fail(bErr("invalid", "upload changed while it was being opened"))
	}
	h := sha256.New()
	buf := make([]byte, 1024*1024)
	var copied int64
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			copied += int64(n)
			if copied > d.Opts.MaxArchiveBytes {
				return fail(bErr("too_large", "uploaded archive exceeds the configured limit"))
			}
			h.Write(buf[:n])
			if _, err := dst.Write(buf[:n]); err != nil {
				return fail(err)
			}
		}
		if rerr == io.EOF || n == 0 {
			break
		}
		if rerr != nil {
			return fail(rerr)
		}
	}
	after, err := fstatInfo(src)
	if err != nil {
		return fail(err)
	}
	if after.Dev != before.Dev || after.Ino != before.Ino || after.Size != before.Size ||
		after.MtimeNs != before.MtimeNs || copied != before.Size {
		return fail(bErr("invalid", "upload changed while it was being copied"))
	}
	if err := setOwnerFd(dst, 0, 0); err != nil {
		return fail(err)
	}
	_ = dst.Chmod(0o600)
	if err := dst.Sync(); err != nil {
		return fail(err)
	}
	actual := hex.EncodeToString(h.Sum(nil))
	if expected != "" && actual != expected {
		return fail(bErr("conflict", "staged server backup no longer matches its checksum"))
	}
	return destination, actual, copied, nil
}

func cleanupJobUpload(path string) {
	if path == "" {
		return
	}
	_ = os.Remove(path)
	_ = os.Remove(path + ".sha256")
}

func ensureFreeSpace(path string, required int64) error {
	anchor := path
	if _, err := os.Stat(anchor); err != nil {
		anchor = filepath.Dir(path)
	}
	usage, err := statDisk(anchor)
	if err != nil {
		return err
	}
	if usage.Free < required {
		return bErr("insufficient_space", "insufficient free space: %d bytes available, %d required", usage.Free, required)
	}
	return nil
}

func sanitizeManifest(value any) (map[string]any, error) {
	obj, ok := value.(map[string]any)
	if !ok {
		return nil, bErr("invalid", "backup manifest is not a JSON object")
	}
	result := map[string]any{}
	for _, key := range manifestKeys {
		item := obj[key]
		switch x := item.(type) {
		case nil, bool, float64, json.Number:
			result[key] = x
		case string:
			result[key] = truncRunes(x, 1024)
		}
	}
	if result["format"] != "easy-ha-proxy-full-backup" {
		return nil, bErr("invalid", "unsupported full-backup manifest")
	}
	for _, key := range []string{"payload_expanded_bytes", "ssh_payload_expanded_bytes"} {
		size := result[key]
		if size == nil {
			continue
		}
		n, ok := strictInt(size)
		if _, isBool := size.(bool); isBool || !ok || n < 0 {
			return nil, bErr("invalid", "backup manifest field is invalid: %s", key)
		}
	}
	return result, nil
}

func restoreExpandedBytes(manifest map[string]any, restoreSSH bool) (int64, error) {
	core, ok := strictInt(manifest["payload_expanded_bytes"])
	if !ok || core < 0 {
		return 0, bErr("conflict", "repeat archive inspection to calculate restore disk requirements")
	}
	var ssh int64
	if restoreSSH && manifest["ssh_included"] == true {
		v, ok := strictInt(manifest["ssh_payload_expanded_bytes"])
		if !ok || v < 0 {
			return 0, bErr("conflict", "repeat archive inspection to calculate SSH restore disk requirements")
		}
		ssh = v
	}
	total := core + ssh
	if total > 65*1024*1024*1024 {
		return 0, bErr("too_large", "expanded backup exceeds the supported restore limit")
	}
	return total, nil
}

func splitLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	lines := strings.Split(s, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

func (d *Daemon) markerValue(output, marker string) (string, error) {
	lines := splitLines(output)
	label := strings.TrimSuffix(marker, "=")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.HasPrefix(lines[i], marker) {
			value := strings.TrimSpace(lines[i][len(marker):])
			if value == "" || len(value) > d.Opts.MaxStateBytes {
				return "", bErr("invalid", "invalid %s marker", label)
			}
			return value, nil
		}
	}
	return "", bErr("invalid", "backup helper did not return %s", label)
}

func (d *Daemon) manifestFromOutput(output string) (map[string]any, error) {
	raw, err := d.markerValue(output, manifestMarker)
	if err != nil {
		return nil, err
	}
	parsed, err := decodeJSON([]byte(raw))
	if err != nil {
		return nil, bErr("invalid", "backup helper returned invalid manifest JSON")
	}
	return sanitizeManifest(parsed)
}

// sanitizeOutput redacts the passphrase and the marker lines, drops control
// characters and keeps the last MAX_CAPTURE_BYTES.
func (d *Daemon) sanitizeOutput(value, passphrase string) string {
	if passphrase != "" {
		value = strings.ReplaceAll(value, passphrase, "[REDACTED]")
	}
	lines := splitLines(value)
	clean := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.HasPrefix(line, manifestMarker) {
			line = manifestMarker + "<omitted>"
		} else if strings.HasPrefix(line, backupFileMarker) {
			line = backupFileMarker + "<stored>"
		}
		var b strings.Builder
		for _, r := range line {
			if r == '\t' || r >= 32 {
				b.WriteRune(r)
			}
		}
		clean = append(clean, b.String())
	}
	result := strings.Join(clean, "\n")
	if len(result) > d.Opts.MaxCaptureBytes {
		tail := result[len(result)-d.Opts.MaxCaptureBytes:]
		result = "[output truncated]\n" + strings.ToValidUTF8(tail, "�")
	}
	return result
}

func readPathTail(path string, limit int64) string {
	f, err := os.OpenFile(path, os.O_RDONLY|oNoFollow, 0)
	if err != nil {
		return ""
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() <= 0 {
		return ""
	}
	offset := info.Size() - limit
	if offset < 0 {
		offset = 0
	}
	buf := make([]byte, info.Size()-offset)
	n, _ := f.ReadAt(buf, offset)
	return strings.ToValidUTF8(string(buf[:n]), "�")
}

func childEnvironment(recoverySource string) []string {
	lang := os.Getenv("LANG")
	if _, ok := os.LookupEnv("LANG"); !ok {
		lang = "C.UTF-8"
	}
	lcAll := os.Getenv("LC_ALL")
	if _, ok := os.LookupEnv("LC_ALL"); !ok {
		lcAll = "C.UTF-8"
	}
	env := []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG=" + lang,
		"LC_ALL=" + lcAll,
		"PYTHONUNBUFFERED=1",
		"EASY_HA_PROXY_OFFLINE_RESTORE=1",
		"EASY_HA_PROXY_MAINTENANCE_LOCK_HELD=backupd",
	}
	if recoverySource != "" {
		env = append(env, "EASY_HA_PROXY_SOURCE_DIR="+recoverySource)
	}
	return env
}

// transientJobsSupported: privileged children escape the broker's sandbox
// through PID 1 when running as root under systemd.
func (d *Daemon) transientJobsSupported() bool {
	if geteuid() != 0 {
		return false
	}
	if fi, err := os.Stat("/run/systemd/system"); err != nil || !fi.IsDir() {
		return false
	}
	fi, err := os.Stat(systemdRunPath)
	return err == nil && fi.Mode()&0o111 != 0
}

func systemctlProperties(unit string, names []string) map[string]string {
	args := []string{"show", unit}
	for _, n := range names {
		args = append(args, "--property="+n)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, systemctlPath, args...).Output()
	props := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			props[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return props
}

func stopTransientUnit(unit string) {
	for _, args := range [][]string{{"stop", unit}, {"reset-failed", unit}} {
		ctx, cancel := context.WithTimeout(context.Background(), (transientStopSecs+15)*time.Second)
		if err := exec.CommandContext(ctx, systemctlPath, args...).Run(); err != nil && ctx.Err() != nil {
			log.Printf("Could not clean up transient unit %s", unit)
		}
		cancel()
	}
}

func privateFile(path string, content []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|oNoFollow, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(content); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

type helperResult struct {
	returncode             int
	rawStdout, rawStderr   string
	safeStdout, safeStderr string
}

func (d *Daemon) publishLive(jobID, stdout, stderr, passphrase string) {
	if jobID == "" {
		return
	}
	if _, err := d.updateJob(jobID, map[string]any{"output": map[string]any{
		"stdout": d.sanitizeOutput(stdout, passphrase),
		"stderr": d.sanitizeOutput(stderr, passphrase),
		"live":   true,
	}}); err != nil {
		log.Printf("Skipping one live progress publish for job %s", jobID)
	}
}

func (d *Daemon) tailLimit() int64 {
	limit := int64(d.Opts.MaxCaptureBytes * 4)
	if int64(d.Opts.MaxStateBytes) > limit {
		limit = int64(d.Opts.MaxStateBytes)
	}
	return limit
}

// runTransientHelper runs the helper as a systemd-run transient unit, the
// passphrase fed from a root-only file on the runtime tmpfs.
func (d *Daemon) runTransientHelper(argv []string, passphrase, jobID, recoverySource string) (helperResult, error) {
	token := randomHex(6)
	unit := "easy-ha-proxy-backupd-job-" + token + ".service"
	stdoutPath := filepath.Join(d.Opts.JobsDir(), ".job-"+token+".stdout")
	stderrPath := filepath.Join(d.Opts.JobsDir(), ".job-"+token+".stderr")
	stdinPath := filepath.Join(filepath.Dir(d.Opts.SocketPath), ".job-"+token+".stdin")
	defer func() {
		stopTransientUnit(unit)
		_ = os.Remove(stdinPath)
		_ = os.Remove(stdoutPath)
		_ = os.Remove(stderrPath)
	}()
	for _, p := range []struct {
		path string
		body []byte
	}{{stdoutPath, nil}, {stderrPath, nil}, {stdinPath, []byte(passphrase + "\n")}} {
		if err := privateFile(p.path, p.body); err != nil {
			return helperResult{}, err
		}
	}
	command := []string{
		"--quiet", "--no-block", "--unit", unit, "--service-type=oneshot",
		"-p", "RemainAfterExit=yes",
		"-p", "StandardInput=file:" + stdinPath,
		"-p", "StandardOutput=append:" + stdoutPath,
		"-p", "StandardError=append:" + stderrPath,
		"-p", "KillMode=control-group",
		"-p", fmt.Sprintf("TimeoutStopSec=%d", transientStopSecs),
	}
	for _, kv := range childEnvironment(recoverySource) {
		command = append(command, "--setenv="+kv)
	}
	command = append(command, "--")
	command = append(command, argv...)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	cmd := exec.CommandContext(ctx, systemdRunPath, command...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err := cmd.Run()
	cancel()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			detail := strings.TrimSpace(stderr.String())
			msg := "could not start the privileged backup job"
			if detail != "" {
				msg += ": " + detail
			}
			return helperResult{}, bErr("invalid", "%s", msg)
		}
		return helperResult{}, bErr("invalid", "could not start the privileged backup job: %v", err)
	}
	begun := time.Now()
	var lastPublish time.Time
	returncode := 0
	limit := int64(d.Opts.MaxCaptureBytes / 2)
	for {
		props := systemctlProperties(unit, []string{"LoadState", "ActiveState", "SubState", "ExecMainStatus"})
		active := props["ActiveState"]
		if props["LoadState"] == "not-found" {
			returncode = 0
			break
		}
		if active == "failed" {
			rc, err := strconv.Atoi(props["ExecMainStatus"])
			if err != nil || props["ExecMainStatus"] == "" {
				rc = 1
			}
			if rc == 0 {
				rc = 1
			}
			returncode = rc
			break
		}
		if active == "active" && props["SubState"] == "exited" {
			rc, err := strconv.Atoi(props["ExecMainStatus"])
			if err != nil {
				rc = 0
			}
			returncode = rc
			break
		}
		if time.Since(begun) > time.Duration(d.Opts.JobTimeoutSeconds)*time.Second {
			return helperResult{}, bErr("invalid", "backup job exceeded the configured timeout")
		}
		if jobID != "" && time.Since(lastPublish) >= 2*time.Second {
			d.publishLive(jobID, readPathTail(stdoutPath, limit), readPathTail(stderrPath, limit), passphrase)
			lastPublish = time.Now()
		}
		d.sleep(500 * time.Millisecond)
	}
	rawOut := readPathTail(stdoutPath, d.tailLimit())
	rawErr := readPathTail(stderrPath, d.tailLimit())
	return helperResult{returncode, rawOut, rawErr, d.sanitizeOutput(rawOut, passphrase), d.sanitizeOutput(rawErr, passphrase)}, nil
}

// runDirectHelper is the unprivileged fallback: the helper in its own session.
func (d *Daemon) runDirectHelper(argv []string, passphrase, jobID, recoverySource string) (helperResult, error) {
	outFile, err := os.CreateTemp("", "backupd-out-")
	if err != nil {
		return helperResult{}, err
	}
	defer func() { _ = outFile.Close(); _ = os.Remove(outFile.Name()) }()
	errFile, err := os.CreateTemp("", "backupd-err-")
	if err != nil {
		return helperResult{}, err
	}
	defer func() { _ = errFile.Close(); _ = os.Remove(errFile.Name()) }()
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = childEnvironment(recoverySource)
	cmd.Stdout = outFile
	cmd.Stderr = errFile
	cmd.Stdin = strings.NewReader(passphrase + "\n")
	cmd.SysProcAttr = newSessionAttr()
	if err := cmd.Start(); err != nil {
		return helperResult{}, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	deadline := time.Now().Add(time.Duration(d.Opts.JobTimeoutSeconds) * time.Second)
	var lastPublish time.Time
	limit := int64(d.Opts.MaxCaptureBytes / 2)
	returncode := 0
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
wait:
	for {
		select {
		case werr := <-done:
			returncode = exitCode(werr)
			killGroup(cmd.Process.Pid, syscall.SIGKILL)
			break wait
		case <-ticker.C:
		}
		if time.Now().After(deadline) {
			killGroup(cmd.Process.Pid, syscall.SIGTERM)
			select {
			case <-done:
			case <-time.After(30 * time.Second):
				killGroup(cmd.Process.Pid, syscall.SIGKILL)
				<-done
			}
			return helperResult{}, bErr("invalid", "backup job exceeded the configured timeout")
		}
		if jobID != "" && time.Since(lastPublish) >= 2*time.Second {
			d.publishLive(jobID, readPathTail(outFile.Name(), limit), readPathTail(errFile.Name(), limit), passphrase)
			lastPublish = time.Now()
		}
	}
	rawOut := readPathTail(outFile.Name(), d.tailLimit())
	rawErr := readPathTail(errFile.Name(), d.tailLimit())
	return helperResult{returncode, rawOut, rawErr, d.sanitizeOutput(rawOut, passphrase), d.sanitizeOutput(rawErr, passphrase)}, nil
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return -int(ws.Signal())
		}
		return exitErr.ExitCode()
	}
	return 1
}

func (d *Daemon) runHelper(argv []string, passphrase, jobID, recoverySource string) (helperResult, error) {
	if d.transient() {
		return d.runTransientHelper(argv, passphrase, jobID, recoverySource)
	}
	return d.runDirectHelper(argv, passphrase, jobID, recoverySource)
}

func (d *Daemon) helperScript() (string, error) {
	script := filepath.Join(d.Opts.SourceDir, "installer", "full_backup.py")
	fi, err := os.Lstat(script)
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", bErr("invalid", "the managed full-backup helper is unavailable")
	}
	return script, nil
}

func (d *Daemon) rebootScheduled() bool {
	for _, p := range []string{d.Opts.RebootMarker, d.Opts.AssistantRebootMarker} {
		if _, err := os.Lstat(p); err == nil {
			return true
		}
	}
	return false
}

// acquireOperation is acquire_operation: the in-process lock, then the flock
// shared with updated and the CLI.
func (d *Daemon) acquireOperation() (*os.File, error) {
	if d.shuttingDown() {
		return nil, bErr("conflict", "backup daemon is shutting down")
	}
	if d.rebootScheduled() {
		return nil, bErr("conflict", "a server reboot is scheduled")
	}
	deadline := time.Now().Add(time.Second)
	for !d.opMu.TryLock() {
		if time.Now().After(deadline) {
			return nil, bErr("busy", "another backup operation is already active")
		}
		time.Sleep(20 * time.Millisecond)
	}
	f, err := os.OpenFile(d.Opts.OperationLockPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err == nil {
		err = flockExclusive(f)
		if err != nil {
			_ = f.Close()
		}
	}
	if err != nil {
		d.opMu.Unlock()
		if d.shuttingDown() {
			d.requestStop()
		}
		return nil, bErr("busy", "another backup operation is already active")
	}
	if d.shuttingDown() {
		d.releaseOperation(f)
		return nil, bErr("conflict", "backup daemon is shutting down")
	}
	if d.rebootScheduled() {
		d.releaseOperation(f)
		return nil, bErr("conflict", "a server reboot is scheduled")
	}
	return f, nil
}

func (d *Daemon) releaseOperation(f *os.File) {
	if f != nil {
		flockRelease(f)
		_ = f.Close()
	}
	d.opMu.Unlock()
	if d.shuttingDown() {
		d.requestStop()
	}
}

func resultOutput(returncode int, stdout, stderr string, extra map[string]any) map[string]any {
	out := map[string]any{"returncode": returncode, "stdout": stdout, "stderr": stderr}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func (d *Daemon) finishFailed(jobID string, err error, returncode int, stdout, stderr string) {
	message := err.Error()
	if message == "" {
		message = fmt.Sprintf("%T", err)
	}
	lines := splitLines(stderr)
	detail := ""
	for i := len(lines) - 1; i >= 0; i-- {
		if s := strings.TrimSpace(lines[i]); s != "" {
			detail = s
			break
		}
	}
	if detail != "" && !strings.Contains(message, detail) {
		message = message + ": " + detail
	}
	message = truncRunes(message, 4096)
	if returncode == 0 {
		returncode = 1
	}
	_, _ = d.updateJob(jobID, map[string]any{
		"status": "failed", "completed_at": utcNow(),
		"output": resultOutput(returncode, stdout, stderr, nil), "error": message,
	})
	log.Printf("Job %s failed: %s", jobID, message)
	operation := ""
	if job, err := d.loadJob(jobID, false); err == nil {
		operation = pyStr(job["operation"])
	}
	rule := "backup.failed"
	if operation == "restore" {
		rule = "restore.failed"
	}
	label := operation
	if label == "" {
		label = "backup"
	}
	d.reportAlert(rule, jobID, fmt.Sprintf("The %s job failed", label), message)
}

// insideDir is Path.resolve().relative_to(work).
func insideDir(candidate, dir string) bool {
	rc, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		rc = filepath.Clean(candidate)
	}
	rd, err := filepath.EvalSymlinks(dir)
	if err != nil {
		rd = filepath.Clean(dir)
	}
	rel, err := filepath.Rel(rd, rc)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func (d *Daemon) storeBackupArtifact(jobID, rawStdout string, manifest map[string]any, workDir string) (map[string]any, error) {
	marker, err := d.markerValue(rawStdout, backupFileMarker)
	if err != nil {
		return nil, err
	}
	if !filepath.IsAbs(marker) {
		return nil, bErr("invalid", "backup helper returned a relative archive path")
	}
	if !insideDir(marker, workDir) {
		return nil, bErr("invalid", "backup helper returned an archive outside its work area")
	}
	info, err := safeRegularFile(marker, d.rootUID, d.Opts.MaxArchiveBytes)
	if err != nil {
		return nil, err
	}
	checksumSource := marker + ".sha256"
	checksumInfo, err := safeRegularFile(checksumSource, d.rootUID, 64*1024)
	if err != nil {
		return nil, err
	}
	checksum, err := sha256File(marker)
	if err != nil {
		return nil, err
	}
	expected, err := readChecksumFile(checksumSource, checksumInfo)
	if err != nil {
		return nil, err
	}
	if expected != checksum {
		return nil, bErr("invalid", "backup helper checksum does not match the encrypted archive")
	}
	backupID := uuidHex()
	destination := d.backupArchivePath(backupID)
	checksumDestination := d.backupChecksumPath(backupID)
	metadataPath := d.backupMetaPath(backupID)
	checksumTemporary := filepath.Join(d.Opts.BackupsDir(), "."+filepath.Base(checksumDestination)+".tmp")
	created := pyStr(manifest["created_at"])
	if created == "" {
		created = utcNow()
	}
	metadata := map[string]any{
		"id": backupID, "archive_name": filepath.Base(destination),
		"checksum_name": filepath.Base(checksumDestination), "size_bytes": info.Size,
		"created_at": created, "sha256": checksum, "manifest": manifest, "job_id": jobID,
	}
	store := func() error {
		if err := os.Rename(marker, destination); err != nil {
			return err
		}
		if err := os.Rename(checksumSource, checksumDestination); err != nil {
			return err
		}
		if err := setOwner(destination, 0, d.Opts.AppGroupGID); err != nil {
			return err
		}
		if err := os.Chmod(destination, 0o640); err != nil {
			return err
		}
		f, err := os.OpenFile(checksumTemporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|oNoFollow, 0o600)
		if err != nil {
			return err
		}
		_, werr := fmt.Fprintf(f, "%s  %s\n", checksum, filepath.Base(destination))
		if werr == nil {
			werr = setOwnerFd(f, 0, d.Opts.AppGroupGID)
		}
		if werr == nil {
			werr = f.Chmod(0o640)
		}
		if werr == nil {
			werr = f.Sync()
		}
		_ = f.Close()
		if werr != nil {
			return werr
		}
		if err := os.Rename(checksumTemporary, checksumDestination); err != nil {
			return err
		}
		if err := d.atomicJSON(metadataPath, metadata, 0o640); err != nil {
			return err
		}
		return fsyncDirectory(d.Opts.BackupsDir())
	}
	if err := store(); err != nil {
		for _, p := range []string{destination, checksumDestination, checksumTemporary, metadataPath} {
			_ = os.Remove(p)
		}
		_ = fsyncDirectory(d.Opts.BackupsDir())
		return nil, err
	}
	return publicBackup(metadata), nil
}

func publicBackup(v map[string]any) map[string]any {
	var manifest any
	if m, ok := v["manifest"].(map[string]any); ok {
		manifest = m
	}
	return map[string]any{
		"id": pyStr(v["id"]), "archive_name": pyStr(v["archive_name"]),
		"checksum_name": pyStr(v["checksum_name"]), "size_bytes": intOr(v["size_bytes"], 0),
		"created_at": v["created_at"], "sha256": pyStr(v["sha256"]), "manifest": manifest,
	}
}

// allBackups is every valid archive on this server, newest first.
func (d *Daemon) allBackups() []map[string]any {
	matches, _ := filepath.Glob(filepath.Join(d.Opts.BackupsDir(), "*"+MetaSuffix))
	backups := []map[string]any{}
	for _, path := range matches {
		backupID := strings.TrimSuffix(filepath.Base(path), MetaSuffix)
		if !identifierRe.MatchString(backupID) {
			continue
		}
		check := func() (map[string]any, error) {
			metadata, err := d.safeJSONFile(path)
			if err != nil {
				return nil, err
			}
			if metadata["id"] != backupID {
				return nil, bErr("invalid", "backup metadata identifier does not match")
			}
			archiveInfo, err := safeRegularFile(d.backupArchivePath(backupID), d.rootUID, d.Opts.MaxArchiveBytes)
			if err != nil {
				return nil, err
			}
			if _, err := safeRegularFile(d.backupChecksumPath(backupID), d.rootUID, 64*1024); err != nil {
				return nil, err
			}
			if archiveInfo.Size != intOr(metadata["size_bytes"], -1) {
				return nil, bErr("invalid", "backup size does not match metadata")
			}
			if !sha256Re.MatchString(pyStr(metadata["sha256"])) {
				return nil, bErr("invalid", "backup metadata checksum is invalid")
			}
			return publicBackup(metadata), nil
		}
		item, err := check()
		if err != nil {
			log.Printf("Ignoring unsafe backup metadata %s", filepath.Base(path))
			continue
		}
		backups = append(backups, item)
	}
	sortByCreatedDesc(backups)
	return backups
}

func (d *Daemon) localStorage(backups []map[string]any) map[string]any {
	if backups == nil {
		backups = d.allBackups()
	}
	anchor := d.Opts.BackupsDir()
	for {
		if _, err := os.Stat(anchor); err == nil || filepath.Dir(anchor) == anchor {
			break
		}
		anchor = filepath.Dir(anchor)
	}
	usage, _ := statDisk(anchor)
	threshold := int64(float64(usage.Total) * lowSpaceFraction)
	if d.Opts.LowSpaceBytes < threshold {
		threshold = d.Opts.LowSpaceBytes
	}
	if 2*d.Opts.MinFreeBytes > threshold {
		threshold = 2 * d.Opts.MinFreeBytes
	}
	var total int64
	for _, b := range backups {
		total += intOr(b["size_bytes"], 0)
	}
	return map[string]any{
		"count": len(backups), "bytes": total, "free_bytes": usage.Free,
		"filesystem_bytes": usage.Total, "low_space_bytes": threshold, "low": usage.Free < threshold,
	}
}

func (d *Daemon) stagedBackupIDs() map[string]bool {
	staged := map[string]bool{}
	matches, _ := filepath.Glob(filepath.Join(d.Opts.JobsDir(), stageRecordPrefix+"*"+stageRecordSuffix))
	for _, path := range matches {
		if rec, err := d.safeJSONFile(path); err == nil {
			if id := pyStr(rec["backup_id"]); identifierRe.MatchString(id) {
				staged[id] = true
			}
		}
	}
	return staged
}

func (d *Daemon) removeBackupFiles(backupID string) ([]string, error) {
	paths := []struct {
		path string
		max  int64
	}{
		{d.backupArchivePath(backupID), d.Opts.MaxArchiveBytes},
		{d.backupChecksumPath(backupID), 64 * 1024},
		{d.backupMetaPath(backupID), int64(d.Opts.MaxStateBytes)},
	}
	for _, p := range paths {
		if _, err := safeRegularFile(p.path, d.rootUID, p.max); err != nil {
			return nil, err
		}
	}
	deleted := []string{}
	for _, p := range paths {
		if err := os.Remove(p.path); err != nil {
			return deleted, err
		}
		deleted = append(deleted, filepath.Base(p.path))
	}
	return deleted, nil
}

func (d *Daemon) pruneLocalBackups(keep int) []string {
	staged := d.stagedBackupIDs()
	removed := []string{}
	if keep < 1 {
		keep = 1
	}
	all := d.allBackups()
	if len(all) <= keep {
		return removed
	}
	for _, backup := range all[keep:] {
		id := backup["id"].(string)
		if staged[id] {
			continue
		}
		if _, err := d.removeBackupFiles(id); err != nil {
			log.Printf("Could not remove old local backup %s: %v", id, err)
			continue
		}
		removed = append(removed, id)
	}
	return removed
}

func readChecksumFile(path string, info statInfo) (string, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|oNoFollow, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	opened, err := fstatInfo(f)
	if err != nil {
		return "", err
	}
	if opened.Dev != info.Dev || opened.Ino != info.Ino {
		return "", bErr("invalid", "backup checksum changed while it was being opened")
	}
	raw := make([]byte, 64*1024+1)
	n, _ := readFull(f, raw)
	if n > 64*1024 {
		return "", bErr("too_large", "backup checksum file is too large")
	}
	text := string(raw[:n])
	for _, r := range text {
		if r > 127 {
			return "", bErr("invalid", "backup checksum file is invalid")
		}
	}
	if !utf8.ValidString(text) {
		return "", bErr("invalid", "backup checksum file is invalid")
	}
	fields := strings.Fields(text)
	if len(fields) == 0 || !sha256Re.MatchString(fields[0]) {
		return "", bErr("invalid", "backup checksum file is invalid")
	}
	return fields[0], nil
}

func (d *Daemon) verifiedBackupFiles(backupID string, verifyContent bool) (string, statInfo, string, error) {
	archive := d.backupArchivePath(backupID)
	checksumPath := d.backupChecksumPath(backupID)
	archiveInfo, err := safeRegularFile(archive, d.rootUID, d.Opts.MaxArchiveBytes)
	if err != nil {
		return "", statInfo{}, "", err
	}
	checksumInfo, err := safeRegularFile(checksumPath, d.rootUID, 64*1024)
	if err != nil {
		return "", statInfo{}, "", err
	}
	metadata, err := d.safeJSONFile(d.backupMetaPath(backupID))
	if err != nil {
		return "", statInfo{}, "", err
	}
	if metadata["id"] != backupID || metadata["archive_name"] != filepath.Base(archive) ||
		metadata["checksum_name"] != filepath.Base(checksumPath) ||
		intOr(metadata["size_bytes"], -1) != archiveInfo.Size {
		return "", statInfo{}, "", bErr("invalid", "backup metadata does not match its files")
	}
	if _, err := sanitizeManifest(metadata["manifest"]); err != nil {
		return "", statInfo{}, "", err
	}
	expected := pyStr(metadata["sha256"])
	if !sha256Re.MatchString(expected) {
		return "", statInfo{}, "", bErr("invalid", "backup metadata checksum is invalid")
	}
	sidecar, err := readChecksumFile(checksumPath, checksumInfo)
	if err != nil {
		return "", statInfo{}, "", err
	}
	if sidecar != expected {
		return "", statInfo{}, "", bErr("invalid", "backup checksum sidecar does not match metadata")
	}
	if verifyContent {
		actual, err := sha256File(archive)
		if err != nil {
			return "", statInfo{}, "", err
		}
		if actual != expected {
			return "", statInfo{}, "", bErr("invalid", "backup archive checksum verification failed")
		}
	}
	return archive, archiveInfo, expected, nil
}
