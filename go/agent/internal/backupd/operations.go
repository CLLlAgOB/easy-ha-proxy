package backupd

import (
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// loadStageRecord returns nil (no error) when the upload is not a staged
// server backup.
func (d *Daemon) loadStageRecord(uploadID string) (map[string]any, string, statInfo, string, error) {
	path := d.stageRecordPath(uploadID)
	record, err := d.safeJSONFile(path)
	if err != nil {
		if isNotExist(err) {
			return nil, "", statInfo{}, "", nil
		}
		return nil, "", statInfo{}, "", err
	}
	backupID, err := identifier(record["backup_id"], "staged backup id")
	if err != nil {
		return nil, "", statInfo{}, "", err
	}
	if record["upload_id"] != uploadID {
		return nil, "", statInfo{}, "", bErr("invalid", "staged backup record identifier does not match")
	}
	archive, info, expected, err := d.verifiedBackupFiles(backupID, false)
	if err != nil {
		return nil, "", statInfo{}, "", err
	}
	if record["sha256"] != expected || intOr(record["size_bytes"], -1) != info.Size {
		return nil, "", statInfo{}, "", bErr("conflict", "staged backup record no longer matches the server backup")
	}
	return record, archive, info, expected, nil
}

// resolveUploadSource returns the file an upload id names and, for a staged
// server backup, the checksum it must still have.
func (d *Daemon) resolveUploadSource(uploadID string) (string, statInfo, string, error) {
	record, archive, info, expected, err := d.loadStageRecord(uploadID)
	if err != nil {
		return "", statInfo{}, "", err
	}
	if record != nil {
		return archive, info, expected, nil
	}
	source, err := d.uploadPath(uploadID)
	if err != nil {
		return "", statInfo{}, "", err
	}
	info, err = safeRegularFile(source, d.Opts.AppUID, d.Opts.MaxArchiveBytes)
	if err != nil {
		if isNotExist(err) {
			return "", statInfo{}, "", bErr("not_found", "uploaded archive was not found")
		}
		return "", statInfo{}, "", err
	}
	return source, info, "", nil
}

func (d *Daemon) stageBackup(req map[string]any) (map[string]any, error) {
	backupID, err := identifier(req["backup_id"], "backup id")
	if err != nil {
		return nil, err
	}
	lock, err := d.acquireOperation()
	if err != nil {
		return nil, err
	}
	defer d.releaseOperation(lock)
	_, info, expected, err := d.verifiedBackupFiles(backupID, false)
	if err != nil {
		return nil, err
	}
	uploadID := uuidHex()
	for {
		if _, err := os.Lstat(d.stageRecordPath(uploadID)); err != nil {
			break
		}
		uploadID = uuidHex()
	}
	if err := d.atomicJSON(d.stageRecordPath(uploadID), map[string]any{
		"upload_id": uploadID, "backup_id": backupID, "sha256": expected,
		"size_bytes": info.Size, "created_at": utcNow(),
	}, 0o640); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "upload_id": uploadID, "size": info.Size}, nil
}

func (d *Daemon) successfulInspections() map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, job := range d.listJobs() {
		_, hasOutput := job["output"].(map[string]any)
		uploadID, isStr := job["upload_id"].(string)
		if job["operation"] == "inspect" && job["status"] == "completed" && hasOutput && isStr {
			if _, seen := out[uploadID]; !seen {
				out[uploadID] = job
			}
		}
	}
	return out
}

func (d *Daemon) expireOrphanedUploads() {
	if !d.opMu.TryLock() {
		return
	}
	defer func() {
		d.opMu.Unlock()
		if d.shuttingDown() {
			d.requestStop()
		}
	}()
	cutoff := time.Now().Add(-time.Duration(d.Opts.UploadTTLSeconds) * time.Second).UnixNano()
	parts, _ := filepath.Glob(filepath.Join(d.Opts.UploadsDir(), ".*.part"))
	for _, path := range parts {
		name := filepath.Base(path)
		uploadID := strings.TrimSuffix(name[1:], ".part")
		if !identifierRe.MatchString(uploadID) {
			continue
		}
		info, err := lstatInfo(path)
		if err != nil {
			continue
		}
		if info.Mode.IsRegular() && info.Nlink == 1 && info.UID == d.Opts.AppUID && info.MtimeNs < cutoff {
			if os.Remove(path) == nil {
				log.Printf("Expired interrupted upload %s", uploadID)
			}
		}
	}
	archives, _ := filepath.Glob(filepath.Join(d.Opts.UploadsDir(), "*"+ArchiveSuffix))
	for _, path := range archives {
		uploadID := strings.TrimSuffix(filepath.Base(path), ArchiveSuffix)
		if !identifierRe.MatchString(uploadID) {
			continue
		}
		info, err := safeRegularFile(path, d.Opts.AppUID, d.Opts.MaxArchiveBytes)
		if err != nil {
			if !isNotExist(err) {
				log.Printf("Could not safely expire upload %s", filepath.Base(path))
			}
			continue
		}
		if info.MtimeNs < cutoff && os.Remove(path) == nil {
			log.Printf("Expired orphaned upload %s", uploadID)
		}
	}
	stages, _ := filepath.Glob(filepath.Join(d.Opts.JobsDir(), stageRecordPrefix+"*"+stageRecordSuffix))
	for _, path := range stages {
		name := filepath.Base(path)
		uploadID := strings.TrimSuffix(strings.TrimPrefix(name, stageRecordPrefix), stageRecordSuffix)
		if !identifierRe.MatchString(uploadID) {
			continue
		}
		info, err := lstatInfo(path)
		if err != nil {
			continue
		}
		if _, err := d.safeJSONFile(path); err != nil {
			log.Printf("Could not safely expire stage record %s", name)
			continue
		}
		if info.MtimeNs < cutoff && os.Remove(path) == nil {
			log.Printf("Expired staged server backup %s", uploadID)
		}
	}
}

func (d *Daemon) listUploads() []map[string]any {
	inspections := d.successfulInspections()
	uploads := []map[string]any{}
	describe := func(uploadID string) (any, any, any) {
		inspection, ok := inspections[uploadID]
		if !ok {
			return nil, nil, nil
		}
		var sha any
		if out, ok := inspection["output"].(map[string]any); ok {
			sha = out["sha256"]
		}
		return sha, inspection["manifest"], inspection["id"]
	}
	archives, _ := filepath.Glob(filepath.Join(d.Opts.UploadsDir(), "*"+ArchiveSuffix))
	for _, path := range archives {
		uploadID := strings.TrimSuffix(filepath.Base(path), ArchiveSuffix)
		if !identifierRe.MatchString(uploadID) {
			continue
		}
		info, err := safeRegularFile(path, d.Opts.AppUID, d.Opts.MaxArchiveBytes)
		if err != nil {
			continue
		}
		sha, manifest, jobID := describe(uploadID)
		uploads = append(uploads, map[string]any{
			"id": uploadID, "archive_name": filepath.Base(path), "size_bytes": info.Size,
			"created_at": pyISO(time.Unix(0, info.MtimeNs)), "sha256": sha,
			"manifest": manifest, "inspection_job_id": jobID,
		})
	}
	stages, _ := filepath.Glob(filepath.Join(d.Opts.JobsDir(), stageRecordPrefix+"*"+stageRecordSuffix))
	for _, path := range stages {
		name := filepath.Base(path)
		uploadID := strings.TrimSuffix(strings.TrimPrefix(name, stageRecordPrefix), stageRecordSuffix)
		if !identifierRe.MatchString(uploadID) {
			continue
		}
		record, _, info, _, err := d.loadStageRecord(uploadID)
		if err != nil {
			log.Printf("Ignoring unsafe staged server backup %s", name)
			continue
		}
		if record == nil {
			continue
		}
		kept := uploads[:0]
		for _, item := range uploads {
			if item["id"] != uploadID {
				kept = append(kept, item)
			}
		}
		uploads = kept
		sha, manifest, jobID := describe(uploadID)
		uploads = append(uploads, map[string]any{
			"id": uploadID, "archive_name": uploadID + ArchiveSuffix, "size_bytes": info.Size,
			"created_at": record["created_at"], "sha256": sha, "manifest": manifest,
			"inspection_job_id": jobID, "staged_backup_id": record["backup_id"],
		})
	}
	sortByCreatedDesc(uploads)
	if len(uploads) > d.Opts.ListLimit {
		uploads = uploads[:d.Opts.ListLimit]
	}
	return uploads
}

func (d *Daemon) helperArgv(args ...string) ([]string, error) {
	command, err := d.helperCommand()
	if err != nil {
		return nil, err
	}
	return append(command, args...), nil
}

func (d *Daemon) backupWorker(jobID, passphrase string, includeSSH, quiesce bool, lock *os.File) {
	workDir := filepath.Join(d.Opts.BackupsDir(), ".work-"+jobID)
	var safeOut, safeErr string
	returncode := 0
	defer func() {
		_ = os.RemoveAll(workDir)
		d.releaseOperation(lock)
	}()
	fail := func(err error) { d.finishFailed(jobID, err, returncode, safeOut, safeErr) }
	d.sleep(2 * time.Second)
	if _, err := d.updateJob(jobID, map[string]any{"status": "running", "started_at": utcNow()}); err != nil {
		fail(err)
		return
	}
	if err := ensureFreeSpace(d.Opts.BackupsDir(), d.Opts.MinFreeBytes); err != nil {
		fail(err)
		return
	}
	if err := os.Mkdir(workDir, 0o700); err != nil {
		fail(err)
		return
	}
	args := []string{"backup", "--output-dir", workDir, "--passphrase-stdin"}
	if includeSSH {
		args = append(args, "--include-ssh")
	}
	if !quiesce {
		args = append(args, "--no-quiesce")
	}
	argv, err := d.helperArgv(args...)
	if err != nil {
		fail(err)
		return
	}
	res, err := d.runHelper(argv, passphrase, jobID, "")
	if err != nil {
		fail(err)
		return
	}
	returncode, safeOut, safeErr = res.returncode, res.safeStdout, res.safeStderr
	if returncode != 0 {
		fail(bErr("invalid", "full backup helper failed"))
		return
	}
	manifest, err := d.manifestFromOutput(res.rawStdout)
	if err != nil {
		// Older format-v1 helpers only print the archive path; inspect it.
		marker, merr := d.markerValue(res.rawStdout, backupFileMarker)
		if merr != nil {
			fail(merr)
			return
		}
		if !insideDir(marker, workDir) {
			fail(bErr("invalid", "backup helper returned an archive outside its work area"))
			return
		}
		if _, err := safeRegularFile(marker, d.rootUID, d.Opts.MaxArchiveBytes); err != nil {
			fail(err)
			return
		}
		inspectArgv, err := d.helperArgv("inspect", marker, "--passphrase-stdin")
		if err != nil {
			fail(err)
			return
		}
		ires, err := d.runHelper(inspectArgv, passphrase, jobID, "")
		if err != nil {
			fail(err)
			return
		}
		safeOut = d.sanitizeOutput(res.rawStdout+"\n"+ires.rawStdout, passphrase)
		safeErr = d.sanitizeOutput(res.rawStderr+"\n"+ires.rawStderr, passphrase)
		if ires.returncode != 0 {
			returncode = ires.returncode
			fail(bErr("invalid", "new full backup failed its manifest inspection"))
			return
		}
		manifest, err = d.manifestFromOutput(ires.rawStdout)
		if err != nil {
			fail(err)
			return
		}
	}
	artifact, err := d.storeBackupArtifact(jobID, res.rawStdout, manifest, workDir)
	if err != nil {
		fail(err)
		return
	}
	if _, err := d.updateJob(jobID, map[string]any{
		"status": "completed", "completed_at": utcNow(), "manifest": manifest, "error": nil,
		"output": resultOutput(returncode, safeOut, safeErr, map[string]any{
			"backup_id": artifact["id"], "archive_name": artifact["archive_name"],
			"checksum_name": artifact["checksum_name"], "size_bytes": artifact["size_bytes"],
			"sha256": artifact["sha256"],
		}),
	}); err != nil {
		fail(err)
	}
}

func (d *Daemon) inspectWorker(jobID, uploadID, passphrase string, lock *os.File) {
	staged := ""
	var safeOut, safeErr string
	returncode := 0
	defer func() {
		cleanupJobUpload(staged)
		d.releaseOperation(lock)
	}()
	fail := func(err error) { d.finishFailed(jobID, err, returncode, safeOut, safeErr) }
	if _, err := d.updateJob(jobID, map[string]any{"status": "running", "started_at": utcNow()}); err != nil {
		fail(err)
		return
	}
	_, info, _, err := d.resolveUploadSource(uploadID)
	if err != nil {
		fail(err)
		return
	}
	need := info.Size*2 + d.Opts.MinFreeBytes
	for _, dir := range []string{d.Opts.JobsDir(), os.TempDir()} {
		if err := ensureFreeSpace(dir, need); err != nil {
			fail(err)
			return
		}
	}
	path, checksum, size, err := d.copyUploadToJob(uploadID, jobID)
	if err != nil {
		fail(err)
		return
	}
	staged = path
	argv, err := d.helperArgv("inspect", staged, "--passphrase-stdin")
	if err != nil {
		fail(err)
		return
	}
	res, err := d.runHelper(argv, passphrase, jobID, "")
	if err != nil {
		fail(err)
		return
	}
	returncode, safeOut, safeErr = res.returncode, res.safeStdout, res.safeStderr
	if returncode != 0 {
		fail(bErr("invalid", "full backup inspection failed"))
		return
	}
	manifest, err := d.manifestFromOutput(res.rawStdout)
	if err != nil {
		fail(err)
		return
	}
	if _, err := d.updateJob(jobID, map[string]any{
		"status": "completed", "completed_at": utcNow(), "manifest": manifest, "error": nil,
		"output": resultOutput(returncode, safeOut, safeErr, map[string]any{"sha256": checksum, "size_bytes": size}),
	}); err != nil {
		fail(err)
	}
}

// copyRecoverySource copies the managed source so a restore that replaces it
// keeps running from a stable tree.
func (d *Daemon) copyRecoverySource(jobID string) (string, error) {
	for _, rel := range []string{"install-local.sh", "installer/easy_ha_proxy.py",
		"ansible/easy-ha-proxy.yml", "ansible/requirements.yml"} {
		fi, err := os.Stat(filepath.Join(d.Opts.SourceDir, rel))
		if err != nil || !fi.Mode().IsRegular() {
			return "", bErr("invalid", "managed recovery source is incomplete")
		}
	}
	destination := filepath.Join(d.Opts.JobsDir(), "."+jobID+".recovery-source")
	if _, err := os.Lstat(destination); err == nil {
		return "", bErr("conflict", "recovery source copy already exists")
	}
	err := filepath.WalkDir(d.Opts.SourceDir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(d.Opts.SourceDir, path)
		name := entry.Name()
		if path != d.Opts.SourceDir && (name == ".git" || name == "__pycache__" || strings.HasSuffix(name, ".pyc")) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		target := filepath.Join(destination, rel)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			if err := os.Symlink(link, target); err != nil {
				return err
			}
		case info.IsDir():
			if err := os.Mkdir(target, info.Mode().Perm()); err != nil {
				return err
			}
			_ = os.Chmod(target, info.Mode().Perm())
		case info.Mode().IsRegular():
			if err := copyFile(path, target, info.Mode().Perm()); err != nil {
				return err
			}
			_ = os.Chtimes(target, info.ModTime(), info.ModTime())
		default:
			return nil
		}
		return setOwner(target, 0, 0)
	})
	if err != nil {
		_ = os.RemoveAll(destination)
		return "", err
	}
	return destination, nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := out.ReadFrom(in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chmod(dst, mode)
}

func (d *Daemon) requestSelfRestartIfNeeded() {
	fi, err := os.Stat(d.Opts.RestartRequestMarker)
	if err != nil || !fi.Mode().IsRegular() {
		return
	}
	d.requestShutdown()
	if err := os.Remove(d.Opts.RestartRequestMarker); err != nil {
		return
	}
	cmd := exec.Command("/bin/systemctl", "restart", "--no-block", d.Opts.ServiceName)
	cmd.Env = childEnvironment("")
	cmd.SysProcAttr = newSessionAttr()
	if err := cmd.Start(); err != nil {
		log.Printf("Could not request a deferred backup daemon restart: %v", err)
		return
	}
	go func() { _ = cmd.Wait() }()
}

func (d *Daemon) restoreWorker(jobID, uploadID, expectedSHA string, manifest map[string]any, passphrase string,
	restoreSSH bool, scope string, lock *os.File) {
	staged, recovery := "", ""
	var safeOut, safeErr string
	returncode := 0
	defer func() {
		cleanupJobUpload(staged)
		if recovery != "" {
			_ = os.RemoveAll(recovery)
		}
		_ = os.Remove(d.Opts.RestoreActiveMarker)
		d.requestSelfRestartIfNeeded()
		d.releaseOperation(lock)
	}()
	fail := func(err error) { d.finishFailed(jobID, err, returncode, safeOut, safeErr) }
	d.sleep(2 * time.Second)
	if _, err := d.updateJob(jobID, map[string]any{"status": "running", "started_at": utcNow()}); err != nil {
		fail(err)
		return
	}
	_, info, _, err := d.resolveUploadSource(uploadID)
	if err != nil {
		fail(err)
		return
	}
	if _, err := restoreExpandedBytes(manifest, restoreSSH); err != nil {
		fail(err)
		return
	}
	need := info.Size*2 + d.Opts.MinFreeBytes
	for _, check := range []struct {
		dir  string
		need int64
	}{{d.Opts.JobsDir(), need}, {os.TempDir(), need}, {"/", d.Opts.MinFreeBytes}} {
		if err := ensureFreeSpace(check.dir, check.need); err != nil {
			fail(err)
			return
		}
	}
	path, checksum, size, err := d.copyUploadToJob(uploadID, jobID)
	if err != nil {
		fail(err)
		return
	}
	staged = path
	if checksum != expectedSHA {
		fail(bErr("invalid", "uploaded archive changed after the successful inspection"))
		return
	}
	sidecar := staged + ".sha256"
	if err := os.WriteFile(sidecar, []byte(fmt.Sprintf("%s  %s\n", checksum, filepath.Base(staged))), 0o600); err != nil {
		fail(err)
		return
	}
	_ = os.Chmod(sidecar, 0o600)
	if err := setOwner(sidecar, 0, 0); err != nil {
		fail(err)
		return
	}
	recovery, err = d.copyRecoverySource(jobID)
	if err != nil {
		recovery = ""
		fail(err)
		return
	}
	// The installed agent restores; the recovery copy of the source is what
	// it puts back over the source the archive brings.
	argv, err := d.helperArgv("restore", staged, "--mode", "overlay", "--apply", "--yes", "--passphrase-stdin")
	if err != nil {
		fail(err)
		return
	}
	if scope == "config" {
		argv = append(argv, "--scope", "config", "--skip-ssh")
	} else {
		argv = append(argv, "--replace-managed")
		if restoreSSH {
			argv = append(argv, "--restore-ssh")
		} else {
			argv = append(argv, "--skip-ssh")
		}
	}
	res, err := d.runHelper(argv, passphrase, jobID, recovery)
	if err != nil {
		fail(err)
		return
	}
	returncode, safeOut, safeErr = res.returncode, res.safeStdout, res.safeStderr
	if returncode != 0 {
		fail(bErr("invalid", "full backup restore failed"))
		return
	}
	if _, err := d.updateJob(jobID, map[string]any{
		"status": "completed", "completed_at": utcNow(), "manifest": manifest, "error": nil,
		"output": resultOutput(returncode, safeOut, safeErr, map[string]any{"sha256": checksum, "size_bytes": size}),
	}); err != nil {
		fail(err)
	}
}

func (d *Daemon) startBackup(req map[string]any) (map[string]any, error) {
	passphrase, err := requirePassphrase(req["passphrase"])
	if err != nil {
		return nil, err
	}
	includeSSH, err := requireBool(req["include_ssh"], "include_ssh")
	if err != nil {
		return nil, err
	}
	quiesce, err := requireBool(req["quiesce"], "quiesce")
	if err != nil {
		return nil, err
	}
	lock, err := d.acquireOperation()
	if err != nil {
		return nil, err
	}
	job, err := d.newJob("backup", nil)
	if err != nil {
		d.releaseOperation(lock)
		return nil, err
	}
	go d.backupWorker(job["id"].(string), passphrase, includeSSH, quiesce, lock)
	return map[string]any{"ok": true, "job_id": job["id"]}, nil
}

func (d *Daemon) startInspect(req map[string]any) (map[string]any, error) {
	uploadID, err := identifier(req["upload_id"], "upload id")
	if err != nil {
		return nil, err
	}
	passphrase, err := requirePassphrase(req["passphrase"])
	if err != nil {
		return nil, err
	}
	lock, err := d.acquireOperation()
	if err != nil {
		return nil, err
	}
	if _, _, _, err := d.resolveUploadSource(uploadID); err != nil {
		d.releaseOperation(lock)
		return nil, err
	}
	job, err := d.newJob("inspect", uploadID)
	if err != nil {
		d.releaseOperation(lock)
		return nil, err
	}
	go d.inspectWorker(job["id"].(string), uploadID, passphrase, lock)
	return map[string]any{"ok": true, "job_id": job["id"]}, nil
}

func (d *Daemon) startRestore(req map[string]any) (map[string]any, error) {
	uploadID, err := identifier(req["upload_id"], "upload id")
	if err != nil {
		return nil, err
	}
	inspectionJobID, err := identifier(req["inspection_job_id"], "inspection job id")
	if err != nil {
		return nil, err
	}
	passphrase, err := requirePassphrase(req["passphrase"])
	if err != nil {
		return nil, err
	}
	restoreSSH, err := requireBool(req["restore_ssh"], "restore_ssh")
	if err != nil {
		return nil, err
	}
	scopeValue, present := req["scope"]
	if !present {
		scopeValue = "full"
	}
	scope, _ := scopeValue.(string)
	if scope != "full" && scope != "config" {
		return nil, bErr("invalid", "restore scope must be full or config")
	}
	if scope == "config" && restoreSSH {
		return nil, bErr("invalid", "SSH keys are not part of a configuration-scope restore")
	}
	if req["confirmation"] != "RESTORE" {
		return nil, bErr("invalid", "restore confirmation must be exactly RESTORE")
	}
	lock, err := d.acquireOperation()
	if err != nil {
		return nil, err
	}
	markerCreated := false
	abort := func(e error) (map[string]any, error) {
		if markerCreated {
			_ = os.Remove(d.Opts.RestoreActiveMarker)
		}
		d.releaseOperation(lock)
		return nil, e
	}
	if _, _, _, err := d.resolveUploadSource(uploadID); err != nil {
		return abort(err)
	}
	inspection, err := d.loadJob(inspectionJobID, true)
	if err != nil {
		return abort(err)
	}
	output, outOK := inspection["output"].(map[string]any)
	manifest, manOK := inspection["manifest"].(map[string]any)
	if inspection["operation"] != "inspect" || inspection["status"] != "completed" ||
		inspection["upload_id"] != uploadID || !outOK || !sha256Re.MatchString(pyStr(output["sha256"])) || !manOK {
		return abort(bErr("conflict", "restore requires a successful inspection of the same uploaded archive"))
	}
	if _, err := restoreExpandedBytes(manifest, restoreSSH); err != nil {
		return abort(err)
	}
	f, err := os.OpenFile(d.Opts.RestoreActiveMarker, os.O_WRONLY|os.O_CREATE|os.O_EXCL|oNoFollow, 0o600)
	if err != nil {
		return abort(err)
	}
	_, werr := f.WriteString(inspectionJobID + "\n")
	if werr == nil {
		werr = f.Sync()
	}
	_ = f.Close()
	markerCreated = true
	if werr != nil {
		return abort(werr)
	}
	job, err := d.newJob("restore", uploadID)
	if err != nil {
		return abort(err)
	}
	jobID := job["id"].(string)
	if _, err := d.updateJob(jobID, map[string]any{"manifest": manifest, "scope": scope}); err != nil {
		return abort(err)
	}
	go d.restoreWorker(jobID, uploadID, pyStr(output["sha256"]), manifest, passphrase, restoreSSH, scope, lock)
	return map[string]any{"ok": true, "job_id": jobID}, nil
}

func (d *Daemon) deleteItem(req map[string]any) (map[string]any, error) {
	if req["confirmation"] != "DELETE" {
		return nil, bErr("invalid", "delete confirmation must be exactly DELETE")
	}
	kind, _ := req["kind"].(string)
	if kind != "upload" && kind != "backup" && kind != "job" {
		return nil, bErr("invalid", "delete kind must be upload, backup, or job")
	}
	itemID, err := identifier(req["id"], kind+" id")
	if err != nil {
		return nil, err
	}
	lock, err := d.acquireOperation()
	if err != nil {
		return nil, err
	}
	defer d.releaseOperation(lock)
	deleted := []string{}
	switch kind {
	case "upload":
		path := d.stageRecordPath(itemID)
		if _, err := os.Lstat(path); err == nil {
			if _, err := d.safeJSONFile(path); err != nil {
				return nil, err
			}
		} else {
			path, _ = d.uploadPath(itemID)
			if _, err := safeRegularFile(path, d.Opts.AppUID, d.Opts.MaxArchiveBytes); err != nil {
				if isNotExist(err) {
					return nil, bErr("not_found", "uploaded archive was not found")
				}
				return nil, err
			}
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
		deleted = append(deleted, filepath.Base(path))
	case "backup":
		files, err := d.removeBackupFiles(itemID)
		if err != nil {
			return nil, err
		}
		deleted = append(deleted, files...)
	default:
		job, err := d.loadJob(itemID, true)
		if err != nil {
			return nil, err
		}
		if activeStatus(job["status"]) {
			return nil, bErr("conflict", "an active job cannot be deleted")
		}
		path, _ := d.statePath(itemID)
		if err := os.Remove(path); err != nil {
			return nil, err
		}
		deleted = append(deleted, filepath.Base(path))
	}
	return map[string]any{"ok": true, "deleted": map[string]any{"kind": kind, "id": itemID, "files": deleted}}, nil
}

func (d *Daemon) statusResponse(req map[string]any) (map[string]any, error) {
	d.expireOrphanedUploads()
	var jobs []map[string]any
	if requested, ok := req["job_id"]; ok {
		id, err := identifier(requested, "job id")
		if err != nil {
			return nil, err
		}
		job, err := d.loadJob(id, true)
		if err != nil {
			return nil, err
		}
		jobs = []map[string]any{job}
	} else {
		jobs = d.listJobs()
	}
	backups := d.allBackups()
	listed := backups
	if len(listed) > d.Opts.ListLimit {
		listed = listed[:d.Opts.ListLimit]
	}
	var active any
	if job := d.activeJob(); job != nil {
		active = job
	}
	return map[string]any{
		"ok": true, "jobs": jobs, "backups": listed, "local": d.localStorage(backups),
		"uploads": d.listUploads(), "active_job": active,
	}, nil
}
