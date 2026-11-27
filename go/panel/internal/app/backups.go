package app

// Port of routes_backup.py: the superadmin full-backup and disaster-recovery
// workflow, backed by the root backup daemon.

import (
	"errors"
	"fmt"
	"hash/adler32"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

var (
	backupIdentifierRe = regexp.MustCompile(`^[a-f0-9]{32}$`)
	safeFilenameRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$`)
	destinationNameRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
	scheduleTimeRe     = regexp.MustCompile(`^(?:[01][0-9]|2[0-3]):[0-5][0-9]$`)
	backupAudited      = map[string]struct {
		action string
		fields []string
	}{
		"start_backup":        {"backup.start", []string{"include_ssh", "quiesce"}},
		"start_restore":       {"restore.start", []string{"upload_id", "scope", "restore_ssh"}},
		"delete":              {"backup.delete", []string{"kind", "id"}},
		"destination_save":    {"backup_destination.save", []string{"name", "type", "host", "user"}},
		"destination_delete":  {"backup_destination.delete", []string{"name"}},
		"destination_test":    {"backup_destination.test", []string{"name"}},
		"destination_retrust": {"backup_destination.retrust", []string{"name"}},
		"upload":              {"backup.upload", []string{"backup_id", "destination"}},
		"schedule_save":       {"backup_schedule.save", []string{"enabled", "destinations"}},
		"run_scheduled":       {"backup_schedule.run", nil},
	}
	destinationKeys = []string{"type", "host", "user", "path", "port", "private_key", "host_key", "keep_daily",
		"keep_weekly", "keep_monthly", "endpoint", "region", "bucket", "prefix", "access_key", "secret_key",
		"allow_insecure", "verify", "auth", "password"}
)

func backupExchangeRoot() string {
	return envOr("EASY_HA_PROXY_BACKUP_EXCHANGE_ROOT", "/var/lib/easy-ha-proxy/backup-web")
}

func envInt64(name string, def int64) int64 {
	if v, ok := os.LookupEnv(name); ok {
		if n, err := parsePyIntString(v); err == nil {
			return n
		}
	}
	return def
}

func backupMaxUpload() int64 {
	return envInt64("EASY_HA_PROXY_BACKUP_MAX_UPLOAD_BYTES", 8*1024*1024*1024)
}

func envOrFirst(names []string, def string) string {
	for _, n := range names {
		if v := strings.TrimSpace(os.Getenv(n)); v != "" {
			return v
		}
	}
	return def
}

func backupdSocketPath() string {
	return envOrFirst([]string{"EASY_HA_PROXY_BACKUPD_SOCKET", "BACKUPD_SOCKET_PATH"}, "/run/easy-ha-proxy/easy-ha-proxy-backupd.sock")
}

func updatedSocketPath() string {
	return envOrFirst([]string{"EASY_HA_PROXY_UPDATED_SOCKET", "UPDATED_SOCKET_PATH"}, "/run/easy-ha-proxy/easy-ha-proxy-updated.sock")
}

func backupRequest(payload *Map, timeout time.Duration) (*Map, error) {
	return JSONLineRequest(backupdSocketPath(),
		payload, "full-backup", timeout, 64*1024, 4*1024*1024)
}

func (c *Ctx) backupResponse(result *Map, accepted bool) error {
	if truthy(result.Value("ok")) {
		if accepted {
			return c.JSON(202, result)
		}
		return c.JSON(200, result)
	}
	code := strOrEmpty(result.Value("error_code"))
	status := 502
	switch {
	case code == "busy" || code == "conflict" || code == "operation_active" || truthy(result.Value("conflict")):
		status = 409
	case code == "not_found" || code == "missing":
		status = 404
	case code == "too_large":
		status = 413
	case code == "insufficient_space":
		status = 507
	case code == "invalid" || code == "validation" || code == "bad_request" || truthy(result.Value("validation_error")):
		status = 400
	}
	return c.JSON(status, result)
}

// backupCall is _call_daemon: one audit point; the summary comes from an
// allow-list because the payload can carry the archive passphrase.
func (c *Ctx) backupCall(payload *Map, accepted bool, timeout time.Duration) error {
	entry, audited := backupAudited[strOrEmpty(payload.Value("action"))]
	result, err := backupRequest(payload, timeout)
	if err != nil {
		if audited {
			c.RecordRequest(entry.action, AuditEntry{ObjectType: "backup",
				ObjectID: pyStr(orValue(payload.Value("id"), payload.Value("upload_id"), "")),
				Result:   auditResultFailure, Detail: truncRunes(err.Error(), 500)})
		}
		return c.JSON(503, newMap("ok", false, "error", err.Error()))
	}
	if audited {
		ok := truthy(result.Value("ok"))
		var parts []string
		for _, f := range entry.fields {
			if v, found := payload.Get(f); found {
				parts = append(parts, f+": "+pyStr(v))
			}
		}
		detail := ""
		if !ok {
			detail = truncRunes(strOrEmpty(result.Value("error")), 500)
		}
		c.RecordRequest(entry.action, AuditEntry{ObjectType: "backup",
			ObjectID: pyStr(orValue(result.Value("job_id"), payload.Value("id"), payload.Value("upload_id"), "")),
			Result:   recordResult(ok), Summary: strings.Join(parts, ", "), Detail: detail})
	}
	return c.backupResponse(result, accepted)
}

func backupPassphrase(v any) (string, error) {
	s, ok := v.(string)
	if !ok || pyLen(s) < 12 || pyLen(s) > 1024 {
		return "", Abort(400, "the backup passphrase must contain 12 to 1024 characters")
	}
	if strings.ContainsAny(s, "\x00\n\r") {
		return "", Abort(400, "the backup passphrase contains unsupported characters")
	}
	return s, nil
}

func backupIdentifier(v any, label string) (string, error) {
	text := strings.ToLower(pyStripSpace(strOrEmpty(v)))
	if !backupIdentifierRe.MatchString(text) {
		return "", Abort(400, "invalid "+label)
	}
	return text, nil
}

func destinationName(v any) (string, error) {
	text := strings.ToLower(pyStripSpace(strOrEmpty(v)))
	if !destinationNameRe.MatchString(text) {
		return "", Abort(400, "the destination name may use a-z, 0-9 and dashes")
	}
	return text, nil
}

// pyErrnoError is str(OSError(errno, message)).
func pyErrnoError(no syscall.Errno, msg string) string {
	return fmt.Sprintf("[Errno %d] %s", int(no), msg)
}

func (c *Ctx) uploadArchive() error {
	maxUpload := backupMaxUpload()
	length := c.R.ContentLength
	if length < 0 {
		return c.JSON(411, newMap("ok", false, "error", "Content-Length is required"))
	}
	if length < 1 {
		return c.JSON(400, newMap("ok", false, "error", "the backup file is empty"))
	}
	if length > maxUpload {
		return c.JSON(413, newMap("ok", false, "error", "the backup file is too large"))
	}
	if mt, _, _ := mime.ParseMediaType(c.R.Header.Get("Content-Type")); mt != "application/octet-stream" {
		return c.JSON(415, newMap("ok", false, "error", "application/octet-stream is required"))
	}
	root := filepath.Join(backupExchangeRoot(), "uploads")
	if !dirFollow(root) {
		return c.JSON(503, newMap("ok", false, "error", "the restore upload spool is unavailable"))
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(root, &st); err != nil {
		return c.JSON(503, newMap("ok", false, "error", "cannot inspect free disk space: "+pyFileError(err, root)))
	}
	free := int64(st.Bavail) * int64(st.Frsize)
	if free-envInt64("EASY_HA_PROXY_BACKUP_DISK_RESERVE_BYTES", 512*1024*1024) < length {
		return c.JSON(507, newMap("ok", false, "error", "not enough free disk space for the upload"))
	}
	uploadID := uuidHex()
	temporary := filepath.Join(root, "."+uploadID+".part")
	destination := filepath.Join(root, uploadID+".tar.gz.enc")
	var written int64
	fail := func(no syscall.Errno, msg string, committed bool) error {
		os.Remove(temporary)
		if committed {
			os.Remove(destination)
		}
		status := 400
		if no == syscall.EFBIG {
			status = 413
		}
		return c.JSON(status, newMap("ok", false, "error", "upload failed: "+msg))
	}
	f, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fail(0, pyFileError(err, temporary), false)
	}
	buf := make([]byte, 1024*1024)
	for {
		n, rerr := c.R.Body.Read(buf)
		if n > 0 {
			written += int64(n)
			if written > maxUpload || written > length {
				f.Close()
				return fail(syscall.EFBIG, pyErrnoError(syscall.EFBIG, "upload exceeds the declared size"), false)
			}
			if _, werr := f.Write(buf[:n]); werr != nil {
				f.Close()
				return fail(0, pyOSError(werr), false)
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			var tooLarge *http.MaxBytesError
			f.Close()
			if errors.As(rerr, &tooLarge) {
				return fail(syscall.EFBIG, pyErrnoError(syscall.EFBIG, "upload exceeds the declared size"), false)
			}
			return fail(0, pyOSError(rerr), false)
		}
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fail(0, pyOSError(err), false)
	}
	if err := f.Close(); err != nil {
		return fail(0, pyOSError(err), false)
	}
	if written != length {
		return fail(syscall.EIO, pyErrnoError(syscall.EIO, "upload ended before the declared size"), false)
	}
	if err := os.Rename(temporary, destination); err != nil {
		return fail(0, pyOSError(err), false)
	}
	if d, err := os.Open(root); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return c.JSON(201, newMap("ok", true, "upload_id", uploadID, "size", written))
}

// backupRecord is _backup_record.
func backupRecord(backupID string) (*Map, error) {
	result, err := backupRequest(newMap("action", "status"), 10*time.Second)
	if err != nil {
		return nil, Abort(503, err.Error())
	}
	if !truthy(result.Value("ok")) {
		return nil, Abort(503, pyStr(orValue(result.Value("error"), "backup service error")))
	}
	for _, item := range listOf(result, "backups") {
		m, ok := asMap(item)
		if !ok {
			continue
		}
		if strings.ToLower(pyStr(orValue(m.Value("id"), m.Value("backup_id"), ""))) == backupID {
			return m, nil
		}
	}
	return nil, Abort(404, "backup not found")
}

// downloadPath is _download_path: the artifact, after its safety checks.
func downloadPath(backupID string, record *Map, checksum bool) (string, string, error) {
	key := "archive_name"
	if checksum {
		key = "checksum_name"
	}
	filename := strOrEmpty(record.Value(key))
	if !safeFilenameRe.MatchString(filename) || filepath.Base(filename) != filename {
		return "", "", Abort(502, "the backup service returned an unsafe artifact name")
	}
	if !strings.HasPrefix(filename, backupID+".") {
		return "", "", Abort(502, "the backup artifact does not match its identifier")
	}
	downloadRoot := filepath.Join(backupExchangeRoot(), "backups")
	candidate := filepath.Join(downloadRoot, filename)
	info, err1 := os.Lstat(candidate)
	resolved, err2 := filepath.EvalSymlinks(candidate)
	root, err3 := filepath.EvalSymlinks(downloadRoot)
	if err1 != nil || err2 != nil || err3 != nil {
		return "", "", Abort(404, "backup artifact not found")
	}
	resolved, _ = filepath.Abs(resolved)
	root, _ = filepath.Abs(root)
	nlink := uint64(1)
	if sys, ok := info.Sys().(*syscall.Stat_t); ok {
		nlink = uint64(sys.Nlink)
	}
	if !strings.HasPrefix(resolved, root+string(os.PathSeparator)) || !info.Mode().IsRegular() || nlink != 1 {
		return "", "", Abort(502, "the backup artifact failed a safety check")
	}
	return resolved, filename, nil
}

func (a *App) registerBackups() {
	a.Handle("system_backups.status_view", func(c *Ctx) error {
		payload := newMap("action", "status")
		raw, _ := c.queryOpt("job_id")
		if job := strings.ToLower(pyStripSpace(raw)); job != "" {
			id, err := backupIdentifier(job, "job id")
			if err != nil {
				return err
			}
			payload.Set("job_id", id)
		}
		return c.backupCall(payload, false, 10*time.Second)
	})

	a.Handle("system_backups.start_backup", func(c *Ctx) error {
		payload, err := c.jsonPayloadFields([]string{"passphrase", "include_ssh", "quiesce"})
		if err != nil {
			return err
		}
		_, b1 := payload.Value("include_ssh").(bool)
		_, b2 := payload.Value("quiesce").(bool)
		if !b1 || !b2 {
			return Abort(400, "include_ssh and quiesce must be boolean")
		}
		pass, err := backupPassphrase(payload.Value("passphrase"))
		if err != nil {
			return err
		}
		return c.backupCall(newMap("action", "start_backup", "passphrase", pass, "include_ssh", payload.Value("include_ssh"),
			"quiesce", payload.Value("quiesce")), true, 10*time.Second)
	})

	a.Handle("system_backups.upload_archive", func(c *Ctx) error { return c.uploadArchive() })

	a.Handle("system_backups.inspect_archive", func(c *Ctx) error {
		payload, err := c.jsonPayloadFields([]string{"passphrase"})
		if err != nil {
			return err
		}
		id, err := backupIdentifier(c.Args["upload_id"], "upload id")
		if err != nil {
			return err
		}
		pass, err := backupPassphrase(payload.Value("passphrase"))
		if err != nil {
			return err
		}
		return c.backupCall(newMap("action", "start_inspect", "upload_id", id, "passphrase", pass), true, 10*time.Second)
	})

	a.Handle("system_backups.stage_backup", func(c *Ctx) error {
		id, err := backupIdentifier(c.Args["backup_id"], "backup id")
		if err != nil {
			return err
		}
		return c.backupCall(newMap("action", "stage_backup", "backup_id", id), false, 10*time.Second)
	})

	a.Handle("system_backups.start_restore", func(c *Ctx) error {
		payload, err := c.jsonPayloadFields([]string{"upload_id", "inspection_job_id", "passphrase", "restore_ssh", "confirmation"}, "scope")
		if err != nil {
			return err
		}
		if payload.Value("confirmation") != "RESTORE" {
			return Abort(400, "type RESTORE to confirm full replacement")
		}
		restoreSSH, isB := payload.Value("restore_ssh").(bool)
		if !isB {
			return Abort(400, "restore_ssh must be boolean")
		}
		scope, found := payload.Get("scope")
		if !found {
			scope = "full"
		}
		if scope != "full" && scope != "config" {
			return Abort(400, "scope must be full or config")
		}
		if scope == "config" && restoreSSH {
			return Abort(400, "SSH keys are not part of a configuration-scope restore")
		}
		uploadID, err := backupIdentifier(payload.Value("upload_id"), "upload id")
		if err != nil {
			return err
		}
		inspection, err := backupIdentifier(payload.Value("inspection_job_id"), "inspection job id")
		if err != nil {
			return err
		}
		pass, err := backupPassphrase(payload.Value("passphrase"))
		if err != nil {
			return err
		}
		return c.backupCall(newMap("action", "start_restore", "upload_id", uploadID, "inspection_job_id", inspection,
			"passphrase", pass, "restore_ssh", restoreSSH, "confirmation", "RESTORE", "scope", scope), true, 10*time.Second)
	})

	a.Handle("system_backups.delete_artifact", func(c *Ctx) error {
		payload, err := c.jsonPayloadFields([]string{"kind", "id", "confirmation"})
		if err != nil {
			return err
		}
		kind := payload.Value("kind")
		if kind != "backup" && kind != "upload" {
			return Abort(400, "kind must be backup or upload")
		}
		if payload.Value("confirmation") != "DELETE" {
			return Abort(400, "type DELETE to remove the artifact")
		}
		id, err := backupIdentifier(payload.Value("id"), "artifact id")
		if err != nil {
			return err
		}
		return c.backupCall(newMap("action", "delete", "kind", kind, "id", id, "confirmation", "DELETE"), false, 10*time.Second)
	})

	a.Handle("system_backups.download_backup", func(c *Ctx) error {
		id, err := backupIdentifier(c.Args["backup_id"], "backup id")
		if err != nil {
			return err
		}
		checksum := c.queryDefault("checksum", "") == "1"
		record, err := backupRecord(id)
		if err != nil {
			return err
		}
		path, filename, err := downloadPath(id, record, checksum)
		if err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil {
			return err
		}
		mtime := pyStatMtime(info.ModTime())
		h := c.W.Header()
		h.Set("Content-Disposition", contentDisposition(filename))
		h.Set("Cache-Control", "no-cache, max-age=0")
		h.Set("Expires", httpDate(time.Now()))
		h.Set("ETag", fmt.Sprintf(`"%s-%d-%d"`, pyStr(mtime), info.Size(), adler32.Checksum([]byte(path))))
		ctype := mime.TypeByExtension(filepath.Ext(filename))
		if ctype == "" {
			ctype = "application/octet-stream"
		}
		h.Set("Content-Type", ctype)
		c.commitCookies()
		c.written = true
		http.ServeContent(c.W, c.R, "", info.ModTime(), f)
		return nil
	})

	// ---- off-host destinations ----
	a.Handle("system_backups.list_destinations_view", func(c *Ctx) error {
		return c.backupCall(newMap("action", "destinations"), false, 10*time.Second)
	})
	a.Handle("system_backups.save_destination_view", func(c *Ctx) error {
		payload, err := c.jsonPayloadFields([]string{"name", "type"}, destinationKeys[1:]...)
		if err != nil {
			return err
		}
		name, err := destinationName(payload.Value("name"))
		if err != nil {
			return err
		}
		command := newMap("action", "destination_save", "name", name)
		for _, k := range destinationKeys {
			if v, found := payload.Get(k); found {
				command.Set(k, v)
			}
		}
		// Without a host key the daemon reads the far end's, which takes a moment.
		return c.backupCall(command, false, 60*time.Second)
	})
	named := func(action string, timeout time.Duration) HandlerFunc {
		return func(c *Ctx) error {
			payload, err := c.jsonPayloadFields([]string{"name"})
			if err != nil {
				return err
			}
			name, err := destinationName(payload.Value("name"))
			if err != nil {
				return err
			}
			return c.backupCall(newMap("action", action, "name", name), false, timeout)
		}
	}
	a.Handle("system_backups.delete_destination_view", named("destination_delete", 10*time.Second))
	a.Handle("system_backups.test_destination_view", named("destination_test", 90*time.Second))
	a.Handle("system_backups.trust_destination_host_key_view", named("destination_retrust", 60*time.Second))
	a.Handle("system_backups.upload_backup_view", func(c *Ctx) error {
		payload, err := c.jsonPayloadFields([]string{"backup_id", "destination"})
		if err != nil {
			return err
		}
		id, err := backupIdentifier(payload.Value("backup_id"), "backup id")
		if err != nil {
			return err
		}
		dest, err := destinationName(payload.Value("destination"))
		if err != nil {
			return err
		}
		return c.backupCall(newMap("action", "upload", "backup_id", id, "destination", dest), false, 1800*time.Second)
	})

	// ---- the nightly schedule ----
	a.Handle("system_backups.schedule_view", func(c *Ctx) error {
		return c.backupCall(newMap("action", "schedule"), false, 10*time.Second)
	})
	a.Handle("system_backups.save_schedule_view", func(c *Ctx) error {
		payload, err := c.jsonPayloadFields(nil, "enabled", "destinations", "include_ssh", "quiesce", "passphrase", "time", "keep_local")
		if err != nil {
			return err
		}
		command := newMap("action", "schedule_save")
		if v, found := payload.Get("enabled"); found {
			if _, isB := v.(bool); !isB {
				return Abort(400, "enabled must be boolean")
			}
			command.Set("enabled", v)
		}
		for _, k := range []string{"include_ssh", "quiesce"} {
			if v, found := payload.Get(k); found {
				if _, isB := v.(bool); !isB {
					return Abort(400, k+" must be boolean")
				}
				command.Set(k, v)
			}
		}
		if v, found := payload.Get("time"); found {
			wanted := pyStripSpace(strOrEmpty(v))
			if !scheduleTimeRe.MatchString(wanted) {
				return Abort(400, "the time must be given as HH:MM on a 24-hour clock")
			}
			command.Set("time", wanted)
		}
		if v, found := payload.Get("keep_local"); found {
			n, ok := v.(int64)
			if !ok {
				return Abort(400, "the number of backups kept on this server must be a whole number")
			}
			command.Set("keep_local", n)
		}
		if v, found := payload.Get("destinations"); found {
			list, ok := v.([]any)
			if !ok {
				return Abort(400, "destinations must be a list")
			}
			names := []any{}
			for _, item := range list {
				n, err := destinationName(item)
				if err != nil {
					return err
				}
				names = append(names, n)
			}
			command.Set("destinations", names)
		}
		if v, found := payload.Get("passphrase"); found {
			// An empty string asks for the stored passphrase to be forgotten.
			if v == "" {
				command.Set("passphrase", "")
			} else {
				pass, err := backupPassphrase(v)
				if err != nil {
					return err
				}
				command.Set("passphrase", pass)
			}
		}
		return c.backupCall(command, false, 10*time.Second)
	})
	a.Handle("system_backups.run_schedule_view", func(c *Ctx) error {
		return c.backupCall(newMap("action", "run_scheduled", "on_demand", true), false, 1800*time.Second)
	})
}
