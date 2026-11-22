package server

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

var (
	identifierRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,95}$`)
	destNameRe        = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,39}$`)
	safeFilenameRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$`)
	hhmmRe            = regexp.MustCompile(`^(?:[01][0-9]|2[0-3]):[0-5][0-9]$`)
	uploadDiskReserve = int64(256 * 1024 * 1024)
)

func (s *Server) registerBackupRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /system/backups/api/status", s.handleBackupStatus)
	mux.HandleFunc("POST /system/backups/api/jobs/backup", s.handleBackupStart)
	mux.HandleFunc("POST /system/backups/api/uploads", s.handleBackupUpload)
	mux.HandleFunc("POST /system/backups/api/uploads/{upload_id}/inspect", s.handleBackupInspect)
	mux.HandleFunc("POST /system/backups/api/backups/{backup_id}/stage", s.handleBackupStage)
	mux.HandleFunc("POST /system/backups/api/jobs/restore", s.handleBackupRestore)
	mux.HandleFunc("POST /system/backups/api/delete", s.handleBackupDelete)
	mux.HandleFunc("GET /system/backups/download/{backup_id}", s.handleBackupDownload)

	mux.HandleFunc("GET /system/backups/api/destinations", s.handleBackupDestinationsList)
	mux.HandleFunc("POST /system/backups/api/destinations", s.handleBackupDestinationSave)
	mux.HandleFunc("POST /system/backups/api/destinations/delete", s.handleBackupDestinationDelete)
	mux.HandleFunc("POST /system/backups/api/destinations/test", s.handleBackupDestinationTest)
	mux.HandleFunc("POST /system/backups/api/destinations/trust-host-key", s.handleBackupDestinationRetrust)
	mux.HandleFunc("POST /system/backups/api/destinations/upload", s.handleBackupDestinationUpload)

	mux.HandleFunc("GET /system/backups/api/schedule", s.handleBackupScheduleGet)
	mux.HandleFunc("POST /system/backups/api/schedule", s.handleBackupScheduleSave)
	mux.HandleFunc("POST /system/backups/api/schedule/run", s.handleBackupScheduleRun)
}

func (s *Server) callBackupd(w http.ResponseWriter, r *http.Request, payload map[string]any, timeout time.Duration, accepted bool) {
	res, err := s.Pool.Backupd.Call(r.Context(), payload, timeout)
	if err != nil {
		s.writeUnavailable(w, r, err)
		return
	}
	okVal, _ := res["ok"].(bool)
	status := http.StatusOK
	if okVal {
		if accepted {
			status = http.StatusAccepted
		}
	} else {
		status = http.StatusBadRequest
		if busy, _ := res["busy"].(bool); busy {
			status = http.StatusConflict
		}
	}
	s.writeJSON(w, r, status, res)
}

func validIdentifier(raw string) (string, bool) {
	v := strings.ToLower(strings.TrimSpace(raw))
	return v, identifierRe.MatchString(v)
}

func validDestName(raw string) (string, bool) {
	v := strings.ToLower(strings.TrimSpace(raw))
	return v, destNameRe.MatchString(v)
}

func validPassphrase(raw any) (string, bool) {
	p, ok := raw.(string)
	if !ok || len(p) < 8 || len(p) > 256 {
		return "", false
	}
	return p, true
}

func (s *Server) handleBackupStatus(w http.ResponseWriter, r *http.Request) {
	cmd := map[string]any{"action": "status"}
	if rawJob := r.URL.Query().Get("job_id"); strings.TrimSpace(rawJob) != "" {
		id, ok := validIdentifier(rawJob)
		if !ok {
			s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid job id"})
			return
		}
		cmd["job_id"] = id
	}
	s.callBackupd(w, r, cmd, 15*time.Second, false)
}

func (s *Server) handleBackupStart(w http.ResponseWriter, r *http.Request) {
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	pass, okPass := validPassphrase(payload["passphrase"])
	incSSH, ok1 := payload["include_ssh"].(bool)
	quiesce, ok2 := payload["quiesce"].(bool)
	if !ok1 || !ok2 {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "include_ssh and quiesce must be boolean"})
		return
	}
	if !okPass {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "passphrase must be between 8 and 256 characters"})
		return
	}
	s.callBackupd(w, r, map[string]any{
		"action":      "start_backup",
		"passphrase":  pass,
		"include_ssh": incSSH,
		"quiesce":     quiesce,
	}, 15*time.Second, true)
}

func (s *Server) handleBackupUpload(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength < 0 {
		s.writeJSON(w, r, http.StatusLengthRequired, map[string]any{"ok": false, "error": "Content-Length is required"})
		return
	}
	if r.ContentLength == 0 {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "the backup file is empty"})
		return
	}
	maxBytes := s.Cfg.MaxUploadBytes
	if maxBytes <= 0 {
		maxBytes = 8 * 1024 * 1024 * 1024
	}
	if r.ContentLength > maxBytes {
		s.writeJSON(w, r, http.StatusRequestEntityTooLarge, map[string]any{"ok": false, "error": "the backup file is too large"})
		return
	}
	ct := strings.ToLower(strings.TrimSpace(strings.SplitN(r.Header.Get("Content-Type"), ";", 2)[0]))
	if ct != "application/octet-stream" {
		s.writeJSON(w, r, http.StatusUnsupportedMediaType, map[string]any{"ok": false, "error": "application/octet-stream is required"})
		return
	}

	uploadRoot := s.Cfg.BackupUploadsDir
	info, err := os.Stat(uploadRoot)
	if err != nil || !info.IsDir() {
		s.writeJSON(w, r, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "the restore upload spool is unavailable"})
		return
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(uploadRoot, &st); err != nil {
		s.writeJSON(w, r, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": fmt.Sprintf("cannot inspect free disk space: %v", err)})
		return
	}
	freeBytes := int64(st.Bavail) * int64(st.Bsize)
	if freeBytes-uploadDiskReserve < r.ContentLength {
		s.writeJSON(w, r, http.StatusInsufficientStorage, map[string]any{"ok": false, "error": "not enough free disk space for the upload"})
		return
	}

	idBytes := make([]byte, 16)
	_, _ = rand.Read(idBytes)
	uploadID := hex.EncodeToString(idBytes)
	tmpPath := filepath.Join(uploadRoot, "."+uploadID+".part")
	dstPath := filepath.Join(uploadRoot, uploadID+".tar.gz.enc")

	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": fmt.Sprintf("upload failed: %v", err)})
		return
	}

	written, copyErr := io.Copy(f, io.LimitReader(r.Body, r.ContentLength+1))
	syncErr := f.Sync()
	closeErr := f.Close()

	if copyErr != nil || syncErr != nil || closeErr != nil || written != r.ContentLength {
		_ = os.Remove(tmpPath)
		status := http.StatusBadRequest
		if written > r.ContentLength {
			status = http.StatusRequestEntityTooLarge
		}
		s.writeJSON(w, r, status, map[string]any{"ok": false, "error": "upload failed or size mismatch"})
		return
	}
	if err := os.Rename(tmpPath, dstPath); err != nil {
		_ = os.Remove(tmpPath)
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": fmt.Sprintf("upload failed: %v", err)})
		return
	}
	s.writeJSON(w, r, http.StatusCreated, map[string]any{
		"ok":        true,
		"upload_id": uploadID,
		"size":      written,
	})
}

func (s *Server) handleBackupInspect(w http.ResponseWriter, r *http.Request) {
	uploadID, ok := validIdentifier(r.PathValue("upload_id"))
	if !ok {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid upload id"})
		return
	}
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	pass, okPass := validPassphrase(payload["passphrase"])
	if !okPass {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "passphrase must be between 8 and 256 characters"})
		return
	}
	s.callBackupd(w, r, map[string]any{
		"action":     "start_inspect",
		"upload_id":  uploadID,
		"passphrase": pass,
	}, 15*time.Second, true)
}

func (s *Server) handleBackupStage(w http.ResponseWriter, r *http.Request) {
	backupID, ok := validIdentifier(r.PathValue("backup_id"))
	if !ok {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid backup id"})
		return
	}
	s.callBackupd(w, r, map[string]any{
		"action":    "stage_backup",
		"backup_id": backupID,
	}, 10*time.Second, false)
}

func (s *Server) handleBackupRestore(w http.ResponseWriter, r *http.Request) {
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if asString(payload["confirmation"]) != "RESTORE" {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "type RESTORE to confirm full replacement"})
		return
	}
	restoreSSH, okBool := payload["restore_ssh"].(bool)
	if !okBool {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "restore_ssh must be boolean"})
		return
	}
	scope := strings.TrimSpace(asString(payload["scope"]))
	if scope == "" {
		scope = "full"
	}
	if scope != "full" && scope != "config" {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "scope must be full or config"})
		return
	}
	if scope == "config" && restoreSSH {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "SSH keys are not part of a configuration-scope restore"})
		return
	}
	uploadID, okU := validIdentifier(asString(payload["upload_id"]))
	inspID, okI := validIdentifier(asString(payload["inspection_job_id"]))
	pass, okP := validPassphrase(payload["passphrase"])
	if !okU || !okI || !okP {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid restore parameters"})
		return
	}
	s.callBackupd(w, r, map[string]any{
		"action":            "start_restore",
		"upload_id":         uploadID,
		"inspection_job_id": inspID,
		"passphrase":        pass,
		"restore_ssh":       restoreSSH,
		"confirmation":      "RESTORE",
		"scope":             scope,
	}, 15*time.Second, true)
}

func (s *Server) handleBackupDelete(w http.ResponseWriter, r *http.Request) {
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	kind := strings.TrimSpace(asString(payload["kind"]))
	if kind != "backup" && kind != "upload" {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "kind must be backup or upload"})
		return
	}
	if asString(payload["confirmation"]) != "DELETE" {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "type DELETE to remove the artifact"})
		return
	}
	artID, ok := validIdentifier(asString(payload["id"]))
	if !ok {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid artifact id"})
		return
	}
	s.callBackupd(w, r, map[string]any{
		"action":       "delete",
		"kind":         kind,
		"id":           artID,
		"confirmation": "DELETE",
	}, 15*time.Second, false)
}

func (s *Server) handleBackupDownload(w http.ResponseWriter, r *http.Request) {
	backupID, ok := validIdentifier(r.PathValue("backup_id"))
	if !ok {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid backup id"})
		return
	}
	statusRes, err := s.Pool.Backupd.Call(r.Context(), map[string]any{"action": "status"}, 10*time.Second)
	if err != nil {
		s.writeUnavailable(w, r, err)
		return
	}
	if okVal, _ := statusRes["ok"].(bool); !okVal {
		s.writeJSON(w, r, http.StatusServiceUnavailable, statusRes)
		return
	}

	var record map[string]any
	if list, ok := statusRes["backups"].([]any); ok {
		for _, item := range list {
			m, _ := item.(map[string]any)
			id := strings.ToLower(strings.TrimSpace(asString(m["id"])))
			if id == "" {
				id = strings.ToLower(strings.TrimSpace(asString(m["backup_id"])))
			}
			if id == backupID {
				record = m
				break
			}
		}
	}
	if record == nil {
		s.writeJSON(w, r, http.StatusNotFound, map[string]any{"ok": false, "error": "backup not found"})
		return
	}

	key := "archive_name"
	if r.URL.Query().Get("checksum") == "1" {
		key = "checksum_name"
	}
	filename := asString(record[key])
	if !safeFilenameRe.MatchString(filename) || filepath.Base(filename) != filename {
		s.writeJSON(w, r, http.StatusBadGateway, map[string]any{"ok": false, "error": "the backup service returned an unsafe artifact name"})
		return
	}
	if !strings.HasPrefix(filename, backupID+".") {
		s.writeJSON(w, r, http.StatusBadGateway, map[string]any{"ok": false, "error": "the backup artifact does not match its identifier"})
		return
	}

	root, err := filepath.EvalSymlinks(s.Cfg.BackupDownloadsDir)
	if err != nil {
		s.writeJSON(w, r, http.StatusNotFound, map[string]any{"ok": false, "error": "backup artifact not found"})
		return
	}
	candidate := filepath.Join(root, filename)
	lstatInfo, err := os.Lstat(candidate)
	if err != nil {
		s.writeJSON(w, r, http.StatusNotFound, map[string]any{"ok": false, "error": "backup artifact not found"})
		return
	}
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil || filepath.Dir(resolved) != root || !lstatInfo.Mode().IsRegular() {
		s.writeJSON(w, r, http.StatusBadGateway, map[string]any{"ok": false, "error": "the backup artifact failed a safety check"})
		return
	}
	if st, ok := lstatInfo.Sys().(*syscall.Stat_t); ok && st.Nlink != 1 {
		s.writeJSON(w, r, http.StatusBadGateway, map[string]any{"ok": false, "error": "the backup artifact failed a safety check"})
		return
	}

	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Cache-Control", "no-store")
	http.ServeFile(w, r, resolved)
}

func (s *Server) handleBackupDestinationsList(w http.ResponseWriter, r *http.Request) {
	s.callBackupd(w, r, map[string]any{"action": "destinations"}, 15*time.Second, false)
}

func (s *Server) handleBackupDestinationSave(w http.ResponseWriter, r *http.Request) {
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	name, ok := validDestName(asString(payload["name"]))
	if !ok {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid destination name"})
		return
	}
	cmd := map[string]any{"action": "destination_save", "name": name}
	for _, k := range []string{
		"type", "host", "user", "path", "port", "private_key", "host_key",
		"keep_daily", "keep_weekly", "keep_monthly", "endpoint", "region",
		"bucket", "prefix", "access_key", "secret_key", "allow_insecure",
		"verify", "auth", "password",
	} {
		if v, exists := payload[k]; exists {
			cmd[k] = v
		}
	}
	s.callBackupd(w, r, cmd, 60*time.Second, false)
}

func (s *Server) handleBackupDestinationDelete(w http.ResponseWriter, r *http.Request) {
	s.handleBackupDestByName(w, r, "destination_delete", 15*time.Second)
}

func (s *Server) handleBackupDestinationTest(w http.ResponseWriter, r *http.Request) {
	s.handleBackupDestByName(w, r, "destination_test", 90*time.Second)
}

func (s *Server) handleBackupDestinationRetrust(w http.ResponseWriter, r *http.Request) {
	s.handleBackupDestByName(w, r, "destination_retrust", 60*time.Second)
}

func (s *Server) handleBackupDestByName(w http.ResponseWriter, r *http.Request, action string, timeout time.Duration) {
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	name, ok := validDestName(asString(payload["name"]))
	if !ok {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid destination name"})
		return
	}
	s.callBackupd(w, r, map[string]any{"action": action, "name": name}, timeout, false)
}

func (s *Server) handleBackupDestinationUpload(w http.ResponseWriter, r *http.Request) {
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	backupID, ok1 := validIdentifier(asString(payload["backup_id"]))
	dest, ok2 := validDestName(asString(payload["destination"]))
	if !ok1 || !ok2 {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid backup_id or destination"})
		return
	}
	s.callBackupd(w, r, map[string]any{
		"action":      "upload",
		"backup_id":   backupID,
		"destination": dest,
	}, 1800*time.Second, false)
}

func (s *Server) handleBackupScheduleGet(w http.ResponseWriter, r *http.Request) {
	s.callBackupd(w, r, map[string]any{"action": "schedule"}, 15*time.Second, false)
}

func (s *Server) handleBackupScheduleSave(w http.ResponseWriter, r *http.Request) {
	payload, err := s.readJSONBody(r)
	if err != nil {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	cmd := map[string]any{"action": "schedule_save"}
	for _, k := range []string{"enabled", "include_ssh", "quiesce"} {
		if v, exists := payload[k]; exists {
			b, ok := v.(bool)
			if !ok {
				s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": k + " must be boolean"})
				return
			}
			cmd[k] = b
		}
	}
	if v, exists := payload["time"]; exists {
		t := strings.TrimSpace(asString(v))
		if !hhmmRe.MatchString(t) {
			s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "the time must be given as HH:MM on a 24-hour clock"})
			return
		}
		cmd["time"] = t
	}
	if v, exists := payload["keep_local"]; exists {
		keep, ok := parseWholeNumber(v)
		if !ok {
			s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "the number of backups kept on this server must be a whole number"})
			return
		}
		cmd["keep_local"] = keep
	}
	if v, exists := payload["destinations"]; exists {
		arr, ok := v.([]any)
		if !ok {
			s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "destinations must be a list"})
			return
		}
		names := make([]string, 0, len(arr))
		for _, item := range arr {
			name, ok := validDestName(asString(item))
			if !ok {
				s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid destination name"})
				return
			}
			names = append(names, name)
		}
		cmd["destinations"] = names
	}
	if v, exists := payload["passphrase"]; exists {
		sVal, ok := v.(string)
		if !ok {
			s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid passphrase"})
			return
		}
		if sVal == "" {
			cmd["passphrase"] = ""
		} else {
			pass, okP := validPassphrase(sVal)
			if !okP {
				s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"ok": false, "error": "passphrase must be between 8 and 256 characters"})
				return
			}
			cmd["passphrase"] = pass
		}
	}
	s.callBackupd(w, r, cmd, 15*time.Second, false)
}

func (s *Server) handleBackupScheduleRun(w http.ResponseWriter, r *http.Request) {
	s.callBackupd(w, r, map[string]any{"action": "run_scheduled", "on_demand": true}, 1800*time.Second, false)
}
