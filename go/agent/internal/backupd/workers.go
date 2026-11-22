package backupd

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/alerts"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/unixrpc"
)

func randomHex32() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (s *Service) saveJob(job map[string]any) {
	id, _ := job["id"].(string)
	if !IdentifierRe.MatchString(id) {
		return
	}
	data, err := json.MarshalIndent(job, "", "  ")
	if err != nil {
		return
	}
	_ = writeAtomic(filepath.Join(s.Opts.JobsDir(), id+".json"), append(data, '\n'), 0o600)
}

func (s *Service) reportAlert(ctx context.Context, rule, subject, summary, detail string) {
	if s.Alerts != nil && s.Alerts.Enabled() {
		s.Alerts.Observe(ctx, alerts.Observation{
			Rule:    rule,
			Subject: subject,
			Summary: summary,
			Detail:  detail,
		})
	}
}

// buildTarGz creates a gzipped tar archive of the given host paths natively in Go.
func buildTarGz(dstPath string, roots []string) (int, int64, error) {
	f, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)
	files := 0
	var expanded int64

	for _, root := range roots {
		info, err := os.Stat(root)
		if err != nil {
			continue
		}
		if !info.IsDir() {
			if err := addFileToTar(tw, root, strings.TrimPrefix(filepath.ToSlash(root), "/"), info); err == nil {
				files++
				expanded += info.Size()
			}
			continue
		}
		_ = filepath.Walk(root, func(p string, fi os.FileInfo, werr error) error {
			if werr != nil || fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
				return nil
			}
			name := strings.TrimPrefix(filepath.ToSlash(p), "/")
			if err := addFileToTar(tw, p, name, fi); err == nil {
				files++
				expanded += fi.Size()
			}
			return nil
		})
	}
	if err := tw.Close(); err != nil {
		return 0, 0, err
	}
	if err := gw.Close(); err != nil {
		return 0, 0, err
	}
	return files, expanded, nil
}

func addFileToTar(tw *tar.Writer, srcPath, tarName string, fi os.FileInfo) error {
	hdr, err := tar.FileInfoHeader(fi, "")
	if err != nil {
		return err
	}
	hdr.Name = tarName
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()
	_, err = io.Copy(tw, src)
	return err
}

// encryptFileOpenSSL encrypts src -> dst with AES-256-CBC + PBKDF2, passing passphrase via fd:3.
func encryptFileOpenSSL(ctx context.Context, opensslBin, src, dst, passphrase string) error {
	if strings.ContainsAny(passphrase, "\r\n") || len(passphrase) < 8 {
		return errors.New("passphrase must be at least 8 characters with no line breaks")
	}
	if opensslBin == "" {
		opensslBin = "openssl"
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		return err
	}
	_, _ = pw.WriteString(passphrase + "\n")
	_ = pw.Close()
	defer pr.Close()

	cmdCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, opensslBin, "enc", "-aes-256-cbc", "-pbkdf2", "-salt",
		"-in", src, "-out", dst, "-pass", "fd:3")
	cmd.ExtraFiles = []*os.File{pr}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("openssl encrypt failed: %s", strings.TrimSpace(stderr.String()))
	}
	_ = os.Chmod(dst, 0o600)
	return nil
}

// decryptFileOpenSSL decrypts src -> dst using AES-256-CBC + PBKDF2 via fd:3.
func decryptFileOpenSSL(ctx context.Context, opensslBin, src, dst, passphrase string) error {
	if strings.ContainsAny(passphrase, "\r\n") || passphrase == "" {
		return errors.New("passphrase is required")
	}
	if opensslBin == "" {
		opensslBin = "openssl"
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		return err
	}
	_, _ = pw.WriteString(passphrase + "\n")
	_ = pw.Close()
	defer pr.Close()

	cmdCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, opensslBin, "enc", "-d", "-aes-256-cbc", "-pbkdf2",
		"-in", src, "-out", dst, "-pass", "fd:3")
	cmd.ExtraFiles = []*os.File{pr}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("openssl decrypt failed: %s", strings.TrimSpace(stderr.String()))
	}
	return nil
}

// inspectTarGz validates gzip + tar headers, rejecting path traversal or absolute paths.
func inspectTarGz(path string) (int, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	gr, err := gzip.NewReader(f)
	if err != nil {
		return 0, 0, err
	}
	defer gr.Close()
	tr := tar.NewReader(gr)
	files := 0
	var totalBytes int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, 0, err
		}
		clean := filepath.Clean(hdr.Name)
		if strings.HasPrefix(hdr.Name, "/") || strings.HasPrefix(clean, "..") || strings.Contains(clean, "/../") {
			return 0, 0, fmt.Errorf("unsafe archive path: %q", hdr.Name)
		}
		if hdr.Typeflag == tar.TypeReg {
			files++
			totalBytes += hdr.Size
		}
	}
	return files, totalBytes, nil
}

// RunBackupSync creates one encrypted .tar.gz.enc backup synchronously under the maintenance lock.
func (s *Service) RunBackupSync(ctx context.Context, passphrase string, includeSSH, quiesce bool) (string, map[string]any, error) {
	if s.rebootScheduled() {
		return "", nil, unixrpc.NewError("conflict", "a server reboot is scheduled")
	}
	storage := s.storageSummary()
	if below, _ := storage["below_min_free"].(bool); below {
		return "", nil, unixrpc.NewError("insufficient_space", "insufficient free disk space for backup")
	}
	lockFile, err := tryLockOperation(s.Opts.OperationLockPath)
	if err != nil {
		return "", nil, unixrpc.NewError("conflict", "another backup or update operation is already running")
	}
	defer unlockOperation(lockFile)

	jobID := randomHex32()
	backupID := randomHex32()
	nowStr := time.Now().UTC().Format(time.RFC3339)
	job := map[string]any{
		"id":         jobID,
		"kind":       "backup",
		"backup_id":  backupID,
		"status":     "running",
		"created_at": nowStr,
	}
	s.saveJob(job)

	roots := s.BackupRoots
	if len(roots) == 0 {
		roots = []string{"/etc/haproxy", "/opt/haproxy-admin/config", "/etc/easy-ha-proxy", "/opt/authelia"}
		if includeSSH {
			roots = append(roots, "/etc/ssh")
		}
	}

	tmpPlain := filepath.Join(s.Opts.BackupsDir(), "."+backupID+".tar.gz.tmp")
	defer os.Remove(tmpPlain)
	files, expanded, err := buildTarGz(tmpPlain, roots)
	if err != nil {
		job["status"] = "failed"
		job["error"] = err.Error()
		job["finished_at"] = time.Now().UTC().Format(time.RFC3339)
		s.saveJob(job)
		s.reportAlert(ctx, "backup.failed", backupID, "Backup archive build failed", err.Error())
		return jobID, nil, err
	}

	encPath := filepath.Join(s.Opts.BackupsDir(), backupID+ArchiveSuffix)
	tmpEnc := encPath + ".tmp"
	if err := encryptFileOpenSSL(ctx, s.OpenSSLBin, tmpPlain, tmpEnc, passphrase); err != nil {
		_ = os.Remove(tmpEnc)
		job["status"] = "failed"
		job["error"] = err.Error()
		job["finished_at"] = time.Now().UTC().Format(time.RFC3339)
		s.saveJob(job)
		s.reportAlert(ctx, "backup.failed", backupID, "Backup encryption failed", err.Error())
		return jobID, nil, err
	}
	if err := os.Rename(tmpEnc, encPath); err != nil {
		_ = os.Remove(tmpEnc)
		return jobID, nil, err
	}

	encRaw, _ := os.ReadFile(encPath)
	sum := sha256.Sum256(encRaw)
	sumHex := hex.EncodeToString(sum[:])
	_ = writeAtomic(filepath.Join(s.Opts.BackupsDir(), backupID+ChecksumSuffix), []byte(sumHex+"  "+backupID+ArchiveSuffix+"\n"), 0o600)

	host, _ := os.Hostname()
	manifest := map[string]any{
		"format":                 "easy-ha-proxy-full-backup",
		"format_version":         1,
		"created_at":             nowStr,
		"hostname":               host,
		"ssh_included":           includeSSH,
		"quiesced":               quiesce,
		"payload_sha256":         sumHex,
		"payload_expanded_bytes": expanded,
		"files":                  files,
	}
	mBytes, _ := json.MarshalIndent(manifest, "", "  ")
	_ = writeAtomic(filepath.Join(s.Opts.BackupsDir(), backupID+MetaSuffix), append(mBytes, '\n'), 0o600)

	job["status"] = "completed"
	job["finished_at"] = time.Now().UTC().Format(time.RFC3339)
	job["manifest"] = manifest
	s.saveJob(job)
	return jobID, manifest, nil
}

// StartBackup validates inputs and runs an encrypted backup job.
func (s *Service) StartBackup(ctx context.Context, req map[string]any) (map[string]any, error) {
	pass, _ := req["passphrase"].(string)
	if len(pass) < 8 || strings.ContainsAny(pass, "\r\n") {
		return nil, unixrpc.NewError("invalid", "passphrase must be at least 8 characters")
	}
	incSSH, _ := req["include_ssh"].(bool)
	quiesce, _ := req["quiesce"].(bool)
	jobID, manifest, err := s.RunBackupSync(ctx, pass, incSSH, quiesce)
	if err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "job_id": jobID, "manifest": manifest}, nil
}

// StartInspect decrypts an uploaded or local archive and validates its tar structure.
func (s *Service) StartInspect(ctx context.Context, req map[string]any) (map[string]any, error) {
	uid, _ := req["upload_id"].(string)
	if !IdentifierRe.MatchString(uid) {
		return nil, unixrpc.NewError("invalid", "invalid upload_id")
	}
	pass, _ := req["passphrase"].(string)
	if pass == "" {
		return nil, unixrpc.NewError("invalid", "passphrase is required")
	}
	archPath := filepath.Join(s.Opts.UploadsDir(), uid+ArchiveSuffix)
	if _, err := os.Stat(archPath); err != nil {
		archPath = filepath.Join(s.Opts.BackupsDir(), uid+ArchiveSuffix)
		if _, err2 := os.Stat(archPath); err2 != nil {
			return nil, unixrpc.NewError("not_found", "archive not found")
		}
	}

	tmpPlain, err := os.CreateTemp(s.Opts.UploadsDir(), ".inspect-*.tar.gz")
	if err != nil {
		return nil, err
	}
	tmpPath := tmpPlain.Name()
	_ = tmpPlain.Close()
	defer os.Remove(tmpPath)

	if err := decryptFileOpenSSL(ctx, s.OpenSSLBin, archPath, tmpPath, pass); err != nil {
		return nil, unixrpc.NewError("invalid", err.Error())
	}
	files, totalBytes, err := inspectTarGz(tmpPath)
	if err != nil {
		return nil, unixrpc.NewError("invalid", err.Error())
	}
	jobID := randomHex32()
	job := map[string]any{
		"id":             jobID,
		"kind":           "inspect",
		"upload_id":      uid,
		"status":         "completed",
		"files":          files,
		"expanded_bytes": totalBytes,
		"created_at":     time.Now().UTC().Format(time.RFC3339),
		"finished_at":    time.Now().UTC().Format(time.RFC3339),
	}
	s.saveJob(job)
	return map[string]any{"ok": true, "job_id": jobID, "job": job}, nil
}

// StageBackup prepares a local backup archive metadata record for download.
func (s *Service) StageBackup(req map[string]any) (map[string]any, error) {
	bid, _ := req["backup_id"].(string)
	if !IdentifierRe.MatchString(bid) {
		return nil, unixrpc.NewError("invalid", "invalid backup_id")
	}
	arch := filepath.Join(s.Opts.BackupsDir(), bid+ArchiveSuffix)
	fi, err := os.Stat(arch)
	if err != nil {
		return nil, unixrpc.NewError("not_found", "backup archive not found")
	}
	return map[string]any{
		"ok":         true,
		"backup_id":  bid,
		"path":       arch,
		"size_bytes": fi.Size(),
	}, nil
}

// RunScheduled executes the scheduled backup policy when enabled, reporting low space.
func (s *Service) RunScheduled(ctx context.Context) (map[string]any, error) {
	s.mu.Lock()
	var sched map[string]any
	if raw, err := os.ReadFile(s.Opts.SchedulePath()); err == nil {
		_ = json.Unmarshal(raw, &sched)
	}
	s.mu.Unlock()

	enabled, _ := sched["enabled"].(bool)
	if !enabled {
		return map[string]any{"ok": true, "skipped": "scheduled backups are disabled"}, nil
	}
	pass, _ := sched["passphrase"].(string)
	if len(pass) < 8 {
		return nil, unixrpc.NewError("invalid", "scheduled backup passphrase is not configured")
	}
	incSSH, _ := sched["include_ssh"].(bool)
	quiesce, _ := sched["quiesce"].(bool)

	jobID, manifest, err := s.RunBackupSync(ctx, pass, incSSH, quiesce)
	if err != nil {
		return nil, err
	}
	storage := s.storageSummary()
	if low, _ := storage["low_space"].(bool); low {
		s.reportAlert(ctx, "backup.space_low", "backups", "Backup storage is running low on free space", "")
	}
	return map[string]any{
		"ok":        true,
		"job_id":    jobID,
		"backup_id": manifest["payload_sha256"],
		"uploads":   []string{},
		"local":     storage,
	}, nil
}
