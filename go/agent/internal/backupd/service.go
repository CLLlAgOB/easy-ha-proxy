package backupd

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/alerts"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/unixrpc"
)

// Service implements the backupd request dispatcher, storage, destinations, schedule, and job tracking.
type Service struct {
	mu          sync.Mutex
	Opts        Options
	Alerts      *alerts.Client
	OpenSSLBin  string
	BackupRoots []string
}

// NewService prepares the spool directory layout, recovers stale jobs, and returns Service.
func NewService(opts Options) (*Service, error) {
	for _, d := range []string{opts.SpoolRoot, opts.JobsDir(), opts.UploadsDir(), opts.BackupsDir()} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return nil, err
		}
	}
	s := &Service{Opts: opts, Alerts: alerts.FromEnv(), OpenSSLBin: "openssl"}
	s.RecoverStaleJobs()
	return s, nil
}

// RecoverStaleJobs marks orphaned queued/running job records as interrupted after a crash/restart.
func (s *Service) RecoverStaleJobs() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.Opts.JobsDir())
	if err != nil {
		return 0
	}
	recovered := 0
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".json") {
			continue
		}
		p := filepath.Join(s.Opts.JobsDir(), ent.Name())
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var job map[string]any
		if json.Unmarshal(raw, &job) != nil {
			continue
		}
		st, _ := job["status"].(string)
		if st == "queued" || st == "running" {
			job["status"] = "interrupted"
			job["error"] = "backup daemon restarted while job was active"
			job["finished_at"] = time.Now().UTC().Format(time.RFC3339)
			if data, err := json.MarshalIndent(job, "", "  "); err == nil {
				_ = writeAtomic(p, append(data, '\n'), 0o600)
				recovered++
			}
		}
	}
	return recovered
}

func (s *Service) rebootScheduled() bool {
	for _, p := range []string{s.Opts.RebootMarker, s.Opts.AssistantRebootMarker} {
		if p != "" {
			if _, err := os.Lstat(p); err == nil {
				return true
			}
		}
	}
	return false
}

// Dispatch validates strict action & field whitelists and routes the request.
func (s *Service) Dispatch(ctx context.Context, req map[string]any) (map[string]any, error) {
	action, _ := req["action"].(string)
	allowed, ok := RequestFields[action]
	if !ok {
		return nil, unixrpc.NewError("invalid", "unknown backup daemon action")
	}
	var unexpected []string
	for k := range req {
		if _, exists := allowed[k]; !exists {
			unexpected = append(unexpected, k)
		}
	}
	if len(unexpected) > 0 {
		sort.Strings(unexpected)
		return nil, unixrpc.NewError("invalid", "unexpected request fields: "+strings.Join(unexpected, ", "))
	}

	switch action {
	case "status":
		return s.statusResponse(req), nil
	case "stage_backup":
		return s.StageBackup(req)
	case "start_backup":
		return s.StartBackup(ctx, req)
	case "start_inspect":
		return s.StartInspect(ctx, req)
	case "run_scheduled":
		return s.RunScheduled(ctx)
	case "destinations":
		return s.listDestinations(), nil
	case "destination_save":
		return s.saveDestination(req)
	case "destination_delete":
		return s.deleteDestination(req)
	case "schedule":
		return s.scheduleStatus(), nil
	case "schedule_save":
		return s.saveSchedule(req)
	case "delete":
		return s.deleteItem(req)
	default:
		if s.rebootScheduled() {
			return nil, unixrpc.NewError("conflict", "a server reboot is scheduled")
		}
		return nil, unixrpc.NewError("invalid", fmt.Sprintf("action %q is not yet enabled", action))
	}
}

func (s *Service) storageSummary() map[string]any {
	u, err := statFilesystem(s.Opts.SpoolRoot)
	low := false
	belowMin := false
	if err == nil && u.TotalBytes > 0 {
		belowMin = u.AvailBytes < s.Opts.MinFreeBytes
		low = u.AvailBytes < s.Opts.LowSpaceBytes || float64(u.AvailBytes)/float64(u.TotalBytes) < 0.10
	}
	return map[string]any{
		"total_bytes":     u.TotalBytes,
		"free_bytes":      u.FreeBytes,
		"available_bytes": u.AvailBytes,
		"low_space":       low,
		"below_min_free":  belowMin,
	}
}

func (s *Service) listLocalBackups() []map[string]any {
	entries, err := os.ReadDir(s.Opts.BackupsDir())
	if err != nil {
		return []map[string]any{}
	}
	out := make([]map[string]any, 0)
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ArchiveSuffix) {
			continue
		}
		id := strings.TrimSuffix(ent.Name(), ArchiveSuffix)
		if !IdentifierRe.MatchString(id) {
			continue
		}
		item := map[string]any{"id": id, "filename": ent.Name()}
		if fi, err := ent.Info(); err == nil {
			item["size_bytes"] = fi.Size()
			item["mtime"] = fi.ModTime().UTC().Format(time.RFC3339)
		}
		if raw, err := os.ReadFile(filepath.Join(s.Opts.BackupsDir(), id+MetaSuffix)); err == nil {
			var meta map[string]any
			if json.Unmarshal(raw, &meta) == nil {
				item["metadata"] = meta
			}
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		mi, _ := out[i]["mtime"].(string)
		mj, _ := out[j]["mtime"].(string)
		return mi > mj
	})
	if s.Opts.ListLimit > 0 && len(out) > s.Opts.ListLimit {
		out = out[:s.Opts.ListLimit]
	}
	return out
}

func (s *Service) listJobs() []map[string]any {
	entries, err := os.ReadDir(s.Opts.JobsDir())
	if err != nil {
		return []map[string]any{}
	}
	out := make([]map[string]any, 0)
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(s.Opts.JobsDir(), ent.Name()))
		if err != nil {
			continue
		}
		var job map[string]any
		if json.Unmarshal(raw, &job) == nil {
			out = append(out, job)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		ci, _ := out[i]["created_at"].(string)
		cj, _ := out[j]["created_at"].(string)
		return ci > cj
	})
	if s.Opts.ListLimit > 0 && len(out) > s.Opts.ListLimit {
		out = out[:s.Opts.ListLimit]
	}
	return out
}

func (s *Service) statusResponse(req map[string]any) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	res := map[string]any{
		"ok":               true,
		"backups":          s.listLocalBackups(),
		"jobs":             s.listJobs(),
		"storage":          s.storageSummary(),
		"reboot_scheduled": s.rebootScheduled(),
	}
	if jid, ok := req["job_id"].(string); ok && IdentifierRe.MatchString(jid) {
		if raw, err := os.ReadFile(filepath.Join(s.Opts.JobsDir(), jid+".json")); err == nil {
			var job map[string]any
			if json.Unmarshal(raw, &job) == nil {
				res["job"] = job
			}
		}
	}
	return res
}

func (s *Service) readDestinationsLocked() map[string]map[string]any {
	dests := map[string]map[string]any{}
	if raw, err := os.ReadFile(s.Opts.DestinationsPath()); err == nil {
		_ = json.Unmarshal(raw, &dests)
	}
	return dests
}

func redactDestination(d map[string]any) map[string]any {
	cp := make(map[string]any, len(d))
	for k, v := range d {
		switch k {
		case "private_key", "secret_key", "passphrase":
			if str, _ := v.(string); str != "" {
				cp[k] = "***"
			} else {
				cp[k] = ""
			}
		default:
			cp[k] = v
		}
	}
	return cp
}

func (s *Service) listDestinations() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	dests := s.readDestinationsLocked()
	names := make([]string, 0, len(dests))
	for k := range dests {
		names = append(names, k)
	}
	sort.Strings(names)
	out := make([]map[string]any, 0, len(names))
	for _, n := range names {
		out = append(out, redactDestination(dests[n]))
	}
	return map[string]any{"ok": true, "destinations": out}
}

func (s *Service) saveDestination(req map[string]any) (map[string]any, error) {
	name, _ := req["name"].(string)
	if !DestNameRe.MatchString(name) {
		return nil, unixrpc.NewError("invalid", "invalid destination name")
	}
	dtype, _ := req["type"].(string)
	if dtype != "sftp" && dtype != "s3" {
		return nil, unixrpc.NewError("invalid", "destination type must be sftp or s3")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dests := s.readDestinationsLocked()
	prev := dests[name]

	entry := map[string]any{"name": name, "type": dtype, "updated_at": time.Now().UTC().Format(time.RFC3339)}
	for k, v := range req {
		if k == "action" {
			continue
		}
		if (k == "private_key" || k == "secret_key" || k == "passphrase") && v == "***" && prev != nil {
			entry[k] = prev[k]
			continue
		}
		entry[k] = v
	}
	dests[name] = entry
	data, err := json.MarshalIndent(dests, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeAtomic(s.Opts.DestinationsPath(), append(data, '\n'), 0o600); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "destination": redactDestination(entry)}, nil
}

func (s *Service) deleteDestination(req map[string]any) (map[string]any, error) {
	name, _ := req["name"].(string)
	if !DestNameRe.MatchString(name) {
		return nil, unixrpc.NewError("invalid", "invalid destination name")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dests := s.readDestinationsLocked()
	if _, exists := dests[name]; !exists {
		return nil, unixrpc.NewError("not_found", "destination not found")
	}
	delete(dests, name)
	data, _ := json.MarshalIndent(dests, "", "  ")
	if err := writeAtomic(s.Opts.DestinationsPath(), append(data, '\n'), 0o600); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "deleted": name}, nil
}

func (s *Service) scheduleStatus() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	sched := map[string]any{"enabled": false, "cadence": "daily", "hour": 3, "minute": 0, "keep_local": 5}
	if raw, err := os.ReadFile(s.Opts.SchedulePath()); err == nil {
		var loaded map[string]any
		if json.Unmarshal(raw, &loaded) == nil {
			for k, v := range loaded {
				sched[k] = v
			}
		}
	}
	return map[string]any{"ok": true, "schedule": redactDestination(sched)}
}

func (s *Service) saveSchedule(req map[string]any) (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := map[string]any{}
	if raw, err := os.ReadFile(s.Opts.SchedulePath()); err == nil {
		_ = json.Unmarshal(raw, &prev)
	}
	next := map[string]any{"updated_at": time.Now().UTC().Format(time.RFC3339)}
	for k, v := range req {
		if k == "action" {
			continue
		}
		if k == "passphrase" && v == "***" {
			next[k] = prev[k]
			continue
		}
		next[k] = v
	}
	data, _ := json.MarshalIndent(next, "", "  ")
	if err := writeAtomic(s.Opts.SchedulePath(), append(data, '\n'), 0o600); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "schedule": redactDestination(next)}, nil
}

func (s *Service) deleteItem(req map[string]any) (map[string]any, error) {
	if s.rebootScheduled() {
		return nil, unixrpc.NewError("conflict", "a server reboot is scheduled")
	}
	kind, _ := req["kind"].(string)
	id, _ := req["id"].(string)
	if !IdentifierRe.MatchString(id) {
		return nil, unixrpc.NewError("invalid", "invalid backup identifier")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch kind {
	case "backup":
		arch := filepath.Join(s.Opts.BackupsDir(), id+ArchiveSuffix)
		if _, err := os.Stat(arch); err != nil {
			return nil, unixrpc.NewError("not_found", "backup archive not found")
		}
		_ = os.Remove(arch)
		_ = os.Remove(filepath.Join(s.Opts.BackupsDir(), id+ChecksumSuffix))
		_ = os.Remove(filepath.Join(s.Opts.BackupsDir(), id+MetaSuffix))
		return map[string]any{"ok": true, "deleted": id}, nil
	case "upload":
		arch := filepath.Join(s.Opts.UploadsDir(), id+ArchiveSuffix)
		if _, err := os.Stat(arch); err != nil {
			return nil, unixrpc.NewError("not_found", "uploaded archive not found")
		}
		_ = os.Remove(arch)
		_ = os.Remove(filepath.Join(s.Opts.UploadsDir(), id+MetaSuffix))
		return map[string]any{"ok": true, "deleted": id}, nil
	default:
		return nil, unixrpc.NewError("invalid", "kind must be backup or upload")
	}
}

func writeAtomic(target string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(target)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(target)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	_ = tmp.Chmod(mode)
	_ = tmp.Sync()
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, target); err != nil {
		cleanup()
		return err
	}
	return nil
}

// Run starts the backupd AF_UNIX JSON-line RPC server until SIGTERM/SIGINT.
func Run(opts Options) error {
	svc, err := NewService(opts)
	if err != nil {
		return err
	}
	srv := unixrpc.NewServer(opts.AppUID, opts.MaxRequestBytes, 2*1024*1024, opts.MaxConnections, svc.Dispatch)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	log.Printf("easy-ha-proxy-backupd (Go) listening on %s spool=%s", opts.SocketPath, opts.SpoolRoot)
	return srv.ListenAndServe(ctx, opts.SocketPath, 0o600)
}
