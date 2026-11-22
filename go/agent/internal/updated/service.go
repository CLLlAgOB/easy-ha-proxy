package updated

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/exec"
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

// Service implements the update broker JSON-line RPC protocol.
type Service struct {
	mu     sync.Mutex
	Opts   Options
	Alerts *alerts.Client
}

// NewService initializes state directories and recovers any interrupted jobs.
func NewService(opts Options) (*Service, error) {
	for _, d := range []string{opts.StateRoot, opts.JobsDir()} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return nil, err
		}
	}
	s := &Service{Opts: opts, Alerts: alerts.FromEnv()}
	s.RecoverStaleJobs()
	return s, nil
}

// RecoverStaleJobs marks orphaned queued/running jobs as interrupted after a broker restart.
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
			job["error"] = "update broker restarted while job was active"
			job["finished_at"] = time.Now().UTC().Format(time.RFC3339)
			if data, err := json.MarshalIndent(job, "", "  "); err == nil {
				_ = writeAtomic(p, append(data, '\n'), 0o600)
				recovered++
			}
		}
	}
	return recovered
}

func (s *Service) bootID() string {
	raw, err := os.ReadFile(s.Opts.BootIDPath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.ToLower(string(raw)))
}

func (s *Service) readSettingsLocked() map[string]any {
	settings := map[string]any{
		"auto_check_hours": s.Opts.AutoCheckHours,
		"auto_reboot":      false,
		"service_restarts": true,
	}
	if raw, err := os.ReadFile(s.Opts.SettingsPath()); err == nil {
		var loaded map[string]any
		if json.Unmarshal(raw, &loaded) == nil {
			for k, v := range loaded {
				settings[k] = v
			}
		}
	}
	return settings
}

func (s *Service) writeSettingsLocked(settings map[string]any) error {
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(s.Opts.SettingsPath(), append(data, '\n'), 0o600)
}

func (s *Service) rebootState() map[string]any {
	if raw, err := os.ReadFile(s.Opts.RebootMarker); err == nil {
		var m map[string]any
		if json.Unmarshal(raw, &m) == nil {
			m["scheduled"] = true
			return m
		}
	}
	if _, err := os.Lstat(s.Opts.AssistantRebootMarker); err == nil {
		return map[string]any{"scheduled": true, "source": "assistant"}
	}
	return map[string]any{"scheduled": false}
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
			if logStr, ok := job["log"].(string); ok && logStr != "" {
				job["progress"] = ParseProgress(logStr)
			}
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

// Dispatch enforces REQUEST_FIELDS whitelists and routes update broker actions.
func (s *Service) Dispatch(ctx context.Context, req map[string]any) (map[string]any, error) {
	action, _ := req["action"].(string)
	allowed, ok := RequestFields[action]
	if !ok {
		return nil, unixrpc.NewError("invalid", "unknown update broker action")
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
	case "summary":
		return s.summaryResponse(), nil
	case "start_check":
		return s.StartCheck(ctx, req)
	case "start_apply":
		return s.StartApply(ctx, req)
	case "set_settings":
		return s.setSettings(req)
	case "set_auto_reboot":
		return s.setBoolSetting("auto_reboot", req)
	case "set_service_restarts":
		return s.setBoolSetting("service_restarts", req)
	case "reboot":
		return s.requestReboot(ctx, req)
	case "cancel_reboot":
		return s.cancelReboot(ctx, req)
	case "ssh_protection_monitor":
		return s.setSSHMonitor(req)
	case "ssh_protection_unban":
		return s.validateSSHUnban(req)
	default:
		return nil, unixrpc.NewError("invalid", fmt.Sprintf("action %q requires update runner execution", action))
	}
}

func (s *Service) statusResponse(req map[string]any) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	res := map[string]any{
		"ok":               true,
		"protocol_version": ProtocolVersion,
		"boot_id":          s.bootID(),
		"settings":         s.readSettingsLocked(),
		"reboot":           s.rebootState(),
		"jobs":             s.listJobs(),
	}
	if raw, err := os.ReadFile(s.Opts.LatestPlanPath()); err == nil {
		var plan map[string]any
		if json.Unmarshal(raw, &plan) == nil {
			res["plan"] = plan
		}
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

func (s *Service) summaryResponse() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	var version string
	if raw, err := os.ReadFile(filepath.Join(s.Opts.SourceDir, "VERSION")); err == nil {
		version = strings.TrimSpace(string(raw))
	}
	return map[string]any{
		"ok":               true,
		"protocol_version": ProtocolVersion,
		"version":          version,
		"boot_id":          s.bootID(),
		"reboot":           s.rebootState(),
		"settings":         s.readSettingsLocked(),
	}
}

func (s *Service) setSettings(req map[string]any) (map[string]any, error) {
	hoursFloat, ok := req["auto_check_hours"].(float64)
	if !ok {
		return nil, unixrpc.NewError("invalid", "auto_check_hours must be an integer")
	}
	hours := int(hoursFloat)
	if _, valid := AutoCheckChoices[hours]; !valid {
		return nil, unixrpc.NewError("invalid", "unsupported auto_check_hours interval")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	settings := s.readSettingsLocked()
	settings["auto_check_hours"] = hours
	if err := s.writeSettingsLocked(settings); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "settings": settings}, nil
}

func (s *Service) setBoolSetting(key string, req map[string]any) (map[string]any, error) {
	val, ok := req["enabled"].(bool)
	if !ok {
		return nil, unixrpc.NewError("invalid", "enabled must be boolean")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	settings := s.readSettingsLocked()
	settings[key] = val
	if err := s.writeSettingsLocked(settings); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "settings": settings}, nil
}

func (s *Service) requestReboot(ctx context.Context, req map[string]any) (map[string]any, error) {
	conf, _ := req["confirmation"].(string)
	if conf != "REBOOT" {
		return nil, unixrpc.NewError("invalid", "reboot confirmation must be REBOOT")
	}
	actor, _ := req["actor"].(string)
	if actor != "" && !ActorRe.MatchString(actor) {
		return nil, unixrpc.NewError("invalid", "invalid actor")
	}
	curBoot := s.bootID()
	if expected, _ := req["expected_boot_id"].(string); expected != "" && curBoot != "" && expected != curBoot {
		return nil, unixrpc.NewError("conflict", "host boot_id changed; reload before rebooting")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Opts.ShutdownBin != "" {
		cmdCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if out, err := exec.CommandContext(cmdCtx, s.Opts.ShutdownBin, "-r", "+1", "Scheduled via easy-ha-proxy").CombinedOutput(); err != nil {
			return nil, unixrpc.NewError("internal", fmt.Sprintf("shutdown failed: %s", strings.TrimSpace(string(out))))
		}
	}
	marker := map[string]any{
		"scheduled":    true,
		"scheduled_at": time.Now().UTC().Format(time.RFC3339),
		"boot_id":      curBoot,
		"actor":        actor,
	}
	data, _ := json.MarshalIndent(marker, "", "  ")
	if err := os.MkdirAll(filepath.Dir(s.Opts.RebootMarker), 0o750); err != nil {
		return nil, err
	}
	if err := writeAtomic(s.Opts.RebootMarker, append(data, '\n'), 0o600); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "reboot": marker}, nil
}

func (s *Service) cancelReboot(ctx context.Context, _ map[string]any) (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Opts.ShutdownBin != "" {
		cmdCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		_ = exec.CommandContext(cmdCtx, s.Opts.ShutdownBin, "-c").Run()
	}
	_ = os.Remove(s.Opts.RebootMarker)
	return map[string]any{"ok": true, "reboot": map[string]any{"scheduled": false}}, nil
}

func (s *Service) setSSHMonitor(req map[string]any) (map[string]any, error) {
	enabled, ok := req["enabled"].(bool)
	if !ok {
		return nil, unixrpc.NewError("invalid", "Invalid SSH monitoring setting")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, _ := json.MarshalIndent(map[string]any{"enabled": enabled}, "", "  ")
	if err := writeAtomic(s.Opts.SSHProtectionMonitorPath, append(data, '\n'), 0o600); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "enabled": enabled}, nil
}

func (s *Service) validateSSHUnban(req map[string]any) (map[string]any, error) {
	rawIP, _ := req["ip"].(string)
	if len(rawIP) < 1 || len(rawIP) > 64 || strings.Contains(rawIP, "%") {
		return nil, unixrpc.NewError("invalid", "Invalid IP address")
	}
	addr, err := netip.ParseAddr(rawIP)
	if err != nil {
		return nil, unixrpc.NewError("invalid", "Invalid IP address")
	}
	return map[string]any{"ok": true, "ip": addr.String()}, nil
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

// Run starts the updated AF_UNIX JSON-line RPC server until SIGTERM/SIGINT.
func Run(opts Options) error {
	svc, err := NewService(opts)
	if err != nil {
		return err
	}
	srv := unixrpc.NewServer(opts.AppUID, opts.MaxRequestBytes, opts.MaxResponseBytes, opts.MaxConnections, svc.Dispatch)
	srv.SocketUser = opts.SocketUser
	srv.SocketGroup = opts.SocketGroup
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	log.Printf("easy-ha-proxy-updated (Go) listening on %s state=%s", opts.SocketPath, opts.StateRoot)
	return srv.ListenAndServe(ctx, opts.SocketPath, 0o660)
}
