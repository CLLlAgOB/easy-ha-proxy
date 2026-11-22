package updated

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/alerts"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/unixrpc"
)

const planTTLSeconds = 15 * 60

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
	raw, err := json.MarshalIndent(job, "", "  ")
	if err != nil {
		return
	}
	_ = writeAtomic(filepath.Join(s.Opts.JobsDir(), id+".json"), append(raw, '\n'), 0o600)
}

func (s *Service) haproxyTransactionActive() bool {
	if s.Opts.HAProxyTransactionState == "" {
		return false
	}
	raw, err := os.ReadFile(s.Opts.HAProxyTransactionState)
	if err != nil {
		return false
	}
	var st struct {
		State string `json:"state"`
	}
	if json.Unmarshal(raw, &st) != nil {
		return false
	}
	switch st.State {
	case "prepared", "pending_confirmation", "rolling_back", "rollback_failed":
		return true
	default:
		return false
	}
}

func (s *Service) reportAlert(ctx context.Context, rule, subject string, active *bool, summary, detail string) {
	if s.Alerts != nil && s.Alerts.Enabled() {
		s.Alerts.Observe(ctx, alerts.Observation{
			Rule:    rule,
			Subject: subject,
			Active:  active,
			Summary: summary,
			Detail:  detail,
		})
	}
}

// StartCheck runs the read-only update checker command and persists latest-plan.json.
func (s *Service) StartCheck(ctx context.Context, req map[string]any) (map[string]any, error) {
	if s.haproxyTransactionActive() {
		return nil, unixrpc.NewError("conflict", "an active HAProxy config transaction blocks update checks")
	}
	lockFile, err := tryLockMaintenance(s.Opts.MaintenanceLockPath)
	if err != nil {
		return nil, unixrpc.NewError("conflict", "another maintenance operation is already running")
	}
	defer unlockMaintenance(lockFile)

	jobID := randomHex32()
	now := time.Now().UTC()
	job := map[string]any{
		"id":         jobID,
		"kind":       "check",
		"status":     "running",
		"created_at": now.Format(time.RFC3339),
	}
	s.saveJob(job)

	args := []string{"update", "--check", "--json"}
	if ch, _ := req["release_channel"].(string); ch != "" {
		args = append(args, "--channel", ch)
	}
	cmdCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(cmdCtx, s.Opts.CLIPath, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = err.Error()
		}
		job["status"] = "failed"
		job["error"] = detail
		job["finished_at"] = time.Now().UTC().Format(time.RFC3339)
		s.saveJob(job)
		return nil, unixrpc.NewError("internal", detail)
	}

	var plan map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &plan); err != nil || plan == nil {
		plan = map[string]any{"raw": strings.TrimSpace(stdout.String())}
	}
	planID := randomHex32()
	plan["plan_id"] = planID
	plan["created_at"] = now.Format(time.RFC3339)
	plan["expires_at"] = now.Add(planTTLSeconds * time.Second).Unix()
	if rawPlan, err := json.MarshalIndent(plan, "", "  "); err == nil {
		_ = writeAtomic(s.Opts.LatestPlanPath(), append(rawPlan, '\n'), 0o600)
	}

	if avail, _ := plan["updates_available"].(bool); avail {
		s.reportAlert(ctx, "update.available", "gateway", alerts.BoolPtr(true), "Software updates are available", "")
	} else {
		s.reportAlert(ctx, "update.available", "gateway", alerts.BoolPtr(false), "Gateway is up to date", "")
	}

	job["status"] = "completed"
	job["plan_id"] = planID
	job["finished_at"] = time.Now().UTC().Format(time.RFC3339)
	s.saveJob(job)
	return map[string]any{"ok": true, "job_id": jobID, "plan": plan}, nil
}

// StartApply validates plan_id, components, and confirmation, then executes the update CLI.
func (s *Service) StartApply(ctx context.Context, req map[string]any) (map[string]any, error) {
	if s.rebootState()["scheduled"] == true {
		return nil, unixrpc.NewError("conflict", "a server reboot is scheduled")
	}
	if s.haproxyTransactionActive() {
		return nil, unixrpc.NewError("conflict", "an active HAProxy config transaction blocks software updates")
	}
	planID, _ := req["plan_id"].(string)
	if !IdentifierRe.MatchString(planID) {
		return nil, unixrpc.NewError("invalid", "invalid plan_id")
	}
	rawComps, ok := req["components"].([]any)
	if !ok || len(rawComps) == 0 {
		return nil, unixrpc.NewError("invalid", "at least one component is required")
	}
	components := make([]string, 0, len(rawComps))
	for _, c := range rawComps {
		name, _ := c.(string)
		if _, valid := AllowedComponents[name]; !valid {
			return nil, unixrpc.NewError("invalid", fmt.Sprintf("unsupported component: %q", name))
		}
		components = append(components, name)
	}

	// Verify plan exists, matches plan_id, and is not expired.
	rawPlan, err := os.ReadFile(s.Opts.LatestPlanPath())
	if err != nil {
		return nil, unixrpc.NewError("conflict", "no active update plan; run check first")
	}
	var plan map[string]any
	if err := json.Unmarshal(rawPlan, &plan); err != nil {
		return nil, unixrpc.NewError("conflict", "stored update plan is unreadable")
	}
	if plan["plan_id"] != planID {
		return nil, unixrpc.NewError("conflict", "plan_id does not match latest plan")
	}
	if exp, ok := plan["expires_at"].(float64); ok && int64(exp) < time.Now().Unix() {
		return nil, unixrpc.NewError("conflict", "update plan has expired; run check again")
	}

	lockFile, err := tryLockMaintenance(s.Opts.MaintenanceLockPath)
	if err != nil {
		return nil, unixrpc.NewError("conflict", "another maintenance operation is already running")
	}
	defer unlockMaintenance(lockFile)

	jobID := randomHex32()
	job := map[string]any{
		"id":         jobID,
		"kind":       "apply",
		"plan_id":    planID,
		"components": components,
		"status":     "running",
		"created_at": time.Now().UTC().Format(time.RFC3339),
	}
	s.saveJob(job)

	args := append([]string{"update", "--apply"}, components...)
	cmdCtx, cancel := context.WithTimeout(ctx, 2*time.Hour)
	defer cancel()
	var combined bytes.Buffer
	cmd := exec.CommandContext(cmdCtx, s.Opts.CLIPath, args...)
	cmd.Stdout = &combined
	cmd.Stderr = &combined
	err = cmd.Run()

	logText := combined.String()
	if len(logText) > 256*1024 {
		logText = logText[len(logText)-256*1024:]
	}
	job["log"] = logText
	job["progress"] = ParseProgress(logText)
	job["finished_at"] = time.Now().UTC().Format(time.RFC3339)
	if err != nil {
		job["status"] = "failed"
		job["error"] = err.Error()
		s.saveJob(job)
		s.reportAlert(ctx, "update.failed", "gateway", nil, "Software update failed", err.Error())
		return map[string]any{"ok": false, "job_id": jobID, "job": job, "error": err.Error()}, nil
	}
	job["status"] = "completed"
	s.saveJob(job)
	return map[string]any{"ok": true, "job_id": jobID, "job": job}, nil
}
