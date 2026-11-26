package updated

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/alerts"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/pyx"
)

// ---------------------------------------------------------------------------
// HAProxy package migration
// ---------------------------------------------------------------------------

func (d *Daemon) haproxyOperation() map[string]any {
	ops := []map[string]any{}
	for _, p := range []string{d.Opts.HAProxyUpdateState, d.Opts.HAProxyMigrationState} {
		if op := readHAProxyOperation(p); op != nil {
			ops = append(ops, op)
		}
	}
	key := func(op map[string]any) (bool, float64) {
		phase, _ := op["phase"].(string)
		updated, _ := pyx.Number(op["updated_at"])
		return !haproxySettledPhases[phase], updated
	}
	sort.SliceStable(ops, func(i, j int) bool {
		ui, ti := key(ops[i])
		uj, tj := key(ops[j])
		if ui != uj {
			return ui
		}
		return ti > tj
	})
	if len(ops) == 0 {
		return nil
	}
	return ops[0]
}

func (d *Daemon) haproxyPatchActive() bool {
	for _, p := range []string{d.Opts.HAProxyUpdateState, d.Opts.HAProxyMigrationState} {
		op := readHAProxyOperation(p)
		if op == nil {
			if lexists(p) {
				return true
			}
		} else if phase, _ := op["phase"].(string); !haproxySettledPhases[phase] {
			return true
		}
	}
	return false
}

func (d *Daemon) toolBytes(name, missing string, markers ...string) (string, []byte, error) {
	tool, err := d.trustedSource(name)
	if err != nil {
		return "", nil, err
	}
	fi, err := os.Stat(tool)
	if err != nil {
		return "", nil, err
	}
	if fi.Size() > 1024*1024 {
		return "", nil, uErr("dependency", "%s", missing)
	}
	raw, err := os.ReadFile(tool)
	if err != nil {
		return "", nil, err
	}
	for _, m := range markers {
		if !bytes.Contains(raw, []byte(m)) {
			return "", nil, uErr("dependency", "%s", missing)
		}
	}
	return tool, raw, nil
}

func (d *Daemon) migrationToolDigest() (string, error) {
	_, raw, err := d.toolBytes("haproxy_package_migrate.py", "Update host services before preparing a HAProxy migration",
		"WEB_MIGRATION_PROTOCOL = 1")
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func (d *Daemon) migrationOffer(plan map[string]any) map[string]any {
	result := func(state, reason string) map[string]any {
		return map[string]any{"target_branch": "3.4", "state": state, "reason": reason}
	}
	if _, err := d.migrationToolDigest(); err != nil {
		return result("blocked", "Update host services before preparing a HAProxy migration")
	}
	if plan == nil || planIsExpired(plan) {
		return result("check_required", "Check for updates before preparing a HAProxy migration")
	}
	m, _ := planComponentMap(plan)
	details := pyx.Map(m["haproxy"]["details"])
	if details["branch"] == "3.4" && details["binary_matches"] == true {
		return result("blocked", "HAProxy 3.4 is already installed; use updates within its branch")
	}
	if details["qualified"] != true {
		return result("blocked", "Migration requires Ubuntu 24.04 on AMD64 or ARM64")
	}
	if details["package"] != "haproxy" || !strings.HasPrefix(pyx.StrOr(details["installed_version"]), "2.8.") ||
		!strings.HasPrefix(pyx.StrOr(details["running_version"]), "2.8.") || details["binary_matches"] != true {
		return result("blocked", "Migration requires a verified distribution HAProxy 2.8 installation")
	}
	return result("available", "Prepare and review the transition from HAProxy 2.8 to 3.4 LTS")
}

func migrationFingerprint(op map[string]any) string {
	material := map[string]any{}
	for _, k := range []string{"id", "kind", "architecture", "created_at", "engine_digest", "old_version",
		"target_runtime_version", "target_packages", "extra_packages"} {
		material[k] = op[k]
	}
	sum := sha256.Sum256(pyx.Compact(material, true))
	return hex.EncodeToString(sum[:])
}

func (d *Daemon) migrationReview(requireFresh bool) (map[string]any, error) {
	if !lexists(d.Opts.MigrationPlanPath()) {
		if requireFresh {
			return nil, uErr("stale_plan", "Prepare a new HAProxy migration plan first")
		}
		return nil, nil
	}
	plan, err := d.safeJSONFile(d.Opts.MigrationPlanPath())
	if err != nil {
		return nil, err
	}
	if _, err := identifier(plan["id"], "migration plan id"); err != nil {
		return nil, err
	}
	if _, err := identifier(plan["transaction_id"], "migration transaction id"); err != nil {
		return nil, err
	}
	op := readHAProxyOperation(d.Opts.HAProxyMigrationState)
	fresh := !planIsExpired(plan) && !pyx.Truthy(plan["consumed_by"]) && op != nil && op["kind"] == "migration" &&
		op["phase"] == "prepared" && op["id"] == plan["transaction_id"] && migrationFingerprint(op) == plan["fingerprint"]
	if fresh {
		digest, err := d.migrationToolDigest()
		if err != nil {
			return nil, err
		}
		fresh = digest == plan["source_digest"]
	}
	if requireFresh && !fresh {
		return nil, uErr("stale_plan", "The HAProxy migration plan is stale; prepare it again")
	}
	out := pyx.Copy(plan)
	out["stale"] = !fresh
	return out, nil
}

func publicMigrationOperation(op map[string]any) any {
	if op == nil {
		return nil
	}
	result := map[string]any{}
	for _, k := range []string{"id", "phase", "old_version", "architecture", "target_runtime_version",
		"target_verified", "rollback_verified", "updated_at"} {
		result[k] = op[k]
	}
	pkgs := func(key string) []any {
		out := []any{}
		for i, p := range pyx.List(op[key]) {
			if i >= 8 {
				break
			}
			if m := pyx.Map(p); m != nil {
				out = append(out, map[string]any{"name": pyx.TruncRunes(pyx.StrOr(pyx.Get(m, "Package", "")), 80),
					"version": pyx.TruncRunes(pyx.StrOr(pyx.Get(m, "Version", "")), 120)})
			}
		}
		return out
	}
	result["packages"] = pkgs("target_packages")
	result["dependencies"] = pkgs("extra_packages")
	return result
}

func (d *Daemon) migrationStatus(plan map[string]any) map[string]any {
	offer := d.migrationOffer(plan)
	recoveryBlocked := d.haproxyPatchActive()
	if recoveryBlocked {
		offer["state"] = "blocked"
		offer["reason"] = "HAProxy update or recovery is in progress. Other maintenance is blocked."
	}
	op := readHAProxyOperation(d.Opts.HAProxyMigrationState)
	review, err := d.migrationReview(false)
	if err != nil {
		review = nil
	}
	var public any
	if review != nil {
		p := map[string]any{}
		for _, k := range []string{"id", "transaction_id", "expires_at", "stale", "consumed_by"} {
			p[k] = review[k]
		}
		p["stale"] = pyx.Truthy(p["stale"]) || recoveryBlocked
		p["operation"] = publicMigrationOperation(op)
		public = p
	}
	offer["plan"] = public
	offer["last_operation"] = publicMigrationOperation(op)
	offer["automatic"] = d.automaticMigrationOffer(plan, op, recoveryBlocked)
	return offer
}

func migrationPlatformSupported() bool {
	raw, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return false
	}
	release := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			release[k] = strings.Trim(v, `"`)
		}
	}
	return release["ID"] == "ubuntu" && release["VERSION_ID"] == "24.04" && (runtime.GOARCH == "arm64" || runtime.GOARCH == "amd64")
}

func (d *Daemon) automaticMigrationTool() (string, error) {
	if _, err := d.migrationToolDigest(); err != nil {
		return "", err
	}
	tool, _, err := d.toolBytes("haproxy_package_migrate.py", "Update host services before using the automatic HAProxy transition",
		"AUTOMATIC_MIGRATION_PROTOCOL = 1")
	if err != nil {
		return "", err
	}
	if _, err := d.trustedSource("apt_metadata.py"); err != nil {
		return "", err
	}
	return tool, nil
}

func (d *Daemon) automaticMigrationOffer(plan, op map[string]any, recoveryBlocked bool) map[string]any {
	result := func(can, current bool, reason string) map[string]any {
		return map[string]any{"can_start": can, "current": current, "reason": reason}
	}
	if _, err := d.automaticMigrationTool(); err != nil {
		return result(false, false, "Update host services before using the automatic HAProxy transition")
	}
	if recoveryBlocked {
		return result(false, false, "HAProxy update or recovery is in progress. Other maintenance is blocked.")
	}
	if !migrationPlatformSupported() {
		return result(false, false, "Migration requires Ubuntu 24.04 on AMD64 or ARM64")
	}
	var details map[string]any
	if plan != nil {
		m, _ := planComponentMap(plan)
		details = pyx.Map(m["haproxy"]["details"])
	}
	var current bool
	if plan != nil && !planIsExpired(plan) && details["binary_matches"] == true {
		current = details["branch"] == "3.4"
	} else {
		current = op != nil && op["phase"] == "committed" && op["target_verified"] == true
	}
	if current {
		return result(false, true, "HAProxy 3.4 is already installed; use updates within its branch")
	}
	return result(true, false, "Configuration checks, package preparation and the transition run automatically after confirmation.")
}

func (d *Daemon) migrationWorker(jobID string, lock *os.File, review map[string]any, automatic bool) {
	logText := ""
	defer func() {
		_ = os.Remove(d.Opts.ActiveMarker)
		d.releaseOperation(lock)
	}()
	err := func() error {
		if d.haproxyTransactionActive() {
			return uErr("config_pending", "Resolve pending HAProxy configuration changes before migration")
		}
		phase := "starting"
		if automatic {
			phase = "checking"
		} else if review == nil {
			phase = "prepare"
		}
		if _, err := d.updateJob(jobID, map[string]any{"status": "running", "started_at": pyx.UTCNow(),
			"current_component": "haproxy", "progress": map[string]any{"phase": phase}}); err != nil {
			return err
		}
		if err := os.WriteFile(d.Opts.ActiveMarker, []byte("job_id="+jobID+"\n"), 0o600); err != nil {
			return err
		}
		tool, err := d.trustedSource("haproxy_package_migrate.py")
		if err != nil {
			return err
		}
		command := []string{d.python(), tool}
		previous := readHAProxyOperation(d.Opts.HAProxyMigrationState)
		prevID := pyx.Map(anyMap(previous))["id"]
		switch {
		case automatic:
			if _, err := d.automaticMigrationTool(); err != nil {
				return err
			}
			_ = os.Remove(d.Opts.MigrationPlanPath())
			_ = os.Remove(d.Opts.LatestPlanPath())
			command = append(command, "migrate", "--web-progress")
		case review == nil:
			_ = os.Remove(d.Opts.MigrationPlanPath())
			command = append(command, "prepare", "--web-progress")
		default:
			op := readHAProxyOperation(d.Opts.HAProxyMigrationState)
			digest, derr := d.migrationToolDigest()
			if derr != nil {
				return derr
			}
			if op == nil || op["phase"] != "prepared" || migrationFingerprint(op) != review["fingerprint"] ||
				digest != review["source_digest"] || planIsExpired(review) {
				return uErr("stale_plan", "The HAProxy migration plan is stale; prepare it again")
			}
			_ = os.Remove(d.Opts.LatestPlanPath())
			command = append(command, "apply", "--id", pyx.Str(review["transaction_id"]), "--web-progress")
		}
		pyx.FlockRelease(lock)
		code, out, err := d.runCommand(jobID, command, d.Opts.JobTimeoutSeconds, "")
		if err != nil {
			return err
		}
		logText = out
		op := readHAProxyOperation(d.Opts.HAProxyMigrationState)
		digest, _ := d.migrationToolDigest()
		var message string
		if review == nil && !automatic {
			if code != 0 || op == nil || op["id"] == prevID || op["phase"] != "prepared" || op["kind"] != "migration" ||
				!strings.HasPrefix(pyx.StrOr(op["target_runtime_version"]), "3.4.") || op["engine_digest"] != digest {
				return uErr("verification_failed", "HAProxy migration preparation failed; review the job log")
			}
			txID, err := identifier(op["id"], "migration transaction id")
			if err != nil {
				return err
			}
			newReview := map[string]any{"id": pyx.UUIDHex(), "transaction_id": txID,
				"expires_at":  pyx.ISO(time.Now().UTC().Add(time.Duration(d.Opts.PlanTTLSeconds) * time.Second)),
				"fingerprint": migrationFingerprint(op), "source_digest": digest}
			if err := d.atomicJSON(d.Opts.MigrationPlanPath(), newReview); err != nil {
				return err
			}
			message = "HAProxy migration prepared; review the target version before confirming"
		} else {
			if op != nil {
				_, _ = d.updateJob(jobID, map[string]any{"result": map[string]any{"haproxy": publicMigrationOperation(op)}})
			}
			var wrong bool
			if automatic {
				wrong = op != nil && op["id"] == prevID
			} else {
				wrong = op == nil || op["id"] != review["transaction_id"]
			}
			if code != 0 || op == nil || wrong ||
				(automatic && (op["kind"] != "migration" || !strings.HasPrefix(pyx.StrOr(op["target_runtime_version"]), "3.4.") ||
					op["engine_digest"] != digest)) ||
				op["phase"] != "committed" || op["target_verified"] != true {
				return uErr("verification_failed", "HAProxy migration failed; review its recovery status and job log")
			}
			message = "HAProxy migration verified"
		}
		_, err = d.updateJob(jobID, map[string]any{"status": "completed", "completed_at": pyx.UTCNow(),
			"result": map[string]any{"message": message, "haproxy": publicMigrationOperation(op)},
			"output": map[string]any{"log": logText}})
		return err
	}()
	if err != nil {
		d.finishFailed(jobID, err, logText, true)
	}
}

func (d *Daemon) startHAProxyMigration(req map[string]any, apply bool) (map[string]any, error) {
	var planID string
	if apply {
		if req["confirmation"] != haproxyMigrationConfirmation {
			return nil, uErr("invalid", "Type MIGRATE 3.4 to confirm the HAProxy transition")
		}
		id, err := identifier(req["plan_id"], "migration plan id")
		if err != nil {
			return nil, err
		}
		planID = id
	} else if req["target_branch"] != "3.4" {
		return nil, uErr("invalid", "Only the qualified HAProxy 3.4 LTS migration is supported")
	}
	lock, err := d.acquireOperation(false, false)
	if err != nil {
		return nil, err
	}
	fail := func(e error) (map[string]any, error) {
		d.releaseOperation(lock)
		return nil, e
	}
	if d.haproxyTransactionActive() {
		return fail(uErr("config_pending", "Resolve pending HAProxy configuration changes before migration"))
	}
	var review map[string]any
	if apply {
		review, err = d.migrationReview(true)
		if err != nil {
			return fail(err)
		}
		if review["id"] != planID {
			return fail(uErr("stale_plan", "The HAProxy migration plan is stale; prepare it again"))
		}
	} else {
		plan, err := d.loadLatestPlan()
		if err != nil {
			return fail(err)
		}
		offer := d.migrationOffer(plan)
		if offer["state"] != "available" {
			return fail(uErr("dependency", "%s", pyx.Str(offer["reason"])))
		}
	}
	op := "haproxy-prepare"
	var planRef any
	if apply {
		op = "haproxy-migrate"
	}
	if review != nil {
		planRef = review["id"]
	}
	job, err := d.newJob(op, map[string]any{"components": []any{"haproxy"}, "plan_id": planRef})
	if err != nil {
		return fail(err)
	}
	if review != nil {
		consumed := pyx.Copy(review)
		consumed["consumed_by"] = job["id"]
		if err := d.atomicJSON(d.Opts.MigrationPlanPath(), consumed); err != nil {
			return fail(err)
		}
	}
	go d.migrationWorker(job["id"].(string), lock, review, false)
	return map[string]any{"ok": true, "job_id": job["id"], "job": publicJob(job, true)}, nil
}

func (d *Daemon) startHAProxyTransition(req map[string]any) (map[string]any, error) {
	if req["target_branch"] != "3.4" || req["confirmed"] != true {
		return nil, uErr("invalid", "Confirm the transition to HAProxy 3.4 LTS")
	}
	if _, err := d.automaticMigrationTool(); err != nil {
		return nil, err
	}
	if !migrationPlatformSupported() {
		return nil, uErr("dependency", "Migration requires Ubuntu 24.04 on AMD64 or ARM64")
	}
	lock, err := d.acquireOperation(false, false)
	if err != nil {
		return nil, err
	}
	if d.haproxyTransactionActive() {
		d.releaseOperation(lock)
		return nil, uErr("config_pending", "Resolve pending HAProxy configuration changes before migration")
	}
	job, err := d.newJob("haproxy-transition", map[string]any{"components": []any{"haproxy"}})
	if err != nil {
		d.releaseOperation(lock)
		return nil, err
	}
	go d.migrationWorker(job["id"].(string), lock, nil, true)
	return map[string]any{"ok": true, "job_id": job["id"], "job": publicJob(job, true)}, nil
}

// ---------------------------------------------------------------------------
// OS security, automatic reboots, service restarts
// ---------------------------------------------------------------------------

func (d *Daemon) osPath(name string) string { return filepath.Join(d.Opts.OSSecurityRoot(), name) }

func (d *Daemon) securityRecoveryPending() bool {
	path := d.osPath("policy.json")
	if !lexists(path) {
		return false
	}
	record, err := d.safeJSONFile(path)
	if err != nil {
		return true
	}
	if _, err := osSecurityPolicy(pyx.Map(record["policy"])); err != nil {
		return true
	}
	return record["phase"] != "ready"
}

func osSecurityPolicy(req map[string]any) (map[string]any, error) {
	mode, okMode := req["mode"].(string)
	interval, okInt := strictInt(req["interval"])
	start, okS := strictInt(req["start"])
	end, okE := strictInt(req["end"])
	validInterval := false
	for _, v := range osSecurityIntervals {
		if okInt && v == interval {
			validInterval = true
		}
	}
	if !okMode || !osSecurityModes[mode] || !validInterval || !okS || !okE || start < 0 || start > 23 ||
		end < 0 || end > 23 || start == end {
		return nil, uErr("invalid", "Invalid OS security policy")
	}
	return map[string]any{"mode": mode, "interval": interval, "start": start, "end": end}, nil
}

func defaultOSPolicy() map[string]any {
	return map[string]any{"mode": "system", "interval": int64(4), "start": int64(3), "end": int64(5)}
}

func (d *Daemon) hostAgentTool(subcommand, missing string) ([]string, error) {
	if !isRegular(agentBinary) {
		return nil, uErr("dependency", "%s", missing)
	}
	return []string{agentBinary, subcommand}, nil
}

func (d *Daemon) osSecurityCommand() ([]string, error) {
	return d.hostAgentTool("os-security", "Update host services before using OS security management")
}

func (d *Daemon) autoRebootCommand() ([]string, error) {
	return d.hostAgentTool("auto-reboot", "Update host services before configuring automatic reboots")
}

func (d *Daemon) serviceRestartCommand() ([]string, error) {
	return d.hostAgentTool("service-restarts", "Update host services before managing service restarts")
}

func (d *Daemon) autoRebootRecord() (map[string]any, error) {
	path := d.osPath("reboot-policy.json")
	if !lexists(path) {
		return map[string]any{"enabled": false, "time": "03:00", "id": nil, "updated_at": int64(0)}, nil
	}
	v, err := d.safeJSONFile(path)
	if err != nil {
		return nil, err
	}
	_, okEnabled := v["enabled"].(bool)
	t, okTime := v["time"].(string)
	_, okUpdated := pyx.Number(v["updated_at"])
	_, okAttempt := pyx.Get(v, "attempt", map[string]any{}).(map[string]any)
	_, okAllow := pyx.Get(v, "allow_service_reboot", false).(bool)
	if !okEnabled || !okTime || !autoRebootTimeRe.MatchString(t) || !identifierRe.MatchString(pyx.StrOr(pyx.Get(v, "id", ""))) ||
		!okUpdated || !okAttempt || !okAllow {
		return nil, uErr("conflict", "The automatic reboot policy is invalid")
	}
	return v, nil
}

func autoRebootWindow(local time.Time, text string) (time.Time, string) {
	h, _ := strconv.Atoi(text[:2])
	m, _ := strconv.Atoi(text[3:])
	anchor := time.Date(local.Year(), local.Month(), local.Day(), h, m, 0, 0, local.Location())
	if local.Before(anchor) {
		anchor = time.Date(local.Year(), local.Month(), local.Day()-1, h, m, 0, 0, local.Location())
	}
	return anchor, anchor.Format("2006-01-02") + " " + text
}

func (d *Daemon) serviceRestartRecord() (map[string]any, error) {
	unified, err := d.unifiedPolicy()
	if err != nil {
		return nil, err
	}
	if unified != nil {
		return mwRestartPolicy(unified), nil
	}
	path := d.osPath("restart-policy.json")
	if !lexists(path) {
		return map[string]any{"enabled": false, "time": "02:15", "id": nil, "updated_at": int64(0)}, nil
	}
	v, err := d.safeJSONFile(path)
	if err != nil {
		return nil, err
	}
	_, okEnabled := v["enabled"].(bool)
	t, okTime := v["time"].(string)
	_, okUpdated := pyx.Number(v["updated_at"])
	if !okEnabled || !okTime || !autoRebootTimeRe.MatchString(t) || !identifierRe.MatchString(pyx.StrOr(pyx.Get(v, "id", ""))) || !okUpdated {
		return nil, uErr("conflict", "The service restart policy is invalid")
	}
	return v, nil
}

func (d *Daemon) osSecurityLastInstall() (float64, error) {
	path := d.osPath("status.json")
	status := map[string]any{}
	if lexists(path) {
		if s, err := d.safeJSONFile(path); err == nil {
			status = s
		}
	}
	values := []float64{}
	for _, k := range []string{"last_install_at", "last_install_attempt"} {
		if f, ok := pyx.Number(status[k]); ok {
			values = append(values, f)
		}
	}
	pkg := d.osPath("package-install.json")
	if lexists(pkg) {
		rec, err := d.safeJSONFile(pkg)
		if err != nil {
			return 0, err
		}
		attempted, ok := pyx.Number(rec["last_install_attempt"])
		if !ok || !(attempted > 0) || math.IsInf(attempted, 1) {
			return 0, uErr("conflict", "The OS package installation record is invalid")
		}
		values = append(values, attempted)
	}
	best := 0.0
	for _, v := range values {
		if v > best {
			best = v
		}
	}
	return best, nil
}

func (d *Daemon) serviceRestartDue(value, status map[string]any, local time.Time, installedAt *float64) (bool, string, error) {
	anchor, key := autoRebootWindow(local, pyx.Str(value["time"]))
	var inst float64
	if installedAt != nil {
		inst = *installedAt
	} else {
		v, err := d.osSecurityLastInstall()
		if err != nil {
			return false, "", err
		}
		inst = v
	}
	boot, _ := d.currentBootID()
	same := status["policy_id"] == value["id"] && status["boot_id"] == boot
	retry := 300.0
	if status["state"] == "running" {
		retry = 900
	}
	done := status["policy_id"] == value["id"] && status["window"] == key && status["state"] == "ready" &&
		pyx.Truthy(status["applied"]) && pyx.Float(pyx.Get(status, "completed_at", 0)) >= inst
	ts := pyx.Timestamp(local)
	diff := ts - pyx.Timestamp(anchor)
	due := value["enabled"] == true && diff >= 0 && diff < 3600 && pyx.Float(value["updated_at"]) <= pyx.Timestamp(anchor) &&
		!done && (!same || ts-pyx.Float(pyx.Get(status, "last_attempt", 0)) >= retry)
	return due, key, nil
}

func (d *Daemon) serviceRestartSnapshot() map[string]any {
	result := map[string]any{"available": false, "enabled": false, "time": "02:15", "status": nil}
	err := func() error {
		if _, err := d.serviceRestartCommand(); err != nil {
			return err
		}
		result["available"] = true
		value, err := d.serviceRestartRecord()
		if err != nil {
			return err
		}
		for _, k := range []string{"enabled", "time", "updated_at"} {
			result[k] = value[k]
		}
		path := d.osPath("restart-status.json")
		status := map[string]any{}
		if lexists(path) {
			if status, err = d.safeJSONFile(path); err != nil {
				return err
			}
		}
		if len(status) > 0 {
			result["status"] = status
		} else {
			result["status"] = nil
		}
		if value["enabled"] == true {
			local := d.localTime()
			due, _, err := d.serviceRestartDue(value, status, local, nil)
			if err != nil {
				return err
			}
			var upcoming time.Time
			if due {
				upcoming = local
			} else {
				retry := 300.0
				if status["state"] == "running" {
					retry = 900
				}
				upcoming = pyx.FromTimestamp(math.Max(pyx.Timestamp(local), pyx.Float(pyx.Get(status, "last_attempt", 0))+retry), local.Location())
				ok, _, err := d.serviceRestartDue(value, status, upcoming, nil)
				if err != nil {
					return err
				}
				if !ok {
					t := pyx.Str(value["time"])
					h, _ := strconv.Atoi(t[:2])
					m, _ := strconv.Atoi(t[3:])
					upcoming = time.Date(local.Year(), local.Month(), local.Day(), h, m, 0, 0, local.Location())
					if !upcoming.After(local) {
						upcoming = time.Date(local.Year(), local.Month(), local.Day()+1, h, m, 0, 0, local.Location())
					}
				}
			}
			result["next_window"] = pyx.ISO(upcoming.In(local.Location()))
		}
		return nil
	}()
	if err != nil {
		result["error"] = err.Error()
	}
	return result
}

func (d *Daemon) setServiceRestarts(req map[string]any) (map[string]any, error) {
	bootID, actor, err := d.requestIdentity(req)
	if err != nil {
		return nil, err
	}
	enabled, okE := req["enabled"].(bool)
	t, okT := req["time"].(string)
	if !okE || !okT || !autoRebootTimeRe.MatchString(t) || req["confirmation"] != "SECURITY" {
		return nil, uErr("invalid", "Confirm a valid service restart policy")
	}
	if _, err := d.serviceRestartCommand(); err != nil {
		return nil, err
	}
	lock, err := d.acquireOperation(true, !enabled)
	if err != nil {
		return nil, err
	}
	value, err := func() (map[string]any, error) {
		defer d.releaseOperation(lock)
		if enabled && pyx.Map(d.osSecuritySnapshot()["policy"])["mode"] == "system" {
			return nil, uErr("dependency", "Enable managed OS security updates before scheduling service restarts")
		}
		if enabled && d.haproxyTransactionActive() {
			return nil, uErr("config_pending", "Resolve pending HAProxy configuration changes before OS maintenance")
		}
		marker, err := d.rebootMarkerState()
		if err != nil {
			return nil, err
		}
		if marker != nil && pyx.Map(marker["automatic"])["reason"] == "services" {
			if err := d.cancelAutomaticRebootIntent(marker); err != nil {
				return nil, err
			}
			if err := d.stopRebootUnit(pyx.Str(marker["unit"])); err != nil {
				return nil, err
			}
			if err := os.Remove(d.Opts.RebootMarker); err != nil {
				return nil, err
			}
			_ = pyx.FsyncDir(filepath.Dir(d.Opts.RebootMarker))
		}
		value := map[string]any{"enabled": enabled, "time": t, "id": pyx.UUIDHex(), "actor": actor, "updated_at": pyx.Timestamp(time.Now())}
		_ = os.MkdirAll(d.Opts.OSSecurityRoot(), 0o700)
		return value, d.atomicJSON(d.osPath("restart-policy.json"), value)
	}()
	if err != nil {
		return nil, err
	}
	log.Printf("Service restart policy changed by %s: enabled=%v time=%s", actor, value["enabled"], value["time"])
	return map[string]any{"ok": true, "service_restarts": d.serviceRestartSnapshot(), "boot_id": bootID}, nil
}

func (d *Daemon) serviceRestartTick() (string, error) {
	if d.shuttingDown() {
		return "disabled", nil
	}
	snapshot := d.serviceRestartSnapshot()
	managed := d.osSecuritySnapshot()
	if snapshot["available"] != true || pyx.Truthy(snapshot["error"]) || snapshot["enabled"] != true ||
		pyx.Truthy(managed["recovery_required"]) || pyx.Map(managed["policy"])["mode"] == "system" {
		return "disabled", nil
	}
	value, err := d.serviceRestartRecord()
	if err != nil {
		return "", err
	}
	status := pyx.Map(snapshot["status"])
	if status == nil {
		status = map[string]any{}
	}
	due, _, err := d.serviceRestartDue(value, status, d.localTime(), nil)
	if err != nil {
		return "", err
	}
	if !due {
		return "waiting", nil
	}
	if _, err := d.startOSSecurity(map[string]any{"action": "os_security_restart_cycle"}, true); err != nil {
		var ue *Error
		if errors.As(err, &ue) {
			return ue.Code, nil
		}
		return "", err
	}
	return "started", nil
}

func (d *Daemon) serviceRebootReason() ([]any, error) {
	tool, err := d.serviceRestartCommand()
	if err != nil {
		return nil, err
	}
	argv := append(tool, "reboot-reason", "--state-root", d.Opts.OSSecurityRoot())
	rc, out, _, err := d.commandRunner(90*time.Second, nil, argv...)
	failed := uErr("verification_failed", "The remaining service restarts could not be verified")
	if err != nil {
		return nil, failed
	}
	v, derr := pyx.Decode([]byte(out))
	value := pyx.Map(v)
	services, ok := value["services"].([]any)
	if derr != nil || rc != 0 || value == nil || value["ok"] != true || !ok {
		return nil, failed
	}
	return services, nil
}

func autoRebootDue(record map[string]any, local time.Time) (bool, string) {
	anchor, key := autoRebootWindow(local, pyx.Str(record["time"]))
	attempt := pyx.Map(record["attempt"])
	if attempt == nil {
		attempt = map[string]any{}
	}
	ts := pyx.Timestamp(local)
	diff := ts - pyx.Timestamp(anchor)
	st := attempt["state"]
	blocked := attempt["window"] == key && (st == "scheduled" || st == "triggered" || st == "canceled")
	return record["enabled"] == true && diff >= 0 && diff < 3600 && pyx.Float(record["updated_at"]) <= pyx.Timestamp(anchor) &&
		!blocked && ts-pyx.Float(pyx.Get(attempt, "at", 0)) >= 300, key
}

func (d *Daemon) autoRebootSnapshot() map[string]any {
	result := map[string]any{"available": false, "required": exists(d.Opts.RebootRequiredPath), "pending": nil}
	err := func() error {
		if _, err := d.autoRebootCommand(); err != nil {
			return err
		}
		result["available"] = true
		record, err := d.autoRebootRecord()
		if err != nil {
			return err
		}
		for _, k := range []string{"enabled", "time", "updated_at", "attempt"} {
			result[k] = record[k]
		}
		result["allow_service_reboot"] = pyx.Get(record, "allow_service_reboot", false)
		marker, err := d.rebootMarkerState()
		if err != nil {
			return err
		}
		if marker != nil {
			pending := map[string]any{}
			for _, k := range []string{"scheduled_at", "delay_seconds", "automatic"} {
				pending[k] = marker[k]
			}
			scheduled, _, ok := pyx.ParseISO(pyx.Str(marker["scheduled_at"]))
			if !ok {
				return uErr("invalid", "Invalid isoformat string: %s", pyx.Str(marker["scheduled_at"]))
			}
			delay := pyx.Float(marker["delay_seconds"])
			pending["due_at"] = pyx.ISO(scheduled.Add(time.Duration(delay * float64(time.Second))))
			result["pending"] = pending
		}
		if record["enabled"] == true {
			local := d.localTime()
			attempt := pyx.Map(record["attempt"])
			retry := pyx.FromTimestamp(math.Max(pyx.Timestamp(local), pyx.Float(pyx.Get(attempt, "at", 0))+300), local.Location())
			if due, _ := autoRebootDue(record, retry); due {
				result["next_window"] = pyx.ISO(retry)
			} else {
				t := pyx.Str(record["time"])
				h, _ := strconv.Atoi(t[:2])
				m, _ := strconv.Atoi(t[3:])
				upcoming := time.Date(local.Year(), local.Month(), local.Day(), h, m, 0, 0, local.Location())
				if !upcoming.After(local) {
					upcoming = time.Date(local.Year(), local.Month(), local.Day()+1, h, m, 0, 0, local.Location())
				}
				result["next_window"] = pyx.ISO(upcoming)
			}
		}
		return nil
	}()
	if err != nil {
		result["error"] = err.Error()
	}
	return result
}

func (d *Daemon) cancelAutomaticRebootIntent(marker map[string]any) error {
	automatic := pyx.Map(marker["automatic"])
	if marker == nil || !pyx.Truthy(automatic) {
		return nil
	}
	record, err := d.autoRebootRecord()
	if err != nil {
		return err
	}
	if record["id"] == automatic["policy_revision"] {
		record["attempt"] = map[string]any{"window": automatic["window"], "state": "canceled", "at": pyx.Timestamp(time.Now())}
		return d.atomicJSON(d.osPath("reboot-policy.json"), record)
	}
	return nil
}

func (d *Daemon) setAutoReboot(req map[string]any) (map[string]any, error) {
	bootID, actor, err := d.requestIdentity(req)
	if err != nil {
		return nil, err
	}
	enabled, okE := req["enabled"].(bool)
	t, okT := req["time"].(string)
	allow, okA := pyx.Get(req, "allow_service_reboot", false).(bool)
	if !okE || !okT || !autoRebootTimeRe.MatchString(t) || req["confirmation"] != "REBOOT" || !okA {
		return nil, uErr("invalid", "Confirm a valid automatic reboot policy")
	}
	if _, err := d.autoRebootCommand(); err != nil {
		return nil, err
	}
	if allow {
		if _, err := d.serviceRestartCommand(); err != nil {
			return nil, err
		}
	}
	lock, err := d.acquireOperation(true, !enabled)
	if err != nil {
		return nil, err
	}
	value, err := func() (map[string]any, error) {
		defer d.releaseOperation(lock)
		if enabled && pyx.Map(d.osSecuritySnapshot()["policy"])["mode"] == "system" {
			return nil, uErr("dependency", "Enable managed OS security updates before enabling scheduled reboots")
		}
		if enabled && d.haproxyTransactionActive() {
			return nil, uErr("config_pending", "Resolve pending HAProxy configuration changes before OS maintenance")
		}
		marker, err := d.rebootMarkerState()
		if err != nil {
			return nil, err
		}
		if marker != nil && pyx.Truthy(marker["automatic"]) {
			if err := d.cancelAutomaticRebootIntent(marker); err != nil {
				return nil, err
			}
			if err := d.stopRebootUnit(pyx.Str(marker["unit"])); err != nil {
				return nil, err
			}
			if err := os.Remove(d.Opts.RebootMarker); err != nil {
				return nil, err
			}
			_ = pyx.FsyncDir(filepath.Dir(d.Opts.RebootMarker))
		}
		value := map[string]any{"enabled": enabled, "time": t, "allow_service_reboot": allow, "id": pyx.UUIDHex(),
			"actor": actor, "updated_at": pyx.Timestamp(time.Now())}
		_ = os.MkdirAll(d.Opts.OSSecurityRoot(), 0o700)
		return value, d.atomicJSON(d.osPath("reboot-policy.json"), value)
	}()
	if err != nil {
		return nil, err
	}
	log.Printf("Automatic reboot policy changed by %s: enabled=%v time=%s", actor, value["enabled"], value["time"])
	return map[string]any{"ok": true, "automatic_reboot": d.autoRebootSnapshot(), "boot_id": bootID}, nil
}

func (d *Daemon) autoRebootTick() (string, error) {
	if d.shuttingDown() {
		return "disabled", nil
	}
	record, err := d.autoRebootRecord()
	if err != nil {
		return "", err
	}
	if record["enabled"] != true || !(exists(d.Opts.RebootRequiredPath) || pyx.Get(record, "allow_service_reboot", false) == true) {
		return "disabled", nil
	}
	local := d.localTime()
	// Checked again under the lock below, where the window key is taken.
	if due, _ := autoRebootDue(record, local); !due {
		return "waiting", nil
	}
	if _, err := d.autoRebootCommand(); err != nil {
		var ue *Error
		if errors.As(err, &ue) {
			return ue.Code, nil
		}
		return "", err
	}
	lock, err := d.acquireOperation(false, false)
	if err != nil {
		var ue *Error
		if errors.As(err, &ue) {
			return ue.Code, nil
		}
		return "", err
	}
	defer d.releaseOperation(lock)
	record, err = d.autoRebootRecord()
	if err != nil {
		return "", err
	}
	due, key := autoRebootDue(record, local)
	if !due || pyx.Map(d.osSecuritySnapshot()["policy"])["mode"] == "system" {
		return "disabled", nil
	}
	record["attempt"] = map[string]any{"window": key, "state": "scheduled", "at": pyx.Timestamp(local)}
	if err := d.atomicJSON(d.osPath("reboot-policy.json"), record); err != nil {
		return "", err
	}
	boot, err := d.currentBootID()
	if err == nil {
		_, err = d.requestReboot(map[string]any{"confirmation": rebootConfirmation, "expected_boot_id": boot, "actor": "os-security-auto"},
			map[string]any{"policy_revision": record["id"], "window": key}, lock)
	}
	if err != nil {
		var ue *Error
		notRequired := errors.As(err, &ue) && ue.Code == "not_required"
		if !lexists(d.Opts.RebootMarker) {
			if notRequired {
				record["attempt"] = map[string]any{"window": key, "state": "not_required", "at": pyx.Timestamp(local)}
			} else {
				attempt := pyx.Map(record["attempt"])
				attempt["state"] = "deferred"
				attempt["error"] = pyx.TruncRunes(err.Error(), 500)
			}
			_ = d.atomicJSON(d.osPath("reboot-policy.json"), record)
		}
		if notRequired {
			return "not_required", nil
		}
		if ue != nil {
			log.Printf("Scheduled automatic reboot deferred: %s", ue.Msg)
			return ue.Code, nil
		}
		return "", err
	}
	return "scheduled", nil
}

func (d *Daemon) osSecuritySnapshot() map[string]any {
	result := map[string]any{"policy": defaultOSPolicy(), "status": nil, "recovery_required": false, "available": false}
	err := func() error {
		if _, err := d.osSecurityCommand(); err != nil {
			return err
		}
		result["available"] = true
		result["daily_supported"] = true
		if path := d.osPath("policy.json"); lexists(path) {
			record, err := d.safeJSONFile(path)
			if err != nil {
				return err
			}
			policy, err := osSecurityPolicy(pyx.Map(record["policy"]))
			if err != nil {
				return err
			}
			result["policy"] = policy
			result["policy_phase"] = record["phase"]
			result["policy_updated_at"] = record["updated_at"]
			result["recovery_required"] = record["phase"] != "ready"
		}
		if path := d.osPath("status.json"); lexists(path) {
			status, err := d.safeJSONFile(path)
			if err != nil {
				return err
			}
			out := map[string]any{}
			for _, k := range []string{"state", "error", "last_attempt", "checked_at", "last_success", "platform", "packages",
				"package_count", "eligible_count", "restart", "native_timer", "native_policy", "installed_count",
				"last_install_at", "last_install_attempt"} {
				out[k] = status[k]
			}
			out["unapplied_count"] = len(pyx.Map(status["unapplied_packages"]))
			if l, ok := status["unapplied_packages"].([]any); ok {
				out["unapplied_count"] = len(l)
			}
			result["status"] = out
		}
		if path := d.osPath("restart-status.json"); lexists(path) {
			service, err := d.safeJSONFile(path)
			if err != nil {
				return err
			}
			current := pyx.Map(result["status"])
			if current == nil {
				current = map[string]any{"state": "unverified"}
			}
			boot, _ := d.currentBootID()
			sameBoot := service["boot_id"] == boot
			candidates := []map[string]any{}
			add := func(v any) {
				if m := pyx.Map(v); m != nil {
					candidates = append(candidates, m)
				}
			}
			add(current["restart"])
			if sameBoot {
				add(service["restart"])
			}
			if service["check_boot_id"] == boot {
				add(service["check"])
			}
			if sameBoot && service["state"] == "unknown" {
				errText := service["error"]
				if !pyx.Truthy(errText) {
					errText = "Service restarts could not be verified"
				}
				current["restart"] = map[string]any{"error": errText, "checked_at": pyx.Get(service, "last_attempt", 0)}
				result["status"] = current
			} else if len(candidates) > 0 {
				best := candidates[0]
				for _, c := range candidates[1:] {
					if pyx.Float(pyx.Get(c, "checked_at", 0)) > pyx.Float(pyx.Get(best, "checked_at", 0)) {
						best = c
					}
				}
				current["restart"] = best
				result["status"] = current
			}
		}
		return nil
	}()
	if err != nil {
		result["error"] = err.Error()
		result["recovery_required"] = d.securityRecoveryPending()
	}
	return result
}

// cachedInspect is a copy of the last Linux settings read and when it was taken.
func (d *Daemon) cachedInspect() (map[string]any, time.Time) {
	d.inspectCacheMu.Lock()
	defer d.inspectCacheMu.Unlock()
	if d.inspectValue == nil {
		return nil, d.inspectAt
	}
	return pyx.Copy(d.inspectValue), d.inspectAt
}

func (d *Daemon) osSecurityLiveSettings() map[string]any {
	// inspectMu is held for the whole read; the cached answer has its own
	// lock, so a request that finds the read running still gets the last
	// answer without racing the reader that replaces it.
	if !d.inspectMu.TryLock() {
		if cached, _ := d.cachedInspect(); cached != nil {
			return cached
		}
		return map[string]any{"error": "Reading current Linux settings…"}
	}
	defer d.inspectMu.Unlock()
	if cached, at := d.cachedInspect(); !at.IsZero() && time.Since(at) < 30*time.Second {
		return cached
	}
	value := func() map[string]any {
		tool, err := d.osSecurityCommand()
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		argv := append(tool, "inspect")
		rc, out, _, err := d.commandRunner(8*time.Second, nil, argv...)
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		v, derr := pyx.Decode([]byte(out))
		if derr != nil {
			return map[string]any{"error": derr.Error()}
		}
		m := pyx.Map(v)
		if rc != 0 || m == nil || m["ok"] != true {
			msg := "Current Linux settings could not be read"
			if m != nil {
				msg = pyx.Str(pyx.Get(m, "error", msg))
			}
			return map[string]any{"error": msg}
		}
		return m
	}()
	d.inspectCacheMu.Lock()
	d.inspectAt = time.Now()
	d.inspectValue = value
	d.inspectCacheMu.Unlock()
	return pyx.Copy(value)
}

func (d *Daemon) osSecurityInstallDue(policy, status map[string]any, local time.Time) bool {
	last := pyx.Float(status["last_install_at"])
	var previous *time.Time
	if last != 0 {
		p := pyx.FromTimestamp(last, local.Location())
		previous = &p
	}
	start, _ := pyx.Int(policy["start"])
	end, _ := pyx.Int(policy["end"])
	if policy["mode"] == "daily" {
		return int64(local.Hour()) == start && (previous == nil || previous.Format("2006-01-02") != local.Format("2006-01-02"))
	}
	return policy["mode"] == "window" && inInstallWindow(local, start, end) &&
		(previous == nil || installNight(*previous, start, end) != installNight(local, start, end))
}

func (d *Daemon) osSecuritySchedule(snapshot map[string]any) map[string]any {
	policy := pyx.Map(snapshot["policy"])
	status := pyx.Map(snapshot["status"])
	if status == nil {
		status = map[string]any{}
	}
	if pyx.Truthy(snapshot["recovery_required"]) || pyx.Truthy(snapshot["configuring"]) || policy["mode"] == "system" {
		return map[string]any{}
	}
	local := d.localTime()
	stamp := pyx.Timestamp(local)
	interval, _ := pyx.Int(policy["interval"])
	nextCheck := math.Max(stamp, math.Max(pyx.Float(status["last_success"])+float64(interval)*3600, pyx.Float(status["last_attempt"])+1800))
	result := map[string]any{"next_check": nextCheck}
	if policy["mode"] == "auto" {
		result["next_install"] = pyx.ISO(pyx.FromTimestamp(nextCheck, local.Location()))
	}
	if policy["mode"] == "daily" || policy["mode"] == "window" {
		start, _ := pyx.Int(policy["start"])
		end, _ := pyx.Int(policy["end"])
		var next time.Time
		if d.osSecurityInstallDue(policy, status, local) {
			next = pyx.FromTimestamp(math.Max(stamp, pyx.Float(status["last_install_attempt"])+1800), local.Location())
			windowEnd := end
			if policy["mode"] == "daily" {
				windowEnd = (start + 1) % 24
			}
			if !inInstallWindow(next, start, windowEnd) {
				tomorrow := local.AddDate(0, 0, 1)
				next = time.Date(tomorrow.Year(), tomorrow.Month(), tomorrow.Day(), int(start), 0, 0, 0, local.Location())
			}
		} else {
			next = time.Date(local.Year(), local.Month(), local.Day(), int(start), 0, 0, 0, local.Location())
			if !next.After(local) {
				next = next.AddDate(0, 0, 1)
			}
		}
		result["next_install"] = pyx.ISO(next)
	}
	return result
}

func (d *Daemon) osSecurityNotifications(snapshot map[string]any) {
	if !d.alertsOn() || pyx.Truthy(snapshot["error"]) {
		return
	}
	status := pyx.Map(snapshot["status"])
	if status == nil {
		status = map[string]any{}
	}
	state := status["state"]
	if state != "ready" && state != "unknown" {
		return
	}
	d.observe(level("os.security_check_failed", "host", state == "unknown", "OS security updates could not be checked",
		pyx.StrOr(status["error"])))
	if state != "ready" {
		return
	}
	if count, ok := pyx.Int(status["package_count"]); ok {
		policy := pyx.Map(snapshot["policy"])
		if policy == nil {
			policy = defaultOSPolicy()
		}
		mode := policy["mode"]
		automatic := mode == "auto" || mode == "daily" || mode == "window"
		if mode != "system" {
			if s := d.autoInstallSettings(); s["unified"] == true {
				automatic = s["enabled"] == true
			}
		}
		switch {
		case count == 0:
			d.observe(level("os.security_updates", "host", false, "No OS security updates are pending", ""))
		case !automatic:
			d.observe(level("os.security_updates", "host", true, "OS security updates are available",
				fmt.Sprintf("%d package(s) require a security update.", count)))
		default:
			if unapplied, _ := pyx.Int(status["unapplied_count"]); unapplied != 0 {
				d.observe(level("os.security_updates", "host", true, "OS security updates remain after an installation attempt",
					fmt.Sprintf("%d package(s) still require a security update after an installation attempt.", unapplied)))
			} else {
				obs := level("os.security_updates", "host", false, "Security updates are left to the automatic installation", "")
				obs.Retired = true
				d.observe(obs)
			}
		}
	}
	restart := pyx.Map(status["restart"])
	if restart == nil {
		restart = map[string]any{}
	}
	if !pyx.Truthy(restart["error"]) {
		pending := pyx.Truthy(restart["reboot_required"]) || pyx.Truthy(restart["services"])
		if d.restartCheckPredatesBoot(restart) {
			pending = false
		}
		summary := "Some services require a restart after security updates"
		if pyx.Truthy(restart["reboot_required"]) {
			summary = "Security updates require a server reboot"
		}
		names := []string{}
		for _, s := range pyx.List(restart["services"]) {
			names = append(names, pyx.Str(s))
		}
		d.observe(level("os.security_restart", "host", pending, summary, strings.Join(names, ", ")))
	}
}

func (d *Daemon) osSecurityStalled(now float64, lastAnswer string) string {
	path := d.osPath("policy.json")
	if !lexists(path) {
		return ""
	}
	record, err := d.safeJSONFile(path)
	var policy map[string]any
	if err == nil {
		policy, err = osSecurityPolicy(pyx.Map(record["policy"]))
	}
	if err != nil {
		return "The OS security policy cannot be read, so it is not known whether updates are installed. " + pyx.TruncRunes(err.Error(), 300)
	}
	if record["phase"] != "ready" {
		if active := d.activeJob(); active != nil && active["operation"] == "security-configure" && activeStatus(active["status"]) {
			return ""
		}
		return "An interrupted policy change left OS security needing recovery. " +
			"Linux's own automatic updates may be switched off, and the panel installs nothing until it is resolved."
	}
	if policy["mode"] == "system" {
		return ""
	}
	snapshot := d.osSecuritySnapshot()
	if pyx.Truthy(snapshot["error"]) {
		return "Managed OS security cannot run. " + pyx.TruncRunes(pyx.Str(snapshot["error"]), 300)
	}
	status := pyx.Map(snapshot["status"])
	interval, _ := pyx.Int(policy["interval"])
	limit := math.Max(24*3600, 3*float64(interval)*3600)
	last := math.Max(pyx.Float(status["last_success"]), pyx.Float(record["updated_at"]))
	if now-last <= limit {
		return ""
	}
	detail := fmt.Sprintf("No OS security check has succeeded for %d hours.", int((now-last)/3600))
	if status["state"] == "unknown" && pyx.Truthy(status["error"]) {
		detail += " Last error: " + pyx.TruncRunes(pyx.Str(status["error"]), 300)
	} else if lastAnswer != "" && lastAnswer != "started" && lastAnswer != "waiting" {
		detail += " The schedule could not start a check: " + pyx.TruncRunes(lastAnswer, 80) + "."
	}
	return detail
}

func (d *Daemon) osSecurityWatch(lastAnswer string) string {
	if !d.alertsOn() {
		return ""
	}
	now := pyx.Timestamp(time.Now())
	reason := d.osSecurityStalled(now, lastAnswer)
	if d.watchReason != nil && *d.watchReason == reason && now-d.watchAt < 600 {
		return reason
	}
	d.watchAt = now
	d.watchReason = &reason
	d.observe(level("os.security_stalled", "host", reason != "", "OS security updates are not running", reason))
	return reason
}

func (d *Daemon) osSecurityWorker(jobID string, lock *os.File, action string, policy map[string]any, maintenanceRevision string) {
	logText := ""
	defer func() {
		d.inspectMu.Lock()
		d.inspectCacheMu.Lock()
		d.inspectAt, d.inspectValue = time.Time{}, nil
		d.inspectCacheMu.Unlock()
		d.inspectMu.Unlock()
		d.osSecurityNotifications(d.osSecuritySnapshot())
		_ = os.Remove(d.Opts.ActiveMarker)
		d.releaseOperation(lock)
	}()
	err := func() error {
		if d.haproxyTransactionActive() {
			return uErr("config_pending", "Resolve pending HAProxy configuration changes before OS maintenance")
		}
		var tool []string
		var err error
		if action == "restart-check" || action == "restart" || action == "restart-cycle" {
			tool, err = d.serviceRestartCommand()
		} else {
			tool, err = d.osSecurityCommand()
		}
		if err != nil {
			return err
		}
		if _, err := d.updateJob(jobID, map[string]any{"status": "running", "started_at": pyx.UTCNow(),
			"current_component": "os", "progress": map[string]any{"phase": "checking"}}); err != nil {
			return err
		}
		if err := os.WriteFile(d.Opts.ActiveMarker, []byte("job_id="+jobID+"\n"), 0o600); err != nil {
			return err
		}
		command := append(tool, action, "--state-root", d.Opts.OSSecurityRoot(),
			"--maintenance-lock", d.Opts.MaintenanceLockPath, "--request-id", jobID)
		if maintenanceRevision != "" {
			command = append(command, "--maintenance-revision", maintenanceRevision)
		}
		if policy != nil {
			for _, k := range []string{"mode", "interval", "start", "end"} {
				command = append(command, "--"+k, pyx.Str(policy[k]))
			}
		}
		pyx.FlockRelease(lock)
		code, out, err := d.runCommand(jobID, command, d.Opts.JobTimeoutSeconds, "")
		if err != nil {
			return err
		}
		logText = out
		result := map[string]any{}
		lines := strings.Split(strings.TrimSpace(out), "\n")
		if len(lines) > 0 {
			if v, err := pyx.Decode([]byte(lines[len(lines)-1])); err == nil {
				if m := pyx.Map(v); m != nil {
					result = m
				}
			}
		}
		if code != 0 || result["ok"] != true || result["request_id"] != jobID {
			msg := pyx.StrOr(result["error"])
			if msg == "" {
				msg = "OS security operation failed; review the job log"
			}
			return uErr("verification_failed", "%s", msg)
		}
		if action == "restart" || (action == "restart-cycle" && pyx.Truthy(result["applied"])) {
			if result["applied"] != true || result["verified"] != true || pyx.Truthy(result["unresolved"]) || pyx.Truthy(result["failed_services"]) {
				return uErr("verification_failed", "Service restarts remain unverified; review remaining services in OS security")
			}
		}
		if action == "install" || action == "cycle" || action == "configure" {
			_ = os.Remove(d.Opts.LatestPlanPath())
		}
		_, err = d.updateJob(jobID, map[string]any{"status": "completed", "completed_at": pyx.UTCNow(),
			"result": map[string]any{"message": pyx.StrOr(result["message"])}, "output": map[string]any{"log": logText}})
		return err
	}()
	if err != nil {
		d.finishFailed(jobID, err, logText, true)
	}
}

var _ = alerts.Observation{}
