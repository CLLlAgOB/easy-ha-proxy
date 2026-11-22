package updated

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/alerts"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/pyx"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/unixrpc"
)

var osSecurityActions = map[string]string{
	"os_security_check": "check", "os_security_install": "install", "os_security_configure": "configure",
	"os_security_cycle": "cycle", "os_security_restart_check": "restart-check", "os_security_restart": "restart",
	"os_security_restart_cycle": "restart-cycle",
}

func (d *Daemon) startOSSecurity(req map[string]any, scheduled bool) (map[string]any, error) {
	action := osSecurityActions[pyx.StrOr(req["action"])]
	var policy map[string]any
	if action == "configure" {
		p, err := osSecurityPolicy(req)
		if err != nil {
			return nil, err
		}
		policy = p
	}
	if policy != nil && policy["mode"] == "system" {
		unified, err := d.unifiedPolicy()
		if err != nil {
			return nil, err
		}
		if unified != nil {
			return nil, uErr("dependency", "Disable the unified maintenance window before returning updates to Linux")
		}
	}
	if (action == "install" || action == "configure" || action == "restart") && req["confirmation"] != "SECURITY" {
		return nil, uErr("invalid", "Type SECURITY to confirm OS security management")
	}
	if _, _, err := d.osSecurityTool(); err != nil {
		return nil, err
	}
	restartAction := action == "restart-check" || action == "restart" || action == "restart-cycle"
	if restartAction {
		if _, err := d.serviceRestartTool(); err != nil {
			return nil, err
		}
	}
	lock, err := d.acquireOperation(false, policy != nil && policy["mode"] == "system")
	if err != nil {
		return nil, err
	}
	fail := func(e error) (map[string]any, error) {
		d.releaseOperation(lock)
		return nil, e
	}
	if d.haproxyTransactionActive() {
		return fail(uErr("config_pending", "Resolve pending HAProxy configuration changes before OS maintenance"))
	}
	if policy != nil && policy["mode"] == "system" {
		if rec, err := d.autoRebootRecord(); err != nil {
			return fail(err)
		} else if rec["enabled"] == true {
			rec["enabled"], rec["id"], rec["updated_at"] = false, pyx.UUIDHex(), pyx.Timestamp(time.Now())
			if err := d.atomicJSON(d.osPath("reboot-policy.json"), rec); err != nil {
				return fail(err)
			}
		}
		if rec, err := d.serviceRestartRecord(); err != nil {
			return fail(err)
		} else if rec["enabled"] == true {
			rec = pyx.Copy(rec)
			rec["enabled"], rec["id"], rec["updated_at"] = false, pyx.UUIDHex(), pyx.Timestamp(time.Now())
			if err := d.atomicJSON(d.osPath("restart-policy.json"), rec); err != nil {
				return fail(err)
			}
		}
	}
	if (action == "install" || action == "cycle" || action == "restart" || action == "restart-cycle") &&
		pyx.Map(d.osSecuritySnapshot()["policy"])["mode"] == "system" {
		return fail(uErr("dependency", "Enable OS security management before installing updates"))
	}
	job, err := d.newJob("security-"+action, map[string]any{"components": []any{"os"}, "scheduled": scheduled})
	if err != nil {
		return fail(err)
	}
	go d.osSecurityWorker(job["id"].(string), lock, action, policy, "")
	return map[string]any{"ok": true, "job_id": job["id"], "job": publicJob(job, true)}, nil
}

func codeOf(err error) (string, bool) {
	var ue *Error
	if errors.As(err, &ue) {
		return ue.Code, true
	}
	return "", false
}

func (d *Daemon) osSecurityTick() (string, error) {
	snapshot := d.osSecuritySnapshot()
	policy := pyx.Map(snapshot["policy"])
	status := pyx.Map(snapshot["status"])
	if status == nil {
		status = map[string]any{}
	}
	if snapshot["available"] != true || pyx.Truthy(snapshot["recovery_required"]) || policy["mode"] == "system" {
		return "disabled", nil
	}
	local := d.localTime()
	stamp := pyx.Timestamp(local)
	interval, _ := pyx.Int(policy["interval"])
	due := stamp-pyx.Float(status["last_success"]) >= float64(interval)*3600
	installDue := d.osSecurityInstallDue(policy, status, local)
	lastRelevant := pyx.Float(status["last_attempt"])
	if installDue {
		lastRelevant = pyx.Float(status["last_install_attempt"])
	}
	if stamp-lastRelevant < 1800 || (!due && !installDue) {
		return "waiting", nil
	}
	if _, err := d.startOSSecurity(map[string]any{"action": "os_security_cycle"}, true); err != nil {
		if code, ok := codeOf(err); ok {
			return code, nil
		}
		return "", err
	}
	return "started", nil
}

func (d *Daemon) bootStartedAt() float64 {
	raw, err := os.ReadFile(d.Opts.ProcStatPath)
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "btime ") {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				f, err := strconv.ParseFloat(parts[1], 64)
				if err == nil {
					return f
				}
			}
		}
	}
	return 0
}

func (d *Daemon) restartCheckPredatesBoot(restart map[string]any) bool {
	if restart == nil {
		return false
	}
	checked, ok := pyx.Number(restart["checked_at"])
	boot := d.bootStartedAt()
	return ok && boot > 0 && checked < boot
}

func (d *Daemon) osSecurityCheckTick() (string, error) {
	snapshot := d.osSecuritySnapshot()
	policy := pyx.Map(snapshot["policy"])
	status := pyx.Map(snapshot["status"])
	if status == nil {
		status = map[string]any{}
	}
	if snapshot["available"] != true || pyx.Truthy(snapshot["recovery_required"]) || policy["mode"] == "system" {
		return "disabled", nil
	}
	stamp := pyx.Timestamp(d.localTime())
	lastAttempt := pyx.Float(status["last_attempt"])
	stale := d.restartCheckPredatesBoot(pyx.Map(status["restart"]))
	interval, _ := pyx.Int(policy["interval"])
	due := stamp-pyx.Float(status["last_success"]) >= float64(interval)*3600
	if stale && lastAttempt < d.bootStartedAt() {
		due = true
	} else if stamp-lastAttempt < 1800 {
		return "waiting", nil
	}
	if !due && !stale {
		return "waiting", nil
	}
	if _, err := d.startOSSecurity(map[string]any{"action": "os_security_check"}, true); err != nil {
		if code, ok := codeOf(err); ok {
			return code, nil
		}
		return "", err
	}
	return "started", nil
}

func (d *Daemon) osSecurityResponse(req map[string]any) (map[string]any, error) {
	result := map[string]any{"ok": true}
	for k, v := range d.osSecuritySnapshot() {
		result[k] = v
	}
	jobs := []map[string]any{}
	for _, job := range d.listJobs() {
		if strings.HasPrefix(pyx.StrOr(job["operation"]), "security-") && len(jobs) < 10 {
			jobs = append(jobs, job)
		}
	}
	result["jobs"] = jobs
	active := d.activeJob()
	if active != nil {
		result["active_job"] = active
	} else {
		result["active_job"] = nil
	}
	configuring := active != nil && active["operation"] == "security-configure" && activeStatus(active["status"])
	result["configuring"] = configuring
	if configuring {
		result["recovery_required"] = false
	}
	if result["available"] == true {
		result["live_settings"] = d.osSecurityLiveSettings()
	} else {
		result["live_settings"] = nil
	}
	result["schedule"] = d.osSecuritySchedule(result)
	result["automatic_reboot"] = d.autoRebootSnapshot()
	result["service_restarts"] = d.serviceRestartSnapshot()
	unified, err := d.unifiedPolicy()
	if err != nil {
		return nil, err
	}
	if unified != nil {
		result["maintenance_window"] = unified
	} else {
		result["maintenance_window"] = nil
	}
	boot, err := d.currentBootID()
	if err != nil {
		return nil, err
	}
	result["boot_id"] = boot
	if status := pyx.Map(result["status"]); status != nil && d.restartCheckPredatesBoot(pyx.Map(status["restart"])) {
		restart := pyx.Copy(pyx.Map(status["restart"]))
		restart["before_boot"] = true
		status["restart"] = restart
	}
	if pyx.Truthy(req["job_id"]) {
		id, err := identifier(req["job_id"], "job id")
		if err != nil {
			return nil, err
		}
		job, err := d.loadJob(id, true)
		if err != nil {
			return nil, err
		}
		if !strings.HasPrefix(pyx.StrOr(job["operation"]), "security-") {
			return nil, uErr("not_found", "OS security job was not found")
		}
		result["job"] = job
	}
	result["server_time"] = pyx.UTCNow()
	now := time.Now()
	name, offset := now.Zone()
	sign := "+"
	if offset < 0 {
		sign, offset = "-", -offset
	}
	result["server_timezone"] = fmt.Sprintf("%s %s%02d%02d", name, sign, offset/3600, (offset%3600)/60)
	return result, nil
}

// ---------------------------------------------------------------------------
// SSH protection
// ---------------------------------------------------------------------------

func (d *Daemon) sshProtectionCommand(operation string) ([]string, error) {
	tool, err := d.trustedSource("ssh_protection.py")
	if err != nil {
		return nil, err
	}
	return []string{"/usr/bin/python3", tool, operation}, nil
}

func (d *Daemon) sshProtectionQuery(operation string, options ...string) (map[string]any, error) {
	command, err := d.sshProtectionCommand(operation)
	if err != nil {
		return nil, err
	}
	rc, out, _, err := d.commandRunner(9*time.Second, childEnvironment(), append(command, options...)...)
	if err == nil {
		if v, derr := pyx.Decode([]byte(out)); derr == nil {
			if payload := pyx.Map(v); payload != nil {
				if rc == 0 && payload["ok"] == true {
					return payload, nil
				}
				if pyx.Truthy(payload["error"]) {
					return nil, uErr("verification_failed", "%s", pyx.Str(payload["error"]))
				}
			}
		}
	}
	return nil, uErr("verification_failed", "Could not read Fail2ban on the server")
}

func (d *Daemon) sshMonitoringEnabled() (bool, error) {
	if !exists(d.Opts.SSHMonitorPath()) {
		return true, nil
	}
	rec, err := d.safeJSONFile(d.Opts.SSHMonitorPath())
	if err != nil {
		return false, err
	}
	return rec["enabled"] != false, nil
}

func (d *Daemon) sshProtectionStatus(req map[string]any) (map[string]any, error) {
	enabled, err := d.sshMonitoringEnabled()
	if err != nil {
		return nil, err
	}
	var job any
	if requested, ok := req["job_id"]; ok && requested != nil {
		id, err := identifier(requested, "job id")
		if err != nil {
			return nil, err
		}
		j, err := d.loadJob(id, true)
		if err != nil {
			return nil, err
		}
		if j["operation"] != sshProtectionJob {
			return nil, uErr("not_found", "SSH protection job was not found")
		}
		job = j
	} else {
		for _, j := range d.listJobs() {
			if j["operation"] == sshProtectionJob {
				job = j
				break
			}
		}
	}
	result := map[string]any{"ok": true, "monitoring": enabled, "job": job}
	if enabled {
		status, err := d.sshProtectionQuery("status")
		if err != nil {
			result["state"] = "unavailable"
			result["error"] = err.Error()
		} else {
			for k, v := range status {
				result[k] = v
			}
		}
		result["ok"] = true
	}
	return result, nil
}

func (d *Daemon) sshProtectionWatchLoop() {
	expected := false
	type sample struct {
		at    time.Time
		count int64
	}
	samples := []sample{}
	for {
		select {
		case <-d.stop:
			return
		case <-time.After(60 * time.Second):
		}
		if exists(d.Opts.ActiveMarker) {
			continue
		}
		detail, burst, retired := "", false, false
		err := func() error {
			enabled, err := d.sshMonitoringEnabled()
			if err != nil {
				return err
			}
			if !enabled {
				expected, samples, retired = false, nil, true
				return nil
			}
			status, err := d.sshProtectionQuery("monitor")
			if err != nil {
				return err
			}
			state, ok := status["state"]
			if !ok {
				return uErr("invalid", "state")
			}
			active := state == "active"
			if pyx.Truthy(status["managed"]) {
				expected = pyx.Truthy(status["managed_enabled"])
			} else {
				expected = expected || active
			}
			retired = pyx.Truthy(status["managed"]) && !pyx.Truthy(status["managed_enabled"]) && !active
			firewall := pyx.Map(status["firewall"])["state"]
			switch {
			case expected && !active:
				detail = "The expected Fail2ban SSH rule is inactive or its service is unavailable."
			case expected && pyx.Truthy(status["managed_enabled"]) && pyx.Truthy(status["external_config"]):
				detail = "External SSH settings can override the panel-managed Fail2ban rule."
			case expected && pyx.Truthy(status["error"]):
				detail = "Could not read Fail2ban on the server"
			case expected && (firewall == "missing" || firewall == "ports_changed" || firewall == "unknown" || firewall == "order_unknown"):
				detail = map[any]string{
					"missing":       "The firewall is missing rules for one or more active SSH blocks.",
					"ports_changed": "The SSH listening ports have changed since the Fail2ban rule was configured.",
					"unknown":       "The firewall rules for SSH could not be read.",
					"order_unknown": "Earlier firewall rules may take precedence over SSH blocks.",
				}[firewall]
			}
			total, okTotal := strictInt(status["total_banned"])
			if active && okTotal {
				now := time.Now()
				if len(samples) > 0 && total < samples[len(samples)-1].count {
					samples = nil
				}
				kept := []sample{}
				for _, s := range samples {
					if now.Sub(s.at) <= 300*time.Second {
						kept = append(kept, s)
					}
				}
				samples = append(kept, sample{now, total})
				burst = total-samples[0].count >= 10
			} else {
				samples = nil
			}
			return nil
		}()
		if err != nil {
			if expected {
				d.observe(level("ssh.protection_lost", "host", true, "SSH blocking could not be verified", "Could not read Fail2ban on the server"))
			}
			continue
		}
		lost := level("ssh.protection_lost", "host", detail != "", "SSH blocking could not be verified", detail)
		lost.Retired = retired
		d.observe(lost)
		burstDetail := ""
		if burst {
			burstDetail = "Fail2ban recorded at least ten new SSH blocks within five minutes."
		}
		b := level("ssh.ban_burst", "host", burst, "Burst of SSH blocks", burstDetail)
		b.Retired = retired
		d.observe(b)
	}
}

func (d *Daemon) sshProtectionWorker(jobID string, lock *os.File, argv []string) {
	logText := ""
	defer func() {
		if len(argv) > 2 && argv[2] == "install" {
			_ = os.Remove(d.Opts.LatestPlanPath())
		}
		_ = os.Remove(d.Opts.ActiveMarker)
		d.releaseOperation(lock)
	}()
	generic := uErr("invalid", "Could not configure SSH protection; review the job log")
	err := func() error {
		if _, err := d.updateJob(jobID, map[string]any{"status": "running", "started_at": pyx.UTCNow()}); err != nil {
			return err
		}
		if err := os.WriteFile(d.Opts.ActiveMarker, []byte("job_id="+jobID+"\n"), 0o600); err != nil {
			return err
		}
		pyx.FlockRelease(lock)
		code, out, err := d.runCommand(jobID, argv, 900, "")
		if err != nil {
			return err
		}
		logText = out
		lines := strings.Split(strings.TrimSpace(out), "\n")
		v, derr := pyx.Decode([]byte(lines[len(lines)-1]))
		payload := pyx.Map(v)
		if derr != nil || payload == nil {
			return generic
		}
		if code != 0 || payload["ok"] != true || payload["request_id"] != jobID {
			if pyx.Truthy(payload["error"]) {
				return uErr("invalid", "%s", pyx.Str(payload["error"]))
			}
			return generic
		}
		message, ok := payload["message"]
		if !ok {
			return generic
		}
		_, err = d.updateJob(jobID, map[string]any{"status": "completed", "completed_at": pyx.UTCNow(),
			"result": map[string]any{"message": message}, "output": map[string]any{"log": logText}})
		return err
	}()
	if err != nil {
		d.finishFailed(jobID, err, logText, false)
	}
}

func normalizeAddress(value string) (string, bool) {
	if strings.Contains(value, "/") {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			addr, aerr := netip.ParseAddr(strings.SplitN(value, "/", 2)[0])
			if aerr != nil {
				return "", false
			}
			bits, berr := strconv.Atoi(strings.SplitN(value, "/", 2)[1])
			if berr != nil {
				return "", false
			}
			prefix, err = addr.Prefix(bits)
			if err != nil {
				return "", false
			}
		}
		return prefix.Masked().String(), true
	}
	addr, err := netip.ParseAddr(value)
	if err != nil || addr.Zone() != "" {
		return "", false
	}
	return addr.String(), true
}

func (d *Daemon) configureSSHProtection(req map[string]any) (map[string]any, error) {
	operation, _ := req["operation"].(string)
	trusted, okT := req["trusted"].([]any)
	if (operation != "install" && operation != "enable" && operation != "disable") || !okT || len(trusted) > 32 {
		return nil, uErr("invalid", "Invalid SSH protection operation")
	}
	addresses := []string{}
	for _, v := range trusted {
		s, ok := v.(string)
		if !ok || len([]rune(s)) < 1 || len([]rune(s)) > 64 || strings.Contains(s, "%") {
			return nil, uErr("invalid", "Enter a valid IPv4 or IPv6 address or subnet")
		}
		norm, ok := normalizeAddress(s)
		if !ok {
			return nil, uErr("invalid", "Enter a valid IPv4 or IPv6 address or subnet")
		}
		addresses = append(addresses, norm)
	}
	argv, err := d.sshProtectionCommand(operation)
	if err != nil {
		return nil, err
	}
	if policyRaw, present := req["policy"]; present {
		policy := pyx.Map(policyRaw)
		keys := []string{}
		for k := range policy {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		valid := policy != nil && strings.Join(keys, ",") == "bantime,findtime,maxretry"
		ints := map[string]int64{}
		if valid {
			for _, k := range keys {
				n, ok := strictInt(policy[k])
				if !ok {
					valid = false
				}
				ints[k] = n
			}
		}
		if !valid || ints["maxretry"] < 2 || ints["maxretry"] > 50 || ints["findtime"] < 60 || ints["findtime"] > 86400 ||
			ints["findtime"]%60 != 0 || ints["bantime"] < 60 || ints["bantime"] > 604800 || ints["bantime"]%60 != 0 {
			return nil, uErr("invalid", "Invalid SSH blocking thresholds")
		}
		// json.dumps keeps the request's key order; the page sends these three.
		encoded := fmt.Sprintf(`{"maxretry": %d, "findtime": %d, "bantime": %d}`, ints["maxretry"], ints["findtime"], ints["bantime"])
		argv = append(argv, "--policy", encoded)
	}
	lock, err := d.acquireOperation(false, operation != "install")
	if err != nil {
		return nil, err
	}
	job, err := d.newJob(sshProtectionJob, nil)
	if err != nil {
		d.releaseOperation(lock)
		return nil, err
	}
	jobID := job["id"].(string)
	argv = append(argv, "--maintenance-lock", d.Opts.MaintenanceLockPath, "--request-id", jobID, "--trusted")
	argv = append(argv, addresses...)
	go d.sshProtectionWorker(jobID, lock, argv)
	return map[string]any{"ok": true, "job_id": jobID, "job": publicJob(job, false)}, nil
}

// ---------------------------------------------------------------------------
// Status, reboots, dispatch
// ---------------------------------------------------------------------------

func (d *Daemon) statusResponse(req map[string]any) (map[string]any, error) {
	var jobs []map[string]any
	if requested, ok := req["job_id"]; ok && requested != nil {
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
	plan, err := d.loadLatestPlan()
	if err != nil {
		return nil, err
	}
	var planOut any
	if plan != nil {
		p := pyx.Copy(plan)
		p["stale"] = planIsExpired(plan)
		planOut = p
		plan = p
	}
	boot, err := d.currentBootID()
	if err != nil {
		return nil, err
	}
	scheduled, err := d.rebootIsScheduled()
	if err != nil {
		return nil, err
	}
	var active any
	if a := d.activeJob(); a != nil {
		active = a
	}
	var haproxyOp any
	if op := d.haproxyOperation(); op != nil {
		haproxyOp = op
	}
	return map[string]any{
		"ok": true, "protocol_version": protocolVersion, "deployment": d.readDeployment(), "plan": planOut,
		"jobs": jobs, "active_job": active, "boot_id": boot, "reboot_required": exists(d.Opts.RebootRequiredPath),
		"reboot_scheduled": scheduled, "reboot_scheduled_elsewhere": lexists(d.Opts.AssistantRebootMarker),
		"reboot_delay_seconds": d.Opts.RebootDelaySeconds, "settings": d.settingsPayload(),
		"summary": d.summaryPayload(plan), "haproxy_operation": haproxyOp, "haproxy_migration": d.migrationStatus(plan),
	}, nil
}

func (d *Daemon) currentBootID() (string, error) {
	raw, err := os.ReadFile(d.Opts.BootIDPath)
	if err != nil {
		return "", uErr("conflict", "the current boot id is unavailable")
	}
	value := strings.ToLower(strings.TrimSpace(string(raw)))
	if !bootIDRe.MatchString(value) {
		return "", uErr("conflict", "the current boot id is invalid")
	}
	return value, nil
}

func (d *Daemon) requestIdentity(req map[string]any) (string, string, error) {
	expected, ok := req["expected_boot_id"].(string)
	if !ok || !bootIDRe.MatchString(expected) {
		return "", "", uErr("validation", "a valid expected boot id is required")
	}
	actor, ok := req["actor"].(string)
	if !ok || !actorRe.MatchString(actor) {
		return "", "", uErr("validation", "a valid authenticated actor is required")
	}
	boot, err := d.currentBootID()
	if err != nil {
		return "", "", err
	}
	if expected != boot {
		return "", "", uErr("stale_boot", "the server boot changed; reload the page and try again")
	}
	return boot, actor, nil
}

func (d *Daemon) rebootMarkerState() (map[string]any, error) {
	if !lexists(d.Opts.RebootMarker) {
		return nil, nil
	}
	state, err := d.safeJSONFile(d.Opts.RebootMarker)
	if err != nil {
		log.Printf("The web reboot marker is unsafe or unreadable: %v", err)
		return nil, uErr("conflict", "the web reboot marker is unsafe")
	}
	unit, okU := state["unit"].(string)
	markerBoot, okB := state["boot_id"].(string)
	if !okU || !rebootUnitRe.MatchString(unit) || !okB || !bootIDRe.MatchString(markerBoot) {
		return nil, uErr("conflict", "the web reboot marker is invalid")
	}
	boot, err := d.currentBootID()
	if err != nil {
		return nil, err
	}
	if markerBoot != boot {
		_ = os.Remove(d.Opts.RebootMarker)
		_ = pyx.FsyncDir(filepath.Dir(d.Opts.RebootMarker))
		return nil, nil
	}
	return state, nil
}

func (d *Daemon) rebootIsScheduled() (bool, error) {
	state, err := d.rebootMarkerState()
	return state != nil, err
}

func (d *Daemon) rebootGuardPresent() bool {
	return lexists(d.Opts.RebootMarker) || lexists(d.Opts.AssistantRebootMarker)
}

func (d *Daemon) stopRebootUnit(unit string) error {
	if !rebootUnitRe.MatchString(unit) {
		return uErr("conflict", "the scheduled reboot unit is invalid")
	}
	_, out, errOut, err := d.commandRunner(15*time.Second, nil, systemctlPath, "stop", unit+".timer", unit+".service")
	if err != nil {
		return uErr("invalid", "failed to stop the reboot timer: %v", err)
	}
	remaining := []string{}
	for _, suffix := range []string{"timer", "service"} {
		props := d.systemctlProperties(unit+"."+suffix, []string{"LoadState", "ActiveState"})
		_, okL := props["LoadState"]
		_, okA := props["ActiveState"]
		if !okL || !okA {
			return uErr("invalid", "failed to verify the reboot timer stopped")
		}
		switch props["ActiveState"] {
		case "activating", "active", "reloading", "deactivating":
			remaining = append(remaining, unit+"."+suffix)
		}
	}
	if len(remaining) > 0 {
		detail := errOut
		if detail == "" {
			detail = out
		}
		if detail == "" {
			detail = strings.Join(remaining, ", ")
		}
		return uErr("invalid", "failed to stop the reboot timer: %s", strings.TrimSpace(detail))
	}
	return nil
}

func (d *Daemon) alreadyScheduled(boot string) map[string]any {
	return map[string]any{"ok": true, "message": "Reboot is already scheduled.", "reboot_scheduled": true,
		"reboot_delay_seconds": d.Opts.RebootDelaySeconds, "boot_id": boot}
}

func (d *Daemon) requestReboot(req map[string]any, automatic map[string]any, heldLock *os.File) (map[string]any, error) {
	if req["confirmation"] != rebootConfirmation {
		return nil, uErr("invalid", "reboot requires an explicit confirmation")
	}
	boot, actor, err := d.requestIdentity(req)
	if err != nil {
		return nil, err
	}
	if existing, err := d.rebootMarkerState(); err != nil {
		return nil, err
	} else if existing != nil {
		return d.alreadyScheduled(boot), nil
	}
	lock := heldLock
	if lock == nil {
		if lock, err = d.acquireOperation(false, false); err != nil {
			return nil, err
		}
		defer d.releaseOperation(lock)
	}
	if existing, err := d.rebootMarkerState(); err != nil {
		return nil, err
	} else if existing != nil {
		return d.alreadyScheduled(boot), nil
	}
	if automatic != nil && !exists(d.Opts.RebootRequiredPath) {
		allowed := false
		if automatic["unified"] == true {
			unified, err := d.unifiedPolicy()
			if err != nil {
				return nil, err
			}
			allowed = unified != nil && unified["enabled"] == true && unified["id"] == automatic["policy_revision"]
		}
		if !allowed {
			rec, err := d.autoRebootRecord()
			if err != nil {
				return nil, err
			}
			allowed = rec["allow_service_reboot"] == true
		}
		services := []any{}
		if allowed {
			if services, err = d.serviceRebootReason(); err != nil {
				return nil, err
			}
		}
		if !allowed || len(services) == 0 {
			return nil, uErr("not_required", "the operating system does not currently require a reboot")
		}
		rec, err := d.serviceRestartRecord()
		if err != nil {
			return nil, err
		}
		automatic["reason"] = "services"
		automatic["restart_policy_revision"] = rec["id"]
	}
	if exists(d.Opts.BackupdRestoreMarker) {
		return nil, uErr("operation_active", "a restore is in progress; the reboot was refused")
	}
	if d.haproxyTransactionActive() {
		return nil, uErr("config_pending", "an HAProxy configuration confirmation is active")
	}
	unit := rebootUnitPrefix + "-" + pyx.RandomHex(6)
	marker := map[string]any{"version": 1, "unit": unit, "boot_id": boot, "actor": actor, "scheduled_at": pyx.UTCNow(),
		"delay_seconds": d.Opts.RebootDelaySeconds}
	if automatic != nil {
		marker["automatic"] = automatic
	}
	schedule := func() error {
		if err := d.atomicJSON(d.Opts.RebootMarker, marker); err != nil {
			return err
		}
		command := []string{systemdRunPath, "--unit=" + unit, "--description=easy-ha-proxy web controlled reboot",
			fmt.Sprintf("--on-active=%ds", d.Opts.RebootDelaySeconds), "--timer-property=AccuracySec=1s"}
		if automatic != nil {
			tool, _, err := d.autoRebootTool()
			if err != nil {
				return err
			}
			command = append(command, "--timer-property=RemainAfterElapse=no", "--property=TimeoutStartSec=infinity",
				"--", "/usr/bin/python3", tool, "fire", "--state-root", d.Opts.OSSecurityRoot(),
				"--maintenance-lock", d.Opts.MaintenanceLockPath, "--reboot-marker", d.Opts.RebootMarker,
				"--required-marker", d.Opts.RebootRequiredPath, "--unit", unit)
		} else {
			command = append(command, systemctlPath, "reboot")
		}
		rc, out, errOut, err := d.commandRunner(15*time.Second, nil, command...)
		if err != nil {
			return uErr("invalid", "failed to schedule the reboot: %v", err)
		}
		if rc != 0 {
			detail := errOut
			if detail == "" {
				detail = out
			}
			if detail == "" {
				detail = "unknown error"
			}
			return uErr("invalid", "failed to schedule the reboot: %s", strings.TrimSpace(detail))
		}
		return nil
	}
	if err := schedule(); err != nil {
		if cerr := d.stopRebootUnit(unit); cerr != nil {
			log.Printf("Could not prove the failed reboot timer was stopped: %v", cerr)
		} else if lexists(d.Opts.RebootMarker) {
			_ = os.Remove(d.Opts.RebootMarker)
			_ = pyx.FsyncDir(filepath.Dir(d.Opts.RebootMarker))
		}
		return nil, err
	}
	log.Printf("reboot scheduled from the web UI by %s (delay %ds)", actor, d.Opts.RebootDelaySeconds)
	return map[string]any{"ok": true, "message": "Reboot scheduled.", "reboot_scheduled": true,
		"reboot_delay_seconds": d.Opts.RebootDelaySeconds, "boot_id": boot}, nil
}

func (d *Daemon) cancelReboot(req map[string]any) (map[string]any, error) {
	boot, actor, err := d.requestIdentity(req)
	if err != nil {
		return nil, err
	}
	lock, err := d.acquireOperation(true, false)
	if err != nil {
		return nil, err
	}
	err = func() error {
		defer d.releaseOperation(lock)
		state, err := d.rebootMarkerState()
		if err != nil {
			return err
		}
		if state == nil {
			return uErr("not_found", "no web-scheduled reboot exists")
		}
		if err := d.cancelAutomaticRebootIntent(state); err != nil {
			return err
		}
		if err := d.stopRebootUnit(pyx.Str(state["unit"])); err != nil {
			return err
		}
		if err := os.Remove(d.Opts.RebootMarker); err != nil {
			return err
		}
		return pyx.FsyncDir(filepath.Dir(d.Opts.RebootMarker))
	}()
	if err != nil {
		return nil, err
	}
	log.Printf("reboot canceled from the web UI by %s", actor)
	return map[string]any{"ok": true, "message": "Reboot canceled.", "reboot_scheduled": false, "boot_id": boot}, nil
}

// Dispatch is dispatch() plus handle_connection's exception mapping.
func (d *Daemon) Dispatch(_ context.Context, req map[string]any) (resp map[string]any, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Unhandled update broker request error: %v", r)
			resp, err = nil, unixrpc.NewError("internal", "internal update broker error")
		}
		if err != nil {
			err = mapError(err)
		}
	}()
	action, _ := req["action"].(string)
	allowed, ok := RequestFields[action]
	if !ok {
		return nil, uErr("invalid", "unknown update broker action")
	}
	unexpected := []string{}
	for k := range req {
		if !allowed[k] {
			unexpected = append(unexpected, k)
		}
	}
	if len(unexpected) > 0 {
		sort.Strings(unexpected)
		return nil, uErr("invalid", "unexpected request fields: %s", strings.Join(unexpected, ", "))
	}
	switch action {
	case "status":
		return d.statusResponse(req)
	case "start_check":
		return d.startCheck(req)
	case "set_channels":
		return d.setChannels(req)
	case "set_settings":
		return d.setSettings(req)
	case "set_auto_install":
		return d.setAutoInstall(req)
	case "summary":
		return d.summaryResponse(), nil
	case "reboot":
		return d.requestReboot(req, nil, nil)
	case "cancel_reboot":
		return d.cancelReboot(req)
	case "set_auto_reboot":
		return d.setAutoReboot(req)
	case "set_service_restarts":
		return d.setServiceRestarts(req)
	case "prepare_haproxy_migration":
		return d.startHAProxyMigration(req, false)
	case "apply_haproxy_migration":
		return d.startHAProxyMigration(req, true)
	case "start_haproxy_transition":
		return d.startHAProxyTransition(req)
	case "os_security_status":
		return d.osSecurityResponse(req)
	case "ssh_protection_status":
		return d.sshProtectionStatus(req)
	case "ssh_protection_connection":
		enabled, err := d.sshMonitoringEnabled()
		if err != nil {
			return nil, err
		}
		if !enabled {
			return nil, uErr("invalid", "Resume SSH monitoring before checking a connection")
		}
		options := []string{}
		for _, key := range []string{"user", "ip", "hostname", "local_address", "port"} {
			v := pyx.Get(req, key, "")
			s, ok := v.(string)
			if !ok || len([]rune(s)) > 253 {
				return nil, uErr("invalid", "Invalid OpenSSH connection parameters")
			}
			if s != "" {
				options = append(options, "--"+strings.ReplaceAll(key, "_", "-")+"="+s)
			}
		}
		return d.sshProtectionQuery("check-connection", options...)
	case "ssh_protection_monitor":
		enabled, ok := req["enabled"].(bool)
		if !ok {
			return nil, uErr("invalid", "Invalid SSH monitoring setting")
		}
		if err := d.atomicJSON(d.Opts.SSHMonitorPath(), map[string]any{"enabled": enabled}); err != nil {
			return nil, err
		}
		return map[string]any{"ok": true}, nil
	case "ssh_protection_configure":
		return d.configureSSHProtection(req)
	case "ssh_protection_unban":
		ip, ok := req["ip"].(string)
		if !ok || len([]rune(ip)) < 1 || len([]rune(ip)) > 64 || strings.Contains(ip, "%") {
			return nil, uErr("invalid", "Invalid IP address")
		}
		addr, perr := netip.ParseAddr(ip)
		if perr != nil {
			return nil, uErr("invalid", "Invalid IP address")
		}
		lock, err := d.acquireOperation(true, true)
		if err != nil {
			return nil, err
		}
		defer d.releaseOperation(lock)
		return d.sshProtectionQuery("unban", "--ip", addr.String())
	case "os_security_check", "os_security_install", "os_security_configure", "os_security_restart_check", "os_security_restart":
		return d.startOSSecurity(req, false)
	}
	return d.startApply(req)
}

func mapError(err error) error {
	var ue *Error
	if errors.As(err, &ue) {
		return unixrpc.NewError(ue.Code, pyx.TruncRunes(ue.Msg, 4096))
	}
	var re *unixrpc.Error
	if errors.As(err, &re) {
		return re
	}
	var ve *valueError
	if errors.As(err, &ve) {
		return unixrpc.NewError("invalid", ve.msg)
	}
	var se *json.SyntaxError
	if errors.As(err, &se) {
		return unixrpc.NewError("invalid", err.Error())
	}
	msg := pyx.TruncRunes(err.Error(), 4096)
	var errno syscall.Errno
	switch {
	case errors.Is(err, os.ErrNotExist):
		return unixrpc.NewError("not_found", msg)
	case errors.As(err, &errno):
		switch errno {
		case syscall.ENOSPC, syscall.Errno(122):
			return unixrpc.NewError("insufficient_space", msg)
		case syscall.EBUSY, syscall.EEXIST:
			return unixrpc.NewError("conflict", msg)
		}
		return unixrpc.NewError("internal", msg)
	}
	log.Printf("Unhandled update broker request error: %v", err)
	return unixrpc.NewError("internal", "internal update broker error")
}

// Run is serve().
func Run(opts Options) error {
	d := NewDaemon(opts)
	if err := d.ensureLayout(); err != nil {
		return fmt.Errorf("Cannot start update broker: %w", err)
	}
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
	if err := d.recoverStaleJobs(); err != nil {
		return fmt.Errorf("Cannot start update broker: %w", err)
	}
	go d.autoCheckLoop()
	if d.alertsOn() {
		go d.sshProtectionWatchLoop()
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-d.stop
		cancel()
	}()
	srv := unixrpc.NewServer(d.Opts.AppUID, d.Opts.MaxRequestBytes, d.Opts.MaxResponseBytes, d.Opts.MaxConnections, d.Dispatch)
	srv.SocketUser = strconv.Itoa(d.Opts.AppUID)
	srv.SocketGroup = strconv.Itoa(d.Opts.AppPrimaryGID)
	log.Printf("Listening on %s", d.Opts.SocketPath)
	return srv.ListenAndServe(ctx, d.Opts.SocketPath, 0o600)
}

var _ = alerts.Observation{}
