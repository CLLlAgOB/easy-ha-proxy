package updated

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/pyx"
)

// ---------------------------------------------------------------------------
// installer/maintenance_window.py, ported (the file must still exist: the
// Python broker refuses the unified window without it).
// ---------------------------------------------------------------------------

var revisionRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

type valueError struct{ msg string }

func (e *valueError) Error() string { return e.msg }

func mwPolicy(settings map[string]any) (map[string]any, error) {
	if settings["auto_install_unified"] != true {
		return nil, nil
	}
	start, okS := strictInt(settings["auto_install_start"])
	end, okE := strictInt(settings["auto_install_end"])
	updated, okU := pyx.Number(settings["maintenance_updated_at"])
	if _, isBool := settings["maintenance_updated_at"].(bool); isBool {
		okU = false
	}
	if !okS || !okE || start < 0 || start >= 24 || end < 0 || end >= 24 || start == end ||
		!revisionRe.MatchString(pyx.StrOr(settings["maintenance_revision"])) || !okU || !(updated > 0) || math.IsInf(updated, 1) {
		return nil, &valueError{"The unified maintenance policy is invalid"}
	}
	return map[string]any{"enabled": settings["auto_install"] == true, "start": start, "end": end,
		"runtime": settings["auto_install_runtime"] == true, "id": settings["maintenance_revision"],
		"updated_at": pyx.Get(settings, "maintenance_updated_at", 0)}, nil
}

// strictInt is type(v) is int (bool excluded).
func strictInt(v any) (int64, bool) {
	if _, isBool := v.(bool); isBool {
		return 0, false
	}
	return pyx.Int(v)
}

func mwWindow(local time.Time, start, end int64) map[string]any {
	day := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, local.Location())
	if int64(local.Hour()) < start {
		day = day.AddDate(0, 0, -1)
	}
	opened := time.Date(day.Year(), day.Month(), day.Day(), int(start), 0, 0, 0, local.Location())
	closeDay := day
	if end <= start {
		closeDay = day.AddDate(0, 0, 1)
	}
	closed := time.Date(closeDay.Year(), closeDay.Month(), closeDay.Day(), int(end), 0, 0, 0, local.Location())
	return map[string]any{"key": day.Format("2006-01-02"), "opens_at": pyx.Timestamp(opened), "closes_at": pyx.Timestamp(closed)}
}

func mwCurrent(value map[string]any, local time.Time) map[string]any {
	start, _ := pyx.Int(value["start"])
	end, _ := pyx.Int(value["end"])
	result := mwWindow(local, start, end)
	ts := pyx.Timestamp(local)
	opens := result["opens_at"].(float64)
	if value["enabled"] == true && opens <= ts && ts < result["closes_at"].(float64) && pyx.Float(value["updated_at"]) <= opens {
		return result
	}
	return nil
}

func mwRestartPolicy(value map[string]any) map[string]any {
	start, _ := pyx.Int(value["start"])
	return map[string]any{"enabled": value["enabled"], "time": fmt.Sprintf("%02d:00", start), "id": value["id"],
		"updated_at": value["updated_at"]}
}

func (d *Daemon) maintenanceModule() error {
	if !isRegular(agentBinary) {
		return uErr("dependency", "Update host services before using unified maintenance")
	}
	return nil
}

func (d *Daemon) unifiedPolicy() (map[string]any, error) {
	settings := d.readSettings()
	if settings["auto_install_unified"] != true {
		return nil, nil
	}
	if err := d.maintenanceModule(); err != nil {
		return nil, err
	}
	return mwPolicy(settings)
}

func (d *Daemon) localTime() time.Time { return d.now().In(time.Local) }

// ---------------------------------------------------------------------------
// Automatic installation and the unified maintenance window
// ---------------------------------------------------------------------------

func (d *Daemon) autoInstallSettings() map[string]any {
	s := d.readSettings()
	start, okS := strictInt(s["auto_install_start"])
	end, okE := strictInt(s["auto_install_end"])
	if !(okS && okE && start >= 0 && start <= 23 && end >= 0 && end <= 23 && start != end) {
		start, end = 3, 5
	}
	return map[string]any{
		"enabled": s["auto_install"] == true, "start": start, "end": end, "os": s["auto_install_os"] == true,
		"unified": s["auto_install_unified"] == true, "runtime": s["auto_install_runtime"] == true,
		"updated_at": s["maintenance_updated_at"],
	}
}

func (d *Daemon) setAutoInstall(req map[string]any) (map[string]any, error) {
	enabled, ok := req["enabled"].(bool)
	if !ok {
		return nil, uErr("invalid", "enabled must be true or false")
	}
	current := d.autoInstallSettings()
	withOS := pyx.Get(req, "os", current["os"])
	if _, ok := withOS.(bool); !ok {
		return nil, uErr("invalid", "os must be true or false")
	}
	options := map[string]any{"unified": pyx.Get(req, "unified", current["unified"]), "runtime": pyx.Get(req, "runtime", current["runtime"])}
	for _, v := range options {
		if _, ok := v.(bool); !ok {
			return nil, uErr("invalid", "maintenance options must be true or false")
		}
	}
	if options["unified"] == true && (enabled || current["unified"] != true) {
		security := d.osSecuritySnapshot()
		if pyx.Truthy(security["error"]) || pyx.Truthy(security["recovery_required"]) || pyx.Map(security["policy"])["mode"] == "system" {
			return nil, uErr("dependency", "Enable managed OS security before enabling the unified maintenance window")
		}
	}
	start, end := req["start"], req["end"]
	for _, v := range []any{start, end} {
		n, ok := strictInt(v)
		if !ok || n < 0 || n > 23 {
			return nil, uErr("invalid", "the window is given in whole hours, 0 to 23")
		}
	}
	s, _ := strictInt(start)
	e, _ := strictInt(end)
	if s == e {
		return nil, uErr("invalid", "the window must not start and end at the same hour")
	}
	settings := d.readSettings()
	settings["auto_install"] = enabled
	settings["auto_install_start"] = s
	settings["auto_install_end"] = e
	settings["auto_install_os"] = withOS == true || options["unified"] == true
	settings["auto_install_unified"] = options["unified"]
	settings["auto_install_runtime"] = options["runtime"]
	settings["maintenance_revision"] = pyx.UUIDHex()
	settings["maintenance_updated_at"] = pyx.Timestamp(time.Now())
	if err := d.atomicJSON(d.Opts.SettingsPath(), settings); err != nil {
		return nil, err
	}
	onOff := map[bool]string{true: "on", false: "off"}[enabled]
	incl := map[bool]string{true: "included", false: "excluded"}[withOS == true]
	log.Printf("Automatic installation %s, window %02d:00-%02d:00, operating-system packages %s", onOff, s, e, incl)
	return map[string]any{"ok": true, "settings": d.settingsPayload()}, nil
}

func inInstallWindow(local time.Time, start, end int64) bool {
	h := int64(local.Hour())
	if start < end {
		return start <= h && h < end
	}
	return h >= start || h < end
}

func installNight(local time.Time, start, end int64) string {
	opened := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, local.Location())
	if start > end && int64(local.Hour()) < end {
		opened = opened.AddDate(0, 0, -1)
	}
	return opened.Format("2006-01-02")
}

func projectSelection(plan map[string]any) []string {
	available, _ := planComponentMap(plan)
	actionable := []string{}
	for id, item := range available {
		if item["state"] == "available" && item["actionable"] == true && id != "os" && id != "haproxy" {
			actionable = append(actionable, id)
		}
	}
	has := setOf(actionable...)
	if has["all"] && changesScope(available["all"]) != nil {
		out := []string{changesComponent}
		for _, id := range []string{"authelia-container", "admin-container"} {
			if has[id] {
				out = append(out, id)
			}
		}
		return out
	}
	if has["all"] {
		return []string{"all"}
	}
	sort.Strings(actionable)
	return actionable
}

func autoInstallSelection(plan map[string]any, withOS bool) []string {
	selection := projectSelection(plan)
	m, _ := planComponentMap(plan)
	osEntry := m["os"]
	if withOS && osEntry["state"] == "available" && osEntry["actionable"] == true {
		selection = append(selection, "os")
	}
	return selection
}

func (d *Daemon) lastAutoInstall() map[string]any {
	if !exists(d.Opts.AutoInstallPath()) {
		return nil
	}
	r, err := d.safeJSONFile(d.Opts.AutoInstallPath())
	if err != nil {
		return nil
	}
	return r
}

func (d *Daemon) recordAutoInstall(outcome string, values map[string]any) {
	record := map[string]any{"at": pyx.UTCNow(), "outcome": outcome}
	for k, v := range values {
		record[k] = v
	}
	if err := d.atomicJSON(d.Opts.AutoInstallPath(), record); err != nil {
		log.Printf("Could not record the automatic installation")
	}
	log.Printf("Automatic installation: %s %s", outcome, pyValuesRepr(values))
}

// pyValuesRepr is `values or ""` for the keyword arguments Python logs, in
// the order its call sites pass them.
func pyValuesRepr(values map[string]any) string {
	if len(values) == 0 {
		return ""
	}
	quote := func(s string) string {
		return "'" + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), "'", `\'`) + "'"
	}
	parts := []string{}
	for _, k := range []string{"components", "job_id", "error"} {
		v, ok := values[k]
		if !ok {
			continue
		}
		var text string
		switch x := v.(type) {
		case []string:
			items := make([]string, len(x))
			for i, s := range x {
				items[i] = quote(s)
			}
			text = "[" + strings.Join(items, ", ") + "]"
		case string:
			text = quote(x)
		default:
			text = fmt.Sprint(x)
		}
		parts = append(parts, quote(k)+": "+text)
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

func (d *Daemon) autoInstallOnce() (string, error) {
	if d.shuttingDown() || d.rebootGuardPresent() || exists(d.Opts.ActiveMarker) {
		return "busy", nil
	}
	plan, err := d.loadLatestPlan()
	if err != nil {
		return "", err
	}
	if plan == nil || planIsExpired(plan) {
		checked := d.autoCheckOnce()
		if checked == "busy" {
			return "busy", nil
		}
		plan, err = d.loadLatestPlan()
		if err != nil {
			return "", err
		}
		if checked != "done" || plan == nil || planIsExpired(plan) {
			d.recordAutoInstall("check-failed", nil)
			d.reportAlert("update.failed", "auto-install", "The automatic installation could not check for updates", "")
			return "check-failed", nil
		}
	}
	options := d.autoInstallSettings()
	m, _ := planComponentMap(plan)
	if options["unified"] == true {
		if st := m["os"]["state"]; st != "current" && st != "available" {
			d.recordAutoInstall("refused", map[string]any{"error": "The OS package plan is unverified"})
			d.reportAlert("update.failed", "unified-maintenance", "The OS package plan is unverified; installation was refused", "")
			return "refused", nil
		}
	}
	components := autoInstallSelection(plan, options["os"] == true || options["unified"] == true)
	if len(components) == 0 {
		d.recordAutoInstall("nothing", nil)
		return "nothing", nil
	}
	var lock *os.File
	err = d.validateSelection(plan, components)
	if err == nil {
		lock, err = d.acquireOperation(false, false)
	}
	if err != nil {
		var ue *Error
		if errors.As(err, &ue) {
			if ue.Code == "busy" {
				return "busy", nil
			}
			d.recordAutoInstall("refused", map[string]any{"components": components, "error": pyx.TruncRunes(ue.Msg, 500)})
			d.reportAlert("update.failed", "auto-install", "The automatic installation was refused", pyx.TruncRunes(ue.Msg, 1000))
			return "refused", nil
		}
		return "", err
	}
	extra := map[string]any{}
	unified, err := d.unifiedPolicy()
	if err != nil {
		d.releaseOperation(lock)
		return "", err
	}
	var maintenance map[string]any
	if unified != nil {
		window := mwCurrent(unified, d.localTime())
		if window == nil {
			d.releaseOperation(lock)
			return "deferred", nil
		}
		maintenance = pyx.Copy(window)
		maintenance["revision"] = unified["id"]
		maintenance["runtime"] = unified["runtime"]
		extra["maintenance"] = maintenance
	}
	values := map[string]any{"components": components, "plan_id": plan["id"], "scheduled": true}
	for k, v := range extra {
		values[k] = v
	}
	job, err := d.newJob("apply", values)
	if err != nil {
		d.releaseOperation(lock)
		return "", err
	}
	jobID := job["id"].(string)
	d.recordAutoInstall("started", map[string]any{"components": components, "job_id": jobID})
	d.applyWorker(jobID, lock, plan, components, maintenance)
	result, _ := d.loadJob(jobID, false)
	outcome := "failed"
	if pyx.Truthy(pyx.Map(result["result"])["deferred_components"]) {
		outcome = "deferred"
	} else if result["status"] == "completed" {
		outcome = "installed"
	}
	d.recordAutoInstall(outcome, map[string]any{"components": components, "job_id": jobID})
	return outcome, nil
}

func (d *Daemon) autoInstallTick() (string, error) {
	settings := d.autoInstallSettings()
	if settings["unified"] == true {
		return d.unifiedMaintenanceTick()
	}
	if settings["enabled"] != true {
		return "", nil
	}
	local := d.localTime()
	start, end := settings["start"].(int64), settings["end"].(int64)
	if !inInstallWindow(local, start, end) {
		return "", nil
	}
	night := installNight(local, start, end)
	d.autoMu.Lock()
	seen := d.autoNight == night
	d.autoMu.Unlock()
	if seen {
		return "", nil
	}
	outcome, err := d.autoInstallOnce()
	if err != nil {
		return "", err
	}
	if outcome != "busy" {
		d.autoMu.Lock()
		d.autoNight = night
		d.autoMu.Unlock()
	}
	return outcome, nil
}

func (d *Daemon) unifiedSecurityStage(action string) error {
	lock, err := d.acquireOperation(false, false)
	if err != nil {
		return err
	}
	value, err := d.unifiedPolicy()
	if err == nil && (value == nil || mwCurrent(value, d.localTime()) == nil) {
		err = uErr("window_closed", "The maintenance window closed before application")
	}
	var job map[string]any
	if err == nil {
		job, err = d.newJob("security-"+action, map[string]any{"components": []any{"os"}, "scheduled": true})
	}
	if err != nil {
		d.releaseOperation(lock)
		return err
	}
	jobID := job["id"].(string)
	d.osSecurityWorker(jobID, lock, action, nil, pyx.Str(value["id"]))
	result, _ := d.loadJob(jobID, false)
	if result["status"] != "completed" {
		text := strings.ToLower(pyx.StrOr(result["error"]))
		if strings.Contains(text, "window") && strings.Contains(text, "closed") {
			return uErr("window_closed", "The maintenance window closed before application")
		}
		return uErr("invalid", "Unified maintenance could not finish the service or security stage")
	}
	return nil
}

func (d *Daemon) unifiedReboot(value, window map[string]any) (string, error) {
	if !exists(d.Opts.RebootRequiredPath) {
		services, err := d.serviceRebootReason()
		if err != nil {
			return "", err
		}
		if len(services) == 0 {
			return "completed", nil
		}
	}
	if pyx.Timestamp(time.Now())+float64(d.Opts.RebootDelaySeconds) >= pyx.Float(window["closes_at"]) {
		return "deferred", nil
	}
	lock, err := d.acquireOperation(false, false)
	if err != nil {
		return "", err
	}
	defer d.releaseOperation(lock)
	current, err := d.unifiedPolicy()
	if err != nil {
		return "", err
	}
	if current == nil || current["id"] != value["id"] || mwCurrent(current, d.localTime()) == nil {
		return "deferred", nil
	}
	record := mwRestartPolicy(value)
	record["allow_service_reboot"] = true
	record["attempt"] = map[string]any{"window": window["key"], "state": "scheduled", "at": pyx.Timestamp(time.Now())}
	if err := d.atomicJSON(filepath.Join(d.Opts.OSSecurityRoot(), "maintenance-reboot.json"), record); err != nil {
		return "", err
	}
	boot, err := d.currentBootID()
	if err != nil {
		return "", err
	}
	if _, err := d.requestReboot(map[string]any{"confirmation": rebootConfirmation, "expected_boot_id": boot, "actor": "unified-maintenance"},
		map[string]any{"unified": true, "policy_revision": value["id"], "window": window["key"]}, lock); err != nil {
		return "", err
	}
	return "reboot-scheduled", nil
}

func (d *Daemon) unifiedMaintenanceTick() (string, error) {
	value, err := d.unifiedPolicy()
	if err != nil {
		return "", err
	}
	if value == nil || value["enabled"] != true {
		return "", nil
	}
	window := mwCurrent(value, d.localTime())
	if window == nil || d.shuttingDown() || exists(d.Opts.ActiveMarker) || d.rebootGuardPresent() {
		return "", nil
	}
	path := d.Opts.MaintenanceCyclePath()
	previous := map[string]any{}
	if exists(path) {
		if previous, err = d.safeJSONFile(path); err != nil {
			return "", err
		}
	}
	if previous["night"] == window["key"] && previous["revision"] == value["id"] && previous["outcome"] != "busy" {
		if previous["outcome"] == "running" {
			previous["outcome"] = "interrupted"
			previous["completed_at"] = pyx.UTCNow()
			_ = d.atomicJSON(path, previous)
			d.reportAlert("update.failed", "unified-maintenance", "Unified maintenance was interrupted; review recovery status", "")
			d.recordAutoInstall("interrupted", nil)
		}
		return "", nil
	}
	if !d.opMu.TryLock() {
		return "busy", nil
	}
	d.opMu.Unlock()
	record := map[string]any{"night": window["key"], "revision": value["id"], "started_at": pyx.UTCNow(), "outcome": "running"}
	if err := d.atomicJSON(path, record); err != nil {
		return "", err
	}
	d.autoMu.Lock()
	d.cycleRunning = true
	d.autoMu.Unlock()
	outcome := "completed"
	stageErr := func() error {
		runtimeState := filepath.Join(d.Opts.OSSecurityRoot(), "runtime-maintenance.json")
		if exists(runtimeState) {
			rs, err := d.safeJSONFile(runtimeState)
			if err != nil {
				return err
			}
			if ph := rs["phase"]; ph != "completed" && ph != "recovered" {
				return uErr("invalid", "Runtime maintenance requires operator recovery before another automatic cycle")
			}
		}
		for _, stage := range []string{"updates", "security", "haproxy", "services", "reboot"} {
			current, err := d.unifiedPolicy()
			if err != nil {
				return err
			}
			if current == nil || current["id"] != value["id"] || mwCurrent(current, d.localTime()) == nil {
				outcome = "deferred"
				return nil
			}
			record["stage"] = stage
			if err := d.atomicJSON(path, record); err != nil {
				return err
			}
			switch stage {
			case "updates":
				answer, err := d.autoInstallOnce()
				if err != nil {
					return err
				}
				if answer != "installed" && answer != "nothing" {
					if answer == "busy" || answer == "deferred" {
						outcome = answer
					} else {
						outcome = "failed"
					}
					return nil
				}
			case "security":
				if err := d.unifiedSecurityStage("install"); err != nil {
					return err
				}
			case "haproxy":
				if d.autoCheckOnce() != "done" {
					return uErr("invalid", "Could not check HAProxy after installing system packages")
				}
				plan, err := d.loadLatestPlan()
				if err != nil {
					return err
				}
				m, err := planComponentMap(plan)
				if err != nil {
					return err
				}
				entry := m["haproxy"]
				if entry == nil {
					entry = map[string]any{}
				}
				maint := pyx.Copy(window)
				maint["revision"] = value["id"]
				maint["runtime"] = value["runtime"]
				if entry["state"] == "available" && entry["actionable"] == true {
					lock, err := d.acquireOperation(false, false)
					if err != nil {
						return err
					}
					job, err := d.newJob("apply", map[string]any{"components": []any{"haproxy"}, "plan_id": plan["id"],
						"scheduled": true, "maintenance": maint})
					if err != nil {
						d.releaseOperation(lock)
						return err
					}
					d.applyWorker(job["id"].(string), lock, plan, []string{"haproxy"}, maint)
					if j, _ := d.loadJob(job["id"].(string), false); j["status"] != "completed" {
						return uErr("invalid", "Controlled HAProxy application did not complete")
					}
				} else if st := entry["state"]; st == "unknown" || st == "blocked" {
					details := pyx.Map(entry["details"])
					installed := entry["current_version"]
					if !pyx.Truthy(installed) {
						installed = entry["installed"]
					}
					candidate := entry["available_version"]
					if !pyx.Truthy(candidate) {
						candidate = entry["available"]
					}
					if pyx.Truthy(details["needs_reload"]) ||
						(pyx.Truthy(candidate) && pyx.Truthy(installed) && pyx.Str(candidate) != pyx.Str(installed)) ||
						details["qualified"] == true {
						return uErr("invalid", "Pending HAProxy application requires operator review")
					}
				}
			case "services":
				if err := d.unifiedSecurityStage("restart"); err != nil {
					return err
				}
			default:
				answer, err := d.unifiedReboot(value, window)
				if err != nil {
					return err
				}
				outcome = answer
			}
		}
		return nil
	}()
	if stageErr != nil {
		var ue *Error
		deferred := errors.As(stageErr, &ue) && ue.Code == "window_closed"
		record["outcome"] = map[bool]string{true: "deferred", false: "failed"}[deferred]
		record["error"] = pyx.TruncRunes(stageErr.Error(), 1000)
		if !deferred {
			d.reportAlert("update.failed", "unified-maintenance", "Unified maintenance failed", pyx.TruncRunes(stageErr.Error(), 1000))
		}
	} else {
		record["outcome"] = outcome
	}
	record["completed_at"] = pyx.UTCNow()
	_ = d.atomicJSON(path, record)
	d.recordAutoInstall(pyx.Str(record["outcome"]), nil)
	d.autoMu.Lock()
	d.cycleRunning = false
	d.autoMu.Unlock()
	d.requestSelfRestartIfNeeded()
	return pyx.Str(record["outcome"]), nil
}

func (d *Daemon) setSettings(req map[string]any) (map[string]any, error) {
	value, ok := strictInt(req["auto_check_hours"])
	valid := false
	for _, c := range autoCheckChoices {
		if ok && c == value {
			valid = true
		}
	}
	if !valid {
		parts := []string{}
		for _, c := range autoCheckChoices {
			parts = append(parts, fmt.Sprint(c))
		}
		return nil, uErr("invalid", "auto_check_hours must be one of %s", strings.Join(parts, ", "))
	}
	settings := d.readSettings()
	settings["auto_check_hours"] = value
	if err := d.atomicJSON(d.Opts.SettingsPath(), settings); err != nil {
		return nil, err
	}
	d.autoMu.Lock()
	d.autoNextAt, d.autoRetry = 0, 0
	d.autoMu.Unlock()
	log.Printf("Automatic update checks set to every %d h (0 = off)", value)
	return map[string]any{"ok": true, "settings": d.settingsPayload()}, nil
}

func (d *Daemon) lastCheckTime() float64 {
	plan, err := d.loadLatestPlan()
	if err != nil || plan == nil {
		return 0
	}
	t, _, ok := pyx.ParseISO(pyx.StrOr(plan["created_at"]))
	if !ok {
		return 0
	}
	return pyx.Timestamp(t)
}

// autoCheckLoop is auto_check_loop: one pass a minute.
func (d *Daemon) autoCheckLoop() {
	started := pyx.Timestamp(time.Now())
	delay := float64(d.Opts.AutoCheckDelaySeconds)
	guard := func(name string, f func() error) {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("%s failed: %v", name, r)
			}
		}()
		if err := f(); err != nil {
			log.Printf("%s failed: %v", name, err)
		}
	}
	for {
		unified := false
		policyOK := true
		if exists(d.Opts.SettingsPath()) {
			if _, err := d.safeJSONFile(d.Opts.SettingsPath()); err != nil {
				log.Printf("The maintenance policy could not be read: %v", err)
				policyOK = false
			}
		}
		if policyOK {
			unified = d.autoInstallSettings()["unified"] == true
			due := pyx.Timestamp(time.Now()) >= started+delay
			answer := ""
			if due {
				guard("Scheduled OS security maintenance", func() error {
					var err error
					if unified {
						answer, err = d.osSecurityCheckTick()
					} else {
						answer, err = d.osSecurityTick()
					}
					if err != nil {
						answer = "failed"
					}
					return err
				})
				guard("The OS security watch", func() error { d.osSecurityWatch(answer); return nil })
				if !unified {
					guard("Scheduled service restarts", func() error { _, err := d.serviceRestartTick(); return err })
					guard("Scheduled automatic reboot", func() error { _, err := d.autoRebootTick(); return err })
				}
			}
			guard("Scheduled update check", func() error {
				now := pyx.Timestamp(time.Now())
				hours := d.autoCheckHours()
				d.autoMu.Lock()
				if hours <= 0 {
					d.autoNextAt = 0
					d.autoMu.Unlock()
					return nil
				}
				wait := math.Max(0, d.lastCheckTime()+float64(hours)*3600-now)
				dueAt := math.Max(math.Max(now+wait, started+delay), d.autoRetry)
				d.autoNextAt = dueAt
				d.autoMu.Unlock()
				if now >= dueAt {
					outcome := d.autoCheckOnce()
					log.Printf("Scheduled update check: %s", outcome)
					if outcome != "done" {
						d.autoMu.Lock()
						d.autoRetry = pyx.Timestamp(time.Now()) + autoCheckRetrySeconds
						d.autoMu.Unlock()
					}
				}
				return nil
			})
			if pyx.Timestamp(time.Now()) >= started+delay {
				guard("Automatic installation", func() error { _, err := d.autoInstallTick(); return err })
			}
		}
		select {
		case <-d.stop:
			return
		case <-time.After(autoCheckPollSeconds * time.Second):
		}
	}
}

func (d *Daemon) updateCommand(component, sourceChannel, imageChannel, expectedRevision string) ([]string, error) {
	if !allowedComponents[component] {
		return nil, uErr("invalid", "unsupported update component")
	}
	command := []string{d.Opts.CLIPath, "update", "--component", component, "--source-channel", sourceChannel}
	if component == "all" || component == "admin-container" {
		command = append(command, "--image-channel", imageChannel)
	}
	if sourceComponents[component] && sourceChannel == "github" {
		revision := strings.ToLower(expectedRevision)
		if !sourceRevisionRe.MatchString(revision) {
			return nil, uErr("invalid", "the approved source revision is unavailable")
		}
		command = append(command, "--expected-source-revision", revision)
	}
	if component == changesComponent {
		command = append(command, "--no-full-fallback")
	}
	return command, nil
}

// runningReplacedBinary reports whether this process still executes a file
// that has since been replaced on disk: Linux shows its executable link as
// "<path> (deleted)" then.
var runningReplacedBinary = func() bool {
	link, err := os.Readlink("/proc/self/exe")
	return err == nil && strings.HasSuffix(link, " (deleted)")
}

// requestSelfRestartIfNeeded restarts the broker once no job of its own is
// running, when the installer asked for it (the restart marker) or when the
// agent binary it runs from was replaced underneath it -- the marker can be
// missed (an older installer, a manual copy), the deleted executable cannot.
func (d *Daemon) requestSelfRestartIfNeeded() {
	d.autoMu.Lock()
	running := d.cycleRunning
	d.autoMu.Unlock()
	if running || (!exists(d.Opts.RestartRequestMarker) && !runningReplacedBinary()) {
		return
	}
	rc, _, _, err := d.commandRunner(10*time.Second, childEnvironment(), systemctlPath, "try-restart", "--no-block", d.Opts.ServiceName)
	if err != nil {
		log.Printf("Could not request deferred update-broker restart: %v", err)
		return
	}
	if rc != 0 {
		log.Printf("Could not request deferred update-broker restart: systemctl exit %d", rc)
		return
	}
	_ = os.Remove(d.Opts.RestartRequestMarker)
}

func (d *Daemon) applyHAProxyPatch(jobID string, plan map[string]any, logPrefix string, maintenance map[string]any) (map[string]any, string, error) {
	m, err := planComponentMap(plan)
	if err != nil {
		return nil, "", err
	}
	entry := m["haproxy"]
	details := pyx.Map(entry["details"])
	expected := entry["available_version"]
	if !pyx.Truthy(expected) {
		expected = entry["available"]
	}
	exp, ok := expected.(string)
	if !ok || !haproxyVersionRe.MatchString(exp) {
		return nil, "", uErr("stale_plan", "The reviewed HAProxy version is unavailable")
	}
	command, err := d.hostAgentTool("haproxy-migrate", "Update host services before updating HAProxy")
	if err != nil {
		return nil, "", err
	}
	command = append(command, "patch", "--expected-version", exp)
	if maintenance != nil {
		command = append(command, "--maintenance-revision", pyx.Str(maintenance["revision"]),
			"--maintenance-until", pyFloatStr(maintenance["closes_at"]), "--maintenance-state-root", d.Opts.OSSecurityRoot())
	}
	if details["needs_reload"] == true {
		command = append(command, "--reinstall")
	}
	previous := d.haproxyOperation()
	code, output, err := d.runCommand(jobID, command, d.Opts.JobTimeoutSeconds, logPrefix)
	if err != nil {
		return nil, "", err
	}
	result := d.haproxyOperation()
	if maintenance != nil && result != nil && result["phase"] == "prepared" && pyx.Timestamp(time.Now()) >= pyx.Float(maintenance["closes_at"]) {
		return nil, "", uErr("window_closed", "The maintenance window closed before HAProxy application")
	}
	if result != nil && result["id"] != pyx.Map(anyMap(previous))["id"] {
		_, _ = d.updateJob(jobID, map[string]any{"result": map[string]any{"haproxy": result}})
	}
	if code != 0 || result == nil || result["id"] == pyx.Map(anyMap(previous))["id"] ||
		result["phase"] != "committed" || result["target_verified"] != true {
		return nil, "", uErr("verification_failed", "HAProxy update failed; review its recovery status and job log")
	}
	return result, output, nil
}

func anyMap(m map[string]any) any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

// pyFloatStr is str(float) as Python prints a timestamp.
func pyFloatStr(v any) string {
	f := pyx.Float(v)
	if f == math.Trunc(f) {
		return fmt.Sprintf("%.1f", f)
	}
	return fmt.Sprint(f)
}

func (d *Daemon) applyWorker(jobID string, lock *os.File, plan map[string]any, components []string, maintenance map[string]any) {
	combined := ""
	componentSeconds := map[string]any{}
	applied := 0
	var haproxyResult map[string]any
	lockHeld := true
	defer func() {
		_ = os.Remove(d.Opts.ActiveMarker)
		d.releaseOperation(lock)
		d.requestSelfRestartIfNeeded()
	}()
	err := func() error {
		d.sleep(time.Second)
		if err := d.validateSelection(plan, components); err != nil {
			return err
		}
		if contains(components, "haproxy") && components[len(components)-1] != "haproxy" {
			return uErr("invalid", "The controlled HAProxy update must run last")
		}
		if err := os.WriteFile(d.Opts.ActiveMarker, []byte("job_id="+jobID+"\n"), 0o600); err != nil {
			return err
		}
		_ = os.Chmod(d.Opts.ActiveMarker, 0o600)
		if _, err := d.updateJob(jobID, map[string]any{"status": "running", "started_at": pyx.UTCNow(),
			"progress": map[string]any{"phase": "verifying"}}); err != nil {
			return err
		}
		branch := ""
		if pyx.Truthy(plan["branch"]) {
			branch = pyx.Str(plan["branch"])
		}
		imageChannel := pyx.StrOr(plan["image_channel"])
		if imageChannel == "" {
			imageChannel = "latest"
		}
		sourceChannelArg := pyx.StrOr(plan["source_channel"])
		if sourceChannelArg == "" {
			sourceChannelArg = "github"
		}
		fresh, err := d.executeChecker(jobID, imageChannel, sourceChannelArg, branch)
		if err != nil {
			return err
		}
		if err := validateFreshCandidates(plan, fresh, components); err != nil {
			return err
		}
		if err := validateReviewedContainerCandidates(plan, fresh, components); err != nil {
			return err
		}
		sourceChannel := pyx.Str(plan["source_channel"])
		imageChannelRaw := pyx.Str(plan["image_channel"])
		revision, err := reviewedSourceRevision(plan, components)
		if err != nil {
			return err
		}
		deferred := []string{}
		for index, component := range components {
			if maintenance != nil {
				current, err := d.unifiedPolicy()
				if err != nil {
					return err
				}
				if current == nil || current["id"] != maintenance["revision"] || mwCurrent(current, d.localTime()) == nil {
					deferred = components[index:]
					break
				}
			}
			begun := time.Now()
			if _, err := d.updateJob(jobID, map[string]any{"current_component": component, "component_index": index,
				"component_started_at": pyx.UTCNow(), "progress": map[string]any{"phase": "starting"}}); err != nil {
				return err
			}
			heading := "\n=== Applying component: " + component + " ==="
			var code int
			var output string
			if component == "haproxy" {
				pyx.FlockRelease(lock)
				lockHeld = false
				result, out, err := d.applyHAProxyPatch(jobID, plan, d.sanitizeLog(combined+heading), maintenance)
				if err != nil {
					return err
				}
				haproxyResult, output = result, out
				if pyx.FlockTry(lock) == nil {
					lockHeld = true
				}
			} else {
				command, err := d.updateCommand(component, sourceChannel, imageChannelRaw, revision)
				if err != nil {
					return err
				}
				if component == "os" {
					if j, _ := d.loadJob(jobID, false); j["scheduled"] == true {
						command = append(command, "--automatic-os")
						if maintenance != nil {
							flag := "--maintenance-revision"
							if maintenance["runtime"] == true {
								flag = "--runtime-maintenance"
							}
							command = append(command, flag, pyx.Str(maintenance["revision"]),
								"--maintenance-until", pyFloatStr(maintenance["closes_at"]))
						}
					}
				}
				code, output, err = d.runCommand(jobID, command, d.Opts.JobTimeoutSeconds, d.sanitizeLog(combined+heading))
				if err != nil {
					return err
				}
			}
			combined = d.sanitizeLog(output)
			if code != 0 {
				return uErr("invalid", "component update failed: %s (exit code %d)", component, code)
			}
			componentSeconds[component] = int64(time.Since(begun).Seconds())
			applied++
		}
		appliedComponents := components[:applied]
		result := map[string]any{"components": appliedComponents, "deferred_components": deferred,
			"reboot_required": exists("/var/run/reboot-required"), "component_seconds": componentSeconds}
		if haproxyResult != nil {
			result["haproxy"] = haproxyResult
		}
		if _, err := d.updateJob(jobID, map[string]any{"progress": map[string]any{"phase": "rechecking"}}); err != nil {
			return err
		}
		recheck := func() error {
			if !lockHeld {
				return uErr("invalid", "The update was verified; recheck after the other maintenance operation completes")
			}
			refreshed, err := d.executeChecker(jobID, imageChannelRaw, sourceChannel, branch)
			if err != nil {
				return err
			}
			if err := validateAppliedContainerDigests(plan, refreshed, appliedComponents); err != nil {
				return err
			}
			stored, err := d.storePlan(refreshed)
			if err != nil {
				return err
			}
			d.reportAvailability(stored)
			result["refreshed_plan_id"] = stored["id"]
			return nil
		}
		if err := recheck(); err != nil {
			if len(containerComponentsFor(appliedComponents)) > 0 {
				return err
			}
			result["recheck_error"] = pyx.TruncRunes(err.Error(), 4096)
			_ = os.Remove(d.Opts.LatestPlanPath())
		}
		_, err = d.updateJob(jobID, map[string]any{"status": "completed", "completed_at": pyx.UTCNow(),
			"current_component": nil, "output": map[string]any{"log": combined}, "result": result})
		return err
	}()
	if err != nil {
		var ue *Error
		if errors.As(err, &ue) && ue.Code == "window_closed" && maintenance != nil {
			_, _ = d.updateJob(jobID, map[string]any{"status": "completed", "completed_at": pyx.UTCNow(),
				"current_component": nil, "output": map[string]any{"log": combined},
				"result": map[string]any{"components": components[:applied], "deferred_components": components[applied:]}})
		} else {
			d.finishFailed(jobID, err, combined, true)
		}
	}
}

func contains(list []string, s string) bool {
	for _, it := range list {
		if it == s {
			return true
		}
	}
	return false
}

func optStr(req map[string]any, key string) (string, bool, bool) {
	v, present := req[key]
	if !present || v == nil {
		return "", false, true
	}
	s, ok := v.(string)
	return s, true, ok
}

func (d *Daemon) startCheck(req map[string]any) (map[string]any, error) {
	release, hasRelease, okR := optStr(req, "release_channel")
	if hasRelease && (!okR || !releaseChannels[release]) {
		return nil, uErr("invalid", "release channel must be stable, alpha or local")
	}
	image, hasImage, okI := optStr(req, "image_channel")
	source, hasSource, okS := optStr(req, "source_channel")
	branch := ""
	if hasRelease && release == "local" {
		source, hasSource, okS = "local", true, true
	} else if mapping, ok := releaseChannelMap[release]; hasRelease && ok {
		source, hasSource, okS = "github", true, true
		branch = mapping[0]
		image, hasImage, okI = mapping[1], true, true
	}
	if hasImage && (!okI || !imageChannels[image]) {
		return nil, uErr("invalid", "image channel must be latest or alpha")
	}
	if hasSource && (!okS || !sourceChannels[source]) {
		return nil, uErr("invalid", "source channel must be github or local")
	}
	if branch != "" && !branchRe.MatchString(branch) {
		return nil, uErr("invalid", "invalid git branch")
	}
	lock, err := d.acquireOperation(false, false)
	if err != nil {
		return nil, err
	}
	job, err := d.newJob("check", nil)
	if err != nil {
		d.releaseOperation(lock)
		return nil, err
	}
	jobID := job["id"].(string)
	go func() {
		defer d.releaseOperation(lock)
		d.runCheck(jobID, image, source, branch, true)
	}()
	return map[string]any{"ok": true, "job_id": jobID, "job": publicJob(job, true)}, nil
}

func (d *Daemon) startApply(req map[string]any) (map[string]any, error) {
	if req["confirmation"] != "UPDATE" {
		return nil, uErr("invalid", "type UPDATE to confirm component updates")
	}
	planID, err := identifier(req["plan_id"], "plan id")
	if err != nil {
		return nil, err
	}
	plan, err := d.loadLatestPlan()
	if err != nil {
		return nil, err
	}
	if plan == nil || plan["id"] != planID || planIsExpired(plan) {
		return nil, uErr("stale_plan", "the update plan is stale; check again")
	}
	components, err := selectedComponents(req["components"])
	if err != nil {
		return nil, err
	}
	if err := d.validateSelection(plan, components); err != nil {
		return nil, err
	}
	lock, err := d.acquireOperation(false, false)
	if err != nil {
		return nil, err
	}
	compsAny := make([]any, len(components))
	for i, c := range components {
		compsAny[i] = c
	}
	job, err := d.newJob("apply", map[string]any{"components": compsAny, "plan_id": planID})
	if err != nil {
		d.releaseOperation(lock)
		return nil, err
	}
	jobID := job["id"].(string)
	go d.applyWorker(jobID, lock, plan, components, nil)
	return map[string]any{"ok": true, "job_id": jobID, "job": publicJob(job, true)}, nil
}

var (
	metaSourceRe = regexp.MustCompile(`(?m)^source_channel:\s*['"]?([a-z]+)['"]?\s*(?:#.*)?$`)
	metaImageRe  = regexp.MustCompile(`(?m)^image_channel:\s*['"]?([a-z]+)['"]?\s*(?:#.*)?$`)
	metaBranchRe = regexp.MustCompile(`(?m)^branch:\s*['"]?([A-Za-z0-9._/-]{1,100})['"]?\s*(?:#.*)?$`)
)

func (d *Daemon) readDeployment() map[string]string {
	deployment := map[string]string{}
	path := filepath.Join(d.Opts.ConfigDir, "metadata.yml")
	if fi, err := os.Lstat(path); err == nil && fi.Mode().IsRegular() && fi.Size() <= int64(d.Opts.MaxStateBytes) {
		if raw, err := os.ReadFile(path); err == nil {
			text := string(raw)
			if m := metaSourceRe.FindStringSubmatch(text); m != nil && sourceChannels[m[1]] {
				deployment["source_channel"] = m[1]
			}
			if m := metaImageRe.FindStringSubmatch(text); m != nil && imageChannels[m[1]] {
				deployment["image_channel"] = m[1]
			}
			if m := metaBranchRe.FindStringSubmatch(text); m != nil && branchRe.MatchString(m[1]) {
				deployment["branch"] = m[1]
			}
		}
	}
	source := deployment["source_channel"]
	image := deployment["image_channel"]
	switch {
	case source == "local":
		deployment["release_channel"] = "local"
	case image == "alpha":
		deployment["release_channel"] = "alpha"
	default:
		deployment["release_channel"] = "stable"
	}
	return deployment
}

func (d *Daemon) setChannels(req map[string]any) (map[string]any, error) {
	release, hasRelease, okR := optStr(req, "release_channel")
	if hasRelease && (!okR || !releaseChannels[release]) {
		return nil, uErr("invalid", "release channel must be stable, alpha or local")
	}
	source, hasSource, okS := optStr(req, "source_channel")
	if hasSource && (!okS || !sourceChannels[source]) {
		return nil, uErr("invalid", "source channel must be github or local")
	}
	image, hasImage, okI := optStr(req, "image_channel")
	if hasImage && (!okI || !imageChannels[image]) {
		return nil, uErr("invalid", "image channel must be latest or alpha")
	}
	if !hasRelease && !hasSource && !hasImage {
		return nil, uErr("invalid", "select a channel to persist")
	}
	command := []string{d.Opts.CLIPath, "set-channels"}
	if hasRelease {
		command = append(command, "--release-channel", release)
	}
	if hasSource {
		command = append(command, "--source-channel", source)
	}
	if hasImage {
		command = append(command, "--image-channel", image)
	}
	lock, err := d.acquireOperation(false, false)
	if err != nil {
		return nil, err
	}
	defer d.releaseOperation(lock)
	rc, out, errOut, err := d.commandRunner(60*time.Second, childEnvironment(), command...)
	if err != nil {
		if strings.Contains(err.Error(), "timed out") {
			return nil, uErr("invalid", "persisting the deployment channels timed out")
		}
		return nil, err
	}
	if rc != 0 {
		lines := strings.Split(strings.TrimSpace(d.sanitizeLog(out+errOut)), "\n")
		msg := "persisting the deployment channels failed"
		if len(lines) > 0 && lines[len(lines)-1] != "" {
			msg += ": " + lines[len(lines)-1]
		}
		return nil, uErr("invalid", "%s", msg)
	}
	_ = os.Remove(d.Opts.LatestPlanPath())
	return map[string]any{"ok": true, "deployment": d.readDeployment()}, nil
}

func (d *Daemon) sourceGit(args ...string) (string, bool) {
	argv := append([]string{"git", "-c", "safe.directory=" + d.Opts.SourceDir, "-C", d.Opts.SourceDir}, args...)
	rc, out, _, err := d.commandRunner(15*time.Second, nil, argv...)
	if err != nil || rc != 0 {
		return "", false
	}
	return out, true
}

func (d *Daemon) readHostBuild() map[string]any {
	if !exists(filepath.Join(d.Opts.SourceDir, ".git")) {
		return nil
	}
	headOut, _ := d.sourceGit("log", "-1", "--format=%H %cI")
	head := strings.Fields(headOut)
	if len(head) != 2 || !sourceRevisionRe.MatchString(head[0]) {
		return nil
	}
	committed, aware, ok := pyx.ParseISO(head[1])
	if !ok {
		return nil
	}
	if !aware {
		committed = committed.In(time.Local)
	}
	tree := func(inputs []string) string {
		listing, _ := d.sourceGit(append([]string{"ls-tree", "-r", "--full-tree", "HEAD", "--"}, inputs...)...)
		if listing == "" {
			return ""
		}
		sum := sha256.Sum256([]byte(listing))
		return hex.EncodeToString(sum[:])
	}
	goWebTree := tree(goWebTreeInputs)
	version := ""
	if raw, err := os.ReadFile(filepath.Join(d.Opts.SourceDir, "VERSION")); err == nil {
		if text := strings.TrimSpace(string(raw)); sourceVersionRe.MatchString(text) {
			version = text
		}
	}
	return map[string]any{"revision": head[0], "committed_at": committed.UTC().Format("2006-01-02T15:04:05") + "+00:00",
		"go_web_tree": goWebTree, "version": version}
}

func (d *Daemon) hostBuild() map[string]any {
	d.buildMu.Lock()
	defer d.buildMu.Unlock()
	if !d.buildAt.IsZero() && time.Since(d.buildAt) < time.Minute {
		return d.buildValue
	}
	d.buildValue = d.readHostBuild()
	d.buildAt = time.Now()
	return d.buildValue
}

func (d *Daemon) summaryPayload(plan map[string]any) map[string]any {
	kinds := []string{}
	for _, it := range pyx.List(plan["components"]) {
		item := pyx.Map(it)
		if item != nil && item["state"] == "available" && item["actionable"] == true {
			kinds = append(kinds, pyx.Str(item["id"]))
		}
	}
	var levelV any
	for _, k := range kinds {
		if k != "os" {
			levelV = "product"
		}
	}
	if levelV == nil && len(kinds) > 0 {
		levelV = "os"
	}
	var build any
	if b := d.hostBuild(); b != nil {
		build = b
	}
	return map[string]any{"level": levelV, "components": kinds, "checked_at": plan["created_at"], "build": build}
}

func (d *Daemon) summaryResponse() map[string]any {
	plan, err := d.loadLatestPlan()
	if err != nil {
		plan = nil
	}
	out := map[string]any{"ok": true}
	for k, v := range d.summaryPayload(plan) {
		out[k] = v
	}
	return out
}

var operationKeys = []string{"id", "kind", "phase", "architecture", "created_at", "engine_digest", "old_version",
	"target_runtime_version", "target_packages", "extra_packages", "updated_at", "failure", "target_verified", "rollback_verified"}

func readHAProxyOperation(path string) map[string]any {
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 {
		return nil
	}
	st, err := os.Stat(path)
	if err != nil || st.Size() > 64*1024 {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	v, err := pyx.Decode(raw)
	data := pyx.Map(v)
	if err != nil || data == nil || !identifierRe.MatchString(pyx.StrOr(data["id"])) {
		return nil
	}
	if _, ok := data["phase"].(string); !ok {
		return nil
	}
	for _, key := range []string{"target_packages", "extra_packages"} {
		if data[key] != nil {
			if _, ok := data[key].([]any); !ok {
				return nil
			}
		}
	}
	out := map[string]any{}
	for _, k := range operationKeys {
		out[k] = data[k]
	}
	return out
}
