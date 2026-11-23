package app

// Port of routes_updates.py, routes_os_security.py and routes_ssh_security.py:
// the superadmin controls backed by the root update broker.

import (
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	updIdentifierRe = regexp.MustCompile(`^[a-f0-9]{32}$`)
	updBootIDRe     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	updActorRe      = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,128}$`)
	updTimeRe       = regexp.MustCompile(`^(?:[01][0-9]|2[0-3]):[0-5][0-9]$`)
	imageChannels   = []string{"alpha", "latest"}
	sourceChannels  = []string{"github", "local"}
	releaseChannels = []string{"alpha", "local", "stable"}
	updComponents   = []string{"all", "changes", "services", "daemons", "authelia-container", "admin-container", "os", "haproxy"}
	configSensitive = []string{"all", "changes", "daemons", "haproxy", "services"}
	autoCheckHours  = map[int64]bool{0: true, 6: true, 12: true, 24: true, 72: true, 168: true}
	conflictCodes   = map[string]bool{"busy": true, "conflict": true, "config_pending": true, "operation_active": true,
		"stale_plan": true, "stale_boot": true, "not_required": true, "dependency": true}
	auditedActions = map[string]struct {
		action string
		fields []string
	}{
		"set_channels":              {"update.channels", []string{"release_channel", "image_channel", "source_channel"}},
		"start_apply":               {"update.apply", []string{"plan_id", "components"}},
		"set_settings":              {"update.settings", []string{"auto_check_hours"}},
		"set_auto_install":          {"update.auto_install", []string{"enabled", "start", "end", "os", "unified", "runtime"}},
		"reboot":                    {"system.reboot", []string{"expected_boot_id"}},
		"cancel_reboot":             {"system.reboot_cancel", []string{"expected_boot_id"}},
		"prepare_haproxy_migration": {"update.haproxy_prepare", []string{"target_branch"}},
		"apply_haproxy_migration":   {"update.haproxy_migrate", []string{"plan_id"}},
		"start_haproxy_transition":  {"update.haproxy_transition", []string{"target_branch"}},
		"os_security_configure":     {"os.security_policy", []string{"mode", "interval", "start", "end"}},
		"os_security_install":       {"os.security_install", nil},
		"set_auto_reboot":           {"os.automatic_reboot", []string{"enabled", "time", "allow_service_reboot"}},
		"set_service_restarts":      {"os.service_restart_policy", []string{"enabled", "time"}},
		"os_security_restart":       {"os.service_restart", nil},
		"ssh_protection_monitor":    {"ssh.monitoring", []string{"enabled"}},
		"ssh_protection_configure":  {"ssh.protection", []string{"operation", "policy"}},
		"ssh_protection_unban":      {"ssh.unban", []string{"ip"}},
	}
)

// daemonResponse is _daemon_response.
func (c *Ctx) daemonResponse(result *Map, accepted bool) error {
	if truthy(result.Value("ok")) {
		if accepted {
			return c.JSON(202, result)
		}
		return c.JSON(200, result)
	}
	code := strOrEmpty(result.Value("error_code"))
	status := 502
	switch {
	case conflictCodes[code] || truthy(result.Value("conflict")):
		status = 409
	case code == "not_found" || code == "missing":
		status = 404
	case code == "invalid" || code == "validation" || code == "bad_request" || truthy(result.Value("validation_error")):
		status = 400
	}
	return c.JSON(status, result)
}

// callDaemon is _call_daemon: one audit point for every action that changes the host.
func (c *Ctx) callDaemon(payload *Map, accepted bool) (*Map, error) {
	entry, audited := auditedActions[strOrEmpty(payload.Value("action"))]
	result, err := c.App.UpdatedRequest(payload, 10*time.Second)
	if err != nil {
		if audited {
			c.RecordRequest(entry.action, AuditEntry{ObjectType: "system", ObjectID: "updates", Result: auditResultFailure,
				Detail: truncRunes(err.Error(), 500)})
		}
		return nil, c.JSON(503, newMap("ok", false, "error", err.Error()))
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
		c.RecordRequest(entry.action, AuditEntry{ObjectType: "system", ObjectID: pyStr(orValue(result.Value("job_id"), "updates")),
			Result: recordResult(ok), Summary: strings.Join(parts, ", "), Detail: detail})
	}
	return result, c.daemonResponse(result, accepted)
}

func (c *Ctx) daemon(payload *Map, accepted bool) error {
	_, err := c.callDaemon(payload, accepted)
	return err
}

// jsonPayloadFields is _json_payload: an object with exactly the allowed keys.
func (c *Ctx) jsonPayloadFields(required []string, optional ...string) (*Map, error) {
	payload, ok := asMap(c.SilentJSON())
	if !ok {
		return nil, Abort(400, "a JSON object is required")
	}
	allowed := map[string]bool{}
	for _, k := range append(append([]string{}, required...), optional...) {
		allowed[k] = true
	}
	bad := false
	payload.Each(func(k, _ any) {
		if ks, isStr := k.(string); !isStr || !allowed[ks] {
			bad = true
		}
	})
	for _, k := range required {
		if !has(payload, k) {
			bad = true
		}
	}
	if bad {
		return nil, Abort(400, "invalid request fields")
	}
	return payload, nil
}

func updIdentifier(v any, label string) (string, error) {
	text := strings.ToLower(pyStripSpace(strOrEmpty(v)))
	if !updIdentifierRe.MatchString(text) {
		return "", Abort(400, "invalid "+label)
	}
	return text, nil
}

func updBootID(v any) (string, error) {
	text := strings.ToLower(pyStripSpace(strOrEmpty(v)))
	if !updBootIDRe.MatchString(text) {
		return "", Abort(400, "invalid boot id")
	}
	return text, nil
}

func (c *Ctx) updActor() (string, error) {
	value := pyStripSpace(c.User())
	if !updActorRe.MatchString(value) {
		return "", Abort(403, "authenticated actor is unavailable")
	}
	return value, nil
}

func isIntNotBool(v any) (int64, bool) {
	n, ok := v.(int64)
	return n, ok
}

func channelOf(payload *Map, key string, allowed []string) (string, error) {
	v, ok := payload.Value(key).(string)
	if !ok || pick(allowed, v, "") == "" {
		return "", Abort(400, key+" must be one of: "+strings.Join(allowed, ", "))
	}
	return v, nil
}

// migrationConfigurationError is _migration_configuration_error: blocked is
// true when the refusal has been answered and the view must stop.
func (c *Ctx) migrationConfigurationError() (blocked bool, err error) {
	state, serr := GetHAProxyConfigurationState(c.op())
	if serr != nil {
		return true, c.JSON(503, newMap("ok", false, "error", "HAProxy configuration state is unavailable",
			"error_code", "configuration_state_unavailable"))
	}
	if state.Value("state") != "clean" {
		return true, c.JSON(409, newMap("ok", false, "error", "Resolve pending HAProxy configuration changes before migration",
			"error_code", "configuration_not_clean"))
	}
	return false, nil
}

func withAction(action string, payload *Map) *Map {
	out := newMap("action", action)
	if payload != nil {
		payload.Each(func(k, v any) { out.Set(k, v) })
	}
	return out
}

func (c *Ctx) statusWithJob(action string, strict bool) (*Map, error) {
	payload := newMap("action", action)
	raw, _ := c.queryOpt("job_id")
	if strict {
		raw = strings.ToLower(pyStripSpace(raw))
	}
	if raw != "" {
		id, err := updIdentifier(raw, "job id")
		if err != nil {
			return nil, err
		}
		payload.Set("job_id", id)
	}
	return payload, nil
}

func (a *App) registerUpdatesOps() {
	// ---- software updates ----
	a.Handle("system_updates.status_view", func(c *Ctx) error {
		payload, err := c.statusWithJob("status", true)
		if err != nil {
			return err
		}
		result, err := c.callDaemon(payload, false)
		// Every poll of the page keeps the navigation's dot in step with it.
		if result != nil && truthy(result.Value("ok")) {
			if summary, ok := asMap(result.Value("summary")); ok {
				RememberBadge(summary)
			}
		}
		return err
	})

	channels := func(action string, needOne bool) HandlerFunc {
		return func(c *Ctx) error {
			payload, err := c.jsonPayloadFields(nil, "image_channel", "source_channel", "release_channel")
			if err != nil {
				return err
			}
			command := newMap("action", action)
			for _, ch := range []struct {
				key     string
				allowed []string
			}{{"release_channel", releaseChannels}, {"image_channel", imageChannels}, {"source_channel", sourceChannels}} {
				if has(payload, ch.key) {
					v, err := channelOf(payload, ch.key, ch.allowed)
					if err != nil {
						return err
					}
					command.Set(ch.key, v)
				}
			}
			if needOne && command.Len() == 1 {
				return Abort(400, "select a channel to persist")
			}
			return c.daemon(command, action == "start_check")
		}
	}
	a.Handle("system_updates.start_check", channels("start_check", false))
	a.Handle("system_updates.save_channels", channels("set_channels", true))

	a.Handle("system_updates.save_settings", func(c *Ctx) error {
		payload, err := c.jsonPayloadFields([]string{"auto_check_hours"})
		if err != nil {
			return err
		}
		n, ok := isIntNotBool(payload.Value("auto_check_hours"))
		if !ok || !autoCheckHours[n] {
			return Abort(400, "choose one of the offered check intervals")
		}
		return c.daemon(newMap("action", "set_settings", "auto_check_hours", n), false)
	})

	a.Handle("system_updates.save_auto_install", func(c *Ctx) error {
		payload, err := c.jsonPayloadFields([]string{"enabled", "start", "end"}, "os", "unified", "runtime")
		if err != nil {
			return err
		}
		enabled, isB := payload.Value("enabled").(bool)
		badFlag := false
		for _, k := range []string{"os", "unified", "runtime"} {
			if v, found := payload.Get(k); found {
				if _, ok := v.(bool); !ok {
					badFlag = true
				}
			}
		}
		if !isB || badFlag {
			return Abort(400, "enabled must be true or false")
		}
		start, okS := isIntNotBool(payload.Value("start"))
		end, okE := isIntNotBool(payload.Value("end"))
		for _, pair := range []struct {
			ok bool
			n  int64
		}{{okS, start}, {okE, end}} {
			if !pair.ok || pair.n < 0 || pair.n > 23 {
				return Abort(400, "the window is given in whole hours, 0 to 23")
			}
		}
		if start == end {
			return Abort(400, "the window must not start and end at the same hour")
		}
		req := newMap("action", "set_auto_install", "enabled", enabled, "start", start, "end", end)
		for _, k := range []string{"os", "unified", "runtime"} {
			if v, found := payload.Get(k); found {
				req.Set(k, v)
			}
		}
		return c.daemon(req, false)
	})

	a.Handle("system_updates.start_apply", func(c *Ctx) error {
		payload, err := c.jsonPayloadFields([]string{"plan_id", "components", "confirmation"})
		if err != nil {
			return err
		}
		if payload.Value("confirmation") != "UPDATE" {
			return Abort(400, "type UPDATE to confirm software updates")
		}
		planID, err := updIdentifier(payload.Value("plan_id"), "plan id")
		if err != nil {
			return err
		}
		list, ok := payload.Value("components").([]any)
		if !ok || len(list) == 0 {
			return Abort(400, "components must be a non-empty list")
		}
		seen := map[string]bool{}
		var sensitive []string
		for _, item := range list {
			s, isStr := item.(string)
			if !isStr || pick(updComponents, s, "") == "" {
				return Abort(400, "unsupported update component")
			}
		}
		for _, item := range list {
			s := item.(string)
			if seen[s] {
				return Abort(400, "duplicate update component")
			}
			seen[s] = true
			if pick(configSensitive, s, "") != "" {
				sensitive = append(sensitive, s)
			}
		}
		sort.Strings(sensitive)
		if len(sensitive) > 0 {
			state, err := GetHAProxyConfigurationState(c.op())
			if err != nil {
				return c.JSON(503, newMap("ok", false, "error", "HAProxy configuration state is unavailable; source and host-service updates are blocked",
					"error_code", "configuration_state_unavailable"))
			}
			st := pyStr(orValue(state.Value("state"), "unknown"))
			if st != "clean" {
				return c.JSON(409, newMap("ok", false, "error", "Resolve pending HAProxy configuration changes before updating source or host services",
					"error_code", "configuration_not_clean", "configuration_state", st, "blocked_components", strList(sensitive...)))
			}
		}
		return c.daemon(newMap("action", "start_apply", "plan_id", planID, "components", list, "confirmation", "UPDATE"), true)
	})

	a.Handle("system_updates.start_haproxy_transition", func(c *Ctx) error {
		payload, err := c.jsonPayloadFields([]string{"target_branch", "confirmed"})
		if err != nil {
			return err
		}
		if payload.Value("target_branch") != "3.4" || payload.Value("confirmed") != true {
			return Abort(400, "Confirm the transition to HAProxy 3.4 LTS")
		}
		if blocked, err := c.migrationConfigurationError(); blocked {
			return err
		}
		return c.daemon(newMap("action", "start_haproxy_transition", "target_branch", "3.4", "confirmed", true), true)
	})
	a.Handle("system_updates.prepare_haproxy_migration", func(c *Ctx) error {
		payload, err := c.jsonPayloadFields([]string{"target_branch"})
		if err != nil {
			return err
		}
		if payload.Value("target_branch") != "3.4" {
			return Abort(400, "Only the qualified HAProxy 3.4 LTS migration is supported")
		}
		if blocked, err := c.migrationConfigurationError(); blocked {
			return err
		}
		return c.daemon(newMap("action", "prepare_haproxy_migration", "target_branch", "3.4"), true)
	})
	a.Handle("system_updates.apply_haproxy_migration", func(c *Ctx) error {
		payload, err := c.jsonPayloadFields([]string{"plan_id", "confirmation"})
		if err != nil {
			return err
		}
		if payload.Value("confirmation") != "MIGRATE 3.4" {
			return Abort(400, "Type MIGRATE 3.4 to confirm the HAProxy transition")
		}
		planID, err := updIdentifier(payload.Value("plan_id"), "migration plan id")
		if err != nil {
			return err
		}
		if blocked, err := c.migrationConfigurationError(); blocked {
			return err
		}
		return c.daemon(newMap("action", "apply_haproxy_migration", "plan_id", planID, "confirmation", "MIGRATE 3.4"), true)
	})
	a.Handle("system_updates.reboot", func(c *Ctx) error {
		payload, err := c.jsonPayloadFields([]string{"confirmation", "expected_boot_id"})
		if err != nil {
			return err
		}
		if payload.Value("confirmation") != "REBOOT" {
			return Abort(400, "type REBOOT to confirm the server reboot")
		}
		boot, err := updBootID(payload.Value("expected_boot_id"))
		if err != nil {
			return err
		}
		actor, err := c.updActor()
		if err != nil {
			return err
		}
		return c.daemon(newMap("action", "reboot", "confirmation", "REBOOT", "expected_boot_id", boot, "actor", actor), false)
	})
	a.Handle("system_updates.cancel_reboot", func(c *Ctx) error {
		payload, err := c.jsonPayloadFields([]string{"expected_boot_id"})
		if err != nil {
			return err
		}
		boot, err := updBootID(payload.Value("expected_boot_id"))
		if err != nil {
			return err
		}
		actor, err := c.updActor()
		if err != nil {
			return err
		}
		return c.daemon(newMap("action", "cancel_reboot", "expected_boot_id", boot, "actor", actor), false)
	})

	// ---- OS security ----
	a.Handle("os_security.status", func(c *Ctx) error {
		payload, err := c.statusWithJob("os_security_status", false)
		if err != nil {
			return err
		}
		return c.daemon(payload, false)
	})
	simple := func(action string, confirm string, description string, migration bool) HandlerFunc {
		return func(c *Ctx) error {
			var required []string
			if confirm != "" {
				required = []string{"confirmation"}
			}
			payload, err := c.jsonPayloadFields(required)
			if err != nil {
				return err
			}
			if confirm != "" && payload.Value("confirmation") != confirm {
				return Abort(400, description)
			}
			if migration {
				if blocked, err := c.migrationConfigurationError(); blocked {
					return err
				}
			}
			command := newMap("action", action)
			if confirm != "" {
				command.Set("confirmation", confirm)
			}
			return c.daemon(command, true)
		}
	}
	a.Handle("os_security.check", simple("os_security_check", "", "", false))
	a.Handle("os_security.restart_check", simple("os_security_restart_check", "", "", false))
	a.Handle("os_security.install", simple("os_security_install", "SECURITY", "Type SECURITY to confirm OS security management", true))
	a.Handle("os_security.restart_services", simple("os_security_restart", "SECURITY", "Confirm service restarts", true))

	a.Handle("os_security.policy", func(c *Ctx) error {
		payload, err := c.jsonPayloadFields([]string{"mode", "interval", "start", "end", "confirmation"})
		if err != nil {
			return err
		}
		mode, isStr := payload.Value("mode").(string)
		interval, okI := isIntNotBool(payload.Value("interval"))
		bad := !isStr || pick([]string{"system", "notify", "auto", "window", "daily"}, mode, "") == "" || !okI
		if !bad {
			switch interval {
			case 1, 2, 4, 6, 12, 24:
			default:
				bad = true
			}
		}
		start, okS := isIntNotBool(payload.Value("start"))
		end, okE := isIntNotBool(payload.Value("end"))
		if !bad && (!okS || start < 0 || start > 23 || !okE || end < 0 || end > 23 || start == end ||
			payload.Value("confirmation") != "SECURITY") {
			bad = true
		}
		if bad {
			return Abort(400, "Invalid OS security policy or confirmation")
		}
		if blocked, err := c.migrationConfigurationError(); blocked {
			return err
		}
		return c.daemon(withAction("os_security_configure", payload), true)
	})

	a.Handle("os_security.automatic_reboot", func(c *Ctx) error {
		payload, err := c.jsonPayloadFields([]string{"enabled", "time", "confirmation", "expected_boot_id"}, "allow_service_reboot")
		if err != nil {
			return err
		}
		enabled, isB := payload.Value("enabled").(bool)
		tm, isStr := payload.Value("time").(string)
		allow, found := payload.Get("allow_service_reboot")
		_, allowBool := allow.(bool)
		if !found {
			allowBool = true
		}
		if !isB || !isStr || !updTimeRe.MatchString(tm) || payload.Value("confirmation") != "REBOOT" || !allowBool {
			return Abort(400, "Confirm a valid automatic reboot policy")
		}
		if enabled {
			if blocked, err := c.migrationConfigurationError(); blocked {
				return err
			}
		}
		command := newMap("action", "set_auto_reboot", "enabled", enabled, "time", tm)
		if found {
			command.Set("allow_service_reboot", allow)
		}
		command.Set("confirmation", "REBOOT")
		boot, err := updBootID(payload.Value("expected_boot_id"))
		if err != nil {
			return err
		}
		command.Set("expected_boot_id", boot)
		actor, err := c.updActor()
		if err != nil {
			return err
		}
		command.Set("actor", actor)
		return c.daemon(command, false)
	})

	a.Handle("os_security.restart_policy", func(c *Ctx) error {
		payload, err := c.jsonPayloadFields([]string{"enabled", "time", "confirmation", "expected_boot_id"})
		if err != nil {
			return err
		}
		enabled, isB := payload.Value("enabled").(bool)
		tm, isStr := payload.Value("time").(string)
		if !isB || !isStr || !updTimeRe.MatchString(tm) || payload.Value("confirmation") != "SECURITY" {
			return Abort(400, "Confirm a valid service restart policy")
		}
		if enabled {
			if blocked, err := c.migrationConfigurationError(); blocked {
				return err
			}
		}
		command := withAction("set_service_restarts", payload)
		boot, err := updBootID(payload.Value("expected_boot_id"))
		if err != nil {
			return err
		}
		command.Set("expected_boot_id", boot)
		actor, err := c.updActor()
		if err != nil {
			return err
		}
		command.Set("actor", actor)
		return c.daemon(command, false)
	})

	// ---- SSH security ----
	a.Handle("ssh_security.status", func(c *Ctx) error {
		payload, err := c.statusWithJob("ssh_protection_status", false)
		if err != nil {
			return err
		}
		return c.daemon(payload, false)
	})
	a.Handle("ssh_security.connection", func(c *Ctx) error {
		payload, err := c.jsonPayloadFields([]string{"user", "ip"}, "hostname", "local_address", "port")
		if err != nil {
			return err
		}
		return c.daemon(withAction("ssh_protection_connection", payload), false)
	})
	a.Handle("ssh_security.unblock_history", func(c *Ctx) error {
		history := Audit().Query(AuditQuery{Action: "ssh.unban", Result: auditResultSuccess, Limit: 25})
		events := []any{}
		for _, row := range listOf(history, "events") {
			events = append(events, newMap("ts", get(row, "ts"), "actor", get(row, "actor"), "summary", get(row, "summary")))
		}
		return c.JSON(200, newMap("ok", true, "available", history.Value("available"), "events", events))
	})
	a.Handle("ssh_security.monitoring", func(c *Ctx) error {
		payload, err := c.jsonPayloadFields([]string{"enabled"})
		if err != nil {
			return err
		}
		if _, isB := payload.Value("enabled").(bool); !isB {
			return Abort(400, "Invalid SSH monitoring setting")
		}
		return c.daemon(withAction("ssh_protection_monitor", payload), false)
	})
	a.Handle("ssh_security.protection", func(c *Ctx) error {
		payload, err := c.jsonPayloadFields([]string{"operation", "trusted"}, "policy")
		if err != nil {
			return err
		}
		op := payload.Value("operation")
		_, trustedList := payload.Value("trusted").([]any)
		if (op != "install" && op != "enable" && op != "disable") || !trustedList {
			return Abort(400, "Invalid SSH protection operation")
		}
		return c.daemon(withAction("ssh_protection_configure", payload), true)
	})
	a.Handle("ssh_security.unban", func(c *Ctx) error {
		payload, err := c.jsonPayloadFields([]string{"ip"})
		if err != nil {
			return err
		}
		return c.daemon(withAction("ssh_protection_unban", payload), false)
	})
}
