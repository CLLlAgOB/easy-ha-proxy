package stages

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"easy-ha-proxy/panel/shared/jinja"
	"easy-ha-proxy/panel/shared/pyyaml"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/engine"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/vars"
)

// The status check: roles/healthcheck/tasks/status.yml, the second play's
// only role (the role's main.yml hands it to the agent or includes it). Its
// report is the task file's own message templates, rendered over the same
// facts the task file sets.
func init() {
	register(Stage{Name: "healthcheck", Parts: []Part{
		{Name: "healthcheck/status", Role: "healthcheck", File: "status", Play: 1, Build: healthcheck},
	}})
}

// results is a registered loop result's list of items.
func results(v any) []*pyyaml.Map {
	m, ok := v.(*pyyaml.Map)
	if !ok {
		return nil
	}
	return siteMaps(m.Value("results"))
}

// path reads a nested value (a.b.c) out of mappings; nil when absent.
func path(v any, keys ...string) any {
	for _, k := range keys {
		m, ok := v.(*pyyaml.Map)
		if !ok {
			return nil
		}
		v = m.Value(k)
	}
	return v
}

func asInt(v any) int {
	switch x := v.(type) {
	case int64:
		return int(x)
	case int:
		return x
	case float64:
		return int(x)
	case string:
		n, _ := strconv.Atoi(x)
		return n
	}
	return 0
}

var (
	jobFailedState = regexp.MustCompile(`(?m)^ActiveState=failed$`)
	jobFailedExec  = regexp.MustCompile(`(?m)^ExecMainStatus=([1-9][0-9]*)$`)
	jobResult      = regexp.MustCompile(`(?m)^Result=(.*)$`)
	jobInactive    = regexp.MustCompile(`(?m)^ActiveState=inactive$`)
	jobNeverExited = regexp.MustCompile(`(?m)^InactiveExitTimestamp=(?:n/a)?$`)
)

// jobFailedResult is '(?m)^Result=(?!(?:success)?$).+$' (Go has no
// look-ahead): a Result line that is neither empty nor "success".
func jobFailedResult(out string) bool {
	for _, m := range jobResult.FindAllStringSubmatch(out, -1) {
		if m[1] != "" && m[1] != "success" {
			return true
		}
	}
	return false
}

func healthcheck(b *Builder) []engine.Step {
	set := func(name, expr string) func() error {
		return func() error {
			v, err := b.Set.Template(expr)
			if err != nil {
				return err
			}
			b.Set.SetFact(name, v)
			return nil
		}
	}
	get := func(name string) any { v, _ := b.Set.Get(name); return v }
	strs := func(name string) []string { return strList(get(name)) }
	appendTo := func(name, value string) {
		b.Set.SetFact(name, append(anyList(strs(name)), value))
	}
	say := func(name string) engine.Step {
		return engine.Step{Name: name, Build: func(*engine.Run) (engine.Resource, error) {
			msg, err := b.Set.Render(healthcheckMsgs[name])
			if err != nil {
				return nil, err
			}
			return report(msg), nil
		}}
	}
	provider := &engine.Command{Argv: []string{"dpkg-query", "--show", "--showformat=${db:Status-Status}", "haproxy-awslc"}, Probe: true, IgnoreErrors: true}
	probe := &statusProbe{}
	var jobs, timers []*engine.Command
	var journals, composeLogs []*engine.Command
	sha := func(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
	lookupFile := func(name string) ([]byte, error) {
		if !filepath.IsAbs(name) {
			name = filepath.Join(b.RoleDir, "files", name)
		}
		return os.ReadFile(name)
	}

	steps := []engine.Step{
		fact("Status check | prepare list of systemd services", nil, set("status_check_systemd_enabled",
			"{{ (status_check_systemd_units | default([])) | selectattr('enabled') | list }}")),
		fact("Status check | prepare list of Docker containers", nil, set("status_check_docker_enabled",
			"{{ (status_check_docker_containers | default([])) | selectattr('enabled') | list }}")),
		{Name: "Status check | detect the installed HAProxy package provider", Resource: provider},
		fact("Status check | select the actual HAProxy package name", nil, func() error {
			name := "haproxy"
			if provider.Code == 0 && provider.Output == "installed" {
				name = "haproxy-awslc"
			}
			b.Set.SetFact("status_check_haproxy_apt_package", name)
			return nil
		}),
		fact("Status check | prepare managed artifacts list", nil, func() error {
			if err := set("status_check_managed_artifacts_enabled", "{{ status_check_managed_artifacts | default([]) | selectattr('enabled') | list }}")(); err != nil {
				return err
			}
			b.Set.SetFact("status_check_managed_artifact_versions", pyyaml.NewMap())
			b.Set.SetFact("status_check_managed_artifacts_outdated", []any{})
			return nil
		}),
		{Name: "Status check | probe services, files, packages and containers in one pass", Build: func(*engine.Run) (engine.Resource, error) {
			arg, err := b.Set.Render(`{{ {
     'units': status_check_systemd_enabled,
     'retries': status_check_is_active_retries | default(3) | int,
     'delay': status_check_is_active_delay | default(4) | int,
     'daemon_files': status_check_systemd_enabled | selectattr('version_file', 'defined') | list,
     'artifacts': status_check_managed_artifacts_enabled,
     'apt': status_check_apt_packages | default([]),
     'docker': status_check_docker_enabled,
     'snaps': status_check_snap_packages | default([])
   } | to_json }}`)
			if err != nil {
				return nil, err
			}
			probe.spec = arg
			return probe, nil
		}},
		fact("Status check | read the probe", nil, func() error {
			v, err := pyyaml.JSONLoads([]byte(probe.Output))
			if err != nil {
				return fmt.Errorf("the status probe's output: %w", err)
			}
			b.Set.SetFact("status_check_probe", v)
			return nil
		}),
		fact("Status check | systemd is-active for each service", nil, set("status_check_systemd_result", "{{ status_check_probe.systemd }}")),
		fact("Status check | initialize helper daemon version data", nil, func() error {
			b.Set.SetFact("status_check_daemon_versions", pyyaml.NewMap())
			b.Set.SetFact("status_check_daemon_outdated", []any{})
			return nil
		}),
		fact("Status check | inspect installed helper daemon versions", nil, set("status_check_daemon_version_result", "{{ status_check_probe.daemon_versions }}")),
		fact("Status check | prepare helper daemon version map", nil, func() error {
			versions := pyyaml.NewMap()
			for _, r := range results(get("status_check_daemon_version_result")) {
				raw, err := lookupFile(jinja.Str(path(r, "item", "version_source")))
				if err != nil {
					return err
				}
				installed := "missing"
				if c := path(r, "stat", "checksum"); c != nil {
					installed = jinja.Str(c)
				}
				v := pyyaml.NewMap()
				v.Set("installed", installed)
				v.Set("source", sha(raw))
				versions.Set(jinja.Str(path(r, "item", "name")), v)
			}
			b.Set.SetFact("status_check_daemon_versions", versions)
			return nil
		}),
		fact("Status check | collect outdated helper daemons", nil, func() error {
			var outdated []string
			if m, ok := get("status_check_daemon_versions").(*pyyaml.Map); ok {
				m.Each(func(k, v any) {
					if jinja.Str(path(v, "installed")) != jinja.Str(path(v, "source")) {
						outdated = append(outdated, jinja.Str(k))
					}
				})
			}
			b.Set.SetFact("status_check_daemon_outdated", anyList(outdated))
			return nil
		}),
		fact("Status check | normalize outdated helper daemon list", nil, func() error {
			b.Set.SetFact("status_check_daemon_outdated", anyList(unique(strs("status_check_daemon_outdated"))))
			return nil
		}),
		say("Status check | summary for systemd services"),
		fact("Status check | prepare scheduled oneshot jobs", nil, func() error {
			if err := set("status_check_systemd_jobs_enabled", "{{ status_check_systemd_jobs | default([]) | selectattr('enabled') | list }}")(); err != nil {
				return err
			}
			b.Set.SetFact("status_check_systemd_jobs_failed", []any{})
			b.Set.SetFact("status_check_systemd_jobs_never_run", []any{})
			return nil
		}),
		{Name: "Status check | inspect scheduled oneshot results", Build: func(*engine.Run) (engine.Resource, error) {
			loop := &engine.Multi{Desc: "systemctl show (jobs)"}
			jobs = nil
			for _, job := range siteMaps(get("status_check_systemd_jobs_enabled")) {
				cmd := &engine.Command{Argv: []string{"systemctl", "show", jinja.Str(job.Value("service")), "--property=ActiveState",
					"--property=Result", "--property=ExecMainStatus", "--property=InactiveExitTimestamp", "--no-pager"}, Probe: true, IgnoreErrors: true}
				jobs = append(jobs, cmd)
				loop.Items = append(loop.Items, cmd)
			}
			return loop, nil
		}},
		{Name: "Status check | inspect timer schedules", Build: func(*engine.Run) (engine.Resource, error) {
			loop := &engine.Multi{Desc: "systemctl show (timers)"}
			timers = nil
			for _, job := range siteMaps(get("status_check_systemd_jobs_enabled")) {
				cmd := &engine.Command{Argv: []string{"systemctl", "show", jinja.Str(job.Value("timer")), "--property=LastTriggerUSec",
					"--property=NextElapseUSecRealtime", "--no-pager"}, Probe: true, IgnoreErrors: true}
				timers = append(timers, cmd)
				loop.Items = append(loop.Items, cmd)
			}
			return loop, nil
		}},
		fact("Status check | collect failed scheduled oneshot jobs", nil, func() error {
			list := siteMaps(get("status_check_systemd_jobs_enabled"))
			jobResults, timerResults := []any{}, []any{}
			for i, cmd := range jobs {
				out := strings.TrimRight(cmd.Output, "\n")
				r := pyyaml.NewMap()
				r.Set("item", list[i])
				r.Set("rc", int64(cmd.Code))
				r.Set("stdout", out)
				jobResults = append(jobResults, r)
				t := pyyaml.NewMap()
				t.Set("item", list[i])
				t.Set("rc", int64(timers[i].Code))
				t.Set("stdout", strings.TrimRight(timers[i].Output, "\n"))
				timerResults = append(timerResults, t)
				if cmd.Code != 0 || jobFailedState.MatchString(out) || jobFailedResult(out) || jobFailedExec.MatchString(out) {
					appendTo("status_check_systemd_jobs_failed", jinja.Str(list[i].Value("service")))
				}
			}
			jr, tr := pyyaml.NewMap(), pyyaml.NewMap()
			jr.Set("results", jobResults)
			tr.Set("results", timerResults)
			b.Set.SetFact("status_check_systemd_jobs_result", jr)
			b.Set.SetFact("status_check_systemd_timer_result", tr)
			return nil
		}),
		fact("Status check | collect scheduled oneshot jobs that have not run yet", nil, func() error {
			for _, r := range results(get("status_check_systemd_jobs_result")) {
				out, service := jinja.Str(r.Value("stdout")), jinja.Str(path(r, "item", "service"))
				if asInt(r.Value("rc")) == 0 && !contains(strs("status_check_systemd_jobs_failed"), service) &&
					jobInactive.MatchString(out) && jobNeverExited.MatchString(out) {
					appendTo("status_check_systemd_jobs_never_run", service)
				}
			}
			return nil
		}),
		say("Status check | summary for scheduled oneshot jobs"),
		fact("Status check | init failed services list", nil, func() error {
			b.Set.SetFact("status_check_systemd_failed", []any{})
			return nil
		}),
		fact("Status check | collect failed systemd services (non-zero rc)", nil, func() error {
			for _, r := range results(get("status_check_systemd_result")) {
				if asInt(r.Value("rc")) != 0 {
					appendTo("status_check_systemd_failed", jinja.Str(path(r, "item", "name")))
				}
			}
			return nil
		}),
		fact("Status check | collect failed systemd services (bad state)", nil, func() error {
			for _, r := range results(get("status_check_systemd_result")) {
				if asInt(r.Value("rc")) == 0 && strings.TrimSpace(jinja.Str(r.Value("stdout"))) != "active" {
					appendTo("status_check_systemd_failed", jinja.Str(path(r, "item", "name")))
				}
			}
			return nil
		}),
		fact("Status check | docker containers info", nil, set("status_check_docker_result", "{{ status_check_probe.docker }}")),
		say("Status check | summary for Docker containers"),
		fact("Status check | init failed containers list", nil, func() error {
			b.Set.SetFact("status_check_docker_failed", []any{})
			return nil
		}),
		fact("Status check | collect failed containers", nil, func() error {
			if len(siteMaps(get("status_check_docker_enabled"))) == 0 {
				return nil
			}
			for _, r := range results(get("status_check_docker_result")) {
				state := path(r, "container", "State")
				status, hasStatus := path(state, "Status"), path(state, "Status") != nil
				health := path(state, "Health")
				bad := !jinja.Truthy(r.Value("exists")) ||
					(path(r, "container") != nil && ((hasStatus && jinja.Str(status) != "running") ||
						(health != nil && jinja.Str(path(health, "Status")) != "healthy")))
				if bad {
					appendTo("status_check_docker_failed", jinja.Str(path(r, "item", "name")))
				}
			}
			return nil
		}),
		fact("Status check | inspect managed artifacts", nil, set("status_check_managed_artifact_result", "{{ status_check_probe.artifacts }}")),
		fact("Status check | prepare managed artifact version map", nil, func() error {
			versions, _ := get("status_check_managed_artifact_versions").(*pyyaml.Map)
			if versions == nil {
				versions = pyyaml.NewMap()
			}
			for _, r := range results(get("status_check_managed_artifact_result")) {
				item := r.Value("item").(*pyyaml.Map)
				installed := "missing"
				if c := path(r, "stat", "checksum"); c != nil {
					installed = jinja.Str(c)
				}
				var source string
				switch {
				case item.Value("expected_checksum") != nil:
					// "A if defined else (B) | hash('sha256')": the filter binds
					// to the else branch only, so the expected checksum is used
					// as it is.
					source = jinja.Str(item.Value("expected_checksum"))
				case jinja.Str(item.Value("source_type")) == "template":
					out, err := b.Set.RenderFile(jinja.Str(item.Value("source")), nil, vars.TemplateOptions{})
					if err != nil {
						return err
					}
					lines := strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n")
					if len(lines) > 0 && lines[len(lines)-1] == "" {
						lines = lines[:len(lines)-1]
					}
					source = sha([]byte(strings.Join(lines, "\n") + "\n"))
				default:
					raw, err := lookupFile(jinja.Str(item.Value("source")))
					if err != nil {
						return err
					}
					source = sha(raw)
				}
				v := pyyaml.NewMap()
				v.Set("label", item.Value("label"))
				v.Set("installed", installed)
				v.Set("source", source)
				versions.Set(jinja.Str(item.Value("name")), v)
			}
			b.Set.SetFact("status_check_managed_artifact_versions", versions)
			return nil
		}),
		fact("Status check | collect outdated managed artifacts", nil, func() error {
			if m, ok := get("status_check_managed_artifact_versions").(*pyyaml.Map); ok {
				m.Each(func(k, v any) {
					if jinja.Str(path(v, "installed")) != jinja.Str(path(v, "source")) {
						appendTo("status_check_managed_artifacts_outdated", jinja.Str(k))
					}
				})
			}
			return nil
		}),
		say("Status check | summary for managed artifacts"),
		fact("Status check | initialize package failures", nil, func() error {
			b.Set.SetFact("status_check_package_failed", []any{})
			return nil
		}),
		fact("Status check | installed APT package versions", nil, set("status_check_apt_installed_result", "{{ status_check_probe.apt_installed }}")),
		fact("Status check | collect missing APT packages", nil, func() error {
			for _, r := range results(get("status_check_apt_installed_result")) {
				if asInt(r.Value("rc")) != 0 {
					appendTo("status_check_package_failed", "apt:"+jinja.Str(r.Value("item")))
				}
			}
			return nil
		}),
		fact("Status check | APT candidate package versions", nil, set("status_check_apt_candidate_result", "{{ status_check_probe.apt_candidate }}")),
		say("Status check | summary for APT package versions"),
		fact("Status check | installed snap package versions", nil, set("status_check_snap_result", "{{ status_check_probe.snaps }}")),
		fact("Status check | collect missing snap packages", nil, func() error {
			for _, r := range results(get("status_check_snap_result")) {
				rc := 1
				if v, ok := r.Get("rc"); ok {
					rc = asInt(v)
				}
				if rc != 0 {
					appendTo("status_check_package_failed", "snap:"+jinja.Str(r.Value("item")))
				}
			}
			return nil
		}),
		say("Status check | summary for snap package versions"),
		fact("Status check | unique failed services list", nil, func() error {
			b.Set.SetFact("status_check_systemd_failed_unique", anyList(unique(strs("status_check_systemd_failed"))))
			return nil
		}),
		fact("Status check | unique failed containers list", nil, func() error {
			b.Set.SetFact("status_check_docker_failed_unique", anyList(unique(strs("status_check_docker_failed"))))
			return nil
		}),
		say("Status check | final summary"),
	}
	failedUnits := func(*engine.Run) bool { return len(strs("status_check_systemd_failed_unique")) > 0 }
	failedContainers := func(*engine.Run) bool {
		return b.Bool("{{ status_check_docker_logs_enabled | default(true) | bool }}") && len(strs("status_check_docker_failed_unique")) > 0
	}
	lines := b.S("{{ status_check_journal_lines | default(40) }}")
	logLines := b.S("{{ status_check_docker_log_lines | default(80) }}")
	composeDir := b.S("{{ status_check_docker_logs_compose_dir | default('/opt/authelia') }}")
	printEach := func(name string, cmds *[]*engine.Command, items func() []string) engine.Step {
		return engine.Step{Name: name, Build: func(*engine.Run) (engine.Resource, error) {
			var msgs []string
			for i, item := range items() {
				r := pyyaml.NewMap()
				r.Set("item", item)
				r.Set("stdout", strings.TrimRight((*cmds)[i].Output, "\n"))
				msg, err := b.Set.RenderLocal(healthcheckMsgs[name], map[string]any{"item": r})
				if err != nil {
					return nil, err
				}
				msgs = append(msgs, msg)
			}
			return report(strings.Join(msgs, "\n")), nil
		}}
	}
	journal := printEach("Status check | print logs for failed services", &journals, func() []string { return strs("status_check_systemd_failed_unique") })
	journal.When = failedUnits
	docker := printEach("Status check | print docker logs for failed containers", &composeLogs, func() []string { return strs("status_check_docker_failed_unique") })
	docker.When = failedContainers
	return append(steps,
		engine.Step{Name: "Status check | journalctl for failed services", When: failedUnits, Build: func(*engine.Run) (engine.Resource, error) {
			loop := &engine.Multi{Desc: "journalctl"}
			journals = nil
			for _, unit := range strs("status_check_systemd_failed_unique") {
				cmd := &engine.Command{Argv: []string{"journalctl", "-u", unit, "-n", lines, "--no-pager"}, Probe: true, IgnoreErrors: true}
				journals = append(journals, cmd)
				loop.Items = append(loop.Items, cmd)
			}
			return loop, nil
		}},
		journal,
		engine.Step{Name: "Status check | docker compose logs (failed containers)", When: failedContainers, Build: func(*engine.Run) (engine.Resource, error) {
			loop := &engine.Multi{Desc: "docker compose logs"}
			composeLogs = nil
			for _, name := range strs("status_check_docker_failed_unique") {
				cmd := &engine.Command{Argv: []string{"docker", "compose", "logs", "--tail", logLines, name}, Dir: composeDir, Probe: true, IgnoreErrors: true}
				composeLogs = append(composeLogs, cmd)
				loop.Items = append(loop.Items, cmd)
			}
			return loop, nil
		}},
		docker,
		engine.Step{Name: "Status check | fail if there are problems (optional)",
			When: func(*engine.Run) bool {
				return b.Bool("{{ status_check_fail_on_error | default(false) | bool }}") &&
					(len(strs("status_check_systemd_failed_unique")) > 0 || len(strs("status_check_systemd_jobs_failed")) > 0 ||
						len(strs("status_check_managed_artifacts_outdated")) > 0 || len(strs("status_check_package_failed")) > 0 ||
						len(strs("status_check_docker_failed_unique")) > 0)
			},
			Build: func(*engine.Run) (engine.Resource, error) {
				msg, err := b.Set.Render(healthcheckMsgs["Status check | fail if there are problems (optional)"])
				if err != nil {
					return nil, err
				}
				return nil, fmt.Errorf("%s", msg)
			}},
	)
}
