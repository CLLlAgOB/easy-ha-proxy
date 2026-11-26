package apply

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"easy-ha-proxy/panel/shared/jinja"
	"easy-ha-proxy/panel/shared/pyyaml"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/engine"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/facts"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/stages"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/vars"
)

// entry is one role entry (or pre-task) of the playbook, with the parts it
// runs and the tags Ansible would select it by.
type entry struct {
	play      int
	label     string
	taskStage string
	parts     []string
	tags      []string
}

// haproxyAdminEntries are the haproxy-admin entries that import several task
// files (install.yml, daemons.yml) instead of one.
var haproxyAdminEntries = map[string][]string{
	"install": {"packages", "fs", "certd", "controld", "backupd", "iptables-ban", "iptables-udp"},
	"daemons": {"native", "certd", "controld", "backupd", "updated", "alertd", "metricsd", "guardd", "healthd"},
}

// roleWithoutStage is the part of a role whose main.yml is one task file.
var roleWithoutStage = map[string]string{
	"docker":          "docker/docker",
	"geoip_acl":       "geoip_acl/geoip",
	"update_packages": "update_packages/upgrade",
	"healthcheck":     "healthcheck/status",
}

// partsFor maps a role entry to the parts that run it; nil when the Go
// installer does not run it yet.
func partsFor(role, stage string) []string {
	known := stages.Parts()
	if stage == "" {
		if p, ok := roleWithoutStage[role]; ok {
			return []string{p}
		}
		return nil
	}
	if role == "haproxy-admin" {
		if list, ok := haproxyAdminEntries[stage]; ok {
			return list
		}
		if _, ok := known[stage]; ok {
			return []string{stage}
		}
		return nil
	}
	if _, ok := known[role+"/"+stage]; ok {
		return []string{role + "/" + stage}
	}
	return nil
}

func tagList(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		out := []string{}
		for _, t := range x {
			out = append(out, jinja.Str(t))
		}
		return out
	}
	return nil
}

// readEntries reads the playbook's plays: the HAProxy protection pre-task and
// every role entry, in order. The other pre-tasks set facts the loader sets
// itself (secrets, the proxy secret, the time zone, certbot_domains), or are
// handled by the runner (the secret's check, addsite's issuance mode).
func readEntries(sourceDir string) ([]entry, error) {
	raw, err := os.ReadFile(filepath.Join(sourceDir, vars.Playbook))
	if err != nil {
		return nil, err
	}
	doc, err := pyyaml.Load(raw)
	if err != nil {
		return nil, err
	}
	plays, _ := doc.([]any)
	var out []entry
	for i, p := range plays {
		play, ok := p.(*pyyaml.Map)
		if !ok {
			continue
		}
		pre, _ := play.Value("pre_tasks").([]any)
		for _, t := range pre {
			task := t.(*pyyaml.Map)
			role, _ := task.Value("ansible.builtin.import_role").(*pyyaml.Map)
			if role != nil && role.Value("name") == "haproxy" {
				out = append(out, entry{play: i, label: "pre_tasks: " + jinja.Str(task.Value("name")),
					parts: []string{"haproxy/protection"}, tags: tagList(task.Value("tags"))})
			}
		}
		roles, _ := play.Value("roles").([]any)
		for _, r := range roles {
			m := r.(*pyyaml.Map)
			role := jinja.Str(m.Value("role"))
			stage := ""
			if s, ok := m.Get("task_stage"); ok {
				stage = jinja.Str(s)
			}
			label := role
			if stage != "" {
				label += " (" + stage + ")"
			}
			out = append(out, entry{play: i, label: label, taskStage: stage, parts: partsFor(role, stage), tags: tagList(m.Value("tags"))})
		}
	}
	return out, nil
}

// selected is Ansible's tag evaluation for a task with these tags.
func selected(tags []string, only, skip map[string]bool) bool {
	has := func(set map[string]bool) bool {
		for _, t := range tags {
			if set[t] {
				return true
			}
		}
		return false
	}
	own := map[string]bool{}
	for _, t := range tags {
		own[t] = true
	}
	run := false
	switch {
	case own["always"]:
		run = true
	case only["all"] && !own["never"]:
		run = true
	case has(only):
		run = true
	case only["tagged"] && len(tags) > 0 && !own["never"]:
		run = true
	}
	if run && len(skip) > 0 {
		switch {
		case skip["all"]:
			if !own["always"] || skip["always"] {
				run = false
			}
		case has(skip):
			run = false
		case skip["tagged"] && len(tags) > 0:
			run = false
		}
	}
	return run
}

func splitTags(s string) map[string]bool {
	out := map[string]bool{}
	for _, t := range strings.Split(s, ",") {
		if t = strings.TrimSpace(t); t != "" {
			out[t] = true
		}
	}
	return out
}

var proxySecret = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// runPlaybook is "apply playbook": the whole playbook as ansible-playbook
// --tags would run it, every role entry through its parts, the handlers at a
// flush and at the end of each play. It refuses to start when a selected
// entry has no part yet, so a caller can fall back to Ansible.
func runPlaybook(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("apply playbook", flag.ContinueOnError)
	fs.SetOutput(stderr)
	source := fs.String("source", "/opt/easy-ha-proxy/source", "the checkout holding ansible/")
	config := fs.String("config", "/etc/easy-ha-proxy", "the managed configuration")
	tags := fs.String("tags", "all", "the tags to run, as --tags")
	skipTags := fs.String("skip-tags", "", "the tags to skip, as --skip-tags")
	check := fs.Bool("check", false, "plan only: change nothing, as --check")
	supported := fs.Bool("supported", false, "only say whether every selected entry runs in the Go installer (exit 0) or not (exit 3)")
	extra := pairs{}
	fs.Var(extra, "extra", "an extra variable, key=value (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	only, skip := splitTags(*tags), splitTags(*skipTags)
	entries, err := readEntries(*source)
	if err != nil {
		fmt.Fprintf(stderr, "playbook: %v\n", err)
		return 1
	}
	var run []entry
	var missing []string
	for _, e := range entries {
		if !selected(e.tags, only, skip) {
			continue
		}
		if e.parts == nil {
			missing = append(missing, e.label)
			continue
		}
		run = append(run, e)
	}
	if len(missing) > 0 {
		fmt.Fprintf(stderr, "not in the Go installer yet: %s\n", strings.Join(missing, ", "))
		return 3
	}
	if *supported {
		return 0
	}

	mode := engine.Apply
	if *check {
		mode = engine.Plan
	}
	hostFacts, err := facts.Setup(facts.Options{})
	if err != nil {
		fmt.Fprintf(stderr, "facts: %v\n", err)
		return 1
	}
	extra["easy_ha_proxy_config_dir"] = *config
	if _, ok := extra["easy_ha_proxy_target"]; !ok {
		extra["easy_ha_proxy_target"] = "easy_ha_proxy"
	}
	r := engine.NewRun(mode, engine.Host(), nil)
	for tag := range skip {
		r.SkipTags[tag] = true
	}
	setFacts := map[string]any{}
	// The addsite pre-task: issue only the lineages that are missing.
	if selected([]string{"addsite"}, only, skip) {
		setFacts["cert_issue_mode"] = "new"
	}
	ctx := stages.Context{SourceDir: *source, ConfigDir: *config, Facts: hostFacts, Sys: r.Sys, Extra: extra,
		SetFacts: setFacts, Handed: map[string]any{}, HostTimezone: facts.Timezone(facts.Exec, ""), Shared: map[string]any{}}

	// The pre-task that refuses a missing or unsafe proxy secret (tagged always).
	set, err := vars.Load(vars.Options{SourceDir: *source, ConfigDir: *config, Extra: extra, Facts: hostFacts, HostTimezone: ctx.HostTimezone})
	if err != nil {
		fmt.Fprintf(stderr, "vars: %v\n", err)
		return 1
	}
	if s, err := set.Render("{{ haproxy_admin_proxy_secret | string }}"); err != nil || len(s) < 32 || !proxySecret.MatchString(s) {
		fmt.Fprintln(stderr, "haproxy_admin_proxy_secret is missing or unsafe. Run the current easy-ha-proxy installer once to migrate secrets.yml.")
		return 1
	}

	progress := os.Getenv("EASY_HA_PROXY_PROGRESS") == "1"
	total, done := 0, 0
	if progress {
		for _, e := range run {
			for _, p := range e.parts {
				total += stages.CountSteps(ctx, p, e.taskStage)
			}
		}
		fmt.Fprintf(stdout, "EHP-PROGRESS 0/%d\n", total)
		r.OnStep = func(stage, step string) {
			// Handlers are not in the count; named without moving the bar,
			// as Ansible's progress callback does.
			if !strings.Contains(stage, "/handler/") {
				done++
			}
			fmt.Fprintf(stdout, "EHP-PROGRESS %d/%d %s | %s\n", done, total, stage, strings.Join(strings.Fields(step), " "))
		}
	}

	printed := 0
	report := func() {
		for _, res := range r.Results[printed:] {
			if res.Status == "changed" || res.Status == "would_change" || res.Status == "failed" {
				line := fmt.Sprintf("%-12s %s | %s", res.Status, res.Stage, res.Step)
				if res.Summary != "" {
					line += ": " + res.Summary
				}
				if res.Error != "" {
					line += ": " + res.Error
				}
				fmt.Fprintln(stdout, line)
			}
		}
		printed = len(r.Results)
	}
	fail := func(err error) int {
		report()
		fmt.Fprintf(stderr, "apply playbook: %v\n", err)
		recap(stdout, r)
		return 1
	}
	play := -1
	for _, e := range run {
		if e.play != play {
			if play >= 0 {
				if err := stages.FlushHandlers(ctx, r); err != nil {
					return fail(err)
				}
			}
			play = e.play
		}
		fmt.Fprintf(stdout, "== %s\n", e.label)
		for _, p := range e.parts {
			if err := stages.RunPart(ctx, p, e.taskStage, r); err != nil {
				return fail(err)
			}
		}
		// cert renew flushes the handlers at once (renew__30_assemble.yml).
		if e.taskStage == "renew" && contains(r.Notified(), "build_pems_and_reload") {
			if err := stages.FlushHandlers(ctx, r); err != nil {
				return fail(err)
			}
		}
		report()
	}
	if err := stages.FlushHandlers(ctx, r); err != nil {
		return fail(err)
	}
	report()
	recap(stdout, r)
	return 0
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func recap(w io.Writer, r *engine.Run) {
	c := r.Counts()
	fmt.Fprintf(w, "RECAP ok=%d changed=%d would_change=%d skipped=%d failed=%d\n",
		c["ok"], c["changed"], c["would_change"], c["skipped"], c["failed"])
}
