// Package apply is the Go installer that replaces ansible/easy-ha-proxy.yml,
// stage by stage: its inputs (vars, facts), the engine that checks and applies
// resources (engine), and the stages themselves (stages). So far it only reads:
// "apply vars" prints a role's variables, "apply plan" what a stage would change.
package apply

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"easy-ha-proxy/panel/shared/pyyaml"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/engine"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/facts"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/stages"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/vars"
)

// Run is "easy-ha-proxy-agent apply <command>".
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "vars":
			return runVars(args[1:], stdout, stderr)
		case "plan":
			return runStage(engine.Plan, args[1:], stdout, stderr)
		case "run":
			return runStage(engine.Apply, args[1:], stdout, stderr)
		case "parts":
			return runParts(stdout)
		}
	}
	fmt.Fprintln(stderr, "usage: easy-ha-proxy-agent apply vars [--play N] [--role NAME] [--param k=v]... [--extra k=v]... [--names FILE]")
	fmt.Fprintln(stderr, "       easy-ha-proxy-agent apply plan|run (--stage NAME | --part NAME [--task-stage NAME])")
	fmt.Fprintln(stderr, "                            [--changed REGISTER]... [--skip-tag TAG]... [--extra k=v]... [--json]")
	fmt.Fprintln(stderr, "       easy-ha-proxy-agent apply parts")
	return 2
}

type list []string

func (l *list) String() string     { return strings.Join(*l, ",") }
func (l *list) Set(s string) error { *l = append(*l, s); return nil }

// runParts prints the parts this agent can run and the registered results
// each one reads, for Ansible to decide which task files to hand over.
func runParts(stdout io.Writer) int {
	out := map[string]any{}
	for name, part := range stages.Parts() {
		reads := part.Reads
		if reads == nil {
			reads = []string{}
		}
		out[name] = map[string]any{"role": part.Role, "reads": reads}
	}
	raw, _ := json.Marshal(map[string]any{"parts": out})
	fmt.Fprintln(stdout, string(raw))
	return 0
}

// Summary is runStage's last line: what Ansible reads back.
type Summary struct {
	Changed   bool            `json:"changed"`
	Registers map[string]bool `json:"registers"`
	// Exports are the registers some part reads (its Reads), the only ones
	// Ansible needs to keep as facts for later calls.
	Exports map[string]bool `json:"exports"`
	// Notified are the handlers the steps notified; during the hybrid period
	// Ansible notifies its own handlers with them.
	Notified []string `json:"notified"`
	// Facts are the set_fact values later task files read (the parts'
	// Facts), with their values; Ansible keeps them and hands them back.
	Facts  map[string]any `json:"facts"`
	Counts map[string]int `json:"counts"`
}

// runStage checks (plan) or applies (run) a stage or one part. It prints one
// line per step, then a JSON summary line: whether anything changed (or would)
// and every registered result with whether it changed.
func runStage(mode engine.Mode, args []string, stdout, stderr io.Writer) int {
	name := "apply plan"
	if mode == engine.Apply {
		name = "apply run"
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	source := fs.String("source", "/opt/easy-ha-proxy/source", "the checkout holding ansible/")
	config := fs.String("config", "/etc/easy-ha-proxy", "the managed configuration")
	stage := fs.String("stage", "", "a stage: "+strings.Join(stages.Names(), ", "))
	taskStage := fs.String("task-stage", "", "the task_stage of the role entry running the part")
	asJSON := fs.Bool("json", false, "print the journal (JSON lines) instead of a table")
	var changed, skipTags, partNames list
	fs.Var(&partNames, "part", "a part (a task file); repeat to run several in order in one run")
	extra := pairs{}
	fs.Var(&changed, "changed", "a registered result of an earlier stage that changed (repeatable)")
	fs.Var(&skipTags, "skip-tag", "a task tag to skip, as --skip-tags (repeatable)")
	fs.Var(extra, "extra", "an extra variable, key=value (repeatable)")
	factsJSON := fs.String("facts", "", "set_fact values of earlier task files, as a JSON object")
	if err := fs.Parse(args); err != nil || (*stage == "") == (len(partNames) == 0) {
		fmt.Fprintf(stderr, "usage: easy-ha-proxy-agent %s (--stage NAME | --part NAME) ...\n", name)
		return 2
	}
	hostFacts, err := facts.Setup(facts.Options{})
	if err != nil {
		fmt.Fprintf(stderr, "facts: %v\n", err)
		return 1
	}
	var journal io.Writer
	if *asJSON {
		journal = stdout
	}
	run := engine.NewRun(mode, engine.Host(), journal, changed...)
	for _, tag := range skipTags {
		run.SkipTags[tag] = true
	}
	extra["easy_ha_proxy_config_dir"] = *config
	if _, ok := extra["easy_ha_proxy_target"]; !ok {
		extra["easy_ha_proxy_target"] = "easy_ha_proxy"
	}
	setFacts := map[string]any{}
	if *factsJSON != "" {
		if setFacts, err = parseFacts(*factsJSON); err != nil {
			fmt.Fprintf(stderr, "--facts: %v\n", err)
			return 2
		}
	}
	handed := map[string]any{}
	ctx := stages.Context{SourceDir: *source, ConfigDir: *config, Facts: hostFacts, Sys: run.Sys, Extra: extra,
		SetFacts: setFacts, Handed: handed, HostTimezone: facts.Timezone(facts.Exec, "")}
	if len(partNames) > 0 {
		for _, name := range partNames {
			if err = stages.RunPart(ctx, name, *taskStage, run); err != nil {
				break
			}
		}
	} else {
		err = stages.Run(ctx, *stage, run)
	}
	if !*asJSON {
		for _, res := range run.Results {
			line := fmt.Sprintf("%-12s %s", res.Status, res.Step)
			if res.Summary != "" {
				line += ": " + res.Summary
			}
			if res.Error != "" {
				line += ": " + res.Error
			}
			fmt.Fprintln(stdout, line)
		}
	}
	counts := run.Counts()
	registers := run.Registers()
	exports := map[string]bool{}
	for _, p := range stages.Parts() {
		for _, name := range append(append([]string{}, p.Reads...), p.Exports...) {
			if v, ok := registers[name]; ok {
				exports[name] = v
			}
		}
	}
	summary := Summary{Changed: counts["changed"]+counts["would_change"] > 0, Registers: registers, Exports: exports,
		Notified: run.Notified(), Facts: handed, Counts: counts}
	if summary.Notified == nil {
		summary.Notified = []string{}
	}
	raw, _ := json.Marshal(summary)
	fmt.Fprintln(stdout, string(raw))
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", name, err)
		return 1
	}
	return 0
}

type pairs map[string]any

func (p pairs) String() string { return fmt.Sprint(map[string]any(p)) }

func (p pairs) Set(s string) error {
	k, v, ok := strings.Cut(s, "=")
	if !ok || k == "" {
		return fmt.Errorf("%q is not key=value", s)
	}
	p[k] = v
	return nil
}

// runVars prints, as JSON, every variable a task of the role sees:
// {"name": {"v": value}} or {"name": {"error": "..."}}. Read only.
func runVars(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("apply vars", flag.ContinueOnError)
	fs.SetOutput(stderr)
	source := fs.String("source", "/opt/easy-ha-proxy/source", "the checkout holding ansible/")
	config := fs.String("config", "/etc/easy-ha-proxy", "the managed configuration")
	play := fs.Int("play", 0, "the play's index in the playbook")
	role := fs.String("role", "", "the running role (empty: the play's own tasks)")
	namesFile := fs.String("names", "", "a JSON list of the names to print (default: every name the sources define)")
	params, extra := pairs{}, pairs{}
	fs.Var(params, "param", "a role parameter, key=value (repeatable)")
	fs.Var(extra, "extra", "an extra variable, key=value (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	hostFacts, err := facts.Setup(facts.Options{})
	if err != nil {
		fmt.Fprintf(stderr, "facts: %v\n", err)
		return 1
	}
	set, err := vars.Load(vars.Options{SourceDir: *source, ConfigDir: *config, Play: *play, Role: *role,
		Params: params, Extra: extra, Facts: hostFacts, HostTimezone: facts.Timezone(facts.Exec, "")})
	if err != nil {
		fmt.Fprintf(stderr, "vars: %v\n", err)
		return 1
	}
	names := set.Names()
	if *namesFile != "" {
		raw, err := os.ReadFile(*namesFile)
		if err != nil {
			fmt.Fprintf(stderr, "names: %v\n", err)
			return 1
		}
		names = nil
		if err := json.Unmarshal(raw, &names); err != nil {
			fmt.Fprintf(stderr, "names: %v\n", err)
			return 1
		}
	}
	sort.Strings(names)
	out := pyyaml.NewMap()
	for _, name := range names {
		entry := pyyaml.NewMap()
		if v, err := set.Get(name); err != nil {
			entry.Set("error", err.Error())
		} else {
			entry.Set("v", v)
		}
		out.Set(name, entry)
	}
	text, err := pyyaml.JSONDumps(out, false, false)
	if err != nil {
		fmt.Fprintf(stderr, "json: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, text)
	return 0
}

// parseFacts reads --facts: a JSON object whose numbers become int64 where
// they are whole, as YAML would have read them.
func parseFacts(raw string) (map[string]any, error) {
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	var out map[string]any
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	for k, v := range out {
		out[k] = fromJSON(v)
	}
	return out, nil
}

func fromJSON(v any) any {
	switch x := v.(type) {
	case json.Number:
		if n, err := x.Int64(); err == nil {
			return n
		}
		f, _ := x.Float64()
		return f
	case []any:
		for i := range x {
			x[i] = fromJSON(x[i])
		}
		return x
	case map[string]any:
		m := pyyaml.NewMap()
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			m.Set(k, fromJSON(x[k]))
		}
		return m
	}
	return v
}
