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
			return runPlan(args[1:], stdout, stderr)
		}
	}
	fmt.Fprintln(stderr, "usage: easy-ha-proxy-agent apply vars [--play N] [--role NAME] [--param k=v]... [--extra k=v]... [--names FILE]")
	fmt.Fprintln(stderr, "       easy-ha-proxy-agent apply plan --stage NAME [--changed REGISTER]... [--json]")
	return 2
}

type list []string

func (l *list) String() string     { return strings.Join(*l, ",") }
func (l *list) Set(s string) error { *l = append(*l, s); return nil }

// runPlan checks a stage against the host and prints what an apply would
// change, step by step. It changes nothing.
func runPlan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("apply plan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	source := fs.String("source", "/opt/easy-ha-proxy/source", "the checkout holding ansible/")
	config := fs.String("config", "/etc/easy-ha-proxy", "the managed configuration")
	stage := fs.String("stage", "", "the stage: "+strings.Join(stages.Names(), ", "))
	asJSON := fs.Bool("json", false, "print the journal (JSON lines) instead of a table")
	var changed list
	fs.Var(&changed, "changed", "a registered result of an earlier stage that changed (repeatable)")
	if err := fs.Parse(args); err != nil || *stage == "" {
		fmt.Fprintln(stderr, "usage: easy-ha-proxy-agent apply plan --stage NAME [--changed REGISTER]... [--json]")
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
	run := engine.NewRun(engine.Plan, engine.Host(), journal, changed...)
	ctx := stages.Context{SourceDir: *source, ConfigDir: *config, Facts: hostFacts, Sys: run.Sys,
		Extra: map[string]any{"easy_ha_proxy_config_dir": *config, "easy_ha_proxy_target": "easy_ha_proxy"}}
	err = stages.Run(ctx, *stage, run)
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
		counts := run.Counts()
		fmt.Fprintf(stdout, "\n%d steps: %d ok, %d would change, %d skipped\n", len(run.Results),
			counts["ok"], counts["would_change"], counts["skipped"])
	}
	if err != nil {
		fmt.Fprintf(stderr, "plan: %v\n", err)
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
		Params: params, Extra: extra, Facts: hostFacts})
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
