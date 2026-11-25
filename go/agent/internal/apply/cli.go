// Package apply is the Go installer that replaces ansible/easy-ha-proxy.yml,
// stage by stage. Phase 0 has only its inputs: the variables (vars) and the
// host facts (facts), and a read-only command that prints them.
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
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/facts"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/vars"
)

// Run is "easy-ha-proxy-agent apply <command>".
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "vars" {
		fmt.Fprintln(stderr, "usage: easy-ha-proxy-agent apply vars [--play N] [--role NAME] [--param k=v]... [--extra k=v]... [--names FILE]")
		return 2
	}
	return runVars(args[1:], stdout, stderr)
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
