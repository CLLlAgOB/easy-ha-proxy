package updatescope

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
)

// RunCLI is "easy-ha-proxy-agent update-scope plan|record", for the
// installer's "changes only" update and its record of a complete one:
//
//	update-scope plan --config DIR --source DIR      what applying the source needs (JSON)
//	update-scope record --config DIR --source DIR [--revision R]
func RunCLI(args []string, stdout, stderr io.Writer) int {
	usage := func() int {
		fmt.Fprintln(stderr, "usage: easy-ha-proxy-agent update-scope plan|record --config DIR --source DIR [--revision R]")
		return 2
	}
	if len(args) < 1 || (args[0] != "plan" && args[0] != "record") {
		return usage()
	}
	fs := flag.NewFlagSet("update-scope", flag.ContinueOnError)
	fs.SetOutput(stderr)
	config := fs.String("config", "/etc/easy-ha-proxy", "the managed configuration")
	source := fs.String("source", "/opt/easy-ha-proxy/source", "the source tree")
	revision := fs.String("revision", "", "the source revision (record)")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
		return usage()
	}
	if args[0] == "record" {
		if _, err := WriteApplied(*config, *source, *revision); err != nil {
			fmt.Fprintf(stderr, "could not record the applied source: %v\n", err)
			return 1
		}
		return 0
	}
	raw, err := json.Marshal(PlanScope(*config, *source))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintln(stdout, string(raw))
	return 0
}
