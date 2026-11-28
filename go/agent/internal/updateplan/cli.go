package updateplan

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
)

// buildPlan is the checker the command runs; the tests replace it.
var buildPlan = BuildUpdatePlan

// RunCLI is "easy-ha-proxy-agent update-plan": the update broker runs it and
// signs the plan it prints.
//
//	update-plan [--format json] [--source-channel github|local] [--image-channel latest|alpha]
//	            [--branch NAME] [--haproxy-status]
func RunCLI(args []string, stdout, stderr io.Writer) int {
	fail := func(message string) int {
		fmt.Fprintln(stderr, "usage: easy-ha-proxy-agent update-plan [--format json] [--source-channel github|local] "+
			"[--image-channel latest|alpha] [--branch NAME] [--haproxy-status]")
		fmt.Fprintln(stderr, "easy-ha-proxy-agent update-plan: error: "+message)
		return 2
	}
	fs := flag.NewFlagSet("update-plan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	format := fs.String("format", "json", "")
	sourceChannel := fs.String("source-channel", "", "")
	imageChannel := fs.String("image-channel", "", "")
	branch := fs.String("branch", "", "")
	haproxyStatus := fs.Bool("haproxy-status", false, "")
	if err := fs.Parse(args); err != nil {
		return fail(err.Error())
	}
	if fs.NArg() != 0 {
		return fail("unrecognized arguments")
	}
	if *format != "json" {
		return fail("invalid --format")
	}
	if *sourceChannel != "" && !validSourceChannels[*sourceChannel] {
		return fail("invalid --source-channel")
	}
	if *imageChannel != "" && !validImageChannels[*imageChannel] {
		return fail("invalid --image-channel")
	}
	branchSet := false
	fs.Visit(func(f *flag.Flag) { branchSet = branchSet || f.Name == "branch" })
	if branchSet && !validBranch(*branch) {
		return fail("invalid --branch")
	}
	plan, err := buildPlan(Options{
		SourceChannel:  *sourceChannel,
		ImageChannel:   *imageChannel,
		Branch:         *branch,
		IncludeHAProxy: *haproxyStatus,
		// The scheduled and the requested checks ask the registry.
		Fetch: HTTPGet,
	})
	if err != nil {
		return fail(err.Error())
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(plan); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}
