// Command pinned-versions reports newer releases of the versions pinned in
// Ansible role defaults (the weekly dependencies job).
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/pinnedversions"
)

func main() {
	github := flag.Bool("github", false, "write the job summary and keep the tracking issue in step")
	root := flag.String("root", ".", "the checkout holding ansible/")
	flag.Parse()
	rows := pinnedversions.Check(*root, pinnedversions.GetJSON)
	text := pinnedversions.Report(rows)
	fmt.Print(text)
	if *github {
		if summary := os.Getenv("GITHUB_STEP_SUMMARY"); summary != "" {
			if f, err := os.OpenFile(summary, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
				fmt.Fprint(f, "## Pinned versions\n\n"+text)
				f.Close()
			}
		}
		body := "Versions pinned in Ansible role defaults that have newer releases. " +
			"Take the same-series update after reading its notes; a newer series may " +
			"need care.\n\n" + text
		if err := pinnedversions.SyncIssue(body, pinnedversions.Behind(rows)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
