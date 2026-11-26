package contract

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// A renewed certificate that HAProxy never loads is not a renewed
// certificate. In the incident, the PEMs were rebuilt correctly but HAProxy
// kept presenting the previous ones for eight hours: the reload was guarded
// by `if systemctl list-unit-files | grep -q ...` under set -euo pipefail.
// grep -q exits at the first match, systemctl takes SIGPIPE part-way through
// writing four hundred more unit names, pipefail turns the status into 141
// and the condition is false -- the reload never ran. These tests keep the
// fix from decaying back into a pipeline, and keep any other shipped hook
// from repeating the mistake.

const reloadHookPath = "ansible/roles/cert/templates/905-haproxy-pems-reload.sh.j2"

// reloadHookSourceAndTail is the hook and everything after its
// "# Reload HAProxy." marker.
func reloadHookSourceAndTail(t *testing.T) (string, string) {
	t.Helper()
	source := read(t, reloadHookPath)
	parts := strings.SplitN(source, "# Reload HAProxy.", 2)
	if len(parts) != 2 {
		t.Fatal("no '# Reload HAProxy.' marker in the reload hook")
	}
	return source, parts[1]
}

func TestTheScriptStillUsesPipefail(t *testing.T) {
	// Not a thing to remove -- the rest of the script wants it. The guard
	// has to stop depending on a pipeline instead.
	source, _ := reloadHookSourceAndTail(t)
	mustContain(t, source, "set -euo pipefail", "905-haproxy-pems-reload.sh.j2")
}

func TestTheReloadIsNotGuardedByAPipeline(t *testing.T) {
	_, tail := reloadHookSourceAndTail(t)
	for _, line := range strings.Split(tail, "\n") {
		stripped := strings.TrimSpace(line)
		if stripped == "" || strings.HasPrefix(stripped, "#") {
			continue
		}
		// A pipe anywhere in the guard reintroduces the fault: under
		// pipefail the status is the last non-zero one, and a
		// short-circuiting reader makes the writer fail.
		if strings.Contains(line, "|") {
			label := []rune(stripped)
			if len(label) > 60 {
				label = label[:60]
			}
			t.Errorf("reload guard holds a pipe: %s", string(label))
		}
	}
}

func TestItStillChecksTheUnitExists(t *testing.T) {
	// The check is worth keeping: the same script runs on hosts that have
	// no HAProxy at all.
	_, tail := reloadHookSourceAndTail(t)
	mustContain(t, tail, "systemctl cat", "reload tail")
}

func TestItReloadsAndFallsBackToRestart(t *testing.T) {
	_, tail := reloadHookSourceAndTail(t)
	mustContain(t, tail, "systemctl reload", "reload tail")
	mustContain(t, tail, "systemctl restart", "reload tail")
}

func TestAReloadThatFailsIsLoud(t *testing.T) {
	// The incident was silent. A rebuilt certificate that is not being
	// served has to make the renewal report a failure.
	_, tail := reloadHookSourceAndTail(t)
	mustContain(t, tail, "ERROR", "reload tail")
	mustContain(t, tail, "exit 1", "reload tail")
	mustContain(t, tail, ">&2", "reload tail")
}

func TestTheReloadComesAfterThePemsAreBuilt(t *testing.T) {
	source, _ := reloadHookSourceAndTail(t)
	build := strings.Index(source, "build_pem")
	reload := strings.Index(source, "systemctl reload")
	if build < 0 || reload < 0 {
		t.Fatal("build_pem or systemctl reload missing from the hook")
	}
	if build >= reload {
		t.Errorf("build_pem at %d must come before systemctl reload at %d", build, reload)
	}
}

var shortCircuitPipe = regexp.MustCompile(`^(if|elif|while)\s+.*\|\s*grep\s+-q`)
var guardPrefix = regexp.MustCompile(`^(if|elif|while)\s+!?\s*`)
var exemptWriter = regexp.MustCompile(`^(echo|printf)[ \t]`)

func TestNoShippedHookGuardsACommandWithAShortCircuitingPipe(t *testing.T) {
	// The pattern is easy to write and fails only under load.
	root := repoRoot(t)
	sources := []struct{ dir, suffix string }{
		{filepath.Join(root, "ansible", "roles", "cert", "templates"), ".sh.j2"},
		{filepath.Join(root, "go", "agent", "internal", "apply", "stages"), "_scripts.go"},
	}
	var paths []string
	for _, src := range sources {
		entries, err := os.ReadDir(src.dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), src.suffix) {
				paths = append(paths, filepath.Join(src.dir, entry.Name()))
			}
		}
	}
	sort.Strings(paths)
	var offenders []string
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		text := string(raw)
		if !strings.Contains(text, "pipefail") {
			continue
		}
		for number, line := range strings.Split(text, "\n") {
			stripped := strings.TrimSpace(line)
			if strings.HasPrefix(stripped, "#") {
				continue
			}
			// `if <writer> | grep -q ...` is the shape that bites: grep
			// leaves early, the writer dies of SIGPIPE, pipefail reports
			// it, and the branch silently does not run.
			//
			// echo and printf are exempt, and not as a convenience: they
			// write one short string that fits the pipe buffer and are
			// finished before grep is scheduled, so there is no signal to
			// take. What is dangerous is a writer with a lot to say --
			// systemctl, journalctl, find, ss -- which is still going
			// when the reader leaves.
			if !shortCircuitPipe.MatchString(stripped) {
				continue
			}
			writer := guardPrefix.ReplaceAllString(stripped, "")
			if exemptWriter.MatchString(writer) {
				continue
			}
			offenders = append(offenders, fmt.Sprintf("%s:%d", filepath.Base(path), number+1))
		}
	}
	if len(offenders) != 0 {
		t.Errorf("hooks guard a command with a short-circuiting pipe: %v", offenders)
	}
}
