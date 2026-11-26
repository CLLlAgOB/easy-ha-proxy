package contract

import (
	"regexp"
	"strings"
	"testing"
)

// The former Python daemons go last, and only when no installed unit names
// them. The native stage used to remove /usr/local/sbin/*.py before the
// later stages rewrote the units; a run from 1.1.x that stopped in between
// (a certificate issue, a refused HAProxy configuration) left units
// starting scripts that were gone, the update broker's own among them.

// nativeCleanupStageRe is task_stage: ([\w-]+) with Python's Unicode \w
// (letters, numbers and underscore).
var nativeCleanupStageRe = regexp.MustCompile(`task_stage: ([\p{L}\p{N}_-]+)`)

// nativeCleanupStagePositions maps each stage of the first play to the
// offset of its task_stage match; a repeated name keeps its last position,
// as the Python dict comprehension did.
func nativeCleanupStagePositions(t *testing.T) map[string]int {
	t.Helper()
	text := read(t, "ansible/easy-ha-proxy.yml")
	parts := strings.SplitN(text, "\n- hosts:", 3)
	if len(parts) < 2 {
		t.Fatal("the playbook has no play")
	}
	firstPlay := parts[1]
	positions := map[string]int{}
	for _, m := range nativeCleanupStageRe.FindAllStringSubmatchIndex(firstPlay, -1) {
		positions[firstPlay[m[2]:m[3]]] = m[0]
	}
	return positions
}

// The cleanup of the former Python daemons runs after every stage that
// writes a unit, so no unit is ever left starting a removed script.
func TestTheCleanupRunsAfterEveryUnitStage(t *testing.T) {
	positions := nativeCleanupStagePositions(t)
	cleanup, ok := positions["native-cleanup"]
	if !ok {
		t.Fatal("no native-cleanup stage")
	}
	for _, stage := range []string{"native", "healthd", "controld", "backupd", "updated", "alertd", "metricsd", "guardd",
		"start"} {
		pos, ok := positions[stage]
		if !ok {
			t.Errorf("no stage %s", stage)
			continue
		}
		if pos >= cleanup {
			t.Errorf("%s runs at %d, not before native-cleanup at %d", stage, pos, cleanup)
		}
	}
}

// nativeCleanupJobPattern is the transient unit an OS update runs in, as
// the needrestart exclusions spell it out (the regex source, literally).
const nativeCleanupJobPattern = "easy-ha-proxy-updated-job-[0-9a-f]{12}"

// needrestart must not stop the transient unit an OS update runs in: every
// place that writes exclusions names the job unit.
func TestEveryPlaceThatWritesExclusionsNamesTheJobUnit(t *testing.T) {
	for _, place := range []struct{ name, rel string }{
		{"installer agent", agentInternal + "/apply/stages/update_packages.go"},
		{"os_security", agentInternal + "/hostsec/os_security.go"},
		{"service_restarts", agentInternal + "/hostsec/service_restarts.go"},
	} {
		mustContain(t, read(t, place.rel), nativeCleanupJobPattern, place.name)
	}
}
