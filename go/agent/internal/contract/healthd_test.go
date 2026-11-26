package contract

import "testing"

// Regression tests for the privileged monitoring daemon's panel side. The
// Python daemon module this suite once loaded is gone (the daemon now lives
// in go/agent/internal/healthd); the loader was never exercised by a test,
// so what remains is the tri-state health rendering contract of health.js:
// "unknown" must stay distinct from "failed" in the summaries.

func TestSummariesUseTriStateHealth(t *testing.T) {
	source := read(t, webDir+"/static/js/health.js")
	for _, want := range []string{
		"function systemdHealthState(unit)",
		"if (unit.healthy === null) return null;",
		"function dockerHealthState(container)",
		`if (!health || health === "healthy") return true;`,
		`if (health === "starting") return null;`,
		"const hasFailed = states.some",
		`hasOwnProperty.call(u, "display_sub_state")`,
		"titleParts.push(`result=${unit.result}`)",
	} {
		mustContain(t, source, want, "health.js")
	}
}
