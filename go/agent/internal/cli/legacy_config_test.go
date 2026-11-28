package cli

import (
	"bytes"
	"testing"
)

func TestPrepareLegacyHelpProbeSucceeds(t *testing.T) {
	// install.sh probes `prepare-legacy-config --help` to decide whether the
	// installed agent can prepare a legacy snapshot; --help must exit 0, not 2,
	// or the installer re-fetches the agent on every run (and fails offline).
	var stdout, stderr bytes.Buffer
	if code := RunPrepareLegacyCLI([]string{"--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("--help exit %d, want 0", code)
	}
	if code := RunPrepareLegacyCLI([]string{"--no-such-flag"}, &stdout, &stderr); code != 2 {
		t.Fatalf("bad flag exit %d, want 2", code)
	}
	if code := RunPrepareLegacyCLI(nil, &stdout, &stderr); code != 2 {
		t.Fatalf("missing args exit %d, want 2", code)
	}
}
