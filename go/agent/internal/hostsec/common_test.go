package hostsec

import (
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestRunCommandRawOutputKeepsTheBeginning(t *testing.T) {
	// rawOutput is data the caller parses (apt-cache policy batches); a
	// truncated tail silently drops the first packages of a large batch.
	for _, tool := range []string{"/bin/sh", "head", "tr"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip("needs " + tool)
		}
	}
	script := "printf 'STARTMARK\\n'; head -c 200000 /dev/zero | tr '\\0' 'x'; printf '\\nENDMARK\\n'"
	rc, out, err := runCommand([]string{"/bin/sh", "-c", script}, cmdOpts{rawOutput: true, timeout: 30 * time.Second})
	if err != nil || rc != 0 {
		t.Fatalf("rc=%d err=%v", rc, err)
	}
	if !strings.HasPrefix(out, "STARTMARK\n") {
		t.Fatalf("rawOutput dropped the beginning of a large output (%d bytes)", len(out))
	}
	if !strings.Contains(out, "ENDMARK") || len(out) < 200000 {
		t.Fatalf("rawOutput truncated the output: %d bytes", len(out))
	}
}
