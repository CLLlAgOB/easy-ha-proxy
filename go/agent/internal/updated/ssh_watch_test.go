package updated

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Without the Fail2ban client and the panel's jail drop-in, the minute's SSH
// watch answers "not installed" itself; with either one it asks the tool.
func TestSSHWatchStartsNoToolWithoutFail2ban(t *testing.T) {
	d := newTestDaemon(t)
	agent := filepath.Join(t.TempDir(), "easy-ha-proxy-agent")
	if err := os.WriteFile(agent, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	savedAgent := agentBinary
	agentBinary = agent
	defer func() { agentBinary = savedAgent }()
	var calls []string
	d.commandRunner = func(_ time.Duration, _ []string, argv ...string) (int, string, string, error) {
		calls = append(calls, strings.Join(argv, " "))
		return 0, `{"ok": true, "state": "active", "managed": false}`, "", nil
	}
	dir := t.TempDir()
	oldClient, oldDropIn := fail2banClientPath, fail2banDropInPath
	fail2banClientPath = filepath.Join(dir, "fail2ban-client")
	fail2banDropInPath = filepath.Join(dir, "99-easy-ha-proxy-sshd.local")
	defer func() { fail2banClientPath, fail2banDropInPath = oldClient, oldDropIn }()

	status, err := d.sshMonitorStatus()
	if err != nil || status["state"] != "not_installed" || status["managed"] != false || len(calls) != 0 {
		t.Fatalf("without Fail2ban: %v %v, tool runs %v", status, err, calls)
	}
	for _, present := range []string{fail2banClientPath, fail2banDropInPath} {
		calls = nil
		if err := os.WriteFile(present, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		status, err = d.sshMonitorStatus()
		if err != nil || status["state"] != "active" || len(calls) != 1 || !strings.HasSuffix(calls[0], "ssh-protection monitor") {
			t.Fatalf("with %s: %v %v, tool runs %v", filepath.Base(present), status, err, calls)
		}
		if err := os.Remove(present); err != nil {
			t.Fatal(err)
		}
	}
}
