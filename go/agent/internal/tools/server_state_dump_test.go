//go:build unix

package tools

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

// The installed dumper (haproxy-state-dump.sh.j2) run as HAProxy's reload
// runs it, with this test binary standing in for the agent.

const dumpAgentEnv = "EHP_TEST_AS_AGENT"

func TestMain(m *testing.M) {
	if os.Getenv(dumpAgentEnv) == "1" {
		if calls := os.Getenv("EHP_TEST_AGENT_CALLS"); calls != "" {
			f, err := os.OpenFile(calls, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
			if err == nil {
				_, _ = f.WriteString(strings.Join(os.Args[1:], " ") + "\n")
				f.Close()
			}
		}
		if len(os.Args) < 2 || os.Args[1] != "server-state" {
			os.Exit(2)
		}
		os.Exit(RunServerState(os.Args[2:], os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

func dumperTemplate(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "ansible/roles/haproxy/templates/haproxy-state-dump.sh.j2"))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

const (
	dumpHeader = "be_id be_name srv_id srv_name srv_addr srv_op_state srv_admin_state srv_uweight srv_iweight srv_time_since_last_change srv_check_status srv_check_result srv_check_health srv_check_state srv_agent_state bk_f_forced_id srv_f_forced_id srv_fqdn srv_port srvrecord srv_use_ssl srv_check_port srv_check_addr srv_agent_addr srv_agent_port"
	dumpRow    = "36 target 1 main 127.0.0.1 2 1 17 100 10 15 3 4 6 0 0 0 - 1025 - 0 0 - - 0"
)

type dumpCase struct {
	reply    string
	offline  bool
	config   *string
	previous string
	mode     os.FileMode
	// named: the agent is passed as the dumper's second argument rather
	// than rendered as its default agent.
	named bool
}

type dumpResult struct {
	state string
	calls string
}

func runDump(t *testing.T, c dumpCase) dumpResult {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("needs sh")
	}
	if c.previous == "" {
		c.previous = "previous-state\n"
	}
	if c.mode == 0 {
		c.mode = 0o644
	}
	root := t.TempDir()
	state := filepath.Join(root, "state")
	initial := c.previous
	if c.offline {
		initial = c.reply
	}
	if err := os.WriteFile(state, []byte(initial), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(state, c.mode); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(state)
	owner := before.Sys().(*syscall.Stat_t)
	reply := filepath.Join(root, "reply")
	_ = os.WriteFile(reply, []byte(c.reply), 0o600)
	_ = os.WriteFile(filepath.Join(root, "socat"), []byte("#!/bin/sh\ncat \"$STATE_REPLY\"\n"), 0o700)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	calls := filepath.Join(root, "agent-calls")
	agent := filepath.Join(root, "agent")
	_ = os.WriteFile(agent, []byte("#!/bin/sh\nexec env "+dumpAgentEnv+"=1 EHP_TEST_AGENT_CALLS=\""+calls+"\" \""+self+"\" \"$@\"\n"), 0o700)
	socket := filepath.Join(root, "socket")
	script := strings.NewReplacer(
		"{{ haproxy_socket | default('/run/haproxy/admin.sock') }}", socket,
		"{{ haproxy_server_state_file | default('/var/lib/haproxy/server-state') }}", state,
		"{{ native_agent_bin | default('/usr/local/sbin/easy-ha-proxy-agent') }}", map[bool]string{true: "/nonexistent/agent", false: agent}[c.named],
	).Replace(dumperTemplate(t))
	if strings.Contains(script, "{{") {
		t.Fatalf("unrendered template: %s", script)
	}
	dump := filepath.Join(root, "dump.sh")
	_ = os.WriteFile(dump, []byte(script), 0o700)
	configPath := filepath.Join(root, "haproxy.cfg")
	if c.config != nil {
		_ = os.WriteFile(configPath, []byte(*c.config), 0o600)
	}
	if !c.offline {
		listener, err := net.Listen("unix", socket)
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
	}
	args := []string{dump, configPath}
	if c.named {
		args = append(args, agent)
	}
	cmd := exec.Command("sh", args...)
	cmd.Env = append(os.Environ(), "PATH="+root+string(os.PathListSeparator)+os.Getenv("PATH"), "STATE_REPLY="+reply)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("dumper: %v\n%s", err, out)
	}
	after, _ := os.Stat(state)
	if after.Mode().Perm() != c.mode {
		t.Fatalf("mode %v, want %v", after.Mode().Perm(), c.mode)
	}
	if st := after.Sys().(*syscall.Stat_t); st.Uid != owner.Uid || st.Gid != owner.Gid {
		t.Fatal("the owner changed")
	}
	if leftovers, _ := filepath.Glob(state + ".tmp.*"); len(leftovers) != 0 {
		t.Fatalf("leftovers %v", leftovers)
	}
	raw, _ := os.ReadFile(state)
	recorded, _ := os.ReadFile(calls)
	return dumpResult{string(raw), string(recorded)}
}

func text(s string) *string { return &s }

func dumpLines(s string) [][]string {
	var rows [][]string
	for _, line := range strings.Split(strings.TrimSuffix(s, "\n"), "\n") {
		rows = append(rows, strings.Fields(line))
	}
	return rows
}

func TestTheTLSSuffixIsDroppedWithoutChangingMaintenanceOrWeights(t *testing.T) {
	for _, tls := range []string{"0", "1"} {
		fields := strings.Fields(dumpRow)
		fields[20] = tls
		rows := dumpLines(runDump(t, dumpCase{reply: "1\n# " + dumpHeader + "\n" + strings.Join(fields, " ") + "\n"}).state)
		if strings.Join(rows[2], " ") != strings.Join(fields[:20], " ") || strings.Join(rows[1][1:], " ") != strings.Join(strings.Fields(dumpHeader)[:20], " ") ||
			strings.Join(rows[2][6:9], " ") != "1 17 100" {
			t.Fatalf("tls %s: %v", tls, rows)
		}
	}
}

func TestTheDumperRunsTheAgentNamedOrInstalled(t *testing.T) {
	reply := "1\n# " + dumpHeader + "\n" + dumpRow + "\n"
	installed := runDump(t, dumpCase{reply: reply})
	named := runDump(t, dumpCase{reply: reply, named: true})
	if installed.state != named.state {
		t.Fatalf("installed %q named %q", installed.state, named.state)
	}
	calls := strings.Fields(installed.calls)
	if len(calls) < 5 || calls[0] != "server-state" || calls[1] != "--config" || calls[3] != "--state" {
		t.Fatalf("calls %q", installed.calls)
	}
}

func TestTheOlderTwentyFieldFormatIsKept(t *testing.T) {
	row := strings.Join(strings.Fields(dumpRow)[:20], " ")
	reply := "1\n# " + strings.Join(strings.Fields(dumpHeader)[:20], " ") + "\n" + row + "\n"
	if got := runDump(t, dumpCase{reply: reply}).state; got != reply {
		t.Fatalf("%q", got)
	}
}

func TestAStoppedGatewayAlsoCleansItsPreviousStateBeforeStart(t *testing.T) {
	reply := "1\n# " + dumpHeader + "\n" + dumpRow + "\n"
	if rows := dumpLines(runDump(t, dumpCase{reply: reply, offline: true}).state); len(rows[2]) != 20 {
		t.Fatalf("%v", rows)
	}
}

func TestTheConfiguredPortWinsWithoutChangingAdministrationOrWeights(t *testing.T) {
	reply := "1\n# " + dumpHeader + "\n" + dumpRow + "\n"
	for _, offline := range []bool{false, true} {
		for _, endpoint := range []string{"127.0.0.1:1026", "[::1]:1026", "mesh.example.test:1026"} {
			config := "backend target\n    server main " + endpoint + " weight 100 check\n"
			row := dumpLines(runDump(t, dumpCase{reply: reply, offline: offline, config: &config}).state)[2]
			if row[18] != "1026" || strings.Join(row[6:9], " ") != strings.Join(strings.Fields(dumpRow)[6:9], " ") {
				t.Fatalf("offline=%v %s: %v", offline, endpoint, row)
			}
		}
	}
}

func TestPortsAreMatchedByBackendAndServerName(t *testing.T) {
	second := strings.Replace(dumpRow, "36 target ", "37 other ", 1)
	reply := "1\n# " + dumpHeader + "\n" + dumpRow + "\n" + second + "\n"
	config := "backend target\n server main 127.0.0.1:1026\nbackend other\n server main 127.0.0.1:1043\n"
	rows := dumpLines(runDump(t, dumpCase{reply: reply, config: &config}).state)[2:]
	if rows[0][18] != "1026" || rows[1][18] != "1043" {
		t.Fatalf("%v", rows)
	}
}

func TestADNSSRVPortIsKeptWithoutAnExplicitConfiguredPort(t *testing.T) {
	fields := strings.Fields(dumpRow)
	fields[17] = "target.example.test"
	fields[19] = "_service._tcp.example.test"
	reply := "1\n# " + dumpHeader + "\n" + strings.Join(fields, " ") + "\n"
	if row := dumpLines(runDump(t, dumpCase{reply: reply, config: text("backend target\n server main _service._tcp.example.test resolvers dns\n")}).state)[2]; row[18] != "1025" {
		t.Fatalf("%v", row)
	}
}

func TestAnInvalidReplyNeverReplacesTheState(t *testing.T) {
	for _, reply := range []string{"2\n# " + dumpHeader + "\n" + dumpRow + "\n", "1\n# wrong header\n" + dumpRow + "\n",
		"1\n# " + dumpHeader + "\n36 target 1 main\n", "permission denied\n"} {
		if got := runDump(t, dumpCase{reply: reply}).state; got != "previous-state\n" {
			t.Fatalf("%q replaced the state: %q", reply, got)
		}
	}
}

func TestRuntimeErrorsStillReconcileTheLastValidSnapshot(t *testing.T) {
	previous := "1\n# " + dumpHeader + "\n" + dumpRow + "\n"
	config := "backend target\n server main 127.0.0.1:1026 check\n"
	for _, reply := range []string{"", "permission denied\n", "1\n# " + dumpHeader + "\ntruncated\n"} {
		row := dumpLines(runDump(t, dumpCase{reply: reply, config: &config, previous: previous}).state)[2]
		if row[18] != "1026" || strings.Join(row[6:9], " ") != strings.Join(strings.Fields(dumpRow)[6:9], " ") {
			t.Fatalf("%q: %v", reply, row)
		}
	}
}

func TestColdStartNormalizationKeepsAPrivateSnapshotPrivate(t *testing.T) {
	runDump(t, dumpCase{reply: "1\n# " + dumpHeader + "\n" + dumpRow + "\n", offline: true, mode: 0o600})
}
