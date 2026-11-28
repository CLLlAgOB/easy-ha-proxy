package contract

import (
	"regexp"
	"strings"
	"testing"

	"easy-ha-proxy/panel/shared/jinja"
)

// Regression checks for persisted HAProxy server state: the dump and the
// loader ship together behind one switch, the write is atomic, and a
// runtime problem never turns into a failed reload. How the dumper behaves
// with a real normalizer is tested with the agent, in
// go/agent/internal/tools/server_state_dump_test.go.

const serverStateRole = "ansible/roles/haproxy"
const serverStateTemplate = serverStateRole + "/templates/haproxy.cfg.j2"
const serverStateDumper = serverStateRole + "/templates/haproxy-state-dump.sh.j2"
const serverStateDefaults = serverStateRole + "/defaults/main.yml"

// Without the loader the dump would be written and never read.
func TestTheStateFileIsDeclaredInGlobal(t *testing.T) {
	template := read(t, serverStateTemplate)
	mustContain(t, template, "server-state-file", "haproxy.cfg.j2")
	mustContain(t, template, "load-server-state-from-file global", "haproxy.cfg.j2")
}

// serverStateGuard is one {% if haproxy_server_state_enabled %} block, up
// to its first endif, as the Python pattern captured it.
var serverStateGuard = regexp.MustCompile(`(?s)\{%\s*if\s+haproxy_server_state_enabled.*?%\}(.*?)\{%\s*endif\s*%\}`)

// Shipping one half without the other is the failure that looks like it
// works: the dump is written and nothing ever restores from it, or the
// loader points at a file nobody maintains.
func TestBothHalvesAreBehindTheSameSwitch(t *testing.T) {
	template := read(t, serverStateTemplate)
	var guarded []string
	for _, m := range serverStateGuard.FindAllStringSubmatch(template, -1) {
		guarded = append(guarded, m[1])
	}
	unguarded := serverStateGuard.ReplaceAllString(template, "")
	for _, directive := range []string{"server-state-file", "load-server-state-from-file global"} {
		if !strings.Contains(strings.Join(guarded, "\n"), directive) {
			t.Errorf("%s is not behind the switch", directive)
		}
		if strings.Contains(unguarded, directive) {
			t.Errorf("%s appears outside the switch", directive)
		}
	}
}

// The state file lives inside the chroot directory, and the feature is on
// by default.
func TestTheStateFileLivesInsideTheChrootDirectory(t *testing.T) {
	defaults := read(t, serverStateDefaults)
	mustContain(t, defaults, `haproxy_server_state_file: "{{ haproxy_chroot }}/server-state"`, "defaults/main.yml")
	mustContain(t, defaults, "haproxy_server_state_enabled: true", "defaults/main.yml")
}

// HAProxy reads this at startup; a half-written file is worse than a stale
// one, so the dump is moved into place, never written straight there.
func TestTheWriteIsAtomic(t *testing.T) {
	script := read(t, serverStateDumper)
	mustContain(t, script, "TMP_FILE", "haproxy-state-dump.sh.j2")
	if !regexp.MustCompile(`mv -f "\$TMP_FILE" "\$STATE_FILE"`).MatchString(script) {
		t.Error("the dump is not moved into place with mv -f")
	}
	if regexp.MustCompile(`>\s*"\$STATE_FILE"`).MatchString(script) {
		t.Error("the script redirects straight into the state file")
	}
}

// The reply always starts with a version line; anything shorter means the
// runtime API answered with an error or nothing at all, and overwriting a
// good state file with that would lose every server's state.
func TestAShortReplyNeverOverwritesAGoodFile(t *testing.T) {
	script := read(t, serverStateDumper)
	mustContain(t, script, `wc -l < "$TMP_FILE"`, "haproxy-state-dump.sh.j2")
	mustContain(t, script, "-lt 2", "haproxy-state-dump.sh.j2")
}

// A missing socket is not an error: HAProxy may simply be stopped.
func TestAMissingSocketIsNotAnError(t *testing.T) {
	script := read(t, serverStateDumper)
	mustContain(t, script, `if [ ! -S "$SOCKET" ]`, "haproxy-state-dump.sh.j2")
	mustContain(t, script, "exit 0", "haproxy-state-dump.sh.j2")
}

// The temporary files are cleaned up on failure.
func TestTheTemporaryFileIsCleanedUpOnFailure(t *testing.T) {
	mustContain(t, read(t, serverStateDumper), `trap 'rm -f "$TMP_FILE" "$FILTERED_FILE"'`, "haproxy-state-dump.sh.j2")
}

// A failed dump must not turn into a failed reload.
func TestTheScriptNeverExitsNonZeroOnARuntimeProblem(t *testing.T) {
	if regexp.MustCompile(`(?m)^\s*exit [1-9][0-9]*\s*$`).MatchString(read(t, serverStateDumper)) {
		t.Error("the dumper exits non-zero on a runtime problem")
	}
}

// The dumper names the agent that normalizes the dump: the installer agent
// by default, and a native build's own path when one is given.
func TestTheDumperNamesTheAgent(t *testing.T) {
	env := jinja.NewEnvironment(nil)
	env.Autoescape = false
	env.TrimBlocks = false
	env.LstripBlocks = false
	tmpl, err := env.FromString("haproxy-state-dump.sh.j2", read(t, serverStateDumper))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		vars  map[string]any
		agent string
	}{
		{map[string]any{}, "/usr/local/sbin/easy-ha-proxy-agent"},
		{map[string]any{"native_agent_bin": "/opt/agent"}, "/opt/agent"},
	} {
		out, err := env.RenderTemplate(tmpl, tc.vars)
		if err != nil {
			t.Fatal(err)
		}
		var lines []string
		for _, line := range errorPagesSplitLines(out) {
			if strings.HasPrefix(line, "AGENT=") {
				lines = append(lines, line)
			}
		}
		want := `AGENT="` + tc.agent + `"`
		if len(lines) != 1 || lines[0] != want {
			t.Errorf("AGENT lines %q, want [%q] (vars %v)", lines, want, tc.vars)
		}
	}
}

// The state file is persistent, not temporary: both guides must stop
// calling it temporary.
func TestBothReadmesStopCallingTheStateTemporary(t *testing.T) {
	for _, name := range []string{"docs/guide.md", "docs/guide.ru.md"} {
		if strings.Contains(read(t, name), "no server state file") {
			t.Errorf("%s still calls the state temporary", name)
		}
	}
}
