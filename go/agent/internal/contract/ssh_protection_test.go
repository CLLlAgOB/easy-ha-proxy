package contract

import (
	"regexp"
	"strings"
	"testing"
)

// Cross-component contracts for SSH protection (logic tested in
// go/agent/internal/hostsec): the shipped ban rules stay on the web ports
// with safe verdicts, and the update broker's fail2ban shortcuts name the
// same client and drop-in the hostsec constants do.

func TestHpBanRulesOnlyTouchHttpAndHttpsWithSafeVerdicts(t *testing.T) {
	// A ban must never cut the operator's SSH session: every HP_BAN rule
	// targets port 80 or 443 and ends in a safe verdict.
	rules := read(t, "ansible/roles/haproxy-admin/files/haproxy_ban.rules")
	var verdicts []string
	var banLines []string
	for _, line := range strings.Split(rules, "\n") {
		if !strings.HasPrefix(line, "-A HP_BAN ") {
			continue
		}
		banLines = append(banLines, line)
		parts := strings.SplitN(line, " -j ", 2)
		if len(parts) != 2 {
			t.Fatalf("no verdict in %q", line)
		}
		fields := strings.Fields(parts[1])
		if len(fields) == 0 {
			t.Fatalf("empty verdict in %q", line)
		}
		verdicts = append(verdicts, fields[0])
	}
	if len(verdicts) == 0 {
		t.Fatal("no HP_BAN rules")
	}
	for _, verdict := range verdicts {
		switch verdict {
		case "DROP", "REJECT", "RETURN":
		default:
			t.Errorf("unsafe verdict %q", verdict)
		}
	}
	for _, line := range banLines {
		if !strings.Contains(line, "--dport 80 ") && !strings.Contains(line, "--dport 443 ") {
			t.Errorf("rule off the web ports: %q", line)
		}
	}
}

func TestBrokerShortcutPathsMatchSshProtectionConstants(t *testing.T) {
	// The broker decides whether SSH protection exists from the same paths
	// hostsec writes; a drifted constant hides the feature from the panel.
	protection := read(t, "go/agent/internal/hostsec/ssh_protection.go")
	client := sshProtectionConstant(t, protection, `sshDefaultClient\s*=\s*"([^"]+)"`)
	configDir := sshProtectionConstant(t, protection, `sshDefaultConfigDir\s*=\s*"([^"]+)"`)
	dropIn := sshProtectionConstant(t, protection,
		`sshDropInPath\s*=\s*filepath\.Join\(sshDefaultConfigDir, "jail\.d", "([^"]+)"\)`)
	broker := read(t, "go/agent/internal/updated/api.go")
	mustContain(t, broker, `fail2banClientPath = "`+client+`"`, "updated/api.go")
	mustContain(t, broker, `fail2banDropInPath = "`+configDir+`/jail.d/`+dropIn+`"`, "updated/api.go")
}

// sshProtectionConstant is re.search(pattern, protection).group(1); a
// missing match is the AttributeError the Python search would raise.
func sshProtectionConstant(t *testing.T, protection, pattern string) string {
	t.Helper()
	m := regexp.MustCompile(pattern).FindStringSubmatch(protection)
	if m == nil {
		t.Fatalf("no match for %s", pattern)
	}
	return m[1]
}
