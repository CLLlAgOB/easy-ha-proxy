package contract

import (
	"strings"
	"testing"
)

// The ban loader touches its own chain only (F01, 30 October review):
// iptables-legacy-restore without --noflush emptied the whole filter table
// it restored -- the host's INPUT and FORWARD rules and Docker's chains
// were gone, and only HP_BAN was left. With --noflush and the jump added
// once, both survive two runs.

const banLoaderRulesFile = "ansible/roles/haproxy-admin/files/haproxy_ban.rules"

// banLoaderUnitLine is the first unit line starting with the prefix.
func banLoaderUnitLine(t *testing.T, prefix string) string {
	t.Helper()
	for _, line := range strings.Split(read(t, unitDir+"/iptables-haproxy-ban.service.j2"), "\n") {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	t.Fatalf("the ban unit has no %s line", prefix)
	return ""
}

func TestBanLoaderRestoresWithoutFlushingTheTable(t *testing.T) {
	start := banLoaderUnitLine(t, "ExecStart=")
	mustContain(t, start, "iptables-legacy-restore --noflush /etc/iptables/haproxy_ban.rules", "ExecStart")
}

func TestBanLoaderJumpIsAddedOnce(t *testing.T) {
	post := banLoaderUnitLine(t, "ExecStartPost=")
	mustContain(t, post, "iptables-legacy -C INPUT -j HP_BAN", "ExecStartPost")
	mustContain(t, post, "|| /usr/sbin/iptables-legacy -I INPUT 1 -j HP_BAN", "ExecStartPost")
}

func TestBanRulesDeclareOnlyTheirOwnChain(t *testing.T) {
	// A Windows checkout gives the .rules file CRLF endings; the contract
	// is about its logical lines.
	rules := strings.ReplaceAll(read(t, banLoaderRulesFile), "\r\n", "\n")
	if strings.Contains(rules, "-I INPUT") {
		t.Error("the rules file inserts into INPUT")
	}
	if strings.Contains(rules, "-A INPUT") {
		t.Error("the rules file appends to INPUT")
	}
	var chains []string
	for _, line := range strings.Split(rules, "\n") {
		if strings.HasPrefix(line, ":") {
			chains = append(chains, line)
		}
	}
	if len(chains) != 1 || chains[0] != ":HP_BAN - [0:0]" {
		t.Errorf("chains = %v, want [:HP_BAN - [0:0]]", chains)
	}
	for _, line := range strings.Split(rules, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		own := false
		for _, prefix := range []string{"-A HP_BAN", ":", "*filter", "COMMIT"} {
			if strings.HasPrefix(line, prefix) {
				own = true
				break
			}
		}
		if !own {
			t.Errorf("rule outside HP_BAN: %s", line)
		}
	}
}
