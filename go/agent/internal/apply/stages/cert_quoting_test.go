package stages

import (
	"os/exec"
	"strings"
	"testing"
)

func TestDNSCheckQuotesEveryArgument(t *testing.T) {
	const secondMarker = "{{ acme_resolvers | map('quote') | join(' ') }}"
	name := "operator's " + secondMarker
	resolver := "dns with spaces"
	script := dnsCheckScript([]string{name}, []string{resolver})
	if !strings.Contains(script, "for n in "+quoteAll([]string{name})+"; do") ||
		!strings.Contains(script, "for r in "+quoteAll([]string{resolver})+"; do") {
		t.Fatalf("substitutions changed an argument: %s", script)
	}
	if bash, err := exec.LookPath("bash"); err == nil {
		cmd := exec.Command(bash, "-n")
		cmd.Stdin = strings.NewReader(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("invalid rendered shell: %v: %s", err, out)
		}
	}
}
