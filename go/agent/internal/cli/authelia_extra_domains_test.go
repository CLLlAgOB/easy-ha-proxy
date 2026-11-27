package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"easy-ha-proxy/panel/shared/pyyaml"
)

func extraDomainsSyncDirs(t *testing.T, runtimeVars string) (string, string) {
	t.Helper()
	root := t.TempDir()
	managed, runtime := filepath.Join(root, "managed"), filepath.Join(root, "runtime")
	_ = os.MkdirAll(managed, 0o700)
	_ = os.MkdirAll(runtime, 0o700)
	_ = WriteText(filepath.Join(managed, "metadata.yml"), "configuration_pending: false\n", 0o600)
	_ = WriteText(filepath.Join(managed, "vars.yml"), "root_domain: example.test\n", 0o600)
	_ = WriteText(filepath.Join(managed, "websites.yml"), "sites: []\n", 0o600)
	_ = WriteText(filepath.Join(managed, "tcp.yml"), "tcp_proxies: []\n", 0o600)
	_ = WriteText(filepath.Join(runtime, "vars.yml"), runtimeVars, 0o600)
	_ = WriteText(filepath.Join(runtime, "websites.yml"), "sites: []\n", 0o600)
	_ = WriteText(filepath.Join(runtime, "tcp.yml"), "tcp_proxies: []\n", 0o600)
	return managed, runtime
}

// The panel keeps the list in its own vars.yml; an update must carry it into
// the managed configuration, or the next render would drop the domains.
func TestAnUpdateKeepsTheExtraSignInDomains(t *testing.T) {
	managed, runtime := extraDomainsSyncDirs(t, "root_domain: example.test\nauthelia_extra_domains:\n- {domain: other.test, portal: aut.other.test}\n")
	var out bytes.Buffer
	if changed, err := SyncRuntimeHAProxyConfigToManaged(&out, managed, runtime); err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	vars, _ := LoadYAMLMapping(filepath.Join(managed, "vars.yml"))
	if got := AutheliaExtraDomainNames(vars); len(got) != 1 || got[0] != "other.test" {
		t.Fatalf("managed vars: %v", got)
	}
}

// The runtime file is the unprivileged container's; what it says lands in
// haproxy.cfg and Authelia's configuration, written as root.
func TestAMalformedSignInDomainListIsRefused(t *testing.T) {
	for _, bad := range []string{
		"authelia_extra_domains: other.test\n",
		"authelia_extra_domains:\n- {domain: other.test}\n",
		"authelia_extra_domains:\n- {domain: other.test, portal: aut.elsewhere.test}\n",
		"authelia_extra_domains:\n- {domain: 'other.test\nbad', portal: aut.other.test}\n",
		"authelia_extra_domains:\n- {domain: other.test, portal: 'aut.other.test x'}\n",
		"authelia_extra_domains:\n- {domain: Other.Test, portal: aut.other.test}\n",
		"authelia_extra_domains:\n- {domain: other.test, portal: aut.other.test, script: x}\n",
		"authelia_extra_domains:\n- {domain: other.test, portal: aut.other.test, certificate_source: self}\n",
		"authelia_extra_domains:\n- {domain: other.test, portal: aut.other.test}\n- {domain: other.test, portal: login.other.test}\n",
	} {
		managed, runtime := extraDomainsSyncDirs(t, bad)
		var out bytes.Buffer
		if _, err := SyncRuntimeHAProxyConfigToManaged(&out, managed, runtime); err == nil {
			t.Errorf("accepted:\n%s", bad)
		}
	}
	v, _ := pyyaml.Load([]byte("- {domain: other.test, portal: aut.other.test, certificate_source: internal, dns_profile: hetzner}\n"))
	if err := ValidateAutheliaExtraDomains(v, "test"); err != nil {
		t.Fatal(err)
	}
}

func TestSignInDomainsOverlapByLabels(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"example.test", "example.test", true},
		{"app.example.test", "example.test", true},
		{"example.test", "app.example.test", true},
		{"xexample.test", "example.test", false},
		{"other.test", "example.test", false},
	} {
		if got := domainsOverlap(c.a, c.b); got != c.want {
			t.Errorf("%s / %s: %v", c.a, c.b, got)
		}
	}
}

func TestMigrationRefusesARootThatOverlapsASignInDomain(t *testing.T) {
	vars, _ := pyyaml.Load([]byte("authelia_extra_domains:\n- {domain: other.test, portal: aut.other.test}\n"))
	names := AutheliaExtraDomainNames(vars.(*pyyaml.Map))
	if len(names) != 1 || !domainsOverlap(names[0], "other.test") || domainsOverlap(names[0], "new.test") {
		t.Fatalf("%v", names)
	}
	src, err := os.ReadFile("domain.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "AutheliaExtraDomainNames(current[\"vars.yml\"])") {
		t.Fatal("migrate-domain no longer checks the extra sign-in domains")
	}
}
