package contract

import (
	"strings"
	"testing"

	"easy-ha-proxy/panel/shared/jinja"
	"easy-ha-proxy/panel/shared/pyyaml"
)

// Every update first copies the live access_control.rules into authelia.yml
// (SyncRuntimeAutheliaRulesToManaged), the access-gate rules the template
// generated included. The template rendered those apart from the managed
// list, with a blank line between, and the copy moved them into the list: the
// first update after each installation rewrote configuration.yml and
// restarted Authelia, which `easy-ha-proxy plan` (no copy) never showed.

const autheliaConfigTemplate = "ansible/roles/authelia/templates/configuration.yml.j2"

// autheliaAccessControl renders the template's access_control part the way
// the agent renders templates (vars.newEnv: trim_blocks, strict undefined,
// Ansible filters).
func autheliaAccessControl(t *testing.T, rules []any, sites []any) string {
	t.Helper()
	src := read(t, autheliaConfigTemplate)
	start := strings.Index(src, "{# Access-gate sites need a login rule")
	end := strings.Index(src, "| to_nice_yaml(indent=2) | indent(4) }}\n")
	if start < 0 || end < start {
		t.Fatal("the access_control part of configuration.yml.j2 changed shape; update this test")
	}
	// The sentinel keeps the newline after "}}": Jinja drops a template's last one.
	part := src[start:end+len("| to_nice_yaml(indent=2) | indent(4) }}\n")] + "# end of access_control\n"
	env := jinja.NewEnvironment(nil)
	env.Autoescape = false
	env.TrimBlocks = true
	env.StrictUndefined = true
	jinja.AddAnsibleFilters(env)
	tmpl, err := env.FromString("access_control", part)
	if err != nil {
		t.Fatal(err)
	}
	out, err := env.RenderTemplate(tmpl, map[string]any{
		"authelia_default_policy":       "deny",
		"authelia_access_control_rules": rules,
		"sites":                         sites,
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func gateTestYAML(t *testing.T, text string) any {
	t.Helper()
	v, err := pyyaml.Load([]byte(text))
	if err != nil {
		t.Fatalf("%v\n%s", err, text)
	}
	return v
}

// liveRules is what the sync reads back: access_control.rules of the file.
func liveRules(t *testing.T, rendered string) []any {
	t.Helper()
	doc, ok := gateTestYAML(t, rendered).(*pyyaml.Map)
	if !ok {
		t.Fatalf("rendered access_control is not a mapping:\n%s", rendered)
	}
	access, ok := doc.Value("access_control").(*pyyaml.Map)
	if !ok {
		t.Fatalf("no access_control mapping:\n%s", rendered)
	}
	rules, ok := access.Value("rules").([]any)
	if !ok {
		t.Fatalf("access_control.rules is not a list:\n%s", rendered)
	}
	return rules
}

func managedTestRules(t *testing.T) []any {
	t.Helper()
	rules, ok := gateTestYAML(t, `
- domain: ha.example.test
  policy: one_factor
  subject: [group:superadmin]
- domain: ha.example.test
  policy: deny
  resources: ['^/haproxy(/.*)?$']
- domain: aut.example.test
  policy: one_factor
  resources: ['^/access_granted/?$']
`).([]any)
	if !ok {
		t.Fatal("managed rules fixture is not a list")
	}
	return rules
}

func gateTestSites(t *testing.T) []any {
	t.Helper()
	sites, ok := gateTestYAML(t, `
- {name: gate, domain: a.example.test, access_gate: true}
- {name: gate2, domain: b.example.test, alt_names: [c.example.test, a.example.test], access_gate: true}
- {name: plain, domain: plain.example.test}
`).([]any)
	if !ok {
		t.Fatal("sites fixture is not a list")
	}
	return sites
}

func TestAutheliaConfigRendersTheSameAfterTheRuleSync(t *testing.T) {
	installed := autheliaAccessControl(t, managedTestRules(t), gateTestSites(t))
	synced := liveRules(t, installed)
	if len(synced) != 6 {
		t.Fatalf("want 3 managed + 3 gate rules (a, b, c once each), got %d:\n%s", len(synced), installed)
	}
	updated := autheliaAccessControl(t, synced, gateTestSites(t))
	if installed != updated {
		t.Fatalf("configuration.yml changes after the update copies the live rules:\n--- installed\n%s--- updated\n%s",
			installed, updated)
	}
	// A third pass changes nothing either.
	if again := autheliaAccessControl(t, liveRules(t, updated), gateTestSites(t)); again != updated {
		t.Fatalf("the rendering does not settle:\n%s", again)
	}
}

func TestAutheliaGateRulesStayInsideTheRuleList(t *testing.T) {
	out := autheliaAccessControl(t, managedTestRules(t), gateTestSites(t))
	body := out[strings.Index(out, "  rules:\n"):strings.Index(out, "# end of access_control")]
	if strings.Contains(strings.TrimRight(body, "\n"), "\n\n") {
		t.Fatalf("a blank line splits access_control.rules:\n%s", out)
	}
	for _, domain := range []string{"a.example.test", "b.example.test", "c.example.test"} {
		if got := strings.Count(out, "domain: "+domain+"\n"); got != 1 {
			t.Errorf("%s has %d rules, want 1:\n%s", domain, got, out)
		}
	}
	if strings.Contains(out, "plain.example.test") {
		t.Errorf("a site without access_gate got a rule:\n%s", out)
	}
}

func TestAutheliaGateRuleSkipsADomainAManagedRuleCovers(t *testing.T) {
	rules := append(managedTestRules(t), gateTestYAML(t, "{domain: [a.example.test], policy: two_factor}"))
	out := autheliaAccessControl(t, rules, gateTestSites(t))
	if got := strings.Count(out, " a.example.test\n"); got != 1 {
		t.Fatalf("a.example.test appears %d times, want only the managed rule:\n%s", got, out)
	}
	if got := len(liveRules(t, out)); got != 6 {
		t.Fatalf("want 4 managed + b and c from the gates, got %d rules:\n%s", got, out)
	}
}

func TestAutheliaRulesWithoutGateSitesRenderAsBefore(t *testing.T) {
	out := autheliaAccessControl(t, managedTestRules(t), nil)
	if got := len(liveRules(t, out)); got != 3 {
		t.Fatalf("want the 3 managed rules, got %d:\n%s", got, out)
	}
	empty := autheliaAccessControl(t, []any{}, nil)
	if !strings.Contains(empty, "  rules:\n    []\n") {
		t.Fatalf("no rules should render as an empty list:\n%s", empty)
	}
}
