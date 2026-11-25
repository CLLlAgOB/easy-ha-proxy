package authelia

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"easy-ha-proxy/panel/shared/pyyaml"
)

func newTestConfigd(t *testing.T) (*Configd, string) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "configuration.yml")
	text := "theme: light\nsession:\n  secret: s3cr3t\n  name: authelia_session\naccess_control:\n  default_policy: deny\n  rules:\n  - domain: app.example.com\n    policy: one_factor\n"
	if err := os.WriteFile(cfg, []byte(text), 0o640); err != nil {
		t.Fatal(err)
	}
	c := NewConfigd(ConfigdOptions{ConfigFile: cfg, MailLockFile: filepath.Join(dir, "mail.lock"), ManagedConfigDir: dir})
	c.protectedDomains = func() string { return "admin.example.com" }
	return c, dir
}

func req(t *testing.T, raw string) any {
	v, err := pyyaml.JSONLoads([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestConfigdRulesRoundTrip(t *testing.T) {
	c, _ := newTestConfigd(t)
	got, err := c.HandleRequest(req(t, `{"action":"rules_get"}`), 0)
	if err != nil || got["ok"] != true || got["rules_yaml"] != "- domain: app.example.com\n  policy: one_factor\n" {
		t.Fatalf("rules_get: %v %v", got, err)
	}
	rev := got["revision"].(string)
	set, _ := c.HandleRequest(req(t, `{"action":"rules_set","rules_yaml":"- domain: admin.example.com\n  policy: bypass\n"}`), 0)
	if set["ok"] != false || !strings.Contains(set["error"].(string), "protected domain admin.example.com") {
		t.Fatalf("bypass on protected: %v", set)
	}
	set, _ = c.HandleRequest(req(t, `{"action":"rules_set","rules_yaml":"- domain: b.example.com\n  policy: two_factor\n","expected_revision":"`+rev+`"}`), 0)
	if set["ok"] != true {
		t.Fatalf("rules_set: %v", set)
	}
	raw, _ := os.ReadFile(c.Opts.ConfigFile)
	if !strings.Contains(string(raw), "  rules:\n  - domain: b.example.com\n    policy: two_factor\n") ||
		!strings.HasPrefix(string(raw), "theme: light\nsession:\n") {
		t.Fatalf("saved file: %s", raw)
	}
	stale, _ := c.HandleRequest(req(t, `{"action":"rules_set","rules_yaml":"[]","expected_revision":"`+rev+`"}`), 0)
	if stale["conflict"] != true {
		t.Fatalf("stale revision accepted: %v", stale)
	}
}

func TestConfigdConfigViewMasksSecrets(t *testing.T) {
	c, _ := newTestConfigd(t)
	got, err := c.HandleRequest(req(t, `{"action":"config_view"}`), 1000)
	if err != nil {
		t.Fatal(err)
	}
	cfg := got["config"].(*pyyaml.Map)
	if asMap(cfg.Value("session")).Value("secret") != "*****" || asMap(cfg.Value("access_control")).Value("rules") != nil {
		t.Fatalf("config_view: %v", got)
	}
}

func TestConfigdSettingsAndPeers(t *testing.T) {
	c, _ := newTestConfigd(t)
	bad, _ := c.HandleRequest(req(t, `{"action":"settings_update","config":{"storage":{}}}`), 0)
	if bad["error"] != "unsupported configuration sections: storage" {
		t.Fatalf("%v", bad)
	}
	ok, _ := c.HandleRequest(req(t, `{"action":"settings_update","config":{"session":{"secret":"x","expiration":"1h"},"log":{"level":"debug"}}}`), 0)
	if ok["ok"] != true {
		t.Fatalf("%v", ok)
	}
	raw, _ := os.ReadFile(c.Opts.ConfigFile)
	if !strings.Contains(string(raw), "  secret: s3cr3t\n  name: authelia_session\n  expiration: 1h\n") || !strings.HasSuffix(string(raw), "log:\n  level: debug\n") {
		t.Fatalf("merged file: %s", raw)
	}
	denied, _ := c.HandleRequest(req(t, `{"action":"notification_reveal"}`), 4242)
	if denied["forbidden"] != true {
		t.Fatalf("%v", denied)
	}
	unknown, _ := c.HandleRequest(req(t, `{"action":"nope"}`), 0)
	if unknown["error"] != "unknown action: 'nope'" {
		t.Fatalf("%v", unknown)
	}
}

func TestEnvRendering(t *testing.T) {
	env := parseEnv("# c\nSMTP_PASSWORD=\"a$$b\"\nOTHER=x\nSMTP_PASSWORD=old\n")
	if env.get("SMTP_PASSWORD") != "old" || env.get("OTHER") != "x" {
		t.Fatalf("%v", env.vals)
	}
	out := renderEnvWithUpdates("# c\nSMTP_PASSWORD=old\nOTHER=x\nSMTP_PASSWORD=dup\n", []kv{{"SMTP_PASSWORD", "p$w \"q\""}, {"NEW", "é"}})
	if out != "# c\nSMTP_PASSWORD=\"p$$w \\\"q\\\"\"\nOTHER=x\nNEW=\"é\"\n" {
		t.Fatalf("%q", out)
	}
	if _, state := parseMailTestDelivery("Nov 1 ABC123: message-id=<x@y>\nNov 1 ABC123: to=<a@b>, status=sent (250 ok)", "<x@y>"); state != "relay_accepted" {
		t.Fatal(state)
	}
	if !haproxyStatsReportBackendUp("# pxname,svname,status\nauthelia_backend,authelia,UP 1/2\n") {
		t.Fatal("stats")
	}
}

func TestProtectedDomainsRejectMatchingBypassRules(t *testing.T) {
	options := ConfigdOptions{ProtectedDomains: "admin.example.com"}
	daemon := NewConfigd(options)
	for _, tc := range []struct {
		key, value string
		rejected   bool
	}{
		{"domain", "*.example.com", true},
		{"domain_regex", "^admin[.]example[.]com$", true},
		{"domain", "*.other.example.com", false},
	} {
		rule := pyyaml.NewMap()
		rule.Set("policy", "bypass")
		rule.Set(tc.key, tc.value)
		if err := daemon.rejectUnprotectedControlPlane([]any{rule}); (err != nil) != tc.rejected {
			t.Errorf("%s %q: got %v", tc.key, tc.value, err)
		}
	}
}
