package contract

import (
	"strings"
	"testing"

	"easy-ha-proxy/panel/shared/jinja"
	"easy-ha-proxy/panel/shared/pyyaml"
)

// Regression tests for relay-only Authelia and certificate mail delivery:
// inert defaults for the new relay fields, a private persistent relay
// container that never exposes credentials, no direct application SMTP
// path, and the relay running before the first certificate renewal.

// mailLoadYAML reads a role defaults file as a mapping.
func mailLoadYAML(t *testing.T, rel string) *pyyaml.Map {
	t.Helper()
	v, err := pyyaml.Load([]byte(read(t, rel)))
	if err != nil {
		t.Fatalf("%s: %v", rel, err)
	}
	m, ok := v.(*pyyaml.Map)
	if !ok {
		t.Fatalf("%s: not a mapping", rel)
	}
	return m
}

// mailTruthy is Python bool(v) for the values yaml.safe_load produces.
func mailTruthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case int64:
		return x != 0
	case float64:
		return x != 0
	case string:
		return x != ""
	case []any:
		return len(x) > 0
	case *pyyaml.Map:
		return x.Len() > 0
	}
	return true
}

// mailIndex is str.index: a missing marker fails the test, as the Python
// ValueError did.
func mailIndex(t *testing.T, text, marker, where string) int {
	t.Helper()
	i := strings.Index(text, marker)
	if i < 0 {
		t.Fatalf("%s: marker %q not found", where, marker)
	}
	return i
}

func TestAutheliaRoleSuppliesInertDefaultsForNewRelayFields(t *testing.T) {
	defaults := mailLoadYAML(t, "ansible/roles/authelia/defaults/main.yml")
	certDefaults := mailLoadYAML(t, "ansible/roles/cert/defaults/main.yml")
	required := []string{
		"mail_notify_enabled",
		"mail_notify_to",
		"mail_notify_from",
		"mail_notify_only_for",
		"mail_relay_server",
		"mail_smtp_host",
		"mail_smtp_port",
		"mail_smtp_user",
		"mail_smtp_pass",
		"mail_smtp_server",
		"mail_smtp_username",
		"mail_smtp_password",
		"mail_smtp_ssl_mode",
		"mail_smtp_tls_skip_verify",
		"mail_smtp_timeout",
	}
	var missing []string
	for _, key := range required {
		if _, ok := defaults.Get(key); !ok {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		t.Errorf("authelia defaults lack %v", missing)
	}
	if mailTruthy(defaults.Value("mail_notify_enabled")) {
		t.Error("mail_notify_enabled must default to a falsy value")
	}
	if mailTruthy(defaults.Value("mail_relay_server")) {
		t.Error("mail_relay_server must default to a falsy value")
	}
	host, _ := defaults.Value("mail_smtp_host").(string)
	if !strings.HasSuffix(host, ".invalid") {
		t.Errorf("mail_smtp_host %q must end in .invalid", host)
	}
	if jinja.Equal(defaults.Value("mail_smtp_pass"), "CHANGE_ME") {
		t.Error("mail_smtp_pass must not default to CHANGE_ME")
	}
	for _, key := range []string{
		"mail_notify_enabled",
		"mail_notify_to",
		"mail_notify_from",
		"mail_notify_only_for",
		"mail_smtp_host",
		"mail_smtp_port",
		"mail_smtp_user",
		"mail_smtp_pass",
		"mail_smtp_ssl_mode",
	} {
		got, ok := defaults.Get(key)
		if !ok {
			t.Fatalf("authelia defaults lack %s", key)
		}
		want, ok := certDefaults.Get(key)
		if !ok {
			t.Fatalf("cert defaults lack %s", key)
		}
		if !jinja.Equal(got, want) {
			t.Errorf("%s: authelia default %v != cert default %v", key, got, want)
		}
	}
}

func TestComposeUsesAPrivatePersistentRelayWithoutExposingCredentials(t *testing.T) {
	compose := read(t, "ansible/roles/authelia/templates/docker-compose.yml.j2")
	relayStart := mailIndex(t, compose, "  mail_relay:", "authelia compose")
	autheliaStart := mailIndex(t, compose, "  {{ authelia_container_name }}:", "authelia compose")
	relay := compose[relayStart:autheliaStart]
	authelia := compose[autheliaStart:]
	mustContain(t, relay, "mail_relay_spool:/var/spool/postfix", "mail_relay service")
	mustContain(t, compose, "name: easy-ha-proxy-mail-relay-spool", "authelia compose")
	if strings.Contains(relay, "ports:") {
		t.Error("mail_relay must not publish ports")
	}
	mustContain(t, relay, "env_file:", "mail_relay service")
	if strings.Contains(authelia, "env_file:") {
		t.Error("the authelia service must not read the relay env_file")
	}
	mustContain(t, relay, `profiles: ["mail-relay"]`, "mail_relay service")
}

func TestTemplatesHaveNoDirectApplicationSmtpPath(t *testing.T) {
	config := read(t, "ansible/roles/authelia/templates/configuration.yml.j2")
	mustContain(t, config, "address: 'smtp://mail_relay:25'", "configuration.yml.j2")
	mustContain(t, config, "disable_starttls: true", "configuration.yml.j2")
	if strings.Contains(config, "mail_smtp_password") {
		t.Error("configuration.yml.j2 must not reference mail_smtp_password")
	}
}

func TestForwardAuthFailureCannotRedirectWithoutALocation(t *testing.T) {
	config := read(t, "ansible/roles/haproxy/templates/haproxy.cfg.j2")
	var redirects []string
	for _, line := range strings.Split(config, "\n") {
		stripped := strings.TrimSpace(line)
		if strings.HasPrefix(stripped, "http-request redirect location %[var(txn.auth_response_location)]") {
			redirects = append(redirects, stripped)
		}
	}
	if len(redirects) != 2 {
		t.Fatalf("found %d auth-response redirects, want 2", len(redirects))
	}
	for _, redirect := range redirects {
		mustContain(t, redirect, "{ var(txn.auth_response_location) -m found }", "redirect line")
	}
	if got := strings.Count(config, "http-request deny status 503 if"); got != 2 {
		t.Errorf("found %d 'http-request deny status 503 if' lines, want 2", got)
	}
	unit := read(t, "ansible/roles/authelia/templates/authelia-configd.service.j2")
	mustContain(t, unit, "AUTHELIA_HAPROXY_SOCKET={{ haproxy_socket", "authelia-configd.service.j2")
}

func TestCertHookReadsDynamicStateAndUsesTheSameQueue(t *testing.T) {
	hook := read(t, "ansible/roles/cert/templates/910-mail-notify.sh.j2")
	mustContain(t, hook, "mail-notify.json", "910-mail-notify.sh.j2")
	mustContain(t, hook, "flock -s -w 30", "910-mail-notify.sh.j2")
	mustContain(t, hook, "docker exec -i mail_relay /usr/sbin/sendmail", "910-mail-notify.sh.j2")
	for _, unwanted := range []string{"127.0.0.1:2525", "msmtp", "eval "} {
		if strings.Contains(hook, unwanted) {
			t.Errorf("910-mail-notify.sh.j2 holds %q", unwanted)
		}
	}
	// The agent validates the state (go/agent/internal/tools/cert_notify.go);
	// the host has no Python for it.
	mustContain(t, hook, `"${AGENT}" cert-notify-state "${STATE_FILE}" "${RENEWED_DOMAINS}"`, "910-mail-notify.sh.j2")
	if strings.Contains(hook, "python") {
		t.Error("910-mail-notify.sh.j2 must not call python")
	}
}

func TestCleanInstallStartsRelayBeforeFirstCertificateRenewal(t *testing.T) {
	playbook := read(t, "ansible/easy-ha-proxy.yml")
	authelia := mailIndex(t, playbook, "task_stage: install\n      tags:\n        - authelia", "playbook")
	renew := strings.Index(playbook[authelia:], "task_stage: renew")
	if renew < 0 {
		t.Fatal("no cert renew stage after the authelia install stage")
	}
	renew += authelia
	haproxyConfig := strings.Index(playbook[renew:], "task_stage: config")
	if haproxyConfig < 0 {
		t.Fatal("no haproxy config stage after the cert renew stage")
	}
	haproxyConfig += renew
	if authelia >= renew {
		t.Errorf("authelia install at %d must precede cert renew at %d", authelia, renew)
	}
	if renew >= haproxyConfig {
		t.Errorf("cert renew at %d must precede haproxy config at %d", renew, haproxyConfig)
	}
}

func TestInstallerAndLegacyAdoptionEnableOnlyTheRelay(t *testing.T) {
	installer := read(t, "go/agent/internal/cli/wizard.go")
	migration := read(t, "go/agent/internal/cli/legacy_config.go")
	mustContain(t, installer, "Configure email notifications through the internal relay", "wizard.go")
	if strings.Contains(installer, "Configure direct SMTP notifications") {
		t.Error("wizard.go must not offer direct SMTP notifications")
	}
	mustContain(t, migration, `result.Set("mail_relay_server", true)`, "legacy_config.go")
}
