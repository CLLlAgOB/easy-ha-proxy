package contract

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Regression tests for container-level application readiness checks: the
// admin container is probed through the same authenticated boundary HAProxy
// uses, the unhealthy window stays at two minutes, and Redis keeps a native
// ping healthcheck.

// adminHealthcheckStanza is just the healthcheck stanza of the admin
// service.
func adminHealthcheckStanza(t *testing.T) string {
	t.Helper()
	compose := read(t, "ansible/roles/haproxy-admin/templates/docker-compose.yml.j2")
	parts := strings.SplitN(compose, "healthcheck:", 2)
	if len(parts) != 2 {
		t.Fatal("no healthcheck stanza in the admin compose template")
	}
	return strings.SplitN(parts[1], "networks:", 2)[0]
}

func TestAdminHealthcheckUsesTheAuthenticatedMinimalEndpoint(t *testing.T) {
	// The point of the check: it goes through the same authenticated
	// boundary HAProxy uses, rather than some separate unauthenticated
	// readiness path that would prove less. The panel binary's own
	// subcommand makes that request.
	healthcheck := adminHealthcheckStanza(t)
	mustContain(t, healthcheck, "- /usr/local/bin/easy-ha-proxy-panel", "admin healthcheck")
	mustContain(t, healthcheck, "- healthcheck", "admin healthcheck")
	main := read(t, "go/panel/cmd/easy-ha-proxy-panel/main.go")
	parts := strings.SplitN(main, "func runHealthcheck() error {", 2)
	if len(parts) != 2 {
		t.Fatal("runHealthcheck not found in the panel main")
	}
	check := strings.SplitN(parts[1], "\n}\n", 2)[0]
	for _, want := range []string{
		"HAPROXY_ADMIN_PROXY_SECRET",
		"security.ControlPlaneHealthPath",
		"security.ControlPlaneHealthUser",
		"security.ControlPlaneHealthGroup",
		`payload["ok"]`,
	} {
		mustContain(t, check, want, "runHealthcheck")
	}
}

func TestTheUnhealthyWindowIsUnchanged(t *testing.T) {
	// Asking less often must not mean noticing later. It was twelve
	// attempts ten seconds apart; any pair multiplying to the same two
	// minutes is fine. A pair that does not changes how long a wedged
	// container stays in service, and that should be a decision rather than
	// a side effect of tuning CPU.
	healthcheck := adminHealthcheckStanza(t)
	intervalMatch := regexp.MustCompile(`interval:\s*(\d+)s`).FindStringSubmatch(healthcheck)
	retriesMatch := regexp.MustCompile(`retries:\s*(\d+)`).FindStringSubmatch(healthcheck)
	if intervalMatch == nil || retriesMatch == nil {
		t.Fatal("interval or retries missing from the admin healthcheck")
	}
	interval, err := strconv.Atoi(intervalMatch[1])
	if err != nil {
		t.Fatal(err)
	}
	retries, err := strconv.Atoi(retriesMatch[1])
	if err != nil {
		t.Fatal(err)
	}
	if interval*retries != 120 {
		t.Errorf("interval %ds x retries %d = %ds, want 120s", interval, retries, interval*retries)
	}
}

func TestRedisHasANativePingHealthcheck(t *testing.T) {
	compose := read(t, "ansible/roles/authelia/templates/docker-compose.yml.j2")
	parts := strings.SplitN(compose, "  authelia-redis:", 2)
	if len(parts) != 2 {
		t.Fatal("no authelia-redis service in the authelia compose template")
	}
	// The end marker may have moved on; the split then keeps the rest of
	// the file, exactly as the Python slice did.
	redisService := strings.SplitN(parts[1], "\n\n{% if mail_relay_server", 2)[0]
	mustContain(t, redisService, `test: ["CMD", "redis-cli", "ping"]`, "authelia-redis")
	mustContain(t, redisService, "start_period: 5s", "authelia-redis")
}
