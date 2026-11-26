package contract

import (
	"strings"
	"testing"
)

// Regression tests for the non-network security boundaries: the remote
// installer's apply path, the UI update's daemon compatibility tag, the
// Authelia container hardening, and the proxy secret header that must work
// without a systemd Environment= directive.

func TestRemoteSyncCanApplyLocalSourceWithAlphaImage(t *testing.T) {
	// --sync-source alone must be able to apply the local source channel
	// while keeping the chosen (alpha) image channel.
	remote := read(t, "install-remote.sh")
	mustContain(t, remote, "--apply", "install-remote.sh")
	mustContain(t, remote, "--source-channel local", "install-remote.sh")
	mustContain(t, remote, "--image-channel ${image_channel}", "install-remote.sh")
}

func TestUIUpdateDeploysCompatibleCertificateDaemon(t *testing.T) {
	// The UI update component must carry the daemon tag, or a UI update
	// would leave an incompatible certificate daemon behind.
	installer := read(t, "go/agent/internal/cli/config.go")
	afterUITags := strings.SplitN(installer, "UITags =", 2)
	if len(afterUITags) != 2 {
		t.Fatal("config.go has no UITags assignment")
	}
	uiTags := strings.SplitN(afterUITags[1], "DaemonTags =", 2)[0]
	mustContain(t, uiTags, "ha-adm-daemons", "UITags")
}

func TestAutheliaKeepsSupportedContainerHardening(t *testing.T) {
	// Authelia 4.39 needs a writable root filesystem, so read_only: true
	// must stay off its service; the rest of the hardening must stay on.
	compose := read(t, "ansible/roles/authelia/templates/docker-compose.yml.j2")
	afterService := strings.SplitN(compose, "  {{ authelia_container_name }}:", 2)
	if len(afterService) != 2 {
		t.Fatal("docker-compose.yml.j2 has no authelia service")
	}
	autheliaService := strings.SplitN(afterService[1], "\nnetworks:", 2)[0]
	if strings.Contains(autheliaService, "read_only: true") {
		t.Error("authelia service sets read_only: true, which its startup checks cannot survive")
	}
	mustContain(t, autheliaService, "cap_drop:\n      - ALL", "authelia service")
	mustContain(t, autheliaService, "no-new-privileges:true", "authelia service")
}

func TestProxySecretHeaderIsValidWithoutSystemdEnvironment(t *testing.T) {
	// HAProxy reads the secret from its own environment file, so the
	// %[env(...)] fetch must be paired with the env template writing it.
	haproxyTemplate := read(t, "ansible/roles/haproxy/templates/haproxy.cfg.j2")
	adminEnvironment := read(t, "ansible/roles/haproxy-admin/templates/haproxy-admin.env.j2")
	mustContain(t, haproxyTemplate, "%[env(HAPROXY_ADMIN_PROXY_SECRET)]", "haproxy.cfg.j2")
	mustContain(t, adminEnvironment, "HAPROXY_ADMIN_PROXY_SECRET={{ haproxy_admin_proxy_secret", "haproxy-admin.env.j2")
}
