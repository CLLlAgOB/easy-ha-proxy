package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"easy-ha-proxy/panel/shared/pyyaml"
)

const testRevision = "0123456789abcdef0123456789abcdef01234567"

func makeTarGz(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0o755,
			Size: int64(len(body)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func startFakeRegistry(t *testing.T, agent, sums []byte, revision string) *httptest.Server {
	t.Helper()
	blob := makeTarGz(t, map[string][]byte{
		"sbin/easy-ha-proxy-agent": agent,
		"SHA256SUMS":               sums,
	})
	cfg, _ := json.Marshal(map[string]any{
		"config": map[string]any{
			"Labels": map[string]string{"org.opencontainers.image.revision": revision},
		},
	})
	image, _ := json.Marshal(map[string]any{
		"config": map[string]any{"digest": "sha256:" + sha256Hex(cfg)},
		"layers": []map[string]any{{"digest": "sha256:" + sha256Hex(blob)}},
	})
	index, _ := json.Marshal(map[string]any{
		"manifests": []map[string]any{
			{
				"digest":   "sha256:" + sha256Hex(image),
				"platform": map[string]any{"os": "linux", "architecture": "arm64"},
			},
		},
	})
	bodies := map[string][]byte{
		"/v2/clllagob/haproxy-admin-ui/manifests/native-alpha-0123456789ab":  index,
		"/v2/clllagob/haproxy-admin-ui/manifests/sha256:" + sha256Hex(image): image,
		"/v2/clllagob/haproxy-admin-ui/blobs/sha256:" + sha256Hex(cfg):       cfg,
		"/v2/clllagob/haproxy-admin-ui/blobs/sha256:" + sha256Hex(blob):      blob,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			_, _ = w.Write([]byte(`{"token":"t"}`))
			return
		}
		body, ok := bodies[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	origReg := bootstrapRegistry
	origAuth := bootstrapAuthURL
	origClient := bootstrapHTTPClient
	bootstrapRegistry = srv.URL
	bootstrapAuthURL = srv.URL + "/token?repo=%s"
	bootstrapHTTPClient = srv.Client()
	t.Cleanup(func() {
		bootstrapRegistry = origReg
		bootstrapAuthURL = origAuth
		bootstrapHTTPClient = origClient
	})
	return srv
}

func TestImageReference(t *testing.T) {
	if got := ImageReference(map[string]any{"haproxy_admin_image": "clllagob/haproxy-admin-ui:alpha"}, testRevision); got != "clllagob/haproxy-admin-ui:native-alpha-0123456789ab" {
		t.Fatalf("unexpected alpha ref: %q", got)
	}
	if got := ImageReference(map[string]any{}, testRevision); got != "clllagob/haproxy-admin-ui:native-latest-0123456789ab" {
		t.Fatalf("unexpected default ref: %q", got)
	}
	if got := ImageReference(map[string]any{"native_release_base_url": "https://x"}, testRevision); got != "" {
		t.Fatalf("expected empty ref when release URL is set, got %q", got)
	}
}

func TestFetchAgentVerifiedAndRejectedCases(t *testing.T) {
	agent := []byte("\x7fELF agent")
	goodSums := []byte(fmt.Sprintf("%s  sbin/easy-ha-proxy-agent\n", sha256Hex(agent)))

	startFakeRegistry(t, agent, goodSums, testRevision)
	got, err := FetchAgent("clllagob/haproxy-admin-ui:native-alpha-0123456789ab", testRevision, "arm64")
	if err != nil {
		t.Fatalf("FetchAgent failed: %v", err)
	}
	if !bytes.Equal(got, agent) {
		t.Fatalf("unexpected agent bytes: %q", got)
	}

	// Wrong revision
	startFakeRegistry(t, agent, goodSums, strings.Repeat("f", 40))
	if _, err := FetchAgent("clllagob/haproxy-admin-ui:native-alpha-0123456789ab", testRevision, "arm64"); err == nil || !strings.Contains(err.Error(), "built from") {
		t.Fatalf("expected built-from error, got %v", err)
	}

	// Bad checksum
	badSums := []byte(strings.Repeat("0", 64) + "  sbin/easy-ha-proxy-agent\n")
	startFakeRegistry(t, agent, badSums, testRevision)
	if _, err := FetchAgent("clllagob/haproxy-admin-ui:native-alpha-0123456789ab", testRevision, "arm64"); err == nil || !strings.Contains(err.Error(), "SHA256SUMS") {
		t.Fatalf("expected SHA256SUMS error, got %v", err)
	}

	// Missing platform
	startFakeRegistry(t, agent, goodSums, testRevision)
	if _, err := FetchAgent("clllagob/haproxy-admin-ui:native-alpha-0123456789ab", testRevision, "amd64"); err == nil || !strings.Contains(err.Error(), "no linux/amd64") {
		t.Fatalf("expected platform error, got %v", err)
	}
}

func TestBundleAgentAndInstallAgent(t *testing.T) {
	dir := t.TempDir()
	tarBytes := makeTarGz(t, map[string][]byte{"./sbin/easy-ha-proxy-agent": []byte("local")})
	if err := os.WriteFile(filepath.Join(dir, "easy-ha-proxy-native-linux-arm64.tar.gz"), tarBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := BundleAgent(map[string]any{"native_local_bundle_dir": dir}, "arm64")
	if err != nil || string(got) != "local" {
		t.Fatalf("unexpected local bundle result: %q, %v", got, err)
	}
	if got, err := BundleAgent(map[string]any{}, "arm64"); err != nil || got != nil {
		t.Fatalf("expected nil for empty config, got %q, %v", got, err)
	}
	if _, err := BundleAgent(map[string]any{"native_release_base_url": "https://x"}, "arm64"); err == nil || !strings.Contains(err.Error(), "no SHA-256") {
		t.Fatalf("expected missing checksum error, got %v", err)
	}

	target := filepath.Join(t.TempDir(), "sub", "agent")
	if err := InstallAgent([]byte("binary"), target); err != nil {
		t.Fatalf("InstallAgent failed: %v", err)
	}
	raw, err := os.ReadFile(target)
	if err != nil || string(raw) != "binary" {
		t.Fatalf("unexpected installed content: %q, %v", raw, err)
	}
	st, err := os.Stat(target)
	if err != nil || st.Mode().Perm() != 0o755 {
		t.Fatalf("expected mode 0755, got %v", st.Mode().Perm())
	}
}

func TestPrepareLegacyConfig(t *testing.T) {
	root := t.TempDir()
	live := filepath.Join(root, "live")
	controller := filepath.Join(root, "controller")
	output := filepath.Join(root, "prepared-config")

	for _, rel := range []string{
		"opt/haproxy-admin/config",
		"opt/authelia",
	} {
		if err := os.MkdirAll(filepath.Join(live, rel), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(controller, "ansible"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile := func(p, body string) {
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(filepath.Join(live, "opt/haproxy-admin/config/vars.yml"), "root_domain: example.test\nadmin_domain: ha.example.test\naut_domain: aut.example.test\n")
	writeFile(filepath.Join(live, "opt/haproxy-admin/config/websites.yml"), "sites:\n  - name: app\n    domain: app.example.test\n")
	writeFile(filepath.Join(live, "opt/haproxy-admin/config/tcp.yml"), "tcp_proxies:\n  - name: ssh\n")
	writeFile(filepath.Join(live, "opt/authelia/configuration.yml"), `
session:
  secret: sess-sec
  cookies:
    - domain: example.test
      authelia_url: https://aut.example.test
identity_validation:
  reset_password:
    jwt_secret: jwt-sec
storage:
  encryption_key: stor-key
notifier:
  smtp:
    subject: "[example.test] Alert"
    timeout: 10s
access_control:
  default_policy: deny
  rules:
    - domain: ha.example.test
      policy: one_factor
`)
	writeFile(filepath.Join(live, "opt/authelia/users_database.yml"), "users:\n  admin:\n    displayname: Admin\n    password: hash\n")
	writeFile(filepath.Join(live, "opt/authelia/.env"), "MAIL_SMTP_PASSWORD=mail-pass\n")
	writeFile(filepath.Join(controller, "ansible/authelia.yml"), "authelia_enabled: true\n")

	var out bytes.Buffer
	if err := PrepareLegacyConfig(live, controller, output, &out); err != nil {
		t.Fatalf("PrepareLegacyConfig failed: %v", err)
	}
	if !strings.Contains(out.String(), "Sites preserved: 1") || !strings.Contains(out.String(), "Authelia users preserved: 1") {
		t.Fatalf("unexpected stdout: %s", out.String())
	}
	aut, err := LoadYAMLMapping(filepath.Join(output, "authelia.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if aut.Value("authelia_notifier_type") != "smtp" || aut.Value("mail_relay_server") != true {
		t.Fatalf("expected smtp notifier with mail_relay_server=true, got %v / %v", aut.Value("authelia_notifier_type"), aut.Value("mail_relay_server"))
	}
	secs, err := LoadYAMLMapping(filepath.Join(output, "secrets.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if secs.Value("authelia_session_secret") != "sess-sec" || secs.Value("mail_smtp_pass") != "mail-pass" || strVal(secs.Value("haproxy_admin_proxy_secret")) == "" {
		t.Fatalf("unexpected secrets: %v", mapToGoMap(secs))
	}
	users, err := LoadYAMLMapping(filepath.Join(output, "authelia_users_initial.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := users.Value("authelia_users").(*pyyaml.Map); !ok {
		t.Fatalf("expected authelia_users mapping")
	}
}
