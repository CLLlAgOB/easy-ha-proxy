package cli

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"easy-ha-proxy/panel/shared/pyyaml"
)

func TestReconfigurePreservesSitesTCPAndFutureValues(t *testing.T) {
	origCfg := configDirOverride
	origRuntime := runtimeHAProxyConfigDir
	origBackup := backupConfigurationFn
	t.Cleanup(func() {
		configDirOverride = origCfg
		runtimeHAProxyConfigDir = origRuntime
		backupConfigurationFn = origBackup
	})

	root := t.TempDir()
	cfg := filepath.Join(root, "managed")
	runtime := filepath.Join(root, "runtime")
	_ = os.MkdirAll(cfg, 0o700)
	_ = os.MkdirAll(runtime, 0o700)

	_ = WriteText(filepath.Join(cfg, "metadata.yml"),
		"product: easy-ha-proxy\nrepository: https://git.example.org/custom/repo.git\ntest_mode: false\n"+
			"certificate_source: internal\nsource_channel: local\nimage_channel: latest\n"+
			"admin_domain: ha.example.com\nauthelia_domain: aut.example.com\n"+
			"installation_complete: true\nconfiguration_pending: false\ncustom_metadata:\n  owner: operations\n", 0o600)
	_ = WriteText(filepath.Join(cfg, "vars.yml"),
		"root_domain: example.com\nadmin_domain: ha.example.com\naut_domain: aut.example.com\n"+
			"certbot_email: ops@example.com\nhaproxy_admin_timezone: Europe/Warsaw\n"+
			"admin_ips_enabled: false\nadmin_allowed_ips: []\nenable_geoip: true\ngeoip_country_codes: [PL, DE]\n"+
			"mail_notify_enabled: true\nmail_smtp_host: smtp.example.com\nmail_smtp_user: relay@example.com\n"+
			"site_defaults:\n  hsts: 31536000\n  custom_site_option: future-value\n"+
			"custom_future_option:\n  enabled: true\n", 0o600)
	_ = WriteText(filepath.Join(cfg, "authelia.yml"),
		"aut_domain: aut.example.com\nauthelia_timezone: Europe/Warsaw\nmail_subject: Custom security subject\n"+
			"custom_authelia_option:\n  future: kept\n", 0o600)
	_ = WriteText(filepath.Join(cfg, "secrets.yml"),
		"authelia_session_secret: session-secret\ncustom_future_secret: must-not-rotate\n", 0o600)
	_ = WriteText(filepath.Join(cfg, "authelia_users_initial.yml"), "authelia_users:\n  admin:\n    password: hash\n", 0o600)
	_ = WriteText(filepath.Join(cfg, "websites.yml"), "sites:\n  - name: managed-site\n", 0o600)
	_ = WriteText(filepath.Join(cfg, "tcp.yml"), "tcp_proxies:\n  - name: managed-tcp\n", 0o600)

	// Runtime overrides UI-owned keys only.
	_ = WriteText(filepath.Join(runtime, "vars.yml"),
		"enable_http80: true\nmail_notify_enabled: false\nsite_defaults:\n  hsts: 12345\n  custom_site_option: future-value\n", 0o600)
	_ = WriteText(filepath.Join(runtime, "websites.yml"), "sites:\n  - name: runtime-site\n", 0o600)
	_ = WriteText(filepath.Join(runtime, "tcp.yml"), "tcp_proxies:\n  - name: runtime-tcp\n", 0o600)

	configDirOverride = cfg
	runtimeHAProxyConfigDir = runtime
	backupCalled := 0
	backupConfigurationFn = func(_ ioWriter, _ string) (string, error) { backupCalled++; return "", nil }
	t.Setenv("EASY_HA_PROXY_ALLOW_STDIN", "1")

	var out bytes.Buffer
	ctx := NewContext(strings.NewReader("\n\n"), &out, &out)
	ctx.promptFn = func(label, def string, _ func(string) string) (string, error) {
		if def == "" {
			t.Fatalf("missing default for %q", label)
		}
		return def, nil
	}
	ctx.boolFn = func(label string, _ bool) (bool, error) {
		t.Fatalf("unexpected bool prompt %q during reconfigure", label)
		return false, nil
	}

	if _, err := ConfigureInteractively(ctx, ConfigureOptions{
		Overwrite:         true,
		CertificateSource: "internal",
		ImageChannel:      "latest",
		SourceChannel:     "local",
	}); err != nil {
		t.Fatalf("ConfigureInteractively failed: %v", err)
	}
	if backupCalled != 1 {
		t.Fatalf("expected 1 backup, got %d", backupCalled)
	}
	vars, _ := LoadYAMLMapping(filepath.Join(cfg, "vars.yml"))
	aut, _ := LoadYAMLMapping(filepath.Join(cfg, "authelia.yml"))
	secs, _ := LoadYAMLMapping(filepath.Join(cfg, "secrets.yml"))
	web, _ := LoadYAMLMapping(filepath.Join(cfg, "websites.yml"))
	tcp, _ := LoadYAMLMapping(filepath.Join(cfg, "tcp.yml"))
	meta, _ := LoadYAMLMapping(filepath.Join(cfg, "metadata.yml"))

	if vars.Value("enable_http80") != true || vars.Value("mail_notify_enabled") != true {
		t.Fatalf("runtime/installer authority mismatch: %v", mapToGoMap(vars))
	}
	if aut.Value("mail_subject") != "Custom security subject" || secs.Value("custom_future_secret") != "must-not-rotate" {
		t.Fatalf("future values lost")
	}
	sites := web.Value("sites").([]any)
	if sites[0].(*pyyaml.Map).Value("name") != "runtime-site" {
		t.Fatalf("expected runtime-site, got %v", sites[0])
	}
	proxies := tcp.Value("tcp_proxies").([]any)
	if proxies[0].(*pyyaml.Map).Value("name") != "runtime-tcp" {
		t.Fatalf("expected runtime-tcp, got %v", proxies[0])
	}
	if meta.Value("installation_complete") != true || meta.Value("configuration_pending") != true {
		t.Fatalf("unexpected metadata flags: %v", mapToGoMap(meta))
	}
}

func TestFreshInstallAccessGateAndArgon2id(t *testing.T) {
	origCfg := configDirOverride
	origLocalIP := detectLocalIPFn
	t.Cleanup(func() {
		configDirOverride = origCfg
		detectLocalIPFn = origLocalIP
	})
	detectLocalIPFn = func() string { return "192.168.56.10" }
	t.Setenv("EASY_HA_PROXY_ALLOW_STDIN", "1")

	for _, tc := range []struct {
		testMode bool
		source   string
	}{
		{true, "internal"},
		{false, "letsencrypt"},
	} {
		dir := t.TempDir()
		configDirOverride = dir
		var out bytes.Buffer
		ctx := NewContext(strings.NewReader("\n\n"), &out, &out)
		ctx.promptFn = func(label, def string, _ func(string) string) (string, error) {
			switch label {
			case "Root domain":
				return "example.com", nil
			case "Timezone":
				return "UTC", nil
			case "Let's Encrypt / administrator email":
				return "admin@example.com", nil
			default:
				return def, nil
			}
		}
		ctx.boolFn = func(_ string, def bool) (bool, error) { return def, nil }
		ctx.passFn = func(_ string) (string, error) { return "super-secret-password-123", nil }

		tm := tc.testMode
		if _, err := ConfigureInteractively(ctx, ConfigureOptions{
			Overwrite:         true,
			TestMode:          &tm,
			CertificateSource: tc.source,
			ImageChannel:      "latest",
			SourceChannel:     "local",
		}); err != nil {
			t.Fatalf("fresh install (%s) failed: %v", tc.source, err)
		}
		web, _ := LoadYAMLMapping(filepath.Join(dir, "websites.yml"))
		sites := web.Value("sites").([]any)
		if len(sites) != 1 {
			t.Fatalf("expected 1 access gate site, got %d", len(sites))
		}
		gate := sites[0].(*pyyaml.Map)
		if gate.Value("certificate_source") != tc.source || gate.Value("le_managed") != (tc.source == "letsencrypt") {
			t.Fatalf("unexpected gate cert config: %v", mapToGoMap(gate))
		}
		usersDoc, _ := LoadYAMLMapping(filepath.Join(dir, "authelia_users_initial.yml"))
		adminUser := usersDoc.Value("authelia_users").(*pyyaml.Map).Value("admin").(*pyyaml.Map)
		pwHash := strVal(adminUser.Value("password"))
		if !strings.HasPrefix(pwHash, "$argon2id$v=19$m=65536,t=3,p=4$") {
			t.Fatalf("unexpected argon2id PHC hash: %q", pwHash)
		}
	}
}

func TestGenerateInternalCertificateAndSymlinkSafety(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed")
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	cfg := filepath.Join(root, "config")
	certs := filepath.Join(root, "certs")
	caRoot := filepath.Join(root, "authorities")
	_ = os.MkdirAll(home, 0o755)
	_ = os.MkdirAll(cfg, 0o700)
	_ = WriteText(filepath.Join(cfg, "metadata.yml"),
		"admin_domain: ha.example.test\nauthelia_domain: aut.example.test\ncertificate_source: internal\n", 0o600)

	victim := filepath.Join(root, "victim")
	_ = os.WriteFile(victim, []byte("keep me\n"), 0o600)
	export := filepath.Join(home, "internal-ca.crt")
	if err := os.Symlink(victim, export); err != nil {
		t.Fatal(err)
	}

	t.Setenv("EASY_HA_PROXY_HOME", home)
	t.Setenv("EASY_HA_PROXY_CERT_DIR", certs)
	t.Setenv("HAPROXY_CA_ROOT_DIR", caRoot)
	t.Setenv("EASY_HA_PROXY_CA_EXPORT", "")
	_ = os.Unsetenv("EASY_HA_PROXY_CA_EXPORT")

	var out bytes.Buffer
	caPath, err := GenerateInternalCertificate(&out, cfg)
	if err != nil {
		t.Fatalf("GenerateInternalCertificate failed: %v", err)
	}
	if caPath != filepath.Join(caRoot, "internal", "ca.crt") {
		t.Fatalf("unexpected caPath: %s", caPath)
	}

	// Victim was untouched and symlink was atomically replaced.
	victimRaw, _ := os.ReadFile(victim)
	if string(victimRaw) != "keep me\n" {
		t.Fatalf("symlink victim was overwritten: %q", victimRaw)
	}
	if isSymlink(export) {
		t.Fatal("export path should no longer be a symlink")
	}
	caPEM, _ := os.ReadFile(caPath)
	expPEM, _ := os.ReadFile(export)
	if !bytes.Equal(caPEM, expPEM) || bytes.Contains(expPEM, []byte("PRIVATE KEY")) {
		t.Fatal("exported CA cert mismatch or leaked private key")
	}

	// Verify X.509 signature and SANs.
	caBlock, _ := pem.Decode(caPEM)
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil || !caCert.IsCA {
		t.Fatalf("invalid CA cert: err=%v isCA=%v", err, caCert.IsCA)
	}
	leafPEM, _ := os.ReadFile(filepath.Join(certs, "easy-ha-proxy-internal.pem"))
	leafBlock, _ := pem.Decode(leafPEM)
	leafCert, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := leafCert.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("leaf cert signature verification failed: %v", err)
	}
	if strings.Join(leafCert.DNSNames, ",") != "ha.example.test,aut.example.test" {
		t.Fatalf("unexpected SANs: %v", leafCert.DNSNames)
	}
}

func TestDetectTimezone(t *testing.T) {
	dir := t.TempDir()
	tzFile := filepath.Join(dir, "timezone")
	localLink := filepath.Join(dir, "localtime")

	_ = os.WriteFile(tzFile, []byte("Europe/Warsaw\n"), 0o644)
	if got := DetectTimezone(tzFile, localLink); got != "Europe/Warsaw" {
		t.Fatalf("expected Europe/Warsaw, got %q", got)
	}

	_ = os.Remove(tzFile)
	_ = os.Symlink("/usr/share/zoneinfo/posix/Asia/Tokyo", localLink)
	if got := DetectTimezone(tzFile, localLink); got != "Asia/Tokyo" {
		t.Fatalf("expected Asia/Tokyo, got %q", got)
	}

	_ = os.Remove(localLink)
	if got := DetectTimezone(tzFile, localLink); got != "UTC" {
		t.Fatalf("expected UTC fallback, got %q", got)
	}
}
