package certrestore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenewalPolicy(t *testing.T) {
	const root = "/etc/letsencrypt"
	const standalone = "version = 5.5.0\narchive_dir = /etc/letsencrypt/archive/example.test\n" +
		"privkey = /etc/letsencrypt/live/example.test/privkey.pem\n[renewalparams]\nauthenticator = standalone\n"
	const profile = "[renewalparams]\nauthenticator = dns-cloudflare\ndns_cloudflare_credentials = "
	for _, data := range []string{standalone + "[[webroot_map]]\n", profile + DefaultDNSCredentialsDir + "/operator.ini\n"} {
		if !SafeRenewal([]byte(data), root, DefaultDNSCredentialsDir, "example.test") {
			t.Errorf("refused supported renewal config %q", data)
		}
	}
	for _, data := range []string{
		standalone + "manual-auth-hook = disabled\n",
		strings.Replace(standalone, "= standalone", "= webroot", 1),
		standalone + "[[webroot_map]]\nexample.test = /unmanaged\n",
		strings.Replace(standalone, "live/example.test", "live/other.test", 1),
		profile + "/unmanaged/credentials.ini\n",
	} {
		if SafeRenewal([]byte(data), root, DefaultDNSCredentialsDir, "example.test") {
			t.Errorf("accepted unsupported renewal config %q", data)
		}
	}
}

func TestRestorePreservesCertbotLiveLink(t *testing.T) {
	root := t.TempDir()
	rel := []string{"live", "example.test", "privkey.pem"}
	live := filepath.Join(append([]string{root}, rel...)...)
	if err := os.MkdirAll(filepath.Dir(live), 0o700); err != nil {
		t.Fatal(err)
	}
	const link = "../../archive/example.test/privkey2.pem"
	if err := os.Symlink(link, live); err != nil {
		t.Fatal(err)
	}
	if err := WriteLEFile(root, rel, []byte("restored")); err != nil {
		t.Fatal(err)
	}
	if got, err := os.Readlink(live); err != nil || got != link {
		t.Fatalf("link = %q, %v", got, err)
	}
	if got, err := os.ReadFile(live); err != nil || string(got) != "restored" {
		t.Fatalf("certificate = %q, %v", got, err)
	}
	if err := os.Remove(live); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../archive/other.test/privkey2.pem", live); err != nil {
		t.Fatal(err)
	}
	if err := WriteLEFile(root, rel, []byte("refused")); err == nil {
		t.Fatal("accepted a cross-lineage link")
	}
}
