package certd

import (
	"strings"
	"testing"
)

func TestNormalizeDNSName(t *testing.T) {
	cases := map[string]string{"Example.COM.": "example.com", "a-b.example.org": "a-b.example.org"}
	for in, want := range cases {
		got, err := normalizeDNSName(in, false)
		if err != nil || got != want {
			t.Fatalf("%q: %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "single", "-a.example.com", "a..example.com", "*.example.com", "a/b.example.com"} {
		if _, err := normalizeDNSName(bad, false); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	if got, err := normalizeDNSName("*.Example.org", true); err != nil || got != "*.example.org" {
		t.Fatalf("wildcard: %q %v", got, err)
	}
	if _, err := normalizeDNSName("*.org", true); err == nil || err.Error() != "DNS name must contain at least two labels" {
		t.Fatalf("short wildcard: %v", err)
	}
}

func TestWildcardMatching(t *testing.T) {
	if !hostnameMatchesPattern("a.example.org", "*.example.org") || hostnameMatchesPattern("a.b.example.org", "*.example.org") ||
		hostnameMatchesPattern("example.org", "*.example.org") {
		t.Fatal("wildcard covers exactly one label")
	}
	if !nameCovers("*.example.org", "x.example.org") || nameCovers("*.example.org", "y.x.example.org") {
		t.Fatal("nameCovers")
	}
}

func TestRenewalPauseText(t *testing.T) {
	text := "version = 2\n[renewalparams]\nauthenticator = standalone\n"
	paused := renewalTextWithPause(text, true)
	if !strings.Contains(paused, "[renewalparams]\n"+renewalPauseMarker+"\nautorenew = False\nauthenticator") {
		t.Fatalf("pause: %q", paused)
	}
	if renewalTextWithPause(paused, false) != text {
		t.Fatal("unpause must restore the original text")
	}
	if lineageDomain("example.com-ecdsa-0001") != "example.com" || lineageDomain("Example.com-rsa") != "example.com" {
		t.Fatal("lineage domain")
	}
}

func TestNormaliseUploadedPEM(t *testing.T) {
	cert := "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
	key := "-----BEGIN PRIVATE KEY-----\nBBBB\n-----END PRIVATE KEY-----\n"
	out, err := normaliseUploadedPEM([]byte(key+cert), []byte(key+cert))
	if err != nil || string(out) != strings.TrimSpace(cert)+"\n"+strings.TrimSpace(key)+"\n" {
		t.Fatalf("normalise: %q %v", out, err)
	}
	if _, err := normaliseUploadedPEM([]byte(cert)); err == nil || !strings.Contains(err.Error(), "no private key") {
		t.Fatalf("no key: %v", err)
	}
	if _, err := extractPEMBlocks([]byte("-----BEGIN CERTIFICATE-----\nAAA"), "CERTIFICATE"); err == nil {
		t.Fatal("incomplete block accepted")
	}
}

func TestSafeSlugAndBase64Errors(t *testing.T) {
	if s, _ := safeSlug(" My CA/2 "); s != "My-CA-2" {
		t.Fatalf("slug: %q", s)
	}
	if _, err := safeSlug("..."); err == nil {
		t.Fatal("dots-only slug accepted")
	}
	if pyBase64Error("!!!") != "Only base64 data is allowed" || pyBase64Error("abc") != "Incorrect padding" {
		t.Fatal("base64 messages")
	}
}
