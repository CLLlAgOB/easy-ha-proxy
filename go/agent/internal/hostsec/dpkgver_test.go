package hostsec

import (
	"testing"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "2.0", -1},
		{"2.0", "1.0", 1},
		{"1.0~rc1", "1.0", -1},
		{"1.0~alpha", "1.0~beta", -1},
		{"1.0~", "1.0~~", 1},
		{"1:1.0", "2.0", 1},
		{"0:1.0", "1.0", 0},
		{"1.0-1", "1.0-2", -1},
		{"1.0-1ubuntu1", "1.0-1ubuntu1.1", -1},
		{"1.0-1ubuntu1.2", "1.0-1ubuntu1.10", -1},
		{"5:28.5.1-1~ubuntu.24.04~noble", "5:28.5.2-1~ubuntu.24.04~noble", -1},
		{"2.39-0ubuntu8.3", "2.39-0ubuntu8.4", -1},
		{"1.0+dfsg-1", "1.0-1", 1},
		{"1.0-0", "1.0", 0},
	}
	for _, tc := range cases {
		got := CompareVersions(tc.a, tc.b)
		if (tc.want < 0 && got >= 0) || (tc.want > 0 && got <= 0) || (tc.want == 0 && got != 0) {
			t.Errorf("CompareVersions(%q, %q) = %d, want sign %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestParsePolicyFilesAndPackages(t *testing.T) {
	globalPolicy := `Package files:
 100 /var/lib/dpkg/status
     release a=now
 500 http://security.ubuntu.com/ubuntu noble-security/main amd64 Packages
     release v=24.04,o=Ubuntu,a=noble-security,n=noble,l=Ubuntu,c=main,b=amd64
     origin security.ubuntu.com
 500 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 Packages
     release v=24.04,o=Ubuntu,a=noble-updates,n=noble,l=Ubuntu,c=main,b=amd64
     origin archive.ubuntu.com
 500 https://esm.ubuntu.com/apps/ubuntu noble-apps-security/main amd64 Packages
     release v=24.04,o=UbuntuESMApps,a=noble-apps-security,n=noble,l=UbuntuESMApps,c=main,b=amd64
 500 https://deb.debian.org/debian-security bookworm-security/main amd64 Packages
     release v=12,o=Debian,a=stable-security,n=bookworm-security,l=Debian-Security,c=main,b=amd64
Pinned packages:
`
	origins := parsePolicyFiles(globalPolicy, false)
	secURL := "http://security.ubuntu.com/ubuntu noble-security/main amd64 Packages"
	updURL := "http://archive.ubuntu.com/ubuntu noble-updates/main amd64 Packages"
	esmURL := "https://esm.ubuntu.com/apps/ubuntu noble-apps-security/main amd64 Packages"
	debURL := "https://deb.debian.org/debian-security bookworm-security/main amd64 Packages"

	if !isSecurityOrigin(origins[secURL], "ubuntu", "noble") {
		t.Fatalf("expected ubuntu noble-security origin to match: %+v", origins[secURL])
	}
	if isSecurityOrigin(origins[updURL], "ubuntu", "noble") {
		t.Fatalf("expected ubuntu noble-updates NOT to be security origin")
	}
	if !isSecurityOrigin(origins[esmURL], "ubuntu", "noble") {
		t.Fatalf("expected UbuntuESMApps noble-apps-security to match: %+v", origins[esmURL])
	}
	if !isSecurityOrigin(origins[debURL], "debian", "bookworm") {
		t.Fatalf("expected Debian bookworm-security to match: %+v", origins[debURL])
	}
	if !isOfficialDistroOrigin(origins[updURL], "ubuntu", "noble") {
		t.Fatalf("expected noble-updates to be official distro origin")
	}
	if isOfficialDistroOrigin(origins[debURL], "ubuntu", "noble") {
		t.Fatalf("expected Debian origin NOT to be official Ubuntu origin")
	}

	pkgPolicy := `openssl:
  Installed: 3.0.13-0ubuntu3.1
  Candidate: 3.0.13-0ubuntu3.4
  Version table:
     3.0.13-0ubuntu3.4 500
        500 http://security.ubuntu.com/ubuntu noble-security/main amd64 Packages
 *** 3.0.13-0ubuntu3.1 100
        100 /var/lib/dpkg/status
curl:
  Installed: 8.5.0-2ubuntu10.1
  Candidate: 8.5.0-2ubuntu10.4
  Version table:
     8.5.0-2ubuntu10.4 500
        500 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 Packages
 *** 8.5.0-2ubuntu10.1 100
        100 /var/lib/dpkg/status
`
	parsed := parsePackagePolicies(pkgPolicy)
	if len(parsed) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(parsed))
	}
	ossl := parsed["openssl"]
	if len(ossl) != 2 || ossl[0].Version != "3.0.13-0ubuntu3.4" || ossl[1].Version != "3.0.13-0ubuntu3.1" {
		t.Fatalf("unexpected openssl policy: %+v", ossl)
	}
	if len(ossl[0].Files) != 1 || ossl[0].Files[0] != secURL {
		t.Fatalf("unexpected openssl sources: %+v", ossl[0].Files)
	}
}

func TestParseAptConfigShell(t *testing.T) {
	text := "PERIODIC='0'\nREBOOT='false'\nSHUTDOWN='true'\n"
	vals := parseAptConfigShell(text)
	if vals["PERIODIC"] != "0" || parseAptBool(vals["REBOOT"], true) || !parseAptBool(vals["SHUTDOWN"], false) {
		t.Fatalf("unexpected apt-config parse: %+v", vals)
	}
}
