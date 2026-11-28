package contract

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Regression tests for the systemd hardening on the helper daemons.
// haproxy-certd runs snap-confined certbot, and snapd insists on creating a
// per-user data directory under the home of the account it runs as (/root),
// which it reads from the passwd entry and not from $HOME. ProtectHome=yes
// mounts /root read-only, so certbot died with "cannot create snap home
// dir: mkdir /root/snap: read-only file system" and no certificate could be
// issued from the web interface at all. Only tmpfs both hides the real home
// directories and leaves somewhere for snapd to write.

const unitDir = "ansible/roles/haproxy-admin/templates"
const agentInternal = "go/agent/internal"

// unitForPackage is the unit each agent package's daemon runs in.
var unitForPackage = map[string]string{"certd": "haproxy-certd.service.j2"}

// blocksSnap: ProtectHome=yes and =read-only both make /root unwritable.
var blocksSnap = map[string]bool{"yes": true, "true": true, "on": true, "read-only": true}

// unitsRunningCertbot derives the unit templates whose daemon executes
// certbot, so a second daemon that starts shelling out to certbot is covered
// the day it does.
func unitsRunningCertbot(t *testing.T) []string {
	t.Helper()
	root := repoRoot(t)
	packages, err := os.ReadDir(filepath.Join(root, agentInternal))
	if err != nil {
		t.Fatal(err)
	}
	var units []string
	for _, pkg := range packages {
		if !pkg.IsDir() {
			continue
		}
		dir := filepath.Join(root, agentInternal, pkg.Name())
		sources, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		runs := false
		for _, f := range sources {
			name := f.Name()
			if f.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			// Reading the binary's setting, not merely mentioning certbot.
			raw, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), `"CERTBOT_BIN"`) {
				runs = true
				break
			}
		}
		if !runs {
			continue
		}
		unit, ok := unitForPackage[pkg.Name()]
		if !ok {
			t.Fatalf("%s runs certbot; add its unit to unitForPackage", pkg.Name())
		}
		units = append(units, unit)
	}
	return units
}

var protectHomeRe = regexp.MustCompile(`(?m)^ProtectHome\s*=\s*(\S+)`)

func protectHome(t *testing.T, unit string) string {
	t.Helper()
	m := protectHomeRe.FindStringSubmatch(read(t, unitDir+"/"+unit))
	if m == nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(m[1]))
}

func TestTheCertificateDaemonIsAmongTheCertbotUnits(t *testing.T) {
	// If this ever finds nothing, the test below is vacuously true and
	// would keep passing while protecting nothing.
	for _, unit := range unitsRunningCertbot(t) {
		if unit == "haproxy-certd.service.j2" {
			return
		}
	}
	t.Fatalf("haproxy-certd.service.j2 not among the certbot units: %v", unitsRunningCertbot(t))
}

func TestNoUnitThatRunsCertbotMakesRootUnwritable(t *testing.T) {
	for _, unit := range unitsRunningCertbot(t) {
		if got := protectHome(t, unit); blocksSnap[got] {
			t.Errorf("%s runs snap-confined certbot; ProtectHome=%s makes /root read-only and snapd cannot create /root/snap", unit, got)
		}
	}
}

func TestHomeDirectoriesAreStillHidden(t *testing.T) {
	// The fix must not decay into "drop the protection": removing the
	// setting altogether would also make certbot work, and would also
	// expose every real home directory to this daemon.
	if got := protectHome(t, "haproxy-certd.service.j2"); got != "tmpfs" {
		t.Fatalf("ProtectHome=%s, want tmpfs", got)
	}
}

// unitSetting is every value of a setting, split on whitespace (systemd
// list syntax).
func unitSetting(t *testing.T, unit, name string) []string {
	t.Helper()
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(name) + `\s*=\s*(.*)$`)
	var values []string
	for _, m := range re.FindAllStringSubmatch(read(t, unitDir+"/"+unit), -1) {
		values = append(values, strings.Fields(m[1])...)
	}
	return values
}

// healthd keeps the journalctl --cursor-file state of its "follow" log mode
// in /run/haproxy-healthd-cursors, outside its socket directory; with only
// easy-ha-proxy listed under ProtectSystem=strict, journalctl could not save
// the cursor and the mode answered errors.

func cursorDefault(t *testing.T) string {
	t.Helper()
	re := regexp.MustCompile(`envOr\("HEALTHD_CURSOR_DIR",\s*"([^"]+)"\)`)
	m := re.FindStringSubmatch(read(t, agentInternal+"/healthd/state.go"))
	if m == nil {
		t.Fatal("cursor directory default not found in healthd")
	}
	return m[1]
}

func TestTheHealthdUnitIsStrict(t *testing.T) {
	// Without strict the directories below need not be listed, and this
	// test would protect nothing.
	got := unitSetting(t, "haproxy-healthd.service.j2", "ProtectSystem")
	if len(got) != 1 || got[0] != "strict" {
		t.Fatalf("ProtectSystem=%v, want [strict]", got)
	}
}

func TestHealthdCursorDirectoryIsWritableUnderStrict(t *testing.T) {
	const unit = "haproxy-healthd.service.j2"
	writable := map[string]bool{}
	for _, name := range unitSetting(t, unit, "RuntimeDirectory") {
		writable["/run/"+name] = true
	}
	// A leading "-" only makes a missing path non-fatal.
	for _, p := range unitSetting(t, unit, "ReadWritePaths") {
		writable[strings.TrimLeft(p, "-")] = true
	}
	path := cursorDefault(t)
	if !writable[path] {
		t.Fatalf("healthd writes cursors to %s, which ProtectSystem=strict leaves read-only (RuntimeDirectory: %v)",
			path, unitSetting(t, unit, "RuntimeDirectory"))
	}
}

func TestHealthdSocketDirectoryIsStillListed(t *testing.T) {
	for _, name := range unitSetting(t, "haproxy-healthd.service.j2", "RuntimeDirectory") {
		if name == "easy-ha-proxy" {
			return
		}
	}
	t.Fatal("easy-ha-proxy is not listed in RuntimeDirectory")
}
