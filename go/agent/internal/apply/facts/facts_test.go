package facts

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"easy-ha-proxy/panel/shared/pyyaml"
)

func fakeRoot(t *testing.T, osRelease, cpuinfo string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range map[string]string{"etc/os-release": osRelease, "proc/cpuinfo": cpuinfo} {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestSetupMatchesAnsibleOnTheHostsWeRunOn(t *testing.T) {
	cases := []struct {
		name, osRelease, machine string
		cpus                     int
		want                     map[string]any
	}{
		{"ubuntu noble on x86", `PRETTY_NAME="Ubuntu 24.04.3 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
UBUNTU_CODENAME=noble
`, "x86_64", 2, map[string]any{"os_family": "Debian", "distribution": "Ubuntu", "distribution_release": "noble",
			"distribution_version": "24.04", "distribution_major_version": "24", "architecture": "x86_64", "processor_vcpus": int64(2)}},
		{"debian bookworm on arm", `PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
VERSION_ID="12"
ID=debian
`, "aarch64", 4, map[string]any{"os_family": "Debian", "distribution": "Debian", "distribution_release": "bookworm",
			"distribution_major_version": "12", "architecture": "aarch64", "processor_vcpus": int64(4)}},
		// Ansible maps the distribution name alone; ID_LIKE plays no part.
		{"an unknown derivative", "ID=armbian\nID_LIKE=\"debian ubuntu\"\nVERSION_CODENAME=jammy\n", "armv7l", 1,
			map[string]any{"os_family": "Armbian", "distribution": "Armbian", "distribution_release": "jammy", "architecture": "armv7l"}},
		{"32-bit x86", "ID=debian\nVERSION_CODENAME=bookworm\n", "i686", 1, map[string]any{"architecture": "i386"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cpuinfo := strings.Repeat("processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: x\n\n", c.cpus)
			got, err := Setup(Options{Root: fakeRoot(t, c.osRelease, cpuinfo), Machine: c.machine})
			if err != nil {
				t.Fatal(err)
			}
			for k, want := range c.want {
				if got[k] != want {
					t.Errorf("%s = %#v, want %#v", k, got[k], want)
				}
			}
		})
	}
}

// processor_vcpus as Ansible 2.17 computes it from these exact cpuinfo shapes.
func TestProcessorVCPUsFollowAnsible(t *testing.T) {
	block := func(fields ...string) string { return strings.Join(fields, "\n") + "\n\n" }
	amdVM := strings.Repeat(block("processor\t: 0", "vendor_id\t: AuthenticAMD", "model name\t: AMD Ryzen",
		"physical id\t: 0", "siblings\t: 2", "core id\t\t: 0", "cpu cores\t: 1"), 2)
	hybrid := ""
	for n := 0; n < 20; n++ { // 14 cores, 20 threads: Ansible says 14
		hybrid += block("processor\t: x", "vendor_id\t: GenuineIntel", "model name\t: Core",
			"physical id\t: 0", "siblings\t: 20", "core id\t\t: 1", "cpu cores\t: 14")
	}
	arm := strings.Repeat(block("processor\t: 0", "BogoMIPS\t: 48.00", "CPU implementer\t: 0x41"), 4)
	noTopology := strings.Repeat(block("processor\t: 0", "vendor_id\t: GenuineIntel", "model name\t: Xeon"), 3)
	for _, c := range []struct {
		name, cpuinfo, arch string
		want                int
	}{
		{"hyper-v amd, 2 threads", amdVM, "x86_64", 2},
		{"hybrid intel", hybrid, "x86_64", 14},
		{"arm, 4 processors", arm, "aarch64", 4},
		{"no topology lines", noTopology, "x86_64", 3},
	} {
		path := filepath.Join(t.TempDir(), "cpuinfo")
		if err := os.WriteFile(path, []byte(c.cpuinfo), 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := processorVCPUs(path, c.arch)
		if err != nil || got != c.want {
			t.Errorf("%s: %d, %v; want %d", c.name, got, err, c.want)
		}
	}
}

// With no root the reads are the host's own, wherever the process runs from.
func TestSetupReadsTheHostWithoutARoot(t *testing.T) {
	if _, err := os.Stat("/etc/os-release"); err != nil {
		t.Skip("no /etc/os-release here")
	}
	t.Chdir(t.TempDir())
	got, err := Setup(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got["distribution"] == "" || got["processor_vcpus"].(int64) < 1 {
		t.Fatalf("host facts: %v", got)
	}
}

func TestPackagesListOnlyInstalledOnes(t *testing.T) {
	run := func(name string, args ...string) (string, error) {
		return "ii \thaproxy-awslc\t3.4.1-1~noble\tamd64\n" +
			"rc \told-thing\t1.0\tamd64\n" +
			"ii \tlibc6\t2.39-0ubuntu8\tamd64\n" +
			"ii \tlibc6\t2.39-0ubuntu8\ti386\n" +
			"hi \theld-pkg\t2.0\tall\n", nil
	}
	pkgs, err := Packages(run)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(pkgs.Keys(), []any{"haproxy-awslc", "libc6", "held-pkg"}) {
		t.Fatalf("names: %v", pkgs.Keys())
	}
	first := pkgs.Value("haproxy-awslc").([]any)[0].(*pyyaml.Map)
	if first.Value("version") != "3.4.1-1~noble" {
		t.Fatalf("version: %v", first.Value("version"))
	}
	if n := len(pkgs.Value("libc6").([]any)); n != 2 {
		t.Fatalf("one entry per architecture, got %d", n)
	}
}

func TestServicesJoinUnitsAndUnitFiles(t *testing.T) {
	run := func(name string, args ...string) (string, error) {
		if args[0] == "list-units" {
			return "haproxy.service loaded active running HAProxy\n" +
				"● certbot.service loaded failed failed Certbot\n" +
				"ssh.socket loaded active listening OpenSSH\n", nil
		}
		return "haproxy.service enabled enabled\nfail2ban.service disabled enabled\n", nil
	}
	svc, err := Services(run)
	if err != nil {
		t.Fatal(err)
	}
	check := func(name, state, status string) {
		t.Helper()
		m, ok := svc.Value(name).(*pyyaml.Map)
		if !ok || m.Value("state") != state || m.Value("status") != status {
			t.Fatalf("%s: %#v", name, m)
		}
	}
	check("haproxy.service", "running", "enabled")
	check("certbot.service", "failed", "unknown")
	check("fail2ban.service", "inactive", "disabled")
	if _, ok := svc.Get("ssh.socket"); ok {
		t.Fatal("only service units")
	}
}
