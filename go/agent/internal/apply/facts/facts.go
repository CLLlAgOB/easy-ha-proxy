// Package facts gathers, once per run, the host facts the roles read: what
// Ansible's setup module gives them (ansible_os_family, ansible_distribution,
// ansible_distribution_release, ansible_architecture, ansible_processor_vcpus)
// and, for the stages that ask, package_facts and service_facts.
//
// Values follow Ansible's spelling so templates read them unchanged: names
// without the ansible_ prefix, ints as int64, lists as []any, dicts as
// *pyyaml.Map.
package facts

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"easy-ha-proxy/panel/shared/pyyaml"
)

// Options lets tests point the reads at a fake root.
type Options struct {
	Root    string // prefix for /etc/os-release and /proc/cpuinfo; "" is /
	Machine string // uname -m; "" asks the kernel
}

// Runner runs a command and returns its standard output.
type Runner func(name string, args ...string) (string, error)

// Exec is the Runner the installer uses on a host.
func Exec(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).Output()
	return string(out), err
}

// debianFamily is the Debian part of Ansible's OS_FAMILY_MAP.
var debianFamily = map[string]bool{
	"Debian": true, "Ubuntu": true, "Raspbian": true, "Neon": true, "KDE neon": true, "Linux Mint": true,
	"SteamOS": true, "Devuan": true, "Kali": true, "Cumulus Linux": true, "Pop!_OS": true,
	"Parrot": true, "Pardus GNU/Linux": true, "Uos": true, "Deepin": true, "OSMC": true,
}

// distributionNames are the os-release IDs Ansible does not merely capitalise.
var distributionNames = map[string]string{
	"linuxmint": "Linux Mint", "pop": "Pop!_OS", "neon": "KDE neon", "raspbian": "Raspbian",
	"debian": "Debian", "ubuntu": "Ubuntu", "devuan": "Devuan", "kali": "Kali", "osmc": "OSMC",
}

var codenameInPretty = regexp.MustCompile(`\(([^)]+)\)`)

// Setup is the part of Ansible's setup module the roles read.
func Setup(opts Options) (map[string]any, error) {
	if opts.Root == "" {
		opts.Root = "/"
	}
	osRelease, err := readOSRelease(filepath.Join(opts.Root, "etc", "os-release"))
	if err != nil {
		return nil, err
	}
	id := strings.ToLower(osRelease["ID"])
	distribution := distributionNames[id]
	if distribution == "" {
		distribution = capitalize(id)
	}
	// OS_FAMILY.get(distribution) or distribution: ID_LIKE plays no part.
	family := distribution
	if debianFamily[distribution] {
		family = "Debian"
	}
	release := osRelease["VERSION_CODENAME"]
	if release == "" {
		release = osRelease["UBUNTU_CODENAME"]
	}
	if release == "" {
		if m := codenameInPretty.FindStringSubmatch(osRelease["PRETTY_NAME"]); m != nil {
			release = m[1]
		}
	}
	version := osRelease["VERSION_ID"]
	major, _, _ := strings.Cut(version, ".")

	machine := opts.Machine
	if machine == "" {
		var u unix.Utsname
		if err := unix.Uname(&u); err != nil {
			return nil, fmt.Errorf("uname: %w", err)
		}
		machine = unix.ByteSliceToString(u.Machine[:])
	}
	vcpus, err := processorVCPUs(filepath.Join(opts.Root, "proc", "cpuinfo"), architecture(machine))
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"system":                     "Linux",
		"os_family":                  family,
		"distribution":               distribution,
		"distribution_release":       release,
		"distribution_version":       version,
		"distribution_major_version": major,
		"architecture":               architecture(machine),
		"machine":                    machine,
		"processor_vcpus":            int64(vcpus),
	}, nil
}

// architecture is Ansible's: x86_64 stays, i?86 is i386, the rest is uname -m.
func architecture(machine string) string {
	if len(machine) == 4 && machine[0] == 'i' && strings.HasSuffix(machine, "86") {
		return "i386"
	}
	return machine
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func readOSRelease(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.HasPrefix(line, "#") {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		out[strings.TrimSpace(k)] = v
	}
	return out, sc.Err()
}

// processorVCPUs is LinuxHardware.get_cpu_facts' processor_vcpus, quirks
// kept: threads per core x sockets x cores per socket, read from the first
// socket and core seen, where "siblings" lands on the previous core id and a
// core id equal to a socket id is never recorded. Xen paravirt and s390x,
// which no gateway runs on, are left out.
func processorVCPUs(path, arch string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return runtime.NumCPU(), nil
		}
		return 0, err
	}
	i, vendor, model, proc := 0, 0, 0, 0
	// Python dicts keyed by the initial int 0 or by the strings read.
	physid, coreid := "int:0", "int:0"
	var sockets, cores orderedCounts
	for _, line := range strings.Split(string(raw), "\n") {
		k, v, _ := strings.Cut(line, ":")
		key, val := strings.TrimSpace(k), strings.TrimSpace(v)
		switch key {
		case "model name", "Processor", "vendor_id", "cpu", "Vendor", "processor":
			switch key {
			case "vendor_id":
				vendor++
			case "model name":
				model++
			case "processor":
				proc++
			}
			i++
		case "physical id":
			physid = "str:" + val
			if !sockets.has(physid) {
				sockets.set(physid, 1)
			}
		case "core id":
			coreid = "str:" + val
			if !sockets.has(coreid) {
				cores.set(coreid, 1)
			}
		case "cpu cores":
			sockets.set(physid, atoi(val))
		case "siblings":
			cores.set(coreid, atoi(val))
		}
	}
	if vendor > 0 && vendor == model {
		i = vendor
	}
	if strings.HasPrefix(arch, "armv") || strings.HasPrefix(arch, "aarch") || strings.HasPrefix(arch, "ppc") {
		i = proc
	}
	count := i
	if len(sockets.keys) > 0 {
		count = len(sockets.keys)
	}
	perSocket := 1
	if len(sockets.keys) > 0 && sockets.first() != 0 {
		perSocket = sockets.first()
	}
	threads := int(math.RoundToEven(1 / float64(perSocket)))
	if len(cores.keys) > 0 {
		threads = int(math.RoundToEven(float64(cores.first()) / float64(perSocket)))
	}
	return threads * count * perSocket, nil
}

type orderedCounts struct {
	keys []string
	vals map[string]int
}

func (o *orderedCounts) has(k string) bool { _, ok := o.vals[k]; return ok }

func (o *orderedCounts) set(k string, v int) {
	if o.vals == nil {
		o.vals = map[string]int{}
	}
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
}

func (o *orderedCounts) first() int { return o.vals[o.keys[0]] }

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// Packages is package_facts for apt: installed package name -> a list of
// {name, version, arch, source}, one entry per installed architecture.
func Packages(run Runner) (*pyyaml.Map, error) {
	out, err := run("dpkg-query", "-W", "-f", "${db:Status-Abbrev}\t${Package}\t${Version}\t${Architecture}\n")
	if err != nil {
		return nil, fmt.Errorf("dpkg-query: %w", err)
	}
	pkgs := pyyaml.NewMap()
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) != 4 || len(fields[0]) < 2 || fields[0][1] != 'i' {
			continue // not installed (removed, config files only, half-installed)
		}
		name := fields[1]
		entry := pyyaml.NewMap()
		entry.Set("name", name)
		entry.Set("version", fields[2])
		entry.Set("arch", fields[3])
		entry.Set("source", "apt")
		list, _ := pkgs.Value(name).([]any)
		pkgs.Set(name, append(list, entry))
	}
	return pkgs, nil
}

// Services is service_facts for systemd: every service unit systemd knows,
// loaded or only installed, -> {name, state, status, source}.
func Services(run Runner) (*pyyaml.Map, error) {
	units, err := run("systemctl", "list-units", "--no-pager", "--type", "service", "--all", "--plain", "--no-legend")
	if err != nil {
		return nil, fmt.Errorf("systemctl list-units: %w", err)
	}
	files, err := run("systemctl", "list-unit-files", "--no-pager", "--type", "service", "--all", "--plain", "--no-legend")
	if err != nil {
		return nil, fmt.Errorf("systemctl list-unit-files: %w", err)
	}
	services := pyyaml.NewMap()
	entry := func(name string) *pyyaml.Map {
		if m, ok := services.Value(name).(*pyyaml.Map); ok {
			return m
		}
		m := pyyaml.NewMap()
		m.Set("name", name)
		m.Set("state", "inactive")
		m.Set("status", "unknown")
		m.Set("source", "systemd")
		services.Set(name, m)
		return m
	}
	for _, line := range strings.Split(units, "\n") {
		f := strings.Fields(strings.TrimPrefix(strings.TrimSpace(line), "●"))
		if len(f) < 4 || !strings.HasSuffix(f[0], ".service") {
			continue
		}
		state := "stopped"
		switch f[3] { // SUB
		case "running":
			state = "running"
		case "failed":
			state = "failed"
		}
		entry(f[0]).Set("state", state)
	}
	for _, line := range strings.Split(files, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || !strings.HasSuffix(f[0], ".service") {
			continue
		}
		entry(f[0]).Set("status", f[1])
	}
	return services, nil
}
