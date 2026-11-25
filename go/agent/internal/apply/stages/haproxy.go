package stages

import (
	"fmt"

	"easy-ha-proxy/panel/shared/pyyaml"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/engine"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/facts"
)

// The HAProxy stage: roles/haproxy's task files, as "haproxy/<file>": the
// package protection the first play runs before anything else, the install
// stage (package, directories, bootstrap, pages) and AppArmor. config.yml
// follows. Their handlers (apply haproxy, the AppArmor chain) are handed back
// to Ansible during the hybrid period.
func init() {
	register(Stage{Name: "haproxy", Parts: []Part{
		{Name: "haproxy/protection", Role: "haproxy", File: "protection", PreTask: true, Build: haproxyProtection},
		{Name: "haproxy/install", Role: "haproxy", File: "install", Build: haproxyInstall},
		{Name: "haproxy/apparmor", Role: "haproxy", File: "apparmor", Build: haproxyAppArmor},
	}})
}

// execRunner adapts the System's Exec to the facts package's Runner.
func execRunner(sys *engine.System) facts.Runner {
	return func(name string, args ...string) (string, error) {
		out, code, err := sys.Exec(name, args...)
		if err == nil && code != 0 {
			err = fmt.Errorf("%s: exit %d", name, code)
		}
		return out, err
	}
}

// needrestartHaproxy is the copy task's content:, word for word.
const needrestartHaproxy = `# Managed by easy-ha-proxy. The update page detects replaced libraries.
$nrconf{override_rc}{qr(^haproxy\.service$)} = 0;
`

func haproxyProtection(b *Builder) []engine.Step {
	debian := b.S("{{ ansible_os_family }}") == "Debian"
	var packages *pyyaml.Map
	installed := func(name string) bool {
		if packages == nil {
			return false
		}
		_, ok := packages.Get(name)
		return ok
	}
	core := func(*engine.Run) bool { return debian && (installed("haproxy") || installed("haproxy-awslc")) }
	return []engine.Step{
		{Name: "HAProxy updates | read actual installed packages", When: func(*engine.Run) bool { return debian },
			Resource: &engine.Func{Desc: "package_facts", CheckFn: func(sys *engine.System) (engine.Change, error) {
				p, err := facts.Packages(execRunner(sys))
				packages = p
				return engine.Change{Summary: "read"}, err
			}}},
		{Name: "HAProxy updates | hold core packages outside explicit updates", When: func(*engine.Run) bool { return debian },
			Build: func(*engine.Run) (engine.Resource, error) {
				loop := &engine.Multi{Desc: "dpkg holds"}
				for _, name := range []string{"haproxy", "haproxy-awslc", "libssl-awslc"} {
					if installed(name) {
						loop.Items = append(loop.Items, &engine.Hold{Name: name})
					}
				}
				return loop, nil
			}},
		{Name: "HAProxy updates | create needrestart configuration directory", When: core,
			Resource: b.Dir("/etc/needrestart/conf.d", "root", "root", "0755")},
		{Name: "HAProxy updates | defer core restart to the controlled update", When: core,
			Build: b.CopyContent(needrestartHaproxy, "/etc/needrestart/conf.d/easy-ha-proxy-haproxy.conf", "root", "root", "0644")},
	}
}

func haproxyFS(b *Builder) []engine.Step {
	steps := []engine.Step{}
	for _, d := range []struct{ path, owner, group string }{
		{"/etc/haproxy", "root", "root"},
		{"/var/lib/haproxy", "root", "root"},
		{"/var/log/haproxy", "syslog", "adm"},
	} {
		steps = append(steps, engine.Step{Name: "Ensure HAProxy base dirs exist", Resource: b.Dir(d.path, d.owner, d.group, "0755")})
	}
	return append(steps,
		engine.Step{Name: "Ensure HAProxy errors directory exists", Resource: b.Dir("/etc/haproxy/errors", "root", "root", "0755")},
		engine.Step{Name: "Ensure HAProxy certs directory exists", Resource: b.Dir("{{ haproxy_certs_dir }}", "root", "root", "0755")},
		engine.Step{Name: "Ensure the client authentication directory exists", Resource: b.Dir("{{ haproxy_mtls_dir }}", "root", "root", "0755")},
	)
}
