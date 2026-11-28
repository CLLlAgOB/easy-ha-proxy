package stages

import (
	"errors"
	"fmt"
	"os"
	"os/user"

	"easy-ha-proxy/panel/shared/pyyaml"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/engine"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/facts"
)

// The HAProxy stage: roles/haproxy's task files, as "haproxy/<file>": the
// package protection the first play runs before anything else, the install
// stage (package, directories, bootstrap, pages), AppArmor, and config.yml
// (haproxy.cfg and what it reads). Their handlers (validate and apply haproxy,
// the AppArmor chain) are handed back to Ansible during the hybrid period,
// with the two results the apply handler reads to choose restart or reload.
func init() {
	register(Stage{Name: "haproxy", Parts: []Part{
		{Name: "haproxy/protection", Role: "haproxy", File: "protection", PreTask: true, Build: haproxyProtection},
		{Name: "haproxy/install", Role: "haproxy", File: "install", Build: haproxyInstall},
		// No playbook entry runs it alone: the HAProxy 3.4 package workflow
		// does, on disposable runners (haproxy/install includes it).
		{Name: "haproxy/package", Role: "haproxy", File: "package", Build: haproxyPackage},
		{Name: "haproxy/apparmor", Role: "haproxy", File: "apparmor", Build: haproxyAppArmor},
		{Name: "haproxy/config", Role: "haproxy", File: "config", Build: haproxyConfig,
			Exports: []string{"haproxy_runtime_environment", "haproxy_secret_dropin"}},
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
	} {
		steps = append(steps, engine.Step{Name: "Ensure HAProxy base dirs exist", Resource: b.Dir(d.path, d.owner, d.group, "0755")})
	}
	// Ubuntu's rsyslog drops privileges to syslog. Debian's service uses root
	// and its package does not require a syslog account.
	logOwner := func(r *engine.Run) (string, error) {
		_, err := r.Sys.LookupUser("syslog")
		var missing user.UnknownUserError
		if errors.As(err, &missing) {
			return "root", nil
		}
		return "syslog", err
	}
	steps = append(steps, engine.Step{Name: "Ensure HAProxy base dirs exist", Build: func(r *engine.Run) (engine.Resource, error) {
		owner, err := logOwner(r)
		return b.Dir("/var/log/haproxy", owner, "adm", "0755"), err
	}})
	// On images where /var/log is root-owned 0755, rsyslog cannot create the
	// access log itself, and the panel compose bind mount of the missing file
	// creates a directory in its place, leaving guardd and the Log Explorer
	// without their source. Prepare the log with adm group access before
	// anything mounts it. Replace an empty directory and refuse a filled one.
	const logPath = "/var/log/haproxy.log"
	steps = append(steps,
		engine.Step{Name: "Replace an empty directory at the HAProxy access log path",
			Resource: &engine.Func{Desc: "empty directory " + logPath,
				CheckFn: func(sys *engine.System) (engine.Change, error) {
					fi, err := os.Lstat(sys.Path(logPath))
					if errors.Is(err, os.ErrNotExist) || (err == nil && !fi.IsDir()) {
						return engine.Change{}, nil
					}
					if err != nil {
						return engine.Change{}, err
					}
					entries, err := os.ReadDir(sys.Path(logPath))
					if err != nil {
						return engine.Change{}, err
					}
					if len(entries) > 0 {
						return engine.Change{}, fmt.Errorf("%s is a directory with contents; empty it by hand before the access log can be restored", logPath)
					}
					return engine.Change{Needed: true, Summary: "replace the empty directory with a file"}, nil
				},
				ApplyFn: func(sys *engine.System) error { return os.Remove(sys.Path(logPath)) }}},
		engine.Step{Name: "Ensure the HAProxy access log exists for rsyslog and the panel",
			Build: func(r *engine.Run) (engine.Resource, error) {
				owner, err := logOwner(r)
				return &engine.Touch{Path: logPath, Owner: owner, Group: "adm", Mode: 0o640, Preserve: true}, err
			}},
	)
	return append(steps,
		engine.Step{Name: "Ensure HAProxy errors directory exists", Resource: b.Dir("/etc/haproxy/errors", "root", "root", "0755")},
		engine.Step{Name: "Ensure HAProxy certs directory exists", Resource: b.Dir("{{ haproxy_certs_dir }}", "root", "root", "0755")},
		engine.Step{Name: "Ensure the client authentication directory exists", Resource: b.Dir("{{ haproxy_mtls_dir }}", "root", "root", "0755")},
	)
}
