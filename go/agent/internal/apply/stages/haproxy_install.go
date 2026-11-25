package stages

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"easy-ha-proxy/panel/shared/pyyaml"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/engine"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/facts"
)

// The handlers roles/haproxy's tasks notify. During the hybrid period the
// agent hands them back to Ansible, which runs them at the end of the play.
const (
	applyHaproxy    = "apply haproxy"
	apparmorRsyslog = "apparmor rsyslogd reload"
)

// assertStep is an assert task: the step fails with msg unless ok() holds.
func assertStep(name string, ok func(*engine.Run) bool, msg string) engine.Step {
	return engine.Step{Name: name, Build: func(r *engine.Run) (engine.Resource, error) {
		if !ok(r) {
			return nil, fmt.Errorf("%s", msg)
		}
		return nil, nil
	}}
}

// withTags adds tags to steps, as an import_tasks with tags does.
func withTags(steps []engine.Step, tags ...string) []engine.Step {
	for i := range steps {
		steps[i].Tags = append(append([]string{}, steps[i].Tags...), tags...)
	}
	return steps
}

// apparmorRsyslogd is the copy task's content:, word for word.
const apparmorRsyslogd = `# Managed by Ansible (ansible-haproxy-flex)
# allow rsyslog to work with HAProxy chroot socket
{{ haproxy_chroot }}/ r,
{{ haproxy_chroot }}/dev/ rwk,
{{ haproxy_chroot }}/dev/log rwk,
`

func haproxyAppArmor(b *Builder) []engine.Step {
	enabled := b.Bool("{{ haproxy_enable_rsyslog_apparmor | bool }}")
	on := func(*engine.Run) bool { return enabled }
	flag := "/sys/module/apparmor/parameters/enabled"
	status := &engine.Command{Argv: []string{"cat", flag}, Probe: true}
	statusRan := false
	return []engine.Step{
		{Name: "AppArmor | install rsyslog profile dependencies", When: on, Tags: restoreNetwork,
			Resource: &engine.Packages{Names: []string{"apparmor", "apparmor-utils", "rsyslog"}}},
		{Name: "AppArmor | ensure local override dir exists", When: on, Resource: b.Dir("/etc/apparmor.d/local", "root", "root", "0755")},
		{Name: "AppArmor | deploy local rules for rsyslogd (HAProxy chroot socket)", When: on, Notify: []string{apparmorRsyslog},
			Build: b.CopyContent(apparmorRsyslogd, "/etc/apparmor.d/local/usr.sbin.rsyslogd", "root", "root", "0644")},
		{Name: "AppArmor | debug status",
			When: func(*engine.Run) bool { statusRan = enabled && b.Exists(flag, false); return statusRan }, Resource: status},
		{Name: "AppArmor | warn if not enforcing/complain", When: func(*engine.Run) bool { return statusRan },
			Build: func(*engine.Run) (engine.Resource, error) {
				state := strings.ToLower(strings.TrimSpace(status.Output))
				switch state {
				case "y", "yes", "enforcing", "complain", "enforce":
					return nil, nil
				}
				return &engine.Func{Desc: "report", CheckFn: func(*engine.System) (engine.Change, error) {
					return engine.Change{Summary: "AppArmor seems disabled (" + state + "). Local rsyslogd override was still installed."}, nil
				}}, nil
			}},
	}
}

// haproxyPin is the copy task's content:, word for word.
const haproxyPin = `# Only the explicitly selected HAProxy branch may be installed.
Package: haproxy-awslc
Pin: version {{ haproxy_package_branch }}.*
Pin-Priority: 990

Package: haproxy-awslc
Pin: version *
Pin-Priority: -1

# A distribution update must not replace this provider implicitly.
Package: haproxy
Pin: version *
Pin-Priority: -1

# Do not let this extra repository replace unrelated system packages.
Package: *
Pin: origin "www.haproxy.com"
Pin-Priority: 100
`

var haproxyVersion34 = regexp.MustCompile(`HAProxy version 3[.]4[.]`)

// aptValid is the play's module_defaults cache_valid_time for apt tasks.
func (b *Builder) aptValid() time.Duration {
	n, err := strconv.Atoi(b.S("{{ easy_ha_proxy_apt_cache_valid_time | default(3600) }}"))
	if err != nil {
		b.fail(err)
	}
	return time.Duration(n) * time.Second
}

// haproxyPackage transcribes package.yml, protection.yml (which it imports
// at its end) included.
func haproxyPackage(b *Builder) []engine.Step {
	provider := b.S("{{ haproxy_package_provider }}")
	branch := b.S("{{ haproxy_package_branch }}")
	valid := b.aptValid()
	var packages *pyyaml.Map
	installed := func(name string) bool {
		if packages == nil {
			return false
		}
		_, ok := packages.Get(name)
		return ok
	}
	version := func(name string) string {
		if list, ok := packages.Value(name).([]any); ok && len(list) > 0 {
			v, _ := list[0].(*pyyaml.Map).Value("version").(string)
			return v
		}
		return ""
	}
	tech := func(*engine.Run) bool { return provider == "haproxy-technologies" }
	arch := b.S("{{ ansible_architecture }}")
	repoArch := "amd64"
	if arch == "aarch64" {
		repoArch = "arm64"
	}
	steps := []engine.Step{
		assertStep("HAProxy package | Validate the provider",
			func(*engine.Run) bool { return provider == "distribution" || provider == "haproxy-technologies" },
			"Unknown HAProxy package provider; choose distribution or haproxy-technologies."),
		{Name: "HAProxy package | Read installed packages", Resource: &engine.Func{Desc: "package_facts",
			CheckFn: func(sys *engine.System) (engine.Change, error) {
				p, err := facts.Packages(execRunner(sys))
				packages = p
				return engine.Change{Summary: "read"}, err
			}}},
		assertStep("HAProxy package | Require a separate provider migration", func(*engine.Run) bool {
			return (provider != "distribution" || !installed("haproxy-awslc")) &&
				(provider != "haproxy-technologies" || !installed("haproxy"))
		}, "Refusing to replace an installed HAProxy package with a different provider. Follow docs/haproxy-3.4-migration.md, "+
			"including package/configuration backup and rollback qualification. An ordinary install or update must not migrate it."),
		{Name: "HAProxy package | Install the distribution package", When: func(*engine.Run) bool { return provider == "distribution" },
			Resource: &engine.AptInstall{Names: []string{"haproxy"}, UpdateCache: true, CacheValid: valid}},
	}
	block := []engine.Step{
		assertStep("HAProxy package | Validate the platform before changing APT", func(*engine.Run) bool {
			return b.S("{{ ansible_distribution }}") == "Ubuntu" && b.S("{{ ansible_distribution_release }}") == "noble" &&
				(arch == "aarch64" || arch == "x86_64") && branch == "3.4" &&
				(!installed("haproxy-awslc") || strings.HasPrefix(version("haproxy-awslc"), "3.4."))
		}, "The HAProxy Technologies provider is qualified for Ubuntu 24.04 noble, ARM64 and AMD64, branch 3.4 only. "+
			"Other platforms keep the distribution provider until they are explicitly qualified. An installed package from "+
			"another branch must use a separate migration procedure."),
		{Name: "HAProxy package | Install repository prerequisites",
			Resource: &engine.AptInstall{Names: []string{"ca-certificates"}, UpdateCache: true, CacheValid: valid}},
		{Name: "HAProxy package | Create the dedicated key directory", Resource: b.Dir("/usr/share/keyrings", "root", "root", "0755")},
		{Name: "HAProxy package | Install the pinned community signing key", Register: "haproxy_package_key",
			Resource: &engine.GetURL{URL: "https://pks.haproxy.com/linux/community/RPM-GPG-KEY-HAProxy",
				Dest: "/usr/share/keyrings/easy-ha-proxy-haproxy-community.asc", SHA256: b.S("{{ haproxy_community_key_sha256 }}"),
				Owner: "root", Group: "root", Mode: 0o644}},
		{Name: "HAProxy package | Keep package updates within the selected branch", Register: "haproxy_package_pin",
			Build: b.CopyContent(haproxyPin, "/etc/apt/preferences.d/easy-ha-proxy-haproxy", "root", "root", "0644")},
		{Name: "HAProxy package | Add the architecture-specific signed repository", Register: "haproxy_package_repository",
			Resource: &engine.AptRepository{File: "easy-ha-proxy-haproxy", Mode: 0o644,
				Line: "deb [arch=" + repoArch + " signed-by=/usr/share/keyrings/easy-ha-proxy-haproxy-community.asc] " +
					"https://www.haproxy.com/download/haproxy/performance/ubuntu/ha34 noble main"}},
		{Name: "HAProxy package | Refresh APT after repository changes",
			When:     Changed("haproxy_package_key", "haproxy_package_pin", "haproxy_package_repository"),
			Resource: &engine.AptCache{ValidTime: 0}},
		{Name: "HAProxy package | Install the selected 3.4 package without starting services",
			When: func(*engine.Run) bool { return !installed("haproxy-awslc") },
			Resource: &engine.AptInstall{Names: []string{"haproxy-awslc=" + branch + ".*"}, PolicyRcD: 101,
				UpdateCache: true, CacheValid: time.Hour}},
		{Name: "HAProxy package | Verify the installed binary", When: func(r *engine.Run) bool { return r.Mode == engine.Apply },
			Resource: &engine.Func{Desc: "haproxy -v", CheckFn: func(sys *engine.System) (engine.Change, error) {
				out, code, err := sys.Exec("/usr/sbin/haproxy", "-v")
				if err != nil {
					return engine.Change{}, err
				}
				if code != 0 || !haproxyVersion34.MatchString(out) {
					return engine.Change{}, fmt.Errorf("haproxy -v: exit %d, not HAProxy 3.4", code)
				}
				return engine.Change{Summary: "3.4"}, nil
			}}},
	}
	for i := range block {
		block[i].When = andWhen(tech, block[i].When)
	}
	steps = append(steps, block...)
	return append(steps, haproxyProtection(b)...)
}

// andWhen joins a block's condition with a task's own.
func andWhen(outer, inner func(*engine.Run) bool) func(*engine.Run) bool {
	if inner == nil {
		return outer
	}
	return func(r *engine.Run) bool { return outer(r) && inner(r) }
}

// adminIPs is the copy task's content:, word for word.
const adminIPs = `{% for ip in admin_allowed_ips %}
{{ ip }}
{% endfor %}
`

// haproxyInstall transcribes install.yml, with the package (package.yml,
// protection.yml) and the directories (fs.yml) it imports.
func haproxyInstall(b *Builder) []engine.Step {
	marker := "/var/lib/haproxy/.first_start_done"
	fresh := func(*engine.Run) bool { return !b.Exists(marker, false) }
	bootstrapFailed := false
	dyn := b.Bool("{{ admin_dyn_enabled | default(false) }}")
	onDyn := func(*engine.Run) bool { return dyn }
	install := []string{"install"}

	steps := []engine.Step{
		{Name: "Ensure HAProxy runtime socket group exists before package installation",
			Resource: &engine.Group{Name: b.S("{{ haproxy_socket_group }}"), System: true}},
	}
	steps = append(steps, withTags(haproxyPackage(b), "install", "restore-network")...)
	steps = append(steps, haproxyFS(b)...)
	steps = append(steps, engine.Step{Name: "Validate HAProxy config if present", Tags: install,
		Resource: &engine.Command{Argv: []string{"haproxy", "-c", "-f", "/etc/haproxy/haproxy.cfg"}, IgnoreErrors: true}})
	boot := []engine.Step{
		{Name: "Start HAProxy (bootstrap)", When: fresh,
			Resource: &engine.Rescued{Inner: Unit("haproxy", nil, "started"), Failed: &bootstrapFailed, Note: "HAProxy bootstrap failed; not marking initialized."}},
		{Name: "Stop HAProxy (bootstrap)", When: func(r *engine.Run) bool { return fresh(r) && !bootstrapFailed },
			Resource: &engine.Rescued{Inner: Unit("haproxy", nil, "stopped"), Failed: &bootstrapFailed, Note: "HAProxy bootstrap failed; not marking initialized."}},
		{Name: "Mark HAProxy initialized", When: func(r *engine.Run) bool { return fresh(r) && !bootstrapFailed },
			Resource: &engine.Touch{Path: marker, Owner: "root", Group: "root", Mode: 0o644}},
	}
	steps = append(steps, withTags(boot, "install")...)
	rest := []engine.Step{
		{Name: "Deploy maintenance error page", Notify: []string{applyHaproxy},
			Build: b.Template("maintenance.http.j2", "/etc/haproxy/errors/maintenance.http", "root", "root", "0644")},
		{Name: "Deploy access granted page", Notify: []string{applyHaproxy},
			Build: b.Template("access_granted.http.j2", "/etc/haproxy/errors/access_granted.http", "root", "root", "0644")},
		{Name: "Deploy the first-step ban page", Notify: []string{applyHaproxy},
			Build: b.Template("ban_first_step.html.j2", "/etc/haproxy/errors/ban-first-step.html", "root", "root", "0644")},
		{Name: "Deploy the default favicon", Notify: []string{applyHaproxy},
			Build: b.CopyFile("default-favicon.ico", "/etc/haproxy/errors/default-favicon.ico", "root", "root", "0644")},
		{Name: "Ensure admin IPs file exists with static admin_allowed_ips",
			Build: b.CopyContent(adminIPs, "{{ admin_ips_file }}", "root", "haproxy", "0640")},
		{Name: "Ensure socat is present (for runtime socket ops)", When: onDyn, Tags: restoreNetwork,
			Resource: &engine.Packages{Names: []string{"socat"}}},
		{Name: "Install runtime update script (no reload)", When: onDyn,
			Build: b.Template("update-admin-rt.sh.j2", "/usr/local/sbin/update-admin-rt.sh", "root", "root", "0755")},
		{Name: "Install systemd service", When: onDyn,
			Build: b.Template("update-admin-rt.service.j2", "/etc/systemd/system/update-admin-rt.service", "", "", "0644")},
		{Name: "Install systemd timer", When: onDyn,
			Build: b.Template("update-admin-rt.timer.j2", "/etc/systemd/system/update-admin-rt.timer", "", "", "0644")},
		{Name: "systemd daemon-reload", When: onDyn, Resource: engine.DaemonReload{}},
		{Name: "Enable & start timer", When: onDyn, Resource: Unit("update-admin-rt.timer", engine.Bool(true), "started")},
		{Name: "Run once now to populate runtime ACL", When: onDyn,
			Resource: &engine.Command{Argv: []string{"/usr/local/sbin/update-admin-rt.sh"}, IgnoreErrors: true}},
	}
	return append(steps, withTags(rest, "install")...)
}
