package stages

import (
	"fmt"
	"strings"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/engine"
)

// The package upgrade stage: roles/update_packages/tasks/upgrade.yml (the
// role's main.yml hands it to the agent or includes it), with Docker's
// live_restore.yml and HAProxy's protection.yml it imports.
func init() {
	register(Stage{Name: "update_packages", Parts: []Part{
		{Name: "update_packages/upgrade", Role: "update_packages", File: "upgrade", Build: updatePackages},
	}})
}

// The copy tasks' content:, word for word.
const (
	aptRetries = `Acquire::Retries "5";
Acquire::http::Timeout "30";
Acquire::https::Timeout "30";
Acquire::http::No-Cache "true";
`
	needrestartBrokers = `# Managed by easy-ha-proxy.
$nrconf{override_rc}{qr(^easy-ha-proxy-updated\.service$)} = 0;
$nrconf{override_rc}{qr(^easy-ha-proxy-updated-job-[0-9a-f]{12}\.service$)} = 0;
$nrconf{override_rc}{qr(^easy-ha-proxy-backupd\.service$)} = 0;
`
)

// aptEnv is the apt module's environment for apt-get.
var aptEnv = []string{"DEBIAN_FRONTEND=noninteractive", "DEBIAN_PRIORITY=critical", "LANG=C", "LC_ALL=C", "LC_MESSAGES=C", "LC_CTYPE=C"}

// AptUpgrade is the apt module's upgrade: yes with force_apt_get: apt-get
// upgrade --with-new-pkgs, keeping changed configuration files; a plan asks
// apt-get -s, as check mode does. Nothing to upgrade is "0 upgraded, 0 newly
// installed".
type AptUpgrade struct{}

func (AptUpgrade) Describe() string { return "apt-get upgrade" }

func (AptUpgrade) argv(simulate bool) []string {
	argv := []string{"env"}
	argv = append(argv, aptEnv...)
	argv = append(argv, "apt-get", "-y", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold")
	if simulate {
		argv = append(argv, "-s")
	}
	return append(argv, "upgrade", "--with-new-pkgs")
}

func aptNothing(out string) bool { return strings.Contains(out, "0 upgraded, 0 newly installed") }

func (a AptUpgrade) Check(sys *engine.System) (engine.Change, error) {
	argv := a.argv(true)
	out, code, err := sys.Exec(argv[0], argv[1:]...)
	if err != nil {
		return engine.Change{}, err
	}
	if code != 0 {
		return engine.Change{}, fmt.Errorf("apt-get -s upgrade: exit %d %s", code, strings.TrimSpace(out))
	}
	if aptNothing(out) {
		return engine.Change{}, nil
	}
	return engine.Change{Needed: true, Summary: "packages to upgrade"}, nil
}

func (a AptUpgrade) Apply(sys *engine.System, _ engine.Change) error {
	argv := a.argv(false)
	out, code, err := sys.Exec(argv[0], argv[1:]...)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("apt-get upgrade: exit %d %s", code, strings.TrimSpace(out))
	}
	return nil
}

// shlexSplit is shlex.split for the command lines the tasks template (what
// quote produces: single quotes, double quotes, backslashes outside them).
func shlexSplit(s string) []string {
	var out []string
	var cur strings.Builder
	inWord := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'':
			inWord = true
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				cur.WriteString(s[i+1:])
				i = len(s)
				break
			}
			cur.WriteString(s[i+1 : i+1+j])
			i += j + 1
		case c == '"':
			inWord = true
			for i++; i < len(s) && s[i] != '"'; i++ {
				if s[i] == '\\' && i+1 < len(s) && strings.ContainsRune("\\\"$`\n", rune(s[i+1])) {
					i++
				}
				cur.WriteByte(s[i])
			}
		case c == '\\' && i+1 < len(s):
			inWord = true
			i++
			cur.WriteByte(s[i])
		case c == ' ' || c == '\t' || c == '\n':
			if inWord {
				out = append(out, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			inWord = true
			cur.WriteByte(c)
		}
	}
	if inWord {
		out = append(out, cur.String())
	}
	return out
}

func updatePackages(b *Builder) []engine.Step {
	needrestart := func(*engine.Run) bool { return b.Exists("/usr/sbin/needrestart", false) }
	revision := b.S("{{ easy_ha_proxy_maintenance_revision | default('') }}")
	runtimeRevision := b.S("{{ easy_ha_proxy_runtime_maintenance_revision | default('') }}")
	agent := b.S("{{ native_agent_bin | default('/usr/local/sbin/easy-ha-proxy-agent') }}")
	guard := b.S(`{{ '--automatic' if easy_ha_proxy_automatic_os_upgrade | default(false) | bool else '' }}
      --state-root {{ ((updated_state_root | default('/var/lib/easy-ha-proxy/update-web')) ~ '/os-security') | quote }}
      {{ ('--runtime-maintenance ' ~ (easy_ha_proxy_runtime_maintenance_revision | quote) ~ ' --maintenance-until ' ~ (easy_ha_proxy_runtime_maintenance_until | string | quote))
         if easy_ha_proxy_runtime_maintenance_revision | default('') | length > 0 else
         ('--maintenance-revision ' ~ (easy_ha_proxy_maintenance_revision | quote) ~ ' --maintenance-until ' ~ (easy_ha_proxy_runtime_maintenance_until | string | quote))
         if easy_ha_proxy_maintenance_revision | default('') | length > 0 else '' }}`)
	timesyncd := &engine.Command{Argv: []string{"systemctl", "show", "systemd-timesyncd.service", "--property=LoadState", "--value"}, IgnoreErrors: true}
	reboot := func(*engine.Run) bool { return b.Exists("/var/run/reboot-required", false) }
	wanted := b.Bool("{{ easy_ha_proxy_reboot_after_upgrade | default(false) | bool }}")
	local := b.S("{{ ansible_connection | default('smart') }}") == "local"

	steps := []engine.Step{
		{Name: "Configure APT retries and timeouts", Build: b.CopyContent(aptRetries, "/etc/apt/apt.conf.d/80-retries", "root", "root", "0644")},
		{Name: "Ensure the needrestart drop-in directory exists", When: needrestart, Resource: b.Dir("/etc/needrestart/conf.d", "root", "root", "0755")},
		{Name: "Keep needrestart from stopping active maintenance brokers", When: needrestart,
			Build: b.CopyContent(needrestartBrokers, "/etc/needrestart/conf.d/easy-ha-proxy.conf", "root", "root", "0644")},
	}
	steps = append(steps, dockerLiveRestore(b)...)
	steps = append(steps, haproxyProtection(b)...)
	return append(steps,
		engine.Step{Name: "Refresh APT metadata before reviewing the package upgrade", Resource: &engine.AptCache{ValidTime: 0}},
		engine.Step{Name: "Verify package upgrade safety and record the installation attempt",
			When: func(r *engine.Run) bool { return r.Mode == engine.Apply },
			Build: func(*engine.Run) (engine.Resource, error) {
				return &engine.Command{Argv: append([]string{agent, "os-upgrade-guard"}, shlexSplit(guard)...), Changes: true}, nil
			}},
		engine.Step{Name: "Update and upgrade apt packages", When: func(*engine.Run) bool { return revision == "" && runtimeRevision == "" },
			Resource: AptUpgrade{}},
		engine.Step{Name: "Read the systemd-timesyncd unit load state", Resource: timesyncd},
		engine.Step{Name: "Ensure systemd-timesyncd stays enabled and running after the upgrade",
			When:     func(*engine.Run) bool { return strings.TrimSpace(timesyncd.Output) == "loaded" },
			Resource: Unit("systemd-timesyncd.service", engine.Bool(true), "started")},
		engine.Step{Name: "Report the required reboot", When: reboot,
			Resource: report("The system requires a reboot. The easy-ha-proxy assistant will ask whether to schedule it after the installer finishes. " +
				"When running the agent directly, reboot the server manually.")},
		engine.Step{Name: "Reboot an SSH-managed target when explicitly requested",
			When: func(r *engine.Run) bool { return reboot(r) && wanted && !local },
			Build: func(*engine.Run) (engine.Resource, error) {
				return nil, fmt.Errorf("the Go installer runs on the gateway itself and cannot reboot it and wait for it like an SSH-managed target; reboot it from the assistant")
			}},
		engine.Step{Name: "Explain why the gateway is not rebooted from here", When: func(r *engine.Run) bool { return reboot(r) && wanted && local },
			Resource: report("Automatic reboot was deferred: the installer runs on the gateway itself. Use the easy-ha-proxy assistant prompt or reboot manually.")},
	)
}
