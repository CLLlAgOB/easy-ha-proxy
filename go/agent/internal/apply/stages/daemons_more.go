package stages

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/engine"
)

// restoreNetwork is the tag an offline restore skips: package installs.
var restoreNetwork = []string{"restore-network"}

func updated(b *Builder) []engine.Step {
	unit := "easy-ha-proxy-updated.service"
	group := "{{ app_group }}"
	marker := b.S("{{ updated_active_marker }}")
	updating := func(*engine.Run) bool { return b.Exists(marker, true) }
	restartFor := Changed("updated_unit", "_native_agent_copy", "daemons_env_t")
	return []engine.Step{
		{Name: "easy-ha-proxy-updated | Ensure persistent job directories", Resource: b.Dir("{{ updated_state_root }}", "root", group, "0750")},
		{Name: "easy-ha-proxy-updated | Ensure persistent job directories", Resource: b.Dir("{{ updated_jobs_dir }}", "root", group, "0750")},
		{Name: "easy-ha-proxy-updated | Install systemd unit", Register: "updated_unit",
			Build: b.Template("easy-ha-proxy-updated.service.j2", "/etc/systemd/system/"+unit, "root", "root", "0644")},
		{Name: "easy-ha-proxy-updated | Reload systemd when unit changed", When: Changed("updated_unit"), Resource: engine.DaemonReload{}},
		// set_fact updated_binary_changed: the conditions below read the
		// native stage's _native_agent_copy directly.
		{Name: "easy-ha-proxy-updated | Note a replaced native agent binary"},
		{Name: "easy-ha-proxy-updated | Defer self restart during an active update",
			When:     func(r *engine.Run) bool { return updating(r) && restartFor(r) },
			Resource: &engine.Touch{Path: b.S("{{ updated_restart_request_marker }}"), Owner: "root", Group: b.S(group), Mode: 0o600}},
		{Name: "easy-ha-proxy-updated | Enable service", Resource: Unit(unit, engine.Bool(true), "")},
		{Name: "easy-ha-proxy-updated | Restart changed service outside an update",
			When: func(r *engine.Run) bool { return !updating(r) && restartFor(r) }, Resource: Unit(unit, nil, "restarted")},
		{Name: "easy-ha-proxy-updated | Ensure service is started", Resource: Unit(unit, nil, "started")},
	}
}

// certDeliver is the copy task's content:, word for word.
const certDeliver = `#!/bin/sh
# Managed by easy-ha-proxy: certbot's 906 deploy hook and certd run this.
exec {{ native_agent_bin | default('/usr/local/sbin/easy-ha-proxy-agent') }} cert-deliver "$@"
`

var pluginName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func certd(b *Builder) []engine.Step {
	unit := "haproxy-certd.service"
	steps := []engine.Step{
		{Name: "haproxy-certd | Install runtime packages", Tags: restoreNetwork, Resource: &engine.Packages{Names: []string{"openssl"}}},
	}
	steps = append(steps, dnsPlugins(b)...)
	return append(steps,
		engine.Step{Name: "haproxy-certd | Install systemd unit", Register: "certd_unit",
			Build: b.Template("haproxy-certd.service.j2", "/etc/systemd/system/"+unit, "root", "root", "0644")},
		engine.Step{Name: "haproxy-certd | Ensure the Certbot renewal override directory",
			Resource: b.Dir("/etc/systemd/system/snap.certbot.renew.service.d", "root", "root", "0755")},
		engine.Step{Name: "haproxy-certd | Bind automatic renewal to saved DNS profiles", Register: "certbot_renew_unit",
			Build: b.Template("certbot-renew.service.conf.j2", "/etc/systemd/system/snap.certbot.renew.service.d/easy-ha-proxy.conf", "root", "root", "0644")},
		engine.Step{Name: "haproxy-certd | systemd daemon-reload if unit changed", When: Changed("certd_unit", "certbot_renew_unit"),
			Resource: engine.DaemonReload{}},
		engine.Step{Name: "haproxy-certd | Enable service", Resource: Unit(unit, engine.Bool(true), "")},
		engine.Step{Name: "haproxy-certd | Restart service if changed", When: Changed("certd_unit", "daemons_env_t"),
			Resource: Unit(unit, nil, "restarted")},
		engine.Step{Name: "haproxy-certd | Ensure service started", Resource: Unit(unit, nil, "started")},
		engine.Step{Name: "Install the certificate delivery worker",
			Build: b.CopyContent(certDeliver, "/usr/local/sbin/easy-ha-proxy-cert-deliver", "root", "root", "0755")},
		engine.Step{Name: "Ensure certificate delivery targets directory exists",
			Resource: b.Dir("/etc/easy-ha-proxy/cert-destinations", "root", "root", "0700")},
	)
}

// dnsPlugins transcribes dns-plugins.yml, which certd.yml imports.
func dnsPlugins(b *Builder) []engine.Step {
	plugins := b.List("{{ dns_plugins_enabled | default([]) }}")
	present := &engine.Command{Argv: []string{"certbot", "plugins", "--non-interactive"}, Probe: true, IgnoreErrors: true}
	after := &engine.Command{Argv: []string{"certbot", "plugins", "--non-interactive"}, Probe: true, IgnoreErrors: true}
	any := func(*engine.Run) bool { return len(plugins) > 0 }
	missing := func(out string) []string {
		var m []string
		for _, p := range plugins {
			if !strings.Contains(out, "dns-"+p) {
				m = append(m, p)
			}
		}
		return m
	}
	return []engine.Step{
		{Name: "dns-plugins | Ensure the credentials directory",
			Resource: b.Dir("{{ dns_credentials_dir | default('/etc/easy-ha-proxy/dns-providers') }}", "root", "root", "0700")},
		{Name: "dns-plugins | Which certbot plugins are already present", Resource: present},
		{Name: "dns-plugins | Validate selected plugin names", Build: func(*engine.Run) (engine.Resource, error) {
			for _, p := range plugins {
				if !pluginName.MatchString(p) {
					return nil, fmt.Errorf("Invalid DNS plugin name: %s", p)
				}
			}
			return nil, nil
		}},
		{Name: "dns-plugins | Install the selected plugin snaps", Tags: restoreNetwork, Build: func(*engine.Run) (engine.Resource, error) {
			loop := &engine.Multi{Desc: "snap install certbot-dns-*"}
			for _, p := range missing(present.Output) {
				loop.Items = append(loop.Items, &engine.Command{Argv: []string{"snap", "install", "certbot-dns-" + p},
					Changes: true, Retries: 3, Delay: 5 * time.Second})
			}
			return loop, nil
		}},
		{Name: "dns-plugins | Allow certbot plugins to run with root privileges", When: any,
			Resource: &engine.Command{Argv: []string{"snap", "set", "certbot", "trust-plugin-with-root=ok"}}},
		{Name: "dns-plugins | Connect each plugin to certbot", Build: func(*engine.Run) (engine.Resource, error) {
			loop := &engine.Multi{Desc: "snap connect certbot:plugin certbot-dns-*"}
			for _, p := range plugins {
				loop.Items = append(loop.Items, &engine.Command{Argv: []string{"snap", "connect", "certbot:plugin", "certbot-dns-" + p},
					IgnoreErrors: true})
			}
			return loop, nil
		}},
		{Name: "dns-plugins | Confirm certbot can see them", When: any, Resource: after},
		{Name: "dns-plugins | Report any plugin certbot still cannot see", When: any,
			Build: func(*engine.Run) (engine.Resource, error) {
				m := missing(after.Output)
				return &engine.Func{Desc: "report", CheckFn: func(*engine.System) (engine.Change, error) {
					if len(m) == 0 {
						return engine.Change{}, nil
					}
					return engine.Change{Summary: "certbot does not list dns-" + strings.Join(m, ", dns-") +
						"; DNS-01 for these providers is refused until each snap matches certbot's version"}, nil
				}}, nil
			}},
	}
}

func iptablesBan(b *Builder) []engine.Step {
	unit := "iptables-haproxy-ban"
	return []engine.Step{
		{Name: "iptables-ban | Install required packages", Tags: restoreNetwork,
			Resource: &engine.Packages{Names: []string{"ipset", "iptables", "iptables-persistent"}}},
		{Name: "iptables-ban | Ensure /etc/iptables exists", Resource: b.Dir("/etc/iptables", "root", "root", "0755")},
		{Name: "iptables-ban | Ensure ipset haproxy_ban exists",
			Resource: &engine.Command{Argv: []string{"ipset", "create", "haproxy_ban", "hash:ip", "family", "inet", "-exist"}}},
		{Name: "iptables-ban | Ensure ipset haproxy_ban_page exists",
			Resource: &engine.Command{Argv: []string{"ipset", "create", "haproxy_ban_page", "hash:ip", "family", "inet", "-exist"}}},
		{Name: "iptables-ban | Copy iptables rules file", Register: "rules_file",
			Build: b.CopyFile("haproxy_ban.rules", "/etc/iptables/haproxy_ban.rules", "root", "root", "0644")},
		{Name: "iptables-ban | Install loader systemd unit", Register: "ipt_unit",
			Build: b.Template("iptables-haproxy-ban.service.j2", "/etc/systemd/system/iptables-haproxy-ban.service", "root", "root", "0644")},
		{Name: "iptables-ban | systemd daemon-reload if unit changed", When: Changed("ipt_unit"), Resource: engine.DaemonReload{}},
		{Name: "iptables-ban | Enable & start iptables loader", Build: func(r *engine.Run) (engine.Resource, error) {
			state := "started"
			if r.ChangedAny("rules_file", "ipt_unit") {
				state = "restarted"
			}
			return Unit(unit, engine.Bool(true), state), nil
		}},
	}
}

// udpForwards is the copy task's content:, word for word.
const udpForwards = `# Managed by easy-ha-proxy. UDP forwards (kernel NAT / iptables DNAT).
udp_forwards: []
`

func iptablesUDP(b *Builder) []engine.Step {
	unit := "iptables-haproxy-udp"
	sysctlFile := "/etc/sysctl.d/99-easy-ha-proxy-udp.conf"
	return []engine.Step{
		{Name: "iptables-udp | Install required packages", Tags: restoreNetwork,
			Resource: &engine.Packages{Names: []string{"ipset", "iptables", "iputils-ping", "conntrack"}}},
		{Name: "iptables-udp | Enable IPv4 forwarding for DNATed UDP flows",
			Resource: &engine.Sysctl{Name: "net.ipv4.ip_forward", Value: "1", File: sysctlFile, Reload: true}},
		{Name: "iptables-udp | Keep external routing to loopback disabled",
			Resource: &engine.Sysctl{Name: "net.ipv4.conf.all.route_localnet", Value: "0", File: sysctlFile, Reload: true}},
		{Name: "iptables-udp | Keep loopback routing disabled on future interfaces",
			Resource: &engine.Sysctl{Name: "net.ipv4.conf.default.route_localnet", Value: "0", File: sysctlFile, Reload: true}},
		{Name: "iptables-udp | Ensure a managed udp.yml exists (empty by default)",
			Build: b.CopyContent(udpForwards, "{{ app_dir }}/config/udp.yml", "{{ app_user }}", "{{ app_group }}", "0640", NoForce)},
		{Name: "iptables-udp | Install loader systemd unit", Register: "udp_unit",
			Build: b.Template("iptables-haproxy-udp.service.j2", "/etc/systemd/system/iptables-haproxy-udp.service", "root", "root", "0644")},
		{Name: "iptables-udp | systemd daemon-reload if unit changed", When: Changed("udp_unit"), Resource: engine.DaemonReload{}},
		{Name: "iptables-udp | Enable & (re)load UDP forwarding rules", Build: func(r *engine.Run) (engine.Resource, error) {
			state := "started"
			if r.Changed("udp_unit") {
				state = "restarted"
			}
			return Unit(unit, engine.Bool(true), state), nil
		}},
	}
}
