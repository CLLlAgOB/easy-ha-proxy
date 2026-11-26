package stages

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"easy-ha-proxy/panel/shared/pyyaml"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/engine"
)

// validateHaproxy is the handler chain a changed haproxy.cfg notifies first
// (haproxy -c, then the readable error); apply haproxy reloads after it.
const validateHaproxy = "validate haproxy"

// The copy tasks' content:, word for word.
const (
	haproxyEnvironment  = "HAPROXY_ADMIN_PROXY_SECRET={{ haproxy_admin_proxy_secret }}\n"
	haproxySecretDropIn = `[Service]
EnvironmentFile=/etc/haproxy/easy-ha-proxy.env
`
	haproxyStateGuard = `[Service]
ExecStartPre=-/usr/local/sbin/haproxy-state-dump
`
)

// The runtime source the panel writes, in the order the generation hashes it.
var runtimeSources = []string{"vars.yml", "websites.yml", "tcp.yml"}

var configGeneration = regexp.MustCompile(`^[0-9a-f]{64}$`)

// generation is easy_ha_proxy_config_generation: sha256 over the three
// files' base64 (slurp's content), joined as config.yml joins them.
func generation(raw [][]byte) string {
	text := "easy-ha-proxy-config-generation-v1|"
	for i, name := range runtimeSources {
		if i > 0 {
			text += "|"
		}
		text += name + ":" + base64.StdEncoding.EncodeToString(raw[i])
	}
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

// truthy is a bare when: condition, as Jinja's {% if %} reads it.
func truthy(expr string) string { return "{{ true if (" + expr + ") else false }}" }

// eval is an assert's or a condition's expression at run time, when the
// facts earlier steps set are in place.
func (b *Builder) eval(expr string) (bool, error) {
	v, err := b.Set.Template("{{ " + expr + " }}")
	if err != nil {
		return false, fmt.Errorf("%q: %w", expr, err)
	}
	switch x := v.(type) {
	case bool:
		return x, nil
	case string:
		return x == "True" || x == "true", nil
	}
	return v != nil, nil
}

// assertAll is an assert task whose that: holds Jinja expressions read
// against the facts at run time.
func (b *Builder) assertAll(name string, when func(*engine.Run) bool, msg string, that ...string) engine.Step {
	return engine.Step{Name: name, When: when, Build: func(*engine.Run) (engine.Resource, error) {
		for _, expr := range that {
			ok, err := b.eval(expr)
			if err != nil {
				return nil, err
			}
			if !ok {
				return nil, fmt.Errorf("%s", msg)
			}
		}
		return nil, nil
	}}
}

// fact is a set_fact task: run at its turn, in plan mode too.
func fact(name string, when func(*engine.Run) bool, set func() error) engine.Step {
	return engine.Step{Name: name, When: when, Build: func(*engine.Run) (engine.Resource, error) { return nil, set() }}
}

// haproxyConfig transcribes config.yml: the runtime source the panel writes
// (or else the managed one) and the configuration generation derived from
// it, HAProxy's private environment, the server-state dumper, the path
// shield's lists, and haproxy.cfg, checked by haproxy -c before it replaces
// the old one.
func haproxyConfig(b *Builder) []engine.Step {
	sync := b.Bool("{{ haproxy_admin_sync_managed_config | default(false) | bool }}")
	notSync := func(*engine.Run) bool { return !sync }
	stateOn := b.Bool(truthy("haproxy_server_state_enabled | default(true)"))
	onState := func(*engine.Run) bool { return stateOn }
	runtimeDir := b.S("{{ haproxy_runtime_config_dir }}")
	managedDir := b.S("{{ easy_ha_proxy_config_dir | default(playbook_dir) }}")
	shieldDir := b.S("{{ (whitelist_global_file | default('/etc/haproxy/whitelist.ip')) | dirname }}")
	secret := b.S("{{ haproxy_admin_proxy_secret }}")
	notify := []string{validateHaproxy, applyHaproxy}
	metrics := b.Bool("{{ metrics_export_enabled | default(false) | bool }}")

	var stats []os.FileInfo // nil entry: absent
	count := 0
	active := false
	gen := ""
	var runtimeRaw, managedRaw [][]byte
	complete := func(*engine.Run) bool { return !sync && count == 3 }
	isActive := func(*engine.Run) bool { return active }
	slurp := func(dir string, into *[][]byte) func() error {
		return func() error {
			*into = nil
			for _, name := range runtimeSources {
				raw, err := os.ReadFile(b.Sys.Path(filepath.Join(dir, name)))
				if err != nil {
					return err
				}
				*into = append(*into, raw)
			}
			return nil
		}
	}

	cfg := b.Template("haproxy.cfg.j2", "/etc/haproxy/haproxy.cfg", "root", "haproxy", "0644", LstripBlocks)
	steps := []engine.Step{
		b.assertAll("Prometheus export | The token is the second gate, so it cannot be empty",
			func(*engine.Run) bool { return metrics },
			"metrics_export_enabled is true but metrics_export_token is empty or too short. The allow-listed source is one "+
				"gate and the bearer token is the other; without it the endpoint would answer 401 to the scraper and the "+
				"export would look broken rather than unconfigured.",
			"(metrics_export_token | default('')) | length >= 24"),
		fact("Initialize the optional HAProxy Admin runtime source", nil, func() error {
			for _, name := range []string{"easy_ha_proxy_runtime_vars", "easy_ha_proxy_runtime_websites", "easy_ha_proxy_runtime_tcp"} {
				b.Set.SetFact(name, pyyaml.NewMap())
			}
			b.Set.SetFact("easy_ha_proxy_runtime_source_active", false)
			active = false
			return nil
		}),
		fact("Inspect HAProxy Admin runtime source files", notSync, func() error {
			stats = nil
			for _, name := range runtimeSources {
				fi, err := os.Lstat(b.Sys.Path(filepath.Join(runtimeDir, name)))
				if err != nil && !os.IsNotExist(err) {
					return err
				}
				stats = append(stats, fi)
			}
			return nil
		}),
		fact("Count available HAProxy Admin runtime source files", nil, func() error {
			count = 0
			for _, fi := range stats {
				if fi != nil {
					count++
				}
			}
			return nil
		}),
		assertStep("Reject incomplete HAProxy Admin runtime source",
			func(*engine.Run) bool { return sync || count == 0 || count == 3 },
			"The HAProxy Admin runtime configuration is incomplete. Restore vars.yml, websites.yml, and tcp.yml together before updating HAProxy."),
		assertStep("Validate HAProxy Admin runtime source file boundaries", func(*engine.Run) bool {
			for _, fi := range stats {
				if sync || fi == nil {
					continue
				}
				if !fi.Mode().IsRegular() || fi.Size() <= 0 || fi.Size() > 2097152 {
					return false
				}
			}
			return true
		}, "Refusing an unsafe HAProxy Admin runtime source file. Runtime YAML must be a regular, non-symlink file between 1 byte and 2 MiB."),
		fact("Read the HAProxy Admin runtime source", complete, slurp(runtimeDir, &runtimeRaw)),
		fact("Decode the HAProxy Admin runtime source in a private namespace", complete, func() error {
			for i, name := range []string{"easy_ha_proxy_runtime_vars", "easy_ha_proxy_runtime_websites", "easy_ha_proxy_runtime_tcp"} {
				v, err := pyyaml.Load(runtimeRaw[i])
				if err != nil {
					return fmt.Errorf("%s: %w", runtimeSources[i], err)
				}
				b.Set.SetFact(name, v)
			}
			b.Set.SetFact("easy_ha_proxy_runtime_source_active", true)
			active = true
			return nil
		}),
		b.assertAll("Validate the decoded HAProxy Admin runtime source", isActive,
			"The HAProxy Admin runtime YAML has an invalid root, sites list, or TCP proxy list. No HAProxy configuration was changed.",
			"easy_ha_proxy_runtime_vars is mapping",
			"easy_ha_proxy_runtime_websites is mapping",
			"easy_ha_proxy_runtime_tcp is mapping",
			"easy_ha_proxy_runtime_vars.site_defaults | default({}) is mapping",
			"easy_ha_proxy_runtime_websites.sites | default([]) is sequence",
			"easy_ha_proxy_runtime_websites.sites | default([]) is not string",
			"easy_ha_proxy_runtime_tcp.tcp_proxies | default(easy_ha_proxy_runtime_tcp.tcp | default([])) is sequence",
			"easy_ha_proxy_runtime_tcp.tcp_proxies | default(easy_ha_proxy_runtime_tcp.tcp | default([])) is not string"),
		fact("Calculate the runtime HAProxy configuration generation", isActive, func() error {
			gen = generation(runtimeRaw)
			b.Set.SetFact("easy_ha_proxy_config_generation", gen)
			return nil
		}),
		fact("Read the managed HAProxy source for its configuration generation",
			func(*engine.Run) bool { return !active }, slurp(managedDir, &managedRaw)),
		fact("Calculate the managed HAProxy configuration generation", func(*engine.Run) bool { return !active }, func() error {
			gen = generation(managedRaw)
			b.Set.SetFact("easy_ha_proxy_config_generation", gen)
			return nil
		}),
		assertStep("Validate the HAProxy configuration generation", func(*engine.Run) bool { return configGeneration.MatchString(gen) },
			"The HAProxy configuration generation could not be derived from the exact vars.yml, websites.yml, and tcp.yml source bytes."),
		{Name: "Ensure HAProxy systemd drop-in directory exists", Resource: b.Dir("/etc/systemd/system/haproxy.service.d", "root", "root", "0755")},
		{Name: "Install private HAProxy runtime environment", Register: "haproxy_runtime_environment", Notify: notify,
			Build: b.CopyContent(haproxyEnvironment, "/etc/haproxy/easy-ha-proxy.env", "root", "root", "0600")},
		{Name: "Configure HAProxy to load its private environment", Register: "haproxy_secret_dropin", Notify: notify,
			Build: b.CopyContent(haproxySecretDropIn, "/etc/systemd/system/haproxy.service.d/easy-ha-proxy.conf", "root", "root", "0644")},
		{Name: "Reload systemd after HAProxy environment drop-in changed", When: Changed("haproxy_secret_dropin"), Resource: engine.DaemonReload{}},
		// The agent normalizes the dumps (easy-ha-proxy-agent server-state);
		// the Python copy earlier installers put here is not used any more.
		{Name: "server-state | Remove the former Python normalizer",
			Resource: &engine.Absent{Path: "/usr/local/libexec/easy-ha-proxy/haproxy-server-state.py"}},
		{Name: "server-state | Install the dump script", When: onState,
			Build: b.Template("haproxy-state-dump.sh.j2", "/usr/local/sbin/haproxy-state-dump", "root", "root", "0755")},
		{Name: "server-state | Normalize state before every cold start", When: onState, Register: "haproxy_state_start_guard",
			Build: b.CopyContent(haproxyStateGuard, "/etc/systemd/system/haproxy.service.d/server-state.conf", "root", "root", "0644")},
		{Name: "server-state | Remove startup guard when state loading is disabled", When: func(*engine.Run) bool { return !stateOn },
			Register: "haproxy_state_start_guard_removed", Resource: &engine.Absent{Path: "/etc/systemd/system/haproxy.service.d/server-state.conf"}},
		{Name: "server-state | Reload systemd after startup guard changed",
			When: Changed("haproxy_state_start_guard", "haproxy_state_start_guard_removed"), Resource: engine.DaemonReload{}},
	}
	for _, unit := range []string{"service", "timer"} {
		steps = append(steps, engine.Step{Name: "server-state | Install the dump unit and timer", When: onState, Register: "haproxy_state_units",
			Build: b.Template("haproxy-state-dump."+unit+".j2", "/etc/systemd/system/haproxy-state-dump."+unit, "root", "root", "0644")})
	}
	steps = append(steps,
		engine.Step{Name: "server-state | systemd daemon-reload if the units changed", When: Changed("haproxy_state_units"), Resource: engine.DaemonReload{}},
		engine.Step{Name: "server-state | Enable the refresh timer", When: onState, Resource: Unit("haproxy-state-dump.timer", engine.Bool(true), "started")},
		engine.Step{Name: "server-state | Seed an empty state file", When: onState,
			Build: b.CopyContent("1\n", "{{ haproxy_server_state_file }}", "root", "root", "0644", NoForce)},
	)
	for _, list := range []string{"guardd-shield-segments.lst", "guardd-shield-paths.lst", "guardd-shield-exempt.lst"} {
		steps = append(steps, engine.Step{Name: "path shield | Ensure the empty list files exist",
			Build: b.CopyContent("", filepath.Join(shieldDir, list), "root", "root", "0644", NoForce)})
	}
	return append(steps,
		engine.Step{Name: "Copy HAProxy configuration", Notify: notify, Build: func(r *engine.Run) (engine.Resource, error) {
			res, err := cfg(r)
			if err != nil {
				return nil, err
			}
			f := res.(*engine.File)
			f.Validate = func(sys *engine.System, tmp string) error {
				// The secret reaches haproxy -c in its environment, as the
				// task's environment: gives it, never in the argument list.
				out, code, err := sys.RunEnv([]string{"HAPROXY_ADMIN_PROXY_SECRET=" + secret},
					"/bin/sh", "-c", `exec /usr/sbin/haproxy -c -f "$1" 2>&1`, "haproxy-validate", tmp)
				if err != nil {
					return err
				}
				if code != 0 {
					return fmt.Errorf("haproxy -c refused the new configuration (exit %d); /etc/haproxy/haproxy.cfg was left as it was:\n%s", code, out)
				}
				return nil
			}
			return f, nil
		}},
		engine.Step{Name: "server-state | Refresh administrative state without transport overrides", When: onState,
			Resource: &engine.Command{Argv: []string{"/usr/local/sbin/haproxy-state-dump"}}},
		engine.Step{Name: "Ensure HAProxy is enabled and running after configuration", Resource: Unit("haproxy", engine.Bool(true), "started")},
	)
}
