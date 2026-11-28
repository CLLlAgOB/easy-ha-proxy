package stages

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"easy-ha-proxy/panel/shared/jinja"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/engine"
)

// The play's handlers, in the order Ansible runs them: the order the roles'
// handler files define them (cert, haproxy, docker). Each listens on one
// topic; a handler may notify later ones, which run in the same flush.
var handlerOrder = []Part{
	{Name: "handler/build_pems_and_reload", Role: "cert", File: "build_pems_and_reload", Build: handlerBuildPEMs},
	{Name: "handler/validate haproxy", Role: "haproxy", File: validateHaproxy, Build: handlerValidateHaproxy},
	{Name: "handler/apply haproxy", Role: "haproxy", File: applyHaproxy, Build: handlerApplyHaproxy},
	{Name: "handler/apparmor rsyslogd reload", Role: "haproxy", File: apparmorRsyslog, Build: handlerAppArmor},
	{Name: "handler/rsyslog | restart", Role: "haproxy", File: "rsyslog | restart", Build: func(*Builder) []engine.Step {
		return []engine.Step{{Name: "rsyslog | restart", Resource: Unit("rsyslog", nil, "restarted")}}
	}},
	{Name: "handler/wait | haproxy devlog socket", Role: "haproxy", File: "wait | haproxy devlog socket", Build: handlerWaitDevlog},
	{Name: "handler/haproxy | restart for logging", Role: "haproxy", File: "haproxy | restart for logging", Build: func(*Builder) []engine.Step {
		return []engine.Step{{Name: "haproxy | restart for logging", Resource: Unit("haproxy", nil, "restarted")}}
	}},
	{Name: "handler/Restart Docker", Role: "docker", File: "Restart Docker", Build: func(*Builder) []engine.Step {
		return []engine.Step{{Name: "Restart Docker", Resource: Unit("docker", nil, "restarted")}}
	}},
}

// HandlerTopics lists the topics the Go handlers listen on, in order.
func HandlerTopics() []string {
	out := make([]string, len(handlerOrder))
	for i, h := range handlerOrder {
		out[i] = h.File
	}
	return out
}

// FlushHandlers runs every notified handler, in definition order, until
// none is left (meta: flush_handlers, and the end of a play). A topic no Go
// handler listens on is an error: Ansible would have refused the notify.
func FlushHandlers(ctx Context, run *engine.Run) error {
	for {
		pending := run.TakeNotified()
		if len(pending) == 0 {
			return nil
		}
		want := map[string]bool{}
		for _, name := range pending {
			want[name] = true
		}
		for _, h := range handlerOrder {
			if !want[h.File] {
				continue
			}
			delete(want, h.File)
			if err := runPart(ctx, h, "", run); err != nil {
				return err
			}
			// A handler's own notifications for later handlers run in this pass.
			for _, name := range run.TakeNotified() {
				want[name] = true
			}
		}
		for name := range want {
			return fmt.Errorf("no handler listens on %q", name)
		}
	}
}

// handlerBuildPEMs is cert's build_pems_and_reload: the certs directory, a
// PEM per lineage (scripts word for word), then a reload when HAProxy is
// there and allowed.
func handlerBuildPEMs(b *Builder) []engine.Step {
	certsDir := b.S("{{ haproxy_certs_dir }}")
	steps := []engine.Step{{Name: "Ensure HAProxy certs dir exists", Resource: b.Dir(certsDir, "root", "root", "0755")}}
	sites := siteMaps(b.Value("{{ sites | default([]) }}"))
	pem := func(name, script, lineage, dest string) engine.Step {
		return engine.Step{Name: name, Build: func(*engine.Run) (engine.Resource, error) {
			out, err := b.Set.RenderLocal(script, map[string]any{"lineage": lineage, "dest": dest})
			if err != nil {
				return nil, err
			}
			return &engine.Command{Argv: []string{"/bin/bash", "-c", out},
				ChangedWhen: func(o string, _ int) bool { return strings.Contains(o, "PEM written:") }}, nil
		}}
	}
	for _, site := range sites {
		kts, ok := site.Get("key_types")
		if !ok {
			continue
		}
		types := strList(kts)
		domain := jinja.Str(site.Value("domain"))
		base := certsDir + "/" + domain + ".pem"
		if p, ok := site.Get("cert_path"); ok {
			base = jinja.Str(p)
		}
		for _, kt := range types {
			dest, lineage := base, domain
			if len(types) > 1 {
				lineage = domain + "-" + kt
				if strings.HasSuffix(base, ".pem") {
					dest = base[:len(base)-4] + "-" + kt + ".pem"
				} else {
					dest = base + "-" + kt + ".pem"
				}
			}
			steps = append(steps, pem("Build PEMs (sites with explicit key_types)", pemExplicit, lineage, dest))
		}
	}
	for _, site := range sites {
		if _, ok := site.Get("key_types"); ok {
			continue
		}
		domain := jinja.Str(site.Value("domain"))
		dest := certsDir + "/" + domain + ".pem"
		if p, ok := site.Get("cert_path"); ok {
			dest = jinja.Str(p)
		}
		steps = append(steps, pem("Build PEMs (sites without key_types → default key type)", pemSingle, domain, dest))
	}
	reload := b.Bool("{{ true if (haproxy_autoreload | default(true)) else false }}") &&
		b.Bool("{{ true if (haproxy_present | default(false)) else false }}")
	return append(steps, engine.Step{Name: "Reload HAProxy (only if present)", When: func(*engine.Run) bool { return reload },
		Resource: Unit("haproxy", nil, "reloaded")})
}

var alertLine = regexp.MustCompile(`.*(ALERT|WARNING).*`)

// cfgTest is the validate handler's haproxy -c, which apply reads.
type cfgTest struct {
	ran  bool
	code int
}

func shared(b *Builder) *cfgTest {
	if b.Shared == nil {
		return &cfgTest{}
	}
	t, _ := b.Shared["haproxy_cfg_test"].(*cfgTest)
	if t == nil {
		t = &cfgTest{}
		b.Shared["haproxy_cfg_test"] = t
	}
	return t
}

// handlerValidateHaproxy is "validate haproxy": haproxy -c with the proxy
// secret in its environment; on a failure the ALERT and WARNING lines, then
// the play stops.
func handlerValidateHaproxy(b *Builder) []engine.Step {
	secret := b.S("{{ haproxy_admin_proxy_secret }}")
	test := shared(b)
	var out string
	return []engine.Step{
		{Name: "run haproxy -c syntax-check", Resource: &engine.Func{Desc: "haproxy -c -f /etc/haproxy/haproxy.cfg",
			CheckFn: func(sys *engine.System) (engine.Change, error) {
				o, code, err := sys.RunEnv([]string{"HAPROXY_ADMIN_PROXY_SECRET=" + secret}, "/bin/sh", "-c",
					`exec haproxy -c -f /etc/haproxy/haproxy.cfg 2>&1`)
				if err != nil {
					return engine.Change{}, err
				}
				out, test.ran, test.code = o, true, code
				return engine.Change{Summary: fmt.Sprintf("rc=%d", code)}, nil
			}}},
		{Name: "show pretty syntax error", When: func(*engine.Run) bool { return test.code != 0 },
			Build: func(*engine.Run) (engine.Resource, error) {
				var bad []string
				for _, line := range strings.Split(out, "\n") {
					if alertLine.MatchString(line) {
						bad = append(bad, line)
					}
				}
				return report("HAProxy configuration error!\n" + strings.Join(bad, "\n")), nil
			}},
		{Name: "stop play on invalid config", When: func(*engine.Run) bool { return test.code != 0 },
			Build: func(*engine.Run) (engine.Resource, error) {
				return nil, fmt.Errorf("HAProxy syntax check failed — see details above.")
			}},
	}
}

// handlerApplyHaproxy is "apply haproxy": when the check passed (or did not
// run), a restart if the private environment or its drop-in changed, else a
// reload; a failed reload becomes a restart, a failed restart fails.
func handlerApplyHaproxy(b *Builder) []engine.Step {
	test := shared(b)
	reloadFailed := false
	return []engine.Step{
		{Name: "apply validated HAProxy configuration", When: func(*engine.Run) bool { return test.code == 0 },
			Build: func(r *engine.Run) (engine.Resource, error) {
				state := "reloaded"
				if r.ChangedAny("haproxy_runtime_environment", "haproxy_secret_dropin") {
					state = "restarted"
				}
				return &engine.Rescued{Inner: Unit("haproxy", nil, state), Failed: &reloadFailed, Note: "reload failed; restarting"}, nil
			}},
		{Name: "hard restart haproxy if reload failed", When: func(*engine.Run) bool { return test.code == 0 && reloadFailed },
			Resource: Unit("haproxy", nil, "restarted")},
	}
}

// handlerAppArmor is "apparmor rsyslogd reload": the profile reloaded with
// apparmor_parser, else AppArmor reloaded; either way rsyslog restarts, the
// chroot's log socket is waited for, and HAProxy restarts.
func handlerAppArmor(b *Builder) []engine.Step {
	parser := &engine.Command{Argv: []string{"apparmor_parser", "-r", "/etc/apparmor.d/usr.sbin.rsyslogd"}, IgnoreErrors: true,
		ChangedWhen: func(_ string, code int) bool { return code == 0 }}
	chain := []string{"rsyslog | restart", "wait | haproxy devlog socket", "haproxy | restart for logging"}
	return []engine.Step{
		{Name: "apparmor | reload rsyslogd profile", Resource: parser, Notify: chain},
		{Name: "apparmor | systemd reload", When: func(r *engine.Run) bool { return r.Mode == engine.Apply && parser.Code != 0 },
			Resource: Unit("apparmor", nil, "reloaded"), Notify: chain},
	}
}

// handlerWaitDevlog is wait_for path=/var/lib/haproxy/dev/log timeout=5.
func handlerWaitDevlog(b *Builder) []engine.Step {
	return []engine.Step{{Name: "wait | haproxy devlog socket", Resource: &engine.Func{Desc: "wait for /var/lib/haproxy/dev/log",
		CheckFn: func(*engine.System) (engine.Change, error) {
			return engine.Change{Summary: "runs on apply", Run: true}, nil
		},
		ApplyFn: func(sys *engine.System) error {
			for i := 0; i < 5; i++ {
				if b.Exists("/var/lib/haproxy/dev/log", false) {
					return nil
				}
				healthSleep()
			}
			if b.Exists("/var/lib/haproxy/dev/log", false) {
				return nil
			}
			return fmt.Errorf("Timeout when waiting for file /var/lib/haproxy/dev/log")
		}}}}
}

func healthSleep() { time.Sleep(time.Second) }
