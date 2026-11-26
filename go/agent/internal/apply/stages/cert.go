package stages

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"easy-ha-proxy/panel/shared/jinja"
	"easy-ha-proxy/panel/shared/pyyaml"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/engine"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/facts"
)

// The certificate stage: roles/cert's install, notify, hooks and renew
// entries. renew notifies build_pems_and_reload and flushes it at once, as
// renew__30_assemble.yml does; the handler is Ansible's during the hybrid
// period, so it is handed back with haproxy_present, which it reads.
func init() {
	register(Stage{Name: "cert", Parts: []Part{
		{Name: "cert/install", Role: "cert", File: "install", Build: certInstall, Facts: []string{"haproxy_present"}},
		{Name: "cert/notify", Role: "cert", File: "notify", Build: certNotify},
		{Name: "cert/hooks", Role: "cert", File: "hooks", Build: certHooks},
		{Name: "cert/renew", Role: "cert", File: "renew", Build: certRenew, Facts: []string{"haproxy_present"}},
	}})
}

const buildPEMs = "build_pems_and_reload"

// haproxyPresent is service_facts plus "'haproxy.service' in services".
func haproxyPresent(b *Builder, name string) engine.Step {
	return engine.Step{Name: name, Resource: &engine.Func{Desc: "service_facts", CheckFn: func(sys *engine.System) (engine.Change, error) {
		services, err := facts.Services(execRunner(sys))
		if err != nil {
			return engine.Change{}, err
		}
		_, ok := services.Get("haproxy.service")
		b.Set.SetFact("haproxy_present", ok)
		return engine.Change{Summary: "read"}, nil
	}}}
}

func certInstall(b *Builder) []engine.Step {
	version := &engine.Command{Argv: []string{"/snap/bin/certbot", "--version"}}
	return []engine.Step{
		{Name: "Install snapd for the current Certbot release", Tags: restoreNet,
			Resource: &engine.AptInstall{Names: []string{"snapd"}, UpdateCache: true, CacheValid: b.aptValid()}},
		{Name: "Ensure snap core is installed", Tags: restoreNet, When: func(*engine.Run) bool { return !b.Exists("/snap/core/current", false) },
			Resource: &engine.Command{Argv: []string{"snap", "install", "core", "--classic"}, Changes: true}},
		{Name: "Install Certbot with snap", Tags: restoreNet, When: func(*engine.Run) bool { return !b.Exists("/snap/bin/certbot", false) },
			Resource: &engine.Command{Argv: []string{"snap", "install", "--classic", "certbot"}, Changes: true}},
		{Name: "Link /usr/bin/certbot to the snap executable", Resource: &engine.Link{Path: "/usr/bin/certbot", Target: "/snap/bin/certbot"}},
		// service_facts and the set_fact that reads it are one step.
		haproxyPresent(b, "Gather service facts"),
		fact("Record whether haproxy.service is installed", nil, func() error { return nil }),
		{Name: "Read the snap Certbot version", Resource: version},
		{Name: "Report the Certbot version", When: func(r *engine.Run) bool { return r.Mode == engine.Apply },
			Build: func(*engine.Run) (engine.Resource, error) {
				return report("Using Certbot " + strings.TrimRight(version.Output, "\n")), nil
			}},
	}
}

var (
	msmtpManaged = regexp.MustCompile(`Ansible managed|managed by Ansible`)
)

func certNotify(b *Builder) []engine.Step {
	remove := false
	return []engine.Step{
		{Name: "Ensure the managed configuration directory exists",
			Resource: b.Dir("{{ easy_ha_proxy_config_dir | default('/etc/easy-ha-proxy') }}", "root", "root", "0700")},
		{Name: "Write the dynamic certificate notification state",
			Build: b.Template("mail-notify.json.j2", "{{ easy_ha_proxy_config_dir | default('/etc/easy-ha-proxy') }}/mail-notify.json", "root", "root", "0600")},
		fact("Read the legacy managed msmtp configuration", nil, func() error {
			remove = false
			fi, err := os.Lstat(b.Sys.Path("/etc/msmtprc"))
			if err != nil || !fi.Mode().IsRegular() {
				return nil
			}
			raw, err := os.ReadFile(b.Sys.Path("/etc/msmtprc"))
			if err != nil {
				return err
			}
			uid, gid := fileOwner(fi)
			text := string(raw)
			// Ansible doubles the backslashes of string literals inside
			// {{ }}, so the task's '\ndefaults\n' is a backslash and an n,
			// not a newline: the check has never matched a real file, and
			// no gateway's msmtprc was ever removed. Kept so: removing it now
			// is a change of behaviour for the operator to decide.
			remove = uid == 0 && gid == 0 && fi.Mode().Perm() == 0o600 && msmtpManaged.MatchString(text) &&
				strings.Contains(text, `\ndefaults\n`) && strings.Contains(text, `\nsyslog          LOG_MAIL\n`) &&
				strings.Contains(text, `\naccount         default\n`) && strings.Contains(text, `\nset_from_header on\n`)
			return nil
		}),
		fact("Recognize the legacy role-owned msmtp configuration", nil, func() error {
			b.Set.SetFact("cert_remove_legacy_msmtprc", remove)
			return nil
		}),
		{Name: "Remove the recognized legacy role-owned msmtp configuration", When: func(*engine.Run) bool { return remove },
			Resource: &engine.Absent{Path: "/etc/msmtprc"}},
		{Name: "Ensure deploy-hooks directory exists", Resource: b.Dir("/etc/letsencrypt/renewal-hooks/deploy", "root", "root", "0755")},
		{Name: "Deploy the dynamic Certbot e-mail notification hook",
			Build: b.Template("910-mail-notify.sh.j2", "/etc/letsencrypt/renewal-hooks/deploy/910-mail-notify.sh", "root", "root", "0755")},
	}
}

func certHooks(b *Builder) []engine.Step {
	return []engine.Step{
		{Name: "Ensure Certbot deploy-hooks directory exists", Resource: b.Dir("/etc/letsencrypt/renewal-hooks/deploy", "root", "root", "0755")},
		{Name: "Install jq (for manifest reading)", Tags: restoreNet,
			Resource: &engine.AptInstall{Names: []string{"jq"}, UpdateCache: true, CacheValid: b.aptValid()}},
		{Name: "Deploy HAProxy PEM assembly & reload hook (DEPLOY)",
			Build: b.Template("905-haproxy-pems-reload.sh.j2", "/etc/letsencrypt/renewal-hooks/deploy/905-haproxy-pems-reload.sh", "root", "root", "0755")},
		{Name: "Ensure certificate delivery targets directory exists", Resource: b.Dir("/etc/easy-ha-proxy/cert-destinations", "root", "root", "0700")},
		{Name: "Deploy certificate delivery hook (DEPLOY)",
			Build: b.Template("906-deliver-certificates.sh.j2", "/etc/letsencrypt/renewal-hooks/deploy/906-deliver-certificates.sh", "root", "root", "0755")},
		{Name: "Ensure HAProxy certs dir exists", Resource: b.Dir("{{ haproxy_certs_dir | default('/etc/haproxy/certs') }}", "root", "root", "0755")},
	}
}

// siteMaps reads a list of sites (mappings).
func siteMaps(v any) []*pyyaml.Map {
	list, _ := v.([]any)
	var out []*pyyaml.Map
	for _, item := range list {
		if m, ok := item.(*pyyaml.Map); ok {
			out = append(out, m)
		}
	}
	return out
}

func strList(v any) []string {
	list, _ := v.([]any)
	var out []string
	for _, item := range list {
		out = append(out, jinja.Str(item))
	}
	return out
}

func unique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func anyList(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

var keyTypeSuffix = regexp.MustCompile(`(-rsa|-ecdsa)$`)

// certState carries renew's set_facts from step to step.
type certState struct {
	sites                          []*pyyaml.Map
	mode, keyType                  string
	existing                       []string
	explicit, single               []string // all_*_lineages
	targetsExplicit, targetsSingle []string
	dns01, planned                 []string
	plannedItems                   []plannedItem
	checks                         []*engine.Command
	ready                          []string
	issueExplicit, issueSingle     []string
	count                          int
	bootstrap                      bool
	port, ipt4, ip6, ipt6          *engine.Command
	failed                         error // the block's failure, raised after its always:
}

type plannedItem struct {
	lineage string
	names   []string
}

func (c *certState) site(domain string) *pyyaml.Map {
	for _, s := range c.sites {
		if jinja.Str(s.Value("domain")) == domain {
			return s
		}
	}
	return nil
}

// guarded runs a block step's resource; a failure is kept for after the
// always: steps instead of stopping the run.
type guarded struct {
	engine.Resource
	state *certState
}

func (g *guarded) Check(sys *engine.System) (engine.Change, error) {
	c, err := g.Resource.Check(sys)
	if err != nil {
		g.state.failed = err
		return engine.Change{Summary: "failed: " + err.Error()}, nil
	}
	return c, nil
}

func (g *guarded) Apply(sys *engine.System, c engine.Change) error {
	if err := g.Resource.Apply(sys, c); err != nil {
		g.state.failed = err
	}
	return nil
}

func (g *guarded) Changed() bool {
	if o, ok := g.Resource.(engine.Outcome); ok {
		return o.Changed()
	}
	return false
}

// dnsCheck is renew__15_dns_check.yml's shell script, word for word.
const dnsCheck = `set -eo pipefail
ok=1
for n in {{ names | map('quote') | join(' ') }}; do
  for r in {{ acme_resolvers | map('quote') | join(' ') }}; do
    if ! (dig +time=2 +tries=1 +short A "$n" @"$r" | grep -E '^[0-9]+\.' >/dev/null \
       || dig +time=2 +tries=1 +short AAAA "$n" @"$r" | grep -E '^[0-9a-f:]' >/dev/null); then
      ok=0
    fi
  done
done
echo "$ok"
`

func quoteAll(list []string) string {
	out := make([]string, len(list))
	for i, s := range list {
		q, _ := jinja.AnsibleQuote(nil, s, nil, nil)
		out[i] = q.(string)
	}
	return strings.Join(out, " ")
}

func certRenew(b *Builder) []engine.Step {
	c := &certState{}
	resolvers := strList(b.Value("{{ acme_resolvers | default(['1.1.1.1','8.8.8.8']) }}"))
	ipv6 := b.Bool("{{ true if (acme_ipv6 | default(true)) else false }}")
	email := b.S("{{ certbot_email }}")
	rsaSize, curve := b.S("{{ rsa_key_size }}"), b.S("{{ ecdsa_curve }}")
	include := strList(b.Value("{{ sites_include | default([]) }}"))
	issuing := func(*engine.Run) bool { return c.count > 0 && c.failed == nil }

	steps := []engine.Step{
		fact("Ensure sites is a list", nil, func() error {
			v, err := b.Set.Template("{{ sites | default([], true) | list }}")
			if err != nil {
				return err
			}
			b.Set.SetFact("sites", v)
			return nil
		}),
		fact("Build local cert_sites (sites + certbot_domains)", nil, func() error {
			v, err := b.Set.Get("sites")
			if err != nil {
				return err
			}
			var out []*pyyaml.Map
			var existing []string
			for _, s := range siteMaps(v) {
				if paused, ok := s.Get("cert_renewal_paused"); !ok || paused != true {
					out = append(out, s)
				}
				if d, ok := s.Get("domain"); ok {
					existing = append(existing, jinja.Str(d))
				}
			}
			domains, _ := b.Set.Template("{{ certbot_domains | default([]) }}")
			for _, d := range strList(domains) {
				if !contains(existing, d) {
					m := pyyaml.NewMap()
					m.Set("name", d)
					m.Set("domain", d)
					out = append(out, m)
					existing = append(existing, d)
				}
			}
			c.sites = out
			list := make([]any, len(out))
			for i, s := range out {
				list[i] = s
			}
			b.Set.SetFact("cert_sites", list)
			return nil
		}),
		fact("Defaults for mode and key type", nil, func() error {
			c.mode, c.keyType = b.S("{{ cert_issue_mode | default('all') }}"), b.S("{{ cert_key_type | default('ecdsa') }}")
			return nil
		}),
		fact("Find existing renewal lineages", nil, func() error {
			c.existing = nil
			entries, _ := os.ReadDir(b.Sys.Path("/etc/letsencrypt/renewal"))
			for _, e := range entries {
				if e.Type().IsRegular() && strings.HasSuffix(e.Name(), ".conf") {
					c.existing = append(c.existing, strings.TrimSuffix(e.Name(), ".conf"))
				}
			}
			return nil
		}),
		fact("Build list of existing lineage names", nil, func() error { return nil }),
		{Name: "debug existing_lineages", Build: func(*engine.Run) (engine.Resource, error) {
			return report(fmt.Sprintf("existing_lineages: %v", c.existing)), nil
		}},
		fact("Build all_explicit targets (lineage names)", nil, func() error {
			c.explicit = nil
			for _, s := range c.sites {
				kts, ok := s.Get("key_types")
				if !ok {
					continue
				}
				types := strList(kts)
				for _, kt := range types {
					if len(types) > 1 {
						c.explicit = append(c.explicit, jinja.Str(s.Value("domain"))+"-"+kt)
					} else {
						c.explicit = append(c.explicit, jinja.Str(s.Value("domain")))
					}
				}
			}
			c.explicit = unique(c.explicit)
			return nil
		}),
		fact("Build all_explicit targets (lineage names, no external filters)", nil, func() error { return nil }),
		fact("Build all_single targets (lineage names)", nil, func() error {
			c.single = nil
			for _, s := range c.sites {
				if _, ok := s.Get("key_types"); ok {
					continue
				}
				if d, ok := s.Get("domain"); ok {
					c.single = append(c.single, jinja.Str(d))
				}
			}
			c.single = unique(c.single)
			return nil
		}),
		fact("Apply sites_include filter (if provided)", func(*engine.Run) bool { return len(include) > 0 }, func() error {
			var explicit, single []string
			for _, lin := range c.explicit {
				if contains(include, keyTypeSuffix.ReplaceAllString(lin, "")) {
					explicit = append(explicit, lin)
				}
			}
			for _, lin := range c.single {
				if contains(include, lin) {
					single = append(single, lin)
				}
			}
			c.explicit, c.single = unique(explicit), unique(single)
			return nil
		}),
		fact("Select final targets by mode", nil, func() error {
			c.targetsExplicit, c.targetsSingle = c.explicit, c.single
			if c.mode == "new" {
				c.targetsExplicit, c.targetsSingle = nil, nil
				for _, lin := range c.explicit {
					if !contains(c.existing, lin) {
						c.targetsExplicit = append(c.targetsExplicit, lin)
					}
				}
				for _, lin := range c.single {
					if !contains(c.existing, lin) {
						c.targetsSingle = append(c.targetsSingle, lin)
					}
				}
			}
			return nil
		}),
		fact("Count targets", nil, func() error { return nil }),
		{Name: "debug", Build: func(*engine.Run) (engine.Resource, error) {
			return report(fmt.Sprintf("targets_explicit: %v; targets_single: %v; current_lineages: %v; mode: %s, total targets: %d",
				c.targetsExplicit, c.targetsSingle, c.existing, c.mode, len(c.targetsExplicit)+len(c.targetsSingle))), nil
		}},
		fact("Defaults for DNS check", nil, func() error { return nil }),
		fact("Aggregate planned targets", nil, func() error { return nil }),
		fact("Collect the DNS-01 targets", nil, func() error {
			c.dns01 = nil
			for _, lin := range append(append([]string{}, c.targetsExplicit...), c.targetsSingle...) {
				if site := c.site(keyTypeSuffix.ReplaceAllString(lin, "")); site != nil && jinja.Truthy(site.Value("dns_profile")) {
					c.dns01 = append(c.dns01, lin)
				}
			}
			return nil
		}),
		fact("Keep only the HTTP-01 targets for this role", nil, func() error {
			c.planned = nil
			for _, lin := range append(append([]string{}, c.targetsExplicit...), c.targetsSingle...) {
				if !contains(c.dns01, lin) {
					c.planned = append(c.planned, lin)
				}
			}
			return nil
		}),
		{Name: "Report the targets left to haproxy-certd", When: func(*engine.Run) bool { return len(c.dns01) > 0 },
			Build: func(*engine.Run) (engine.Resource, error) {
				return report("DNS-01 targets are issued by haproxy-certd, not here: " + strings.Join(c.dns01, ", ") +
					". Use the site page or apply the HAProxy configuration to issue them."), nil
			}},
		fact("Normalize planned targets into uniform objects", nil, func() error {
			c.plannedItems = nil
			for _, lin := range c.planned {
				base := keyTypeSuffix.ReplaceAllString(lin, "")
				names := []string{base}
				if site := c.site(base); site != nil {
					names = append(names, strList(site.Value("alt_names"))...)
				}
				c.plannedItems = append(c.plannedItems, plannedItem{lineage: lin, names: names})
			}
			return nil
		}),
		{Name: "DNS readiness per target", Build: func(*engine.Run) (engine.Resource, error) {
			loop := &engine.Multi{Desc: "dig per target"}
			c.checks = nil
			for _, item := range c.plannedItems {
				script := strings.Replace(dnsCheck, "{{ names | map('quote') | join(' ') }}", quoteAll(item.names), 1)
				script = strings.Replace(script, "{{ acme_resolvers | map('quote') | join(' ') }}", quoteAll(resolvers), 1)
				cmd := &engine.Command{Argv: []string{"/bin/bash", "-c", script}}
				c.checks = append(c.checks, cmd)
				loop.Items = append(loop.Items, cmd)
			}
			return loop, nil
		}},
		fact("Compute ready/not-ready lineages", nil, func() error {
			c.ready = nil
			for i, cmd := range c.checks {
				if strings.TrimRight(cmd.Output, "\n") == "1" {
					c.ready = append(c.ready, c.plannedItems[i].lineage)
				}
			}
			return nil
		}),
		fact("Build issue target lists in the original shape", nil, func() error {
			c.issueExplicit, c.issueSingle = nil, nil
			for _, lin := range c.targetsExplicit {
				if contains(c.ready, lin) {
					c.issueExplicit = append(c.issueExplicit, lin)
				}
			}
			for _, lin := range c.targetsSingle {
				if contains(c.ready, lin) {
					c.issueSingle = append(c.issueSingle, lin)
				}
			}
			return nil
		}),
		fact("Compute issue_targets_count", nil, func() error {
			c.count = len(c.issueExplicit) + len(c.issueSingle)
			b.Set.SetFact("issue_targets_count", strconv.Itoa(c.count))
			return nil
		}),
		{Name: "Show DNS readiness summary", Build: func(*engine.Run) (engine.Resource, error) {
			var notReady []string
			for _, item := range c.plannedItems {
				if !contains(c.ready, item.lineage) {
					notReady = append(notReady, item.lineage)
				}
			}
			return report(fmt.Sprintf("DNS-ready: %v; Not ready: %v; Will issue count: %d", c.ready, notReady, c.count)), nil
		}},
	}

	// The block (NAT on, issue, assemble) and its always: (NAT off).
	c.port = &engine.Command{Argv: []string{"ss", "-Hltn", "sport", "=", ":8000"}}
	c.ipt4 = &engine.Command{Argv: []string{"iptables", "-t", "nat", "-C", "PREROUTING", "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", "8000"}, IgnoreErrors: true}
	c.ip6 = &engine.Command{Argv: []string{"bash", "-lc", "command -v ip6tables >/dev/null && echo yes || echo no"}}
	c.ipt6 = &engine.Command{Argv: []string{"ip6tables", "-t", "nat", "-C", "PREROUTING", "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", "8000"}, IgnoreErrors: true}
	dnat := func(r *engine.Run) bool { return issuing(r) && c.bootstrap }
	v6 := func(r *engine.Run) bool { return dnat(r) && strings.TrimRight(c.ip6.Output, "\n") == "yes" && ipv6 }
	exitIn01 := func(cmd *engine.Command) error {
		if cmd.Code != 0 && cmd.Code != 1 {
			return fmt.Errorf("%s: exit %d", strings.Join(cmd.Argv, " "), cmd.Code)
		}
		return nil
	}
	block := []engine.Step{
		haproxyPresent(b, "Collect service facts"),
		fact("Detect HAProxy presence", nil, func() error { return nil }),
		fact("Decide if DNAT bootstrap is needed", nil, func() error {
			v, err := b.Set.Template("{{ (acme_bootstrap | bool) if (acme_bootstrap is defined and acme_bootstrap is not none) else (not (haproxy_present | bool)) }}")
			if err != nil {
				return err
			}
			c.bootstrap = jinja.Truthy(v)
			return nil
		}),
		{Name: "Ensure port 8000 is FREE (only if we have issue targets)", Resource: c.port},
		{Name: "Fail if 8000 is BUSY", When: func(*engine.Run) bool { return strings.TrimSpace(c.port.Output) != "" },
			Build: func(*engine.Run) (engine.Resource, error) {
				return nil, fmt.Errorf("Port 8000 is in use -- standalone Certbot cannot listen on :8000.")
			}},
		{Name: "Add IPv4 DNAT 80->8000 (check)", When: dnat, Resource: c.ipt4},
		{Name: "Add IPv4 DNAT 80->8000", When: func(r *engine.Run) bool { return dnat(r) && c.ipt4.Code == 1 },
			Build: func(*engine.Run) (engine.Resource, error) {
				if err := exitIn01(c.ipt4); err != nil {
					return nil, err
				}
				return &engine.Command{Argv: []string{"iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", "8000"}, Changes: true}, nil
			}},
		{Name: "Check ip6tables available", When: dnat, Resource: c.ip6},
		{Name: "Add IPv6 DNAT 80->8000 (check)", When: v6, Resource: c.ipt6},
		{Name: "Add IPv6 DNAT 80->8000", When: func(r *engine.Run) bool { return v6(r) && c.ipt6.Code == 1 },
			Build: func(*engine.Run) (engine.Resource, error) {
				if err := exitIn01(c.ipt6); err != nil {
					return nil, err
				}
				return &engine.Command{Argv: []string{"ip6tables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", "8000"}, Changes: true}, nil
			}},
	}
	issue := func(name string, lineages func() []string, keyType func(string) string, siteOf func(string) *pyyaml.Map) engine.Step {
		return engine.Step{Name: name, Build: func(*engine.Run) (engine.Resource, error) {
			loop := &engine.Multi{Desc: "certbot certonly"}
			for _, lin := range lineages() {
				if b.Exists("/etc/letsencrypt/live/"+lin+"/fullchain.pem", false) {
					continue // creates:
				}
				kt := keyType(lin)
				site := siteOf(lin)
				argv := []string{"/snap/bin/certbot", "certonly", "--standalone", "--non-interactive", "--agree-tos", "--email", email,
					"--http-01-port", "8000", "--http-01-address", "0.0.0.0", "--preferred-challenges", "http-01", "--key-type", kt}
				if kt == "rsa" {
					argv = append(argv, "--rsa-key-size", rsaSize)
				}
				if kt == "ecdsa" {
					argv = append(argv, "--elliptic-curve", curve)
				}
				argv = append(argv, "--cert-name", lin, "--keep-until-expiring")
				if site != nil {
					names := append([]string{jinja.Str(site.Value("domain"))}, strList(site.Value("alt_names"))...)
					for _, n := range unique(append(names, strList(site.Value("cert_alt_names"))...)) {
						argv = append(argv, "-d", n)
					}
				}
				loop.Items = append(loop.Items, &engine.Command{Argv: argv, Changes: true})
			}
			return loop, nil
		}}
	}
	block = append(block,
		issue("Issue/renew (explicit key_types, filtered)", func() []string { return c.issueExplicit }, func(lin string) string {
			switch {
			case strings.HasSuffix(lin, "-ecdsa"):
				return "ecdsa"
			case strings.HasSuffix(lin, "-rsa"):
				return "rsa"
			}
			return b.S("{{ cert_key_type }}")
		}, func(lin string) *pyyaml.Map { return c.site(keyTypeSuffix.ReplaceAllString(lin, "")) }),
		issue("Issue/renew (single → default key type, filtered)", func() []string { return c.issueSingle }, func(string) string {
			return b.S("{{ cert_key_type }}")
		}, c.site),
		engine.Step{Name: "Trigger PEM assembly + HAProxy reload", Notify: []string{buildPEMs},
			Resource: &engine.Func{Desc: "notify " + buildPEMs, CheckFn: func(*engine.System) (engine.Change, error) {
				return engine.Change{Needed: true, Summary: "Trigger PEM assembly & HAProxy reload (if present)"}, nil
			}, ApplyFn: func(*engine.System) error { return nil }}},
	)
	for i := range block {
		if block[i].Resource != nil {
			block[i].Resource = &guarded{Resource: block[i].Resource, state: c}
		}
		if build := block[i].Build; build != nil {
			block[i].Build = func(r *engine.Run) (engine.Resource, error) {
				res, err := build(r)
				if err != nil {
					c.failed = err
					return nil, nil
				}
				if res == nil {
					return nil, nil
				}
				return &guarded{Resource: res, state: c}, nil
			}
		}
		block[i].When = andWhen(issuing, block[i].When)
	}
	steps = append(steps, block...)
	always := func(r *engine.Run) bool { return c.count > 0 && c.bootstrap }
	del4 := &delRule{argv: []string{"iptables", "-t", "nat", "-D", "PREROUTING", "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", "8000"}}
	del6 := &delRule{argv: []string{"ip6tables", "-t", "nat", "-D", "PREROUTING", "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", "8000"}}
	return append(steps,
		engine.Step{Name: "Remove IPv4 DNAT 80->8000 (if present)", When: always, Resource: del4},
		// The last always: step also raises the block's failure, if any.
		engine.Step{Name: "Remove IPv6 DNAT 80->8000 (if present)",
			When: func(r *engine.Run) bool { return (always(r) && ipv6) || c.failed != nil },
			Build: func(r *engine.Run) (engine.Resource, error) {
				if !(always(r) && ipv6) {
					return nil, c.failed
				}
				del6.then = c.failed
				return del6, nil
			}},
	)
}

// delRule is the always: section's iptables -D: changed when it removed the
// rule (exit 0), fine when there was none (1), failed otherwise; then is the
// block's failure, raised once the rule is gone.
type delRule struct {
	argv    []string
	then    error
	changed bool
}

func (d *delRule) Describe() string { return "command " + strings.Join(d.argv, " ") }

func (d *delRule) Check(*engine.System) (engine.Change, error) {
	d.changed = false
	return engine.Change{Summary: "runs on apply", Run: true}, nil
}

func (d *delRule) Apply(sys *engine.System, _ engine.Change) error {
	out, code, err := sys.Exec(d.argv[0], d.argv[1:]...)
	if err != nil {
		return err
	}
	if code != 0 && code != 1 {
		return fmt.Errorf("%s: exit %d %s", d.argv[0], code, strings.TrimSpace(out))
	}
	d.changed = code == 0
	return d.then
}

func (d *delRule) Changed() bool { return d.changed }
