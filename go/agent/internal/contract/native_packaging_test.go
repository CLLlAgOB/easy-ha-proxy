package contract

import (
	"strings"
	"testing"

	"easy-ha-proxy/panel/shared/jinja"
	"easy-ha-proxy/panel/shared/pyyaml"
)

// Dual-arch native Rust + Go packaging and the native-only daemon units:
// no switch back to a Python implementation or the Flask panel, the daemon
// environment tokens rendered before the first stage that consumes them,
// the images following the configured channel, and CI assembling both
// architectures' release bundles with their checksums.

// nativePackagingUnits are the daemon units and the native command each
// must run (the Python suite's NATIVE_UNITS).
var nativePackagingUnits = []struct{ template, command string }{
	{"easy-ha-proxy-guardd.service.j2", "guardd-core') }} serve"},
	{"haproxy-healthd.service.j2", "easy-ha-proxy-agent') }} healthd"},
	{"easy-ha-proxy-metricsd.service.j2", "easy-ha-proxy-agent') }} metricsd"},
	{"easy-ha-proxy-alertd.service.j2", "easy-ha-proxy-agent') }} alertd"},
	{"haproxy-controld.service.j2", "easy-ha-proxy-agent') }} controld"},
	{"haproxy-certd.service.j2", "easy-ha-proxy-agent') }} certd"},
	{"easy-ha-proxy-backupd.service.j2", "easy-ha-proxy-agent') }} backupd"},
	{"easy-ha-proxy-updated.service.j2", "easy-ha-proxy-agent') }} updated"},
}

func nativePackagingDefaults(t *testing.T) *pyyaml.Map {
	t.Helper()
	v, err := pyyaml.Load([]byte(read(t, "ansible/roles/haproxy-admin/defaults/main.yml")))
	if err != nil {
		t.Fatal(err)
	}
	defaults, ok := v.(*pyyaml.Map)
	if !ok {
		t.Fatal("the haproxy-admin defaults are not a mapping")
	}
	return defaults
}

// The native binaries are the only implementation: every daemon unit runs
// one, and no default switches back to Python or the Flask panel.
func TestTheNativeBinariesAreTheOnlyImplementation(t *testing.T) {
	defaults := nativePackagingDefaults(t)
	if got := defaults.Value("native_agent_bin"); got != "/usr/local/sbin/easy-ha-proxy-agent" {
		t.Errorf("native_agent_bin %v", got)
	}
	if got := defaults.Value("native_guardd_bin"); got != "/usr/local/sbin/guardd-core" {
		t.Errorf("native_guardd_bin %v", got)
	}
	// No switch back to a Python implementation or the Flask panel.
	defaults.Each(func(key, _ any) {
		name, _ := key.(string)
		if strings.HasPrefix(name, "native_") && strings.HasSuffix(name, "_enabled") {
			t.Errorf("a native implementation switch remains: %s", name)
		}
	})
	for _, gone := range []string{"haproxy_admin_use_go_panel", "native_guardd_lib"} {
		if _, ok := defaults.Get(gone); ok {
			t.Errorf("%s is still a default", gone)
		}
	}
	for _, unit := range nativePackagingUnits {
		t.Run(unit.template, func(t *testing.T) {
			text := read(t, unitDir+"/"+unit.template)
			mustContain(t, text, unit.command, unit.template)
			for _, unwanted := range []string{"python3", "EASY_HA_PROXY_DAEMON_VERSION"} {
				if strings.Contains(text, unwanted) {
					t.Errorf("%s holds %q", unit.template, unwanted)
				}
			}
		})
	}

	compose := read(t, unitDir+"/docker-compose.yml.j2")
	mustContain(t, compose, `image: "{{ haproxy_admin_go_image }}"`, "docker-compose.yml.j2")
	mustContain(t, compose, "/usr/local/bin/easy-ha-proxy-panel", "docker-compose.yml.j2")
	if strings.Contains(compose, "python") {
		t.Error("docker-compose.yml.j2 holds python")
	}

	installer := read(t, agentInternal+"/cli/config.go")
	for _, bundle := range []string{"InstallTags", "UpdateTags", "UITags", "DaemonTags", "HostServiceTags"} {
		mustContain(t, installer, bundle, "cli/config.go")
	}
	if n := strings.Count(installer, "ha-adm-native"); n < 5 {
		t.Errorf("cli/config.go names ha-adm-native %d times, want at least 5", n)
	}
}

// daemons_env renders the daemon tokens before any stage consumes them,
// and carries every tag those consumer stages run under.
func TestDaemonTokensAreRenderedBeforeTheFirstConsumer(t *testing.T) {
	v, err := pyyaml.Load([]byte(read(t, "ansible/easy-ha-proxy.yml")))
	if err != nil {
		t.Fatal(err)
	}
	plays, ok := v.([]any)
	if !ok {
		t.Fatal("the playbook is not a list of plays")
	}
	var roles []*pyyaml.Map
	var stages []string
	for _, p := range plays {
		play, ok := p.(*pyyaml.Map)
		if !ok {
			t.Fatal("a play is not a mapping")
		}
		list, _ := play.Value("roles").([]any)
		for _, entry := range list {
			role, ok := entry.(*pyyaml.Map)
			if ok && role.Value("role") == "haproxy-admin" {
				roles = append(roles, role)
				stage, _ := role.Value("task_stage").(string)
				stages = append(stages, stage)
			}
		}
	}
	indexOf := func(name string) int {
		for i, s := range stages {
			if s == name {
				return i
			}
		}
		t.Fatalf("no haproxy-admin stage %q", name)
		return -1
	}
	stage := indexOf("daemons_env")
	// set(roles[stage]["tags"]): a list of tags; a bare string would be
	// iterated character by character, as Python's set(str) does.
	stageTags := map[string]bool{}
	switch v := roles[stage].Value("tags").(type) {
	case []any:
		for _, tag := range v {
			stageTags[tag.(string)] = true
		}
	case string:
		for _, r := range v {
			stageTags[string(r)] = true
		}
	default:
		t.Fatalf("daemons_env tags %v", v)
	}
	for _, consumer := range []string{"install", "daemons", "healthd", "controld", "backupd",
		"updated", "alertd", "metricsd", "guardd"} {
		pos := indexOf(consumer)
		if stage >= pos {
			t.Errorf("%s runs at %d, not after daemons_env at %d", consumer, pos, stage)
		}
		var tags []any
		switch v := roles[pos].Value("tags").(type) {
		case string:
			tags = []any{v}
		case []any:
			tags = v
		default:
			t.Fatalf("%s tags %v", consumer, v)
		}
		for _, tag := range tags {
			name := tag.(string)
			if name != "never" && !stageTags[name] {
				t.Errorf("%s tag %q is not rendered by daemons_env", consumer, name)
			}
		}
	}
}

// The go panel and native release images take their tag from the channel
// the configured panel image ends in.
func TestNativeImagesFollowTheConfiguredChannel(t *testing.T) {
	defaults := nativePackagingDefaults(t)
	env := jinja.NewEnvironment(nil)
	env.Autoescape = false
	env.Filters["regex_replace"] = jinja.RegexReplaceFilter
	for _, channel := range []string{"alpha", "latest"} {
		t.Run(channel, func(t *testing.T) {
			context := map[string]any{"haproxy_admin_image": "registry.example:5000/panel:" + channel}
			render := func(key string) string {
				src, ok := defaults.Value(key).(string)
				if !ok {
					t.Fatalf("%s is not a string default", key)
				}
				tmpl, err := env.FromString(key, src)
				if err != nil {
					t.Fatal(err)
				}
				out, err := env.RenderTemplate(tmpl, context)
				if err != nil {
					t.Fatal(err)
				}
				return out
			}
			context["haproxy_admin_image_channel"] = render("haproxy_admin_image_channel")
			if got, want := render("haproxy_admin_go_image"), "registry.example:5000/panel:go-"+channel; got != want {
				t.Errorf("go image %q, want %q", got, want)
			}
			if got, want := render("native_release_image"), "clllagob/haproxy-admin-ui:native-"+channel; got != want {
				t.Errorf("native release image %q, want %q", got, want)
			}
		})
	}
}

// CI builds both architectures, checks the bundles' checksums, and only
// publishes the images from jobs that tested and scanned them.
func TestCIAssemblesDualArchNativeReleaseBundlesWithSHA256(t *testing.T) {
	jobs := ciJobs(t)
	for _, name := range []string{"rust-guardd", "go-agent", "go-panel", "go-panel-image", "native-release-image"} {
		if _, ok := jobs.Get(name); !ok {
			t.Errorf("no job %s", name)
		}
	}
	goImg := ciJob(t, jobs, "go-panel-image")
	needs := needsOf(goImg)
	for _, check := range []string{"go-panel", "go-parity", "go-vulnerabilities", "javascript", "secrets"} {
		if !needs[check] {
			t.Errorf("go-panel-image does not need %s", check)
		}
	}
	imageNeeds := needsOf(ciJob(t, jobs, "native-release-image"))
	for _, check := range []string{"go-vulnerabilities", "rust-vulnerabilities", "go-parity"} {
		if !imageNeeds[check] {
			t.Errorf("native-release-image does not need %s", check)
		}
	}
	parity := ciJob(t, jobs, "go-parity")
	parityNeeds := needsOf(parity)
	if len(parityNeeds) != 3 || !parityNeeds["go-panel"] || !parityNeeds["go-agent"] || !parityNeeds["rust-guardd"] {
		t.Errorf("go-parity needs %v, want go-panel, go-agent and rust-guardd", parityNeeds)
	}
	archs := map[string]bool{}
	include, _ := parity.Value("strategy").(*pyyaml.Map).Value("matrix").(*pyyaml.Map).Value("include").([]any)
	for _, item := range include {
		arch, _ := item.(*pyyaml.Map).Value("arch").(string)
		archs[arch] = true
	}
	if len(archs) != 2 || !archs["amd64"] || !archs["arm64"] {
		t.Errorf("go-parity archs %v, want amd64 and arm64", archs)
	}
	publish := runOf(ciStep(t, goImg, "Publish Go panel image"))
	mustContain(t, publish, "--platform linux/amd64,linux/arm64", "Publish Go panel image")
	mustContain(t, publish, "-f go/panel/Dockerfile", "Publish Go panel image")
	for _, name := range []string{"go-agent", "native-release"} {
		if _, ok := jobs.Get(name); !ok {
			t.Errorf("no job %s", name)
		}
	}
	release := ciJob(t, jobs, "native-release")
	releaseNeeds := needsOf(release)
	if len(releaseNeeds) != 2 || !releaseNeeds["rust-guardd"] || !releaseNeeds["go-agent"] {
		t.Errorf("native-release needs %v, want rust-guardd and go-agent", releaseNeeds)
	}
	// The first step whose name mentions tarballs assembles the bundles.
	var assemble string
	found := false
	steps, _ := release.Value("steps").([]any)
	for _, s := range steps {
		step, ok := s.(*pyyaml.Map)
		if !ok {
			continue
		}
		name, _ := step.Value("name").(string)
		if strings.Contains(name, "tarballs") {
			assemble, found = runOf(step), true
			break
		}
	}
	if !found {
		t.Fatal("native-release has no tarballs step")
	}
	for _, want := range []string{
		"for arch in amd64 arm64",
		"easy-ha-proxy-native-linux-${arch}.tar.gz",
		"sha256sum -c SHA256SUMS",
	} {
		mustContain(t, assemble, want, "native-release tarballs")
	}
}
