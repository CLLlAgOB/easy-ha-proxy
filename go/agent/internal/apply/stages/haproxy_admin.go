package stages

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"easy-ha-proxy/panel/shared/jinja"
	"easy-ha-proxy/panel/shared/pyyaml"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/engine"
)

// The panel's own stages of roles/haproxy-admin: its account (getuseruid),
// the packages and directories install.yml imports before the daemons, the
// configuration and Compose file (config), bringing the stack up (start),
// and the native binaries with the cleanup of the former Python daemons.
func init() {
	register(Stage{Name: "haproxy-admin", Parts: []Part{
		{Name: "native", Role: "haproxy-admin", Build: adminNative},
		{Name: "getuseruid", Role: "haproxy-admin", Build: getuseruid,
			Facts: []string{"hadmin_gid", "haproxy_admin_uid", "haproxy_admin_gid"}},
		{Name: "packages", Role: "haproxy-admin", Build: adminPackages},
		{Name: "fs", Role: "haproxy-admin", Build: adminFS},
		{Name: "config", Role: "haproxy-admin", Build: adminConfig},
		{Name: "start", Role: "haproxy-admin", Build: adminStart},
		{Name: "native-cleanup", Role: "haproxy-admin", Build: adminNativeCleanup},
		{Name: "update_haproxy_admin", Role: "haproxy-admin", Build: adminImageUpdate},
	}})
}

// pyJSON is json.dumps of a string (ensure_ascii), what to_json gives.
func pyJSON(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r < 0x20 || (r >= 0x7f && r < 0x10000):
			fmt.Fprintf(&b, `\u%04x`, r)
		case r >= 0x10000:
			hi, lo := utf16.EncodeRune(r)
			fmt.Fprintf(&b, `\u%04x\u%04x`, hi, lo)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func getuseruid(b *Builder) []engine.Step {
	docker := b.Bool("{{ haproxy_admin_use_docker | bool }}")
	on := func(*engine.Run) bool { return docker }
	group, user := b.S("{{ app_group }}"), b.S("{{ app_user }}")
	gent := &engine.Command{Argv: []string{"getent", "group", group}, Probe: true}
	uid := &engine.Command{Argv: []string{"id", "-u", user}, Probe: true}
	gid := &engine.Command{Argv: []string{"id", "-g", user}, Probe: true}
	return []engine.Step{
		{Name: "hadmin | Ensure group exists", When: on, Resource: &engine.Group{Name: group, System: true}},
		{Name: "haproxyadmin | Ensure user exists", When: on,
			Resource: &engine.User{Name: user, Group: group, Shell: "/usr/sbin/nologin", System: true, NoHome: true}},
		{Name: "hadmin | Get group GID via getent", When: on, Resource: gent},
		fact("hadmin | Set hadmin_gid fact", on, func() error {
			fields := strings.Split(gent.Output, ":")
			if len(fields) < 3 {
				return fmt.Errorf("getent group %s: %q", group, gent.Output)
			}
			b.Set.SetFact("hadmin_gid", strings.TrimSpace(fields[2]))
			return nil
		}),
		{Name: "haproxyadmin | Get UID via id -u", When: on, Resource: uid},
		{Name: "haproxyadmin | Get GID via id -g", When: on, Resource: gid},
		fact("haproxyadmin | Set haproxy_admin_uid/gid facts", on, func() error {
			b.Set.SetFact("haproxy_admin_uid", strings.TrimSpace(uid.Output))
			b.Set.SetFact("haproxy_admin_gid", strings.TrimSpace(gid.Output))
			return nil
		}),
	}
}

// adminPackages transcribes packages.yml: the haproxy role's package.yml
// (with protection.yml), then the panel's packages; install.yml tags it all
// restore-network.
func adminPackages(b *Builder) []engine.Step {
	steps := append(haproxyPackage(b), engine.Step{Name: "Install required panel packages",
		Resource: &engine.AptInstall{Names: []string{"openssl", "socat", "ipset", "iptables", "iptables-persistent"},
			UpdateCache: true, CacheValid: b.aptValid()}})
	return withTags(steps, "restore-network")
}

func adminFS(b *Builder) []engine.Step {
	user, group := "{{ app_user }}", "{{ app_group }}"
	docker := b.Bool("{{ haproxy_admin_use_docker | bool }}")
	geo := b.Bool("{{ geo_ip_dir is defined and geo_ip_dir|length > 0 }}")
	whitelist := b.S("{{ whitelist_global_file }}")
	return []engine.Step{
		{Name: "Ensure private runtime directory exists", Resource: b.Dir("/run/easy-ha-proxy", "root", group, "0750")},
		{Name: "Ensure app dir exists", Resource: b.Dir("{{ app_dir }}", user, group, "0755")},
		{Name: "Ensure audit dir exists",
			Resource: b.Dir("{{ (audit_database_path | default('/var/lib/easy-ha-proxy/audit/audit.db')) | dirname }}", user, group, "0770")},
		{Name: "Ensure app config dir exists", Resource: b.Dir("{{ app_dir }}/config", user, group, "0755")},
		{Name: "Ensure backups dir exists", Resource: b.Dir("{{ app_dir }}/backups", user, group, "0755")},
		{Name: "Ensure the local GeoIP data directory exists", When: func(*engine.Run) bool { return geo },
			Resource: b.Dir("{{ geo_ip_dir | default('') }}", "root", "haproxy", "0755")},
		{Name: "Ensure whitelist.geo exists",
			Resource: &engine.Attrs{Path: b.S("{{ whitelist_geo_file }}"), Owner: b.S(user), Group: b.S(group), Mode: b.Mode("0644")}},
		{Name: "Create whitelist_global_file if it does not exist", When: func(*engine.Run) bool { return !b.Exists(whitelist, false) },
			Resource: &engine.Touch{Path: whitelist, Owner: b.S(user), Group: b.S(group), Mode: b.Mode("0644")}},
		{Name: "Ensure data dir exists (for container)", When: func(*engine.Run) bool { return docker },
			Resource: b.Dir("{{ haproxy_admin_data_dir }}", user, group, "0750")},
	}
}

func adminConfig(b *Builder) []engine.Step {
	user, group := "{{ app_user }}", "{{ app_group }}"
	owner, grp := b.S(user), b.S(group)
	docker := b.Bool("{{ haproxy_admin_use_docker | bool }}")
	onDocker := func(*engine.Run) bool { return docker }
	geo := b.Bool("{{ geo_ip_dir is defined and geo_ip_dir|length > 0 }}")
	sync := b.Bool("{{ haproxy_admin_sync_managed_config | default(false) | bool }}")
	appDir := b.S("{{ app_dir }}")
	vars := filepath.Join(appDir, "config", "vars.yml")
	managed := b.S("{{ easy_ha_proxy_config_dir | default(playbook_dir) }}")
	configDir := b.S("{{ easy_ha_proxy_config_dir | default('') }}")
	nbthread := b.S(`{{ haproxy_nbthread | default([[ansible_processor_vcpus | default(1) | int, 1] | max, [haproxy_nbthread_max | default(2) | int, 1] | max] | min, true) | int }}`)
	audit := b.S("{{ audit_database_path | default('/var/lib/easy-ha-proxy/audit/audit.db') }}")
	root := b.S("{{ haproxy_admin_root_dir }}")
	mode := b.Mode("0644")

	steps := []engine.Step{
		{Name: "Ensure app dir", Resource: b.Dir("{{ app_dir }}", user, group, "0755")},
		{Name: "Ensure app config dir", Resource: b.Dir("{{ app_dir }}/config", user, group, "0755")},
		{Name: "Ensure backups dir", Resource: b.Dir("{{ app_dir }}/backups", user, group, "0755")},
		{Name: "Ensure the local GeoIP data directory exists", When: func(*engine.Run) bool { return geo },
			Resource: b.Dir("{{ geo_ip_dir | default('') }}", "root", "haproxy", "0755")},
		{Name: "haproxy-admin | Render .env for app", Register: "hapadm_env_t",
			Build: b.Template("haproxy-admin.env.j2", "{{ haproxy_admin_env_file }}", "root", group, "0640")},
		{Name: "Sync haproxy.cfg.j2",
			Build: b.CopySrc("{{ playbook_dir }}/roles/haproxy/templates/haproxy.cfg.j2", "{{ app_dir }}/config/haproxy.cfg.j2", user, group, "0644")},
	}
	for _, name := range runtimeSources {
		steps = append(steps, engine.Step{Name: "Seed runtime config from the managed config (only if missing)",
			Build: b.CopySrc(filepath.Join(managed, name), filepath.Join(appDir, "config", name), user, group, "0644", NoForce)})
	}
	for _, name := range runtimeSources {
		steps = append(steps, engine.Step{Name: "Sync control-plane runtime config when explicitly requested",
			When:  func(*engine.Run) bool { return sync },
			Build: b.CopySrc(filepath.Join(configDir, name), filepath.Join(appDir, "config", name), user, group, "0644")})
	}
	for _, kv := range [][2]string{
		{"haproxy_socket", b.S("{{ haproxy_socket | default('/run/haproxy/admin.sock', true) }}")},
		{"haproxy_socket_group", b.S("{{ haproxy_socket_group | default('hadmin', true) }}")},
	} {
		steps = append(steps, engine.Step{Name: "Persist managed HAProxy runtime socket values",
			Resource: &engine.LineInFile{Path: vars, Regexp: regexp.MustCompile(`^\s*` + regexp.QuoteMeta(kv[0]) + `\s*:`),
				Line: kv[0] + ": " + pyJSON(kv[1]), Same: sameYAMLLine, Owner: owner, Group: grp, Mode: mode}})
	}
	steps = append(steps,
		fact("Calculate effective HAProxy thread count for the UI renderer", nil, func() error {
			b.Set.SetFact("haproxy_effective_nbthread", nbthread)
			return nil
		}),
		engine.Step{Name: "Persist effective HAProxy thread count in runtime vars",
			Resource: &engine.LineInFile{Path: vars, Regexp: regexp.MustCompile(`^\s*haproxy_nbthread\s*:`),
				Line: "haproxy_nbthread: " + nbthread, Same: sameYAMLLine, Owner: owner, Group: grp, Mode: mode}},
		engine.Step{Name: "haproxy-admin | Ensure data dir exists (for container)", When: onDocker,
			Resource: b.Dir("{{ haproxy_admin_data_dir }}", user, group, "0750")},
	)
	for _, dir := range []string{b.S("{{ haproxy_admin_data_dir }}"), root + "/config", root + "/backups"} {
		steps = append(steps, engine.Step{Name: "haproxy-admin | Restore ownership of writable tree after backup restore",
			When: onDocker, Resource: &engine.Tree{Path: dir, Owner: owner, Group: grp}})
	}
	steps = append(steps, engine.Step{Name: "haproxy-admin | Ensure change log directory exists", When: onDocker,
		Resource: b.Dir(filepath.Dir(audit), user, group, "0770")})
	for _, path := range []string{audit, audit + "-wal", audit + "-shm"} {
		steps = append(steps, engine.Step{Name: "haproxy-admin | Give restored change log files to the panel",
			When: func(*engine.Run) bool {
				fi, err := os.Lstat(b.Sys.Path(path))
				return docker && err == nil && fi.Mode().IsRegular()
			},
			Resource: &engine.Attrs{Path: path, Owner: owner, Group: grp}})
	}
	return append(steps,
		engine.Step{Name: "haproxy-admin | Render docker-compose.yml", When: onDocker, Register: "hapadm_compose_t",
			Build: b.Template("docker-compose.yml.j2", "{{ haproxy_admin_root_dir }}/docker-compose.yml", "root", group, "0640")},
		fact("haproxy-admin | Mark configs changed", onDocker, func() error { return nil }),
	)
}

// composeChanged is the up task's changed_when.
var composeChanged = regexp.MustCompile(`(?i)(creating|created|recreating|recreated|starting|started|removing|removed)`)

func adminStart(b *Builder) []engine.Step {
	docker := b.Bool("{{ haproxy_admin_use_docker | bool }}")
	onDocker := func(*engine.Run) bool { return docker }
	root := b.S("{{ haproxy_admin_root_dir }}")
	env := []string{"COMPOSE_PROGRESS=plain", "DOCKER_CLI_HINTS=false"}
	up := b.List(`{{ ['timeout', haproxy_admin_compose_up_timeout | int | string, 'docker', 'compose', 'up', '--detach', '--remove-orphans']` +
		` + (['--pull', 'never'] if easy_ha_proxy_offline_restore | default(false) | bool else [])` +
		` + (['--force-recreate'] if haproxy_admin_force_recreate | default(false) | bool else []) }}`)
	container := b.S("{{ haproxy_admin_container_name }}")
	wait, _ := strconv.Atoi(b.S("{{ haproxy_admin_start_wait_timeout | int }}"))
	tries := wait / 5
	if tries < 1 {
		tries = 1
	}
	steps := []engine.Step{}
	for _, unit := range []string{"haproxy-controld", "haproxy-certd"} {
		steps = append(steps, engine.Step{Name: "Start core services via systemd", Resource: Unit(unit, engine.Bool(true), "started")})
	}
	return append(steps,
		engine.Step{Name: "haproxy-admin | docker compose pull", When: onDocker, Tags: []string{"restore-network"},
			Resource: &engine.Command{Argv: []string{"timeout", b.S("{{ haproxy_admin_compose_pull_timeout | int | string }}"),
				"docker", "compose", "pull", "--quiet"}, Dir: root, Env: env, Retries: 3, Delay: 20 * time.Second}},
		engine.Step{Name: "haproxy-admin | docker compose up", When: onDocker,
			Resource: &engine.Command{Argv: up, Dir: root, Env: env, MergeStderr: true, Retries: 2, Delay: 10 * time.Second,
				ChangedWhen: func(out string, _ int) bool { return composeChanged.MatchString(out) }}},
		engine.Step{Name: "haproxy-admin | Read container health status", When: onDocker,
			Resource: &engine.Func{Desc: "container health " + container, CheckFn: func(sys *engine.System) (engine.Change, error) {
				return engine.Change{Summary: "healthy"}, waitHealthy(sys, container, tries, wait)
			}}},
		engine.Step{Name: "haproxy-admin | Remove the legacy external GeoIP JSON cache", When: onDocker,
			Resource: &engine.Absent{Path: root + "/backups/country_cache.json"}},
	)
}

// healthDelay is the health read's delay between tries (a test shortens it).
var healthDelay = 5 * time.Second

// waitHealthy is wait_haproxy_admin_healthy.yml: the container's health read
// until it is healthy (in plan mode too: reading changes nothing), and on
// giving up its health details in the failure, as the rescue reports them.
func waitHealthy(sys *engine.System, container string, tries, wait int) error {
	var last string
	for attempt := 0; attempt <= tries; attempt++ {
		if attempt > 0 {
			time.Sleep(healthDelay)
		}
		out, code, err := sys.Exec("docker", "container", "inspect", "--format",
			"{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}", container)
		if err == nil && code == 0 && strings.TrimSpace(out) == "healthy" {
			return nil
		}
		last = strings.TrimSpace(out)
	}
	details, _, _ := sys.Exec("docker", "container", "inspect", "--format", "{{json .State.Health}}", container)
	if strings.TrimSpace(details) == "" {
		details = last
		if details == "" {
			details = "unavailable"
		}
	}
	return fmt.Errorf("The %s container did not become healthy within %d seconds. Docker health details: %s",
		container, wait, strings.TrimSpace(details))
}

func adminNativeCleanup(b *Builder) []engine.Step {
	return []engine.Step{
		{Name: "native-cleanup | Remove the former Python daemons once no installed unit names them",
			Build: func(*engine.Run) (engine.Resource, error) {
				quoted := make([]string, len(nativeLegacyPaths))
				for i, p := range nativeLegacyPaths {
					q, _ := jinja.AnsibleQuote(nil, p, nil, nil)
					quoted[i] = q.(string)
				}
				script := strings.Replace(nativeCleanup, "{{ native_legacy_paths | map('quote') | join(' ') }}", strings.Join(quoted, " "), 1)
				return &engine.Command{Argv: []string{"/bin/bash", "-c", script},
					ChangedWhen: func(out string, _ int) bool { return strings.Contains(out, "removed:") }}, nil
			}},
	}
}

// adminNative transcribes native.yml: the release bundle (a local tarball,
// HTTPS with a pinned checksum, or the OCI image CI tagged with this
// revision), smoke checks, the two binaries replaced together (the first put
// back if the second fails), and the restarts that pick them up.
func adminNative(b *Builder) []engine.Step {
	stage := "/var/lib/easy-ha-proxy/native-staging"
	arch := map[string]string{"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}[b.S("{{ ansible_architecture }}")]
	bundle := stage + "/easy-ha-proxy-native-linux-" + arch + ".tar.gz"
	mode := "none"
	switch {
	case b.S("{{ native_local_bundle_dir | default('') }}") != "":
		mode = "local"
	case b.S("{{ native_release_base_url | default('') }}") != "":
		mode = "https"
	case b.S("{{ native_release_image | default('') }}") != "":
		mode = "oci"
	}
	is := func(modes ...string) func(*engine.Run) bool {
		return func(*engine.Run) bool {
			for _, m := range modes {
				if mode == m {
					return true
				}
			}
			return false
		}
	}
	offline := b.Bool("{{ easy_ha_proxy_offline_restore | default(false) | bool }}")
	pin := b.Bool("{{ native_release_pin_revision | default(true) | bool }}")
	checksum := ""
	if mode == "https" {
		// Index by the Go arch computed above, not the _native_arch fact: the
		// fact step runs later, so rendering _native_arch here would always be
		// empty and the HTTPS checksum validation would always fail.
		checksum = b.S("{{ native_release_checksums['" + arch + "'] | default('') }}")
	}
	source := b.S("{{ playbook_dir | dirname }}")
	revision := &engine.Command{Argv: []string{"/bin/bash", "-c",
		`source "$1/installer/agent-fetch.sh" && easy_ha_proxy_source_revision "$1"`, "source-revision", source},
		Probe: true, IgnoreErrors: true}
	agentDest := b.S("{{ native_agent_bin | default('/usr/local/sbin/easy-ha-proxy-agent') }}")
	guarddDest := b.S("{{ native_guardd_bin | default('/usr/local/sbin/guardd-core') }}")
	files := []struct{ source, dest, register string }{
		{"sbin/easy-ha-proxy-agent", agentDest, "_native_agent_copy"},
		{"sbin/guardd-core", guarddDest, "_native_guardd_copy"},
	}
	install := &nativeFiles{}
	agentChanged := Changed("_native_agent_copy")
	group := b.S("{{ app_group }}")
	restoreMarker := b.S("{{ backupd_restore_active_marker }}")
	updateMarker := b.S("{{ updated_active_marker | default('/run/easy-ha-proxy/easy-ha-proxy-update.active') }}")

	steps := []engine.Step{
		fact("native-daemons | Map host architecture to release arch", nil, func() error {
			b.Set.SetFact("_native_arch", arch)
			return nil
		}),
		assertStep("native-daemons | Require supported architecture (amd64 or arm64)",
			func(*engine.Run) bool { return arch == "amd64" || arch == "arm64" },
			fmt.Sprintf("Unsupported host architecture '%s' for native easy-ha-proxy binaries (supported: x86_64, aarch64).", b.S("{{ ansible_architecture }}"))),
		fact("native-daemons | Select delivery mode", nil, func() error {
			b.Set.SetFact("_native_mode", mode)
			return nil
		}),
		assertStep("native-daemons | Validate configured delivery source", func(*engine.Run) bool {
			if mode == "none" {
				return false
			}
			return mode != "https" || (strings.HasPrefix(b.S("{{ native_release_base_url | default('') }}"), "https://") &&
				regexp.MustCompile(`^[0-9a-fA-F]{64}$`).MatchString(checksum))
		}, "Configure native_release_image, native_local_bundle_dir, or both an https:// native_release_base_url and a 64-hex SHA-256 entry in native_release_checksums['"+arch+"']."),
		{Name: "native-daemons | Ensure the staging directory exists", Resource: b.Dir(stage, "root", "root", "0755")},
		{Name: "native-daemons | Copy local release bundle when configured", When: is("local"),
			Build: func(r *engine.Run) (engine.Resource, error) {
				return b.CopySrc("{{ native_local_bundle_dir }}/easy-ha-proxy-native-linux-"+arch+".tar.gz", bundle, "root", "root", "0600")(r)
			}},
		{Name: "native-daemons | Download and SHA-256 verify release bundle over HTTPS",
			When: func(r *engine.Run) bool { return mode == "https" && !offline },
			Build: func(*engine.Run) (engine.Resource, error) {
				base := strings.TrimRight(b.S("{{ native_release_base_url }}"), "/")
				return &engine.GetURL{URL: base + "/easy-ha-proxy-native-linux-" + arch + ".tar.gz", Dest: bundle,
					SHA256: strings.ToLower(checksum), Owner: "root", Group: "root", Mode: 0o600}, nil
			}},
		assertStep("Require the configured release checksum", func(*engine.Run) bool {
			if mode != "https" || !offline {
				return true
			}
			fi, err := os.Lstat(b.Sys.Path(bundle))
			if err != nil || !fi.Mode().IsRegular() {
				return false
			}
			sum, err := fileSHA256(b.Sys.Path(bundle))
			return err == nil && sum == strings.ToLower(checksum)
		}, "Prepare the verified native release bundle on this host before offline restore."),
	}
	for _, dir := range []string{"sbin", "lib"} {
		steps = append(steps, engine.Step{Name: "native-daemons | Clear previous staged files before unpacking tarball bundle",
			When: is("local", "https"), Resource: &engine.Absent{Path: stage + "/" + dir}})
	}
	pull := &engine.Command{ChangedWhen: func(out string, _ int) bool { return strings.Contains(out, "NATIVE_BUNDLE_CHANGED") }}
	steps = append(steps,
		engine.Step{Name: "native-daemons | Unpack tarball bundle into staging directory", When: is("local", "https"),
			Resource: &engine.Command{Argv: []string{"tar", "-xzf", bundle, "-C", stage}, Changes: true}},
		engine.Step{Name: "native-daemons | Read the source revision being installed",
			When: func(*engine.Run) bool { return mode == "oci" && pin }, Resource: revision},
		engine.Step{Name: "native-daemons | Pull and verify native binary bundle from OCI image", When: is("oci"),
			Build: func(*engine.Run) (engine.Resource, error) {
				result := pyyaml.NewMap()
				if mode == "oci" && pin {
					result.Set("stdout", revision.Output)
					result.Set("rc", int64(revision.Code))
				} else {
					result.Set("skipped", true)
				}
				b.Set.SetFact("_native_source_revision", result)
				script, err := b.Set.Render(nativeOCIPull)
				if err != nil {
					return nil, err
				}
				pull.Argv = []string{"/bin/bash", "-c", script}
				return pull, nil
			}},
		engine.Step{Name: "native-daemons | Smoke-check easy-ha-proxy-agent binary",
			Resource: &engine.Command{Argv: []string{stage + "/sbin/easy-ha-proxy-agent", "version"}}},
		engine.Step{Name: "native-daemons | Smoke-check guardd-core binary", Resource: &engine.Func{Desc: "guardd-core --help",
			CheckFn: func(*engine.System) (engine.Change, error) {
				return engine.Change{Summary: "runs on apply", Run: true}, nil
			},
			ApplyFn: func(sys *engine.System) error {
				out, code, err := sys.Exec("/bin/sh", "-c", `exec "$0" --help 2>&1`, stage+"/sbin/guardd-core")
				if err != nil {
					return err
				}
				if code != 0 && !strings.Contains(out, "usage: guardd-core") {
					return fmt.Errorf("guardd-core --help: exit %d %s", code, strings.TrimSpace(out))
				}
				return nil
			}}},
		assertStep("Require regular files at existing installation paths", func(*engine.Run) bool {
			for _, f := range files {
				if fi, err := os.Lstat(b.Sys.Path(f.dest)); err == nil && !fi.Mode().IsRegular() {
					return false
				}
			}
			return true
		}, "Assertion failed: an existing native installation path is not a regular file."),
	)
	for _, f := range files {
		f := f
		steps = append(steps, engine.Step{Name: "Replace the verified native files", Register: f.register,
			Build: func(*engine.Run) (engine.Resource, error) {
				raw, err := os.ReadFile(b.Sys.Path(stage + "/" + f.source))
				if err != nil {
					return nil, install.fail(err)
				}
				return &nativeFile{File: engine.File{Path: f.dest, Content: raw, Owner: "root", Group: "root", Mode: 0o755}, set: install}, nil
			}})
	}
	steps = append(steps,
		fact("Remember which daemon binaries were replaced", nil, func() error { return nil }),
		engine.Step{Name: "native-daemons | Remove temporary copies of replaced native files", Resource: &engine.Func{Desc: "backups",
			CheckFn: func(*engine.System) (engine.Change, error) {
				return engine.Change{Needed: len(install.backups) > 0, Summary: fmt.Sprintf("%d backups", len(install.backups))}, nil
			},
			ApplyFn: func(sys *engine.System) error { return install.drop() }}},
		engine.Step{Name: "native-daemons | Restart running daemons that use the replaced agent binary", When: agentChanged,
			Resource: tryRestart(false, "haproxy-healthd.service", "easy-ha-proxy-metricsd.service",
				"easy-ha-proxy-alertd.service", "haproxy-controld.service", "haproxy-certd.service", "authelia-bansd.service",
				"authelia-usersd.service", "authelia-configd.service")},
		engine.Step{Name: "Ask the backup broker to restart after restore cleanup",
			When:     func(r *engine.Run) bool { return agentChanged(r) && b.Exists(restoreMarker, true) },
			Resource: &engine.Touch{Path: b.S("{{ backupd_restart_request_marker }}"), Owner: "root", Group: group, Mode: 0o600}},
		engine.Step{Name: "Restart the running backup broker outside a restore",
			When:     func(r *engine.Run) bool { return agentChanged(r) && !b.Exists(restoreMarker, true) },
			Resource: tryRestart(true, "easy-ha-proxy-backupd.service")},
		engine.Step{Name: "native-daemons | Ask the update broker to restart once its job ends",
			When: func(r *engine.Run) bool { return agentChanged(r) && b.Exists(updateMarker, true) },
			Resource: &engine.Touch{Path: b.S("{{ updated_restart_request_marker | default('/run/easy-ha-proxy/easy-ha-proxy-updated-restart.requested') }}"),
				Owner: "root", Group: b.S("{{ app_group | default('hadmin') }}"), Mode: 0o600}},
		engine.Step{Name: "native-daemons | Restart the update broker on the replaced binary",
			When:     func(r *engine.Run) bool { return agentChanged(r) && !b.Exists(updateMarker, true) },
			Resource: tryRestart(false, "easy-ha-proxy-updated.service")},
		engine.Step{Name: "native-daemons | Restart guardd when its Rust binary was replaced", When: Changed("_native_guardd_copy"),
			Resource: tryRestart(false, "easy-ha-proxy-guardd.service")},
	)
	return steps
}

// tryRestart is the native stage's "systemctl try-restart" over the units
// that exist. try-restart leaves a stopped unit alone, but a unit that is not
// there at all is an error (exit 5) -- and on a fresh host the native stage
// runs before the stages that install the daemons. Like the command task it
// stands for (changed_when: true), it reports a change whenever it runs.
func tryRestart(noBlock bool, units ...string) engine.Resource {
	return &engine.Func{Desc: "systemctl try-restart " + strings.Join(units, " "),
		CheckFn: func(*engine.System) (engine.Change, error) { return engine.Change{Needed: true, Summary: "run"}, nil },
		ApplyFn: func(sys *engine.System) error {
			argv := []string{"try-restart"}
			if noBlock {
				argv = append(argv, "--no-block")
			}
			present := argv
			for _, unit := range units {
				out, code, err := sys.Exec("systemctl", "show", "--property=LoadState", "--value", unit)
				if err != nil {
					return err
				}
				if code == 0 && strings.TrimSpace(out) == "loaded" {
					present = append(present, unit)
				}
			}
			if len(present) == len(argv) {
				return nil
			}
			out, code, err := sys.Exec("systemctl", present...)
			if err == nil && code != 0 {
				err = fmt.Errorf("systemctl %s: exit %d %s", strings.Join(present, " "), code, strings.TrimSpace(out))
			}
			return err
		}}
}

// adminImageUpdate is update_haproxy_admin.yml (ha-adm-update): Docker
// started (either service; a failure is not one), the panel's images pulled,
// the stack brought up, its health waited for.
func adminImageUpdate(b *Builder) []engine.Step {
	dir := b.S("{{ app_dir }}")
	env := []string{"COMPOSE_PROGRESS=plain", "DOCKER_CLI_HINTS=false"}
	container := b.S("{{ haproxy_admin_container_name }}")
	wait, _ := strconv.Atoi(b.S("{{ haproxy_admin_start_wait_timeout | int }}"))
	tries := wait / 5
	if tries < 1 {
		tries = 1
	}
	return []engine.Step{
		{Name: "Ensure Docker daemon is running (classic docker.service)", Resource: ignoredUnit("docker")},
		{Name: "Ensure Docker daemon is running (snap.docker.dockerd.service)", Resource: ignoredUnit("snap.docker.dockerd")},
		{Name: "Pull images", Resource: &engine.Command{Argv: []string{"timeout", b.S("{{ haproxy_admin_compose_pull_timeout | int | string }}"),
			"docker", "compose", "pull", "--quiet"}, Dir: dir, Env: env, Retries: 3, Delay: 20 * time.Second}},
		{Name: "Up -d (recreate if needed)", Resource: &engine.Command{Argv: []string{"timeout", b.S("{{ haproxy_admin_compose_up_timeout | int | string }}"),
			"docker", "compose", "up", "--detach", "--remove-orphans"}, Dir: dir, Env: env, MergeStderr: true, Retries: 2, Delay: 10 * time.Second,
			ChangedWhen: func(out string, _ int) bool { return composeChanged.MatchString(out) }}},
		{Name: "haproxy-admin | Read container health status",
			Resource: &engine.Func{Desc: "container health " + container, CheckFn: func(sys *engine.System) (engine.Change, error) {
				return engine.Change{Summary: "healthy"}, waitHealthy(sys, container, tries, wait)
			}}},
		{Name: "Remove the legacy external GeoIP JSON cache", Resource: &engine.Absent{Path: b.S("{{ haproxy_admin_root_dir }}") + "/backups/country_cache.json"}},
	}
}

// ignoredUnit is a service task with failed_when: false: enabled and
// started when the unit is there; a unit systemd does not know fails the
// module, which is ignored and changes nothing.
func ignoredUnit(name string) engine.Resource {
	u := Unit(name, engine.Bool(true), "started")
	return &engine.Func{Desc: "unit " + name,
		CheckFn: func(sys *engine.System) (engine.Change, error) {
			out, _, err := sys.Exec("systemctl", "show", name, "--property=LoadState", "--value")
			if err != nil || strings.TrimSpace(out) != "loaded" {
				return engine.Change{Summary: "not installed (ignored)"}, nil
			}
			c, err := u.Check(sys)
			if err != nil {
				return engine.Change{Summary: "failed (ignored): " + err.Error()}, nil
			}
			return c, nil
		},
		ApplyFn: func(sys *engine.System) error {
			c, err := u.Check(sys)
			if err == nil {
				u.Apply(sys, c)
			}
			return nil
		}}
}

// sameYAMLLine: two "key: value" lines of the runtime vars.yml that give the
// key the same value. The panel rewrites that file through a YAML dump,
// which drops the quotes these steps write; rewriting them back changed the
// file, so the configuration generation HAProxy carries, and the next update
// reloaded HAProxy for nothing after every save of the panel's settings.
func sameYAMLLine(existing, want string) bool {
	a, errA := pyyaml.Load([]byte(existing))
	b, errB := pyyaml.Load([]byte(want))
	am, okA := a.(*pyyaml.Map)
	bm, okB := b.(*pyyaml.Map)
	if errA != nil || errB != nil || !okA || !okB || am.Len() != 1 || bm.Len() != 1 {
		return false
	}
	ka, kb := am.Keys()[0], bm.Keys()[0]
	va, vb := am.Value(ka), bm.Value(kb)
	if ka != kb {
		return false
	}
	switch va.(type) {
	case string, int64, int, bool, float64:
		return va == vb
	}
	return false
}
