package stages

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/engine"
)

// The Authelia stage: roles/authelia's install entry (install.yml with the
// fs, config, start, configd, bansd and usersd files it imports and the
// helpers they include). The role's other entries are run on request
// (never-tagged) and stay in Ansible for now.
func init() {
	register(Stage{Name: "authelia", Parts: []Part{
		{Name: "authelia/install", Role: "authelia", File: "install", Build: autheliaInstall},
	}})
}

// rescueNote is a block with a rescue that cleans up (cleanup may be nil)
// and then fails with its own message: the step's failure becomes that.
type rescueNote struct {
	engine.Resource
	cleanup func(sys *engine.System)
	msg     string
}

func (r *rescueNote) Apply(sys *engine.System, c engine.Change) error {
	if err := r.Resource.Apply(sys, c); err != nil {
		if r.cleanup != nil {
			r.cleanup(sys)
		}
		return fmt.Errorf("%s (%v)", r.msg, err)
	}
	return nil
}

// Changed passes an inner command's outcome through.
func (r *rescueNote) Changed() bool {
	if o, ok := r.Resource.(engine.Outcome); ok {
		return o.Changed()
	}
	return false
}

// poll is a command task with retries and until: (on apply only, as a
// command without check_mode: false); the last output and code are kept.
type poll struct {
	argv     []string
	tries    int
	delay    time.Duration
	until    func(out string, code int) bool
	fail     func(out string, code int) error // nil: failed_when: false
	out      string
	code     int
	ran      bool
	planRead bool // check_mode: false: it reads in plan mode too
}

func (p *poll) Describe() string { return "command " + strings.Join(p.argv, " ") }

func (p *poll) Check(sys *engine.System) (engine.Change, error) {
	if p.planRead {
		return engine.Change{Summary: "read"}, p.run(sys)
	}
	return engine.Change{Summary: "runs on apply", Run: true}, nil
}

func (p *poll) Apply(sys *engine.System, _ engine.Change) error {
	if p.planRead {
		return nil
	}
	return p.run(sys)
}

func (p *poll) run(sys *engine.System) error {
	p.ran = true
	for attempt := 0; attempt <= p.tries; attempt++ {
		if attempt > 0 {
			time.Sleep(p.delay)
		}
		out, code, err := sys.Exec(p.argv[0], p.argv[1:]...)
		if err != nil {
			out, code = "", -1
		}
		p.out, p.code = out, code
		if p.until == nil || p.until(out, code) {
			break
		}
	}
	if p.fail != nil {
		return p.fail(p.out, p.code)
	}
	return nil
}

func trimmed(s string) string { return strings.TrimSpace(s) }

func autheliaInstall(b *Builder) []engine.Step {
	enabled := b.Bool("{{ authelia_enabled | default(false) | bool }}")
	timesync := []string{"timedatectl", "show", "--property=NTPSynchronized", "--value"}
	initial := &poll{argv: timesync, planRead: true}
	unit := &poll{argv: []string{"systemctl", "show", "systemd-timesyncd.service", "--property=LoadState", "--value"}, planRead: true}
	final := &poll{argv: timesync, planRead: true}
	drifted := func(*engine.Run) bool { return trimmed(initial.out) != "yes" }
	retries, _ := strconv.Atoi(b.S("{{ authelia_test_time_sync_retries | int }}"))
	delay, _ := strconv.Atoi(b.S("{{ authelia_test_time_sync_delay | int }}"))
	syncFail := fmt.Sprintf("systemd-timesyncd could not synchronize the host clock within %d seconds. Check network access to "+
		"the configured NTP servers and run `timedatectl timesync-status`; then retry.", retries*delay)
	usersFile := b.S("{{ authelia_users_file }}")
	reader := b.S("{{ authelia_log_reader_user }}")
	lang := b.S("{{ authelia_notification_language }}")

	steps := []engine.Step{
		{Name: "Read host NTP synchronization state", Resource: initial},
		{Name: "Detect systemd-timesyncd", When: drifted, Resource: unit},
		assertStep("Require a time synchronization provider",
			func(r *engine.Run) bool { return !drifted(r) || (unit.code == 0 && trimmed(unit.out) == "loaded") },
			"The host clock is not synchronized and systemd-timesyncd is not available. Install it (for example `apt install "+
				"systemd-timesyncd`) or synchronize the clock with your own NTP provider, verify `timedatectl show --property=NTPSynchronized "+
				"--value` returns `yes`, and retry."),
		{Name: "Enable systemd-managed NTP", When: drifted,
			Resource: &rescueNote{Resource: &engine.Command{Argv: []string{"timedatectl", "set-ntp", "true"}}, msg: syncFail}},
		{Name: "Enable and restart systemd-timesyncd", When: drifted,
			Resource: &rescueNote{Resource: Unit("systemd-timesyncd.service", engine.Bool(true), "restarted"), msg: syncFail}},
		{Name: "Wait until the host clock is synchronized", When: drifted,
			Resource: &poll{argv: timesync, tries: retries, delay: time.Duration(delay) * time.Second,
				until: func(out string, _ int) bool { return trimmed(out) == "yes" },
				fail: func(out string, code int) error {
					if code != 0 || trimmed(out) != "yes" {
						return fmt.Errorf("%s", syncFail)
					}
					return nil
				}}},
		{Name: "Verify final host NTP synchronization state", Resource: final},
		assertStep("Stop before deploying Authelia with an inaccurate clock",
			func(*engine.Run) bool { return final.code == 0 && trimmed(final.out) == "yes" },
			"The host still does not report an NTP-synchronized clock. Authelia would refuse to start. Run `timedatectl status` and "+
				"`timedatectl timesync-status`, correct the time provider, and retry."),
		{Name: "Install Authelia host-side maintenance dependencies", Tags: restoreNet,
			Resource: &engine.AptInstall{Names: []string{"logrotate"}, UpdateCache: true, CacheValid: b.aptValid()}},
	}
	steps = append(steps, autheliaFS(b)...)
	redisOn := b.Bool("{{ authelia_session_redis_enabled | default(true) }}") && b.Bool("{{ authelia_redis_tune_overcommit | default(true) }}")
	selfservice := b.S("{{ authelia_users_mode }}") == "selfservice"
	steps = append(steps,
		engine.Step{Name: "Ensure vm.overcommit_memory=1 for Redis", When: func(*engine.Run) bool { return redisOn },
			Resource: &engine.Sysctl{Name: "vm.overcommit_memory", Value: b.S("{{ authelia_redis_overcommit_value | string }}"),
				File: b.S("{{ authelia_redis_sysctl_file }}"), Reload: true}},
		engine.Step{Name: "Seed Authelia users database once (selfservice mode)", When: func(*engine.Run) bool { return selfservice },
			Register: "authelia_users_t",
			Build:    b.Template("users_database.yml.j2", "{{ authelia_users_host_path }}", "authelia", "authelia", "0640", NoForce)},
		engine.Step{Name: b.S("Take back {{ authelia_log_reader_user }}'s read access to the Authelia users file"),
			When: func(*engine.Run) bool { return b.Exists(usersFile, false) }, Resource: &engine.ACL{Path: usersFile, User: reader, Absent: true}},
		engine.Step{Name: "Deploy logrotate config for Authelia", When: func(*engine.Run) bool { return b.Bool("{{ authelia_logrotate_enabled | default(true) | bool }}") },
			Build: b.Template("logrotate-authelia.j2", "/etc/logrotate.d/authelia", "root", "root", "0644")},
		assertStep("Validate Authelia notification language", func(*engine.Run) bool { return lang == "en" || lang == "ru" },
			"authelia_notification_language must be either 'en' or 'ru'."),
	)
	for _, tmpl := range []struct{ name, file string }{
		{"Event HTML", "Event.html"}, {"Event TXT", "Event.txt"},
		{"IdentityVerificationJWT HTML", "IdentityVerificationJWT.html"}, {"IdentityVerificationJWT TXT", "IdentityVerificationJWT.txt"},
		{"IdentityVerificationOTC HTML", "IdentityVerificationOTC.html"}, {"IdentityVerificationOTC TXT", "IdentityVerificationOTC.txt"},
	} {
		src := tmpl.file + "." + lang + ".j2"
		steps = append(steps, engine.Step{Name: "Deploy " + tmpl.name + " template (" + strings.ToUpper(lang) + ")",
			Build: b.Template(src, "/opt/authelia/email_templates/"+tmpl.file, "authelia", "authelia", "0640")})
	}
	steps = append(steps,
		engine.Step{Name: "Install bundled haproxy-lua-http http.lua",
			Build: b.CopyFile("lua/http.lua", "/etc/haproxy/lua/haproxy-lua-http/http.lua", "root", "root", "0644")},
		engine.Step{Name: "Install bundled json.lua", Build: b.CopyFile("lua/json.lua", "/etc/haproxy/lua/json.lua", "root", "root", "0644")},
		engine.Step{Name: "Install bundled auth-request.lua",
			Build: b.CopyFile("lua/auth-request.lua", "/etc/haproxy/lua/auth-request.lua", "root", "root", "0644")},
	)
	steps = append(steps, autheliaConfig(b, "install")...)
	steps = append(steps, autheliaConfigd(b)...)
	steps = append(steps, autheliaBansd(b)...)
	steps = append(steps, autheliaUsersd(b)...)
	for i := range steps {
		steps[i].When = andWhen(func(*engine.Run) bool { return enabled }, steps[i].When)
	}
	return steps
}

func autheliaFS(b *Builder) []engine.Step {
	readerGroup := "{{ authelia_log_reader_group }}"
	reader := b.S("{{ authelia_log_reader_user }}")
	root := b.S("{{ authelia_root_dir }}")
	redisDir := b.S("{{ authelia_redis_data_dir }}")
	logsDir := b.S("{{ authelia_logs_dir }}")
	logFile := b.S("{{ authelia_log_file }}")
	redis := b.Bool("{{ authelia_session_redis_enabled | default(true) }}")
	onRedis := func(*engine.Run) bool { return redis }
	logExisted := false
	steps := []engine.Step{
		{Name: "Ensure private runtime directory exists", Resource: b.Dir("/run/easy-ha-proxy", "root", readerGroup, "0750")},
		{Name: "Ensure groups for Authelia stack exist", Resource: &engine.Group{Name: "authelia", GID: b.S("{{ authelia_gid }}"), System: true}},
		{Name: "Ensure groups for Authelia stack exist", Resource: &engine.Group{Name: "authelia_redis", GID: b.S("{{ authelia_redis_gid }}"), System: true}},
		{Name: "Ensure users for Authelia stack exist", Resource: &engine.User{Name: "authelia", UID: b.S("{{ authelia_uid }}"), Group: "authelia",
			Shell: "/usr/sbin/nologin", System: true, NoHome: true}},
		{Name: "Ensure users for Authelia stack exist", Resource: &engine.User{Name: "authelia_redis", UID: b.S("{{ authelia_redis_uid }}"),
			Group: "authelia_redis", Shell: "/usr/sbin/nologin", System: true, NoHome: true}},
		{Name: "Ensure Authelia base dir exists and has correct permissions", Resource: b.Dir(root, "authelia", "authelia", "0750")},
		{Name: "Ensure the local Authelia notification file is private",
			Resource: &engine.Touch{Path: root + "/notification.log", Owner: "authelia", Group: "authelia", Mode: 0o600, Preserve: true}},
		{Name: "Ensure Authelia redis data dir exists", When: onRedis, Resource: b.Dir(redisDir, "authelia_redis", "authelia_redis", "0750")},
		{Name: "Ensure Authelia logs dir exists", Resource: b.Dir(logsDir, "authelia", readerGroup, "0750")},
		{Name: "Ensure directory for Authelia log exists",
			When:     func(*engine.Run) bool { logExisted = b.Exists(logFile, false); return !logExisted },
			Resource: b.Dir(filepath.Dir(logFile), "authelia", readerGroup, "0750")},
		{Name: "Create Authelia log file if it does not exist", When: func(*engine.Run) bool { return !logExisted },
			Resource: &engine.Touch{Path: logFile, Owner: "authelia", Group: b.S(readerGroup), Mode: 0o640}},
		{Name: "Ensure permissions on the existing Authelia log file", When: func(*engine.Run) bool { return logExisted },
			Resource: &engine.Attrs{Path: logFile, Owner: "authelia", Group: b.S(readerGroup), Mode: 0o640}},
		{Name: "Ensure ACL support is installed", Tags: restoreNet,
			Resource: &engine.AptInstall{Names: []string{"acl"}, UpdateCache: true, CacheValid: b.aptValid()}},
		{Name: "Allow haproxy reader user to read Authelia log (current file)", Resource: &engine.ACL{Path: logFile, User: reader, Perms: "r"}},
		{Name: "Ensure default ACL for Authelia logs dir", Resource: &engine.ACL{Path: logsDir, User: reader, Perms: "rx", Default: true}},
		{Name: "Remove inherited default ACL for log reader on Authelia root dir",
			Resource: &engine.ACL{Path: root, User: reader, Default: true, Absent: true}},
		{Name: "Remove inherited default ACL for log reader on Authelia redis dir", When: onRedis,
			Resource: &engine.ACL{Path: redisDir, User: reader, Default: true, Absent: true}},
	}
	db := root + "/" + filepath.Base(b.S("{{ authelia_storage_local_path | default('/config/db.sqlite3') }}"))
	for _, path := range []string{b.S("{{ authelia_config_file }}"), b.S("{{ authelia_env_file }}"), b.S("{{ authelia_docker_compose_file }}"),
		root + "/notification.log", db, db + "-wal", db + "-shm", db + "-journal", redisDir} {
		path := path
		steps = append(steps, engine.Step{Name: "Remove inherited log-reader ACL from private Authelia files and dirs",
			When: func(*engine.Run) bool {
				fi, err := os.Lstat(b.Sys.Path(path))
				return err == nil && fi.Mode()&os.ModeSymlink == 0
			},
			Resource: &engine.ACL{Path: path, User: reader, Absent: true}})
	}
	return append(steps,
		engine.Step{Name: "Allow haproxy reader user to traverse Authelia root dir (non-default ACL)", Resource: &engine.ACL{Path: root, User: reader, Perms: "x"}},
		engine.Step{Name: "Allow haproxy reader user to traverse Authelia logs dir (non-default ACL)", Resource: &engine.ACL{Path: logsDir, User: reader, Perms: "rx"}},
		engine.Step{Name: "Ensure Authelia email templates dir exists", Resource: b.Dir("/opt/authelia/email_templates", "authelia", "authelia", "0750")},
		engine.Step{Name: "Ensure HAProxy lua dir exists", Resource: b.Dir("/etc/haproxy/lua", "root", "root", "0755")},
		engine.Step{Name: "Ensure haproxy-lua-http dir exists", Resource: b.Dir("/etc/haproxy/lua/haproxy-lua-http", "root", "root", "0755")},
	)
}

func autheliaMailNotifyState(b *Builder) engine.Step {
	return engine.Step{Name: "Ensure the managed mail notification state exists",
		Build: b.Template("mail-notify.json.j2", "{{ easy_ha_proxy_config_dir | default('/etc/easy-ha-proxy') }}/mail-notify.json", "root", "root", "0600")}
}

// autheliaConfig transcribes config.yml for a role entry (install or
// config): the files, then restart.yml (config) or start.yml (install) when
// one of them changed or a restart is forced.
func autheliaConfig(b *Builder, entry string) []engine.Step {
	root := b.S("{{ authelia_root_dir }}")
	managed := b.S("{{ authelia_users_mode }}") == "managed"
	selfservice := b.S("{{ authelia_users_mode }}") == "selfservice"
	force := b.Bool("{{ authelia_force_restart | default(false) }}")
	changed := false
	trustSrc := filepath.Join(b.RoleDir, "files", "mail_relay.d", "10-trust.sh")
	steps := []engine.Step{
		autheliaMailNotifyState(b),
		{Name: "Deploy Authelia configuration", Register: "authelia_cfg_t",
			Build: b.Template("configuration.yml.j2", "/opt/authelia/configuration.yml", "authelia", "authelia", "0640")},
		{Name: "Deploy Authelia users database (managed mode)", When: func(*engine.Run) bool { return managed }, Register: "authelia_users_t",
			Build: b.Template("users_database.yml.j2", "{{ authelia_users_host_path }}", "authelia", "authelia", "0640")},
		{Name: "Seed Authelia users database once (selfservice mode)", When: func(*engine.Run) bool { return selfservice }, Register: "authelia_users_t",
			Build: b.Template("users_database.yml.j2", "{{ authelia_users_host_path }}", "authelia", "authelia", "0640", NoForce)},
		{Name: "Render .env file for Authelia docker stack", Register: "authelia_env_t",
			Build: b.Template("authelia.env.j2", "{{ authelia_env_file }}", "root", "root", "0600")},
		{Name: "Create the mail relay start-up scripts directory", Resource: b.Dir(root+"/mail_relay.d", "root", "root", "0755")},
		{Name: "Install the mail relay trust settings", Register: "authelia_mail_relay_trust",
			Build: b.CopyFile("mail_relay.d/10-trust.sh", root+"/mail_relay.d/10-trust.sh", "root", "root", "0644")},
		fact("Remember the mail relay scripts' checksum", nil, func() error {
			raw, err := os.ReadFile(trustSrc)
			if err != nil {
				return err
			}
			sum := sha1.Sum(raw) // the copy module's checksum
			b.Set.SetFact("authelia_mail_relay_scripts_digest", hex.EncodeToString(sum[:]))
			return nil
		}),
		{Name: "Deploy Authelia docker-compose.yml", Register: "authelia_compose_t",
			Build: b.Template("docker-compose.yml.j2", "/opt/authelia/docker-compose.yml", "root", "docker", "0640")},
		{Name: "Authelia | set flag if any config changed", Build: func(r *engine.Run) (engine.Resource, error) {
			changed = r.ChangedAny("authelia_cfg_t", "authelia_users_t", "authelia_compose_t", "authelia_env_t")
			b.Set.SetFact("authelia_configs_changed", changed)
			return nil, nil
		}},
	}
	restart := func(r *engine.Run) bool { return entry == "config" && (changed || force) }
	start := func(r *engine.Run) bool { return entry == "install" && (changed || force) }
	steps = append(steps, autheliaStart(b, restart)...)
	return append(steps, autheliaStart(b, start)...)
}

var authCredential = regexp.MustCompile(`(?i)(@|authorization|cookie|credential|encryption.?key|jwt|password|recipient|secret|sender|token)`)

// autheliaStart transcribes start.yml (with check.yml and the helpers it
// includes) under the import's condition.
func autheliaStart(b *Builder, cond func(*engine.Run) bool) []engine.Step {
	root := b.S("{{ authelia_root_dir }}")
	name := b.S("{{ authelia_container_name }}")
	version := b.S("{{ authelia_version | default('4.39.28') }}")
	offline := b.Bool("{{ easy_ha_proxy_offline_restore | default(false) | bool }}")
	env := []string{"COMPOSE_PROGRESS=plain", "DOCKER_CLI_HINTS=false"}
	redis := b.Bool("{{ authelia_session_redis_enabled | default(true) | bool }}")
	relayUsed := b.Bool("{{ mail_notify_enabled | default(false) | bool or mail_relay_server | default(false) | bool }}")
	wait, _ := strconv.Atoi(b.S("{{ authelia_start_wait_timeout | int }}"))

	validate := []string{"docker", "run", "--rm"}
	if offline {
		validate = append(validate, "--pull=never")
	}
	validate = append(validate, "-v", "/opt/authelia:/config", "authelia/authelia:"+version, "authelia", "config", "validate", "--config", "/config/configuration.yml")
	up := []string{"docker", "compose", "up", "--detach", "--force-recreate", "--remove-orphans"}
	if offline {
		up = append(up, "--pull", "never")
	}
	running := &poll{argv: []string{"docker", "inspect", "--format", "{{.Image}} {{.Config.Image}}", name}, planRead: true}
	target := &poll{argv: []string{"docker", "image", "inspect", "--format", "{{.Id}}", "authelia/authelia:" + version}, planRead: true}
	dump := b.S("{{ authelia_redis_data_dir }}") + "/dump.rdb"
	dumpCheck := &poll{argv: []string{"docker", "run", "--rm", "--pull", "never", "--network", "none", "--read-only", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges:true", "--user", b.S("{{ authelia_redis_uid }}:{{ authelia_redis_gid }}"),
		"--volume", b.S("{{ authelia_redis_data_dir }}") + ":/data:ro", "--entrypoint", "redis-check-rdb", b.S("{{ authelia_redis_image }}"), "/data/dump.rdb"},
		planRead: true}
	unreadable := func(r *engine.Run) bool { return dumpCheck.ran && dumpCheck.code == 1 }
	relay := &poll{argv: []string{"docker", "inspect", "--format", "{{.State.Running}}", "mail_relay"}}
	state := &poll{argv: []string{"docker", "inspect", "--format", "{{.State.Status}}", name}, tries: 12, delay: 5 * time.Second,
		until: func(out string, code int) bool { return code == 0 && trimmed(out) == "running" }}
	notRunning := func(r *engine.Run) bool { return state.ran && (state.code != 0 || trimmed(state.out) != "running") }
	ps := &poll{argv: []string{"env", "-C", root, "docker", "compose", "ps", "--all"}}
	logs := &poll{argv: []string{"/bin/sh", "-c", `exec docker logs --timestamps --tail 80 "$0" 2>&1`, name}}
	timeStatus := &poll{argv: []string{"timedatectl", "status"}}
	apply := func(r *engine.Run) bool { return r.Mode == engine.Apply }

	steps := []engine.Step{
		{Name: "Validate Authelia docker-compose.yml",
			Resource: &engine.Command{Argv: []string{"docker", "compose", "-f", "/opt/authelia/docker-compose.yml", "config", "--quiet"}}},
		{Name: "Validate Authelia configuration.yml via CLI in container", Resource: &engine.Command{Argv: validate}},
		{Name: "Pull Authelia stack images", Tags: restoreNet,
			Resource: &engine.Command{Argv: []string{"docker", "compose", "pull"}, Dir: root, Env: env, Retries: 3, Delay: 20 * time.Second}},
		{Name: "Safely migrate the legacy container-layer mail relay spool", When: apply,
			Build: func(*engine.Run) (engine.Resource, error) {
				script, err := b.Set.Render(autheliaSpoolMigration)
				if err != nil {
					return nil, err
				}
				return &rescueNote{Resource: &engine.Command{Argv: []string{"/bin/bash", "-c", script}, Dir: root,
					ChangedWhen: func(out string, _ int) bool { return trimmed(out) == "migrated" }},
					msg: "The legacy mail_relay spool could not be migrated safely. Its container and queue were preserved or recovered. " +
						"Verify Docker, let any queued mail drain, and retry the update."}, nil
			}},
		{Name: "Read the image the running Authelia container was created from", Resource: running},
		{Name: "Read the image Authelia is about to run", Resource: target},
		{Name: "Copy the Authelia database before a different image starts on it",
			When: func(*engine.Run) bool {
				fields := strings.Split(trimmed(running.out), " ")
				return running.code == 0 && target.code == 0 && fields[0] != trimmed(target.out)
			},
			Build: func(*engine.Run) (engine.Resource, error) {
				fields := strings.Split(trimmed(running.out), " ")
				return &engine.Command{Argv: []string{"python3", b.RoleDir + "/files/authelia_db_backup.py",
					root + "/" + filepath.Base(b.S("{{ authelia_storage_local_path | default('/config/db.sqlite3') }}")),
					b.S("{{ authelia_db_backup_dir }}"), fields[len(fields)-1], b.S("{{ authelia_db_backup_keep | string }}")},
					ChangedWhen: func(out string, _ int) bool { return !strings.Contains(out, "nothing to copy") }}, nil
			}},
		{Name: "Let the Redis image about to run check the session dump",
			When: func(*engine.Run) bool { return redis && b.Exists(dump, false) }, Resource: dumpCheck},
		{Name: "Stop the Redis that wrote the dump", When: func(r *engine.Run) bool { return redis && unreadable(r) },
			Resource: &engine.Command{Argv: []string{"docker", "stop", "authelia-redis"}, Changes: true, IgnoreErrors: true}},
		{Name: "Move the unreadable dump out of the way", When: func(r *engine.Run) bool { return redis && unreadable(r) },
			Build: func(*engine.Run) (engine.Resource, error) {
				return &engine.Command{Argv: []string{"mv", "--no-clobber", dump, dump + ".unreadable-" + time.Now().UTC().Format("20060102T150405Z")},
					Changes: true}, nil
			}},
		{Name: "Say why everyone has to sign in again", When: func(r *engine.Run) bool { return redis && unreadable(r) },
			Resource: report(b.S("{{ authelia_redis_image }}") + " cannot read the session dump an earlier Redis wrote, so it was moved aside in " +
				b.S("{{ authelia_redis_data_dir }}") + " and Redis starts empty. Signed-in users have to sign in again.")},
		{Name: "Ensure Authelia stack is up", Resource: &rescueNote{
			Resource: &engine.Command{Argv: up, Dir: root, Env: env, Changes: true, Retries: 2, Delay: 10 * time.Second},
			cleanup: func(sys *engine.System) {
				if relayUsed {
					sys.Exec("docker", "start", "mail_relay")
				}
				sys.Exec("docker", "start", name)
			},
			msg: "Docker Compose could not reconcile the Authelia stack. If the legacy spool migration stopped Authelia, a best-effort " +
				"restart was attempted and the old relay spool was not deleted explicitly."}},
		{Name: "See whether the mail relay is running", Resource: relay},
		{Name: "Send the mail the relay holds back", When: func(*engine.Run) bool { return relay.ran && trimmed(relay.out) == "true" },
			Resource: &poll{argv: []string{"docker", "exec", "mail_relay", "postqueue", "-f"}, tries: 3, delay: 3 * time.Second,
				until: func(_ string, code int) bool { return code == 0 }}},
		{Name: "Inspect Authelia container state after compose up", Resource: state},
		{Name: "Inspect Authelia compose status when container is not running", When: notRunning, Resource: ps},
		{Name: "Collect recent Authelia logs when startup fails", When: notRunning, Resource: logs},
		{Name: "Collect host time status when Authelia startup fails", When: notRunning, Resource: timeStatus},
		{Name: "Fail if Authelia container did not start", When: notRunning, Build: func(*engine.Run) (engine.Resource, error) {
			var kept []string
			for _, line := range strings.Split(strings.TrimRight(logs.out, "\n"), "\n") {
				if line != "" && !authCredential.MatchString(line) {
					kept = append(kept, line)
				}
			}
			shown := strings.Join(kept, "\n")
			if shown == "" {
				shown = "no non-sensitive log lines collected"
			}
			times := trimmed(timeStatus.out)
			if times == "" {
				times = "not collected"
			}
			return nil, fmt.Errorf("Authelia container did not start after docker compose up.\ninspect rc=%d\ninspect stdout=%s\n"+
				"docker compose ps:\n%s\ntimedatectl status:\n%s\nsanitized docker logs (credential-related lines omitted):\n%s",
				state.code, trimmed(state.out), ps.out, times, shown)
		}},
		{Name: "Wait for Authelia to listen on port 9091", Resource: &engine.Func{Desc: "wait for 127.0.0.1:9091",
			CheckFn: func(*engine.System) (engine.Change, error) {
				return engine.Change{Summary: "runs on apply", Run: true}, nil
			},
			ApplyFn: func(*engine.System) error {
				return waitPort("127.0.0.1:9091", 3*time.Second, time.Duration(wait)*time.Second)
			}}},
	}
	for i := range steps {
		steps[i].When = andWhen(cond, steps[i].When)
	}
	return steps
}

// waitPort is wait_for host/port: after delay, until a connection is
// accepted or the timeout passes.
func waitPort(addr string, delay, timeout time.Duration) error {
	time.Sleep(delay)
	deadline := time.Now().Add(timeout)
	for {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			conn.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("Timeout when waiting for %s", addr)
		}
		time.Sleep(time.Second)
	}
}

// autheliaDaemon is configd.yml, bansd.yml and usersd.yml's shape: the unit,
// daemon-reload, enable, restart if the unit changed, started.
func autheliaDaemon(b *Builder, daemon, register string, on bool) []engine.Step {
	when := func(*engine.Run) bool { return on }
	unit := daemon + ".service"
	return []engine.Step{
		{Name: daemon + " | Install systemd unit", When: when, Register: register,
			Build: b.Template(daemon+".service.j2", "/etc/systemd/system/"+unit, "root", "root", "0640")},
		{Name: daemon + " | systemd daemon-reload if unit changed", When: andWhen(when, Changed(register)), Resource: engine.DaemonReload{}},
		{Name: daemon + " | Enable service", When: when, Resource: Unit(unit, engine.Bool(true), "")},
		{Name: daemon + " | Restart service if changed", When: andWhen(when, Changed(register)), Resource: Unit(unit, nil, "restarted")},
		{Name: daemon + " | Ensure service started", When: when, Resource: Unit(unit, nil, "started")},
	}
}

func autheliaConfigd(b *Builder) []engine.Step {
	return append([]engine.Step{autheliaMailNotifyState(b)},
		autheliaDaemon(b, "authelia-configd", "authelia_configd_unit", b.Bool("{{ authelia_configd_enabled | default(true) | bool }}"))...)
}

func autheliaBansd(b *Builder) []engine.Step {
	return append([]engine.Step{{Name: "authelia-bans | Deploy helper script",
		Build: b.Template("authelia-bans.sh.j2", "{{ authelia_bans_script_path }}", "root", "root", "{{ authelia_bans_script_mode }}")}},
		autheliaDaemon(b, "authelia-bansd", "authelia_bansd_unit", b.Bool("{{ authelia_bans_daemon_enabled | default(true) | bool }}"))...)
}

func autheliaUsersd(b *Builder) []engine.Step {
	return autheliaDaemon(b, "authelia-usersd", "authelia_usersd_unit", true)
}
