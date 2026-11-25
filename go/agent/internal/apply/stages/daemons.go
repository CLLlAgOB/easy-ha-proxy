package stages

import "github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/engine"

// The native daemons stage: the root daemons' token file, configs, units and
// services. Each part transcribes roles/haproxy-admin/tasks/<task_stage>.yml.
// Still to come in this stage: updated, certd, the iptables units and the
// native binary bundle.
func init() {
	register(Stage{Name: "daemons", Parts: []Part{
		{Role: "haproxy-admin", TaskStage: "daemons_env", Build: daemonsEnv},
		{Role: "haproxy-admin", TaskStage: "healthd", Build: healthd},
		{Role: "haproxy-admin", TaskStage: "controld", Build: controld},
		{Role: "haproxy-admin", TaskStage: "backupd", Build: backupd},
		{Role: "haproxy-admin", TaskStage: "alertd", Build: alertd},
		{Role: "haproxy-admin", TaskStage: "metricsd", Build: metricsd},
		{Role: "haproxy-admin", TaskStage: "guardd", Build: guardd},
		{Role: "haproxy-admin", TaskStage: "journald-retention", Build: journald},
	}})
}

const appGroup = "{{ app_group | default('hadmin') }}"

// Changes made earlier in the run (or by Ansible, in the hybrid period) that
// restart every daemon: the panel's env file and the daemons' token file.
var envChanged = []string{"hapadm_env_t", "daemons_env_t"}

func with(names ...string) []string { return append(append([]string{}, names...), envChanged...) }

func daemonsEnv(b *Builder) []engine.Step {
	return []engine.Step{
		{Name: "Ensure /etc/easy-ha-proxy directory exists for daemon token file",
			Resource: b.Dir("{{ (daemons_env_file | default('/etc/easy-ha-proxy/daemons.env')) | dirname }}", "root", "root", "0700")},
		{Name: "Render root-only daemon IPC token file", Register: "daemons_env_t",
			Build: b.Template("daemons.env.j2", "{{ daemons_env_file | default('/etc/easy-ha-proxy/daemons.env') }}", "root", "root", "0600")},
	}
}

// standardDaemon is the shape alertd, metricsd and guardd share: install the
// unit, reload if it changed, enable, restart on a change, ensure started.
func standardDaemon(prefix, unit, register string, restartOn []string) []engine.Step {
	return []engine.Step{
		{Name: prefix + " | systemd daemon-reload if unit changed", When: Changed(register), Resource: engine.DaemonReload{}},
		{Name: prefix + " | Enable service", Resource: Unit(unit, engine.Bool(true), "")},
		{Name: prefix + " | Restart service if changed", When: Changed(restartOn...), Resource: Unit(unit, nil, "restarted")},
		{Name: prefix + " | Ensure service started", Resource: Unit(unit, nil, "started")},
	}
}

func healthd(b *Builder) []engine.Step {
	appDir := "{{ app_dir | default('/opt/haproxy-admin') }}"
	cfg := "{{ healthd_config_path | default((app_dir | default('/opt/haproxy-admin')) ~ '/healthd.json') }}"
	legacy := b.S(appDir + "/config/healthd.json")
	steps := []engine.Step{
		{Name: "haproxy-healthd | Ensure config dir",
			Resource: b.Dir(appDir+"/config", "{{ app_user | default('haproxyadmin') }}", appGroup, "0755")},
		{Name: "haproxy-healthd | Render config", Register: "healthd_cfg",
			Build: b.Template("healthd.json.j2", cfg, "root", appGroup, "0640")},
		{Name: "haproxy-healthd | Remove the legacy config-dir healthd.json",
			When:     func(*engine.Run) bool { return b.S(cfg) != legacy },
			Resource: &engine.Absent{Path: legacy}},
		{Name: "haproxy-healthd | Install systemd unit", Register: "healthd_unit",
			Build: b.Template("haproxy-healthd.service.j2", "/etc/systemd/system/haproxy-healthd.service", "root", "root", "0644")},
	}
	return append(steps, standardDaemon("haproxy-healthd", "haproxy-healthd.service", "healthd_unit",
		with("healthd_unit", "healthd_cfg"))...)
}

func controld(b *Builder) []engine.Step {
	unit := "haproxy-controld.service"
	envFile := b.S("{{ haproxy_admin_env_file }}")
	envExists := func(*engine.Run) bool { return b.Exists(envFile, false) }
	return []engine.Step{
		{Name: "haproxy-controld | Install required packages (ipset, socat)", Resource: &engine.Packages{Names: []string{"ipset", "socat"}}},
		{Name: "haproxy-controld | Install systemd unit", Register: "haproxy_controld_unit",
			Build: b.Template("haproxy-controld.service.j2", "/etc/systemd/system/"+unit, "root", "root", "0644")},
		{Name: "haproxy-controld | Reload systemd if unit changed", When: Changed("haproxy_controld_unit"), Resource: engine.DaemonReload{}},
		{Name: "haproxy-controld | Enable service", Resource: Unit(unit, engine.Bool(true), "")},
		{Name: "haproxy-controld | Keep service stopped until configuration exists",
			When: func(r *engine.Run) bool { return !envExists(r) }, Resource: Unit(unit, nil, "stopped")},
		{Name: "haproxy-controld | Ensure configured service is started", When: envExists,
			Build: func(r *engine.Run) (engine.Resource, error) {
				state := "started"
				if r.ChangedAny(with("haproxy_controld_unit")...) {
					state = "restarted"
				}
				return Unit(unit, nil, state), nil
			}},
	}
}

func backupd(b *Builder) []engine.Step {
	unit := "easy-ha-proxy-backupd.service"
	appUser := "{{ app_user }}"
	group := "{{ app_group }}"
	marker := b.S("{{ backupd_restore_active_marker }}")
	restoring := func(*engine.Run) bool { return b.Exists(marker, true) }
	unitChanged := Changed("backupd_unit", "daemons_env_t")
	scheduleOn := b.Bool("{{ backup_schedule_enabled | default(true) | bool }}")
	scheduleState := "stopped"
	if scheduleOn {
		scheduleState = "started"
	}
	steps := []engine.Step{}
	for _, d := range []struct{ path, owner, mode string }{
		{"{{ backupd_root_dir }}", "root", "0750"},
		{"{{ backupd_jobs_dir }}", "root", "0750"},
		{"{{ backupd_uploads_dir }}", appUser, "0700"},
		{"{{ backupd_backups_dir }}", "root", "0750"},
	} {
		steps = append(steps, engine.Step{Name: "easy-ha-proxy-backupd | Ensure persistent spool directories",
			Resource: b.Dir(d.path, d.owner, group, d.mode)})
	}
	return append(steps,
		engine.Step{Name: "easy-ha-proxy-backupd | Install systemd unit", Register: "backupd_unit",
			Build: b.Template("easy-ha-proxy-backupd.service.j2", "/etc/systemd/system/"+unit, "root", "root", "0644")},
		engine.Step{Name: "easy-ha-proxy-backupd | Reload systemd when unit changed", When: Changed("backupd_unit"), Resource: engine.DaemonReload{}},
		engine.Step{Name: "easy-ha-proxy-backupd | Defer self restart during active restore",
			When:     func(r *engine.Run) bool { return restoring(r) && unitChanged(r) },
			Resource: &engine.Touch{Path: b.S("{{ backupd_restart_request_marker }}"), Owner: "root", Group: b.S(group), Mode: 0o600}},
		engine.Step{Name: "easy-ha-proxy-backupd | Enable service", Resource: Unit(unit, engine.Bool(true), "")},
		engine.Step{Name: "easy-ha-proxy-backupd | Restart changed service outside restore",
			When: func(r *engine.Run) bool { return !restoring(r) && unitChanged(r) }, Resource: Unit(unit, nil, "restarted")},
		engine.Step{Name: "easy-ha-proxy-backupd | Ensure service is started", Resource: Unit(unit, nil, "started")},
		engine.Step{Name: "easy-ha-proxy-backupd | Ensure the destinations directory",
			Resource: b.Dir("{{ backupd_destinations_dir | default('/etc/easy-ha-proxy/backup-destinations') }}", "root", "root", "0700")},
		engine.Step{Name: "easy-ha-proxy-backupd | Install the unit-failure reporter unit", Register: "backup_failure_unit",
			Build: b.Template("easy-ha-proxy-unit-failed@.service.j2", "/etc/systemd/system/easy-ha-proxy-unit-failed@.service", "root", "root", "0644")},
		engine.Step{Name: "easy-ha-proxy-backupd | Install the schedule unit", Register: "backup_schedule_unit",
			Build: b.Template("easy-ha-proxy-backup.service.j2", "/etc/systemd/system/easy-ha-proxy-backup.service", "root", "root", "0644")},
		engine.Step{Name: "easy-ha-proxy-backupd | Install the schedule timer", Register: "backup_schedule_timer",
			Build: b.Template("easy-ha-proxy-backup.timer.j2", "/etc/systemd/system/easy-ha-proxy-backup.timer", "root", "root", "0644")},
		engine.Step{Name: "easy-ha-proxy-backupd | Reload systemd for the schedule",
			When: Changed("backup_schedule_unit", "backup_schedule_timer", "backup_failure_unit"), Resource: engine.DaemonReload{}},
		engine.Step{Name: "easy-ha-proxy-backupd | Enable the schedule timer",
			Resource: Unit("easy-ha-proxy-backup.timer", engine.Bool(scheduleOn), scheduleState)},
	)
}

func alertd(b *Builder) []engine.Step {
	steps := []engine.Step{
		{Name: "easy-ha-proxy-alertd | Ensure state directory",
			Resource: b.Dir("{{ (alertd_database_path | default('/var/lib/easy-ha-proxy/alerts/alerts.db')) | dirname }}", "root", appGroup, "0750")},
		{Name: "easy-ha-proxy-alertd | Seed the settings file", Register: "alertd_cfg",
			Build: b.Template("alertd.json.j2", "{{ alertd_config_path | default((app_dir | default('/opt/haproxy-admin')) ~ '/alertd.json') }}",
				"root", appGroup, "0640", NoForce)},
		{Name: "easy-ha-proxy-alertd | Install systemd unit", Register: "alertd_unit",
			Build: b.Template("easy-ha-proxy-alertd.service.j2", "/etc/systemd/system/easy-ha-proxy-alertd.service", "root", "root", "0644")},
	}
	return append(steps, standardDaemon("easy-ha-proxy-alertd", "easy-ha-proxy-alertd.service", "alertd_unit",
		with("alertd_unit"))...)
}

func metricsd(b *Builder) []engine.Step {
	steps := []engine.Step{
		{Name: "easy-ha-proxy-metricsd | Render config", Register: "metricsd_cfg",
			Build: b.Template("metricsd.json.j2", "{{ metricsd_config_path | default((app_dir | default('/opt/haproxy-admin')) ~ '/metricsd.json') }}",
				"root", appGroup, "0640")},
		{Name: "easy-ha-proxy-metricsd | Ensure state directory",
			Resource: b.Dir("{{ (metricsd_database_path | default('/var/lib/easy-ha-proxy/metrics/metrics.db')) | dirname }}", "root", appGroup, "0750")},
		{Name: "easy-ha-proxy-metricsd | Install systemd unit", Register: "metricsd_unit",
			Build: b.Template("easy-ha-proxy-metricsd.service.j2", "/etc/systemd/system/easy-ha-proxy-metricsd.service", "root", "root", "0644")},
	}
	return append(steps, standardDaemon("easy-ha-proxy-metricsd", "easy-ha-proxy-metricsd.service", "metricsd_unit",
		with("metricsd_unit", "metricsd_cfg"))...)
}

func guardd(b *Builder) []engine.Step {
	steps := []engine.Step{
		{Name: "easy-ha-proxy-guardd | Install the scanner signatures", Register: "guardd_signatures",
			Build: b.CopyFile("scanner-signatures.json", "/usr/local/sbin/scanner-signatures.json", "root", "root", "0644")},
		{Name: "easy-ha-proxy-guardd | Render config", Register: "guardd_cfg",
			Build: b.Template("guardd.json.j2", "{{ guardd_config_path | default((app_dir | default('/opt/haproxy-admin')) ~ '/guardd.json') }}",
				"root", appGroup, "0640")},
		{Name: "easy-ha-proxy-guardd | Ensure state directory",
			Resource: b.Dir("{{ (guardd_database_path | default('/var/lib/easy-ha-proxy/security/security.db')) | dirname }}", "root", appGroup, "0750")},
		{Name: "easy-ha-proxy-guardd | Install systemd unit", Register: "guardd_unit",
			Build: b.Template("easy-ha-proxy-guardd.service.j2", "/etc/systemd/system/easy-ha-proxy-guardd.service", "root", "root", "0644")},
	}
	return append(steps, standardDaemon("easy-ha-proxy-guardd", "easy-ha-proxy-guardd.service", "guardd_unit",
		with("guardd_unit", "guardd_cfg", "guardd_signatures"))...)
}

// journaldRetention is the copy task's content:, word for word (a test holds
// it to the task file).
const journaldRetention = `# Managed by Ansible (haproxy-admin)
[Journal]
# Keep journal entries for ~10 days (time-based retention)
MaxRetentionSec={{ journald_retention_sec | default('10day') }}
# Rotate each journal file daily (helps time-based retention operate on archived files)
MaxFileSec={{ journald_max_file_sec | default('1day') }}
`

func journald(b *Builder) []engine.Step {
	vacuumChanged := Changed("journald_vacuum_service", "journald_vacuum_timer")
	return []engine.Step{
		{Name: "journald | Ensure drop-in dir", Resource: b.Dir("/etc/systemd/journald.conf.d", "root", "root", "0755")},
		{Name: "journald | Configure retention (MaxRetentionSec/MaxFileSec)", Register: "journald_retention_conf",
			Build: b.CopyContent(journaldRetention,
				"/etc/systemd/journald.conf.d/80-retention.conf", "root", "root", "0644")},
		{Name: "journald | Install vacuum service", Register: "journald_vacuum_service",
			Build: b.Template("journal-vacuum.service.j2", "/etc/systemd/system/journal-vacuum.service", "root", "root", "0644")},
		{Name: "journald | Install vacuum timer", Register: "journald_vacuum_timer",
			Build: b.Template("journal-vacuum.timer.j2", "/etc/systemd/system/journal-vacuum.timer", "root", "root", "0644")},
		{Name: "journald | systemd daemon-reload if units changed", When: vacuumChanged, Resource: engine.DaemonReload{}},
		{Name: "journald | Restart systemd-journald if retention config changed", When: Changed("journald_retention_conf"),
			Resource: Unit("systemd-journald.service", nil, "restarted")},
		{Name: "journald | Enable and start vacuum timer", Resource: Unit("journal-vacuum.timer", engine.Bool(true), "started")},
		{Name: "journald | Run vacuum once if config/units changed",
			When:     Changed("journald_retention_conf", "journald_vacuum_service", "journald_vacuum_timer"),
			Resource: Unit("journal-vacuum.service", nil, "started")},
	}
}
