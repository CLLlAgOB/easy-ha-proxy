// Package updated is the Go port of easy-ha-proxy-updated (ansible/roles/
// haproxy-admin/files/updated/*.py). The Python package is the specification:
// same socket protocol, request fields, error codes, job and plan files, and
// the same fixed-argv helpers it runs from the managed source.
package updated

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Error is UpdatedError: an expected failure safe to return to the web UI.
type Error struct {
	Code string
	Msg  string
}

func (e *Error) Error() string { return e.Msg }

func uErr(code, format string, args ...any) *Error {
	if code == "" {
		code = "invalid"
	}
	msg := format
	if len(args) > 0 {
		msg = fmt.Sprintf(format, args...)
	}
	return &Error{Code: code, Msg: msg}
}

const (
	protocolVersion        = 2
	changesComponent       = "changes"
	componentHeading       = "=== Applying component:"
	maxProgressTask        = 160
	autoCheckRetrySeconds  = 3600
	autoCheckPollSeconds   = 60
	systemdRunPath         = "/usr/bin/systemd-run"
	systemctlPath          = "/usr/bin/systemctl"
	transientStopTimeout   = 30
	rebootUnitPrefix       = "easy-ha-proxy-web-reboot"
	rebootConfirmation     = "REBOOT"
	availableRule          = "update.available"
	availableSubject       = "software"
	alertChangelogLines    = 15
	channelMismatchMessage = "This update was checked for a different release channel than the one " +
		"this gateway is set to. Save the channel first, or run the check again."
	haproxyMigrationConfirmation = "MIGRATE 3.4"
	sshProtectionJob             = "ssh-protection"
)

var (
	identifierRe     = regexp.MustCompile(`^[0-9a-f]{32}$`)
	bootIDRe         = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	actorRe          = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,128}$`)
	sourceRevisionRe = regexp.MustCompile(`^[0-9a-f]{40,64}$`)
	imageDigestRe    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	controlRe        = regexp.MustCompile(`[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]`)
	progressRe       = regexp.MustCompile(`(?m)^EHP-PROGRESS (?:phase=([a-z-]{1,24})|(\d{1,6})/(\d{1,6})(?: ([^\n]{0,400}))?)[ \t]*$`)
	branchRe         = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,100}$`)
	rebootUnitRe     = regexp.MustCompile(`^` + regexp.QuoteMeta(rebootUnitPrefix) + `-[0-9a-f]{12}$`)
	autoRebootTimeRe = regexp.MustCompile(`^(?:[01][0-9]|2[0-3]):[0-5][0-9]$`)
	sourceVersionRe  = regexp.MustCompile(`^\d{1,4}\.\d{1,4}\.\d{1,4}(?:-[0-9A-Za-z.]{1,24})?$`)
	haproxyVersionRe = regexp.MustCompile(`^[0-9][A-Za-z0-9.+:~_-]{1,100}$`)
)

var (
	allowedComponents   = setOf("all", changesComponent, "services", "daemons", "authelia-container", "admin-container", "os", "haproxy")
	sourceComponents    = setOf("all", "services", "daemons", changesComponent)
	containerComponents = setOf("authelia-container", "admin-container")
	progressPhases      = setOf("checking", "verifying", "starting", "source", "prepare", "syntax", "playbook", "rechecking")
	autoCheckChoices    = []int64{0, 6, 12, 24, 72, 168}
	sourceChannels      = setOf("github", "local")
	imageChannels       = setOf("latest", "alpha")
	releaseChannels     = setOf("stable", "alpha", "local")
	releaseChannelMap   = map[string][2]string{"stable": {"main", "latest"}, "alpha": {"alpha", "alpha"}}
	componentOrder      = map[string]int{"all": 0, changesComponent: 1, "services": 1, "daemons": 2,
		"authelia-container": 3, "admin-container": 4, "os": 5, "haproxy": 6}
	alertComponentNames = map[string]string{
		"all": "a new source revision", "services": "host services", "daemons": "helper daemons",
		"authelia-container": "Authelia containers", "admin-container": "the web application",
		"os": "operating-system packages", "haproxy": "HAProxy",
	}
	haproxyTransactionActive  = setOf("prepared", "pending_confirmation", "rolling_back", "rollback_failed")
	haproxyTransactionSettled = setOf("confirmed", "rolled_back")
	haproxySettledPhases      = setOf("committed", "rolled_back", "aborted", "preparing", "prepared")
	osSecurityModes           = setOf("system", "notify", "auto", "window", "daily")
	osSecurityIntervals       = []int64{1, 2, 4, 6, 12, 24}
	webTreeInputs             = []string{"Dockerfile", ".dockerignore", "docker/app"}
	// The Go panel image's inputs, as CI fingerprints them (go_web_tree).
	goWebTreeInputs = []string{"go/panel", "docker/app/haproxy_admin/static", "docker/app/haproxy_admin/translations",
		"docker/app/haproxy_admin/templates"}
)

func setOf(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, it := range items {
		m[it] = true
	}
	return m
}

func fields(items ...string) map[string]bool { return setOf(append([]string{"action"}, items...)...) }

// RequestFields is REQUEST_FIELDS.
var RequestFields = map[string]map[string]bool{
	"status":                    fields("job_id"),
	"set_settings":              fields("auto_check_hours"),
	"set_auto_install":          fields("enabled", "start", "end", "os", "unified", "runtime"),
	"summary":                   fields(),
	"start_check":               fields("image_channel", "source_channel", "release_channel"),
	"start_apply":               fields("plan_id", "components", "confirmation"),
	"set_channels":              fields("image_channel", "source_channel", "release_channel"),
	"reboot":                    fields("confirmation", "expected_boot_id", "actor"),
	"cancel_reboot":             fields("expected_boot_id", "actor"),
	"prepare_haproxy_migration": fields("target_branch"),
	"apply_haproxy_migration":   fields("plan_id", "confirmation"),
	"start_haproxy_transition":  fields("target_branch", "confirmed"),
	"os_security_status":        fields("job_id"),
	"ssh_protection_status":     fields("job_id"),
	"ssh_protection_connection": fields("user", "ip", "hostname", "local_address", "port"),
	"ssh_protection_monitor":    fields("enabled"),
	"ssh_protection_configure":  fields("operation", "trusted", "policy"),
	"ssh_protection_unban":      fields("ip"),
	"os_security_check":         fields(),
	"os_security_install":       fields("confirmation"),
	"os_security_configure":     fields("mode", "interval", "start", "end", "confirmation"),
	"set_auto_reboot":           fields("enabled", "time", "allow_service_reboot", "confirmation", "expected_boot_id", "actor"),
	"set_service_restarts":      fields("enabled", "time", "confirmation", "expected_boot_id", "actor"),
	"os_security_restart_check": fields(),
	"os_security_restart":       fields("confirmation"),
}

// Options holds every path and limit constants.py and runner.py read.
type Options struct {
	SocketPath, StateRoot, SourceDir, ConfigDir, PythonPath, CLIPath   string
	AppUser, AppGroup, ServiceName                                     string
	ActiveMarker, RestartRequestMarker, RebootMarker                   string
	AssistantRebootMarker, MaintenanceLockPath                         string
	HAProxyTransactionMarker, HAProxyTransactionState                  string
	BackupdRestoreMarker, BootIDPath, RebootRequiredPath, ProcStatPath string
	HAProxyUpdateState, HAProxyMigrationState                          string

	MaxRequestBytes, MaxResponseBytes, MaxCaptureBytes, MaxStateBytes int
	JobTimeoutSeconds, CheckTimeoutSeconds, PlanTTLSeconds, ListLimit int
	AutoCheckHours, AutoCheckDelaySeconds, MaxConnections             int
	RebootDelaySeconds                                                int

	AppUID, AppPrimaryGID, AppGroupGID int
}

func envOr(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

// OptionsFromEnv reads the same environment the Python package does.
func OptionsFromEnv() (Options, error) {
	o := Options{
		SocketPath:               envOr("UPDATED_SOCKET_PATH", "/run/easy-ha-proxy/easy-ha-proxy-updated.sock"),
		StateRoot:                envOr("UPDATED_STATE_ROOT", "/var/lib/easy-ha-proxy/update-web"),
		SourceDir:                envOr("UPDATED_SOURCE_DIR", "/opt/easy-ha-proxy/source"),
		ConfigDir:                envOr("UPDATED_CONFIG_DIR", "/etc/easy-ha-proxy"),
		PythonPath:               envOr("UPDATED_PYTHON_PATH", "/opt/easy-ha-proxy/venv/bin/python"),
		CLIPath:                  envOr("UPDATED_CLI_PATH", "/usr/local/bin/easy-ha-proxy"),
		AppUser:                  envOr("UPDATED_SOCKET_USER", "haproxyadmin"),
		AppGroup:                 envOr("UPDATED_APP_GROUP", "hadmin"),
		ServiceName:              envOr("UPDATED_SERVICE_NAME", "easy-ha-proxy-updated.service"),
		ActiveMarker:             envOr("UPDATED_ACTIVE_MARKER", "/run/easy-ha-proxy/easy-ha-proxy-update.active"),
		RestartRequestMarker:     envOr("UPDATED_RESTART_REQUEST_MARKER", "/run/easy-ha-proxy/easy-ha-proxy-updated-restart.requested"),
		RebootMarker:             envOr("UPDATED_REBOOT_MARKER", "/run/easy-ha-proxy/easy-ha-proxy-web-reboot.json"),
		AssistantRebootMarker:    "/run/easy-ha-proxy/reboot-scheduled",
		MaintenanceLockPath:      envOr("UPDATED_MAINTENANCE_LOCK", "/run/easy-ha-proxy/easy-ha-proxy-backupd.operation.lock"),
		HAProxyTransactionMarker: envOr("UPDATED_HAPROXY_TRANSACTION_MARKER", "/opt/haproxy-admin/backups/haproxy/pending_ui_transaction.json"),
		HAProxyTransactionState:  envOr("UPDATED_HAPROXY_TRANSACTION_STATE", "/var/lib/easy-ha-proxy/haproxy-config-guard/transaction.json"),
		BackupdRestoreMarker:     envOr("UPDATED_BACKUPD_RESTORE_MARKER", "/run/easy-ha-proxy/easy-ha-proxy-backupd-restore.active"),
		BootIDPath:               "/proc/sys/kernel/random/boot_id",
		RebootRequiredPath:       "/var/run/reboot-required",
		ProcStatPath:             "/proc/stat",
		HAProxyUpdateState:       "/var/lib/easy-ha-proxy/haproxy-package-migration/last-update.json",
		HAProxyMigrationState:    "/var/lib/easy-ha-proxy/haproxy-package-migration/last-migration.json",
		AppUID:                   -1, AppPrimaryGID: -1, AppGroupGID: -1,
	}
	type spec struct {
		key           string
		def, min, max int
		dst           *int
	}
	for _, sp := range []spec{
		{"UPDATED_MAX_REQUEST_BYTES", 32 * 1024, 1, 64 * 1024, &o.MaxRequestBytes},
		{"UPDATED_MAX_RESPONSE_BYTES", 2 * 1024 * 1024, 1, 4 * 1024 * 1024, &o.MaxResponseBytes},
		{"UPDATED_MAX_CAPTURE_BYTES", 256 * 1024, 1, 1024 * 1024, &o.MaxCaptureBytes},
		{"UPDATED_MAX_STATE_BYTES", 1024 * 1024, 1, 2 * 1024 * 1024, &o.MaxStateBytes},
		{"UPDATED_JOB_TIMEOUT_SECONDS", 2 * 60 * 60, 1, 12 * 60 * 60, &o.JobTimeoutSeconds},
		{"UPDATED_CHECK_TIMEOUT_SECONDS", 10 * 60, 1, 30 * 60, &o.CheckTimeoutSeconds},
		{"UPDATED_PLAN_TTL_SECONDS", 15 * 60, 1, 24 * 60 * 60, &o.PlanTTLSeconds},
		{"UPDATED_LIST_LIMIT", 30, 1, 100, &o.ListLimit},
		{"UPDATED_AUTO_CHECK_HOURS", 24, 0, 24 * 30, &o.AutoCheckHours},
		{"UPDATED_AUTO_CHECK_DELAY_SECONDS", 900, 0, 24 * 3600, &o.AutoCheckDelaySeconds},
		{"UPDATED_MAX_CONNECTIONS", 16, 1, 64, &o.MaxConnections},
		{"UPDATED_REBOOT_DELAY_SECONDS", 60, 15, 15 * 60, &o.RebootDelaySeconds},
	} {
		raw, ok := os.LookupEnv(sp.key)
		if !ok {
			raw = strconv.Itoa(sp.def)
		}
		v, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil {
			return o, uErr("invalid", "%s must be an integer", sp.key)
		}
		if v < sp.min || v > sp.max {
			return o, uErr("invalid", "%s is outside the supported range", sp.key)
		}
		*sp.dst = v
	}
	return o, nil
}

func (o Options) JobsDir() string         { return filepath.Join(o.StateRoot, "jobs") }
func (o Options) LatestPlanPath() string  { return filepath.Join(o.StateRoot, "latest-plan.json") }
func (o Options) SettingsPath() string    { return filepath.Join(o.StateRoot, "settings.json") }
func (o Options) AutoInstallPath() string { return filepath.Join(o.StateRoot, "auto-install.json") }
func (o Options) OSSecurityRoot() string  { return filepath.Join(o.StateRoot, "os-security") }
func (o Options) MigrationPlanPath() string {
	return filepath.Join(o.StateRoot, "haproxy-migration-plan.json")
}
func (o Options) SSHMonitorPath() string {
	return filepath.Join(o.StateRoot, "ssh-protection-monitor.json")
}
func (o Options) MaintenanceCyclePath() string {
	return filepath.Join(o.StateRoot, "maintenance-cycle.json")
}
