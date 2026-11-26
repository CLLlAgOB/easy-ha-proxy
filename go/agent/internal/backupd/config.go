// Package backupd is the Go port of easy-ha-proxy-backupd (ansible/roles/
// haproxy-admin/files/backupd/*.py). The Python package is the specification:
// the same socket protocol, request fields, error codes, state files, archive
// format (made by the agent's full-backup command) and off-host copy layout, so the
// two implementations can replace each other on a running gateway.
package backupd

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Error is an expected request or job failure safe to return to the UI
// (BackupdError).
type Error struct {
	Code string
	Msg  string
}

func (e *Error) Error() string { return e.Msg }

func bErr(code, format string, args ...any) *Error {
	if code == "" {
		code = "invalid"
	}
	msg := format
	if len(args) > 0 {
		msg = fmt.Sprintf(format, args...)
	}
	return &Error{Code: code, Msg: msg}
}

var (
	identifierRe = regexp.MustCompile(`^[0-9a-f]{32}$`)
	sha256Re     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

const (
	ArchiveSuffix     = ".tar.gz.enc"
	ChecksumSuffix    = ArchiveSuffix + ".sha256"
	MetaSuffix        = ArchiveSuffix + ".json"
	stageRecordPrefix = "stage-"
	stageRecordSuffix = ".json"
	manifestMarker    = "EASY_HA_PROXY_BACKUP_MANIFEST_JSON="
	backupFileMarker  = "EASY_HA_PROXY_FULL_BACKUP_FILE="
	lowSpaceFraction  = 0.10
	systemdRunPath    = "/usr/bin/systemd-run"
	systemctlPath     = "/usr/bin/systemctl"
	transientStopSecs = 30
)

var manifestKeys = []string{
	"format", "format_version", "created_at", "hostname", "machine",
	"ssh_included", "metrics_included", "quiesced", "payload_sha256",
	"ssh_payload_sha256", "payload_expanded_bytes", "ssh_payload_expanded_bytes",
	"root_domain", "admin_domain", "configuration_mode",
}

func setOf(items ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(items))
	for _, it := range items {
		m[it] = struct{}{}
	}
	return m
}

// RequestFields is REQUEST_FIELDS: the exact fields each action accepts.
var RequestFields = map[string]map[string]struct{}{
	"status":        setOf("action", "job_id"),
	"stage_backup":  setOf("action", "backup_id"),
	"start_backup":  setOf("action", "passphrase", "include_ssh", "quiesce"),
	"start_inspect": setOf("action", "upload_id", "passphrase"),
	"start_restore": setOf("action", "upload_id", "passphrase", "inspection_job_id",
		"restore_ssh", "confirmation", "scope"),
	"delete":       setOf("action", "kind", "id", "confirmation"),
	"destinations": setOf("action"),
	"destination_save": setOf("action", "name", "type", "host", "port", "user", "path",
		"private_key", "host_key", "keep_daily", "keep_weekly", "keep_monthly",
		"endpoint", "region", "bucket", "prefix", "access_key", "secret_key",
		"allow_insecure", "verify", "auth", "password"),
	"destination_delete":  setOf("action", "name"),
	"destination_test":    setOf("action", "name"),
	"destination_retrust": setOf("action", "name"),
	"upload":              setOf("action", "backup_id", "destination"),
	"schedule":            setOf("action"),
	"schedule_save": setOf("action", "enabled", "destinations", "include_ssh", "quiesce",
		"passphrase", "time", "keep_local"),
	"run_scheduled": setOf("action", "on_demand"),
}

// Options holds every path and limit the Python daemon reads from BACKUPD_*.
type Options struct {
	SocketPath            string
	SpoolRoot             string
	SourceDir             string
	AppUser               string
	AppGroup              string
	RestoreActiveMarker   string
	RestartRequestMarker  string
	RebootMarker          string
	AssistantRebootMarker string
	OperationLockPath     string
	ServiceName           string
	DestinationsDir       string
	SchedulePath          string
	SchedulePassphrase    string
	TimerDropinDir        string

	MaxRequestBytes   int
	MaxArchiveBytes   int64
	MinFreeBytes      int64
	LowSpaceBytes     int64
	MaxCaptureBytes   int
	MaxStateBytes     int
	JobTimeoutSeconds int
	ListLimit         int
	UploadTTLSeconds  int
	MaxConnections    int

	SFTPTimeoutSeconds      int
	S3TimeoutSeconds        int
	ScheduledTimeoutSeconds int
	VerifyDownloadMaxBytes  int64

	// Resolved at start (ensure_layout).
	AppUID        int
	AppPrimaryGID int
	AppGroupGID   int
}

func envOr(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

// envInt is env_int: an integer within [minimum, maximum] or an error.
func envInt(key string, def, minimum, maximum int) (int, error) {
	raw, ok := os.LookupEnv(key)
	if !ok {
		raw = strconv.Itoa(def)
	}
	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, bErr("invalid", "%s must be an integer", key)
	}
	if v < minimum || (maximum > 0 && v > maximum) {
		return 0, bErr("invalid", "%s is outside the supported range", key)
	}
	return v, nil
}

func plainEnvInt(key string, def int) int {
	if v, err := strconv.Atoi(strings.TrimSpace(os.Getenv(key))); err == nil {
		return v
	}
	return def
}

// OptionsFromEnv reads the same environment constants.py and destinations.py do.
func OptionsFromEnv() (Options, error) {
	o := Options{
		SocketPath:            envOr("BACKUPD_SOCKET_PATH", "/run/easy-ha-proxy/easy-ha-proxy-backupd.sock"),
		SpoolRoot:             envOr("BACKUPD_ROOT_DIR", "/var/lib/easy-ha-proxy/backup-web"),
		SourceDir:             envOr("BACKUPD_SOURCE_DIR", "/opt/easy-ha-proxy/source"),
		AppUser:               envOr("BACKUPD_SOCKET_USER", "haproxyadmin"),
		AppGroup:              envOr("BACKUPD_APP_GROUP", "hadmin"),
		RestoreActiveMarker:   envOr("BACKUPD_RESTORE_ACTIVE_MARKER", "/run/easy-ha-proxy/easy-ha-proxy-backupd-restore.active"),
		RestartRequestMarker:  envOr("BACKUPD_RESTART_REQUEST_MARKER", "/run/easy-ha-proxy/easy-ha-proxy-backupd-restart.requested"),
		RebootMarker:          envOr("BACKUPD_REBOOT_MARKER", "/run/easy-ha-proxy/easy-ha-proxy-web-reboot.json"),
		AssistantRebootMarker: "/run/easy-ha-proxy/reboot-scheduled",
		OperationLockPath:     envOr("BACKUPD_OPERATION_LOCK", "/run/easy-ha-proxy/easy-ha-proxy-backupd.operation.lock"),
		ServiceName:           envOr("BACKUPD_SERVICE_NAME", "easy-ha-proxy-backupd.service"),
		DestinationsDir:       envOr("BACKUPD_DESTINATIONS_DIR", "/etc/easy-ha-proxy/backup-destinations"),
		SchedulePath:          envOr("BACKUPD_SCHEDULE", "/etc/easy-ha-proxy/backup-schedule.json"),
		SchedulePassphrase:    envOr("BACKUPD_SCHEDULE_PASSPHRASE", "/etc/easy-ha-proxy/backup-schedule.key"),
		TimerDropinDir:        envOr("BACKUPD_TIMER_DROPIN", "/etc/systemd/system/easy-ha-proxy-backup.timer.d"),

		SFTPTimeoutSeconds:      plainEnvInt("BACKUPD_SFTP_TIMEOUT", 900),
		S3TimeoutSeconds:        plainEnvInt("BACKUPD_S3_TIMEOUT", 900),
		ScheduledTimeoutSeconds: plainEnvInt("BACKUPD_SCHEDULED_TIMEOUT", 6*3600),
		VerifyDownloadMaxBytes:  int64(plainEnvInt("BACKUPD_VERIFY_DOWNLOAD_MAX", 2*1024*1024*1024)),
		AppUID:                  -1,
		AppPrimaryGID:           -1,
		AppGroupGID:             -1,
	}
	type spec struct {
		key           string
		def, min, max int
		set           func(int)
	}
	specs := []spec{
		{"BACKUPD_MAX_REQUEST_BYTES", 64 * 1024, 1, 64 * 1024, func(v int) { o.MaxRequestBytes = v }},
		{"BACKUPD_MAX_ARCHIVE_BYTES", 8 * 1024 * 1024 * 1024, 1, 0, func(v int) { o.MaxArchiveBytes = int64(v) }},
		{"BACKUPD_MIN_FREE_BYTES", 512 * 1024 * 1024, 1, 0, func(v int) { o.MinFreeBytes = int64(v) }},
		{"BACKUPD_LOW_SPACE_BYTES", 2 * 1024 * 1024 * 1024, 1, 0, func(v int) { o.LowSpaceBytes = int64(v) }},
		{"BACKUPD_MAX_CAPTURE_BYTES", 64 * 1024, 1, 512 * 1024, func(v int) { o.MaxCaptureBytes = v }},
		{"BACKUPD_MAX_STATE_BYTES", 256 * 1024, 1, 1024 * 1024, func(v int) { o.MaxStateBytes = v }},
		{"BACKUPD_JOB_TIMEOUT_SECONDS", 6 * 60 * 60, 1, 24 * 60 * 60, func(v int) { o.JobTimeoutSeconds = v }},
		{"BACKUPD_LIST_LIMIT", 50, 1, 200, func(v int) { o.ListLimit = v }},
		{"BACKUPD_UPLOAD_TTL_SECONDS", 24 * 60 * 60, 1, 30 * 24 * 60 * 60, func(v int) { o.UploadTTLSeconds = v }},
		{"BACKUPD_MAX_CONNECTIONS", 16, 1, 64, func(v int) { o.MaxConnections = v }},
	}
	for _, sp := range specs {
		v, err := envInt(sp.key, sp.def, sp.min, sp.max)
		if err != nil {
			return o, err
		}
		sp.set(v)
	}
	return o, nil
}

func (o Options) JobsDir() string    { return filepath.Join(o.SpoolRoot, "jobs") }
func (o Options) UploadsDir() string { return filepath.Join(o.SpoolRoot, "uploads") }
func (o Options) BackupsDir() string { return filepath.Join(o.SpoolRoot, "backups") }
func (o Options) TimerDropinPath() string {
	return filepath.Join(o.TimerDropinDir, "schedule.conf")
}
