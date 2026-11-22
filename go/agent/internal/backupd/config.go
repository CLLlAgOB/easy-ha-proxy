// Package backupd implements the easy-ha-proxy-backupd JSON-line AF_UNIX daemon.
package backupd

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/unixrpc"
)

var (
	IdentifierRe = regexp.MustCompile(`^[0-9a-f]{32}$`)
	SHA256Re     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	DestNameRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,39}$`)
)

const (
	ArchiveSuffix  = ".tar.gz.enc"
	ChecksumSuffix = ArchiveSuffix + ".sha256"
	MetaSuffix     = ArchiveSuffix + ".json"
)

// RequestFields mirrors backupd/constants.py REQUEST_FIELDS strict field whitelist.
var RequestFields = map[string]map[string]struct{}{
	"status":              setOf("action", "job_id"),
	"stage_backup":        setOf("action", "backup_id"),
	"start_backup":        setOf("action", "passphrase", "include_ssh", "quiesce"),
	"start_inspect":       setOf("action", "upload_id", "passphrase"),
	"start_restore":       setOf("action", "upload_id", "passphrase", "inspection_job_id", "restore_ssh", "confirmation", "scope"),
	"delete":              setOf("action", "kind", "id", "confirmation"),
	"destinations":        setOf("action"),
	"destination_save":    setOf("action", "name", "type", "host", "port", "user", "path", "private_key", "host_key", "keep_daily", "keep_weekly", "keep_monthly", "endpoint", "region", "bucket", "prefix", "access_key", "secret_key", "allow_insecure", "verify", "passphrase"),
	"destination_delete":  setOf("action", "name"),
	"destination_test":    setOf("action", "name"),
	"destination_retrust": setOf("action", "name"),
	"upload":              setOf("action", "backup_id", "destination"),
	"schedule":            setOf("action"),
	"schedule_save":       setOf("action", "enabled", "cadence", "hour", "minute", "weekday", "day", "include_ssh", "quiesce", "passphrase", "destinations", "keep_local"),
	"run_scheduled":       setOf("action"),
}

func setOf(items ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(items))
	for _, it := range items {
		m[it] = struct{}{}
	}
	return m
}

// Options holds runtime directories and limits from BACKUPD_* environment variables.
type Options struct {
	SocketPath            string
	SpoolRoot             string
	SourceDir             string
	OperationLockPath     string
	RebootMarker          string
	AssistantRebootMarker string
	RestoreActiveMarker   string
	SocketUser            string
	SocketGroup           string
	AppUID                int
	MaxRequestBytes       int
	MinFreeBytes          uint64
	LowSpaceBytes         uint64
	ListLimit             int
	MaxConnections        int
}

// OptionsFromEnv reads Options matching backupd/constants.py.
func OptionsFromEnv() Options {
	envOr := func(key, fallback string) string {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			return v
		}
		return fallback
	}
	envInt := func(key string, fallback int) int {
		if raw := strings.TrimSpace(os.Getenv(key)); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil && n >= 0 {
				return n
			}
		}
		return fallback
	}
	sockUser := envOr("BACKUPD_SOCKET_USER", "haproxyadmin")
	sockGroup := envOr("BACKUPD_APP_GROUP", "hadmin")
	return Options{
		SocketPath:            envOr("BACKUPD_SOCKET_PATH", "/run/easy-ha-proxy/easy-ha-proxy-backupd.sock"),
		SocketUser:            sockUser,
		SocketGroup:           sockGroup,
		SpoolRoot:             envOr("BACKUPD_ROOT_DIR", "/var/lib/easy-ha-proxy/backup-web"),
		SourceDir:             envOr("BACKUPD_SOURCE_DIR", "/opt/easy-ha-proxy/source"),
		OperationLockPath:     envOr("BACKUPD_OPERATION_LOCK", "/run/easy-ha-proxy/easy-ha-proxy-backupd.operation.lock"),
		RebootMarker:          envOr("BACKUPD_REBOOT_MARKER", "/run/easy-ha-proxy/easy-ha-proxy-web-reboot.json"),
		AssistantRebootMarker: "/run/easy-ha-proxy/reboot-scheduled",
		RestoreActiveMarker:   envOr("BACKUPD_RESTORE_ACTIVE_MARKER", "/run/easy-ha-proxy/easy-ha-proxy-backupd-restore.active"),
		AppUID:                unixrpc.ResolveUID(sockUser, os.Getuid()),
		MaxRequestBytes:       envInt("BACKUPD_MAX_REQUEST_BYTES", 64*1024),
		MinFreeBytes:          uint64(envInt("BACKUPD_MIN_FREE_BYTES", 512*1024*1024)),
		LowSpaceBytes:         uint64(envInt("BACKUPD_LOW_SPACE_BYTES", 2*1024*1024*1024)),
		ListLimit:             envInt("BACKUPD_LIST_LIMIT", 50),
		MaxConnections:        envInt("BACKUPD_MAX_CONNECTIONS", 16),
	}
}

func (o Options) JobsDir() string         { return filepath.Join(o.SpoolRoot, "jobs") }
func (o Options) UploadsDir() string      { return filepath.Join(o.SpoolRoot, "uploads") }
func (o Options) BackupsDir() string      { return filepath.Join(o.SpoolRoot, "backups") }
func (o Options) DestinationsPath() string { return filepath.Join(o.SpoolRoot, "destinations.json") }
func (o Options) SchedulePath() string    { return filepath.Join(o.SpoolRoot, "schedule.json") }
