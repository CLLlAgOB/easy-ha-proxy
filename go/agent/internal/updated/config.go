// Package updated implements the easy-ha-proxy-updated JSON-line AF_UNIX broker.
package updated

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/unixrpc"
)

const ProtocolVersion = 2

var (
	IdentifierRe = regexp.MustCompile(`^[0-9a-f]{32}$`)
	BootIDRe     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	ActorRe      = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,128}$`)
)

// AutoCheckChoices mirrors updated/constants.py AUTO_CHECK_CHOICES.
var AutoCheckChoices = map[int]struct{}{
	0: {}, 6: {}, 12: {}, 24: {}, 72: {}, 168: {},
}

// AllowedComponents mirrors updated/constants.py ALLOWED_COMPONENTS.
var AllowedComponents = map[string]struct{}{
	"all": {}, "changes": {}, "services": {}, "daemons": {},
	"authelia-container": {}, "admin-container": {}, "os": {}, "haproxy": {},
}

// RequestFields mirrors updated/constants.py REQUEST_FIELDS strict field whitelist.
var RequestFields = map[string]map[string]struct{}{
	"status":                    setOf("action", "job_id"),
	"set_settings":              setOf("action", "auto_check_hours"),
	"set_auto_install":          setOf("action", "enabled", "start", "end", "os", "unified", "runtime"),
	"set_auto_reboot":           setOf("action", "enabled"),
	"set_service_restarts":      setOf("action", "enabled"),
	"summary":                   setOf("action"),
	"start_check":               setOf("action", "image_channel", "source_channel", "release_channel"),
	"start_apply":               setOf("action", "plan_id", "components", "confirmation"),
	"set_channels":              setOf("action", "image_channel", "source_channel", "release_channel"),
	"reboot":                    setOf("action", "confirmation", "expected_boot_id", "actor"),
	"cancel_reboot":             setOf("action", "expected_boot_id", "actor"),
	"prepare_haproxy_migration": setOf("action", "target_branch"),
	"apply_haproxy_migration":   setOf("action", "plan_id", "confirmation"),
	"start_haproxy_transition":  setOf("action", "target_branch", "confirmed"),
	"os_security_status":        setOf("action", "job_id"),
	"os_security_check":         setOf("action"),
	"os_security_install":       setOf("action"),
	"os_security_configure":     setOf("action", "policy"),
	"os_security_restart_check": setOf("action"),
	"os_security_restart":       setOf("action", "confirmation"),
	"ssh_protection_status":     setOf("action", "job_id"),
	"ssh_protection_connection": setOf("action", "user", "ip", "hostname", "local_address", "port"),
	"ssh_protection_monitor":    setOf("action", "enabled"),
	"ssh_protection_configure":  setOf("action", "operation", "trusted", "policy"),
	"ssh_protection_unban":      setOf("action", "ip"),
}

func setOf(items ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(items))
	for _, it := range items {
		m[it] = struct{}{}
	}
	return m
}

// Options holds runtime paths and limits matching updated/constants.py.
type Options struct {
	SocketPath               string
	StateRoot                string
	SourceDir                string
	ConfigDir                string
	CLIPath                  string
	RebootMarker             string
	AssistantRebootMarker    string
	MaintenanceLockPath      string
	HAProxyTransactionState  string
	SSHProtectionMonitorPath string
	BootIDPath               string
	ShutdownBin              string
	SocketUser               string
	SocketGroup              string
	AppUID                   int
	MaxRequestBytes          int
	MaxResponseBytes         int
	ListLimit                int
	AutoCheckHours           int
	MaxConnections           int
}

// OptionsFromEnv reads Options from UPDATED_* environment variables.
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
	stateRoot := envOr("UPDATED_STATE_ROOT", "/var/lib/easy-ha-proxy/update-web")
	sockUser := envOr("UPDATED_SOCKET_USER", "haproxyadmin")
	sockGroup := envOr("UPDATED_APP_GROUP", "hadmin")
	return Options{
		SocketPath:               envOr("UPDATED_SOCKET_PATH", "/run/easy-ha-proxy/easy-ha-proxy-updated.sock"),
		SocketUser:               sockUser,
		SocketGroup:              sockGroup,
		StateRoot:                stateRoot,
		SourceDir:                envOr("UPDATED_SOURCE_DIR", "/opt/easy-ha-proxy/source"),
		ConfigDir:                envOr("UPDATED_CONFIG_DIR", "/etc/easy-ha-proxy"),
		CLIPath:                  envOr("UPDATED_CLI_PATH", "/usr/local/bin/easy-ha-proxy"),
		RebootMarker:             envOr("UPDATED_REBOOT_MARKER", "/run/easy-ha-proxy/easy-ha-proxy-web-reboot.json"),
		AssistantRebootMarker:    "/run/easy-ha-proxy/reboot-scheduled",
		MaintenanceLockPath:      envOr("UPDATED_MAINTENANCE_LOCK", "/run/easy-ha-proxy/easy-ha-proxy-backupd.operation.lock"),
		HAProxyTransactionState:  envOr("UPDATED_HAPROXY_TRANSACTION_STATE", "/var/lib/easy-ha-proxy/haproxy-config-guard/transaction.json"),
		SSHProtectionMonitorPath: filepath.Join(stateRoot, "ssh-protection-monitor.json"),
		BootIDPath:               "/proc/sys/kernel/random/boot_id",
		ShutdownBin:              "/sbin/shutdown",
		AppUID:                   unixrpc.ResolveUID(sockUser, os.Getuid()),
		MaxRequestBytes:          envInt("UPDATED_MAX_REQUEST_BYTES", 32*1024),
		MaxResponseBytes:         envInt("UPDATED_MAX_RESPONSE_BYTES", 2*1024*1024),
		ListLimit:                envInt("UPDATED_LIST_LIMIT", 30),
		AutoCheckHours:           envInt("UPDATED_AUTO_CHECK_HOURS", 24),
		MaxConnections:           envInt("UPDATED_MAX_CONNECTIONS", 16),
	}
}

func (o Options) JobsDir() string        { return filepath.Join(o.StateRoot, "jobs") }
func (o Options) LatestPlanPath() string { return filepath.Join(o.StateRoot, "latest-plan.json") }
func (o Options) SettingsPath() string   { return filepath.Join(o.StateRoot, "settings.json") }
