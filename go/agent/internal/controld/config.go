// Package controld is the Go port of haproxy-controld (ansible/roles/
// haproxy-admin/files/controld/*.py). The Python package is the
// specification: the same line protocol over the control socket, the same
// replies (OK/ERROR, base64 JSON where Python sends it), the same files
// (transaction state, configuration history, GeoIP selection and releases,
// admin allow list, UDP failover state) and the same fixed commands.
package controld

import (
	"os"
	"strconv"
	"strings"
	"sync"
)

// Options holds what constants.py reads from the environment.
type Options struct {
	HAProxyAdminSocket, BanTable, IpsetName, PageIpset, AuthTable, AuthIpset string
	CertsHAPDir, CertsLEDir, HAProxyCfgPath, LogTimeOrder, LogFile           string
	LogLimit, BanDeltaSeconds                                                int
	DebugOnEmpty, JournalUseGrep                                             bool
	JournalSources                                                           []string
	JournalPerSourceTimeout, JournalTotalTimeout                             float64
	JournalLinesMult, BanTTLOverride, BanTTLCacheSeconds                     int
	LogsIPCacheSeconds                                                       float64
	LogFileTailChunk, LogFileTailMaxBytes                                    int64
	MaxCommandBytes, MaxConfigBytes                                          int
	ConfigBackupDir                                                          string
	GuardedConfigBackups, ControlPlaneCheckAttempts                          int
	ControlPlaneCheckInterval, ControlPlaneCheckTimeout                      float64
	ConfigSourceDir, ConfigTransactionDir                                    string
	MaintenanceRebootMarker, AssistantRebootMarker                           string
	ConfigTransactionMaxTimeout                                              int
	MaxTransactionSourceFileBytes, MaxTransactionSourcesPayloadBytes         int
	MaxTransactionStateBytes                                                 int
	ConfigHistoryDir                                                         string
	ConfigHistoryKeep                                                        int
	AdminAllowlistPath                                                       string
	GeoIPDirectory, GeoIPUpdateCommand, GeoIPForceMarker, GeoIPTimerDropin   string
	GeoIPUpdateTimeout                                                       int
	UDPForwardState, UDPFailoverState, UDPConfig                             string
	UDPHealthInterval                                                        int
	MaxArchiveBytes, MaxArchiveFiles, MaxArchiveExpandedBytes                int64
	MaxCompressionRatio                                                      int64
	Interval                                                                 int
	ControlSocket, SystemctlCmd, HAProxyBin, StateDumpCmd                    string
	BanRestartGraceSeconds, AuthIpsetTTL                                     int
	ProcNetUDP                                                               []string
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func envI(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err == nil {
			return n
		}
	}
	return def
}

func envF(key string, def float64) float64 {
	if v, ok := os.LookupEnv(key); ok {
		f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err == nil {
			return f
		}
	}
	return def
}

func envFlag(key, def string, falsy ...string) bool {
	v := env(key, def)
	for _, f := range falsy {
		if v == f {
			return false
		}
	}
	return true
}

// OptionsFromEnv reads the environment exactly as constants.py does.
func OptionsFromEnv() Options {
	sources := []string{}
	for _, s := range strings.Split(env("HAPADM_JOURNAL_SOURCES",
		"-u haproxy, SYSLOG_IDENTIFIER=haproxy, -u haproxy.service, -u rsyslog.service, *"), ",") {
		if s = strings.TrimSpace(s); s != "" {
			sources = append(sources, s)
		}
	}
	interval := 10
	if v, ok := os.LookupEnv("HAPADM_BAN_SYNC_INTERVAL"); ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			interval = n
		}
	}
	health := envI("HP_UDP_HEALTH_INTERVAL", 5)
	if health < 2 {
		health = 2
	}
	grace := envI("HAPADM_BAN_RESTART_GRACE_SECONDS", 60)
	if grace < 0 {
		grace = 0
	}
	authTTL := envI("HAPADM_AUTH_IPSET_TTL", 900)
	if authTTL < 30 {
		authTTL = 30
	}
	return Options{
		HAProxyAdminSocket:                env("SOCKET_PATH", "/run/haproxy/admin.sock"),
		BanTable:                          env("HAPADM_BAN_TABLE", "tbl_ban"),
		IpsetName:                         env("HAPADM_IPSET_NAME", "haproxy_ban"),
		PageIpset:                         env("HAPADM_BAN_PAGE_IPSET", "haproxy_ban_page"),
		AuthTable:                         env("HAPADM_AUTH_TABLE", "tbl_ip_auth"),
		AuthIpset:                         env("HAPADM_AUTH_IPSET", "haproxy_ip_auth"),
		CertsHAPDir:                       env("HAPADM_CERTS_HAP_DIR", "/etc/haproxy/certs"),
		CertsLEDir:                        env("HAPADM_CERTS_LE_DIR", "/etc/letsencrypt"),
		HAProxyCfgPath:                    env("HAPROXY_CFG_PATH", "/etc/haproxy/haproxy.cfg"),
		LogTimeOrder:                      strings.ToLower(env("HAPADM_LOG_TIME_ORDER", "asc")),
		LogFile:                           strings.TrimSpace(env("LOG_FILE", "/var/log/haproxy.log")),
		LogLimit:                          envI("HAPADM_LOG_LIMIT", 30),
		BanDeltaSeconds:                   envI("HAPADM_BAN_DELTA_SECONDS", 120),
		DebugOnEmpty:                      envFlag("HAPADM_DEBUG_ON_EMPTY", "1", "0", "false", "False", ""),
		JournalSources:                    sources,
		JournalPerSourceTimeout:           envF("HAPADM_JOURNAL_TIMEOUT", 3),
		JournalTotalTimeout:               envF("HAPADM_JOURNAL_TOTAL_TIMEOUT", 8),
		JournalUseGrep:                    envFlag("HAPADM_JOURNAL_USE_GREP", "1", "0", "false", "False", "no", ""),
		JournalLinesMult:                  envI("HAPADM_JOURNAL_LINES_MULT", 4),
		BanTTLOverride:                    envI("HAPADM_BAN_TTL_SECONDS", 0),
		BanTTLCacheSeconds:                envI("HAPADM_BAN_TTL_CACHE_SECONDS", 300),
		LogsIPCacheSeconds:                envF("HAPADM_LOGS_IP_CACHE_SECONDS", 2),
		LogFileTailChunk:                  int64(envI("HAPADM_LOG_FILE_TAIL_CHUNK", 65536)),
		LogFileTailMaxBytes:               int64(envI("HAPADM_LOG_FILE_TAIL_MAX_BYTES", 64*1024*1024)),
		MaxCommandBytes:                   envI("HAPADM_MAX_COMMAND_BYTES", 32*1024*1024),
		MaxConfigBytes:                    envI("HAPADM_MAX_CONFIG_BYTES", 4*1024*1024),
		ConfigBackupDir:                   env("HAPROXY_CONFIG_BACKUP_DIR", "/opt/haproxy-admin/backups/haproxy"),
		GuardedConfigBackups:              envI("HAPROXY_GUARDED_CONFIG_BACKUPS", 14),
		ControlPlaneCheckAttempts:         envI("HAPROXY_CONTROL_PLANE_CHECK_ATTEMPTS", 6),
		ControlPlaneCheckInterval:         envF("HAPROXY_CONTROL_PLANE_CHECK_INTERVAL", 1),
		ControlPlaneCheckTimeout:          envF("HAPROXY_CONTROL_PLANE_CHECK_TIMEOUT", 2),
		ConfigSourceDir:                   env("HAPROXY_CONFIG_SOURCE_DIR", "/opt/haproxy-admin/config"),
		ConfigTransactionDir:              env("HAPROXY_CONFIG_TRANSACTION_DIR", "/var/lib/easy-ha-proxy/haproxy-config-guard"),
		MaintenanceRebootMarker:           env("EASY_HA_PROXY_REBOOT_MARKER", "/run/easy-ha-proxy/easy-ha-proxy-web-reboot.json"),
		AssistantRebootMarker:             "/run/easy-ha-proxy/reboot-scheduled",
		ConfigTransactionMaxTimeout:       envI("HAPROXY_CONFIG_TRANSACTION_MAX_TIMEOUT", 900),
		MaxTransactionSourceFileBytes:     envI("HAPROXY_CONFIG_SOURCE_MAX_BYTES", 2*1024*1024),
		MaxTransactionSourcesPayloadBytes: envI("HAPROXY_CONFIG_SOURCES_PAYLOAD_MAX_BYTES", 18*1024*1024),
		MaxTransactionStateBytes:          envI("HAPROXY_CONFIG_TRANSACTION_STATE_MAX_BYTES", 20*1024*1024),
		ConfigHistoryDir:                  env("HAPROXY_CONFIG_HISTORY_DIR", "/var/lib/easy-ha-proxy/config-history"),
		ConfigHistoryKeep:                 envI("HAPROXY_CONFIG_HISTORY_KEEP", 50),
		AdminAllowlistPath:                env("HAPROXY_ADMIN_ALLOWLIST_PATH", "/etc/haproxy/admin.allow"),
		GeoIPDirectory:                    env("CONTROLD_GEOIP_DIRECTORY", "/etc/haproxy/geoip"),
		GeoIPUpdateCommand:                "/usr/local/bin/update-geoip.sh",
		GeoIPForceMarker:                  "/run/easy-ha-proxy/geoip-force-download",
		GeoIPTimerDropin:                  env("CONTROLD_GEOIP_TIMER_DROPIN", "/etc/systemd/system/easy-ha-proxy-geoip-update.timer.d/zz-web-schedule.conf"),
		GeoIPUpdateTimeout:                envI("HAPROXY_GEOIP_UPDATE_TIMEOUT", 300),
		UDPForwardState:                   env("HAPROXY_UDP_FORWARD_STATE", "/run/easy-ha-proxy/udp-forward-state.json"),
		UDPFailoverState:                  env("HP_UDP_FAILOVER", "/run/easy-ha-proxy/udp-failover.json"),
		UDPConfig:                         env("HP_UDP_CONFIG", "/opt/haproxy-admin/config/udp.yml"),
		UDPHealthInterval:                 health,
		MaxArchiveBytes:                   int64(envI("HAPADM_MAX_ARCHIVE_BYTES", 64*1024*1024)),
		MaxArchiveFiles:                   int64(envI("HAPADM_MAX_ARCHIVE_FILES", 4096)),
		MaxArchiveExpandedBytes:           int64(envI("HAPADM_MAX_ARCHIVE_EXPANDED_BYTES", 256*1024*1024)),
		MaxCompressionRatio:               int64(envI("HAPADM_MAX_COMPRESSION_RATIO", 100)),
		Interval:                          interval,
		ControlSocket:                     env("HAPROXY_CONTROL_SOCKET", "/run/easy-ha-proxy/haproxy-controld.sock"),
		SystemctlCmd:                      env("HAPROXY_SYSTEMCTL_CMD", "systemctl reload haproxy"),
		HAProxyBin:                        "/usr/sbin/haproxy",
		StateDumpCmd:                      "/usr/local/sbin/haproxy-state-dump",
		BanRestartGraceSeconds:            grace,
		AuthIpsetTTL:                      authTTL,
		ProcNetUDP:                        []string{"/proc/net/udp", "/proc/net/udp6"},
	}
}

const (
	firstStepPageCode           = 41
	ipsetTimeout                = 15
	haproxyCheckTimeout         = 30
	haproxyReloadTimeout        = 120
	configTransactionState      = "transaction.json"
	configTransactionVersion    = 1
	configHistoryMeta           = "meta.json"
	adminAllowlistMaxEntries    = 256
	adminAllowlistMaxBytes      = 64 * 1024
	geoipUpdateService          = "easy-ha-proxy-geoip-update.service"
	geoipUpdateTimer            = "easy-ha-proxy-geoip-update.timer"
	geoipMaxSelectionBytes      = 16 * 1024
	geoipMaxStateBytes          = 128 * 1024
	geoipMaxCountries           = 249
	udpForwardStateMaxBytes     = 16 * 1024
	udpMaxPortRange             = 1024
	udpFailoverStateMaxBytes    = 64 * 1024
	udpFailAfter                = 3
	udpRecoverAfter             = 6
	udpFailoverRule             = "udp.failover"
	udpFailoverReportSeconds    = 300
	udpApplyRetrySeconds        = 30
	logsIPCacheMax              = 512
	logsIPCacheMaxLimit         = 2000
	configTransactionMinTimeout = 1
)

var (
	configSourceFilenames = map[string]bool{"vars.yml": true, "websites.yml": true, "tcp.yml": true}
	activeStates          = map[string]bool{"prepared": true, "pending_confirmation": true, "rolling_back": true, "rollback_failed": true}
	geoipAllowedSchedules = []string{"daily", "weekly", "monthly"}
)

// Daemon holds the module-level state.
type Daemon struct {
	Opts      Options
	guarded   sync.Mutex // _GUARDED_APPLY_LOCK
	geoipOp   sync.Mutex // _GEOIP_OPERATION_LOCK
	logScans  chan struct{}
	ttlMu     sync.Mutex
	ttlValue  int
	ttlAt     float64
	ttlSet    bool
	logsMu    sync.Mutex
	logsCache map[string]logsCacheEntry
	logsOrder []string
	failover  *udpFailover
	alerts    alertSink
}

type logsCacheEntry struct {
	expires float64
	lines   []string
}
