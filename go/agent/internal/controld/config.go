// Package controld implements the AF_UNIX line-protocol control daemon for HAProxy.
package controld

import (
	"os"
	"strconv"
	"strings"
)

const (
	MaxCommandBytes      = 32 * 1024 * 1024
	MaxConfigBytes       = 4 * 1024 * 1024
	UDPMaxPortRange      = 1024
	MaxClientSlots       = 32
	FirstStepPageCode    = 41
	TxMinTimeoutSeconds  = 1
	TxMaxTimeoutSeconds  = 900
	TxVersion            = 1
	UDPFailAfter         = 3
	UDPRecoverAfter      = 6
)

// Options holds runtime paths and limits loaded from environment variables.
type Options struct {
	ControlSocket           string
	HAProxyAdminSocket      string
	HAProxyBin              string
	HAProxyCfgPath          string
	SystemctlBin            string
	IpsetBin                string
	ServerStatePath         string
	BanTable                string
	IpsetName               string
	PageIpset               string
	AuthTable               string
	AuthIpset               string
	BanSyncIntervalSec      int
	BanRestartGraceSec      int
	AuthIpsetTTLSec         int
	LogFile                 string
	LogLimit                int
	LogTailChunk            int
	LogTailMaxBytes         int64
	ConfigBackupDir         string
	ConfigSourceDir         string
	ConfigHistoryDir        string
	ConfigTransactionDir    string
	MaintenanceRebootMarker string
	AssistantRebootMarker   string
	UDPForwardState         string
	UDPFailoverState        string
	UDPHealthIntervalSec    int
	GeoIPDir                string
	ProcNetUDPPath          string
	ProcNetUDP6Path         string
}

// OptionsFromEnv constructs Options matching controld/constants.py environment variables.
func OptionsFromEnv() Options {
	envOr := func(key, fallback string) string {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			return v
		}
		return fallback
	}
	envInt := func(key string, fallback int) int {
		raw := strings.TrimSpace(os.Getenv(key))
		if raw == "" {
			return fallback
		}
		if n, err := strconv.Atoi(raw); err == nil {
			return n
		}
		return fallback
	}
	authTTL := envInt("HAPADM_AUTH_IPSET_TTL", 900)
	if authTTL < 30 {
		authTTL = 30
	}
	udpInterval := envInt("HP_UDP_HEALTH_INTERVAL", 5)
	if udpInterval < 2 {
		udpInterval = 2
	}
	ctrlSock := envOr("HAPROXY_CONTROL_SOCKET", envOr("HAPADM_CONTROL_SOCKET", "/run/easy-ha-proxy/haproxy-controld.sock"))
	cfgPath := envOr("HAPROXY_CFG", envOr("HAPROXY_CFG_PATH", "/etc/haproxy/haproxy.cfg"))
	return Options{
		ControlSocket:           ctrlSock,
		HAProxyAdminSocket:      envOr("SOCKET_PATH", "/run/haproxy/admin.sock"),
		HAProxyBin:              envOr("HAPROXY_BIN", "/usr/sbin/haproxy"),
		HAProxyCfgPath:          cfgPath,
		SystemctlBin:            envOr("SYSTEMCTL_BIN", "/usr/bin/systemctl"),
		IpsetBin:                envOr("IPSET_BIN", "ipset"),
		ServerStatePath:         envOr("HAPROXY_SERVER_STATE_FILE", "/var/lib/haproxy/server-state"),
		BanTable:                envOr("HAPADM_BAN_TABLE", "tbl_ban"),
		IpsetName:               envOr("HAPADM_IPSET_NAME", "haproxy_ban"),
		PageIpset:               envOr("HAPADM_BAN_PAGE_IPSET", "haproxy_ban_page"),
		AuthTable:               envOr("HAPADM_AUTH_TABLE", "tbl_ip_auth"),
		AuthIpset:               envOr("HAPADM_AUTH_IPSET", "haproxy_ip_auth"),
		BanSyncIntervalSec:      max(2, envInt("HAPADM_BAN_SYNC_INTERVAL", 10)),
		BanRestartGraceSec:      max(0, envInt("HAPADM_BAN_RESTART_GRACE_SECONDS", 60)),
		AuthIpsetTTLSec:         authTTL,
		LogFile:                 envOr("LOG_FILE", "/var/log/haproxy.log"),
		LogLimit:                envInt("HAPADM_LOG_LIMIT", 30),
		LogTailChunk:            envInt("HAPADM_LOG_FILE_TAIL_CHUNK", 65536),
		LogTailMaxBytes:         int64(envInt("HAPADM_LOG_FILE_TAIL_MAX_BYTES", 64*1024*1024)),
		ConfigBackupDir:         envOr("HAPROXY_CONFIG_BACKUP_DIR", "/opt/haproxy-admin/backups/haproxy"),
		ConfigSourceDir:         envOr("HAPROXY_CONFIG_SOURCE_DIR", "/opt/haproxy-admin/config"),
		ConfigHistoryDir:        envOr("HAPROXY_CONFIG_HISTORY_DIR", "/var/lib/easy-ha-proxy/config-history"),
		ConfigTransactionDir:    envOr("HAPROXY_CONFIG_TRANSACTION_DIR", "/var/lib/easy-ha-proxy/haproxy-config-guard"),
		MaintenanceRebootMarker: envOr("EASY_HA_PROXY_REBOOT_MARKER", "/run/easy-ha-proxy/easy-ha-proxy-web-reboot.json"),
		AssistantRebootMarker:   "/run/easy-ha-proxy/reboot-scheduled",
		UDPForwardState:         envOr("HAPROXY_UDP_FORWARD_STATE", "/run/easy-ha-proxy/udp-forward-state.json"),
		UDPFailoverState:        envOr("HP_UDP_FAILOVER", "/run/easy-ha-proxy/udp-failover.json"),
		UDPHealthIntervalSec:    udpInterval,
		GeoIPDir:                "/etc/haproxy/geoip",
		ProcNetUDPPath:          "/proc/net/udp",
		ProcNetUDP6Path:         "/proc/net/udp6",
	}
}
