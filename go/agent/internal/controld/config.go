// Package controld implements the AF_UNIX line-protocol control daemon for HAProxy.
package controld

import (
	"os"
	"strconv"
	"strings"
)

const (
	MaxCommandBytes = 32 * 1024 * 1024
	MaxConfigBytes  = 4 * 1024 * 1024
	UDPMaxPortRange = 1024
	MaxClientSlots  = 32
)

// Options holds runtime paths and limits loaded from environment variables.
type Options struct {
	ControlSocket           string
	HAProxyAdminSocket      string
	HAProxyBin              string
	HAProxyCfgPath          string
	SystemctlBin            string
	LogFile                 string
	LogLimit                int
	LogTailChunk            int
	LogTailMaxBytes         int64
	ConfigHistoryDir        string
	ConfigTransactionDir    string
	MaintenanceRebootMarker string
	AssistantRebootMarker   string
	UDPForwardState         string
	UDPFailoverState        string
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
	return Options{
		ControlSocket:           envOr("HAPADM_CONTROL_SOCKET", "/run/haproxy-controld.sock"),
		HAProxyAdminSocket:      envOr("SOCKET_PATH", "/run/haproxy/admin.sock"),
		HAProxyBin:              envOr("HAPROXY_BIN", "/usr/sbin/haproxy"),
		HAProxyCfgPath:          envOr("HAPROXY_CFG_PATH", "/etc/haproxy/haproxy.cfg"),
		SystemctlBin:            envOr("SYSTEMCTL_BIN", "/usr/bin/systemctl"),
		LogFile:                 envOr("LOG_FILE", "/var/log/haproxy.log"),
		LogLimit:                envInt("HAPADM_LOG_LIMIT", 30),
		LogTailChunk:            envInt("HAPADM_LOG_FILE_TAIL_CHUNK", 65536),
		LogTailMaxBytes:         int64(envInt("HAPADM_LOG_FILE_TAIL_MAX_BYTES", 64*1024*1024)),
		ConfigHistoryDir:        envOr("HAPROXY_CONFIG_HISTORY_DIR", "/var/lib/easy-ha-proxy/config-history"),
		ConfigTransactionDir:    envOr("HAPROXY_CONFIG_TRANSACTION_DIR", "/var/lib/easy-ha-proxy/haproxy-config-guard"),
		MaintenanceRebootMarker: envOr("EASY_HA_PROXY_REBOOT_MARKER", "/run/easy-ha-proxy/easy-ha-proxy-web-reboot.json"),
		AssistantRebootMarker:   "/run/easy-ha-proxy/reboot-scheduled",
		UDPForwardState:         envOr("HAPROXY_UDP_FORWARD_STATE", "/run/easy-ha-proxy/udp-forward-state.json"),
		UDPFailoverState:        envOr("HP_UDP_FAILOVER", "/run/easy-ha-proxy/udp-failover.json"),
		GeoIPDir:                "/etc/haproxy/geoip",
		ProcNetUDPPath:          "/proc/net/udp",
		ProcNetUDP6Path:         "/proc/net/udp6",
	}
}
