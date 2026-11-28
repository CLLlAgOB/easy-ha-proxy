// Package config loads runtime settings for the easy-ha-proxy Go web panel
// from the same environment variables consumed by the Flask application.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

var Version = "dev"

const (
	DefaultListenAddr    = "0.0.0.0:5000"
	DefaultSecretFile    = "/var/lib/haproxy-admin/secret_key"
	DefaultMaxBodyBytes  = 32 * 1024 * 1024
	DefaultMaxUploadSize = 8 * 1024 * 1024 * 1024
)

// Config holds the immutable runtime configuration loaded at startup.
type Config struct {
	ListenAddr         string
	ProxySecret        string
	SecretKey          string
	SecretFile         string
	DefaultLanguage    string
	DebugRoutes        bool
	StaticDir          string
	TranslationsDir    string
	Timezone           string
	ServerTimezone     string
	AuditDatabase      string
	ConfigDir          string
	ConfigBackupDir    string
	HAProxySocket      string
	HAProxyCfg         string
	HAProxyLog         string
	WhitelistGlobal    string
	WhitelistGeo       string
	GeoIPDBPath        string
	BanTable           string
	BackupUploadsDir   string
	BackupDownloadsDir string
	ExcludeExact       []string
	ExcludePrefix      []string
	MaxBodyBytes       int64
	MaxUploadBytes     int64
	SessionSecure      bool

	// Host daemon Unix sockets and tokens.
	HealthdSocket       string
	HealthdToken        string
	MetricsdSocket      string
	AlertdSocket        string
	AlertdToken         string
	GuarddSocket        string
	GuarddToken         string
	CertdSocket         string
	ControldSocket      string
	BackupdSocket       string
	UpdatedSocket       string
	AutheliaUsersSocket string
	AutheliaBansSocket  string
	AutheliaCfgSocket   string

	// Optional Prometheus scrape endpoint.
	MetricsExportEnabled bool
	MetricsExportToken   string
}

// Load reads Config from process environment variables.
func Load() (*Config, error) {
	defaultLang := strings.ToLower(strings.TrimSpace(envOr("HAPROXY_ADMIN_DEFAULT_LANGUAGE", "en")))
	if defaultLang != "en" && defaultLang != "ru" {
		defaultLang = "en"
	}

	cfg := &Config{
		ListenAddr:          envOr("HAPROXY_ADMIN_LISTEN_ADDR", DefaultListenAddr),
		ProxySecret:         strings.TrimSpace(os.Getenv("HAPROXY_ADMIN_PROXY_SECRET")),
		SecretFile:          envOr("HAPROXY_ADMIN_SECRET_FILE", DefaultSecretFile),
		DefaultLanguage:     defaultLang,
		DebugRoutes:         parseBool(os.Getenv("HAPROXY_ADMIN_DEBUG_ROUTES")),
		StaticDir:           envOr("HAPROXY_ADMIN_STATIC_DIR", "/app/static"),
		TranslationsDir:     envOr("HAPROXY_ADMIN_TRANSLATIONS_DIR", "/app/translations"),
		Timezone:            envOr("TZ", "UTC"),
		ServerTimezone:      envOr("EHP_SERVER_TIMEZONE", envOr("TZ", "UTC")),
		AuditDatabase:       envOr("AUDIT_DATABASE", "/var/lib/easy-ha-proxy/audit/audit.db"),
		ConfigDir:           envOr("HAPROXY_ADMIN_CONFIG_DIR", "/opt/haproxy-admin/config"),
		ConfigBackupDir:     envOr("HAPROXY_ADMIN_BACKUPS_DIR", "/opt/haproxy-admin/backups"),
		HAProxySocket:       envOr("SOCKET_PATH", "/run/haproxy/admin.sock"),
		HAProxyCfg:          envOr("HAPROXY_CFG", "/etc/haproxy/haproxy.cfg"),
		HAProxyLog:          envOr("LOG_FILE", "/var/log/haproxy.log"),
		WhitelistGlobal:     envOr("WHITELIST_GLOBAL_FILE", "/etc/haproxy/whitelist.ip"),
		WhitelistGeo:        envOr("WHITELIST_GEO_FILE", "/etc/haproxy/geoip/whitelist.geo"),
		GeoIPDBPath:         envOr("HAPROXY_ADMIN_GEOIP_DB", "/etc/haproxy/geoip/current/dbip-country-lite.mmdb"),
		BanTable:            envOr("HAPADM_BAN_TABLE", "tbl_ban"),
		BackupUploadsDir:    envOr("BACKUPD_UPLOADS_DIR", "/var/lib/easy-ha-proxy/backup-web/uploads"),
		BackupDownloadsDir:  envOr("BACKUPD_BACKUPS_DIR", "/var/lib/easy-ha-proxy/backup-web/backups"),
		ExcludeExact:        splitCSV(os.Getenv("UI_EXCLUDE_EXACT")),
		ExcludePrefix:       splitCSV(os.Getenv("UI_EXCLUDE_PREFIX")),
		MaxBodyBytes:        DefaultMaxBodyBytes,
		MaxUploadBytes:      envInt64("EASY_HA_PROXY_BACKUP_MAX_UPLOAD_BYTES", DefaultMaxUploadSize),
		SessionSecure:       !parseBool(os.Getenv("HAPROXY_ADMIN_INSECURE_COOKIES")),
		HealthdSocket:       envOr("HEALTHD_SOCKET_PATH", "/run/easy-ha-proxy/haproxy-healthd.sock"),
		HealthdToken:        strings.TrimSpace(os.Getenv("HEALTHD_TOKEN")),
		MetricsdSocket:      envOr("METRICSD_SOCKET_PATH", "/run/easy-ha-proxy/easy-ha-proxy-metricsd.sock"),
		AlertdSocket:        envOr("ALERTD_SOCKET_PATH", "/run/easy-ha-proxy/easy-ha-proxy-alertd.sock"),
		AlertdToken:         strings.TrimSpace(os.Getenv("ALERTD_TOKEN")),
		GuarddSocket:        envOr("GUARDD_SOCKET_PATH", "/run/easy-ha-proxy/easy-ha-proxy-guardd.sock"),
		GuarddToken:         strings.TrimSpace(os.Getenv("GUARDD_TOKEN")),
		CertdSocket:         envOr("CERTD_SOCKET_PATH", "/run/easy-ha-proxy/haproxy-certd.sock"),
		ControldSocket:      envOr("HAPROXY_CONTROL_SOCKET", "/run/easy-ha-proxy/haproxy-controld.sock"),
		BackupdSocket:       envOrFirst([]string{"EASY_HA_PROXY_BACKUPD_SOCKET", "BACKUPD_SOCKET_PATH"}, "/run/easy-ha-proxy/easy-ha-proxy-backupd.sock"),
		UpdatedSocket:       envOrFirst([]string{"EASY_HA_PROXY_UPDATED_SOCKET", "UPDATED_SOCKET_PATH"}, "/run/easy-ha-proxy/easy-ha-proxy-updated.sock"),
		AutheliaUsersSocket: envOr("AUTHELIA_USERS_SOCKET", "/run/easy-ha-proxy/authelia-usersd.sock"),
		AutheliaBansSocket:  strings.TrimSpace(os.Getenv("AUTHELIA_BANS_SOCKET")),
		AutheliaCfgSocket:   envOr("AUTHELIA_CONFIG_SOCKET", "/run/easy-ha-proxy/authelia-configd.sock"),

		MetricsExportEnabled: parseBool(os.Getenv("METRICS_EXPORT_ENABLED")),
		MetricsExportToken:   strings.TrimSpace(os.Getenv("METRICS_EXPORT_TOKEN")),
	}

	secretKey, err := LoadOrCreateSecretKey(
		strings.TrimSpace(os.Getenv("HAPROXY_ADMIN_SECRET_KEY")),
		cfg.SecretFile,
	)
	if err != nil {
		return nil, err
	}
	cfg.SecretKey = secretKey
	return cfg, nil
}

// LoadOrCreateSecretKey returns the env secret key if set, otherwise reads or
// atomically creates a 64-hex-char shared secret key under an exclusive flock.
func LoadOrCreateSecretKey(envKey, secretFile string) (string, error) {
	if strings.TrimSpace(envKey) != "" {
		return strings.TrimSpace(envKey), nil
	}
	if secretFile == "" {
		secretFile = DefaultSecretFile
	}
	dir := filepath.Dir(secretFile)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", fmt.Errorf("cannot create secret key directory %s: %w", dir, err)
		}
	}

	lockPath := secretFile + ".lock"
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return "", fmt.Errorf("cannot open secret key lock %s: %w", lockPath, err)
	}
	defer lockFile.Close()

	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return "", fmt.Errorf("cannot lock secret key %s: %w", lockPath, err)
	}
	defer func() { _ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN) }()

	if data, err := os.ReadFile(secretFile); err == nil {
		if existing := strings.TrimSpace(string(data)); existing != "" {
			return existing, nil
		}
	}

	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("cannot generate secret key: %w", err)
	}
	newKey := hex.EncodeToString(buf)

	tmpPath := secretFile + ".new"
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return "", fmt.Errorf("cannot create temporary secret key %s: %w", tmpPath, err)
	}
	if _, err := f.WriteString(newKey); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("cannot write secret key: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("cannot sync secret key: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("cannot close secret key: %w", err)
	}
	_ = os.Chmod(tmpPath, 0o600)
	if err := os.Rename(tmpPath, secretFile); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("cannot move secret key into place: %w", err)
	}
	return newKey, nil
}

func envOr(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}

func envOrFirst(names []string, fallback string) string {
	for _, n := range names {
		if v := strings.TrimSpace(os.Getenv(n)); v != "" {
			return v
		}
	}
	return fallback
}

func envInt64(name string, fallback int64) int64 {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v <= 0 {
		return fallback
	}
	return v
}

func parseBool(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func splitCSV(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if s := strings.TrimSpace(part); s != "" {
			out = append(out, s)
		}
	}
	return out
}
