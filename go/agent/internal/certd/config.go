// Package certd is the Go port of haproxy-certd (ansible/roles/haproxy-admin/
// files/certd/*.py). The Python package is the specification: the same HTTP
// routes over the Unix socket, request and response shapes, file layout
// (HAProxy PEMs, standbys and holds, internal and external CAs, client-auth
// material, DNS profiles, delivery targets, the trash) and the same fixed
// commands (certbot, haproxy -c, systemctl reload, openssl verify, the PEM
// rebuild hook and the delivery worker).
package certd

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// Options holds every path and limit the Python modules read at import.
type Options struct {
	SocketPath, GroupName, ConfigYAML, CertbotBin                   string
	HAProxyCertsDir, LetsEncryptRoot, CARootDir, MTLSDir            string
	CertsAvailableDir, DNSCredentialsDir, DeliveryDir, TrashDir     string
	HAProxyBin, HAProxyCfg, PEMsScript, DeliveryWorker, HooksDir    string
	AppliedWebsites, AppliedVars                                    string
	DryRun                                                          bool
	MaxRequestBytes, MaxArchiveBytes, MaxArchiveExpanded            int64
	MaxArchiveFiles, MaxCompressionRatio, ExpiryWatchIntervalSecond int
}

func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func envInt(key string, def int64) int64 {
	if v, ok := os.LookupEnv(key); ok {
		if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
			return n
		}
	}
	return def
}

func resolved(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	if r, err := filepath.EvalSymlinks(abs); err == nil {
		return r
	}
	return abs
}

func absolute(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}

// OptionsFromEnv reads the same environment as certd/constants.py.
func OptionsFromEnv() Options {
	return Options{
		SocketPath:                envOr("HAPROXY_CERTD_SOCKET", "/run/easy-ha-proxy/haproxy-certd.sock"),
		GroupName:                 envOr("HAPROXY_CERTD_SOCKET_GROUP", "hadmin"),
		ConfigYAML:                envOr("HAPROXY_VARS_YAML", "/opt/haproxy-admin/config/vars.yml"),
		CertbotBin:                envOr("CERTBOT_BIN", "/snap/bin/certbot"),
		HAProxyCertsDir:           resolved(envOr("HAPROXY_CERTS_DIR", "/etc/haproxy/certs")),
		LetsEncryptRoot:           resolved(envOr("LETSENCRYPT_ROOT_DIR", "/etc/letsencrypt")),
		CARootDir:                 absolute(envOr("HAPROXY_CA_ROOT_DIR", "/etc/haproxy/certificate-authorities")),
		MTLSDir:                   envOr("HAPROXY_MTLS_DIR", "/etc/haproxy/mtls"),
		CertsAvailableDir:         resolved(envOr("HAPROXY_CERTS_AVAILABLE_DIR", "/etc/haproxy/certs-available")),
		DNSCredentialsDir:         envOr("HAPROXY_DNS_CREDENTIALS_DIR", "/etc/easy-ha-proxy/dns-providers"),
		DeliveryDir:               envOr("CERT_DESTINATIONS_DIR", "/etc/easy-ha-proxy/cert-destinations"),
		TrashDir:                  envOr("HAPROXY_CERTD_TRASH_DIR", "/var/lib/easy-ha-proxy/cert-trash"),
		HAProxyBin:                envOr("HAPROXY_BIN", "/usr/sbin/haproxy"),
		HAProxyCfg:                envOr("HAPROXY_CFG", "/etc/haproxy/haproxy.cfg"),
		PEMsScript:                envOr("HAPROXY_PEMS_SCRIPT", "/etc/letsencrypt/renewal-hooks/deploy/905-haproxy-pems-reload.sh"),
		DeliveryWorker:            "/usr/local/sbin/easy-ha-proxy-cert-deliver",
		HooksDir:                  "/etc/letsencrypt/renewal-hooks/deploy",
		AppliedWebsites:           envOr("HAPROXY_APPLIED_WEBSITES", "/opt/haproxy-admin/backups/haproxy/last_applied_websites.yml"),
		AppliedVars:               envOr("HAPROXY_APPLIED_VARS", "/opt/haproxy-admin/backups/haproxy/last_applied_vars.yml"),
		DryRun:                    os.Getenv("HAPROXY_CERTD_DRY_RUN") == "1",
		MaxRequestBytes:           envInt("HAPROXY_CERTD_MAX_REQUEST_BYTES", 32*1024*1024),
		MaxArchiveBytes:           envInt("HAPROXY_CERTD_MAX_ARCHIVE_BYTES", 64*1024*1024),
		MaxArchiveFiles:           int(envInt("HAPROXY_CERTD_MAX_ARCHIVE_FILES", 4096)),
		MaxArchiveExpanded:        envInt("HAPROXY_CERTD_MAX_ARCHIVE_EXPANDED_BYTES", 256*1024*1024),
		MaxCompressionRatio:       int(envInt("HAPROXY_CERTD_MAX_COMPRESSION_RATIO", 100)),
		ExpiryWatchIntervalSecond: int(envInt("CERTD_EXPIRY_WATCH_INTERVAL", 6*3600)),
	}
}

const (
	certbotHTTPPort            = 8000
	certbotHTTPAddr            = "0.0.0.0"
	dnsValueMax                = 4096
	dnsPropagationMin          = 10
	dnsPropagationMax          = 1800
	dnsPropagationDefault      = 60
	certbotTimeoutSeconds      = 600
	certbotQuickTimeoutSeconds = 300
	haproxyCheckTimeout        = 60
	haproxyReloadTimeout       = 120
	opensslTimeout             = 30
	pemRebuildTimeout          = 300
	deliveryTimeout            = 180
	timedOutRC                 = 124
	certWarnDays               = 30
	automatedLifetimeDays      = 100
	mtlsTrustFile              = "client-auth.json"
	mtlsBundleName             = "clients-ca.pem"
	mtlsRevokedName            = "revoked.list"
	mtlsEmptyMarker            = "# managed by easy-ha-proxy; edit through the web interface\n"
	mtlsMaxRevoked             = 2000
	renewalPauseMarker         = "# easy-ha-proxy: renewal paused from the panel"
	letsencryptSlot            = "letsencrypt"
	pinFile                    = ".pinned"
	maxDeliveryTargets         = 50
	trashSettings              = "settings.json"
	trashMaxKeepDays           = 3650
	trashPurgeIntervalSeconds  = 3600
	requestTimeoutSeconds      = 30
)

type dnsProvider struct {
	Plugin, Snap string
	Keys         []string
}

var dnsProviders = map[string]dnsProvider{
	"cloudflare":   {"dns-cloudflare", "certbot-dns-cloudflare", []string{"dns_cloudflare_api_token"}},
	"digitalocean": {"dns-digitalocean", "certbot-dns-digitalocean", []string{"dns_digitalocean_token"}},
	"route53":      {"dns-route53", "certbot-dns-route53", []string{"aws_access_key_id", "aws_secret_access_key"}},
	"rfc2136": {"dns-rfc2136", "certbot-dns-rfc2136", []string{"dns_rfc2136_server", "dns_rfc2136_port",
		"dns_rfc2136_name", "dns_rfc2136_secret", "dns_rfc2136_algorithm"}},
}

// dnsProviderOrder is the dict order of DNS_PROVIDERS.
var dnsProviderOrder = []string{"cloudflare", "digitalocean", "route53", "rfc2136"}

var (
	dnsProfileRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
	sha256HexRe    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	deliveryNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
	trashIDRe      = regexp.MustCompile(`^([0-9]{1,12})-[a-f0-9]{12}$`)
	lineageSuffix  = regexp.MustCompile(`(?:-(?:rsa|ecdsa))?(?:-\d{4})?$`)
	hookKeyRe      = regexp.MustCompile(`(?im)^\s*(?:pre|post|deploy|renew|manual_auth|manual_cleanup)[_-]hook\s*=`)
	authenticRe    = regexp.MustCompile(`(?m)^\s*authenticator\s*=\s*([^\s#]+)`)
)

var trashKinds = []string{"haproxy_cert", "letsencrypt", "standby", "external_ca", "internal_ca", "dns_provider", "cert_delivery"}

var (
	deliveryFormats    = []string{"pfx", "pem-pair", "pem-combined"}
	deliveryTransports = []string{"sftp", "scp"}
)

// Daemon holds the module-level state of the Python package.
type Daemon struct {
	Opts         Options
	caMu         sync.Mutex // CA_LOCK (not reentrant)
	standbyMu    sync.Mutex // _STANDBY_SWITCH_LOCK
	trashMu      sync.Mutex // TRASH_LOCK
	alertsClient alertSink
	plugins      pluginCache // listedDNSPlugins
}

// certWarnDaysFor is cert_warn_days.
func certWarnDaysFor(lifetime *int) int {
	if lifetime != nil && *lifetime > 0 && *lifetime <= automatedLifetimeDays {
		v := *lifetime / 4
		if v < 1 {
			v = 1
		}
		return v
	}
	return certWarnDays
}
