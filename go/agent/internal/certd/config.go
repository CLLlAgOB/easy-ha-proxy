// Package certd implements the native Go certificate manager daemon (haproxy-certd).
package certd

import (
	"os"
	"regexp"
	"strconv"
	"strings"
)

const (
	DefaultSocketPath      = "/run/easy-ha-proxy/haproxy-certd.sock"
	DefaultHAProxyCertsDir = "/etc/haproxy/certs"
	DefaultLERootDir       = "/etc/letsencrypt"
	DefaultCARootDir       = "/etc/haproxy/certificate-authorities"
	DefaultDNSCredsDir     = "/etc/easy-ha-proxy/dns-providers"
	DefaultCertbotBin      = "/snap/bin/certbot"
	DefaultMaxRequestBytes = 16 * 1024 * 1024

	CertWarnDaysDefault   = 30
	AutomatedLifetimeDays = 100
	DNSValueMax           = 4096
	DNSPropagationMin     = 10
	DNSPropagationMax     = 1800
	DNSPropagationDefault = 60
)

var (
	DNSProfileRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
	CertFileRe   = regexp.MustCompile(`^[A-Za-z0-9._-]{1,200}\.pem$`)
)

// DNSProviderSpec defines one supported Certbot DNS-01 provider and its allowed credential keys.
type DNSProviderSpec struct {
	Plugin string
	Snap   string
	Keys   []string
}

// DNSProviders mirrors certd/constants.py DNS_PROVIDERS.
var DNSProviders = map[string]DNSProviderSpec{
	"cloudflare": {
		Plugin: "dns-cloudflare",
		Snap:   "certbot-dns-cloudflare",
		Keys:   []string{"dns_cloudflare_api_token"},
	},
	"digitalocean": {
		Plugin: "dns-digitalocean",
		Snap:   "certbot-dns-digitalocean",
		Keys:   []string{"dns_digitalocean_token"},
	},
	"route53": {
		Plugin: "dns-route53",
		Snap:   "certbot-dns-route53",
		Keys:   []string{"aws_access_key_id", "aws_secret_access_key"},
	},
	"rfc2136": {
		Plugin: "dns-rfc2136",
		Snap:   "certbot-dns-rfc2136",
		Keys: []string{
			"dns_rfc2136_server",
			"dns_rfc2136_port",
			"dns_rfc2136_name",
			"dns_rfc2136_secret",
			"dns_rfc2136_algorithm",
		},
	},
}

// Options holds runtime directories and paths loaded from environment variables.
type Options struct {
	SocketPath         string
	HAProxyCertsDir    string
	LERootDir          string
	CARootDir          string
	DNSCredsDir        string
	TrashDir           string
	StandbyDir         string
	CertbotBin         string
	WatchIntervalSec   int
	DryRun             bool
}

// OptionsFromEnv reads certd options using the same environment variables as haproxy-certd.py.
func OptionsFromEnv() Options {
	envOr := func(key, fallback string) string {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			return v
		}
		return fallback
	}
	watch := 6 * 3600
	if raw := strings.TrimSpace(os.Getenv("CERTD_EXPIRY_WATCH_INTERVAL")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			watch = n
		}
	}
	certsDir := envOr("HAPROXY_CERTS_DIR", DefaultHAProxyCertsDir)
	return Options{
		SocketPath:       envOr("HAPROXY_CERTD_SOCKET", DefaultSocketPath),
		HAProxyCertsDir:  certsDir,
		LERootDir:        envOr("HAPROXY_LE_ROOT_DIR", DefaultLERootDir),
		CARootDir:        envOr("HAPROXY_CA_ROOT_DIR", DefaultCARootDir),
		DNSCredsDir:      envOr("HAPROXY_DNS_CREDENTIALS_DIR", DefaultDNSCredsDir),
		TrashDir:         envOr("HAPROXY_CERTS_TRASH_DIR", "/var/lib/easy-ha-proxy/cert-trash"),
		StandbyDir:       envOr("HAPROXY_CERTS_STANDBY_DIR", "/var/lib/easy-ha-proxy/cert-standby"),
		CertbotBin:       envOr("CERTBOT_BIN", DefaultCertbotBin),
		WatchIntervalSec: watch,
		DryRun:           strings.EqualFold(os.Getenv("CERTD_DRY_RUN"), "1") || strings.EqualFold(os.Getenv("CERTD_DRY_RUN"), "true"),
	}
}

// CertWarnDays returns how many days before expiry a certificate should trigger a warning.
// Automated certificates (lifetime <= 100 days) warn at a quarter of their lifetime (min 1 day);
// manually renewed certificates keep the full 30-day window.
func CertWarnDays(lifetimeDays int) int {
	if lifetimeDays > 0 && lifetimeDays <= AutomatedLifetimeDays {
		if d := lifetimeDays / 4; d >= 1 {
			return d
		}
		return 1
	}
	return CertWarnDaysDefault
}
