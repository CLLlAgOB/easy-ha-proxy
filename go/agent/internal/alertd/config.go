package alertd

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

var (
	headerNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,63}$`)
	subjectRe    = regexp.MustCompile(`^(?:-|[A-Za-z0-9][A-Za-z0-9 ._:/@*-]{0,199})$`)
	emailRe      = regexp.MustCompile(`^[^@\s]{1,64}@[^@\s]{1,253}\.[A-Za-z0-9-]{2,63}$`)
)

// RuleSettings holds per-rule operator overrides.
type RuleSettings struct {
	Enabled      bool `json:"enabled"`
	TriggerDelay int  `json:"trigger_delay"`
	RepeatAfter  int  `json:"repeat_after"`
}

// Config holds operator-visible alerting settings persisted in alertd.json.
type Config struct {
	Enabled             bool                    `json:"enabled"`
	EmailEnabled        bool                    `json:"email_enabled"`
	Recipient           string                  `json:"recipient"`
	MinSeverity         string                  `json:"min_severity"`
	PortalMinSeverity   string                  `json:"portal_min_severity"`
	ConfigVersion       int                     `json:"config_version"`
	WebhookURL          string                  `json:"webhook_url"`
	WebhookHeaderName   string                  `json:"webhook_header_name"`
	WebhookHeaderValue  string                  `json:"webhook_header_value"`
	WebhookAllowPrivate bool                    `json:"webhook_allow_private"`
	Rules               map[string]RuleSettings `json:"rules"`
}

// DaemonOptions holds runtime paths and credentials from environment variables.
type DaemonOptions struct {
	SocketPath         string
	SocketGroup        string
	DatabasePath       string // alerts.db, shared with the Python daemon
	ConfigPath         string
	Token              string
	GatewayName        string
	MailStatePath      string
	MailLockPath       string
	MailRelayContainer string
	DockerBin          string
}

// OptionsFromEnv builds DaemonOptions using the same env vars as easy-ha-proxy-alertd.py.
func OptionsFromEnv() DaemonOptions {
	envOr := func(key, fallback string) string {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			return v
		}
		return fallback
	}
	hostname, _ := os.Hostname()
	gateway := strings.TrimSpace(os.Getenv("ALERTD_GATEWAY_NAME"))
	if gateway == "" {
		gateway = hostname
	}
	dbPath := envOr("ALERTD_DATABASE", "/var/lib/easy-ha-proxy/alerts/alerts.db")
	return DaemonOptions{
		SocketPath:         envOr("ALERTD_SOCKET_PATH", "/run/easy-ha-proxy/easy-ha-proxy-alertd.sock"),
		SocketGroup:        envOr("ALERTD_SOCKET_GROUP", "hadmin"),
		DatabasePath:       dbPath,
		ConfigPath:         envOr("ALERTD_CONFIG", "/opt/haproxy-admin/alertd.json"),
		Token:              strings.TrimSpace(os.Getenv("ALERTD_TOKEN")),
		GatewayName:        gateway,
		MailStatePath:      envOr("ALERTD_MAIL_STATE", "/etc/easy-ha-proxy/mail-notify.json"),
		MailLockPath:       envOr("ALERTD_MAIL_LOCK", "/run/easy-ha-proxy/authelia-mail.lock"),
		MailRelayContainer: envOr("ALERTD_MAIL_CONTAINER", "mail_relay"),
		DockerBin:          envOr("ALERTD_DOCKER_BIN", "/usr/bin/docker"),
	}
}

// DefaultConfig returns the safe default alerting configuration.
func DefaultConfig() Config {
	return Config{
		Enabled:           true,
		EmailEnabled:      true,
		MinSeverity:       SeverityWarning,
		PortalMinSeverity: SeverityWarning,
		ConfigVersion:     ConfigVersion,
		Rules:             map[string]RuleSettings{},
	}
}

// SettingsFor returns the effective RuleSettings for a given rule.
func (c Config) SettingsFor(r Rule) RuleSettings {
	if s, ok := c.Rules[r.Name]; ok {
		return s
	}
	return RuleSettings{
		Enabled:      r.Enabled,
		TriggerDelay: r.TriggerDelay,
		RepeatAfter:  r.RepeatAfter,
	}
}

// Clone returns a deep copy of Config.
func (c Config) Clone() Config {
	cp := c
	cp.Rules = make(map[string]RuleSettings, len(c.Rules))
	for k, v := range c.Rules {
		cp.Rules[k] = v
	}
	return cp
}

// Redacted returns a browser-safe copy with secrets masked.
func (c Config) Redacted() Config {
	cp := c.Clone()
	cp.WebhookURL = RedactURL(c.WebhookURL)
	if c.WebhookHeaderValue != "" {
		cp.WebhookHeaderValue = "***"
	} else {
		cp.WebhookHeaderValue = ""
	}
	return cp
}

// RedactURL keeps scheme and host and hides paths/tokens.
func RedactURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return "***"
	}
	return u.Scheme + "://" + u.Hostname() + "/***"
}

// LoadConfig reads alertd.json, falling back to defaults on missing/corrupt files.
func LoadConfig(path string) Config {
	data, err := os.ReadFile(path)
	if err != nil {
		return DefaultConfig()
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil || raw == nil {
		return DefaultConfig()
	}
	return ParseConfigMap(raw)
}

// ParseConfigMap normalizes and validates a raw config JSON object.
func ParseConfigMap(raw map[string]any) Config {
	cfg := DefaultConfig()
	if v, ok := raw["enabled"]; ok {
		if b, ok := v.(bool); ok && !b {
			cfg.Enabled = false
		}
	}
	if v, ok := raw["email_enabled"]; ok {
		if b, ok := v.(bool); ok && !b {
			cfg.EmailEnabled = false
		}
	}
	if rec := strings.TrimSpace(asString(raw["recipient"])); emailRe.MatchString(rec) {
		cfg.Recipient = rec
	}
	sev := strings.ToLower(strings.TrimSpace(asString(raw["min_severity"])))
	if ValidSeverity(sev) {
		cfg.MinSeverity = sev
	}
	version := asInt(raw["config_version"], 0)
	if version < 2 && cfg.MinSeverity == SeverityInfo {
		cfg.MinSeverity = SeverityWarning
	}
	portal := strings.ToLower(strings.TrimSpace(asString(raw["portal_min_severity"])))
	if ValidSeverity(portal) {
		cfg.PortalMinSeverity = portal
	}
	cfg.WebhookURL = strings.TrimSpace(asString(raw["webhook_url"]))
	hName := strings.TrimSpace(asString(raw["webhook_header_name"]))
	if headerNameRe.MatchString(hName) {
		cfg.WebhookHeaderName = hName
	}
	cfg.WebhookHeaderValue = stripControlChars(asString(raw["webhook_header_value"]))
	cfg.WebhookHeaderValue = strings.TrimSpace(cfg.WebhookHeaderValue)
	if len(cfg.WebhookHeaderValue) > 4096 {
		cfg.WebhookHeaderValue = cfg.WebhookHeaderValue[:4096]
	}
	if b, ok := raw["webhook_allow_private"].(bool); ok && b {
		cfg.WebhookAllowPrivate = true
	}
	if rulesRaw, ok := raw["rules"].(map[string]any); ok {
		for name, v := range rulesRaw {
			rule, exists := RulesByName[name]
			if !exists {
				continue
			}
			rm, ok := v.(map[string]any)
			if !ok {
				continue
			}
			enabled := rule.Enabled
			if ev, has := rm["enabled"]; has {
				if b, isBool := ev.(bool); isBool {
					enabled = b
				}
			}
			cfg.Rules[name] = RuleSettings{
				Enabled:      enabled,
				TriggerDelay: clampInt(asInt(rm["trigger_delay"], rule.TriggerDelay), 0, 86400),
				RepeatAfter:  clampInt(asInt(rm["repeat_after"], rule.RepeatAfter), 300, 7*86400),
			}
		}
	}
	return cfg
}

// SaveConfig atomically writes alertd.json with mode 0640 and fsync.
func SaveConfig(path string, cfg Config) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	cfg.ConfigVersion = ConfigVersion
	if cfg.Rules == nil {
		cfg.Rules = map[string]RuleSettings{}
	}
	payload, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Chmod(0o640); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return err
	}
	return nil
}

func stripControlChars(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if (r >= 0x00 && r <= 0x08) || r == 0x0b || r == 0x0c || (r >= 0x0e && r <= 0x1f) || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func hasAnyControlChar(s string) bool {
	for _, r := range s {
		if r < 32 || r == 127 {
			return true
		}
	}
	return false
}

func cleanText(s string, limit int) string {
	out := strings.TrimSpace(stripControlChars(s))
	if limit > 0 && utf8.RuneCountInString(out) > limit {
		return string([]rune(out)[:limit])
	}
	return out
}

func clampInt(v, minV, maxV int) int {
	if v < minV {
		return minV
	}
	if v > maxV {
		return maxV
	}
	return v
}

func asString(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func asInt(v any, fallback int) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	default:
		return fallback
	}
}
