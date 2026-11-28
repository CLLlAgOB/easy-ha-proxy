// Package alertd implements the easy-ha-proxy-alertd notification engine and AF_UNIX HTTP API.
package alertd

const (
	StateOK      = "ok"
	StatePending = "pending"
	StateFiring  = "firing"

	TransitionFired      = "fired"
	TransitionRepeated   = "repeated"
	TransitionEscalated  = "escalated"
	TransitionRecovered  = "recovered"
	TransitionSuppressed = "suppressed"
	TransitionDismissed  = "dismissed"
	TransitionStale      = "stale"
	TransitionExpired    = "stale_closed"
	TransitionRetired    = "retired"

	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"

	KindLevel = "level"
	KindEvent = "event"

	StaleCloseAfter       = 7 * 86400
	MaxMuteSeconds        = 30 * 86400
	EvaluateIntervalSec   = 15
	RetentionDays         = 90
	MaxEventRows          = 50000
	MaxStateRows          = 5000
	MaxTextChars          = 2000
	MaxSubjectChars       = 200
	StormWindowSeconds    = 300
	StormMaxNotifications = 8
	MailQueueCheckSeconds = 300
	MailStuckSeconds      = 15 * 60
	MailRetryRecheckSec   = 30
	ConfigVersion         = 2
	WebhookTimeoutSec     = 10
	WebhookMaxRespBytes   = 8192
	WebhookUserAgent      = "easy-ha-proxy-alertd/1.0"
)

// Rule defines one condition the gateway knows how to track and notify about.
type Rule struct {
	Name          string
	Kind          string
	Severity      string
	Title         string
	TriggerDelay  int
	RepeatAfter   int
	AutoClear     int
	StaleAfter    int
	Enabled       bool
	Report        bool
	RecoveryTitle string
}

// Rules is the complete catalogue matching easy-ha-proxy-alertd.py.
var Rules = []Rule{
	{Name: "site.down", Kind: KindLevel, Severity: SeverityCritical, Title: "Site is down", TriggerDelay: 300, RepeatAfter: 6 * 3600, AutoClear: 3600, StaleAfter: 900, Enabled: true},
	{Name: "http.error_ratio", Kind: KindLevel, Severity: SeverityWarning, Title: "HTTP 5xx ratio above the threshold", TriggerDelay: 300, RepeatAfter: 6 * 3600, AutoClear: 3600, StaleAfter: 900, Enabled: true},
	{Name: "response.slow", Kind: KindLevel, Severity: SeverityWarning, Title: "Response time above the threshold", TriggerDelay: 300, RepeatAfter: 6 * 3600, AutoClear: 3600, StaleAfter: 900, Enabled: true},
	{Name: "authelia.unavailable", Kind: KindLevel, Severity: SeverityCritical, Title: "Authelia is not answering", TriggerDelay: 120, RepeatAfter: 6 * 3600, AutoClear: 3600, StaleAfter: 900, Enabled: true, RecoveryTitle: "Authelia is answering"},
	{Name: "monitoring.storage", Kind: KindLevel, Severity: SeverityWarning, Title: "Monitoring storage is under pressure", TriggerDelay: 0, RepeatAfter: 6 * 3600, AutoClear: 3600, StaleAfter: 900, Enabled: true},
	{Name: "monitoring.paused", Kind: KindLevel, Severity: SeverityWarning, Title: "Historical monitoring is paused", TriggerDelay: 0, RepeatAfter: 6 * 3600, AutoClear: 3600, StaleAfter: 900, Enabled: true},
	{Name: "certificate.expiring", Kind: KindLevel, Severity: SeverityWarning, Title: "Certificate expires soon", TriggerDelay: 0, RepeatAfter: 24 * 3600, AutoClear: 3600, StaleAfter: 13 * 3600, Enabled: true},
	{Name: "certificate.renewal_failed", Kind: KindEvent, Severity: SeverityCritical, Title: "Certificate renewal failed", TriggerDelay: 0, RepeatAfter: 6 * 3600, AutoClear: 6 * 3600, StaleAfter: 900, Enabled: true},
	{Name: "security.burst", Kind: KindEvent, Severity: SeverityWarning, Title: "Burst of hostile requests", TriggerDelay: 0, RepeatAfter: 6 * 3600, AutoClear: 3600, StaleAfter: 900, Enabled: true},
	{Name: "security.hostile_ip", Kind: KindEvent, Severity: SeverityInfo, Title: "Adaptive protection acted on an address", TriggerDelay: 0, RepeatAfter: 6 * 3600, AutoClear: 3600, StaleAfter: 900, Enabled: true},
	{Name: "security.engine_failing", Kind: KindLevel, Severity: SeverityWarning, Title: "Adaptive protection is not working", TriggerDelay: 300, RepeatAfter: 6 * 3600, AutoClear: 3600, StaleAfter: 900, Enabled: true},
	{Name: "security.weekly_summary", Kind: KindEvent, Severity: SeverityInfo, Title: "Adaptive protection: the week", TriggerDelay: 0, RepeatAfter: 6 * 3600, AutoClear: 6 * 86400, StaleAfter: 900, Enabled: true, Report: true},
	{Name: "backup.failed", Kind: KindEvent, Severity: SeverityCritical, Title: "Backup job failed", TriggerDelay: 0, RepeatAfter: 6 * 3600, AutoClear: 6 * 3600, StaleAfter: 900, Enabled: true},
	{Name: "backup.space_low", Kind: KindEvent, Severity: SeverityWarning, Title: "Backup storage is running out of space", TriggerDelay: 0, RepeatAfter: 6 * 3600, AutoClear: 24 * 3600, StaleAfter: 900, Enabled: true},
	{Name: "restore.failed", Kind: KindEvent, Severity: SeverityCritical, Title: "Restore job failed", TriggerDelay: 0, RepeatAfter: 6 * 3600, AutoClear: 6 * 3600, StaleAfter: 900, Enabled: true},
	{Name: "update.failed", Kind: KindEvent, Severity: SeverityWarning, Title: "Software update failed", TriggerDelay: 0, RepeatAfter: 6 * 3600, AutoClear: 6 * 3600, StaleAfter: 900, Enabled: true},
	{Name: "update.available", Kind: KindLevel, Severity: SeverityInfo, Title: "Software updates are available", TriggerDelay: 0, RepeatAfter: 7 * 86400, AutoClear: 3600, StaleAfter: 8 * 86400, Enabled: true},
	{Name: "os.security_updates", Kind: KindLevel, Severity: SeverityWarning, Title: "OS security updates are available", TriggerDelay: 0, RepeatAfter: 86400, AutoClear: 3600, StaleAfter: 8 * 86400, Enabled: true, RecoveryTitle: "No OS security updates are pending"},
	{Name: "os.security_restart", Kind: KindLevel, Severity: SeverityWarning, Title: "Security updates require a restart", TriggerDelay: 0, RepeatAfter: 86400, AutoClear: 3600, StaleAfter: 8 * 86400, Enabled: true},
	{Name: "os.security_check_failed", Kind: KindLevel, Severity: SeverityWarning, Title: "OS security updates could not be checked", TriggerDelay: 0, RepeatAfter: 86400, AutoClear: 3600, StaleAfter: 8 * 86400, Enabled: true},
	{Name: "os.security_stalled", Kind: KindLevel, Severity: SeverityWarning, Title: "OS security updates are not running", TriggerDelay: 0, RepeatAfter: 86400, AutoClear: 3600, StaleAfter: 3600, Enabled: true},
	{Name: "ssh.protection_lost", Kind: KindLevel, Severity: SeverityWarning, Title: "SSH blocking could not be verified", TriggerDelay: 120, RepeatAfter: 86400, AutoClear: 3600, StaleAfter: 600, Enabled: true},
	{Name: "ssh.ban_burst", Kind: KindLevel, Severity: SeverityWarning, Title: "Burst of SSH blocks", TriggerDelay: 0, RepeatAfter: 3600, AutoClear: 3600, StaleAfter: 600, Enabled: true},
	{Name: "config.apply_failed", Kind: KindEvent, Severity: SeverityCritical, Title: "HAProxy apply or reload failed", TriggerDelay: 0, RepeatAfter: 6 * 3600, AutoClear: 3600, StaleAfter: 900, Enabled: true},
	{Name: "udp.failover", Kind: KindLevel, Severity: SeverityWarning, Title: "A UDP forward runs on its backup backend", TriggerDelay: 0, RepeatAfter: 86400, AutoClear: 3600, StaleAfter: 1800, Enabled: true},
	{Name: "mail.delivery_failed", Kind: KindLevel, Severity: SeverityCritical, Title: "Mail cannot be delivered", TriggerDelay: 0, RepeatAfter: 6 * 3600, AutoClear: 3600, StaleAfter: 6 * 3600, Enabled: true},
}

// RulesByName maps rule names to their immutable definitions.
var RulesByName = func() map[string]Rule {
	m := make(map[string]Rule, len(Rules))
	for _, r := range Rules {
		m[r.Name] = r
	}
	return m
}()

// ValidSeverity returns true when s is info, warning, or critical.
func ValidSeverity(s string) bool {
	return s == SeverityInfo || s == SeverityWarning || s == SeverityCritical
}

// SeverityRank returns 0 for info, 1 for warning, 2 for critical.
func SeverityRank(s string) int {
	switch s {
	case SeverityCritical:
		return 2
	case SeverityWarning:
		return 1
	default:
		return 0
	}
}
