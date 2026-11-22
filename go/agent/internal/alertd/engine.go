package alertd

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	// ErrInvalid indicates client input validation failure (HTTP 400).
	ErrInvalid = errors.New("invalid request")
	// ErrNotFound indicates a missing alert record (HTTP 404).
	ErrNotFound = errors.New("not found")
)

type codedError struct {
	kind error
	msg  string
}

func (e codedError) Error() string { return e.msg }
func (e codedError) Unwrap() error { return e.kind }

func invalidErr(msg string) error  { return codedError{kind: ErrInvalid, msg: msg} }
func notFoundErr(msg string) error { return codedError{kind: ErrNotFound, msg: msg} }

// Engine implements the alertd state machine, storm control, quietening, and sweep loop.
type Engine struct {
	mu         sync.Mutex
	configMu   sync.Mutex
	config     Config
	store      *Store
	channels   []Channel
	opts       DaemonOptions
	nowFn      func() int64
	lastPrune  int64
	lookupHook LookupIPFunc
}

// NewEngine constructs an AlertEngine with explicit options, store, and optional custom channels.
func NewEngine(opts DaemonOptions, cfg Config, store *Store, channels []Channel) *Engine {
	if channels == nil {
		channels = []Channel{
			&EmailChannel{
				MailStatePath:      opts.MailStatePath,
				MailLockPath:       opts.MailLockPath,
				MailRelayContainer: opts.MailRelayContainer,
				DockerBin:          opts.DockerBin,
			},
			&WebhookChannel{},
		}
	}
	return &Engine{
		config:   cfg,
		store:    store,
		channels: channels,
		opts:     opts,
		nowFn:    func() int64 { return time.Now().Unix() },
	}
}

func (e *Engine) now() int64 { return e.nowFn() }

func formatISO(ts int64) string {
	return time.Unix(ts, 0).UTC().Format("2006-01-02 15:04 UTC")
}

func formatISOSec(ts int64) string {
	return time.Unix(ts, 0).UTC().Format("2006-01-02 15:04:05 UTC")
}

// RunLoop executes periodic sweeps and mail queue checks until ctx is canceled.
func (e *Engine) RunLoop(ctx context.Context) {
	ticker := time.NewTicker(EvaluateIntervalSec * time.Second)
	defer ticker.Stop()
	var lastMailCheck int64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.Sweep()
			now := e.now()
			if now-lastMailCheck >= MailQueueCheckSeconds {
				lastMailCheck = now
				e.CheckMailQueue(ctx)
			}
		}
	}
}

// Observe records one producer observation and fires/recovers/repeats notifications as configured.
func (e *Engine) Observe(ctx context.Context, payload map[string]any) (map[string]any, error) {
	ruleName := strings.TrimSpace(asString(payload["rule"]))
	rule, ok := RulesByName[ruleName]
	if !ok {
		return nil, invalidErr(fmt.Sprintf("unknown rule: %q", ruleName))
	}

	rawSubject := asString(payload["subject"])
	if rawSubject == "" {
		rawSubject = "-"
	}
	subject := cleanText(rawSubject, MaxSubjectChars)
	if !subjectRe.MatchString(subject) {
		return nil, invalidErr("subject may use letters, digits and . _ : / @ * -")
	}

	var active bool
	if rule.Kind == KindEvent {
		active = true
	} else {
		b, isBool := payload["active"].(bool)
		if !isBool {
			return nil, invalidErr("active must be true or false for a level condition")
		}
		active = b
	}

	severity := strings.ToLower(strings.TrimSpace(asString(payload["severity"])))
	if !ValidSeverity(severity) {
		severity = rule.Severity
	}
	summary := cleanText(asString(payload["summary"]), MaxTextChars)
	if summary == "" {
		summary = rule.Title
	}
	detail := cleanText(asString(payload["detail"]), MaxTextChars)

	var overrideDelay *int
	if rawDelay, has := payload["trigger_delay"]; has && rawDelay != nil && rule.Kind == KindLevel {
		d := clampInt(asInt(rawDelay, rule.TriggerDelay), 0, 86400)
		overrideDelay = &d
	}
	recipient := strings.TrimSpace(asString(payload["recipient"]))
	if recipient != "" && !emailRe.MatchString(recipient) {
		return nil, invalidErr("the recipient is not a valid email address")
	}

	if retired, _ := payload["retired"].(bool); retired && rule.Kind == KindLevel {
		e.mu.Lock()
		defer e.mu.Unlock()
		return e.retireLocked(rule, subject, summary), nil
	}

	return e.apply(ctx, rule, subject, active, severity, summary, detail, overrideDelay, recipient), nil
}

func (e *Engine) retireLocked(rule Rule, subject, summary string) map[string]any {
	row, ok := e.store.GetState(rule.Name, subject)
	if !ok || row.State == StateOK {
		return map[string]any{"rule": rule.Name, "subject": subject, "state": StateOK}
	}
	e.store.DropState(rule.Name, subject)
	e.store.AddEvent(AlertEvent{
		TS:         e.now(),
		Rule:       rule.Name,
		Subject:    subject,
		Transition: TransitionRetired,
		Severity:   row.Severity,
		Summary:    row.Summary,
		Detail:     summary,
	})
	return map[string]any{
		"rule":       rule.Name,
		"subject":    subject,
		"state":      StateOK,
		"transition": TransitionRetired,
		"notified":   false,
	}
}

type preparedDelivery struct {
	eventID     int64
	mailSubject string
	body        string
}

func (e *Engine) apply(
	ctx context.Context,
	rule Rule,
	subject string,
	active bool,
	severity string,
	summary string,
	detail string,
	overrideDelay *int,
	recipient string,
) map[string]any {
	var pending *preparedDelivery
	var now int64
	var transition string
	var state string

	e.mu.Lock()
	now = e.now()
	settings := e.config.SettingsFor(rule)
	delay := settings.TriggerDelay
	if overrideDelay != nil {
		delay = *overrideDelay
	}
	row, hasRow := e.store.GetState(rule.Name, subject)
	state = StateOK
	since := now
	firstSeen := now
	var lastNotified int64
	notifyCount := 0
	if hasRow {
		state = row.State
		since = row.SinceTS
		firstSeen = row.FirstSeenTS
		lastNotified = row.LastNotifiedTS
		notifyCount = row.NotifyCount
	}

	if !active {
		if state == StateFiring {
			transition = TransitionRecovered
			state = StateOK
			since = now
		} else if state == StatePending {
			state = StateOK
			since = now
		}
	} else {
		if state == StateOK {
			state = StatePending
			since = now
			firstSeen = now
			notifyCount = 0
		}
		if state == StatePending && now-since >= int64(delay) {
			state = StateFiring
			since = now
			transition = TransitionFired
		} else if state == StateFiring && hasRow && SeverityRank(severity) > SeverityRank(row.Severity) {
			transition = TransitionEscalated
		} else if state == StateFiring && now-lastNotified >= int64(settings.RepeatAfter) {
			transition = TransitionRepeated
		}
	}

	e.store.PutState(AlertState{
		Rule:           rule.Name,
		Subject:        subject,
		State:          state,
		Severity:       severity,
		SinceTS:        since,
		FirstSeenTS:    firstSeen,
		LastSeenTS:     now,
		LastNotifiedTS: lastNotified,
		NotifyCount:    notifyCount,
		Summary:        summary,
		Detail:         detail,
		TriggerDelay:   overrideDelay,
		Recipient:      recipient,
	})

	if state == StateOK && hasRow && row.AcknowledgedTS > 0 {
		e.store.ClearAcknowledgement(rule.Name, subject)
	}

	result := map[string]any{
		"rule":    rule.Name,
		"subject": subject,
		"state":   state,
	}
	if transition == "" {
		e.mu.Unlock()
		return result
	}
	pending = e.prepareNotifyLocked(rule, subject, transition, severity, summary, detail, now)
	e.mu.Unlock()

	notified := false
	if pending != nil {
		// Perform channel I/O outside e.mu so slow SMTP/webhook calls never stall other producers.
		delivered, errs := e.Deliver(ctx, pending.mailSubject, pending.body, recipient)
		notified = len(delivered) > 0
		e.mu.Lock()
		e.store.SetDelivery(pending.eventID, strings.Join(delivered, ","), strings.Join(errs, "; "))
		if notified {
			if cur, ok := e.store.GetState(rule.Name, subject); ok {
				cur.LastNotifiedTS = now
				cur.NotifyCount++
				e.store.PutState(cur)
			}
		}
		e.mu.Unlock()
	}

	result["transition"] = transition
	result["notified"] = notified
	return result
}

func (e *Engine) shouldNotifyLocked(rule Rule, severity string) (bool, string) {
	if !e.config.Enabled {
		return false, "alerting is switched off"
	}
	if !e.config.SettingsFor(rule).Enabled {
		return false, "the rule is switched off"
	}
	if !rule.Report && SeverityRank(severity) < SeverityRank(e.config.MinSeverity) {
		return false, "below the configured minimum severity"
	}
	return true, ""
}

func (e *Engine) quietReasonLocked(rule Rule, subject, transition string, now int64) string {
	row, ok := e.store.GetState(rule.Name, subject)
	if !ok {
		return ""
	}
	if row.MutedUntil > now && transition != TransitionRecovered {
		return fmt.Sprintf("muted until %s", formatISO(row.MutedUntil))
	}
	if row.AcknowledgedTS > 0 && transition == TransitionRepeated {
		return "acknowledged"
	}
	return ""
}

func (e *Engine) prepareNotifyLocked(rule Rule, subject, transition, severity, summary, detail string, now int64) *preparedDelivery {
	allowed, reason := e.shouldNotifyLocked(rule, severity)
	if allowed {
		if quiet := e.quietReasonLocked(rule, subject, transition, now); quiet != "" {
			allowed, reason = false, quiet
		}
	}
	if allowed && transition == TransitionRecovered && severity == SeverityInfo {
		allowed, reason = false, "information: no message when it ends"
	}
	if allowed && transition == TransitionRecovered {
		if row, ok := e.store.GetState(rule.Name, subject); ok && row.NotifyCount == 0 {
			allowed, reason = false, "no notification was delivered for this incident"
		}
	}
	if !allowed {
		e.store.AddEvent(AlertEvent{
			TS:            now,
			Rule:          rule.Name,
			Subject:       subject,
			Transition:    transition,
			Severity:      severity,
			Summary:       summary,
			Detail:        detail,
			DeliveryError: reason,
		})
		return nil
	}

	recent := e.store.NotificationsSince(now - StormWindowSeconds)
	if transition != TransitionRecovered && recent >= StormMaxNotifications {
		e.store.AddEvent(AlertEvent{
			TS:         now,
			Rule:       rule.Name,
			Subject:    subject,
			Transition: TransitionSuppressed,
			Severity:   severity,
			Summary:    summary,
			Detail:     detail,
			DeliveryError: fmt.Sprintf(
				"more than %d notifications in %d minutes",
				StormMaxNotifications, StormWindowSeconds/60,
			),
		})
		return nil
	}

	eventID := e.store.AddEvent(AlertEvent{
		TS:         now,
		Rule:       rule.Name,
		Subject:    subject,
		Transition: transition,
		Severity:   severity,
		Summary:    summary,
		Detail:     detail,
	})
	mailSubj, body := e.Render(rule, subject, transition, severity, summary, detail, now)
	return &preparedDelivery{eventID: eventID, mailSubject: mailSubj, body: body}
}

// Deliver sends a message across all available channels.
func (e *Engine) Deliver(ctx context.Context, subject, body, recipient string) ([]string, []string) {
	e.mu.Lock()
	cfg := e.config.Clone()
	channels := e.channels
	e.mu.Unlock()
	if recipient != "" {
		cfg.Recipient = recipient
	}

	delivered := []string{}
	errs := []string{}
	for _, ch := range channels {
		if !ch.Available(cfg) {
			continue
		}
		ok, errMsg := ch.Send(ctx, cfg, subject, body)
		if ok {
			delivered = append(delivered, ch.Name())
		} else {
			errs = append(errs, fmt.Sprintf("%s: %s", ch.Name(), errMsg))
		}
	}
	if len(delivered) == 0 && len(errs) == 0 {
		errs = append(errs, "no channel is configured")
	}
	return delivered, errs
}

// Render formats the notification subject and body matching easy-ha-proxy-alertd.py.
func (e *Engine) Render(rule Rule, subject, transition, severity, summary, detail string, now int64) (string, string) {
	verb := "ALERT"
	switch transition {
	case TransitionRepeated:
		verb = "STILL"
	case TransitionEscalated:
		verb = "WORSE"
	case TransitionRecovered:
		verb = "RESOLVED"
	}
	if severity == SeverityInfo && (transition == TransitionFired || transition == TransitionRepeated) {
		verb = "INFO"
	}
	title := rule.Title
	if transition == TransitionRecovered && rule.RecoveryTitle != "" {
		title = rule.RecoveryTitle
	}
	head := fmt.Sprintf("[%s] %s %s: %s", e.opts.GatewayName, verb, severity, title)
	if subject != "" && subject != "-" {
		head += fmt.Sprintf(" (%s)", subject)
	}
	if summary == "" {
		summary = rule.Title
	}
	lines := []string{
		summary,
		"",
		fmt.Sprintf("Condition : %s", rule.Name),
		fmt.Sprintf("Subject   : %s", subject),
		fmt.Sprintf("Severity  : %s", severity),
		fmt.Sprintf("State     : %s", strings.ToLower(verb)),
		fmt.Sprintf("Time      : %s", formatISOSec(now)),
		fmt.Sprintf("Gateway   : %s", e.opts.GatewayName),
	}
	if detail != "" {
		lines = append(lines, "", detail)
	}
	lines = append(lines, "", "Sent by easy-ha-proxy. Alert settings live on the Alerts page.")
	return head, strings.Join(lines, "\n")
}

// Sweep marks stale firing levels, closes expired stale alerts, clears aged events, and prunes hourly.
func (e *Engine) Sweep() map[string]int {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	stale, expired, cleared := 0, 0, 0

	for _, row := range e.store.OpenStates() {
		rule, ok := RulesByName[row.Rule]
		if !ok {
			e.store.DropState(row.Rule, row.Subject)
			continue
		}
		age := now - row.LastSeenTS
		if rule.Kind == KindEvent {
			if age >= int64(rule.AutoClear) {
				e.store.DropState(rule.Name, row.Subject)
				cleared++
			}
			continue
		}
		if age < int64(rule.StaleAfter) {
			continue
		}
		if row.State != StateFiring {
			e.store.DropState(rule.Name, row.Subject)
			cleared++
			continue
		}
		if row.StaleSinceTS == 0 {
			e.store.MarkStale(rule.Name, row.Subject, now)
			e.store.AddEvent(AlertEvent{
				TS:         now,
				Rule:       rule.Name,
				Subject:    row.Subject,
				Transition: TransitionStale,
				Severity:   row.Severity,
				Summary:    row.Summary,
				Detail: fmt.Sprintf(
					"No report since %s; the last reported state is kept until the source reports again.",
					formatISO(row.LastSeenTS),
				),
			})
			stale++
		} else if now-row.StaleSinceTS >= StaleCloseAfter {
			e.store.DropState(rule.Name, row.Subject)
			e.store.AddEvent(AlertEvent{
				TS:         now,
				Rule:       rule.Name,
				Subject:    row.Subject,
				Transition: TransitionExpired,
				Severity:   row.Severity,
				Summary:    row.Summary,
				Detail: fmt.Sprintf(
					"No report since %s; closed without a recovery.",
					formatISO(row.LastSeenTS),
				),
			})
			expired++
		}
	}
	if now-e.lastPrune >= 3600 {
		e.lastPrune = now
		e.store.Prune(now)
	}
	return map[string]int{"stale": stale, "expired": expired, "cleared": cleared}
}

// Quieten acknowledges, mutes, or clears quiet state for an alert.
func (e *Engine) Quieten(payload map[string]any) (map[string]any, error) {
	ruleName := asString(payload["rule"])
	rule, ok := RulesByName[ruleName]
	if !ok {
		return nil, invalidErr("unknown rule")
	}
	subject := asString(payload["subject"])
	mode := asString(payload["mode"])
	actor := cleanText(asString(payload["by"]), 120)
	now := e.now()

	var ackTS, mutedUntil int64
	var ackBy string
	switch mode {
	case "acknowledge":
		ackTS, ackBy, mutedUntil = now, actor, 0
	case "mute":
		secs := clampInt(asInt(payload["seconds"], 3600), 300, MaxMuteSeconds)
		ackTS, ackBy, mutedUntil = now, actor, now+int64(secs)
	case "clear":
		ackTS, ackBy, mutedUntil = 0, "", 0
	default:
		return nil, invalidErr("mode must be acknowledge, mute or clear")
	}

	e.mu.Lock()
	found := e.store.SetQuiet(rule.Name, subject, ackTS, ackBy, mutedUntil)
	e.mu.Unlock()
	if !found {
		return nil, notFoundErr("no such alert")
	}
	return map[string]any{
		"rule":            rule.Name,
		"subject":         subject,
		"acknowledged_ts": ackTS,
		"acknowledged_by": ackBy,
		"muted_until":     mutedUntil,
	}, nil
}

// Dismiss closes an event early or closes a stale level alert.
func (e *Engine) Dismiss(payload map[string]any) (map[string]any, error) {
	ruleName := asString(payload["rule"])
	rule, ok := RulesByName[ruleName]
	if !ok {
		return nil, invalidErr("unknown rule")
	}
	subject := asString(payload["subject"])
	actor := cleanText(asString(payload["by"]), 120)
	now := e.now()

	e.mu.Lock()
	defer e.mu.Unlock()
	row, exists := e.store.GetState(rule.Name, subject)
	if !exists {
		return nil, notFoundErr("no such alert")
	}
	if rule.Kind != KindEvent && row.StaleSinceTS <= 0 {
		return nil, invalidErr("a condition that still holds cannot be dismissed; mute it instead")
	}
	e.store.DropState(rule.Name, subject)
	detail := "dismissed"
	if actor != "" {
		detail = "dismissed by " + actor
	}
	e.store.AddEvent(AlertEvent{
		TS:         now,
		Rule:       rule.Name,
		Subject:    subject,
		Transition: TransitionDismissed,
		Severity:   row.Severity,
		Summary:    row.Summary,
		Detail:     detail,
	})
	return map[string]any{"rule": rule.Name, "subject": subject, "dismissed": true}, nil
}

// DeleteHistory deletes selected, older, or all history rows.
func (e *Engine) DeleteHistory(payload map[string]any) (int, error) {
	if all, _ := payload["all"].(bool); all {
		return e.store.DeleteEvents(nil, true, 0), nil
	}
	if rawBefore, has := payload["before"]; has && rawBefore != nil {
		before := int64(clampInt(asInt(rawBefore, 0), 1, 2000000000))
		return e.store.DeleteEvents(nil, false, before), nil
	}
	rawIDs, ok := payload["ids"].([]any)
	if !ok || len(rawIDs) == 0 {
		return 0, invalidErr("ids, before or all is required")
	}
	ids := make([]int64, 0, len(rawIDs))
	for _, v := range rawIDs {
		switch n := v.(type) {
		case float64:
			ids = append(ids, int64(n))
		case int:
			ids = append(ids, int64(n))
		case int64:
			ids = append(ids, n)
		default:
			return 0, invalidErr("ids must be numbers")
		}
	}
	return e.store.DeleteEvents(ids, false, 0), nil
}

// Portal returns the header banner alerts that are unacknowledged and unmuted.
func (e *Engine) Portal() map[string]any {
	e.mu.Lock()
	cfg := e.config
	now := e.now()
	e.mu.Unlock()

	floor := SeverityRank(cfg.PortalMinSeverity)
	type portalItem struct {
		Rule     string `json:"rule"`
		Title    string `json:"title"`
		Subject  string `json:"subject"`
		Severity string `json:"severity"`
		Since    int64  `json:"since"`
		Summary  string `json:"summary"`
	}
	items := make([]portalItem, 0)
	quiet := 0
	for _, row := range e.store.ActiveAlerts() {
		if SeverityRank(row.Severity) < floor {
			continue
		}
		if row.MutedUntil > now || (row.AcknowledgedTS > 0 && row.MutedUntil == 0) {
			quiet++
			continue
		}
		title := row.Rule
		if r, ok := RulesByName[row.Rule]; ok {
			title = r.Title
		}
		items = append(items, portalItem{
			Rule:     row.Rule,
			Title:    title,
			Subject:  row.Subject,
			Severity: row.Severity,
			Since:    row.SinceTS,
			Summary:  row.Summary,
		})
	}
	sort.Slice(items, func(i, j int) bool {
		ri, rj := SeverityRank(items[i].Severity), SeverityRank(items[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return items[i].Since > items[j].Since
	})
	critical := 0
	for _, it := range items {
		if it.Severity == SeverityCritical {
			critical++
		}
	}
	capped := items
	if len(capped) > 20 {
		capped = capped[:20]
	}
	return map[string]any{
		"items":        capped,
		"total":        len(items),
		"critical":     critical,
		"quiet":        quiet,
		"min_severity": cfg.PortalMinSeverity,
	}
}

// Health returns daemon status, channel availability, and store counts.
func (e *Engine) Health() map[string]any {
	e.mu.Lock()
	cfg := e.config
	channels := e.channels
	e.mu.Unlock()

	chMap := make(map[string]bool, len(channels))
	for _, ch := range channels {
		chMap[ch.Name()] = ch.Available(cfg)
	}
	stats := e.store.Stats()
	return map[string]any{
		"enabled":        cfg.Enabled,
		"hostname":       e.opts.GatewayName,
		"channels":       chMap,
		"rules":          len(Rules),
		"firing":         stats.Firing,
		"pending":        stats.Pending,
		"events":         stats.Events,
		"database_bytes": stats.DatabaseBytes,
	}
}

// Snapshot returns active alerts, pending alerts, history, rule catalogue, and redacted config.
func (e *Engine) Snapshot(limit int) map[string]any {
	e.mu.Lock()
	cfg := e.config.Clone()
	e.mu.Unlock()

	active := e.store.ActiveAlerts()
	pending := make([]AlertState, 0)
	for _, row := range e.store.OpenStates() {
		if row.State == StatePending {
			pending = append(pending, row)
		}
	}
	total, history := e.store.Events(EventFilter{Limit: limit})
	catalogue := make([]map[string]any, 0, len(Rules))
	for _, r := range Rules {
		s := cfg.SettingsFor(r)
		catalogue = append(catalogue, map[string]any{
			"name":          r.Name,
			"kind":          r.Kind,
			"title":         r.Title,
			"severity":      r.Severity,
			"enabled":       s.Enabled,
			"trigger_delay": s.TriggerDelay,
			"repeat_after":  s.RepeatAfter,
		})
	}
	return map[string]any{
		"active":        active,
		"pending":       pending,
		"history":       history,
		"history_total": total,
		"catalogue":     catalogue,
		"config":        cfg.Redacted(),
	}
}

// UpdateConfig validates, saves atomically to disk, and activates new settings.
func (e *Engine) UpdateConfig(ctx context.Context, payload map[string]any) (Config, error) {
	if payload == nil {
		return Config{}, invalidErr("a JSON object is required")
	}
	e.configMu.Lock()
	defer e.configMu.Unlock()

	e.mu.Lock()
	next := e.config.Clone()
	e.mu.Unlock()

	if v, ok := payload["enabled"]; ok {
		b, isBool := v.(bool)
		next.Enabled = !isBool || b
	}
	if v, ok := payload["email_enabled"]; ok {
		b, isBool := v.(bool)
		next.EmailEnabled = !isBool || b
	}
	if v, ok := payload["recipient"]; ok {
		rec := strings.TrimSpace(asString(v))
		if rec != "" && !emailRe.MatchString(rec) {
			return Config{}, invalidErr("the recipient is not a valid email address")
		}
		next.Recipient = rec
	}
	if v, ok := payload["min_severity"]; ok {
		s := strings.ToLower(strings.TrimSpace(asString(v)))
		if !ValidSeverity(s) {
			return Config{}, invalidErr("min_severity must be info, warning or critical")
		}
		next.MinSeverity = s
	}
	if v, ok := payload["portal_min_severity"]; ok {
		s := strings.ToLower(strings.TrimSpace(asString(v)))
		if !ValidSeverity(s) {
			return Config{}, invalidErr("portal_min_severity must be info, warning or critical")
		}
		next.PortalMinSeverity = s
	}
	if v, ok := payload["webhook_allow_private"]; ok {
		b, _ := v.(bool)
		next.WebhookAllowPrivate = b
	}
	if v, ok := payload["webhook_url"]; ok {
		u := strings.TrimSpace(asString(v))
		if u != "" {
			if _, err := ResolveWebhookTarget(ctx, u, next.WebhookAllowPrivate, e.lookupHook); err != nil {
				return Config{}, invalidErr(err.Error())
			}
		}
		next.WebhookURL = u
	}
	if v, ok := payload["webhook_header_name"]; ok {
		name := strings.TrimSpace(asString(v))
		if name != "" && !headerNameRe.MatchString(name) {
			return Config{}, invalidErr("the header name may use letters, digits and -")
		}
		next.WebhookHeaderName = name
	}
	if v, ok := payload["webhook_header_value"]; ok {
		val := asString(v)
		if val != "***" {
			if hasAnyControlChar(val) {
				return Config{}, invalidErr("the header value contains invalid characters")
			}
			if len(val) > 4096 {
				val = val[:4096]
			}
			next.WebhookHeaderValue = val
		}
	}
	if rawRules, has := payload["rules"]; has && rawRules != nil {
		rm, ok := rawRules.(map[string]any)
		if !ok {
			return Config{}, invalidErr("rules must be an object")
		}
		for name, val := range rm {
			rule, exists := RulesByName[name]
			if !exists {
				return Config{}, invalidErr("unknown rule: " + name)
			}
			obj, ok := val.(map[string]any)
			if !ok {
				return Config{}, invalidErr("rule " + name + " must be an object")
			}
			enabled := rule.Enabled
			if ev, hasEn := obj["enabled"]; hasEn {
				if b, isBool := ev.(bool); isBool {
					enabled = b
				}
			}
			next.Rules[name] = RuleSettings{
				Enabled:      enabled,
				TriggerDelay: clampInt(asInt(obj["trigger_delay"], rule.TriggerDelay), 0, 86400),
				RepeatAfter:  clampInt(asInt(obj["repeat_after"], rule.RepeatAfter), 300, 7*86400),
			}
		}
	}
	next.ConfigVersion = ConfigVersion

	if e.opts.ConfigPath != "" {
		if err := SaveConfig(e.opts.ConfigPath, next); err != nil {
			return Config{}, err
		}
	}
	e.mu.Lock()
	e.config = next
	e.mu.Unlock()
	return next, nil
}

// CheckMailQueue inspects mail_relay's Postfix queue and updates mail.delivery_failed.
func (e *Engine) CheckMailQueue(ctx context.Context) *bool {
	e.mu.Lock()
	cfg := e.config
	e.mu.Unlock()
	em := &EmailChannel{
		MailStatePath:      e.opts.MailStatePath,
		MailLockPath:       e.opts.MailLockPath,
		MailRelayContainer: e.opts.MailRelayContainer,
		DockerBin:          e.opts.DockerBin,
	}
	if !em.Available(cfg) {
		return nil
	}
	cmdCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cmdCtx, e.opts.DockerBin, "exec", e.opts.MailRelayContainer, "postqueue", "-j").Output()
	if err != nil {
		return nil
	}
	now := e.now()
	stuck := ParseMailQueueStuck(string(out), now)
	var oldest int64
	reason := ""
	for _, it := range stuck {
		if age := now - it.Arrival; age > oldest {
			oldest = age
		}
		if reason == "" && it.Reason != "" {
			reason = it.Reason
		}
	}
	active := len(stuck) > 0
	summary := "Mail is being delivered again"
	if active {
		summary = fmt.Sprintf("Mail cannot be delivered: %d message(s) waiting, the oldest for %d min", len(stuck), oldest/60)
	}
	detail := ""
	if reason != "" {
		detail = "The relay's last reason: " + reason
	}
	_, _ = e.Observe(ctx, map[string]any{
		"rule":    "mail.delivery_failed",
		"subject": "relay",
		"active":  active,
		"summary": summary,
		"detail":  detail,
	})
	return &active
}

// RetryMail flushes the Postfix queue via `postqueue -f` and schedules a recheck.
func (e *Engine) RetryMail(ctx context.Context) (map[string]any, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := exec.CommandContext(cmdCtx, e.opts.DockerBin, "exec", e.opts.MailRelayContainer, "postqueue", "-f").Run(); err != nil {
		return nil, fmt.Errorf("the mail relay could not be asked to retry: %v", err)
	}
	time.AfterFunc(MailRetryRecheckSec*time.Second, func() {
		e.CheckMailQueue(context.Background())
	})
	return map[string]any{"retried": true, "recheck_in": MailRetryRecheckSec}, nil
}
