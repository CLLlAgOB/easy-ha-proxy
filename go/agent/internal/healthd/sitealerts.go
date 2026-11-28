package healthd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/alerts"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/haproxy"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/hostfile"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/pyx"
	"gopkg.in/yaml.v3"
)

// Per-site availability alerts (SiteAlertEngine): sites that opt in through
// websites.yml are watched through HAProxy's statistics. With the alert
// engine reachable this only reports; without it, the local state machine
// mails through mail_relay itself.
var (
	siteAlertsWebsites  = envOr("HAPADM_SITE_ALERTS_WEBSITES", "/opt/haproxy-admin/config/websites.yml")
	siteAlertsInterval  = math.Max(5, envFloat("HAPADM_SITE_ALERTS_INTERVAL", 15))
	siteAlertsSocket    = envOr("HAPADM_SITE_ALERTS_HAPROXY_SOCKET", "/run/haproxy/admin.sock")
	siteAlertsMailState = envOr("HAPADM_SITE_ALERTS_MAIL_STATE", "/etc/easy-ha-proxy/mail-notify.json")
	siteAlertsMailLock  = envOr("HAPADM_SITE_ALERTS_MAIL_LOCK", "/run/easy-ha-proxy/authelia-mail.lock")
	siteAlertsRepeat    = math.Max(600, float64(envInt("HAPADM_SITE_ALERTS_REPEAT_SECONDS", 21600)))
	siteAlertsStatePath = envOr("HAPADM_SITE_ALERTS_STATE_PATH", "/var/lib/easy-ha-proxy/site-alerts.json")

	intervalValueRe = regexp.MustCompile(`^([1-9][0-9]*)(ms|s|m|h|d)$`)
	siteIDRe        = regexp.MustCompile(`[^A-Za-z0-9_]`)
	alertEmailRe    = regexp.MustCompile(`^[^@\s]{1,64}@[^@\s]{1,253}\.[A-Za-z0-9-]{2,63}$`)
)

const (
	siteAlertsStateMaxBytes     = 1024 * 1024
	siteAlertsStateMaxIncidents = 1024
	siteAlertsStateVersion      = 1
)

func alertAfterSeconds(v any) float64 {
	switch t := v.(type) {
	case int:
		if t > 0 {
			return float64(t)
		}
	case float64:
		if t > 0 {
			return t
		}
	}
	m := intervalValueRe.FindStringSubmatch(strings.TrimSpace(fmt.Sprint(nilToEmpty(v))))
	if m == nil {
		return 300
	}
	n, _ := strconv.Atoi(m[1])
	unit := map[string]float64{"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400}[m[2]]
	return float64(n) * unit
}

func nilToEmpty(v any) any {
	if v == nil {
		return ""
	}
	return v
}

func formatDuration(seconds float64) string {
	total := int(math.Max(0, seconds))
	days, rem := total/86400, total%86400
	hours, rem := rem/3600, rem%3600
	minutes, secs := rem/60, rem%60
	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	case hours > 0:
		return fmt.Sprintf("%dh %dm", hours, minutes)
	case minutes > 0:
		return fmt.Sprintf("%dm %ds", minutes, secs)
	}
	return fmt.Sprintf("%ds", secs)
}

type serverState struct {
	Name string
	Addr string
	Up   bool
}

func formatServers(servers []serverState) string {
	lines := make([]string, 0, len(servers))
	for _, s := range servers {
		state := "DOWN"
		if s.Up {
			state = "UP"
		}
		if s.Addr != "" {
			lines = append(lines, fmt.Sprintf("  - %s (%s): %s", s.Name, s.Addr, state))
		} else {
			lines = append(lines, fmt.Sprintf("  - %s: %s", s.Name, state))
		}
	}
	return strings.Join(lines, "\n")
}

type siteCondition struct {
	State   string
	Up      int
	Total   int
	Servers []serverState
}

func siteConditionFor(siteID string, rows []haproxy.StatRow) *siteCondition {
	backend := "be_" + siteID
	var backendUp *bool
	c := &siteCondition{}
	for _, row := range rows {
		if row["pxname"] != backend {
			continue
		}
		sv := row["svname"]
		status := strings.ToUpper(row["status"])
		if sv == "BACKEND" {
			up := !strings.HasPrefix(status, "DOWN")
			backendUp = &up
		} else if sv != "FRONTEND" {
			c.Total++
			isUp := strings.HasPrefix(status, "UP") || strings.HasPrefix(status, "NO CHECK")
			if isUp {
				c.Up++
			}
			c.Servers = append(c.Servers, serverState{Name: sv, Addr: row["addr"], Up: isUp})
		}
	}
	if backendUp == nil {
		return nil
	}
	switch {
	case !*backendUp || (c.Total > 0 && c.Up == 0):
		c.State = "down"
	case c.Total > 0 && c.Up < c.Total:
		c.State = "degraded"
	default:
		c.State = "ok"
	}
	return c
}

// incident is one site's local alert record.
type incident struct {
	BadSince     *float64 `json:"bad_since"`
	AlertedAt    *float64 `json:"alerted_at"`
	AlertedState string   `json:"alerted_state"`
	GoodSince    *float64 `json:"good_since"`
}

func (i incident) active() bool {
	return i.BadSince != nil || i.AlertedAt != nil || i.GoodSince != nil
}

func validIncident(i incident) bool {
	for _, p := range []*float64{i.BadSince, i.AlertedAt, i.GoodSince} {
		if p != nil && (math.IsNaN(*p) || math.IsInf(*p, 0) || *p < 0) {
			return false
		}
	}
	if i.AlertedState != "" && i.AlertedState != "down" && i.AlertedState != "degraded" {
		return false
	}
	if i.AlertedAt != nil && i.BadSince == nil {
		return false
	}
	if i.GoodSince != nil && i.AlertedAt == nil {
		return false
	}
	return true
}

// SiteAlerts is SiteAlertEngine.
type SiteAlerts struct {
	stateDirty bool
	alerts     *alerts.Client
	incidents  map[string]*incident
	send       func(recipient, subject, body string) bool
}

// NewSiteAlerts builds the engine; client may be nil or unconfigured.
func NewSiteAlerts(client *alerts.Client) *SiteAlerts {
	sa := &SiteAlerts{incidents: loadIncidents()}
	if client.Enabled() {
		sa.alerts = client
	}
	sa.send = sendMail
	return sa
}

func stateFileSafe(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().IsRegular() && int(st.Uid) == os.Geteuid() && info.Mode().Perm()&0o022 == 0
}

func readSiteAlertFile(path string, maxBytes int64, state bool) ([]byte, error) {
	if !state {
		return hostfile.ReadRegular(path, maxBytes)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > maxBytes || !stateFileSafe(info) {
		return nil, fmt.Errorf("invalid site alerts file %s", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err == nil && int64(len(data)) > maxBytes {
		err = fmt.Errorf("site alerts file too large: %s", path)
	}
	return data, err
}

func loadIncidents() map[string]*incident {
	path := siteAlertsStatePath
	out := map[string]*incident{}
	if !filepath.IsAbs(path) {
		return out
	}
	raw, err := readSiteAlertFile(path, siteAlertsStateMaxBytes, true)
	if err != nil || len(raw) == 0 || len(raw) > siteAlertsStateMaxBytes {
		return out
	}
	var doc struct {
		Version   int                  `json:"version"`
		Incidents map[string]*incident `json:"incidents"`
	}
	if json.Unmarshal(raw, &doc) != nil || doc.Version != siteAlertsStateVersion || doc.Incidents == nil || len(doc.Incidents) > siteAlertsStateMaxIncidents {
		log.Printf("site-alerts: invalid state file ignored")
		return out
	}
	for name, rec := range doc.Incidents {
		if name == "" || len(name) > 253 || rec == nil || !validIncident(*rec) || strings.IndexFunc(name, func(r rune) bool { return r < 32 }) >= 0 {
			log.Printf("site-alerts: invalid state file ignored")
			return map[string]*incident{}
		}
		out[name] = rec
	}
	return out
}

func (sa *SiteAlerts) persist() error {
	path := siteAlertsStatePath
	if !filepath.IsAbs(path) {
		return fmt.Errorf("site alert state path must be absolute")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && !stateFileSafe(info) {
		return fmt.Errorf("invalid site alert state file")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	active := map[string]*incident{}
	for name, rec := range sa.incidents {
		if rec.active() {
			active[name] = rec
		}
	}
	raw, err := json.Marshal(map[string]any{"version": siteAlertsStateVersion, "incidents": active})
	if err != nil {
		return err
	}
	if len(raw)+1 > siteAlertsStateMaxBytes || len(active) > siteAlertsStateMaxIncidents {
		return fmt.Errorf("site alert state exceeds its size limit")
	}
	tmp, err := os.CreateTemp(dir, ".site-alerts.")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	return pyx.FsyncDir(dir)
}

func loadSites() ([]map[string]any, bool) {
	raw, err := readSiteAlertFile(siteAlertsWebsites, 16<<20, false)
	if err != nil {
		log.Printf("site-alerts: configuration is temporarily unavailable: %s", siteAlertsWebsites)
		return nil, false
	}
	var data map[string]any
	if err := yaml.Unmarshal(raw, &data); err != nil {
		log.Printf("site-alerts: cannot read %s: %v", siteAlertsWebsites, err)
		return nil, false
	}
	if data == nil {
		return []map[string]any{}, true
	}
	list, ok := data["sites"].([]any)
	if !ok {
		if data["sites"] == nil {
			return []map[string]any{}, true
		}
		log.Printf("site-alerts: configuration sites value is not a list")
		return nil, false
	}
	var out []map[string]any
	for _, s := range list {
		site, ok := s.(map[string]any)
		if ok && site["alert_enabled"] == true && site["paused"] != true {
			out = append(out, site)
		}
	}
	return out, true
}

func mailState() (string, string, bool) {
	raw, err := readSiteAlertFile(siteAlertsMailState, 1<<20, false)
	if err != nil {
		return "", "", false
	}
	var st map[string]any
	if json.Unmarshal(raw, &st) != nil || st["enabled"] != true {
		return "", "", false
	}
	sender := fmt.Sprint(nilToEmpty(st["from"]))
	recipient := fmt.Sprint(nilToEmpty(st["to"]))
	if !alertEmailRe.MatchString(sender) {
		return "", "", false
	}
	return sender, recipient, true
}

func sendMail(recipient, subject, body string) bool {
	sender, defaultTo, ok := mailState()
	if !ok {
		log.Printf("site-alerts: email delivery is disabled; alert not sent (%s)", subject)
		return false
	}
	if strings.ContainsAny(sender, "\r\n") {
		return false
	}
	to := defaultTo
	if alertEmailRe.MatchString(recipient) {
		to = recipient
	}
	if !alertEmailRe.MatchString(to) {
		log.Printf("site-alerts: no valid recipient; alert not sent")
		return false
	}
	oneLine := strings.NewReplacer("\r", " ", "\n", " ").Replace(subject)
	if len(oneLine) > 200 {
		oneLine = oneLine[:200]
	}
	clean := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\r", "\n"), "\n", "\r\n")
	message := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n", sender, to, oneLine, clean)
	_ = os.MkdirAll(filepath.Dir(siteAlertsMailLock), 0o750)
	lock, err := os.OpenFile(siteAlertsMailLock, os.O_CREATE|os.O_RDWR|os.O_APPEND|syscall.O_NOFOLLOW, 0o640)
	if err != nil {
		return false
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_SH); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/docker", "exec", "-i", "mail_relay", "/usr/sbin/sendmail", "-i", "-f", sender, "--", to)
	cmd.Stdin = strings.NewReader(message)
	if err := cmd.Run(); err != nil {
		log.Printf("site-alerts: mail delivery failed: %v", err)
		return false
	}
	return true
}

// Run evaluates every interval until ctx ends.
func (sa *SiteAlerts) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(siteAlertsInterval * float64(time.Second)))
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sa.cycle(ctx)
		}
	}
}

func (sa *SiteAlerts) cycle(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("site-alerts: evaluation cycle failed: %v", r)
		}
	}()
	defer func() {
		if sa.stateDirty {
			if err := sa.persist(); err != nil {
				log.Printf("site-alerts: cannot persist incident state: %v", err)
			} else {
				sa.stateDirty = false
			}
		}
	}()
	sites, ok := loadSites()
	if !ok {
		return
	}
	if len(sites) == 0 {
		if len(sa.incidents) > 0 {
			sa.incidents = map[string]*incident{}
			sa.stateDirty = true
		}
		return
	}
	rows, err := haproxy.NewClient(siteAlertsSocket).ShowStat(ctx)
	if err != nil {
		log.Printf("site-alerts: cannot read HAProxy statistics: %v", err)
		return
	}
	if len(rows) == 0 {
		return
	}
	seen := map[string]bool{}
	changed := false
	for _, site := range sites {
		name := fmt.Sprint(nilToEmpty(site["name"]))
		if name == "" {
			name = fmt.Sprint(nilToEmpty(site["domain"]))
		}
		if name == "" {
			continue
		}
		seen[name] = true
		cond := siteConditionFor(siteIDRe.ReplaceAllString(name, "_"), rows)
		if cond == nil {
			continue
		}
		if sa.evaluate(ctx, site, name, cond, float64(time.Now().UnixNano())/1e9) {
			changed = true
		}
	}
	for name := range sa.incidents {
		if !seen[name] {
			delete(sa.incidents, name)
			changed = true
		}
	}
	sa.stateDirty = sa.stateDirty || changed
}

func f64(v float64) *float64 { return &v }

func (sa *SiteAlerts) evaluate(ctx context.Context, site map[string]any, name string, c *siteCondition, now float64) bool {
	mode := fmt.Sprint(nilToEmpty(site["alert_mode"]))
	if mode == "" {
		mode = "down"
	}
	triggered := c.State == "down" || (mode != "down" && c.State == "degraded")
	recipient := fmt.Sprint(nilToEmpty(site["alert_email"]))
	threshold := alertAfterSeconds(site["alert_after"])
	if sa.alerts != nil {
		detail := fmt.Sprintf("Backend servers up: %d/%d", c.Up, c.Total)
		if block := formatServers(c.Servers); block != "" {
			detail += "\n" + block
		}
		severity := "warning"
		if c.State == "down" {
			severity = "critical"
		}
		rcpt := ""
		if alertEmailRe.MatchString(recipient) {
			rcpt = recipient
		}
		sa.alerts.Observe(ctx, alerts.Observation{
			Rule: "site.down", Subject: name, Active: alerts.BoolPtr(triggered), Severity: severity,
			Summary: fmt.Sprintf("Site %s is %s", name, c.State), Detail: detail,
			TriggerDelay: alerts.IntPtr(int(threshold)), Recipient: rcpt,
		})
		return false
	}
	rec, ok := sa.incidents[name]
	if !ok {
		rec = &incident{}
		sa.incidents[name] = rec
	}
	before := *rec
	summary := fmt.Sprintf("Backend servers up: %d/%d\n", c.Up, c.Total)
	if block := formatServers(c.Servers); block != "" {
		summary += block + "\n"
	}
	if triggered {
		rec.GoodSince = nil
		if rec.BadSince == nil {
			rec.BadSince = f64(now)
		}
		elapsed := math.Max(0, now-*rec.BadSince)
		repeatDue := rec.AlertedAt != nil && now-*rec.AlertedAt >= siteAlertsRepeat
		escalated := rec.AlertedAt != nil && rec.AlertedState == "degraded" && c.State == "down"
		if elapsed >= threshold && (rec.AlertedAt == nil || repeatDue || escalated) {
			label := "PARTIALLY DOWN"
			if c.State == "down" {
				label = "DOWN"
			}
			if sa.send(recipient, fmt.Sprintf("[easy-ha-proxy] %s: %s", name, label),
				fmt.Sprintf("Site: %s\nState: %s for %s\n", name, strings.ToLower(label), formatDuration(elapsed))+summary) {
				log.Printf("site-alerts: alert sent for %s (%s)", name, c.State)
				rec.AlertedAt = f64(now)
				rec.AlertedState = c.State
			}
		}
	} else if rec.AlertedAt != nil {
		if rec.GoodSince == nil {
			rec.GoodSince = f64(now)
		}
		recovered := math.Max(0, now-*rec.GoodSince)
		if recovered >= threshold {
			if sa.send(recipient, fmt.Sprintf("[easy-ha-proxy] %s: RECOVERED", name),
				fmt.Sprintf("Site: %s\nState: available again for %s\n", name, formatDuration(recovered))+summary) {
				log.Printf("site-alerts: recovery notice sent for %s", name)
				*rec = incident{}
			} else {
				log.Printf("site-alerts: recovery notice not delivered for %s; keeping the incident open to retry", name)
			}
		}
	} else {
		rec.BadSince, rec.AlertedState, rec.GoodSince = nil, "", nil
	}
	return !sameIncident(before, *rec)
}

func sameIncident(a, b incident) bool {
	eq := func(x, y *float64) bool {
		if x == nil || y == nil {
			return x == nil && y == nil
		}
		return *x == *y
	}
	return eq(a.BadSince, b.BadSince) && eq(a.AlertedAt, b.AlertedAt) && eq(a.GoodSince, b.GoodSince) && a.AlertedState == b.AlertedState
}
