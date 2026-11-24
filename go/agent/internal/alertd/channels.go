package alertd

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Channel delivers alert notifications; implementations never panic and return (ok, errMsg).
type Channel interface {
	Name() string
	Available(cfg Config) bool
	Send(ctx context.Context, cfg Config, subject, body string) (bool, string)
}

// WebhookTarget is a validated and DNS-pinned HTTPS webhook destination.
type WebhookTarget struct {
	Hostname string
	Address  string
	Port     int
	RawURL   string
}

// LookupIPFunc abstracts DNS resolution for deterministic unit tests.
type LookupIPFunc func(ctx context.Context, host string) ([]netip.Addr, error)

func defaultLookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{addr}, nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	return ips, nil
}

var reservedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("255.255.255.255/32"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("fec0::/10"),
}

func isReservedAddr(addr netip.Addr) bool {
	for _, p := range reservedPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// ResolveWebhookTarget validates an HTTPS webhook URL and pins it to a single vetted IP address.
func ResolveWebhookTarget(ctx context.Context, rawURL string, allowPrivate bool, lookup LookupIPFunc) (WebhookTarget, error) {
	if lookup == nil {
		lookup = defaultLookupIP
	}
	trimmed := strings.TrimSpace(rawURL)
	if hasAnyControlChar(trimmed) || strings.ContainsAny(trimmed, " \t\r\n") {
		return WebhookTarget{}, errors.New("the webhook URL contains invalid characters")
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return WebhookTarget{}, errors.New("the webhook URL is invalid")
	}
	if u.Scheme != "https" {
		return WebhookTarget{}, errors.New("the webhook URL must use https")
	}
	hostname := u.Hostname()
	if hostname == "" {
		return WebhookTarget{}, errors.New("the webhook URL has no host")
	}
	if u.User != nil {
		return WebhookTarget{}, errors.New("put the secret in the header, not in the URL")
	}
	port := 443
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return WebhookTarget{}, errors.New("the webhook port is out of range")
		}
		port = n
	}

	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	if hasAnyControlChar(path) || strings.ContainsAny(path, " \t\r\n") {
		return WebhookTarget{}, errors.New("the webhook path contains invalid characters")
	}

	addrs, err := lookup(ctx, hostname)
	if err != nil {
		return WebhookTarget{}, fmt.Errorf("the webhook host does not resolve: %v", err)
	}
	for _, raw := range addrs {
		addr := raw.Unmap()
		if !addr.IsValid() {
			continue
		}
		if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsInterfaceLocalMulticast() {
			return WebhookTarget{}, errors.New("the webhook host resolves to a loopback or link-local address")
		}
		if addr.IsUnspecified() || isReservedAddr(addr) {
			return WebhookTarget{}, errors.New("the webhook host resolves to a reserved address")
		}
		if addr.IsPrivate() && !allowPrivate {
			return WebhookTarget{}, errors.New("the webhook host resolves to a private address; enable 'allow private destinations' if that is intended")
		}
		return WebhookTarget{
			Hostname: hostname,
			Address:  addr.String(),
			Port:     port,
			RawURL:   trimmed,
		}, nil
	}
	return WebhookTarget{}, errors.New("the webhook host did not resolve to a usable address")
}

// WebhookChannel posts JSON notifications to a DNS-pinned HTTPS URL without following redirects.
type WebhookChannel struct {
	Lookup LookupIPFunc
}

func (w *WebhookChannel) Name() string { return "webhook" }

func (w *WebhookChannel) Available(cfg Config) bool { return cfg.WebhookURL != "" }

func (w *WebhookChannel) Send(ctx context.Context, cfg Config, subject, body string) (bool, string) {
	return w.Post(ctx, cfg, map[string]any{"subject": subject, "body": body})
}

func (w *WebhookChannel) Post(ctx context.Context, cfg Config, payload map[string]any) (bool, string) {
	reqCtx, cancel := context.WithTimeout(ctx, WebhookTimeoutSec*time.Second)
	defer cancel()
	target, err := ResolveWebhookTarget(reqCtx, cfg.WebhookURL, cfg.WebhookAllowPrivate, w.Lookup)
	if err != nil {
		return false, err.Error()
	}
	doc, err := json.Marshal(payload)
	if err != nil {
		return false, err.Error()
	}

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, target.RawURL, bytes.NewReader(doc))
	if err != nil {
		return false, err.Error()
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("User-Agent", WebhookUserAgent)
	if cfg.WebhookHeaderName != "" && cfg.WebhookHeaderValue != "" {
		if !headerNameRe.MatchString(cfg.WebhookHeaderName) || hasAnyControlChar(cfg.WebhookHeaderValue) {
			return false, "webhook header contains invalid characters"
		}
		req.Header.Set(cfg.WebhookHeaderName, cfg.WebhookHeaderValue)
	}

	pinnedAddr := net.JoinHostPort(target.Address, strconv.Itoa(target.Port))
	tr := &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{
			ServerName: target.Hostname,
			MinVersion: tls.VersionTLS12,
		},
		DialContext: func(dctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(dctx, "tcp", pinnedAddr)
		},
	}
	defer tr.CloseIdleConnections()

	client := &http.Client{
		Transport: tr,
		Timeout:   WebhookTimeoutSec * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Sprintf("the webhook could not be reached: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, WebhookMaxRespBytes))

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return true, ""
	}
	return false, fmt.Sprintf("the webhook answered %s", resp.Status)
}

// EmailChannel delivers plain-text notifications through the mail_relay container.
type EmailChannel struct {
	MailStatePath      string
	MailLockPath       string
	MailRelayContainer string
	DockerBin          string
}

type mailStateFile struct {
	Enabled bool   `json:"enabled"`
	From    string `json:"from"`
	To      string `json:"to"`
}

func (e *EmailChannel) readState() (*mailStateFile, bool) {
	data, err := os.ReadFile(e.MailStatePath)
	if err != nil {
		return nil, false
	}
	var st mailStateFile
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, false
	}
	if !st.Enabled || !emailRe.MatchString(st.From) {
		return nil, false
	}
	return &st, true
}

func (e *EmailChannel) Name() string { return "email" }

func (e *EmailChannel) Available(cfg Config) bool {
	if !cfg.EmailEnabled {
		return false
	}
	_, ok := e.readState()
	return ok
}

func (e *EmailChannel) Send(ctx context.Context, cfg Config, subject, body string) (bool, string) {
	st, ok := e.readState()
	if !ok {
		return false, "email delivery is disabled"
	}
	sender := st.From
	recipient := cfg.Recipient
	if recipient == "" {
		recipient = st.To
	}
	if !emailRe.MatchString(recipient) {
		return false, "no valid recipient configured"
	}

	oneLine := strings.ReplaceAll(strings.ReplaceAll(subject, "\r", " "), "\n", " ")
	if len(oneLine) > 200 {
		oneLine = oneLine[:200]
	}
	normBody := strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\n", "\r\n")
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n",
		sender, recipient, oneLine, normBody)

	if e.MailLockPath != "" {
		_ = os.MkdirAll(filepath.Dir(e.MailLockPath), 0o750)
		lf, err := os.OpenFile(e.MailLockPath, os.O_CREATE|os.O_RDWR, 0o640)
		if err != nil {
			return false, fmt.Sprintf("mail delivery failed: %v", err)
		}
		defer lf.Close()
		if err := lockFileShared(lf); err != nil {
			return false, fmt.Sprintf("mail delivery failed: %v", err)
		}
		defer unlockFile(lf)
	}

	cmdCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(
		cmdCtx, e.DockerBin, "exec", "-i", e.MailRelayContainer,
		"/usr/sbin/sendmail", "-i", "-f", sender, "--", recipient,
	)
	cmd.Stdin = strings.NewReader(msg)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			return false, fmt.Sprintf("mail delivery failed: %v", err)
		}
		out := fmt.Sprintf("mail_relay failed: %s", detail)
		if len(out) > MaxTextChars {
			out = out[:MaxTextChars]
		}
		return false, out
	}
	return true, ""
}

// StuckMail describes one message stuck in Postfix's deferred or hold queue.
type StuckMail struct {
	Arrival int64
	Reason  string
}

// ParseMailQueueStuck parses `postqueue -j` JSONL output and returns messages older than MailStuckSeconds.
func ParseMailQueueStuck(output string, now int64) []StuckMail {
	var stuck []StuckMail
	sc := bufio.NewScanner(strings.NewReader(output))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var item struct {
			QueueName   string `json:"queue_name"`
			ArrivalTime int64  `json:"arrival_time"`
			Recipients  []struct {
				DelayReason string `json:"delay_reason"`
			} `json:"recipients"`
		}
		if err := json.Unmarshal([]byte(line), &item); err != nil {
			continue
		}
		if item.QueueName != "deferred" && item.QueueName != "hold" {
			continue
		}
		if item.ArrivalTime <= 0 || now-item.ArrivalTime < MailStuckSeconds {
			continue
		}
		reason := ""
		for _, r := range item.Recipients {
			if r.DelayReason != "" {
				reason = cleanText(r.DelayReason, 300)
				break
			}
		}
		stuck = append(stuck, StuckMail{Arrival: item.ArrivalTime, Reason: reason})
	}
	return stuck
}
