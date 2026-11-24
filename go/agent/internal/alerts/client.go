// Package alerts implements the best-effort AF_UNIX client for easy-ha-proxy-alertd.
package alerts

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	DefaultSocketPath = "/run/easy-ha-proxy/easy-ha-proxy-alertd.sock"
	DefaultTimeout    = 3 * time.Second
	TokenHeader       = "X-Alertd-Token"
	resendUnchanged   = 2 * time.Minute
	maxRecentAlerts   = 2000
	maxAlertResponse  = 64 * 1024
)

// Observation matches the POST /api/v1/alerts/notify contract of easy-ha-proxy-alertd.
type Observation struct {
	Rule         string `json:"rule"`
	Subject      string `json:"subject,omitempty"`
	Active       *bool  `json:"active,omitempty"`
	Severity     string `json:"severity,omitempty"`
	Summary      string `json:"summary,omitempty"`
	Detail       string `json:"detail,omitempty"`
	TriggerDelay *int   `json:"trigger_delay,omitempty"`
	Recipient    string `json:"recipient,omitempty"`
	Retired      bool   `json:"retired,omitempty"`
}

// BoolPtr returns a pointer to v for level observations.
func BoolPtr(v bool) *bool { return &v }

// IntPtr returns a pointer to v for optional trigger_delay overrides.
func IntPtr(v int) *int { return &v }

// Client delivers observations over the local alertd Unix socket.
// When Token is empty, Observe is a no-op so daemons never fail without alertd.
type Client struct {
	SocketPath string
	Token      string
	httpClient *http.Client
	mu         sync.Mutex
	recent     map[[2]string]acceptedObservation
}

type acceptedObservation struct {
	hash [sha256.Size]byte
	at   time.Time
}

// FromEnv constructs a Client from ALERTD_SOCKET_PATH and ALERTD_TOKEN.
func FromEnv() *Client {
	sock := strings.TrimSpace(os.Getenv("ALERTD_SOCKET_PATH"))
	if sock == "" {
		sock = DefaultSocketPath
	}
	return NewClient(sock, strings.TrimSpace(os.Getenv("ALERTD_TOKEN")))
}

// NewClient constructs a Client bound to the given AF_UNIX socket path.
func NewClient(socketPath, token string) *Client {
	if strings.TrimSpace(socketPath) == "" {
		socketPath = DefaultSocketPath
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		},
	}
	return &Client{
		SocketPath: socketPath,
		Token:      strings.TrimSpace(token),
		recent:     make(map[[2]string]acceptedObservation),
		httpClient: &http.Client{
			Transport: tr,
			Timeout:   DefaultTimeout,
		},
	}
}

// Enabled reports whether alert delivery is configured with a token.
func (c *Client) Enabled() bool {
	return c != nil && c.Token != ""
}

// Observe sends one observation to POST /api/v1/alerts/notify; returns true on HTTP 2xx.
func (c *Client) Observe(ctx context.Context, obs Observation) bool {
	if !c.Enabled() {
		return false
	}
	body, err := json.Marshal(obs)
	if err != nil {
		return false
	}
	key := [2]string{obs.Rule, obs.Subject}
	hash := sha256.Sum256(body)
	started := time.Now()
	c.mu.Lock()
	previous, ok := c.recent[key]
	c.mu.Unlock()
	if ok && previous.hash == hash && started.Sub(previous.at) < resendUnchanged {
		return true
	}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		"http://unix/api/v1/alerts/notify",
		bytes.NewReader(body),
	)
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(TokenHeader, c.Token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxAlertResponse))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if previous, exists := c.recent[key]; !exists || started.After(previous.at) {
		if len(c.recent) >= maxRecentAlerts && !exists {
			clear(c.recent)
		}
		c.recent[key] = acceptedObservation{hash: hash, at: started}
	}
	return true
}
