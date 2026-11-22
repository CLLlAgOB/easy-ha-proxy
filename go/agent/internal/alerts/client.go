// Package alerts implements the best-effort AF_UNIX client for easy-ha-proxy-alertd.
package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	DefaultSocketPath = "/run/easy-ha-proxy/easy-ha-proxy-alertd.sock"
	DefaultTimeout    = 3 * time.Second
)

// Event represents one alert condition sent to easy-ha-proxy-alertd.
type Event struct {
	Rule     string         `json:"rule"`
	Subject  string         `json:"subject"`
	State    string         `json:"state,omitempty"`
	Severity string         `json:"severity,omitempty"`
	Summary  string         `json:"summary,omitempty"`
	Details  map[string]any `json:"details,omitempty"`
}

// Client delivers alerts over the local alertd Unix socket.
// When Token is empty, Report is a no-op so daemons never fail without alertd.
type Client struct {
	SocketPath string
	Token      string
	httpClient *http.Client
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

// Report sends one alert event to alertd; returns true only on HTTP 2xx.
func (c *Client) Report(ctx context.Context, ev Event) bool {
	if !c.Enabled() {
		return false
	}
	body, err := json.Marshal(ev)
	if err != nil {
		return false
	}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		"http://unix/api/v1/alerts/report",
		bytes.NewReader(body),
	)
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Alert-Token", c.Token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}
