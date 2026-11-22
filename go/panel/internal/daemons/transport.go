// Package daemons implements the AF_UNIX transports used by the web panel to
// reach host daemons: HTTP-over-Unix (healthd, metricsd, alertd, guardd, certd),
// bounded JSON-line RPC (backupd, updated, authelia-usersd, authelia-bansd,
// authelia-configd), and plain line protocol (controld, HAProxy admin.sock).
package daemons

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"easy-ha-proxy/panel/internal/config"
)

const (
	DefaultMaxJSONLineRequest  = 1 * 1024 * 1024
	DefaultMaxJSONLineResponse = 4 * 1024 * 1024
	DefaultMaxHTTPResponse     = 8 * 1024 * 1024
)

// UnavailableError indicates a host daemon socket could not be reached or
// returned an unexpected protocol/5xx response.
type UnavailableError struct {
	Service string
	Err     error
}

func (e *UnavailableError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("the %s service is unavailable", e.Service)
	}
	return fmt.Sprintf("the %s service is unavailable: %v", e.Service, e.Err)
}

func (e *UnavailableError) Unwrap() error { return e.Err }

// RejectedError indicates the daemon answered with an explicit 4xx rejection
// carrying an operator-actionable reason.
type RejectedError struct {
	Status int
	Reason string
	Body   map[string]any
}

func (e *RejectedError) Error() string {
	if e.Reason != "" {
		return e.Reason
	}
	return fmt.Sprintf("rejected (HTTP %d)", e.Status)
}

// UnixHTTPClient talks JSON-over-HTTP to one AF_UNIX daemon socket.
type UnixHTTPClient struct {
	Service     string
	SocketPath  string
	TokenHeader string
	Token       string
	httpClient  *http.Client
}

// NewUnixHTTPClient constructs a pooled HTTP client over an AF_UNIX socket.
func NewUnixHTTPClient(service, socketPath, tokenHeader, token string) *UnixHTTPClient {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			if strings.TrimSpace(socketPath) == "" {
				return nil, fmt.Errorf("%s socket is not configured", service)
			}
			return dialer.DialContext(ctx, "unix", socketPath)
		},
		MaxIdleConns:        16,
		MaxIdleConnsPerHost: 16,
		IdleConnTimeout:     30 * time.Second,
	}
	return &UnixHTTPClient{
		Service:     service,
		SocketPath:  strings.TrimSpace(socketPath),
		TokenHeader: tokenHeader,
		Token:       strings.TrimSpace(token),
		httpClient:  &http.Client{Transport: tr},
	}
}

// RequestOptions tunes one HTTP-over-Unix call.
type RequestOptions struct {
	Query           url.Values
	Timeout         time.Duration
	WithToken       bool
	CheckStatus     bool
	RejectedStatus  int
	AcceptedStatuses []int
}

// GetJSON executes GET on path and returns the decoded JSON object and HTTP status.
func (c *UnixHTTPClient) GetJSON(ctx context.Context, path string, opts RequestOptions) (map[string]any, int, error) {
	return c.doJSON(ctx, http.MethodGet, path, nil, opts)
}

// PostJSON executes POST on path with body encoded as JSON.
func (c *UnixHTTPClient) PostJSON(ctx context.Context, path string, body any, opts RequestOptions) (map[string]any, int, error) {
	return c.doJSON(ctx, http.MethodPost, path, body, opts)
}

func (c *UnixHTTPClient) doJSON(ctx context.Context, method, path string, body any, opts RequestOptions) (map[string]any, int, error) {
	if c.SocketPath == "" {
		return nil, 0, &UnavailableError{Service: c.Service, Err: errors.New("socket not configured")}
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	target := "http://unix" + path
	if len(opts.Query) > 0 {
		target += "?" + opts.Query.Encode()
	}

	var bodyReader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("encode %s request: %w", c.Service, err)
		}
		bodyReader = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(reqCtx, method, target, bodyReader)
	if err != nil {
		return nil, 0, &UnavailableError{Service: c.Service, Err: err}
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if opts.WithToken && c.TokenHeader != "" && c.Token != "" {
		req.Header.Set(c.TokenHeader, c.Token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, &UnavailableError{Service: c.Service, Err: err}
	}
	defer resp.Body.Close()

	rawResp, err := io.ReadAll(io.LimitReader(resp.Body, DefaultMaxHTTPResponse+1))
	if err != nil {
		return nil, resp.StatusCode, &UnavailableError{Service: c.Service, Err: err}
	}
	if len(rawResp) > DefaultMaxHTTPResponse {
		return nil, resp.StatusCode, &UnavailableError{Service: c.Service, Err: errors.New("response too large")}
	}

	var parsed map[string]any
	if len(bytes.TrimSpace(rawResp)) > 0 {
		if err := json.Unmarshal(rawResp, &parsed); err != nil {
			if opts.CheckStatus && resp.StatusCode >= 400 {
				return nil, resp.StatusCode, &UnavailableError{
					Service: c.Service,
					Err:     fmt.Errorf("HTTP %d", resp.StatusCode),
				}
			}
			return nil, resp.StatusCode, &UnavailableError{
				Service: c.Service,
				Err:     fmt.Errorf("non-JSON response (HTTP %d)", resp.StatusCode),
			}
		}
	}

	if opts.RejectedStatus != 0 && resp.StatusCode == opts.RejectedStatus {
		reason := "rejected"
		if parsed != nil {
			if s, ok := parsed["error"].(string); ok && s != "" {
				reason = s
			}
		}
		return parsed, resp.StatusCode, &RejectedError{
			Status: resp.StatusCode,
			Reason: reason,
			Body:   parsed,
		}
	}

	if opts.CheckStatus && resp.StatusCode >= 400 && !containsInt(opts.AcceptedStatuses, resp.StatusCode) {
		return parsed, resp.StatusCode, &UnavailableError{
			Service: c.Service,
			Err:     fmt.Errorf("HTTP %d", resp.StatusCode),
		}
	}
	if parsed == nil {
		parsed = map[string]any{}
	}
	return parsed, resp.StatusCode, nil
}

func containsInt(list []int, target int) bool {
	for _, v := range list {
		if v == target {
			return true
		}
	}
	return false
}

// JSONLineClient talks bounded single-line JSON RPC over an AF_UNIX socket.
type JSONLineClient struct {
	Service     string
	SocketPath  string
	MaxRequest  int
	MaxResponse int
}

// Call sends one compact JSON line and reads one JSON object line back.
// Never includes the request payload in returned errors because payloads may
// carry passphrases or credentials.
func (c *JSONLineClient) Call(ctx context.Context, payload map[string]any, timeout time.Duration) (map[string]any, error) {
	if strings.TrimSpace(c.SocketPath) == "" {
		return nil, &UnavailableError{Service: c.Service, Err: errors.New("socket is not configured")}
	}
	maxReq := c.MaxRequest
	if maxReq <= 0 {
		maxReq = DefaultMaxJSONLineRequest
	}
	maxResp := c.MaxResponse
	if maxResp <= 0 {
		maxResp = DefaultMaxJSONLineResponse
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("the %s request cannot be encoded", c.Service)
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maxReq {
		return nil, fmt.Errorf("the %s request is too large", c.Service)
	}

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "unix", c.SocketPath)
	if err != nil {
		return nil, &UnavailableError{Service: c.Service, Err: err}
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write(encoded); err != nil {
		return nil, &UnavailableError{Service: c.Service, Err: err}
	}

	reader := bufio.NewReaderSize(io.LimitReader(conn, int64(maxResp)+1), 64*1024)
	line, err := reader.ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, &UnavailableError{Service: c.Service, Err: err}
	}
	if len(line) > maxResp {
		return nil, fmt.Errorf("the %s service response is too large", c.Service)
	}
	trimmed := bytes.TrimSpace(line)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("the %s service returned an empty response", c.Service)
	}
	var result map[string]any
	if err := json.Unmarshal(trimmed, &result); err != nil {
		return nil, fmt.Errorf("the %s service returned invalid JSON", c.Service)
	}
	if result == nil {
		return nil, fmt.Errorf("the %s service returned an invalid response", c.Service)
	}
	return result, nil
}

// LineCommand sends a single command line over an AF_UNIX socket (such as
// HAProxy admin.sock or haproxy-controld) and reads the full reply until EOF.
func LineCommand(ctx context.Context, socketPath, command string, timeout time.Duration, maxBytes int) (string, error) {
	if strings.TrimSpace(socketPath) == "" {
		return "", errors.New("socket path is not configured")
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if maxBytes <= 0 {
		maxBytes = 4 * 1024 * 1024
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	if !strings.HasSuffix(command, "\n") {
		command += "\n"
	}
	if _, err := conn.Write([]byte(command)); err != nil {
		return "", err
	}
	if uc, ok := conn.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}
	raw, err := io.ReadAll(io.LimitReader(conn, int64(maxBytes)))
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// Pool groups all host daemon clients configured for the web panel.
type Pool struct {
	Healthd       *UnixHTTPClient
	Metricsd      *UnixHTTPClient
	Alertd        *UnixHTTPClient
	Guardd        *UnixHTTPClient
	Certd         *UnixHTTPClient
	Backupd       *JSONLineClient
	Updated       *JSONLineClient
	AutheliaUsers *JSONLineClient
	AutheliaBans  *JSONLineClient
	AutheliaCfg   *JSONLineClient
	ControldPath  string
	HAProxySocket string
}

// NewPool creates a Pool from runtime Config.
func NewPool(cfg *config.Config) *Pool {
	return &Pool{
		Healthd:  NewUnixHTTPClient("healthd", cfg.HealthdSocket, "X-Healthd-Token", cfg.HealthdToken),
		Metricsd: NewUnixHTTPClient("metricsd", cfg.MetricsdSocket, "", ""),
		Alertd:   NewUnixHTTPClient("alertd", cfg.AlertdSocket, "X-Alertd-Token", cfg.AlertdToken),
		Guardd:   NewUnixHTTPClient("guardd", cfg.GuarddSocket, "X-Guardd-Token", cfg.GuarddToken),
		Certd:    NewUnixHTTPClient("certd", cfg.CertdSocket, "", ""),
		Backupd: &JSONLineClient{
			Service:    "full-backup",
			SocketPath: cfg.BackupdSocket,
		},
		Updated: &JSONLineClient{
			Service:    "update",
			SocketPath: cfg.UpdatedSocket,
		},
		AutheliaUsers: &JSONLineClient{
			Service:    "authelia-users",
			SocketPath: cfg.AutheliaUsersSocket,
		},
		AutheliaBans: &JSONLineClient{
			Service:    "authelia-bans",
			SocketPath: cfg.AutheliaBansSocket,
		},
		AutheliaCfg: &JSONLineClient{
			Service:    "authelia-config",
			SocketPath: cfg.AutheliaCfgSocket,
		},
		ControldPath:  cfg.ControldSocket,
		HAProxySocket: cfg.HAProxySocket,
	}
}
