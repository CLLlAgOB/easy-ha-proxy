// Package haproxy provides a shared AF_UNIX client for the HAProxy Runtime API.
package haproxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const (
	DefaultSocketPath = "/run/haproxy/admin.sock"
	DefaultTimeout    = 5 * time.Second
	DefaultMaxBytes   = 8 * 1024 * 1024
)

// ErrAnswerTooLarge is returned when HAProxy's response exceeds the safety cap.
var ErrAnswerTooLarge = errors.New("haproxy runtime answer exceeds maximum byte limit")

// Client communicates with a HAProxy admin socket over AF_UNIX.
type Client struct {
	SocketPath string
	Timeout    time.Duration
	MaxBytes   int
}

// NewClient constructs a Client with safe defaults.
func NewClient(socketPath string) *Client {
	if strings.TrimSpace(socketPath) == "" {
		socketPath = DefaultSocketPath
	}
	return &Client{
		SocketPath: socketPath,
		Timeout:    DefaultTimeout,
		MaxBytes:   DefaultMaxBytes,
	}
}

// Command sends one line command to the HAProxy runtime socket and returns the full reply.
func (c *Client) Command(ctx context.Context, cmd string) (string, error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	maxBytes := c.MaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "unix", c.SocketPath)
	if err != nil {
		return "", fmt.Errorf("connect %s: %w", c.SocketPath, err)
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)

	if _, err := io.WriteString(conn, strings.TrimSpace(cmd)+"\n"); err != nil {
		return "", fmt.Errorf("write command: %w", err)
	}

	var buf bytes.Buffer
	limited := io.LimitReader(conn, int64(maxBytes)+1)
	n, err := io.Copy(&buf, limited)
	if err != nil {
		return "", fmt.Errorf("read reply: %w", err)
	}
	if n > int64(maxBytes) {
		return "", ErrAnswerTooLarge
	}
	return buf.String(), nil
}

// StatRow represents one parsed row from `show stat`.
type StatRow map[string]string

// ObjectKey identifies a HAProxy frontend, backend, or server object.
type ObjectKey struct {
	Kind   string // "frontend", "backend", "server"
	Proxy  string
	Server string
}

// ShowStat executes `show stat` and returns parsed rows.
func (c *Client) ShowStat(ctx context.Context) ([]StatRow, error) {
	raw, err := c.Command(ctx, "show stat")
	if err != nil {
		return nil, err
	}
	return ParseShowStat(raw), nil
}

// ShowInfo executes `show info` and returns key/value pairs.
func (c *Client) ShowInfo(ctx context.Context) (map[string]string, error) {
	raw, err := c.Command(ctx, "show info")
	if err != nil {
		return nil, err
	}
	return ParseShowInfo(raw), nil
}

// ParseShowStat parses HAProxy `show stat` CSV output matching Python `metricsd.runtime.parse_show_stat`.
func ParseShowStat(payload string) []StatRow {
	lines := strings.Split(payload, "\n")
	var header []string
	var rows []StatRow
	pxIdx := -1
	svIdx := -1

	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		if header == nil {
			if !strings.HasPrefix(line, "#") {
				return nil
			}
			trimmed := strings.TrimLeft(line, "# ")
			cols := strings.Split(trimmed, ",")
			for i := range cols {
				cols[i] = strings.TrimSpace(cols[i])
				if cols[i] == "pxname" {
					pxIdx = i
				} else if cols[i] == "svname" {
					svIdx = i
				}
			}
			if pxIdx < 0 || svIdx < 0 {
				return nil
			}
			header = cols
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		cells := strings.Split(line, ",")
		limit := len(header)
		if len(cells) < limit {
			limit = len(cells)
		}
		row := make(StatRow, limit)
		for i := 0; i < limit; i++ {
			row[header[i]] = cells[i]
		}
		if row["pxname"] != "" && row["svname"] != "" {
			rows = append(rows, row)
		}
	}
	return rows
}

// ParseShowInfo parses HAProxy `show info` lines (`Key: Value`).
func ParseShowInfo(payload string) map[string]string {
	out := make(map[string]string)
	for _, rawLine := range strings.Split(payload, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key := strings.TrimSpace(k)
		if key != "" {
			out[key] = strings.TrimSpace(v)
		}
	}
	return out
}

// Classify returns the ObjectKey for a stat row, or (zero, false) if invalid.
func Classify(row StatRow) (ObjectKey, bool) {
	proxy := strings.TrimSpace(row["pxname"])
	svname := strings.TrimSpace(row["svname"])
	if proxy == "" || svname == "" {
		return ObjectKey{}, false
	}
	switch svname {
	case "FRONTEND":
		return ObjectKey{Kind: "frontend", Proxy: proxy, Server: ""}, true
	case "BACKEND":
		return ObjectKey{Kind: "backend", Proxy: proxy, Server: ""}, true
	default:
		return ObjectKey{Kind: "server", Proxy: proxy, Server: svname}, true
	}
}
