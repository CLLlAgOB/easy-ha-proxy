package authelia

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/unixrpc"
)

// ConfigdOptions configures authelia-configd from AUTHELIA_CONFIG_* environment variables.
type ConfigdOptions struct {
	SocketPath        string
	ConfigFile        string
	MailStatePath     string
	NotificationFile  string
	AutheliaRootDir   string
	AutheliaContainer string
	DockerBin         string
	MaxRequestBytes   int
	AllowedNotifUID   int
}

// ConfigdOptionsFromEnv reads options matching authelia-configd.py.
func ConfigdOptionsFromEnv() ConfigdOptions {
	envOr := func(k, fb string) string {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
		return fb
	}
	rootDir := envOr("AUTHELIA_ROOT_DIR", "/opt/authelia")
	return ConfigdOptions{
		SocketPath:        envOr("AUTHELIA_CONFIG_SOCKET", "/run/easy-ha-proxy/authelia-configd.sock"),
		ConfigFile:        envOr("AUTHELIA_CONFIG_FILE", filepath.Join(rootDir, "configuration.yml")),
		MailStatePath:     envOr("AUTHELIA_MAIL_STATE", "/etc/easy-ha-proxy/mail-notify.json"),
		NotificationFile:  envOr("AUTHELIA_NOTIFICATION_FILE", filepath.Join(rootDir, "notification.txt")),
		AutheliaRootDir:   rootDir,
		AutheliaContainer: envOr("AUTHELIA_CONTAINER_NAME", "authelia"),
		DockerBin:         envOr("DOCKER_BIN", "/usr/bin/docker"),
		MaxRequestBytes:   256 * 1024,
		AllowedNotifUID:   0, // root-only by default for notification_reveal / notification_handle
	}
}

// ConfigdServer serves authelia-configd JSON-line actions with SO_PEERCRED checks.
type ConfigdServer struct {
	mu   sync.Mutex
	Opts ConfigdOptions
}

// NewConfigdServer constructs a ConfigdServer.
func NewConfigdServer(opts ConfigdOptions) *ConfigdServer {
	if opts.MaxRequestBytes <= 0 {
		opts.MaxRequestBytes = 256 * 1024
	}
	return &ConfigdServer{Opts: opts}
}

// HandleRequest dispatches authelia-configd actions enforcing peer UID rules.
func (s *ConfigdServer) HandleRequest(ctx context.Context, req map[string]any, peerUID int) map[string]any {
	action := strings.TrimSpace(asStr(req["action"]))
	if (action == "notification_reveal" || action == "notification_handle") && peerUID != s.Opts.AllowedNotifUID {
		return map[string]any{
			"ok":        false,
			"forbidden": true,
			"error":     "the local notification action is not available to this client",
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	switch action {
	case "config_view":
		raw, err := os.ReadFile(s.Opts.ConfigFile)
		if err != nil {
			return map[string]any{"ok": false, "error": err.Error()}
		}
		return map[string]any{"ok": true, "config": string(raw)}

	case "mail_view":
		st := map[string]any{"enabled": false, "from": "", "to": ""}
		if raw, err := os.ReadFile(s.Opts.MailStatePath); err == nil {
			var parsed map[string]any
			if json.Unmarshal(raw, &parsed) == nil {
				for k, v := range parsed {
					if strings.Contains(strings.ToLower(k), "pass") || strings.Contains(strings.ToLower(k), "secret") {
						if str, _ := v.(string); str != "" {
							st[k] = "***"
						}
						continue
					}
					st[k] = v
				}
			}
		}
		return map[string]any{"ok": true, "mail": st}

	case "notification_latest":
		raw, err := os.ReadFile(s.Opts.NotificationFile)
		if err != nil {
			if os.IsNotExist(err) {
				return map[string]any{"ok": true, "available": false}
			}
			return map[string]any{"ok": false, "error": err.Error()}
		}
		trimmed := strings.TrimSpace(string(raw))
		return map[string]any{"ok": true, "available": trimmed != "", "bytes": len(raw)}

	case "notification_reveal":
		raw, err := os.ReadFile(s.Opts.NotificationFile)
		if err != nil {
			return map[string]any{"ok": false, "error": err.Error()}
		}
		return map[string]any{"ok": true, "content": string(raw)}

	case "notification_handle":
		if err := os.WriteFile(s.Opts.NotificationFile, []byte{}, 0o600); err != nil && !os.IsNotExist(err) {
			return map[string]any{"ok": false, "error": err.Error()}
		}
		return map[string]any{"ok": true, "handled": true}

	case "restart":
		cmdCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		var out bytes.Buffer
		cmd := exec.CommandContext(cmdCtx, s.Opts.DockerBin, "restart", s.Opts.AutheliaContainer)
		cmd.Stdout = &out
		cmd.Stderr = &out
		if err := cmd.Run(); err != nil {
			return map[string]any{"ok": false, "error": fmt.Sprintf("restart failed: %s", strings.TrimSpace(out.String()))}
		}
		return map[string]any{"ok": true, "restarted": true}

	default:
		return map[string]any{"ok": false, "error": fmt.Sprintf("unknown action: %q", action)}
	}
}

// Serve accepts connections on ln until ctx is canceled.
func (s *ConfigdServer) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		s.serveConn(ctx, conn)
	}
}

func (s *ConfigdServer) serveConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	peerUID, err := unixrpc.PeerUID(conn)
	if err != nil {
		peerUID = -1
	}
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	lr := io.LimitReader(conn, int64(s.Opts.MaxRequestBytes)+1)
	line, err := bufio.NewReaderSize(lr, 4096).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		writeLineJSON(conn, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if len(line) > s.Opts.MaxRequestBytes {
		writeLineJSON(conn, map[string]any{"ok": false, "error": "request is too large"})
		return
	}
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return
	}
	var req map[string]any
	if err := json.Unmarshal([]byte(trimmed), &req); err != nil || req == nil {
		writeLineJSON(conn, map[string]any{"ok": false, "error": "invalid json"})
		return
	}
	writeLineJSON(conn, s.HandleRequest(ctx, req, peerUID))
}

// RunConfigd starts authelia-configd until SIGTERM/SIGINT.
func RunConfigd(opts ConfigdOptions) error {
	if err := os.MkdirAll(filepath.Dir(opts.SocketPath), 0o750); err != nil {
		return err
	}
	_ = os.Remove(opts.SocketPath)
	ln, err := net.Listen("unix", opts.SocketPath)
	if err != nil {
		return err
	}
	_ = os.Chmod(opts.SocketPath, 0o660)
	defer os.Remove(opts.SocketPath)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	log.Printf("authelia-configd (Go) listening on %s", opts.SocketPath)
	return NewConfigdServer(opts).Serve(ctx, ln)
}
