// Package authelia implements the native Go Authelia host daemons
// (authelia-bansd, authelia-usersd, authelia-configd) inside easy-ha-proxy-agent.
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
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var usernameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._@-]{0,127}$`)

// BansdOptions configures the authelia-bansd daemon from AUTHELIA_BANS_* env vars.
type BansdOptions struct {
	SocketPath      string
	ScriptPath      string
	CommandTimeout  time.Duration
	MaxRequestBytes int
	MaxWorkers      int
	SocketGroup     string
}

// BansdOptionsFromEnv reads options matching authelia-bansd.py.
func BansdOptionsFromEnv() BansdOptions {
	envOr := func(k, fb string) string {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
		return fb
	}
	envInt := func(k string, def, minV, maxV int) int {
		v := def
		if raw := strings.TrimSpace(os.Getenv(k)); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil {
				v = n
			}
		}
		if v < minV {
			v = minV
		}
		if v > maxV {
			v = maxV
		}
		return v
	}
	return BansdOptions{
		SocketPath:      envOr("AUTHELIA_BANS_SOCKET", "/run/authelia-bansd.sock"),
		ScriptPath:      envOr("AUTHELIA_BANS_SCRIPT", "/usr/local/sbin/authelia-bans.sh"),
		CommandTimeout:  time.Duration(envInt("AUTHELIA_BANS_COMMAND_TIMEOUT", 5, 1, 60)) * time.Second,
		MaxRequestBytes: envInt("AUTHELIA_BANS_MAX_REQUEST_BYTES", 65536, 1024, 1048576),
		MaxWorkers:      envInt("AUTHELIA_BANS_MAX_WORKERS", 4, 1, 16),
		SocketGroup:     envDefault("AUTHELIA_BANS_SOCKET_GROUP", "haproxy-admin"),
	}
}

// BansdServer serves authelia-bansd JSON-line requests over AF_UNIX.
type BansdServer struct {
	Opts  BansdOptions
	slots chan struct{}
}

// NewBansdServer constructs a BansdServer.
func NewBansdServer(opts BansdOptions) *BansdServer {
	if opts.MaxWorkers <= 0 {
		opts.MaxWorkers = 4
	}
	if opts.CommandTimeout <= 0 {
		opts.CommandTimeout = 5 * time.Second
	}
	if opts.MaxRequestBytes <= 0 {
		opts.MaxRequestBytes = 65536
	}
	return &BansdServer{
		Opts:  opts,
		slots: make(chan struct{}, opts.MaxWorkers),
	}
}

func (s *BansdServer) runScript(ctx context.Context, args ...string) (int, string, string) {
	cmdCtx, cancel := context.WithTimeout(ctx, s.Opts.CommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, s.Opts.ScriptPath, args...)
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if errors.Is(cmdCtx.Err(), context.DeadlineExceeded) {
		detail := strings.Join(strings.Fields(errBuf.String()), " ")
		msg := fmt.Sprintf("command timed out after %ds", int(s.Opts.CommandTimeout.Seconds()))
		if detail != "" {
			msg += ": " + detail
		}
		return 124, out.String(), msg
	}
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode(), out.String(), errBuf.String()
		}
		return 1, "", fmt.Sprintf("exception: %v", err)
	}
	return 0, out.String(), errBuf.String()
}

// HandleRequest dispatches ping, list, revoke-user, and revoke-ip.
func (s *BansdServer) HandleRequest(ctx context.Context, req map[string]any) map[string]any {
	action := "None"
	if v, ok := req["action"]; ok {
		action = pyStr(jsonToPy(v))
	}
	if action == "ping" {
		return map[string]any{"ok": true, "pong": true}
	}
	if _, err := os.Stat(s.Opts.ScriptPath); err != nil {
		return map[string]any{"ok": false, "error": fmt.Sprintf("script %s not found", s.Opts.ScriptPath)}
	}

	switch action {
	case "list":
		var rcU, rcI int
		var outU, errU, outI, errI string
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			rcU, outU, errU = s.runScript(ctx, "list-users")
		}()
		go func() {
			defer wg.Done()
			rcI, outI, errI = s.runScript(ctx, "list-ips")
		}()
		wg.Wait()
		if rcU != 0 || rcI != 0 {
			return map[string]any{
				"ok":           false,
				"error":        "list failed",
				"rc_users":     rcU,
				"rc_ips":       rcI,
				"stderr_users": errU,
				"stderr_ips":   errI,
				"stdout_users": outU,
				"stdout_ips":   outI,
			}
		}
		return map[string]any{"ok": true, "users": outU, "ips": outI}

	case "revoke-user":
		user := pyStrip(pyStrOr(jsonToPy(req["username"])))
		if user == "" {
			return map[string]any{"ok": false, "error": "username is required"}
		}
		if !usernameRe.MatchString(user) {
			return map[string]any{"ok": false, "error": "invalid username"}
		}
		rc, out, errOut := s.runScript(ctx, "revoke-user", user)
		if rc != 0 {
			msg := errOut
			if msg == "" {
				msg = out
			}
			if msg == "" {
				msg = fmt.Sprintf("rc=%d", rc)
			}
			return map[string]any{"ok": false, "error": msg}
		}
		return map[string]any{"ok": true, "message": out}

	case "revoke-ip":
		ip := pyStrip(pyStrOr(jsonToPy(req["ip"])))
		if ip == "" {
			return map[string]any{"ok": false, "error": "ip is required"}
		}
		if !validIPNetwork(ip) {
			return map[string]any{"ok": false, "error": "invalid IP/CIDR"}
		}
		rc, out, errOut := s.runScript(ctx, "revoke-ip", ip)
		if rc != 0 {
			msg := errOut
			if msg == "" {
				msg = out
			}
			if msg == "" {
				msg = fmt.Sprintf("rc=%d", rc)
			}
			return map[string]any{"ok": false, "error": msg}
		}
		return map[string]any{"ok": true, "message": out}

	default:
		return map[string]any{"ok": false, "error": fmt.Sprintf("unknown action %s", action)}
	}
}

// Serve accepts connections on ln until ctx is canceled.
func (s *BansdServer) Serve(ctx context.Context, ln net.Listener) error {
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	defer func() { _ = ln.Close() }()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case s.slots <- struct{}{}:
		case <-ctx.Done():
			_ = conn.Close()
			return nil
		}
		go func(c net.Conn) {
			defer func() { <-s.slots }()
			serveJSONLineConn(ctx, c, s.Opts.MaxRequestBytes, func(ctx context.Context, req map[string]any) map[string]any {
				return s.HandleRequest(ctx, req)
			})
		}(conn)
	}
}

// RunBansd binds the authelia-bansd AF_UNIX socket and serves until SIGTERM/SIGINT.
func RunBansd(opts BansdOptions) error {
	if err := os.MkdirAll(filepath.Dir(opts.SocketPath), 0o750); err != nil {
		return err
	}
	_ = os.Remove(opts.SocketPath)
	ln, err := net.Listen("unix", opts.SocketPath)
	if err != nil {
		return err
	}
	setBansSocketPerms(opts.SocketPath, opts.SocketGroup)
	defer os.Remove(opts.SocketPath)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	log.Printf("authelia-bansd (Go) listening on %s", opts.SocketPath)
	return NewBansdServer(opts).Serve(ctx, ln)
}

func serveJSONLineConn(ctx context.Context, conn net.Conn, maxBytes int, fn func(context.Context, map[string]any) map[string]any) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))

	lr := io.LimitReader(conn, int64(maxBytes)+1)
	line, err := bufio.NewReaderSize(lr, 4096).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		writeLineJSON(conn, map[string]any{"ok": false, "error": fmt.Sprintf("read error: %v", err)})
		return
	}
	if len(line) > maxBytes {
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
	writeLineJSON(conn, fn(ctx, req))
}

func writeLineJSON(conn net.Conn, payload map[string]any) {
	_ = conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	raw, err := json.Marshal(payload)
	if err != nil {
		raw = []byte(`{"ok":false,"error":"marshal error"}`)
	}
	raw = append(raw, '\n')
	_, _ = conn.Write(raw)
}

// setBansSocketPerms is set_socket_perms: root:<group>, mode 0660.
func setBansSocketPerms(path, group string) {
	gid := os.Getgid()
	if g, err := user.LookupGroup(group); err == nil {
		if n, err := strconv.Atoi(g.Gid); err == nil {
			gid = n
		}
	} else {
		log.Printf("group %s not found, leaving socket group as root", group)
	}
	_ = os.Chown(path, 0, gid)
	_ = os.Chmod(path, 0o660)
}

// jsonToPy turns encoding/json values into the shapes pyStr understands.
func jsonToPy(v any) any {
	if f, ok := v.(float64); ok && f == float64(int64(f)) && !strings.ContainsAny(fmt.Sprint(f), "e") {
		return int64(f)
	}
	return v
}

// validIPNetwork is ipaddress.ip_network(text, strict=False) succeeding.
func validIPNetwork(text string) bool {
	if strings.Count(text, "/") > 1 {
		return false
	}
	addrText, mask, hasMask := strings.Cut(text, "/")
	addr, err := netip.ParseAddr(addrText)
	if err != nil || addr.Zone() != "" {
		return false
	}
	if !hasMask {
		return true
	}
	if n, err := strconv.Atoi(mask); err == nil && strings.Trim(mask, "0123456789") == "" && mask != "" {
		return n >= 0 && n <= addr.BitLen()
	}
	if !addr.Is4() {
		return false
	}
	m, err := netip.ParseAddr(mask)
	if err != nil || !m.Is4() {
		return false
	}
	b := m.As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	for n := 0; n <= 32; n++ {
		full := uint32(0)
		if n > 0 {
			full = ^uint32(0) << (32 - n)
		}
		if v == full || v == ^full {
			return true
		}
	}
	return false
}
