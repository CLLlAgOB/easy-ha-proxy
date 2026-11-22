package controld

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var rebootBlockedExact = map[string]struct{}{
	"reload":         {},
	"udp-apply":      {},
	"udp-apply-json": {},
}

var rebootBlockedPrefixes = []string{
	"certs-restore ",
	"write-config ",
	"apply-config ",
	"begin-config-transaction ",
	"geoip-update ",
	"geoip-configure ",
	"geoip-schedule ",
}

func isBlockedByReboot(cmd string) bool {
	if _, ok := rebootBlockedExact[cmd]; ok {
		return true
	}
	for _, p := range rebootBlockedPrefixes {
		if strings.HasPrefix(cmd, p) {
			return true
		}
	}
	return false
}

// Server handles the line-based AF_UNIX control socket protocol for haproxy-controld.
type Server struct {
	Controller *Controller
	slots      chan struct{}
}

// NewServer constructs a Server with MaxClientSlots concurrent client capacity.
func NewServer(ctrl *Controller) *Server {
	return &Server{
		Controller: ctrl,
		slots:      make(chan struct{}, MaxClientSlots),
	}
}

func encodeControlJSON(ok bool, payload map[string]any) string {
	raw, _ := json.Marshal(payload)
	b64 := base64.StdEncoding.EncodeToString(raw)
	prefix := "ERROR"
	if ok {
		prefix = "OK"
	}
	return prefix + " " + b64 + "\n"
}

// HandleCommand processes one trimmed protocol line and returns the exact wire reply.
func (s *Server) HandleCommand(ctx context.Context, cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return ""
	}
	if s.Controller.RebootScheduled() && isBlockedByReboot(cmd) {
		return "ERROR a server reboot is scheduled\n"
	}

	switch {
	case cmd == "ping":
		return "OK pong\n"

	case cmd == "reload":
		ok, msg := s.Controller.Reload(ctx)
		if ok {
			return fmt.Sprintf("OK %s\n", msg)
		}
		return fmt.Sprintf("ERROR %s\n", msg)

	case cmd == "udp-status":
		st := s.Controller.UDPStatus()
		return encodeControlJSON(true, st)

	case strings.HasPrefix(cmd, "udp-port-check"):
		parts := strings.Fields(cmd)
		if len(parts) < 2 || len(parts) > 3 {
			return "ERROR udp-port-check: invalid port range\n"
		}
		start, err1 := strconv.Atoi(parts[1])
		end := start
		var err2 error
		if len(parts) == 3 {
			end, err2 = strconv.Atoi(parts[2])
		}
		if err1 != nil || err2 != nil || start < 1 || end < start || end > 65535 || end-start+1 > UDPMaxPortRange {
			return "ERROR udp-port-check: invalid port range\n"
		}
		busy := s.Controller.UDPPortsInUse(start, end)
		if len(busy) > 0 {
			return fmt.Sprintf("OK busy %d\n", busy[0])
		}
		return fmt.Sprintf("OK free %d-%d\n", start, end)

	case strings.HasPrefix(cmd, "check-config "):
		cfgB64 := strings.TrimPrefix(cmd, "check-config ")
		rc, stdout, stderr, err := s.Controller.CheckConfig(ctx, cfgB64)
		if err != nil {
			return fmt.Sprintf("ERROR check-config: %v\n", err)
		}
		outB64 := base64.StdEncoding.EncodeToString([]byte(stdout))
		errB64 := base64.StdEncoding.EncodeToString([]byte(stderr))
		return fmt.Sprintf("OK %d\n%s\n%s\n", rc, outB64, errB64)

	case strings.HasPrefix(cmd, "write-config "):
		cfgB64 := strings.TrimPrefix(cmd, "write-config ")
		if err := s.Controller.WriteConfig(ctx, cfgB64); err != nil {
			return fmt.Sprintf("ERROR write-config: %v\n", err)
		}
		return "OK wrote haproxy.cfg\n"

	case cmd == "config-versions" || strings.HasPrefix(cmd, "config-versions "):
		parts := strings.Fields(cmd)
		if len(parts) > 2 {
			return encodeControlJSON(false, map[string]any{"ok": false, "failure": "config-versions accepts one optional limit"})
		}
		limit := 50
		if len(parts) == 2 {
			n, err := strconv.Atoi(parts[1])
			if err != nil {
				return encodeControlJSON(false, map[string]any{"ok": false, "failure": "invalid limit"})
			}
			limit = n
		}
		versions, err := s.Controller.ListConfigVersions(limit)
		if err != nil {
			return encodeControlJSON(false, map[string]any{"ok": false, "failure": err.Error()})
		}
		return encodeControlJSON(true, map[string]any{"ok": true, "versions": versions})

	case strings.HasPrefix(cmd, "config-version "):
		parts := strings.Fields(cmd)
		if len(parts) != 2 {
			return encodeControlJSON(false, map[string]any{"ok": false, "failure": "config-version accepts exactly one id"})
		}
		ver, err := s.Controller.GetConfigVersion(parts[1])
		if err != nil {
			return encodeControlJSON(false, map[string]any{"ok": false, "failure": err.Error()})
		}
		return encodeControlJSON(true, map[string]any{"ok": true, "version": ver})

	case cmd == "geoip-status":
		st := s.Controller.GeoIPStatus()
		ok, _ := st["ok"].(bool)
		return encodeControlJSON(ok, st)

	case strings.HasPrefix(cmd, "logs-ip "):
		rest := strings.TrimSpace(strings.TrimPrefix(cmd, "logs-ip "))
		parts := strings.Fields(rest)
		if len(parts) == 0 {
			return "ERROR logs-ip: missing ip\n"
		}
		ip := parts[0]
		if _, err := netip.ParseAddr(ip); err != nil {
			return fmt.Sprintf("ERROR logs-ip: invalid ip: %v\n", err)
		}
		n := s.Controller.Opts.LogLimit
		if len(parts) >= 2 {
			parsed, err := strconv.Atoi(parts[1])
			if err != nil {
				return fmt.Sprintf("ERROR logs-ip: invalid limit: %v\n", err)
			}
			n = parsed
		}
		if n < 1 {
			n = 1
		}
		if n > 200 {
			n = 200
		}
		lines, err := s.Controller.LogsForIP(ip, n)
		if err != nil {
			return fmt.Sprintf("ERROR logs-ip: %v\n", err)
		}
		b64 := base64.StdEncoding.EncodeToString([]byte(strings.Join(lines, "\n")))
		return fmt.Sprintf("OK %s\n", b64)

	default:
		return "ERROR unknown command\n"
	}
}

// ServeConn reads one newline-delimited command from conn and writes the reply.
func (s *Server) ServeConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	lr := io.LimitReader(conn, MaxCommandBytes+1)
	reader := bufio.NewReaderSize(lr, 8192)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		_, _ = io.WriteString(conn, fmt.Sprintf("ERROR read failed: %v\n", err))
		return
	}
	if len(line) > MaxCommandBytes {
		_, _ = io.WriteString(conn, "ERROR command is too large\n")
		return
	}
	if strings.TrimSpace(line) == "" {
		return
	}
	reply := s.HandleCommand(ctx, line)
	if reply != "" {
		_, _ = io.WriteString(conn, reply)
	}
}

// Serve accepts connections on ln until ctx is canceled.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
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
		select {
		case s.slots <- struct{}{}:
			go func(c net.Conn) {
				defer func() { <-s.slots }()
				s.ServeConn(ctx, c)
			}(conn)
		default:
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			_, _ = io.WriteString(conn, "ERROR busy\n")
			_ = conn.Close()
		}
	}
}

// Run binds the controld AF_UNIX socket and serves until SIGTERM/SIGINT.
func Run(opts Options) error {
	if err := os.MkdirAll(filepath.Dir(opts.ControlSocket), 0o755); err != nil {
		return err
	}
	_ = os.Remove(opts.ControlSocket)
	ln, err := net.Listen("unix", opts.ControlSocket)
	if err != nil {
		return err
	}
	_ = os.Chmod(opts.ControlSocket, 0o660)
	defer os.Remove(opts.ControlSocket)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	srv := NewServer(NewController(opts))
	log.Printf("haproxy-controld (Go) listening on %s cfg=%s", opts.ControlSocket, opts.HAProxyCfgPath)
	return srv.Serve(ctx, ln)
}
