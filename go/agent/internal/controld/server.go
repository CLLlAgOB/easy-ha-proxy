package controld

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/alerts"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/pyx"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/unixrpc"
)

// NewDaemon builds the daemon state; alerts come from the environment.
func NewDaemon(opts Options) *Daemon {
	d := &Daemon{Opts: opts, logScans: make(chan struct{}, 2), logsCache: map[string]logsCacheEntry{}}
	if c := alerts.FromEnv(); c.Enabled() {
		d.alerts = c
	}
	d.failover = newUDPFailover(d)
	return d
}

// Run is main(): recover a pending transaction, start the loops, serve.
func Run(opts Options) error {
	d := NewDaemon(opts)
	log.Printf("Starting haproxy-controld: SOCKET_PATH=%s, BAN_TABLE=%s, IPSET_NAME=%s, INTERVAL=%ds, CONTROL_SOCKET=%s",
		opts.HAProxyAdminSocket, opts.BanTable, opts.IpsetName, opts.Interval, opts.ControlSocket)
	if err := d.recoverConfigTransaction(); err != nil {
		log.Printf("Could not recover the persisted HAProxy config transaction: %s", pyErr(err))
	}
	go d.udpFailoverLoop()
	go d.bansLoop()
	return d.controlSocketLoop()
}

// Serve accepts control socket clients until ctx is canceled and waits for
// in-flight operations to finish before returning.
func (d *Daemon) Serve(ctx context.Context, ln net.Listener) error {
	ln = unixrpc.PanelListener(ln)
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	var active sync.WaitGroup
	defer func() {
		stop()
		_ = ln.Close()
		active.Wait()
	}()
	slots := make(chan struct{}, 32)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		select {
		case slots <- struct{}{}:
		default:
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			_, _ = conn.Write([]byte("ERROR busy\n"))
			_ = conn.Close()
			continue
		}
		active.Add(1)
		go func(c net.Conn) {
			defer active.Done()
			defer func() { <-slots }()
			defer c.Close()
			d.handleClient(c)
		}(conn)
	}
}

func (d *Daemon) controlSocketLoop() error {
	path := d.Opts.ControlSocket
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "/run"
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	ln, err := unixrpc.ListenUnix(path, "", "", 0o660)
	if err != nil {
		log.Printf("Failed to bind/listen on %s: %v", path, err)
		return err
	}
	log.Printf("haproxy-controld is listening on %s", path)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	defer func() {
		if ctx.Err() != nil {
			log.Printf("Received shutdown signal; draining active operations")
		}
		_ = ln.Close()
		if _, err := os.Stat(path); err == nil {
			_ = os.Remove(path)
		}
	}()
	return d.Serve(ctx, ln)
}

type replier struct{ c net.Conn }

func (r replier) send(s string) {
	_ = r.c.SetWriteDeadline(time.Now().Add(30 * time.Second))
	_, _ = r.c.Write([]byte(s))
}

func (r replier) b64(ok bool, v any) {
	r.send(okPrefix(ok) + " " + b64JSON(v) + "\n")
}

var rebootBlockedPrefixes = []string{"certs-restore ", "write-config ", "apply-config ", "begin-config-transaction ",
	"geoip-update ", "geoip-configure ", "geoip-schedule "}

func errText(err error) string { return pyx.TruncRunes(pyErr(err), 4000) }

func pyIntErr(text string) error {
	return vErr("invalid literal for int() with base 10: %s", pyRepr(text))
}

func pySplitN(s, sep string, n int) []string { return strings.SplitN(s, sep, n+1) }

func (d *Daemon) handleClient(conn net.Conn) {
	r := replier{conn}
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("Error while handling client: %v", rec)
			r.send(fmt.Sprintf("ERROR exception: %v\n", rec))
		}
	}()
	var chunks bytes.Buffer
	buf := make([]byte, 4096)
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			if chunks.Len()+n > d.Opts.MaxCommandBytes {
				r.send("ERROR command is too large\n")
				return
			}
			chunks.Write(buf[:n])
			if bytes.IndexByte(buf[:n], '\n') >= 0 {
				break
			}
		}
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				log.Printf("Error while handling client: timed out")
				r.send("ERROR exception: timed out\n")
				return
			}
			break
		}
	}
	if chunks.Len() == 0 {
		return
	}
	line := chunks.Bytes()
	if i := bytes.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	cmd := pyStrip(decodeReplace(line))

	blocked := cmd == "reload" || cmd == "udp-apply" || cmd == "udp-apply-json"
	for _, p := range rebootBlockedPrefixes {
		if strings.HasPrefix(cmd, p) {
			blocked = true
		}
	}
	if blocked && (lexists(d.Opts.MaintenanceRebootMarker) || lexists(d.Opts.AssistantRebootMarker)) {
		r.send("ERROR a server reboot is scheduled\n")
		return
	}

	switch {
	case cmd == "reload":
		ok, msg := d.cmdReload()
		r.send(okPrefix(ok) + " " + msg + "\n")

	case cmd == "sync-bans":
		if err := d.syncBansOnce(); err != nil {
			r.send("ERROR sync-bans: " + pyErr(err) + "\n")
		} else {
			r.send("OK sync-bans done\n")
		}

	case cmd == "udp-apply" || cmd == "udp-apply-json":
		_, err := runCmd([]string{"systemctl", "restart", "iptables-haproxy-udp.service"}, nil, 60*time.Second)
		var state map[string]any
		if err == nil {
			state, err = d.readUDPForwardState()
		}
		if err != nil {
			log.Printf("udp-apply error: %s", pyErr(err))
			if cmd == "udp-apply-json" {
				r.send("ERROR " + compactB64(map[string]any{"ok": false, "error": "UDP forwarding apply failed: " + pyErr(err)}) + "\n")
			} else {
				r.send("ERROR udp-apply: " + pyErr(err) + "\n")
			}
			return
		}
		if cmd == "udp-apply-json" {
			out := map[string]any{"ok": true}
			for k, v := range state {
				out[k] = v
			}
			r.send("OK " + compactB64(out) + "\n")
		} else {
			r.send("OK udp-apply done\n")
		}

	case cmd == "udp-status":
		state, err := d.readUDPForwardState()
		if err != nil {
			r.send("ERROR " + compactB64(map[string]any{"ok": false, "error": errText(err)}) + "\n")
			return
		}
		out := map[string]any{"ok": true}
		for k, v := range state {
			out[k] = v
		}
		out["failover"] = d.failover.publicState()
		r.send("OK " + compactB64(out) + "\n")

	case strings.HasPrefix(cmd, "udp-port-check"):
		parts := pyFields(cmd)
		bad := func() { r.send("ERROR udp-port-check: invalid port range\n") }
		if len(parts) < 2 {
			bad()
			return
		}
		start, ok := pyIntBase10(parts[1])
		end := start
		if ok && len(parts) >= 3 {
			end, ok = pyIntBase10(parts[2])
		}
		if !ok || !(1 <= start && start <= end && end <= 65535) || end-start+1 > udpMaxPortRange {
			bad()
			return
		}
		busy := d.udpPortsInUse(int(start), int(end))
		if len(busy) > 0 {
			low := 65536
			for p := range busy {
				if p < low {
					low = p
				}
			}
			r.send(fmt.Sprintf("OK busy %d\n", low))
		} else {
			r.send(fmt.Sprintf("OK free %d-%d\n", start, end))
		}

	case cmd == "certs-backup":
		b64, err := d.certsBackupB64()
		if err != nil {
			log.Printf("certs-backup error: %s", pyErr(err))
			r.send("ERROR certs-backup: " + pyErr(err) + "\n")
			return
		}
		r.send("OK " + b64 + "\n")

	case strings.HasPrefix(cmd, "certs-restore "):
		msg, err := d.certsRestoreB64(pySplitN(cmd, " ", 1)[1])
		if err != nil {
			log.Printf("certs-restore error: %s", pyErr(err))
			r.send("ERROR certs-restore: " + pyErr(err) + "\n")
			return
		}
		r.send("OK " + msg + "\n")

	case strings.HasPrefix(cmd, "check-config "):
		rc, stdout, stderr, err := d.haproxyCheckConfigFromB64(pySplitN(cmd, " ", 1)[1])
		if err != nil {
			r.send("ERROR check-config: " + pyErr(err) + "\n")
			return
		}
		r.send(fmt.Sprintf("OK %d\n%s\n%s\n", rc, base64.StdEncoding.EncodeToString([]byte(stdout)),
			base64.StdEncoding.EncodeToString([]byte(stderr))))

	case strings.HasPrefix(cmd, "write-config "):
		if err := d.haproxyWriteConfigSerialized(pySplitN(cmd, " ", 1)[1]); err != nil {
			r.send("ERROR write-config: " + pyErr(err) + "\n")
			return
		}
		r.send("OK wrote haproxy.cfg\n")

	case strings.HasPrefix(cmd, "apply-config "):
		parts := pySplitN(cmd, " ", 2)
		var result map[string]any
		var err error
		if len(parts) != 3 {
			err = vErr("apply-config requires config and checks payloads")
		} else {
			result, err = d.haproxyApplyConfigGuarded(parts[1], parts[2])
		}
		if err != nil {
			r.b64(false, map[string]any{"ok": false, "applied": false, "rolled_back": false, "rollback_ok": nil,
				"failure": "guarded apply request failed: " + pyErr(err)})
			return
		}
		r.b64(pyx.Truthy(result["ok"]), result)

	case strings.HasPrefix(cmd, "begin-config-transaction "):
		parts := pySplitN(cmd, " ", 4)
		var result map[string]any
		var err error
		if len(parts) != 5 {
			err = vErr("begin-config-transaction requires config, checks, sources, and timeout payloads")
		} else {
			result, err = d.beginConfigTransaction(parts[1], parts[2], parts[3], parts[4])
		}
		if err != nil {
			r.b64(false, txError(err))
			return
		}
		r.b64(pyx.Truthy(result["pending"]), result)

	case cmd == "config-versions" || strings.HasPrefix(cmd, "config-versions "):
		parts := pyFields(cmd)
		var result map[string]any
		switch {
		case len(parts) > 2:
			result = map[string]any{"ok": false, "failure": "config-versions accepts one optional limit"}
		default:
			limit := int64(50)
			ok := true
			if len(parts) == 2 {
				limit, ok = pyIntBase10(parts[1])
			}
			if !ok {
				result = map[string]any{"ok": false, "failure": errText(pyIntErr(parts[1]))}
			} else {
				result = map[string]any{"ok": true, "versions": d.listConfigVersions(int(limit))}
			}
		}
		r.b64(pyx.Truthy(result["ok"]), result)

	case strings.HasPrefix(cmd, "config-version "):
		parts := pyFields(cmd)
		var result map[string]any
		if len(parts) != 2 {
			result = map[string]any{"ok": false, "failure": "config-version accepts exactly one id"}
		} else if v, err := d.getConfigVersion(parts[1]); err != nil {
			result = map[string]any{"ok": false, "failure": errText(err)}
		} else {
			result = map[string]any{"ok": true, "version": v}
		}
		r.b64(pyx.Truthy(result["ok"]), result)

	case cmd == "config-transaction-status" || strings.HasPrefix(cmd, "config-transaction-status "):
		parts := pyFields(cmd)
		if len(parts) > 2 {
			r.b64(false, txError(vErr("config-transaction-status accepts one optional id")))
			return
		}
		id := ""
		if len(parts) == 2 {
			id = parts[1]
		}
		result, err := d.configTransactionStatus(id)
		if err != nil {
			r.b64(false, txError(err))
			return
		}
		r.b64(true, result)

	case strings.HasPrefix(cmd, "confirm-config-transaction "):
		parts := pyFields(cmd)
		if len(parts) != 3 {
			r.b64(false, txError(vErr("confirm-config-transaction requires id and candidate hash")))
			return
		}
		result, err := d.confirmConfigTransaction(parts[1], parts[2])
		if err != nil {
			r.b64(false, txError(err))
			return
		}
		r.b64(pyx.Truthy(result["ok"]), result)

	case strings.HasPrefix(cmd, "rollback-config-transaction "):
		parts := pyFields(cmd)
		if len(parts) != 2 {
			r.b64(false, txError(vErr("rollback-config-transaction requires an id")))
			return
		}
		result, err := d.rollbackConfigTransaction(parts[1])
		if err != nil {
			r.b64(false, txError(err))
			return
		}
		r.b64(result["state"] == "rolled_back", result)

	case cmd == "geoip-status":
		result := d.geoipStatus()
		r.b64(pyx.Truthy(result["ok"]), result)

	case strings.HasPrefix(cmd, "geoip-update "):
		payload, err := decodeGeoIPPayload(pySplitN(cmd, " ", 1)[1], "force")
		var result map[string]any
		if err == nil {
			force, ok := payload["force"].(bool)
			if !ok {
				err = vErr("force must be boolean")
			} else {
				result, err = d.geoipUpdateNow(force)
			}
		}
		d.geoipReply(r, result, err)

	case strings.HasPrefix(cmd, "geoip-configure "):
		payload, err := decodeGeoIPPayload(pySplitN(cmd, " ", 1)[1], "countries", "revision")
		var result map[string]any
		if err == nil {
			result, err = d.geoipConfigure(payload["countries"], payload["revision"])
		}
		d.geoipReply(r, result, err)

	case strings.HasPrefix(cmd, "geoip-schedule "):
		payload, err := decodeGeoIPPayload(pySplitN(cmd, " ", 1)[1], "schedule")
		var result map[string]any
		if err == nil {
			result = d.geoipSetSchedule(payload["schedule"])
		}
		d.geoipReply(r, result, err)

	case strings.HasPrefix(cmd, "logs-ip "):
		parts := pyFields(pySplitN(cmd, " ", 1)[1])
		if len(parts) == 0 {
			r.send("ERROR logs-ip: missing ip\n")
			return
		}
		ip := pyStrip(parts[0])
		n := int64(d.Opts.LogLimit)
		if len(parts) >= 2 {
			v, ok := pyIntBase10(parts[1])
			if !ok {
				r.send("ERROR logs-ip: " + pyErr(pyIntErr(parts[1])) + "\n")
				return
			}
			n = v
		}
		if n > logsIPCacheMaxLimit {
			n = logsIPCacheMaxLimit
		}
		if n < 1 {
			n = 1
		}
		if _, err := pyIPAddress(ip); err != nil {
			r.send("ERROR logs-ip: " + err.Error() + "\n")
			return
		}
		lines, err := d.grepLastLogsForIP(ip, int(n))
		if err == nil {
			lines, err = d.sortLogLinesByTime(lines)
		}
		if err != nil {
			r.send("ERROR logs-ip: " + pyErr(err) + "\n")
			return
		}
		r.send("OK " + base64.StdEncoding.EncodeToString([]byte(strings.Join(lines, "\n"))) + "\n")

	case cmd == "logs-attackers":
		data, err := d.logsAttackers()
		if err != nil {
			r.send("ERROR logs-attackers: " + pyErr(err) + "\n")
			return
		}
		r.send("OK " + b64JSON(data) + "\n")

	case cmd == "ping":
		r.send("OK pong\n")

	default:
		r.send("ERROR unknown command\n")
	}
}

func txError(err error) map[string]any {
	return map[string]any{"ok": false, "state": "error", "pending": false, "failure": errText(err)}
}

func (d *Daemon) geoipReply(r replier, result map[string]any, err error) {
	if err != nil {
		r.b64(false, map[string]any{"ok": false, "error": errText(err)})
		return
	}
	r.b64(pyx.Truthy(result["ok"]), result)
}

// compactB64 is _send_control_json's payload (separators=(",", ":")).
func compactB64(v map[string]any) string { return b64JSON(v) }
