package app

// Port of utils.py: shared constants and helpers.

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"easy-ha-proxy/panel/shared/pyyaml"
)

func envStrip(name, def string) string {
	v, ok := os.LookupEnv(name)
	if !ok {
		v = def
	}
	return strings.TrimSpace(v)
}

func envInt(name string, def int) int {
	if v, ok := os.LookupEnv(name); ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
	}
	return def
}

var (
	// SOCKET is the HAProxy runtime API socket.
	SOCKET              = envStrip("SOCKET_PATH", "/run/haproxy/admin.sock")
	WhitelistFile       = envStrip("WHITELIST_GEO_FILE", "/etc/haproxy/geoip/whitelist.geo")
	WhitelistGlobalFile = envStrip("WHITELIST_GLOBAL_FILE", "/etc/haproxy/whitelist.ip")
	LogFile             = envStrip("LOG_FILE", "/var/log/haproxy.log")
	BanTable            = func() string {
		if v, ok := os.LookupEnv("HAPADM_BAN_TABLE"); ok {
			return v
		}
		return "tbl_ban"
	}()
	LogLimit      = envInt("HAPADM_LOG_LIMIT", 30)
	ControlSocket = envStrip("HAPROXY_CONTROL_SOCKET", "/run/easy-ha-proxy/haproxy-controld.sock")
)

const runCmdTimeout = 30 * time.Second

// RunCmd is run_cmd: run a command without a shell; errors come back as text.
func RunCmd(args []string) string {
	if len(args) == 0 {
		return "Command error: empty command"
	}
	ctx, cancel := context.WithTimeout(context.Background(), runCmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return "Command timed out"
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return fmt.Sprintf("Command failed (%d): %s", ee.ExitCode(), strings.TrimSpace(errb.String()))
		}
		return "Command error: " + pyOSError(err)
	}
	return out.String()
}

// HAProxyRuntimeCommand is haproxy_runtime_command.
func HAProxyRuntimeCommand(command, socketPath string, timeout time.Duration) (string, error) {
	if strings.ContainsAny(command, "\n\r\x00") {
		return "", &ValueError{"invalid HAProxy runtime command"}
	}
	conn, err := net.DialTimeout("unix", socketPath, timeout)
	if err != nil {
		return "", &OSError{pyOSError(err)}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(command + "\n")); err != nil {
		return "", &OSError{pyOSError(err)}
	}
	if uc, ok := conn.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}
	var buf bytes.Buffer
	chunk := make([]byte, 65536)
	for {
		n, err := conn.Read(chunk)
		buf.Write(chunk[:n])
		if buf.Len() > 16*1024*1024 {
			return "", &ValueError{"HAProxy runtime response is too large"}
		}
		if err != nil {
			break
		}
	}
	return strings.ToValidUTF8(buf.String(), "�"), nil
}

// ValueError and OSError mirror the Python exception classes callers catch.
type ValueError struct{ Msg string }

func (e *ValueError) Error() string { return e.Msg }

type OSError struct{ Msg string }

func (e *OSError) Error() string { return e.Msg }

var tableMetaRe = regexp.MustCompile(`table:\s+(\w+).*type:\s+(\w+).*size:(\d+).*used:(\d+)`)

// ParseTableOutput is parse_table_output.
func ParseTableOutput(output string) *pyyaml.Map {
	lines := pySplitlines(output)
	if len(lines) == 0 {
		return nil
	}
	meta := pyyaml.NewMap()
	if m := tableMetaRe.FindStringSubmatch(lines[0]); m != nil {
		size, _ := strconv.ParseInt(m[3], 10, 64)
		used, _ := strconv.ParseInt(m[4], 10, 64)
		meta.Set("name", m[1])
		meta.Set("type", m[2])
		meta.Set("size", size)
		meta.Set("used", used)
	}
	var rows [][]string
	for _, ln := range lines[1:] {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		parts := strings.Fields(ln)
		data := pyyaml.NewMap()
		for _, p := range parts[1:] {
			if k, v, ok := strings.Cut(p, "="); ok {
				data.Set(k, v)
			}
		}
		ip, _ := data.Value("key").(string)
		expRaw := "0"
		if v, ok := data.Get("exp"); ok {
			expRaw = v.(string)
		}
		expSec := expRaw
		if n, err := strconv.ParseInt(strings.TrimSpace(expRaw), 10, 64); err == nil {
			expSec = strconv.FormatInt(int64(float64(n)/1000), 10)
		}
		if g, ok := data.Get("gpc0"); ok {
			blocked := false
			if n, err := strconv.ParseInt(strings.TrimSpace(g.(string)), 10, 64); err == nil {
				blocked = n > 0
			}
			code, _ := data.Value("gpt0").(string)
			status := "Not blocked"
			if blocked {
				status = "Blocked"
			}
			rows = append(rows, []string{ip, status, code, expSec})
			continue
		}
		for _, k := range data.Keys() {
			if strings.Contains(k.(string), "http_err_rate") {
				rows = append(rows, []string{ip, data.Value(k).(string), expSec})
				break
			}
		}
	}
	name, _ := meta.Value("name").(string)
	if strings.HasPrefix(name, "tbl_err") {
		key := func(r []string) int64 {
			if isDigits(r[1]) {
				n, _ := strconv.ParseInt(r[1], 10, 64)
				return n
			}
			return 0
		}
		sort.SliceStable(rows, func(i, j int) bool { return key(rows[i]) > key(rows[j]) })
		if len(rows) > 10 {
			rows = rows[:10]
		}
	}
	var headers []any
	switch {
	case strings.HasPrefix(name, "tbl_ban"):
		headers = []any{"IP Address", "Status", "Reason", "Expires"}
	case strings.HasPrefix(name, "tbl_err"):
		headers = []any{"IP Address", "Error Count", "Expires"}
	default:
		headers = []any{"IP Address", "Value", "Expires"}
	}
	rowList := make([]any, len(rows))
	for i, r := range rows {
		cells := make([]any, len(r))
		for j, c := range r {
			cells[j] = c
		}
		rowList[i] = cells
	}
	out := pyyaml.NewMap()
	out.Set("headers", headers)
	out.Set("rows", rowList)
	out.Set("meta", meta)
	return out
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// pySplitlines is str.splitlines() for the line breaks that occur in text.
func pySplitlines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	if s == "" {
		return nil
	}
	lines := strings.Split(s, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

var timeRx = regexp.MustCompile(`^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$`)

func ageToSec(txt string) int64 {
	m := timeRx.FindStringSubmatch(txt)
	if m == nil {
		return 0
	}
	var total int64
	for i, mult := range []int64{3600, 60, 1} {
		if m[i+1] != "" {
			n, _ := strconv.ParseInt(m[i+1], 10, 64)
			total += n * mult
		}
	}
	return total
}

// ParseSessions is parse_sessions.
func ParseSessions(output string) []any {
	now := float64(time.Now().UnixNano()) / 1e9
	var conns []*pyyaml.Map
	for _, raw := range pySplitlines(output) {
		raw = strings.TrimSpace(raw)
		parts := strings.Fields(raw)
		if len(parts) == 0 {
			continue
		}
		c := pyyaml.NewMap()
		c.Set("id", strings.TrimRight(parts[0], ":"))
		c.Set("src_ip", nil)
		c.Set("src_port", nil)
		c.Set("fe", nil)
		c.Set("be", nil)
		c.Set("srv", nil)
		c.Set("duration", int64(0))
		c.Set("age_raw", nil)
		for _, p := range parts[1:] {
			k, v, ok := strings.Cut(p, "=")
			if !ok {
				continue
			}
			switch {
			case k == "src":
				if i := strings.LastIndex(v, ":"); i >= 0 {
					c.Set("src_ip", v[:i])
					c.Set("src_port", v[i+1:])
				} else {
					c.Set("src_ip", v)
					c.Set("src_port", nil)
				}
			case k == "fe" || k == "be" || k == "srv":
				c.Set(k, v)
			case k == "age_ms" && isDigits(v):
				n, _ := strconv.ParseInt(v, 10, 64)
				c.Set("duration", n/1000)
				c.Set("age_raw", v)
			case k == "age":
				c.Set("age_raw", v)
				if isDigits(v) {
					n, _ := strconv.ParseInt(v, 10, 64)
					c.Set("duration", n)
				} else {
					c.Set("duration", ageToSec(v))
				}
			case k == "ctime" && isDigits(v):
				n, _ := strconv.ParseInt(v, 10, 64)
				c.Set("duration", int64(now-float64(n)))
			}
		}
		if s, _ := c.Value("src_ip").(string); s != "" {
			conns = append(conns, c)
		}
	}
	sort.SliceStable(conns, func(i, j int) bool {
		return conns[i].Value("duration").(int64) > conns[j].Value("duration").(int64)
	})
	out := make([]any, len(conns))
	for i, c := range conns {
		out[i] = c
	}
	return out
}

// ControldRequest is _controld_request: one command line, the raw answer.
func ControldRequest(cmd string, timeout time.Duration) string {
	if ControlSocket == "" {
		return "ERROR control socket is empty"
	}
	conn, err := net.DialTimeout("unix", ControlSocket, timeout)
	if err != nil {
		return "ERROR controld request failed: " + pyOSError(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(strings.TrimSpace(cmd) + "\n")); err != nil {
		return "ERROR controld request failed: " + pyOSError(err)
	}
	raw, err := io.ReadAll(conn)
	if err != nil {
		return "ERROR controld request failed: " + pyOSError(err)
	}
	return strings.Trim(strings.ToValidUTF8(string(raw), "�"), "\n")
}

// ReloadHAProxy is reload_haproxy.
func ReloadHAProxy() string {
	const masterSock = "/run/haproxy/master.sock"
	var attempts []string
	if ControlSocket != "" {
		if _, err := os.Stat(ControlSocket); err == nil {
			resp := strings.TrimSpace(ControldRequest("reload", 15*time.Second))
			if strings.HasPrefix(resp, "OK") {
				detail := strings.TrimSpace(resp[2:])
				if detail == "" {
					detail = "ok"
				}
				return "controld reload ok: " + detail
			}
			msg := resp
			if msg == "" {
				msg = "empty response"
			}
			attempts = append(attempts, "controld reload failed: "+msg)
			log.Printf("reload_haproxy via controld failed: %s", msg)
		}
	}
	if _, err := os.Stat(masterSock); err == nil {
		out, err := HAProxyRuntimeCommand("reload", masterSock, 5*time.Second)
		if err == nil {
			out = strings.TrimSpace(out)
			if out != "" && strings.Contains(out, "Error") {
				return "master reload error: " + out
			}
			return "master reload ok"
		}
		attempts = append(attempts, "master reload failed: "+err.Error())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "systemctl", "reload", "haproxy").CombinedOutput(); err == nil {
		_ = out
		return "systemctl reload ok"
	} else {
		attempts = append(attempts, "systemctl reload failed: "+pySubprocessError(err, []string{"systemctl", "reload", "haproxy"}))
	}
	if len(attempts) > 0 {
		return strings.Join(attempts, "; ")
	}
	return "reload skipped"
}

func pySubprocessError(err error, args []string) string {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return fmt.Sprintf("Command '%s' returned non-zero exit status %d.", pyListRepr(args), ee.ExitCode())
	}
	var pe *exec.Error
	if errors.As(err, &pe) {
		return fmt.Sprintf("[Errno 2] No such file or directory: '%s'", args[0])
	}
	return pyOSError(err)
}

func pyListRepr(args []string) string {
	parts := make([]string, len(args))
	for i, a := range args {
		parts[i] = "'" + a + "'"
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// ReadLogFile is read_log_file.
func ReadLogFile() (string, string, int) {
	raw, err := os.ReadFile(LogFile)
	if err != nil {
		return "Error reading logs: " + pyFileError(err, LogFile), "error", 0
	}
	text := strings.ToValidUTF8(string(raw), "�")
	return text, "file", len(pySplitlines(text))
}

// pyFileError is str(OSError) for a failed open: "[Errno 2] No such file or directory: '/x'".
func pyFileError(err error, path string) string {
	return pyOSError(err) + ": '" + path + "'"
}

// GrepLastLogsForIP is grep_last_logs_for_ip.
func GrepLastLogsForIP(ip string, limit int) []string {
	if _, err := netip.ParseAddr(ip); err != nil || strings.Contains(ip, "%") {
		return []string{"[ERROR] invalid ip: " + ip}
	}
	resp := ControldRequest(fmt.Sprintf("logs-ip %s %d", ip, limit), 10*time.Second)
	if resp == "" {
		return []string{"[ERROR] empty response from controld"}
	}
	if strings.HasPrefix(resp, "ERROR") {
		return []string{resp}
	}
	if !strings.HasPrefix(resp, "OK") {
		return []string{"[ERROR] unexpected response: " + truncRunes(resp, 200)}
	}
	_, payload, found := strings.Cut(resp, " ")
	if !found {
		return []string{}
	}
	payload = strings.TrimSpace(payload)
	if payload == "" {
		return []string{}
	}
	raw, err := pyB64Decode(payload)
	if err != nil {
		return []string{"[ERROR] cannot decode logs payload: " + err.Error()}
	}
	var out []string
	for _, ln := range pySplitlines(strings.ToValidUTF8(string(raw), "�")) {
		if strings.TrimSpace(ln) != "" {
			out = append(out, ln)
		}
	}
	return out
}

// pyB64Decode is base64.b64decode(validate=False): non-alphabet bytes are dropped.
func pyB64Decode(s string) ([]byte, error) {
	var b strings.Builder
	for _, c := range s {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' {
			b.WriteRune(c)
		}
	}
	clean := strings.TrimRight(b.String(), "=")
	raw, err := base64.RawStdEncoding.DecodeString(clean)
	if err != nil {
		return nil, errors.New("Incorrect padding")
	}
	return raw, nil
}

func truncRunes(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

// ControldGetAttackers is controld_get_attackers.
func ControldGetAttackers(timeout time.Duration) *pyyaml.Map {
	diag := func() *pyyaml.Map {
		d := pyyaml.NewMap()
		d.Set("source", "controld")
		return d
	}
	fail := func(msg string) *pyyaml.Map {
		m := pyyaml.NewMap()
		m.Set("error", msg)
		m.Set("diagnostic", diag())
		return m
	}
	resp := ControldRequest("logs-attackers", timeout)
	if resp == "" {
		return fail("empty response from controld")
	}
	if strings.HasPrefix(resp, "ERROR") {
		return fail(resp)
	}
	if !strings.HasPrefix(resp, "OK") {
		return fail("unexpected response: " + truncRunes(resp, 200))
	}
	payload := ""
	if _, rest, ok := strings.Cut(resp, " "); ok {
		payload = strings.TrimSpace(rest)
	}
	if payload == "" {
		m := pyyaml.NewMap()
		m.Set("code_400", []any{})
		m.Set("code_451", []any{})
		d := diag()
		d.Set("empty", true)
		m.Set("diagnostic", d)
		return m
	}
	if raw, err := pyB64Decode(payload); err == nil {
		if v, err := pyyaml.JSONLoads([]byte(strings.ToValidUTF8(string(raw), "�"))); err == nil {
			if m, ok := v.(*pyyaml.Map); ok {
				return m
			}
			return fail("controld payload is not a JSON object")
		}
	}
	v, err := pyyaml.JSONLoads([]byte(payload))
	if err != nil {
		return fail("cannot parse controld payload as json: " + err.Error())
	}
	if m, ok := v.(*pyyaml.Map); ok {
		return m
	}
	return fail("controld payload is not a JSON object")
}
