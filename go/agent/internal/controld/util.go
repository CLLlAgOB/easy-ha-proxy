package controld

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/alerts"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/pyx"
)

type alertSink interface {
	Enabled() bool
	Observe(ctx context.Context, obs alerts.Observation) bool
}

func (d *Daemon) observe(obs alerts.Observation) {
	if d.alerts == nil || !d.alerts.Enabled() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	d.alerts.Observe(ctx, obs)
}

func (d *Daemon) reportAlert(rule, subject, summary, detail string) {
	d.observe(alerts.Observation{Rule: rule, Subject: subject, Summary: summary, Detail: detail})
}

// valueError and runtimeError keep the Python exception kinds apart where
// a caller turns them into different replies.
type valueError struct{ msg string }

func (e *valueError) Error() string { return e.msg }

type runtimeError struct{ msg string }

func (e *runtimeError) Error() string { return e.msg }

func vErr(format string, args ...any) error {
	if len(args) > 0 {
		return &valueError{fmt.Sprintf(format, args...)}
	}
	return &valueError{format}
}

func rErr(format string, args ...any) error {
	if len(args) > 0 {
		return &runtimeError{fmt.Sprintf(format, args...)}
	}
	return &runtimeError{format}
}

type timeoutErr struct {
	argv    []string
	seconds float64
}

func (e *timeoutErr) Error() string {
	return fmt.Sprintf("Command '%s' timed out after %s seconds", pyArgv(e.argv), pyNum(e.seconds))
}

func pyNum(f float64) string {
	if f == float64(int64(f)) {
		return fmt.Sprintf("%d", int64(f))
	}
	return fmt.Sprint(f)
}

// pyArgv is repr() of a list of strings.
func pyArgv(argv []string) string {
	parts := make([]string, len(argv))
	for i, a := range argv {
		parts[i] = pyRepr(a)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func pyRepr(s string) string {
	if strings.Contains(s, "'") && !strings.Contains(s, `"`) {
		return `"` + s + `"`
	}
	return "'" + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), "'", `\'`) + "'"
}

type procResult struct {
	rc             int
	stdout, stderr string
}

// execRaw runs argv with optional stdin; err is set when it could not run.
func execRaw(argv []string, input *string, timeout time.Duration) (procResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	if input != nil {
		cmd.Stdin = strings.NewReader(*input)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return procResult{}, &timeoutErr{argv, timeout.Seconds()}
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return procResult{ee.ExitCode(), universalNewlines(out.String()), universalNewlines(errb.String())}, nil
		}
		return procResult{}, pyExecError(argv, err)
	}
	return procResult{0, universalNewlines(out.String()), universalNewlines(errb.String())}, nil
}

// pyExecError renders a failed exec like FileNotFoundError.
func pyExecError(argv []string, err error) error {
	var ee *exec.Error
	if errors.As(err, &ee) && errors.Is(ee.Err, exec.ErrNotFound) {
		return &os.PathError{Op: "exec", Path: argv[0], Err: syscall.ENOENT}
	}
	var pe *os.PathError
	if errors.As(err, &pe) {
		return &os.PathError{Op: "exec", Path: argv[0], Err: pe.Err}
	}
	return err
}

// runCmd is run_cmd: a non-zero exit is an error naming the command.
func runCmd(argv []string, input *string, timeout time.Duration) (procResult, error) {
	res, err := execRaw(argv, input, timeout)
	if err != nil {
		return res, err
	}
	if res.rc != 0 {
		return res, rErr("Command %s failed with code %d: %s", pyArgv(argv), res.rc, strings.TrimSpace(res.stderr))
	}
	return res, nil
}

func strPtr(s string) *string { return &s }

// pyErr is str(exc) for the errors that reach a reply.
func pyErr(err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		var errno syscall.Errno
		if errors.As(pe.Err, &errno) {
			msg := errno.Error()
			if msg != "" {
				msg = strings.ToUpper(msg[:1]) + msg[1:]
			}
			return fmt.Sprintf("[Errno %d] %s: '%s'", int(errno), msg, pe.Path)
		}
	}
	return err.Error()
}

// b64JSON is base64(json.dumps(result, ensure_ascii=False)).
func b64JSON(v any) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return base64.StdEncoding.EncodeToString(bytes.TrimRight(buf.Bytes(), "\n"))
}

func okPrefix(ok bool) string {
	if ok {
		return "OK"
	}
	return "ERROR"
}

// b64decodeStrict is base64.b64decode(value, validate=True).
func b64decodeStrict(value string) ([]byte, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil {
		return nil, &valueError{pyBase64Error(value)}
	}
	return raw, nil
}

func pyBase64Error(s string) string {
	data := 0
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '+', r == '/':
			data++
		case r == '=':
		default:
			return "Only base64 data is allowed"
		}
	}
	if data%4 == 1 {
		return fmt.Sprintf("Invalid base64-encoded string: number of data characters (%d) cannot be 1 more than a multiple of 4", data)
	}
	return "Incorrect padding"
}

func nowEpoch() float64 { return pyx.Timestamp(time.Now()) }

func lexists(p string) bool { _, err := os.Lstat(p); return err == nil }

func isFile(p string) bool { fi, err := os.Stat(p); return err == nil && fi.Mode().IsRegular() }

func isDir(p string) bool { fi, err := os.Stat(p); return err == nil && fi.IsDir() }

func fsyncDir(path string) {
	if d, err := os.Open(path); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

// decodeJSONObject is json.loads for payloads, keeping numbers exact.
func decodeJSONObject(raw []byte) (any, error) {
	v, err := pyx.Decode(raw)
	if err != nil {
		return nil, vErr("%s", pyJSONError(err))
	}
	return v, nil
}

func pyJSONError(err error) string {
	var se *json.SyntaxError
	if errors.As(err, &se) {
		return fmt.Sprintf("Expecting value: line 1 column %d (char %d)", se.Offset, se.Offset-1)
	}
	return err.Error()
}
