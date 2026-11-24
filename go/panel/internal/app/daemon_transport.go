package app

// Port of daemon_transport.py: how the web application reaches the host
// daemons over their sockets.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"

	"easy-ha-proxy/panel/internal/pyyaml"
)

// DaemonError is a client's error class (BackupdError, UpdatedError, ...).
type DaemonError struct{ Msg string }

func (e *DaemonError) Error() string { return e.Msg }

// pyOSError renders a Go network/file error the way str(OSError) reads in
// Python ("[Errno 2] No such file or directory", "timed out").
func pyOSError(err error) string {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timed out"
	}
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return "timed out"
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return fmt.Sprintf("[Errno %d] %s", int(errno), pyStrerror(errno))
	}
	return err.Error()
}

var strerrors = map[syscall.Errno]string{
	syscall.ENOENT:       "No such file or directory",
	syscall.ECONNREFUSED: "Connection refused",
	syscall.EACCES:       "Permission denied",
	syscall.ECONNRESET:   "Connection reset by peer",
	syscall.EPIPE:        "Broken pipe",
	syscall.ENOTSOCK:     "Socket operation on non-socket",
	syscall.EAGAIN:       "Resource temporarily unavailable",
}

func pyStrerror(e syscall.Errno) string {
	if s, ok := strerrors[e]; ok {
		return s
	}
	s := e.Error()
	if s != "" {
		return strings.ToUpper(s[:1]) + s[1:]
	}
	return s
}

// JSONLineRequest is json_line_request: one compact JSON line out, one
// JSON object back, every failure worded with service.
func JSONLineRequest(socketPath string, payload any, service string, timeout time.Duration, maxRequest, maxResponse int) (*pyyaml.Map, error) {
	if socketPath == "" {
		return nil, &DaemonError{fmt.Sprintf("the %s service socket is not configured", service)}
	}
	text, err := pyyaml.JSONDumps(payload, true, true)
	if err != nil {
		return nil, &DaemonError{err.Error()}
	}
	encoded := []byte(text + "\n")
	if len(encoded) > maxRequest {
		return nil, &DaemonError{fmt.Sprintf("the %s request is too large", service)}
	}
	conn, err := net.DialTimeout("unix", socketPath, timeout)
	if err != nil {
		return nil, &DaemonError{fmt.Sprintf("the %s service is unavailable: %s", service, pyOSError(err))}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(encoded); err != nil {
		return nil, &DaemonError{fmt.Sprintf("the %s service is unavailable: %s", service, pyOSError(err))}
	}
	var response []byte
	buf := make([]byte, 64*1024)
	for !bytes.Contains(response, []byte("\n")) {
		n, err := conn.Read(buf)
		response = append(response, buf[:n]...)
		if len(response) > maxResponse {
			return nil, &DaemonError{fmt.Sprintf("the %s service response is too large", service)}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, &DaemonError{fmt.Sprintf("the %s service is unavailable: %s", service, pyOSError(err))}
		}
	}
	raw, _, _ := bytes.Cut(response, []byte("\n"))
	if len(raw) == 0 {
		return nil, &DaemonError{fmt.Sprintf("the %s service returned an empty response", service)}
	}
	v, err := pyyaml.JSONLoads(raw)
	if err != nil {
		return nil, &DaemonError{fmt.Sprintf("the %s service returned invalid JSON", service)}
	}
	m, ok := v.(*pyyaml.Map)
	if !ok {
		return nil, &DaemonError{fmt.Sprintf("the %s service returned an invalid response", service)}
	}
	return m, nil
}

// UnixHTTP is daemon_transport.UnixHttp: JSON over HTTP on a Unix socket.
type UnixHTTP struct {
	Service     string
	SocketPath  string
	TokenHeader string
	Token       string
}

// Unavailable is the client's "unavailable" error class.
type Unavailable struct{ Msg string }

func (e *Unavailable) Error() string { return e.Msg }

// Rejected is the ValueError a refused setting comes back as.
type Rejected struct{ Msg string }

func (e *Rejected) Error() string { return e.Msg }

// HTTPOptions are the keyword arguments of UnixHttp.get/post.
type HTTPOptions struct {
	Params         []QueryValue
	Timeout        time.Duration
	WithToken      bool
	NoCheckStatus  bool
	RejectedStatus int
	RequireObject  bool
}

func (u *UnixHTTP) client(timeout time.Duration) *http.Client {
	return unixSocketClient(u.SocketPath, timeout)
}

// unixSocketClient talks HTTP to a daemon's AF_UNIX socket one connection per
// request, as the Python clients' UnixHTTPConnection did. Each call builds its
// own Transport, so a kept-alive connection would never be reused: it would
// only hold the socket and two goroutines here, and a handler goroutine in the
// daemon, until the daemon's idle timeout closed it.
func unixSocketClient(socketPath string, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
	}
}

// Get is UnixHttp.get.
func (u *UnixHTTP) Get(path string, o HTTPOptions) (any, error) {
	return u.request("GET", path, nil, o)
}

// Post is UnixHttp.post.
func (u *UnixHTTP) Post(path string, body any, o HTTPOptions) (any, error) {
	return u.request("POST", path, body, o)
}

const maxDaemonResponseBytes int64 = 16 << 20

func readBoundedBody(resp *http.Response, limit int64) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("daemon response exceeds %d bytes", limit)
	}
	if resp.ContentLength > 0 && int64(len(raw)) < resp.ContentLength {
		return nil, io.ErrUnexpectedEOF
	}
	return raw, nil
}

func (u *UnixHTTP) request(method, path string, body any, o HTTPOptions) (any, error) {
	target := "http://localhost" + path
	if len(o.Params) > 0 {
		vals := make([]string, 0, len(o.Params))
		for _, p := range o.Params {
			vals = append(vals, url.QueryEscape(p.Key)+"="+url.QueryEscape(p.Value))
		}
		target += "?" + strings.Join(vals, "&")
	}
	var reader io.Reader
	if method == "POST" {
		text, err := pyyaml.JSONDumps(body, true, false)
		if err != nil {
			return nil, &Unavailable{err.Error()}
		}
		reader = strings.NewReader(text)
	}
	req, err := http.NewRequest(method, target, reader)
	if err != nil {
		return nil, &Unavailable{err.Error()}
	}
	if method == "POST" {
		req.Header.Set("Content-Type", "application/json")
	}
	if o.WithToken && u.TokenHeader != "" && u.Token != "" {
		req.Header.Set(u.TokenHeader, u.Token)
	}
	resp, err := u.client(o.Timeout).Do(req)
	if err != nil {
		return nil, &Unavailable{pyOSError(err)}
	}
	defer resp.Body.Close()
	raw, err := readBoundedBody(resp, maxDaemonResponseBytes)
	if err != nil {
		return nil, &Unavailable{pyOSError(err)}
	}
	if o.RejectedStatus != 0 && resp.StatusCode == o.RejectedStatus {
		reason := "rejected"
		if v, err := pyyaml.JSONLoads(raw); err == nil {
			if m, ok := v.(*pyyaml.Map); ok {
				if r, ok := m.Value("error").(string); ok && r != "" {
					reason = r
				}
			}
		}
		return nil, &Rejected{reason}
	}
	if !o.NoCheckStatus && resp.StatusCode >= 400 {
		kind := "Client Error"
		if resp.StatusCode >= 500 {
			kind = "Server Error"
		}
		return nil, &Unavailable{fmt.Sprintf("%d %s: %s for url: %s", resp.StatusCode, kind, httpReason(resp.StatusCode), u.displayURL(path, o.Params))}
	}
	data, err := pyyaml.JSONLoads(raw)
	if err != nil {
		return nil, &Unavailable{u.Service + " returned a non-JSON response"}
	}
	if o.RequireObject {
		if _, ok := data.(*pyyaml.Map); !ok {
			return nil, &Unavailable{u.Service + " returned an unexpected payload"}
		}
	}
	return data, nil
}

func httpReason(code int) string {
	if code == 404 {
		return "Not Found"
	}
	return http.StatusText(code)
}

func (u *UnixHTTP) displayURL(path string, params []QueryValue) string {
	out := "http+unix://" + strings.ReplaceAll(url.PathEscape(u.SocketPath), "/", "%2F") + path
	if len(params) > 0 {
		vals := make([]string, 0, len(params))
		for _, p := range params {
			vals = append(vals, url.QueryEscape(p.Key)+"="+url.QueryEscape(p.Value))
		}
		out += "?" + strings.Join(vals, "&")
	}
	return out
}
