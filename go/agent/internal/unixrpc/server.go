package unixrpc

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ResolveUID looks up a local username (pure-Go /etc/passwd) and returns its
// numeric UID, or fallback if empty or not found.
func ResolveUID(username string, fallback int) int {
	name := strings.TrimSpace(username)
	if name == "" {
		return fallback
	}
	if n, err := strconv.Atoi(name); err == nil && n >= 0 {
		return n
	}
	if u, err := user.Lookup(name); err == nil {
		if n, err := strconv.Atoi(u.Uid); err == nil && n >= 0 {
			return n
		}
	}
	return fallback
}

// ChownSocket applies optional user/group ownership and permissions to a Unix socket.
func ChownSocket(socketPath, userName, groupName string, mode os.FileMode) error {
	uid := -1
	gid := -1
	if u := strings.TrimSpace(userName); u != "" {
		if n, err := strconv.Atoi(u); err == nil {
			uid = n
		} else if info, err := user.Lookup(u); err == nil {
			n, convErr := strconv.Atoi(info.Uid)
			if convErr != nil {
				return fmt.Errorf("invalid uid for user %q: %w", u, convErr)
			}
			uid = n
		} else if os.Geteuid() == 0 {
			return fmt.Errorf("lookup socket user %q: %w", u, err)
		}
	}
	if g := strings.TrimSpace(groupName); g != "" {
		if n, err := strconv.Atoi(g); err == nil {
			gid = n
		} else if info, err := user.LookupGroup(g); err == nil {
			n, convErr := strconv.Atoi(info.Gid)
			if convErr != nil {
				return fmt.Errorf("invalid gid for group %q: %w", g, convErr)
			}
			gid = n
		} else if os.Geteuid() == 0 {
			return fmt.Errorf("lookup socket group %q: %w", g, err)
		}
	}
	if uid >= 0 || gid >= 0 {
		if err := os.Chown(socketPath, uid, gid); err != nil {
			if os.Geteuid() == 0 || !errors.Is(err, syscall.EPERM) {
				return fmt.Errorf("chown socket %s: %w", socketPath, err)
			}
		}
	}
	if err := os.Chmod(socketPath, mode); err != nil {
		return fmt.Errorf("chmod socket %s: %w", socketPath, err)
	}
	return nil
}

// ListenUnix binds a Unix socket at a private temporary path, applies owner/group
// and permissions via ChownSocket, and atomically publishes it at socketPath.
func ListenUnix(socketPath, userName, groupName string, mode os.FileMode) (net.Listener, error) {
	dir := filepath.Dir(socketPath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	var rnd [4]byte
	_, _ = rand.Read(rnd[:])
	tmpPath := filepath.Join(dir, fmt.Sprintf(".s.%d.%s", os.Getpid(), hex.EncodeToString(rnd[:])))
	_ = os.Remove(tmpPath)
	ln, err := net.Listen("unix", tmpPath)
	if err != nil {
		return nil, err
	}
	if ul, ok := ln.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}
	if err := ChownSocket(tmpPath, userName, groupName, mode); err != nil {
		_ = ln.Close()
		_ = os.Remove(tmpPath)
		return nil, err
	}
	if err := os.Rename(tmpPath, socketPath); err != nil {
		_ = ln.Close()
		_ = os.Remove(tmpPath)
		return nil, err
	}
	return ln, nil
}

// Error carries a structured error_code matching backupd and updated wire replies.
type Error struct {
	Code string
	Msg  string
}

func (e *Error) Error() string { return e.Msg }

// NewError builds a structured RPC Error with default code "invalid".
func NewError(code, msg string) *Error {
	if code == "" {
		code = "invalid"
	}
	return &Error{Code: code, Msg: msg}
}

// Handler processes one decoded JSON request object and returns a JSON response object.
type Handler func(ctx context.Context, req map[string]any) (map[string]any, error)

// Server serves single-line JSON RPC requests over an AF_UNIX stream socket.
type Server struct {
	AllowedUIDs      map[int]struct{}
	SocketUser       string
	SocketGroup      string
	MaxRequestBytes  int
	MaxResponseBytes int
	MaxConnections   int
	Handler          Handler
	slots            chan struct{}
}

// NewServer constructs a Server with safe defaults.
func NewServer(appUID, maxReq, maxResp, maxConns int, h Handler) *Server {
	if maxReq <= 0 {
		maxReq = 64 * 1024
	}
	if maxResp <= 0 {
		maxResp = 2 * 1024 * 1024
	}
	if maxConns <= 0 {
		maxConns = 16
	}
	allowed := map[int]struct{}{0: {}}
	if appUID >= 0 {
		allowed[appUID] = struct{}{}
	}
	return &Server{
		AllowedUIDs:      allowed,
		MaxRequestBytes:  maxReq,
		MaxResponseBytes: maxResp,
		MaxConnections:   maxConns,
		Handler:          h,
		slots:            make(chan struct{}, maxConns),
	}
}

func (s *Server) readSingleJSONLine(conn net.Conn) ([]byte, error) {
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var buf bytes.Buffer
	tmp := make([]byte, 4096)
	for buf.Len() <= s.MaxRequestBytes {
		want := len(tmp)
		rem := s.MaxRequestBytes + 1 - buf.Len()
		if rem < want {
			want = rem
		}
		n, err := conn.Read(tmp[:want])
		if n > 0 {
			buf.Write(tmp[:n])
			if bytes.IndexByte(tmp[:n], '\n') >= 0 {
				break
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				return nil, NewError("invalid", "request timed out")
			}
			return nil, NewError("invalid", err.Error())
		}
	}
	data := buf.Bytes()
	if len(data) > s.MaxRequestBytes {
		return nil, NewError("too_large", "request is too large")
	}
	if len(data) == 0 || data[len(data)-1] != '\n' || bytes.Count(data, []byte{'\n'}) != 1 {
		return nil, NewError("invalid", "request must contain exactly one JSON line")
	}
	return data[:len(data)-1], nil
}

// ServeConn handles one AF_UNIX connection end-to-end.
func (s *Server) ServeConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	var resp map[string]any
	if uid, err := PeerUID(conn); err != nil {
		resp = map[string]any{"ok": false, "error": "Unix peer credentials are unavailable", "error_code": "invalid"}
	} else if _, ok := s.AllowedUIDs[uid]; !ok {
		resp = map[string]any{"ok": false, "error": "socket peer is not authorized", "error_code": "invalid"}
	} else {
		raw, err := s.readSingleJSONLine(conn)
		if err != nil {
			resp = errorReply(err)
		} else {
			var req map[string]any
			if err := json.Unmarshal(raw, &req); err != nil || req == nil {
				resp = map[string]any{"ok": false, "error": "request must be a JSON object", "error_code": "invalid"}
			} else {
				out, err := s.Handler(ctx, req)
				if err != nil {
					resp = errorReply(err)
				} else {
					resp = out
				}
			}
		}
	}

	encoded, err := json.Marshal(resp)
	if err != nil {
		encoded = []byte(`{"ok":false,"error":"failed to encode response","error_code":"internal"}`)
	}
	encoded = append(encoded, '\n')
	if s.MaxResponseBytes > 0 && len(encoded) > s.MaxResponseBytes {
		encoded = []byte(`{"ok":false,"error":"response is too large","error_code":"too_large"}` + "\n")
	}
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write(encoded)
}

func errorReply(err error) map[string]any {
	var rpcErr *Error
	code := "internal"
	msg := err.Error()
	if errors.As(err, &rpcErr) {
		code = rpcErr.Code
		msg = rpcErr.Msg
	} else if os.IsNotExist(err) {
		code = "not_found"
	}
	if len(msg) > 4096 {
		msg = msg[:4096]
	}
	return map[string]any{"ok": false, "error": msg, "error_code": code}
}

// Serve accepts connections on ln until ctx is canceled.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	var active sync.WaitGroup
	defer func() {
		stop()
		_ = ln.Close()
		active.Wait()
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
			active.Go(func() {
				defer func() { <-s.slots }()
				s.ServeConn(ctx, conn)
			})
		default:
			_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
			_, _ = io.WriteString(conn, `{"ok":false,"error":"too many active requests","error_code":"busy"}`+"\n")
			_ = conn.Close()
		}
	}
}

// ListenAndServe binds socketPath with mode and serves until ctx is canceled.
func (s *Server) ListenAndServe(ctx context.Context, socketPath string, mode os.FileMode) error {
	ln, err := ListenUnix(socketPath, s.SocketUser, s.SocketGroup, mode)
	if err != nil {
		return err
	}
	defer func() {
		_ = ln.Close()
		_ = os.Remove(socketPath)
	}()
	return s.Serve(ctx, ln)
}
