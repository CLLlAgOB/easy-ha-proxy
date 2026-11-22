package unixrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"
)

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
			_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
			_, _ = io.WriteString(conn, `{"ok":false,"error":"too many active requests","error_code":"busy"}`+"\n")
			_ = conn.Close()
		}
	}
}

// ListenAndServe binds socketPath with mode 0600 and serves until ctx is canceled.
func (s *Server) ListenAndServe(ctx context.Context, socketPath string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o750); err != nil {
		return err
	}
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	_ = os.Chmod(socketPath, mode)
	defer os.Remove(socketPath)
	return s.Serve(ctx, ln)
}
