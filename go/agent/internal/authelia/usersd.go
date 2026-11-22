package authelia

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	usersNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._@-]{0,63}$`)
	groupNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)
)

// UsersdOptions configures authelia-usersd from AUTHELIA_USERS_* environment variables.
type UsersdOptions struct {
	SocketPath        string
	UsersFile         string
	AutheliaContainer string
	DockerBin         string
	MaxRequestBytes   int
}

// UsersdOptionsFromEnv reads options matching authelia-usersd.py.
func UsersdOptionsFromEnv() UsersdOptions {
	envOr := func(k, fb string) string {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
		return fb
	}
	return UsersdOptions{
		SocketPath:        envOr("AUTHELIA_USERS_SOCKET", "/run/easy-ha-proxy/authelia-usersd.sock"),
		UsersFile:         envOr("AUTHELIA_USERS_FILE", "/opt/authelia/users_database.yml"),
		AutheliaContainer: envOr("AUTHELIA_CONTAINER_NAME", "authelia"),
		DockerBin:         envOr("DOCKER_BIN", "/usr/bin/docker"),
		MaxRequestBytes:   65536,
	}
}

// UserRecord holds one Authelia file-provider user entry.
type UserRecord struct {
	DisplayName string   `json:"displayname"`
	Email       string   `json:"email"`
	Password    string   `json:"-"`
	Groups      []string `json:"groups"`
	Disabled    bool     `json:"disabled"`
}

// UsersdServer manages Authelia's users_database.yml with last-superadmin protection.
type UsersdServer struct {
	mu       sync.Mutex
	Opts     UsersdOptions
	HashFunc func(ctx context.Context, plain string) (string, error)
}

// NewUsersdServer constructs a UsersdServer.
func NewUsersdServer(opts UsersdOptions) *UsersdServer {
	if opts.MaxRequestBytes <= 0 {
		opts.MaxRequestBytes = 65536
	}
	return &UsersdServer{Opts: opts}
}

func (s *UsersdServer) hashPassword(ctx context.Context, plain string) (string, error) {
	if s.HashFunc != nil {
		return s.HashFunc(ctx, plain)
	}
	cmdCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(
		cmdCtx, s.Opts.DockerBin, "exec", "-i", s.Opts.AutheliaContainer,
		"authelia", "crypto", "hash", "generate", "argon2", "--password", plain,
	)
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%v: %s", err, strings.TrimSpace(errBuf.String()))
	}
	for _, line := range strings.Split(out.String(), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Digest:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Digest:")), nil
		}
		if strings.HasPrefix(line, "$argon2") {
			return line, nil
		}
	}
	return "", errors.New("authelia did not output an argon2 digest")
}

// ParseUsersYAML parses Authelia's users_database.yml without external YAML dependencies.
func ParseUsersYAML(content string) map[string]*UserRecord {
	users := make(map[string]*UserRecord)
	inUsers := false
	var curName string
	var cur *UserRecord
	inGroups := false

	for _, rawLine := range strings.Split(content, "\n") {
		line := strings.TrimRight(rawLine, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent == 0 {
			inUsers = trimmed == "users:"
			curName = ""
			cur = nil
			inGroups = false
			continue
		}
		if !inUsers {
			continue
		}
		if indent == 2 && strings.HasSuffix(trimmed, ":") {
			curName = unquoteYAML(strings.TrimSuffix(trimmed, ":"))
			cur = &UserRecord{Groups: []string{}}
			users[curName] = cur
			inGroups = false
			continue
		}
		if cur == nil {
			continue
		}
		if inGroups && strings.HasPrefix(trimmed, "- ") {
			g := unquoteYAML(strings.TrimSpace(strings.TrimPrefix(trimmed, "- ")))
			if g != "" {
				cur.Groups = append(cur.Groups, g)
			}
			continue
		}
		inGroups = false
		key, val, found := strings.Cut(trimmed, ":")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		switch key {
		case "displayname":
			cur.DisplayName = unquoteYAML(val)
		case "email":
			cur.Email = unquoteYAML(val)
		case "password":
			cur.Password = unquoteYAML(val)
		case "disabled":
			cur.Disabled = strings.EqualFold(val, "true")
		case "groups":
			if val == "" {
				inGroups = true
			} else if strings.HasPrefix(val, "[") && strings.HasSuffix(val, "]") {
				inner := strings.TrimSpace(val[1 : len(val)-1])
				if inner != "" {
					for _, part := range strings.Split(inner, ",") {
						g := unquoteYAML(strings.TrimSpace(part))
						if g != "" {
							cur.Groups = append(cur.Groups, g)
						}
					}
				}
			}
		}
	}
	return users
}

// RenderUsersYAML writes a canonical Authelia users_database.yml file.
func RenderUsersYAML(users map[string]*UserRecord) string {
	names := make([]string, 0, len(users))
	for k := range users {
		names = append(names, k)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString("users:\n")
	for _, name := range names {
		u := users[name]
		fmt.Fprintf(&b, "  %s:\n", quoteYAML(name))
		fmt.Fprintf(&b, "    displayname: %s\n", quoteYAML(u.DisplayName))
		fmt.Fprintf(&b, "    email: %s\n", quoteYAML(u.Email))
		fmt.Fprintf(&b, "    password: %s\n", quoteYAML(u.Password))
		if u.Disabled {
			b.WriteString("    disabled: true\n")
		} else {
			b.WriteString("    disabled: false\n")
		}
		if len(u.Groups) == 0 {
			b.WriteString("    groups: []\n")
		} else {
			b.WriteString("    groups:\n")
			for _, g := range u.Groups {
				fmt.Fprintf(&b, "      - %s\n", quoteYAML(g))
			}
		}
	}
	return b.String()
}

func unquoteYAML(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'")
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		inner := s[1 : len(s)-1]
		inner = strings.ReplaceAll(inner, `\"`, `"`)
		inner = strings.ReplaceAll(inner, `\\`, `\`)
		return inner
	}
	return s
}

func quoteYAML(s string) string {
	escaped := strings.ReplaceAll(s, "'", "''")
	return "'" + escaped + "'"
}

func isEnabledSuperadmin(u *UserRecord) bool {
	if u == nil || u.Disabled {
		return false
	}
	for _, g := range u.Groups {
		if g == "superadmins" || g == "admins" {
			return true
		}
	}
	return false
}

func removesLastSuperadmin(users map[string]*UserRecord, target string, replacement *UserRecord) bool {
	count := 0
	for name, u := range users {
		eff := u
		if name == target {
			eff = replacement
		}
		if isEnabledSuperadmin(eff) {
			count++
		}
	}
	return count == 0 && isEnabledSuperadmin(users[target])
}

func safeUserView(username string, u *UserRecord) map[string]any {
	groups := append([]string(nil), u.Groups...)
	if groups == nil {
		groups = []string{}
	}
	return map[string]any{
		"username":     username,
		"displayname":  u.DisplayName,
		"email":        u.Email,
		"groups":       groups,
		"disabled":     u.Disabled,
		"has_password": u.Password != "",
	}
}

func (s *UsersdServer) loadLocked() (map[string]*UserRecord, error) {
	raw, err := os.ReadFile(s.Opts.UsersFile)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]*UserRecord{}, nil
		}
		return nil, err
	}
	return ParseUsersYAML(string(raw)), nil
}

func (s *UsersdServer) saveLocked(users map[string]*UserRecord) error {
	if err := os.MkdirAll(filepath.Dir(s.Opts.UsersFile), 0o750); err != nil {
		return err
	}
	return writeFileAtomic(s.Opts.UsersFile, []byte(RenderUsersYAML(users)), 0o600)
}

func parseGroups(raw any) ([]string, error) {
	list, ok := raw.([]any)
	if !ok {
		return nil, errors.New("groups must be a list")
	}
	out := make([]string, 0, len(list))
	seen := map[string]struct{}{}
	for _, it := range list {
		g := strings.TrimSpace(asStr(it))
		if !groupNameRe.MatchString(g) {
			return nil, fmt.Errorf("invalid group name: %q", g)
		}
		if _, dup := seen[g]; !dup {
			seen[g] = struct{}{}
			out = append(out, g)
		}
	}
	return out, nil
}

// HandleRequest dispatches list, get, create, update, and delete actions.
func (s *UsersdServer) HandleRequest(ctx context.Context, req map[string]any) map[string]any {
	action := strings.TrimSpace(asStr(req["action"]))
	s.mu.Lock()
	defer s.mu.Unlock()

	users, err := s.loadLocked()
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}

	switch action {
	case "list":
		names := make([]string, 0, len(users))
		for k := range users {
			names = append(names, k)
		}
		sort.Strings(names)
		out := make([]map[string]any, 0, len(names))
		for _, n := range names {
			out = append(out, safeUserView(n, users[n]))
		}
		return map[string]any{"ok": true, "users": out}

	case "get":
		username := strings.TrimSpace(asStr(req["username"]))
		if !usersNameRe.MatchString(username) {
			return map[string]any{"ok": false, "error": "invalid username"}
		}
		u, ok := users[username]
		if !ok {
			return map[string]any{"ok": false, "error": fmt.Sprintf("user '%s' not found", username)}
		}
		return map[string]any{"ok": true, "user": safeUserView(username, u)}

	case "create":
		username := strings.TrimSpace(asStr(req["username"]))
		if !usersNameRe.MatchString(username) {
			return map[string]any{"ok": false, "error": "invalid username"}
		}
		if _, exists := users[username]; exists {
			return map[string]any{"ok": false, "error": fmt.Sprintf("user '%s' already exists", username)}
		}
		plain := asStr(req["password_plain"])
		if plain == "" {
			return map[string]any{"ok": false, "error": "password_plain is required for create"}
		}
		hash, err := s.hashPassword(ctx, plain)
		if err != nil {
			return map[string]any{"ok": false, "error": fmt.Sprintf("Could not hash the password: %v", err)}
		}
		u := &UserRecord{
			DisplayName: strings.TrimSpace(asStr(req["displayname"])),
			Email:       strings.TrimSpace(asStr(req["email"])),
			Password:    hash,
			Groups:      []string{},
		}
		if b, ok := req["disabled"].(bool); ok {
			u.Disabled = b
		}
		if rawG, has := req["groups"]; has && rawG != nil {
			g, err := parseGroups(rawG)
			if err != nil {
				return map[string]any{"ok": false, "error": err.Error()}
			}
			u.Groups = g
		}
		users[username] = u
		if err := s.saveLocked(users); err != nil {
			return map[string]any{"ok": false, "error": err.Error()}
		}
		return map[string]any{"ok": true, "user": safeUserView(username, u)}

	case "update":
		username := strings.TrimSpace(asStr(req["username"]))
		if !usersNameRe.MatchString(username) {
			return map[string]any{"ok": false, "error": "invalid username"}
		}
		cur, ok := users[username]
		if !ok {
			return map[string]any{"ok": false, "error": fmt.Sprintf("user '%s' not found", username)}
		}
		next := &UserRecord{
			DisplayName: cur.DisplayName,
			Email:       cur.Email,
			Password:    cur.Password,
			Groups:      append([]string(nil), cur.Groups...),
			Disabled:    cur.Disabled,
		}
		if v, has := req["displayname"]; has {
			next.DisplayName = strings.TrimSpace(asStr(v))
		}
		if v, has := req["email"]; has {
			next.Email = strings.TrimSpace(asStr(v))
		}
		if b, ok := req["disabled"].(bool); ok {
			next.Disabled = b
		}
		if rawG, has := req["groups"]; has && rawG != nil {
			g, err := parseGroups(rawG)
			if err != nil {
				return map[string]any{"ok": false, "error": err.Error()}
			}
			next.Groups = g
		}
		if removesLastSuperadmin(users, username, next) {
			return map[string]any{"ok": false, "error": "the last enabled superadmin cannot be disabled or demoted"}
		}
		if plain := asStr(req["password_plain"]); plain != "" {
			hash, err := s.hashPassword(ctx, plain)
			if err != nil {
				return map[string]any{"ok": false, "error": fmt.Sprintf("Could not hash the password: %v", err)}
			}
			next.Password = hash
		}
		users[username] = next
		if err := s.saveLocked(users); err != nil {
			return map[string]any{"ok": false, "error": err.Error()}
		}
		return map[string]any{"ok": true, "user": safeUserView(username, next)}

	case "delete":
		username := strings.TrimSpace(asStr(req["username"]))
		if !usersNameRe.MatchString(username) {
			return map[string]any{"ok": false, "error": "invalid username"}
		}
		cur, ok := users[username]
		if !ok {
			return map[string]any{"ok": false, "error": fmt.Sprintf("user '%s' not found", username)}
		}
		if removesLastSuperadmin(users, username, nil) {
			return map[string]any{"ok": false, "error": "the last enabled superadmin cannot be deleted"}
		}
		delete(users, username)
		if err := s.saveLocked(users); err != nil {
			return map[string]any{"ok": false, "error": err.Error()}
		}
		return map[string]any{"ok": true, "message": fmt.Sprintf("user '%s' deleted", username), "user": safeUserView(username, cur)}

	default:
		return map[string]any{"ok": false, "error": fmt.Sprintf("unknown action: %s", action)}
	}
}

// Serve accepts connections on ln until ctx is canceled.
func (s *UsersdServer) Serve(ctx context.Context, ln net.Listener) error {
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
		serveJSONLineConn(ctx, conn, s.Opts.MaxRequestBytes, s.HandleRequest)
	}
}

// RunUsersd starts authelia-usersd until SIGTERM/SIGINT.
func RunUsersd(opts UsersdOptions) error {
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
	log.Printf("authelia-usersd (Go) listening on %s", opts.SocketPath)
	return NewUsersdServer(opts).Serve(ctx, ln)
}

func writeFileAtomic(target string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(target)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(target)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	_ = tmp.Chmod(mode)
	_ = tmp.Sync()
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, target); err != nil {
		cleanup()
		return err
	}
	return nil
}
