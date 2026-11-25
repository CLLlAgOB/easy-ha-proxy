package authelia

// The Go port of authelia-usersd.py: one JSON line per request on a Unix
// socket, served one at a time; users_database.yml read without following
// links and written back through the shared pyyaml (sort_keys=True), with a
// hard-link backup rotation; argon2id hashed locally with argon2-cffi's
// parameters so the password never reaches a process's argv.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"

	"easy-ha-proxy/panel/shared/pyyaml"
)

// UsersdOptions holds what authelia-usersd.py reads from the environment.
type UsersdOptions struct {
	SocketPath string
	UsersFile  string
}

// UsersdOptionsFromEnv reads the environment as authelia-usersd.py does.
func UsersdOptionsFromEnv() UsersdOptions {
	return UsersdOptions{
		SocketPath: envDefault("AUTHELIA_USERS_SOCKET", "/run/easy-ha-proxy/authelia-usersd.sock"),
		UsersFile:  envDefault("AUTHELIA_USERS_FILE", "/opt/authelia/users_database.yml"),
	}
}

const (
	usersMaxRequest = 1024 * 1024
	usersMaxFile    = 10 * 1024 * 1024
)

var usernameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}$`)

// Usersd is the daemon state.
type Usersd struct {
	Opts UsersdOptions
	// HashPassword can be replaced in tests; it defaults to argon2id.
	HashPassword func(plain string) (string, error)
}

// NewUsersd builds the daemon.
func NewUsersd(opts UsersdOptions) *Usersd {
	return &Usersd{Opts: opts, HashPassword: hashArgon2id}
}

func valueErr(format string, args ...any) error { return newErr("ValueError", format, args...) }

// hashArgon2id is PasswordHasher(time_cost=3, memory_cost=65536,
// parallelism=4, hash_len=32, salt_len=16).hash(plain).
func hashArgon2id(plain string) (string, error) {
	if n := utf8.RuneCountInString(plain); n < 8 || n > 1024 {
		return "", valueErr("The password must be 8 to 1024 characters long")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(plain), salt, 3, 65536, 4, 32)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=4$%s$%s", enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

func (u *Usersd) backupUsersFile() {
	path := u.Opts.UsersFile
	if _, err := os.Stat(path); err != nil {
		return
	}
	now := time.Now()
	backup := path + ".bak-" + now.Format("20060102-150405") + fmt.Sprintf("-%06d", now.Nanosecond()/1000)
	if err := os.Link(path, backup); err != nil {
		log.Printf("Backup failed (%s): %s", backup, osErr(err))
	} else {
		log.Printf("Backup created: %s", backup)
	}
	dir, prefix := filepath.Dir(path), filepath.Base(path)+".bak-"
	ents, err := os.ReadDir(dir)
	if err != nil {
		log.Printf("Backup rotation list failed: %s", osErr(err))
		return
	}
	type cand struct {
		p string
		t int64
	}
	cands := []cand{}
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), prefix) {
			p := filepath.Join(dir, e.Name())
			var t int64
			if fi, err := os.Stat(p); err == nil {
				t = fi.ModTime().UnixNano()
			}
			cands = append(cands, cand{p, t})
		}
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].t > cands[j].t })
	for i := 14; i < len(cands); i++ {
		if err := os.Remove(cands[i].p); err != nil {
			log.Printf("Failed to remove old backup %s: %s", cands[i].p, osErr(err))
		} else {
			log.Printf("Old backup removed: %s", cands[i].p)
		}
	}
}

func (u *Usersd) loadUsersData() (*pyyaml.Map, *pyyaml.Map, error) {
	path := u.Opts.UsersFile
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if err == syscall.ENOENT {
			return nil, nil, newErr("FileNotFoundError", "users file not found: %s", path)
		}
		return nil, nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, nil, valueErr("users file is not a regular file: %s", path)
	}
	raw, err := io.ReadAll(io.LimitReader(f, usersMaxFile+1))
	if err != nil {
		return nil, nil, err
	}
	if len(raw) > usersMaxFile {
		return nil, nil, valueErr("users file exceeds allowed size: %s", path)
	}
	if err := utf8Error(raw); err != nil {
		return nil, nil, err
	}
	v, err := pyyaml.Load(raw)
	if err != nil {
		return nil, nil, err
	}
	if !truthy(v) {
		v = pyyaml.NewMap()
	}
	data, ok := v.(*pyyaml.Map)
	if !ok {
		return nil, nil, valueErr("unexpected YAML structure (root is not a dict)")
	}
	if users, ok := data.Value("users").(*pyyaml.Map); ok {
		return data, users, nil
	}
	return data, data, nil
}

func (u *Usersd) saveUsersData(root *pyyaml.Map) error {
	path := u.Opts.UsersFile
	var prev *syscall.Stat_t
	var st syscall.Stat_t
	if err := syscall.Lstat(path, &st); err == nil {
		if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
			return valueErr("users file is not a regular file: %s", path)
		}
		prev = &st
	} else if err != syscall.ENOENT {
		log.Printf("Failed to stat %s before save: %v", path, err)
	}
	u.backupUsersFile()
	uid, gid := -1, -1
	if prev != nil {
		uid, gid = int(prev.Uid), int(prev.Gid)
	} else if acct, err := user.Lookup("authelia"); err == nil {
		uid, _ = strconv.Atoi(acct.Uid)
		gid, _ = strconv.Atoi(acct.Gid)
	}
	text, err := pyyaml.Dump(root, pyyaml.Options{AllowUnicode: true, SortKeys: true})
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".users_database.*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(name)
		}
	}()
	if _, err := tmp.WriteString(text); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := syncTempFile(tmp); err != nil {
		_ = tmp.Close()
		return err
	}
	if uid != -1 {
		if err := tmp.Chown(uid, gid); err != nil {
			if os.Geteuid() == 0 || !errors.Is(err, syscall.EPERM) {
				_ = tmp.Close()
				return err
			}
			log.Printf("Failed to set owner/group on temp users file: %v", err)
		}
	}
	if err := tmp.Chmod(0o640); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := closeTempFile(tmp); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	keep = true
	log.Printf("Users file updated: %s", path)
	return nil
}

func userGroups(raw any) []any {
	switch g := raw.(type) {
	case []any:
		out := make([]any, len(g))
		for i, x := range g {
			out[i] = pyStr(x)
		}
		return out
	case nil:
		return []any{}
	}
	if !truthy(raw) {
		return []any{}
	}
	return []any{pyStr(raw)}
}

func orEmpty(v any) any {
	if !truthy(v) {
		return ""
	}
	return v
}

func safeUserView(username string, raw *pyyaml.Map) map[string]any {
	return map[string]any{"username": username, "displayname": orEmpty(getDefault(raw, "displayname", "")),
		"email": orEmpty(getDefault(raw, "email", "")), "groups": userGroups(raw.Value("groups")),
		"disabled": truthy(getDefault(raw, "disabled", false))}
}

func validatedUsername(req *pyyaml.Map) (string, error) {
	username := pyStrip(pyStrOr(req.Value("username")))
	if !usernameRE.MatchString(username) {
		return "", valueErr("username must contain only letters, digits, '.', '_', '@' or '-' (max 64)")
	}
	return username, nil
}

func validatedFields(req *pyyaml.Map) (*pyyaml.Map, error) {
	raw := req.Value("fields")
	if !truthy(raw) {
		raw = pyyaml.NewMap()
	}
	fields, ok := raw.(*pyyaml.Map)
	if !ok {
		return nil, valueErr("fields must be an object")
	}
	out := pyyaml.NewMap()
	for _, key := range []string{"displayname", "email"} {
		v, present := fields.Get(key)
		if !present {
			continue
		}
		rawValue := pyStrOr(v)
		for _, r := range rawValue {
			if r < 32 || r == 127 {
				return nil, valueErr("%s is invalid", key)
			}
		}
		value := pyStrip(rawValue)
		maximum := 320
		if key == "email" {
			maximum = 254
		}
		if value == "" || utf8.RuneCountInString(value) > maximum {
			return nil, valueErr("%s is invalid", key)
		}
		if key == "email" && !emailRE.MatchString(value) {
			return nil, valueErr("email is invalid")
		}
		out.Set(key, value)
	}
	if v, present := fields.Get("groups"); present {
		groups, ok := v.([]any)
		if !ok || len(groups) > 50 {
			return nil, valueErr("groups must be a list with no more than 50 entries")
		}
		clean := []any{}
		for _, g := range groups {
			s := pyStrip(pyStr(g))
			if usernameRE.MatchString(s) {
				clean = append(clean, s)
			}
		}
		if len(clean) != len(groups) {
			return nil, valueErr("group name is invalid")
		}
		out.Set("groups", clean)
	}
	if v, present := fields.Get("disabled"); present {
		out.Set("disabled", truthy(v))
	}
	return out, nil
}

func passwordFromRequest(req *pyyaml.Map) (string, error) {
	v := req.Value("password_plain")
	if v == nil {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", valueErr("password_plain must be a string")
	}
	return s, nil
}

func isEnabledSuperadmin(raw any) bool {
	u, ok := raw.(*pyyaml.Map)
	if !ok || truthy(getDefault(u, "disabled", false)) {
		return false
	}
	groups := u.Value("groups")
	if !truthy(groups) {
		groups = []any{}
	}
	list, ok := groups.([]any)
	if !ok {
		list = []any{groups}
	}
	for _, g := range list {
		if pyStrip(pyStr(g)) == "superadmin" {
			return true
		}
	}
	return false
}

func removesLastEnabledSuperadmin(users *pyyaml.Map, username string, replacement *pyyaml.Map) bool {
	if !isEnabledSuperadmin(users.Value(username)) {
		return false
	}
	if replacement != nil && isEnabledSuperadmin(replacement) {
		return false
	}
	other := false
	users.Each(func(k, v any) {
		if pyStr(k) != username && isEnabledSuperadmin(v) {
			other = true
		}
	})
	return !other
}

func (u *Usersd) handleList() (map[string]any, error) {
	_, users, err := u.loadUsersData()
	if err != nil {
		return nil, err
	}
	names := []string{}
	byName := map[string]any{}
	users.Each(func(k, v any) {
		names = append(names, pyStr(k))
		byName[pyStr(k)] = v
	})
	sort.Slice(names, func(i, j int) bool { return lessRunes(names[i], names[j]) })
	out := []any{}
	for _, n := range names {
		val := byName[n]
		if !truthy(val) {
			val = pyyaml.NewMap()
		}
		m, ok := val.(*pyyaml.Map)
		if !ok {
			continue
		}
		out = append(out, safeUserView(n, m))
	}
	return map[string]any{"ok": true, "users": out}, nil
}

func lessRunes(a, b string) bool {
	ra, rb := []rune(a), []rune(b)
	for i := 0; i < len(ra) && i < len(rb); i++ {
		if ra[i] != rb[i] {
			return ra[i] < rb[i]
		}
	}
	return len(ra) < len(rb)
}

func (u *Usersd) handleGet(req *pyyaml.Map) (map[string]any, error) {
	username, err := validatedUsername(req)
	if err != nil {
		return nil, err
	}
	_, users, err := u.loadUsersData()
	if err != nil {
		return nil, err
	}
	m, ok := users.Value(username).(*pyyaml.Map)
	if !ok {
		return map[string]any{"ok": false, "error": fmt.Sprintf("user '%s' not found", username)}, nil
	}
	return map[string]any{"ok": true, "user": safeUserView(username, m)}, nil
}

func (u *Usersd) handleUpdate(req *pyyaml.Map) (map[string]any, error) {
	username, err := validatedUsername(req)
	if err != nil {
		return nil, err
	}
	fields, err := validatedFields(req)
	if err != nil {
		return nil, err
	}
	password, err := passwordFromRequest(req)
	if err != nil {
		return nil, err
	}
	root, users, err := u.loadUsersData()
	if err != nil {
		return nil, err
	}
	usr, ok := users.Value(username).(*pyyaml.Map)
	if !ok {
		return map[string]any{"ok": false, "error": fmt.Sprintf("user '%s' not found", username)}, nil
	}
	prospective := pyyaml.DeepCopy(usr).(*pyyaml.Map)
	fields.Each(func(k, v any) { prospective.Set(k, v) })
	if removesLastEnabledSuperadmin(users, username, prospective) {
		return map[string]any{"ok": false, "error": "the last enabled superadmin cannot be disabled or demoted"}, nil
	}
	if _, present := usr.Get("groups"); !present {
		usr.Set("groups", []any{})
	}
	for _, key := range []string{"displayname", "email", "disabled", "groups"} {
		if v, present := fields.Get(key); present {
			usr.Set(key, v)
		}
	}
	if password != "" {
		hash, err := u.HashPassword(password)
		if err != nil {
			log.Printf("hash password failed: %v", err)
			return map[string]any{"ok": false, "error": "Could not hash the password: " + errText(err)}, nil
		}
		usr.Set("password", hash)
	}
	users.Set(username, usr)
	if err := u.saveUsersData(root); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "user": safeUserView(username, usr)}, nil
}

func (u *Usersd) handleCreate(req *pyyaml.Map) (map[string]any, error) {
	username, err := validatedUsername(req)
	if err != nil {
		return nil, err
	}
	fields, err := validatedFields(req)
	if err != nil {
		return nil, err
	}
	password, err := passwordFromRequest(req)
	if err != nil {
		return nil, err
	}
	if password == "" {
		return map[string]any{"ok": false, "error": "password_plain is required for create"}, nil
	}
	root, users, err := u.loadUsersData()
	if err != nil {
		return nil, err
	}
	if _, exists := users.Get(username); exists {
		return map[string]any{"ok": false, "error": fmt.Sprintf("user '%s' already exists", username)}, nil
	}
	hash, err := u.HashPassword(password)
	if err != nil {
		log.Printf("hash password failed: %v", err)
		return map[string]any{"ok": false, "error": "Could not hash the password: " + errText(err)}, nil
	}
	groups, _ := fields.Value("groups").([]any)
	if groups == nil {
		groups = []any{}
	}
	usr := pyyaml.NewMap()
	usr.Set("password", hash)
	usr.Set("displayname", orEmpty(getDefault(fields, "displayname", "")))
	usr.Set("email", orEmpty(getDefault(fields, "email", "")))
	usr.Set("groups", append([]any{}, groups...))
	usr.Set("disabled", truthy(getDefault(fields, "disabled", false)))
	users.Set(username, usr)
	if err := u.saveUsersData(root); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "user": safeUserView(username, usr)}, nil
}

func (u *Usersd) handleDelete(req *pyyaml.Map) (map[string]any, error) {
	username, err := validatedUsername(req)
	if err != nil {
		return nil, err
	}
	root, users, err := u.loadUsersData()
	if err != nil {
		return nil, err
	}
	deleted, exists := users.Get(username)
	if !exists {
		return map[string]any{"ok": false, "error": fmt.Sprintf("user '%s' not found", username)}, nil
	}
	if removesLastEnabledSuperadmin(users, username, nil) {
		return map[string]any{"ok": false, "error": "the last enabled superadmin cannot be deleted"}, nil
	}
	users.Delete(username)
	if err := u.saveUsersData(root); err != nil {
		return nil, err
	}
	dm, ok := deleted.(*pyyaml.Map)
	if !truthy(deleted) {
		dm = pyyaml.NewMap()
	} else if !ok {
		// Python saved the file, then failed building the reply.
		return nil, fmt.Errorf("'%s' object has no attribute 'get'", pyTypeName(deleted))
	}
	return map[string]any{"ok": true, "message": fmt.Sprintf("user '%s' deleted", username), "user": safeUserView(username, dm)}, nil
}

// HandleRequest is handle_request: ValueError becomes an error reply,
// anything else an "internal error" from the server loop.
func (u *Usersd) HandleRequest(reqAny any) (map[string]any, error) {
	req, ok := reqAny.(*pyyaml.Map)
	if !ok {
		return map[string]any{"ok": false, "error": "request must be a JSON object"}, nil
	}
	actionRaw := req.Value("action")
	if !truthy(actionRaw) {
		actionRaw = ""
	}
	actionStr, ok := actionRaw.(string)
	if !ok {
		return nil, fmt.Errorf("'%s' object has no attribute 'strip'", pyTypeName(actionRaw))
	}
	var resp map[string]any
	var err error
	switch action := pyStrip(actionStr); action {
	case "list":
		resp, err = u.handleList()
	case "get":
		resp, err = u.handleGet(req)
	case "update":
		resp, err = u.handleUpdate(req)
	case "create":
		resp, err = u.handleCreate(req)
	case "delete":
		resp, err = u.handleDelete(req)
	default:
		return map[string]any{"ok": false, "error": "unknown action: " + action}, nil
	}
	if err != nil && errKind(err) == "ValueError" {
		return map[string]any{"ok": false, "error": errText(err)}, nil
	}
	return resp, err
}

func (u *Usersd) serveConn(conn net.Conn) {
	defer conn.Close()
	var resp map[string]any
	func() {
		defer func() {
			if r := recover(); r != nil {
				resp = map[string]any{"ok": false, "error": fmt.Sprintf("internal error: %v", r)}
			}
		}()
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
		data := []byte{}
		buf := make([]byte, 4096)
		for !bytes.Contains(data, []byte("\n")) {
			n, err := conn.Read(buf)
			if n > 0 {
				data = append(data, buf[:n]...)
				if len(data) > usersMaxRequest {
					resp = map[string]any{"ok": false, "error": "internal error: request is too large"}
					return
				}
			}
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					resp = map[string]any{"ok": false, "error": "internal error: timed out"}
					return
				}
				break
			}
		}
		if len(data) == 0 {
			return
		}
		line := data
		if i := bytes.IndexByte(line, '\n'); i >= 0 {
			line = line[:i]
		}
		text := pyStrip(strings.ToValidUTF8(string(line), "�"))
		if text == "" {
			return
		}
		req, err := pyyaml.JSONLoads([]byte(text))
		if err != nil {
			resp = map[string]any{"ok": false, "error": "invalid json: " + jsonErrText(err)}
			return
		}
		_ = conn.SetDeadline(time.Time{})
		r, err := u.HandleRequest(req)
		if err != nil {
			log.Printf("request handling failed: %v", err)
			resp = map[string]any{"ok": false, "error": "internal error: " + errText(err)}
			return
		}
		resp = r
	}()
	if resp == nil {
		return
	}
	_ = conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	_, _ = conn.Write(replyJSON(resp))
}

// Serve accepts connections on ln one at a time until ctx is canceled or ln fails.
func (u *Usersd) Serve(ctx context.Context, ln net.Listener) error {
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		u.serveConn(conn)
	}
}

// RunUsersd is main(): serve the socket one request at a time.
func RunUsersd(opts UsersdOptions) error {
	u := NewUsersd(opts)
	if _, err := os.Stat(opts.SocketPath); err == nil {
		_ = os.Remove(opts.SocketPath)
	}
	ln, err := net.Listen("unix", opts.SocketPath)
	if err != nil {
		return err
	}
	if err := os.Chmod(opts.SocketPath, 0o660); err != nil {
		_ = ln.Close()
		_ = os.Remove(opts.SocketPath)
		return err
	}
	log.Printf("authelia-usersd listening on %s", opts.SocketPath)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	defer func() {
		_ = ln.Close()
		if _, err := os.Stat(opts.SocketPath); err == nil {
			_ = os.Remove(opts.SocketPath)
		}
	}()
	return u.Serve(ctx, ln)
}
