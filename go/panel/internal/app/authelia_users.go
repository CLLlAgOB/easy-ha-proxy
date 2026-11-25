package app

// Ports of the Authelia user and ban routes in routes.py and their services
// in services.py (authelia-usersd, authelia-bansd, the Authelia log reader).

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"easy-ha-proxy/panel/shared/pyyaml"
)

func envBounded(name string, def, lo, hi int64) int64 {
	v := def
	if raw, ok := os.LookupEnv(name); ok {
		if n, err := parsePyIntString(raw); err == nil {
			v = n
		}
	}
	return max(lo, min(v, hi))
}

var (
	autheliaBansCmd         = envStrip("AUTHELIA_BANS_CMD", "/usr/local/sbin/authelia-bans.sh")
	autheliaBansSocket      = envStrip("AUTHELIA_BANS_SOCKET", "")
	autheliaBansTimeout     = envBounded("AUTHELIA_BANS_SOCKET_TIMEOUT", 10, 2, 60)
	autheliaBansMaxResponse = envBounded("AUTHELIA_BANS_MAX_RESPONSE_BYTES", 2*1024*1024, 4096, 16*1024*1024)
	autheliaLogFile         = envStrip("AUTHELIA_LOG_FILE", "")
	autheliaLogLimit        = envBounded("AUTHELIA_LOG_LIMIT", 200, 1, 1000)
	autheliaLogMaxScan      = envBounded("AUTHELIA_LOG_MAX_SCAN_BYTES", 16*1024*1024, 64*1024, 128*1024*1024)
	autheliaUsersSocket     = envStrip("AUTHELIA_USERS_SOCKET", "/run/easy-ha-proxy/authelia-usersd.sock")
	autheliaUsersTimeout    = envBounded("AUTHELIA_USERS_SOCKET_TIMEOUT", 10, 2, 60)
	autheliaUsersMaxResp    = envBounded("AUTHELIA_USERS_MAX_RESPONSE_BYTES", 2*1024*1024, 4096, 16*1024*1024)

	autheliaUsernameRe = regexp.MustCompile(`^[a-zA-Z0-9._@-]+$`)
	autheliaIPCIDRRe   = regexp.MustCompile(`^[0-9a-fA-F:./]+$`)
)

// pyIsSpace is str.isspace for one character.
func pyIsSpace(r rune) bool {
	return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f)
}

func pyStripSpace(s string) string { return strings.TrimFunc(s, pyIsSpace) }

// jsonLineCall is the shared body of _call_authelia_usersd and _call_authelia_bansd:
// connect within 2 s, one JSON line each way, any failure as {"ok": False, "error": str(exc)}.
func jsonLineCall(socketPath string, payload *Map, timeout time.Duration, maxResponse int64, name string) *Map {
	text, err := PyJSON(payload, JSONOpts{})
	if err != nil {
		return newMap("ok", false, "error", err.Error())
	}
	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		return newMap("ok", false, "error", pyOSError(err))
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(text + "\n")); err != nil {
		return newMap("ok", false, "error", pyOSError(err))
	}
	var buf []byte
	chunk := make([]byte, 4096)
	for !bytes.Contains(buf, []byte("\n")) {
		n, err := conn.Read(chunk)
		buf = append(buf, chunk[:n]...)
		if int64(len(buf)) > maxResponse {
			return newMap("ok", false, "error", "reply from "+name+" is too large")
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return newMap("ok", false, "error", pyOSError(err))
		}
	}
	if len(buf) == 0 {
		if name == "authelia-usersd" {
			return newMap("ok", false, "error", "empty reply from authelia-usersd")
		}
		return newMap("ok", false, "error", "empty reply from daemon")
	}
	line, _, _ := bytes.Cut(buf, []byte("\n"))
	v, err := pyyaml.JSONLoads(line)
	if err != nil {
		return newMap("ok", false, "error", err.Error())
	}
	m, ok := asMap(v)
	if !ok {
		return newMap("ok", false, "error", "invalid reply from "+name)
	}
	return m
}

func callUsersd(payload *Map) *Map {
	if autheliaUsersSocket == "" {
		return newMap("ok", false, "error", "AUTHELIA_USERS_SOCKET not set")
	}
	return jsonLineCall(autheliaUsersSocket, payload, time.Duration(autheliaUsersTimeout)*time.Second, autheliaUsersMaxResp, "authelia-usersd")
}

func callBansd(action string, kv ...any) *Map {
	if autheliaBansSocket == "" {
		return newMap("ok", false, "error", "AUTHELIA_BANS_SOCKET not set")
	}
	req := newMap(append([]any{"action", action}, kv...)...)
	return jsonLineCall(autheliaBansSocket, req, time.Duration(autheliaBansTimeout)*time.Second, autheliaBansMaxResponse, "authelia-bansd")
}

func usersdError(resp *Map, def string) string {
	return pyStr(orValue(resp.Value("error"), def))
}

func normalizeGroups(v any) []any {
	g := orValue(v, []any{})
	if l, ok := asList(g); ok {
		out := make([]any, len(l))
		for i, x := range l {
			out[i] = pyStr(x)
		}
		return out
	}
	return []any{pyStr(g)}
}

func getOr(m *Map, key string, def any) any {
	if v, ok := m.Get(key); ok {
		return v
	}
	return def
}

// GetAutheliaUsers is get_authelia_users: (users, all_groups, error).
func GetAutheliaUsers() ([]any, []any, any) {
	resp := callUsersd(newMap("action", "list"))
	if !truthy(resp.Value("ok")) {
		return []any{}, []any{}, usersdError(resp, "authelia-usersd list failed")
	}
	users, ok := asList(orValue(resp.Value("users"), []any{}))
	if !ok {
		users = nil
	}
	seen := map[string]bool{}
	var all []string
	out := []any{}
	for _, it := range users {
		u, ok := asMap(it)
		if !ok {
			continue
		}
		groups := normalizeGroups(u.Value("groups"))
		for _, g := range groups {
			if s := g.(string); !seen[s] {
				seen[s] = true
				all = append(all, s)
			}
		}
		out = append(out, newMap("username", pyStr(getOr(u, "username", "")), "displayname", orValue(getOr(u, "displayname", ""), ""),
			"email", orValue(getOr(u, "email", ""), ""), "groups", groups, "disabled", truthy(getOr(u, "disabled", false))))
	}
	sort.Strings(all)
	allAny := make([]any, len(all))
	for i, s := range all {
		allAny[i] = s
	}
	return out, allAny, nil
}

// GetAutheliaUser is get_authelia_user: (user, error).
func GetAutheliaUser(username string) (*Map, string) {
	username = strings.TrimFunc(username, pyIsSpace)
	if username == "" {
		return nil, "username is required"
	}
	resp := callUsersd(newMap("action", "get", "username", username))
	if !truthy(resp.Value("ok")) {
		return nil, usersdError(resp, "authelia-usersd get failed")
	}
	u, ok := asMap(orValue(resp.Value("user"), newMap()))
	if !ok {
		return nil, "invalid user payload from authelia-usersd"
	}
	return newMap("username", pyStr(getOr(u, "username", username)), "displayname", orValue(getOr(u, "displayname", ""), ""),
		"email", orValue(getOr(u, "email", ""), ""), "groups", normalizeGroups(u.Value("groups")), "disabled", truthy(getOr(u, "disabled", false))), ""
}

func usersdWrite(action, username string, fields *Map, password string, hasPassword bool) string {
	username = strings.TrimFunc(username, pyIsSpace)
	if username == "" {
		return "username is required"
	}
	payload := newMap("action", action, "username", username, "fields", fields)
	if hasPassword {
		payload.Set("password_plain", password)
	}
	resp := callUsersd(payload)
	if !truthy(resp.Value("ok")) {
		return usersdError(resp, "authelia-usersd "+action+" failed")
	}
	if _, ok := asMap(orValue(resp.Value("user"), newMap())); !ok {
		return "invalid user payload from authelia-usersd"
	}
	return ""
}

func deleteAutheliaUser(username string) string {
	username = strings.TrimFunc(username, pyIsSpace)
	if username == "" {
		return "username is required"
	}
	resp := callUsersd(newMap("action", "delete", "username", username))
	if !truthy(resp.Value("ok")) {
		return usersdError(resp, "authelia-usersd delete failed")
	}
	return ""
}

// ---- bans ----

func autheliaBansError(resp *Map) string {
	errText := pyStripSpace(pyStr(orValue(resp.Value("error"), "authelia-bansd error")))
	var details []string
	for _, kl := range [][2]string{{"rc_users", "users"}, {"rc_ips", "ips"}} {
		v := resp.Value(kl[0])
		if v == nil || pyEqual(v, int64(0)) || v == "0" {
			continue
		}
		details = append(details, kl[1]+" rc="+pyStr(v))
	}
	for _, kl := range [][2]string{{"stderr_users", "users"}, {"stderr_ips", "ips"}, {"stdout_users", "users output"}, {"stdout_ips", "ips output"}} {
		v := strings.Join(strings.FieldsFunc(pyStr(orValue(resp.Value(kl[0]), "")), pyIsSpace), " ")
		if v != "" {
			details = append(details, kl[1]+": "+truncRunes(v, 1000))
		}
	}
	if len(details) > 0 {
		return errText + ": " + strings.Join(details, "; ")
	}
	return errText
}

func parseAutheliaBanList(output any, subjectHeader string) ([]any, string) {
	text := pyStripSpace(pyStr(orValue(output, "")))
	if text == "" {
		return []any{}, ""
	}
	if strings.TrimRight(strings.ToLower(text), ".") == "no results" {
		return []any{}, ""
	}
	var lines [][]rune
	for _, l := range pySplitlines(text) {
		if pyStripSpace(l) != "" {
			lines = append(lines, []rune(strings.TrimRightFunc(l, pyIsSpace)))
		}
	}
	if len(lines) < 2 {
		return []any{}, text
	}
	header := lines[0]
	var starts []int
	var words []string
	for i := 0; i < len(header); {
		if pyIsSpace(header[i]) {
			i++
			continue
		}
		j := i
		for j < len(header) && !pyIsSpace(header[j]) {
			j++
		}
		starts = append(starts, i)
		words = append(words, strings.ToLower(string(header[i:j])))
		i = j
	}
	expected := []string{"id", strings.ToLower(subjectHeader), "expires", "source", "reason"}
	if strings.Join(words, "\x00") != strings.Join(expected, "\x00") {
		return []any{}, text
	}
	entries := []any{}
	for _, line := range lines[1:] {
		values := make([]string, len(starts))
		for i, st := range starts {
			end := len(line)
			if i+1 < len(starts) {
				end = min(starts[i+1], len(line))
			}
			if st > len(line) {
				st = len(line)
			}
			if end < st {
				end = st
			}
			values[i] = pyStripSpace(string(line[st:end]))
		}
		if len(values) != 5 || values[0] == "" || values[1] == "" {
			return []any{}, text
		}
		entries = append(entries, newMap("id", values[0], "subject", values[1], "expires", values[2], "source", values[3], "reason", values[4]))
	}
	return entries, ""
}

func autheliaBansResult(usersOut, ipsOut any) *Map {
	users, usersRaw := parseAutheliaBanList(usersOut, "Username")
	ips, ipsRaw := parseAutheliaBanList(ipsOut, "IP")
	return newMap("users", users, "ips", ips, "users_raw", usersRaw, "ips_raw", ipsRaw, "error", nil)
}

func emptyBans(errText string) *Map {
	return newMap("users", []any{}, "ips", []any{}, "users_raw", "", "ips_raw", "", "error", errText)
}

func cmdFailed(out string) bool {
	return strings.HasPrefix(out, "Command failed") || strings.HasPrefix(out, "Command timed out")
}

// GetAutheliaBans is get_authelia_bans.
func GetAutheliaBans() *Map {
	if autheliaBansSocket != "" {
		resp := callBansd("list")
		if !truthy(resp.Value("ok")) {
			return emptyBans(autheliaBansError(resp))
		}
		return autheliaBansResult(getOr(resp, "users", ""), getOr(resp, "ips", ""))
	}
	if autheliaBansCmd == "" {
		return emptyBans("AUTHELIA_BANS_CMD is not configured")
	}
	helper, err := shlexSplit(autheliaBansCmd)
	if err != nil {
		panic(err)
	}
	users := RunCmd(append(append([]string{}, helper...), "list-users"))
	ips := RunCmd(append(append([]string{}, helper...), "list-ips"))
	var parts []string
	if cmdFailed(users) {
		parts = append(parts, "users: "+users)
		users = ""
	}
	if cmdFailed(ips) {
		parts = append(parts, "ips: "+ips)
		ips = ""
	}
	if len(parts) > 0 {
		return emptyBans(strings.Join(parts, "\n"))
	}
	return autheliaBansResult(users, ips)
}

func autheliaUnban(kind, value string) (string, int) {
	if autheliaBansSocket != "" {
		var resp *Map
		if kind == "user" {
			resp = callBansd("revoke-user", "username", value)
		} else {
			resp = callBansd("revoke-ip", "ip", value)
		}
		if !truthy(resp.Value("ok")) {
			return pyStr(getOr(resp, "error", "authelia-bansd daemon error")), 500
		}
		def := "User unbanned (if a ban existed)"
		if kind == "ip" {
			def = "IP unbanned (if a ban existed)"
		}
		return pyStr(orValue(resp.Value("message"), def)), 200
	}
	if autheliaBansCmd == "" {
		return "AUTHELIA_BANS_CMD is not configured", 500
	}
	helper, err := shlexSplit(autheliaBansCmd)
	if err != nil {
		panic(err)
	}
	out := RunCmd(append(helper, "revoke-"+kind, value))
	if cmdFailed(out) {
		return out, 500
	}
	if kind == "user" {
		return "User unbanned (if a ban existed)", 200
	}
	return "IP unbanned (if a ban existed)", 200
}

func autheliaUnbanUser(username string) (string, int) {
	username = strings.TrimFunc(username, pyIsSpace)
	if username == "" {
		return "Empty username", 400
	}
	if !autheliaUsernameRe.MatchString(username) {
		return "Invalid characters in username", 400
	}
	return autheliaUnban("user", username)
}

func autheliaUnbanIP(ip string) (string, int) {
	ip = strings.TrimFunc(ip, pyIsSpace)
	if ip == "" {
		return "IP is required", 400
	}
	if !autheliaIPCIDRRe.MatchString(ip) {
		return "Invalid IP/CIDR", 400
	}
	if _, ok := pyIPNetwork(ip); !ok {
		return "Invalid IP/CIDR", 400
	}
	return autheliaUnban("ip", ip)
}

// ---- Authelia log ----

// shlexSplit is shlex.split(s) (POSIX mode, no comments).
func shlexSplit(s string) ([]string, error) {
	var out []string
	var tok strings.Builder
	inTok := false
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			if inTok {
				out = append(out, tok.String())
				tok.Reset()
				inTok = false
			}
		case c == '\\':
			if i+1 >= len(rs) {
				return nil, &ValueError{"No escaped character"}
			}
			i++
			tok.WriteRune(rs[i])
			inTok = true
		case c == '\'':
			inTok = true
			j := i + 1
			for j < len(rs) && rs[j] != '\'' {
				j++
			}
			if j >= len(rs) {
				return nil, &ValueError{"No closing quotation"}
			}
			tok.WriteString(string(rs[i+1 : j]))
			i = j
		case c == '"':
			inTok = true
			j := i + 1
			for ; j < len(rs) && rs[j] != '"'; j++ {
				if rs[j] == '\\' {
					if j+1 >= len(rs) {
						return nil, &ValueError{"No closing quotation"}
					}
					if rs[j+1] == '"' || rs[j+1] == '\\' {
						j++
						tok.WriteRune(rs[j])
						continue
					}
				}
				tok.WriteRune(rs[j])
			}
			if j >= len(rs) {
				return nil, &ValueError{"No closing quotation"}
			}
			i = j
		default:
			tok.WriteRune(c)
			inTok = true
		}
	}
	if inTok {
		out = append(out, tok.String())
	}
	return out, nil
}

// autheliaLogLinesReverse is _iter_authelia_log_lines_reverse.
func autheliaLogLinesReverse(f *os.File, yield func(string) bool) error {
	end, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	position := end
	remaining := min(position, autheliaLogMaxScan)
	const chunk = 64 * 1024
	var pending []byte
	for position > 0 && remaining > 0 {
		size := min(chunk, position, remaining)
		position -= size
		remaining -= size
		block := make([]byte, size)
		if _, err := f.ReadAt(block, position); err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		block = append(block, pending...)
		parts := bytes.Split(block, []byte("\n"))
		pending = parts[0]
		for k := len(parts) - 1; k >= 1; k-- {
			if len(parts[k]) > 0 {
				if !yield(strings.TrimRight(pyDecodeReplace(parts[k]), "\r")) {
					return nil
				}
			}
		}
	}
	if position == 0 && len(pending) > 0 {
		yield(strings.TrimRight(pyDecodeReplace(pending), "\r"))
	}
	return nil
}

func parseAutheliaTextLogLine(line string) *Map {
	if !strings.Contains(line, "=") {
		return newMap()
	}
	tokens, err := shlexSplit(line)
	if err != nil {
		return newMap()
	}
	res := newMap()
	for _, t := range tokens {
		k, v, ok := strings.Cut(t, "=")
		if ok && k != "" {
			res.Set(k, v)
		}
	}
	if has(res, "time") || has(res, "level") || has(res, "msg") {
		return res
	}
	return newMap()
}

func parseAutheliaLogLine(line string) *Map {
	var parsed *Map
	if v, err := pyyaml.JSONLoads([]byte(line)); err == nil {
		if m, ok := asMap(v); ok {
			parsed = m
		} else {
			parsed = newMap()
		}
	} else {
		parsed = parseAutheliaTextLogLine(line)
	}
	parsed.Set("raw", line)
	return parsed
}

func autheliaLogText(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case *Map, []any, bool, int64, int, float64:
		if s, err := PyJSON(x, JSONOpts{SortKeys: true}); err == nil {
			return s
		}
	}
	return pyStr(v)
}

var autheliaLogPrimary = map[string]bool{"time": true, "level": true, "remote_ip": true, "method": true, "path": true,
	"username": true, "msg": true, "error": true, "raw": true}

func autheliaLogEntry(data *Map, line string) *Map {
	type detail struct{ name, value string }
	var details []detail
	data.Each(func(k, v any) {
		name := pyStr(k)
		if autheliaLogPrimary[name] || v == nil || v == "" {
			return
		}
		details = append(details, detail{name, autheliaLogText(v)})
	})
	rank := func(n string) int {
		if n == "provider" || n == "providers" {
			return 0
		}
		return 1
	}
	sort.SliceStable(details, func(i, j int) bool {
		if ri, rj := rank(details[i].name), rank(details[j].name); ri != rj {
			return ri < rj
		}
		return details[i].name < details[j].name
	})
	dl := make([]any, len(details))
	for i, d := range details {
		dl[i] = newMap("name", d.name, "value", d.value)
	}
	e := newMap()
	for _, k := range []string{"time", "level", "remote_ip", "method", "path", "username", "msg", "error"} {
		e.Set(k, autheliaLogText(data.Value(k)))
	}
	e.Set("details", dl)
	e.Set("raw", line)
	return e
}

// GetAutheliaLogs is get_authelia_logs.
func GetAutheliaLogs(ip, username, level string) ([]any, any) {
	if autheliaLogFile == "" {
		return []any{}, "AUTHELIA_LOG_FILE is not configured (no path to Authelia logs)"
	}
	limit := autheliaLogLimit
	st, err := os.Stat(autheliaLogFile)
	if err != nil {
		return []any{}, "Cannot access Authelia log file: " + pyFileError(err, autheliaLogFile)
	}
	if st.Size() == 0 {
		return []any{}, nil
	}
	ip = pyStripSpace(ip)
	username = pyStripSpace(username)
	level = strings.ToLower(pyStripSpace(level))
	userFolded := strings.ToLower(username)
	entries := []any{}
	f, err := os.Open(autheliaLogFile)
	if err != nil {
		return []any{}, "Cannot read Authelia log file: " + pyFileError(err, autheliaLogFile)
	}
	defer f.Close()
	err = autheliaLogLinesReverse(f, func(line string) bool {
		if pyStripSpace(line) == "" {
			return true
		}
		entry := autheliaLogEntry(parseAutheliaLogLine(line), line)
		if level != "" && strings.ToLower(entry.Value("level").(string)) != level {
			return true
		}
		if ip != "" {
			remote := pyStripSpace(entry.Value("remote_ip").(string))
			if remote != "" {
				if ip != remote {
					return true
				}
			} else if !strings.Contains(line, ip) {
				return true
			}
		}
		if userFolded != "" {
			searchable := strings.ToLower(entry.Value("username").(string) + "\n" + entry.Value("msg").(string) + "\n" + entry.Value("error").(string))
			if !strings.Contains(searchable, userFolded) {
				return true
			}
		}
		entries = append(entries, entry)
		return int64(len(entries)) < limit
	})
	if err != nil {
		return []any{}, "Cannot read Authelia log file: " + pyFileError(err, autheliaLogFile)
	}
	return entries, nil
}

// ---- routes ----

func sortedUnique(items []string) []any {
	seen := map[string]bool{}
	var out []string
	for _, s := range items {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	res := make([]any, len(out))
	for i, s := range out {
		res[i] = s
	}
	return res
}

func (a *App) registerAutheliaUsers() {
	a.Handle("routes.authelia_users", func(c *Ctx) error {
		users, all, errV := GetAutheliaUsers()
		msg := c.QueryStr("msg")
		return c.Render("authelia_users.html", map[string]any{"users": users, "all_groups": all, "error": errV, "message": msg})
	})
	a.Handle("routes.authelia_user_new", func(c *Ctx) error {
		_, all, usersErr := GetAutheliaUsers()
		if c.R.Method == http.MethodGet {
			return c.Render("authelia_user_new.html", map[string]any{"all_groups": all, "error": usersErr})
		}
		username := c.FormStrip("username")
		displayname := c.FormStrip("displayname")
		email := c.FormStrip("email")
		selected := c.FormList("groups")
		extraRaw := c.FormStrip("groups_extra")
		groups := append([]string{}, selected...)
		for _, g := range strings.Split(extraRaw, ",") {
			if t := strip(g); t != "" {
				groups = append(groups, t)
			}
		}
		groupList := sortedUnique(groups)
		password, _ := c.Form("password")
		password2, _ := c.Form("password2")
		selAny := make([]any, len(selected))
		for i, s := range selected {
			selAny[i] = s
		}
		form := newMap("username", username, "displayname", displayname, "email", email, "selected_groups", selAny, "groups_extra", extraRaw)
		fail := func(msg string) error {
			return c.Render("authelia_user_new.html", map[string]any{"error": msg, "form": form, "all_groups": all})
		}
		switch {
		case username == "":
			return fail("Enter the username")
		case displayname == "":
			return fail("Enter the user display name")
		case email == "":
			return fail("Enter the user email")
		case password == "":
			return fail("Enter a password")
		case password != password2:
			return fail("Password and confirmation do not match")
		}
		fields := newMap("displayname", displayname, "email", email, "disabled", false, "groups", groupList)
		if e := usersdWrite("create", username, fields, password, true); e != "" {
			c.RecordRequest("user.create", AuditEntry{ObjectType: "user", ObjectID: username, Result: auditResultFailure, Detail: e})
			return fail("Creation error: " + e)
		}
		after := copyMap(fields)
		after.Set("password", "set")
		c.RecordRequest("user.create", AuditEntry{ObjectType: "user", ObjectID: username, Summary: AuditSummarize(newMap(), after)})
		return c.Redirect(c.URLFor("routes.authelia_users", "msg", "User "+username+" created"), 303)
	})
	a.Handle("routes.authelia_user_edit", func(c *Ctx) error {
		username := strings.TrimFunc(c.Args["username"], pyIsSpace)
		if username == "" {
			return c.Redirect(c.URLFor("routes.authelia_users", "msg", "Empty username"), 302)
		}
		if c.R.Method == http.MethodPost {
			displayname := c.FormStrip("displayname")
			email := c.FormStrip("email")
			dis, _ := c.Form("disabled")
			disabled := dis != ""
			groups := append([]string{}, c.FormList("groups")...)
			if extra := c.FormStrip("groups_extra"); extra != "" {
				for _, g := range strings.Split(extra, ",") {
					g = strip(g)
					if g != "" && !containsStr(groups, g) {
						groups = append(groups, g)
					}
				}
			}
			groupList := sortedUnique(groups)
			password, _ := c.Form("password")
			confirm, _ := c.Form("password2")
			var required []string
			if displayname == "" {
				required = append(required, "Enter the user display name.")
			}
			if email == "" {
				required = append(required, "Enter the user email.")
			}
			if password != confirm {
				required = append(required, "Password and confirmation do not match")
			}
			renderErr := func(errV any) error {
				_, all, _ := GetAutheliaUsers()
				names := make([]string, 0, len(all)+len(groupList))
				for _, g := range all {
					names = append(names, g.(string))
				}
				for _, g := range groupList {
					if !containsStr(names, g.(string)) {
						names = append(names, g.(string))
					}
				}
				sort.Strings(names)
				allAny := make([]any, len(names))
				for i, s := range names {
					allAny[i] = s
				}
				user := newMap("username", username, "displayname", displayname, "email", email, "groups", groupList, "disabled", disabled)
				return c.Render("authelia_user_edit.html", map[string]any{"user": user, "all_groups": allAny, "error": errV, "is_new": false})
			}
			if len(required) > 0 {
				return renderErr(strings.Join(required, " "))
			}
			fields := newMap("displayname", displayname, "email", email, "disabled", disabled, "groups", groupList)
			previous, _ := GetAutheliaUser(username)
			if previous == nil {
				previous = newMap()
			}
			before := newMap()
			for _, k := range []string{"displayname", "email", "disabled", "groups"} {
				before.Set(k, previous.Value(k))
			}
			after := copyMap(fields)
			if password != "" {
				before.Set("password", "kept")
				after.Set("password", "changed")
			}
			if e := usersdWrite("update", username, fields, password, password != ""); e != "" {
				c.RecordRequest("user.update", AuditEntry{ObjectType: "user", ObjectID: username, Result: auditResultFailure, Detail: e})
				return renderErr(e)
			}
			c.RecordRequest("user.update", AuditEntry{ObjectType: "user", ObjectID: username, Summary: AuditSummarize(before, after)})
			return c.Redirect(c.URLFor("routes.authelia_users", "msg", "User "+username+" updated"), 303)
		}
		user, e := GetAutheliaUser(username)
		if e != "" {
			return c.Redirect(c.URLFor("routes.authelia_users", "msg", e), 302)
		}
		_, all, _ := GetAutheliaUsers()
		return c.Render("authelia_user_edit.html", map[string]any{"user": user, "all_groups": all, "error": nil, "is_new": false})
	})
	a.Handle("routes.authelia_user_delete", func(c *Ctx) error {
		username := strings.TrimFunc(c.Args["username"], pyIsSpace)
		if username == "" {
			return c.Redirect(c.URLFor("routes.authelia_users", "msg", "Empty username"), 302)
		}
		if username == strings.TrimFunc(c.User(), pyIsSpace) {
			return c.Redirect(c.URLFor("routes.authelia_users", "msg", "The currently authenticated user cannot be deleted"), 303)
		}
		if e := deleteAutheliaUser(username); e != "" {
			c.RecordRequest("user.delete", AuditEntry{ObjectType: "user", ObjectID: username, Result: auditResultFailure, Detail: e})
			return c.Redirect(c.URLFor("routes.authelia_users", "msg", "Deletion error: "+username+": "+e), 302)
		}
		c.RecordRequest("user.delete", AuditEntry{ObjectType: "user", ObjectID: username})
		return c.Redirect(c.URLFor("routes.authelia_users", "msg", "User "+username+" deleted"), 303)
	})
	a.Handle("routes.authelia_bans", func(c *Ctx) error {
		logIP := truncRunes(pyStripSpace(c.QueryStr("log_ip")), 256)
		logUser := truncRunes(pyStripSpace(c.QueryStr("log_user")), 256)
		logLevel := truncRunes(pyStripSpace(c.QueryStr("log_level")), 64)
		if c.R.Method == http.MethodPost {
			action, _ := c.Form("action")
			target := ""
			var message string
			var code int
			switch action {
			case "unban_user":
				target, _ = c.Form("username")
				message, code = autheliaUnbanUser(target)
			case "unban_ip":
				target, _ = c.Form("ip")
				message, code = autheliaUnbanIP(target)
			default:
				message, code = "Unknown unban action", 400
			}
			if action == "unban_user" || action == "unban_ip" {
				objType := "ip"
				if action == "unban_user" {
					objType = "user"
				}
				detail := ""
				if code != 200 {
					detail = truncRunes(message, 500)
				}
				c.RecordRequest("authelia_ban.lift", AuditEntry{ObjectType: objType, ObjectID: target, Result: recordResult(code == 200), Detail: detail})
			}
			cat := "error"
			if code == 200 {
				cat = "success"
			}
			c.Flash(message, cat)
			var args []any
			for _, kv := range [][2]string{{"log_ip", logIP}, {"log_user", logUser}, {"log_level", logLevel}} {
				if kv[1] != "" {
					args = append(args, kv[0], kv[1])
				}
			}
			return c.Redirect(c.URLFor("routes.authelia_bans", args...), 303)
		}
		// The ban list comes from authelia-bansd, the log from a file: read both at once.
		var bans *Map
		var logs []any
		var logsErr any
		concurrently(func() { bans = GetAutheliaBans() },
			func() { logs, logsErr = GetAutheliaLogs(logIP, logUser, logLevel) })
		return c.Render("authelia_bans.html", map[string]any{"bans": bans, "bans_error": bans.Value("error"), "logs": logs,
			"logs_error": logsErr, "log_ip": logIP, "log_user": logUser, "log_level": logLevel})
	})
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
