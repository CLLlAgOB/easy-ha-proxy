package app

// Port of the runtime half of services.py (ban/err tables, the allow lists,
// sessions, backend states, threat analytics), cache.get_country_code and
// services_runtime.py.

import (
	"encoding/csv"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	"easy-ha-proxy/panel/internal/geoip"
)

// ---- cache.get_country_code ----

var countryReader = geoip.NewReader(envOr("HAPROXY_ADMIN_GEOIP_DB", "/etc/haproxy/geoip/current/dbip-country-lite.mmdb"))

func mustPrefixes(list ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(list))
	for i, s := range list {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// Python 3.12's ipaddress tables of what is not globally reachable.
var (
	v4Private = mustPrefixes("0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.0.170/31", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "240.0.0.0/4", "255.255.255.255/32")
	v4PrivateExceptions = mustPrefixes("192.0.0.9/32", "192.0.0.10/32")
	v4Shared            = netip.MustParsePrefix("100.64.0.0/10")
	v6Private           = mustPrefixes("::1/128", "::/128", "::ffff:0:0/96", "64:ff9b:1::/48", "100::/64", "2001::/23",
		"2001:db8::/32", "2002::/16", "3fff::/20", "fc00::/7", "fe80::/10")
	v6PrivateExceptions = mustPrefixes("2001:1::1/128", "2001:1::2/128", "2001:3::/32", "2001:4:112::/48",
		"2001:20::/28", "2001:30::/28")
)

func inAny(a netip.Addr, list []netip.Prefix) bool {
	for _, p := range list {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// pyIsGlobal is ipaddress' is_global (Python 3.12).
func pyIsGlobal(a netip.Addr) bool {
	a = a.WithZone("")
	if a.Is4In6() {
		a = a.Unmap()
	}
	if a.Is4() {
		private := inAny(a, v4Private) && !inAny(a, v4PrivateExceptions)
		return !v4Shared.Contains(a) && !private
	}
	return !(inAny(a, v6Private) && !inAny(a, v6PrivateExceptions))
}

// getCountryCode is cache.get_country_code: an uppercase ISO code, or "??".
func getCountryCode(ip string) string {
	a, ok := pyIPAddress(pyStripSpace(ip))
	if !ok {
		return "??"
	}
	if a.Is4In6() {
		a = a.Unmap()
	}
	if !pyIsGlobal(a) {
		return "??"
	}
	iso, found := countryReader.CountryISO(a.String())
	if !found {
		return "??"
	}
	if iso == nil {
		return "??"
	}
	code := strings.ToUpper(pyStripSpace(pyStr(iso)))
	rs := []rune(code)
	if len(rs) == 2 && unicode.IsLetter(rs[0]) && unicode.IsLetter(rs[1]) {
		return code
	}
	return "??"
}

// ---- stick tables ----

var (
	tablesMu      sync.Mutex
	tableCache    = newMap("ban", nil, "err", nil)
	cacheTime     time.Time
	banTableCache = newMap("ban", nil)
	banCacheTime  time.Time

	tableNameRe1 = regexp.MustCompile(`\btable:\s*([^\s,]+)`)
	tableNameRe2 = regexp.MustCompile(`\btable=([^\s,]+)`)
)

var adaptiveBanCodes = []string{"40", "41"}

func runtimeCmd(command string) (string, error) {
	return HAProxyRuntimeCommand(command, SOCKET, 2*time.Second)
}

func listAllTables() ([]string, error) {
	out, err := runtimeCmd("show table")
	if err != nil {
		return nil, err
	}
	names := map[string]bool{}
	for _, ln := range pySplitlines(out) {
		ln = pyStripSpace(ln)
		if ln == "" || (strings.HasPrefix(ln, "#") && !strings.Contains(ln, "table")) {
			continue
		}
		m := tableNameRe1.FindStringSubmatch(ln)
		if m == nil {
			m = tableNameRe2.FindStringSubmatch(ln)
		}
		if m != nil {
			names[m[1]] = true
		}
	}
	return sortedKeys(names), nil
}

func listErrTables() ([]string, error) {
	all, err := listAllTables()
	if err != nil {
		return nil, err
	}
	var errs []string
	has := false
	for _, n := range all {
		if n == "tbl_err_nosni" || strings.HasPrefix(n, "tbl_err_") {
			errs = append(errs, n)
		}
		has = has || n == "tbl_err"
	}
	if len(errs) == 0 && has {
		errs = []string{"tbl_err"}
	}
	sort.Strings(errs)
	return errs, nil
}

func tableRows(t any) []any {
	l, _ := asList(get(t, "rows"))
	return l
}

func rowAt(row any, i int) any {
	l, _ := asList(row)
	if i < len(l) {
		return l[i]
	}
	return nil
}

func rowLen(row any) int {
	l, _ := asList(row)
	return len(l)
}

func intStr(v any) int64 {
	n, err := parsePyIntString(pyStr(v))
	if err != nil {
		return 0
	}
	return n
}

func aggregateErrTables(tables []any) *Map {
	type acc struct{ cnt, exp int64 }
	var order []string
	byIP := map[string]*acc{}
	for _, t := range tables {
		if !truthy(t) || !truthy(get(t, "rows")) {
			continue
		}
		for _, row := range tableRows(t) {
			ip := pyStr(rowAt(row, 0))
			cur := byIP[ip]
			if cur == nil {
				cur = &acc{}
				byIP[ip] = cur
				order = append(order, ip)
			}
			cur.cnt += intStr(rowAt(row, 1))
			cur.exp = max(cur.exp, intStr(rowAt(row, 2)))
		}
	}
	sort.SliceStable(order, func(i, j int) bool { return byIP[order[i]].cnt > byIP[order[j]].cnt })
	if len(order) > 50 {
		order = order[:50]
	}
	rows := []any{}
	for _, ip := range order {
		rows = append(rows, []any{ip, byIP[ip].cnt, byIP[ip].exp})
	}
	return newMap("headers", strList("IP Address", "Error Count", "Expires"), "rows", rows,
		"meta", newMap("name", "tbl_err_all", "used", int64(len(rows)), "size", int64(len(rows))))
}

// applyAdaptiveExpiry is _apply_adaptive_expiry: an adaptive ban's real end.
func applyAdaptiveExpiry(ban *Map) error {
	if ban == nil || !truthy(ban.Value("rows")) {
		return nil
	}
	rows := tableRows(ban)
	any40 := false
	for _, row := range rows {
		if rowLen(row) >= 4 && pick(adaptiveBanCodes, pyStr(rowAt(row, 2)), "") != "" {
			any40 = true
		}
	}
	if !any40 {
		return nil
	}
	schedule, err := guarddBanSchedule()
	if err != nil {
		return nil
	}
	if !truthy(schedule.Value("enforcing")) {
		return nil
	}
	held := orValue(schedule.Value("bans"), newMap())
	heldMap, ok := asMap(held)
	if !ok {
		return noAttr(held, "get")
	}
	now, err := intOr0(schedule.Value("now"))
	if err != nil {
		return err
	}
	fromSchedule := []any{}
	for _, row := range rows {
		if rowLen(row) < 4 || pick(adaptiveBanCodes, pyStr(rowAt(row, 2)), "") == "" {
			continue
		}
		until := heldMap.Value(pyStr(rowAt(row, 0)))
		if !truthy(until) || now == 0 {
			continue
		}
		n, err := pyInt(until)
		if err != nil {
			return err
		}
		l, _ := asList(row)
		l[3] = strconv.FormatInt(max(0, n-now), 10)
		fromSchedule = append(fromSchedule, rowAt(row, 0))
	}
	meta, ok := asMap(ban.Value("meta"))
	if !ok {
		meta = newMap()
		ban.Set("meta", meta)
	}
	meta.Set("expiry_from_schedule", fromSchedule)
	return nil
}

func invalidateTableCache() {
	tablesMu.Lock()
	cacheTime, banCacheTime = time.Time{}, time.Time{}
	tablesMu.Unlock()
}

func parseBanTable() (*Map, error) {
	raw, err := runtimeCmd("show table tbl_ban")
	if err != nil {
		return nil, err
	}
	ban := ParseTableOutput(raw)
	if err := applyAdaptiveExpiry(ban); err != nil {
		return nil, err
	}
	return ban, nil
}

func mapOrNil(m *Map) any {
	if m == nil {
		return nil
	}
	return m
}

// getTables is get_tables: tbl_ban plus the totals of every tbl_err_*, cached 5 s.
func getTables(includeErrors bool) *Map {
	tablesMu.Lock()
	defer tablesMu.Unlock()
	fresh := func(t time.Time) bool { return !t.IsZero() && time.Since(t) <= 5*time.Second }
	if !includeErrors {
		if fresh(cacheTime) {
			return newMap("ban", tableCache.Value("ban"))
		}
		if fresh(banCacheTime) {
			return banTableCache
		}
		ban, err := parseBanTable()
		if err != nil {
			log.Printf("parse ban table: %v", err)
			banTableCache = newMap("ban", nil)
		} else {
			banTableCache = newMap("ban", mapOrNil(ban))
		}
		banCacheTime = time.Now()
		return banTableCache
	}
	if fresh(cacheTime) {
		return tableCache
	}
	build := func() (*Map, error) {
		ban, err := parseBanTable()
		if err != nil {
			return nil, err
		}
		names, err := listErrTables()
		if err != nil {
			return nil, err
		}
		multi := []any{}
		tables := []any{}
		for _, name := range names {
			raw, err := runtimeCmd("show table " + name)
			if err != nil {
				return nil, err
			}
			parsed := mapOrNil(ParseTableOutput(raw))
			multi = append(multi, newMap("name", name, "table", parsed))
			tables = append(tables, parsed)
		}
		return newMap("ban", mapOrNil(ban), "err", aggregateErrTables(tables), "err_multi", multi), nil
	}
	if t, err := build(); err != nil {
		log.Printf("parse tables: %v", err)
		tableCache = newMap("ban", nil, "err", nil, "err_multi", []any{})
	} else {
		tableCache = t
	}
	cacheTime = time.Now()
	return tableCache
}

func getTablesRaw() (*Map, error) {
	safe := func(command string) string {
		out, err := runtimeCmd(command)
		if err != nil {
			log.Printf("raw table error: %v", err)
			return "ERROR: " + err.Error()
		}
		return out
	}
	banRaw := safe("show table tbl_ban")
	ipAuthRaw := safe("show table tbl_ip_auth")
	names, err := listErrTables()
	if err != nil {
		return nil, err // _list_err_tables raised: so did get_tables_raw
	}
	if len(names) == 0 {
		return newMap("ban_raw", banRaw, "err_raw", safe("show table tbl_err")+"\n\n"+ipAuthRaw), nil
	}
	errRaw := newMap()
	for _, n := range names {
		errRaw.Set(n, safe("show table "+n))
	}
	errRaw.Set("tbl_ip_auth", ipAuthRaw)
	return newMap("ban_raw", banRaw, "err_raw", errRaw), nil
}

func ipAuthEmpty(errText string) *Map {
	return newMap("headers", strList("IP", "Flag (gpc0)", "TTL (sec)"), "rows", []any{},
		"meta", newMap("name", "tbl_ip_auth", "used", int64(0), "size", int64(0), "error", errText))
}

// getIPAuthTable is get_ip_auth_table.
func getIPAuthTable() (*Map, error) {
	raw, err := runtimeCmd("show table tbl_ip_auth")
	if err != nil {
		log.Printf("ip_auth table error: %v", err)
		return ipAuthEmpty("exception: " + err.Error()), nil
	}
	rawStrip := pyStripSpace(raw)
	if rawStrip == "" || strings.Contains(rawStrip, "Unknown table") || strings.Contains(rawStrip, "No such table") {
		return ipAuthEmpty("table_missing"), nil
	}
	rows := []any{}
	var size, used int64
	for _, line := range pySplitlines(rawStrip) {
		line = pyStripSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "# table:") {
			for _, p := range strings.Split(line, ",") {
				p = pyStripSpace(p)
				if v, ok := strings.CutPrefix(p, "size="); ok {
					if n, err := parsePyIntString(v); err == nil {
						size = n
					}
				} else if v, ok := strings.CutPrefix(p, "used="); ok {
					if n, err := parsePyIntString(v); err == nil {
						used = n
					}
				}
			}
			continue
		}
		ip := ""
		var flag, ttl int64
		for _, token := range strings.Fields(line) {
			switch {
			case strings.HasPrefix(token, "key="):
				ip = token[4:]
			case strings.HasPrefix(token, "gpc0="):
				flag, _ = parsePyIntString(token[5:])
			case strings.HasPrefix(token, "exp="):
				if ms, err := parsePyIntString(token[4:]); err == nil {
					ttl = max(0, pyFloorDiv(ms, 1000))
				} else {
					ttl = 0
				}
			}
		}
		if ip != "" {
			rows = append(rows, []any{ip, flag, ttl})
		}
	}
	identities := newMap()
	if id, err := guarddIdentities(); err != nil {
		if !isUnavailable(err) {
			return nil, err
		}
	} else {
		v := orValue(id.Value("users_by_ip"), newMap())
		m, ok := asMap(v)
		if !ok {
			return nil, noAttr(v, "get")
		}
		identities = m
	}
	usersByIP := newMap()
	for _, row := range rows {
		r := row.([]any)
		if r[1].(int64) > 0 {
			users, found := identities.Get(r[0])
			if !found {
				users = []any{}
			}
			usersByIP.Set(r[0], users)
		}
	}
	if used == 0 {
		used = int64(len(rows))
	}
	if size == 0 {
		size = int64(len(rows))
	}
	return newMap("users_by_ip", usersByIP, "headers", strList("IP", "Flag (gpc0)", "TTL (sec)"), "rows", rows,
		"meta", newMap("name", "tbl_ip_auth", "used", used, "size", size, "error", nil)), nil
}

func pyFloorDiv(a, b int64) int64 {
	q := a / b
	if (a%b != 0) && ((a < 0) != (b < 0)) {
		q--
	}
	return q
}

// ---- allow lists ----

func readTextUniversal(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	text := strings.ToValidUTF8(string(raw), "�")
	return strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\r", "\n"), nil
}

func aclIDFor(filePath string) (string, error) {
	out, err := runtimeCmd("show acl")
	if err != nil {
		return "", err
	}
	for _, line := range pySplitlines(out) {
		parts := strings.Fields(pyStripSpace(line))
		if len(parts) < 2 {
			continue
		}
		if strings.Trim(parts[1], "()") == filePath {
			return "#" + parts[0], nil
		}
	}
	return "", nil
}

func aclDumpFor(filePath string) (string, error) {
	id, err := aclIDFor(filePath)
	if err != nil {
		return "", err
	}
	if id == "" {
		return fmt.Sprintf("(ACL for %s was not found in memory)", filePath), nil
	}
	body, err := runtimeCmd("show acl " + id)
	if err != nil {
		return "", err
	}
	if t := pyStripSpace(body); t != "" {
		return t, nil
	}
	return fmt.Sprintf("(ACL %s is empty)", id), nil
}

func getWhitelists() *Map {
	file := func(path string) string {
		if _, err := os.Stat(path); err != nil {
			return "(file is missing)"
		}
		text, err := readTextUniversal(path)
		if err != nil {
			return "(read error: " + pyFileError(err, path) + ")"
		}
		return text
	}
	runtime := func(path string) string {
		out, err := aclDumpFor(path)
		if err != nil {
			return "(runtime ACL read error: " + err.Error() + ")"
		}
		return out
	}
	return newMap("geo_file_path", WhitelistFile, "geo_file", file(WhitelistFile), "geo_runtime", runtime(WhitelistFile),
		"global_file_path", WhitelistGlobalFile, "global_file", file(WhitelistGlobalFile),
		"global_runtime", runtime(WhitelistGlobalFile))
}

func runtimeOK(response string) bool { return pyStripSpace(response) == "" }

var reloadOKRe = regexp.MustCompile(`\breload ok\b`)

func reloadOK(result string) bool { return reloadOKRe.MatchString(strings.ToLower(result)) }

var ipv4DottedRe = regexp.MustCompile(`^\d{1,3}(?:\.\d{1,3}){3}$`)

// unbanIP is unban_ip: (text, status).
func unbanIP(ip string) (string, int, error) {
	if !ipv4DottedRe.MatchString(ip) {
		return "Invalid IP", 400, nil
	}
	engineNote := ""
	answer, err := guarddForgetBan(ip)
	if err != nil {
		log.Printf("adaptive engine not reachable while unbanning %s: %v", ip, err)
		engineNote = "Lifted in HAProxy, but the adaptive engine did not answer: a ban it scheduled may come back."
	}
	if m, ok := asMap(answer); ok && err == nil {
		if truthy(m.Value("cleared")) {
			invalidateTableCache()
			return "OK", 200, nil
		}
		if truthy(m.Value("refused")) {
			return "HAProxy did not lift the ban: " + truncRunes(pyStr(m.Value("refused")), 200), 502, nil
		}
	}
	response, err := runtimeCmd(fmt.Sprintf("set table tbl_ban key %s data.gpc0 0", ip))
	if err != nil {
		var oe *OSError
		if errors.As(err, &oe) {
			return "HAProxy did not lift the ban: " + oe.Msg, 502, nil
		}
		return "", 0, err
	}
	if !runtimeOK(response) {
		return "HAProxy did not lift the ban: " + truncRunes(pyStripSpace(response), 200), 502, nil
	}
	invalidateTableCache()
	if engineNote != "" {
		return engineNote, 200, nil
	}
	return "OK", 200, nil
}

func whitelistOutcome(done, cidr, runtime, reload string) (string, int) {
	if reloadOK(reload) {
		return done + ": " + cidr, 200
	}
	if runtimeOK(runtime) {
		return fmt.Sprintf("%s in the running HAProxy: %s. The reload failed, so it is in the file but the next restart may not have it: %s", done, cidr, reload), 200
	}
	rt := pyStripSpace(runtime)
	if rt == "" {
		rt = "no answer"
	}
	return fmt.Sprintf("Saved to the file, but HAProxy did not take it: %s. Runtime: %s; reload: %s", cidr, rt, reload), 502
}

func aclRuntime(filePath, verb, cidr string) (string, error) {
	id, err := aclIDFor(filePath)
	if err != nil {
		return "", err
	}
	if id == "" {
		return "ACL-id not found; skipped runtime update", nil
	}
	out, err := runtimeCmd(fmt.Sprintf("%s acl %s %s", verb, id, cidr))
	if err != nil {
		return "", err
	}
	return pyStripSpace(out), nil
}

func safeRuntimeACL(action, filePath, verb, cidr string) string {
	out, err := aclRuntime(filePath, verb, cidr)
	if err != nil {
		log.Printf("whitelist runtime ACL %s failed for %s: %v", action, cidr, err)
		return fmt.Sprintf("runtime ACL %s failed: %s", action, err.Error())
	}
	return out
}

func canonicalCIDR(value string) (string, bool) {
	text := pyStripSpace(value)
	if text == "" {
		return "", false
	}
	if strings.Contains(text, "/") {
		p, ok := pyIPNetwork(text)
		if !ok {
			return "", false
		}
		return p.String(), true
	}
	a, ok := pyIPAddress(text)
	if !ok {
		return "", false
	}
	return fmt.Sprintf("%s/%d", a.String(), a.BitLen()), true
}

func ensureFile(path, header, label string) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o777); err != nil {
		log.Printf("%s: cannot create dir %q: %v", label, dir, err)
		return
	}
	if _, err := os.Stat(path); err == nil {
		return
	}
	if err := os.WriteFile(path, []byte(header), 0o644); err != nil {
		log.Printf("%s: cannot create file %q: %v", label, path, err)
		return
	}
	_ = os.Chmod(path, 0o644)
}

func ensureWhitelistGlobalFile() {
	ensureFile(WhitelistGlobalFile, "# HAProxy global whitelist\n", "ensure_whitelist_global_file")
}

// splitKeepEnds is readlines(): lines with their endings (universal newlines read as "\n").
func splitKeepEnds(text string) []string {
	var out []string
	for text != "" {
		i := strings.IndexByte(text, '\n')
		if i < 0 {
			out = append(out, text)
			break
		}
		out = append(out, text[:i+1])
		text = text[i+1:]
	}
	return out
}

// rewriteLocked is the open(path, "r+") + flock read-modify-write.
func rewriteLocked(path string, edit func(lines []string) ([]string, bool)) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return &OSError{pyFileError(err, path)}
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return &OSError{pyOSError(err)}
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	raw, err := readAll(f)
	if err != nil {
		return &OSError{pyOSError(err)}
	}
	text := strings.ReplaceAll(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\r", "\n")
	kept, write := edit(splitKeepEnds(text))
	if !write {
		return nil
	}
	if _, err := f.Seek(0, 0); err != nil {
		return &OSError{pyOSError(err)}
	}
	if _, err := f.WriteString(strings.Join(kept, "")); err != nil {
		return &OSError{pyOSError(err)}
	}
	pos, _ := f.Seek(0, 1)
	if err := f.Truncate(pos); err != nil {
		return &OSError{pyOSError(err)}
	}
	return f.Sync()
}

func toggleCIDRInFile(path, cidr string) (bool, error) {
	removed := false
	err := rewriteLocked(path, func(lines []string) ([]string, bool) {
		for _, l := range lines {
			if pyStripSpace(l) == cidr {
				removed = true
			}
		}
		var kept []string
		if removed {
			for _, l := range lines {
				if pyStripSpace(l) != cidr {
					kept = append(kept, l)
				}
			}
		} else {
			for _, l := range lines {
				if !strings.HasSuffix(l, "\n") {
					l += "\n"
				}
				kept = append(kept, l)
			}
			kept = append(kept, cidr+"\n")
		}
		return kept, true
	})
	return removed, err
}

func toggleWhitelist(ip string, global bool) (string, int) {
	cidr, ok := canonicalCIDR(ip)
	if !ok {
		return "Invalid IP/network", 400
	}
	path, action := WhitelistFile, ""
	if global {
		path = WhitelistGlobalFile
		ensureWhitelistGlobalFile()
		action = "-global"
	} else {
		EnsureWhitelistFile()
	}
	removed, err := toggleCIDRInFile(path, cidr)
	if err != nil {
		if global {
			return "Global allow-list file write error: " + err.Error(), 500
		}
		return "Allow-list file write error: " + err.Error(), 500
	}
	if removed {
		rt := safeRuntimeACL("remove"+action, path, "del", cidr)
		rl := ReloadHAProxy()
		if global {
			return whitelistOutcome("Removed from global allow list", cidr, rt, rl)
		}
		return whitelistOutcome("Removed", cidr, rt, rl)
	}
	rt := safeRuntimeACL("add"+action, path, "add", cidr)
	rl := ReloadHAProxy()
	if global {
		return whitelistOutcome("Added to global allow list", cidr, rt, rl)
	}
	if !reloadOK(rl) {
		return whitelistOutcome("Added", cidr, rt, rl)
	}
	return "Added: " + cidr, 200
}

// removeHostFromGlobalWhitelist is remove_host_from_global_whitelist.
func removeHostFromGlobalWhitelist(ip string) (bool, string) {
	text := pyStripSpace(ip)
	a, ok := pyIPAddress(text)
	if !ok {
		return false, "Invalid IP"
	}
	forms := map[string]bool{a.String(): true, fmt.Sprintf("%s/%d", a.String(), a.BitLen()): true}
	ensureWhitelistGlobalFile()
	var removedForms []string
	err := rewriteLocked(WhitelistGlobalFile, func(lines []string) ([]string, bool) {
		var kept []string
		for _, l := range lines {
			if forms[pyStripSpace(l)] {
				removedForms = append(removedForms, pyStripSpace(l))
			} else {
				if !strings.HasSuffix(l, "\n") {
					l += "\n"
				}
				kept = append(kept, l)
			}
		}
		return kept, len(removedForms) > 0
	})
	if err != nil {
		log.Printf("remove_host_from_global_whitelist: file error: %v", err)
		return false, err.Error()
	}
	for _, form := range removedForms {
		safeRuntimeACL("remove-global", WhitelistGlobalFile, "del", form)
	}
	if len(removedForms) > 0 {
		ReloadHAProxy()
	}
	return len(removedForms) > 0, ""
}

// ---- sessions, backends, attackers ----

func allAdminSockets() []string {
	dir := filepath.Dir(SOCKET)
	if dir == "" || dir == "." {
		dir = "/run/haproxy"
	}
	base := filepath.Base(SOCKET)
	if base == "" || base == "." {
		base = "admin.sock"
	}
	re := regexp.MustCompile(`^` + regexp.QuoteMeta(base) + `(\.\d+)?$`)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []string{SOCKET}
	}
	var out []string
	for _, e := range entries {
		if re.MatchString(e.Name()) {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		return []string{SOCKET}
	}
	return out
}

func getConnections() (*Map, error) {
	var all []*Map
	for _, sock := range allAdminSockets() {
		raw, err := HAProxyRuntimeCommand("show sess", sock, 2*time.Second)
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(raw, "Command") {
			continue
		}
		for _, c := range ParseSessions(raw) {
			m, _ := asMap(c)
			if m == nil || !truthy(m.Value("src_ip")) || strings.HasPrefix(pyStr(m.Value("src_ip")), "unix:") ||
				strings.ToUpper(pyStr(orValue(m.Value("fe"), ""))) == "GLOBAL" {
				continue
			}
			all = append(all, m)
		}
	}
	var order []string
	counts := map[string]int64{}
	for _, c := range all {
		ip := pyStr(c.Value("src_ip"))
		if _, seen := counts[ip]; !seen {
			order = append(order, ip)
		}
		counts[ip]++
	}
	sort.SliceStable(order, func(i, j int) bool {
		if counts[order[i]] != counts[order[j]] {
			return counts[order[i]] > counts[order[j]]
		}
		return order[i] < order[j]
	})
	items := []any{}
	for _, ip := range order {
		items = append(items, newMap("src_ip", ip, "count", counts[ip], "country", getCountryCode(ip)))
	}
	return newMap("list", items, "total", int64(len(all))), nil
}

func showStat(sock string) string {
	out, err := HAProxyRuntimeCommand("show stat", sock, 2*time.Second)
	if err != nil {
		log.Printf("show stat failed on %s: %v", sock, err)
		return ""
	}
	return out
}

// statRow is one csv.DictReader row: missing columns are None.
type statRow map[string]*string

func (r statRow) get(key string) string {
	if v := r[key]; v != nil {
		return *v
	}
	return ""
}

func (r statRow) has(key string) bool { return r[key] != nil }

// parseShowStat is _parse_show_stat (csv.DictReader over the CSV).
func parseShowStat(text string) []statRow {
	if pyStripSpace(text) == "" {
		return nil
	}
	var lines []string
	for _, ln := range pySplitlines(text) {
		if pyStripSpace(ln) != "" {
			lines = append(lines, ln)
		}
	}
	header := pyStripSpace(strings.TrimLeft(lines[0], "# "))
	r := csv.NewReader(strings.NewReader(strings.Join(append([]string{header}, lines[1:]...), "\n")))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	records, _ := r.ReadAll()
	if len(records) == 0 {
		return nil
	}
	fields := records[0]
	var out []statRow
	for _, rec := range records[1:] {
		row := statRow{}
		for i, f := range fields {
			if i < len(rec) {
				v := rec[i]
				row[f] = &v
			} else if _, set := row[f]; !set {
				row[f] = nil
			}
		}
		out = append(out, row)
	}
	return out
}

var (
	excludeExact  = splitCommas(envOr("UI_EXCLUDE_EXACT", "be_admin,be_stats,be_http_challenge,be_tls_terminator,be_maintenance"))
	excludePrefix = splitCommas(envOr("UI_EXCLUDE_PREFIX", "tbl_"))
	systemBackend = map[string]string{"authelia_backend": "Authelia", "be_access_granted": "Authelia"}
	siteHostRe    = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
)

func splitCommas(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func isServiceBackend(px string) bool {
	if px == "" || contains(excludeExact, px) {
		return true
	}
	for _, p := range excludePrefix {
		if strings.HasPrefix(px, p) {
			return true
		}
	}
	return false
}

func prettyBackend(px string) string {
	return strings.ReplaceAll(strings.TrimPrefix(px, "be_"), "_", ".")
}

func backendKind(px string) string {
	if _, ok := systemBackend[px]; ok {
		return "system"
	}
	if strings.HasPrefix(px, "be_tcp_") {
		return "tcp"
	}
	return "site"
}

func siteHosts(display string) []any {
	hosts := []any{}
	seen := map[string]bool{}
	for _, part := range strings.Split(display, ",") {
		host := strings.TrimRight(strings.ToLower(pyStripSpace(part)), ".")
		if d := strings.ReplaceAll(host, ".", ""); d != "" && pyIsDigit(d) {
			continue
		}
		if len(host) >= 1 && len(host) <= 253 && siteHostRe.MatchString(host) && !seen[host] {
			seen[host] = true
			hosts = append(hosts, host)
		}
	}
	return hosts
}

func getBackendsStatus() *Map {
	var rows []statRow
	for _, sock := range allAdminSockets() {
		if txt := showStat(sock); txt != "" {
			rows = append(rows, parseShowStat(txt)...)
		}
	}
	type key struct {
		px, sv  string
		hp, hsv bool
	}
	seen := map[key]bool{}
	var dedup []statRow
	for _, r := range rows {
		k := key{r.get("pxname"), r.get("svname"), r.has("pxname"), r.has("svname")}
		if seen[k] {
			continue
		}
		seen[k] = true
		dedup = append(dedup, r)
	}
	byBE := map[string][]statRow{}
	for _, r := range dedup {
		if sv := r.get("svname"); r.has("svname") && (sv == "FRONTEND" || sv == "BACKEND") {
			continue
		}
		be := pyStripSpace(r.get("pxname"))
		if be == "" || isServiceBackend(be) {
			continue
		}
		byBE[be] = append(byBE[be], r)
	}
	names := loadDisplayMap()
	isUp := func(status string) bool {
		s := strings.ToLower(pyStripSpace(status))
		return strings.HasPrefix(s, "up") || s == "no check" || s == "open" || strings.HasPrefix(s, "ready")
	}
	keys := make([]string, 0, len(byBE))
	for k := range byBE {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	items := []any{}
	for _, be := range keys {
		lst := byBE[be]
		total := int64(len(lst))
		var ups int64
		for _, r := range lst {
			if isUp(r.get("status")) {
				ups++
			}
		}
		downs := total - ups
		color := "green"
		if total == 0 || ups == 0 {
			color = "red"
		} else if downs > 0 {
			color = "yellow"
		}
		kind := backendKind(be)
		if kind == "system" && color == "green" {
			continue
		}
		display := names[be]
		if display == "" {
			display = systemBackend[be]
		}
		if display == "" {
			display = prettyBackend(be)
		}
		hosts := []any{}
		if kind == "site" {
			hosts = siteHosts(names[be])
		}
		items = append(items, newMap("backend", be, "site", display, "up", ups, "down", downs, "total", total,
			"status", color, "kind", kind, "hosts", hosts))
	}
	return newMap("items", items)
}

func normalizeAttackers(src any) []any {
	if m, ok := asMap(src); ok {
		var list []any
		m.Each(func(k, v any) { list = append(list, newMap("ip", k, "count", v)) })
		src = list
	}
	list, ok := src.([]any)
	if !ok {
		return []any{}
	}
	type item struct {
		m   *Map
		cnt int64
	}
	var out []item
	for _, it := range list {
		m, ok := asMap(it)
		if !ok {
			continue
		}
		ipV, found := m.Get("ip")
		if !found {
			ipV = ""
		}
		ip := pyStripSpace(pyStr(ipV))
		if ip == "" {
			continue
		}
		cnt, err := pyInt(orValue(m.Value("count"), m.Value("cnt"), m.Value("hits"), int64(0)))
		if err != nil {
			cnt = 0
		}
		country := orValue(m.Value("country"))
		if !truthy(country) {
			country = getCountryCode(ip)
		}
		out = append(out, item{newMap("ip", ip, "count", cnt, "country", country), cnt})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].cnt > out[j].cnt })
	res := []any{}
	for i, it := range out {
		if i < 10 {
			res = append(res, it.m)
		}
	}
	return res
}

func getAttackers() *Map {
	if counted, err := guarddAttackers(); err == nil && truthy(counted.Value("ok")) {
		since, ferr := pyFloatStrict(orValue(counted.Value("since"), int64(0)))
		if ferr == nil && since <= float64(time.Now().UnixNano())/1e9-3600 {
			return newMap("code_400", normalizeAttackers(counted.Value("code_400")),
				"code_451", normalizeAttackers(counted.Value("code_451")),
				"diagnostic", newMap("source", "guardd", "since", counted.Value("since")))
		}
	}
	data := ControldGetAttackers(10 * time.Second)
	diagFor := func() any {
		diag := orValue(data.Value("diagnostic"), newMap())
		if m, ok := asMap(diag); ok {
			if _, has := m.Get("source"); !has {
				m.Set("source", "controld")
			}
		}
		return diag
	}
	if truthy(data.Value("error")) {
		return newMap("error", data.Value("error"), "diagnostic", diagFor())
	}
	raw400 := orValue(data.Value("code_400"), data.Value("a400"), data.Value("400"), []any{})
	raw451 := orValue(data.Value("code_451"), data.Value("a451"), data.Value("451"), []any{})
	return newMap("code_400", normalizeAttackers(raw400), "code_451", normalizeAttackers(raw451), "diagnostic", diagFor())
}

// pyFloatStrict is float(value) for a JSON value, with its errors.
func pyFloatStrict(v any) (float64, error) {
	switch x := v.(type) {
	case float64:
		return x, nil
	case int64:
		return float64(x), nil
	case bool:
		if x {
			return 1, nil
		}
		return 0, nil
	case string:
		f, err := strconv.ParseFloat(pyStripSpace(x), 64)
		if err != nil {
			return 0, &ValueError{fmt.Sprintf("could not convert string to float: %s", pyRepr(x))}
		}
		return f, nil
	}
	return 0, &TypeError{"float() argument must be a string or a real number"}
}

// ---- services_runtime ----

var (
	runtimeStates     = []string{"ready", "drain", "maint"}
	protectedBackends = func() map[string]bool {
		m := map[string]bool{"authelia_backend": true, "be_access_granted": true, "be_access_portal": true, "be_maintenance": true}
		for _, e := range excludeExact {
			m[e] = true
		}
		return m
	}()
)

// RuntimeRefusal is services_runtime.RuntimeError_: safe to show.
type RuntimeRefusal struct{ Msg string }

func (e *RuntimeRefusal) Error() string { return e.Msg }

func isOperable(px string) bool {
	if px == "" || protectedBackends[px] {
		return false
	}
	for _, p := range excludePrefix {
		if strings.HasPrefix(px, p) {
			return false
		}
	}
	return true
}

func adminState(status string) string {
	v := strings.ToUpper(pyStripSpace(status))
	switch {
	case strings.HasPrefix(v, "MAINT"):
		return "maint"
	case strings.HasPrefix(v, "DRAIN"):
		return "drain"
	}
	return "ready"
}

func toIntLoose(s string) int64 {
	n, err := parsePyIntString(s)
	if err != nil {
		return 0
	}
	return n
}

func listRuntimeBackends() []any {
	rows := parseShowStat(showStat(SOCKET))
	names := loadDisplayMap()
	grouped := map[string][]*Map{}
	for _, r := range rows {
		px := pyStripSpace(r.get("pxname"))
		sv := pyStripSpace(r.get("svname"))
		if sv == "FRONTEND" || sv == "BACKEND" || !isOperable(px) {
			continue
		}
		status := pyStripSpace(r.get("status"))
		weight := "None"
		if r.has("weight") {
			weight = r.get("weight")
		}
		scur := "None"
		if r.has("scur") {
			scur = r.get("scur")
		}
		grouped[px] = append(grouped[px], newMap("server", sv, "address", pyStripSpace(r.get("addr")), "status", status,
			"admin_state", adminState(status), "weight", toIntLoose(weight), "sessions", toIntLoose(scur),
			"check_status", pyStripSpace(r.get("check_status"))))
	}
	keys := make([]string, 0, len(grouped))
	for k := range grouped {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := []any{}
	for _, px := range keys {
		servers := grouped[px]
		sort.SliceStable(servers, func(i, j int) bool {
			return servers[i].Value("server").(string) < servers[j].Value("server").(string)
		})
		list := make([]any, len(servers))
		for i, s := range servers {
			list[i] = s
		}
		display := names[px]
		if display == "" {
			display = prettyBackend(px)
		}
		out = append(out, newMap("backend", px, "label", display, "servers", list))
	}
	return out
}

func resolveServer(backend, server any) (string, string, error) {
	wb, ws := orStr(backend), orStr(server)
	for _, e := range listRuntimeBackends() {
		if get(e, "backend") != wb {
			continue
		}
		for _, s := range listOf(e.(*Map), "servers") {
			if get(s, "server") == ws {
				return wb, ws, nil
			}
		}
	}
	return "", "", &RuntimeRefusal{"unknown backend or server"}
}

func runRuntime(command string) error {
	reply, err := HAProxyRuntimeCommand(command, SOCKET, 5*time.Second)
	if err != nil {
		return err
	}
	if r := pyStripSpace(reply); r != "" {
		return &RuntimeRefusal{truncRunes(pySplitlines(r)[0], 200)}
	}
	return nil
}

func setServerState(backend, server, state any) (*Map, error) {
	wanted := strings.ToLower(orStr(state))
	if pick(runtimeStates, wanted, "") == "" {
		return nil, &RuntimeRefusal{"state must be one of " + strings.Join(runtimeStates, ", ")}
	}
	name, srv, err := resolveServer(backend, server)
	if err != nil {
		return nil, err
	}
	if err := runRuntime(fmt.Sprintf("set server %s/%s state %s", name, srv, wanted)); err != nil {
		return nil, err
	}
	log.Printf("Runtime state of %s/%s set to %s", name, srv, wanted)
	return newMap("ok", true, "backend", name, "server", srv, "state", wanted), nil
}

func setServerWeight(backend, server, weight any) (*Map, error) {
	value, err := parsePyIntString(pyStr(weight))
	if err != nil {
		return nil, &RuntimeRefusal{"weight must be a whole number"}
	}
	if value < 0 || value > 256 {
		return nil, &RuntimeRefusal{"weight must be between 0 and 256"}
	}
	name, srv, err := resolveServer(backend, server)
	if err != nil {
		return nil, err
	}
	if err := runRuntime(fmt.Sprintf("set server %s/%s weight %d", name, srv, value)); err != nil {
		return nil, err
	}
	log.Printf("Runtime weight of %s/%s set to %d", name, srv, value)
	return newMap("ok", true, "backend", name, "server", srv, "weight", value), nil
}
