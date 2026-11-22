package controld

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"math"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/pyx"
)

func (d *Daemon) ensureIpset() error {
	for _, name := range []string{d.Opts.IpsetName, d.Opts.PageIpset} {
		if _, err := runCmd([]string{"ipset", "create", name, "hash:ip", "family", "inet", "-exist"}, nil, ipsetTimeout*time.Second); err != nil {
			log.Printf("Failed to ensure ipset %s: %s", name, pyErr(err))
			return err
		}
		log.Printf("Ensured ipset %s exists", name)
	}
	return nil
}

var (
	tableRowRE = regexp.MustCompile(`key=(\d+\.\d+\.\d+\.\d+).*?\bgpc0=(\d+)`)
	expRE      = regexp.MustCompile(`\bexp=(\d+)`)
	gpt0RE     = regexp.MustCompile(`\bgpt0=(\d+)`)
	uptimeRE   = regexp.MustCompile(`(?m)^Uptime_sec:\s*(\d+)`)
)

type flaggedRow struct{ left, code int64 }

func (d *Daemon) socat(input string) (procResult, error) {
	return runCmd([]string{"socat", d.Opts.HAProxyAdminSocket, "stdio"}, strPtr(input), 5*time.Second)
}

func atoi64(s string) int64 { n, _ := strconv.ParseInt(s, 10, 64); return n }

func (d *Daemon) readFlaggedRows(table string) map[string]flaggedRow {
	res, err := d.socat("show table " + table + "\n")
	if err != nil {
		log.Printf("Failed to fetch table %s from HAProxy: %s", table, pyErr(err))
		return nil
	}
	lines := pySplitlines(res.stdout)
	if len(lines) == 0 || !strings.HasPrefix(lines[0], "# table: "+table+",") {
		first := ""
		if len(lines) > 0 {
			first = pyx.TruncRunes(lines[0], 120)
		}
		log.Printf("HAProxy did not return table %s: %s", table, pyRepr(first))
		return nil
	}
	flagged := map[string]flaggedRow{}
	for _, line := range lines[1:] {
		m := tableRowRE.FindStringSubmatch(line)
		if m == nil || atoi64(m[2]) <= 0 {
			continue
		}
		var row flaggedRow
		if e := expRE.FindStringSubmatch(line); e != nil {
			row.left = atoi64(e[1]) / 1000
		}
		if c := gpt0RE.FindStringSubmatch(line); c != nil {
			row.code = atoi64(c[1])
		}
		flagged[m[1]] = row
	}
	return flagged
}

func (d *Daemon) ipsetMembers(name string) map[string]bool {
	if name == "" {
		name = d.Opts.IpsetName
	}
	res, err := runCmd([]string{"ipset", "list", name}, nil, ipsetTimeout*time.Second)
	if err != nil {
		log.Printf("Failed to list ipset %s: %s", name, pyErr(err))
		return map[string]bool{}
	}
	members := map[string]bool{}
	capture := false
	for _, line := range pySplitlines(res.stdout) {
		line = pyStrip(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "Members:") {
			capture = true
			continue
		}
		if !capture {
			continue
		}
		parts := pyFields(line)
		if len(parts) > 0 && strings.Count(parts[0], ".") == 3 {
			members[parts[0]] = true
		}
	}
	return members
}

func ipv4Entries(addresses map[string]bool) []string {
	entries := []string{}
	for a := range addresses {
		addr, err := netip.ParseAddr(a)
		if err != nil || !addr.Is4() {
			log.Printf("Not an IPv4 address, left out of the ipset: %s", pyRepr(a))
			continue
		}
		entries = append(entries, addr.String())
	}
	sort.Strings(entries)
	return entries
}

func (d *Daemon) updateIpset(set string, toAdd, toDel map[string]bool, timeouts map[string]int64) bool {
	lines := []string{}
	for _, ip := range ipv4Entries(toDel) {
		lines = append(lines, "del "+set+" "+ip)
	}
	for _, ip := range ipv4Entries(toAdd) {
		if timeouts == nil {
			lines = append(lines, "add "+set+" "+ip)
		} else {
			t, ok := timeouts[ip]
			if !ok {
				t = 1
			}
			lines = append(lines, fmt.Sprintf("add %s %s timeout %d", set, ip, t))
		}
	}
	if len(lines) == 0 {
		return true
	}
	if _, err := runCmd([]string{"ipset", "-exist", "restore"}, strPtr(strings.Join(lines, "\n")+"\n"), ipsetTimeout*time.Second); err != nil {
		log.Printf("Failed to update ipset %s (+%d, -%d): %s", set, len(toAdd), len(toDel), pyErr(err))
		return false
	}
	return true
}

func (d *Daemon) haproxyUptime() (int64, bool) {
	res, err := d.socat("show info\n")
	if err != nil {
		return 0, false
	}
	m := uptimeRE.FindStringSubmatch(res.stdout)
	if m == nil {
		return 0, false
	}
	return atoi64(m[1]), true
}

func minus(a, b map[string]bool) map[string]bool {
	out := map[string]bool{}
	for k := range a {
		if !b[k] {
			out[k] = true
		}
	}
	return out
}

func (d *Daemon) syncBansOnce() error {
	banned := d.readFlaggedRows(d.Opts.BanTable)
	if banned == nil {
		return nil
	}
	haproxyBanned, firstSteps := map[string]bool{}, map[string]bool{}
	for ip, row := range banned {
		haproxyBanned[ip] = true
		if row.code == firstStepPageCode {
			firstSteps[ip] = true
		}
	}
	ipsetMembers := d.ipsetMembers("")
	pageMembers := d.ipsetMembers(d.Opts.PageIpset)
	if len(haproxyBanned) == 0 && len(ipsetMembers) == 0 && len(pageMembers) == 0 {
		return nil
	}
	pageAdd, pageDel := minus(firstSteps, pageMembers), minus(pageMembers, firstSteps)
	if len(pageAdd) > 0 && d.updateIpset(d.Opts.PageIpset, pageAdd, nil, nil) {
		log.Printf("First steps shown a page: +%d", len(pageAdd))
	}
	toAdd, toDel := minus(haproxyBanned, ipsetMembers), minus(ipsetMembers, haproxyBanned)
	if len(toDel) > 0 && d.Opts.BanRestartGraceSeconds > 0 {
		if uptime, ok := d.haproxyUptime(); ok && uptime < int64(d.Opts.BanRestartGraceSeconds) {
			log.Printf("HAProxy has run for %ds: %d bans stay in the firewall until its table is filled again", uptime, len(toDel))
			toDel = map[string]bool{}
		}
	}
	if d.updateIpset(d.Opts.IpsetName, toAdd, toDel, nil) && (len(toAdd) > 0 || len(toDel) > 0) {
		log.Printf("Sync done: +%d, -%d (haproxy=%d, ipset=%d)", len(toAdd), len(toDel), len(haproxyBanned), len(ipsetMembers))
	}
	if len(pageDel) > 0 && d.updateIpset(d.Opts.PageIpset, nil, pageDel, nil) {
		log.Printf("First steps no longer shown a page: -%d", len(pageDel))
	}
	return nil
}

func (d *Daemon) authIpsetListing() (map[string]bool, bool, bool) {
	res, err := runCmd([]string{"ipset", "list", d.Opts.AuthIpset}, nil, ipsetTimeout*time.Second)
	if err != nil {
		log.Printf("Failed to list ipset %s: %s", d.Opts.AuthIpset, pyErr(err))
		return nil, false, false
	}
	members := map[string]bool{}
	timeouts, capture := false, false
	for _, line := range pySplitlines(res.stdout) {
		line = pyStrip(line)
		if line == "" {
			continue
		}
		if !capture && strings.HasPrefix(line, "Header:") {
			timeouts = strings.Contains(" "+line+" ", " timeout ")
			continue
		}
		if strings.HasPrefix(line, "Members:") {
			capture = true
			continue
		}
		if capture {
			parts := pyFields(line)
			if len(parts) > 0 && strings.Count(parts[0], ".") == 3 {
				members[parts[0]] = true
			}
		}
	}
	return members, timeouts, true
}

func (d *Daemon) ensureAuthIpset() error {
	members, timeouts, ok := d.authIpsetListing()
	set := d.Opts.AuthIpset
	if !ok {
		if _, err := runCmd([]string{"ipset", "create", set, "hash:ip", "family", "inet", "timeout", "0", "-exist"}, nil, ipsetTimeout*time.Second); err != nil {
			return err
		}
		log.Printf("Ensured ipset %s exists", set)
		return nil
	}
	if timeouts {
		return nil
	}
	temporary := pyx.TruncRunes(set+"_t", 31)
	_, _ = runCmd([]string{"ipset", "destroy", temporary}, nil, ipsetTimeout*time.Second)
	if _, err := runCmd([]string{"ipset", "create", temporary, "hash:ip", "family", "inet", "timeout", "0"}, nil, ipsetTimeout*time.Second); err != nil {
		return err
	}
	lines := []string{}
	for _, ip := range ipv4Entries(members) {
		lines = append(lines, fmt.Sprintf("add %s %s timeout %d", temporary, ip, d.Opts.AuthIpsetTTL))
	}
	if len(lines) > 0 {
		if _, err := runCmd([]string{"ipset", "-exist", "restore"}, strPtr(strings.Join(lines, "\n")+"\n"), ipsetTimeout*time.Second); err != nil {
			return err
		}
	}
	if _, err := runCmd([]string{"ipset", "swap", set, temporary}, nil, ipsetTimeout*time.Second); err != nil {
		return err
	}
	if _, err := runCmd([]string{"ipset", "destroy", temporary}, nil, ipsetTimeout*time.Second); err != nil {
		return err
	}
	log.Printf("ipset %s now expires its entries (%d moved over)", set, len(members))
	return nil
}

func (d *Daemon) syncAuthOnce() error {
	rows := d.readFlaggedRows(d.Opts.AuthTable)
	if rows == nil {
		return nil
	}
	members, timeouts, ok := d.authIpsetListing()
	if !ok {
		members, timeouts = map[string]bool{}, false
	}
	wanted := map[string]bool{}
	for ip := range rows {
		wanted[ip] = true
	}
	if len(wanted) == 0 && len(members) == 0 {
		return nil
	}
	if timeouts {
		t := map[string]int64{}
		for ip, row := range rows {
			left := row.left
			if left < 1 {
				left = 1
			}
			if left > int64(d.Opts.AuthIpsetTTL) {
				left = int64(d.Opts.AuthIpsetTTL)
			}
			t[ip] = left
		}
		d.updateIpset(d.Opts.AuthIpset, wanted, minus(members, wanted), t)
	} else {
		d.updateIpset(d.Opts.AuthIpset, minus(wanted, members), minus(members, wanted), nil)
	}
	return nil
}

func (d *Daemon) bansLoop() {
	log.Printf("Ban-sync loop started: table=%s, ipset=%s, interval=%ds", d.Opts.BanTable, d.Opts.IpsetName, d.Opts.Interval)
	if err := d.ensureIpset(); err != nil {
		log.Printf("Ban-sync loop aborted: ipset init failed")
		return
	}
	if err := d.ensureAuthIpset(); err != nil {
		log.Printf("Auth ipset init failed; zero-trust UDP will not update: %s", pyErr(err))
	}
	guard := func(label string, f func() error) {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("%s: %v", label, r)
			}
		}()
		if err := f(); err != nil {
			log.Printf("%s: %s", label, pyErr(err))
		}
	}
	for {
		guard("Unexpected ban-sync error", d.syncBansOnce)
		guard("Unexpected auth-sync error", d.syncAuthOnce)
		time.Sleep(time.Duration(d.Opts.Interval) * time.Second)
	}
}

// ---------------------------------------------------------------------------
// logs-ip
// ---------------------------------------------------------------------------

func isHexOrDot(c byte, colon bool) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' || colon && (c == '.' || c == ':')
}

// lineHasIP is _line_has_ip: the address itself, not one starting with it.
func lineHasIP(line, ip string) bool {
	if ip == "" {
		return true
	}
	for start := 0; ; {
		i := strings.Index(line[start:], ip)
		if i < 0 {
			return false
		}
		i += start
		end := i + len(ip)
		leftOK := i == 0 || !isHexOrDot(line[i-1], true)
		rightOK := end >= len(line) || !isHexOrDot(line[end], false)
		if leftOK && rightOK {
			return true
		}
		start = i + 1
	}
}

func isSelfcheckLine(line, ip string) bool {
	return strings.Contains(line, "GET /ip/") || strings.Contains(line, "/ip/"+ip)
}

func fmtSec(v int64) string {
	switch {
	case v < 60:
		return fmt.Sprintf("%ds", v)
	case v < 3600:
		return fmt.Sprintf("%dm%02ds", v/60, v%60)
	case v < 86400:
		return fmt.Sprintf("%dh%02dm%02ds", v/3600, (v%3600)/60, v%60)
	}
	return fmt.Sprintf("%dd%02dh%02dm", v/86400, (v%86400)/3600, (v%3600)/60)
}

var (
	expireRE  = regexp.MustCompile(`\bexpire\b[^\d]*(\d+)\s*([a-zA-Z]+)?`)
	remainRE1 = regexp.MustCompile(`\bexp(?:ire)?\s*[:=]?\s*(\d+)\s*([a-zA-Z]+)?\b`)
	remainRE2 = regexp.MustCompile(`\bexpires?\s+in\s+(\d+)\s*([a-zA-Z]+)\b`)
)

func parseExpireSeconds(text string) (int64, bool) {
	m := expireRE.FindStringSubmatch(text)
	if m == nil {
		return 0, false
	}
	val := atoi64(m[1])
	switch strings.ToLower(m[2]) {
	case "ms", "msec":
		if val/1000 < 1 {
			return 1, true
		}
		return val / 1000, true
	case "", "s", "sec":
		return val, true
	case "m", "min":
		return val * 60, true
	case "h":
		return val * 3600, true
	case "d", "day", "days":
		return val * 86400, true
	}
	return 0, false
}

func (d *Daemon) banTableTTL() int64 {
	if d.Opts.BanTTLOverride > 0 {
		return int64(d.Opts.BanTTLOverride)
	}
	now := nowEpoch()
	d.ttlMu.Lock()
	cacheFor := float64(d.Opts.BanTTLCacheSeconds)
	if cacheFor < 1 {
		cacheFor = 1
	}
	if d.ttlSet && now-d.ttlAt < cacheFor {
		v := d.ttlValue
		d.ttlMu.Unlock()
		return int64(v)
	}
	d.ttlMu.Unlock()
	var ttl int64
	found := false
	for _, cmd := range []string{"show table " + d.Opts.BanTable + " key 0.0.0.0\n", "show table " + d.Opts.BanTable + "\n"} {
		res, err := d.socat(cmd)
		if err != nil {
			log.Printf("_get_ban_table_ttl_seconds: %s", pyErr(err))
			break
		}
		if ttl, found = parseExpireSeconds(res.stdout); found {
			break
		}
	}
	if !found {
		ttl = 7 * 24 * 3600
	}
	d.ttlMu.Lock()
	d.ttlValue, d.ttlAt, d.ttlSet = int(ttl), now, true
	d.ttlMu.Unlock()
	return ttl
}

func (d *Daemon) banRemainingSeconds(ip string) (int64, bool) {
	res, err := d.socat("show table " + d.Opts.BanTable + " key " + ip + "\n")
	if err != nil {
		log.Printf("_get_ban_remaining_seconds: %s", pyErr(err))
		return 0, false
	}
	out := pyStrip(res.stdout)
	if out == "" {
		return 0, false
	}
	m := remainRE1.FindStringSubmatch(out)
	if m == nil {
		m = remainRE2.FindStringSubmatch(out)
	}
	if m == nil {
		return 0, false
	}
	val := atoi64(m[1])
	switch strings.ToLower(m[2]) {
	case "", "ms", "msec":
		if val/1000 < 1 {
			return 1, true
		}
		return val / 1000, true
	case "s", "sec":
		return val, true
	case "m", "min":
		return val * 60, true
	case "h":
		return val * 3600, true
	case "d", "day", "days":
		return val * 86400, true
	}
	return val, true
}

func normalizeRemainingSeconds(rem, ttl int64) int64 {
	if rem <= 0 {
		return 0
	}
	if ttl > 0 && rem > ttl*10 {
		rem = rem / 1000
	}
	if ttl > 0 && rem > ttl*2 {
		rem = ttl
	}
	if rem < 0 {
		return 0
	}
	return rem
}

func parseSourceToArgs(flag string) ([]string, []string) {
	src := pyStrip(flag)
	if src == "" || src == "*" {
		return nil, nil
	}
	lead := strings.TrimLeftFunc(src, pySpace)
	if strings.Contains(src, "=") && !strings.HasPrefix(lead, "-") {
		return nil, []string{src}
	}
	if !strings.HasPrefix(lead, "-") && !strings.Contains(src, " ") {
		return []string{"-t", src}, nil
	}
	return pyFields(src), nil
}

type tsLine struct {
	t     time.Time
	aware bool
	i     int
	line  string
}

func parseShortISOTs(line string) (time.Time, bool, bool) {
	ts := pyStrip(strings.SplitN(line, " ", 2)[0])
	if ts == "" {
		return time.Time{}, false, false
	}
	return pyx.ParseISO(ts)
}

// sortLogLinesByTime is _sort_log_lines_by_time; comparing a naive stamp
// with an aware one fails as it does in Python.
func (d *Daemon) sortLogLinesByTime(lines []string) ([]string, error) {
	order := d.Opts.LogTimeOrder
	if order != "asc" && order != "desc" {
		return lines, nil
	}
	withTS, noTS := []tsLine{}, []string{}
	naive, aware := false, false
	for i, ln := range lines {
		t, isAware, ok := parseShortISOTs(ln)
		if !ok {
			noTS = append(noTS, ln)
			continue
		}
		if isAware {
			aware = true
		} else {
			naive = true
			t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), time.UTC)
		}
		withTS = append(withTS, tsLine{t, isAware, i, ln})
	}
	if naive && aware && len(withTS) > 1 {
		return nil, fmt.Errorf("can't compare offset-naive and offset-aware datetimes")
	}
	sort.SliceStable(withTS, func(a, b int) bool {
		if order == "desc" {
			return withTS[a].t.After(withTS[b].t)
		}
		return withTS[a].t.Before(withTS[b].t)
	})
	out := make([]string, 0, len(lines))
	for _, x := range withTS {
		out = append(out, x.line)
	}
	return append(out, noTS...), nil
}

type journalSourceInfo struct {
	source               string
	args                 []string
	duration             float64
	rc                   *int
	foundTotal, returned int
	stderr               string
	usedGrep             bool
}

func (d *Daemon) journalWindowForIP(ip string, since, until int64, limit int) ([]string, []journalSourceInfo, error) {
	started := time.Now()
	infos := []journalSourceInfo{}
	mult := d.Opts.JournalLinesMult
	if mult < 1 {
		mult = 1
	}
	nlines := limit * mult
	if limit+5 > nlines {
		nlines = limit + 5
	}
	elapsed := func() float64 { return time.Since(started).Seconds() }
	runOne := func(src string, useGrep bool) ([]string, journalSourceInfo, error) {
		opt, match := parseSourceToArgs(src)
		args := []string{"journalctl", "--no-pager", "-q", "-o", "short-iso", "--since", fmt.Sprintf("@%d", since),
			"--until", fmt.Sprintf("@%d", until), "-n", itoa(nlines)}
		args = append(append(args, opt...), match...)
		if useGrep {
			args = append(args, "--grep", regexp.QuoteMeta(ip))
		}
		timeout := math.Min(d.Opts.JournalPerSourceTimeout, math.Max(0.1, d.Opts.JournalTotalTimeout-elapsed()))
		out, errText := "", ""
		var rc *int
		t0 := time.Now()
		res, err := execRaw(args, nil, time.Duration(timeout*float64(time.Second)))
		if err != nil {
			if _, ok := err.(*timeoutErr); ok {
				errText = "TIMEOUT"
			} else {
				errText = "EXC: " + pyErr(err)
			}
		} else {
			code := res.rc
			rc, out, errText = &code, res.stdout, res.stderr
		}
		dt := time.Since(t0).Seconds()
		filtered := []string{}
		for _, ln := range pySplitlines(out) {
			if lineHasIP(ln, ip) && !isSelfcheckLine(ln, ip) {
				filtered = append(filtered, ln)
			}
		}
		ordered, err := d.sortLogLinesByTime(filtered)
		if err != nil {
			return nil, journalSourceInfo{}, err
		}
		if len(ordered) > limit {
			ordered = ordered[:limit]
		}
		return ordered, journalSourceInfo{source: src, args: args, duration: math.Round(dt*1000) / 1000, rc: rc,
			foundTotal: len(filtered), returned: len(ordered), stderr: pyx.TruncRunes(errText, 4000), usedGrep: useGrep}, nil
	}
	for _, src := range d.Opts.JournalSources {
		if elapsed() >= d.Opts.JournalTotalTimeout {
			break
		}
		lines1, info1, err := runOne(src, d.Opts.JournalUseGrep)
		if err != nil {
			return nil, infos, err
		}
		infos = append(infos, info1)
		if len(lines1) > 0 {
			return lines1, infos, nil
		}
		if d.Opts.JournalUseGrep && info1.rc != nil && *info1.rc != 0 && info1.stderr != "" {
			lines2, info2, err := runOne(src, false)
			if err != nil {
				return nil, infos, err
			}
			infos = append(infos, info2)
			if len(lines2) > 0 {
				return lines2, infos, nil
			}
		}
	}
	return []string{}, infos, nil
}

func (d *Daemon) fileTailForIP(ip string, limit int) []string {
	if d.Opts.LogFile == "" || !lexists(d.Opts.LogFile) {
		return []string{}
	}
	if _, err := os.Stat(d.Opts.LogFile); err != nil {
		return []string{}
	}
	chunk := d.Opts.LogFileTailChunk
	if chunk < 4096 {
		chunk = 4096
	}
	d.logScans <- struct{}{}
	defer func() { <-d.logScans }()
	return d.fileTailScan(ip, limit, chunk, d.Opts.LogFileTailMaxBytes)
}

func decodeReplace(raw []byte) string { return strings.ToValidUTF8(string(raw), "�") }

func (d *Daemon) fileTailScan(ip string, limit int, chunkSize, maxBytes int64) []string {
	f, err := os.Open(d.Opts.LogFile)
	if err != nil {
		log.Printf("_file_tail_for_ip: %s", pyErr(err))
		return []string{}
	}
	defer f.Close()
	pos, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return []string{}
	}
	found := []string{}
	buf := []byte{}
	var scanned int64
	for pos > 0 && len(found) < limit {
		if maxBytes > 0 && scanned >= maxBytes {
			break
		}
		toRead := chunkSize
		if pos < toRead {
			toRead = pos
		}
		pos -= toRead
		chunk := make([]byte, toRead)
		n, err := f.ReadAt(chunk, pos)
		if err != nil && err != io.EOF {
			log.Printf("_file_tail_for_ip: %s", pyErr(err))
			return []string{}
		}
		chunk = chunk[:n]
		scanned += toRead
		buf = append(chunk, buf...)
		parts := strings.Split(string(buf), "\n")
		buf = []byte(parts[0])
		for j := len(parts) - 1; j >= 1; j-- {
			if len(found) >= limit {
				break
			}
			ln := decodeReplace([]byte(parts[j]))
			if lineHasIP(ln, ip) && !isSelfcheckLine(ln, ip) {
				found = append(found, ln)
			}
		}
	}
	if pos == 0 && len(buf) > 0 && len(found) < limit {
		ln := decodeReplace(buf)
		if lineHasIP(ln, ip) && !isSelfcheckLine(ln, ip) {
			found = append(found, ln)
		}
	}
	for i, j := 0, len(found)-1; i < j; i, j = i+1, j-1 {
		found[i], found[j] = found[j], found[i]
	}
	return found
}

func (d *Daemon) logsIPCachePut(key string, lines []string) {
	now := nowEpoch()
	d.logsMu.Lock()
	defer d.logsMu.Unlock()
	if d.logsCache == nil {
		d.logsCache = map[string]logsCacheEntry{}
	}
	if len(d.logsCache) >= logsIPCacheMax {
		for k, v := range d.logsCache {
			if v.expires <= now {
				delete(d.logsCache, k)
			}
		}
		kept := d.logsOrder[:0]
		for _, k := range d.logsOrder {
			if _, ok := d.logsCache[k]; ok {
				kept = append(kept, k)
			}
		}
		d.logsOrder = kept
		for len(d.logsCache) >= logsIPCacheMax && len(d.logsOrder) > 0 {
			delete(d.logsCache, d.logsOrder[0])
			d.logsOrder = d.logsOrder[1:]
		}
	}
	if _, ok := d.logsCache[key]; !ok {
		d.logsOrder = append(d.logsOrder, key)
	}
	d.logsCache[key] = logsCacheEntry{now + d.Opts.LogsIPCacheSeconds, lines}
}

func (d *Daemon) grepLastLogsForIP(ip string, limit int) ([]string, error) {
	if limit > logsIPCacheMaxLimit {
		limit = logsIPCacheMaxLimit
	}
	if limit < 1 {
		limit = 1
	}
	key := ip + "\x00" + itoa(limit)
	if d.Opts.LogsIPCacheSeconds > 0 {
		d.logsMu.Lock()
		item, ok := d.logsCache[key]
		d.logsMu.Unlock()
		if ok && item.expires > nowEpoch() {
			return item.lines, nil
		}
	}
	if lines := d.fileTailForIP(ip, limit); len(lines) > 0 {
		if d.Opts.LogsIPCacheSeconds > 0 {
			d.logsIPCachePut(key, lines)
		}
		return lines, nil
	}
	if raw, ok := d.banRemainingSeconds(ip); ok {
		ttl := d.banTableTTL()
		remaining := normalizeRemainingSeconds(raw, ttl)
		served := ttl - remaining
		if served < 0 {
			served = 0
		}
		banStart := int64(nowEpoch() - float64(served))
		since := banStart - int64(d.Opts.BanDeltaSeconds)
		if since < 0 {
			since = 0
		}
		until := banStart + int64(d.Opts.BanDeltaSeconds)
		if until < 0 {
			until = 0
		}
		jLines, infos, err := d.journalWindowForIP(ip, since, until, limit)
		if err != nil {
			return nil, err
		}
		if len(jLines) > 0 {
			if d.Opts.LogsIPCacheSeconds > 0 {
				d.logsIPCachePut(key, jLines)
			}
			return jLines, nil
		}
		if d.Opts.DebugOnEmpty {
			names := []string{}
			for _, s := range infos {
				names = append(names, s.source)
			}
			block := []string{
				"[DEBUG] No journal matches for banned IP",
				"ip=" + ip,
				fmt.Sprintf("ban_remaining_raw=%d", raw),
				fmt.Sprintf("ban_ttl=%d (%s)", ttl, fmtSec(ttl)),
				fmt.Sprintf("ban_remaining_norm=%d (%s)", remaining, fmtSec(remaining)),
				fmt.Sprintf("served=%d (%s)", served, fmtSec(served)),
				fmt.Sprintf("ban_start_epoch=%d", banStart),
				fmt.Sprintf("window_since_epoch=%d", since),
				fmt.Sprintf("window_until_epoch=%d", until),
				"sources_tried=" + strings.Join(names, ", "),
			}
			for _, s := range infos {
				rc := "None"
				if s.rc != nil {
					rc = itoa(*s.rc)
				}
				block = append(block, fmt.Sprintf("  - %s: found_total=%d returned=%d dur=%ss rc=%s used_grep=%s args=%s stderr=%s",
					s.source, s.foundTotal, s.returned, pyFloatRepr(s.duration), rc, pyBool(s.usedGrep), strings.Join(s.args, " "), s.stderr))
			}
			return block, nil
		}
		return []string{}, nil
	}
	if d.Opts.DebugOnEmpty {
		exists, size, mtime := false, int64(0), "n/a"
		if fi, err := os.Stat(d.Opts.LogFile); err == nil {
			exists, size, mtime = true, fi.Size(), fi.ModTime().Local().Format("2006-01-02 15:04:05")
		}
		return []string{
			"[DEBUG] No file matches for non-banned IP",
			"ip=" + ip,
			"log_file=" + d.Opts.LogFile,
			fmt.Sprintf("exists=%s size=%dB mtime_local=%s", pyBool(exists), size, mtime),
			fmt.Sprintf("limit=%d", limit),
		}, nil
	}
	return []string{}, nil
}

func pyBool(b bool) string {
	if b {
		return "True"
	}
	return "False"
}

// pyFloatRepr is repr(float).
func pyFloatRepr(f float64) string {
	if f == math.Trunc(f) && math.Abs(f) < 1e16 {
		return strconv.FormatFloat(f, 'f', 1, 64)
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}

// ---------------------------------------------------------------------------
// logs-attackers
// ---------------------------------------------------------------------------

var (
	attackerIPRE = regexp.MustCompile(`(\d{1,3}(?:\.\d{1,3}){3})`)
	logStatusRE  = regexp.MustCompile(`\s-?\d+/-?\d+/-?\d+/-?\d+/-?\d+\s(\d{3})\s`)
)

func (d *Daemon) logsAttackers() (map[string]any, error) {
	if !lexists(d.Opts.LogFile) || func() bool { _, err := os.Stat(d.Opts.LogFile); return err != nil }() {
		return map[string]any{"error": "Log file not found", "diagnostic": map[string]any{"log_path": d.Opts.LogFile}}, nil
	}
	total, with400, with451, ipMatches := 0, 0, 0, 0
	a400, a451 := map[string]int{}, map[string]int{}
	order400, order451 := []string{}, []string{}
	d.logScans <- struct{}{}
	defer func() { <-d.logScans }()
	f, err := os.Open(d.Opts.LogFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := fi.Size()
	var start int64
	if d.Opts.LogFileTailMaxBytes > 0 && size > d.Opts.LogFileTailMaxBytes {
		start = size - d.Opts.LogFileTailMaxBytes
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil, err
	}
	r := bufio.NewReaderSize(f, 1<<20)
	if start > 0 {
		if _, err := r.ReadBytes('\n'); err != nil && err != io.EOF {
			return nil, err
		}
	}
	for {
		raw, err := r.ReadBytes('\n')
		if len(raw) > 0 {
			ln := decodeReplace(raw)
			total++
			code := ""
			if m := logStatusRE.FindStringSubmatch(ln); m != nil {
				code = m[1]
			}
			has400, has451 := code == "400", code == "451"
			if has400 {
				with400++
			}
			if has451 {
				with451++
			}
			if has400 || has451 {
				if m := attackerIPRE.FindStringSubmatch(ln); m != nil {
					ip := m[1]
					ipMatches++
					if has400 {
						if _, ok := a400[ip]; !ok {
							order400 = append(order400, ip)
						}
						a400[ip]++
					}
					if has451 {
						if _, ok := a451[ip]; !ok {
							order451 = append(order451, ip)
						}
						a451[ip]++
					}
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	top := func(order []string, counts map[string]int) []any {
		items := append([]string{}, order...)
		sort.SliceStable(items, func(i, j int) bool { return counts[items[i]] > counts[items[j]] })
		if len(items) > 10 {
			items = items[:10]
		}
		out := make([]any, len(items))
		for i, ip := range items {
			out[i] = map[string]any{"ip": ip, "count": counts[ip]}
		}
		return out
	}
	diag := map[string]any{"source": "file", "log_path": d.Opts.LogFile, "total_lines": total, "lines_with_400": with400,
		"lines_with_451": with451, "ip_matches": ipMatches, "partial": start > 0, "scanned_bytes": size - start}
	return map[string]any{"code_400": top(order400, a400), "code_451": top(order451, a451), "diagnostic": diag}, nil
}

// dumpServerState is dump_server_state.
func (d *Daemon) dumpServerState() {
	if !lexists(d.Opts.StateDumpCmd) {
		return
	}
	if _, err := os.Stat(d.Opts.StateDumpCmd); err != nil {
		return
	}
	res, err := execRaw([]string{d.Opts.StateDumpCmd}, nil, 15*time.Second)
	if err != nil {
		log.Printf("Server state dump failed: %s", pyReprErr(err))
		return
	}
	if res.rc != 0 {
		log.Printf("Server state dump exited with %d: %s", res.rc, pyx.TruncRunes(pyStrip(res.stderr), 200))
	}
}
