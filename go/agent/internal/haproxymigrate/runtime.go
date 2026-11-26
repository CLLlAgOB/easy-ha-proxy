package haproxymigrate

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	_ "modernc.org/sqlite"
)

// TableRow represents a single stick-table entry returned by HAProxy Runtime API.
type TableRow struct {
	Address  string
	ExpiryMS int64
	GPC0     int64
	HasGPT0  bool
	GPT0     int64
}

// PeerLayout captures the qualified single-node loopback peers section and tables.
type PeerLayout struct {
	Cluster string            `json:"cluster"`
	Local   string            `json:"local"`
	Port    int               `json:"port"`
	Tables  map[string]string `json:"tables"`
}

// Injectable runtime hooks for unit tests.
var (
	linesFromSocketFunc = defaultLinesFromSocket
	runtimeCmdFunc      = defaultRuntimeCmd
	runtimeInfoFunc     = defaultRuntimeInfo
	tableRowsFunc       = defaultTableRows
	localProbeFunc      = defaultLocalProbe
)

func defaultLinesFromSocket(socketPath, command string) ([]string, error) {
	conn, err := net.DialTimeout("unix", socketPath, 10*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte(command + "\n")); err != nil {
		return nil, err
	}
	if uc, ok := conn.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}
	r := bufio.NewReaderSize(conn, 64*1024)
	var lines []string
	for {
		line, err := r.ReadString('\n')
		if len(line) > 1024*1024 {
			return nil, migErr("Unexpectedly large Runtime API line")
		}
		if len(line) > 0 {
			if !utf8.ValidString(line) {
				return nil, migErr("Invalid UTF-8 in Runtime API response")
			}
			lines = append(lines, strings.TrimRight(line, "\r\n"))
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
	}
	return lines, nil
}

func defaultRuntimeCmd(socketPath, command string) (string, error) {
	lines, err := linesFromSocketFunc(socketPath, command)
	if err != nil {
		return "", err
	}
	return strings.Join(lines, "\n"), nil
}

func defaultRuntimeInfo(socketPath string) (map[string]string, error) {
	lines, err := linesFromSocketFunc(socketPath, "show info")
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, line := range lines {
		if k, v, ok := strings.Cut(line, ": "); ok {
			out[k] = v
		}
	}
	return out, nil
}

func defaultTableRows(socketPath, table string) ([]TableRow, error) {
	lines, err := linesFromSocketFunc(socketPath, "show table "+table)
	if err != nil {
		return nil, err
	}
	header := false
	prefix := "# table: " + table + ", type: ip,"
	var rows []TableRow
	for _, line := range lines {
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, prefix) {
			header = true
			continue
		}
		if !header {
			return nil, migErr("Unexpected critical-table response")
		}
		fields := map[string]string{}
		for _, item := range strings.Fields(line) {
			if k, v, ok := strings.Cut(item, "="); ok {
				fields[k] = v
			}
		}
		addr, err := netip.ParseAddr(fields["key"])
		if err != nil || !addr.Is4() {
			return nil, migErr("Invalid critical-table entry")
		}
		expStr, ok := fields["exp"]
		if !ok {
			return nil, migErr("Invalid critical-table entry")
		}
		exp, err := strconv.ParseInt(expStr, 10, 64)
		if err != nil {
			return nil, migErr("Invalid critical-table entry")
		}
		gpcStr, ok := fields["gpc0"]
		if !ok {
			return nil, migErr("Invalid critical-table entry")
		}
		gpc, err := strconv.ParseInt(gpcStr, 10, 64)
		if err != nil || gpc < 0 || gpc > 0xffffffff {
			return nil, migErr("Invalid critical-table entry")
		}
		row := TableRow{
			Address:  addr.String(),
			ExpiryMS: exp,
			GPC0:     gpc,
		}
		if gptStr, hasGPT := fields["gpt0"]; hasGPT {
			gpt, err := strconv.ParseInt(gptStr, 10, 64)
			if err != nil || gpt < 0 || gpt > 0xffffffff {
				return nil, migErr("Invalid critical-table entry")
			}
			row.HasGPT0 = true
			row.GPT0 = gpt
		} else if table == "tbl_ban" {
			return nil, migErr("Invalid critical-table entry")
		}
		rows = append(rows, row)
	}
	if !header {
		return nil, migErr("Critical table is missing")
	}
	return rows, nil
}

// SnapshotTables streams critical stick-table entries into a SQLite database on disk.
func SnapshotTables(socketPath, destination string, tables map[string]string) (map[string]int, error) {
	ext := filepath.Ext(destination)
	temp := strings.TrimSuffix(destination, ext) + ".new.sqlite"
	_ = os.Remove(temp)
	db, err := sql.Open("sqlite", temp)
	if err != nil {
		return nil, err
	}
	cleanup := true
	defer func() {
		_ = db.Close()
		if cleanup {
			_ = os.Remove(temp)
		}
	}()
	if _, err := db.Exec(`CREATE TABLE entries (tab TEXT, ip TEXT, expiry INTEGER, gpc0 INTEGER, gpt0 INTEGER, seen INTEGER DEFAULT 0, PRIMARY KEY(tab,ip))`); err != nil {
		return nil, err
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	stmt, err := tx.Prepare(`INSERT INTO entries(tab,ip,expiry,gpc0,gpt0) VALUES(?,?,?,?,?)`)
	if err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	tableNames := make([]string, 0, len(tables))
	for name := range tables {
		tableNames = append(tableNames, name)
	}
	sort.Strings(tableNames)
	counts := make(map[string]int, len(tableNames))
	for _, table := range tableNames {
		rows, err := tableRowsFunc(socketPath, table)
		if err != nil {
			_ = stmt.Close()
			_ = tx.Rollback()
			return nil, err
		}
		count := 0
		for _, r := range rows {
			nowMS := nowFunc().UnixMilli()
			var gpt any
			if r.HasGPT0 {
				gpt = r.GPT0
			}
			if _, err := stmt.Exec(table, r.Address, nowMS+r.ExpiryMS, r.GPC0, gpt); err != nil {
				_ = stmt.Close()
				_ = tx.Rollback()
				return nil, err
			}
			count++
		}
		counts[table] = count
	}
	_ = stmt.Close()
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	if err := db.Close(); err != nil {
		return nil, err
	}
	if err := os.Chmod(temp, 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(temp, destination); err != nil {
		return nil, err
	}
	cleanup = false
	return counts, nil
}

// VerifyTables compares live stick-table entries against the SQLite snapshot.
func VerifyTables(socketPath, snapshotPath string, tables map[string]string) (map[string]int, error) {
	changed, extended, missing := 0, 0, 0
	marker := nowFunc().UnixNano()
	db, err := sql.Open("sqlite", snapshotPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	tableNames := make([]string, 0, len(tables))
	for name := range tables {
		tableNames = append(tableNames, name)
	}
	sort.Strings(tableNames)

	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	for _, table := range tableNames {
		rows, err := tableRowsFunc(socketPath, table)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			var snapExp, snapGPC int64
			var snapGPT sql.NullInt64
			err := tx.QueryRow(`SELECT expiry, gpc0, gpt0 FROM entries WHERE tab=? AND ip=?`, table, r.Address).
				Scan(&snapExp, &snapGPC, &snapGPT)
			if err == sql.ErrNoRows {
				continue
			}
			if err != nil {
				return nil, err
			}
			nowMS := nowFunc().UnixMilli()
			if snapExp <= nowMS+1000 {
				continue
			}
			if _, err := tx.Exec(`UPDATE entries SET seen=? WHERE tab=? AND ip=?`, marker, table, r.Address); err != nil {
				return nil, err
			}
			authRenewed := table == "tbl_ip_auth" && r.GPC0 > snapGPC
			gptMismatch := false
			if table == "tbl_ban" {
				if !r.HasGPT0 || !snapGPT.Valid || r.GPT0 != snapGPT.Int64 {
					gptMismatch = true
				}
			}
			if r.GPC0 < snapGPC || gptMismatch {
				changed++
			}
			if !authRenewed && nowMS+r.ExpiryMS > snapExp+2000 {
				extended++
			}
		}
		var m int
		if err := tx.QueryRow(`SELECT count(*) FROM entries WHERE tab=? AND seen!=? AND expiry>?`,
			table, marker, nowFunc().UnixMilli()+1000).Scan(&m); err != nil {
			return nil, err
		}
		missing += m
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	if changed > 0 || extended > 0 || missing > 0 {
		return nil, migErr("Critical state mismatch: missing=%d, changed=%d, extended=%d", missing, changed, extended)
	}
	return map[string]int{"missing": missing, "changed": changed, "extended": extended}, nil
}

func readOnlySQLiteURI(path string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?mode=ro"
}

var (
	localpeerRe = regexp.MustCompile(`(?m)^[ \t]+localpeer ([A-Za-z0-9_-]+)[ \t]*$`)
	peersSecRe  = regexp.MustCompile(`(?m)^peers ([A-Za-z0-9_-]+)[ \t]*\n((?:[ \t].*\n|\n|#[^\n]*\n)*)`)
	peerLineRe  = regexp.MustCompile(`(?m)^[ \t]+peer ([A-Za-z0-9_-]+) (127\.0\.0\.1):([0-9]+)[ \t]*$`)
)

// ParsePeerLayout qualifies the single-node loopback peers section and critical tables.
func ParsePeerLayout(text string) (PeerLayout, error) {
	norm := strings.ReplaceAll(text, "\r\n", "\n")
	if !strings.HasSuffix(norm, "\n") {
		norm += "\n"
	}
	locals := localpeerRe.FindAllStringSubmatch(norm, -1)
	sections := peersSecRe.FindAllStringSubmatch(norm, -1)
	if len(locals) != 1 || len(sections) != 1 {
		return PeerLayout{}, migErr("Exactly one local peers section is required")
	}
	localName := locals[0][1]
	clusterName := sections[0][1]
	body := sections[0][2]
	peers := peerLineRe.FindAllStringSubmatch(body, -1)
	var significant []string
	for _, line := range strings.Split(body, "\n") {
		t := strings.TrimSpace(line)
		if t != "" && !strings.HasPrefix(t, "#") {
			significant = append(significant, t)
		}
	}
	if len(peers) != 1 || len(significant) != 1 || peers[0][1] != localName {
		return PeerLayout{}, migErr("Remote/custom peer layouts need a separate migration procedure")
	}
	port, err := strconv.Atoi(peers[0][3])
	if err != nil {
		return PeerLayout{}, migErr("Remote/custom peer layouts need a separate migration procedure")
	}

	stickRe := regexp.MustCompile(`^stick-table type ip size [0-9]+[km]? expire [0-9]+[smhd] store (?:gpc0,gpt0|gpt0,gpc0|gpc0) peers ` + regexp.QuoteMeta(clusterName) + `$`)
	tables := map[string]string{}
	for _, table := range []string{"tbl_ban", "tbl_ip_auth"} {
		beRe := regexp.MustCompile(`(?m)^backend ` + regexp.QuoteMeta(table) + `[ \t]*\n((?:[ \t].*\n|\n|#[^\n]*\n)*)`)
		block := beRe.FindStringSubmatch(norm)
		if block == nil {
			if table == "tbl_ban" {
				return PeerLayout{}, migErr("Ban table is missing")
			}
			continue
		}
		var decls []string
		for _, line := range strings.Split(block[1], "\n") {
			t := strings.TrimSpace(line)
			if strings.HasPrefix(t, "stick-table ") {
				decls = append(decls, t)
			}
		}
		if len(decls) != 1 || !stickRe.MatchString(decls[0]) {
			return PeerLayout{}, migErr("Unsupported critical-table definition")
		}
		if table == "tbl_ban" && !strings.Contains(decls[0], "gpt0") {
			return PeerLayout{}, migErr("Ban reason counter is missing")
		}
		tables[table] = decls[0]
	}
	return PeerLayout{Cluster: clusterName, Local: localName, Port: port, Tables: tables}, nil
}

// AddSeed inserts a temporary migration peer right after the local peer line.
func AddSeed(text string, layout PeerLayout, name string, port int) (string, error) {
	marker := fmt.Sprintf("    peer %s 127.0.0.1:%d", layout.Local, layout.Port)
	lines := strings.SplitAfter(text, "\n")
	var matches []int
	for i, line := range lines {
		if strings.TrimRight(line, "\r\n") == marker {
			matches = append(matches, i)
		}
	}
	if len(matches) != 1 {
		return "", migErr("Local peer declaration changed")
	}
	idx := matches[0]
	insert := fmt.Sprintf("    peer %s 127.0.0.1:%d\n", name, port)
	out := make([]string, 0, len(lines)+1)
	out = append(out, lines[:idx+1]...)
	out = append(out, insert)
	out = append(out, lines[idx+1:]...)
	return strings.Join(out, ""), nil
}

// SeedConfig generates the temporary standalone HAProxy seed peer configuration.
func SeedConfig(layout PeerLayout, name string, port int, socketPath string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `global
    localpeer %s
    nbthread 1
    user haproxy
    group haproxy
    stats socket %s mode 600 user root group root level admin
defaults
    mode http
    timeout connect 2s
    timeout client 5s
    timeout server 5s
peers %s
    peer %s 127.0.0.1:%d
    peer %s 127.0.0.1:%d
`, name, socketPath, layout.Cluster, name, port, layout.Local, layout.Port)
	names := make([]string, 0, len(layout.Tables))
	for k := range layout.Tables {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, table := range names {
		fmt.Fprintf(&b, "\nbackend %s\n    %s\n", table, layout.Tables[table])
	}
	return b.String()
}

// InternalCAPath returns the internal root CA path where the installer and certd keep it.
func InternalCAPath() string {
	root := os.Getenv("HAPROXY_CA_ROOT_DIR")
	if root == "" {
		root = "/etc/haproxy/certificate-authorities"
	}
	return filepath.Join(root, "internal", "ca.crt")
}

func defaultLocalProbe(domain, path string) (int, error) {
	if !hostnameRe.MatchString(domain) {
		return 0, migErr("Invalid control-plane hostname")
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	ca := InternalCAPath()
	if isRegularFile(ca) {
		if pemBytes, rerr := os.ReadFile(ca); rerr == nil {
			pool.AppendCertsFromPEM(pemBytes)
		}
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	tr := &http.Transport{
		DialTLSContext: nil,
		DialContext: func(_ context.Context, network, _ string) (net.Conn, error) {
			return dialer.Dial(network, "127.0.0.1:443")
		},
		TLSClientConfig: &tls.Config{
			ServerName: domain,
			RootCAs:    pool,
			MinVersion: tls.VersionTLS12,
		},
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport: tr,
		Timeout:   5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest("GET", "https://"+domain+path, nil)
	if err != nil {
		return 0, err
	}
	req.Host = domain
	req.Header.Set("Connection", "close")
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 65536))
	return resp.StatusCode, nil
}
