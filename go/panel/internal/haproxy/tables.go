package haproxy

import (
	"bufio"
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"easy-ha-proxy/panel/internal/daemons"
)

// TableEntry represents one parsed row from HAProxy `show table <name>`.
type TableEntry struct {
	Key    string            `json:"key"`
	ExpMs  int64             `json:"exp"`
	Fields map[string]string `json:"fields,omitempty"`
}

// ParseShowTable parses HAProxy's `show table <name>` output.
func ParseShowTable(raw string) []TableEntry {
	var out []TableEntry
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := make(map[string]string)
		var key string
		var exp int64
		for _, tok := range strings.Fields(line) {
			k, v, ok := strings.Cut(tok, "=")
			if !ok {
				continue
			}
			switch k {
			case "key":
				key = v
			case "exp":
				exp, _ = strconv.ParseInt(v, 10, 64)
			default:
				fields[k] = v
			}
		}
		if key != "" {
			out = append(out, TableEntry{Key: key, ExpMs: exp, Fields: fields})
		}
	}
	return out
}

// ShowTable runs `show table <name>` against HAProxy's runtime socket.
func (rt *Runtime) ShowTable(ctx context.Context, table string) (string, []TableEntry, error) {
	clean := strings.TrimSpace(table)
	if clean == "" {
		return "", nil, &ValidationError{Msg: "table name is required"}
	}
	raw, err := daemons.LineCommand(ctx, rt.SocketPath, "show table "+clean, 5*time.Second, 8*1024*1024)
	if err != nil {
		return "", nil, err
	}
	return raw, ParseShowTable(raw), nil
}

// ListTableNames runs `show table` and returns the declared table names.
func (rt *Runtime) ListTableNames(ctx context.Context) ([]string, error) {
	raw, err := daemons.LineCommand(ctx, rt.SocketPath, "show table", 5*time.Second, 2*1024*1024)
	if err != nil {
		return nil, err
	}
	var names []string
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "# table:") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, "# table:"))
		name, _, _ := strings.Cut(rest, ",")
		name = strings.TrimSpace(name)
		if name != "" {
			names = append(names, name)
		}
	}
	return names, nil
}

// ClearTableKey removes a single IP key from a HAProxy stick-table.
func (rt *Runtime) ClearTableKey(ctx context.Context, table, ip string) error {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return &ValidationError{Msg: "invalid IP address"}
	}
	cleanTable := strings.TrimSpace(table)
	if cleanTable == "" {
		return &ValidationError{Msg: "table name is required"}
	}
	_, err = daemons.LineCommand(ctx, rt.SocketPath, fmt.Sprintf("clear table %s key %s", cleanTable, addr.String()), 5*time.Second, 64*1024)
	return err
}

// ConnectionsSummary aggregates current frontend/backend connection counts
// from HAProxy `show stat`.
func (rt *Runtime) ConnectionsSummary(ctx context.Context) (map[string]any, error) {
	raw, err := daemons.LineCommand(ctx, rt.SocketPath, "show stat", 5*time.Second, 8*1024*1024)
	if err != nil {
		return nil, err
	}
	rows := ParseShowStat(raw)
	frontends := make([]map[string]any, 0)
	backends := make([]map[string]any, 0)
	totalCurrent := 0
	totalRate := 0

	for _, row := range rows {
		px := row["pxname"]
		sv := row["svname"]
		scur := parseInt(row["scur"])
		rate := parseInt(row["rate"])
		switch sv {
		case "FRONTEND":
			totalCurrent += scur
			totalRate += rate
			frontends = append(frontends, map[string]any{
				"name":   px,
				"scur":   scur,
				"smax":   parseInt(row["smax"]),
				"rate":   rate,
				"status": row["status"],
			})
		case "BACKEND":
			if !rt.isOperable(px) {
				continue
			}
			backends = append(backends, map[string]any{
				"name":   px,
				"label":  rt.DisplayName(px),
				"scur":   scur,
				"smax":   parseInt(row["smax"]),
				"rate":   rate,
				"status": row["status"],
			})
		}
	}

	return map[string]any{
		"ok":         true,
		"total_scur": totalCurrent,
		"total_rate": totalRate,
		"frontends":  frontends,
		"backends":   backends,
	}, nil
}

// ReadWhitelistFile reads non-comment lines from a HAProxy ACL whitelist file.
func ReadWhitelistFile(path string) []string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return []string{}
	}
	seen := make(map[string]struct{})
	var out []string
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, dup := seen[line]; !dup {
			seen[line] = struct{}{}
			out = append(out, line)
		}
	}
	sort.Strings(out)
	return out
}

// AddToWhitelistFile atomically appends an IP or CIDR to a HAProxy ACL file
// if not already present, and updates the live HAProxy ACL if reachable.
func (rt *Runtime) AddToWhitelistFile(ctx context.Context, aclFile, rawEntry string) error {
	entry, err := normalizeIPOrCIDR(rawEntry)
	if err != nil {
		return &ValidationError{Msg: "invalid IP or CIDR"}
	}
	existing := ReadWhitelistFile(aclFile)
	for _, item := range existing {
		if item == entry {
			return nil
		}
	}
	existing = append(existing, entry)
	sort.Strings(existing)

	dir := filepath.Dir(aclFile)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmp := aclFile + ".tmp"
	content := strings.Join(existing, "\n") + "\n"
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, aclFile); err != nil {
		_ = os.Remove(tmp)
		return err
	}

	// Best-effort live HAProxy ACL update (matching services.py behavior).
	if rt.SocketPath != "" {
		_, _ = daemons.LineCommand(ctx, rt.SocketPath, fmt.Sprintf("add acl %s %s", aclFile, entry), 3*time.Second, 64*1024)
	}
	return nil
}

func normalizeIPOrCIDR(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return "", err
		}
		return p.Masked().String(), nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return "", err
	}
	return addr.String(), nil
}
