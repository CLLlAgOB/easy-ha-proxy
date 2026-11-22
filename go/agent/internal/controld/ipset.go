package controld

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/haproxy"
)

var (
	stickRowRe = regexp.MustCompile(`key=(\d+\.\d+\.\d+\.\d+).*?\bgpc0=(\d+)`)
	stickExpRe = regexp.MustCompile(`\bexp=(\d+)`)
	stickGptRe = regexp.MustCompile(`\bgpt0=(\d+)`)
)

// StickTableEntry represents one flagged (gpc0 > 0) IPv4 entry from a HAProxy stick table.
type StickTableEntry struct {
	IP         string `json:"ip"`
	ExpSeconds int    `json:"exp_seconds"`
	Code       int    `json:"code"`
}

// ParseStickTable parses HAProxy `show table <table>` output.
// Returns ok=false when the table header is missing (e.g. "No such table"), so callers
// never mistake a failed read for an empty table and accidentally drop active bans.
func ParseStickTable(raw, tableName string) (map[string]StickTableEntry, bool) {
	lines := strings.Split(raw, "\n")
	if len(lines) == 0 || !strings.HasPrefix(strings.TrimSpace(lines[0]), "# table: "+tableName+",") {
		return nil, false
	}
	out := make(map[string]StickTableEntry)
	for _, line := range lines[1:] {
		m := stickRowRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		gpc0, err := strconv.Atoi(m[2])
		if err != nil || gpc0 <= 0 {
			continue
		}
		ip := m[1]
		if addr, err := netip.ParseAddr(ip); err != nil || !addr.Is4() {
			continue
		}
		expSec := 0
		if em := stickExpRe.FindStringSubmatch(line); em != nil {
			if ms, err := strconv.Atoi(em[1]); err == nil && ms > 0 {
				expSec = ms / 1000
			}
		}
		code := 0
		if cm := stickGptRe.FindStringSubmatch(line); cm != nil {
			code, _ = strconv.Atoi(cm[1])
		}
		out[ip] = StickTableEntry{IP: ip, ExpSeconds: expSec, Code: code}
	}
	return out, true
}

// IpsetRunner abstracts kernel ipset CLI operations for deterministic testing.
type IpsetRunner interface {
	List(ctx context.Context, name string) (members map[string]struct{}, hasTimeout bool, err error)
	Create(ctx context.Context, name string, withTimeout bool) error
	Restore(ctx context.Context, script string) error
	SwapAndDestroy(ctx context.Context, liveName, tempName string) error
}

// ExecIpsetRunner executes real `ipset` commands with bounded timeouts.
type ExecIpsetRunner struct {
	Bin string
}

func (r *ExecIpsetRunner) bin() string {
	if r.Bin != "" {
		return r.Bin
	}
	return "ipset"
}

func (r *ExecIpsetRunner) run(ctx context.Context, stdin string, args ...string) (string, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, r.bin(), args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errBuf.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("ipset %s: %s", strings.Join(args, " "), msg)
	}
	return out.String(), nil
}

func (r *ExecIpsetRunner) List(ctx context.Context, name string) (map[string]struct{}, bool, error) {
	out, err := r.run(ctx, "", "list", name)
	if err != nil {
		return nil, false, err
	}
	members := make(map[string]struct{})
	hasTimeout := false
	capture := false
	for _, rawLine := range strings.Split(out, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		if !capture && strings.HasPrefix(line, "Header:") {
			hasTimeout = strings.Contains(" "+line+" ", " timeout ")
			continue
		}
		if strings.HasPrefix(line, "Members:") {
			capture = true
			continue
		}
		if !capture {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 {
			if addr, err := netip.ParseAddr(fields[0]); err == nil && addr.Is4() {
				members[addr.String()] = struct{}{}
			}
		}
	}
	return members, hasTimeout, nil
}

func (r *ExecIpsetRunner) Create(ctx context.Context, name string, withTimeout bool) error {
	args := []string{"create", name, "hash:ip", "family", "inet"}
	if withTimeout {
		args = append(args, "timeout", "0")
	}
	args = append(args, "-exist")
	_, err := r.run(ctx, "", args...)
	return err
}

func (r *ExecIpsetRunner) Restore(ctx context.Context, script string) error {
	if strings.TrimSpace(script) == "" {
		return nil
	}
	_, err := r.run(ctx, script, "-exist", "restore")
	return err
}

func (r *ExecIpsetRunner) SwapAndDestroy(ctx context.Context, liveName, tempName string) error {
	if _, err := r.run(ctx, "", "swap", liveName, tempName); err != nil {
		return err
	}
	_, err := r.run(ctx, "", "destroy", tempName)
	return err
}

func buildIpsetRestoreScript(setName string, toAdd, toDel []string, timeouts map[string]int) string {
	sort.Strings(toDel)
	sort.Strings(toAdd)
	var b strings.Builder
	// Deletions run first so a full set frees slots before additions.
	for _, ip := range toDel {
		if addr, err := netip.ParseAddr(ip); err == nil && addr.Is4() {
			fmt.Fprintf(&b, "del %s %s\n", setName, addr.String())
		}
	}
	for _, ip := range toAdd {
		addr, err := netip.ParseAddr(ip)
		if err != nil || !addr.Is4() {
			continue
		}
		if timeouts != nil {
			ttl := timeouts[ip]
			if ttl < 1 {
				ttl = 1
			}
			fmt.Fprintf(&b, "add %s %s timeout %d\n", setName, addr.String(), ttl)
		} else {
			fmt.Fprintf(&b, "add %s %s\n", setName, addr.String())
		}
	}
	return b.String()
}

// EnsureIpsets creates ban, page, and zero-trust auth ipsets (upgrading legacy auth set to timeout-enabled).
func (c *Controller) EnsureIpsets(ctx context.Context) error {
	for _, name := range []string{c.Opts.IpsetName, c.Opts.PageIpset} {
		if err := c.Ipset.Create(ctx, name, false); err != nil {
			return err
		}
	}
	members, hasTimeout, err := c.Ipset.List(ctx, c.Opts.AuthIpset)
	if err != nil {
		return c.Ipset.Create(ctx, c.Opts.AuthIpset, true)
	}
	if hasTimeout {
		return nil
	}
	tempName := c.Opts.AuthIpset + "_t"
	if len(tempName) > 31 {
		tempName = tempName[:31]
	}
	if err := c.Ipset.Create(ctx, tempName, true); err != nil {
		return err
	}
	if len(members) > 0 {
		add := make([]string, 0, len(members))
		ttls := make(map[string]int, len(members))
		for ip := range members {
			add = append(add, ip)
			ttls[ip] = c.Opts.AuthIpsetTTLSec
		}
		if err := c.Ipset.Restore(ctx, buildIpsetRestoreScript(tempName, add, nil, ttls)); err != nil {
			return err
		}
	}
	return c.Ipset.SwapAndDestroy(ctx, c.Opts.AuthIpset, tempName)
}

func (c *Controller) haproxyClient() *haproxy.Client {
	if c.HAProxy != nil {
		return c.HAProxy
	}
	return haproxy.NewClient(c.Opts.HAProxyAdminSocket)
}

func (c *Controller) haproxyUptime(ctx context.Context) (int, bool) {
	info, err := c.haproxyClient().ShowInfo(ctx)
	if err != nil {
		return 0, false
	}
	raw, ok := info["Uptime_sec"]
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, false
	}
	return n, true
}

// SyncBansOnce mirrors tbl_ban -> haproxy_ban + haproxy_ban_page with restart grace protection.
func (c *Controller) SyncBansOnce(ctx context.Context) error {
	raw, err := c.haproxyClient().Command(ctx, "show table "+c.Opts.BanTable)
	if err != nil {
		return err
	}
	banned, ok := ParseStickTable(raw, c.Opts.BanTable)
	if !ok {
		return nil // Never drop firewall bans when HAProxy did not return the table header.
	}

	firstSteps := make(map[string]struct{})
	for ip, ent := range banned {
		if ent.Code == FirstStepPageCode {
			firstSteps[ip] = struct{}{}
		}
	}

	ipsetMembers, _, _ := c.Ipset.List(ctx, c.Opts.IpsetName)
	pageMembers, _, _ := c.Ipset.List(ctx, c.Opts.PageIpset)
	if len(banned) == 0 && len(ipsetMembers) == 0 && len(pageMembers) == 0 {
		return nil
	}

	// First-step bans enter PAGE_IPSET BEFORE IPSET_NAME so TCP rules never drop them early.
	var pageAdd, pageDel []string
	for ip := range firstSteps {
		if _, has := pageMembers[ip]; !has {
			pageAdd = append(pageAdd, ip)
		}
	}
	for ip := range pageMembers {
		if _, has := firstSteps[ip]; !has {
			pageDel = append(pageDel, ip)
		}
	}
	if len(pageAdd) > 0 {
		_ = c.Ipset.Restore(ctx, buildIpsetRestoreScript(c.Opts.PageIpset, pageAdd, nil, nil))
	}

	var toAdd, toDel []string
	for ip := range banned {
		if _, has := ipsetMembers[ip]; !has {
			toAdd = append(toAdd, ip)
		}
	}
	for ip := range ipsetMembers {
		if _, has := banned[ip]; !has {
			toDel = append(toDel, ip)
		}
	}

	// During the restart grace window, never remove bans from the firewall while HAProxy repopulates.
	if len(toDel) > 0 && c.Opts.BanRestartGraceSec > 0 {
		if uptime, known := c.haproxyUptime(ctx); known && uptime < c.Opts.BanRestartGraceSec {
			log.Printf("controld: HAProxy uptime %ds < grace %ds; keeping %d existing firewall bans",
				uptime, c.Opts.BanRestartGraceSec, len(toDel))
			toDel = nil
		}
	}

	if len(toAdd) > 0 || len(toDel) > 0 {
		if err := c.Ipset.Restore(ctx, buildIpsetRestoreScript(c.Opts.IpsetName, toAdd, toDel, nil)); err != nil {
			return err
		}
	}

	// Remove expired first-step entries from PAGE_IPSET AFTER IPSET_NAME update.
	if len(pageDel) > 0 {
		_ = c.Ipset.Restore(ctx, buildIpsetRestoreScript(c.Opts.PageIpset, nil, pageDel, nil))
	}
	return nil
}

// SyncAuthOnce mirrors tbl_ip_auth -> haproxy_ip_auth with bounded per-entry timeouts.
func (c *Controller) SyncAuthOnce(ctx context.Context) error {
	raw, err := c.haproxyClient().Command(ctx, "show table "+c.Opts.AuthTable)
	if err != nil {
		return err
	}
	authorized, ok := ParseStickTable(raw, c.Opts.AuthTable)
	if !ok {
		return nil
	}
	members, hasTimeout, err := c.Ipset.List(ctx, c.Opts.AuthIpset)
	if err != nil {
		members = map[string]struct{}{}
	}
	if len(authorized) == 0 && len(members) == 0 {
		return nil
	}

	var toDel []string
	for ip := range members {
		if _, still := authorized[ip]; !still {
			toDel = append(toDel, ip)
		}
	}
	if hasTimeout {
		toAdd := make([]string, 0, len(authorized))
		ttls := make(map[string]int, len(authorized))
		for ip, ent := range authorized {
			toAdd = append(toAdd, ip)
			ttl := ent.ExpSeconds
			if ttl < 1 {
				ttl = 1
			}
			if ttl > c.Opts.AuthIpsetTTLSec {
				ttl = c.Opts.AuthIpsetTTLSec
			}
			ttls[ip] = ttl
		}
		return c.Ipset.Restore(ctx, buildIpsetRestoreScript(c.Opts.AuthIpset, toAdd, toDel, ttls))
	}
	var toAdd []string
	for ip := range authorized {
		if _, has := members[ip]; !has {
			toAdd = append(toAdd, ip)
		}
	}
	return c.Ipset.Restore(ctx, buildIpsetRestoreScript(c.Opts.AuthIpset, toAdd, toDel, nil))
}

// DumpServerState persists `show servers state` atomically before a HAProxy reload.
func (c *Controller) DumpServerState(ctx context.Context) {
	if c.Opts.ServerStatePath == "" {
		return
	}
	raw, err := c.haproxyClient().Command(ctx, "show servers state")
	if err != nil || strings.TrimSpace(raw) == "" {
		return
	}
	dir := filepath.Dir(c.Opts.ServerStatePath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	tmp, err := os.CreateTemp(dir, ".server-state.*.tmp")
	if err != nil {
		return
	}
	tmpName := tmp.Name()
	if _, err := tmp.WriteString(raw); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return
	}
	_ = tmp.Chmod(0o644)
	_ = tmp.Sync()
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return
	}
	_ = os.Rename(tmpName, c.Opts.ServerStatePath)
}

// LogsAttackers returns the current banned attacker entries from HAProxy's ban table.
func (c *Controller) LogsAttackers(ctx context.Context) ([]StickTableEntry, error) {
	raw, err := c.haproxyClient().Command(ctx, "show table "+c.Opts.BanTable)
	if err != nil {
		return nil, err
	}
	entries, ok := ParseStickTable(raw, c.Opts.BanTable)
	if !ok {
		return []StickTableEntry{}, nil
	}
	out := make([]StickTableEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out, nil
}

// RunBansLoop continuously synchronizes ban and zero-trust auth ipsets until ctx is canceled.
func (c *Controller) RunBansLoop(ctx context.Context) {
	_ = c.EnsureIpsets(ctx)
	interval := time.Duration(max(2, c.Opts.BanSyncIntervalSec)) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = c.SyncBansOnce(ctx)
			_ = c.SyncAuthOnce(ctx)
		}
	}
}
