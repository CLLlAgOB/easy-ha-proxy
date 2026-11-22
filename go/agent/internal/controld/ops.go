package controld

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/alerts"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/haproxy"
)

// Controller executes HAProxy control-plane operations with guarded serialization.
type Controller struct {
	Opts        Options
	Ipset       IpsetRunner
	HAProxy     *haproxy.Client
	Alerts      *alerts.Client
	UDPFailover *UDPFailoverManager
	CheckRunner func(ctx context.Context, checks []ControlPlaneCheck) (bool, []CheckResult)
	applyMu     sync.Mutex
	logScanCh   chan struct{}
}

// NewController constructs a Controller using opts.
func NewController(opts Options) *Controller {
	c := &Controller{
		Opts:      opts,
		Ipset:     &ExecIpsetRunner{Bin: opts.IpsetBin},
		HAProxy:   haproxy.NewClient(opts.HAProxyAdminSocket),
		Alerts:    alerts.FromEnv(),
		logScanCh: make(chan struct{}, 2),
	}
	c.UDPFailover = NewUDPFailoverManager(opts.UDPFailoverState, c.UDPApply, c.Alerts)
	return c
}

// UDPApply restarts iptables-haproxy-udp.service synchronously.
func (c *Controller) UDPApply(ctx context.Context) error {
	cmdCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cmdCtx, c.Opts.SystemctlBin, "restart", "iptables-haproxy-udp.service").CombinedOutput()
	if err != nil {
		return fmt.Errorf("UDP forwarding apply failed: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (c *Controller) runHAProxyCheckFile(ctx context.Context, path string) (int, string, string, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, c.Opts.HAProxyBin, "-c", "-f", path)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if errors.Is(cmdCtx.Err(), context.DeadlineExceeded) {
		return 124, "", "haproxy -c did not finish within 30 seconds and was stopped", nil
	}
	rc := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			rc = exitErr.ExitCode()
		} else {
			return 0, "", "", err
		}
	}
	return rc, stdout.String(), stderr.String(), nil
}

func (c *Controller) runSystemctlReload(ctx context.Context) (bool, string) {
	cmdCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, c.Opts.SystemctlBin, "reload", "haproxy")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if errors.Is(cmdCtx.Err(), context.DeadlineExceeded) {
		return false, "the reload did not finish within 30 seconds and was stopped"
	}
	if err == nil {
		msg := strings.TrimSpace(stdout.String())
		if msg == "" {
			msg = "reloaded"
		}
		return true, msg
	}
	msg := strings.TrimSpace(stderr.String())
	if msg == "" {
		msg = err.Error()
	}
	return false, msg
}

// RebootScheduled returns true when either reboot marker exists on disk.
func (c *Controller) RebootScheduled() bool {
	if c.Opts.MaintenanceRebootMarker != "" {
		if _, err := os.Lstat(c.Opts.MaintenanceRebootMarker); err == nil {
			return true
		}
	}
	if c.Opts.AssistantRebootMarker != "" {
		if _, err := os.Lstat(c.Opts.AssistantRebootMarker); err == nil {
			return true
		}
	}
	return false
}

// CheckConfig validates base64-encoded haproxy.cfg against policy and `haproxy -c`.
func (c *Controller) CheckConfig(ctx context.Context, b64 string) (int, string, string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return 0, "", "", fmt.Errorf("invalid base64 config: %w", err)
	}
	if len(raw) > MaxConfigBytes {
		return 0, "", "", errors.New("HAProxy configuration exceeds the allowed size")
	}
	if err := EnforceConfigPolicy(raw); err != nil {
		return 0, "", "", err
	}

	tmp, err := os.CreateTemp("", "hapadm-check-*.cfg")
	if err != nil {
		return 0, "", "", err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return 0, "", "", err
	}
	if err := tmp.Close(); err != nil {
		return 0, "", "", err
	}

	cmdCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, c.Opts.HAProxyBin, "-c", "-f", tmpPath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if errors.Is(cmdCtx.Err(), context.DeadlineExceeded) {
		return 124, "", "haproxy -c did not finish within 30 seconds and was stopped", nil
	}
	rc := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			rc = exitErr.ExitCode()
		} else {
			return 0, "", "", err
		}
	}
	return rc, stdout.String(), stderr.String(), nil
}

// WriteConfig validates and atomically replaces HAPROXY_CFG_PATH.
func (c *Controller) WriteConfig(ctx context.Context, b64 string) error {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return fmt.Errorf("invalid base64 config: %w", err)
	}
	if len(raw) == 0 || len(raw) > MaxConfigBytes {
		return errors.New("invalid HAProxy configuration size")
	}
	if err := EnforceConfigPolicy(raw); err != nil {
		return err
	}

	c.applyMu.Lock()
	defer c.applyMu.Unlock()

	dir := filepath.Dir(c.Opts.HAProxyCfgPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".haproxy.cfg.*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}

	cmdCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cmdCtx, c.Opts.HAProxyBin, "-c", "-f", tmpPath).CombinedOutput()
	if err != nil {
		cleanup()
		return fmt.Errorf("haproxy -c failed: %s", strings.TrimSpace(string(out)))
	}
	if err := os.Rename(tmpPath, c.Opts.HAProxyCfgPath); err != nil {
		cleanup()
		return err
	}
	return nil
}

// Reload runs `systemctl reload haproxy`.
func (c *Controller) Reload(ctx context.Context) (bool, string) {
	c.applyMu.Lock()
	defer c.applyMu.Unlock()

	cmdCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, c.Opts.SystemctlBin, "reload", "haproxy")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if errors.Is(cmdCtx.Err(), context.DeadlineExceeded) {
		return false, "the reload did not finish within 30 seconds and was stopped"
	}
	if err == nil {
		msg := strings.TrimSpace(stdout.String())
		if msg == "" {
			msg = "reloaded"
		}
		return true, msg
	}
	msg := strings.TrimSpace(stderr.String())
	if msg == "" {
		msg = err.Error()
	}
	return false, msg
}

// ListConfigVersions returns metadata entries from CONFIG_HISTORY_DIR newest first.
func (c *Controller) ListConfigVersions(limit int) ([]map[string]any, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	entries, err := os.ReadDir(c.Opts.ConfigHistoryDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []map[string]any{}, nil
		}
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, ent := range entries {
		if ent.IsDir() {
			names = append(names, ent.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))

	out := make([]map[string]any, 0, min(len(names), limit))
	for _, name := range names {
		if len(out) >= limit {
			break
		}
		metaBytes, err := os.ReadFile(filepath.Join(c.Opts.ConfigHistoryDir, name, "meta.json"))
		if err != nil {
			continue
		}
		var meta map[string]any
		if err := json.Unmarshal(metaBytes, &meta); err != nil {
			continue
		}
		if _, hasID := meta["id"]; !hasID {
			meta["id"] = name
		}
		out = append(out, meta)
	}
	return out, nil
}

// GetConfigVersion reads one version snapshot's metadata and source files.
func (c *Controller) GetConfigVersion(id string) (map[string]any, error) {
	cleanID := strings.TrimSpace(id)
	if cleanID == "" || strings.Contains(cleanID, "/") || strings.Contains(cleanID, "\\") || strings.Contains(cleanID, "..") {
		return nil, errors.New("invalid config version id")
	}
	verDir := filepath.Join(c.Opts.ConfigHistoryDir, cleanID)
	metaBytes, err := os.ReadFile(filepath.Join(verDir, "meta.json"))
	if err != nil {
		return nil, fmt.Errorf("config version not found: %s", cleanID)
	}
	var meta map[string]any
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return nil, err
	}
	sources := map[string]string{}
	for _, name := range []string{"vars.yml", "websites.yml", "tcp.yml"} {
		if b, err := os.ReadFile(filepath.Join(verDir, name)); err == nil {
			sources[name] = string(b)
		}
	}
	meta["sources"] = sources
	return meta, nil
}

// UDPPortsInUse parses /proc/net/udp and /proc/net/udp6 to find bound ports in [start, end].
func (c *Controller) UDPPortsInUse(start, end int) []int {
	busySet := map[int]struct{}{}
	for _, p := range []string{c.Opts.ProcNetUDPPath, c.Opts.ProcNetUDP6Path} {
		parseProcNetPorts(p, start, end, busySet)
	}
	ports := make([]int, 0, len(busySet))
	for port := range busySet {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports
}

func parseProcNetPorts(path string, start, end int, out map[int]struct{}) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		colon := strings.LastIndexByte(fields[1], ':')
		if colon < 0 {
			continue
		}
		port64, err := strconv.ParseInt(fields[1][colon+1:], 16, 32)
		if err != nil {
			continue
		}
		port := int(port64)
		if port >= start && port <= end {
			out[port] = struct{}{}
		}
	}
}

// UDPStatus reads durable UDP forwarding and failover JSON state files.
func (c *Controller) UDPStatus() map[string]any {
	res := map[string]any{"ok": true}
	if b, err := os.ReadFile(c.Opts.UDPForwardState); err == nil && len(b) <= 16*1024 {
		var st map[string]any
		if json.Unmarshal(b, &st) == nil {
			for k, v := range st {
				res[k] = v
			}
		}
	}
	if b, err := os.ReadFile(c.Opts.UDPFailoverState); err == nil && len(b) <= 64*1024 {
		var fo map[string]any
		if json.Unmarshal(b, &fo) == nil {
			res["failover"] = fo
		}
	}
	return res
}

// GeoIPStatus reads selection.json and the current GeoIP release with SHA-256 verification.
func (c *Controller) GeoIPStatus() map[string]any {
	selPath := filepath.Join(c.Opts.GeoIPDir, "selection.json")
	selection := map[string]any{
		"available":             false,
		"countries":             []string{},
		"access_filter_enabled": false,
		"revision":              "",
	}
	var selErr string
	if raw, err := os.ReadFile(selPath); err == nil {
		var parsed map[string]any
		if err := json.Unmarshal(raw, &parsed); err == nil {
			sum := sha256.Sum256(raw)
			parsed["available"] = true
			parsed["revision"] = hex.EncodeToString(sum[:])
			selection = parsed
		} else {
			selErr = err.Error()
		}
	} else if !os.IsNotExist(err) {
		selErr = err.Error()
	}

	database := map[string]any{"available": false, "integrity_ok": false}
	curLink := filepath.Join(c.Opts.GeoIPDir, "current")
	if resolved, err := filepath.EvalSymlinks(curLink); err == nil {
		stateBytes, err := os.ReadFile(filepath.Join(resolved, "state.json"))
		if err == nil {
			var state map[string]any
			if json.Unmarshal(stateBytes, &state) == nil {
				dbPath := filepath.Join(resolved, "dbip-country-lite.mmdb")
				allowedPath := filepath.Join(resolved, "allowed.geo")
				var dbSize, allowedSize int64
				if fi, err := os.Stat(dbPath); err == nil {
					dbSize = fi.Size()
				}
				if fi, err := os.Stat(allowedPath); err == nil {
					allowedSize = fi.Size()
				}
				fmtVer, _ := state["release_format_version"].(float64)
				dbHash, _ := state["database_sha256"].(string)
				alHash, _ := state["allowed_sha256"].(string)
				integrityOK := int(fmtVer) == 1 && fileSHA256Matches(dbPath, dbHash) && fileSHA256Matches(allowedPath, alHash)
				database = map[string]any{
					"available":             dbSize > 0,
					"release":               filepath.Base(resolved),
					"provider":              state["provider"],
					"source_period":         state["source_period"],
					"activated_at":          state["activated_at"],
					"size_bytes":            dbSize,
					"allowed_size_bytes":    allowedSize,
					"countries":             state["countries"],
					"access_filter_enabled": state["access_filter_enabled"],
					"integrity_ok":          integrityOK,
				}
			}
		}
	}

	out := map[string]any{
		"ok":        selErr == "",
		"database":  database,
		"selection": selection,
	}
	if selErr != "" {
		out["error"] = selErr
	}
	return out
}

func fileSHA256Matches(p, expected string) bool {
	if len(expected) != 64 {
		return false
	}
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false
	}
	return strings.EqualFold(hex.EncodeToString(h.Sum(nil)), expected)
}

// LogsForIP runs a concurrency-bounded reverse-chunk log search for one IP address.
func (c *Controller) LogsForIP(ip string, limit int) ([]string, error) {
	c.logScanCh <- struct{}{}
	defer func() { <-c.logScanCh }()
	return GrepLastLogsForIP(c.Opts.LogFile, ip, limit, c.Opts.LogTailChunk, c.Opts.LogTailMaxBytes)
}
