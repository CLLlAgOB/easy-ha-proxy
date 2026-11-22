package controld

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/alerts"
)

// ControlPlaneCheck describes one post-reload reachability probe.
type ControlPlaneCheck struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"` // "http", "https", or "tcp"
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Path   string `json:"path,omitempty"`
	SNI    string `json:"sni,omitempty"`
	Method string `json:"method,omitempty"`
}

// CheckResult reports the outcome of one control-plane probe.
type CheckResult struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Status int    `json:"status,omitempty"`
	Error  string `json:"error,omitempty"`
}

// TransactionState is persisted atomically in CONFIG_TRANSACTION_DIR/transaction.json.
type TransactionState struct {
	Version              int                  `json:"version"`
	TransactionID        string               `json:"transaction_id"`
	State                string               `json:"state"`
	CreatedAt            string               `json:"created_at"`
	CandidateSHA256      string               `json:"candidate_sha256"`
	PreviousSHA256       string               `json:"previous_sha256"`
	PreviousConfigB64    string               `json:"previous_config_b64,omitempty"`
	PreviousSources      map[string]string    `json:"previous_sources,omitempty"`
	ControlPlaneChecks   []ControlPlaneCheck  `json:"control_plane_checks,omitempty"`
	Checks               []CheckResult        `json:"checks"`
	BackupPath           string               `json:"backup_path,omitempty"`
	DeadlineEpoch        float64              `json:"deadline_epoch"`
	Failure              string               `json:"failure"`
	Rollback             map[string]any       `json:"rollback"`
}

var allowedSourceFiles = map[string]struct{}{
	"vars.yml": {}, "websites.yml": {}, "tcp.yml": {},
}

func isActiveTxState(state string) bool {
	switch state {
	case "prepared", "pending_confirmation", "rolling_back", "rollback_failed":
		return true
	default:
		return false
	}
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func randomTxID() string {
	var b [24]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func (c *Controller) txPath() string {
	return filepath.Join(c.Opts.ConfigTransactionDir, "transaction.json")
}

func (c *Controller) loadTxLocked() (*TransactionState, error) {
	raw, err := os.ReadFile(c.txPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var st TransactionState
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func (c *Controller) saveTxLocked(st *TransactionState) error {
	if err := os.MkdirAll(c.Opts.ConfigTransactionDir, 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(c.txPath(), append(raw, '\n'), 0o600)
}

func sanitizedTxResponse(st *TransactionState) map[string]any {
	if st == nil {
		return map[string]any{"ok": true, "state": "idle", "pending": false}
	}
	pending := st.State == "pending_confirmation"
	remaining := 0
	if pending && st.DeadlineEpoch > 0 {
		rem := int(st.DeadlineEpoch - float64(time.Now().Unix()))
		if rem > 0 {
			remaining = rem
		}
	}
	return map[string]any{
		"ok":                st.State != "rollback_failed" && st.State != "error",
		"transaction_id":    st.TransactionID,
		"state":             st.State,
		"pending":           pending,
		"created_at":        st.CreatedAt,
		"candidate_sha256":  st.CandidateSHA256,
		"previous_sha256":   st.PreviousSHA256,
		"deadline_epoch":    st.DeadlineEpoch,
		"remaining_seconds": remaining,
		"checks":            st.Checks,
		"failure":           st.Failure,
		"rollback":          st.Rollback,
	}
}

func (c *Controller) runControlPlaneChecks(ctx context.Context, checks []ControlPlaneCheck) (bool, []CheckResult) {
	if len(checks) == 0 {
		return true, []CheckResult{}
	}
	if c.CheckRunner != nil {
		return c.CheckRunner(ctx, checks)
	}
	results := make([]CheckResult, 0, len(checks))
	allOK := true
	for _, chk := range checks {
		res := probeCheck(ctx, chk)
		if !res.OK {
			allOK = false
		}
		results = append(results, res)
	}
	return allOK, results
}

func probeCheck(ctx context.Context, chk ControlPlaneCheck) CheckResult {
	host := chk.Host
	if host == "" {
		host = "127.0.0.1"
	}
	addr := net.JoinHostPort(host, strconv.Itoa(chk.Port))
	if chk.Kind == "tcp" || chk.Kind == "" {
		var d net.Dialer
		d.Timeout = 2 * time.Second
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return CheckResult{Name: chk.Name, OK: false, Error: err.Error()}
		}
		_ = conn.Close()
		return CheckResult{Name: chk.Name, OK: true}
	}
	scheme := "http"
	if chk.Kind == "https" {
		scheme = "https"
	}
	p := chk.Path
	if p == "" {
		p = "/"
	}
	method := chk.Method
	if method == "" {
		method = http.MethodGet
	}
	urlStr := fmt.Sprintf("%s://%s%s", scheme, addr, p)
	reqCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, method, urlStr, nil)
	if err != nil {
		return CheckResult{Name: chk.Name, OK: false, Error: err.Error()}
	}
	if chk.SNI != "" {
		req.Host = chk.SNI
	}
	tr := &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{ServerName: chk.SNI, InsecureSkipVerify: true}, // local loopback probe
	}
	defer tr.CloseIdleConnections()
	resp, err := (&http.Client{Transport: tr, Timeout: 2 * time.Second}).Do(req)
	if err != nil {
		return CheckResult{Name: chk.Name, OK: false, Error: err.Error()}
	}
	_ = resp.Body.Close()
	ok := resp.StatusCode >= 200 && resp.StatusCode < 500
	return CheckResult{Name: chk.Name, OK: ok, Status: resp.StatusCode}
}

func decodeChecks(checksB64 string) ([]ControlPlaneCheck, error) {
	if strings.TrimSpace(checksB64) == "" {
		return nil, nil
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(checksB64))
	if err != nil {
		return nil, fmt.Errorf("invalid checks base64: %w", err)
	}
	var checks []ControlPlaneCheck
	if err := json.Unmarshal(raw, &checks); err != nil {
		return nil, fmt.Errorf("invalid checks JSON: %w", err)
	}
	return checks, nil
}

func (c *Controller) writeConfigRawLocked(ctx context.Context, raw []byte) error {
	if len(raw) == 0 || len(raw) > MaxConfigBytes {
		return errors.New("invalid HAProxy configuration size")
	}
	if err := EnforceConfigPolicy(raw); err != nil {
		return err
	}
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
	_ = tmp.Chmod(0o644)
	_ = tmp.Sync()
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if rc, _, stderr, err := c.runHAProxyCheckFile(ctx, tmpPath); err != nil || rc != 0 {
		cleanup()
		if err != nil {
			return err
		}
		return fmt.Errorf("haproxy -c failed (rc=%d): %s", rc, strings.TrimSpace(stderr))
	}
	if err := os.Rename(tmpPath, c.Opts.HAProxyCfgPath); err != nil {
		cleanup()
		return err
	}
	return nil
}

func (c *Controller) reloadLocked(ctx context.Context) (bool, string) {
	c.DumpServerState(ctx)
	return c.runSystemctlReload(ctx)
}

func (c *Controller) notifyApplyFailed(ctx context.Context, summary, detail string) {
	if c.Alerts != nil && c.Alerts.Enabled() {
		c.Alerts.Observe(ctx, alerts.Observation{
			Rule:    "config.apply_failed",
			Subject: "haproxy",
			Summary: summary,
			Detail:  detail,
		})
	}
}

// ApplyConfigGuarded atomically applies a candidate haproxy.cfg, reloads, verifies checks,
// and rolls back to the previous config automatically if reload or checks fail.
func (c *Controller) ApplyConfigGuarded(ctx context.Context, cfgB64, checksB64 string) map[string]any {
	candidate, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cfgB64))
	if err != nil || len(candidate) == 0 || len(candidate) > MaxConfigBytes {
		return map[string]any{"ok": false, "applied": false, "rolled_back": false, "failure": "invalid candidate config"}
	}
	checks, err := decodeChecks(checksB64)
	if err != nil {
		return map[string]any{"ok": false, "applied": false, "rolled_back": false, "failure": err.Error()}
	}

	c.applyMu.Lock()
	defer c.applyMu.Unlock()

	if existing, _ := c.loadTxLocked(); existing != nil && isActiveTxState(existing.State) {
		return map[string]any{"ok": false, "applied": false, "rolled_back": false, "failure": "another HAProxy config transaction is still active"}
	}
	previous, err := os.ReadFile(c.Opts.HAProxyCfgPath)
	if err != nil || len(previous) == 0 {
		return map[string]any{"ok": false, "applied": false, "rolled_back": false, "failure": "current haproxy.cfg could not be read for rollback"}
	}

	if err := c.writeConfigRawLocked(ctx, candidate); err != nil {
		c.notifyApplyFailed(ctx, "HAProxy configuration validation failed", err.Error())
		return map[string]any{"ok": false, "applied": false, "rolled_back": false, "failure": err.Error()}
	}

	reloadOK, reloadMsg := c.reloadLocked(ctx)
	checksOK := false
	var results []CheckResult
	if reloadOK {
		checksOK, results = c.runControlPlaneChecks(ctx, checks)
	}
	if reloadOK && checksOK {
		return map[string]any{
			"ok":          true,
			"applied":     true,
			"rolled_back": false,
			"checks":      results,
		}
	}

	failure := reloadMsg
	if reloadOK && !checksOK {
		failure = "post-reload control-plane checks failed"
	}
	rbErr := c.writeConfigRawLocked(ctx, previous)
	rbReloadOK := false
	if rbErr == nil {
		rbReloadOK, _ = c.reloadLocked(ctx)
	}
	c.notifyApplyFailed(ctx, "HAProxy guarded apply rolled back", failure)
	return map[string]any{
		"ok":          false,
		"applied":     false,
		"rolled_back": true,
		"rollback_ok": rbErr == nil && rbReloadOK,
		"checks":      results,
		"failure":     failure,
	}
}

// BeginConfigTransaction starts a confirmable transaction with an automatic deadline rollback watchdog.
func (c *Controller) BeginConfigTransaction(ctx context.Context, cfgB64, checksB64, sourcesB64, timeoutStr string) (map[string]any, error) {
	timeoutSec, err := strconv.Atoi(strings.TrimSpace(timeoutStr))
	if err != nil || timeoutSec < TxMinTimeoutSeconds || timeoutSec > TxMaxTimeoutSeconds {
		return nil, errors.New("config transaction timeout is outside the allowed range")
	}
	candidate, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cfgB64))
	if err != nil || len(candidate) == 0 || len(candidate) > MaxConfigBytes {
		return nil, errors.New("invalid HAProxy configuration size")
	}
	checks, err := decodeChecks(checksB64)
	if err != nil {
		return nil, err
	}

	prevSources := map[string]string{}
	if strings.TrimSpace(sourcesB64) != "" {
		rawSrc, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sourcesB64))
		if err != nil {
			return nil, fmt.Errorf("invalid sources payload: %w", err)
		}
		var payload struct {
			Previous map[string]string `json:"previous"`
		}
		if err := json.Unmarshal(rawSrc, &payload); err == nil {
			for k, v := range payload.Previous {
				if _, ok := allowedSourceFiles[k]; ok {
					prevSources[k] = v
				}
			}
		}
	}

	c.applyMu.Lock()
	defer c.applyMu.Unlock()

	if existing, _ := c.loadTxLocked(); existing != nil {
		if existing.State == "pending_confirmation" && existing.DeadlineEpoch > 0 && float64(time.Now().Unix()) >= existing.DeadlineEpoch {
			_ = c.rollbackLocked(ctx, existing, "confirmation timeout expired")
			existing, _ = c.loadTxLocked()
		}
		if existing != nil && isActiveTxState(existing.State) {
			return nil, errors.New("another HAProxy config transaction is still active")
		}
	}

	previous, err := os.ReadFile(c.Opts.HAProxyCfgPath)
	if err != nil || len(previous) == 0 {
		return nil, errors.New("a valid current HAProxy configuration is required for rollback")
	}

	txID := randomTxID()
	st := &TransactionState{
		Version:            TxVersion,
		TransactionID:      txID,
		State:              "prepared",
		CreatedAt:          time.Now().UTC().Format(time.RFC3339),
		CandidateSHA256:    sha256Hex(candidate),
		PreviousSHA256:     sha256Hex(previous),
		PreviousConfigB64:  base64.StdEncoding.EncodeToString(previous),
		PreviousSources:    prevSources,
		ControlPlaneChecks: checks,
		Checks:             []CheckResult{},
	}
	if err := c.saveTxLocked(st); err != nil {
		return nil, err
	}

	if err := c.writeConfigRawLocked(ctx, candidate); err != nil {
		st.State = "rolled_back"
		st.Failure = err.Error()
		st.PreviousConfigB64 = ""
		_ = c.saveTxLocked(st)
		return sanitizedTxResponse(st), nil
	}

	reloadOK, reloadMsg := c.reloadLocked(ctx)
	checksOK := false
	if reloadOK {
		checksOK, st.Checks = c.runControlPlaneChecks(ctx, checks)
	}
	if !reloadOK || !checksOK {
		reason := reloadMsg
		if reloadOK {
			reason = "post-reload control-plane checks failed"
		}
		return c.rollbackLocked(ctx, st, reason), nil
	}

	st.State = "pending_confirmation"
	st.DeadlineEpoch = float64(time.Now().Unix() + int64(timeoutSec))
	if err := c.saveTxLocked(st); err != nil {
		return nil, err
	}
	c.startWatchdog(txID, st.DeadlineEpoch)
	return sanitizedTxResponse(st), nil
}

func (c *Controller) startWatchdog(txID string, deadlineEpoch float64) {
	go func() {
		for {
			rem := time.Until(time.Unix(int64(deadlineEpoch), 0))
			if rem > 0 {
				if rem > 30*time.Second {
					rem = 30 * time.Second
				}
				time.Sleep(rem)
				continue
			}
			c.applyMu.Lock()
			st, err := c.loadTxLocked()
			if err == nil && st != nil &&
				subtle.ConstantTimeCompare([]byte(st.TransactionID), []byte(txID)) == 1 &&
				st.State == "pending_confirmation" &&
				float64(time.Now().Unix()) >= st.DeadlineEpoch {
				_ = c.rollbackLocked(context.Background(), st, "confirmation timeout expired")
			}
			c.applyMu.Unlock()
			return
		}
	}()
}

// ConfigTransactionStatus returns current transaction state, rolling back if expired.
func (c *Controller) ConfigTransactionStatus(ctx context.Context, txID string) (map[string]any, error) {
	c.applyMu.Lock()
	defer c.applyMu.Unlock()
	st, err := c.loadTxLocked()
	if err != nil {
		return nil, err
	}
	if st == nil {
		return sanitizedTxResponse(nil), nil
	}
	if txID != "" && subtle.ConstantTimeCompare([]byte(st.TransactionID), []byte(txID)) != 1 {
		return nil, errors.New("config transaction id does not match")
	}
	if st.State == "pending_confirmation" && st.DeadlineEpoch > 0 && float64(time.Now().Unix()) >= st.DeadlineEpoch {
		return c.rollbackLocked(ctx, st, "confirmation timeout expired"), nil
	}
	return sanitizedTxResponse(st), nil
}

// ConfirmConfigTransaction finalizes a pending transaction after verifying ID and live config hash.
func (c *Controller) ConfirmConfigTransaction(_ context.Context, txID, candidateHash string) (map[string]any, error) {
	c.applyMu.Lock()
	defer c.applyMu.Unlock()
	st, err := c.loadTxLocked()
	if err != nil {
		return nil, err
	}
	if st == nil || st.State != "pending_confirmation" {
		return nil, errors.New("no pending HAProxy config transaction to confirm")
	}
	if subtle.ConstantTimeCompare([]byte(st.TransactionID), []byte(txID)) != 1 {
		return nil, errors.New("config transaction id does not match")
	}
	if subtle.ConstantTimeCompare([]byte(st.CandidateSHA256), []byte(candidateHash)) != 1 {
		return nil, errors.New("candidate hash does not match active transaction")
	}
	live, err := os.ReadFile(c.Opts.HAProxyCfgPath)
	if err != nil || subtle.ConstantTimeCompare([]byte(sha256Hex(live)), []byte(st.CandidateSHA256)) != 1 {
		return nil, errors.New("live haproxy.cfg changed before confirmation")
	}

	st.State = "confirmed"
	st.PreviousConfigB64 = ""
	st.PreviousSources = nil
	if err := c.saveTxLocked(st); err != nil {
		return nil, err
	}
	c.recordConfirmedVersionLocked(st)
	return sanitizedTxResponse(st), nil
}

func (c *Controller) recordConfirmedVersionLocked(st *TransactionState) {
	if c.Opts.ConfigHistoryDir == "" {
		return
	}
	verID := time.Now().UTC().Format("20060102T150405Z") + "-" + st.CandidateSHA256[:8]
	verDir := filepath.Join(c.Opts.ConfigHistoryDir, verID)
	if err := os.MkdirAll(verDir, 0o750); err != nil {
		return
	}
	meta := map[string]any{
		"id":               verID,
		"confirmed_at":     time.Now().UTC().Format(time.RFC3339),
		"transaction_id":   st.TransactionID,
		"candidate_sha256": st.CandidateSHA256,
	}
	if b, err := json.MarshalIndent(meta, "", "  "); err == nil {
		_ = writeFileAtomic(filepath.Join(verDir, "meta.json"), append(b, '\n'), 0o640)
	}
	for name := range allowedSourceFiles {
		if raw, err := os.ReadFile(filepath.Join(c.Opts.ConfigSourceDir, name)); err == nil {
			_ = writeFileAtomic(filepath.Join(verDir, name), raw, 0o640)
		}
	}
}

// RollbackConfigTransaction explicitly rolls back an active transaction by ID.
func (c *Controller) RollbackConfigTransaction(ctx context.Context, txID string) (map[string]any, error) {
	c.applyMu.Lock()
	defer c.applyMu.Unlock()
	st, err := c.loadTxLocked()
	if err != nil {
		return nil, err
	}
	if st == nil || !isActiveTxState(st.State) {
		return nil, errors.New("no active HAProxy config transaction to roll back")
	}
	if subtle.ConstantTimeCompare([]byte(st.TransactionID), []byte(txID)) != 1 {
		return nil, errors.New("config transaction id does not match")
	}
	return c.rollbackLocked(ctx, st, "manual rollback requested"), nil
}

func (c *Controller) rollbackLocked(ctx context.Context, st *TransactionState, reason string) map[string]any {
	st.State = "rolling_back"
	st.Failure = reason
	_ = c.saveTxLocked(st)

	var failures []string
	sourcesOK := true
	for name, b64 := range st.PreviousSources {
		if _, ok := allowedSourceFiles[name]; !ok {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			sourcesOK = false
			failures = append(failures, "invalid source backup "+name)
			continue
		}
		if err := os.MkdirAll(c.Opts.ConfigSourceDir, 0o755); err != nil ||
			writeFileAtomic(filepath.Join(c.Opts.ConfigSourceDir, name), raw, 0o644) != nil {
			sourcesOK = false
			failures = append(failures, "failed restoring "+name)
		}
	}

	cfgOK := false
	reloadOK := false
	prevRaw, err := base64.StdEncoding.DecodeString(st.PreviousConfigB64)
	if err != nil || len(prevRaw) == 0 {
		failures = append(failures, "persisted previous haproxy.cfg is missing")
	} else if err := c.writeConfigRawLocked(ctx, prevRaw); err != nil {
		failures = append(failures, err.Error())
	} else {
		cfgOK = true
		reloadOK, _ = c.reloadLocked(ctx)
		if !reloadOK {
			failures = append(failures, "HAProxy reload failed during rollback")
		}
	}

	rollbackOK := cfgOK && reloadOK && sourcesOK
	if rollbackOK {
		st.State = "rolled_back"
		st.PreviousConfigB64 = ""
		st.PreviousSources = nil
	} else {
		st.State = "rollback_failed"
	}
	st.Rollback = map[string]any{
		"ok":         rollbackOK,
		"reload_ok":  reloadOK,
		"sources_ok": sourcesOK,
		"failure":    strings.Join(failures, "; "),
	}
	if len(failures) > 0 {
		st.Failure = strings.Join(failures, "; ")
	}
	_ = c.saveTxLocked(st)
	c.notifyApplyFailed(ctx, "HAProxy config transaction rolled back", st.Failure)
	return sanitizedTxResponse(st)
}

// RecoverTransaction runs at startup to roll back expired/incomplete transactions or re-arm watchdogs.
func (c *Controller) RecoverTransaction(ctx context.Context) error {
	c.applyMu.Lock()
	defer c.applyMu.Unlock()
	st, err := c.loadTxLocked()
	if err != nil || st == nil {
		return err
	}
	switch st.State {
	case "prepared", "rolling_back":
		_ = c.rollbackLocked(ctx, st, "daemon restarted during incomplete transaction")
	case "pending_confirmation":
		if st.DeadlineEpoch > 0 && float64(time.Now().Unix()) >= st.DeadlineEpoch {
			_ = c.rollbackLocked(ctx, st, "confirmation timeout expired during restart")
		} else if st.DeadlineEpoch > 0 {
			c.startWatchdog(st.TransactionID, st.DeadlineEpoch)
		}
	}
	return nil
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
