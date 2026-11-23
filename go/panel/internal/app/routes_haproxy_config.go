package app

// Port of routes_haproxy_config.py: the configuration endpoints.

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"mime"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"easy-ha-proxy/panel/internal/pyyaml"

	"golang.org/x/text/unicode/norm"
)

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// SilentJSON is request.get_json(silent=True): nil unless a JSON body parses.
func (c *Ctx) SilentJSON() any {
	ct, _, _ := mime.ParseMediaType(c.R.Header.Get("Content-Type"))
	if ct != "application/json" && !(strings.HasPrefix(ct, "application/") && strings.HasSuffix(ct, "+json")) {
		return nil
	}
	raw, err := io.ReadAll(c.R.Body)
	if err != nil {
		return nil
	}
	v, err := pyyaml.JSONLoads(raw)
	if err != nil {
		return nil
	}
	return v
}

// silentJSONMap is request.get_json(silent=True) or {}.
func (c *Ctx) silentJSONMap() any {
	v := c.SilentJSON()
	if !truthy(v) {
		return pyyaml.NewMap()
	}
	return v
}

// trustedClientIP is _trusted_client_ip.
func (c *Ctx) trustedClientIP() string {
	raw, _, _ := strings.Cut(c.R.Header.Get("X-Forwarded-For"), ",")
	if a, ok := pyIPAddress(strings.TrimSpace(raw)); ok {
		return a.String()
	}
	return ""
}

const werkzeugTokenChars = "!#$%&'*+-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ^_`abcdefghijklmnopqrstuvwxyz|~"

// quoteHeaderValue is werkzeug.http.quote_header_value.
func quoteHeaderValue(v string) string {
	if v == "" {
		return `""`
	}
	token := true
	for _, r := range v {
		if !strings.ContainsRune(werkzeugTokenChars, r) {
			token = false
			break
		}
	}
	if token {
		return v
	}
	v = strings.ReplaceAll(v, `\`, `\\`)
	return `"` + strings.ReplaceAll(v, `"`, `\"`) + `"`
}

// contentDisposition is the header werkzeug's send_file sets for
// as_attachment=True and a download name: an NFKD ASCII fallback plus an
// RFC 5987 filename* when the name is not ASCII.
func contentDisposition(name string) string {
	ascii := true
	for i := 0; i < len(name); i++ {
		if name[i] > 127 {
			ascii = false
			break
		}
	}
	if ascii {
		return "attachment; filename=" + quoteHeaderValue(name)
	}
	var simple strings.Builder
	for _, r := range norm.NFKD.String(name) {
		if r < 128 {
			simple.WriteRune(r)
		}
	}
	var quoted strings.Builder
	for _, b := range []byte(name) {
		if b < 128 && (b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.IndexByte("_.-~!#$&+^`|", b) >= 0) {
			quoted.WriteByte(b)
		} else {
			fmt.Fprintf(&quoted, "%%%02X", b)
		}
	}
	return "attachment; filename=" + quoteHeaderValue(simple.String()) + "; filename*=UTF-8''" + quoted.String()
}

func (c *Ctx) sendBytes(data []byte, mimetype, downloadName string) error {
	if strings.HasPrefix(mimetype, "text/") {
		mimetype += "; charset=utf-8"
	}
	c.W.Header().Set("Content-Disposition", contentDisposition(downloadName))
	c.W.Header().Set("Cache-Control", "no-cache, max-age=0")
	return c.Text(200, mimetype, string(data))
}

func recordResult(ok bool) string {
	if ok {
		return auditResultSuccess
	}
	return auditResultFailure
}

func detailIfFailed(ok bool, text string) string {
	if ok {
		return ""
	}
	return truncRunes(text, 500)
}

func (a *App) registerConfigRoutes() {
	a.Handle("routes.haproxy_config_preview", func(c *Ctx) error {
		cfg, err := RenderHAProxyCfg(nil)
		if err != nil {
			return err
		}
		return c.Text(200, "text/plain; charset=utf-8", cfg)
	})
	a.Handle("routes.haproxy_download_cfg", func(c *Ctx) error {
		var cfg, filename string
		switch c.Args["source"] {
		case "rendered":
			text, err := RenderHAProxyCfg(nil)
			if err != nil {
				log.Printf("Unhandled exception in route: %v", err)
				return c.Text(500, "text/plain; charset=utf-8", "Failed to generate configuration: "+err.Error())
			}
			cfg, filename = text, "haproxy-rendered.cfg"
		case "server":
			raw, err := os.ReadFile(HAProxyCfgPath)
			if err != nil {
				if os.IsNotExist(err) {
					return c.Text(404, "text/plain; charset=utf-8", fmt.Sprintf("File %s was not found on the server", HAProxyCfgPath))
				}
				return c.Text(500, "text/plain; charset=utf-8", fmt.Sprintf("Failed to read %s: %s", HAProxyCfgPath, pyFileError(err, HAProxyCfgPath)))
			}
			cfg, filename = string(raw), "haproxy-server.cfg"
		default:
			return Abort(404, "")
		}
		c.W.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
		c.W.Header().Set("Cache-Control", "no-store")
		return c.Text(200, "text/plain; charset=utf-8", cfg)
	})
	a.Handle("routes.haproxy_download_all_configs", func(c *Ctx) error {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		add := func(path, arc string) {
			raw, err := os.ReadFile(path)
			if err != nil {
				return
			}
			info, _ := os.Stat(path)
			h := &zip.FileHeader{Name: arc, Method: zip.Deflate}
			if info != nil {
				h.Modified = info.ModTime()
			}
			w, err := zw.CreateHeader(h)
			if err == nil {
				_, _ = w.Write(raw)
			}
		}
		add(HAProxyCfgPath, "haproxy/haproxy.cfg")
		add(HAPTemplate, "haproxy/haproxy.cfg.j2")
		add(WebsitesYAML, "haproxy/websites.yml")
		add(TCPYAML, "haproxy/tcp.yml")
		add(ConfigYAML, "haproxy/vars.yml")
		add(StatePath, "haproxy/last_applied_state.json")
		add(StateWebsites, "haproxy/last_applied_websites.yml")
		add(StateTCP, "haproxy/last_applied_tcp.yml")
		add(StateVars, "haproxy/last_applied_vars.yml")
		_ = zw.Close()
		return c.sendBytes(buf.Bytes(), "application/zip", "haproxy-configs-"+time.Now().Format("20060102-150405")+".zip")
	})
	a.Handle("routes.haproxy_config_diff", func(c *Ctx) error {
		out, err := func() (*Map, error) {
			rendered, err := RenderHAProxyCfg(nil)
			if err != nil {
				return nil, err
			}
			server := GetServerCfgText()
			htmlDiff := MakeCfgHTMLDiff(c, server, rendered)
			summary, err := GetConfigDiffSummary(&rendered)
			if err != nil {
				return nil, err
			}
			return newMap("ok", true, "rendered_cfg", rendered, "server_cfg", server, "html_diff", htmlDiff, "diff_summary", summary), nil
		}()
		if err != nil {
			log.Printf("Unhandled exception in route: %v", err)
			return c.JSON(500, newMap("ok", false, "error", "Failed to build diff: "+err.Error()))
		}
		return c.JSON(200, out)
	})
	a.Handle("routes.haproxy_configuration_state", func(c *Ctx) error {
		state, err := GetHAProxyConfigurationState(c.op())
		if err != nil {
			log.Printf("Unhandled exception in route: %v", err)
			return c.JSON(503, newMap("ok", false, "state", "unknown", "status_available", false, "pending", false, "error", "Configuration status is unavailable"))
		}
		return c.JSON(200, state)
	})
	a.Handle("routes.haproxy_config_page", func(c *Ctx) error {
		op := c.op()
		var errMsg, diffSummary any
		cfgText := ""
		var sections any = []any{}
		varsYAML, varsRev := "", ""
		if text, err := RenderHAProxyCfg(nil); err != nil {
			errMsg = "Configuration generation error: " + err.Error()
		} else {
			cfgText = text
			if _, err := EnsureAppliedStateBaseline(op, cfgText); err != nil {
				log.Printf("Unhandled exception in route: %v", err)
			}
			if s, err := GetConfigDiffSummary(&cfgText); err == nil {
				diffSummary = s
			} else {
				log.Printf("Unhandled exception in route: %v", err)
			}
		}
		if model, err := GetVarsEditorModel(); err != nil {
			if errMsg != nil {
				errMsg = pyStr(errMsg) + "\nvars.yml editor error: " + err.Error()
			} else {
				errMsg = "vars.yml editor error: " + err.Error()
			}
		} else {
			sections, varsYAML, varsRev = model.Value("sections"), model.Value("yaml").(string), model.Value("revision").(string)
		}
		return c.Render("haproxy_config.html", map[string]any{
			"cfg_text": cfgText, "error": errMsg, "diff_summary": diffSummary, "vars_sections": sections,
			"vars_yaml": varsYAML, "vars_revision": varsRev, "admin_client_ip": c.trustedClientIP(),
		})
	})
	a.Handle("routes.haproxy_config_check", func(c *Ctx) error {
		cfg, err := RenderHAProxyCfg(nil)
		if err != nil {
			return c.JSON(500, newMap("ok", false, "error", "Failed to generate configuration: "+err.Error(), "stdout", "", "stderr", "", "rc", nil))
		}
		cv, err := loadYAML(ConfigYAML)
		if err != nil {
			return err
		}
		if err := ValidateAdminAccessForClient(cv, c.trustedClientIP()); err != nil {
			return c.JSON(400, newMap("ok", false, "error", err.Error(), "rc", nil, "stdout", "", "stderr", err.Error()))
		}
		rc, out, errText, err := CheckCfg(cfg)
		if err != nil {
			return err
		}
		status := 400
		if rc == 0 {
			status = 200
		}
		return c.JSON(status, newMap("ok", rc == 0, "rc", int64(rc), "stdout", out, "stderr", errText))
	})
	a.Handle("routes.haproxy_config_apply", func(c *Ctx) error {
		res, status, err := configApply(c)
		if err != nil {
			log.Printf("Unhandled exception in route: %v", err)
			c.RecordRequest("config.apply", AuditEntry{ObjectType: "haproxy", Result: auditResultFailure, Detail: truncRunes(err.Error(), 500)})
			return c.JSON(500, newMap("ok", false, "error", "Failed to apply configuration: "+err.Error(), "stdout", "", "stderr", ""))
		}
		return c.JSON(status, res)
	})
	a.Handle("routes.haproxy_config_apply_status", func(c *Ctx) error {
		txID := strings.TrimSpace(strOrEmpty(c.Query("transaction_id")))
		result := GetConfigTransactionStatus(c.op(), txID)
		state := strings.ToLower(strOrEmpty(orValue(result.Value("state"), result.Value("status"))))
		result.Set("candidate_reachable", (state == "pending" || state == "pending_confirmation") &&
			CandidateRequestReachable(txID, c.R.Header.Get(ConfigGenerationHeader)))
		status := 409
		if truthy(result.Value("ok")) {
			status = 200
		}
		return c.JSON(status, result)
	})
	a.Handle("routes.haproxy_config_confirm", func(c *Ctx) error {
		payload, ok := asMap(c.silentJSONMap())
		if !ok {
			return c.JSON(400, newMap("ok", false, "error", "Invalid confirmation request"))
		}
		txID := orStr(payload.Value("transaction_id"))
		candSHA := orStr(payload.Value("candidate_sha256"))
		if !CandidateRequestReachable(txID, c.R.Header.Get(ConfigGenerationHeader)) {
			return c.JSON(409, newMap("ok", false, "state", "pending_confirmation", "pending", true, "conflict", true,
				"retryable", true, "candidate_reachable", false, "error", "Waiting for a fresh connection through the candidate HAProxy configuration"))
		}
		op := c.op()
		result := ConfirmCfgTransaction(op, txID, candSHA)
		state := strings.ToLower(strOrEmpty(orValue(result.Value("state"), result.Value("status"))))
		if !truthy(result.Value("ok")) || state != "confirmed" {
			shown := state
			if shown == "" {
				shown = "unknown"
			}
			c.RecordRequest("config.confirm", AuditEntry{ObjectType: "haproxy", ObjectID: txID, Result: auditResultFailure,
				Summary: "state: " + shown, Detail: truncRunes(strOrEmpty(result.Value("error")), 500)})
			return c.JSON(409, result)
		}
		var warnings []any
		if err := func() error {
			cfg, err := RenderHAProxyCfg(nil)
			if err != nil {
				return err
			}
			if sha256Hex(cfg) != strings.ToLower(candSHA) {
				return fmt.Errorf("The confirmed HAProxy config no longer matches the runtime YAML")
			}
			return SaveAppliedStateStrict(cfg)
		}(); err != nil {
			log.Printf("Unhandled exception in route: %v", err)
			warnings = append(warnings, "The configuration is confirmed and remains active, but its applied-state snapshot could not be saved: "+err.Error())
		}
		summary := ""
		if len(warnings) > 0 {
			parts := make([]string, len(warnings))
			for i, w := range warnings {
				parts[i] = w.(string)
			}
			summary = strings.Join(parts, "; ")
		}
		c.RecordRequest("config.confirm", AuditEntry{ObjectType: "haproxy", ObjectID: txID, Summary: summary})
		resp := copyMap(result)
		resp.Set("ok", true)
		resp.Set("state", "confirmed")
		resp.Set("message", "Configuration confirmed and kept")
		if len(warnings) > 0 {
			resp.Set("warnings", warnings)
			resp.Set("warning", warnings[0])
		}
		return c.JSON(200, resp)
	})
	a.Handle("routes.haproxy_config_rollback_pending", func(c *Ctx) error {
		payload := c.silentJSONMap()
		txID := orStr(get(payload, "transaction_id"))
		result := RollbackCfgTransaction(c.op(), txID)
		state := strings.ToLower(strOrEmpty(orValue(result.Value("state"), result.Value("status"))))
		rolled := state == "rolled_back" && truthy(result.Value("ok"))
		shown := state
		if shown == "" {
			shown = "unknown"
		}
		c.RecordRequest("config.rollback", AuditEntry{ObjectType: "haproxy", ObjectID: txID, Result: recordResult(rolled),
			Summary: "state: " + shown, Detail: detailIfFailed(rolled, strOrEmpty(result.Value("error")))})
		status := 409
		if rolled {
			status = 200
		}
		return c.JSON(status, result)
	})
	a.Handle("routes.haproxy_config_upload", func(c *Ctx) error {
		kind, hasKind := c.Form("kind")
		filename, raw, hasFile, _ := c.File("file")
		if !hasKind || kind == "" {
			return c.JSON(200, newMap("ok", false, "error", "The kind parameter is required"))
		}
		if !hasFile || filename == "" {
			return c.JSON(200, newMap("ok", false, "error", "No file supplied"))
		}
		content := strings.ToValidUTF8(string(raw), "�")
		ok, msg := UpdateYAMLFile(c.op(), kind, content)
		c.RecordRequest("config.upload", AuditEntry{ObjectType: "yaml", ObjectID: kind, Result: recordResult(ok),
			Summary: fmt.Sprintf("bytes: %d", len(content)), Detail: detailIfFailed(ok, msg)})
		return c.JSON(200, newMap("ok", ok, okKey(ok), msg))
	})
	a.Handle("routes.haproxy_config_save_vars", func(c *Ctx) error {
		payload := c.silentJSONMap()
		values := get(payload, "values")
		result, err := SaveGuidedVars(c.op(), values, strOrEmpty(get(payload, "revision")), c.trustedClientIP())
		if err != nil {
			return err
		}
		summary := "guided editor"
		if vm, ok := asMap(values); ok {
			var keys []string
			for _, k := range vm.Keys() {
				keys = append(keys, pyStr(k))
			}
			sort.Strings(keys)
			summary = "fields: " + strings.Join(keys, ", ")
		}
		ok := truthy(result.Value("ok"))
		c.RecordRequest("vars.update", AuditEntry{ObjectType: "haproxy", ObjectID: "vars.yml", Result: recordResult(ok),
			Summary: summary, Detail: detailIfFailed(ok, strOrEmpty(result.Value("error")))})
		return c.JSON(varsStatus(result), result)
	})
	a.Handle("routes.haproxy_config_save_vars_raw", func(c *Ctx) error {
		payload := c.silentJSONMap()
		content := get(payload, "content")
		result, err := SaveRawVars(c.op(), content, strOrEmpty(get(payload, "revision")))
		if err != nil {
			return err
		}
		ok := truthy(result.Value("ok"))
		c.RecordRequest("vars.update", AuditEntry{ObjectType: "haproxy", ObjectID: "vars.yml", Result: recordResult(ok),
			Summary: fmt.Sprintf("raw editor, bytes: %d", len(strOrEmpty(content))), Detail: detailIfFailed(ok, strOrEmpty(result.Value("error")))})
		return c.JSON(varsStatus(result), result)
	})
	a.Handle("routes.haproxy_config_revert", func(c *Ctx) error {
		ok, msg := RevertToLastAppliedState(c.op())
		c.RecordRequest("config.revert", AuditEntry{ObjectType: "haproxy", Result: recordResult(ok),
			Summary: "restored the last applied websites/tcp/vars", Detail: detailIfFailed(ok, msg)})
		return c.JSON(200, newMap("ok", ok, okKey(ok), msg))
	})
	a.Handle("routes.haproxy_config_download", func(c *Ctx) error {
		path, ok := sourcePath(c.Args["kind"])
		if !ok {
			return Abort(404, "")
		}
		if abs, err := filepath.EvalSymlinks(path); err == nil {
			path = abs
		} else if abs, err := filepath.Abs(path); err == nil {
			path = abs
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return c.Text(404, "text/plain; charset=utf-8", fmt.Sprintf("File %s was not found on the server", path))
		}
		return c.sendBytes(raw, "text/yaml", filepath.Base(path))
	})
}

func varsStatus(result *Map) int {
	if truthy(result.Value("ok")) {
		return 200
	}
	if truthy(result.Value("conflict")) || truthy(result.Value("pending")) {
		return 409
	}
	return 400
}

func configApply(c *Ctx) (*Map, int, error) {
	op := c.op()
	payloadV := c.SilentJSON()
	if payloadV == nil {
		payloadV = pyyaml.NewMap()
	}
	payload, ok := asMap(payloadV)
	if !ok {
		return newMap("ok", false, "error", "The apply request must be a JSON object", "error_code", "invalid_apply_request"), 400, nil
	}
	allowDrift := payload.Value("allow_external_drift") == true
	expected := strings.ToLower(orStr(payload.Value("active_cfg_sha256")))
	if allowDrift && !hex64.MatchString(expected) {
		return newMap("ok", false, "error", "A valid active HAProxy configuration hash is required", "error_code", "invalid_apply_request"), 400, nil
	}
	cfg, err := RenderHAProxyCfg(nil)
	if err != nil {
		return nil, 0, err
	}
	cv, err := loadYAML(ConfigYAML)
	if err != nil {
		return nil, 0, err
	}
	if err := ValidateAdminAccessForClient(cv, c.trustedClientIP()); err != nil {
		return newMap("ok", false, "error", err.Error(), "error_code", "admin_ip_lockout_risk", "stdout", "", "stderr", ""), 400, nil
	}
	pre, err := PreflightCfgConfirmation(cfg, allowDrift, expected)
	if err != nil {
		return nil, 0, err
	}
	if !truthy(pre.Value("ok")) {
		drift := truthy(pre.Value("external_drift_confirmation_required"))
		status := 400
		if drift {
			status = 409
		}
		return newMap("ok", false, "error", pre.Value("error"), "error_code", pre.Value("error_code"),
			"stdout", orValue(pre.Value("stdout"), ""), "stderr", orValue(pre.Value("stderr"), ""),
			"external_drift_confirmation_required", drift, "active_cfg_sha256", pre.Value("active_cfg_sha256")), status, nil
	}
	SyncRenewalPauses()
	certRes, err := EnsureCertsBeforeApply()
	if err != nil {
		return nil, 0, err
	}
	if !truthy(certRes.Value("ok")) {
		return newMap("ok", false, "error", "Failed to issue certificates for some sites", "cert_details", certRes, "stdout", "", "stderr", ""), 200, nil
	}
	res, err := BeginCfgConfirmation(op, cfg, 0, allowDrift, expected)
	if err != nil {
		return nil, 0, err
	}
	ok = truthy(res.Value("ok"))
	stdout := strOrEmpty(res.Value("stdout"))
	stderr := strOrEmpty(res.Value("stderr"))
	state := strings.ToLower(strOrEmpty(orValue(res.Value("state"), res.Value("status"))))
	pending := ok && (state == "pending" || state == "pending_confirmation")
	var diff any
	if s, err := GetConfigDiffSummary(&cfg); err == nil {
		diff = s
	} else {
		log.Printf("Unhandled exception in route: %v", err)
	}
	shownState := state
	if shownState == "" {
		shownState = "applied"
	}
	summary := "state: " + shownState
	if truthy(res.Value("external_drift_overridden")) {
		summary += ", external drift overridden"
	}
	c.RecordRequest("config.apply", AuditEntry{ObjectType: "haproxy", ObjectID: strOrEmpty(orValue(res.Value("transaction_id"), res.Value("id"))),
		Result: recordResult(ok), Summary: summary, Detail: detailIfFailed(ok, strOrEmpty(orValue(res.Value("error"), noneIfEmpty(stderr))))})
	var errOut any = ""
	if !ok {
		errOut = orValue(res.Value("error"), "HAProxy confirmable apply failed (see stderr)")
	}
	status := 400
	switch {
	case pending:
		status = 202
	case ok:
		status = 200
	case truthy(res.Value("external_drift_confirmation_required")):
		status = 409
	}
	return newMap("ok", ok, "stdout", stdout, "stderr", stderr, "error", errOut, "error_code", res.Value("error_code"),
		"baseline_source", res.Value("baseline_source"), "baseline_reconciled", truthy(res.Value("baseline_reconciled")),
		"external_drift_confirmation_required", truthy(res.Value("external_drift_confirmation_required")),
		"active_cfg_sha256", res.Value("active_cfg_sha256"), "external_drift_overridden", truthy(res.Value("external_drift_overridden")),
		"safety", orValue(res.Value("safety"), res), "state", state, "pending_confirmation", pending,
		"transaction_id", orValue(res.Value("transaction_id"), res.Value("id")), "candidate_sha256", res.Value("candidate_sha256"),
		"confirm_by", orValue(res.Value("confirm_by"), res.Value("deadline")), "remaining_seconds", res.Value("remaining_seconds"),
		"diff_summary", diff), status, nil
}

var _ = hex.EncodeToString
var _ = sha256.Sum256
