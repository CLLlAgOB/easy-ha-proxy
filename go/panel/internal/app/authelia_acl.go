package app

// Ports of authelia_config_client.py (the configd transport) and
// authelia_acl.py (the access rules editor).

import (
	"bytes"
	"compress/zlib"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"easy-ha-proxy/panel/shared/pyyaml"
)

const configdMaxResponse = 2 * 1024 * 1024

func autheliaConfigSocket() string {
	if v, ok := os.LookupEnv("AUTHELIA_CONFIG_SOCKET"); ok {
		return v
	}
	return "/run/easy-ha-proxy/authelia-configd.sock"
}

// configdSend is _send_request / _configd_request: one JSON line each way.
func configdSend(payload *Map, connectTimeout, timeout time.Duration, invalidPrefix string) *Map {
	text, err := PyJSON(payload, JSONOpts{})
	if err != nil {
		return newMap("ok", false, "error", err.Error())
	}
	conn, err := net.DialTimeout("unix", autheliaConfigSocket(), connectTimeout)
	if err != nil {
		return newMap("ok", false, "error", "socket error: "+pyOSError(err))
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(text + "\n")); err != nil {
		return newMap("ok", false, "error", "socket error: "+pyOSError(err))
	}
	var buf []byte
	chunk := make([]byte, 4096)
	for !bytes.Contains(buf, []byte("\n")) {
		n, err := conn.Read(chunk)
		buf = append(buf, chunk[:n]...)
		if len(buf) > configdMaxResponse {
			return newMap("ok", false, "error", "response from authelia-configd is too large")
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return newMap("ok", false, "error", "socket error: "+pyOSError(err))
		}
	}
	if len(buf) == 0 {
		return newMap("ok", false, "error", "empty response from authelia-configd")
	}
	line, _, _ := bytes.Cut(buf, []byte("\n"))
	l := strings.TrimSpace(strings.ToValidUTF8(string(line), "�"))
	if l == "" {
		if invalidPrefix == "acl" {
			return newMap("ok", false, "error", "empty JSON line from authelia-configd")
		}
		return newMap("ok", false, "error", "empty JSON from authelia-configd")
	}
	v, err := pyyaml.JSONLoads([]byte(l))
	if err != nil {
		if invalidPrefix == "acl" {
			return newMap("ok", false, "error", "invalid json from daemon: Expecting value: line 1 column 1 (char 0)")
		}
		return newMap("ok", false, "error", "invalid json from authelia-configd: Expecting value: line 1 column 1 (char 0)")
	}
	m, ok := asMap(v)
	if !ok {
		return newMap("ok", false, "error", "invalid response from authelia-configd")
	}
	return m
}

// ConfigdRequest is authelia_acl._configd_request.
func ConfigdRequest(payload *Map) *Map {
	timeout := 10 * time.Second
	if a := payload.Value("action"); a == "rules_set" || a == "restart" {
		timeout = 90 * time.Second
	}
	return configdSend(payload, 2*time.Second, timeout, "acl")
}

// ConfigClient is authelia_config_client._send_request.
func ConfigClient(payload *Map, timeout time.Duration) *Map {
	return configdSend(payload, timeout, timeout, "client")
}

// LoadRulesYAML is load_rules_yaml.
func LoadRulesYAML() (string, error) {
	resp := ConfigdRequest(newMap("action", "rules_get"))
	if !truthy(resp.Value("ok")) {
		return "", fmt.Errorf("%s", pyStr(orValue(resp.Value("error"), "authelia-configd rules_get failed")))
	}
	if s, ok := resp.Value("rules_yaml").(string); ok {
		return s, nil
	}
	if l, ok := asList(resp.Value("rules")); ok {
		return dumpYAML(l), nil
	}
	return "", fmt.Errorf("invalid rules response from authelia-configd")
}

// SaveRulesFromYAML is save_rules_from_yaml.
func SaveRulesFromYAML(rulesYAML string, expectedRevision string, haveRevision bool) (bool, string) {
	payload := newMap("action", "rules_set", "rules_yaml", rulesYAML)
	if haveRevision {
		payload.Set("expected_revision", expectedRevision)
	}
	resp := ConfigdRequest(payload)
	if !truthy(resp.Value("ok")) {
		return false, pyStr(orValue(resp.Value("error"), "Failed to save rules via authelia-configd"))
	}
	return true, pyStr(orValue(resp.Value("message"), "Authelia rules updated successfully via authelia-configd."))
}

func init() {
	autheliaLoadRulesYAML = LoadRulesYAML
	autheliaSaveRulesFromYAML = func(op *Op, text string) (bool, string) { return SaveRulesFromYAML(text, "", false) }
	autheliaConfigdRequest = func(p *Map) (*Map, error) { return ConfigdRequest(p), nil }
}

func waitForAutheliaHealthy(timeout time.Duration) bool {
	url := strings.TrimSpace(os.Getenv("AUTHELIA_HEALTHCHECK_URL"))
	if url == "" {
		url = "http://127.0.0.1:9091/api/health"
	}
	log.Printf("Waiting for Authelia health at %s", url)
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if resp, err := client.Get(url); err == nil {
			resp.Body.Close()
			if resp.StatusCode < 400 {
				return true
			}
		}
		time.Sleep(time.Second)
	}
	return false
}

func rulesRevision(rules []any) string {
	out, err := pyyaml.Dump(rules, pyyaml.Options{AllowUnicode: true, SortKeys: true})
	if err != nil {
		return ""
	}
	sum := sha256.Sum256([]byte(out))
	return hex.EncodeToString(sum[:])
}

func loadBackendRules() ([]any, error) {
	text, err := LoadRulesYAML()
	if err != nil {
		return nil, err
	}
	var v any
	if text != "" {
		if v, err = pyyaml.Load([]byte(text)); err != nil {
			return nil, err
		}
	}
	if v == nil {
		return []any{}, nil
	}
	rules, ok := asList(v)
	if !ok {
		return nil, fmt.Errorf("Authelia rules YAML is not a list of rules")
	}
	for _, r := range rules {
		if _, ok := asMap(r); !ok {
			return nil, fmt.Errorf("Authelia rules YAML is not a list of rules")
		}
	}
	return rules, nil
}

// ---- itsdangerous.URLSafeSerializer(secret, salt) ----

func itsKey(secret []byte, salt string) []byte {
	h := sha1.New()
	h.Write([]byte(salt))
	h.Write([]byte("signer"))
	h.Write(secret)
	return h.Sum(nil)
}

func itsSign(secret []byte, salt, value string) string {
	mac := hmac.New(sha1.New, itsKey(secret, salt))
	mac.Write([]byte(value))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func itsDumps(secret []byte, salt string, obj any) string {
	payload := base64.RawURLEncoding.EncodeToString([]byte(MustJSON(obj, JSONOpts{EnsureASCII: true, Compact: true})))
	return payload + "." + itsSign(secret, salt, payload)
}

func itsLoads(secret []byte, salt, token string) (any, bool) {
	i := strings.LastIndex(token, ".")
	if i < 0 {
		return nil, false
	}
	value, sig := token[:i], token[i+1:]
	if !hmac.Equal([]byte(sig), []byte(itsSign(secret, salt, value))) {
		return nil, false
	}
	compressed := strings.HasPrefix(value, ".")
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, "."))
	if err != nil {
		return nil, false
	}
	if compressed {
		zr, err := zlib.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, false
		}
		if raw, err = io.ReadAll(zr); err != nil {
			return nil, false
		}
	}
	v, err := pyyaml.JSONLoads(raw)
	if err != nil {
		return nil, false
	}
	return v, true
}

func tokenURLSafe(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

const aclSalt = "authelia-acl-snapshot"

func (c *Ctx) aclSnapshotToken(rules []any, uiRules []*Map) string {
	nonce := c.SessionSetDefault("authelia_acl_nonce", tokenURLSafe(24))
	sources := make([]any, len(uiRules))
	for i, u := range uiRules {
		sources[i] = orValue(u.Value("source_index"), "")
		if _, has := u.Get("source_index"); !has {
			sources[i] = ""
		} else {
			sources[i] = u.Value("source_index")
		}
	}
	return itsDumps(c.App.secret, aclSalt, newMap("revision", rulesRevision(rules), "nonce", nonce, "user", c.User(), "sources", sources))
}

func (c *Ctx) verifyACLSnapshot(token string, rules []any) (bool, error) {
	v, ok := itsLoads(c.App.secret, aclSalt, token)
	if !ok {
		return false, Abort(400, "Invalid access rules form. Reload the page.")
	}
	snap, isMap := asMap(v)
	nonce := c.SessionGet("authelia_acl_nonce")
	if !isMap || nonce == "" || !pyEqual(snap.Value("nonce"), nonce) || !pyEqual(snap.Value("user"), c.User()) {
		return false, Abort(400, "Invalid access rules form. Reload the page.")
	}
	ui, err := c.collectUIRules()
	if err != nil {
		return false, err
	}
	sources := make([]any, len(ui))
	for i, u := range ui {
		sources[i] = u.Value("source_index")
	}
	if !pyEqual(snap.Value("sources"), sources) {
		return false, Abort(400, "Invalid access rule references. Reload the page.")
	}
	return pyEqual(snap.Value("revision"), rulesRevision(rules)), nil
}

func ruleIsEditable(rule *Map) bool {
	for _, k := range rule.Keys() {
		switch pyStr(k) {
		case "domain", "policy", "subject", "resources":
		default:
			return false
		}
	}
	doms := rule.Value("domain")
	list, isList := asList(doms)
	if !isList {
		list = []any{doms}
	}
	if len(list) == 0 {
		return false
	}
	for _, d := range list {
		s, ok := d.(string)
		if !ok || strings.TrimSpace(s) == "" || strings.Contains(s, ",") {
			return false
		}
	}
	policy, ok := rule.Value("policy").(string)
	if !ok || !(policy == "one_factor" || policy == "two_factor" || policy == "bypass" || policy == "deny") {
		return false
	}
	subj := rule.Value("subject")
	subjects, isList := asList(subj)
	if !isList {
		subjects = []any{subj}
	}
	for _, it := range subjects {
		if it == nil {
			continue
		}
		s, ok := it.(string)
		if !ok || !(strings.HasPrefix(s, "group:") || strings.HasPrefix(s, "user:")) {
			return false
		}
		name := strings.SplitN(s, ":", 2)[1]
		if name == "" || name != strings.TrimSpace(name) || strings.ContainsAny(name, ",\r\n") || s == "group:authenticated" {
			return false
		}
	}
	res := rule.Value("resources")
	resources, isList := asList(res)
	if !isList {
		resources = []any{res}
	}
	for _, r := range resources {
		if _, ok := r.(string); r != nil && !ok {
			return false
		}
	}
	return true
}

func normalizeRuleDomain(rule *Map) string {
	switch d := rule.Value("domain").(type) {
	case string:
		return d
	case []any:
		var parts []string
		for _, x := range d {
			if truthy(x) {
				parts = append(parts, pyStr(x))
			}
		}
		return strings.Join(parts, ", ")
	}
	return ""
}

func subjectPairs(m *Map) []string {
	var tmp []string
	m.Each(func(k, v any) {
		ks, vs := pyStr(k), pyStr(v)
		switch ks {
		case "group":
			tmp = append(tmp, "group:"+vs)
		case "user":
			tmp = append(tmp, "user:"+vs)
		default:
			tmp = append(tmp, ks+":"+vs)
		}
	})
	return tmp
}

func parseSubjectForUI(subject any) ([]string, []string, bool, bool) {
	var groups, users []string
	auth, anon := false, false
	var inter [][]string
	switch x := subject.(type) {
	case nil:
		return nil, nil, false, false
	case string:
		inter = append(inter, []string{x})
	case []any:
		for _, it := range x {
			switch y := it.(type) {
			case string:
				inter = append(inter, []string{y})
			case []any:
				var inner []string
				for _, z := range y {
					inner = append(inner, pyStr(z))
				}
				inter = append(inter, inner)
			case *Map:
				if tmp := subjectPairs(y); len(tmp) > 0 {
					inter = append(inter, tmp)
				}
			}
		}
	case *Map:
		if tmp := subjectPairs(x); len(tmp) > 0 {
			inter = append(inter, tmp)
		}
	default:
		return nil, nil, false, false
	}
	for _, and := range inter {
		for _, s := range and {
			switch {
			case strings.HasPrefix(s, "group:"):
				g := strings.TrimSpace(strings.SplitN(s, ":", 2)[1])
				if g == "" {
					continue
				}
				switch g {
				case "authenticated":
					auth = true
				case "anonymous":
					anon = true
				default:
					groups = append(groups, g)
				}
			case strings.HasPrefix(s, "user:"):
				if u := strings.TrimSpace(strings.SplitN(s, ":", 2)[1]); u != "" {
					users = append(users, u)
				}
			default:
				groups = append(groups, strings.TrimSpace(s))
			}
		}
	}
	return uniqSorted(groups), uniqSorted(users), auth, anon
}

func uniqSorted(in []string) []string {
	set := map[string]bool{}
	for _, s := range in {
		if s != "" {
			set[s] = true
		}
	}
	return sortedKeys(set)
}

func parseResourcesForUI(res any) string {
	switch x := res.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(x)
	case []any:
		var lines []string
		for _, r := range x {
			if strip(r) != "" {
				lines = append(lines, strip(r))
			}
		}
		return strings.Join(lines, "\n")
	}
	return strip(res)
}

func backendRuleToUI(rule *Map, sourceIndex int) *Map {
	groups, users, auth, anon := parseSubjectForUI(rule.Value("subject"))
	res := strings.ReplaceAll(strings.ReplaceAll(parseResourcesForUI(rule.Value("resources")), "\r\n", "\n"), "\r", "\n")
	policy := orStr(rule.Value("policy"))
	if policy == "" {
		policy = "one_factor"
	}
	src := ""
	if sourceIndex >= 0 {
		src = strconv.Itoa(sourceIndex)
	}
	return newMap("domains", strings.TrimSpace(normalizeRuleDomain(rule)), "policy", policy,
		"groups", strings.Join(groups, ", "), "users", strings.Join(users, ", "),
		"flag_authenticated", auth, "flag_anonymous", anon, "resources", res, "source_index", src,
		"advanced", !ruleIsEditable(rule), "original_yaml", dumpYAML(rule))
}

func emptyUIRule() *Map {
	return newMap("domains", "", "policy", "one_factor", "groups", "", "users", "",
		"flag_authenticated", false, "flag_anonymous", false, "resources", "", "source_index", "")
}

func parseFormBool(v string, present bool) bool {
	if !present {
		return false
	}
	switch strings.ToLower(v) {
	case "1", "true", "on", "yes":
		return true
	}
	return false
}

func (c *Ctx) collectUIRules() ([]*Map, error) {
	totalText, has := c.Form("total_rules")
	if !has {
		totalText = "0"
	}
	total, err := parsePyIntString(totalText)
	if err != nil {
		return nil, Abort(400, "Invalid access rules count.")
	}
	if total < 0 || total > 500 {
		return nil, Abort(400, "At most 500 access rules are allowed.")
	}
	var out []*Map
	for i := int64(0); i < total; i++ {
		p := fmt.Sprintf("rule-%d-", i)
		policy := c.FormStrip(p + "policy")
		if policy == "" {
			policy = "one_factor"
		}
		fa, faOK := c.Form(p + "flag_authenticated")
		fn, fnOK := c.Form(p + "flag_anonymous")
		src, srcOK := c.Form(p + "source_index")
		if !srcOK {
			src = ""
		}
		res := strings.ReplaceAll(strings.ReplaceAll(c.FormStrip(p+"resources"), "\r\n", "\n"), "\r", "\n")
		out = append(out, newMap("domains", c.FormStrip(p+"domains"), "policy", policy, "groups", c.FormStrip(p+"groups"),
			"users", c.FormStrip(p+"users"), "flag_authenticated", parseFormBool(fa, faOK), "flag_anonymous", parseFormBool(fn, fnOK),
			"resources", res, "source_index", src))
	}
	return out, nil
}

func originalRuleForUI(ui *Map, rules []any, seen map[int64]bool) (*Map, error) {
	src := pyStr(ui.Value("source_index"))
	if src == "" {
		return nil, nil
	}
	idx, err := parsePyIntString(src)
	if err != nil || idx < 0 || idx >= int64(len(rules)) || seen[idx] {
		return nil, Abort(400, "Invalid access rule reference. Reload the page.")
	}
	seen[idx] = true
	return rules[idx].(*Map), nil
}

func (c *Ctx) translateNumber(msg string, number int) string {
	return strings.ReplaceAll(c.T(msg), "{number}", strconv.Itoa(number))
}

func splitTrim(s, sep string) []string {
	var out []string
	for _, p := range strings.Split(s, sep) {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func (c *Ctx) convertFormToBackendRules(original []any) ([]any, []*Map, []string, error) {
	ui, err := c.collectUIRules()
	if err != nil {
		return nil, nil, nil, err
	}
	backend := []any{}
	var errs []string
	seen := map[int64]bool{}
	for idx, u := range ui {
		orig, err := originalRuleForUI(u, original, seen)
		if err != nil {
			return nil, nil, nil, err
		}
		var origUI *Map
		if orig != nil {
			origUI = backendRuleToUI(orig, -1)
			same := true
			for _, k := range []string{"domains", "policy", "groups", "users", "flag_anonymous", "resources"} {
				if !pyEqual(u.Value(k), origUI.Value(k)) {
					same = false
				}
			}
			if same {
				backend = append(backend, pyyaml.DeepCopy(orig))
				continue
			}
			if !ruleIsEditable(orig) {
				errs = append(errs, c.translateNumber("Rule #{number}: advanced rules cannot be edited in this form. Reload the page and use the configuration file to edit this rule.", idx+1))
				continue
			}
		}
		domainsRaw := strings.TrimSpace(pyStr(u.Value("domains")))
		policy := strings.TrimSpace(pyStr(u.Value("policy")))
		if policy == "" {
			policy = "one_factor"
		}
		groupsRaw := strings.TrimSpace(pyStr(u.Value("groups")))
		usersRaw := strings.TrimSpace(pyStr(u.Value("users")))
		resRaw := strings.TrimSpace(pyStr(u.Value("resources")))
		anon := truthy(u.Value("flag_anonymous"))
		if domainsRaw == "" && groupsRaw == "" && usersRaw == "" && resRaw == "" && !anon {
			continue
		}
		if domainsRaw == "" {
			errs = append(errs, fmt.Sprintf("Rule #%d: the 'Domain(s)' field is empty.", idx+1))
			continue
		}
		rule := pyyaml.NewMap()
		doms := splitTrim(domainsRaw, ",")
		if len(doms) == 1 {
			rule.Set("domain", doms[0])
		} else if len(doms) > 1 {
			rule.Set("domain", strList(doms...))
		}
		rule.Set("policy", policy)
		var subj []any
		for _, g := range splitTrim(groupsRaw, ",") {
			subj = append(subj, "group:"+g)
		}
		for _, us := range splitTrim(usersRaw, ",") {
			subj = append(subj, "user:"+us)
		}
		if anon {
			subj = append(subj, "group:anonymous")
		}
		if len(subj) > 0 {
			rule.Set("subject", subj)
		}
		if resRaw != "" {
			var lines []any
			for _, l := range pySplitlines(resRaw) {
				if strings.TrimSpace(l) != "" {
					lines = append(lines, strings.TrimSpace(l))
				}
			}
			if len(lines) > 0 {
				rule.Set("resources", lines)
			}
		}
		if orig != nil {
			merged := pyyaml.DeepCopy(orig).(*Map)
			for _, fg := range []struct {
				key    string
				fields []string
			}{{"domain", []string{"domains"}}, {"policy", []string{"policy"}}, {"subject", []string{"groups", "users", "flag_anonymous"}}, {"resources", []string{"resources"}}} {
				changed := false
				for _, f := range fg.fields {
					if !pyEqual(u.Value(f), origUI.Value(f)) {
						changed = true
					}
				}
				if changed {
					merged.Delete(fg.key)
					if v, has := rule.Get(fg.key); has {
						merged.Set(fg.key, v)
					}
				}
			}
			rule = merged
		}
		backend = append(backend, rule)
	}
	return backend, ui, errs, nil
}

func restoreRuleMetadata(ui []*Map, original []any) error {
	seen := map[int64]bool{}
	for _, u := range ui {
		orig, err := originalRuleForUI(u, original, seen)
		if err != nil {
			return err
		}
		if orig != nil {
			u.Set("advanced", !ruleIsEditable(orig))
			u.Set("original_yaml", dumpYAML(orig))
		}
	}
	return nil
}

func moveRule(rules []*Map, i int, dir string) {
	if dir == "up" && i > 0 {
		rules[i-1], rules[i] = rules[i], rules[i-1]
	} else if dir == "down" && i < len(rules)-1 {
		rules[i+1], rules[i] = rules[i], rules[i+1]
	}
}

func (c *Ctx) renderACL(status int, ui []*Map, activeDomain *string, loadError any, original []any) error {
	if len(ui) == 0 && loadError == nil {
		ui = []*Map{emptyUIRule()}
	}
	snapshot := ""
	if original != nil {
		if err := restoreRuleMetadata(ui, original); err != nil {
			return err
		}
		snapshot = c.aclSnapshotToken(original, ui)
	}
	rules := make([]any, len(ui))
	order := []string{}
	byDomain := map[string][]any{}
	for i, u := range ui {
		u.Set("idx", int64(i))
		rules[i] = u
		d := pyStr(orValue(u.Value("domains"), ""))
		if _, seen := byDomain[d]; !seen {
			order = append(order, d)
		}
		byDomain[d] = append(byDomain[d], u)
	}
	groups := []any{}
	for _, d := range order {
		groups = append(groups, newMap("domain", d, "rules", byDomain[d]))
	}
	active := ""
	if activeDomain != nil {
		active = *activeDomain
	} else if len(groups) > 0 {
		active = pyStr(orValue(groups[0].(*Map).Value("domain"), ""))
	}
	html, err := c.RenderString("authelia_acl_edit.html", map[string]any{"rules": rules, "groups": groups, "total_rules": int64(len(ui)),
		"active_group_domain": active, "acl_load_error": loadError, "acl_snapshot": snapshot})
	if err != nil {
		return err
	}
	return c.HTML(status, html)
}

func (a *App) registerAutheliaACL() {
	a.Handle("authelia_acl.edit_rules", func(c *Ctx) error {
		original, err := loadBackendRules()
		if err != nil {
			log.Printf("Failed to load Authelia rules: %v", err)
			return c.renderACL(200, nil, nil, err.Error(), nil)
		}
		if c.R.Method == http.MethodPost {
			ok, err := c.verifyACLSnapshot(c.FormStr("acl_snapshot"), original)
			if err != nil {
				return err
			}
			if !ok {
				return c.renderACL(409, nil, nil, c.T("Access rules changed since this page was loaded. Reload before editing."), nil)
			}
		}
		render := func(ui []*Map, active *string) error { return c.renderACL(200, ui, active, nil, original) }
		if c.R.Method == http.MethodGet {
			ui := make([]*Map, len(original))
			for i, r := range original {
				ui[i] = backendRuleToUI(r.(*Map), i)
			}
			return render(ui, nil)
		}
		active := c.FormStrip("active_group_domain")
		inForm := func(k string) bool { _, ok := c.Form(k); return ok }
		intForm := func(k string) int {
			v, has := c.Form(k)
			if !has {
				v = "-1"
			}
			n, err := parsePyIntString(v)
			if err != nil {
				return -1
			}
			return int(n)
		}
		if inForm("add_rule") {
			ui, err := c.collectUIRules()
			if err != nil {
				return err
			}
			if len(ui) >= 500 {
				c.Flash(c.T("At most 500 access rules are allowed."), "danger")
				return render(ui, &active)
			}
			empty := ""
			return render(append(ui, emptyUIRule()), &empty)
		}
		for _, mv := range []struct{ key, dir string }{{"delete_rule", ""}, {"move_rule_up", "up"}, {"move_rule_down", "down"}} {
			if !inForm(mv.key) {
				continue
			}
			ui, err := c.collectUIRules()
			if err != nil {
				return err
			}
			idx := intForm(mv.key)
			if idx >= 0 && idx < len(ui) {
				if mv.dir == "" {
					ui = append(ui[:idx], ui[idx+1:]...)
				} else {
					moveRule(ui, idx, mv.dir)
				}
			}
			return render(ui, &active)
		}
		submit, _ := c.Form("submit_action")
		if submit == "save" || submit == "apply" {
			backend, ui, errs, err := c.convertFormToBackendRules(original)
			if err != nil {
				return err
			}
			if len(errs) > 0 {
				for _, m := range errs {
					c.Flash(m, "danger")
				}
				return render(ui, &active)
			}
			ok, msg := SaveRulesFromYAML(dumpYAML(backend), rulesRevision(original), true)
			cat := "danger"
			if ok {
				cat = "success"
			}
			c.Flash(c.T(msg), cat)
			if !ok {
				return render(ui, &active)
			}
			if submit == "apply" {
				c.Flash("Authelia rules saved successfully. Restarting Authelia...", "success")
				restart := ConfigdRequest(newMap("action", "restart"))
				if !truthy(restart.Value("ok")) {
					c.Flash("Rules were saved, but Authelia could not be restarted: "+pyStr(orValue(restart.Value("error"), "unknown error")), "warning")
				} else if !waitForAutheliaHealthy(30 * time.Second) {
					c.Flash("Authelia was restarted, but did not become ready before the health-check timed out. If the page does not open, refresh it in a few seconds.", "warning")
				} else {
					c.Flash("Rules saved and Authelia restarted successfully.", "success")
				}
			}
			return c.Redirect(c.URLFor("authelia_acl.edit_rules"), 302)
		}
		ui, err := c.collectUIRules()
		if err != nil {
			return err
		}
		return render(ui, &active)
	})
}

var _ = sort.Strings
