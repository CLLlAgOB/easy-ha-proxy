package app

// Port of backend_presets.py: named lists of backend addresses.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"

	"easy-ha-proxy/panel/internal/pyyaml"
)

const (
	presetsKey  = "backend_presets"
	presetField = "servers_preset"
	portField   = "servers_preset_port"
	idField     = "servers_preset_id"
	noteMax     = 64
	maxPresets  = 50
	maxServers  = 16
	followRetry = 60
)

var presetIDRe = regexp.MustCompile(`^[0-9a-f]{12}$`)

// presetNameOK is NAME_RE = ^[^\W_][\w .-]{0,47}$ with Unicode \w.
func presetNameOK(name string) bool {
	rs := []rune(name)
	if len(rs) == 0 || len(rs) > 48 {
		return false
	}
	isWord := func(r rune) bool {
		return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Nd, r)
	}
	if !isWord(rs[0]) || rs[0] == '_' {
		return false
	}
	for _, r := range rs[1:] {
		if !(isWord(r) || r == ' ' || r == '.' || r == '-') {
			return false
		}
	}
	return true
}

func dumpYAML(data any) string {
	out, err := pyyaml.Dump(data, pyyaml.Options{AllowUnicode: true})
	if err != nil {
		panic(err)
	}
	return out
}

func presetsFrom(varsData any) []*Map {
	raw, ok := asList(get(varsData, presetsKey))
	if !ok {
		return nil
	}
	var out []*Map
	for _, it := range raw {
		if m, ok := asMap(it); ok && truthy(m.Value("name")) {
			out = append(out, m)
		}
	}
	return out
}

func loadPresets() ([]*Map, error) {
	v, err := loadYAML(ConfigYAML)
	if err != nil {
		return nil, err
	}
	return presetsFrom(v), nil
}

func findPreset(presets []*Map, name any) *Map {
	wanted := orStr(name)
	for _, p := range presets {
		if pyStr(p.Value("name")) == wanted {
			return p
		}
	}
	return nil
}

func effectivePresetID(p *Map) string {
	stored := strOrEmpty(p.Value("id"))
	if presetIDRe.MatchString(stored) {
		return stored
	}
	sum := sha256.Sum256([]byte("backend-set:" + pyStr(p.Value("name"))))
	return hex.EncodeToString(sum[:])[:12]
}

func findPresetByID(presets []*Map, id any) *Map {
	wanted := orStr(id)
	if !presetIDRe.MatchString(wanted) {
		return nil
	}
	for _, p := range presets {
		if effectivePresetID(p) == wanted {
			return p
		}
	}
	return nil
}

func tokenHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// NormalizePreset is normalize_preset.
func NormalizePreset(raw any) (*Map, error) {
	m, ok := asMap(raw)
	if !ok {
		return nil, &ValueError{"Invalid backend set (expected an object)"}
	}
	name := orStr(m.Value("name"))
	if !presetNameOK(name) {
		return nil, &ValueError{"Backend set name: up to 48 letters, digits, spaces, dots, dashes or underscores, starting with a letter or digit"}
	}
	in, ok := asList(m.Value("servers"))
	if !ok {
		return nil, &ValueError{"A backend set needs a list of addresses"}
	}
	var servers []any
	seen := map[string]bool{}
	for i, it := range in {
		index := i + 1
		item, ok := asMap(it)
		if !ok {
			continue
		}
		hostText := orStr(item.Value("host"))
		if hostText == "" {
			continue
		}
		host, err := validateHost(hostText, fmt.Sprintf("address %d", index))
		if err != nil {
			return nil, err
		}
		if seen[strings.ToLower(host)] {
			return nil, valueErr("Address %s appears twice in the set", host)
		}
		seen[strings.ToLower(host)] = true
		role := strings.ToLower(orStr(orValue(item.Value("role"), "primary")))
		if role != "primary" && role != "backup" {
			return nil, valueErr("Address %d: role must be primary or backup", index)
		}
		server := newMap("host", host, "role", role)
		w := item.Value("weight")
		if w != nil && w != "" {
			n, err := pyInt(w)
			if err != nil || n < 1 || n > 256 {
				return nil, valueErr("Address %d: weight must be a number from 1 to 256", index)
			}
			server.Set("weight", n)
		}
		note := truncRunes(strings.Join(strings.Fields(strOrEmpty(item.Value("note"))), " "), noteMax)
		if note != "" {
			server.Set("note", note)
		}
		servers = append(servers, server)
	}
	if len(servers) == 0 {
		return nil, &ValueError{"A backend set needs at least one address"}
	}
	if len(servers) > maxServers {
		return nil, valueErr("A backend set holds at most %d addresses", maxServers)
	}
	hasPrimary := false
	for _, s := range servers {
		if s.(*Map).Value("role") == "primary" {
			hasPrimary = true
		}
	}
	if !hasPrimary {
		return nil, &ValueError{"A backend set needs at least one primary address"}
	}
	return newMap("name", name, "servers", servers), nil
}

func expandServers(preset *Map, port int64, weights bool) []any {
	var out []any
	primary, backup := 0, 0
	list, _ := asList(orValue(preset.Value("servers"), []any{}))
	for _, s := range list {
		server := s.(*Map)
		isBackup := server.Value("role") == "backup"
		var name string
		if isBackup {
			backup++
			name = fmt.Sprintf("backup%d", backup)
		} else {
			primary++
			name = fmt.Sprintf("srv%d", primary)
		}
		entry := newMap("name", name, "host", server.Value("host"), "port", port)
		if isBackup {
			entry.Set("backup", true)
		}
		if weights && truthy(server.Value("weight")) {
			entry.Set("weight", server.Value("weight"))
		}
		out = append(out, entry)
	}
	if out == nil {
		out = []any{}
	}
	return out
}

func presetReference(entry *Map, presets []*Map) (*Map, error) {
	name := orStr(entry.Value(presetField))
	if name == "" {
		for _, f := range []string{presetField, portField, idField} {
			entry.Delete(f)
		}
		return nil, nil
	}
	p := findPreset(presets, name)
	if p == nil {
		p = findPresetByID(presets, entry.Value(idField))
	}
	if p == nil {
		return nil, valueErr("Backend set %s does not exist", pyRepr(name))
	}
	entry.Set(presetField, p.Value("name"))
	return p, nil
}

// ApplyPresetToSite is apply_to_site.
func ApplyPresetToSite(entry *Map, presets []*Map) error {
	p, err := presetReference(entry, presets)
	if err != nil || p == nil {
		return err
	}
	port, err := validatePort(entry.Value(portField), "backend set port")
	if err != nil {
		return err
	}
	entry.Set(portField, port)
	entry.Set("servers", expandServers(p, port, true))
	entry.Delete("backend_ip")
	entry.Delete("backend_port")
	return nil
}

// ApplyPresetToTCP is apply_to_tcp.
func ApplyPresetToTCP(entry *Map, presets []*Map) error {
	p, err := presetReference(entry, presets)
	if err != nil || p == nil {
		return err
	}
	port, err := validatePort(entry.Value(portField), "backend set port")
	if err != nil {
		return err
	}
	entry.Set(portField, port)
	entry.Set("servers", expandServers(p, port, false))
	entry.Delete("backend_host")
	entry.Delete("backend_port")
	return nil
}

// ApplyPresetToUDP is apply_to_udp.
func ApplyPresetToUDP(entry *Map, presets []*Map) error {
	p, err := presetReference(entry, presets)
	entry.Delete(portField)
	if err != nil || p == nil {
		return err
	}
	entry.Set(idField, effectivePresetID(p))
	list, _ := asList(orValue(p.Value("servers"), []any{}))
	primary, backup := "", ""
	for _, s := range list {
		sm := s.(*Map)
		if sm.Value("role") != "backup" && primary == "" {
			primary = pyStr(sm.Value("host"))
		}
		if sm.Value("role") == "backup" && backup == "" {
			backup = pyStr(sm.Value("host"))
		}
	}
	entry.Set("backend_host", primary)
	if backup != "" {
		entry.Set("backup_host", backup)
	} else {
		for _, f := range []string{"backup_host", "backup_port", "health_check", "health_port"} {
			entry.Delete(f)
		}
	}
	return nil
}

func dictItems(v any) []*Map {
	list, ok := asList(v)
	if !ok {
		return nil
	}
	var out []*Map
	for _, it := range list {
		if m, ok := asMap(it); ok {
			out = append(out, m)
		}
	}
	return out
}

func sitesOf(data *Map) []*Map { return dictItems(data.Value("sites")) }

func tcpOf(data *Map) []*Map {
	v, has := data.Get("tcp_proxies")
	if !has {
		v = data.Value("tcp")
	}
	return dictItems(v)
}

func udpOf(data *Map) []*Map {
	v, has := data.Get("udp_forwards")
	if !has {
		v = data.Value("udp")
	}
	return dictItems(v)
}

// PresetUsage is usage(): {set name: [{"kind", "name"}]}.
func PresetUsage(websites, tcp, udp *Map, presets []*Map, havePresets bool) (*Map, error) {
	var err error
	if websites == nil {
		if websites, err = loadYAML(WebsitesYAML); err != nil {
			return nil, err
		}
	}
	if tcp == nil {
		if tcp, err = loadYAML(TCPYAML); err != nil {
			return nil, err
		}
	}
	if udp == nil {
		if udp, err = loadYAML(UDPYAML); err != nil {
			return nil, err
		}
	}
	if !havePresets {
		if presets, err = loadPresets(); err != nil {
			return nil, err
		}
	}
	found := pyyaml.NewMap()
	for _, group := range []struct {
		kind    string
		entries []*Map
	}{{"site", sitesOf(websites)}, {"tcp", tcpOf(tcp)}, {"udp", udpOf(udp)}} {
		for _, e := range group.entries {
			name := orStr(e.Value(presetField))
			if name == "" {
				continue
			}
			if group.kind == "udp" {
				if p := findPresetByID(presets, e.Value(idField)); p != nil {
					name = pyStr(p.Value("name"))
				}
			}
			cur, _ := asList(found.Value(name))
			found.Set(name, append(cur, newMap("kind", group.kind, "name", strOrEmpty(e.Value("name")))))
		}
	}
	return found, nil
}

func repoint(entries []*Map, old, newName string) []*Map {
	var touched []*Map
	for _, e := range entries {
		name := orStr(e.Value(presetField))
		if old != "" && name == old {
			e.Set(presetField, newName)
			touched = append(touched, e)
		} else if name == newName {
			touched = append(touched, e)
		}
	}
	return touched
}

func repointUDP(forwards []*Map, old string, preset *Map) []*Map {
	var touched []*Map
	for _, f := range forwards {
		name := orStr(f.Value(presetField))
		if name == "" {
			continue
		}
		sameID := pyEqual(f.Value(idField), effectivePresetID(preset))
		if sameID || name == pyStr(preset.Value("name")) || (old != "" && name == old) {
			f.Set(presetField, preset.Value("name"))
			touched = append(touched, f)
		}
	}
	return touched
}

func expandUDP(data *Map, touched []*Map, presets []*Map) (*Map, error) {
	isTouched := map[*Map]bool{}
	for _, t := range touched {
		isTouched[t] = true
	}
	normalized := []any{}
	for _, f := range udpOf(data) {
		if isTouched[f] {
			ok, msg, clean := normalizeUDPEntry(f, presets, true)
			if !ok || clean == nil {
				return nil, valueErr("UDP forward %s: %s", pyStr(f.Value("name")), msg)
			}
			normalized = append(normalized, clean)
		} else {
			normalized = append(normalized, f)
		}
	}
	out := copyMap(data)
	out.Delete("udp")
	out.Set("udp_forwards", normalized)
	return out, nil
}

type fileSnapshot struct {
	path string
	raw  []byte
	mode os.FileMode
}

func snapshotFiles(paths ...string) []fileSnapshot {
	var out []fileSnapshot
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			out = append(out, fileSnapshot{p, nil, 0o640})
			continue
		}
		mode := os.FileMode(0o640)
		if info, err := os.Stat(p); err == nil {
			mode = info.Mode().Perm()
		}
		out = append(out, fileSnapshot{p, raw, mode})
	}
	return out
}

func putBack(snaps []fileSnapshot) []string {
	var failed []string
	for _, s := range snaps {
		var err error
		if s.raw == nil {
			if e := os.Remove(s.path); e != nil && !os.IsNotExist(e) {
				err = e
			}
		} else {
			err = atomicWriteSnapshot(s.path, s.raw, s.mode)
		}
		if err != nil {
			failed = append(failed, filepath.Base(s.path)+": "+pyOSError(err))
		}
	}
	return failed
}

// SavePreset is save_preset.
func SavePreset(op *Op, raw any, originalName, expectedRevision string) (bool, string) {
	preset, err := NormalizePreset(raw)
	if err != nil {
		return false, err.Error()
	}
	if pending, msg := ConfigTransactionIsPending(op); pending {
		return false, msg
	}
	original := strings.TrimSpace(originalName)
	release, err := op.LockAll("websites", "tcp", "vars", "udp")
	if err != nil {
		return false, err.Error()
	}
	defer release()
	varsData, err := loadYAML(ConfigYAML)
	if err != nil {
		return false, err.Error()
	}
	presets := presetsFrom(varsData)
	if original != "" {
		index := -1
		for i, p := range presets {
			if pyEqual(p.Value("name"), original) {
				index = i
				break
			}
		}
		if index < 0 {
			return false, fmt.Sprintf("Backend set %s was not found", pyRepr(original))
		}
		if err := CheckEntryRevision(presets[index], expectedRevision, "This backend set"); err != nil {
			return false, err.Error()
		}
		if pyStr(preset.Value("name")) != original && findPreset(presets, preset.Value("name")) != nil {
			return false, fmt.Sprintf("Backend set %s already exists", pyRepr(preset.Value("name")))
		}
		withID := newMap("id", effectivePresetID(presets[index]))
		preset.Each(func(k, v any) { withID.Set(k, v) })
		preset = withID
		presets[index] = preset
	} else {
		if findPreset(presets, preset.Value("name")) != nil {
			return false, fmt.Sprintf("Backend set %s already exists", pyRepr(preset.Value("name")))
		}
		if len(presets) >= maxPresets {
			return false, fmt.Sprintf("At most %d backend sets", maxPresets)
		}
		withID := newMap("id", tokenHex(6))
		preset.Each(func(k, v any) { withID.Set(k, v) })
		preset = withID
		presets = append(presets, preset)
	}
	presetList := make([]any, len(presets))
	for i, p := range presets {
		presetList[i] = p
	}
	varsData.Set(presetsKey, presetList)
	websites, err := loadYAML(WebsitesYAML)
	if err != nil {
		return false, err.Error()
	}
	tcp, err := loadYAML(TCPYAML)
	if err != nil {
		return false, err.Error()
	}
	udp, err := loadYAML(UDPYAML)
	if err != nil {
		return false, err.Error()
	}
	newName := pyStr(preset.Value("name"))
	sites := repoint(sitesOf(websites), original, newName)
	proxies := repoint(tcpOf(tcp), original, newName)
	forwards := repointUDP(udpOf(udp), original, preset)
	var newUDP *Map
	checkErr := func() error {
		for _, s := range sites {
			if err := ApplyPresetToSite(s, presets); err != nil {
				return err
			}
		}
		for _, p := range proxies {
			if err := ApplyPresetToTCP(p, presets); err != nil {
				return err
			}
		}
		if len(forwards) > 0 {
			var err error
			if newUDP, err = expandUDP(udp, forwards, presets); err != nil {
				return err
			}
		}
		if err := ValidateConfigData("vars", varsData); err != nil {
			return err
		}
		if len(sites) > 0 {
			if err := ValidateConfigData("websites", websites); err != nil {
				return err
			}
		}
		if len(proxies) > 0 {
			if err := ValidateConfigData("tcp", tcp); err != nil {
				return err
			}
		}
		return nil
	}()
	if checkErr != nil {
		return false, checkErr.Error()
	}
	before := snapshotFiles(ConfigYAML, WebsitesYAML, TCPYAML)
	type write struct {
		kind string
		data *Map
	}
	writes := []write{{"vars", varsData}}
	if len(sites) > 0 {
		writes = append(writes, write{"websites", websites})
	}
	if len(proxies) > 0 {
		writes = append(writes, write{"tcp", tcp})
	}
	for _, w := range writes {
		ok, msg := UpdateYAMLFile(op, w.kind, dumpYAML(w.data))
		if !ok {
			failed := putBack(before)
			if len(failed) > 0 {
				msg += " Restoring failed: " + strings.Join(failed, "; ")
			}
			return false, msg
		}
	}
	if newUDP != nil {
		ok, msg := writeAndApplyUDP(newUDP)
		if !ok {
			failed := putBack(before)
			if len(failed) > 0 {
				return false, fmt.Sprintf("The UDP forwards were not updated: %s Restoring the other sources also failed: %s", msg, strings.Join(failed, "; "))
			}
			return false, "The UDP forwards were not updated, so the set was not saved: " + msg
		}
	}
	parts := []string{fmt.Sprintf("Backend set %s saved.", pyRepr(newName))}
	if len(sites) > 0 || len(proxies) > 0 {
		parts = append(parts, fmt.Sprintf("Updated %d site(s) and %d TCP proxy(ies); validate and apply the HAProxy configuration to put them in effect.", len(sites), len(proxies)))
	}
	if len(forwards) > 0 {
		parts = append(parts, fmt.Sprintf("%d UDP forward(s) updated and applied.", len(forwards)))
	}
	return true, strings.Join(parts, " ")
}

// ReconcileUDP is reconcile_udp.
func ReconcileUDP(op *Op) (bool, int, string, error) {
	release, err := op.Lock("udp")
	if err != nil {
		return false, 0, "", err
	}
	defer release()
	presets, err := loadPresets()
	if err != nil {
		return false, 0, "", err
	}
	data, err := loadYAML(UDPYAML)
	if err != nil {
		return false, 0, "", err
	}
	var touched []*Map
	dropped := 0
	for _, f := range udpOf(data) {
		name := orStr(f.Value(presetField))
		if name == "" {
			continue
		}
		p := findPresetByID(presets, f.Value(idField))
		if p == nil {
			p = findPreset(presets, name)
		}
		if p == nil {
			f.Delete(presetField)
			f.Delete(idField)
			dropped++
			continue
		}
		keys := []string{presetField, idField, "backend_host", "backup_host"}
		before := make([]any, len(keys))
		for i, k := range keys {
			before[i] = f.Value(k)
		}
		candidate := copyMap(f)
		candidate.Set(presetField, p.Value("name"))
		if err := ApplyPresetToUDP(candidate, presets); err != nil {
			return false, 0, "", err
		}
		changed := false
		for i, k := range keys {
			if !pyEqual(candidate.Value(k), before[i]) {
				changed = true
			}
		}
		if changed {
			f.Set(presetField, p.Value("name"))
			touched = append(touched, f)
		}
	}
	if len(touched) == 0 && dropped == 0 {
		return true, 0, "", nil
	}
	newUDP, err := expandUDP(data, touched, presets)
	if err != nil {
		return false, 0, err.Error(), nil
	}
	ok, msg := writeAndApplyUDP(newUDP)
	return ok, len(touched) + dropped, msg, nil
}

func followPath() string {
	return filepath.Join(filepath.Dir(UDPYAML), ".backend-sets-udp-follow.json")
}

func readFollow() *Map {
	raw, err := os.ReadFile(followPath())
	if err != nil {
		return pyyaml.NewMap()
	}
	v, err := pyyaml.JSONLoads(raw)
	if err != nil {
		return pyyaml.NewMap()
	}
	if m, ok := asMap(v); ok {
		return m
	}
	return pyyaml.NewMap()
}

func writeFollow(state *Map) error {
	path := followPath()
	tmp := path + ".tmp"
	text, err := PyJSON(state, JSONOpts{EnsureASCII: true})
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, []byte(text), 0o666); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// markBackendSets is mark_udp_follow (via _mark_backend_sets).
func markBackendSets(op *Op, where string) {
	release, err := op.Lock("udp")
	if err != nil {
		log.Printf("Could not record a pending UDP reconciliation after %s: %v", where, err)
		return
	}
	defer release()
	state := readFollow()
	since := state.Value("since")
	if !truthy(since) {
		since = time.Now().Unix()
	}
	state.Set("where", where)
	state.Set("since", since)
	state.Set("next", int64(0))
	state.Set("token", tokenHex(8))
	if err := writeFollow(state); err != nil {
		log.Printf("Could not record a pending UDP reconciliation after %s: %v", where, err)
	}
}

// followBackendSets is _follow_backend_sets.
func followBackendSets(op *Op, where string, result *Map, mark bool) string {
	if mark {
		markBackendSets(op, where)
	}
	if op.holdsAny() {
		return ""
	}
	note := followUDP(op, mark)
	if note != "" && result != nil {
		result.Set("backend_sets_note", note)
	}
	return note
}

func pyFloat(v any) float64 {
	switch x := v.(type) {
	case int64:
		return float64(x)
	case float64:
		return x
	case bool:
		if x {
			return 1
		}
	case string:
		var f float64
		_, _ = fmt.Sscan(strings.TrimSpace(x), &f)
		return f
	}
	return 0
}

func followUDP(op *Op, force bool) string {
	state := readFollow()
	if state.Len() == 0 {
		return ""
	}
	if !force && float64(time.Now().UnixNano())/1e9 < pyFloat(orValue(state.Value("next"), int64(0))) {
		return "The UDP forwards have not followed the backend sets yet: " + pyStr(orValue(state.Value("error"), "waiting"))
	}
	token := state.Value("token")
	ok, count, msg, err := ReconcileUDP(op)
	if err != nil {
		ok, count, msg = false, 0, pyExceptionText(err)
	}
	release, lerr := op.Lock("udp")
	if lerr != nil {
		return "The UDP forwards could not follow the backend sets: " + lerr.Error()
	}
	defer release()
	current := readFollow()
	if !pyEqual(current.Value("token"), token) {
		if ok && count > 0 {
			return fmt.Sprintf("%d UDP forward(s) followed the backend sets and were applied again.", count)
		}
		return ""
	}
	if ok {
		if err := os.Remove(followPath()); err != nil && !os.IsNotExist(err) {
			log.Printf("Could not clear the pending UDP reconciliation: %v", err)
		}
		if count > 0 {
			return fmt.Sprintf("%d UDP forward(s) followed the backend sets and were applied again.", count)
		}
		return ""
	}
	log.Printf("UDP forwards not reconciled with the backend sets after %s: %s", pyStr(current.Value("where")), msg)
	current.Set("error", truncRunes(msg, 500))
	current.Set("next", float64(time.Now().UnixNano())/1e9+followRetry)
	_ = writeFollow(current)
	return "The UDP forwards could not follow the backend sets: " + msg
}

// pyExceptionText is f"{type(exc).__name__}: {exc}".
func pyExceptionText(err error) string {
	name := "Exception"
	switch err.(type) {
	case *ValueError:
		name = "ValueError"
	case *OSError:
		name = "OSError"
	case *TypeError:
		name = "TypeError"
	}
	return name + ": " + err.Error()
}

// FollowUDPError is follow_udp_error.
func FollowUDPError() string {
	state := readFollow()
	if state.Len() == 0 {
		return ""
	}
	return pyStr(orValue(state.Value("error"), "waiting for the next attempt"))
}

// DeletePreset is delete_preset.
func DeletePreset(op *Op, name string) (bool, string) {
	name = strings.TrimSpace(name)
	if pending, msg := ConfigTransactionIsPending(op); pending {
		return false, msg
	}
	release, err := op.LockAll("websites", "tcp", "vars", "udp")
	if err != nil {
		return false, err.Error()
	}
	defer release()
	varsData, err := loadYAML(ConfigYAML)
	if err != nil {
		return false, err.Error()
	}
	presets := presetsFrom(varsData)
	if findPreset(presets, name) == nil {
		return false, fmt.Sprintf("Backend set %s was not found", pyRepr(name))
	}
	usage, err := PresetUsage(nil, nil, nil, presets, true)
	if err != nil {
		return false, err.Error()
	}
	users, _ := asList(usage.Value(name))
	if len(users) > 0 {
		var listed []string
		for i, u := range users {
			if i >= 5 {
				break
			}
			listed = append(listed, pyStr(get(u, "name")))
		}
		return false, fmt.Sprintf("Backend set %s is used by %d entr(ies): %s. Switch them to another set or to manual addresses first.", pyRepr(name), len(users), strings.Join(listed, ", "))
	}
	var kept []any
	for _, p := range presets {
		if !pyEqual(p.Value("name"), name) {
			kept = append(kept, p)
		}
	}
	if len(kept) == 0 {
		varsData.Delete(presetsKey)
	} else {
		varsData.Set(presetsKey, kept)
	}
	return UpdateYAMLFile(op, "vars", dumpYAML(varsData))
}
