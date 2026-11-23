package app

// Port of services_haproxy_udp.py: kernel-NAT UDP forwarding.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"easy-ha-proxy/panel/internal/pyyaml"
)

const (
	maxUDPYAMLBytes    = 512 * 1024
	maxPortsPerForward = 1024
)

var portRangeRe = regexp.MustCompile(`^([0-9]{1,5})(?:-([0-9]{1,5}))?$`)

// GetUDPForwardsList is get_udp_forwards_list.
func GetUDPForwardsList() ([]any, error) {
	data, err := loadYAML(UDPYAML)
	if err != nil {
		return nil, err
	}
	f := data.Value("udp_forwards")
	if f == nil {
		f = data.Value("udp")
	}
	list, ok := asList(f)
	if !ok {
		return []any{}, nil
	}
	return list, nil
}

func parsePortRange(value any, label string) (int64, int64, any, error) {
	text := ""
	if value != nil {
		text = strip(value)
	}
	m := portRangeRe.FindStringSubmatch(text)
	if m == nil {
		return 0, 0, nil, valueErr("%s must be a port or inclusive range such as 51820-51830", label)
	}
	start, _ := strconv.ParseInt(m[1], 10, 64)
	end := start
	if m[2] != "" {
		end, _ = strconv.ParseInt(m[2], 10, 64)
	}
	if start < 1 || start > 65535 || end < 1 || end > 65535 {
		return 0, 0, nil, valueErr("%s must be between 1 and 65535", label)
	}
	if end < start {
		return 0, 0, nil, valueErr("%s range end must not be lower than its start", label)
	}
	if end-start+1 > maxPortsPerForward {
		return 0, 0, nil, valueErr("%s range may contain at most %d ports", label, maxPortsPerForward)
	}
	var canonical any = start
	if start != end {
		canonical = fmt.Sprintf("%d-%d", start, end)
	}
	return start, end, canonical, nil
}

func boolField(raw *Map, field string, def bool) (bool, error) {
	v, has := raw.Get(field)
	if !has {
		return def, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, valueErr("%s must be true or false", field)
	}
	return b, nil
}

func isLoopbackLiteral(host string) bool {
	a, ok := pyIPAddress(host)
	return ok && a.IsLoopback()
}

// normalizeUDPEntry is _normalize_udp_entry (presets given when havePresets).
func normalizeUDPEntry(rawV any, presets []*Map, havePresets bool) (bool, string, *Map) {
	in, ok := asMap(rawV)
	if !ok {
		return false, "Invalid UDP forward format (expected a JSON object)", nil
	}
	raw := copyMap(in)
	if !havePresets {
		var err error
		if presets, err = loadPresets(); err != nil {
			return false, err.Error(), nil
		}
	}
	if err := ApplyPresetToUDP(raw, presets); err != nil {
		return false, err.Error(), nil
	}
	out := pyyaml.NewMap()
	err := func() error {
		name, err := validateIdentifier(raw.Value("name"), "name")
		if err != nil {
			return err
		}
		out.Set("name", name)
		ls, le, lv, err := parsePortRange(raw.Value("listen_port"), "listen_port")
		if err != nil {
			return err
		}
		out.Set("listen_port", lv)
		host, err := validateHost(raw.Value("backend_host"), "backend_host")
		if err != nil {
			return err
		}
		out.Set("backend_host", host)
		if strings.ToLower(host) == "localhost" || isLoopbackLiteral(host) {
			return &ValueError{"backend_host must not use a loopback address; use a container or LAN backend"}
		}
		bs, be, bv, err := parsePortRange(raw.Value("backend_port"), "backend_port")
		if err != nil {
			return err
		}
		out.Set("backend_port", bv)
		if le-ls != be-bs {
			return &ValueError{"listen_port and backend_port ranges must contain the same number of ports"}
		}
		for _, f := range []struct {
			name string
			def  bool
		}{{"ban_check", true}, {"zero_trust", false}, {"enabled", true}} {
			b, err := boolField(raw, f.name, f.def)
			if err != nil {
				return err
			}
			out.Set(f.name, b)
		}
		return normalizeBackup(raw, out, bs, be)
	}()
	if err != nil {
		return false, err.Error(), nil
	}
	if truthy(raw.Value(presetField)) {
		out.Set(presetField, raw.Value(presetField))
		if truthy(raw.Value(idField)) {
			out.Set(idField, raw.Value(idField))
		}
	}
	return true, "", out
}

func normalizeBackup(raw, out *Map, backendStart, backendEnd int64) error {
	host := orStr(raw.Value("backup_host"))
	if host == "" {
		for _, f := range []string{"backup_port", "health_check", "health_port"} {
			v := orStr(raw.Value(f))
			if v != "" && v != "ping" {
				return valueErr("%s needs a backup_host", f)
			}
		}
		return nil
	}
	bh, err := validateHost(host, "backup_host")
	if err != nil {
		return err
	}
	out.Set("backup_host", bh)
	if strings.ToLower(bh) == "localhost" || isLoopbackLiteral(bh) {
		return &ValueError{"backup_host must not use a loopback address"}
	}
	if strings.ToLower(bh) == strings.ToLower(pyStr(out.Value("backend_host"))) {
		return &ValueError{"backup_host must be different from backend_host"}
	}
	if port := orStr(raw.Value("backup_port")); port != "" {
		s, e, v, err := parsePortRange(port, "backup_port")
		if err != nil {
			return err
		}
		if e-s != backendEnd-backendStart {
			return &ValueError{"backup_port must contain as many ports as backend_port"}
		}
		out.Set("backup_port", v)
	}
	check := strings.ToLower(orStr(orValue(raw.Value("health_check"), "ping")))
	if check != "ping" && check != "tcp" {
		return &ValueError{"health_check must be ping or tcp"}
	}
	out.Set("health_check", check)
	if check == "tcp" {
		text := orStr(raw.Value("health_port"))
		n, err := strconv.ParseInt(text, 10, 64)
		if !pyIsDigit(text) || err != nil || n < 1 || n > 65535 {
			return &ValueError{"health_port must be a TCP port (1-65535) for the tcp check"}
		}
		out.Set("health_port", n)
	}
	return nil
}

func overlappingForward(forwards []any, start, end int64, skip int) string {
	for i, cur := range forwards {
		if i == skip || get(cur, "enabled") == false {
			continue
		}
		cs, ce, _, err := parsePortRange(get(cur, "listen_port"), "existing listen_port")
		if err != nil {
			return "Existing UDP configuration is invalid: " + err.Error()
		}
		if start <= ce && cs <= end {
			name := any("another forward")
			if m, ok := asMap(cur); ok {
				if v, has := m.Get("name"); has {
					name = v
				}
			}
			return fmt.Sprintf("UDP listen range %d-%d overlaps %s (%d-%d)", start, end, pyRepr(name), cs, ce)
		}
	}
	return ""
}

func pyIntOr0(v any) int64 {
	n, _ := pyInt(v)
	return n
}

func udpSuccessMessage(state *Map) string {
	return fmt.Sprintf("UDP forwarding applied immediately. Active forwards: %d; forwarded ports: %d; applied at: %s.",
		pyIntOr0(orValue(state.Value("forwards"), int64(0))), pyIntOr0(orValue(state.Value("ports"), int64(0))),
		pyStr(orValue(state.Value("applied_at"), "unknown")))
}

// writeAndApplyUDP is _write_and_apply.
func writeAndApplyUDP(data *Map) (bool, string) {
	content := dumpYAML(data)
	if len(content) > maxUDPYAMLBytes {
		return false, "udp.yml exceeds the size limit"
	}
	previous := []byte("udp_forwards: []\n")
	mode := os.FileMode(0o640)
	if info, err := os.Stat(UDPYAML); err == nil {
		raw, err := os.ReadFile(UDPYAML)
		if err != nil {
			return false, fmt.Sprintf("Failed to read the previous %s: %s", filepath.Base(UDPYAML), pyFileError(err, UDPYAML))
		}
		previous = raw
		mode = info.Mode().Perm()
	}
	if err := atomicWriteSnapshot(UDPYAML, []byte(content), mode); err != nil {
		return false, fmt.Sprintf("Failed to write %s: %s", filepath.Base(UDPYAML), pyOSError(err))
	}
	ok, state, errText := ApplyUDPForwards()
	if ok {
		return true, udpSuccessMessage(state)
	}
	if err := atomicWriteSnapshot(UDPYAML, previous, mode); err != nil {
		return false, fmt.Sprintf("Applying the UDP rules failed and restoring udp.yml also failed: %s; restore error: %s", errText, pyOSError(err))
	}
	rok, _, rerr := ApplyUDPForwards()
	if rok {
		return false, "Applying the UDP rules failed. The previous configuration and rules were restored automatically: " + errText
	}
	return false, fmt.Sprintf("Applying the UDP rules failed and automatic rule rollback also failed: %s; rollback error: %s", errText, rerr)
}

// UDPRevision is udp_revision.
func UDPRevision(forward any) string { return EntryRevision(forward) }

// SaveUDPFromJSON is save_udp_from_json.
func SaveUDPFromJSON(op *Op, udp any, originalName, revision string) (bool, string) {
	release, err := op.Lock("udp")
	if err != nil {
		return false, err.Error()
	}
	defer release()
	ok, msg, err := saveUDP(udp, originalName, revision)
	if err != nil {
		if se, isStale := err.(*StaleEntry); isStale {
			return false, se.Msg
		}
		return false, err.Error()
	}
	return ok, msg
}

func udpForwardsOf(data *Map) []any {
	f := data.Value("udp_forwards")
	if f == nil {
		f = data.Value("udp")
	}
	list, ok := asList(f)
	if !ok {
		return []any{}
	}
	return list
}

func saveUDP(udp any, originalName, revision string) (bool, string, error) {
	ok, msg, entry := normalizeUDPEntry(udp, nil, false)
	if !ok || entry == nil {
		return false, msg, nil
	}
	name := pyStr(entry.Value("name"))
	data, err := loadYAML(UDPYAML)
	if err != nil {
		return false, "", err
	}
	forwards := udpForwardsOf(data)
	ls, le, _, err := parsePortRange(entry.Value("listen_port"), "listen_port")
	if err != nil {
		return false, err.Error(), nil
	}
	nameTaken := func() bool {
		for _, f := range forwards {
			if pyEqual(get(f, "name"), name) {
				return true
			}
		}
		return false
	}
	if originalName != "" {
		idx := -1
		for i, f := range forwards {
			if pyEqual(get(f, "name"), originalName) {
				idx = i
				break
			}
		}
		if idx < 0 {
			return false, fmt.Sprintf("UDP forward with name=%s not found", pyRepr(originalName)), nil
		}
		if err := CheckEntryRevision(forwards[idx], revision, "UDP forward "+pyRepr(originalName)); err != nil {
			return false, "", err
		}
		if name != originalName && nameTaken() {
			return false, fmt.Sprintf("UDP forward with name=%s already exists", pyRepr(name)), nil
		}
		if o := overlappingForward(forwards, ls, le, idx); o != "" {
			return false, o, nil
		}
		if entry.Value("enabled") == true {
			if c := UDPListenPortConflict(ls, le); c != "" {
				return false, c, nil
			}
		}
		forwards[idx] = entry
	} else {
		if nameTaken() {
			return false, fmt.Sprintf("UDP forward with name=%s already exists", pyRepr(name)), nil
		}
		if o := overlappingForward(forwards, ls, le, -1); o != "" {
			return false, o, nil
		}
		if entry.Value("enabled") == true {
			if c := UDPListenPortConflict(ls, le); c != "" {
				return false, c, nil
			}
		}
		forwards = append(forwards, entry)
	}
	data.Delete("udp")
	data.Set("udp_forwards", forwards)
	ok, msg = writeAndApplyUDP(data)
	return ok, msg, nil
}

// DeleteUDPForward is delete_udp_forward.
func DeleteUDPForward(op *Op, name string) (bool, string) {
	release, err := op.Lock("udp")
	if err != nil {
		return false, err.Error()
	}
	defer release()
	data, err := loadYAML(UDPYAML)
	if err != nil {
		return false, err.Error()
	}
	f := data.Value("udp_forwards")
	if f == nil {
		f = data.Value("udp")
	}
	forwards, ok := asList(f)
	if !ok {
		return false, "Invalid udp.yml structure (expected a udp_forwards list)"
	}
	var removed any
	var kept []any
	for _, fw := range forwards {
		if pyEqual(get(fw, "name"), name) {
			if removed == nil {
				removed = fw
			}
			continue
		}
		kept = append(kept, fw)
	}
	if removed == nil {
		return false, fmt.Sprintf("UDP forward with name=%s not found", pyRepr(name))
	}
	if kept == nil {
		kept = []any{}
	}
	itemID, err := TrashKeep(op, "udp", name, removed, nil)
	if err != nil {
		return false, "The entry could not be kept in the trash, so nothing was deleted: " + err.Error()
	}
	data.Delete("udp")
	data.Set("udp_forwards", kept)
	ok, msg := writeAndApplyUDP(data)
	if !ok {
		if TrashSettle(itemID, udpInSource(name)) {
			return false, msg + " The UDP forward is gone from udp.yml all the same; it was kept in the trash."
		}
		return ok, msg
	}
	TrashCommit(itemID)
	return ok, msg + " The UDP forward was moved to the trash and can be restored there."
}

func udpInSource(name string) bool {
	data, err := loadYAML(UDPYAML)
	if err != nil {
		return false
	}
	f := data.Value("udp_forwards")
	if f == nil {
		f = data.Value("udp")
	}
	list, ok := asList(f)
	if !ok {
		return false
	}
	for _, fw := range list {
		if m, ok := asMap(fw); ok && pyEqual(m.Value("name"), name) {
			return true
		}
	}
	return false
}

// RestoreUDPForward is restore_udp_forward.
func RestoreUDPForward(op *Op, entry *Map, _ *Map) (bool, string, *Map) {
	release, err := op.Lock("udp")
	if err != nil {
		return false, err.Error(), pyyaml.NewMap()
	}
	defer release()
	data, err := loadYAML(UDPYAML)
	if err != nil {
		return false, err.Error(), pyyaml.NewMap()
	}
	f := data.Value("udp_forwards")
	if f == nil {
		f = data.Value("udp")
	}
	if f == nil {
		f = []any{}
	}
	forwards, ok := asList(f)
	if !ok {
		return false, "Invalid udp.yml structure (expected a udp_forwards list)", pyyaml.NewMap()
	}
	name := strOrEmpty(entry.Value("name"))
	for _, fw := range forwards {
		if pyEqual(get(fw, "name"), name) {
			return false, fmt.Sprintf("UDP forward with name=%s already exists", pyRepr(name)), pyyaml.NewMap()
		}
	}
	s, e, _, err := parsePortRange(entry.Value("listen_port"), "listen_port")
	if err != nil {
		return false, err.Error(), pyyaml.NewMap()
	}
	if o := overlappingForward(forwards, s, e, -1); o != "" {
		return false, o, pyyaml.NewMap()
	}
	enabled, has := entry.Get("enabled")
	if !has {
		enabled = true
	}
	if truthy(enabled) {
		if c := UDPListenPortConflict(s, e); c != "" {
			return false, c, pyyaml.NewMap()
		}
	}
	forwards = append(forwards, entry)
	data.Delete("udp")
	data.Set("udp_forwards", forwards)
	ok, msg := writeAndApplyUDP(data)
	return ok, msg, pyyaml.NewMap()
}
