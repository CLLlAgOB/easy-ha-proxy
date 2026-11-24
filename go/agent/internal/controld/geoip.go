package controld

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/pyx"
)

func (d *Daemon) runGeoIPCommand(argv []string) (bool, string) {
	res, err := execRaw(argv, nil, time.Duration(d.Opts.GeoIPUpdateTimeout)*time.Second)
	if err != nil {
		return false, pyErr(err)
	}
	parts := []string{}
	for _, item := range []string{res.stdout, res.stderr} {
		if s := pyStrip(item); s != "" {
			parts = append(parts, s)
		}
	}
	output := strings.Join(parts, "\n")
	if r := []rune(output); len(r) > 8000 {
		output = string(r[len(r)-8000:])
	}
	return res.rc == 0, output
}

func intOrZero(v any) int64 {
	if !pyx.Truthy(v) {
		return 0
	}
	if n, ok := pyx.Int(v); ok {
		return n
	}
	f := pyx.Float(v)
	return int64(f)
}

func (d *Daemon) geoipStatus() map[string]any {
	var selectionError any
	selection, _, err := d.geoipSelection()
	if err != nil {
		selectionError = pyErr(err)
		selection = map[string]any{"available": false, "countries": []any{}, "access_filter_enabled": false, "revision": ""}
	}
	database := map[string]any{"available": false, "integrity_ok": false}
	if release := d.geoipCurrentRelease(); release != "" {
		state := d.readGeoIPState(release)
		dbPath, allowedPath := filepath.Join(release, "dbip-country-lite.mmdb"), filepath.Join(release, "allowed.geo")
		var dbSize, allowedSize int64
		if fi, err := os.Stat(dbPath); err == nil {
			dbSize = fi.Size()
		}
		if fi, err := os.Stat(allowedPath); err == nil {
			allowedSize = fi.Size()
		}
		buildEpoch := intOrZero(state["database_build_epoch"])
		var buildAt any
		if buildEpoch > 0 {
			buildAt = pyx.ISO(time.Unix(buildEpoch, 0).UTC())
		}
		formatOK := false
		if n, ok := pyx.Int(state["release_format_version"]); ok && n == 1 && !isBool(state["release_format_version"]) {
			formatOK = true
		}
		integrity := formatOK && sha256Matches(dbPath, state["database_sha256"]) && sha256Matches(allowedPath, state["allowed_sha256"])
		countryNetworks := any(map[string]any{})
		if m, ok := state["country_networks"].(map[string]any); ok {
			countryNetworks = m
		}
		countries := any([]any{})
		if l, ok := state["countries"].([]any); ok {
			countries = l
		}
		database = map[string]any{
			"available":             dbSize != 0 && len(state) > 0,
			"release":               filepath.Base(release),
			"provider":              pyx.StrOr(state["provider"]),
			"source_period":         pyx.StrOr(state["source_period"]),
			"activated_at":          state["activated_at"],
			"build_at":              buildAt,
			"records":               intOrZero(state["database_records"]),
			"size_bytes":            dbSize,
			"allowed_size_bytes":    allowedSize,
			"allowed_networks":      intOrZero(state["allowed_networks"]),
			"country_networks":      countryNetworks,
			"countries":             countries,
			"access_filter_enabled": pyx.Truthy(state["access_filter_enabled"]),
			"integrity_ok":          integrity,
		}
	}
	serviceRaw, _ := d.systemdProperties(geoipUpdateService, []string{"ActiveState", "SubState", "Result", "ExecMainStatus", "InactiveExitTimestamp"})
	timerRaw, _ := d.systemdProperties(geoipUpdateTimer, []string{"ActiveState", "SubState", "UnitFileState", "LastTriggerUSec", "NextElapseUSecRealtime"})
	get := func(m map[string]string, k, def string) string {
		if v, ok := m[k]; ok {
			return v
		}
		return def
	}
	orNone := func(m map[string]string, k string) any {
		if v := m[k]; v != "" {
			return v
		}
		return nil
	}
	service := map[string]any{
		"active_state": get(serviceRaw, "ActiveState", "unknown"),
		"sub_state":    get(serviceRaw, "SubState", "unknown"),
		"result":       get(serviceRaw, "Result", "unknown"),
		"exit_status":  get(serviceRaw, "ExecMainStatus", ""),
		"last_run_at":  orNone(serviceRaw, "InactiveExitTimestamp"),
	}
	if serviceRaw["error"] != "" {
		service["error"] = serviceRaw["error"]
	}
	timer := map[string]any{
		"active_state":    get(timerRaw, "ActiveState", "unknown"),
		"sub_state":       get(timerRaw, "SubState", "unknown"),
		"enabled":         timerRaw["UnitFileState"] == "enabled",
		"last_trigger_at": orNone(timerRaw, "LastTriggerUSec"),
		"next_run_at":     orNone(timerRaw, "NextElapseUSecRealtime"),
		"schedule":        d.geoipScheduleCurrent(),
	}
	if timerRaw["error"] != "" {
		timer["error"] = timerRaw["error"]
	}
	active, sub := service["active_state"].(string), service["sub_state"].(string)
	result := map[string]any{
		"ok":             selectionError == nil,
		"database":       database,
		"selection":      selection,
		"service":        service,
		"timer":          timer,
		"update_running": (active == "activating" || active == "active") && sub != "dead" && sub != "exited",
		"journal_tail":   d.geoipJournalTail(20),
	}
	if selectionError != nil && selectionError != "" {
		result["error"] = selectionError
	}
	// database.get("available") and countries == ... and enabled == ...
	var applied any = database["available"]
	if pyx.Truthy(applied) {
		applied = sameList(database["countries"], selection["countries"]) || bothEmptyLists(database["countries"], selection["countries"])
		if applied == true {
			applied = database["access_filter_enabled"] == selection["access_filter_enabled"]
		}
	}
	result["selection_applied"] = applied
	return result
}

func bothEmptyLists(a, b any) bool {
	la, oka := a.([]any)
	lb, okb := b.([]any)
	return oka && okb && len(la) == 0 && len(lb) == 0
}

func (d *Daemon) geoipScheduleCurrent() string {
	res, err := execRaw([]string{"/usr/bin/systemctl", "cat", geoipUpdateTimer}, nil, 10*time.Second)
	if err != nil {
		return ""
	}
	value := ""
	for _, line := range pySplitlines(res.stdout) {
		s := pyStrip(line)
		if strings.HasPrefix(s, "OnCalendar=") {
			value = pyStrip(strings.SplitN(s, "=", 2)[1])
		}
	}
	return value
}

func (d *Daemon) geoipSetSchedule(schedule any) map[string]any {
	value := strings.ToLower(pyStrip(pyx.StrOr(schedule)))
	allowed := false
	for _, s := range geoipAllowedSchedules {
		if s == value {
			allowed = true
		}
	}
	if !allowed {
		return map[string]any{"ok": false, "error": "schedule must be one of: " + strings.Join(geoipAllowedSchedules, ", ")}
	}
	content := "# Managed by the easy-ha-proxy web UI.\n[Timer]\nOnCalendar=\nOnCalendar=" + value + "\n"
	dropin := d.Opts.GeoIPTimerDropin
	if err := func() error {
		if err := os.MkdirAll(filepath.Dir(dropin), 0o777); err != nil {
			return err
		}
		tmp := dropin + ".tmp"
		if err := os.WriteFile(tmp, []byte(content), 0o666); err != nil {
			return err
		}
		return os.Rename(tmp, dropin)
	}(); err != nil {
		return map[string]any{"ok": false, "error": "cannot write timer override: " + pyErr(err)}
	}
	if ok, detail := d.runGeoIPCommand([]string{"/usr/bin/systemctl", "daemon-reload"}); !ok {
		return map[string]any{"ok": false, "error": "daemon-reload failed: " + detail}
	}
	if ok, detail := d.runGeoIPCommand([]string{"/usr/bin/systemctl", "restart", geoipUpdateTimer}); !ok {
		return map[string]any{"ok": false, "error": "timer restart failed: " + detail}
	}
	log.Printf("geoip: update schedule set to %s", value)
	return map[string]any{"ok": true, "message": "GeoIP update schedule set to " + value, "schedule": value, "status": d.geoipStatus()}
}

func busyUnit(state string) bool {
	return state == "activating" || state == "active" || state == "reloading"
}

func (d *Daemon) geoipUpdateNow(force bool) (map[string]any, error) {
	if !d.geoipOp.TryLock() {
		return map[string]any{"ok": false, "error": "another GeoIP operation is already running", "conflict": true}, nil
	}
	defer d.geoipOp.Unlock()
	tx, err := d.loadConfigTransaction()
	if err != nil {
		return nil, err
	}
	if tx != nil {
		if s, ok := tx["state"].(string); ok && activeStates[s] {
			return map[string]any{"ok": false, "error": "a HAProxy configuration transaction is still active", "conflict": true}, nil
		}
	}
	service, err := d.systemdProperties(geoipUpdateService, []string{"ActiveState", "SubState"})
	if err != nil {
		return nil, err
	}
	if busyUnit(service["ActiveState"]) {
		return map[string]any{"ok": false, "error": "another GeoIP operation is already running", "conflict": true, "status": d.geoipStatus()}, nil
	}
	markerCreated := false
	if force {
		fd, err := syscall.Open(d.Opts.GeoIPForceMarker, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
		if err != nil {
			if errors.Is(err, syscall.EEXIST) {
				return map[string]any{"ok": false, "error": "a forced GeoIP update is already queued", "conflict": true, "status": d.geoipStatus()}, nil
			}
			return nil, &os.PathError{Op: "open", Path: d.Opts.GeoIPForceMarker, Err: err}
		}
		_, werr := syscall.Write(fd, []byte("force\n"))
		if werr == nil {
			werr = syscall.Fsync(fd)
		}
		syscall.Close(fd)
		if werr != nil {
			return nil, werr
		}
		markerCreated = true
	}
	ok, detail := d.runGeoIPCommand([]string{"/usr/bin/systemctl", "start", "--no-block", geoipUpdateService})
	if !ok && markerCreated {
		_ = os.Remove(d.Opts.GeoIPForceMarker)
	}
	status := d.geoipStatus()
	message, errText := "GeoIP update started", any(nil)
	if !ok {
		message, errText = "GeoIP update failed", "GeoIP update failed"
	}
	return map[string]any{"ok": ok, "started": ok, "message": message, "error": errText, "stdout": detail,
		"active_acl_preserved": pyx.Truthy(status["selection_applied"]), "status": status}, nil
}

func (d *Daemon) geoipConfigure(countries, expectedRevision any) (map[string]any, error) {
	list, ok := countries.([]any)
	if !ok || len(list) > geoipMaxCountries {
		return nil, vErr("countries must be a list with at most 249 entries")
	}
	normalized := map[string]bool{}
	for _, raw := range list {
		s, ok := raw.(string)
		if !ok {
			return nil, vErr("country codes must be strings")
		}
		code := strings.ToUpper(pyStrip(s))
		if !isCountryCode(code) {
			return nil, vErr("invalid ISO country code: %s", pyRepr(s))
		}
		normalized[code] = true
	}
	selected := sortedKeys(normalized)
	revision := strings.ToLower(pyx.StrOr(expectedRevision))
	if !isHex64(revision) {
		return nil, vErr("the GeoIP selection revision is missing or invalid")
	}
	if !d.guarded.TryLock() {
		return map[string]any{"ok": false, "error": "another HAProxy configuration operation is already running", "conflict": true}, nil
	}
	defer d.guarded.Unlock()
	if err := d.ensureNoActiveConfigTransactionLocked(); err != nil {
		if isRuntime(err) {
			return map[string]any{"ok": false, "error": pyErr(err), "conflict": true}, nil
		}
		return nil, err
	}
	if !d.geoipOp.TryLock() {
		return map[string]any{"ok": false, "error": "another GeoIP operation is already running", "conflict": true}, nil
	}
	defer d.geoipOp.Unlock()
	service, err := d.systemdProperties(geoipUpdateService, []string{"ActiveState", "SubState"})
	if err != nil {
		return nil, err
	}
	if busyUnit(service["ActiveState"]) {
		return map[string]any{"ok": false, "error": "another GeoIP operation is already running", "conflict": true, "status": d.geoipStatus()}, nil
	}
	_, currentRaw, err := d.geoipSelection()
	if err != nil {
		return nil, err
	}
	current := sha256Hex(currentRaw)
	if !compareDigest(current, revision) {
		return map[string]any{"ok": false, "error": "GeoIP selection changed in another session; reload it before saving",
			"conflict": true, "current_revision": current, "status": d.geoipStatus()}, nil
	}
	argv := []string{d.Opts.GeoIPUpdateCommand, "--configure-selection"}
	for _, code := range selected {
		argv = append(argv, "--country", code)
	}
	ok, detail := d.runGeoIPCommand(argv)
	status := d.geoipStatus()
	message, errText := "GeoIP country selection updated", any(nil)
	if !ok {
		message, errText = "GeoIP country selection update failed", "GeoIP country selection update failed"
	}
	return map[string]any{"ok": ok, "message": message, "error": errText, "stdout": detail,
		"active_acl_preserved": pyx.Truthy(status["selection_applied"]), "status": status}, nil
}

// ---------------------------------------------------------------------------
// ipaddress
// ---------------------------------------------------------------------------

// pyIPAddress is str(ipaddress.ip_address(text)).
func pyIPAddress(text string) (string, error) {
	addr, err := netip.ParseAddr(text)
	if err != nil || addr.Zone() != "" {
		return "", fmt.Errorf("%s does not appear to be an IPv4 or IPv6 address", pyRepr(text))
	}
	return addr.String(), nil
}

// pyIPNetwork is str(ipaddress.ip_network(text, strict=False)).
func pyIPNetwork(text string) (string, error) {
	bad := fmt.Errorf("%s does not appear to be an IPv4 or IPv6 network", pyRepr(text))
	i := strings.Index(text, "/")
	if i < 0 || strings.Count(text, "/") != 1 {
		return "", bad
	}
	addrText, maskText := text[:i], text[i+1:]
	addr, err := netip.ParseAddr(addrText)
	if err != nil || addr.Zone() != "" {
		return "", bad
	}
	bits := -1
	if n, err := strconv.Atoi(maskText); err == nil && maskText != "" && strings.Trim(maskText, "0123456789") == "" {
		bits = n
	} else if addr.Is4() {
		mask, err := netip.ParseAddr(maskText)
		if err != nil || !mask.Is4() {
			return "", bad
		}
		bits = maskBits(mask.As4())
	}
	if bits < 0 || bits > addr.BitLen() {
		return "", bad
	}
	prefix, err := addr.Prefix(bits)
	if err != nil {
		return "", bad
	}
	return prefix.String(), nil
}

// maskBits reads a netmask or a hostmask; -1 when it is neither.
func maskBits(b [4]byte) int {
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	for n := 0; n <= 32; n++ {
		mask := uint32(0)
		if n > 0 {
			mask = ^uint32(0) << (32 - n)
		}
		if v == mask {
			return n
		}
		if v == ^mask {
			return n
		}
	}
	return -1
}

var _ = sort.Strings
