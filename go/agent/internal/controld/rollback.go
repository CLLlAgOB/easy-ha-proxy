package controld

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/pyx"
)

func (d *Daemon) geoipSelectionPath() string {
	return filepath.Join(d.Opts.GeoIPDirectory, "selection.json")
}
func (d *Daemon) geoipReleasesPath() string { return filepath.Join(d.Opts.GeoIPDirectory, "releases") }

func (d *Daemon) removeAdminAllowlist() error {
	fd, err := d.openAdminAllowlistDirectory()
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	name := filepath.Base(d.Opts.AdminAllowlistPath)
	var st unix.Stat_t
	if err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if err == unix.ENOENT {
			return nil
		}
		return &os.PathError{Op: "stat", Path: name, Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return rErr("admin allow list is not a regular file")
	}
	if err := unix.Unlinkat(fd, name, 0); err != nil {
		return &os.PathError{Op: "unlink", Path: name, Err: err}
	}
	_ = unix.Fsync(fd)
	return nil
}

func (d *Daemon) verifyTransactionAdminAllowlistCandidate(state map[string]any) error {
	raw, present := state["admin_allowlist"]
	if !present || raw == nil {
		return nil
	}
	admin, ok := raw.(map[string]any)
	if !ok {
		return rErr("persisted admin allow list state is invalid")
	}
	expected := pyx.StrOr(admin["candidate_sha256"])
	if !isHex64(expected) {
		return rErr("persisted admin allow list candidate hash is invalid")
	}
	have, current, err := d.readAdminAllowlistRaw()
	if err != nil {
		return err
	}
	if !have || !compareDigest(sha256Hex(current), expected) {
		return rErr("admin allow list changed before confirmation")
	}
	return nil
}

func (d *Daemon) restoreTransactionAdminAllowlist(state map[string]any) error {
	raw, present := state["admin_allowlist"]
	if !present || raw == nil {
		return nil
	}
	admin, ok := raw.(map[string]any)
	if !ok {
		return rErr("persisted admin allow list state is invalid")
	}
	previousPresent := admin["previous_present"] == true
	encoded, ok := admin["previous_b64"].(string)
	if !ok {
		return rErr("persisted admin allow list snapshot is missing")
	}
	previous, err := b64decodeStrict(encoded)
	if err != nil {
		return err
	}
	if previousPresent {
		err = d.writeAdminAllowlistRaw(previous)
	} else {
		err = d.removeAdminAllowlist()
	}
	if err != nil {
		return err
	}
	have, current, err := d.readAdminAllowlistRaw()
	if err != nil {
		return err
	}
	if have != previousPresent || (previousPresent && !compareDigest(string(current), string(previous))) {
		return rErr("admin allow list rollback could not be verified")
	}
	return nil
}

// canonicalConfigGeoIPSelection is json.dumps(indent=2, sort_keys) + "\n".
func canonicalConfigGeoIPSelection(sel map[string]any) []byte {
	countries := pyx.List(sel["countries"])
	var b strings.Builder
	b.WriteString("{\n  \"access_filter_enabled\": ")
	if sel["access_filter_enabled"] == true {
		b.WriteString("true")
	} else {
		b.WriteString("false")
	}
	b.WriteString(",\n  \"countries\": ")
	if len(countries) == 0 {
		b.WriteString("[]")
	} else {
		b.WriteString("[\n")
		for i, c := range countries {
			b.WriteString("    \"" + pyx.Str(c) + "\"")
			if i < len(countries)-1 {
				b.WriteString(",")
			}
			b.WriteString("\n")
		}
		b.WriteString("  ]")
	}
	b.WriteString(",\n  \"version\": 1\n}\n")
	return []byte(b.String())
}

func (d *Daemon) openGeoIPDirectory() (int, error) {
	fd, err := openDirNoFollow(d.Opts.GeoIPDirectory)
	if err != nil {
		return -1, rErr("GeoIP runtime directory is unavailable or unsafe")
	}
	return fd, nil
}

func (d *Daemon) writeGeoIPSelectionRaw(raw []byte) error {
	if len(raw) == 0 || len(raw) > geoipMaxSelectionBytes || strings.Contains(string(raw), "\x00") {
		return vErr("invalid GeoIP selection snapshot")
	}
	if err := utf8Check(raw); err != nil {
		return err
	}
	fd, err := d.openGeoIPDirectory()
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	temporary := ".selection.json.transaction." + tokenHex(8)
	var dst unix.Stat_t
	if err := unix.Fstat(fd, &dst); err != nil {
		return err
	}
	owner, group, mode := int(dst.Uid), int(dst.Gid), uint32(0o644)
	var st unix.Stat_t
	if err := unix.Fstatat(fd, "selection.json", &st, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		if st.Mode&unix.S_IFMT != unix.S_IFREG {
			return rErr("GeoIP selection is not a regular file")
		}
		owner, group, mode = int(st.Uid), int(st.Gid), st.Mode&0o7777
	} else if err != unix.ENOENT {
		return &os.PathError{Op: "stat", Path: "selection.json", Err: err}
	}
	if err := writeTempAt(fd, temporary, raw, mode, owner, group, true); err != nil {
		return err
	}
	if err := unix.Renameat(fd, temporary, fd, "selection.json"); err != nil {
		_ = unix.Unlinkat(fd, temporary, 0)
		return &os.LinkError{Op: "rename", Old: temporary, New: "selection.json", Err: err}
	}
	_ = unix.Fsync(fd)
	return nil
}

func (d *Daemon) removeGeoIPSelection() error {
	fd, err := d.openGeoIPDirectory()
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstatat(fd, "selection.json", &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if err == unix.ENOENT {
			return nil
		}
		return &os.PathError{Op: "stat", Path: "selection.json", Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return rErr("GeoIP selection is not a regular file")
	}
	if err := unix.Unlinkat(fd, "selection.json", 0); err != nil {
		return &os.PathError{Op: "unlink", Path: "selection.json", Err: err}
	}
	_ = unix.Fsync(fd)
	return nil
}

func (d *Daemon) activeGeoIPReleaseName() string {
	if r := d.geoipCurrentRelease(); r != "" {
		return filepath.Base(r)
	}
	return ""
}

var releaseNameRE = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._-]{0,254}$`)

func within(root, p string) bool {
	return p == root || strings.HasPrefix(p, strings.TrimSuffix(root, "/")+"/")
}

func (d *Daemon) switchGeoIPRelease(name string) error {
	if name != "" {
		if name == "." || name == ".." || !releaseNameRE.MatchString(name) {
			return rErr("persisted GeoIP release name is invalid")
		}
		releases := d.geoipReleasesPath()
		fi, err := os.Lstat(releases)
		if err != nil {
			return rErr("GeoIP releases directory is unavailable")
		}
		if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
			return rErr("GeoIP releases directory is unsafe")
		}
		release := filepath.Join(releases, name)
		rfi, err := os.Lstat(release)
		if err != nil {
			return rErr("persisted GeoIP release is unavailable")
		}
		resolved, err1 := filepath.EvalSymlinks(release)
		root, err2 := filepath.EvalSymlinks(releases)
		if err1 != nil || err2 != nil || !within(root, resolved) {
			return rErr("persisted GeoIP release is unavailable")
		}
		if rfi.Mode()&os.ModeSymlink != 0 || !rfi.IsDir() {
			return rErr("persisted GeoIP release is unsafe")
		}
	}
	fd, err := d.openGeoIPDirectory()
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	temporary := ".current.transaction." + tokenHex(8)
	var st unix.Stat_t
	exists := true
	if err := unix.Fstatat(fd, "current", &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if err != unix.ENOENT {
			return &os.PathError{Op: "stat", Path: "current", Err: err}
		}
		exists = false
	}
	if exists && st.Mode&unix.S_IFMT != unix.S_IFLNK {
		return rErr("GeoIP current release pointer is not a symlink")
	}
	if name == "" {
		if exists {
			if err := unix.Unlinkat(fd, "current", 0); err != nil {
				return &os.PathError{Op: "unlink", Path: "current", Err: err}
			}
			_ = unix.Fsync(fd)
		}
		return nil
	}
	if err := unix.Symlinkat("releases/"+name, fd, temporary); err != nil {
		return &os.LinkError{Op: "symlink", Old: "releases/" + name, New: temporary, Err: err}
	}
	if err := unix.Renameat(fd, temporary, fd, "current"); err != nil {
		_ = unix.Unlinkat(fd, temporary, 0)
		return &os.LinkError{Op: "rename", Old: temporary, New: "current", Err: err}
	}
	_ = unix.Fsync(fd)
	return nil
}

func sameList(a, b any) bool {
	la, oka := a.([]any)
	lb, okb := b.([]any)
	if !oka || !okb || len(la) != len(lb) {
		return false
	}
	for i := range la {
		if pyx.Str(la[i]) != pyx.Str(lb[i]) || fmt.Sprintf("%T", la[i]) != fmt.Sprintf("%T", lb[i]) {
			return false
		}
	}
	return true
}

func (d *Daemon) geoipRuntimeFingerprint(expected map[string]any) (map[string]any, error) {
	sel, selRaw, err := d.geoipSelection()
	if err != nil {
		return nil, err
	}
	if !sameList(sel["countries"], expected["countries"]) || sel["access_filter_enabled"] != expected["access_filter_enabled"] {
		return nil, rErr("GeoIP runtime selection does not match the candidate")
	}
	release := d.geoipCurrentRelease()
	if release == "" {
		return nil, rErr("GeoIP runtime has no active release")
	}
	rs := d.readGeoIPState(release)
	dbPath, allowedPath := filepath.Join(release, "dbip-country-lite.mmdb"), filepath.Join(release, "allowed.geo")
	if n, ok := pyx.Int(rs["release_format_version"]); !ok || n != 1 || isBool(rs["release_format_version"]) ||
		!sameList(rs["countries"], expected["countries"]) || !sameBool(rs["access_filter_enabled"], expected["access_filter_enabled"]) ||
		!sha256Matches(dbPath, rs["database_sha256"]) || !sha256Matches(allowedPath, rs["allowed_sha256"]) {
		return nil, rErr("GeoIP active release does not match the candidate")
	}
	if pyx.Truthy(expected["access_filter_enabled"]) {
		fi, err := os.Stat(allowedPath)
		if err != nil {
			return nil, rErr("GeoIP candidate ACL is unavailable")
		}
		if fi.Size() <= 0 {
			return nil, rErr("GeoIP candidate ACL is empty")
		}
	}
	return map[string]any{
		"selection_sha256": sha256Hex(selRaw),
		"release":          filepath.Base(release),
		"database_sha256":  strings.ToLower(pyx.StrOr(rs["database_sha256"])),
		"allowed_sha256":   strings.ToLower(pyx.StrOr(rs["allowed_sha256"])),
	}, nil
}

// sameBool is `a is b` for JSON booleans.
func sameBool(a, b any) bool {
	ab, oka := a.(bool)
	bb, okb := b.(bool)
	return oka && okb && ab == bb
}

func (d *Daemon) verifyTransactionGeoIPCandidate(state map[string]any) error {
	raw, present := state["geoip"]
	if !present || raw == nil {
		return nil
	}
	geoip, ok := raw.(map[string]any)
	if !ok {
		return rErr("persisted GeoIP transaction data is invalid")
	}
	sel, ok1 := geoip["candidate_selection"].(map[string]any)
	expected, ok2 := geoip["candidate_fingerprint"].(map[string]any)
	if !ok1 || !ok2 {
		return rErr("persisted GeoIP candidate data is incomplete")
	}
	current, err := d.geoipRuntimeFingerprint(sel)
	if err != nil {
		return err
	}
	for _, key := range []string{"selection_sha256", "release", "database_sha256", "allowed_sha256"} {
		ev, cv := pyx.StrOr(expected[key]), pyx.StrOr(current[key])
		if ev == "" || !compareDigest(ev, cv) {
			return rErr("GeoIP runtime changed before confirmation")
		}
	}
	return nil
}

func (d *Daemon) restoreTransactionGeoIP(state map[string]any) error {
	raw, present := state["geoip"]
	if !present || raw == nil {
		return nil
	}
	geoip, ok := raw.(map[string]any)
	if !ok {
		return rErr("persisted GeoIP rollback data is invalid")
	}
	previousPresent, ok1 := geoip["previous_selection_present"].(bool)
	encoded, ok2 := geoip["previous_selection_b64"].(string)
	previousRelease, ok3 := geoip["previous_release"].(string)
	if !ok1 || !ok2 || !ok3 {
		return rErr("persisted GeoIP rollback data is incomplete")
	}
	previous, err := b64decodeStrict(encoded)
	if err != nil {
		return err
	}
	if previousPresent {
		err = d.writeGeoIPSelectionRaw(previous)
	} else {
		err = d.removeGeoIPSelection()
	}
	if err != nil {
		return err
	}
	if err := d.switchGeoIPRelease(previousRelease); err != nil {
		return err
	}
	_, now, err := d.geoipSelection()
	if err != nil {
		return err
	}
	if previousPresent {
		if !compareDigest(string(now), string(previous)) {
			return rErr("GeoIP selection rollback could not be verified")
		}
	} else if len(now) > 0 {
		return rErr("GeoIP selection rollback could not be verified")
	}
	if d.activeGeoIPReleaseName() != previousRelease {
		return rErr("GeoIP release rollback could not be verified")
	}
	return nil
}

func safeCheckStatus(item any) map[string]any {
	m, ok := item.(map[string]any)
	if !ok {
		return map[string]any{}
	}
	safe := map[string]any{}
	for _, key := range []string{"service", "domain", "path", "ok", "status", "attempt"} {
		v := m[key]
		switch v.(type) {
		case nil, string, bool, int, int64:
			safe[key] = v
		default:
			if n, ok := v.(interface{ String() string }); ok {
				if _, isInt := pyx.Int(v); isInt && !strings.ContainsAny(n.String(), ".eE") {
					safe[key] = v
				}
			}
		}
	}
	if pyx.Truthy(m["failure"]) {
		safe["failure"] = pyx.TruncRunes(pyx.Str(m["failure"]), 2000)
	}
	return safe
}

func anyList(v any) []any {
	switch x := v.(type) {
	case []any:
		return x
	case []map[string]any:
		return listOfMaps(x)
	}
	return nil
}

func (d *Daemon) sanitizedStatus(state map[string]any) map[string]any {
	if state == nil {
		return map[string]any{"ok": true, "state": "none", "pending": false}
	}
	name := pyx.StrOr(state["state"])
	if name == "" {
		name = "unknown"
	}
	deadline := pyx.Float(state["deadline_epoch"])
	remaining := 0
	var confirmBy, deadlineOut any
	if deadline != 0 {
		r := int(deadline - nowEpoch() + 0.999)
		if r > 0 {
			remaining = r
		}
		confirmBy = pyx.ISO(pyx.FromTimestamp(deadline, time.UTC))
		deadlineOut = deadline
	}
	files := []string{}
	if m, ok := state["candidate_source_sha256"].(map[string]any); ok {
		for k := range m {
			files = append(files, k)
		}
	}
	sort.Strings(files)
	checks := []any{}
	for _, it := range anyList(state["checks"]) {
		checks = append(checks, safeCheckStatus(it))
	}
	result := map[string]any{
		"ok":                name == "pending_confirmation" || name == "confirmed" || name == "rolled_back",
		"state":             name,
		"pending":           name == "pending_confirmation",
		"transaction_id":    pyx.StrOr(state["transaction_id"]),
		"candidate_sha256":  pyx.StrOr(state["candidate_sha256"]),
		"previous_sha256":   pyx.StrOr(state["previous_sha256"]),
		"created_at":        pyx.StrOr(state["created_at"]),
		"deadline_epoch":    deadlineOut,
		"deadline":          confirmBy,
		"confirm_by":        confirmBy,
		"remaining_seconds": remaining,
		"source_files":      stringsToAny(files),
		"checks":            checks,
		"failure":           pyx.TruncRunes(pyx.StrOr(state["failure"]), 4000),
		"rollback_reason":   pyx.TruncRunes(pyx.StrOr(state["rollback_reason"]), 500),
	}
	if rb, ok := state["rollback"].(map[string]any); ok {
		restored := []any{}
		for _, n := range anyList(rb["restored_sources"]) {
			if configSourceFilenames[pyx.Str(n)] {
				restored = append(restored, pyx.Str(n))
			}
		}
		rchecks := []any{}
		for _, it := range anyList(rb["checks"]) {
			rchecks = append(rchecks, safeCheckStatus(it))
		}
		result["rollback"] = map[string]any{
			"ok": pyx.Truthy(rb["ok"]), "reload_ok": pyx.Truthy(rb["reload_ok"]), "sources_ok": pyx.Truthy(rb["sources_ok"]),
			"geoip_ok": pyx.Truthy(pyx.Get(rb, "geoip_ok", true)), "admin_allowlist_ok": pyx.Truthy(pyx.Get(rb, "admin_allowlist_ok", true)),
			"restored_sources": restored, "failure": pyx.TruncRunes(pyx.StrOr(rb["failure"]), 4000), "checks": rchecks,
		}
	}
	return result
}

func transactionMatches(state map[string]any, id string) bool {
	expected := pyx.StrOr(state["transaction_id"])
	return expected != "" && id != "" && compareDigest(expected, id)
}

func (d *Daemon) rollbackConfigTransactionLocked(state map[string]any, reason string) (map[string]any, error) {
	state["state"] = "rolling_back"
	state["rollback_reason"] = reason
	state["failure"] = pyx.StrOr(state["failure"])
	if err := d.persistConfigTransaction(state); err != nil {
		return nil, err
	}
	sourcesOK, restored, sourceFailure := false, []string{}, ""
	func() {
		prev, ok := state["previous_sources"].(map[string]any)
		if !ok {
			sourceFailure = "config source rollback failed: persisted previous config sources are missing"
			return
		}
		decoded := map[string][]byte{}
		for name, enc := range prev {
			raw, err := b64decodeStrict(pyx.Str(enc))
			if err != nil {
				sourceFailure = "config source rollback failed: " + pyErr(err)
				return
			}
			decoded[name] = raw
		}
		r, err := d.restoreConfigSources(decoded)
		if err != nil {
			sourceFailure = "config source rollback failed: " + pyErr(err)
			return
		}
		restored, sourcesOK = r, true
	}()
	adminOK, adminFailure := false, ""
	if err := d.restoreTransactionAdminAllowlist(state); err != nil {
		adminFailure = "admin allow list rollback failed: " + pyErr(err)
	} else {
		adminOK = true
	}
	geoipOK, geoipFailure := false, ""
	if err := d.restoreTransactionGeoIP(state); err != nil {
		geoipFailure = "GeoIP rollback failed: " + pyErr(err)
	} else {
		geoipOK = true
	}
	var configResult map[string]any
	previousConfig, okC := state["previous_config_b64"].(string)
	checksRaw, okK := state["control_plane_checks"].([]any)
	if !okC || !okK {
		configResult = map[string]any{"ok": false, "reload_ok": false, "checks": []any{}, "failure": "persisted rollback data is incomplete"}
	} else {
		configResult = d.restoreGuardedConfig(previousConfig, checksFromState(checksRaw))
	}
	failures := []string{}
	for _, f := range []string{sourceFailure, adminFailure, geoipFailure, pyx.StrOr(configResult["failure"])} {
		if f != "" {
			failures = append(failures, f)
		}
	}
	rollbackOK := pyx.Truthy(configResult["ok"]) && sourcesOK && adminOK && geoipOK
	if rollbackOK {
		state["state"] = "rolled_back"
	} else {
		state["state"] = "rollback_failed"
	}
	checks := configResult["checks"]
	if !pyx.Truthy(checks) {
		checks = []any{}
	}
	state["rollback"] = map[string]any{"ok": rollbackOK, "reload_ok": pyx.Truthy(configResult["reload_ok"]),
		"sources_ok": sourcesOK, "admin_allowlist_ok": adminOK, "geoip_ok": geoipOK,
		"restored_sources": stringsToAny(restored), "checks": checks, "failure": strings.Join(failures, "; ")}
	if len(failures) > 0 {
		state["failure"] = strings.Join(failures, "; ")
	}
	if rollbackOK {
		for _, k := range []string{"previous_config_b64", "previous_sources", "admin_allowlist", "geoip"} {
			delete(state, k)
		}
	}
	if err := d.persistConfigTransaction(state); err != nil {
		return nil, err
	}
	return d.sanitizedStatus(state), nil
}

func (d *Daemon) expireConfigTransactionLocked() (map[string]any, error) {
	state, err := d.loadConfigTransaction()
	if err != nil || state == nil {
		return nil, err
	}
	if state["state"] == "pending_confirmation" {
		deadline := pyx.Float(state["deadline_epoch"])
		if deadline != 0 && nowEpoch() >= deadline {
			return d.rollbackConfigTransactionLocked(state, "confirmation timeout expired")
		}
	}
	return d.sanitizedStatus(state), nil
}

func (d *Daemon) configTransactionWatchdog(id string, deadline float64) {
	for {
		remaining := deadline - nowEpoch()
		if remaining > 0 {
			if remaining > 30 {
				remaining = 30
			}
			time.Sleep(time.Duration(remaining * float64(time.Second)))
			continue
		}
		d.guarded.Lock()
		func() {
			defer d.guarded.Unlock()
			state, err := d.loadConfigTransaction()
			if err == nil && state != nil && transactionMatches(state, id) && state["state"] == "pending_confirmation" &&
				nowEpoch() >= pyx.Float(state["deadline_epoch"]) {
				_, err = d.rollbackConfigTransactionLocked(state, "confirmation timeout expired")
			}
			if err != nil {
				log.Printf("HAProxy config transaction watchdog failed: %v", err)
			}
		}()
		return
	}
}

func (d *Daemon) scheduleWatchdog(id string, deadline float64) {
	go d.configTransactionWatchdog(id, deadline)
}

func (d *Daemon) beginConfigTransaction(cfgB64, checksB64, sourcesB64, timeoutText string) (map[string]any, error) {
	timeout, ok := pyIntBase10(timeoutText)
	if !ok {
		return nil, vErr("invalid config transaction timeout")
	}
	if timeout < configTransactionMinTimeout || timeout > int64(d.Opts.ConfigTransactionMaxTimeout) {
		return nil, vErr("config transaction timeout is outside the allowed range")
	}
	if !d.guarded.TryLock() {
		return nil, rErr("another guarded HAProxy configuration operation is running")
	}
	defer d.guarded.Unlock()
	geoipLocked := false
	defer func() {
		if geoipLocked {
			d.geoipOp.Unlock()
		}
	}()
	existing, err := d.loadConfigTransaction()
	if err != nil {
		return nil, err
	}
	if existing != nil {
		if existing["state"] == "pending_confirmation" {
			deadline := pyx.Float(existing["deadline_epoch"])
			if deadline != 0 && nowEpoch() >= deadline {
				if _, err := d.rollbackConfigTransactionLocked(existing, "confirmation timeout expired"); err != nil {
					return nil, err
				}
				if existing, err = d.loadConfigTransaction(); err != nil {
					return nil, err
				}
			}
		}
		if s, ok := existing["state"].(string); len(existing) > 0 && ok && activeStates[s] {
			return nil, rErr("another HAProxy config transaction is still active")
		}
	}
	checks, err := decodeControlPlaneChecks(checksB64)
	if err != nil {
		return nil, err
	}
	candidate, err := b64decodeStrict(cfgB64)
	if err != nil {
		return nil, err
	}
	if len(candidate) == 0 || len(candidate) > d.Opts.MaxConfigBytes {
		return nil, vErr("invalid HAProxy configuration size")
	}
	src, err := d.decodeConfigTransactionSources(sourcesB64)
	if err != nil {
		return nil, err
	}
	if err := d.verifyCandidateConfigSources(src.candidate); err != nil {
		return nil, err
	}
	var candidateAdminRaw, previousAdminRaw []byte
	previousAdminPresent := false
	if src.hasAdmin {
		if candidateAdminRaw, err = d.canonicalAdminAllowlistRaw(src.adminAllowlist); err != nil {
			return nil, err
		}
		if previousAdminPresent, previousAdminRaw, err = d.readAdminAllowlistRaw(); err != nil {
			return nil, err
		}
	}
	var previousSelection []byte
	previousSelectionPresent, previousRelease := false, ""
	if src.geoip != nil {
		if !d.geoipOp.TryLock() {
			return nil, rErr("another GeoIP operation is already running")
		}
		geoipLocked = true
		service, err := d.systemdProperties(geoipUpdateService, []string{"ActiveState", "SubState"})
		if err != nil {
			return nil, err
		}
		switch service["ActiveState"] {
		case "activating", "active", "reloading":
			return nil, rErr("another GeoIP operation is already running")
		}
		selState, selRaw, err := d.geoipSelection()
		if err != nil {
			return nil, err
		}
		previousSelection, previousSelectionPresent = selRaw, pyx.Truthy(selState["available"])
		previousRelease = d.activeGeoIPReleaseName()
	}
	previous, err := os.ReadFile(d.Opts.HAProxyCfgPath)
	if err != nil {
		return nil, err
	}
	if len(previous) == 0 || len(previous) > d.Opts.MaxConfigBytes {
		return nil, vErr("a valid current HAProxy configuration is required for rollback")
	}
	if err := validateGuardedControlPlaneTransition(previous, candidate, checks); err != nil {
		return nil, err
	}
	candidateSHA, previousSHA := sha256Hex(candidate), sha256Hex(previous)
	transactionID := tokenURLSafe(24)
	backupPath, err := d.createGuardedConfigBackup(previous, candidateSHA)
	if err != nil {
		return nil, err
	}
	sourceHashes, previousSources := map[string]any{}, map[string]any{}
	for name, content := range src.candidate {
		sourceHashes[name] = sha256Hex(content)
	}
	for name, content := range src.previous {
		previousSources[name] = b64(content)
	}
	checksAny := make([]any, len(checks))
	for i, c := range checks {
		checksAny[i] = c
	}
	state := map[string]any{"version": configTransactionVersion, "transaction_id": transactionID, "state": "prepared",
		"created_at": pyx.UTCNow(), "candidate_sha256": candidateSHA, "previous_sha256": previousSHA,
		"candidate_source_sha256": sourceHashes, "previous_config_b64": b64(previous), "previous_sources": previousSources,
		"control_plane_checks": checksAny, "checks": []any{}, "backup_path": backupPath, "deadline_epoch": 0,
		"failure": "", "rollback": nil}
	if src.hasAdmin {
		state["admin_allowlist"] = map[string]any{"candidate_sha256": sha256Hex(candidateAdminRaw),
			"previous_present": previousAdminPresent, "previous_b64": b64(previousAdminRaw)}
	}
	var candidateSelRaw []byte
	if src.geoip != nil {
		candidateSelRaw = canonicalConfigGeoIPSelection(src.geoip)
		state["geoip"] = map[string]any{"candidate_selection": src.geoip, "candidate_selection_sha256": sha256Hex(candidateSelRaw),
			"candidate_fingerprint": nil, "previous_selection_present": previousSelectionPresent,
			"previous_selection_b64": b64(previousSelection), "previous_release": previousRelease}
	}
	if err := d.persistConfigTransaction(state); err != nil {
		return nil, err
	}
	applyErr := func() (map[string]any, error) {
		if src.geoip != nil {
			if err := d.writeGeoIPSelectionRaw(candidateSelRaw); err != nil {
				return nil, err
			}
			ok, output := d.runGeoIPCommand([]string{d.Opts.GeoIPUpdateCommand, "--skip-reload", "--config-transaction-id", transactionID})
			state["geoip_update_output"] = output
			if !ok {
				if output == "" {
					output = "updater failed"
				}
				return nil, rErr("GeoIP candidate preparation failed: %s", output)
			}
			gs, ok := state["geoip"].(map[string]any)
			if !ok {
				return nil, rErr("GeoIP transaction state is unavailable")
			}
			fp, err := d.geoipRuntimeFingerprint(src.geoip)
			if err != nil {
				return nil, err
			}
			gs["candidate_fingerprint"] = fp
			if err := d.persistConfigTransaction(state); err != nil {
				return nil, err
			}
		}
		if src.hasAdmin {
			if err := d.writeAdminAllowlistRaw(candidateAdminRaw); err != nil {
				return nil, err
			}
		}
		if err := d.haproxyWriteConfigFromB64(cfgB64); err != nil {
			return nil, err
		}
		ok, output := d.cmdReload()
		state["reload_output"] = output
		if !ok {
			state["failure"] = "HAProxy reload failed: " + output
			r, err := d.rollbackConfigTransactionLocked(state, "candidate reload failed")
			return r, wrapDone(err)
		}
		cr := d.runControlPlaneChecks(checks)
		state["checks"] = listOfMaps(cr)
		if !allOK(cr) {
			state["failure"] = failedChecks(cr)
			r, err := d.rollbackConfigTransactionLocked(state, "candidate health check failed")
			return r, wrapDone(err)
		}
		return nil, nil
	}
	result, err := applyErr()
	if err != nil {
		if de, ok := err.(*doneErr); ok {
			err = de.err
		}
		state["failure"] = "guarded transaction apply failed: " + pyErr(err)
		return d.rollbackConfigTransactionLocked(state, "candidate apply failed")
	}
	if result != nil {
		return result, nil
	}
	deadline := nowEpoch() + float64(timeout)
	state["state"] = "pending_confirmation"
	state["deadline_epoch"] = deadline
	if err := d.persistConfigTransaction(state); err != nil {
		return nil, err
	}
	d.scheduleWatchdog(transactionID, deadline)
	return d.sanitizedStatus(state), nil
}

// doneErr marks a failure inside a rollback the apply already started; the
// Python except clause still catches it and starts another rollback.
type doneErr struct{ err error }

func (e *doneErr) Error() string { return e.err.Error() }

func wrapDone(err error) error {
	if err == nil {
		return nil
	}
	return &doneErr{err}
}

// pyIntBase10 is int(text, 10).
func pyIntBase10(text string) (int64, bool) {
	s := strings.ReplaceAll(pyStrip(text), "_", "")
	if s == "" || strings.Contains(pyStrip(text), "__") || strings.HasPrefix(pyStrip(text), "_") || strings.HasSuffix(pyStrip(text), "_") {
		return 0, false
	}
	neg := false
	if s[0] == '+' || s[0] == '-' {
		neg = s[0] == '-'
		s = s[1:]
	}
	if s == "" {
		return 0, false
	}
	var n int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int64(c-'0')
		if n > 1<<53 {
			n = 1 << 53
		}
	}
	if neg {
		n = -n
	}
	return n, true
}

func (d *Daemon) configTransactionStatus(id string) (map[string]any, error) {
	if !d.guarded.TryLock() {
		state, err := d.loadConfigTransaction()
		if err != nil {
			return nil, err
		}
		if id != "" && (state == nil || !transactionMatches(state, id)) {
			return nil, vErr("HAProxy config transaction id does not match")
		}
		result := d.sanitizedStatus(state)
		result["busy"] = true
		return result, nil
	}
	defer d.guarded.Unlock()
	statusResult, err := d.expireConfigTransactionLocked()
	if err != nil {
		return nil, err
	}
	state, err := d.loadConfigTransaction()
	if err != nil {
		return nil, err
	}
	if id != "" && (state == nil || !transactionMatches(state, id)) {
		return nil, vErr("HAProxy config transaction id does not match")
	}
	if len(statusResult) > 0 {
		return statusResult, nil
	}
	return d.sanitizedStatus(state), nil
}

func (d *Daemon) configTransactionBusyResult(id, action, candidateSHA string) (map[string]any, error) {
	state, err := d.loadConfigTransaction()
	if err != nil {
		return nil, err
	}
	if state == nil || !transactionMatches(state, id) {
		return nil, vErr("HAProxy config transaction id does not match")
	}
	result := d.sanitizedStatus(state)
	if action == "confirmation" {
		expected := pyx.StrOr(state["candidate_sha256"])
		if !isHex64(candidateSHA) || !compareDigest(expected, candidateSHA) {
			return nil, vErr("HAProxy config transaction candidate hash does not match")
		}
		if state["state"] == "confirmed" {
			return result, nil
		}
	} else if action == "rollback" && state["state"] == "rolled_back" {
		return result, nil
	}
	name := pyx.StrOr(state["state"])
	retryable := name == "prepared" || name == "pending_confirmation"
	if action != "confirmation" {
		retryable = retryable || name == "rolling_back" || name == "rollback_failed"
	}
	msg := "Another HAProxy configuration operation is running; retry " + action + " shortly"
	if !retryable {
		shown := name
		if shown == "" {
			shown = "unknown"
		}
		msg = "HAProxy configuration transaction cannot perform " + action + " while it is " + shown
	}
	result["ok"], result["busy"], result["conflict"], result["retryable"], result["error"] = false, true, true, retryable, msg
	return result, nil
}

func (d *Daemon) confirmConfigTransaction(id, candidateSHA string) (map[string]any, error) {
	if !d.guarded.TryLock() {
		return d.configTransactionBusyResult(id, "confirmation", candidateSHA)
	}
	defer d.guarded.Unlock()
	state, err := d.loadConfigTransaction()
	if err != nil {
		return nil, err
	}
	if state == nil || !transactionMatches(state, id) {
		return nil, vErr("HAProxy config transaction id does not match")
	}
	expected := pyx.StrOr(state["candidate_sha256"])
	if !isHex64(candidateSHA) || !compareDigest(expected, candidateSHA) {
		return nil, vErr("HAProxy config transaction candidate hash does not match")
	}
	if state["state"] == "confirmed" {
		return d.sanitizedStatus(state), nil
	}
	if state["state"] != "pending_confirmation" {
		return nil, rErr("HAProxy config transaction is not awaiting confirmation")
	}
	deadline := pyx.Float(state["deadline_epoch"])
	if deadline == 0 || nowEpoch() >= deadline {
		if _, err := d.rollbackConfigTransactionLocked(state, "confirmation timeout expired"); err != nil {
			return nil, err
		}
		return nil, rErr("HAProxy config transaction confirmation arrived too late")
	}
	if err := d.verifyLiveTransactionCandidate(state); err != nil {
		state["failure"] = "pending candidate verification failed: " + pyErr(err)
		rb, rerr := d.rollbackConfigTransactionLocked(state, "pending candidate changed before confirmation")
		if rerr != nil {
			return nil, rerr
		}
		outcome := "automatic rollback failed"
		if rb["state"] == "rolled_back" {
			outcome = "the previous configuration was restored"
		}
		return nil, rErr("HAProxy config transaction candidate changed; %s", outcome)
	}
	state["state"] = "confirmed"
	state["confirmed_at"] = pyx.UTCNow()
	state["history_version"] = d.recordConfigVersion(state)
	for _, k := range []string{"previous_config_b64", "previous_sources", "admin_allowlist", "geoip"} {
		delete(state, k)
	}
	if err := d.persistConfigTransaction(state); err != nil {
		return nil, err
	}
	return d.sanitizedStatus(state), nil
}

func (d *Daemon) rollbackConfigTransaction(id string) (map[string]any, error) {
	if !d.guarded.TryLock() {
		return d.configTransactionBusyResult(id, "rollback", "")
	}
	defer d.guarded.Unlock()
	state, err := d.loadConfigTransaction()
	if err != nil {
		return nil, err
	}
	if state == nil || !transactionMatches(state, id) {
		return nil, vErr("HAProxy config transaction id does not match")
	}
	if state["state"] == "rolled_back" {
		return d.sanitizedStatus(state), nil
	}
	switch state["state"] {
	case "prepared", "pending_confirmation", "rolling_back", "rollback_failed":
	default:
		return nil, rErr("HAProxy config transaction cannot be rolled back")
	}
	return d.rollbackConfigTransactionLocked(state, "manual rollback requested")
}

func (d *Daemon) recoverConfigTransaction() error {
	d.guarded.Lock()
	defer d.guarded.Unlock()
	state, err := d.loadConfigTransaction()
	if err != nil || state == nil {
		return err
	}
	switch state["state"] {
	case "prepared", "rolling_back", "rollback_failed":
		_, err = d.rollbackConfigTransactionLocked(state, "controld restart recovery")
	case "pending_confirmation":
		deadline := pyx.Float(state["deadline_epoch"])
		if deadline == 0 || nowEpoch() >= deadline {
			_, err = d.rollbackConfigTransactionLocked(state, "confirmation timeout expired during restart")
		} else {
			d.scheduleWatchdog(pyx.Str(state["transaction_id"]), deadline)
		}
	}
	return err
}

// ---------------------------------------------------------------------------
// GeoIP helpers
// ---------------------------------------------------------------------------

func decodeGeoIPPayload(encoded string, expected ...string) (map[string]any, error) {
	raw, err := b64decodeStrict(encoded)
	if err != nil {
		return nil, vErr("invalid GeoIP request encoding")
	}
	if len(raw) == 0 || len(raw) > geoipMaxSelectionBytes {
		return nil, vErr("invalid GeoIP request size")
	}
	if utf8Check(raw) != nil {
		return nil, vErr("invalid GeoIP request JSON")
	}
	v, err := pyx.Decode(raw)
	if err != nil {
		return nil, vErr("invalid GeoIP request JSON")
	}
	m, ok := v.(map[string]any)
	if !ok || len(m) != len(expected) {
		return nil, vErr("invalid GeoIP request fields")
	}
	for _, k := range expected {
		if _, ok := m[k]; !ok {
			return nil, vErr("invalid GeoIP request fields")
		}
	}
	return m, nil
}

func (d *Daemon) geoipSelection() (map[string]any, []byte, error) {
	path := d.geoipSelectionPath()
	fi, err := os.Lstat(path)
	if err != nil {
		if isNotExist(err) {
			return map[string]any{"countries": []any{}, "access_filter_enabled": false,
				"revision": sha256Hex(nil), "available": false}, []byte{}, nil
		}
		return nil, nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		return nil, nil, rErr("GeoIP selection is not a regular file")
	}
	if fi.Size() <= 0 || fi.Size() > geoipMaxSelectionBytes {
		return nil, nil, rErr("GeoIP selection has an invalid size")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	if utf8Check(raw) != nil {
		return nil, nil, rErr("GeoIP selection is invalid")
	}
	v, err := pyx.Decode(raw)
	if err != nil {
		return nil, nil, rErr("GeoIP selection is invalid")
	}
	value, ok := v.(map[string]any)
	_, hv := value["version"]
	_, hc := value["countries"]
	_, he := value["access_filter_enabled"]
	if !ok || len(value) != 3 || !hv || !hc || !he {
		return nil, nil, rErr("GeoIP selection has an invalid format")
	}
	countries, okC := value["countries"].([]any)
	enabled, okE := value["access_filter_enabled"].(bool)
	if n, okV := pyx.Int(value["version"]); !okV || n != 1 || !okC || !okE {
		return nil, nil, rErr("GeoIP selection has an invalid format")
	}
	list := []string{}
	for _, c := range countries {
		s, ok := c.(string)
		if !ok || !isCountryCode(s) {
			return nil, nil, rErr("GeoIP selection contains an invalid country code")
		}
		list = append(list, s)
	}
	if !isSortedUnique(list) {
		return nil, nil, rErr("GeoIP selection countries are not canonical")
	}
	return map[string]any{"available": true, "countries": stringsToAny(list), "access_filter_enabled": enabled,
		"revision": sha256Hex(raw)}, raw, nil
}

func (d *Daemon) geoipCurrentRelease() string {
	target, err := filepath.EvalSymlinks(filepath.Join(d.Opts.GeoIPDirectory, "current"))
	if err != nil {
		return ""
	}
	releases, err := filepath.EvalSymlinks(d.geoipReleasesPath())
	if err != nil || !within(releases, target) {
		return ""
	}
	fi, err := os.Lstat(target)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return ""
	}
	return target
}

func (d *Daemon) readGeoIPState(release string) map[string]any {
	path := filepath.Join(release, "state.json")
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() || fi.Size() <= 0 || fi.Size() > geoipMaxStateBytes {
		return map[string]any{}
	}
	raw, err := os.ReadFile(path)
	if err != nil || utf8Check(raw) != nil {
		return map[string]any{}
	}
	v, err := pyx.Decode(raw)
	if err != nil {
		return map[string]any{}
	}
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func sha256Matches(path string, expected any) bool {
	text := strings.ToLower(pyx.StrOr(expected))
	if !isHex64(text) {
		return false
	}
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		return false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return compareDigest(sha256Hex(raw), text)
}

func (d *Daemon) systemdProperties(unit string, props []string) (map[string]string, error) {
	if unit != geoipUpdateService && unit != geoipUpdateTimer {
		return nil, vErr("unsupported systemd unit")
	}
	argv := []string{"/usr/bin/systemctl", "show", unit}
	for _, p := range props {
		argv = append(argv, "--property="+p)
	}
	res, err := execRaw(argv, nil, 15*time.Second)
	if err != nil {
		return map[string]string{"error": pyErr(err)}, nil
	}
	if res.rc != 0 {
		detail := res.stderr
		if detail == "" {
			detail = res.stdout
		}
		if detail == "" {
			detail = "systemctl failed"
		}
		return map[string]string{"error": pyx.TruncRunes(pyStrip(detail), 2000)}, nil
	}
	want := map[string]bool{}
	for _, p := range props {
		want[p] = true
	}
	out := map[string]string{}
	for _, line := range pySplitlines(res.stdout) {
		i := strings.Index(line, "=")
		if i < 0 {
			continue
		}
		if want[line[:i]] {
			out[line[:i]] = line[i+1:]
		}
	}
	return out, nil
}

func (d *Daemon) geoipJournalTail(lines int) []any {
	if lines < 1 {
		lines = 1
	}
	if lines > 100 {
		lines = 100
	}
	res, err := execRaw([]string{"/usr/bin/journalctl", "-u", geoipUpdateService, "--no-pager", "-q", "-o", "short-iso",
		"--lines", itoa(lines)}, nil, 15*time.Second)
	if err != nil {
		return []any{"journal unavailable: " + pyErr(err)}
	}
	if res.rc != 0 {
		detail := res.stderr
		if detail == "" {
			detail = res.stdout
		}
		if detail == "" {
			detail = "journalctl failed"
		}
		return []any{"journal unavailable: " + pyx.TruncRunes(pyStrip(detail), 1000)}
	}
	all := pySplitlines(res.stdout)
	if len(all) > lines {
		all = all[len(all)-lines:]
	}
	out := make([]any, len(all))
	for i, l := range all {
		out[i] = pyx.TruncRunes(l, 4000)
	}
	return out
}
