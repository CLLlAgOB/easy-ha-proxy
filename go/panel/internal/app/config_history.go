package app

// Ports of services_config_history.py and routes_config_history.py.

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"easy-ha-proxy/panel/shared/pyyaml"
)

const (
	historyCurrent    = "current"
	historyApplied    = "applied"
	historyMaxVersion = 200
	keepSetAside      = 5
)

// HistoryUnavailable is services_config_history.HistoryUnavailable.
type HistoryUnavailable struct{ Msg string }

func (e *HistoryUnavailable) Error() string { return e.Msg }

// RestoreError is services_config_history.RestoreError.
type RestoreError struct {
	Msg  string
	Code string
}

func (e *RestoreError) Error() string { return e.Msg }

func historyRequest(command string) (*Map, error) {
	res := controldJSONRequest(command, 20)
	if !truthy(res.Value("ok")) {
		return nil, &HistoryUnavailable{pyStr(orValue(res.Value("failure"), res.Value("error"), "history unavailable"))}
	}
	return res, nil
}

func listVersions(limit int64) ([]any, error) {
	if limit == 0 {
		limit = 50
	}
	limit = max(1, min(limit, historyMaxVersion))
	res, err := historyRequest(fmt.Sprintf("config-versions %d", limit))
	if err != nil {
		return nil, err
	}
	list, _ := asList(orValue(res.Value("versions"), []any{}))
	return append([]any{}, list...), nil
}

func decodeSources(sources any) map[string]string {
	out := map[string]string{}
	m, ok := asMap(sources)
	if !ok {
		return out
	}
	m.Each(func(k, v any) {
		name := pyStr(k)
		valid := false
		for _, n := range configSourceOrder {
			if n == name {
				valid = true
			}
		}
		if !valid {
			return
		}
		raw, err := pyB64DecodeStrict(pyStr(v))
		if err != nil {
			out[name] = ""
			return
		}
		out[name] = strings.ToValidUTF8(string(raw), "�")
	})
	return out
}

func versionSources(id string) (*Map, map[string]string, error) {
	res, err := historyRequest("config-version " + id)
	if err != nil {
		return nil, nil, err
	}
	payload, ok := asMap(orValue(res.Value("version"), newMap()))
	if !ok {
		payload = newMap()
	}
	return payload, decodeSources(orValue(payload.Value("sources"), newMap())), nil
}

func bundleText(b Bundle) map[string]string {
	out := map[string]string{}
	for k, v := range b {
		out[k] = strings.ToValidUTF8(string(v), "�")
	}
	return out
}

func currentSources() (map[string]string, error) {
	b, err := readConfigSourceBundle(currentConfigSourcePaths(), "current")
	if err != nil {
		return nil, err
	}
	return bundleText(b), nil
}

func appliedSources() (map[string]string, error) {
	b, err := readConfigSourceBundle(appliedConfigSourcePaths(), "applied")
	if err != nil {
		return nil, &ValueError{"Nothing has been applied on this gateway yet"}
	}
	return bundleText(b), nil
}

func sameSources(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}

func unappliedChanges() any {
	cur, err := currentSources()
	if err != nil {
		return nil
	}
	app, err := appliedSources()
	if err != nil {
		return nil
	}
	return !sameSources(cur, app)
}

func historyLoad(text string) *Map {
	v, err := pyyaml.Load([]byte(text))
	if err != nil || !truthy(v) {
		return newMap()
	}
	if m, ok := asMap(v); ok {
		return m
	}
	return newMap()
}

func historyEntries(data *Map, keys []string) (*Map, []string) {
	var items []any
	for _, k := range keys {
		if l, ok := asList(data.Value(k)); ok {
			items = l
			break
		}
	}
	out := pyyaml.NewMap()
	for i, it := range items {
		m, ok := asMap(it)
		if !ok {
			continue
		}
		out.Set(pyStr(orValue(m.Value("name"), m.Value("domain"), m.Value("id"), int64(i))), m)
	}
	var names []string
	for _, k := range out.Keys() {
		names = append(names, k.(string))
	}
	return out, names
}

func shortRepr(v any) string {
	t := pyStr(v)
	if pyLen(t) <= 60 {
		return t
	}
	return truncRunes(t, 59) + "…"
}

func fieldChanges(before, after *Map) []any {
	keys := map[string]any{}
	for _, k := range before.Keys() {
		keys[pyStr(k)] = k
	}
	for _, k := range after.Keys() {
		keys[pyStr(k)] = k
	}
	names := make([]string, 0, len(keys))
	for n := range keys {
		names = append(names, n)
	}
	sort.Strings(names)
	out := []any{}
	for _, n := range names {
		k := keys[n]
		old, nw := before.Value(k), after.Value(k)
		if pyEqual(old, nw) {
			continue
		}
		_, inB := before.Get(k)
		_, inA := after.Get(k)
		switch {
		case !inB:
			out = append(out, fmt.Sprintf("+%s: %s", n, shortRepr(nw)))
		case !inA:
			out = append(out, "-"+n)
		default:
			out = append(out, fmt.Sprintf("%s: %s → %s", n, shortRepr(old), shortRepr(nw)))
		}
	}
	return out
}

func compareCollection(beforeText, afterText string, keys []string, label string) []any {
	before, _ := historyEntries(historyLoad(beforeText), keys)
	after, _ := historyEntries(historyLoad(afterText), keys)
	names := map[string]bool{}
	for _, k := range before.Keys() {
		names[k.(string)] = true
	}
	for _, k := range after.Keys() {
		names[k.(string)] = true
	}
	out := []any{}
	for _, n := range sortedKeys(names) {
		b, inB := before.Get(n)
		a, inA := after.Get(n)
		switch {
		case !inB:
			out = append(out, newMap("kind", label, "name", n, "change", "added"))
		case !inA:
			out = append(out, newMap("kind", label, "name", n, "change", "removed"))
		default:
			if f := fieldChanges(b.(*Map), a.(*Map)); len(f) > 0 {
				out = append(out, newMap("kind", label, "name", n, "change", "modified", "fields", f))
			}
		}
	}
	return out
}

func compareSources(before, after map[string]string) *Map {
	changes := []any{}
	changes = append(changes, compareCollection(before["websites.yml"], after["websites.yml"], []string{"sites"}, "site")...)
	changes = append(changes, compareCollection(before["tcp.yml"], after["tcp.yml"], []string{"tcp_proxies", "tcp"}, "tcp")...)
	if f := fieldChanges(historyLoad(before["vars.yml"]), historyLoad(after["vars.yml"])); len(f) > 0 {
		changes = append(changes, newMap("kind", "variable", "name", "", "change", "modified", "fields", f))
	}
	var files []string
	for _, n := range configSourceOrder {
		if before[n] != after[n] {
			files = append(files, n)
		}
	}
	sort.Strings(files)
	return newMap("changes", changes, "identical", len(changes) == 0, "files_changed", strList(files...))
}

func historyDiff(left, right string) (*Map, error) {
	load := func(id string) (*Map, map[string]string, error) {
		switch id {
		case historyCurrent:
			s, err := currentSources()
			return newMap("id", historyCurrent), s, err
		case historyApplied:
			s, err := appliedSources()
			return newMap("id", historyApplied), s, err
		}
		return versionSources(id)
	}
	lm, ls, err := load(left)
	if err != nil {
		return nil, err
	}
	rm, rs, err := load(right)
	if err != nil {
		return nil, err
	}
	p := compareSources(ls, rs)
	p.Set("left", lm)
	p.Set("right", rm)
	return p, nil
}

func stageHistorySource(path string, data []byte, mode os.FileMode) (string, error) {
	file, err := os.CreateTemp(filepath.Dir(path), ".restore-*")
	if err != nil {
		return "", err
	}
	name := file.Name()
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(name)
		return "", err
	}
	if err := errors.Join(file.Chmod(mode), file.Sync(), file.Close()); err != nil {
		_ = os.Remove(name)
		return "", err
	}
	return name, nil
}

func writeSources(sources map[string]string) error {
	type staged struct{ target, next, previous string }
	var files []staged
	defer func() {
		for _, file := range files {
			_ = os.Remove(file.next)
			if file.previous != "" {
				_ = os.Remove(file.previous)
			}
		}
	}()
	for _, np := range currentConfigSourcePaths() {
		mode := os.FileMode(0o600)
		files = append(files, staged{target: np.path})
		file := &files[len(files)-1]
		info, err := os.Lstat(np.path)
		if err == nil {
			if !info.Mode().IsRegular() {
				return fmt.Errorf("expected a regular managed source: %s", np.name)
			}
			mode = info.Mode().Perm()
			original, err := os.ReadFile(np.path)
			if err != nil {
				return err
			}
			file.previous, err = stageHistorySource(np.path, original, mode)
			if err != nil {
				return err
			}
		} else if !os.IsNotExist(err) {
			return err
		}
		file.next, err = stageHistorySource(np.path, []byte(sources[np.name]), mode)
		if err != nil {
			return err
		}
	}
	for i, file := range files {
		if err := os.Rename(file.next, file.target); err != nil {
			for j := i - 1; j >= 0; j-- {
				replaced := &files[j]
				if replaced.previous == "" {
					err = errors.Join(err, os.Remove(replaced.target))
				} else if restoreErr := os.Rename(replaced.previous, replaced.target); restoreErr != nil {
					err = errors.Join(err, fmt.Errorf("restore %s from %s: %w", replaced.target, replaced.previous, restoreErr))
					replaced.previous = "" // Keep the recovery copy on disk.
				}
			}
			return err
		}
	}
	return nil
}

func setAside(sources map[string]string) (string, error) {
	root := filepath.Join(BaseDir, "backups")
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", err
	}
	folder, err := os.MkdirTemp(root, "before-restore-"+time.Now().Format("20060102150405")+"-")
	if err != nil {
		return "", err
	}
	for name, data := range sources {
		if err := os.WriteFile(filepath.Join(folder, name), []byte(data), 0o600); err != nil {
			return "", err
		}
	}
	matches, _ := filepath.Glob(filepath.Join(filepath.Dir(folder), "before-restore-*"))
	var dirs []string
	for _, m := range matches {
		if info, err := os.Stat(m); err == nil && info.IsDir() {
			dirs = append(dirs, m)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(dirs)))
	for i := keepSetAside; i < len(dirs); i++ {
		entries, _ := os.ReadDir(dirs[i])
		for _, e := range entries {
			os.Remove(filepath.Join(dirs[i], e.Name()))
		}
		os.Remove(dirs[i])
	}
	return "backups/" + filepath.Base(folder), nil
}

func historyRestore(op *Op, id, clientIP string) (*Map, error) {
	meta, sources, err := versionSources(id)
	if err != nil {
		return nil, err
	}
	var missing []string
	for _, n := range configSourceOrder {
		if _, ok := sources[n]; !ok {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		return nil, &RestoreError{"This version does not contain " + strings.Join(missing, ", "), "version_incomplete"}
	}
	release, err := op.LockAll("websites", "tcp", "vars")
	if err != nil {
		return nil, err
	}
	defer release()
	original, err := currentSources()
	if err != nil {
		return nil, err
	}
	unapplied := true
	if app, err := appliedSources(); err == nil {
		unapplied = !sameSources(original, app)
	}
	aside := ""
	if unapplied {
		if aside, err = setAside(original); err != nil {
			return nil, &RestoreError{"The unapplied changes could not be set aside, so nothing was restored: " + pyOSError(err), "set_aside_failed"}
		}
	}
	if err := writeSources(sources); err != nil {
		return nil, &RestoreError{"The version could not be written, so nothing was restored: " + pyOSError(err), "restore_write_failed"}
	}
	result, err := applyRestored(op, original, clientIP)
	if err != nil {
		return nil, err
	}
	result.Set("restored_version", orValue(meta.Value("id"), id))
	if aside != "" {
		result.Set("set_aside", aside)
	}
	return result, nil
}

func applyRestored(op *Op, original map[string]string, clientIP string) (*Map, error) {
	res, err := func() (*Map, error) {
		cfg, err := RenderHAProxyCfg(nil)
		if err != nil {
			return nil, err
		}
		cv, err := loadYAML(ConfigYAML)
		if err != nil {
			return nil, err
		}
		if err := ValidateAdminAccessForClient(cv, clientIP); err != nil {
			return nil, err
		}
		pre, err := PreflightCfgConfirmation(cfg, false, "")
		if err != nil {
			return nil, err
		}
		if !truthy(pre.Value("ok")) {
			return nil, &RestoreError{pyStr(orValue(pre.Value("error"), "the restored configuration was refused")), pyStr(orValue(pre.Value("error_code"), "restore_refused"))}
		}
		started, err := BeginCfgConfirmation(op, cfg, 0, false, "")
		if err == nil && !truthy(started.Value("ok")) {
			err = &RestoreError{pyStr(orValue(started.Value("error"), "the restored configuration was refused")), pyStr(orValue(started.Value("error_code"), "restore_refused"))}
		}
		return started, err
	}()
	if err != nil {
		if werr := writeSources(original); werr != nil {
			log.Printf("could not restore the managed sources after a failed restore: %v", werr)
			return nil, &RestoreError{"The restore failed and the managed configuration could not be returned to its previous state; inspect it on the server", "restore_dirty"}
		}
		var re *RestoreError
		if errors.As(err, &re) {
			return nil, re
		}
		return nil, &RestoreError{err.Error(), "restore_failed"}
	}
	return res, nil
}

func historyUnavailablePayload(err error) *Map {
	log.Printf("configuration history unavailable: %v", err)
	return newMap("ok", false, "unavailable", true, "error", err.Error())
}

func (c *Ctx) clientIP() string {
	forwarded := strings.Split(c.R.Header.Get("X-Forwarded-For"), ",")
	if ip := strings.TrimSpace(forwarded[0]); ip != "" {
		return ip
	}
	return remoteHost(c.R.RemoteAddr)
}

func (a *App) registerConfigHistoryRoutes() {
	a.Handle("routes.api_config_versions", func(c *Ctx) error {
		if !c.Superadmin() {
			return c.JSON(403, newMap("ok", false, "error", "superadmin required"))
		}
		limit := int64(50)
		if v := c.Query("limit"); v != nil {
			if n, err := strconv.ParseInt(strings.TrimSpace(v.(string)), 10, 64); err == nil {
				limit = n
			}
		}
		versions, err := listVersions(limit)
		if err != nil {
			return c.JSON(503, historyUnavailablePayload(err))
		}
		return c.JSON(200, newMap("ok", true, "versions", versions, "unapplied", unappliedChanges()))
	})
	a.Handle("routes.api_config_version_diff", func(c *Ctx) error {
		if !c.Superadmin() {
			return c.JSON(403, newMap("ok", false, "error", "superadmin required"))
		}
		left := strings.TrimSpace(c.QueryStr("left"))
		right := strings.TrimSpace(orStr(orValue(c.Query("right"), historyApplied)))
		if left == "" {
			return c.JSON(400, newMap("ok", false, "error", "left version is required"))
		}
		payload, err := historyDiff(left, right)
		if err != nil {
			if _, unavailable := err.(*HistoryUnavailable); unavailable {
				return c.JSON(503, historyUnavailablePayload(err))
			}
			return c.JSON(400, newMap("ok", false, "error", err.Error()))
		}
		payload.Set("ok", true)
		return c.JSON(200, payload)
	})
	a.Handle("routes.api_config_version_restore", func(c *Ctx) error {
		payload := c.silentJSONMap()
		id := orStr(get(payload, "version"))
		if !c.Superadmin() {
			c.RecordRequest("config.restore", AuditEntry{ObjectType: "config_version", ObjectID: id, Result: auditResultDenied, Detail: "superadmin required"})
			return c.JSON(403, newMap("ok", false, "error", "superadmin required"))
		}
		if id == "" {
			return c.JSON(400, newMap("ok", false, "error", "version is required"))
		}
		result, err := historyRestore(c.op(), id, c.clientIP())
		if err != nil {
			c.RecordRequest("config.restore", AuditEntry{ObjectType: "config_version", ObjectID: id, Result: auditResultFailure, Detail: err.Error()})
			var re *RestoreError
			if errors.As(err, &re) {
				return c.JSON(400, newMap("ok", false, "error", re.Msg, "error_code", re.Code))
			}
			if _, unavailable := err.(*HistoryUnavailable); unavailable {
				return c.JSON(503, historyUnavailablePayload(err))
			}
			return err
		}
		c.RecordRequest("config.restore", AuditEntry{ObjectType: "config_version", ObjectID: id, Summary: "restore started, awaiting confirmation", Detail: strOrEmpty(result.Value("state"))})
		return c.JSON(200, result)
	})
}
