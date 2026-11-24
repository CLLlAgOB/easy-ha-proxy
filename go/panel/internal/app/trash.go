package app

// Port of trash.py: deleted sites, TCP proxies and UDP forwards.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"easy-ha-proxy/panel/internal/pyyaml"
)

var (
	trashIDRe   = regexp.MustCompile(`^([0-9]{1,12})-[a-f0-9]{12}$`)
	trashKinds  = map[string]bool{"site": true, "tcp": true, "udp": true}
	trashClaim  = ".restoring"
	trashPend   = ".pending"
	claimSecs   = 600.0
	pendingSecs = 3600.0
)

const trashSettings = "settings.json"

// TrashError is trash.TrashError.
type TrashError struct{ Msg string }

func (e *TrashError) Error() string { return e.Msg }

// Hooks the access-portal and entry ports fill in.
var (
	accessPortalForget  = func(name, page string) error { return nil }
	accessPortalRestore = func(name, stored string) (bool, error) { return false, nil }
	trashRestorers      = map[string]func(op *Op, entry, extra *Map) (bool, string, *Map){}
)

func trashRoot() string {
	if v := os.Getenv("HAPROXY_ADMIN_TRASH_DIR"); v != "" {
		return v
	}
	return "/var/lib/haproxy-admin/trash"
}

func trashDirectory() (string, error) {
	dir := trashRoot()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	info, err := os.Lstat(dir)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", &TrashError{"Invalid trash directory"}
	}
	return dir, nil
}

func flockFile(path string) (func(), error) {
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	return func() { syscall.Close(fd) }, nil
}

// TrashSettingsLock is settings_lock.
func TrashSettingsLock() (func(), error) {
	dir, err := trashDirectory()
	if err != nil {
		return nil, err
	}
	return flockFile(filepath.Join(dir, ".settings.lock"))
}

func trashLocked() (string, func(), error) {
	dir, err := trashDirectory()
	if err != nil {
		return "", nil, err
	}
	release, err := flockFile(filepath.Join(dir, ".lock"))
	if err != nil {
		return "", nil, err
	}
	return dir, release, nil
}

func trashPath(dir, id string) (string, error) {
	if !trashIDRe.MatchString(id) {
		return "", &TrashError{"Unknown trash item"}
	}
	return filepath.Join(dir, id+".json"), nil
}

func trashPendingPath(dir, id string) (string, error) {
	p, err := trashPath(dir, id)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(p, ".json") + trashPend, nil
}

func trashRead(path string) *Map {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	raw, err := readAll(f)
	if err != nil {
		return nil
	}
	v, err := pyyaml.JSONLoads(raw)
	if err != nil {
		return nil
	}
	m, ok := asMap(v)
	if !ok || !trashKinds[strOrEmptyKind(m.Value("kind"))] {
		return nil
	}
	if _, ok := asMap(m.Value("entry")); !ok {
		return nil
	}
	return m
}

func strOrEmptyKind(v any) string {
	s, _ := v.(string)
	return s
}

func readAll(f *os.File) ([]byte, error) {
	var out []byte
	buf := make([]byte, 32*1024)
	for {
		n, err := f.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil {
			if err.Error() == "EOF" {
				return out, nil
			}
			return out, err
		}
	}
}

func trashWrite(path string, value *Map) error {
	text, err := PyJSON(value, JSONOpts{Indent: 1})
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.WriteString(text); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	f.Close()
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// NormalizeKeepDays is normalize_keep_days.
func NormalizeKeepDays(value any) (int64, error) {
	days, err := parsePyIntString(pyStr(value))
	if err != nil {
		return 0, &TrashError{"The term must be a whole number of days"}
	}
	if days < 0 || days > trashMaxKeepDays {
		return 0, &TrashError{"The term must be between 1 and 3650 days, or 0 to keep items until the trash is emptied"}
	}
	return days, nil
}

// TrashKeepDays is keep_days.
func TrashKeepDays() int64 {
	path := filepath.Join(trashRoot(), trashSettings)
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return 0
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	raw, err := readAll(f)
	if err != nil {
		return 0
	}
	v, err := pyyaml.JSONLoads(raw)
	if err != nil {
		return 0
	}
	m, ok := asMap(v)
	if !ok {
		return 0
	}
	kd, has := m.Get("keep_days")
	if !has {
		kd = int64(0)
	}
	days, err := NormalizeKeepDays(kd)
	if err != nil {
		return 0
	}
	return days
}

// SetTrashKeepDays is set_keep_days.
func SetTrashKeepDays(value any) (int64, error) {
	days, err := NormalizeKeepDays(value)
	if err != nil {
		return 0, err
	}
	now := nowFloat()
	var gone []*Map
	err = func() error {
		dir, release, lerr := trashLocked()
		if lerr != nil {
			return lerr
		}
		defer release()
		if werr := trashWrite(filepath.Join(dir, trashSettings), newMap("keep_days", days)); werr != nil {
			return werr
		}
		gone = trashPurgeLocked(dir, now, days)
		return nil
	}()
	if err != nil {
		return 0, err
	}
	forgetPages(gone)
	return days, nil
}

func nowFloat() float64 { return float64(time.Now().UnixNano()) / 1e9 }

func trashExpired(at int64, now float64, days int64) bool {
	return days > 0 && now-float64(at) >= float64(days*86400)
}

func trashExpiresAt(at, days int64) int64 {
	if days > 0 {
		return at + days*86400
	}
	return 0
}

func globSuffix(dir, suffix string) []string {
	m, _ := filepath.Glob(filepath.Join(dir, "*"+suffix))
	return m
}

func stem(path string) string {
	base := filepath.Base(path)
	return strings.TrimSuffix(base, filepath.Ext(base))
}

func isSymlink(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode()&os.ModeSymlink != 0
}

func trashPurgeLocked(dir string, now float64, days int64) []*Map {
	if days < 0 {
		days = TrashKeepDays()
	}
	revive := func(suffix string, limit float64) {
		for _, p := range globSuffix(dir, suffix) {
			info, err := os.Stat(p)
			if err != nil {
				continue
			}
			stale := now-float64(info.ModTime().UnixNano())/1e9 > limit
			if stale && trashIDRe.MatchString(stem(p)) && !isSymlink(p) {
				_ = os.Rename(p, strings.TrimSuffix(p, suffix)+".json")
			}
		}
	}
	revive(trashPend, pendingSecs)
	revive(trashClaim, claimSecs)
	var gone []*Map
	if days <= 0 {
		return gone
	}
	for _, p := range globSuffix(dir, ".json") {
		m := trashIDRe.FindStringSubmatch(stem(p))
		if m == nil || isSymlink(p) {
			continue
		}
		at, _ := strconv.ParseInt(m[1], 10, 64)
		if trashExpired(at, now, days) {
			item := trashRead(p)
			if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
				log.Printf("Expired trash item %s could not be removed", filepath.Base(p))
				continue
			}
			if item != nil {
				gone = append(gone, item)
			}
		}
	}
	return gone
}

func pageOf(item *Map) string {
	if item.Value("kind") != "site" {
		return ""
	}
	return strOrEmpty(get(orValue(item.Value("extra"), pyyaml.NewMap()), "access_page"))
}

func forgetPages(items []*Map) {
	for _, item := range items {
		page := pageOf(item)
		if page == "" {
			continue
		}
		if err := accessPortalForget(strOrEmpty(item.Value("name")), page); err != nil {
			log.Printf("The access page of deleted site %s could not be removed", pyRepr(item.Value("name")))
		}
	}
}

// TrashReferencedPages is referenced_pages.
func TrashReferencedPages() map[string]bool {
	names := map[string]bool{}
	dir := trashRoot()
	info, err := os.Lstat(dir)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return names
	}
	var found []string
	found = append(found, globSuffix(dir, ".json")...)
	found = append(found, globSuffix(dir, trashClaim)...)
	found = append(found, globSuffix(dir, trashPend)...)
	for _, p := range found {
		if !trashIDRe.MatchString(stem(p)) {
			continue
		}
		if item := trashRead(p); item != nil && pageOf(item) != "" {
			names[pageOf(item)] = true
		}
	}
	return names
}

func uuidHex12() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return hex.EncodeToString(b)[:12]
}

// TrashKeep is keep().
func TrashKeep(op *Op, kind, name string, entry any, extra *Map) (string, error) {
	if !trashKinds[kind] {
		return "", &TrashError{"Unknown trash kind"}
	}
	if _, ok := asMap(entry); !ok {
		return "", &TrashError{"Unknown trash kind"}
	}
	now := nowFloat()
	id := fmt.Sprintf("%d-%s", int64(now), uuidHex12())
	if extra == nil {
		extra = pyyaml.NewMap()
	}
	actor := ""
	if op != nil {
		actor = op.Actor
	}
	var gone []*Map
	err := func() error {
		dir, release, lerr := trashLocked()
		if lerr != nil {
			return lerr
		}
		defer release()
		path, _ := trashPendingPath(dir, id)
		werr := trashWrite(path, newMap("id", id, "kind", kind, "name", name, "deleted_at", int64(now),
			"deleted_by", actor, "entry", entry, "extra", copyMap(extra)))
		if werr == nil {
			gone = trashPurgeLocked(dir, now, -1)
		}
		return werr
	}()
	if err != nil {
		if te, ok := err.(*TrashError); ok {
			return "", te
		}
		log.Printf("The %s %s could not be kept in the trash", kind, pyRepr(name))
		return "", &TrashError{pyOSError(err)}
	}
	forgetPages(gone)
	return id, nil
}

// TrashAnnotate is annotate().
func TrashAnnotate(id string, extra *Map) error {
	dir, release, err := trashLocked()
	if err != nil {
		return &TrashError{err.Error()}
	}
	defer release()
	path, err := trashPendingPath(dir, id)
	if err != nil {
		return err
	}
	item := trashRead(path)
	if item == nil {
		return &TrashError{"Unknown trash item"}
	}
	merged := copyMap(orValue(item.Value("extra"), pyyaml.NewMap()).(*Map))
	extra.Each(func(k, v any) { merged.Set(k, v) })
	item.Set("extra", merged)
	if err := trashWrite(path, item); err != nil {
		return &TrashError{pyOSError(err)}
	}
	return nil
}

// TrashCommit is commit().
func TrashCommit(id string) bool {
	dir, release, err := trashLocked()
	if err != nil {
		log.Printf("The trash item %s could not be listed yet", id)
		return false
	}
	defer release()
	pend, err1 := trashPendingPath(dir, id)
	final, err2 := trashPath(dir, id)
	if err1 != nil || err2 != nil || os.Rename(pend, final) != nil {
		log.Printf("The trash item %s could not be listed yet", id)
		return false
	}
	return true
}

// TrashDrop is drop().
func TrashDrop(id string) {
	dir, release, err := trashLocked()
	if err != nil {
		return
	}
	defer release()
	if p, err := trashPendingPath(dir, id); err == nil {
		_ = os.Remove(p)
	}
}

// TrashSettle is settle(): true when the copy was kept.
func TrashSettle(id string, stillInSource bool) bool {
	if stillInSource {
		TrashDrop(id)
		return false
	}
	TrashCommit(id)
	return true
}

func trashSummary(item *Map, days int64) *Map {
	entry := item.Value("entry").(*Map)
	kind := pyStr(item.Value("kind"))
	var detail string
	switch kind {
	case "site":
		names := []string{strOrEmpty(entry.Value("domain"))}
		if alt, ok := asList(orValue(entry.Value("alt_names"), []any{})); ok {
			for _, n := range alt {
				if strip(n) != "" {
					names = append(names, pyStr(n))
				}
			}
		}
		var kept []string
		for _, n := range names {
			if n != "" {
				kept = append(kept, n)
			}
		}
		detail = strings.Join(kept, ", ")
	case "tcp":
		detail = fmt.Sprintf("%s:%s", pyStr(orValue(entry.Value("bind_ip"), "*")), pyStr(orValue(entry.Value("bind_port"), "")))
	default:
		detail = fmt.Sprintf("udp %s -> %s", pyStr(orValue(entry.Value("listen_port"), "")), pyStr(orValue(entry.Value("backend_host"), entry.Value("backend_ip"), "")))
	}
	deletedAt := pyIntOr0(orValue(item.Value("deleted_at"), int64(0)))
	return newMap("source", "panel", "id", item.Value("id"), "kind", kind, "name", orValue(item.Value("name"), ""),
		"detail", detail, "deleted_at", deletedAt, "deleted_by", orValue(item.Value("deleted_by"), ""),
		"expires_at", trashExpiresAt(deletedAt, days))
}

// TrashListWithTerm is list_with_term.
func TrashListWithTerm() ([]any, int64, error) {
	now := nowFloat()
	var days int64
	var gone []*Map
	var found []*Map
	err := func() error {
		dir, release, err := trashLocked()
		if err != nil {
			return err
		}
		defer release()
		days = TrashKeepDays()
		gone = trashPurgeLocked(dir, now, days)
		for _, p := range globSuffix(dir, ".json") {
			if trashIDRe.MatchString(stem(p)) {
				found = append(found, trashRead(p))
			}
		}
		return nil
	}()
	if err != nil {
		return nil, 0, err
	}
	forgetPages(gone)
	var listed []*Map
	for _, it := range found {
		if it != nil {
			listed = append(listed, trashSummary(it, days))
		}
	}
	sort.SliceStable(listed, func(i, j int) bool {
		a, b := listed[i], listed[j]
		ad, bd := a.Value("deleted_at").(int64), b.Value("deleted_at").(int64)
		if ad != bd {
			return ad > bd
		}
		return pyStr(a.Value("id")) > pyStr(b.Value("id"))
	})
	out := make([]any, len(listed))
	for i, l := range listed {
		out[i] = l
	}
	return out, days, nil
}

// TrashPurge is purge().
func TrashPurge() (int, error) {
	var gone []*Map
	err := func() error {
		dir, release, err := trashLocked()
		if err != nil {
			return err
		}
		defer release()
		gone = trashPurgeLocked(dir, nowFloat(), -1)
		return nil
	}()
	if err != nil {
		return 0, err
	}
	forgetPages(gone)
	return len(gone), nil
}

// TrashRestore is restore().
func TrashRestore(op *Op, id string) (*Map, error) {
	now := nowFloat()
	var path, claim string
	var item *Map
	var expiredItem *Map
	err := func() error {
		dir, release, err := trashLocked()
		if err != nil {
			return err
		}
		defer release()
		p, err := trashPath(dir, id)
		if err != nil {
			return err
		}
		it := trashRead(p)
		if it == nil {
			return &TrashError{"Unknown trash item"}
		}
		cl := strings.TrimSuffix(p, ".json") + trashClaim
		if trashExpired(pyIntOr0(orValue(it.Value("deleted_at"), int64(0))), now, TrashKeepDays()) {
			_ = os.Remove(p)
			expiredItem = it
			return &TrashError{"Unknown trash item"}
		}
		if err := os.Rename(p, cl); err != nil {
			return err
		}
		t := time.Now()
		_ = os.Chtimes(cl, t, t)
		path, claim, item = p, cl, it
		return nil
	}()
	if expiredItem != nil {
		forgetPages([]*Map{expiredItem})
	}
	if err != nil {
		return nil, err
	}
	giveBack := func() {
		_, rel, err := trashLocked()
		if err != nil {
			return
		}
		defer rel()
		_ = os.Rename(claim, path)
	}
	restored := false
	defer func() {
		if !restored {
			giveBack()
		}
	}()
	kind := pyStr(item.Value("kind"))
	restorer, ok := trashRestorers[kind]
	if !ok {
		return nil, fmt.Errorf("no restorer for %s", kind)
	}
	extraMap, ok := orValue(item.Value("extra"), pyyaml.NewMap()).(*Map)
	if !ok {
		extraMap = pyyaml.NewMap()
	}
	entryMap, ok := item.Value("entry").(*Map)
	if !ok || entryMap == nil {
		return nil, &TrashError{"Corrupted trash item"}
	}
	extra := copyMap(extraMap)
	okRestore, message, info := restorer(op, entryMap, extra)
	if !okRestore {
		return newMap("ok", false, "error", message, "kind", kind, "name", item.Value("name")), nil
	}
	restored = true
	result := newMap("ok", true, "message", message, "kind", kind, "name", item.Value("name"))
	if info != nil {
		info.Each(func(k, v any) {
			if truthy(v) {
				result.Set(k, v)
			}
		})
	}
	if _, rel, err := trashLocked(); err == nil {
		func() {
			defer rel()
			_ = os.Remove(claim)
		}()
	}
	return result, nil
}

// TrashRestoreAccessPage is restore_access_page.
func TrashRestoreAccessPage(name, stored string) string {
	ok, err := accessPortalRestore(name, stored)
	if err != nil {
		log.Printf("The access page of restored site %s could not be put back", pyRepr(name))
		return "failed"
	}
	if ok {
		return "restored"
	}
	return "gone"
}

// TrashRemove is remove().
func TrashRemove(id string) (*Map, error) {
	var item *Map
	err := func() error {
		dir, release, err := trashLocked()
		if err != nil {
			return err
		}
		defer release()
		path, err := trashPath(dir, id)
		if err != nil {
			return err
		}
		item = trashRead(path)
		if item == nil {
			return &TrashError{"Unknown trash item"}
		}
		_ = os.Remove(path)
		return nil
	}()
	if err != nil {
		return nil, err
	}
	forgetPages([]*Map{item})
	return newMap("ok", true, "kind", item.Value("kind"), "name", item.Value("name")), nil
}

// TrashEmptyDetailed is empty_detailed.
func TrashEmptyDetailed() (int, []string, error) {
	now := nowFloat()
	var gone []*Map
	var failed []string
	removed := 0
	err := func() error {
		dir, release, err := trashLocked()
		if err != nil {
			return err
		}
		defer release()
		for _, c := range globSuffix(dir, trashClaim) {
			info, err := os.Stat(c)
			if err != nil {
				continue
			}
			if now-float64(info.ModTime().UnixNano())/1e9 > claimSecs && trashIDRe.MatchString(stem(c)) && !isSymlink(c) {
				_ = os.Rename(c, strings.TrimSuffix(c, trashClaim)+".json")
			}
		}
		for _, p := range globSuffix(dir, ".json") {
			if trashIDRe.MatchString(stem(p)) && !isSymlink(p) {
				item := trashRead(p)
				if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
					failed = append(failed, stem(p)+": "+pyOSError(err))
					continue
				}
				removed++
				if item != nil {
					gone = append(gone, item)
				}
			}
		}
		return nil
	}()
	if err != nil {
		return 0, nil, err
	}
	forgetPages(gone)
	return removed, failed, nil
}

// StartTrashPurger is ensure_purger: a purge every hour until ctx is canceled.
func StartTrashPurger(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				func() {
					defer func() {
						if rec := recover(); rec != nil {
							log.Printf("Trash purger recovered from panic: %v", rec)
						}
					}()
					if _, err := TrashPurge(); err != nil {
						log.Printf("The trash could not be purged: %v", err)
					}
				}()
			}
		}
	}()
}
