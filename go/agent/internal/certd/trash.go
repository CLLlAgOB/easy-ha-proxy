package certd

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/pyx"
)

const syscallNoFollow = syscall.O_NOFOLLOW

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (d *Daemon) trashRoot(create bool) (string, error) {
	if create {
		if err := os.MkdirAll(d.Opts.TrashDir, 0o700); err != nil {
			return "", err
		}
		if err := os.Chmod(d.Opts.TrashDir, 0o700); err != nil {
			return "", err
		}
	}
	if isSymlink(d.Opts.TrashDir) {
		return "", vErr("invalid trash directory")
	}
	return d.Opts.TrashDir, nil
}

func statOwner(fi os.FileInfo) (int, int) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid), int(st.Gid)
	}
	return -1, -1
}

func copyFileOwned(src, dst string) error {
	fi, err := os.Stat(src)
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		_ = out.Close()
		return err
	}
	_, err = io.Copy(out, in)
	_ = in.Close()
	if err == nil {
		err = out.Sync()
	}
	if err == nil {
		uid, gid := statOwner(fi)
		_ = out.Chown(uid, gid)
		err = out.Chmod(fi.Mode().Perm() | (fi.Mode() & (os.ModeSetuid | os.ModeSetgid | os.ModeSticky)))
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Chtimes(dst, fi.ModTime(), fi.ModTime())
}

// copyOwned is _copy_owned: a file, a symlink or a tree, owners and modes kept.
func copyOwned(src, dst string) error {
	fi, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		link, err := os.Readlink(src)
		if err != nil {
			return err
		}
		if err := os.Symlink(link, dst); err != nil {
			return err
		}
		uid, gid := statOwner(fi)
		_ = os.Lchown(dst, uid, gid)
		return nil
	}
	if !fi.IsDir() {
		return copyFileOwned(src, dst)
	}
	type dirInfo struct {
		path string
		fi   os.FileInfo
	}
	dirs := []dirInfo{}
	if err := os.Mkdir(dst, 0o700); err != nil {
		return err
	}
	dirs = append(dirs, dirInfo{dst, fi})
	err = filepath.WalkDir(src, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == src {
			return nil
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			if err := os.Symlink(link, target); err != nil {
				return err
			}
			uid, gid := statOwner(info)
			_ = os.Lchown(target, uid, gid)
		case info.IsDir():
			if err := os.Mkdir(target, 0o700); err != nil {
				return err
			}
			dirs = append(dirs, dirInfo{target, info})
		default:
			return copyFileOwned(path, target)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		uid, gid := statOwner(dirs[i].fi)
		_ = os.Chown(dirs[i].path, uid, gid)
		_ = os.Chmod(dirs[i].path, dirs[i].fi.Mode().Perm())
		_ = os.Chtimes(dirs[i].path, dirs[i].fi.ModTime(), dirs[i].fi.ModTime())
	}
	return nil
}

func removePath(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil
	}
	if fi.IsDir() {
		return os.RemoveAll(path)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// trashListing is _trash_listing.
func trashListing(paths []string) []string {
	found := []string{}
	for _, p := range paths {
		if p == "" || !lexists(p) {
			continue
		}
		found = append(found, p)
		if isDir(p) && !isSymlink(p) {
			_ = filepath.WalkDir(p, func(path string, entry fs.DirEntry, err error) error {
				if err != nil {
					return nil
				}
				if path != p {
					found = append(found, path)
				}
				if entry != nil && entry.Type()&os.ModeSymlink != 0 {
					return nil
				}
				return nil
			})
		}
	}
	sort.Strings(found)
	return found
}

func trashFingerprints(paths []string) []any {
	out := []any{}
	for _, item := range trashListing(paths) {
		fi, err := os.Lstat(item)
		if err != nil {
			continue
		}
		var ino uint64
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			ino = st.Ino
		}
		out = append(out, []any{item, ino, fi.Size(), fi.ModTime().UnixNano()})
	}
	return out
}

func sameStrings(a []string, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (d *Daemon) trashSettle(kept string, before []string, paths []string) string {
	if kept == "" {
		return ""
	}
	left := trashListing(paths)
	if sameStrings(left, before) {
		d.trashDrop(kept)
		return ""
	}
	leftAny := make([]any, len(left))
	for i, s := range left {
		leftAny[i] = s
	}
	d.trashUpdateExtra(kept, map[string]any{"leftovers": leftAny, "leftover_fingerprints": trashFingerprints(paths)})
	d.trashCommit(kept)
	return kept
}

// renameNoReplace is _rename_noreplace.
func renameNoReplace(src, dst string) error {
	err := unix.Renameat2(unix.AT_FDCWD, src, unix.AT_FDCWD, dst, unix.RENAME_NOREPLACE)
	if err == nil {
		return nil
	}
	if errors.Is(err, unix.EEXIST) {
		return &os.LinkError{Op: "rename", Old: src, New: dst, Err: syscall.EEXIST}
	}
	if !errors.Is(err, unix.ENOSYS) && !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.ENOTSUP) {
		return &os.LinkError{Op: "rename", Old: src, New: dst, Err: err}
	}
	if isDir(src) && !isSymlink(src) {
		if lexists(dst) {
			return &os.LinkError{Op: "rename", Old: src, New: dst, Err: syscall.EEXIST}
		}
		return os.Rename(src, dst)
	}
	if err := os.Link(src, dst); err != nil {
		return err
	}
	return os.Remove(src)
}

func isExistErr(err error) bool {
	return errors.Is(err, syscall.EEXIST) || os.IsExist(err)
}

func (d *Daemon) trashKeepDays() int {
	root, err := d.trashRoot(false)
	if err != nil {
		return 0
	}
	path := filepath.Join(root, trashSettings)
	if isSymlink(path) {
		return 0
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var payload map[string]any
	if json.Unmarshal(raw, &payload) != nil || payload == nil {
		return 0
	}
	v := pyx.Get(payload, "keep_days", float64(0))
	n, ok := pyIntLoose(v)
	if !ok || n < 0 || n > trashMaxKeepDays {
		return 0
	}
	return int(n)
}

func (d *Daemon) setTrashKeepDays(value any) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(pyx.Str(value)))
	if err != nil {
		return 0, vErr("keep_days must be a whole number of days")
	}
	if n < 0 || n > trashMaxKeepDays {
		return 0, vErr("keep_days must be between 0 and %d", trashMaxKeepDays)
	}
	d.trashMu.Lock()
	defer d.trashMu.Unlock()
	root, err := d.trashRoot(true)
	if err != nil {
		return 0, err
	}
	tmp := filepath.Join(root, ".tmp-settings-"+randHex(4))
	defer os.Remove(tmp)
	if err := os.WriteFile(tmp, []byte(fmt.Sprintf("{\"keep_days\": %d}\n", n)), 0o600); err != nil {
		return 0, err
	}
	_ = os.Chmod(tmp, 0o600)
	if err := os.Rename(tmp, filepath.Join(root, trashSettings)); err != nil {
		return 0, err
	}
	d.trashPurgeLocked(time.Now())
	return n, nil
}

func trashExpired(at int64, now time.Time, days int) bool {
	return days > 0 && float64(now.Unix())-float64(at) >= float64(days*86400)
}

// trashPut is _trash_put.
func (d *Daemon) trashPut(kind, name string, paths []string, actor string, details, extra map[string]any) (string, error) {
	if !containsStr(trashKinds, kind) {
		return "", vErr("unknown trash kind")
	}
	present := []string{}
	for _, p := range paths {
		if p != "" && lexists(p) {
			present = append(present, p)
		}
	}
	if len(present) == 0 {
		return "", vErr("nothing to keep in the trash")
	}
	now := time.Now()
	itemID := fmt.Sprintf("%d-%s", now.Unix(), randHex(6))
	d.trashMu.Lock()
	defer d.trashMu.Unlock()
	root, err := d.trashRoot(true)
	if err != nil {
		return "", err
	}
	staging, err := os.MkdirTemp(root, ".tmp-")
	if err != nil {
		return "", err
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(staging)
		}
	}()
	entries := []any{}
	for i, p := range present {
		stored := strconv.Itoa(i)
		if err := copyOwned(p, filepath.Join(staging, stored)); err != nil {
			return "", err
		}
		pfi, err := os.Stat(filepath.Dir(p))
		if err != nil {
			return "", err
		}
		uid, gid := statOwner(pfi)
		entries = append(entries, map[string]any{"path": p, "stored": stored, "parent_mode": int(pfi.Mode().Perm()),
			"parent_uid": uid, "parent_gid": gid})
	}
	if details == nil {
		details = map[string]any{}
	}
	if extra == nil {
		extra = map[string]any{}
	}
	meta := map[string]any{"id": itemID, "kind": kind, "name": name, "deleted_at": now.Unix(),
		"deleted_by": pyx.TruncRunes(actor, 200), "details": details, "extra": extra, "paths": entries}
	raw := jsonIndentN(meta, " ")
	if err := os.WriteFile(filepath.Join(staging, "meta.json"), append(raw, '\n'), 0o600); err != nil {
		return "", err
	}
	pending, err := d.trashPendingDir(itemID)
	if err != nil {
		return "", err
	}
	if err := os.Rename(staging, pending); err != nil {
		return "", err
	}
	ok = true
	d.trashPurgeLocked(now)
	return itemID, nil
}

func jsonIndentN(v any, indent string) []byte {
	out := jsonIndent(v)
	if indent == "  " {
		return out
	}
	// Re-indent to the requested width (json.dumps(indent=1)).
	var buf []byte
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimLeft(line, " ")
		depth := (len(line) - len(trimmed)) / 2
		buf = append(buf, strings.Repeat(indent, depth)+trimmed+"\n"...)
	}
	return []byte(strings.TrimRight(string(buf), "\n"))
}

func (d *Daemon) trashPendingDir(itemID string) (string, error) {
	if !trashIDRe.MatchString(itemID) {
		return "", vErr("unknown trash item")
	}
	root, err := d.trashRoot(false)
	if err != nil {
		return "", err
	}
	return filepath.Join(root, ".pending-"+itemID), nil
}

func (d *Daemon) trashItemDir(itemID string) (string, error) {
	if !trashIDRe.MatchString(itemID) {
		return "", vErr("unknown trash item")
	}
	root, err := d.trashRoot(false)
	if err != nil {
		return "", err
	}
	return filepath.Join(root, itemID), nil
}

func (d *Daemon) trashCommit(itemID string) {
	if itemID == "" {
		return
	}
	d.trashMu.Lock()
	defer d.trashMu.Unlock()
	pending, err1 := d.trashPendingDir(itemID)
	item, err2 := d.trashItemDir(itemID)
	if err1 != nil || err2 != nil {
		return
	}
	if err := os.Rename(pending, item); err != nil {
		log.Printf("cannot list trash item %s yet: %v", itemID, err)
	}
}

func (d *Daemon) trashUpdateExtra(itemID string, extra map[string]any) bool {
	d.trashMu.Lock()
	defer d.trashMu.Unlock()
	pending, err := d.trashPendingDir(itemID)
	if err != nil {
		return false
	}
	metaPath := filepath.Join(pending, "meta.json")
	meta, err := readJSONMap(metaPath)
	if err != nil {
		log.Printf("cannot update metadata for pending trash item %s", itemID)
		return false
	}
	current := pyx.Map(meta["extra"])
	merged := map[string]any{}
	for k, v := range current {
		merged[k] = v
	}
	for k, v := range extra {
		merged[k] = v
	}
	meta["extra"] = merged
	tmp := filepath.Join(pending, ".meta.json."+randHex(4)+".tmp")
	if err := writeModeFile(tmp, append(jsonIndentN(meta, " "), '\n'), 0o600); err != nil {
		_ = os.Remove(tmp)
		return false
	}
	if err := os.Rename(tmp, metaPath); err != nil {
		_ = os.Remove(tmp)
		return false
	}
	return true
}

func (d *Daemon) trashDrop(itemID string) {
	d.trashMu.Lock()
	defer d.trashMu.Unlock()
	if pending, err := d.trashPendingDir(itemID); err == nil {
		_ = os.RemoveAll(pending)
	}
}

func (d *Daemon) trashMeta(itemID string, live bool) (map[string]any, error) {
	dir, err := d.trashItemDir(itemID)
	if err != nil {
		return nil, err
	}
	metaPath := filepath.Join(dir, "meta.json")
	if isSymlink(dir) || isSymlink(metaPath) || !isFile(metaPath) {
		return nil, vErr("unknown trash item")
	}
	meta, err := readJSONMap(metaPath)
	if err != nil {
		return nil, err
	}
	kind, _ := meta["kind"].(string)
	if !containsStr(trashKinds, kind) {
		return nil, vErr("unknown trash item")
	}
	if _, ok := meta["paths"].([]any); !ok {
		return nil, vErr("unknown trash item")
	}
	if live {
		at, _ := pyIntLoose(pyx.Get(meta, "deleted_at", float64(0)))
		if trashExpired(at, time.Now(), d.trashKeepDays()) {
			_ = os.RemoveAll(dir)
			return nil, vErr("unknown trash item")
		}
	}
	return meta, nil
}

func (d *Daemon) trashPurgeLocked(now time.Time) int {
	root, err := d.trashRoot(false)
	if err != nil || !isDir(root) {
		return 0
	}
	days := d.trashKeepDays()
	for _, entry := range sortedDirEntries(root) {
		if isSymlink(entry) || !isDir(entry) {
			continue
		}
		name := filepath.Base(entry)
		fi, err := os.Stat(entry)
		if err != nil {
			continue
		}
		age := now.Sub(fi.ModTime()).Seconds()
		if strings.HasPrefix(name, ".tmp-") && age > 3600 {
			_ = os.RemoveAll(entry)
		} else if strings.HasPrefix(name, ".pending-") && age > 3600 {
			promoted := strings.TrimPrefix(name, ".pending-")
			if trashIDRe.MatchString(promoted) {
				_ = os.Rename(entry, filepath.Join(root, promoted))
			}
		}
	}
	if days <= 0 {
		return 0
	}
	removed := 0
	for _, entry := range sortedDirEntries(root) {
		if isSymlink(entry) || !isDir(entry) {
			continue
		}
		m := trashIDRe.FindStringSubmatch(filepath.Base(entry))
		if m == nil {
			continue
		}
		at, _ := strconv.ParseInt(m[1], 10, 64)
		if trashExpired(at, now, days) {
			_ = os.RemoveAll(entry)
			removed++
		}
	}
	return removed
}

func (d *Daemon) listTrash() (map[string]any, error) {
	d.trashMu.Lock()
	defer d.trashMu.Unlock()
	days := d.trashKeepDays()
	d.trashPurgeLocked(time.Now())
	items := []map[string]any{}
	root, err := d.trashRoot(false)
	if err != nil {
		return nil, err
	}
	if isDir(root) {
		for _, entry := range sortedDirEntries(root) {
			name := filepath.Base(entry)
			if !trashIDRe.MatchString(name) {
				continue
			}
			meta, err := d.trashMeta(name, false)
			if err != nil {
				continue
			}
			at, _ := pyIntLoose(pyx.Get(meta, "deleted_at", float64(0)))
			expires := int64(0)
			if days > 0 {
				expires = at + int64(days)*86400
			}
			details := pyx.Map(meta["details"])
			if details == nil {
				details = map[string]any{}
			}
			items = append(items, map[string]any{"id": meta["id"], "kind": meta["kind"], "name": pyx.StrOr(meta["name"]),
				"details": details, "deleted_at": at, "deleted_by": pyx.StrOr(meta["deleted_by"]), "expires_at": expires})
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		ai, aj := items[i]["deleted_at"].(int64), items[j]["deleted_at"].(int64)
		if ai != aj {
			return ai > aj
		}
		return pyx.Str(items[i]["id"]) > pyx.Str(items[j]["id"])
	})
	out := make([]any, len(items))
	for i, it := range items {
		out[i] = it
	}
	return map[string]any{"items": out, "keep_days": days}, nil
}

func (d *Daemon) trashRootsFor(kind string) []string {
	switch kind {
	case "haproxy_cert":
		return []string{d.Opts.HAProxyCertsDir}
	case "letsencrypt":
		return []string{d.Opts.LetsEncryptRoot}
	case "standby":
		return []string{d.Opts.CertsAvailableDir}
	case "external_ca", "internal_ca":
		return []string{d.Opts.CARootDir}
	case "dns_provider":
		return []string{d.Opts.DNSCredentialsDir}
	case "cert_delivery":
		return []string{d.Opts.DeliveryDir}
	}
	return nil
}

type trashTarget struct {
	source, target string
	entry          map[string]any
}

func (d *Daemon) trashTargets(meta map[string]any) ([]trashTarget, error) {
	dir, err := d.trashItemDir(pyx.Str(meta["id"]))
	if err != nil {
		return nil, err
	}
	bases := []string{}
	for _, b := range d.trashRootsFor(pyx.Str(meta["kind"])) {
		bases = append(bases, resolvePath(b))
	}
	out := []trashTarget{}
	for _, e := range pyx.List(meta["paths"]) {
		entry, ok := e.(map[string]any)
		if !ok {
			return nil, vErr("damaged trash item")
		}
		target := pyx.StrOr(entry["path"])
		stored := pyx.StrOr(entry["stored"])
		name := filepath.Base(target)
		if !filepath.IsAbs(target) || name == "" || name == "." || name == ".." || !isDigits(stored) {
			return nil, vErr("damaged trash item")
		}
		candidate := filepath.Join(resolvePath(filepath.Dir(target)), name)
		inside := false
		for _, b := range bases {
			if rel, err := filepath.Rel(b, candidate); err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, "../") {
				inside = true
			}
		}
		if !inside {
			return nil, vErr("refusing to restore outside the certificate directories: %s", target)
		}
		source := filepath.Join(dir, stored)
		if !lexists(source) {
			return nil, vErr("damaged trash item")
		}
		out = append(out, trashTarget{source, candidate, entry})
	}
	return out, nil
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func (d *Daemon) trashStagingDir(parent, kind string) string {
	if kind == "haproxy_cert" {
		if root, err := d.trashRoot(true); err == nil {
			a, err1 := os.Stat(root)
			b, err2 := os.Stat(parent)
			if err1 == nil && err2 == nil {
				if sa, ok := a.Sys().(*syscall.Stat_t); ok {
					if sb, ok := b.Sys().(*syscall.Stat_t); ok && sa.Dev == sb.Dev {
						return root
					}
				}
			}
		}
	}
	return parent
}

// restoreTrashItem is restore_trash_item.
func (d *Daemon) restoreTrashItem(itemID string) (map[string]any, error) {
	d.trashMu.Lock()
	first, err := d.trashMeta(itemID, true)
	d.trashMu.Unlock()
	if err != nil {
		return nil, err
	}
	kind := pyx.Str(first["kind"])
	var meta map[string]any
	var targets []trashTarget
	err = func() error {
		if kind == "internal_ca" || kind == "external_ca" {
			d.caMu.Lock()
			defer d.caMu.Unlock()
		}
		d.standbyMu.Lock()
		defer d.standbyMu.Unlock()
		d.trashMu.Lock()
		defer d.trashMu.Unlock()
		meta, err = d.trashMeta(itemID, true)
		if err != nil {
			return err
		}
		if pyx.Str(meta["kind"]) != kind {
			return vErr("damaged trash item")
		}
		targets, err = d.trashTargets(meta)
		if err != nil {
			return err
		}
		targetPaths := []string{}
		taken := []string{}
		for _, t := range targets {
			targetPaths = append(targetPaths, t.target)
			if lexists(t.target) {
				taken = append(taken, t.target)
			}
		}
		extra := pyx.Map(meta["extra"])
		replacing := false
		if leftovers, ok := extra["leftovers"].([]any); ok && len(taken) > 0 {
			want := []string{}
			for _, v := range leftovers {
				want = append(want, pyx.Str(v))
			}
			sort.Strings(want)
			replacing = sameStrings(trashListing(targetPaths), want)
			if fps, ok := extra["leftover_fingerprints"].([]any); ok && replacing {
				a, _ := json.Marshal(trashFingerprints(targetPaths))
				b, _ := json.Marshal(fps)
				replacing = jsonEqual(a, b)
			}
		}
		if len(taken) > 0 && !replacing {
			return vErr("something of the same name is in place now; delete or rename it first: %s", strings.Join(taken, ", "))
		}
		if kind == "internal_ca" && !replacing {
			keyPath, certPath, err := d.internalCAPaths()
			if err != nil {
				return err
			}
			if exists(keyPath) || exists(certPath) {
				return vErr("a new internal certificate authority has been created since; it has to be deleted before the old one can come back")
			}
		}
		written, staged := []string{}, []string{}
		type aside struct{ moved, target string }
		asides := []aside{}
		rollback := func() {
			all := append(append([]string{}, staged...), reverse(written)...)
			for _, p := range all {
				_ = removePath(p)
			}
			for i := len(asides) - 1; i >= 0; i-- {
				if err := renameNoReplace(asides[i].moved, asides[i].target); err != nil && isExistErr(err) {
					log.Printf("cannot restore leftover %s: %s already exists", asides[i].moved, asides[i].target)
					_ = removePath(asides[i].moved)
				}
			}
		}
		for _, t := range targets {
			parent := filepath.Dir(t.target)
			if !exists(parent) {
				mode := os.FileMode(0o700)
				if m, ok := pyIntLoose(t.entry["parent_mode"]); ok && m != 0 {
					mode = os.FileMode(m)
				}
				if err := os.MkdirAll(parent, mode); err != nil {
					rollback()
					return err
				}
				_ = os.Chmod(parent, mode)
				if uid, ok := pyIntLoose(t.entry["parent_uid"]); ok {
					if gid, ok := pyIntLoose(t.entry["parent_gid"]); ok {
						_ = os.Chown(parent, int(uid), int(gid))
					}
				}
				written = append(written, parent)
			}
			stageDir := d.trashStagingDir(parent, kind)
			if replacing && lexists(t.target) {
				moved := filepath.Join(stageDir, ".replaced-"+randHex(6))
				if err := os.Rename(t.target, moved); err != nil {
					rollback()
					return err
				}
				asides = append(asides, aside{moved, t.target})
			}
			temporary := filepath.Join(stageDir, ".restore-"+randHex(6))
			staged = append(staged, temporary)
			if err := copyOwned(t.source, temporary); err != nil {
				rollback()
				return err
			}
			if err := renameNoReplace(temporary, t.target); err != nil {
				rollback()
				if isExistErr(err) {
					return vErr("%s appeared while it was being restored; nothing was replaced", t.target)
				}
				return err
			}
			staged = staged[:len(staged)-1]
			written = append(written, t.target)
		}
		for _, a := range asides {
			_ = removePath(a.moved)
		}
		dir, _ := d.trashItemDir(itemID)
		_ = os.RemoveAll(dir)
		return nil
	}()
	if err != nil {
		return nil, err
	}
	notes := []string{}
	if kind == "external_ca" && pyx.Truthy(pyx.Map(meta["extra"])["client_auth"]) {
		caID := pyx.StrOr(meta["name"])
		trusted := d.loadClientAuthIDs()
		if caID != "" && !containsStr(trusted, caID) {
			ids := []any{}
			for _, t := range trusted {
				ids = append(ids, t)
			}
			status, resp := d.handleCAClientAuth(map[string]any{"ids": append(ids, caID)})
			if resp["ok"] != true {
				reason := pyx.StrOr(resp["error"])
				if reason == "" {
					reason = strconv.Itoa(status)
				}
				notes = append(notes, "it was trusted for client certificates before; trust it again on the certificates page ("+reason+")")
			}
		}
	}
	log.Printf("Restored %s %s from the trash", kind, pyx.StrOr(meta["name"]))
	paths := []string{}
	for _, t := range targets {
		paths = append(paths, t.target)
	}
	return map[string]any{"kind": kind, "name": pyx.StrOr(meta["name"]), "paths": paths, "notes": notes}, nil
}

func jsonEqual(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	xa, _ := json.Marshal(x)
	ya, _ := json.Marshal(y)
	return string(xa) == string(ya)
}

func reverse(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[len(in)-1-i] = s
	}
	return out
}

func (d *Daemon) purgeTrash(itemID string) (map[string]any, error) {
	d.trashMu.Lock()
	defer d.trashMu.Unlock()
	if itemID != "" {
		meta, err := d.trashMeta(itemID, false)
		if err != nil {
			return nil, err
		}
		dir, _ := d.trashItemDir(itemID)
		if err := os.RemoveAll(dir); err != nil {
			return nil, err
		}
		return map[string]any{"removed": 1, "kind": meta["kind"], "name": pyx.StrOr(meta["name"])}, nil
	}
	removed := 0
	failed := []string{}
	root, err := d.trashRoot(false)
	if err != nil {
		return nil, err
	}
	if isDir(root) {
		for _, entry := range sortedDirEntries(root) {
			name := filepath.Base(entry)
			if trashIDRe.MatchString(name) && !isSymlink(entry) && isDir(entry) {
				if err := os.RemoveAll(entry); err != nil {
					failed = append(failed, name+": "+pyOSErr(err))
					continue
				}
				removed++
			}
		}
	}
	return map[string]any{"removed": removed, "failed": failed}, nil
}

func (d *Daemon) handleTrashList(_ map[string]any) (int, map[string]any) {
	listing, err := d.listTrash()
	if err != nil {
		return 500, map[string]any{"ok": false, "error": "cannot read the trash: " + err.Error()}
	}
	return 200, merge(map[string]any{"ok": true}, listing)
}

func (d *Daemon) handleTrashRestore(body map[string]any) (int, map[string]any) {
	restored, err := d.restoreTrashItem(pyx.StrOr(body["id"]))
	if err != nil {
		if isValueErr(err) {
			return 400, map[string]any{"ok": false, "error": err.Error()}
		}
		return 500, map[string]any{"ok": false, "error": "cannot restore: " + pyOSErr(err)}
	}
	return 200, merge(map[string]any{"ok": true}, restored)
}

func (d *Daemon) handleTrashSettings(body map[string]any) (int, map[string]any) {
	if v, ok := body["keep_days"]; ok {
		days, err := d.setTrashKeepDays(v)
		if err != nil {
			if isValueErr(err) {
				return 400, map[string]any{"ok": false, "error": err.Error()}
			}
			return 500, map[string]any{"ok": false, "error": "cannot save the trash settings: " + pyOSErr(err)}
		}
		return 200, map[string]any{"ok": true, "keep_days": days}
	}
	return 200, map[string]any{"ok": true, "keep_days": d.trashKeepDays()}
}

func (d *Daemon) handleTrashPurge(body map[string]any) (int, map[string]any) {
	itemID := pyx.StrOr(body["id"])
	if itemID == "" && body["all"] != true {
		return 400, map[string]any{"ok": false, "error": "id or all is required"}
	}
	result, err := d.purgeTrash(itemID)
	if err != nil {
		if isValueErr(err) {
			return 400, map[string]any{"ok": false, "error": err.Error()}
		}
		return 500, map[string]any{"ok": false, "error": "cannot delete: " + pyOSErr(err)}
	}
	if failed, ok := result["failed"].([]string); ok && len(failed) > 0 {
		return 500, merge(map[string]any{"ok": false, "error": fmt.Sprintf("%d items could not be deleted: %s", len(failed),
			strings.Join(failed, "; "))}, result)
	}
	return 200, merge(map[string]any{"ok": true}, result)
}
