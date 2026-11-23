package app

// Port of access_portal.py: disk-backed instructions and attachments for
// authenticated access gates.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"easy-ha-proxy/panel/internal/pyyaml"
)

const (
	portalMaxFileBytes  = 128 * 1024 * 1024
	portalMaxTotalBytes = 512 * 1024 * 1024
	portalMaxFiles      = 10
	// Where a deleted site's instructions and attachments wait. A site in the
	// panel's trash keeps them for as long as it stays there: the trash removes
	// them with the site. What no trash item names goes after portalTrashSeconds.
	portalTrash        = ".deleted"
	portalTrashSeconds = 30 * 86400
)

var (
	portalIDRe      = regexp.MustCompile(`^[a-f0-9]{32}$`)
	portalTrashedRe = regexp.MustCompile(`^[a-f0-9]{64}-([0-9]{1,12})-[a-f0-9]{8}$`)
	portalTextBadRe = regexp.MustCompile(`[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]`)
	portalNameBadRe = regexp.MustCompile(`[\x00-\x1f\x7f]`)
	portalLanguages = map[string]bool{"auto": true, "en": true, "ru": true}
)

// portalConflict is the FileExistsError a stale revision raises.
type portalConflict struct{ msg string }

func (e *portalConflict) Error() string { return e.msg }

// portalNotFound is FileNotFoundError.
type portalNotFound struct{ msg string }

func (e *portalNotFound) Error() string { return e.msg }

func portalRoot() string {
	if v, ok := os.LookupEnv("HAPROXY_ADMIN_PORTAL_DIR"); ok {
		return v
	}
	return "/var/lib/haproxy-admin/access-portals"
}

// isRealDir is "not path.is_symlink() and path.is_dir()".
func isRealDir(path string) bool {
	fi, err := os.Lstat(path)
	return err == nil && fi.Mode()&os.ModeSymlink == 0 && fi.IsDir()
}

func errInvalidPortalDir() error { return &ValueError{"Invalid portal storage directory"} }

// portalMkdir is path.mkdir(parents=True, exist_ok=True, mode=0o700) followed
// by the symlink/directory check every caller makes.
func portalMkdir(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o777); err != nil {
		return err
	}
	if err := os.Mkdir(path, 0o700); err != nil && !(errors.Is(err, os.ErrExist) && dirFollow(path)) {
		return err
	}
	if !isRealDir(path) {
		return errInvalidPortalDir()
	}
	return nil
}

func dirFollow(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

// portalDirectory is _directory: site names never become filesystem paths.
func portalDirectory(site string) (string, error) {
	dir := filepath.Join(portalRoot(), sha256Hex(site))
	if err := portalMkdir(dir); err != nil {
		return "", err
	}
	return dir, nil
}

func uuidHex() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return hex.EncodeToString(b)
}

func pyTimeNow() float64 { return float64(time.Now().UnixNano()) / 1e9 }

// PortalPurge is purge: remove what has waited in the trash for its whole term.
func PortalPurge(now float64) (int, error) {
	trash := filepath.Join(portalRoot(), portalTrash)
	if !isRealDir(trash) {
		return 0, nil
	}
	entries, err := os.ReadDir(trash)
	if err != nil {
		return 0, err
	}
	removed := 0
	var kept map[string]bool
	for _, entry := range entries {
		m := portalTrashedRe.FindStringSubmatch(entry.Name())
		path := filepath.Join(trash, entry.Name())
		if m == nil || !isRealDir(path) {
			continue // nothing this module put there
		}
		at, _ := strconv.ParseInt(m[1], 10, 64)
		if now-float64(at) >= portalTrashSeconds {
			if kept == nil {
				kept = TrashReferencedPages()
			}
			if kept[entry.Name()] {
				continue // its site is in the trash; it goes with the site
			}
			_ = os.RemoveAll(path)
			removed++
		}
	}
	return removed, nil
}

// portalOpen is _open: never through a link, regular files only.
func portalOpen(path string, flags int) (*os.File, error) {
	f, err := os.OpenFile(path, flags|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		f.Close()
		if err != nil {
			return nil, err
		}
		return nil, &ValueError{"Portal storage must contain regular files"}
	}
	return f, nil
}

// portalSiteLock is _site_lock: a per-site lock outside the site directory, so
// discard and restore never move the lock.
func portalSiteLock(site string) (func(), error) {
	locks := filepath.Join(portalRoot(), ".locks")
	if err := portalMkdir(locks); err != nil {
		return nil, err
	}
	f, err := portalOpen(filepath.Join(locks, sha256Hex(site)), os.O_CREATE|os.O_RDWR)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}

// portalLocked is _locked: the site lock, then its directory.
func portalLocked(site string) (string, func(), error) {
	release, err := portalSiteLock(site)
	if err != nil {
		return "", nil, err
	}
	dir, err := portalDirectory(site)
	if err != nil {
		release()
		return "", nil, err
	}
	return dir, release, nil
}

// PortalDiscard is discard: take a site's instructions and attachments out of
// service, moved aside rather than removed. "" when there was nothing.
func PortalDiscard(site string, now float64) (string, error) {
	if _, err := PortalPurge(now); err != nil {
		return "", err
	}
	name := sha256Hex(site)
	dir := filepath.Join(portalRoot(), name)
	if !isRealDir(dir) {
		return "", nil
	}
	release, err := portalSiteLock(site)
	if err != nil {
		return "", err
	}
	defer release()
	if !isRealDir(dir) {
		return "", nil
	}
	trash := filepath.Join(portalRoot(), portalTrash)
	if err := os.Mkdir(trash, 0o700); err != nil && !(errors.Is(err, os.ErrExist) && dirFollow(trash)) {
		return "", err
	}
	if !isRealDir(trash) {
		return "", errInvalidPortalDir()
	}
	stored := name + "-" + strconv.FormatInt(int64(now), 10) + "-" + uuidHex()[:8]
	if err := os.Rename(dir, filepath.Join(trash, stored)); err != nil {
		return "", err
	}
	return stored, nil
}

func portalStoredSource(site, stored string) (string, bool) {
	name := sha256Hex(site)
	if !portalTrashedRe.MatchString(stored) || !strings.HasPrefix(stored, name+"-") {
		return "", false
	}
	source := filepath.Join(portalRoot(), portalTrash, stored)
	return source, isRealDir(source)
}

// PortalRestore is restore: give a restored site back the page it had.
func PortalRestore(site, stored string) (bool, error) {
	source, ok := portalStoredSource(site, stored)
	if !ok {
		return false, nil
	}
	release, err := portalSiteLock(site)
	if err != nil {
		return false, err
	}
	defer release()
	if !isRealDir(source) {
		return false, nil
	}
	target := filepath.Join(portalRoot(), sha256Hex(site))
	if isSymlink(target) {
		return false, nil
	}
	if dirFollow(target) {
		entries, err := os.ReadDir(target)
		if err != nil {
			return false, err
		}
		for _, e := range entries {
			if e.Name() != ".lock" {
				return false, nil
			}
		}
		if err := os.RemoveAll(target); err != nil {
			return false, err
		}
	}
	if err := os.Rename(source, target); err != nil {
		return false, err
	}
	return true, nil
}

// PortalForget is forget: remove for good the page a site took into the trash.
func PortalForget(site, stored string) (bool, error) {
	source, ok := portalStoredSource(site, stored)
	if !ok {
		return false, nil
	}
	if err := os.RemoveAll(source); err != nil {
		return false, err
	}
	return true, nil
}

// portalDownloadTurn is download_turn: one transfer at a time for one
// signed-in visitor. nil when this visitor already has one running.
func portalDownloadTurn(user string) (*os.File, error) {
	dir := filepath.Join(portalRoot(), ".downloads")
	if err := portalMkdir(dir); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, sha256Hex(user)), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, nil
		}
		return nil, err
	}
	return f, nil
}

func portalDefaults() *Map {
	return newMap("enabled", false, "language", "auto", "text", "", "files", []any{})
}

// portalLoad is _load.
func portalLoad(dir string) (*Map, error) {
	f, err := portalOpen(filepath.Join(dir, "settings.json"), os.O_RDONLY)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return portalDefaults(), nil
		}
		return nil, err
	}
	raw, err := io.ReadAll(f)
	f.Close()
	if err != nil {
		return nil, err
	}
	v, err := pyyaml.JSONLoads(raw)
	if err != nil {
		return nil, &ValueError{"Invalid portal settings"}
	}
	value, ok := asMap(v)
	if !ok {
		return nil, &ValueError{"Invalid portal settings"}
	}
	if _, ok := value.Value("files").([]any); !ok {
		return nil, &ValueError{"Invalid portal settings"}
	}
	if !has(value, "language") {
		value.Set("language", "auto")
	}
	if lang, ok := value.Value("language").(string); !ok || !portalLanguages[lang] {
		return nil, &ValueError{"Unsupported access-page language"}
	}
	return value, nil
}

func portalFiles(value *Map) []any {
	files, _ := value.Value("files").([]any)
	return files
}

// portalSave is _save: an atomic replacement, so readers carry on during an upload.
func portalSave(dir string, value *Map) error {
	text, err := PyJSON(value, JSONOpts{})
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".settings-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.WriteString(text); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, filepath.Join(dir, "settings.json"))
}

// portalText is _text.
func portalText(v any, limit int, label string) (string, error) {
	s, ok := v.(string)
	if !ok || pyLen(s) > limit || portalTextBadRe.MatchString(s) {
		return "", &ValueError{"Invalid " + label}
	}
	return pyStripSpace(s), nil
}

func portalRevision(value *Map) string {
	return sha256Hex(MustJSON(value, JSONOpts{SortKeys: true}))
}

func portalView(value *Map) *Map {
	out := copyMap(value)
	out.Set("revision", portalRevision(value))
	out.Set("max_file_bytes", int64(portalMaxFileBytes))
	out.Set("max_total_bytes", int64(portalMaxTotalBytes))
	out.Set("max_files", int64(portalMaxFiles))
	return out
}

// PortalSettings is settings.
func PortalSettings(site string) (*Map, error) {
	dir, err := portalDirectory(site)
	if err != nil {
		return nil, err
	}
	value, err := portalLoad(dir)
	if err != nil {
		return nil, err
	}
	return portalView(value), nil
}

func keySet(m *Map) map[string]bool {
	out := map[string]bool{}
	m.Each(func(k, _ any) {
		if s, ok := k.(string); ok {
			out[s] = true
		}
	})
	return out
}

func sameKeys(got map[string]bool, want ...string) bool {
	if len(got) != len(want) {
		return false
	}
	for _, k := range want {
		if !got[k] {
			return false
		}
	}
	return true
}

// PortalConfigure is configure; beforeSave runs under the site lock just
// before the settings are written.
func PortalConfigure(site string, payloadV any, beforeSave func(enabled bool) error) (*Map, error) {
	payload, ok := asMap(payloadV)
	keys := map[string]bool{}
	if ok {
		keys = keySet(payload)
		delete(keys, "language")
	}
	if !ok || !sameKeys(keys, "enabled", "text", "files", "revision") {
		return nil, &ValueError{"Invalid portal settings fields"}
	}
	enabled, isB := payload.Value("enabled").(bool)
	items, isList := payload.Value("files").([]any)
	if !isB || !isList || len(items) > portalMaxFiles {
		return nil, &ValueError{"Invalid portal settings"}
	}
	if has(payload, "language") {
		if lang, ok := payload.Value("language").(string); !ok || !portalLanguages[lang] {
			return nil, &ValueError{"Unsupported access-page language"}
		}
	}
	text, err := portalText(payload.Value("text"), 12000, "instructions")
	if err != nil {
		return nil, err
	}
	dir, release, err := portalLocked(site)
	if err != nil {
		return nil, err
	}
	defer release()
	old, err := portalLoad(dir)
	if err != nil {
		return nil, err
	}
	if rev, ok := payload.Value("revision").(string); !ok || rev != portalRevision(old) {
		return nil, &portalConflict{"Portal settings changed; reload before saving"}
	}
	existing := map[string]*Map{}
	for _, f := range portalFiles(old) {
		if m, ok := asMap(f); ok {
			existing[strOrEmpty(m.Value("id"))] = m
		}
	}
	files := []any{}
	seen := map[string]bool{}
	for _, raw := range items {
		item, ok := asMap(raw)
		var id string
		if ok {
			id, ok = item.Value("id").(string)
		}
		if !ok || !sameKeys(keySet(item), "id", "title", "description") || existing[id] == nil {
			return nil, &ValueError{"Invalid attachment settings"}
		}
		if seen[id] {
			return nil, &ValueError{"Duplicate attachment"}
		}
		title, err := portalText(item.Value("title"), 160, "attachment title")
		if err != nil {
			return nil, err
		}
		desc, err := portalText(item.Value("description"), 2000, "attachment description")
		if err != nil {
			return nil, err
		}
		entry := copyMap(existing[id])
		entry.Set("title", title)
		entry.Set("description", desc)
		files = append(files, entry)
		seen[id] = true
	}
	if len(seen) != len(existing) {
		return nil, &ValueError{"Use the delete button to remove attachments"}
	}
	lang := old.Value("language")
	if has(payload, "language") {
		lang = payload.Value("language")
	}
	value := newMap("enabled", enabled, "language", lang, "text", text, "files", files)
	if beforeSave != nil {
		if err := beforeSave(enabled); err != nil {
			return nil, err
		}
	}
	if err := portalSave(dir, value); err != nil {
		return nil, err
	}
	return portalView(value), nil
}

// PortalUpload is upload.
func PortalUpload(site, filename string, stream io.Reader) (*Map, error) {
	filename, err := portalText(filename, 180, "filename")
	if err != nil {
		return nil, err
	}
	if filename == "" || strings.ContainsAny(filename, `/\`) || portalNameBadRe.MatchString(filename) || filename == "." || filename == ".." {
		return nil, &ValueError{"Invalid filename"}
	}
	dir, release, err := portalLocked(site)
	if err != nil {
		return nil, err
	}
	defer release()
	value, err := portalLoad(dir)
	if err != nil {
		return nil, err
	}
	files := portalFiles(value)
	if len(files) >= portalMaxFiles {
		return nil, &ValueError{"Too many attachments"}
	}
	if _, err := PortalPurge(pyTimeNow()); err != nil {
		return nil, err
	}
	// Recover disk space after a worker was stopped mid-upload. The lock
	// guarantees these files belong to no active writer.
	registered := map[string]bool{}
	var used int64
	for _, f := range files {
		registered[strOrEmpty(get(f, "id"))+".bin"] = true
		used += pyIntOr0(get(f, "size"))
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		n := e.Name()
		if strings.HasSuffix(n, ".bin") && portalIDRe.MatchString(strings.TrimSuffix(n, ".bin")) && !registered[n] {
			if err := os.Remove(filepath.Join(dir, n)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
		}
	}
	remaining := min(int64(portalMaxFileBytes), portalMaxTotalBytes-used)
	identifier := uuidHex()
	target := filepath.Join(dir, identifier+".bin")
	out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*Map, error) {
		out.Close()
		os.Remove(target)
		return nil, err
	}
	var size int64
	digest := sha256.New()
	buf := make([]byte, 1024*1024)
	for {
		want := min(int64(len(buf)), max(1, remaining-size+1))
		n, rerr := stream.Read(buf[:want])
		if n > 0 {
			size += int64(n)
			if size > remaining {
				return fail(&ValueError{"Attachment storage limit exceeded"})
			}
			if _, err := out.Write(buf[:n]); err != nil {
				return fail(err)
			}
			digest.Write(buf[:n])
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return fail(rerr)
		}
	}
	if size == 0 {
		return fail(&ValueError{"The attachment is empty"})
	}
	if err := out.Sync(); err != nil {
		return fail(err)
	}
	if err := out.Close(); err != nil {
		os.Remove(target)
		return nil, err
	}
	value.Set("files", append(files, newMap("id", identifier, "filename", filename, "title", filename,
		"description", "", "size", size, "sha256", hex.EncodeToString(digest.Sum(nil)))))
	if err := portalSave(dir, value); err != nil {
		os.Remove(target)
		return nil, err
	}
	return portalView(value), nil
}

// PortalDelete is delete.
func PortalDelete(site, identifier string) (*Map, error) {
	if !portalIDRe.MatchString(identifier) {
		return nil, &ValueError{"Invalid attachment identifier"}
	}
	dir, release, err := portalLocked(site)
	if err != nil {
		return nil, err
	}
	defer release()
	value, err := portalLoad(dir)
	if err != nil {
		return nil, err
	}
	kept := []any{}
	for _, f := range portalFiles(value) {
		if !pyEqual(get(f, "id"), identifier) {
			kept = append(kept, f)
		}
	}
	value.Set("files", kept)
	if err := portalSave(dir, value); err != nil {
		return nil, err
	}
	if err := os.Remove(filepath.Join(dir, identifier+".bin")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return portalView(value), nil
}

// portalOpenDownload is open_download; a *portalNotFound for what is not offered.
func portalOpenDownload(site, identifier string) (*os.File, *Map, error) {
	if !portalIDRe.MatchString(identifier) {
		return nil, nil, &portalNotFound{"Attachment not found"}
	}
	dir, err := portalDirectory(site)
	if err != nil {
		return nil, nil, err
	}
	value, err := portalLoad(dir)
	if err != nil {
		return nil, nil, err
	}
	var item *Map
	for _, f := range portalFiles(value) {
		if m, ok := asMap(f); ok && pyEqual(m.Value("id"), identifier) {
			item = m
			break
		}
	}
	if value.Value("enabled") != true || item == nil {
		return nil, nil, &portalNotFound{"Attachment not found"}
	}
	f, err := portalOpen(filepath.Join(dir, identifier+".bin"), os.O_RDONLY)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, &portalNotFound{err.Error()}
		}
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err != nil || fi.Size() != pyIntOr0(item.Value("size")) {
		f.Close()
		if err != nil {
			return nil, nil, err
		}
		return nil, nil, &ValueError{"Attachment size mismatch"}
	}
	return f, item, nil
}

// The page and every download ask which site a host name belongs to; the
// answer is worked out once per version of the YAML files.
var (
	portalHostsMu sync.Mutex
	portalHosts   = map[string]portalHostsEntry{}
)

type fileSig struct {
	ino   uint64
	mtime int64
	size  int64
}

type portalHostsEntry struct {
	key   [2]*fileSig
	hosts map[string]*Map
}

func signatureOf(path string) *fileSig {
	fi, err := os.Stat(path)
	if err != nil {
		return nil
	}
	sig := &fileSig{mtime: fi.ModTime().UnixNano(), size: fi.Size()}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		sig.ino = uint64(st.Ino)
	}
	return sig
}

func sameSig(a, b *fileSig) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// iterNames is iteration over a YAML value the way a Python for loop sees it.
func iterNames(v any) []any {
	switch x := v.(type) {
	case []any:
		return x
	case string:
		out := []any{}
		for _, r := range x {
			out = append(out, string(r))
		}
		return out
	case *Map:
		out := []any{}
		x.Each(func(k, _ any) { out = append(out, k) })
		return out
	}
	return nil
}

// portalGateHosts is _gate_hosts: host name -> site for the enabled access-gate sites.
func portalGateHosts(websites, variables string) (map[string]*Map, error) {
	data, err := loadYAML(websites)
	if err != nil {
		return nil, err
	}
	vars, err := loadYAML(variables)
	if err != nil {
		return nil, err
	}
	defaults, _ := asMap(vars.Value("site_defaults"))
	hosts := map[string]*Map{}
	sites, _ := data.Value("sites").([]any)
	for _, s := range sites {
		site, ok := asMap(s)
		if !ok {
			continue
		}
		effective := pyyaml.NewMap()
		if defaults != nil {
			defaults.Each(func(k, v any) { effective.Set(k, v) })
		}
		site.Each(func(k, v any) { effective.Set(k, v) })
		if effective.Value("access_gate") != true {
			continue
		}
		if e, has := effective.Get("enabled"); has && e == false {
			continue
		}
		names := append([]any{site.Value("domain")}, iterNames(orValue(site.Value("alt_names"), []any{}))...)
		for _, n := range names {
			if s, ok := n.(string); ok && s != "" {
				if _, taken := hosts[strings.ToLower(s)]; !taken {
					hosts[strings.ToLower(s)] = site
				}
			}
		}
	}
	return hosts, nil
}

func portalHostsOf(websites, variables string) (map[string]*Map, error) {
	key := [2]*fileSig{signatureOf(websites), signatureOf(variables)}
	if key[0] == nil {
		return portalGateHosts(websites, variables)
	}
	portalHostsMu.Lock()
	defer portalHostsMu.Unlock()
	if kept, ok := portalHosts[websites]; ok && sameSig(kept.key[0], key[0]) && sameSig(kept.key[1], key[1]) {
		return kept.hosts, nil
	}
	hosts, err := portalGateHosts(websites, variables)
	if err != nil {
		return nil, err
	}
	portalHosts[websites] = portalHostsEntry{key: key, hosts: hosts}
	return hosts, nil
}

// portalSiteByHost is site_by_host: what HAProxy routes is the applied
// configuration; the draft answers for a gateway with no applied copy yet.
func portalSiteByHost(host string) (*Map, error) {
	hostname, err := validateDomain(host, "domain", false)
	if err != nil {
		return nil, &ValueError{err.Error()}
	}
	hostname = strings.ToLower(hostname)
	for _, pair := range [][2]string{{StateWebsites, StateVars}, {WebsitesYAML, ConfigYAML}} {
		hosts, err := portalHostsOf(pair[0], pair[1])
		if err != nil {
			return nil, err
		}
		if site := hosts[hostname]; site != nil {
			return copyMap(site), nil
		}
	}
	return nil, &portalNotFound{"Access page not found"}
}

func init() {
	accessPortalDiscard = func(name string) (string, error) { return PortalDiscard(name, pyTimeNow()) }
	accessPortalRestore = PortalRestore
	accessPortalForget = func(name, page string) error {
		_, err := PortalForget(name, page)
		return err
	}
}
