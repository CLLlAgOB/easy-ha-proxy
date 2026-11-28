package haproxymigrate

import (
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/haproxypkg"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
)

// PackageRecord identifies an authenticated or downloaded Debian package.
type PackageRecord struct {
	Package string `json:"Package"`
	Version string `json:"Version"`
	SHA256  string `json:"SHA256"`
}

// FileBackup tracks a managed host file backed up before mutation.
type FileBackup struct {
	Exists bool   `json:"exists"`
	File   string `json:"file,omitempty"`
	Digest string `json:"digest,omitempty"`
	Mode   uint32 `json:"mode,omitempty"`
	UID    int    `json:"uid,omitempty"`
	GID    int    `json:"gid,omitempty"`
}

// Engine executes HAProxy provider migrations, in-branch patches, rollbacks and recovery.
type Engine struct {
	Paths     Paths
	Host      Host
	State     map[string]any
	Directory string
	Patch     bool
	Observer  func(summary map[string]any)
	Vendor    string
	KeyURL    string
	platform  haproxypkg.Platform

	lockDepth int
	// Optional test/smoke hooks
	HealthHook       func() error
	BeforeChangeHook func() error
}

// NewEngine creates an Engine with default production paths, SystemHost, and vendor URLs.
func NewEngine(paths *Paths, host Host) *Engine {
	p := DefaultPaths()
	if paths != nil {
		p = *paths
	}
	if host == nil {
		host = &SystemHost{}
	}
	return &Engine{
		Paths:  p,
		Host:   host,
		State:  map[string]any{},
		KeyURL: DefaultKeyURL,
	}
}

func randomHex32() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (e *Engine) withLock(fn func() error) error {
	if e.lockDepth > 0 {
		return fn()
	}
	if err := os.MkdirAll(filepath.Dir(e.Paths.Lock), 0o755); err != nil {
		return err
	}
	fd, err := unix.Open(e.Paths.Lock, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if (requireRootOwner && st.Uid != 0) || (st.Mode&unix.S_IFMT) != unix.S_IFREG {
		return migErr("Unsafe maintenance lock")
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return migErr("Another maintenance operation is running")
		}
		return err
	}
	e.lockDepth++
	defer func() { e.lockDepth-- }()
	return fn()
}

func (e *Engine) save(phase string) error {
	if phase != "" {
		e.State["phase"] = phase
	}
	e.State["updated_at"] = unixNowFloat()
	raw, err := json.MarshalIndent(e.State, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(e.Directory, "transaction.json"), append(raw, '\n'), 0o600, 0, 0); err != nil {
		return err
	}
	kind := strVal(e.State["kind"])
	if kind == "patch" {
		sumRaw, _ := json.Marshal(e.Summary())
		if err := atomicWrite(filepath.Join(e.Paths.Root, "last-update.json"), append(sumRaw, '\n'), 0o600, 0, 0); err != nil {
			return err
		}
	} else if kind == "migration" {
		sumRaw, _ := json.Marshal(e.Summary())
		if err := atomicWrite(filepath.Join(e.Paths.Root, "last-migration.json"), append(sumRaw, '\n'), 0o600, 0, 0); err != nil {
			return err
		}
	}
	if e.Observer != nil {
		e.Observer(e.Summary())
	}
	return nil
}

func (e *Engine) load(identifier string) error {
	if !hex32Re.MatchString(identifier) {
		return migErr("Invalid migration id")
	}
	if err := privateDir(e.Paths.Root); err != nil {
		return err
	}
	e.Directory = filepath.Join(e.Paths.Root, identifier)
	dinfo, err := os.Lstat(e.Directory)
	if err != nil {
		return err
	}
	dst, ok := dinfo.Sys().(*syscall.Stat_t)
	if !ok || !dinfo.IsDir() || (requireRootOwner && dst.Uid != 0) || dinfo.Mode().Perm()&0o077 != 0 {
		return migErr("Unsafe transaction directory")
	}
	jpath := filepath.Join(e.Directory, "transaction.json")
	jinfo, err := os.Lstat(jpath)
	if err != nil {
		return err
	}
	jst, ok := jinfo.Sys().(*syscall.Stat_t)
	if !ok || !jinfo.Mode().IsRegular() || (requireRootOwner && jst.Uid != 0) || jinfo.Mode().Perm()&0o077 != 0 {
		return migErr("Unsafe transaction journal")
	}
	raw, err := os.ReadFile(jpath)
	if err != nil {
		return err
	}
	var st map[string]any
	if err := json.Unmarshal(raw, &st); err != nil {
		return err
	}
	e.State = st
	e.Patch = strVal(st["kind"]) == "patch"
	if intVal(st["format"]) != 1 || strVal(st["id"]) != identifier {
		return migErr("Invalid transaction journal")
	}
	mach, err := e.Host.Machine()
	if err != nil {
		return err
	}
	if strVal(st["machine"]) != mach {
		return migErr("The transaction belongs to a different machine")
	}
	e.Host.SetLog(filepath.Join(e.Directory, "commands.jsonl"))
	return nil
}

func (e *Engine) filesMap() map[string]any {
	m, ok := e.State["files"].(map[string]any)
	if !ok || m == nil {
		m = map[string]any{}
		e.State["files"] = m
	}
	return m
}

func (e *Engine) fileRecord(p string) map[string]any {
	m, _ := e.filesMap()[p].(map[string]any)
	return m
}

func (e *Engine) backup(path string) error {
	files := e.filesMap()
	if _, exists := files[path]; exists {
		return nil
	}
	if !lexists(path) {
		files[path] = map[string]any{"exists": false}
		return nil
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || (requireRootOwner && st.Uid != 0) {
		return migErr("Managed migration files must be regular root-owned files: %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	name := "saved-" + bytesDigest([]byte(path))
	if err := atomicWrite(filepath.Join(e.Directory, name), data, 0o600, 0, 0); err != nil {
		return err
	}
	files[path] = map[string]any{
		"exists": true,
		"file":   name,
		"digest": bytesDigest(data),
		"mode":   int(info.Mode().Perm()),
		"uid":    int(st.Uid),
		"gid":    int(st.Gid),
	}
	return nil
}

func (e *Engine) original(path string) ([]byte, error) {
	rec := e.fileRecord(path)
	if rec == nil || rec["exists"] != true {
		return nil, nil
	}
	saved := filepath.Join(e.Directory, strVal(rec["file"]))
	d, err := fileDigest(saved)
	if err != nil || d != strVal(rec["digest"]) {
		return nil, migErr("Backup integrity check failed")
	}
	return os.ReadFile(saved)
}

func (e *Engine) restore(path string) error {
	rec := e.fileRecord(path)
	if rec == nil {
		return migErr("Missing backup record for %s", path)
	}
	if isSymlink(path) {
		return migErr("Refusing to replace an unexpected symlink")
	}
	if lexists(path) {
		cur, err := fileDigest(path)
		if err != nil {
			return err
		}
		written, _ := e.State["written_files"].(map[string]any)
		origDig := strVal(rec["digest"])
		writDig := strVal(written[path])
		if cur != origDig && cur != writDig {
			return migErr("A managed file changed outside this operation: %s", path)
		}
	}
	if rec["exists"] == true {
		data, err := e.original(path)
		if err != nil {
			return err
		}
		mode := os.FileMode(intVal(rec["mode"]))
		if mode == 0 {
			mode = 0o600
		}
		return atomicWrite(path, data, mode, intVal(rec["uid"]), intVal(rec["gid"]))
	}
	if lexists(path) {
		if !isRegularFile(path) || isSymlink(path) {
			return migErr("Refusing to remove an unexpected migration file")
		}
		return os.Remove(path)
	}
	return nil
}

func (e *Engine) put(path string, data []byte, mode os.FileMode, uid, gid int) error {
	if isSymlink(path) {
		return migErr("Refusing to replace a managed symlink")
	}
	written, ok := e.State["written_files"].(map[string]any)
	if !ok || written == nil {
		written = map[string]any{}
		e.State["written_files"] = written
	}
	written[path] = bytesDigest(data)
	if err := e.save(""); err != nil {
		return err
	}
	return atomicWrite(path, data, mode, uid, gid)
}

func (e *Engine) unchanged(path string) error {
	rec := e.fileRecord(path)
	if rec == nil {
		return migErr("Managed configuration changed after preparation: %s", path)
	}
	wantExists := rec["exists"] == true
	existsNow := lexists(path)
	if wantExists != existsNow || isSymlink(path) {
		return migErr("Managed configuration changed after preparation: %s", path)
	}
	if wantExists {
		d, err := fileDigest(path)
		if err != nil || d != strVal(rec["digest"]) {
			return migErr("Managed configuration changed after preparation: %s", path)
		}
	}
	return nil
}

func (e *Engine) download(rawURL, destination, expected string, limit int64) error {
	if limit <= 0 {
		limit = 64 * 1024 * 1024
	}
	var src io.ReadCloser
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	if u.Scheme == "file" {
		f, err := os.Open(u.Path)
		if err != nil {
			return err
		}
		src = f
	} else {
		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Get(rawURL)
		if err != nil {
			return err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			_ = resp.Body.Close()
			return migErr("Repository download failed (%d): %s", resp.StatusCode, rawURL)
		}
		src = resp.Body
	}
	defer src.Close()

	temp := destination + ".part"
	out, err := os.OpenFile(temp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(temp)
		}
	}()
	n, err := io.Copy(out, io.LimitReader(src, limit+1))
	if err != nil {
		_ = out.Close()
		return err
	}
	if n > limit {
		_ = out.Close()
		return migErr("Repository object exceeds the size limit")
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	if err := os.Chmod(temp, 0o600); err != nil {
		return err
	}
	if expected != "" {
		d, err := fileDigest(temp)
		if err != nil || d != expected {
			return migErr("Repository object checksum mismatch")
		}
	}
	if err := os.Rename(temp, destination); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func (e *Engine) authenticatedPackages(architecture string) ([]PackageRecord, error) {
	vendor := e.platform.Repository() + "/"
	if e.Vendor != "" {
		vendor = e.Vendor
	}
	distribution := vendor + "dists/" + e.platform.Codename + "/"
	defaultsRaw, err := os.ReadFile(filepath.Join(e.Paths.Source, "ansible/roles/haproxy/defaults/main.yml"))
	if err != nil {
		return nil, err
	}
	var defaults map[string]any
	if err := yaml.Unmarshal(defaultsRaw, &defaults); err != nil {
		return nil, err
	}
	signingDigest := strVal(defaults["haproxy_community_key_sha256"])
	if !hex64Re.MatchString(signingDigest) {
		return nil, migErr("Invalid configured signing-key checksum")
	}
	ascPath := filepath.Join(e.Directory, "repository.asc")
	if err := e.download(e.KeyURL, ascPath, signingDigest, 64*1024*1024); err != nil {
		return nil, err
	}
	home := filepath.Join(e.Directory, "gnupg")
	if err := privateDir(home); err != nil {
		return nil, err
	}
	gpgPath := filepath.Join(e.Directory, "repository.gpg")
	if _, err := e.Host.Command([]string{
		"/usr/bin/gpg", "--homedir", home, "--no-options", "--batch", "--dearmor",
		"--output", gpgPath, ascPath,
	}, CmdOpts{Check: true}); err != nil {
		return nil, err
	}
	inRelPath := filepath.Join(e.Directory, "InRelease")
	if err := e.download(distribution+"InRelease", inRelPath, "", 1024*1024); err != nil {
		return nil, err
	}
	relPath := filepath.Join(e.Directory, "Release")
	if _, err := e.Host.Command([]string{
		"/usr/bin/gpgv", "--homedir", home, "--keyring", gpgPath,
		"--output", relPath, inRelPath,
	}, CmdOpts{Check: true}); err != nil {
		return nil, err
	}
	relRaw, err := os.ReadFile(relPath)
	if err != nil {
		return nil, err
	}
	release := string(relRaw)
	paras := ParseParagraphs(release)
	if len(paras) == 0 {
		return nil, migErr("Repository metadata is empty")
	}
	fields := paras[0]
	if fields["Codename"] != e.platform.Codename {
		return nil, migErr("Signed repository codename does not match the host")
	}
	published, err := mail.ParseDate(fields["Date"])
	if err != nil {
		return nil, migErr("Repository metadata date is unreadable")
	}
	now := nowFunc()
	if published.After(now.Add(time.Hour)) || published.Before(now.Add(-60*24*time.Hour)) {
		return nil, migErr("Repository metadata is too old or dated in the future")
	}
	if validUntil := fields["Valid-Until"]; validUntil != "" {
		vu, err := mail.ParseDate(validUntil)
		if err != nil || vu.Before(now) {
			return nil, migErr("Repository metadata expired")
		}
	}
	relative := "main/binary-" + architecture + "/Packages.gz"
	idxRe := regexp.MustCompile(`(?m)^ ([0-9a-f]{64})\s+[0-9]+\s+` + regexp.QuoteMeta(relative) + `\s*$`)
	matches := idxRe.FindAllStringSubmatch(release, -1)
	if len(matches) != 1 {
		return nil, migErr("Signed repository metadata has no unique architecture index")
	}
	pkgGzPath := filepath.Join(e.Directory, "Packages.gz")
	if err := e.download(distribution+relative, pkgGzPath, matches[0][1], 64*1024*1024); err != nil {
		return nil, err
	}
	gzFile, err := os.Open(pkgGzPath)
	if err != nil {
		return nil, err
	}
	defer gzFile.Close()
	gzr, err := gzip.NewReader(gzFile)
	if err != nil {
		return nil, err
	}
	defer gzr.Close()
	idxBytes, err := io.ReadAll(io.LimitReader(gzr, 8*1024*1024+1))
	if err != nil {
		return nil, err
	}
	if len(idxBytes) > 8*1024*1024 {
		return nil, migErr("Package index is unexpectedly large")
	}
	records := ParseParagraphs(string(idxBytes))
	var candidates []map[string]string
	for _, r := range records {
		if r["Package"] == "haproxy-awslc" && r["Architecture"] == architecture && strings.HasPrefix(r["Version"], e.platform.Target+".") {
			candidates = append(candidates, r)
		}
	}
	if len(candidates) == 0 {
		return nil, migErr("No HAProxy %s package for this architecture", e.platform.Target)
	}
	target := candidates[0]
	for _, cand := range candidates[1:] {
		res, err := e.Host.Command([]string{"/usr/bin/dpkg", "--compare-versions", cand["Version"], "gt", target["Version"]}, CmdOpts{Check: false})
		if err == nil && res.Code == 0 {
			target = cand
		}
	}
	depRe := regexp.MustCompile(`libssl-awslc \(= ([^()]+)\)`)
	depMatch := depRe.FindStringSubmatch(target["Depends"])
	if depMatch == nil {
		return nil, migErr("Unqualified TLS dependency layout")
	}
	var libraries []map[string]string
	for _, r := range records {
		if r["Package"] == "libssl-awslc" && r["Architecture"] == architecture && r["Version"] == depMatch[1] {
			libraries = append(libraries, r)
		}
	}
	if len(libraries) != 1 {
		return nil, migErr("The exact TLS dependency is missing")
	}
	var result []PackageRecord
	for _, pkg := range []map[string]string{target, libraries[0]} {
		fn := pkg["Filename"]
		if !poolDebRe.MatchString(fn) || strings.Contains(fn, "..") {
			return nil, migErr("Invalid signed package filename")
		}
		dest := filepath.Join(e.Directory, pkg["Package"]+".deb")
		if err := e.download(vendor+fn, dest, pkg["SHA256"], 64*1024*1024); err != nil {
			return nil, err
		}
		if err := e.checkDeb(dest, pkg["Package"], pkg["Version"], architecture); err != nil {
			return nil, err
		}
		result = append(result, PackageRecord{Package: pkg["Package"], Version: pkg["Version"], SHA256: pkg["SHA256"]})
	}
	return result, nil
}

func (e *Engine) checkDeb(path, pkg, version, architecture string) error {
	res, err := e.Host.Command([]string{"/usr/bin/dpkg-deb", "-f", path, "Package", "Version", "Architecture"}, CmdOpts{Check: true})
	if err != nil {
		return err
	}
	parsed := map[string]string{}
	for _, line := range strings.Split(res.Stdout, "\n") {
		if k, v, ok := strings.Cut(line, ": "); ok {
			parsed[k] = v
		}
	}
	if parsed["Package"] != pkg || parsed["Version"] != version || parsed["Architecture"] != architecture || len(parsed) != 3 {
		return migErr("Package identity does not match the authenticated index")
	}
	return nil
}

func (e *Engine) nativePreflight() (string, map[string]string, error) {
	archRes, err := e.Host.Command([]string{"/usr/bin/dpkg", "--print-architecture"}, CmdOpts{Check: true})
	if err != nil {
		return "", nil, err
	}
	architecture := strings.TrimSpace(archRes.Stdout)
	e.platform = haproxypkg.ReadPlatform(osReleasePath, architecture)
	if e.platform.Target == "" {
		return "", nil, migErr("HAProxy migration requires %s", haproxypkg.SupportedHosts)
	}
	auditRes, err := e.Host.Command([]string{"/usr/bin/dpkg", "--audit"}, CmdOpts{Check: true})
	if err != nil {
		return "", nil, err
	}
	if strings.TrimSpace(auditRes.Stdout) != "" {
		return "", nil, migErr("Resolve unfinished package operations before migration")
	}
	packages, err := e.Host.Packages()
	if err != nil {
		return "", nil, err
	}
	name := "haproxy"
	if e.Patch && packages["haproxy-awslc"] != "" {
		name = "haproxy-awslc"
	}
	branch := e.platform.Baseline
	if name == "haproxy-awslc" {
		branch = e.platform.Target
	}
	if !strings.HasPrefix(packages[name], branch+".") {
		return "", nil, migErr("Preparation requires the qualified %s %s package", name, branch)
	}
	if !e.Patch && packages["haproxy-awslc"] != "" {
		return "", nil, migErr("A provider migration must start on distribution HAProxy %s", e.platform.Baseline)
	}
	if !e.Host.Active("haproxy.service") || !e.Host.Active("haproxy-controld.service") {
		return "", nil, migErr("HAProxy and its control service must be healthy before preparation")
	}
	active, err := runtimeInfoFunc(e.Paths.Socket)
	if err != nil {
		return "", nil, err
	}
	verRes, err := e.Host.Command([]string{e.Paths.Binary, "-v"}, CmdOpts{Check: true})
	if err != nil {
		return "", nil, err
	}
	bm := haproxyVerRe.FindStringSubmatch(verRes.Stdout)
	if bm == nil || active["Version"] != bm[1] {
		return "", nil, migErr("Running and installed HAProxy versions differ")
	}
	wd, err := e.Host.WorkerDigest(active["Pid"])
	if err != nil {
		return "", nil, err
	}
	bd, err := fileDigest(e.Paths.Binary)
	if err != nil || wd != bd {
		return "", nil, migErr("Running and installed HAProxy versions differ")
	}
	varsRaw, err := os.ReadFile(e.Paths.Variables)
	if err != nil {
		return "", nil, err
	}
	var variables map[string]any
	if err := yaml.Unmarshal(varsRaw, &variables); err != nil || variables == nil {
		return "", nil, migErr("Installer provider and installed package differ")
	}
	provider := "distribution"
	if name == "haproxy-awslc" {
		provider = "haproxy-technologies"
	}
	gotProvider := strVal(variables["haproxy_package_provider"])
	if gotProvider == "" {
		gotProvider = "distribution"
	}
	if gotProvider != provider {
		return "", nil, migErr("Installer provider and installed package differ")
	}
	cfgRaw, err := os.ReadFile(e.Paths.Config)
	if err != nil {
		return "", nil, err
	}
	cfgText := string(cfgRaw)
	ssRe := regexp.MustCompile(`(?m)^\s+server-state-file ` + regexp.QuoteMeta(e.Paths.ServerState) + `\s*$`)
	if !ssRe.MatchString(cfgText) {
		return "", nil, migErr("The qualified server-state file must be enabled")
	}
	if !strings.Contains(cfgText, "load-server-state-from-file global") {
		return "", nil, migErr("Administrative server-state loading must be enabled")
	}
	memRaw, err := os.ReadFile(memInfoPath)
	if err != nil {
		return "", nil, err
	}
	mm := memAvailRe.FindStringSubmatch(string(memRaw))
	if mm == nil {
		return "", nil, migErr("At least 384 MiB of available RAM is required for the temporary handoff")
	}
	availKB, _ := strconv.Atoi(mm[1])
	if availKB < 384*1024 {
		return "", nil, migErr("At least 384 MiB of available RAM is required for the temporary handoff")
	}
	return architecture, packages, nil
}

func (e *Engine) checkPreviousOperations() error {
	settled := map[string]bool{"committed": true, "rolled_back": true, "aborted": true, "preparing": true, "prepared": true}
	for _, name := range []string{"last-update.json", "last-migration.json"} {
		prev := filepath.Join(e.Paths.Root, name)
		if !lexists(prev) {
			continue
		}
		info, err := os.Lstat(prev)
		if err != nil || !info.Mode().IsRegular() || info.Size() > 64*1024 {
			return migErr("Unsafe previous HAProxy update record")
		}
		raw, err := os.ReadFile(prev)
		if err != nil {
			return migErr("The previous HAProxy update record is unreadable")
		}
		var op map[string]any
		if err := json.Unmarshal(raw, &op); err != nil || op == nil {
			return migErr("The previous HAProxy update record is unreadable")
		}
		if !settled[strVal(op["phase"])] {
			return migErr("Recover the unfinished HAProxy update before preparing another one")
		}
	}
	return nil
}

func (e *Engine) inspectServiceDropins() (map[string]string, error) {
	result := map[string]string{}
	visited := map[string]bool{}
	for _, dir := range serviceDropinDirs {
		resolved, err := filepath.EvalSymlinks(dir)
		if err != nil {
			resolved = dir
		}
		if visited[resolved] {
			continue
		}
		visited[resolved] = true
		matches, _ := filepath.Glob(filepath.Join(dir, "*.conf"))
		sort.Strings(matches)
		for _, dropin := range matches {
			info, err := os.Lstat(dropin)
			if err != nil {
				return nil, err
			}
			st, ok := info.Sys().(*syscall.Stat_t)
			raw, rerr := os.ReadFile(dropin)
			if !ok || !info.Mode().IsRegular() || (requireRootOwner && st.Uid != 0) || info.Mode().Perm()&0o022 != 0 ||
				rerr != nil || !QualifiedServiceDropin(string(raw), e.Paths.Config) {
				return nil, migErr("Custom HAProxy execution overrides require a separate qualification: %s", filepath.Base(dropin))
			}
			result[dropin] = bytesDigest(raw)
		}
	}
	return result, nil
}

func (e *Engine) unchangedServiceDropins() error {
	raw, ok := e.State["service_dropins"]
	if !ok {
		return nil
	}
	expected := map[string]string{}
	switch m := raw.(type) {
	case map[string]string:
		expected = m
	case map[string]any:
		for k, v := range m {
			expected[k] = strVal(v)
		}
	}
	current, err := e.inspectServiceDropins()
	if err != nil {
		return err
	}
	if len(current) != len(expected) {
		return migErr("HAProxy service overrides changed after preparation; prepare a new transaction")
	}
	for k, v := range expected {
		if current[k] != v {
			return migErr("HAProxy service overrides changed after preparation; prepare a new transaction")
		}
	}
	return nil
}

func (e *Engine) holds() (map[string]bool, error) {
	res, err := e.Host.Command([]string{"/usr/bin/dpkg", "--get-selections"}, CmdOpts{Check: true})
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, line := range strings.Split(res.Stdout, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == "hold" {
			name, _, _ := strings.Cut(fields[0], ":")
			out[name] = true
		}
	}
	return out, nil
}

func (e *Engine) restoreHolds(rollback bool) error {
	installed, err := e.Host.Packages()
	if err != nil {
		return err
	}
	savedHolds := map[string]bool{}
	for _, item := range strSlice(e.State["holds"]) {
		savedHolds[item] = true
	}
	for _, name := range []string{"haproxy", "haproxy-awslc", "libssl-awslc"} {
		if installed[name] != "" {
			action := "hold"
			if rollback && !savedHolds[name] {
				action = "unhold"
			}
			if _, err := e.Host.Command([]string{"/usr/bin/apt-mark", action, name}, CmdOpts{Check: true}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (e *Engine) inspectBaseline() error {
	target := filepath.Join(e.Directory, "baseline")
	if _, err := e.Host.Command([]string{"/usr/bin/dpkg-deb", "-x", filepath.Join(e.Directory, "haproxy-old.deb"), target}, CmdOpts{Check: true}); err != nil {
		return err
	}
	defer os.RemoveAll(target)
	packaged := filepath.Join(target, "usr/lib/systemd/system/haproxy.service")
	if !lexists(packaged) {
		packaged = filepath.Join(target, "lib/systemd/system/haproxy.service")
	}
	installed := haproxyUsrUnit
	if !lexists(installed) {
		installed = haproxyLibUnit
	}
	dPkgBin, err := fileDigest(filepath.Join(target, "usr/sbin/haproxy"))
	if err != nil {
		return err
	}
	dLiveBin, err := fileDigest(e.Paths.Binary)
	if err != nil || dPkgBin != dLiveBin {
		return migErr("The installed binary differs from the exact rollback package")
	}
	dInstUnit, err1 := fileDigest(installed)
	dPkgUnit, err2 := fileDigest(packaged)
	if lexists(haproxyEtcUnit) || err1 != nil || err2 != nil || dInstUnit != dPkgUnit {
		return migErr("Custom HAProxy service units require a separate qualification")
	}
	dropins, err := e.inspectServiceDropins()
	if err != nil {
		return err
	}
	e.State["service_dropins"] = dropins
	control := filepath.Join(e.Directory, "baseline-control")
	if _, err := e.Host.Command([]string{"/usr/bin/dpkg-deb", "-e", filepath.Join(e.Directory, "haproxy-old.deb"), control}, CmdOpts{Check: true}); err != nil {
		return err
	}
	for _, script := range []string{"preinst", "postinst", "prerm", "postrm"} {
		p := filepath.Join(control, script)
		if raw, err := os.ReadFile(p); err == nil && systemctlBadRe.Match(raw) {
			return migErr("Baseline package actions bypass policy-rc.d")
		}
	}
	return nil
}

func (e *Engine) downloadExact(pkg, version, destination string) (PackageRecord, error) {
	temp := filepath.Join(e.Directory, "old-download-"+pkg)
	if err := privateDir(temp); err != nil {
		return PackageRecord{}, err
	}
	_, dlErr := e.Host.Command([]string{
		"/usr/bin/apt-get", "-o", "APT::Get::AllowUnauthenticated=false",
		"download", pkg + "=" + version,
	}, CmdOpts{Cwd: temp, Check: true})
	if dlErr == nil {
		matches, _ := filepath.Glob(filepath.Join(temp, "*.deb"))
		if len(matches) != 1 {
			dlErr = migErr("Exact rollback package download is missing")
		} else if err := os.Rename(matches[0], destination); err != nil {
			dlErr = err
		}
	}
	if dlErr != nil {
		found := false
		entries, _ := os.ReadDir(e.Paths.Root)
		for _, entry := range entries {
			if !hex32Re.MatchString(entry.Name()) {
				continue
			}
			folder := filepath.Join(e.Paths.Root, entry.Name())
			if isSymlink(folder) {
				continue
			}
			journal := filepath.Join(folder, "transaction.json")
			jinfo, err := os.Lstat(journal)
			if err != nil {
				continue
			}
			jst, ok := jinfo.Sys().(*syscall.Stat_t)
			if !ok || !jinfo.Mode().IsRegular() || (requireRootOwner && jst.Uid != 0) || jinfo.Mode().Perm()&0o077 != 0 {
				continue
			}
			raw, err := os.ReadFile(journal)
			if err != nil {
				continue
			}
			var prev map[string]any
			if err := json.Unmarshal(raw, &prev); err != nil {
				continue
			}
			for _, rec := range pkgRecords(prev["target_packages"]) {
				archive := filepath.Join(folder, pkg+".deb")
				if rec.Package == pkg && rec.Version == version && isRegularFile(archive) {
					if d, err := fileDigest(archive); err == nil && d == rec.SHA256 {
						if b, err := os.ReadFile(archive); err == nil {
							if err := os.WriteFile(destination, b, 0o600); err == nil {
								found = true
								break
							}
						}
					}
				}
			}
			if found {
				break
			}
		}
		if !found {
			return PackageRecord{}, migErr("The exact rollback archive is unavailable: %s", pkg)
		}
	}
	if err := e.checkDeb(destination, pkg, version, strVal(e.State["architecture"])); err != nil {
		return PackageRecord{}, err
	}
	d, err := fileDigest(destination)
	if err != nil {
		return PackageRecord{}, err
	}
	return PackageRecord{Package: pkg, Version: version, SHA256: d}, nil
}

func (e *Engine) packageCommand(simulate, rollback bool) []string {
	cmd := []string{
		"/usr/bin/apt-get", "--no-install-recommends", "-o", "Dpkg::Options::=--force-confold",
		"-o", "Dir::Cache::archives=" + filepath.Join(e.Directory, "archives"),
		"--allow-change-held-packages", "--allow-downgrades",
	}
	if simulate {
		cmd = append(cmd, "--simulate")
	} else {
		cmd = append(cmd, "--yes", "--no-download")
	}
	cmd = append(cmd, "install")
	if rollback {
		cmd = append(cmd, "--reinstall", filepath.Join(e.Directory, "haproxy-old.deb"))
		if e.Patch && e.State["old_tls"] != nil {
			cmd = append(cmd, filepath.Join(e.Directory, "tls-old.deb"))
		}
		var remove []string
		if !e.Patch {
			remove = append(remove, "haproxy-awslc")
		}
		if e.State["tls_was_installed"] != true {
			remove = append(remove, "libssl-awslc")
		}
		for _, pkg := range pkgRecords(e.State["extra_packages"]) {
			remove = append(remove, pkg.Package)
		}
		for _, pkg := range remove {
			res, err := e.Host.Command([]string{"/usr/bin/dpkg-query", "-W", "-f=${db:Status-Status}", pkg}, CmdOpts{Check: false})
			if err == nil && res.Code == 0 && strings.TrimSpace(res.Stdout) != "not-installed" {
				cmd = append(cmd, pkg+"-")
			}
		}
	} else {
		if e.Patch {
			cmd = append(cmd, "--reinstall")
		} else {
			cmd = append(cmd, "haproxy-")
		}
		for _, pkg := range append(pkgRecords(e.State["target_packages"]), pkgRecords(e.State["extra_packages"])...) {
			cmd = append(cmd, filepath.Join(e.Directory, pkg.Package+".deb"))
		}
	}
	return cmd
}

func (e *Engine) inspectTarget() error {
	target := filepath.Join(e.Directory, "target")
	unit := filepath.Join(target, "usr/lib/systemd/system/haproxy.service")
	if !lexists(unit) {
		unit = filepath.Join(target, "lib/systemd/system/haproxy.service")
	}
	unitRaw, err := os.ReadFile(unit)
	if err != nil {
		return err
	}
	unitText := string(unitRaw)
	if !strings.Contains(unitText, "ExecReload=/bin/kill -USR2 $MAINPID") ||
		!strings.Contains(unitText, "ExecStart=/usr/sbin/haproxy -Ws ") ||
		!strings.Contains(unitText, "Type=notify") {
		return migErr("The package changed its service contract")
	}
	if entries, err := os.ReadDir(haproxyConfD); err == nil && len(entries) > 0 {
		return migErr("The new service would load an existing conf.d directory")
	}
	e.State["unit_digest"] = bytesDigest(unitRaw)
	tbinDig, err := fileDigest(filepath.Join(target, "usr/sbin/haproxy"))
	if err != nil {
		return err
	}
	e.State["target_binary_digest"] = tbinDig
	control := filepath.Join(e.Directory, "target-control")
	targets := pkgRecords(e.State["target_packages"])
	if len(targets) == 0 {
		return migErr("Missing target packages")
	}
	name := targets[0].Package
	if _, err := e.Host.Command([]string{"/usr/bin/dpkg-deb", "-e", filepath.Join(e.Directory, name+".deb"), control}, CmdOpts{Check: true}); err != nil {
		return err
	}
	for _, script := range []string{"preinst", "postinst", "prerm", "postrm"} {
		p := filepath.Join(control, script)
		if raw, err := os.ReadFile(p); err == nil && systemctlBadRe.Match(raw) {
			return migErr("Package service actions bypass policy-rc.d; review the package")
		}
	}
	libDirs := collectLibDirs(target)
	if len(libDirs) == 0 && name == "haproxy-awslc" {
		return migErr("The private TLS library is missing")
	}
	envExtra := map[string]string{"LD_LIBRARY_PATH": strings.Join(libDirs, ":")}
	verRes, err := e.Host.Command([]string{filepath.Join(target, "usr/sbin/haproxy"), "-v"}, CmdOpts{Check: true, EnvExtra: envExtra})
	if err != nil {
		return err
	}
	m := haproxyVerRe.FindStringSubmatch(verRes.Stdout)
	wantBranch := strVal(e.State["target_branch"])
	if wantBranch == "" {
		wantBranch = "3.4"
	}
	if m == nil || !strings.HasPrefix(m[1], wantBranch+".") {
		return migErr("The private target binary has an unexpected version")
	}
	e.State["target_runtime_version"] = m[1]
	chkRes, err := e.Host.Command([]string{filepath.Join(target, "usr/sbin/haproxy"), "-Ws", "-c", "-dr", "-f", e.Paths.Config},
		CmdOpts{Check: true, EnvExtra: envExtra})
	if err != nil {
		return err
	}
	if strings.Contains(chkRes.Stderr, "not supported by AWS-LC") || strings.Contains(chkRes.Stderr, "bool-sample-conversion") {
		return migErr("Apply the current alpha HAProxy configuration before migration")
	}
	return nil
}

func (e *Engine) storeRecoveryCommands() error {
	exe, err := engineBinaryFunc()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		return err
	}
	if bytesDigest(data) != strVal(e.State["engine_digest"]) {
		return migErr("Migration implementation changed during preparation")
	}
	return atomicWrite(filepath.Join(e.Directory, "recover-agent"), data, 0o700, 0, 0)
}

func (e *Engine) checkArtifacts(requireRecoveryEngine bool) error {
	recoveryBinary, recoveryDigest := e.recoveryCommand()
	if requireRecoveryEngine {
		exe, err := engineBinaryFunc()
		if err != nil {
			return err
		}
		curDig, err := fileDigest(exe)
		if err != nil || curDig != recoveryDigest {
			return migErr("Migration implementation changed; use the saved recovery command or prepare afresh")
		}
	}
	recDig, err := fileDigest(filepath.Join(e.Directory, recoveryBinary))
	if err != nil || recDig != recoveryDigest {
		return migErr("Saved recovery command integrity check failed")
	}
	if unixNowFloat()-floatVal(e.State["created_at"]) > 86400 && strVal(e.State["phase"]) == "prepared" {
		return migErr("Preparation expired; create a fresh transaction")
	}
	if d, err := fileDigest(filepath.Join(e.Directory, "haproxy-old.deb")); err != nil || d != strVal(e.State["old_digest"]) {
		return migErr("Rollback package integrity check failed")
	}
	if d, err := fileDigest(filepath.Join(e.Directory, "baseline-haproxy")); err != nil || d != strVal(e.State["old_binary_digest"]) {
		return migErr("Baseline binary integrity check failed")
	}
	for _, pkg := range append(pkgRecords(e.State["target_packages"]), pkgRecords(e.State["extra_packages"])...) {
		if d, err := fileDigest(filepath.Join(e.Directory, pkg.Package+".deb")); err != nil || d != pkg.SHA256 {
			return migErr("Target package integrity check failed")
		}
	}
	if oldTLS, ok := pkgRecordOne(e.State["old_tls"]); ok {
		if d, err := fileDigest(filepath.Join(e.Directory, "tls-old.deb")); err != nil || d != oldTLS.SHA256 {
			return migErr("Rollback TLS package integrity check failed")
		}
	}
	if hashes, ok := e.State["baseline_library_hashes"].(map[string]any); ok {
		for name, exp := range hashes {
			if d, err := fileDigest(filepath.Join(e.Directory, "baseline-libraries", name)); err != nil || d != strVal(exp) {
				return migErr("Private baseline TLS library integrity check failed")
			}
		}
	}
	return nil
}

// Prepare stages the provider migration for the installed distribution.
func (e *Engine) Prepare() (map[string]any, error) {
	var summary map[string]any
	err := e.withLock(func() error {
		if err := e.checkPreviousOperations(); err != nil {
			return err
		}
		architecture, packages, err := e.nativePreflight()
		if err != nil {
			return err
		}
		if err := privateDir(e.Paths.Root); err != nil {
			return err
		}
		free, err := freeDiskBytes(e.Paths.Root)
		if err != nil {
			return err
		}
		if free < 512*1024*1024 {
			return migErr("At least 512 MiB of free disk space is required for rollback artifacts")
		}
		id := randomHex32()
		e.Directory = filepath.Join(e.Paths.Root, id)
		if err := privateDir(e.Directory); err != nil {
			return err
		}
		e.Host.SetLog(filepath.Join(e.Directory, "commands.jsonl"))
		mach, err := e.Host.Machine()
		if err != nil {
			return err
		}
		exe, err := engineBinaryFunc()
		if err != nil {
			return err
		}
		engDig, err := fileDigest(exe)
		if err != nil {
			return err
		}
		held, err := e.holds()
		if err != nil {
			return err
		}
		var savedHolds []string
		for _, k := range []string{"haproxy", "haproxy-awslc", "libssl-awslc"} {
			if held[k] {
				savedHolds = append(savedHolds, k)
			}
		}
		if savedHolds == nil {
			savedHolds = []string{}
		}
		e.State = map[string]any{
			"format":        1,
			"kind":          "migration",
			"id":            id,
			"machine":       mach,
			"architecture":  architecture,
			"created_at":    unixNowFloat(),
			"files":         map[string]any{},
			"engine_digest": engDig,
			"holds":         savedHolds,
			"old_version":   packages["haproxy"],
			"target_branch": e.platform.Target,
			"phase":         "preparing",
		}
		if err := e.save(""); err != nil {
			return err
		}
		for _, p := range []string{
			e.Paths.Config, e.Paths.Variables, e.Paths.ServerState,
			e.Paths.Policy, e.Paths.Repository, e.Paths.Priorities, e.Paths.SigningKey,
		} {
			if err := e.backup(p); err != nil {
				return err
			}
		}
		origCfg, err := e.original(e.Paths.Config)
		if err != nil {
			return err
		}
		layout, err := ParsePeerLayout(string(origCfg))
		if err != nil {
			return err
		}
		e.State["layout"] = layoutToMap(layout)
		if e.Paths.Socket != "/run/haproxy/admin.sock" {
			return migErr("Custom Runtime API socket is not qualified")
		}
		oldDir := filepath.Join(e.Directory, "old")
		if err := privateDir(oldDir); err != nil {
			return err
		}
		if _, err := e.Host.Command([]string{
			"/usr/bin/apt-get", "-o", "APT::Get::AllowUnauthenticated=false",
			"download", "haproxy=" + packages["haproxy"],
		}, CmdOpts{Cwd: oldDir, Check: true}); err != nil {
			return err
		}
		oldFiles, _ := filepath.Glob(filepath.Join(oldDir, "*.deb"))
		if len(oldFiles) != 1 {
			return migErr("The exact rollback package could not be downloaded")
		}
		oldDeb := filepath.Join(e.Directory, "haproxy-old.deb")
		if err := os.Rename(oldFiles[0], oldDeb); err != nil {
			return err
		}
		if err := e.checkDeb(oldDeb, "haproxy", packages["haproxy"], architecture); err != nil {
			return err
		}
		oldDig, err := fileDigest(oldDeb)
		if err != nil {
			return err
		}
		e.State["old_digest"] = oldDig
		if err := e.inspectBaseline(); err != nil {
			return err
		}
		binBytes, err := os.ReadFile(e.Paths.Binary)
		if err != nil {
			return err
		}
		if err := atomicWrite(filepath.Join(e.Directory, "baseline-haproxy"), binBytes, 0o700, 0, 0); err != nil {
			return err
		}
		e.State["old_binary_digest"] = bytesDigest(binBytes)
		targets, err := e.authenticatedPackages(architecture)
		if err != nil {
			return err
		}
		e.State["target_packages"] = pkgRecordsToAny(targets)
		tlsVer := targets[1].Version
		if installedTLS := packages["libssl-awslc"]; installedTLS != "" && installedTLS != tlsVer {
			return migErr("Migration would upgrade an existing TLS library")
		}
		e.State["tls_was_installed"] = packages["libssl-awslc"] != ""
		if packages["libssl-awslc"] != "" {
			e.State["tls_baseline"] = packages["libssl-awslc"]
		} else {
			e.State["tls_baseline"] = nil
		}
		var extras []PackageRecord
		extraBaseline := map[string]any{}
		for name := range optionalDependencies {
			if v := packages[name]; v != "" {
				extraBaseline[name] = v
			} else {
				extraBaseline[name] = nil
			}
		}
		e.State["extra_packages"] = pkgRecordsToAny(extras)
		e.State["extra_baseline"] = extraBaseline
		planRes, err := e.Host.Command(e.packageCommand(true, false), CmdOpts{Check: true})
		if err != nil {
			return err
		}
		if _, err := ParseAptPlan(planRes.Stdout, allowedPackages); err != nil {
			return err
		}
		optNames := make([]string, 0, len(optionalDependencies))
		for k := range optionalDependencies {
			optNames = append(optNames, k)
		}
		sort.Strings(optNames)
		for _, name := range optNames {
			re := regexp.MustCompile(`(?m)^Inst ` + regexp.QuoteMeta(name) + `(?::\S+)? (?:\[[^\]]+\] )?\((\S+)`)
			m := re.FindStringSubmatch(planRes.Stdout)
			if m == nil {
				continue
			}
			if packages[name] != "" {
				return migErr("Migration would upgrade an existing system dependency: %s", name)
			}
			dlDir := filepath.Join(e.Directory, "download-"+name)
			if err := privateDir(dlDir); err != nil {
				return err
			}
			if _, err := e.Host.Command([]string{
				"/usr/bin/apt-get", "-o", "APT::Get::AllowUnauthenticated=false",
				"download", name + "=" + m[1],
			}, CmdOpts{Cwd: dlDir, Check: true}); err != nil {
				return err
			}
			archives, _ := filepath.Glob(filepath.Join(dlDir, "*.deb"))
			if len(archives) != 1 {
				return migErr("The exact system dependency could not be downloaded: %s", name)
			}
			dest := filepath.Join(e.Directory, name+".deb")
			if err := os.Rename(archives[0], dest); err != nil {
				return err
			}
			if err := e.checkDeb(dest, name, m[1], architecture); err != nil {
				return err
			}
			d, err := fileDigest(dest)
			if err != nil {
				return err
			}
			extras = append(extras, PackageRecord{Package: name, Version: m[1], SHA256: d})
		}
		e.State["extra_packages"] = pkgRecordsToAny(extras)
		recheckRes, err := e.Host.Command(e.packageCommand(true, false), CmdOpts{Check: true})
		if err != nil {
			return err
		}
		if _, err := ParseAptPlan(recheckRes.Stdout, allowedPackages); err != nil {
			return err
		}
		targetDir := filepath.Join(e.Directory, "target")
		if err := privateDir(targetDir); err != nil {
			return err
		}
		for _, pkg := range append(targets, extras...) {
			if _, err := e.Host.Command([]string{"/usr/bin/dpkg-deb", "-x", filepath.Join(e.Directory, pkg.Package+".deb"), targetDir}, CmdOpts{Check: true}); err != nil {
				return err
			}
		}
		if err := e.inspectTarget(); err != nil {
			return err
		}
		if err := e.storeRecoveryCommands(); err != nil {
			return err
		}
		if err := e.save("prepared"); err != nil {
			return err
		}
		summary = e.Summary()
		return nil
	})
	return summary, err
}

// PreparePatch stages an in-branch HAProxy patch update.
func (e *Engine) PreparePatch(expectedVersion string, reinstall bool) (map[string]any, error) {
	e.Patch = true
	summary, err := e.preparePatchInner(expectedVersion, reinstall)
	if err != nil && e.Directory != "" && strVal(e.State["phase"]) == "preparing" {
		e.State["failure"] = err.Error()
		_ = e.save("aborted")
	}
	return summary, err
}

func (e *Engine) preparePatchInner(expectedVersion string, reinstall bool) (map[string]any, error) {
	var summary map[string]any
	err := e.withLock(func() error {
		if err := e.checkPreviousOperations(); err != nil {
			return err
		}
		architecture, packages, err := e.nativePreflight()
		if err != nil {
			return err
		}
		name := "haproxy"
		branch := e.platform.Baseline
		if packages["haproxy-awslc"] != "" {
			name = "haproxy-awslc"
			branch = e.platform.Target
		}
		verRe := regexp.MustCompile(`^` + regexp.QuoteMeta(branch) + `\.[0-9]+[A-Za-z0-9.+:~_-]*$`)
		if !verRe.MatchString(expectedVersion) {
			return migErr("The selected version is outside the installed HAProxy branch")
		}
		ltRes, err := e.Host.Command([]string{"/usr/bin/dpkg", "--compare-versions", expectedVersion, "lt", packages[name]}, CmdOpts{Check: false})
		if err == nil && ltRes.Code == 0 {
			return migErr("A patch update must not downgrade HAProxy")
		}
		if expectedVersion == packages[name] && !reinstall {
			return migErr("The selected HAProxy version is already installed")
		}
		held, err := e.holds()
		if err != nil {
			return err
		}
		required := []string{name}
		if name == "haproxy-awslc" {
			required = append(required, "libssl-awslc")
		}
		for _, r := range required {
			if !held[r] {
				return migErr("Enable controlled HAProxy package protection before updating")
			}
		}
		if err := privateDir(e.Paths.Root); err != nil {
			return err
		}
		free, err := freeDiskBytes(e.Paths.Root)
		if err != nil {
			return err
		}
		if free < 512*1024*1024 {
			return migErr("At least 512 MiB of free disk space is required")
		}
		id := randomHex32()
		e.Directory = filepath.Join(e.Paths.Root, id)
		if err := privateDir(e.Directory); err != nil {
			return err
		}
		e.Host.SetLog(filepath.Join(e.Directory, "commands.jsonl"))
		mach, err := e.Host.Machine()
		if err != nil {
			return err
		}
		exe, err := engineBinaryFunc()
		if err != nil {
			return err
		}
		engDig, err := fileDigest(exe)
		if err != nil {
			return err
		}
		liveInfo, err := runtimeInfoFunc(e.Paths.Socket)
		if err != nil {
			return err
		}
		sort.Strings(required)
		extraBaseline := map[string]any{}
		for dep := range optionalDependencies {
			if v := packages[dep]; v != "" {
				extraBaseline[dep] = v
			} else {
				extraBaseline[dep] = nil
			}
		}
		var tlsBaseline any
		if packages["libssl-awslc"] != "" {
			tlsBaseline = packages["libssl-awslc"]
		}
		e.State = map[string]any{
			"format":              1,
			"kind":                "patch",
			"id":                  id,
			"machine":             mach,
			"architecture":        architecture,
			"created_at":          unixNowFloat(),
			"files":               map[string]any{},
			"engine_digest":       engDig,
			"old_version":         packages[name],
			"old_package":         name,
			"old_runtime_version": liveInfo["Version"],
			"target_branch":       branch,
			"holds":               required,
			"phase":               "preparing",
			"extra_packages":      []any{},
			"extra_baseline":      extraBaseline,
			"tls_was_installed":   packages["libssl-awslc"] != "",
			"tls_baseline":        tlsBaseline,
		}
		if err := e.save(""); err != nil {
			return err
		}
		for _, p := range []string{
			e.Paths.Config, e.Paths.Variables, e.Paths.ServerState,
			e.Paths.Policy, e.Paths.Repository, e.Paths.Priorities, e.Paths.SigningKey,
		} {
			if err := e.backup(p); err != nil {
				return err
			}
		}
		origCfg, err := e.original(e.Paths.Config)
		if err != nil {
			return err
		}
		layout, err := ParsePeerLayout(string(origCfg))
		if err != nil {
			return err
		}
		e.State["layout"] = layoutToMap(layout)
		oldRec, err := e.downloadExact(name, packages[name], filepath.Join(e.Directory, "haproxy-old.deb"))
		if err != nil {
			return err
		}
		e.State["old_digest"] = oldRec.SHA256
		if err := e.inspectBaseline(); err != nil {
			return err
		}
		binBytes, err := os.ReadFile(e.Paths.Binary)
		if err != nil {
			return err
		}
		if err := atomicWrite(filepath.Join(e.Directory, "baseline-haproxy"), binBytes, 0o700, 0, 0); err != nil {
			return err
		}
		e.State["old_binary_digest"] = bytesDigest(binBytes)
		var targets []PackageRecord
		if name == "haproxy-awslc" {
			oldTLS, err := e.downloadExact("libssl-awslc", packages["libssl-awslc"], filepath.Join(e.Directory, "tls-old.deb"))
			if err != nil {
				return err
			}
			e.State["old_tls"] = pkgRecordToMap(oldTLS)
			libraries := filepath.Join(e.Directory, "baseline-libraries")
			if _, err := e.Host.Command([]string{"/usr/bin/dpkg-deb", "-x", filepath.Join(e.Directory, "tls-old.deb"), libraries}, CmdOpts{Check: true}); err != nil {
				return err
			}
			libRoot, err := filepath.EvalSymlinks(libraries)
			if err != nil {
				libRoot = libraries
			}
			libHashes := map[string]any{}
			if err := filepath.WalkDir(libraries, func(p string, d os.DirEntry, werr error) error {
				if werr != nil || d.IsDir() {
					return werr
				}
				fi, err := os.Stat(p)
				if err != nil || !fi.Mode().IsRegular() {
					return nil
				}
				resolved, err := filepath.EvalSymlinks(p)
				if err != nil {
					return err
				}
				rel, err := filepath.Rel(libRoot, resolved)
				if err != nil || strings.HasPrefix(rel, "..") {
					return migErr("A baseline TLS library escapes the private directory")
				}
				relKey, _ := filepath.Rel(libraries, p)
				dig, err := fileDigest(p)
				if err != nil {
					return err
				}
				libHashes[relKey] = dig
				return nil
			}); err != nil {
				return err
			}
			e.State["baseline_library_hashes"] = libHashes
			targets, err = e.authenticatedPackages(architecture)
			if err != nil {
				return err
			}
			if targets[0].Version != expectedVersion {
				return migErr("HAProxy repository changed; check for updates again")
			}
		} else {
			rec, err := e.downloadExact(name, expectedVersion, filepath.Join(e.Directory, name+".deb"))
			if err != nil {
				return err
			}
			targets = []PackageRecord{rec}
		}
		e.State["target_packages"] = pkgRecordsToAny(targets)
		planRes, err := e.Host.Command(e.packageCommand(true, false), CmdOpts{Check: true})
		if err != nil {
			return err
		}
		if _, err := ParseAptPlan(planRes.Stdout, allowedPackages); err != nil {
			return err
		}
		var extras []PackageRecord
		optNames := make([]string, 0, len(optionalDependencies))
		for k := range optionalDependencies {
			optNames = append(optNames, k)
		}
		sort.Strings(optNames)
		for _, dep := range optNames {
			re := regexp.MustCompile(`(?m)^Inst ` + regexp.QuoteMeta(dep) + `(?::\S+)? (?:\[[^\]]+\] )?\((\S+)`)
			m := re.FindStringSubmatch(planRes.Stdout)
			if m == nil {
				continue
			}
			if packages[dep] != "" {
				return migErr("Update the system dependency separately first: %s", dep)
			}
			rec, err := e.downloadExact(dep, m[1], filepath.Join(e.Directory, dep+".deb"))
			if err != nil {
				return err
			}
			extras = append(extras, rec)
		}
		e.State["extra_packages"] = pkgRecordsToAny(extras)
		targetDir := filepath.Join(e.Directory, "target")
		if err := privateDir(targetDir); err != nil {
			return err
		}
		for _, pkg := range append(targets, extras...) {
			if _, err := e.Host.Command([]string{"/usr/bin/dpkg-deb", "-x", filepath.Join(e.Directory, pkg.Package+".deb"), targetDir}, CmdOpts{Check: true}); err != nil {
				return err
			}
		}
		if err := e.inspectTarget(); err != nil {
			return err
		}
		if err := e.storeRecoveryCommands(); err != nil {
			return err
		}
		if err := e.save("prepared"); err != nil {
			return err
		}
		summary = e.Summary()
		return nil
	})
	return summary, err
}

func layoutToMap(l PeerLayout) map[string]any {
	tabs := map[string]any{}
	for k, v := range l.Tables {
		tabs[k] = v
	}
	return map[string]any{"cluster": l.Cluster, "local": l.Local, "port": l.Port, "tables": tabs}
}

func layoutFromState(raw any) PeerLayout {
	m, _ := raw.(map[string]any)
	tabs := map[string]string{}
	if tm, ok := m["tables"].(map[string]any); ok {
		for k, v := range tm {
			tabs[k] = strVal(v)
		}
	} else if tm, ok := m["tables"].(map[string]string); ok {
		for k, v := range tm {
			tabs[k] = v
		}
	}
	return PeerLayout{
		Cluster: strVal(m["cluster"]),
		Local:   strVal(m["local"]),
		Port:    intVal(m["port"]),
		Tables:  tabs,
	}
}

func pkgRecordToMap(p PackageRecord) map[string]any {
	return map[string]any{"Package": p.Package, "Version": p.Version, "SHA256": p.SHA256}
}

func pkgRecordsToAny(pkgs []PackageRecord) []any {
	out := make([]any, 0, len(pkgs))
	for _, p := range pkgs {
		out = append(out, pkgRecordToMap(p))
	}
	return out
}

func pkgRecordOne(raw any) (PackageRecord, bool) {
	m, ok := raw.(map[string]any)
	if !ok || m == nil {
		return PackageRecord{}, false
	}
	return PackageRecord{Package: strVal(m["Package"]), Version: strVal(m["Version"]), SHA256: strVal(m["SHA256"])}, true
}

func pkgRecords(raw any) []PackageRecord {
	var out []PackageRecord
	switch s := raw.(type) {
	case []PackageRecord:
		return append(out, s...)
	case []any:
		for _, item := range s {
			if rec, ok := pkgRecordOne(item); ok {
				out = append(out, rec)
			}
		}
	}
	return out
}

func strSlice(raw any) []string {
	var out []string
	switch s := raw.(type) {
	case []string:
		return append(out, s...)
	case []any:
		for _, item := range s {
			out = append(out, strVal(item))
		}
	}
	return out
}
