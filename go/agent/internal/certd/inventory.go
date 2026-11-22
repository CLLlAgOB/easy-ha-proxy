package certd

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/pyx"
)

func (d *Daemon) handleCertsBackup(_ map[string]any) (int, map[string]any) {
	hapDir := d.Opts.HAProxyCertsDir
	leRoot := d.Opts.LetsEncryptRoot
	caRoot, err := d.prepareCARoot(false)
	if err != nil {
		panic(err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	total, hapFiles, leFiles, caFiles := 0, 0, 0, 0
	add := func(base string, counter *int, strict bool) error {
		if !isDir(base) {
			return nil
		}
		files := []string{}
		_ = filepath.WalkDir(base, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if path != base && isFile(path) {
				files = append(files, path)
			}
			return nil
		})
		sortPathsLikePython(files)
		for _, path := range files {
			if _, err := ensureWithin(base, path); err != nil {
				if strict {
					return err
				}
				continue
			}
			if total >= d.Opts.MaxArchiveFiles {
				return vErr("certificate backup contains too many files")
			}
			fi, err := os.Stat(path)
			if err != nil {
				return err
			}
			_ = zw.Flush()
			if fi.Size()+int64(buf.Len()) > d.Opts.MaxArchiveBytes {
				return vErr("certificate backup exceeds the configured limit")
			}
			rel, _ := filepath.Rel(base, path)
			header, err := zip.FileInfoHeader(fi)
			if err != nil {
				return err
			}
			header.Name = filepath.ToSlash(filepath.Join(filepath.Base(base), rel))
			header.Method = zip.Deflate
			w, err := zw.CreateHeader(header)
			if err != nil {
				return err
			}
			src, err := os.Open(path)
			if err != nil {
				return err
			}
			_, err = io.Copy(w, src)
			_ = src.Close()
			if err != nil {
				return err
			}
			total++
			*counter++
		}
		return nil
	}
	for _, step := range []struct {
		base    string
		counter *int
		strict  bool
	}{{hapDir, &hapFiles, false}, {leRoot, &leFiles, false}, {caRoot, &caFiles, true}} {
		if err := add(step.base, step.counter, step.strict); err != nil {
			panic(err)
		}
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	raw := buf.Bytes()
	msg := fmt.Sprintf("Certificate backup created: %d files total, HAProxy: %d, Let's Encrypt: %d, CA: %d. Archive size: %d bytes.",
		total, hapFiles, leFiles, caFiles, len(raw))
	return 200, map[string]any{"ok": true, "archive_b64": base64.StdEncoding.EncodeToString(raw), "haproxy_certs_dir": hapDir,
		"letsencrypt_root_dir": leRoot, "certificate_authorities_dir": caRoot, "message": msg}
}

// sortPathsLikePython sorts by path components, as sorted() of Paths does.
func sortPathsLikePython(paths []string) {
	key := func(p string) []string { return strings.Split(filepath.ToSlash(p), "/") }
	less := func(a, b []string) bool {
		for i := 0; i < len(a) && i < len(b); i++ {
			if a[i] != b[i] {
				return a[i] < b[i]
			}
		}
		return len(a) < len(b)
	}
	for i := 1; i < len(paths); i++ {
		for j := i; j > 0 && less(key(paths[j]), key(paths[j-1])); j-- {
			paths[j], paths[j-1] = paths[j-1], paths[j]
		}
	}
}

var allowedLERestoreDirs = map[string]bool{"accounts": true, "archive": true, "live": true, "renewal": true, "keys": true, "csr": true}

func allowedLERestoreRel(parts []string) bool {
	if len(parts) < 2 || !allowedLERestoreDirs[parts[0]] {
		return false
	}
	if parts[0] == "renewal" {
		return len(parts) == 2 && strings.HasSuffix(parts[1], ".conf") && !strings.HasPrefix(parts[1], ".")
	}
	return true
}

func pathParts(name string) ([]string, bool) {
	absolute := strings.HasPrefix(name, "/")
	parts := []string{}
	for _, p := range strings.Split(name, "/") {
		if p != "" && p != "." {
			parts = append(parts, p)
		}
	}
	return parts, absolute
}

func (d *Daemon) validateZip(r *zip.Reader) error {
	if len(r.File) > d.Opts.MaxArchiveFiles {
		return vErr("ZIP contains too many entries")
	}
	var expanded int64
	for _, f := range r.File {
		if f.Mode()&os.ModeSymlink != 0 {
			return vErr("ZIP symlink is not allowed: %s", f.Name)
		}
		expanded += int64(f.UncompressedSize64)
		if expanded > d.Opts.MaxArchiveExpanded {
			return vErr("ZIP expanded size exceeds the configured limit")
		}
		if f.UncompressedSize64 > 0 && f.CompressedSize64 == 0 {
			return vErr("invalid ZIP compression metadata")
		}
		if f.CompressedSize64 > 0 && float64(f.UncompressedSize64)/float64(f.CompressedSize64) > float64(d.Opts.MaxCompressionRatio) {
			return vErr("ZIP compression ratio exceeds the configured limit")
		}
	}
	return nil
}

func readZipBounded(f *zip.File, budget int64) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	var out bytes.Buffer
	chunk := make([]byte, 65536)
	var total int64
	for {
		n, err := rc.Read(chunk)
		if n > 0 {
			total += int64(n)
			if total > budget {
				return nil, vErr("ZIP archive expands beyond the allowed size")
			}
			out.Write(chunk[:n])
		}
		if err == io.EOF {
			return out.Bytes(), nil
		}
		if err != nil {
			return nil, err
		}
	}
}

func (d *Daemon) handleCertsRestore(body map[string]any) (int, map[string]any) {
	archive := strings.TrimSpace(pyx.StrOr(body["archive_b64"]))
	if archive == "" {
		return 400, map[string]any{"ok": false, "error": "archive_b64 is required"}
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(archive)
	if err != nil {
		return 400, map[string]any{"ok": false, "error": "invalid base64: " + pyBase64Error(archive)}
	}
	if int64(len(raw)) > d.Opts.MaxArchiveBytes {
		return 413, map[string]any{"ok": false, "error": "ZIP archive is too large"}
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err == nil {
		err = d.validateZip(zr)
	}
	if err != nil {
		return 400, map[string]any{"ok": false, "error": "not a valid ZIP archive: " + err.Error()}
	}
	hapDir, leRoot := d.Opts.HAProxyCertsDir, d.Opts.LetsEncryptRoot
	caRoot, err := d.prepareCARoot(true)
	if err != nil {
		panic(err)
	}
	hapTop, leTop, caTop := filepath.Base(hapDir), filepath.Base(leRoot), filepath.Base(caRoot)
	written, skipped := 0, 0
	budget := d.Opts.MaxArchiveExpanded
	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, "/") {
			continue
		}
		parts, absolute := pathParts(f.Name)
		if absolute || containsStr(parts, "..") || len(parts) < 2 {
			skipped++
			continue
		}
		top, rel := parts[0], parts[1:]
		var base string
		isHAProxy := false
		switch top {
		case hapTop:
			if len(rel) != 1 || !strings.HasSuffix(rel[0], ".pem") || strings.HasPrefix(rel[0], ".") {
				skipped++
				continue
			}
			base, isHAProxy = hapDir, true
		case leTop:
			if !allowedLERestoreRel(rel) {
				skipped++
				continue
			}
			base = leRoot
		case caTop:
			base = caRoot
		default:
			skipped++
			continue
		}
		target, err := ensureWithin(base, filepath.Join(append([]string{base}, rel...)...))
		if err != nil {
			skipped++
			continue
		}
		data, err := readZipBounded(f, budget)
		if err != nil {
			if isValueErr(err) {
				return 400, map[string]any{"ok": false, "error": err.Error()}
			}
			skipped++
			continue
		}
		budget -= int64(len(data))
		if top == leTop && rel[0] == "renewal" && hookKeyRe.Match(data) {
			log.Printf("Refused certbot renewal config containing hook directive: %s", strings.Join(rel, "/"))
			skipped++
			continue
		}
		writeErr := func() error {
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			fh, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscallNoFollow, 0o600)
			if err != nil {
				return err
			}
			if _, err := fh.Write(data); err != nil {
				_ = fh.Close()
				return err
			}
			_ = fh.Sync()
			if err := fh.Close(); err != nil {
				return err
			}
			switch {
			case isHAProxy:
				return setCertPermissions(target)
			case base == caRoot:
				mode := os.FileMode(0o644)
				if filepath.Base(target) == "ca.key" {
					mode = 0o600
				}
				return os.Chmod(target, mode)
			default:
				return os.Chmod(target, 0o600)
			}
		}()
		if writeErr != nil {
			skipped++
			continue
		}
		written++
	}
	var pemRC *int
	pemStdout, pemStderr := "", ""
	if isDir(caRoot) {
		_ = os.Chmod(caRoot, 0o700)
		_, _ = d.prepareCASubdir("internal", false)
		_, _ = d.prepareCASubdir("external", false)
	}
	if exists(d.Opts.PEMsScript) && !d.Opts.DryRun {
		log.Printf("Running PEM rebuild script after restore: %s", d.Opts.PEMsScript)
		res, err := runBounded([]string{d.Opts.PEMsScript}, pemRebuildTimeout*time.Second, nil)
		if err != nil {
			panic(err)
		}
		rc := res.rc
		pemRC, pemStdout, pemStderr = &rc, string(res.stdout), string(res.stderr)
	}
	msg := fmt.Sprintf("Certificate backup restored: %d files written, %d entries skipped.", written, skipped)
	switch {
	case pemRC == nil:
		msg += " The PEM rebuild script was not run."
	case *pemRC == 0:
		msg += " PEM rebuild and HAProxy reload completed successfully."
	default:
		msg += fmt.Sprintf(" PEM rebuild exited with code %d; see pem_stdout and pem_stderr for details.", *pemRC)
	}
	return 200, map[string]any{"ok": rcOK(pemRC), "message": msg, "haproxy_certs_dir": hapDir, "letsencrypt_root_dir": leRoot,
		"certificate_authorities_dir": caRoot, "written_files": written, "skipped_entries": skipped, "pem_rc": rcValue(pemRC),
		"pem_stdout": pemStdout, "pem_stderr": pemStderr}
}

func (d *Daemon) handleCertsList() (int, map[string]any) {
	haproxyItems := []any{}
	if isDir(d.Opts.HAProxyCertsDir) {
		for _, p := range globSorted(filepath.Join(d.Opts.HAProxyCertsDir, "*.pem")) {
			if item := buildCertItemForList(p); item != nil {
				item["kind"] = "haproxy"
				haproxyItems = append(haproxyItems, item)
			}
		}
	}
	leItems := []any{}
	if live := d.leLiveDir(); isDir(live) {
		for _, sub := range sortedDirEntries(live) {
			if !isDir(sub) {
				continue
			}
			full := filepath.Join(sub, "fullchain.pem")
			if !isFile(full) {
				continue
			}
			item := buildCertItemForList(full)
			if item == nil {
				continue
			}
			item["kind"] = "letsencrypt"
			item["lineage"] = filepath.Base(sub)
			if priv := filepath.Join(sub, "privkey.pem"); isFile(priv) {
				item["privkey_path"] = priv
			}
			item["fullchain_path"] = full
			leItems = append(leItems, item)
		}
	}
	cas, err := d.listCertificateAuthorities()
	if err != nil {
		panic(err)
	}
	return 200, map[string]any{"ok": true, "haproxy": haproxyItems, "letsencrypt": leItems, "certificate_authorities": cas}
}

func (d *Daemon) handleDeleteHAProxy(body map[string]any) (int, map[string]any) {
	pathStr := strings.TrimSpace(pyx.StrOr(body["path"]))
	if pathStr == "" {
		return 200, map[string]any{"ok": false, "error": "path is required"}
	}
	base := resolvePath(d.Opts.HAProxyCertsDir)
	target := resolvePath(pathStr)
	rel, err := filepath.Rel(base, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return 200, map[string]any{"ok": false, "error": "refusing to delete file outside haproxy_certs_dir"}
	}
	if !exists(target) {
		return 200, map[string]any{"ok": false, "error": "file not found: " + target}
	}
	if target == base || !isFile(target) {
		return 200, map[string]any{"ok": false, "error": "refusing to delete non-file path: " + target}
	}
	kept, err := d.trashPut("haproxy_cert", filepath.Base(target), []string{target}, pyx.StrOr(body["actor"]), d.certDetails(target), nil)
	if err != nil {
		return 200, map[string]any{"ok": false, "error": "cannot keep a copy in the trash, nothing deleted: " + pyOSErr(err)}
	}
	before := trashListing([]string{target})
	if err := os.Remove(target); err != nil {
		d.trashSettle(kept, before, []string{target})
		return 200, map[string]any{"ok": false, "error": fmt.Sprintf("failed to delete %s: %s", target, pyOSErr(err))}
	}
	d.trashCommit(kept)
	return 200, map[string]any{"ok": true, "message": "HAProxy certificate moved to the trash: " + target, "path": target, "trash_id": kept}
}

func (d *Daemon) handleDeleteLE(body map[string]any) (int, map[string]any) {
	lineage := strings.TrimSpace(pyx.StrOr(body["lineage"]))
	if lineage == "" {
		return 200, map[string]any{"ok": false, "error": "lineage is required"}
	}
	lineage, err := safeSlug(lineage)
	if err != nil {
		return 400, map[string]any{"ok": false, "error": err.Error()}
	}
	cmd := []string{d.Opts.CertbotBin, "delete", "--cert-name", lineage, "--config-dir", d.Opts.LetsEncryptRoot, "--non-interactive"}
	root := d.Opts.LetsEncryptRoot
	binding, err := d.dnsBindingPath(lineage)
	if err != nil {
		panic(err)
	}
	pieces := []string{filepath.Join(root, "live", lineage), filepath.Join(root, "archive", lineage),
		filepath.Join(root, "renewal", lineage+".conf"), binding}
	kept := ""
	if lexists(pieces[0]) || lexists(pieces[1]) || lexists(pieces[2]) {
		kept, err = d.trashPut("letsencrypt", lineage, pieces, pyx.StrOr(body["actor"]),
			d.certDetails(filepath.Join(root, "live", lineage, "cert.pem")), nil)
		if err != nil {
			return 200, map[string]any{"ok": false, "error": "cannot keep a copy in the trash, nothing deleted: " + pyOSErr(err)}
		}
	}
	log.Printf("Running certbot delete: %s", strings.Join(cmd, " "))
	before := trashListing(pieces)
	res, err := runBounded(cmd, certbotQuickTimeoutSeconds*time.Second, nil)
	if err != nil {
		panic(err)
	}
	ok := res.rc == 0
	resp := map[string]any{}
	if ok {
		_ = os.Remove(binding)
		d.trashCommit(kept)
	} else {
		kept = d.trashSettle(kept, before, pieces)
		if kept != "" {
			resp["error"] = "certbot stopped part-way through the deletion; the copy taken before it started is in the trash, " +
				"and restoring it puts the whole lineage back over what certbot left"
		}
	}
	resp["trash_id"] = strOrNil(kept)
	resp["ok"] = ok
	resp["rc"] = res.rc
	resp["cmd"] = strings.Join(cmd, " ")
	resp["stdout"] = string(res.stdout)
	resp["stderr"] = string(res.stderr)
	return 200, resp
}

// pyBase64Error is the binascii.Error text of base64.b64decode(validate=True).
func pyBase64Error(s string) string {
	data := 0
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '+', r == '/':
			data++
		case r == '=':
		default:
			return "Only base64 data is allowed"
		}
	}
	if data%4 == 1 {
		return fmt.Sprintf("Invalid base64-encoded string: number of data characters (%d) cannot be 1 more than a multiple of 4", data)
	}
	return "Incorrect padding"
}
