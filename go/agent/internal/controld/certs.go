package controld

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/certrestore"
)

// ensureWithin is _ensure_within: candidate resolved must stay under root.
func ensureWithin(root, candidate string) (string, error) {
	rootResolved := resolvePath(root)
	cand := resolvePath(candidate)
	if cand != rootResolved && !strings.HasPrefix(cand, strings.TrimSuffix(rootResolved, "/")+"/") {
		return "", vErr("archive path escapes the destination directory")
	}
	return cand, nil
}

// resolvePath is Path.resolve() (strict=False): symlinks resolved as far as
// they exist, the rest joined on.
func resolvePath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	if r, err := filepath.EvalSymlinks(abs); err == nil {
		return r
	}
	parent, base := filepath.Split(abs)
	parent = filepath.Clean(parent)
	if parent == abs || parent == "/" && base == "" {
		return abs
	}
	return filepath.Join(resolvePath(parent), base)
}

func pyPathParts(name string) []string {
	parts := []string{}
	for _, p := range strings.Split(name, "/") {
		if p == "" || p == "." {
			continue
		}
		parts = append(parts, p)
	}
	return parts
}

func (d *Daemon) validateZip(zr *zip.Reader) ([]*zip.File, error) {
	if int64(len(zr.File)) > d.Opts.MaxArchiveFiles {
		return nil, vErr("archive contains too many files")
	}
	var expanded int64
	for _, f := range zr.File {
		name := f.Name
		if strings.HasPrefix(name, "/") {
			return nil, vErr("archive contains an unsafe path")
		}
		for _, p := range pyPathParts(name) {
			if p == ".." {
				return nil, vErr("archive contains an unsafe path")
			}
		}
		if (f.ExternalAttrs>>16)&0o170000 == 0o120000 {
			return nil, vErr("archive contains a symbolic link")
		}
		if d.Opts.MaxArchiveExpandedBytes < expanded || f.UncompressedSize64 > uint64(d.Opts.MaxArchiveExpandedBytes-expanded) {
			return nil, vErr("archive expands beyond the allowed size")
		}
		expanded += int64(f.UncompressedSize64)
		if f.CompressedSize64 > 0 && f.UncompressedSize64 > 1024*1024 &&
			float64(f.UncompressedSize64)/float64(f.CompressedSize64) > float64(d.Opts.MaxCompressionRatio) {
			return nil, vErr("archive has a suspicious compression ratio")
		}
	}
	return zr.File, nil
}

func (d *Daemon) certsBackupB64() (string, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	var totalFiles, totalSize int64
	add := func(root, prefix string) error {
		if !isDir(root) {
			return nil
		}
		return filepath.WalkDir(root, func(p string, de fs.DirEntry, err error) error {
			if err != nil || p == root {
				return nil
			}
			fi, serr := os.Stat(p)
			if serr != nil || !fi.Mode().IsRegular() {
				return nil
			}
			if _, werr := ensureWithin(root, p); werr != nil {
				return nil
			}
			totalFiles++
			totalSize += fi.Size()
			if totalFiles > d.Opts.MaxArchiveFiles || totalSize > d.Opts.MaxArchiveExpandedBytes {
				return vErr("certificate backup exceeds the allowed size")
			}
			rel, _ := filepath.Rel(root, p)
			hdr, herr := zip.FileInfoHeader(fi)
			if herr != nil {
				return herr
			}
			hdr.Name = prefix + "/" + filepath.ToSlash(rel)
			hdr.Method = zip.Deflate
			w, cerr := zw.CreateHeader(hdr)
			if cerr != nil {
				return cerr
			}
			src, oerr := os.Open(p)
			if oerr != nil {
				return oerr
			}
			defer src.Close()
			_, cerr = io.Copy(w, src)
			return cerr
		})
	}
	if err := add(d.Opts.CertsHAPDir, "haproxy_certs"); err != nil {
		return "", err
	}
	if d.Opts.CertsLEDir != "" {
		if err := add(d.Opts.CertsLEDir, "letsencrypt"); err != nil {
			return "", err
		}
	}
	if err := zw.Close(); err != nil {
		return "", err
	}
	raw := buf.Bytes()
	if int64(len(raw)) > d.Opts.MaxArchiveBytes {
		return "", vErr("certificate backup exceeds the allowed size")
	}
	b64 := base64.StdEncoding.EncodeToString(raw)
	log.Printf("certs-backup: size=%d bytes, b64_len=%d", len(raw), len(b64))
	return b64, nil
}

func (d *Daemon) certsRestoreB64(b64 string) (string, error) {
	raw, err := b64decodeStrict(b64)
	if err != nil {
		return "", err
	}
	if int64(len(raw)) > d.Opts.MaxArchiveBytes {
		return "", vErr("certificate archive exceeds the allowed size")
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil && !errors.Is(err, zip.ErrInsecurePath) {
		return "", vErr("File is not a zip file")
	}
	infos, err := d.validateZip(zr)
	if err != nil {
		return "", err
	}
	hapDir, leRoot := d.Opts.CertsHAPDir, d.Opts.CertsLEDir
	restored := 0
	remaining := d.Opts.MaxArchiveExpandedBytes
	for _, info := range infos {
		name := info.Name
		if strings.HasSuffix(name, "/") {
			continue
		}
		isLE := false
		var dst string
		var rel []string
		switch {
		case strings.HasPrefix(name, "haproxy_certs/"):
			rel = pyPathParts(name)[1:]
			if len(rel) != 1 || !strings.HasSuffix(rel[0], ".pem") || strings.HasPrefix(rel[0], ".") {
				continue
			}
			if dst, err = ensureWithin(hapDir, filepath.Join(hapDir, rel[0])); err != nil {
				return "", err
			}
		case strings.HasPrefix(name, "letsencrypt/") && leRoot != "":
			rel = pyPathParts(name)[1:]
			if !certrestore.AllowedLEPath(rel) {
				continue
			}
			isLE = true
		default:
			continue
		}
		src, err := info.Open()
		if err != nil {
			return "", err
		}
		var payload bytes.Buffer
		chunk := make([]byte, 65536)
		var readTotal int64
		for {
			n, rerr := src.Read(chunk)
			if n > 0 {
				readTotal += int64(n)
				if readTotal > remaining {
					src.Close()
					return "", vErr("certificate archive expands beyond the allowed size")
				}
				payload.Write(chunk[:n])
			}
			if rerr == io.EOF {
				break
			}
			if rerr != nil {
				src.Close()
				if errors.Is(rerr, zip.ErrChecksum) {
					return "", vErr("Bad CRC-32 for file %s", pyRepr(name))
				}
				return "", rerr
			}
		}
		src.Close()
		if readTotal != int64(info.UncompressedSize64) {
			return "", vErr("certificate archive entry size mismatch")
		}
		remaining -= readTotal
		if isLE {
			if rel[0] == "renewal" && !certrestore.SafeRenewal(payload.Bytes(), leRoot, env("HAPROXY_DNS_CREDENTIALS_DIR", certrestore.DefaultDNSCredentialsDir), strings.TrimSuffix(rel[1], ".conf")) {
				log.Printf("certs-restore: refused unsafe Certbot renewal config: %s", strings.Join(rel, "/"))
				continue
			}
			if err := certrestore.WriteLEFile(leRoot, rel, payload.Bytes()); err != nil {
				return "", err
			}
			restored++
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o777); err != nil {
			return "", err
		}
		fd, err := syscall.Open(dst, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_TRUNC|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
		if err != nil {
			return "", &os.PathError{Op: "open", Path: dst, Err: err}
		}
		out := os.NewFile(uintptr(fd), dst)
		if _, err := out.Write(payload.Bytes()); err != nil {
			out.Close()
			return "", err
		}
		if err := out.Sync(); err != nil {
			out.Close()
			return "", err
		}
		out.Close()
		restored++
	}
	msg := "restored " + itoa(restored) + " files"
	log.Printf("certs-restore: %s", msg)
	return msg, nil
}
