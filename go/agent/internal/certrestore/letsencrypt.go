// Package certrestore contains the Certbot archive policy shared by the
// certificate daemon and the legacy HAProxy control endpoint.
package certrestore

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const DefaultDNSCredentialsDir = "/etc/easy-ha-proxy/dns-providers"

var (
	profileFile = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}\.ini$`)
	optionKey   = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	archivePEM  = regexp.MustCompile(`^(cert|chain|fullchain|privkey)[1-9][0-9]*\.pem$`)
)

func AllowedLEPath(parts []string) bool {
	if len(parts) < 2 {
		return false
	}
	switch parts[0] {
	case "renewal":
		return len(parts) == 2 && strings.HasSuffix(parts[1], ".conf") && !strings.HasPrefix(parts[1], ".")
	case "accounts", "archive", "live", "keys", "csr":
		return true
	}
	return false
}

// SafeRenewal accepts standalone renewal and the DNS plugins configured by
// this project. Any path Certbot uses to write lineage data is tied to the
// imported certificate name. DNS credentials belong to the destination host.
func SafeRenewal(data []byte, root, dnsDir, lineage string) bool {
	if strings.ContainsAny(string(data), "\x00\ufeff") {
		return false
	}
	section := ""
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == "[renewalparams]" && section == "" {
			section = "renewalparams"
			continue
		}
		if line == "[[webroot_map]]" && section == "renewalparams" {
			// ConfigObj may emit an empty map even for standalone renewal.
			section = "empty map"
			continue
		}
		key, value, found := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if !found || !optionKey.MatchString(key) || section == "empty map" || strings.HasPrefix(value, `"""`) || strings.HasPrefix(value, `'''`) {
			return false
		}
		key = strings.ReplaceAll(strings.ToLower(key), "-", "_")
		// Match sensitive values in full, including any comment syntax.
		// A trimmed prefix is insufficient for comparing a filesystem path.
		if len(value) >= 2 && (value[0] == '\'' || value[0] == '"') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		if strings.HasSuffix(key, "_hook") || strings.HasPrefix(key, "webroot") {
			return false
		}
		switch key {
		case "archive_dir":
			if value != filepath.Join(root, "archive", lineage) {
				return false
			}
		case "cert", "chain", "fullchain", "privkey":
			if value != filepath.Join(root, "live", lineage, key+".pem") {
				return false
			}
		case "authenticator":
			switch value {
			case "standalone", "dns-cloudflare", "dns-digitalocean", "dns-rfc2136", "dns-route53":
			default:
				return false
			}
		case "installer":
			if value != "None" && value != "" {
				return false
			}
		case "dns_cloudflare_credentials", "dns_digitalocean_credentials", "dns_rfc2136_credentials":
			if !safeCredentialPath(dnsDir, value) {
				return false
			}
		default:
			if strings.HasSuffix(key, "_credentials") || strings.HasSuffix(key, "_path") || strings.HasSuffix(key, "_dir") {
				return false
			}
		}
	}
	return true
}

func safeCredentialPath(dir, value string) bool {
	if !filepath.IsAbs(dir) || value != filepath.Join(dir, filepath.Base(value)) || !profileFile.MatchString(filepath.Base(value)) {
		return false
	}
	// The host may install its profile after restoring the certificates.
	fi, err := os.Lstat(value)
	return errors.Is(err, os.ErrNotExist) || err == nil && fi.Mode().IsRegular()
}

func WriteLEFile(rootDir string, rel []string, data []byte) error {
	if err := os.MkdirAll(rootDir, 0o700); err != nil {
		return err
	}
	root, err := os.OpenRoot(rootDir)
	if err != nil {
		return err
	}
	defer root.Close()
	name := filepath.Join(rel...)
	if len(rel) == 3 && rel[0] == "live" {
		fi, err := root.Lstat(name)
		if err == nil && fi.Mode()&os.ModeSymlink != 0 {
			link, err := root.Readlink(name)
			if err != nil {
				return err
			}
			dest := filepath.Clean(filepath.Join(filepath.Dir(name), link))
			base := filepath.Base(dest)
			if filepath.IsAbs(link) || filepath.Dir(dest) != filepath.Join("archive", rel[1]) ||
				!archivePEM.MatchString(base) || strings.TrimRight(strings.TrimSuffix(base, ".pem"), "0123456789")+".pem" != rel[2] {
				return fmt.Errorf("unexpected Certbot live link: %s", name)
			}
			name = dest
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return writeFile(root, name, data, 0o600)
}

func AllowedCAPath(rel []string) bool {
	if len(rel) != 2 {
		return false
	}
	switch rel[0] {
	case "internal":
		return rel[1] == "ca.key" || rel[1] == "ca.crt"
	case "external":
		return strings.HasSuffix(rel[1], ".pem") && !strings.HasPrefix(rel[1], ".")
	}
	return false
}

func WriteCAFile(rootDir string, rel []string, data []byte) error {
	root, err := os.OpenRoot(rootDir)
	if err != nil {
		return err
	}
	defer root.Close()
	mode := os.FileMode(0o644)
	if rel[len(rel)-1] == "ca.key" {
		mode = 0o600
	}
	return writeFile(root, filepath.Join(rel...), data, mode)
}

func writeFile(root *os.Root, name string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(name)
	if err := root.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for parent := dir; parent != "."; parent = filepath.Dir(parent) {
		fi, err := root.Lstat(parent)
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			return fmt.Errorf("certificate parent is not a directory: %s", parent)
		}
	}
	if fi, err := root.Lstat(name); err == nil && !fi.Mode().IsRegular() {
		return fmt.Errorf("certificate destination is not a regular file: %s", name)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temp := filepath.Join(dir, ".cert-restore-"+rand.Text())
	f, err := root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer root.Remove(temp)
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	return root.Rename(temp, name)
}
