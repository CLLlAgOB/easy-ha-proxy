package fullbackup

import (
	"bytes"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
)

// The archive: "EHP2", a 16-byte salt and an HMAC-SHA256 tag over both and
// the OpenSSL ciphertext that follows. The tag is checked before OpenSSL
// sees the data, so a wrong passphrase is told apart from a damaged file
// without decrypting garbage. Archives without the header (v1: the raw
// OpenSSL "Salted__" stream) stay readable.
const (
	encMagic         = "EHP2"
	encSaltLen       = 16
	encMACLen        = 32
	encHeaderLen     = len(encMagic) + encSaltLen + encMACLen
	encKDFIterations = 600_000
)

func deriveMACKey(password string, salt []byte) ([]byte, error) {
	return pbkdf2.Key(sha256.New, password, append([]byte("easy-ha-proxy-backup-mac-v2:"), salt...), encKDFIterations, 32)
}

func streamMAC(key, prefix []byte, ciphertext string, offset int64) ([]byte, error) {
	f, err := os.Open(ciphertext)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return nil, err
		}
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(prefix)
	if _, err := io.Copy(mac, f); err != nil {
		return nil, err
	}
	return mac.Sum(nil), nil
}

func runOpenSSLEnc(source, destination, password string, decrypt bool) error {
	argv := []string{"openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", strconv.Itoa(encKDFIterations), "-md", "sha256"}
	if decrypt {
		argv = append(argv, "-d")
	} else {
		argv = append(argv, "-salt")
	}
	argv = append(argv, "-in", source, "-out", destination, "-pass", "stdin")
	if _, err := run(argv, runOptions{check: true, input: password + "\n"}); err != nil {
		if decrypt {
			return wrongPassphrase()
		}
		return backupErrorf("Cannot encrypt backup.")
	}
	return nil
}

// createPrivate opens a new file 0600 without following a symbolic link.
func createPrivate(p string) (*os.File, error) {
	return os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|noFollow, 0o600)
}

func decryptBackup(source, destination, password string) error {
	in, err := os.OpenFile(source, os.O_RDONLY|noFollow, 0)
	if err != nil {
		return err
	}
	defer in.Close()
	header := make([]byte, encHeaderLen)
	n, err := io.ReadFull(in, header)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return err
	}
	header = header[:n]
	raw, err := os.CreateTemp(filepath.Dir(destination), ".backup-cipher-*")
	if err != nil {
		return err
	}
	defer os.Remove(raw.Name())
	defer raw.Close()
	switch {
	case bytes.HasPrefix(header, []byte(encMagic)):
		if n != encHeaderLen {
			return wrongPassphrase()
		}
		saltEnd := len(encMagic) + encSaltLen
		key, err := deriveMACKey(password, header[len(encMagic):saltEnd])
		if err != nil {
			return err
		}
		mac := hmac.New(sha256.New, key)
		mac.Write(header[:saltEnd])
		// Authenticate the exact private copy passed to OpenSSL.
		if _, err := io.Copy(io.MultiWriter(raw, mac), in); err != nil {
			return err
		}
		if !hmac.Equal(mac.Sum(nil), header[saltEnd:]) {
			return wrongPassphrase()
		}
	case bytes.HasPrefix(header, []byte("Salted__")):
		fmt.Fprintln(term.stderr, "Warning: this legacy backup format does not authenticate its contents.")
		if _, err := io.Copy(raw, io.MultiReader(bytes.NewReader(header), in)); err != nil {
			return err
		}
	default:
		return wrongPassphrase()
	}
	if err := raw.Close(); err != nil {
		return err
	}
	if err := runOpenSSLEnc(raw.Name(), destination, password, true); err != nil {
		return err
	}
	return os.Chmod(destination, 0o600)
}

// opensslCrypt encrypts source into the EHP2 format at destination, or
// decrypts either format.
func opensslCrypt(source, destination, password string, decrypt bool) error {
	dir, name := filepath.Dir(destination), filepath.Base(destination)
	if decrypt {
		return decryptBackup(source, destination, password)
	}
	raw := filepath.Join(dir, fmt.Sprintf(".%s.raw.%d", name, os.Getpid()))
	defer os.Remove(raw)
	if err := runOpenSSLEnc(source, raw, password, false); err != nil {
		return err
	}
	salt := make([]byte, encSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	key, err := deriveMACKey(password, salt)
	if err != nil {
		return err
	}
	prefix := append([]byte(encMagic), salt...)
	tag, err := streamMAC(key, prefix, raw, 0)
	if err != nil {
		return err
	}
	out, err := createPrivate(destination)
	if err != nil {
		return err
	}
	in, err := os.Open(raw)
	if err != nil {
		out.Close()
		return err
	}
	defer in.Close()
	if _, err := out.Write(append(prefix, tag...)); err != nil {
		out.Close()
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chmod(destination, 0o600)
}
