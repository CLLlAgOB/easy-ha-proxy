package stages

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/engine"
)

// nativeFiles is the install block's rescue: the binaries replaced so far are
// kept (a hard link to the old file, which the atomic write leaves alone), so
// a failure puts every one of them back and removes the ones that were new.
type nativeFiles struct {
	backups map[string]string // host path -> its backup
	created []string
}

func (n *nativeFiles) fail(cause error) error {
	for path, backup := range n.backups {
		os.Rename(backup, path)
	}
	for _, path := range n.created {
		os.Remove(path)
	}
	n.backups, n.created = nil, nil
	return fmt.Errorf("Could not install the verified native bundle. Service restarts were skipped. (%v)", cause)
}

// drop removes the backups once both files are in place.
func (n *nativeFiles) drop() error {
	for path, backup := range n.backups {
		if err := os.Remove(backup); err != nil && !os.IsNotExist(err) {
			return err
		}
		delete(n.backups, path)
	}
	n.created = nil
	return nil
}

// nativeFile is one of the binaries, written as File writes it once its
// predecessor is kept.
type nativeFile struct {
	engine.File
	set *nativeFiles
}

func (f *nativeFile) Apply(sys *engine.System, c engine.Change) error {
	path := sys.Path(f.Path)
	if f.set.backups == nil {
		f.set.backups = map[string]string{}
	}
	if _, err := os.Lstat(path); err == nil {
		backup := path + ".ehp-previous"
		os.Remove(backup)
		if err := os.Link(path, backup); err != nil {
			return f.set.fail(err)
		}
		f.set.backups[path] = backup
	} else {
		f.set.created = append(f.set.created, path)
	}
	if err := f.File.Apply(sys, c); err != nil {
		return f.set.fail(err)
	}
	return nil
}

// fileSHA256 is stat's checksum with checksum_algorithm: sha256.
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
