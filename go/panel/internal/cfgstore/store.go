// Package cfgstore manages safe reading, atomic backup-protected writing, and
// allow-listed download of the operator's HAProxy YAML configuration files
// under /opt/haproxy-admin/config.
package cfgstore

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// AllowedFiles maps short API kind names to their exact YAML filenames.
var AllowedFiles = map[string]string{
	"vars":            "vars.yml",
	"websites":        "websites.yml",
	"tcp":             "tcp.yml",
	"udp":             "udp.yml",
	"backend_presets": "backend_presets.yml",
}

// Store provides concurrency-safe atomic YAML config persistence with backups.
type Store struct {
	ConfigDir  string
	BackupDir  string
	HAProxyCfg string
	mu         sync.Mutex
}

// New creates a Store pointing to configDir, backupDir, and haproxyCfg.
func New(configDir, backupDir, haproxyCfg string) *Store {
	if strings.TrimSpace(configDir) == "" {
		configDir = "/opt/haproxy-admin/config"
	}
	if strings.TrimSpace(backupDir) == "" {
		backupDir = "/opt/haproxy-admin/backups"
	}
	if strings.TrimSpace(haproxyCfg) == "" {
		haproxyCfg = "/etc/haproxy/haproxy.cfg"
	}
	return &Store{
		ConfigDir:  configDir,
		BackupDir:  backupDir,
		HAProxyCfg: haproxyCfg,
	}
}

// ResolvePath returns the allow-listed absolute path for kind.
func (s *Store) ResolvePath(kind string) (string, string, error) {
	filename, ok := AllowedFiles[strings.ToLower(strings.TrimSpace(kind))]
	if !ok {
		return "", "", fmt.Errorf("unsupported configuration kind: %q", kind)
	}
	return filepath.Join(s.ConfigDir, filename), filename, nil
}

// Read returns the raw UTF-8 contents and SHA-256 fingerprint of kind.
func (s *Store) Read(kind string) ([]byte, string, string, error) {
	p, filename, err := s.ResolvePath(kind)
	if err != nil {
		return nil, "", "", err
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, filename, "", err
	}
	sum := sha256.Sum256(raw)
	return raw, filename, hex.EncodeToString(sum[:]), nil
}

// Write atomically backs up the previous file into BackupDir (if present) and
// writes content to kind with 0640 permissions.
func (s *Store) Write(kind string, content []byte) (string, error) {
	if len(content) == 0 {
		return "", errors.New("configuration content cannot be empty")
	}
	if len(content) > 4*1024*1024 {
		return "", errors.New("configuration file exceeds 4 MiB limit")
	}
	p, filename, err := s.ResolvePath(kind)
	if err != nil {
		return "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(s.ConfigDir, 0o755); err != nil {
		return "", err
	}
	if prev, err := os.ReadFile(p); err == nil && len(prev) > 0 && s.BackupDir != "" {
		if err := os.MkdirAll(s.BackupDir, 0o755); err == nil {
			ts := time.Now().UTC().Format("20060102150405")
			bak := filepath.Join(s.BackupDir, fmt.Sprintf("%s.bak.%s", filename, ts))
			_ = os.WriteFile(bak, prev, 0o600)
		}
	}

	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, content, 0o640); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, p); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:]), nil
}

// ReadLiveHAProxyCfg returns the active /etc/haproxy/haproxy.cfg contents.
func (s *Store) ReadLiveHAProxyCfg() ([]byte, error) {
	return os.ReadFile(s.HAProxyCfg)
}

// SnapshotHashes returns SHA-256 digests of all present YAML files in ConfigDir.
func (s *Store) SnapshotHashes() map[string]string {
	out := make(map[string]string, len(AllowedFiles))
	for kind := range AllowedFiles {
		if _, _, hash, err := s.Read(kind); err == nil {
			out[kind] = hash
		}
	}
	return out
}
