package certd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/alerts"
)

// DNSProfile stores one validated DNS-01 credential profile.
type DNSProfile struct {
	Name        string            `json:"name"`
	Provider    string            `json:"provider"`
	Propagation int               `json:"propagation_seconds"`
	Credentials map[string]string `json:"credentials"`
	UpdatedAt   string            `json:"updated_at"`
}

// Redacted returns a copy safe for UI responses with all secret values masked.
func (p DNSProfile) Redacted() DNSProfile {
	cp := p
	cp.Credentials = make(map[string]string, len(p.Credentials))
	for k, v := range p.Credentials {
		if v != "" {
			cp.Credentials[k] = "***"
		} else {
			cp.Credentials[k] = ""
		}
	}
	return cp
}

// TrashEntry records a deleted certificate moved to trash for safe recovery.
type TrashEntry struct {
	ID        string   `json:"id"`
	OrigName  string   `json:"orig_name"`
	DeletedAt string   `json:"deleted_at"`
	Cert      CertInfo `json:"cert"`
}

// Manager implements certificate inventory, expiry alerts, DNS-01 profiles, and trash.
type Manager struct {
	mu     sync.Mutex
	Opts   Options
	Alerts *alerts.Client
	NowFn  func() time.Time
}

// NewManager creates a certificate Manager.
func NewManager(opts Options, alertClient *alerts.Client) *Manager {
	return &Manager{
		Opts:   opts,
		Alerts: alertClient,
		NowFn:  func() time.Time { return time.Now().UTC() },
	}
}

func (m *Manager) now() time.Time {
	if m.NowFn != nil {
		return m.NowFn()
	}
	return time.Now().UTC()
}

// ListAll returns HAProxy PEMs, Let's Encrypt live lineages, and standby certs.
func (m *Manager) ListAll() (map[string]any, error) {
	now := m.now()
	hap, err := ListPEMDir(m.Opts.HAProxyCertsDir, now)
	if err != nil {
		return nil, err
	}
	le, err := ListLELive(m.Opts.LERootDir, now)
	if err != nil {
		return nil, err
	}
	standby, err := ListPEMDir(m.Opts.StandbyDir, now)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"ok":      true,
		"haproxy": hap,
		"le":      le,
		"standby": standby,
	}, nil
}

// CheckExpiringCerts inspects live HAProxy certs and sends certificate.expiring alerts.
func (m *Manager) CheckExpiringCerts(ctx context.Context) []CertInfo {
	now := m.now()
	certs, err := ListPEMDir(m.Opts.HAProxyCertsDir, now)
	if err != nil {
		return nil
	}
	var expiring []CertInfo
	for _, c := range certs {
		if c.ExpiringSoon {
			expiring = append(expiring, c)
		}
		if m.Alerts != nil && m.Alerts.Enabled() {
			sev := "warning"
			summary := fmt.Sprintf("Certificate %s expires in %d day(s)", c.Name, c.DaysLeft)
			if c.Expired {
				sev = "critical"
				summary = fmt.Sprintf("Certificate %s has expired", c.Name)
			} else if !c.ExpiringSoon {
				summary = fmt.Sprintf("Certificate %s is valid (%d days left)", c.Name, c.DaysLeft)
			}
			m.Alerts.Observe(ctx, alerts.Observation{
				Rule:     "certificate.expiring",
				Subject:  c.Name,
				Active:   alerts.BoolPtr(c.ExpiringSoon),
				Severity: sev,
				Summary:  summary,
			})
		}
	}
	return expiring
}

// UploadPEM validates and atomically writes a PEM bundle into HAProxyCertsDir.
func (m *Manager) UploadPEM(name string, pemBytes []byte) (CertInfo, error) {
	if !CertFileRe.MatchString(name) {
		return CertInfo{}, errors.New("invalid certificate filename")
	}
	info, err := InspectPEMBytes(pemBytes, m.now())
	if err != nil {
		return CertInfo{}, err
	}
	if !info.HasPrivateKey {
		return CertInfo{}, errors.New("HAProxy PEM bundle must include a private key")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := os.MkdirAll(m.Opts.HAProxyCertsDir, 0o750); err != nil {
		return CertInfo{}, err
	}
	target := filepath.Join(m.Opts.HAProxyCertsDir, name)
	if err := writeAtomic(target, pemBytes, 0o640); err != nil {
		return CertInfo{}, err
	}
	info.Name = name
	info.Path = target
	return info, nil
}

// MoveToTrash moves a HAProxy PEM file safely into TrashDir with metadata.
func (m *Manager) MoveToTrash(name string) (TrashEntry, error) {
	if !CertFileRe.MatchString(name) {
		return TrashEntry{}, errors.New("invalid certificate filename")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	src := filepath.Join(m.Opts.HAProxyCertsDir, name)
	raw, err := os.ReadFile(src)
	if err != nil {
		return TrashEntry{}, err
	}
	info, _ := InspectPEMBytes(raw, m.now())
	info.Name = name
	if err := os.MkdirAll(m.Opts.TrashDir, 0o700); err != nil {
		return TrashEntry{}, err
	}
	id := fmt.Sprintf("%d-%s", m.now().UnixNano(), strings.TrimSuffix(name, ".pem"))
	entry := TrashEntry{
		ID:        id,
		OrigName:  name,
		DeletedAt: m.now().Format(time.RFC3339),
		Cert:      info,
	}
	metaBytes, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return TrashEntry{}, err
	}
	if err := writeAtomic(filepath.Join(m.Opts.TrashDir, id+".pem"), raw, 0o600); err != nil {
		return TrashEntry{}, err
	}
	if err := writeAtomic(filepath.Join(m.Opts.TrashDir, id+".json"), metaBytes, 0o600); err != nil {
		return TrashEntry{}, err
	}
	if err := os.Remove(src); err != nil {
		return TrashEntry{}, err
	}
	return entry, nil
}

// ListTrash lists all recoverable certificate entries in TrashDir.
func (m *Manager) ListTrash() ([]TrashEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entries, err := os.ReadDir(m.Opts.TrashDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []TrashEntry{}, nil
		}
		return nil, err
	}
	var out []TrashEntry
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(m.Opts.TrashDir, ent.Name()))
		if err != nil {
			continue
		}
		var te TrashEntry
		if json.Unmarshal(raw, &te) == nil {
			out = append(out, te)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DeletedAt > out[j].DeletedAt })
	return out, nil
}

// RestoreFromTrash restores a trashed PEM back to HAProxyCertsDir.
func (m *Manager) RestoreFromTrash(id string) (TrashEntry, error) {
	if id == "" || strings.ContainsAny(id, "/\\") || strings.Contains(id, "..") {
		return TrashEntry{}, errors.New("invalid trash id")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	metaPath := filepath.Join(m.Opts.TrashDir, id+".json")
	pemPath := filepath.Join(m.Opts.TrashDir, id+".pem")
	metaBytes, err := os.ReadFile(metaPath)
	if err != nil {
		return TrashEntry{}, err
	}
	var te TrashEntry
	if err := json.Unmarshal(metaBytes, &te); err != nil {
		return TrashEntry{}, err
	}
	if !CertFileRe.MatchString(te.OrigName) {
		return TrashEntry{}, errors.New("corrupt trash metadata")
	}
	pemBytes, err := os.ReadFile(pemPath)
	if err != nil {
		return TrashEntry{}, err
	}
	if err := os.MkdirAll(m.Opts.HAProxyCertsDir, 0o750); err != nil {
		return TrashEntry{}, err
	}
	if err := writeAtomic(filepath.Join(m.Opts.HAProxyCertsDir, te.OrigName), pemBytes, 0o640); err != nil {
		return TrashEntry{}, err
	}
	_ = os.Remove(pemPath)
	_ = os.Remove(metaPath)
	return te, nil
}

// PurgeTrash permanently removes one trash entry (or all when id == "*").
func (m *Manager) PurgeTrash(id string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if id == "*" {
		entries, err := os.ReadDir(m.Opts.TrashDir)
		if err != nil {
			if os.IsNotExist(err) {
				return 0, nil
			}
			return 0, err
		}
		n := 0
		for _, ent := range entries {
			if strings.HasSuffix(ent.Name(), ".json") {
				n++
			}
			_ = os.Remove(filepath.Join(m.Opts.TrashDir, ent.Name()))
		}
		return n, nil
	}
	if id == "" || strings.ContainsAny(id, "/\\") || strings.Contains(id, "..") {
		return 0, errors.New("invalid trash id")
	}
	_ = os.Remove(filepath.Join(m.Opts.TrashDir, id+".pem"))
	if err := os.Remove(filepath.Join(m.Opts.TrashDir, id+".json")); err != nil {
		return 0, err
	}
	return 1, nil
}

// ListDNSProfiles returns all saved DNS-01 profiles with secrets redacted.
func (m *Manager) ListDNSProfiles() ([]DNSProfile, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entries, err := os.ReadDir(m.Opts.DNSCredsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []DNSProfile{}, nil
		}
		return nil, err
	}
	out := make([]DNSProfile, 0)
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(m.Opts.DNSCredsDir, ent.Name()))
		if err != nil {
			continue
		}
		var p DNSProfile
		if json.Unmarshal(raw, &p) == nil {
			out = append(out, p.Redacted())
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// SaveDNSProfile validates and atomically persists a DNS-01 profile with mode 0600,
// preserving existing secret values when the caller echoes "***".
func (m *Manager) SaveDNSProfile(name, provider string, propagation int, creds map[string]string) (DNSProfile, error) {
	if !DNSProfileRe.MatchString(name) {
		return DNSProfile{}, errors.New("profile name must match ^[a-z0-9][a-z0-9-]{0,39}$")
	}
	spec, ok := DNSProviders[provider]
	if !ok {
		return DNSProfile{}, fmt.Errorf("unsupported DNS provider: %s", provider)
	}
	if propagation == 0 {
		propagation = DNSPropagationDefault
	}
	if propagation < DNSPropagationMin {
		propagation = DNSPropagationMin
	}
	if propagation > DNSPropagationMax {
		propagation = DNSPropagationMax
	}
	allowedKeys := make(map[string]struct{}, len(spec.Keys))
	for _, k := range spec.Keys {
		allowedKeys[k] = struct{}{}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	path := filepath.Join(m.Opts.DNSCredsDir, name+".json")
	var prev DNSProfile
	if raw, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(raw, &prev)
	}

	clean := make(map[string]string, len(spec.Keys))
	for k, v := range creds {
		if _, ok := allowedKeys[k]; !ok {
			return DNSProfile{}, fmt.Errorf("unexpected credential key for %s: %s", provider, k)
		}
		if len(v) > DNSValueMax {
			return DNSProfile{}, errors.New("credential value exceeds maximum length")
		}
		if v == "***" && prev.Credentials != nil {
			clean[k] = prev.Credentials[k]
		} else {
			clean[k] = strings.TrimSpace(v)
		}
	}
	prof := DNSProfile{
		Name:        name,
		Provider:    provider,
		Propagation: propagation,
		Credentials: clean,
		UpdatedAt:   m.now().Format(time.RFC3339),
	}
	data, err := json.MarshalIndent(prof, "", "  ")
	if err != nil {
		return DNSProfile{}, err
	}
	if err := os.MkdirAll(m.Opts.DNSCredsDir, 0o700); err != nil {
		return DNSProfile{}, err
	}
	if err := writeAtomic(path, append(data, '\n'), 0o600); err != nil {
		return DNSProfile{}, err
	}
	return prof.Redacted(), nil
}

// DeleteDNSProfile deletes a saved DNS-01 credential profile.
func (m *Manager) DeleteDNSProfile(name string) error {
	if !DNSProfileRe.MatchString(name) {
		return errors.New("invalid profile name")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return os.Remove(filepath.Join(m.Opts.DNSCredsDir, name+".json"))
}

func writeAtomic(target string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(target)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(target)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, target); err != nil {
		cleanup()
		return err
	}
	return nil
}
