package certd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// RevokedEntry tracks one revoked certificate serial for X.509 v2 CRL generation.
type RevokedEntry struct {
	Serial    string `json:"serial"`
	RevokedAt string `json:"revoked_at"`
	Reason    string `json:"reason,omitempty"`
}

func (m *Manager) internalCADir() string {
	return filepath.Join(m.Opts.CARootDir, "internal")
}

// EnsureInternalCA creates an ECDSA P-256 internal root CA and initial CRL if absent.
func (m *Manager) EnsureInternalCA(commonName string, validDays int) (CertInfo, bool, error) {
	if strings.TrimSpace(commonName) == "" {
		commonName = "easy-ha-proxy Internal CA"
	}
	if validDays <= 0 {
		validDays = 3650
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	caDir := m.internalCADir()
	certPath := filepath.Join(caDir, "ca.crt")
	keyPath := filepath.Join(caDir, "ca.key")

	if _, err := os.Stat(certPath); err == nil {
		if _, kerr := os.Stat(keyPath); kerr == nil {
			info, err := InspectPEMFile(certPath, m.now())
			return info, false, err
		}
	}
	info, err := m.generateInternalCALocked(caDir, commonName, validDays)
	return info, true, err
}

// RotateInternalCA replaces the internal CA certificate and key with a fresh ECDSA P-256 CA.
func (m *Manager) RotateInternalCA(commonName string, validDays int) (CertInfo, error) {
	if strings.TrimSpace(commonName) == "" {
		commonName = "easy-ha-proxy Internal CA"
	}
	if validDays <= 0 {
		validDays = 3650
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.generateInternalCALocked(m.internalCADir(), commonName, validDays)
}

func (m *Manager) generateInternalCALocked(caDir, commonName string, validDays int) (CertInfo, error) {
	if err := os.MkdirAll(caDir, 0o700); err != nil {
		return CertInfo{}, err
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return CertInfo{}, err
	}
	now := m.now()
	serial, err := randomSerial()
	if err != nil {
		return CertInfo{}, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return CertInfo{}, err
	}
	ski := sha256.Sum256(pubDER)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"easy-ha-proxy"}},
		SubjectKeyId:          ski[:20],
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(0, 0, validDays),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return CertInfo{}, err
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		return CertInfo{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return CertInfo{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := writeAtomic(filepath.Join(caDir, "ca.crt"), certPEM, 0o644); err != nil {
		return CertInfo{}, err
	}
	if err := writeAtomic(filepath.Join(caDir, "ca.key"), keyPEM, 0o600); err != nil {
		return CertInfo{}, err
	}
	_ = writeAtomic(filepath.Join(caDir, "revoked.json"), []byte("[]\n"), 0o600)
	if err := m.rebuildCRLLocked(caDir, caCert, priv, nil); err != nil {
		return CertInfo{}, err
	}
	info, err := InspectPEMBytes(certPEM, now)
	info.Name = "ca.crt"
	info.Path = filepath.Join(caDir, "ca.crt")
	return info, err
}

func (m *Manager) loadInternalCALocked() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	caDir := m.internalCADir()
	certBytes, err := os.ReadFile(filepath.Join(caDir, "ca.crt"))
	if err != nil {
		return nil, nil, errors.New("internal CA is not initialized")
	}
	keyBytes, err := os.ReadFile(filepath.Join(caDir, "ca.key"))
	if err != nil {
		return nil, nil, errors.New("internal CA key is missing")
	}
	cb, _ := pem.Decode(certBytes)
	if cb == nil {
		return nil, nil, errors.New("corrupt internal CA certificate")
	}
	caCert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	kb, _ := pem.Decode(keyBytes)
	if kb == nil {
		return nil, nil, errors.New("corrupt internal CA private key")
	}
	caKey, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return caCert, caKey, nil
}

// IssueInternalCert signs a server or mTLS client certificate using the internal CA.
func (m *Manager) IssueInternalCert(cn string, sans []string, kind string, validDays int, installToHAProxy bool) (CertInfo, string, error) {
	cn = strings.TrimSpace(cn)
	if cn == "" {
		return CertInfo{}, "", errors.New("common_name is required")
	}
	if validDays <= 0 {
		validDays = 365
	}
	if validDays > 3650 {
		validDays = 3650
	}
	kind = strings.ToLower(strings.TrimSpace(kind))
	if kind == "" {
		kind = "server"
	}
	if kind != "server" && kind != "client" {
		return CertInfo{}, "", errors.New("kind must be server or client")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	caCert, caKey, err := m.loadInternalCALocked()
	if err != nil {
		return CertInfo{}, "", err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return CertInfo{}, "", err
	}
	serial, err := randomSerial()
	if err != nil {
		return CertInfo{}, "", err
	}
	now := m.now()
	eku := x509.ExtKeyUsageServerAuth
	if kind == "client" {
		eku = x509.ExtKeyUsageClientAuth
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.AddDate(0, 0, validDays),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{eku},
	}
	if kind == "server" {
		seenDNS := map[string]struct{}{}
		addSAN := func(s string) {
			s = strings.TrimSpace(s)
			if s == "" {
				return
			}
			if ip := net.ParseIP(s); ip != nil {
				tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			} else if _, dup := seenDNS[s]; !dup {
				seenDNS[s] = struct{}{}
				tmpl.DNSNames = append(tmpl.DNSNames, s)
			}
		}
		addSAN(cn)
		for _, s := range sans {
			addSAN(s)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return CertInfo{}, "", err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		return CertInfo{}, "", err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	bundle := append(append(append([]byte(nil), certPEM...), caPEM...), keyPEM...)

	if installToHAProxy && kind == "server" {
		fname := sanitizeCertFilename(cn) + ".pem"
		if err := os.MkdirAll(m.Opts.HAProxyCertsDir, 0o750); err != nil {
			return CertInfo{}, "", err
		}
		if err := writeAtomic(filepath.Join(m.Opts.HAProxyCertsDir, fname), bundle, 0o640); err != nil {
			return CertInfo{}, "", err
		}
	}
	info, err := InspectPEMBytes(bundle, now)
	return info, string(bundle), err
}

// RevokeInternalCert adds a serial to revoked.json and regenerates ca.crl.
func (m *Manager) RevokeInternalCert(serialHex, reason string) ([]RevokedEntry, error) {
	cleanSerial := strings.ToUpper(strings.TrimSpace(serialHex))
	if cleanSerial == "" {
		return nil, errors.New("serial is required")
	}
	if _, ok := new(big.Int).SetString(cleanSerial, 16); !ok {
		return nil, errors.New("serial must be a hexadecimal string")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	caCert, caKey, err := m.loadInternalCALocked()
	if err != nil {
		return nil, err
	}
	caDir := m.internalCADir()
	list := m.readRevokedLocked(caDir)
	for _, e := range list {
		if e.Serial == cleanSerial {
			return list, nil
		}
	}
	list = append(list, RevokedEntry{
		Serial:    cleanSerial,
		RevokedAt: m.now().Format(time.RFC3339),
		Reason:    strings.TrimSpace(reason),
	})
	raw, _ := json.MarshalIndent(list, "", "  ")
	if err := writeAtomic(filepath.Join(caDir, "revoked.json"), append(raw, '\n'), 0o600); err != nil {
		return nil, err
	}
	if err := m.rebuildCRLLocked(caDir, caCert, caKey, list); err != nil {
		return nil, err
	}
	return list, nil
}

// ListRevoked returns all revoked certificate serials for the internal CA.
func (m *Manager) ListRevoked() []RevokedEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.readRevokedLocked(m.internalCADir())
}

func (m *Manager) readRevokedLocked(caDir string) []RevokedEntry {
	var list []RevokedEntry
	if raw, err := os.ReadFile(filepath.Join(caDir, "revoked.json")); err == nil {
		_ = json.Unmarshal(raw, &list)
	}
	if list == nil {
		list = []RevokedEntry{}
	}
	return list
}

func (m *Manager) rebuildCRLLocked(caDir string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, revoked []RevokedEntry) error {
	now := m.now()
	entries := make([]x509.RevocationListEntry, 0, len(revoked))
	for _, r := range revoked {
		sn, ok := new(big.Int).SetString(r.Serial, 16)
		if !ok {
			continue
		}
		t, err := time.Parse(time.RFC3339, r.RevokedAt)
		if err != nil {
			t = now
		}
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   sn,
			RevocationTime: t,
		})
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(now.Unix()),
		ThisUpdate:                now,
		NextUpdate:                now.AddDate(0, 0, 30),
		RevokedCertificateEntries: entries,
	}, caCert, caKey)
	if err != nil {
		return err
	}
	crlPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})
	return writeAtomic(filepath.Join(caDir, "ca.crl"), crlPEM, 0o644)
}

// ExportInternalCA returns the internal CA public PEM certificate (and CRL if present).
func (m *Manager) ExportInternalCA() (string, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	caDir := m.internalCADir()
	certRaw, err := os.ReadFile(filepath.Join(caDir, "ca.crt"))
	if err != nil {
		return "", "", errors.New("internal CA is not initialized")
	}
	crlRaw, _ := os.ReadFile(filepath.Join(caDir, "ca.crl"))
	return string(certRaw), string(crlRaw), nil
}

// DeleteInternalCA removes the internal CA directory.
func (m *Manager) DeleteInternalCA() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return os.RemoveAll(m.internalCADir())
}

// --- Standby certificate lifecycle -----------------------------------------

// StandbyStore copies an active HAProxy PEM into StandbyDir.
func (m *Manager) StandbyStore(name string) (CertInfo, error) {
	if !CertFileRe.MatchString(name) {
		return CertInfo{}, errors.New("invalid certificate filename")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	raw, err := os.ReadFile(filepath.Join(m.Opts.HAProxyCertsDir, name))
	if err != nil {
		return CertInfo{}, err
	}
	if err := os.MkdirAll(m.Opts.StandbyDir, 0o700); err != nil {
		return CertInfo{}, err
	}
	dst := filepath.Join(m.Opts.StandbyDir, name)
	if err := writeAtomic(dst, raw, 0o600); err != nil {
		return CertInfo{}, err
	}
	return InspectPEMFile(dst, m.now())
}

// StandbyActivate deploys a standby PEM into live HAProxyCertsDir.
func (m *Manager) StandbyActivate(name string) (CertInfo, error) {
	if !CertFileRe.MatchString(name) {
		return CertInfo{}, errors.New("invalid certificate filename")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	raw, err := os.ReadFile(filepath.Join(m.Opts.StandbyDir, name))
	if err != nil {
		return CertInfo{}, err
	}
	if err := os.MkdirAll(m.Opts.HAProxyCertsDir, 0o750); err != nil {
		return CertInfo{}, err
	}
	dst := filepath.Join(m.Opts.HAProxyCertsDir, name)
	if err := writeAtomic(dst, raw, 0o640); err != nil {
		return CertInfo{}, err
	}
	return InspectPEMFile(dst, m.now())
}

// StandbyDelete removes a standby PEM from StandbyDir.
func (m *Manager) StandbyDelete(name string) error {
	if !CertFileRe.MatchString(name) {
		return errors.New("invalid certificate filename")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return os.Remove(filepath.Join(m.Opts.StandbyDir, name))
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	if n.Sign() <= 0 {
		return big.NewInt(1), nil
	}
	return n, nil
}

func sanitizeCertFilename(cn string) string {
	var b strings.Builder
	for _, r := range cn {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), ".")
	if out == "" {
		return "internal-cert"
	}
	return out
}
