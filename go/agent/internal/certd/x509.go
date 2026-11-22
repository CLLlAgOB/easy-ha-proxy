package certd

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// CertInfo holds parsed X.509 certificate metadata inspected natively without invoking openssl.
type CertInfo struct {
	Name           string   `json:"name,omitempty"`
	Path           string   `json:"path,omitempty"`
	SubjectCN      string   `json:"subject_cn"`
	IssuerCN       string   `json:"issuer_cn"`
	SANs           []string `json:"sans"`
	Serial         string   `json:"serial"`
	SHA256         string   `json:"sha256"`
	KeyType        string   `json:"key_type"`
	HasPrivateKey  bool     `json:"has_private_key"`
	ChainLength    int      `json:"chain_length"`
	IsCA           bool     `json:"is_ca"`
	NotBefore      string   `json:"not_before"`
	NotAfter       string   `json:"not_after"`
	LifetimeDays   int      `json:"lifetime_days"`
	DaysLeft       int      `json:"days_left"`
	WarnDays       int      `json:"warn_days"`
	Expired        bool     `json:"expired"`
	ExpiringSoon   bool     `json:"expiring_soon"`
}

// InspectPEMBytes parses a PEM certificate bundle natively using Go's crypto/x509.
func InspectPEMBytes(data []byte, now time.Time) (CertInfo, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var certs []*x509.Certificate
	hasKey := false
	rest := data
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		switch {
		case blk.Type == "CERTIFICATE":
			c, err := x509.ParseCertificate(blk.Bytes)
			if err != nil {
				return CertInfo{}, fmt.Errorf("invalid X.509 certificate: %w", err)
			}
			certs = append(certs, c)
		case strings.Contains(blk.Type, "PRIVATE KEY"):
			hasKey = true
		}
	}
	if len(certs) == 0 {
		return CertInfo{}, errors.New("no CERTIFICATE block found in PEM")
	}

	leaf := certs[0]
	sans := make([]string, 0, len(leaf.DNSNames)+len(leaf.IPAddresses))
	sans = append(sans, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		sans = append(sans, ip.String())
	}

	sum := sha256.Sum256(leaf.Raw)
	lifetime := int(leaf.NotAfter.Sub(leaf.NotBefore).Hours() / 24)
	daysLeft := int(leaf.NotAfter.Sub(now).Hours() / 24)
	if leaf.NotAfter.Before(now) && daysLeft == 0 {
		daysLeft = -1
	}
	warnDays := CertWarnDays(lifetime)

	return CertInfo{
		SubjectCN:     leaf.Subject.CommonName,
		IssuerCN:      leaf.Issuer.CommonName,
		SANs:          sans,
		Serial:        strings.ToUpper(leaf.SerialNumber.Text(16)),
		SHA256:        hex.EncodeToString(sum[:]),
		KeyType:       describePublicKey(leaf.PublicKey),
		HasPrivateKey: hasKey,
		ChainLength:   len(certs),
		IsCA:          leaf.IsCA,
		NotBefore:     leaf.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:      leaf.NotAfter.UTC().Format(time.RFC3339),
		LifetimeDays:  lifetime,
		DaysLeft:      daysLeft,
		WarnDays:      warnDays,
		Expired:       !leaf.NotAfter.After(now),
		ExpiringSoon:  daysLeft <= warnDays,
	}, nil
}

func describePublicKey(pub any) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA-%s", k.Curve.Params().Name)
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return "unknown"
	}
}

// InspectPEMFile reads and parses a PEM file from disk.
func InspectPEMFile(path string, now time.Time) (CertInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return CertInfo{}, err
	}
	info, err := InspectPEMBytes(data, now)
	if err != nil {
		return CertInfo{}, err
	}
	info.Name = filepath.Base(path)
	info.Path = path
	return info, nil
}

// ListPEMDir inspects every *.pem file directly inside dir.
func ListPEMDir(dir string, now time.Time) ([]CertInfo, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []CertInfo{}, nil
		}
		return nil, err
	}
	out := make([]CertInfo, 0, len(entries))
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".pem") {
			continue
		}
		info, err := InspectPEMFile(filepath.Join(dir, ent.Name()), now)
		if err != nil {
			continue
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// ListLELive inspects Let's Encrypt live/<lineage>/fullchain.pem certificates.
func ListLELive(leRoot string, now time.Time) ([]CertInfo, error) {
	liveDir := filepath.Join(leRoot, "live")
	entries, err := os.ReadDir(liveDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []CertInfo{}, nil
		}
		return nil, err
	}
	out := make([]CertInfo, 0, len(entries))
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		fc := filepath.Join(liveDir, ent.Name(), "fullchain.pem")
		info, err := InspectPEMFile(fc, now)
		if err != nil {
			continue
		}
		info.Name = ent.Name()
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
