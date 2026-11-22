package certd

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
	"time"
)

func sortStrings(s []string) { sort.Strings(s) }

type x509Cert = x509.Certificate

// extractPEMBlocks is _extract_pem_blocks: complete blocks with an exact label.
func extractPEMBlocks(data []byte, label string) ([][]byte, error) {
	begin := []byte("-----BEGIN " + label + "-----")
	end := []byte("-----END " + label + "-----")
	blocks := [][]byte{}
	offset := 0
	for {
		start := bytes.Index(data[offset:], begin)
		if start < 0 {
			break
		}
		start += offset
		finish := bytes.Index(data[start+len(begin):], end)
		if finish < 0 {
			return nil, vErr("incomplete PEM block: %s", label)
		}
		finish += start + len(begin) + len(end)
		block := append(append([]byte{}, data[start:finish]...), '\n')
		blocks = append(blocks, block)
		offset = finish
	}
	return blocks, nil
}

func decodeBlock(block []byte) *pem.Block {
	b, _ := pem.Decode(block)
	return b
}

func loadPEMCertificates(data []byte) ([]*x509.Certificate, error) {
	blocks, err := extractPEMBlocks(data, "CERTIFICATE")
	if err != nil {
		return nil, err
	}
	out := []*x509.Certificate{}
	for _, raw := range blocks {
		b := decodeBlock(raw)
		if b == nil {
			return nil, vErr("invalid X.509 certificate in PEM data")
		}
		cert, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, vErr("invalid X.509 certificate in PEM data")
		}
		out = append(out, cert)
	}
	return out, nil
}

func parsePrivateKeyDER(der []byte) (crypto.Signer, error) {
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if s, ok := k.(crypto.Signer); ok {
			return s, nil
		}
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	return nil, fmt.Errorf("unsupported private key")
}

// loadSinglePrivateKey is _load_single_private_key.
func loadSinglePrivateKey(data []byte) (crypto.Signer, error) {
	blocks := [][]byte{}
	for _, label := range []string{"PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"} {
		found, err := extractPEMBlocks(data, label)
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, found...)
	}
	if len(blocks) != 1 {
		return nil, vErr("PEM must contain exactly one unencrypted private key")
	}
	b := decodeBlock(blocks[0])
	if b == nil || len(b.Headers) > 0 {
		return nil, vErr("private key is encrypted or invalid")
	}
	key, err := parsePrivateKeyDER(b.Bytes)
	if err != nil {
		return nil, vErr("private key is encrypted or invalid")
	}
	return key, nil
}

func publicKeyBytes(pub crypto.PublicKey) []byte {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil
	}
	return der
}

func samePublicKey(a, b crypto.PublicKey) bool {
	x, y := publicKeyBytes(a), publicKeyBytes(b)
	return x != nil && bytes.Equal(x, y)
}

// hostnameMatchesPattern is _hostname_matches_pattern.
func hostnameMatchesPattern(host, pattern string) bool {
	host, pattern = strings.ToLower(host), strings.ToLower(pattern)
	if host == pattern {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:]
		if strings.HasSuffix(host, suffix) && strings.Count(host, ".") == strings.Count(suffix, ".") {
			return true
		}
	}
	return false
}

func certMatchesDomain(cert *x509.Certificate, domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false
	}
	for _, name := range certDNSNames(cert) {
		if hostnameMatchesPattern(domain, name) {
			return true
		}
	}
	return false
}

// validateServerPEM is _validate_server_pem.
func validateServerPEM(data []byte, domain string) ([]*x509.Certificate, crypto.Signer, error) {
	certs, err := loadPEMCertificates(data)
	if err != nil {
		return nil, nil, err
	}
	if len(certs) == 0 {
		return nil, nil, vErr("PEM does not contain an X.509 certificate")
	}
	key, err := loadSinglePrivateKey(data)
	if err != nil {
		return nil, nil, err
	}
	if !samePublicKey(certs[0].PublicKey, key.Public()) {
		return nil, nil, vErr("private key does not match the first certificate")
	}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if k.N.BitLen() < 2048 {
			return nil, nil, vErr("RSA private key must be at least 2048 bits")
		}
	case *ecdsa.PrivateKey:
		if k.Curve.Params().BitSize < 256 {
			return nil, nil, vErr("EC private key must be at least 256 bits")
		}
	}
	if domain != "" && !certMatchesDomain(certs[0], domain) {
		return nil, nil, vErr("certificate does not cover domain %s", pyRepr(domain))
	}
	return certs, key, nil
}

// pyRepr is repr() of a str.
func pyRepr(s string) string {
	if strings.Contains(s, "'") && !strings.Contains(s, `"`) {
		return `"` + s + `"`
	}
	return "'" + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), "'", `\'`) + "'"
}

func certificateLabel(cert *x509.Certificate) string {
	if cn := firstAttr(cert.Subject.Names, oidCN); cn != "" {
		return cn
	}
	return cert.Subject.String()
}

var (
	oidCN = []int{2, 5, 4, 3}
	oidO  = []int{2, 5, 4, 10}
)

func firstAttr(names []pkixAttr, oid []int) string {
	for _, attr := range names {
		if attr.Type.Equal(oid) {
			return fmt.Sprint(attr.Value)
		}
	}
	return ""
}

func issuerLabel(cert *x509.Certificate) string {
	if cn := firstAttr(cert.Issuer.Names, oidCN); cn != "" {
		return cn
	}
	if o := firstAttr(cert.Issuer.Names, oidO); o != "" {
		return o
	}
	return cert.Issuer.String()
}

// validateCABundle is _validate_ca_bundle.
func validateCABundle(data []byte) ([]*x509.Certificate, error) {
	for _, marker := range []string{"BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "BEGIN EC PRIVATE KEY"} {
		if bytes.Contains(data, []byte(marker)) {
			return nil, vErr("CA bundle must not contain a private key")
		}
	}
	certs, err := loadPEMCertificates(data)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, vErr("CA bundle does not contain certificates")
	}
	for _, c := range certs {
		if !c.BasicConstraintsValid {
			return nil, vErr("every imported certificate must be a CA certificate")
		}
		if !c.IsCA {
			return nil, vErr("every imported certificate must have CA=true")
		}
	}
	return certs, nil
}

func certificateIsAuthority(cert *x509.Certificate) bool {
	return cert.BasicConstraintsValid && cert.IsCA
}

func isSelfSigned(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawSubject, cert.RawIssuer)
}

func keyFamily(cert *x509.Certificate) string {
	switch cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "rsa"
	case *ecdsa.PublicKey:
		return "ecdsa"
	case ed25519.PublicKey:
		return "ed25519publickey"
	}
	return "unknown"
}

func fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func certPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func keyPEMPKCS8(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func curveName(pub *ecdsa.PublicKey) string {
	switch pub.Curve.Params().Name {
	case "P-256":
		return "secp256r1"
	case "P-384":
		return "secp384r1"
	case "P-521":
		return "secp521r1"
	}
	return pub.Curve.Params().Name
}

// describePEM is _describe_pem.
func describePEM(data []byte) (map[string]any, error) {
	certs, err := loadPEMCertificates(data)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, vErr("PEM does not contain an X.509 certificate")
	}
	leaf := certs[0]
	now := time.Now().UTC()
	keyType := "unknown"
	switch k := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		keyType = fmt.Sprintf("RSA %d", k.N.BitLen())
	case *ecdsa.PublicKey:
		keyType = "EC " + curveName(k)
	case ed25519.PublicKey:
		keyType = "Ed25519PublicKey"
	}
	notAfter, notBefore := leaf.NotAfter.UTC(), leaf.NotBefore.UTC()
	return map[string]any{
		"subject": certificateLabel(leaf), "issuer": issuerLabel(leaf), "names": certDNSNames(leaf),
		"not_before": fmtDate(notBefore), "not_after": fmtDate(notAfter),
		"days_left": pyDays(notAfter.Sub(now)), "usable": !now.Before(notBefore) && now.Before(notAfter),
		"key_type": keyType, "chain_length": len(certs),
	}, nil
}

// describeCertificate is _describe_certificate.
func describeCertificate(cert *x509.Certificate) map[string]any {
	issuer := firstAttr(cert.Issuer.Names, oidCN)
	if issuer == "" {
		issuer = cert.Issuer.String()
	}
	names := []string{}
	if !certificateIsAuthority(cert) {
		names = certDNSNames(cert)
	}
	return map[string]any{
		"subject": certificateLabel(cert), "issuer": issuer, "not_before": fmtDate(cert.NotBefore),
		"not_after": fmtDate(cert.NotAfter), "sha256": fingerprint(cert), "dns_names": names,
		"self_signed": isSelfSigned(cert),
	}
}

// certificateIsIssuedBy is _certificate_is_issued_by.
func certificateIsIssuedBy(cert, authority *x509.Certificate) bool {
	if !bytes.Equal(cert.RawIssuer, authority.RawSubject) {
		return false
	}
	switch authority.PublicKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
	default:
		return false
	}
	return authority.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}

// chainForLeaf is _chain_for_leaf.
func chainForLeaf(leaf *x509.Certificate, authorities []*x509.Certificate) []*x509.Certificate {
	chain := []*x509.Certificate{}
	remaining := []*x509.Certificate{}
	for _, ca := range authorities {
		if !isSelfSigned(ca) {
			remaining = append(remaining, ca)
		}
	}
	current := leaf
	for {
		idx := -1
		for i, ca := range remaining {
			if bytes.Equal(ca.RawSubject, current.RawIssuer) {
				idx = i
				break
			}
		}
		if idx < 0 {
			return chain
		}
		issuer := remaining[idx]
		chain = append(chain, issuer)
		remaining = append(remaining[:idx], remaining[idx+1:]...)
		current = issuer
	}
}

// subjectCNs is _subject_cns.
func subjectCNs(certs []*x509.Certificate) []string {
	names := []string{}
	for _, c := range certs {
		for _, attr := range c.Subject.Names {
			if attr.Type.Equal(oidCN) {
				v := strings.TrimSpace(fmt.Sprint(attr.Value))
				if v != "" && !containsStr(names, v) {
					names = append(names, v)
				}
			}
		}
	}
	return names
}

func containsStr(list []string, s string) bool {
	for _, it := range list {
		if it == s {
			return true
		}
	}
	return false
}
