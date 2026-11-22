package certd

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInternalCAMTLSCRLStandbyAndCertbot(t *testing.T) {
	dir := t.TempDir()
	fakeCertbot := filepath.Join(dir, "fake-certbot.sh")
	_ = os.WriteFile(fakeCertbot, []byte("#!/bin/sh\necho \"certbot-ok:$*\"\nexit 0\n"), 0o755)

	opts := Options{
		HAProxyCertsDir: filepath.Join(dir, "certs"),
		CARootDir:       filepath.Join(dir, "ca"),
		StandbyDir:      filepath.Join(dir, "standby"),
		DNSCredsDir:     filepath.Join(dir, "dns"),
		CertbotBin:      fakeCertbot,
	}
	mgr := NewManager(opts, nil)

	// 1. Ensure internal CA creates ECDSA P-256 CA + initial CRL.
	caInfo, created, err := mgr.EnsureInternalCA("Test Gateway CA", 365)
	if err != nil || !created || !caInfo.IsCA || caInfo.KeyType != "ECDSA-P-256" {
		t.Fatalf("EnsureInternalCA: info=%+v created=%v err=%v", caInfo, created, err)
	}
	// Second call is idempotent.
	_, created2, err := mgr.EnsureInternalCA("Test Gateway CA", 365)
	if err != nil || created2 {
		t.Fatalf("expected second EnsureInternalCA created=false, got created=%v err=%v", created2, err)
	}

	// 2. Issue server cert (installed to HAProxyCertsDir) + mTLS client cert, then revoke client cert.
	srvInfo, _, err := mgr.IssueInternalCert("app.internal", []string{"app.internal", "10.0.0.5"}, "server", 90, true)
	if err != nil || srvInfo.SubjectCN != "app.internal" || !srvInfo.HasPrivateKey {
		t.Fatalf("IssueInternalCert server: %+v err=%v", srvInfo, err)
	}
	cliInfo, _, err := mgr.IssueInternalCert("alice@gateway", nil, "client", 90, false)
	if err != nil || cliInfo.Serial == "" {
		t.Fatalf("IssueInternalCert client: %+v err=%v", cliInfo, err)
	}
	revoked, err := mgr.RevokeInternalCert(cliInfo.Serial, "key_compromise")
	if err != nil || len(revoked) != 1 || revoked[0].Serial != cliInfo.Serial {
		t.Fatalf("RevokeInternalCert: %+v err=%v", revoked, err)
	}

	// Verify exported CRL is a valid signed X.509 v2 CRL containing the revoked serial!
	caPEM, crlPEM, err := mgr.ExportInternalCA()
	if err != nil || caPEM == "" || crlPEM == "" {
		t.Fatalf("ExportInternalCA failed: err=%v", err)
	}
	crlBlk, _ := pem.Decode([]byte(crlPEM))
	crl, err := x509.ParseRevocationList(crlBlk.Bytes)
	if err != nil || len(crl.RevokedCertificateEntries) != 1 {
		t.Fatalf("invalid generated CRL: err=%v entries=%d", err, len(crl.RevokedCertificateEntries))
	}

	// 3. Standby store -> delete live -> activate standby -> restores live PEM.
	if _, err := mgr.StandbyStore("app.internal.pem"); err != nil {
		t.Fatalf("StandbyStore: %v", err)
	}
	_ = os.Remove(filepath.Join(opts.HAProxyCertsDir, "app.internal.pem"))
	if _, err := mgr.StandbyActivate("app.internal.pem"); err != nil {
		t.Fatalf("StandbyActivate: %v", err)
	}
	if _, err := os.Stat(filepath.Join(opts.HAProxyCertsDir, "app.internal.pem")); err != nil {
		t.Fatalf("expected live cert restored by StandbyActivate: %v", err)
	}

	// 4. Certbot issuance with DNS-01 profile builds ephemeral INI creds and invokes certbot.
	_, err = mgr.SaveDNSProfile("cf", "cloudflare", 60, map[string]string{"dns_cloudflare_api_token": "tok"})
	if err != nil {
		t.Fatalf("SaveDNSProfile: %v", err)
	}
	res, err := mgr.IssueWithCertbot(context.Background(), IssueRequest{
		Domains: []string{"*.example.com"}, Email: "ops@example.com", Challenge: "dns-01", DNSProfile: "cf", DryRun: true,
	})
	if err != nil || res["ok"] != true || !strings.Contains(res["stdout"].(string), "--dns-cloudflare") {
		t.Fatalf("IssueWithCertbot: %+v err=%v", res, err)
	}
}
