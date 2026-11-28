package certd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func testAuthority(t *testing.T) (*x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Easy HA Proxy Local Root CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func writeTestFile(t *testing.T, path, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The internal CA is not rotated or deleted while it vouches for clients
// (F19): rotating it left HAProxy trusting the old root. This is what the
// refusal rests on; it was tested against the Python certd, and that test
// skipped itself once the file was gone.
func TestInternalCAClientTrust(t *testing.T) {
	root := t.TempDir()
	d := &Daemon{Opts: Options{
		CARootDir: filepath.Join(root, "ca"), MTLSDir: filepath.Join(root, "mtls"),
		AppliedWebsites: filepath.Join(root, "applied.yml"), ConfigYAML: filepath.Join(root, "config", "vars.yml"),
	}}
	authority, authorityPEM := testAuthority(t)

	if got := d.internalCAClientTrust(authority); got != nil {
		t.Fatalf("an internal CA nobody trusts for clients is held back: %v", got)
	}

	writeTestFile(t, filepath.Join(root, "ca", mtlsTrustFile), `{"ids": ["internal"]}`)
	writeTestFile(t, filepath.Join(root, "config", "websites.yml"), "sites:\n"+
		"  - {name: shop, mtls_ca_id: internal, mtls_mode: required}\n"+
		"  - {name: blog, mtls_ca_id: internal, mtls_mode: disabled}\n"+
		"  - {name: wiki, mtls_ca_id: external-1, mtls_mode: required}\n")
	got := d.internalCAClientTrust(authority)
	want := map[string]any{"trust_list": true, "bundle": false, "sites": []string{"shop"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("on the trust list: got %v, want %v", got, want)
	}

	if err := os.Remove(filepath.Join(root, "ca", mtlsTrustFile)); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(root, "mtls", mtlsBundleName), string(authorityPEM))
	got = d.internalCAClientTrust(authority)
	if got == nil || got["trust_list"] != false || got["bundle"] != true {
		t.Fatalf("a root still in the bundle counts though off the list: %v", got)
	}
}
