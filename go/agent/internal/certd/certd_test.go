package certd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"mime/multipart"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func generateTestBundle(t *testing.T, cn string, sans []string, notBefore, notAfter time.Time, includeKey bool) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     sans,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	var buf bytes.Buffer
	_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	if includeKey {
		keyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatalf("marshal key: %v", err)
		}
		_ = pem.Encode(&buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	}
	return buf.Bytes()
}

func TestCertWarnDaysAndNativeX509Inspection(t *testing.T) {
	if CertWarnDays(90) != 22 {
		t.Fatalf("expected 90-day cert warn threshold 22, got %d", CertWarnDays(90))
	}
	if CertWarnDays(45) != 11 {
		t.Fatalf("expected 45-day cert warn threshold 11, got %d", CertWarnDays(45))
	}
	if CertWarnDays(365) != 30 {
		t.Fatalf("expected 365-day manual cert warn threshold 30, got %d", CertWarnDays(365))
	}

	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	bundle := generateTestBundle(t, "app.example.com", []string{"app.example.com", "www.example.com"}, now.AddDate(0, 0, -80), now.AddDate(0, 0, 10), true)
	info, err := InspectPEMBytes(bundle, now)
	if err != nil {
		t.Fatalf("InspectPEMBytes: %v", err)
	}
	if info.SubjectCN != "app.example.com" || !info.HasPrivateKey || info.KeyType != "ECDSA-P-256" || !info.ExpiringSoon || info.Expired {
		t.Fatalf("unexpected cert info: %+v", info)
	}
}

func TestDNSProfilesTrashAndHTTPAPI(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	opts := Options{
		SocketPath:      filepath.Join(dir, "certd.sock"),
		HAProxyCertsDir: filepath.Join(dir, "certs"),
		LERootDir:       filepath.Join(dir, "le"),
		DNSCredsDir:     filepath.Join(dir, "dns"),
		TrashDir:        filepath.Join(dir, "trash"),
		StandbyDir:      filepath.Join(dir, "standby"),
	}
	mgr := NewManager(opts, nil)
	mgr.NowFn = func() time.Time { return now }

	// DNS profile save, redaction, and secret preservation on "***".
	prof, err := mgr.SaveDNSProfile("cf-prod", "cloudflare", 90, map[string]string{
		"dns_cloudflare_api_token": "super-secret-token",
	})
	if err != nil || prof.Credentials["dns_cloudflare_api_token"] != "***" {
		t.Fatalf("save dns profile: %+v err=%v", prof, err)
	}
	if _, err := mgr.SaveDNSProfile("cf-prod", "cloudflare", 120, map[string]string{
		"dns_cloudflare_api_token": "***",
	}); err != nil {
		t.Fatalf("update dns profile: %v", err)
	}

	// Start AF_UNIX HTTP server and test multipart upload -> list -> delete (trash) -> restore.
	ln, err := net.Listen("unix", opts.SocketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	srv := &http.Server{Handler: (&Server{Manager: mgr}).Handler()}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", opts.SocketPath)
			},
		},
	}

	bundle := generateTestBundle(t, "site.example.com", []string{"site.example.com"}, now.AddDate(0, 0, -5), now.AddDate(0, 0, 85), true)
	var mp bytes.Buffer
	mw := multipart.NewWriter(&mp)
	fw, _ := mw.CreateFormFile("file", "site.example.com.pem")
	_, _ = fw.Write(bundle)
	_ = mw.Close()

	resp, err := client.Post("http://unix/api/v1/certs/upload", mw.FormDataContentType(), &mp)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("upload failed: err=%v status=%v", err, resp)
	}
	resp.Body.Close()

	// Move to trash via POST /api/v1/certs/delete-haproxy, then restore.
	resp, err = client.Post("http://unix/api/v1/certs/delete-haproxy", "application/json", bytes.NewBufferString(`{"name":"site.example.com.pem"}`))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("delete-haproxy failed: err=%v", err)
	}
	var delRes struct {
		OK    bool       `json:"ok"`
		Trash TrashEntry `json:"trash"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&delRes)
	resp.Body.Close()
	if !delRes.OK || delRes.Trash.ID == "" {
		t.Fatalf("unexpected trash response: %+v", delRes)
	}

	restored, err := mgr.RestoreFromTrash(delRes.Trash.ID)
	if err != nil || restored.OrigName != "site.example.com.pem" {
		t.Fatalf("restore failed: %+v err=%v", restored, err)
	}

	// Verify GET /api/v1/certs/list sees the restored certificate.
	resp, err = client.Get("http://unix/api/v1/certs/list")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var listRes struct {
		OK      bool       `json:"ok"`
		HAProxy []CertInfo `json:"haproxy"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&listRes)
	resp.Body.Close()
	if !listRes.OK || len(listRes.HAProxy) != 1 || listRes.HAProxy[0].SubjectCN != "site.example.com" {
		t.Fatalf("unexpected list response: %+v", listRes)
	}
}
