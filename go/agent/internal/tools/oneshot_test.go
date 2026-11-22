package tools

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUDPForwardGeneratorValidationAndFailover(t *testing.T) {
	dir := t.TempDir()
	udpCfg := filepath.Join(dir, "udp.yml")
	failoverPath := filepath.Join(dir, "udp-failover.json")
	_ = os.WriteFile(udpCfg, []byte(`udp_forwards:
  - name: wireguard
    listen_port: 51820-51821
    backend_host: 10.0.0.10
    backend_port: 51820-51821
    backup_host: 10.0.0.20
    health_check: tcp
    health_port: 443
    ban_check: true
    zero_trust: true
`), 0o644)
	_ = os.WriteFile(failoverPath, []byte(`{"version":1,"active":{"wireguard":"backup"}}`), 0o644)

	opts := UDPForwardOptions{
		ConfigPath:   udpCfg,
		FailoverPath: failoverPath,
		BanSet:       "haproxy_ban",
		AuthSet:      "haproxy_ip_auth",
	}

	script, err := ApplyUDPForwards(context.Background(), opts, true, false, false)
	if err != nil {
		t.Fatalf("ApplyUDPForwards dry-run: %v", err)
	}
	for _, want := range []string{
		"-A HP_UDP_RAW -p udp --dport 51820:51821 -m set --match-set haproxy_ban src -j DROP",
		"-A HP_UDP_RAW -p udp --dport 51820:51821 -m set ! --match-set haproxy_ip_auth src -j DROP",
		"-A HP_UDP_PRE -p udp --dport 51820:51821 -j DNAT --to-destination 10.0.0.20:51820-51821",
		"-A HP_UDP_POST -p udp -d 10.0.0.20 --dport 51820:51821 -j MASQUERADE",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("missing expected rule %q in:\n%s", want, script)
		}
	}

	// Reject loopback backend.
	badCfg := filepath.Join(dir, "bad.yml")
	_ = os.WriteFile(badCfg, []byte("udp_forwards:\n  - name: bad\n    listen_port: 53\n    backend_host: 127.0.0.1\n    backend_port: 53\n"), 0o644)
	if _, err := LoadUDPForwards(UDPForwardOptions{ConfigPath: badCfg}); err == nil {
		t.Fatal("loopback backend_host must be rejected")
	}
}

func TestCertDeliverWildcardCoverageAndArtefacts(t *testing.T) {
	if !NameCovered("app.example.com", []string{"*.example.com"}) {
		t.Fatal("single-label wildcard must match")
	}
	if NameCovered("a.b.example.com", []string{"*.example.com"}) {
		t.Fatal("single-label wildcard must NOT match two labels")
	}
	if TargetWantsDomains(CertDeliveryTarget{Domains: []string{"example.com"}}, []string{"notexample.com"}) {
		t.Fatal("substring domain must NOT match")
	}

	// Generate a test lineage with ECDSA cert + key.
	lineage := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "app.example.com"},
		DNSNames:     []string{"app.example.com", "*.svc.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	_ = os.WriteFile(filepath.Join(lineage, "fullchain.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	_ = os.WriteFile(filepath.Join(lineage, "privkey.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600)

	missing, err := UncoveredNames(CertDeliveryTarget{Domains: []string{"app.example.com", "api.svc.example.com"}}, lineage)
	if err != nil || len(missing) != 0 {
		t.Fatalf("expected full coverage, got missing=%v err=%v", missing, err)
	}
	missing, err = UncoveredNames(CertDeliveryTarget{Domains: []string{"other.org"}}, lineage)
	if err != nil || len(missing) != 1 {
		t.Fatalf("expected 1 uncovered domain, got missing=%v err=%v", missing, err)
	}

	workdir := t.TempDir()
	pairs, err := BuildCertArtefacts(context.Background(), lineage, CertDeliveryTarget{
		Format: "pem-combined", RemotePath: "/etc/ssl/app.pem",
	}, workdir, "")
	if err != nil || len(pairs) != 1 || pairs[0].RemotePath != "/etc/ssl/app.pem" {
		t.Fatalf("BuildCertArtefacts pem-combined: %+v err=%v", pairs, err)
	}
}

// buildMinimalIPv4MMDB builds a valid synthetic MaxMind DB (IPv4, 24-bit records, 1 node):
// bit 0 (0.0.0.0/1) -> {"country":{"iso_code":"DE"}}, bit 1 (128.0.0.0/1) -> empty.
func buildMinimalIPv4MMDB() []byte {
	encodeStr := func(s string) []byte {
		return append([]byte{byte((2 << 5) | len(s))}, []byte(s)...)
	}
	encodeUint := func(v uint64) []byte {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], v)
		trim := b[:]
		for len(trim) > 1 && trim[0] == 0 {
			trim = trim[1:]
		}
		return append([]byte{byte((6 << 5) | len(trim))}, trim...)
	}

	// Data section: offset 0 = {"country": {"iso_code": "DE"}}
	var dataSec []byte
	dataSec = append(dataSec, byte((7<<5)|1)) // map size 1
	dataSec = append(dataSec, encodeStr("country")...)
	dataSec = append(dataSec, byte((7<<5)|1)) // map size 1
	dataSec = append(dataSec, encodeStr("iso_code")...)
	dataSec = append(dataSec, encodeStr("DE")...)

	// Tree: 1 node (6 bytes for 24-bit records):
	// left = nodeCount + 16 + 0 = 17 -> points to dataSec[0]
	// right = nodeCount (1) -> empty
	tree := []byte{0, 0, 17, 0, 0, 1}
	sep := make([]byte, 16)

	// Metadata map: {node_count:1, record_size:24, ip_version:4, build_epoch:1700000000}
	var meta []byte
	meta = append(meta, byte((7<<5)|4))
	meta = append(meta, encodeStr("node_count")...)
	meta = append(meta, encodeUint(1)...)
	meta = append(meta, encodeStr("record_size")...)
	meta = append(meta, encodeUint(24)...)
	meta = append(meta, encodeStr("ip_version")...)
	meta = append(meta, encodeUint(4)...)
	meta = append(meta, encodeStr("build_epoch")...)
	meta = append(meta, encodeUint(1700000000)...)

	var out []byte
	out = append(out, tree...)
	out = append(out, sep...)
	out = append(out, dataSec...)
	out = append(out, mmdbMarker...)
	out = append(out, meta...)
	return out
}

func TestPureGoMMDBReaderAndAtomicGeoIPRelease(t *testing.T) {
	mmdb := buildMinimalIPv4MMDB()
	byCountry, epoch, err := ExtractCountryNetworks(mmdb)
	if err != nil {
		t.Fatalf("ExtractCountryNetworks: %v", err)
	}
	if epoch != 1700000000 || len(byCountry["DE"]) != 1 || byCountry["DE"][0] != "0.0.0.0/1" {
		t.Fatalf("unexpected MMDB extraction: epoch=%d byCountry=%+v", epoch, byCountry)
	}

	dir := t.TempDir()
	selPath := filepath.Join(dir, "selection.json")
	sel, err := SaveGeoIPSelection(selPath, []string{"de", "us"}, true)
	if err != nil {
		t.Fatalf("SaveGeoIPSelection: %v", err)
	}
	loaded, err := LoadGeoIPSelection(selPath)
	if err != nil || len(loaded.Countries) != 2 || loaded.Countries[0] != "DE" || !loaded.AccessFilterEnabled {
		t.Fatalf("LoadGeoIPSelection: %+v err=%v", loaded, err)
	}

	relID, err := PublishGeoIPRelease(dir, "2026-11", mmdb, sel)
	if err != nil || !strings.HasPrefix(relID, "2026-11-") {
		t.Fatalf("PublishGeoIPRelease: relID=%q err=%v", relID, err)
	}
	allowed, err := os.ReadFile(filepath.Join(dir, "current", GeoIPAllowedName))
	if err != nil || strings.TrimSpace(string(allowed)) != "0.0.0.0/1" {
		t.Fatalf("unexpected current/allowed.geo: %q err=%v", string(allowed), err)
	}
	stateBytes, err := os.ReadFile(filepath.Join(dir, "current", GeoIPStateName))
	if err != nil {
		t.Fatalf("read state.json: %v", err)
	}
	var st map[string]any
	if json.Unmarshal(stateBytes, &st) != nil || st["allowed_networks"].(float64) != 1 {
		t.Fatalf("unexpected state.json: %s", string(stateBytes))
	}
}
