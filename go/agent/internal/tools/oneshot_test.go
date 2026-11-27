package tools

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/netip"
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
		"-t raw -A HP_UDP_RAW -p udp --dport 51820:51821 -m set --match-set haproxy_ban src -j DROP",
		"-t raw -A HP_UDP_RAW -p udp --dport 51820:51821 -m set ! --match-set haproxy_ip_auth src -j DROP",
		"-t nat -A HP_UDP_PRE -p udp --dport 51820 -j DNAT --to-destination 10.0.0.20:51820",
		"-t nat -A HP_UDP_PRE -p udp --dport 51821 -j DNAT --to-destination 10.0.0.20:51821",
		"-t nat -A HP_UDP_POST -p udp -d 10.0.0.20 --dport 51821 -j MASQUERADE",
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
	if certWantsDomain(map[string]any{"domains": []any{"example.com"}}, []string{"notexample.com"}) {
		t.Fatal("substring domain must NOT match")
	}

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

	opts := CertDeliverOptionsFromEnv()
	opts.DestinationsDir = t.TempDir()
	workdir := t.TempDir()
	pairs, err := opts.buildArtefacts(lineage, map[string]any{"format": "pem-pair", "remote_path": "/etc/ssl/app/"}, workdir)
	if err != nil || len(pairs) != 2 || pairs[0].RemotePath != "/etc/ssl/app/fullchain.pem" {
		t.Fatalf("pem-pair: %+v err=%v", pairs, err)
	}
	if st, _ := os.Stat(pairs[0].LocalPath); st.Mode().Perm() != 0o644 {
		t.Fatalf("pem-pair chain mode %v", st.Mode().Perm())
	}

	// The deploy hook passes --lineage "" when certbot sets nothing: not an error.
	var out, errBuf strings.Builder
	if rc := RunCertDeliver([]string{"--lineage", "", "--domains", ""}, opts, &out, &errBuf); rc != 0 ||
		errBuf.String() != "cert-deliver: INFO no lineage given; nothing to deliver\n" {
		t.Fatalf("empty lineage: rc=%d %q", rc, errBuf.String())
	}
	// A record without "enabled" is enabled, as record.get("enabled", True).
	_ = os.WriteFile(filepath.Join(opts.DestinationsDir, "rdg.json"), []byte(`{"domains":["app.example.com"]}`), 0o600)
	errBuf.Reset()
	if rc := RunCertDeliver([]string{"--lineage", lineage, "--domains", "app.example.com"}, opts, &out, &errBuf); rc != 1 ||
		!strings.Contains(errBuf.String(), "delivery to rdg failed: host is not set") {
		t.Fatalf("missing host: rc=%d %q", rc, errBuf.String())
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
	out = append(out, geoipMMDBMarker...)
	out = append(out, meta...)
	return out
}

func TestGeoIPReaderCollapseAndSelection(t *testing.T) {
	r, err := parseMMDB(buildMinimalIPv4MMDB())
	if err != nil {
		t.Fatal(err)
	}
	if r.buildEpoch != 1700000000 {
		t.Fatalf("epoch %d", r.buildEpoch)
	}
	seen := []string{}
	_ = r.each(func(n mmdbNetwork, rec any) error {
		seen = append(seen, cidr{n.v6, n.addr, n.prefix}.String()+"="+fmt.Sprint(rec.(map[string]any)["country"].(map[string]any)["iso_code"]))
		return nil
	})
	if strings.Join(seen, ",") != "0.0.0.0/1=DE" {
		t.Fatalf("walk: %v", seen)
	}
	mk := func(s string) cidr {
		p := netip.MustParsePrefix(s)
		b := p.Addr().AsSlice()
		return cidr{p.Addr().Is6(), new(big.Int).SetBytes(b), p.Bits()}
	}
	got := []string{}
	for _, c := range collapse([]cidr{mk("10.0.1.0/24"), mk("10.0.0.0/24"), mk("10.0.0.0/25"), mk("10.0.2.0/23")}) {
		got = append(got, c.String())
	}
	if strings.Join(got, ",") != "10.0.0.0/22" {
		t.Fatalf("collapse: %v", got)
	}
	if c, err := normalizeCountries([]string{"de, us", "DE"}); err != nil || strings.Join(c, ",") != "DE,US" {
		t.Fatalf("%v %v", c, err)
	}
	if string(SelectionJSON([]string{"DE"}, true)) != "{\n  \"access_filter_enabled\": true,\n  \"countries\": [\n    \"DE\"\n  ],\n  \"version\": 1\n}\n" {
		t.Fatal("selection json")
	}
	if strings.Join(monthCandidates(time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC), 3), ",") != "2026-01,2025-12,2025-11" {
		t.Fatal("months")
	}
}
