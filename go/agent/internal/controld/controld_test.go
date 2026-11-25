package controld

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const goodConfig = `global
    user haproxy
    group haproxy
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660
    .if version_atleast(3.1)
        tune.lua.bool-sample-conversion normal
    .endif

frontend fe
    acl host_admin hdr(host) -i admin.example.com
`

func TestConfigPolicy(t *testing.T) {
	if err := enforceConfigPolicy([]byte(goodConfig)); err != nil {
		t.Fatalf("good config refused: %v", err)
	}
	cases := map[string]string{
		strings.Replace(goodConfig, "user haproxy", "user root", 1):                "required HAProxy privilege-drop directives are missing",
		strings.Replace(goodConfig, "    chroot", "    setenv X 1\n    chroot", 1): "HAProxy directive 'setenv' is not allowed",
		strings.Replace(goodConfig, "/run/haproxy/admin.sock", "/tmp/a.sock", 1):   "HAProxy stats socket must stay under /run/haproxy",
		strings.Replace(goodConfig, "    .endif\n", "", 1):                         "HAProxy compatibility block must stay inside global",
		strings.Replace(goodConfig, "    .endif\n", "    .else\n", 1):              "invalid HAProxy compatibility block ending",
		goodConfig + "global\n": "multiple global sections are not allowed",
	}
	for cfg, want := range cases {
		if err := enforceConfigPolicy([]byte(cfg)); err == nil || err.Error() != want {
			t.Fatalf("want %q, got %v", want, err)
		}
	}
	if err := enforceConfigPolicy([]byte("global\n\xff")); err == nil || !strings.Contains(err.Error(), "can't decode byte 0xff in position 7") {
		t.Fatalf("utf-8: %v", err)
	}
}

// Lua splits package.path on ";": a value under /etc/haproxy/lua may not
// carry another directory along, or a module from it would run as root
// during the configuration check.
func TestLuaSearchPathPolicy(t *testing.T) {
	withPaths := func(paths ...string) string {
		lines := ""
		for _, p := range paths {
			lines += "    lua-prepend-path " + p + "\n"
		}
		return strings.Replace(goodConfig, "    chroot", lines+"    lua-load /etc/haproxy/lua/auth-request.lua\n    chroot", 1)
	}
	if err := enforceConfigPolicy([]byte(withPaths("/etc/haproxy/lua/?/http.lua", "/etc/haproxy/lua/?.lua"))); err != nil {
		t.Fatalf("the template's own paths refused: %v", err)
	}
	for _, p := range []string{
		"/etc/haproxy/lua/none/?.lua;/tmp/?.lua",
		"/etc/haproxy/lua/x/../../../tmp/?.lua",
		"/etc/haproxy/lua/other/?.lua",
		`"/etc/haproxy/lua/?.lua;/var/tmp/?.lua"`,
	} {
		if err := enforceConfigPolicy([]byte(withPaths(p))); err == nil {
			t.Errorf("accepted %s", p)
		}
	}
}

func TestLineHasIP(t *testing.T) {
	if !lineHasIP("from 203.0.113.1:443", "203.0.113.1") || lineHasIP("from 203.0.113.10", "203.0.113.1") ||
		lineHasIP("x1.203.0.113.1", "203.0.113.1") || !lineHasIP("203.0.113.1", "203.0.113.1") {
		t.Fatal("address boundaries")
	}
}

func TestIPCanonical(t *testing.T) {
	for in, want := range map[string]string{"10.0.0.1/8": "10.0.0.0/8", "192.168.1.7/255.255.255.0": "192.168.1.0/24",
		"2001:db8::1/32": "2001:db8::/32"} {
		if got, err := pyIPNetwork(in); err != nil || got != want {
			t.Fatalf("%s: %s %v", in, got, err)
		}
	}
	if _, err := pyIPNetwork("10.0.0.0/33"); err == nil {
		t.Fatal("bad prefix accepted")
	}
	got, err := canonicalAdminAllowlistEntries([]any{" 10.0.0.1/8 ", "", "10.0.0.0/8", "192.0.2.1"})
	if err != nil || strings.Join(got, ",") != "10.0.0.0/8,192.0.2.1" {
		t.Fatalf("allow list: %v %v", got, err)
	}
}

func TestCanonicalGeoIPSelection(t *testing.T) {
	sel := map[string]any{"version": 1, "countries": []any{"DE", "RU"}, "access_filter_enabled": true}
	want := "{\n  \"access_filter_enabled\": true,\n  \"countries\": [\n    \"DE\",\n    \"RU\"\n  ],\n  \"version\": 1\n}\n"
	if got := string(canonicalConfigGeoIPSelection(sel)); got != want {
		t.Fatalf("selection:\n%s", got)
	}
	empty := map[string]any{"version": 1, "countries": []any{}, "access_filter_enabled": false}
	if got := string(canonicalConfigGeoIPSelection(empty)); got != "{\n  \"access_filter_enabled\": false,\n  \"countries\": [],\n  \"version\": 1\n}\n" {
		t.Fatalf("empty selection:\n%s", got)
	}
}

func TestSortLogLines(t *testing.T) {
	d := &Daemon{Opts: Options{LogTimeOrder: "asc"}}
	got, err := d.sortLogLinesByTime([]string{"2026-01-01T10:00:02+00:00 b", "no stamp", "2026-01-01T10:00:01+00:00 a"})
	if err != nil || strings.Join(got, "|") != "2026-01-01T10:00:01+00:00 a|2026-01-01T10:00:02+00:00 b|no stamp" {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := d.sortLogLinesByTime([]string{"2026-01-01T10:00:02+00:00 b", "2026-01-01T10:00:01 a"}); err == nil {
		t.Fatal("naive and aware stamps compared")
	}
}

func TestTransactionStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	d := NewDaemon(Options{ConfigTransactionDir: filepath.Join(dir, "guard"), MaxTransactionStateBytes: 1 << 20})
	state := map[string]any{"version": 1, "transaction_id": "abc", "state": "pending_confirmation", "deadline_epoch": 1.5,
		"note": "é"}
	if err := d.persistConfigTransaction(state); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "guard", "transaction.json"))
	if !strings.Contains(string(raw), "\"note\":\"\\"+"u00e9\"") || strings.Contains(string(raw), " ") {
		t.Fatalf("state is not compact ASCII JSON: %s", raw)
	}
	loaded, err := d.loadConfigTransaction()
	if err != nil || loaded["transaction_id"] != "abc" {
		t.Fatalf("load: %v %v", loaded, err)
	}
	status := d.sanitizedStatus(loaded)
	if status["pending"] != true || status["ok"] != true || status["remaining_seconds"] != 0 {
		t.Fatalf("status: %v", status)
	}
}

func TestUnfoldLines(t *testing.T) {
	got := unfoldHAProxyLines("a \\\nb\nc\\\\\nd\\")
	if strings.Join(got, "|") != "a b|c\\\\|d" {
		t.Fatalf("%q", got)
	}
}
