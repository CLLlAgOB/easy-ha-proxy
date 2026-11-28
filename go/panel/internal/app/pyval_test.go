package app

import (
	"math"
	"testing"
)

// Expected values come from CPython 3.12 bytes.decode("utf-8", "replace").
func TestPyDecodeReplace(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"\xe2\x82\x78", "�x"},
		{"\xff\xfe\x20\x6f\x6b", "�� ok"},
		{"\xed\xa0\x80", "���"},
		{"\xf0\x9f\x98", "�"},
		{"\xf0\x9f\x98\x80\x21", "\U0001F600!"},
		{"\xc0\xaf", "��"},
		{"\xe0\x80\xaf", "���"},
		{"\xf4\x90\x80\x80", "����"},
		{"\x61\xc3", "a�"},
		{"\xe1\x80\xe1\x80\x80", "�က"},
	} {
		if got := pyDecodeReplace([]byte(tc.in)); got != tc.want {
			t.Errorf("pyDecodeReplace(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// Expected values come from CPython 3.12 shlex.split.
func TestShlexSplit(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string
	}{
		{`a b  c`, []string{"a", "b", "c"}},
		{`msg="x y" k='a b'c`, []string{"msg=x y", "k=a bc"}},
		{`"a\"b\\c\$"`, []string{`a"b\c\$`}},
		{`a\ b \'`, []string{"a b", "'"}},
		{`'' ""`, []string{"", ""}},
		{"x\ty\nz", []string{"x", "y", "z"}},
	} {
		got, err := shlexSplit(tc.in)
		if err != nil || len(got) != len(tc.want) {
			t.Fatalf("shlexSplit(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("shlexSplit(%q)[%d] = %q, want %q", tc.in, i, got[i], tc.want[i])
			}
		}
	}
	for _, bad := range []string{`"open`, `'open`, `end\`} {
		if _, err := shlexSplit(bad); err == nil {
			t.Errorf("shlexSplit(%q) should fail", bad)
		}
	}
}

// Expected values come from CPython 3.12 ipaddress.ip_address(x).is_global.
func TestPyIsGlobal(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"8.8.8.8", true}, {"10.0.0.1", false}, {"100.64.1.1", false}, {"100.128.0.1", true}, {"192.0.0.9", true},
		{"192.0.0.10", true}, {"192.0.0.11", false}, {"192.0.0.170", false}, {"192.0.0.172", false},
		{"198.18.5.5", false}, {"224.0.0.1", true}, {"255.255.255.255", false}, {"0.1.2.3", false},
		{"169.254.1.1", false}, {"172.31.0.1", false}, {"172.32.0.1", true}, {"203.0.113.5", false},
		{"240.0.0.1", false}, {"::1", false}, {"::", false}, {"2001:db8::1", false}, {"2001:4860::8888", true},
		{"2001:1::1", true}, {"2001:1::3", false}, {"2001:3::5", true}, {"2001:20::1", true}, {"2002::1", false},
		{"fc00::1", false}, {"fe80::1", false}, {"ff02::1", true}, {"::ffff:8.8.8.8", true},
		{"::ffff:10.0.0.1", false}, {"64:ff9b:1::1", false}, {"64:ff9b::1", true}, {"3fff::1", false},
		{"100::1", false}, {"100:0:0:1::1", true},
	} {
		a, ok := pyIPAddress(tc.in)
		if !ok {
			t.Fatalf("pyIPAddress(%q) failed", tc.in)
		}
		if got := pyIsGlobal(a); got != tc.want {
			t.Errorf("pyIsGlobal(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// Expected values come from CPython 3.12 format(x, "g").
func TestPyFormatG(t *testing.T) {
	for _, tc := range []struct {
		in   float64
		want string
	}{
		{0.0, "0"}, {math.Copysign(0, -1), "-0"}, {1.0, "1"}, {1.5, "1.5"}, {100.0, "100"}, {123456.0, "123456"},
		{1234567.0, "1.23457e+06"}, {0.0001, "0.0001"}, {1.234e-05, "1.234e-05"}, {1e+16, "1e+16"},
		{2.5e-07, "2.5e-07"}, {999999.5, "1e+06"}, {9999995.0, "1e+07"}, {-42.0, "-42"}, {3.14159265, "3.14159"},
		{1700000000.0, "1.7e+09"}, {0.1 + 0.2, "0.3"}, {1e+100, "1e+100"}, {12.345678, "12.3457"},
	} {
		if got := pyFormatG(tc.in); got != tc.want {
			t.Errorf("pyFormatG(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
