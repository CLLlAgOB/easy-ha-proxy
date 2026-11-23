package app

import "testing"

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
