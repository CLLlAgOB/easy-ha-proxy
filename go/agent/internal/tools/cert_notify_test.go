package tools

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCertNotifyStateLine(t *testing.T) {
	const valid = `{"enabled": true, "to": "admin@example.test", "from": "gateway@example.test"}`
	cases := []struct {
		name, state, domains, want string
	}{
		{"enabled", valid, "example.test www.example.test", "1\tadmin@example.test\tgateway@example.test\texample.test www.example.test"},
		{"extra spaces between names", valid, "  example.test \t www.example.test ", "1\tadmin@example.test\tgateway@example.test\texample.test www.example.test"},
		{"wildcard", valid, "*.example.test", "1\tadmin@example.test\tgateway@example.test\t*.example.test"},
		// Off is answered before anything else is checked.
		{"disabled", `{"enabled": false, "to": 5}`, "", "0\t\t\t"},
		{"enabled must be true itself", `{"enabled": 1, "to": "admin@example.test", "from": "gateway@example.test"}`, "example.test", "0\t\t\t"},
		{"missing enabled", `{}`, "example.test", "0\t\t\t"},
		{"only for a renewed name", `{"enabled": true, "to": "a@example.test", "from": "b@example.test", "only_for": ["www.example.test"]}`,
			"example.test www.example.test", "1\ta@example.test\tb@example.test\texample.test www.example.test"},
		{"only for another name", `{"enabled": true, "to": "a@example.test", "from": "b@example.test", "only_for": ["other.example.test"]}`,
			"example.test", "0\ta@example.test\tb@example.test\texample.test"},
		{"empty only_for means every name", `{"enabled": true, "to": "a@example.test", "from": "b@example.test", "only_for": []}`,
			"example.test", "1\ta@example.test\tb@example.test\texample.test"},
		{"trailing newline", valid + "\n", "example.test", "1\tadmin@example.test\tgateway@example.test\texample.test"},
	}
	for _, c := range cases {
		got, err := CertNotifyState([]byte(c.state), c.domains)
		if err != nil || got != c.want {
			t.Errorf("%s: got %q, %v; want %q", c.name, got, err, c.want)
		}
	}
}

func TestCertNotifyStateRefusesWhatCouldReachTheHeaders(t *testing.T) {
	for name, c := range map[string][2]string{
		"no names":            {`{"enabled": true, "to": "a@example.test", "from": "b@example.test"}`, " "},
		"bad name":            {`{"enabled": true, "to": "a@example.test", "from": "b@example.test"}`, "exa_mple.test"},
		"single label":        {`{"enabled": true, "to": "a@example.test", "from": "b@example.test"}`, "localhost"},
		"newline in to":       {`{"enabled": true, "to": "a@example.test\nBcc: x@example.test", "from": "b@example.test"}`, "example.test"},
		"tab in from":         {`{"enabled": true, "to": "a@example.test", "from": "b@example.test\t"}`, "example.test"},
		"missing to":          {`{"enabled": true, "from": "b@example.test"}`, "example.test"},
		"to is not text":      {`{"enabled": true, "to": ["a@example.test"], "from": "b@example.test"}`, "example.test"},
		"null from":           {`{"enabled": true, "to": "a@example.test", "from": null}`, "example.test"},
		"no at sign":          {`{"enabled": true, "to": "admin", "from": "b@example.test"}`, "example.test"},
		"non-ASCII address":   {`{"enabled": true, "to": "адм@example.test", "from": "b@example.test"}`, "example.test"},
		"only_for not a list": {`{"enabled": true, "to": "a@example.test", "from": "b@example.test", "only_for": "example.test"}`, "example.test"},
		"only_for bad item":   {`{"enabled": true, "to": "a@example.test", "from": "b@example.test", "only_for": [1]}`, "example.test"},
		"not an object":       {`["enabled"]`, "example.test"},
		"null":                {`null`, "example.test"},
		"broken JSON":         {`{"enabled": true`, "example.test"},
		"trailing data":       {`{"enabled": false} }`, "example.test"},
		"invalid UTF-8":       {"{\"enabled\": false, \"x\": \"\xff\"}", "example.test"},
		"byte order mark":     {"\xef\xbb\xbf{\"enabled\": false}", "example.test"},
	} {
		if got, err := CertNotifyState([]byte(c[0]), c[1]); err == nil {
			t.Errorf("%s: accepted as %q", name, got)
		}
	}
}

func TestRunCertNotifyState(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "mail-notify.json")
	if err := os.WriteFile(state, []byte(`{"enabled": true, "to": "a@example.test", "from": "b@example.test"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := RunCertNotifyState([]string{state, "example.test"}, &out, &errOut); code != 0 || out.String() != "1\ta@example.test\tb@example.test\texample.test\n" {
		t.Fatalf("code %d out %q err %q", code, out.String(), errOut.String())
	}
	out.Reset()
	if code := RunCertNotifyState([]string{filepath.Join(dir, "missing.json"), "example.test"}, &out, &errOut); code != 1 || out.Len() != 0 {
		t.Fatalf("a missing state: code %d out %q", code, out.String())
	}
	if err := os.WriteFile(state, []byte(`{"enabled": false, "pad": "`+strings.Repeat("x", certNotifyMaxState)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := RunCertNotifyState([]string{state, "example.test"}, &out, &errOut); code != 1 || out.Len() != 0 {
		t.Fatalf("an oversized state: code %d out %q", code, out.String())
	}
	if code := RunCertNotifyState([]string{state}, &out, &errOut); code != 2 {
		t.Fatalf("usage: code %d", code)
	}
}
