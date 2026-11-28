package i18n

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadRealRepositoryTranslations(t *testing.T) {
	realDir := filepath.Join("..", "..", "web", "translations")
	cat, err := LoadDir(realDir, "en")
	if err != nil {
		t.Fatalf("LoadDir(%s) failed: %v", realDir, err)
	}
	langs := cat.SupportedLanguages()
	if len(langs) < 2 {
		t.Fatalf("expected at least en and ru, got %+v", langs)
	}
	if got := cat.Translate("ru", "CSRF validation failed"); got == "CSRF validation failed" || got == "" {
		t.Fatalf("expected Russian translation for CSRF validation failed, got %q", got)
	}
	url := cat.MessagesURL("ru")
	if !strings.HasPrefix(url, "/i18n/messages.js?lang=ru&v=") {
		t.Fatalf("unexpected MessagesURL: %q", url)
	}
}

func TestSafeLocalRedirect(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"/system/health?tab=1", "/system/health?tab=1"},
		{"//evil.example.com/phish", "/"},
		{"https://evil.example.com/", "/"},
		{`/evil\path`, "/"},
		{"", "/"},
	}
	for _, tc := range cases {
		if got := SafeLocalRedirect(tc.in, "/"); got != tc.want {
			t.Errorf("SafeLocalRedirect(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
