package i18n

import (
	"net/http/httptest"
	"testing"
)

func TestSelectLanguageRespectsQualityWeights(t *testing.T) {
	cat := &Catalog{
		defaultLang: "en",
		messages: map[string]map[string]string{
			"en": {},
			"ru": {},
		},
	}

	// q=0 excludes en; ru with q=0.8 must be selected.
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Language", "en;q=0, ru;q=0.8")
	if got := cat.SelectLanguage(req); got != "ru" {
		t.Fatalf("expected ru when en has q=0, got %q", got)
	}

	// Higher q wins regardless of header order.
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Set("Accept-Language", "en-US;q=0.3, ru-RU;q=0.9")
	if got := cat.SelectLanguage(req2); got != "ru" {
		t.Fatalf("expected ru with higher q=0.9, got %q", got)
	}

	// All q=0 falls back to defaultLang.
	req3 := httptest.NewRequest("GET", "/", nil)
	req3.Header.Set("Accept-Language", "ru;q=0, en;q=0")
	if got := cat.SelectLanguage(req3); got != "en" {
		t.Fatalf("expected default en when all q=0, got %q", got)
	}
}
