package tools

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestParseJournalLastWordsTruncatesByRunesNotBytes(t *testing.T) {
	// 1500 Cyrillic runes (3000 UTF-8 bytes) would split mid-rune if sliced by bytes.
	msg := strings.Repeat("Я", 1500)
	line, err := json.Marshal(map[string]any{
		"SYSLOG_IDENTIFIER": "backup-run",
		"MESSAGE":           msg,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := ParseJournalLastWords(string(line) + "\n")
	if !utf8.ValidString(got) {
		t.Fatalf("truncated output is invalid UTF-8")
	}
	if utf8.RuneCountInString(got) != unitMaxDetailChars {
		t.Fatalf("got %d runes, want %d", utf8.RuneCountInString(got), unitMaxDetailChars)
	}
}
