package contract

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The schedule has to be reachable from the interface. The daemon carried
// schedule, schedule_save and run_scheduled, and the systemd timer fired
// nightly, but nothing exposed any of it: an operator could say where a copy
// should go and never say when, so every firing found the schedule off and
// did nothing. These checks keep the controls, the password field, the
// untranslated machine output and the Russian prose in place.

// backupScheduleCatalogue is the merged Russian catalogue the browser gets:
// the base file plus every fragment, in sorted order. A key may live in any
// fragment (a duplicate across fragments is a hard error elsewhere).
func backupScheduleCatalogue(t *testing.T) map[string]string {
	t.Helper()
	root := filepath.Join(repoRoot(t), catalogDir)
	messages := map[string]string{}
	if _, err := os.Stat(filepath.Join(root, "ru.json")); err == nil {
		for key, value := range loadCatalog(t, catalogDir+"/ru.json").messages {
			messages[key] = value
		}
	}
	fragments, _ := filepath.Glob(filepath.Join(root, "ru", "*.json"))
	sort.Strings(fragments)
	for _, path := range fragments {
		rel, _ := filepath.Rel(root, path)
		for key, value := range loadCatalog(t, catalogDir+"/"+filepath.ToSlash(rel)).messages {
			messages[key] = value
		}
	}
	return messages
}

// backupScheduleHead is Python's s[:n], counted in runes not bytes.
func backupScheduleHead(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		r = r[:n]
	}
	return string(r)
}

func TestBackupSchedulePageCarriesTheScheduleControls(t *testing.T) {
	markup := read(t, webDir+"/templates/system_backups.html")
	for _, element := range []string{
		`id="backup-schedule-form"`,
		`id="schedule-enabled"`,
		`id="schedule-destinations"`,
		`id="schedule-passphrase"`,
		`id="schedule-save"`,
		`id="schedule-run"`,
	} {
		mustContain(t, markup, element, "system_backups.html")
	}
}

func TestBackupScheduleScriptIsLoaded(t *testing.T) {
	markup := read(t, webDir+"/templates/system_backups.html")
	mustContain(t, markup, "js/backup_schedule.js", "system_backups.html")
}

func TestBackupScheduleEmptyPassphraseFieldIsNotSent(t *testing.T) {
	// Sending "" would delete the stored passphrase, which would disable
	// the schedule for someone who only meant to tick a box.
	script := read(t, webDir+"/static/js/backup_schedule.js")
	mustContain(t, script, "if (passphrase) body.passphrase = passphrase;", "backup_schedule.js")
}

func TestBackupSchedulePassphraseFieldIsAPasswordField(t *testing.T) {
	markup := read(t, webDir+"/templates/system_backups.html")
	parts := strings.SplitN(markup, `id="schedule-passphrase"`, 2)
	if len(parts) < 2 {
		t.Fatal("no schedule-passphrase field")
	}
	block := backupScheduleHead(parts[1], 200)
	// The tail of the opening tag before the id, plus the head after it,
	// must carry type="password".
	idx := strings.LastIndex(parts[0], "<input")
	if idx < 0 {
		t.Fatal("no <input before the passphrase field")
	}
	tag := parts[0][idx+len("<input"):] + block
	mustContain(t, tag, `type="password"`, "schedule-passphrase input")
}

func TestBackupScheduleMachineOutputIsNotRunThroughTheTranslator(t *testing.T) {
	// The same trap that translated a daemon's file path as if it were
	// interface text.
	markup := read(t, webDir+"/templates/system_backups.html")
	for _, element := range []string{"schedule-status", "schedule-last-run", "schedule-last-result"} {
		parts := strings.SplitN(markup, `id="`+element+`"`, 2)
		if len(parts) < 2 {
			t.Errorf("no element %s", element)
			continue
		}
		block := backupScheduleHead(parts[1], 160)
		mustContain(t, block, "data-i18n-skip", element)
		mustContain(t, block, `translate="no"`, element)
	}
}

func TestBackupScheduleNewProseIsTranslatedWhole(t *testing.T) {
	messages := backupScheduleCatalogue(t)
	markup := read(t, webDir+"/templates/system_backups.html")
	parts := strings.SplitN(markup, `id="backup-schedule"`, 2)
	if len(parts) < 2 {
		t.Fatal("no backup-schedule section")
	}
	section := strings.SplitN(parts[1], "</section>", 2)[0]
	// Every paragraph of prose in the section, whichever helper class it
	// carries. The one placeholder the script replaces is skipped below.
	paragraphs := regexp.MustCompile(`(?s)<p class="(?:muted|table-meta|vars-field-help)">(.*?)</p>`).FindAllStringSubmatch(section, -1)
	if len(paragraphs) == 0 {
		t.Fatal("no prose paragraphs in the schedule section")
	}
	for _, m := range paragraphs {
		flat := strings.Join(strings.Fields(m[1]), " ")
		if flat == "Loading…" {
			continue // replaced by the script before anyone reads it
		}
		if strings.Contains(flat, "<") {
			t.Errorf("a tag inside a sentence splits it: %q", flat)
		}
		if _, ok := messages[flat]; !ok {
			t.Errorf("paragraph not in the Russian catalogue: %q", flat)
		}
	}
}

func TestBackupScheduleStringsTheScriptShowsAreTranslated(t *testing.T) {
	messages := backupScheduleCatalogue(t)
	script := read(t, webDir+"/static/js/backup_schedule.js")
	// Python's (?<![A-Za-z0-9_])t\("([^"]+)"\): a t( call not preceded by an
	// ASCII word character, so createElement("p") is not read as a t call.
	// RE2 has no lookbehind, so the boundary is checked by hand and, on a
	// rejected match, scanning resumes one byte in (as Python's engine does).
	call := regexp.MustCompile(`t\("([^"]+)"\)`)
	var missing []string
	pos := 0
	for pos < len(script) {
		loc := call.FindStringSubmatchIndex(script[pos:])
		if loc == nil {
			break
		}
		start := pos + loc[0]
		if start > 0 {
			c := script[start-1]
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' {
				pos = start + 1
				continue
			}
		}
		text := script[pos+loc[2] : pos+loc[3]]
		if _, ok := messages[text]; !ok {
			missing = append(missing, text)
		}
		pos = pos + loc[1]
	}
	if len(missing) != 0 {
		t.Errorf("script strings missing from the Russian catalogue: %v", missing)
	}
}
