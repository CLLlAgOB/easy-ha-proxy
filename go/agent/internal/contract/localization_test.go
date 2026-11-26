package contract

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// Regression checks for installer and Authelia notification localization:
// the bootstrap offers both languages, the installed/partial/test menus keep
// their workflow actions, the remote installer accepts an explicit language,
// the wizard persists it, and the Authelia templates and Ansible task names
// stay in their intended language.

const autheliaRoleDir = "ansible/roles/authelia"

// localizationSplitLines is Python's str.splitlines(): it breaks on every
// Unicode line boundary and does not yield a trailing empty line for a
// trailing break.
func localizationSplitLines(s string) []string {
	if s == "" {
		return nil
	}
	var lines []string
	start := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == '\r' {
			end := i
			i += size
			if i < len(s) && s[i] == '\n' {
				i++
			}
			lines = append(lines, s[start:end])
			start = i
			continue
		}
		if localizationIsLineBreak(r) {
			lines = append(lines, s[start:i])
			i += size
			start = i
			continue
		}
		i += size
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func localizationIsLineBreak(r rune) bool {
	switch r {
	case '\n', '\v', '\f', 0x1c, 0x1d, 0x1e, 0x85, 0x2028, 0x2029:
		return true
	}
	return false
}

// localizationAfter is source.split(marker, 1)[1]; a missing marker is the
// IndexError the Python split would raise.
func localizationAfter(t *testing.T, source, marker string) string {
	t.Helper()
	parts := strings.SplitN(source, marker, 2)
	if len(parts) != 2 {
		t.Fatalf("marker %q not found", marker)
	}
	return parts[1]
}

// localizationIsTaskName is re.match(r"^\s*-\s+name:\s*", line) with
// Unicode-aware whitespace.
func localizationIsTaskName(line string) bool {
	rest := strings.TrimLeftFunc(line, unicode.IsSpace)
	if !strings.HasPrefix(rest, "-") {
		return false
	}
	rest = rest[1:]
	name := strings.TrimLeftFunc(rest, unicode.IsSpace)
	if len(name) == len(rest) { // \s+ requires at least one whitespace rune
		return false
	}
	return strings.HasPrefix(name, "name:")
}

func TestArgumentFreeBootstrapOffersEnglishAndRussian(t *testing.T) {
	// A bare ./install.sh must still offer a language choice instead of
	// silently assuming English.
	source := read(t, "install.sh")
	for _, want := range []string{
		`language="${language_from_env:-en}"`,
		"Select language / Выберите язык:",
		`if [[ -z "${mode}" && -z "${language_from_env}" ]]`,
		"select_language",
	} {
		mustContain(t, source, want, "install.sh")
	}
}

func TestInstalledMenuPrioritizesUpdateWorkflow(t *testing.T) {
	// The installed menu leads with checking for updates, not advanced ops.
	source := read(t, "easy-ha-proxy-helper.sh")
	mainMenu := localizationAfter(t, source, "menu_installed() {")
	for _, want := range []string{
		"1) Check for updates and install selected items",
		"2) Check for updates only",
		"6) Advanced operations",
		"1) perform_action smart-update",
		"6) menu_installed_advanced",
	} {
		mustContain(t, mainMenu, want, "menu_installed")
	}
}

func TestInterruptedInstallationHasResumeAndRestartActions(t *testing.T) {
	// A partial install can be resumed with the saved config or reset.
	source := read(t, "easy-ha-proxy-helper.sh")
	partialMenu := strings.SplitN(localizationAfter(t, source, "menu_partial() {"), "menu_legacy() {", 2)[0]
	mustContain(t, source, "installation_complete:", "helper")
	mustContain(t, source, "configuration_pending:", "helper")
	mustContain(t, partialMenu, "Продолжить установку с сохранённой конфигурацией", "menu_partial")
	mustContain(t, partialMenu, "perform_action install-reset", "menu_partial")
	mustContain(t, partialMenu, "perform_action install-test-reset", "menu_partial")
	mustContain(t, source, "Системные службы (справочно", "helper")
}

func TestTestModeMenuOffersProductionPromotion(t *testing.T) {
	// A test install can be promoted to production without reinstalling.
	source := read(t, "easy-ha-proxy-helper.sh")
	mustContain(t, source, "promote-production", "helper")
	mustContain(t, source, "Перевести тестовую установку в production без переустановки", "helper")
}

func TestRemoteInstallerAcceptsExplicitLanguage(t *testing.T) {
	// The remote installer forwards an explicit --language to the gateway.
	source := read(t, "install-remote.sh")
	for _, want := range []string{
		"--language CODE",
		"configure|language|migrate-domain",
		"EASY_HA_PROXY_LANGUAGE=${language}",
		"language|promote-production)",
		`if [[ "${activate_current_source}" == true ]]`,
		"source.before-${remote_action}.",
		`build_source_archive "${source_root}"`,
	} {
		mustContain(t, source, want, "install-remote.sh")
	}
}

func TestRemoteConnectionDetectsStaleInstallerSource(t *testing.T) {
	// A stale remote installer source is detected and can be refreshed.
	remote := read(t, "install-remote.sh")
	helper := read(t, "easy-ha-proxy-helper.sh")
	for _, want := range []string{
		"installer_fingerprint()",
		"local_installer_fingerprint",
		"remote_installer_fingerprint",
		"Загрузить текущие локальные исходники перед продолжением? [Y/n]",
		`source_channel="local"`,
	} {
		mustContain(t, remote, want, "install-remote.sh")
	}
	mustContain(t, helper, `if [[ "${source_channel}" == "github" ]]`, "helper")
	mustContain(t, helper, "Обновляю управляемые исходники из GitHub", "helper")
}

func TestConfigurationWizardPersistsSelectedLanguage(t *testing.T) {
	// The wizard reads the language env and writes it into both settings.
	i18n := read(t, "go/agent/internal/cli/i18n.go")
	wizard := read(t, "go/agent/internal/cli/wizard.go")
	mustContain(t, i18n, `os.Getenv("EASY_HA_PROXY_LANGUAGE")`, "cli/i18n.go")
	mustContain(t, wizard, `"authelia_notification_language", lang`, "cli/wizard.go")
	mustContain(t, wizard, `"haproxy_admin_default_language", lang`, "cli/wizard.go")
}

func TestAutheliaHasCompleteEnglishAndRussianTemplateSets(t *testing.T) {
	// Every notification template ships in English (no Cyrillic) and Russian
	// (with Cyrillic); a missing or mixed-language file breaks notifications.
	stems := []string{
		"Event.html",
		"Event.txt",
		"IdentityVerificationJWT.html",
		"IdentityVerificationJWT.txt",
		"IdentityVerificationOTC.html",
		"IdentityVerificationOTC.txt",
	}
	root := repoRoot(t)
	for _, stem := range stems {
		enRel := autheliaRoleDir + "/templates/" + stem + ".en.j2"
		ruRel := autheliaRoleDir + "/templates/" + stem + ".ru.j2"
		en, enErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(enRel)))
		ru, ruErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(ruRel)))
		if enErr != nil {
			t.Errorf("%s: %v", enRel, enErr)
		} else if cyrillicLetters.MatchString(string(en)) {
			t.Errorf("%s holds Cyrillic", enRel)
		}
		if ruErr != nil {
			t.Errorf("%s: %v", ruRel, ruErr)
		} else if !cyrillicLetters.MatchString(string(ru)) {
			t.Errorf("%s lacks Cyrillic", ruRel)
		}
	}
}

func TestAutheliaRoleSelectsLanguageDynamically(t *testing.T) {
	// The role default keeps notifications English until the wizard sets them.
	defaults := read(t, autheliaRoleDir+"/defaults/main.yml")
	mustContain(t, defaults, `authelia_notification_language: "en"`, "authelia defaults")
}

func TestAnsibleTaskNamesAreEnglish(t *testing.T) {
	// Task names are operator-facing log lines and must stay English.
	root := repoRoot(t)
	var paths []string
	err := filepath.WalkDir(filepath.Join(root, "ansible"), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && (strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml")) {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(paths)
	var failures []string
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		rel, _ := filepath.Rel(root, path)
		for number, line := range localizationSplitLines(string(raw)) {
			if localizationIsTaskName(line) && cyrillicLetters.MatchString(line) {
				failures = append(failures, filepath.ToSlash(rel)+":"+strconv.Itoa(number+1)+": "+strings.TrimSpace(line))
			}
		}
	}
	if len(failures) > 0 {
		t.Errorf("Non-English Ansible task names:\n%s", strings.Join(failures, "\n"))
	}
}
