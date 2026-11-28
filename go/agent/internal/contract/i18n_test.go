package contract

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"easy-ha-proxy/panel/shared/jinja"
)

// Regression checks for the dependency-free UI translation catalogs: the
// English source language, the Russian coverage, the machine output that
// must never be translated, and the catalog delivered as a cacheable asset.

const webDir = "go/panel/web"
const catalogDir = webDir + "/translations"

func mustContain(t *testing.T, text, want, where string) {
	t.Helper()
	if !strings.Contains(text, want) {
		t.Errorf("%s lacks %q", where, want)
	}
}

func TestApplyResultSurvivesTheSuccessReload(t *testing.T) {
	javascript := read(t, webDir+"/static/js/haproxy_config.js")
	template := read(t, webDir+"/templates/haproxy_config.html")
	for _, want := range []string{
		"APPLY_RESULT_STORAGE_KEY",
		"window.sessionStorage.setItem",
		"function restoreApplyResult()",
		"renderApplyResult(saved.data, saved.completedAt)",
		"restoreApplyResult();",
		"persistApplyResult(data, completedAt);",
		"function clearDisplayedApplyResult()",
	} {
		mustContain(t, javascript, want, "haproxy_config.js")
	}
	mustContain(t, template, `id="apply-result-time"`, "haproxy_config.html")
	mustContain(t, template, "Automatic safety check:", "haproxy_config.html")
}

func TestMonitoringIdentifiersAndLogsAreNotTranslated(t *testing.T) {
	template := read(t, webDir+"/templates/health.html")
	javascript := read(t, webDir+"/static/js/health.js")
	for _, elementID := range []string{"control-result", "logs-title-target", "logs-cmd", "logs-text", "recent-log-body"} {
		tag := regexp.MustCompile(`<[^>]+id="` + regexp.QuoteMeta(elementID) + `"[^>]*>`).FindString(template)
		if tag == "" {
			t.Errorf("no element %s", elementID)
			continue
		}
		mustContain(t, tag, "data-i18n-skip", elementID)
		mustContain(t, tag, `translate="no"`, elementID)
	}
	for _, want := range []string{
		"function technicalText(value, mono = false)",
		"function statusIndicator(cls, state, title)",
		`return statusIndicator("ok", display ||`,
		`? "loaded" : a), title)`,
		`technicalText(unit, true)`,
		`technicalText(name, true)`,
		"logsTitleTarget.textContent = `${kind} / ${name}`",
		`new URLSearchParams({ limit: String(limit) })`,
		`query.append("unit", unit)`,
		"if (force) await loadRecentLogs()",
		`technicalText(e.raw_message || "", true)`,
		`uiText("No recent journal entries")`,
		`"haproxy.service"`,
		`"haproxy-healthd.service"`,
	} {
		mustContain(t, javascript, want, "health.js")
	}
	for _, unwanted := range []string{`window.t(state)`, `technicalText(e.message || "", true)`} {
		if strings.Contains(javascript, unwanted) {
			t.Errorf("health.js holds %q", unwanted)
		}
	}
	for _, want := range []string{`id="tblRecent"`, `id="recentLimit"`, `id="recentUnitOptions"`} {
		mustContain(t, template, want, "health.html")
	}
	styles := read(t, webDir+"/static/css/pages.css")
	parts := strings.SplitN(styles, ".recent-table-wrap {", 2)
	if len(parts) != 2 {
		t.Fatal("no .recent-table-wrap rule")
	}
	recent := strings.SplitN(parts[1], "}", 2)[0]
	mustContain(t, recent, "max-height: 430px", ".recent-table-wrap")
	mustContain(t, recent, "scrollbar-gutter: stable", ".recent-table-wrap")

	messages := loadCatalog(t, catalogDir+"/ru.json")
	if got := translateSource("iptables-haproxy-ban.service", messages.messages, messages.order); got != "iptables-haproxy-ban.service" {
		t.Errorf("a unit name was translated: %q", got)
	}
	rawJournal := `time="2026-07-14T21:57:23.183669593Z" level=info msg="stopping restart-manager"`
	if got := translateSource(rawJournal, messages.messages, messages.order); got != rawJournal {
		t.Errorf("raw journal output was translated: %q", got)
	}
}

func TestAutheliaLogRowsAreNotTranslated(t *testing.T) {
	template := read(t, webDir+"/templates/authelia_bans.html")
	logBody := regexp.MustCompile(`<tbody[^>]*>\s*\{% for e in logs %\}`).FindString(template)
	if logBody == "" {
		t.Fatal("no log tbody")
	}
	mustContain(t, logBody, `class="notranslate"`, "log tbody")
	mustContain(t, logBody, `translate="no"`, "log tbody")
	mustContain(t, logBody, "data-i18n-skip", "log tbody")
}

func TestHaproxySocketDefaultsNeverRenderEmpty(t *testing.T) {
	dir := filepath.Join(repoRoot(t), "ansible", "roles", "haproxy", "templates")
	env := jinja.NewEnvironment(func(name string) (string, error) {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		return string(raw), err
	})
	env.Autoescape = false
	env.TrimBlocks = true
	env.LstripBlocks = true
	env.Filters["regex_replace"] = jinja.RegexReplaceFilter
	env.Filters["combine"] = jinja.CombineFilter
	rendered, err := env.Render("haproxy.cfg.j2", map[string]any{
		"sites": []any{}, "tcp_proxies": []any{}, "ansible_processor_vcpus": int64(1),
	})
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, rendered,
		"stats socket /run/haproxy/admin.sock mode 660 user root group hadmin level admin expose-fd listeners",
		"haproxy.cfg.j2")
}

func TestRequiredCatalogsAreValid(t *testing.T) {
	for _, code := range []string{"en", "ru"} {
		c := loadCatalog(t, catalogDir+"/"+code+".json")
		if c.code != code {
			t.Errorf("%s: meta.code %q", code, c.code)
		}
		if c.label == "" {
			t.Errorf("%s: no meta.label", code)
		}
	}
}

func TestEnglishIsTheCanonicalSourceLanguage(t *testing.T) {
	c := loadCatalog(t, catalogDir+"/en.json")
	if len(c.messages) != 0 {
		t.Fatalf("en.json holds %d messages, want none", len(c.messages))
	}
}

func TestRussianCatalogCoversCoreNavigation(t *testing.T) {
	c := loadCatalog(t, catalogDir+"/ru.json")
	for source, translation := range map[string]string{
		"Home":                  "Главная",
		"HTTP sites":            "HTTP-сайты",
		"TCP proxies":           "TCP-прокси",
		"HAProxy configuration": "Конфигурация HAProxy",
		"Certificates":          "Сертификаты",
		"Status":                "Статус",
		"Interface language":    "Язык интерфейса",
	} {
		if got := c.messages[source]; got != translation {
			t.Errorf("%q: %q, want %q", source, got, translation)
		}
	}
}

func TestReservedDomainErrorRecommendsInternalCaInRussian(t *testing.T) {
	c := loadCatalog(t, catalogDir+"/ru.json")
	translated := translateSource(
		"Let's Encrypt cannot issue certificates for reserved/private domains: "+
			"app.example.test. Select Internal CA for this site.",
		c.messages, c.order)
	mustContain(t, translated, "не может выпускать сертификаты", "reserved-domain error")
	mustContain(t, translated, "Выберите Internal CA", "reserved-domain error")
}

// catalogFiles is every catalog under the translations directory.
func catalogFiles(t *testing.T) []string {
	t.Helper()
	root := filepath.Join(repoRoot(t), catalogDir)
	var files []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".json") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestCatalogMetadataMatchesFilename(t *testing.T) {
	root := filepath.Join(repoRoot(t), catalogDir)
	files := catalogFiles(t)
	if len(files) < 2 {
		t.Fatalf("only %d catalogs", len(files))
	}
	for _, path := range files {
		rel, _ := filepath.Rel(root, path)
		c := loadCatalog(t, catalogDir+"/"+filepath.ToSlash(rel))
		expected := strings.TrimSuffix(filepath.Base(path), ".json")
		if filepath.Dir(path) != root {
			expected = filepath.Base(filepath.Dir(path))
		}
		if c.code != expected {
			t.Errorf("%s: meta.code %q, want %q", rel, c.code, expected)
		}
	}
}

func TestCatalogFragmentsDoNotDuplicateKeys(t *testing.T) {
	root := filepath.Join(repoRoot(t), catalogDir)
	seen := map[string]map[string]bool{}
	for _, path := range catalogFiles(t) {
		rel, _ := filepath.Rel(root, path)
		c := loadCatalog(t, catalogDir+"/"+filepath.ToSlash(rel))
		keys := seen[c.code]
		if keys == nil {
			keys = map[string]bool{}
			seen[c.code] = keys
		}
		for _, key := range c.order {
			if keys[key] {
				t.Errorf("duplicate %s key %q in %s", c.code, key, rel)
			}
			keys[key] = true
		}
	}
}

func TestTemplatesAndBrowserMessagesUseEnglishSource(t *testing.T) {
	root := repoRoot(t)
	var missing []string
	templates, _ := filepath.Glob(filepath.Join(root, webDir, "templates", "*.html"))
	for _, path := range templates {
		name := filepath.Base(path)
		for _, fragment := range templateUIFragments(t, webDir+"/templates/"+name) {
			if cyrillicLetters.MatchString(fragment) {
				missing = append(missing, name+": "+fragment)
			}
		}
	}
	scripts, _ := filepath.Glob(filepath.Join(root, webDir, "static", "js", "*.js"))
	for _, path := range scripts {
		name := filepath.Base(path)
		for _, fragment := range javascriptUIFragments(t, webDir+"/static/js/"+name) {
			if cyrillicLetters.MatchString(fragment) {
				missing = append(missing, name+": "+fragment)
			}
		}
	}
	if len(missing) > 0 {
		t.Fatalf("non-English UI source:\n%s", strings.Join(missing, "\n"))
	}
}

// The Python panel whose runtime strings the Python suite also checked is
// gone; the remaining Python is covered by the English-source contract.

func TestBaseTemplateLoadsCatalogAsExternalScriptBeforeI18nJs(t *testing.T) {
	html := read(t, webDir+"/templates/base.html")
	if !regexp.MustCompile(`<script src="\{\{\s*i18n_messages_url\s*\}\}"`).MatchString(html) {
		t.Fatal("the catalog is not loaded as an external script")
	}
	// It must load before i18n.js, which reads HAPROXY_ADMIN_I18N.messages.
	if strings.Index(html, "i18n_messages_url") >= strings.Index(html, "js/i18n.js") {
		t.Fatal("the catalog loads after i18n.js")
	}
}
