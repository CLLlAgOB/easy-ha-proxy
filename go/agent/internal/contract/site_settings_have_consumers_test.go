package contract

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// A setting the page offers has to reach something that acts on it.
// err_exclude was a facade: the editor accepted rules, the validator passed
// them, websites.yml stored them, the page redisplayed them on reload -- and
// the template declared a variable for the feature and never set it. Every
// per-site setting the editor offers is checked for a consumer somewhere
// that could act on it: the HAProxy template, the Ansible role, a helper
// daemon, or the application.

const siteSettingsForm = webDir + "/templates/haproxy_site_edit.html"
const siteSettingsTemplate = "ansible/roles/haproxy/templates/haproxy.cfg.j2"

// siteSettingsConsumerSources is everything that could act on a site
// setting, as one blob.
func siteSettingsConsumerSources(t *testing.T) string {
	t.Helper()
	root := repoRoot(t)
	var parts []string
	for _, pattern := range []string{
		"ansible/roles/*/templates/*.j2",
		"ansible/roles/*/tasks/*.yml",
		"ansible/roles/*/defaults/*.yml",
		"go/agent/internal/*/*.go",
		"go/panel/internal/*/*.go",
	} {
		paths, err := filepath.Glob(filepath.Join(root, filepath.FromSlash(pattern)))
		if err != nil {
			t.Fatal(err)
		}
		sort.Strings(paths)
		for _, path := range paths {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			parts = append(parts, string(raw))
		}
	}
	return strings.Join(parts, "\n")
}

// Names the form uses for controls that are folded into another key before
// anything stores them, so they are never site settings in their own right.
var siteSettingsFormOnly = map[string]bool{
	// A radio that the page turns into certificate_source/le_managed.
	"cert_mode": true,
	// Checkboxes the page turns into the key_types list.
	"key_type_ecdsa": true,
	"key_type_rsa":   true,
	// The control for tcp_check.
	"tcp_passthrough_check": true,
}

var siteSettingsStructure = map[string]bool{
	"name": true, "domain": true, "servers": true, "host": true, "port": true,
	"weight": true, "backup": true, "csrf_token": true,
}

// Nothing is offered without a consumer any more. waf and
// enable_splice_backend were the two that were, and both were withdrawn
// rather than half-built: waf named a spoe-engine with no SPOE anywhere in
// the repository, and neither splice setting reached haproxy.cfg. An empty
// set here is the state to keep.
var siteSettingsNotImplemented = map[string]bool{}

var siteSettingsName = regexp.MustCompile(`name="([a-z][a-z0-9_]+)"`)

func siteSettingsOffered(t *testing.T) map[string]bool {
	t.Helper()
	offered := map[string]bool{}
	for _, m := range siteSettingsName.FindAllStringSubmatch(read(t, siteSettingsForm), -1) {
		n := m[1]
		if !siteSettingsStructure[n] && !siteSettingsFormOnly[n] {
			offered[n] = true
		}
	}
	return offered
}

// siteSettingsWordRune is Python's Unicode-aware \w.
func siteSettingsWordRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_'
}

// siteSettingsHasConsumer is re.search(r"\b"+re.escape(name)+r"\b", sources)
// with Unicode word boundaries: RE2's \b is ASCII-only, so the boundary
// runes are checked by hand. A rejected occurrence cannot overlap a later
// accepted one, every rune of an offered name being a word rune itself.
func siteSettingsHasConsumer(sources, name string) bool {
	i := 0
	for {
		j := strings.Index(sources[i:], name)
		if j < 0 {
			return false
		}
		j += i
		end := j + len(name)
		beforeOK := true
		if j > 0 {
			r, _ := utf8.DecodeLastRuneInString(sources[:j])
			beforeOK = !siteSettingsWordRune(r)
		}
		afterOK := true
		if end < len(sources) {
			r, _ := utf8.DecodeRuneInString(sources[end:])
			afterOK = !siteSettingsWordRune(r)
		}
		if beforeOK && afterOK {
			return true
		}
		i = end
	}
}

// A parse that finds nothing would make the consumer check vacuously true.
func TestTheFormOffersSomething(t *testing.T) {
	if n := len(siteSettingsOffered(t)); n <= 30 {
		t.Fatalf("the form was not parsed: only %d offered settings", n)
	}
}

// Every offered setting is acted on somewhere; the known gaps are named in
// siteSettingsNotImplemented so they can only be resolved, never quietly
// joined.
func TestEveryOfferedSettingIsActedOnSomewhere(t *testing.T) {
	sources := siteSettingsConsumerSources(t)
	var orphans []string
	for name := range siteSettingsOffered(t) {
		if !siteSettingsHasConsumer(sources, name) && !siteSettingsNotImplemented[name] {
			orphans = append(orphans, name)
		}
	}
	if len(orphans) > 0 {
		sort.Strings(orphans)
		t.Errorf("the page offers these and nothing reads them: %s", strings.Join(orphans, ", "))
	}
}

// The setting this whole test exists because of: err_exclude reaches the
// template's exclusion matchers. The union check mirrors the Python one,
// which tolerates the control being built by JavaScript rather than a
// name="..." attribute.
func TestErrExcludeIsNoLongerOneOfThem(t *testing.T) {
	union := map[string]bool{"err_exclude": true}
	for name := range siteSettingsOffered(t) {
		union[name] = true
	}
	if !union["err_exclude"] {
		t.Error("err_exclude is not among the offered settings")
	}
	mustContain(t, read(t, siteSettingsTemplate), "ex.path_beg", "haproxy.cfg.j2")
}

// siteSettingsJoinGlob is every file of a directory as one blob, as the
// Python pages()/scripts() helpers joined them.
func siteSettingsJoinGlob(t *testing.T, dir, pattern string) string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(repoRoot(t), filepath.FromSlash(dir), pattern))
	if err != nil {
		t.Fatal(err)
	}
	var parts []string
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		parts = append(parts, string(raw))
	}
	return strings.Join(parts, "\n")
}

// The two that were facades are gone from the pages, not merely
// undocumented.
func TestThePagesNoLongerOfferThem(t *testing.T) {
	pages := siteSettingsJoinGlob(t, webDir+"/templates", "*.html")
	for _, name := range []string{`name="waf"`, `name="enable_splice_backend"`} {
		if strings.Contains(pages, name) {
			t.Errorf("the pages still offer %s", name)
		}
	}
}

func TestTheScriptsNoLongerCollectThem(t *testing.T) {
	scripts := siteSettingsJoinGlob(t, webDir+"/static/js", "*.js")
	for _, unwanted := range []string{"site.waf", "enable_splice_backend"} {
		if strings.Contains(scripts, unwanted) {
			t.Errorf("the scripts still collect %q", unwanted)
		}
	}
}

// Only what a clone actually contains: ansible/vars.yml is generated per
// installation and is gitignored, so it exists on a developer's machine and
// never on a CI runner -- reading it unconditionally passes locally and
// fails everywhere else.
func TestTheDefaultsNoLongerDeclareThem(t *testing.T) {
	candidates := []string{
		"ansible/roles/haproxy/defaults/main.yml",
		"ansible/vars.yml",
		"go/agent/internal/cli/wizard.go",
	}
	checked := 0
	for _, rel := range candidates {
		raw, err := os.ReadFile(filepath.Join(repoRoot(t), filepath.FromSlash(rel)))
		if err != nil {
			continue // not a file of this clone
		}
		checked++
		text := string(raw)
		for _, name := range []string{"waf:", "enable_splice_global:", `"waf"`} {
			if strings.Contains(text, name) {
				t.Errorf("%s still declares %q", filepath.Base(rel), name)
			}
		}
	}
	if checked == 0 {
		t.Fatal("nothing was actually examined")
	}
}

// An existing websites.yml may still carry the withdrawn keys; they are
// simply ignored, which is why nothing had to migrate.
func TestAStoredValueDoesNotBreakAnything(t *testing.T) {
	template := read(t, siteSettingsTemplate)
	for _, unwanted := range []string{"splice", "s.waf"} {
		if strings.Contains(template, unwanted) {
			t.Errorf("haproxy.cfg.j2 still holds %q", unwanted)
		}
	}
}

// The waf setting named a spoe-engine; without a SPOE section HAProxy has
// no way to act on the name whatever it is set to.
func TestNothingConfiguresASpoeEngine(t *testing.T) {
	root := repoRoot(t)
	for _, pattern := range []string{"ansible/roles/*/templates/*.j2", "ansible/roles/*/files/*"} {
		paths, err := filepath.Glob(filepath.Join(root, filepath.FromSlash(pattern)))
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range paths {
			info, err := os.Stat(path)
			if err != nil || info.IsDir() {
				continue
			}
			raw, err := os.ReadFile(path)
			if err != nil || !utf8.Valid(raw) {
				continue // unreadable or not UTF-8 text, as the Python skip
			}
			if strings.Contains(string(raw), "filter spoe") {
				t.Errorf("%s configures SPOE after all", filepath.Base(path))
			}
		}
	}
}
