package contract

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Machine output must reach the operator unaltered. The DOM translator
// substitutes word by word whatever it does not recognise whole, so pointing
// it at a daemon's output rewrites load-bearing path components (local, ban,
// rules, backup are ordinary English words to it). Every container a script
// fills with daemon output must be exempt from translation.

// machineOutputContainers lists the elements a script fills with text that
// came from a daemon: paths, commands, exit codes, log lines, addresses.
var machineOutputContainers = []struct {
	name string
	ids  []string
}{
	{"system_backups.html", []string{
		"backup-jobs-body", // the Result column carries the helper error
		"backup-job-log",   // raw job log
		"backup-destinations-body",
		"schedule-status",
		"schedule-last-run",
		"schedule-last-result",
		"schedule-next-run",
		"schedule-destinations",
		"schedule-passphrase-state",
		"dest-status",
	}},
	// A chosen file's name belongs to the operating system.
	{"haproxy_certs.html", []string{"material-name", "backup_file_name"}},
	{"haproxy_site_edit.html", []string{"cert-file-name"}},
	// Addresses, names, paths and counts, refreshed every few seconds.
	{"live_activity.html", []string{
		"la-updated", "la-addresses-body", "la-sites-body", "la-events-body",
		"la-banned-body", "la-limited-body", "la-note", "la-reasons",
		"la-limits-note", "la-rate", "la-requests",
	}},
	{"detection_rules.html", []string{
		"dr-mine",       // the operator's own signatures
		"dr-shipped",    // every shipped signature
		"dr-category",   // category names in the add form
		"dr-query-note", // the query rule names
		"dr-counts",
		"dr-version",
		"dr-result",
	}},
}

// machineOutputTag is attributes_of: the attribute text of the element
// carrying this id.
func machineOutputTag(t *testing.T, markup, elementID string) string {
	t.Helper()
	re := regexp.MustCompile(`<([a-zA-Z]+)[^>]*\bid="` + regexp.QuoteMeta(elementID) + `"[^>]*>`)
	tag := re.FindString(markup)
	if tag == "" {
		t.Fatalf("no element with id=%s", elementID)
	}
	return tag
}

func TestEveryMachineOutputContainerIsExempt(t *testing.T) {
	for _, c := range machineOutputContainers {
		markup := read(t, webDir+"/templates/"+c.name)
		for _, id := range c.ids {
			t.Run(c.name+"/"+id, func(t *testing.T) {
				tag := machineOutputTag(t, markup, id)
				// translate="no" is the half browsers and extensions obey;
				// data-i18n-skip is the half this application obeys. Both are
				// needed or one of the two will rewrite the container.
				mustContain(t, tag, "data-i18n-skip", id+" shows daemon output and would be translated")
				mustContain(t, tag, `translate="no"`, id)
			})
		}
	}
}

func TestTheJobsTableSpecifically(t *testing.T) {
	// The one that produced the mangled paths, named on its own so a
	// regression here is unmistakable in the failure output.
	markup := read(t, webDir+"/templates/system_backups.html")
	tag := machineOutputTag(t, markup, "backup-jobs-body")
	mustContain(t, tag, "data-i18n-skip", "backup-jobs-body")
	mustContain(t, tag, `translate="no"`, "backup-jobs-body")
}

func TestASignatureSpecifically(t *testing.T) {
	// The second time this bug shipped: the file names backup.sql and
	// database.sql were shown with "backup" and "database" translated into
	// Russian. A signature rewritten on screen is a rule the operator cannot
	// match against their own traffic.
	markup := read(t, webDir+"/templates/detection_rules.html")
	for _, id := range []string{"dr-shipped", "dr-mine"} {
		t.Run(id, func(t *testing.T) {
			tag := machineOutputTag(t, markup, id)
			mustContain(t, tag, "data-i18n-skip", id)
			mustContain(t, tag, `translate="no"`, id)
		})
	}
}

func TestATranslatedPlaceholderSurvivesTheExemption(t *testing.T) {
	// Exempting the container also stops the fallback text being translated,
	// so the script must translate it instead.
	for _, name := range []string{"haproxy_certs.js", "haproxy_site_edit.js"} {
		t.Run(name, func(t *testing.T) {
			source := read(t, webDir+"/static/js/"+name)
			if strings.Contains(source, `= "No file selected"`) {
				t.Errorf("%s holds %q", name, `= "No file selected"`)
			}
			mustContain(t, source, `window.t("No file selected")`, name)
		})
	}
}

func TestTheScriptMarksTheSignaturesItself(t *testing.T) {
	// Belt and braces: the container attribute is one edit away from being
	// lost, and a signature must survive that edit.
	script := read(t, webDir+"/static/js/detection_rules.js")
	mustContain(t, script, `setAttribute("data-i18n-skip", "")`, "detection_rules.js")
	mustContain(t, script, `setAttribute("translate", "no")`, "detection_rules.js")
	// Applied to the chip that carries a signature, not only somewhere.
	parts := strings.SplitN(script, "function token(", 2)
	if len(parts) != 2 {
		t.Fatal("no function token( in detection_rules.js")
	}
	block := strings.SplitN(parts[1], "function ruleCard", 2)[0]
	mustContain(t, block, "keepVerbatim(", "token() block")
}

func TestTheReplacementRulesAreWhatMakeThisNecessary(t *testing.T) {
	// Not a rule to change -- word-by-word substitution is the documented
	// fallback -- but a reason the exemptions above are not optional. If no
	// single dangerous word is translated any more, this class of bug is gone.
	root := filepath.Join(repoRoot(t), filepath.FromSlash(webDir), "translations")
	var b strings.Builder
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".json") {
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			b.Write(raw)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	russian := strings.ToLower(b.String())
	dangerous := []string{"local", "ban", "rules", "backup", "key", "state", "database", "custom"}
	hits := 0
	for _, word := range dangerous {
		if strings.Contains(russian, `"`+word+`"`) {
			hits++
		}
	}
	if hits == 0 {
		t.Error("if no single dangerous word is translated any more, this whole class of bug is gone and these exemptions can be revisited")
	}
}
