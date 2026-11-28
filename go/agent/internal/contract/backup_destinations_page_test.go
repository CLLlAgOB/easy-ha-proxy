package contract

import (
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Regression checks for the off-host destination routes and page: secrets
// start empty and are only sent when typed (an untouched field means "keep
// what is stored", not "clear it"), only the chosen kind's fields are sent,
// writes carry the CSRF token, and the page explains why the host key matters.

func TestBackupDestinationsEveryElementTheScriptWritesToExists(t *testing.T) {
	javascript := read(t, webDir+"/static/js/backup_destinations.js")
	template := read(t, webDir+"/templates/system_backups.html")
	referenced := map[string]bool{}
	for _, m := range regexp.MustCompile(`byId\("([a-z0-9-]+)"\)`).FindAllStringSubmatch(javascript, -1) {
		referenced[m[1]] = true
	}
	if len(referenced) == 0 {
		t.Error("the script references no elements at all")
	}
	templateIDs := map[string]bool{}
	for _, m := range regexp.MustCompile(`id="([a-z0-9-]+)"`).FindAllStringSubmatch(template, -1) {
		templateIDs[m[1]] = true
	}
	var missing []string
	for id := range referenced {
		if !templateIDs[id] {
			missing = append(missing, id)
		}
	}
	sort.Strings(missing)
	if len(missing) != 0 {
		t.Errorf("elements the script writes to are missing from the template: %v", missing)
	}
}

func TestBackupDestinationsSecretsStartEmptyAndAreOnlySentWhenTyped(t *testing.T) {
	// The daemon never returns them, so an untouched field must mean
	// "keep what is stored" rather than "clear it".
	javascript := read(t, webDir+"/static/js/backup_destinations.js")
	mustContain(t, javascript, `byId("dest-key").value = "";`, "backup_destinations.js")
	mustContain(t, javascript, `byId("dest-host-key").value = "";`, "backup_destinations.js")
	mustContain(t, javascript, "if (key) body.private_key = key;", "backup_destinations.js")
	mustContain(t, javascript, "if (hostKey) body.host_key = hostKey;", "backup_destinations.js")
}

func TestBackupDestinationsWritesCarryTheCsrfToken(t *testing.T) {
	javascript := read(t, webDir+"/static/js/backup_destinations.js")
	mustContain(t, javascript, `options.headers["X-CSRFToken"] = csrfToken();`, "backup_destinations.js")
	// And only writes: a GET must not be turned into one by accident.
	parts := strings.SplitN(javascript, "async function api", 2)
	if len(parts) < 2 {
		t.Fatal("no api function in backup_destinations.js")
	}
	block := strings.SplitN(parts[1], "function status", 2)[0]
	mustContain(t, block, "if (body !== undefined)", "api")
}

func TestBackupDestinationsListIsNotRunThroughTheTranslator(t *testing.T) {
	template := read(t, webDir+"/templates/system_backups.html")
	tag := regexp.MustCompile(`<[^>]+id="backup-destinations-body"[^>]*>`).FindString(template)
	if tag == "" {
		t.Fatal("no backup-destinations-body element")
	}
	mustContain(t, tag, "data-i18n-skip", "backup-destinations-body")
}

func TestBackupDestinationsFormShowsOnlyTheFieldsThatKindNeeds(t *testing.T) {
	template := read(t, webDir+"/templates/system_backups.html")
	javascript := read(t, webDir+"/static/js/backup_destinations.js")
	for _, elementID := range []string{
		"dest-type", "dest-sftp-fields", "dest-s3-fields",
		"dest-endpoint", "dest-bucket", "dest-access-key",
		"dest-secret-key", "dest-allow-insecure",
	} {
		mustContain(t, template, `id="`+elementID+`"`, "system_backups.html")
	}
	mustContain(t, javascript, "function showKind()", "backup_destinations.js")
	mustContain(t, javascript, `byId("dest-s3-fields").hidden = kind !== "s3";`, "backup_destinations.js")
}

func TestBackupDestinationsOnlyTheChosenKindIsSent(t *testing.T) {
	// Sending SFTP fields alongside an S3 destination would have the
	// daemon validate a host that the operator never entered.
	javascript := read(t, webDir+"/static/js/backup_destinations.js")
	parts := strings.SplitN(javascript, "async function save", 2)
	if len(parts) < 2 {
		t.Fatal("no save function in backup_destinations.js")
	}
	block := parts[1]
	mustContain(t, block, `if (kind === "s3") {`, "save")
	mustContain(t, block, "body.secret_key = secret;", "save")
	mustContain(t, block, "body.private_key = key;", "save")
}

func TestBackupDestinationsS3SecretStartsEmptyToo(t *testing.T) {
	javascript := read(t, webDir+"/static/js/backup_destinations.js")
	mustContain(t, javascript, `byId("dest-secret-key").value = "";`, "backup_destinations.js")
	mustContain(t, javascript, "if (secret) body.secret_key = secret;", "backup_destinations.js")
}

func TestBackupDestinationsPageExplainsWhyTheHostKeyMatters(t *testing.T) {
	// The key is pinned on first use now rather than typed in, so what the
	// page has to say is that a change stops the transfer.
	template := read(t, webDir+"/templates/system_backups.html")
	mustContain(t, template, "pinned", "system_backups.html")
	mustContain(t, template, "nothing", "system_backups.html")
	mustContain(t, template, "is sent until you choose to trust the new one", "system_backups.html")
}

func TestBackupDestinationsScriptIsLoaded(t *testing.T) {
	template := read(t, webDir+"/templates/system_backups.html")
	mustContain(t, template, "js/backup_destinations.js", "system_backups.html")
}
