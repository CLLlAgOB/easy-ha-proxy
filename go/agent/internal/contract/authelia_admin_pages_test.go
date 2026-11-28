package contract

import (
	"strings"
	"testing"
)

// Regression checks for the Authelia users, ACL and general settings pages:
// user forms render the CSRF token as a hidden input rather than visible
// text, every audited server form carries an explicit CSRF field, and the ACL
// editor disables itself after a load failure so a stale form cannot
// overwrite the rules.

func TestAutheliaUserFormsRenderCsrfAsHiddenInputNotText(t *testing.T) {
	for _, name := range []string{"authelia_user_new.html", "authelia_user_edit.html"} {
		template := read(t, webDir+"/templates/"+name)
		if strings.Contains(template, "{{ csrf_token() if csrf_token is defined }}") {
			t.Errorf("%s renders the CSRF token as text", name)
		}
		mustContain(t, template, `<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">`, name)
	}
}

func TestAutheliaAllAuditedServerFormsHaveExplicitCsrfFields(t *testing.T) {
	for _, form := range []struct {
		name    string
		minimum int
	}{
		{"authelia_users.html", 1},
		{"authelia_acl_edit.html", 1},
		{"authelia_settings.html", 1},
	} {
		template := read(t, webDir+"/templates/"+form.name)
		if got := strings.Count(template, `name="csrf_token"`); got < form.minimum {
			t.Errorf("%s has %d csrf_token fields, want at least %d", form.name, got, form.minimum)
		}
	}
}

func TestAutheliaAclTemplateDisablesEditorAfterLoadFailure(t *testing.T) {
	template := read(t, webDir+"/templates/authelia_acl_edit.html")
	mustContain(t, template, "{% if acl_load_error %}", "authelia_acl_edit.html")
	mustContain(t, template, "Editing is disabled to prevent accidental overwrite.", "authelia_acl_edit.html")
}
