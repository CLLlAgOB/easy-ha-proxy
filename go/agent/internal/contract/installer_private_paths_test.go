package contract

import (
	"strings"
	"testing"
)

// Shell launchers never use predictable fixed paths under /tmp: a local
// attacker could pre-create or symlink them. The CA export path and
// symlink-safety tests live in go/agent/internal/cli/wizard_test.go.

func TestNoScriptNamesAFixedDirectoryInTmp(t *testing.T) {
	for _, name := range []string{"install.sh", "install-local.sh", "install-remote.sh", "easy-ha-proxy-helper.sh"} {
		text := read(t, name)
		for _, forbidden := range []string{"/tmp/easy-ha-proxy-ansible", "/tmp/easy-ha-proxy-internal-ca"} {
			if strings.Contains(text, forbidden) {
				t.Errorf("%s names the fixed path %q", name, forbidden)
			}
		}
	}
}
