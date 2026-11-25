package app

import (
	"strings"
	"testing"

	"easy-ha-proxy/panel/shared/pyyaml"
)

// The panel image is fingerprinted over the panel's inputs, which the host
// reports as go_web_tree. A web_tree from an older broker (the Flask image's
// fingerprint) is not comparable and must not decide the match.
func TestFooterComparesThePanelWithTheHostsGoTree(t *testing.T) {
	a := testApp(t)
	goTree := strings.Repeat("a", 64)
	t.Setenv("EHP_BUILD_REVISION", strings.Repeat("1", 40))
	t.Setenv("EHP_BUILD_DATE", "2026-11-24T10:00:00+00:00")
	t.Setenv("EHP_SOURCE_TREE", goTree)
	defer ForgetBadge()

	remember := func(fields ...any) {
		build := pyyaml.NewMap()
		build.Set("revision", strings.Repeat("2", 40))
		build.Set("committed_at", "2026-11-24T09:00:00+00:00")
		for i := 0; i < len(fields); i += 2 {
			build.Set(fields[i].(string), fields[i+1])
		}
		summary := pyyaml.NewMap()
		summary.Set("build", build)
		RememberBadge(summary)
	}

	remember("go_web_tree", goTree)
	if got := a.buildFooter(nil).(*pyyaml.Map).Value("match"); got != true {
		t.Fatalf("same Go tree must match, got %v", got)
	}
	remember("go_web_tree", strings.Repeat("c", 64))
	if got := a.buildFooter(nil).(*pyyaml.Map).Value("match"); got != false {
		t.Fatalf("a different Go tree must not match, got %v", got)
	}
	remember("web_tree", goTree)
	if got := a.buildFooter(nil).(*pyyaml.Map).Value("match"); got != nil {
		t.Fatalf("without go_web_tree there is nothing to compare, got %v", got)
	}
}
