package app

import (
	"strings"
	"testing"
	"time"

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

func TestSyncHAProxyVersionFromStatusInvalidatesStaleCache(t *testing.T) {
	defer ForgetHAProxyVersion()

	seed := func(full string) {
		m := pyyaml.NewMap()
		m.Set("short", "2.8.30")
		m.Set("full", full)
		haproxyVer.mu.Lock()
		haproxyVer.value = m
		haproxyVer.at = time.Now()
		haproxyVer.mu.Unlock()
	}

	// Steady-state status with matching version keeps the cache warm.
	seed("2.8.30-0ubuntu0.24.04.2")
	steady := newMap(
		"ok", true,
		"haproxy_operation", newMap("phase", "committed", "target_runtime_version", "2.8.30-0ubuntu0.24.04.2"),
		"plan", newMap("components", []any{
			newMap("id", "haproxy", "details", newMap("running_version", "2.8.30-0ubuntu0.24.04.2")),
		}),
	)
	SyncHAProxyVersionFromStatus(steady)
	if got := cachedHAProxyVersionFull(); got != "2.8.30-0ubuntu0.24.04.2" {
		t.Fatalf("matching status must keep cached version, got %q", got)
	}

	// A committed migration/patch to a new version drops the stale cache immediately.
	committed := newMap(
		"ok", true,
		"haproxy_operation", newMap("phase", "committed", "target_runtime_version", "3.4.8-0+ha34+ubuntu24.04u1"),
	)
	SyncHAProxyVersionFromStatus(committed)
	if got := cachedHAProxyVersionFull(); got != "" {
		t.Fatalf("committed version change must clear cache, got %q", got)
	}

	// A rollback to a different version clears the cache too.
	seed("3.4.8-0+ha34+ubuntu24.04u1")
	rolledBack := newMap(
		"ok", true,
		"haproxy_operation", newMap("phase", "rolled_back", "old_version", "2.8.30-0ubuntu0.24.04.2"),
	)
	SyncHAProxyVersionFromStatus(rolledBack)
	if got := cachedHAProxyVersionFull(); got != "" {
		t.Fatalf("rollback version change must clear cache, got %q", got)
	}

	// An out-of-band upgrade detected in a refreshed plan clears the cache.
	seed("2.8.30-0ubuntu0.24.04.2")
	planDiff := newMap(
		"ok", true,
		"plan", newMap("components", []any{
			newMap("id", "haproxy", "details", newMap("running_version", "3.4.8-0+ha34+ubuntu24.04u1")),
		}),
	)
	SyncHAProxyVersionFromStatus(planDiff)
	if got := cachedHAProxyVersionFull(); got != "" {
		t.Fatalf("plan running_version mismatch must clear cache, got %q", got)
	}

	// An active HAProxy job clears the cache; an unrelated OS job does not.
	seed("2.8.30-0ubuntu0.24.04.2")
	SyncHAProxyVersionFromStatus(newMap("ok", true, "active_job", newMap("operation", "apply", "components", []any{"os"})))
	if got := cachedHAProxyVersionFull(); got != "2.8.30-0ubuntu0.24.04.2" {
		t.Fatalf("unrelated active job must not clear cache, got %q", got)
	}
	SyncHAProxyVersionFromStatus(newMap("ok", true, "active_job", newMap("operation", "haproxy-transition", "components", []any{"haproxy"})))
	if got := cachedHAProxyVersionFull(); got != "" {
		t.Fatalf("active haproxy-transition must clear cache, got %q", got)
	}
}
