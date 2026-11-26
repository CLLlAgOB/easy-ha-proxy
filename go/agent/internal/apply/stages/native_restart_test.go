package stages

import (
	"strings"
	"testing"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/engine"
)

// On a fresh host the native stage replaces the agent before any daemon is
// installed: "systemctl try-restart" of a unit that is not there exits 5 and
// stopped the clean install. Only the units that exist are restarted.
func TestTryRestartSkipsUnitsThatAreNotThere(t *testing.T) {
	for _, tc := range []struct {
		name    string
		loaded  map[string]bool
		noBlock bool
		want    string // the try-restart call, "" for none
	}{
		{"fresh host", map[string]bool{}, false, ""},
		{"some installed", map[string]bool{"a.service": true, "c.service": true}, false, "try-restart a.service c.service"},
		{"no-block kept", map[string]bool{"b.service": true}, true, "try-restart --no-block b.service"},
	} {
		var restarts []string
		sys := &engine.System{Exec: func(name string, args ...string) (string, int, error) {
			if name != "systemctl" {
				t.Fatalf("%s: ran %s", tc.name, name)
			}
			if args[0] == "show" {
				if tc.loaded[args[len(args)-1]] {
					return "loaded\n", 0, nil
				}
				return "not-found\n", 0, nil
			}
			restarts = append(restarts, strings.Join(args, " "))
			return "", 0, nil
		}}
		r := engine.NewRun(engine.Apply, sys, nil)
		step := engine.Step{Name: "restart", Resource: tryRestart(tc.noBlock, "a.service", "b.service", "c.service")}
		if err := r.Do("native", []engine.Step{step}); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := strings.Join(restarts, ";"); got != tc.want {
			t.Errorf("%s: restarts %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestTryRestartReportsAFailedRestart(t *testing.T) {
	sys := &engine.System{Exec: func(name string, args ...string) (string, int, error) {
		if args[0] == "show" {
			return "loaded\n", 0, nil
		}
		return "Job failed", 1, nil
	}}
	err := engine.NewRun(engine.Apply, sys, nil).Do("native", []engine.Step{{Name: "restart", Resource: tryRestart(false, "a.service")}})
	if err == nil || !strings.Contains(err.Error(), "exit 1") {
		t.Fatalf("err %v", err)
	}
}
