package stages

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/engine"
)

// buildPart builds a part's steps over the repository's roles, an empty
// configuration and the given extra variables.
func buildPart(t *testing.T, name string, sys *engine.System, extra map[string]any) []engine.Step {
	t.Helper()
	p, ok := parts[name]
	if !ok {
		t.Fatalf("no part %s", name)
	}
	if sys == nil {
		sys = &engine.System{}
	}
	root := repoRoot(t)
	b := &Builder{Set: mustSetWith(t, root, p, extra), Sys: sys, RoleDir: filepath.Join(root, "ansible", "roles", p.Role)}
	steps := p.Build(b)
	if b.err != nil {
		t.Fatal(b.err)
	}
	return steps
}

// stepAt is the first step of that name; the test fails without one.
func stepAt(t *testing.T, steps []engine.Step, name string) int {
	t.Helper()
	for i, s := range steps {
		if s.Name == name {
			return i
		}
	}
	var names []string
	for _, s := range steps {
		names = append(names, s.Name)
	}
	t.Fatalf("no step %q in:\n  %s", name, strings.Join(names, "\n  "))
	return -1
}

// Steps whose order is what keeps a gateway safe: each list must appear in
// this order within its part.
func TestStepsKeepTheOrderThatKeepsTheGatewaySafe(t *testing.T) {
	for _, c := range []struct {
		part, why string
		order     []string
	}{
		{"authelia/install", "Authelia refuses to start on a clock that is off: stop before anything is deployed",
			[]string{"Stop before deploying Authelia with an inaccurate clock", "Deploy Authelia configuration"}},
		{"authelia/install", "the new image is pulled first; the spool, the database and the session dump are taken care of before it runs",
			[]string{"Pull Authelia stack images", "Safely migrate the legacy container-layer mail relay spool",
				"Copy the Authelia database before a different image starts on it",
				"Let the Redis image about to run check the session dump", "Ensure Authelia stack is up"}},
		{"authelia/update", "a targeted update renders the new Compose file before it migrates the spool, and guards the same way",
			[]string{"Render the current Authelia Compose definition before migration", "Pull Authelia stack images",
				"Safely migrate the legacy container-layer mail relay spool",
				"Copy the Authelia database before a different image starts on it",
				"Let the Redis image about to run check the session dump", "Reconcile Authelia stack after image pull",
				"Wait for Authelia after image update"}},
		{"docker/docker", "the package list is refreshed only after the repository is added, and before the engine is installed",
			[]string{"Add Docker APT repository", "Refresh APT cache after adding the Docker repository", "Install Docker Engine and plugins"}},
		{"update_packages/upgrade", "live-restore is on before apt can restart Docker; the guard reads fresh metadata before the upgrade",
			[]string{"Validate and write Docker live restore while preserving other settings",
				"Refresh APT metadata before reviewing the package upgrade",
				"Verify package upgrade safety and record the installation attempt", "Update and upgrade apt packages"}},
		{"haproxy/config", "the state dumper and its normalizer exist before the configuration that reads them; state is refreshed before the start",
			[]string{"server-state | Install the shared state normalizer", "server-state | Install the dump script",
				"server-state | Normalize state before every cold start", "server-state | Enable the refresh timer",
				"Copy HAProxy configuration", "server-state | Refresh administrative state without transport overrides",
				"Ensure HAProxy is enabled and running after configuration"}},
		{"start", "the panel counts as started when Docker reports it healthy",
			[]string{"haproxy-admin | docker compose up", "haproxy-admin | Read container health status"}},
		{"update_haproxy_admin", "an image update waits for the same health",
			[]string{"Up -d (recreate if needed)", "haproxy-admin | Read container health status"}},
		{"haproxy/install", "a different provider is refused before anything is installed, and the core is held after",
			[]string{"Ensure HAProxy runtime socket group exists before package installation",
				"HAProxy package | Require a separate provider migration", "HAProxy package | Install the distribution package",
				"HAProxy updates | hold core packages outside explicit updates"}},
	} {
		steps := buildPart(t, c.part, nil, nil)
		last := -1
		for _, name := range c.order {
			at := stepAt(t, steps, name)
			if at <= last {
				t.Errorf("%s: %q comes before the step listed ahead of it (%s)", c.part, name, c.why)
			}
			last = at
		}
	}
}

// The panel's containers read the daemon IPC token: it is rendered root-only.
func TestTheDaemonTokenFileIsRootOnly(t *testing.T) {
	steps := buildPart(t, "daemons_env", nil, nil)
	step := steps[stepAt(t, steps, "Render root-only daemon IPC token file")]
	res, err := step.Build(engine.NewRun(engine.Plan, &engine.System{}, nil))
	if err != nil {
		t.Fatal(err)
	}
	file, ok := res.(*engine.File)
	if !ok {
		t.Fatalf("the token is a %T", res)
	}
	if file.Mode != 0o600 || file.Owner != "root" {
		t.Fatalf("token file %s owner %s mode %o", file.Path, file.Owner, file.Mode)
	}
}
