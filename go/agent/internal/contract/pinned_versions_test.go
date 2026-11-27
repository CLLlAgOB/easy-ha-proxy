package contract

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"easy-ha-proxy/panel/shared/pyyaml"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/pinnedversions"
)

// Watching what Dependabot cannot read: the versions pinned as role
// variables are compared with their registries by a weekly job that keeps
// one issue open while anything is behind; Dependabot itself is told not to
// offer what cannot be taken.

func TestVersionParsing(t *testing.T) {
	numbers, suffix, ok := pinnedversions.ParseVersion("7.4.9-alpine")
	if !ok || fmt.Sprint(numbers) != "[7 4 9]" || suffix != "-alpine" {
		t.Fatalf("7.4.9-alpine: %v %q %v", numbers, suffix, ok)
	}
	numbers, suffix, ok = pinnedversions.ParseVersion("v4.39.28")
	if !ok || fmt.Sprint(numbers) != "[4 39 28]" || suffix != "" {
		t.Fatalf("v4.39.28: %v %q %v", numbers, suffix, ok)
	}
	for _, odd := range []string{"latest", "8.0-rc1", "2.0.0-beta.2", "alpine", ""} {
		if _, _, ok := pinnedversions.ParseVersion(odd); ok {
			t.Errorf("%q parsed as a release", odd)
		}
	}
}

func TestSameSeriesAndNewestOfTheSameShape(t *testing.T) {
	tags := []string{"7.4.9-alpine", "7.4.12-alpine", "7.4.13", "8.2.1-alpine", "8.2-alpine",
		"8.4.0-rc1-alpine", "latest", "7.2.99-alpine"}
	series, latest := pinnedversions.NewerReleases("7.4.9-alpine", tags)
	if series != "7.4.12-alpine" || latest != "8.2.1-alpine" {
		t.Fatalf("series %q latest %q", series, latest)
	}
	series, latest = pinnedversions.NewerReleases("8.2.1-alpine", tags)
	if series != "" || latest != "" {
		t.Fatalf("a current pin reports series %q latest %q", series, latest)
	}
}

func TestReadingPins(t *testing.T) {
	text := "authelia_version: \"4.39.28\"\nmail_relay_image: juanluisbaptiste/postfix:1.9.0  # relay\n"
	if got := pinnedversions.ReadPin(text, "authelia_version"); got != "4.39.28" {
		t.Errorf("authelia_version %q", got)
	}
	if got := pinnedversions.ReadPin(text, "mail_relay_image"); got != "juanluisbaptiste/postfix:1.9.0" {
		t.Errorf("mail_relay_image %q", got)
	}
	name, tag := pinnedversions.SplitImage("redis:7.4.9-alpine")
	if name != "redis" || tag != "7.4.9-alpine" {
		t.Errorf("split_image: %q %q", name, tag)
	}
}

func TestEveryPinIsFoundAndOneRegistryDownIsOneLine(t *testing.T) {
	fetch := func(url string) (map[string]any, error) {
		if strings.Contains(url, "pypi.org") {
			return nil, errors.New("pypi unreachable")
		}
		return map[string]any{
			"results": []any{
				map[string]any{"name": "99.0.0"},
				map[string]any{"name": "99.0.0-alpine"},
			},
			"next": nil,
		}, nil
	}
	rows := pinnedversions.Check(repoRoot(t), fetch)
	byVariable := map[string]pinnedversions.Row{}
	for _, row := range rows {
		byVariable[row.Variable] = row
	}
	if len(byVariable) != len(pinnedversions.Pins) {
		t.Fatalf("%d rows, want %d", len(byVariable), len(pinnedversions.Pins))
	}
	for _, pin := range pinnedversions.Pins {
		row, ok := byVariable[pin.Variable]
		if !ok {
			t.Errorf("no row for %s", pin.Variable)
			continue
		}
		if row.Pinned == "" {
			t.Errorf("%s: no pin found", pin.Variable)
		}
	}
	if got := byVariable["authelia_version"].Latest; got != "99.0.0" {
		t.Errorf("authelia_version latest %q", got)
	}
	if got := byVariable["authelia_redis_image"].Latest; got != "99.0.0-alpine" {
		t.Errorf("authelia_redis_image latest %q", got)
	}
	if !pinnedversions.Behind(rows) {
		t.Error("the rows are not behind")
	}
	mustContain(t, pinnedversions.Report(rows), "| `authelia_version` (authelia/authelia) |", "report")
}

// dependabotEntries is each (ecosystem, directory) with its entry;
// directories lists several.
func dependabotEntries(t *testing.T) map[[2]string]*pyyaml.Map {
	t.Helper()
	v, err := pyyaml.Load([]byte(read(t, ".github/dependabot.yml")))
	if err != nil {
		t.Fatal(err)
	}
	entries := map[[2]string]*pyyaml.Map{}
	updates, _ := v.(*pyyaml.Map).Value("updates").([]any)
	for _, u := range updates {
		item := u.(*pyyaml.Map)
		dirs, _ := item.Value("directories").([]any)
		if dirs == nil {
			dirs = []any{item.Value("directory")}
		}
		for _, d := range dirs {
			entries[[2]string{item.Value("package-ecosystem").(string), d.(string)}] = item
		}
	}
	return entries
}

func TestDependabotTargetsAlphaEverywhere(t *testing.T) {
	entries := dependabotEntries(t)
	want := map[[2]string]bool{
		{"docker", "/go/panel"}: true,
		{"github-actions", "/"}: true,
		{"gomod", "/go/agent"}:  true, {"gomod", "/go/panel"}: true,
		{"cargo", "/rust/guardd"}: true,
	}
	if len(entries) != len(want) {
		t.Fatalf("%d entries, want %d", len(entries), len(want))
	}
	for key := range want {
		if _, ok := entries[key]; !ok {
			t.Errorf("no entry for %v", key)
		}
	}
	for key, item := range entries {
		if item.Value("target-branch") != "alpha" {
			t.Errorf("%v does not target alpha", key)
		}
	}
}

func TestDependabotOffersOnlyWhatCanBeTaken(t *testing.T) {
	entries := dependabotEntries(t)
	// Nothing for a gateway: the installer is the host agent.
	if regexp.MustCompile(`(?m)^[^#\s]`).MatchString(read(t, "installer/requirements.txt")) {
		t.Error("installer/requirements.txt holds a requirement")
	}
	// Every action in one pull request.
	actions := entries[[2]string{"github-actions", "/"}]
	patterns := actions.Value("groups").(*pyyaml.Map).Value("actions").(*pyyaml.Map).Value("patterns").([]any)
	if len(patterns) != 1 || patterns[0] != "*" {
		t.Errorf("actions patterns %v", patterns)
	}
}

func TestTheWeeklyJobWritesIssuesAndNothingElse(t *testing.T) {
	v, err := pyyaml.Load([]byte(read(t, ".github/workflows/dependencies.yml")))
	if err != nil {
		t.Fatal(err)
	}
	workflow := v.(*pyyaml.Map)
	perms := workflow.Value("permissions").(*pyyaml.Map)
	if perms.Len() != 1 || perms.Value("contents") != "read" {
		t.Errorf("workflow permissions %v", perms)
	}
	jobs := workflow.Value("jobs").(*pyyaml.Map)
	pinned := jobs.Value("pinned").(*pyyaml.Map)
	pinnedPerms := pinned.Value("permissions").(*pyyaml.Map)
	if pinnedPerms.Len() != 2 || pinnedPerms.Value("contents") != "read" || pinnedPerms.Value("issues") != "write" {
		t.Errorf("pinned permissions %v", pinnedPerms)
	}
	// The Python test dependencies are gone, so there is nothing to pip-audit;
	// Go and Rust vulnerabilities are scanned in CI.
	if jobs.Value("audit") != nil {
		t.Error("the dependencies workflow still runs a pip audit")
	}
}
