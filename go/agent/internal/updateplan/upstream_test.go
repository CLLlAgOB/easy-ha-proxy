package updateplan

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// The update check says when upstream has released past a pinned image (U01),
// as information: no pull, no pin, no button. A list the registry cuts
// short, or no answer, is "unknown", never "nothing newer".

var upstreamTags = []string{"8.10.3-alpine", "8.10.4-alpine", "8.12.0-alpine", "8.12-alpine", "8-alpine", "alpine",
	"8.14.0-rc1-alpine", "8.14.0-alpine3.22", "8.12.1", "9.0.0-alpine", "9.0.0-M01-alpine", "7.4.6-alpine"}

type fakeRegistry struct {
	t     *testing.T
	tags  []string
	link  bool
	err   error
	asked []string
}

func (r *fakeRegistry) fetch(url string, headers map[string]string) ([]byte, map[string]string, error) {
	r.asked = append(r.asked, url)
	if r.err != nil {
		return nil, nil, r.err
	}
	if strings.HasPrefix(url, "https://auth.docker.io/") {
		return []byte(`{"token": "t"}`), map[string]string{}, nil
	}
	if headers["Authorization"] != "Bearer t" {
		r.t.Errorf("authorization %q", headers["Authorization"])
	}
	body, _ := json.Marshal(M{"tags": r.tags})
	if r.link {
		return body, map[string]string{"link": "<next>"}, nil
	}
	return body, map[string]string{}, nil
}

func registry(t *testing.T) *fakeRegistry { return &fakeRegistry{t: t, tags: upstreamTags} }

func TestANewerReleaseInTheSameFlavourIsReported(t *testing.T) {
	entry := upstreamRelease("redis:8.10.3-alpine", "project", registry(t).fetch)
	if entry["state"] != "newer" || entry["newest_same_major"] != "8.12.0-alpine" || entry["newest"] != "9.0.0-alpine" ||
		entry["current"] != "8.10.3-alpine" {
		t.Fatalf("entry %v", entry)
	}
}

func TestPrereleasesAndOtherFlavoursDoNotCount(t *testing.T) {
	r := registry(t)
	r.tags = nil
	for _, tag := range upstreamTags {
		if !strings.HasPrefix(tag, "9.") {
			r.tags = append(r.tags, tag)
		}
	}
	if entry := upstreamRelease("redis:8.12.0-alpine", "project", r.fetch); entry["state"] != "none" || entry["newest"] != nil {
		t.Fatalf("entry %v", entry)
	}
}

func TestAWholeListWithNothingNewerIsNone(t *testing.T) {
	if entry := upstreamRelease("redis:9.0.0-alpine", "project", registry(t).fetch); entry["state"] != "none" {
		t.Fatalf("entry %v", entry)
	}
}

func TestAListCutShortIsNotNone(t *testing.T) {
	r := registry(t)
	r.link = true
	if entry := upstreamRelease("redis:9.0.0-alpine", "project", r.fetch); entry["state"] != "unknown" || entry["reason"] != "tag-list-incomplete" {
		t.Fatalf("entry %v", entry)
	}
	// But what it did see is still news.
	if entry := upstreamRelease("redis:8.10.3-alpine", "project", r.fetch); entry["state"] != "newer" {
		t.Fatalf("entry %v", entry)
	}
}

func TestNoRegistryIsUnknown(t *testing.T) {
	r := registry(t)
	r.err = errors.New("offline")
	if entry := upstreamRelease("redis:8.10.3-alpine", "project", r.fetch); entry["state"] != "unknown" || entry["reason"] != "registry-unavailable" {
		t.Fatalf("entry %v", entry)
	}
}

func TestOnlyAllowListedRepositoriesAreAsked(t *testing.T) {
	r := registry(t)
	if upstreamRelease("authelia/authelia:4.39.28", "project", r.fetch) != nil ||
		upstreamRelease("redis@sha256:"+strings.Repeat("a", 64), "project", r.fetch) != nil || len(r.asked) != 0 {
		t.Fatalf("asked %v", r.asked)
	}
}

func TestAPinThatIsNotAReleaseIsUnknown(t *testing.T) {
	if entry := upstreamRelease("redis:alpine", "project", registry(t).fetch); entry["reason"] != "pin-is-not-a-release" {
		t.Fatalf("entry %v", entry)
	}
}

func TestWhoPinnedItIsSaid(t *testing.T) {
	components := []M{{"id": "authelia-container", "details": M{"images": []any{
		M{"image": "redis:8.10.3-alpine"}, M{"image": "authelia/authelia:4.39.28"}}}}}
	found := upstreamReleases(components, M{"authelia_redis_image": "redis:8.10.3-alpine"}, registry(t).fetch)
	if len(found) != 1 {
		t.Fatalf("found %v", found)
	}
	entry := found[0].(M)
	if entry["repository"] != "redis" || entry["pinned_by"] != "override" || entry["component"] != "authelia-container" {
		t.Fatalf("entry %v", entry)
	}
}

func TestOnlyTheCommandAsksTheRegistry(t *testing.T) {
	root := t.TempDir()
	source := prepareSource(t, root)
	authelia, admin := missingStacks(root)
	plan := buildPlanForTest(t, Options{SourceDir: source, ConfigDir: filepath.Join(root, "config"), AutheliaCompose: authelia,
		AdminCompose: admin, SourceChannel: "local", Runner: newFakeRunner(aptOnly), ArtifactPath: prepareInstalledDaemons(t, root, "")})
	if upstream := plan["upstream"].([]any); len(upstream) != 0 {
		t.Fatalf("upstream %v", upstream)
	}
	var options Options
	saved := buildPlan
	defer func() { buildPlan = saved }()
	buildPlan = func(o Options) (M, error) { options = o; return M{}, nil }
	if code := RunCLI(nil, &strings.Builder{}, &strings.Builder{}); code != 0 || options.Fetch == nil {
		t.Fatalf("code %d fetch %v", code, options.Fetch != nil)
	}
}

func TestThePageShowsUpstreamReleases(t *testing.T) {
	script := readFile(t, filepath.Join(repoRoot(), "go/panel/web/static/js/system_updates.js"))
	if !strings.Contains(script, "renderUpstream(plan);") ||
		!strings.Contains(script, `"Newer upstream release, not yet tested by this project:"`) {
		t.Fatal("the page does not render upstream releases")
	}
	messages := russianMessages(t)
	for _, label := range []string{"Newer upstream release, not yet tested by this project:", "No newer upstream release:",
		"Upstream releases could not be checked:"} {
		if _, found := messages[label]; !found {
			t.Fatalf("%q has no Russian", label)
		}
	}
}
