package updateplan

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func composeFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "docker-compose.yml")
	writeFile(t, path, "services: {}\n")
	return path
}

func firstImage(c M) M { return details(c)["images"].([]any)[0].(M) }

// A gateway running the Go panel is checked against the Go panel's tag. The
// deployment runs "<repo>:go-<channel>" while vars.yml keeps
// "<repo>:<channel>"; the check used to target the plain tag and offered a
// "channel change" every night that the deployment then undid.

type goPanelDocker struct {
	running   string
	inspected []string
}

func (d *goPanelDocker) Run(argv []string, _ time.Duration) CommandResult {
	digest, other := "sha256:"+strings.Repeat("2", 64), "sha256:"+strings.Repeat("9", 64)
	switch {
	case hasSuffix(argv, "config", "--images"):
		return ok(d.running + "\n")
	case hasSuffix(argv, "ps", "-q"):
		return ok("")
	case hasPrefix(argv, "docker", "buildx", "imagetools"):
		d.inspected = append(d.inspected, argv[4])
		if last(argv) == "{{json .Image}}" {
			return ok(mustJSON(M{"config": M{"Labels": M{}}}))
		}
		if strings.HasSuffix(argv[4], ":go-alpha") {
			return ok("Digest: " + digest)
		}
		return ok("Digest: " + other)
	case hasPrefix(argv, "docker", "image", "inspect"):
		if last(argv) == "{{json .RepoDigests}}" {
			return ok(mustJSON([]string{"example/panel@" + digest}))
		}
		return ok("{}")
	}
	return failed(1, "unexpected probe")
}

func probeGoPanel(t *testing.T, d Runner, targetChannel, flavour string) M {
	return probeAdminCompose(composeFile(t), d, adminOptions{configuredImage: "example/panel:alpha", configuredChannel: "alpha",
		targetChannel: targetChannel, targetFlavour: flavour})
}

func TestGoPanelIsComparedWithItsOwnTag(t *testing.T) {
	d := &goPanelDocker{running: "example/panel:go-alpha"}
	image := firstImage(probeGoPanel(t, d, "alpha", "go-"))
	if image["target_image"] != "example/panel:go-alpha" || image["reason"] == "image-channel-change" || image["state"] != "current" {
		t.Fatalf("image: %v", image)
	}
	if !has(d.inspected, "example/panel@sha256:"+strings.Repeat("2", 64)) {
		t.Fatalf("inspected %v", d.inspected)
	}
}

func TestTheTargetPanelFlavourDecidesTheTag(t *testing.T) {
	for _, tc := range []struct{ running, flavour, target string }{
		{"example/panel:alpha", "go-", "example/panel:go-latest"},
		{"example/panel:go-alpha", "", "example/panel:latest"},
	} {
		got := firstImage(probeGoPanel(t, &goPanelDocker{running: tc.running}, "latest", tc.flavour))["target_image"]
		if got != tc.target {
			t.Fatalf("%s with %q: %v", tc.running, tc.flavour, got)
		}
	}
}

func TestFlavourHelpers(t *testing.T) {
	for reference, want := range map[string]string{"r/p:go-alpha": "go-", "r/p:go-nightly": "", "r/p:alpha": ""} {
		if got := panelFlavour(reference); got != want {
			t.Fatalf("panelFlavour(%q) = %q", reference, got)
		}
	}
	if flavoured("r/p:latest", "go-") != "r/p:go-latest" || flavoured("r/p:go-latest", "go-") != "r/p:go-latest" {
		t.Fatal("flavoured")
	}
}

// A pinned image whose local tag went missing does not block every update:
// asked for by tag, Docker said "No such image" about an image that was
// running. The registry already said what the tag points to; the check asks
// for that content by digest.

const lostImage = "example/relay:1.9.0"

var (
	lostDigest = "sha256:" + strings.Repeat("9", 64)
	lostOther  = "sha256:" + strings.Repeat("1", 64)
	noSuch     = failed(1, "Error response from daemon: No such image: "+lostImage)
)

type lostTagDocker struct {
	byTag, registry CommandResult
	byContent       *CommandResult
	asked           [][]string
}

func (d *lostTagDocker) Run(argv []string, _ time.Duration) CommandResult {
	d.asked = append(d.asked, argv)
	if hasPrefix(argv, "docker", "buildx", "imagetools") {
		return d.registry
	}
	if strings.Contains(argv[3], "@sha256:") {
		if d.byContent != nil {
			return *d.byContent
		}
		return failed(1, "No such image")
	}
	return d.byTag
}

func relayRegistry(digest string) CommandResult {
	return ok("Name: " + lostImage + "\nDigest: " + digest + "\n")
}

func relayLocal(digest string) *CommandResult {
	r := ok(`["example/relay@` + digest + `"]` + "\n")
	return &r
}

func TestALostTagWithTheImageHereIsCurrent(t *testing.T) {
	d := &lostTagDocker{byTag: noSuch, registry: relayRegistry(lostDigest), byContent: relayLocal(lostDigest)}
	result := probeImage(lostImage, d)
	if result["state"] != "current" || result["current_digest"] != lostDigest || result["available_digest"] != lostDigest ||
		result["reason"] != "local-tag-missing" {
		t.Fatalf("result: %v", result)
	}
	if _, found := result["error"]; found {
		t.Fatalf("error: %v", result["error"])
	}
	want := []string{"docker", "image", "inspect", "example/relay@" + lostDigest, "--format", "{{json .RepoDigests}}"}
	found := false
	for _, argv := range d.asked {
		found = found || reflect.DeepEqual(argv, want)
	}
	if !found {
		t.Fatalf("not looked up by content: %q", d.asked)
	}
}

func TestAnImageThatReallyIsAbsentIsStillUnknown(t *testing.T) {
	result := probeImage(lostImage, &lostTagDocker{byTag: noSuch, registry: relayRegistry(lostDigest)})
	if result["state"] != "unknown" || result["reason"] != "local-digest-unavailable" ||
		!strings.Contains(result["error"].(string), "No such image") {
		t.Fatalf("result: %v", result)
	}
}

func TestATagThatIsThereIsNotAskedAboutTwice(t *testing.T) {
	d := &lostTagDocker{byTag: *relayLocal(lostDigest), registry: relayRegistry(lostDigest)}
	if probeImage(lostImage, d)["state"] != "current" || len(d.asked) != 2 {
		t.Fatalf("asked %q", d.asked)
	}
}

func TestANewerImageInTheRegistryIsStillAnUpdate(t *testing.T) {
	result := probeImage(lostImage, &lostTagDocker{byTag: *relayLocal(lostOther), registry: relayRegistry(lostDigest)})
	if result["state"] != "available" || result["current_digest"] != lostOther {
		t.Fatalf("result: %v", result)
	}
}

func TestWithoutTheRegistryThereIsNothingToLookUp(t *testing.T) {
	d := &lostTagDocker{byTag: noSuch, registry: failed(1, "timeout")}
	if result := probeImage(lostImage, d); result["reason"] != "local-digest-unavailable" || len(d.asked) != 2 {
		t.Fatalf("result %v asked %q", result, d.asked)
	}
}

// A tag the registry published again with the same image for this platform:
// one image ID, two RepoDigests. The local image is current when any of its
// digests is the one the registry offers.

const sessionsImage = "example/sessions:8.1-alpine"

var (
	sessionsOld = "sha256:" + strings.Repeat("7", 64)
	sessionsNew = "sha256:" + strings.Repeat("a", 64)
)

func sessionsDocker(local, registry CommandResult) Runner {
	return runnerFunc(func(argv []string) CommandResult {
		if hasPrefix(argv, "docker", "buildx", "imagetools") {
			return registry
		}
		return local
	})
}

func sessionsRegistry(digest string) CommandResult {
	return ok("Name: " + sessionsImage + "\nMediaType: application/vnd.oci.image.index.v1+json\nDigest: " + digest + "\n")
}

func repoDigests(digests ...string) CommandResult {
	quoted := make([]string, len(digests))
	for i, d := range digests {
		quoted[i] = `"example/sessions@` + d + `"`
	}
	return ok("[" + strings.Join(quoted, ",") + "]\n")
}

func TestARepublishedTagIsCurrentWhicheverDigestComesFirst(t *testing.T) {
	for _, order := range [][]string{{sessionsOld, sessionsNew}, {sessionsNew, sessionsOld}} {
		result := probeImage(sessionsImage, sessionsDocker(repoDigests(order...), sessionsRegistry(sessionsNew)))
		if result["state"] != "current" || result["current_digest"] != sessionsNew || result["available_digest"] != sessionsNew {
			t.Fatalf("%v: %v", order, result)
		}
	}
}

func TestAnImageWithoutTheOfferedDigestStillHasAnUpdate(t *testing.T) {
	result := probeImage(sessionsImage, sessionsDocker(repoDigests(sessionsOld), sessionsRegistry(sessionsNew)))
	if result["state"] != "available" || result["current_digest"] != sessionsOld {
		t.Fatalf("result: %v", result)
	}
}

func TestLocalDigests(t *testing.T) {
	// Without the registry the first digest is reported as before.
	if localDigest(repoDigests(sessionsOld, sessionsNew).Stdout, "") != sessionsOld || localDigest("[]\n", sessionsNew) != "" {
		t.Fatal("localDigest")
	}
	// A digest listed twice is one digest.
	if got := localDigests(repoDigests(sessionsOld, sessionsOld, sessionsNew).Stdout); !reflect.DeepEqual(got, []string{sessionsOld, sessionsNew}) {
		t.Fatalf("localDigests %v", got)
	}
}

func TestThePanelImageIsReadTheSameWay(t *testing.T) {
	image := "example/panel:go-alpha"
	panel := probeAdminCompose(composeFile(t), runnerFunc(func(argv []string) CommandResult {
		switch {
		case hasSuffix(argv, "config", "--images"):
			return ok(image + "\n")
		case hasSuffix(argv, "ps", "-q"):
			return ok("")
		case hasPrefix(argv, "docker", "buildx", "imagetools") && last(argv) == "{{json .Image}}":
			return ok("{}")
		case hasPrefix(argv, "docker", "buildx", "imagetools"):
			return ok("Digest: " + sessionsNew + "\n")
		case hasPrefix(argv, "docker", "image", "inspect") && last(argv) == "{{json .RepoDigests}}":
			return ok(mustJSON([]string{"example/panel@" + sessionsOld, "example/panel@" + sessionsNew}))
		}
		return ok("{}")
	}), adminOptions{configuredImage: "example/panel:alpha", configuredChannel: "alpha", targetChannel: "alpha", targetFlavour: "go-"})
	if got := firstImage(panel)["current_digest"]; got != sessionsNew {
		t.Fatalf("current digest %v", got)
	}
}

func TestTheReviewedDigestIsFoundAfterThePull(t *testing.T) {
	reviewed := probeImage(sessionsImage, sessionsDocker(repoDigests(sessionsOld), sessionsRegistry(sessionsNew)))
	after := probeImage(sessionsImage, sessionsDocker(repoDigests(sessionsOld, sessionsNew), sessionsRegistry(sessionsNew)))
	if reviewed["available_digest"] != after["current_digest"] {
		t.Fatalf("reviewed %v after %v", reviewed["available_digest"], after["current_digest"])
	}
}

// An image counts as current only when its container runs it (F31): after a
// pull the tag names the new image while the container keeps the old one.
// Held against the tag by content, because the IDs come in kinds that do not
// compare. Unreadable running metadata is "unknown", not "current".

const (
	cacheImage    = "example/cache:8.1-alpine"
	contentFormat = "{{json .RootFS.Layers}}\t{{json .Config}}"
)

var (
	cacheDigest = "sha256:" + strings.Repeat("b", 64)
	container   = strings.Repeat("c", 64)
	newID       = "sha256:" + strings.Repeat("2", 64)
	oldID       = "sha256:" + strings.Repeat("1", 64)
	otherKindID = "sha256:" + strings.Repeat("3", 64)
	newLayers   = []string{"sha256:" + strings.Repeat("a", 64), "sha256:" + strings.Repeat("e", 64)}
	oldLayers   = []string{"sha256:" + strings.Repeat("a", 64), "sha256:" + strings.Repeat("d", 64)}
)

func cacheConfig() M {
	return M{"Cmd": []string{"redis-server"}, "Env": []string{"PATH=/usr/bin"}, "Labels": M{"built": "monday"}}
}

func withConfig(changes M) M {
	c := cacheConfig()
	for k, v := range changes {
		c[k] = v
	}
	return c
}

func imageContentAnswer(layers []string, config M) CommandResult {
	if config == nil {
		config = cacheConfig()
	}
	return ok(mustJSON(layers) + "\t" + mustJSON(config))
}

type cacheDocker struct {
	runningID string
	layers    map[string][]string
	configs   map[string]M
	ps        *CommandResult
}

func (d *cacheDocker) Run(argv []string, _ time.Duration) CommandResult {
	switch {
	case hasSuffix(argv, "config", "--images"):
		return ok(cacheImage + "\n")
	case hasSuffix(argv, "ps", "-q"):
		if d.ps != nil {
			return *d.ps
		}
		return ok(container + "\n")
	case hasPrefix(argv, "docker", "inspect"):
		return ok(mustJSON(cacheImage) + " " + mustJSON(d.runningID) + "\n")
	case hasPrefix(argv, "docker", "buildx", "imagetools"):
		return ok("Name: " + cacheImage + "\nDigest: " + cacheDigest + "\n")
	case hasPrefix(argv, "docker", "image", "inspect") && last(argv) == "{{json .RepoDigests}}":
		return ok(`["example/cache@` + cacheDigest + `"]` + "\n")
	case hasPrefix(argv, "docker", "image", "inspect") && last(argv) == contentFormat:
		layers := d.layers[argv[3]]
		if len(layers) == 0 {
			return failed(1, "No such image")
		}
		return imageContentAnswer(layers, d.configs[argv[3]])
	}
	return failed(1, "unexpected "+strings.Join(argv, " "))
}

func probeCache(t *testing.T, d Runner) (M, M) {
	c := probeCompose("authelia-container", composeFile(t), d, nil)
	return c, firstImage(c)
}

func TestAContainerOnTheOldImageIsNotCurrent(t *testing.T) {
	// running A, downloaded B, registry B: the reported case.
	c, image := probeCache(t, &cacheDocker{runningID: oldID, layers: map[string][]string{cacheImage: newLayers, oldID: oldLayers}})
	if c["state"] != "available" || image["reason"] != "running-older-image" || image["running_image"] != oldID {
		t.Fatalf("image: %v", image)
	}
}

func TestTheSameContentUnderAnotherKindOfIDIsCurrent(t *testing.T) {
	c, image := probeCache(t, &cacheDocker{runningID: otherKindID,
		layers: map[string][]string{cacheImage: newLayers, otherKindID: newLayers}})
	if c["state"] != "current" || image["running"] != "same-content" {
		t.Fatalf("image: %v", image)
	}
}

func TestRunningMetadataThatCannotBeReadIsUnknown(t *testing.T) {
	c, image := probeCache(t, &cacheDocker{runningID: oldID, layers: map[string][]string{cacheImage: newLayers}})
	if c["state"] != "unknown" || image["reason"] != "running-image-unreadable" {
		t.Fatalf("image: %v", image)
	}
}

func TestAStackThatCannotBeListedIsUnknownNotCurrent(t *testing.T) {
	down := failed(1, "daemon down")
	c, image := probeCache(t, &cacheDocker{runningID: oldID, layers: map[string][]string{}, ps: &down})
	if c["state"] != "unknown" || image["reason"] != "running-unchecked" || image["running"] != "unchecked" {
		t.Fatalf("image: %v", image)
	}
}

func TestTheSameFilesRunAnotherWayAreNotCurrent(t *testing.T) {
	changed := withConfig(M{"Env": []string{"PATH=/usr/bin", "POLICY=legacy"}})
	c, image := probeCache(t, &cacheDocker{runningID: otherKindID,
		layers: map[string][]string{cacheImage: newLayers, otherKindID: newLayers}, configs: map[string]M{otherKindID: changed}})
	if c["state"] != "available" || image["reason"] != "running-older-image" {
		t.Fatalf("image: %v", image)
	}
}

func TestLabelsAloneDoNotMakeAnUpdate(t *testing.T) {
	relabelled := withConfig(M{"Labels": M{"built": "tuesday"}})
	c, image := probeCache(t, &cacheDocker{runningID: otherKindID,
		layers: map[string][]string{cacheImage: newLayers, otherKindID: newLayers}, configs: map[string]M{otherKindID: relabelled}})
	if c["state"] != "current" || image["running"] != "same-content" {
		t.Fatalf("image: %v", image)
	}
}

func TestTheOrderOfTheEnvironmentDoesNotMatter(t *testing.T) {
	c, _ := probeCache(t, &cacheDocker{runningID: otherKindID,
		layers: map[string][]string{cacheImage: newLayers, otherKindID: newLayers},
		configs: map[string]M{cacheImage: withConfig(M{"Env": []string{"PATH=/usr/bin", "A=1"}}),
			otherKindID: withConfig(M{"Env": []string{"A=1", "PATH=/usr/bin"}})}})
	if c["state"] != "current" {
		t.Fatalf("state %v", c["state"])
	}
}

func TestAStoppedStackIsJudgedByItsTag(t *testing.T) {
	stopped := ok("")
	if c, _ := probeCache(t, &cacheDocker{runningID: oldID, layers: map[string][]string{}, ps: &stopped}); c["state"] != "current" {
		t.Fatalf("state %v", c["state"])
	}
}

func TestAPanelStillOnTheOldImageIsOfferedTheNew(t *testing.T) {
	image := "ghcr.io/example/haproxy-admin-ui:alpha"
	d := runnerFunc(func(argv []string) CommandResult {
		switch {
		case hasSuffix(argv, "config", "--images"):
			return ok(image + "\n")
		case hasSuffix(argv, "ps", "-q"):
			return ok(container + "\n")
		case hasPrefix(argv, "docker", "inspect"):
			return ok(mustJSON(image) + " " + mustJSON(oldID) + "\n")
		case hasPrefix(argv, "docker", "image", "inspect") && last(argv) == contentFormat:
			if argv[3] == image {
				return imageContentAnswer(newLayers, nil)
			}
			return imageContentAnswer(oldLayers, nil)
		case hasPrefix(argv, "docker", "image", "inspect") && last(argv) == "{{json .RepoDigests}}":
			return ok(`["ghcr.io/example/haproxy-admin-ui@` + cacheDigest + `"]` + "\n")
		case hasPrefix(argv, "docker", "buildx", "imagetools"):
			return ok("Name: " + image + "\nDigest: " + cacheDigest + "\n")
		}
		return failed(1, "not asked")
	})
	c := probeAdminCompose(composeFile(t), d, adminOptions{configuredImage: image, configuredChannel: "alpha", targetChannel: "alpha"})
	if c["state"] != "available" || firstImage(c)["reason"] != "running-older-image" {
		t.Fatalf("panel: %v", c)
	}
}

// Host updates pair with the running panel, even after a download moved its tag.

const pairingImage = "example/panel:latest"

var (
	pairingRunning = "sha256:" + strings.Repeat("1", 64)
	pairingDigest  = "sha256:" + strings.Repeat("2", 64)
	treeOld        = strings.Repeat("a", 64)
	treeNew        = strings.Repeat("b", 64)
)

type pairingDocker struct {
	runningTree    string
	registryDigest string
	stopped        bool
	mixedReplicas  bool
}

func newPairingDocker() *pairingDocker {
	return &pairingDocker{runningTree: treeOld, registryDigest: pairingDigest}
}

func (d *pairingDocker) Run(argv []string, _ time.Duration) CommandResult {
	switch {
	case hasSuffix(argv, "config", "--images"):
		return ok(pairingImage + "\n")
	case hasSuffix(argv, "ps", "-q"):
		if d.stopped {
			return ok("")
		}
		return ok(container + "\n")
	case hasPrefix(argv, "docker", "inspect"):
		if d.mixedReplicas {
			return ok(mustJSON(pairingImage) + " " + mustJSON(pairingDigest) + "\n" +
				mustJSON("example/panel@"+pairingDigest) + " " + mustJSON(pairingRunning) + "\n")
		}
		return ok(mustJSON(pairingImage) + " " + mustJSON(pairingRunning) + "\n")
	case hasPrefix(argv, "docker", "buildx", "imagetools"):
		if last(argv) == "{{json .Image}}" {
			return ok(mustJSON(M{"config": M{"Labels": M{webTreeLabelName: treeNew}}}))
		}
		return ok("Digest: " + d.registryDigest)
	case hasPrefix(argv, "docker", "image", "inspect"):
		switch last(argv) {
		case "{{json .RepoDigests}}":
			return ok(mustJSON([]string{"example/panel@" + pairingDigest}))
		case "{{json .Config.Labels}}":
			tree := treeNew
			if argv[3] == pairingRunning {
				tree = d.runningTree
			}
			if tree == "" {
				return ok("{}")
			}
			return ok(mustJSON(M{webTreeLabelName: tree}))
		case contentFormat:
			layer := treeNew
			if argv[3] == pairingRunning {
				layer = or(d.runningTree, treeOld)
			}
			return ok(mustJSON([]string{"sha256:" + layer}) + "\t{}")
		}
	}
	return failed(1, "unexpected probe")
}

func probePairing(t *testing.T, d Runner) M {
	return probeAdminCompose(composeFile(t), d, adminOptions{configuredImage: pairingImage, configuredChannel: "latest",
		targetChannel: "latest"})
}

func TestADownloadedNewTagDoesNotReplaceTheRunningFingerprint(t *testing.T) {
	panel := probePairing(t, newPairingDocker())
	if panel["state"] != "available" || firstImage(panel)["current_source_tree"] != treeOld {
		t.Fatalf("panel: %v", panel)
	}
}

func TestAHostUpdateStillRequiresRecreatingTheOldPanel(t *testing.T) {
	panel := probePairing(t, newPairingDocker())
	source := M{"id": "all", "state": "available", "actionable": true, "details": M{"scope": M{"ready": true}}}
	linkWebApplication([]M{source, panel}, treeNew, false)
	requires := details(source)["scope"].(M)["requires"]
	if !reflect.DeepEqual(requires, []any{[]any{"admin-container"}}) {
		t.Fatalf("requires %v", requires)
	}
}

func TestTheRunningFingerprintIsReadEvenIfTheRegistryHasAnotherUpdate(t *testing.T) {
	d := newPairingDocker()
	d.registryDigest = "sha256:" + strings.Repeat("3", 64)
	panel := probePairing(t, d)
	if firstImage(panel)["current_source_tree"] != treeOld {
		t.Fatalf("panel: %v", panel)
	}
	// A new registry release does not hide an old running container.
	if panel["state"] != "available" || firstImage(panel)["running"] != "different-content" {
		t.Fatalf("panel: %v", panel)
	}
}

func TestARunningImageWithoutALabelIsNotTheDownloadedImage(t *testing.T) {
	d := newPairingDocker()
	d.runningTree = ""
	if tree := firstImage(probePairing(t, d))["current_source_tree"]; tree != nil {
		t.Fatalf("tree %v", tree)
	}
}

func TestAStoppedPanelUsesItsInstalledTag(t *testing.T) {
	d := newPairingDocker()
	d.stopped = true
	if tree := firstImage(probePairing(t, d))["current_source_tree"]; tree != treeNew {
		t.Fatalf("tree %v", tree)
	}
}

func TestUnreadableRunningInventoryNeverFallsBackToATag(t *testing.T) {
	asked := false
	tree := runningWebTree(pairingImage, nil, false, runnerFunc(func([]string) CommandResult { asked = true; return ok("") }))
	if tree != "" || asked {
		t.Fatalf("tree %q asked %v", tree, asked)
	}
}

func TestRunningReplicasMustAgreeOnTheirBuildInputs(t *testing.T) {
	labels := map[string]string{pairingRunning: treeOld, pairingDigest: treeNew}
	d := runnerFunc(func(argv []string) CommandResult { return ok(mustJSON(M{webTreeLabelName: labels[argv[3]]})) })
	if tree := runningWebTree(pairingImage, map[string][]string{pairingImage: {pairingRunning, pairingDigest}}, true, d); tree != "" {
		t.Fatalf("tree %q", tree)
	}
}

func TestTheRunningReferenceCanBePinnedToADigest(t *testing.T) {
	running := map[string][]string{"example/panel@" + pairingDigest: {pairingRunning}}
	if tree := runningWebTree(pairingImage, running, true, newPairingDocker()); tree != treeOld {
		t.Fatalf("tree %q", tree)
	}
	detail := M{"state": "current"}
	checkRunning(detail, pairingImage, running, true, newPairingDocker())
	if detail["state"] != "available" || detail["reason"] != "running-older-image" {
		t.Fatalf("detail %v", detail)
	}
}

func TestAnOldReplicaIsNotHiddenByTheNewReference(t *testing.T) {
	d := newPairingDocker()
	d.mixedReplicas = true
	image := firstImage(probePairing(t, d))
	if image["current_source_tree"] != nil || image["running"] != "different-content" {
		t.Fatalf("image %v", image)
	}
}
