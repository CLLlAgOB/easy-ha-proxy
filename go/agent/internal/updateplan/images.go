package updateplan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	webTreeLabelName   = "io.easy-ha-proxy.source-tree"
	goWebTreeLabelName = "io.easy-ha-proxy.go-panel-tree"
	autheliaDefaults   = "ansible/roles/authelia/defaults/main.yml"
)

// The images the Authelia role renders into its Compose file, by the role
// variable that pins each one and how that value becomes an image reference.
var autheliaImageVariables = []struct{ variable, prefix string }{
	{"authelia_version", "authelia/authelia:"},
	{"authelia_redis_image", ""},
	{"mail_relay_image", ""},
}

// What a container runs besides its files (R06): the same layers with another
// command, environment or user are another image. Labels are left out: they
// carry build times and revisions, and would make every rebuild look new.
var runtimeConfigKeys = []string{"Entrypoint", "Cmd", "Env", "User", "WorkingDir", "ExposedPorts",
	"Volumes", "StopSignal", "Healthcheck", "Shell"}

// panelFlavours are the tag prefixes of the panel implementations.
var panelFlavours = []string{"go-"}

// splitLines is Python's str.splitlines for the line ends commands print.
func splitLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func hasSpaceOrControl(s string) bool {
	for _, r := range s {
		if unicode.IsSpace(r) || r < 32 {
			return true
		}
	}
	return false
}

func uniqueStrings(items []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			out = append(out, item)
		}
	}
	return out
}

func localDigests(stdout string) []string {
	found := []string{}
	var loaded []any
	if json.Unmarshal([]byte(strings.TrimSpace(stdout)), &loaded) == nil {
		for _, value := range loaded {
			if s, ok := value.(string); ok && strings.Contains(s, "@") {
				if match := digestRe.FindString(strings.ToLower(s)); match != "" {
					found = append(found, match)
				}
			}
		}
	}
	if len(found) == 0 {
		found = digestRe.FindAllString(strings.ToLower(stdout), -1)
	}
	return uniqueStrings(found)
}

// localDigest is the local image's digest, as the registry's when it is one
// of them. One image can carry several digests: when the registry publishes
// a tag again and the image for this platform did not change, a pull adds
// the new index digest beside the old one. The first digest alone still
// named the old index after the pull, so such an update was offered after
// every install and the check after it failed.
func localDigest(stdout, wanted string) string {
	digests := localDigests(stdout)
	if wanted != "" {
		for _, d := range digests {
			if d == wanted {
				return wanted
			}
		}
	}
	if len(digests) > 0 {
		return digests[0]
	}
	return ""
}

func remoteDigest(stdout string) string {
	for _, line := range splitLines(stdout) {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "Digest:" && digestFullRe.MatchString(strings.ToLower(fields[1])) {
			return strings.ToLower(fields[1])
		}
	}
	return ""
}

func imageRepository(image string) string {
	if image == "" || strings.HasPrefix(image, "-") || strings.Contains(image, "://") || hasSpaceOrControl(image) {
		return ""
	}
	withoutDigest, _, _ := strings.Cut(image, "@")
	lastSlash := strings.LastIndex(withoutDigest, "/")
	lastColon := strings.LastIndex(withoutDigest, ":")
	if lastColon > lastSlash {
		return withoutDigest[:lastColon]
	}
	return withoutDigest
}

func taggedImage(image, channel string) string {
	if repository := imageRepository(image); repository != "" {
		return repository + ":" + channel
	}
	return ""
}

func normalizedTaggedImage(image string) string {
	repository := imageRepository(image)
	if repository == "" || strings.Contains(image, "@") {
		return ""
	}
	lastSlash := strings.LastIndex(image, "/")
	lastColon := strings.LastIndex(image, ":")
	tag := "latest"
	if lastColon > lastSlash {
		tag = image[lastColon+1:]
	}
	return repository + ":" + tag
}

// panelFlavour is the tag prefix of the panel flavour a normalised reference runs.
func panelFlavour(reference string) string {
	i := strings.LastIndex(reference, ":")
	if reference == "" || i < 0 {
		return ""
	}
	tag := reference[i+1:]
	for _, flavour := range panelFlavours {
		if strings.HasPrefix(tag, flavour) && validImageChannels[tag[len(flavour):]] {
			return flavour
		}
	}
	return ""
}

func flavoured(reference, flavour string) string {
	if reference == "" || flavour == "" || panelFlavour(reference) == flavour {
		return reference
	}
	i := strings.LastIndex(reference, ":")
	if i < 0 {
		return reference
	}
	return reference[:i] + ":" + flavour + reference[i+1:]
}

func probeImage(image string, runner Runner) M {
	if image == "" || utf8.RuneCountInString(image) > 512 || strings.HasPrefix(image, "-") || hasSpaceOrControl(image) ||
		strings.Contains(image, "://") || strings.Contains(image, "?") || strings.Contains(image, "&") ||
		(strings.Contains(image, "@") && !strings.Contains(image, "@sha256:")) {
		return M{"image": "<invalid>", "state": "unknown", "reason": "invalid-image-reference"}
	}
	if strings.Contains(image, "@sha256:") {
		var digest any
		if d := digestRe.FindString(strings.ToLower(image)); d != "" {
			digest = d
		}
		return M{"image": image, "state": "current", "reason": "digest-pinned", "current_digest": digest, "available_digest": digest}
	}
	if strings.HasPrefix(image, "sha256:") || shortImageIDRe.MatchString(strings.ToLower(image)) {
		return M{"image": image, "state": "unknown", "reason": "non-registry-reference"}
	}
	localResult := runner.Run([]string{"docker", "image", "inspect", image, "--format", "{{json .RepoDigests}}"}, composeTimeout)
	remoteResult := runner.Run([]string{"docker", "buildx", "imagetools", "inspect", image}, registryTimeout)
	remote := ""
	if remoteResult.Returncode == 0 {
		remote = remoteDigest(remoteResult.Stdout)
	}
	local := ""
	if localResult.Returncode == 0 {
		local = localDigest(localResult.Stdout, remote)
	}
	detail := M{"image": image, "current_digest": orNil(local), "available_digest": orNil(remote)}
	repository := imageRepository(image)
	if local == "" && remote != "" && repository != "" {
		// The tag can go missing while the image stays: a container keeps
		// its image alive, but a cleanup tool or a pull of another tag may
		// drop the name it was started under. Asked for by tag, Docker then
		// says "No such image" about an image that is running. Asking for it
		// by content settles it: if what the registry offers is already
		// here, it is current.
		byContent := runner.Run([]string{"docker", "image", "inspect", repository + "@" + remote, "--format",
			"{{json .RepoDigests}}"}, composeTimeout)
		if byContent.Returncode == 0 {
			local = remote
			detail["current_digest"] = local
			detail["reason"] = "local-tag-missing"
		}
	}
	switch {
	case local == "":
		detail["state"], detail["reason"], detail["error"] = "unknown", "local-digest-unavailable", shortError(localResult)
	case remote == "":
		detail["state"], detail["reason"], detail["error"] = "unknown", "registry-digest-unavailable", shortError(remoteResult)
	case local == remote:
		detail["state"] = "current"
	default:
		detail["state"] = "available"
	}
	return detail
}

// orNil is the JSON null for an empty string.
func orNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// sourceImageChanges maps each Authelia image the source update re-pins to
// its new reference. The Compose probe reads the file rendered from the
// installed source, so it cannot see that the candidate pins a newer image;
// the check after the complete update then found a digest the reviewed plan
// never mentioned. A value the operator set in vars.yml wins over either
// default, so it is never a change.
func sourceImageChanges(installedSource, candidateSource string, variables M) map[string]string {
	changes := map[string]string{}
	if candidateSource == "" {
		return changes
	}
	var pins []map[string]string
	for _, root := range []string{installedSource, candidateSource} {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(autheliaDefaults)))
		if err != nil || !utf8.Valid(raw) {
			return map[string]string{}
		}
		pins = append(pins, parseScalarYAML(string(raw)))
	}
	for _, v := range autheliaImageVariables {
		if _, set := variables[v.variable]; set {
			continue
		}
		old, next := pins[0][v.variable], pins[1][v.variable]
		if old != "" && next != "" && old != next {
			changes[v.prefix+old] = v.prefix + next
		}
	}
	return changes
}

// runningImages says what each running container of the stack was started
// from: the image reference it was created with (Config.Image) and the image
// it actually runs (.Image). ok false when either cannot be read; an empty
// mapping when nothing of the stack runs.
func runningImages(composeFile string, runner Runner) (map[string][]string, bool) {
	listed := runner.Run([]string{"docker", "compose", "-f", composeFile, "ps", "-q"}, composeTimeout)
	if listed.Returncode != 0 {
		return nil, false
	}
	containers := []string{}
	for _, line := range splitLines(listed.Stdout) {
		if line = strings.TrimSpace(line); containerIDRe.MatchString(line) {
			containers = append(containers, line)
		}
	}
	if len(containers) == 0 {
		return map[string][]string{}, true
	}
	sort.Strings(containers)
	argv := append([]string{"docker", "inspect", "--format", "{{json .Config.Image}} {{json .Image}}"}, containers...)
	inspected := runner.Run(argv, composeTimeout)
	if inspected.Returncode != 0 {
		return nil, false
	}
	running := map[string][]string{}
	for _, line := range splitLines(inspected.Stdout) {
		first, second, found := strings.Cut(line, " ")
		if !found {
			return nil, false
		}
		var reference, imageID any
		if json.Unmarshal([]byte(first), &reference) != nil || json.Unmarshal([]byte(second), &imageID) != nil {
			return nil, false
		}
		ref, ok1 := reference.(string)
		id, ok2 := imageID.(string)
		if !ok1 || !ok2 {
			continue
		}
		ids := running[ref]
		known := false
		for _, existing := range ids {
			known = known || existing == id
		}
		if !known {
			ids = append(ids, id)
		}
		running[ref] = ids
	}
	for ref := range running {
		sort.Strings(running[ref])
	}
	return running, true
}

type imageContents struct {
	layers  []any
	runtime M
}

// imageContent is an image's filesystem layers and the part of its
// configuration a container runs with; nil when either cannot be read.
func imageContent(reference string, runner Runner) *imageContents {
	result := runner.Run([]string{"docker", "image", "inspect", reference, "--format",
		"{{json .RootFS.Layers}}\t{{json .Config}}"}, composeTimeout)
	if result.Returncode != 0 {
		return nil
	}
	rawLayers, rawConfig, found := strings.Cut(strings.TrimSpace(result.Stdout), "\t")
	if !found {
		return nil
	}
	var layers any
	var config any
	if json.Unmarshal([]byte(rawLayers), &layers) != nil || json.Unmarshal([]byte(rawConfig), &config) != nil {
		return nil
	}
	list, ok := layers.([]any)
	if !ok || len(list) == 0 {
		return nil
	}
	settings, isMap := config.(M)
	if config != nil && !isMap {
		return nil
	}
	runtime := M{}
	for _, key := range runtimeConfigKeys {
		value := settings[key]
		if emptyValue(value) {
			continue
		}
		runtime[key] = value
	}
	if env, ok := runtime["Env"].([]any); ok {
		items := make([]string, len(env))
		for i, item := range env {
			items[i] = pyStr(item)
		}
		sort.Strings(items)
		runtime["Env"] = strList(items)
	}
	return &imageContents{list, runtime}
}

// emptyValue is Python's `value in (None, [], {}, "")`.
func emptyValue(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case string:
		return x == ""
	case []any:
		return len(x) == 0
	case M:
		return len(x) == 0
	}
	return false
}

// startedImageIDs resolves the running image even when Compose changed a
// tag to a digest.
func startedImageIDs(tag string, running map[string][]string) []string {
	if ids, ok := running[tag]; ok {
		return ids
	}
	repository := imageRepository(tag)
	set := map[string]bool{}
	for reference, ids := range running {
		if repository != "" && imageRepository(reference) == repository {
			for _, id := range ids {
				set[id] = true
			}
		}
	}
	out := []string{}
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func labelsFromConfig(config any) map[string]string {
	m, ok := config.(M)
	if !ok {
		return map[string]string{}
	}
	var labels any
	if inner, has := m["config"]; has {
		innerMap, _ := inner.(M)
		labels = innerMap["Labels"]
	} else {
		labels = m["Labels"]
	}
	lm, ok := labels.(M)
	if !ok {
		return map[string]string{}
	}
	out := map[string]string{}
	for k, v := range lm {
		out[k] = pyStr(v)
	}
	return out
}

func webTreeLabel(labels map[string]string) string {
	value, ok := labels[goWebTreeLabelName]
	if !ok {
		value = labels[webTreeLabelName]
	}
	value = strings.ToLower(strings.TrimSpace(value))
	if webTreeRe.MatchString(value) {
		return value
	}
	return ""
}

// localWebTree is the label of an image on this host; any failure is unknown.
func localWebTree(image string, runner Runner) (tree string) {
	defer func() {
		if recover() != nil {
			tree = ""
		}
	}()
	r := runner.Run([]string{"docker", "image", "inspect", image, "--format", "{{json .Config.Labels}}"}, composeTimeout)
	if r.Returncode != 0 {
		return ""
	}
	var labels any
	stdout := r.Stdout
	if strings.TrimSpace(stdout) == "" {
		stdout = "null"
	}
	if json.Unmarshal([]byte(stdout), &labels) != nil {
		return ""
	}
	return webTreeLabel(labelsFromConfig(M{"Labels": labels}))
}

// remoteWebTree is the label of a published image; a multi-platform index
// has one config per platform, all built from the same inputs in one command.
func remoteWebTree(image string, runner Runner) (tree string) {
	defer func() {
		if recover() != nil {
			tree = ""
		}
	}()
	r := runner.Run([]string{"docker", "buildx", "imagetools", "inspect", image, "--format", "{{json .Image}}"}, registryTimeout)
	if r.Returncode != 0 {
		return ""
	}
	stdout := r.Stdout
	if strings.TrimSpace(stdout) == "" {
		stdout = "null"
	}
	var data any
	if json.Unmarshal([]byte(stdout), &data) != nil {
		return ""
	}
	if m, ok := data.(M); ok {
		if _, single := m["config"]; !single {
			trees := map[string]bool{}
			for platform, config := range m {
				if !strings.HasPrefix(platform, "unknown/") {
					trees[webTreeLabel(labelsFromConfig(config))] = true
				}
			}
			if len(trees) == 1 {
				for tree := range trees {
					return tree
				}
			}
			return ""
		}
	}
	return webTreeLabel(labelsFromConfig(data))
}

// runningWebTree is the running panel's build inputs, never those of a newly
// downloaded tag. A pull can move the tag while the old container keeps
// running, so its label is read by immutable image ID. A stopped stack is
// judged by its installed tag. Unknown or disagreeing labels stay unknown.
func runningWebTree(image string, running map[string][]string, listed bool, runner Runner) string {
	if !listed {
		return ""
	}
	if len(running) == 0 {
		return localWebTree(image, runner)
	}
	trees := map[string]bool{}
	started := startedImageIDs(image, running)
	for _, id := range started {
		tree := localWebTree(id, runner)
		if tree == "" {
			return ""
		}
		trees[tree] = true
	}
	if len(started) == 0 || len(trees) != 1 {
		return ""
	}
	for tree := range trees {
		return tree
	}
	return ""
}

// checkRunning compares installed image content with what the container
// really runs. A current tag says what a restart would start, not what runs:
// after a pull the tag names the new image while the container keeps the
// old one. Compared by content -- layers and runtime configuration --
// because the IDs come in kinds that do not compare. A stack that cannot be
// listed is unknown, not current (R06). Evidence is recorded for available
// updates too, so a newer registry release cannot hide a failed recreation
// during the post-update check.
func checkRunning(detail M, tag string, running map[string][]string, listed bool, runner Runner) {
	original := detail["state"]
	if (original != "current" && original != "available") || detail["reason"] == "digest-pinned" {
		return
	}
	if !listed {
		detail["running"] = "unchecked"
		if original == "current" {
			detail["state"], detail["reason"] = "unknown", "running-unchecked"
		}
		return
	}
	started := startedImageIDs(tag, running)
	if len(started) == 0 {
		detail["running"] = "not-running"
		return
	}
	wanted := imageContent(tag, runner)
	for _, id := range started {
		var content *imageContents
		if wanted != nil {
			content = imageContent(id, runner)
		}
		if content == nil {
			detail["running"], detail["running_image"] = "unreadable", id
			if original == "current" {
				detail["state"], detail["reason"] = "unknown", "running-image-unreadable"
			}
			return
		}
		if !reflect.DeepEqual(content, wanted) {
			// The tag is current; the container is not on it. Applying the
			// update recreates it on what the tag now names.
			detail["running"], detail["running_image"] = "different-content", id
			if original == "current" {
				detail["state"], detail["reason"] = "available", "running-older-image"
			}
			return
		}
	}
	detail["running"] = "same-content"
}

// probeRetargetedImage probes an image the source update replaces: what
// runs now, what will.
func probeRetargetedImage(image, target string, runner Runner) M {
	current := probeImage(image, runner)
	if current["current_digest"] == nil {
		return current
	}
	candidate := probeImage(target, runner)
	detail := M{"image": image, "target_image": target, "reason": "source-update-changes-image",
		"current_digest": current["current_digest"], "available_digest": candidate["available_digest"]}
	switch {
	case detail["available_digest"] == nil:
		detail["state"], detail["reason"], detail["error"] = "unknown", "registry-digest-unavailable", candidate["error"]
	case detail["available_digest"] == detail["current_digest"]:
		detail["state"] = "current"
	default:
		detail["state"] = "available"
	}
	return detail
}

func composeImages(stdout string) []string {
	lines := []string{}
	for _, line := range splitLines(stdout) {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return uniqueStrings(lines)
}

func probeCompose(componentID, composeFile string, runner Runner, retarget map[string]string) M {
	if !isFile(composeFile) {
		return component(componentID, "blocked", "The managed Docker Compose file is missing.", nil, nil,
			M{"reason": "compose-file-missing", "compose_file": composeFile})
	}
	result := runner.Run([]string{"docker", "compose", "-f", composeFile, "config", "--images"}, composeTimeout)
	if result.Returncode != 0 {
		state := "unknown"
		if result.Error == "not-found" {
			state = "blocked"
		}
		return component(componentID, state, "The managed Docker image list could not be read.", nil, nil,
			M{"reason": "compose-config-failed", "compose_file": composeFile, "error": shortError(result)})
	}
	// Sorted, because the plan is signed. docker compose config --images
	// prints images in no fixed order, so an unsorted list changed the
	// signature of an unchanged component by itself, and applying it failed
	// with "the update candidate changed" at random.
	images := composeImages(result.Stdout)
	sort.Strings(images)
	if len(images) == 0 {
		return component(componentID, "unknown", "The managed Docker Compose file contains no images.", nil, nil,
			M{"reason": "no-compose-images", "compose_file": composeFile})
	}
	results := make([]M, len(images))
	for i, image := range images {
		if target, ok := retarget[image]; ok {
			results[i] = probeRetargetedImage(image, target, runner)
		} else {
			results[i] = probeImage(image, runner)
		}
	}
	running, listed := runningImages(composeFile, runner)
	for i, image := range images {
		if _, ok := retarget[image]; !ok {
			checkRunning(results[i], image, running, listed, runner)
		}
	}
	available, unknown := 0, 0
	list := make([]any, len(results))
	for i, item := range results {
		list[i] = item
		switch item["state"] {
		case "available":
			available++
		case "unknown":
			unknown++
		}
	}
	d := M{"compose_file": composeFile, "images": list}
	if unknown > 0 {
		return component(componentID, "unknown", "One or more managed Docker image versions could not be checked; "+
			"the stack cannot be updated partially.", nil, nil, d)
	}
	if available > 0 {
		return component(componentID, "available", fmt.Sprintf("%d managed Docker image update(s) are available.", available),
			nil, available, d)
	}
	return component(componentID, "current", "All managed Docker images are current or digest-pinned.", len(results), 0, d)
}

type adminOptions struct {
	configuredImage   string
	configuredChannel string
	targetChannel     string
	// targetFlavour is the panel flavour to run; every deployment runs the
	// Go panel ("go-"): a gateway still on the Flask image is moved to it.
	targetFlavour string
	goImage       string
}

func probeAdminCompose(composeFile string, runner Runner, o adminOptions) M {
	if !isFile(composeFile) {
		return component("admin-container", "blocked", "The managed Docker Compose file is missing.", nil, nil,
			M{"reason": "compose-file-missing", "compose_file": composeFile})
	}
	result := runner.Run([]string{"docker", "compose", "-f", composeFile, "config", "--images"}, composeTimeout)
	if result.Returncode != 0 {
		state := "unknown"
		if result.Error == "not-found" {
			state = "blocked"
		}
		return component("admin-container", state, "The managed HAProxy Admin image could not be read.", nil, nil,
			M{"reason": "compose-config-failed", "compose_file": composeFile, "error": shortError(result)})
	}
	images := composeImages(result.Stdout)
	configuredRepository := ""
	if o.configuredImage != "" {
		configuredRepository = imageRepository(o.configuredImage)
	}
	matching := []string{}
	for _, image := range images {
		if configuredRepository != "" && imageRepository(image) == configuredRepository {
			matching = append(matching, image)
		}
	}
	var currentImage string
	switch {
	case len(matching) == 1:
		currentImage = matching[0]
	case len(images) == 1:
		currentImage = images[0]
	default:
		return component("admin-container", "unknown", "The HAProxy Admin image is missing or ambiguous in its Compose file.",
			nil, nil, M{"reason": "admin-image-ambiguous", "compose_file": composeFile, "image_count": len(images)})
	}
	normalizedCurrent := normalizedTaggedImage(currentImage)
	flavour := o.targetFlavour
	explicitGoImage := ""
	if flavour == "go-" {
		explicitGoImage = o.goImage
	}
	baseImage := o.configuredImage
	if baseImage == "" {
		baseImage = defaultAdminImage
	}
	var targetImage string
	if explicitGoImage != "" {
		targetImage = normalizedTaggedImage(explicitGoImage)
	} else {
		targetImage = taggedImage(baseImage, flavour+o.targetChannel)
	}
	if targetImage == "" || normalizedCurrent == "" {
		return component("admin-container", "unknown", "The HAProxy Admin image reference is invalid.", nil, nil,
			M{"reason": "invalid-image-reference", "compose_file": composeFile})
	}
	localResult := runner.Run([]string{"docker", "image", "inspect", currentImage, "--format", "{{json .RepoDigests}}"},
		composeTimeout)
	targetResult := runner.Run([]string{"docker", "buildx", "imagetools", "inspect", targetImage}, registryTimeout)
	candidate := ""
	if targetResult.Returncode == 0 {
		candidate = remoteDigest(targetResult.Stdout)
	}
	local := ""
	if localResult.Returncode == 0 {
		local = localDigest(localResult.Stdout, candidate)
	}
	imageDetail := M{"image": targetImage, "current_image": currentImage, "target_image": targetImage,
		"current_digest": orNil(local), "available_digest": orNil(candidate)}
	d := M{"compose_file": composeFile, "configured_channel": o.configuredChannel, "target_channel": o.targetChannel,
		"images": []any{imageDetail}}
	if local == "" {
		imageDetail["state"], imageDetail["reason"], imageDetail["error"] = "unknown", "local-digest-unavailable",
			shortError(localResult)
		return component("admin-container", "unknown", "The installed HAProxy Admin image digest could not be read.", nil, nil, d)
	}
	if candidate == "" {
		imageDetail["state"], imageDetail["reason"], imageDetail["error"] = "unknown", "registry-digest-unavailable",
			shortError(targetResult)
		return component("admin-container", "unknown", "The requested HAProxy Admin channel could not be verified.", local, nil, d)
	}

	// A downloaded tag may already name the candidate while the container
	// still runs an older panel. Pair with the running image, not the cache.
	running, listed := runningImages(composeFile, runner)
	if listed && len(running) > 0 {
		// A recreation can leave replicas using both a tag and a digest.
		// This component selects one panel repository, so account for every
		// running replica of it, including older reference names.
		repository := imageRepository(currentImage)
		set := map[string]bool{}
		for reference, started := range running {
			if imageRepository(reference) == repository {
				for _, id := range started {
					set[id] = true
				}
			}
		}
		if len(set) > 0 {
			ids := []string{}
			for id := range set {
				ids = append(ids, id)
			}
			sort.Strings(ids)
			running = map[string][]string{currentImage: ids}
		}
	}
	imageDetail["current_source_tree"] = orNil(runningWebTree(currentImage, running, listed, runner))
	imageDetail["available_source_tree"] = orNil(remoteWebTree(imageRepository(targetImage)+"@"+candidate, runner))
	// Running evidence is recorded even when a newer release appeared in the
	// registry: the broker checks the reviewed digest and this evidence after
	// applying, so a newer candidate must neither hide an old container nor
	// fail a correctly installed reviewed image.
	if local == candidate {
		imageDetail["state"] = "current"
	} else {
		imageDetail["state"] = "available"
	}
	checkRunning(imageDetail, currentImage, running, listed, runner)

	configuredReference := targetImage
	if o.configuredImage != "" && explicitGoImage == "" {
		configuredReference = flavoured(normalizedTaggedImage(o.configuredImage), flavour)
	}
	if o.configuredChannel != o.targetChannel || normalizedCurrent != targetImage || configuredReference != targetImage {
		imageDetail["state"], imageDetail["reason"] = "available", "image-channel-change"
		return component("admin-container", "available",
			"The requested HAProxy Admin image channel differs from the deployed channel.",
			currentImage+"@"+local, targetImage+"@"+candidate, d)
	}
	if local != candidate {
		imageDetail["state"] = "available"
		return component("admin-container", "available", "A HAProxy Admin image update is available in the selected channel.",
			local, candidate, d)
	}
	switch imageDetail["state"] {
	case "available":
		return component("admin-container", "available",
			"The HAProxy Admin container still runs an older image than the one downloaded.", local, candidate, d)
	case "unknown":
		return component("admin-container", "unknown", "The image the HAProxy Admin container runs could not be read.",
			local, nil, d)
	}
	return component("admin-container", "current", "The HAProxy Admin image is current in the selected channel.",
		local, candidate, d)
}
