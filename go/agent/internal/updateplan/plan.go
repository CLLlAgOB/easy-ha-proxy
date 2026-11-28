package updateplan

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/tools"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/updatescope"
)

// hostSourceComponents are the components a host-source update moves.
var hostSourceComponents = []string{"all", "services", "daemons"}

func block(c M, reason, summary string) {
	c["state"], c["actionable"], c["summary"] = "blocked", false, summary
	d, _ := c["details"].(M)
	c["details"] = merged(d, M{"reason": reason})
}

func appendRequire(m M, clause []string) {
	list, _ := m["requires"].([]any)
	m["requires"] = append(list, strList(clause))
}

// linkWebApplication makes the host and the web application move together.
//
// The web application talks to the host's daemons and renders HAProxy's
// configuration from the host's template, so the two must come from the
// same source: after an update the running image must have been built from
// the host source's web files.
//
//   - A host update whose source has other web files than the running image
//     needs the web application update with it -- and only works if the
//     published image is that source's build. Until it is published, the
//     host update waits.
//   - A web application update whose image was built from other web files
//     than the running one needs the host source that has them; an image no
//     reachable source has is not offered.
//   - An image rebuilt from the same files goes alone, and so does a host
//     update that leaves the web files as they were.
//
// Without a required fingerprint the two are installed together whenever
// both have updates. targetTree "" is an unknown fingerprint.
func linkWebApplication(components []M, targetTree string, requireFingerprint bool) {
	byID := map[string]M{}
	for _, item := range components {
		byID[str(item["id"])] = item
	}
	source := byID["all"]
	admin := byID["admin-container"]
	var scope M
	if source != nil {
		d, _ := source["details"].(M)
		scope, _ = d["scope"].(M)
	}
	// A gateway without the managed panel stack has no web application to
	// pair with: requiring the panel's fingerprint there would hold every
	// host update back for an image that will never run.
	if admin == nil {
		return
	}
	if d, _ := admin["details"].(M); d["reason"] == "compose-file-missing" {
		return
	}
	hostIDs := []string{}
	for _, id := range hostSourceComponents {
		if c := byID[id]; c != nil && c["state"] == "available" {
			hostIDs = append(hostIDs, id)
		}
	}
	changesOffered := scope != nil && scope["ready"] == true
	hostOffered := len(hostIDs) > 0 || changesOffered
	adminOffered := admin["state"] == "available"
	var running, offered string
	if d, _ := admin["details"].(M); d != nil {
		if images, _ := d["images"].([]any); len(images) > 0 {
			if first, ok := images[0].(M); ok {
				running, _ = first["current_source_tree"].(string)
				offered, _ = first["available_source_tree"].(string)
			}
		}
	}
	sourceMoves := source != nil && source["state"] == "available"

	require := func(id string, clause []string) {
		if id == "changes" {
			appendRequire(scope, clause)
			return
		}
		c := byID[id]
		d, ok := c["details"].(M)
		if !ok {
			d = M{}
			c["details"] = d
		}
		appendRequire(d, clause)
	}

	hostChoices := []string{}
	if changesOffered {
		hostChoices = append(hostChoices, "changes")
	}
	hostChoices = append(hostChoices, hostIDs...)
	exact := requireFingerprint || (targetTree != "" && running != "" && (offered != "" || !adminOffered))

	if !exact {
		// Without labels the two are paired whenever both move.
		if hostOffered && adminOffered {
			for _, id := range hostChoices {
				if id != "all" {
					require(id, []string{"admin-container"})
				}
			}
			require("admin-container", hostChoices)
		}
		return
	}

	hostNeedsWeb := hostOffered && sourceMoves && (targetTree == "" || targetTree != running)
	if hostNeedsWeb {
		if adminOffered && targetTree != "" && offered == targetTree {
			for _, id := range hostChoices {
				// The full stack pulls the image itself.
				if id != "all" {
					require(id, []string{"admin-container"})
				}
			}
		} else {
			message := "This version also changes the web application, and its image is not published yet. " +
				"Check again once it is."
			for _, id := range hostIDs {
				block(byID[id], "web-application-not-published", message)
			}
			if changesOffered {
				scope["ready"] = false
				scope["reason"] = "web-application-not-published"
			}
			hostChoices = []string{}
		}
	}

	if adminOffered && (offered != running || (requireFingerprint && offered == "")) {
		switch {
		case len(hostChoices) > 0 && sourceMoves && targetTree != "" && offered == targetTree:
			require("admin-container", hostChoices)
		case !sourceMoves && targetTree != "" && offered == targetTree:
			// The host already has this image's source: it catches up.
		default:
			block(admin, "web-application-without-source",
				"This web application image was built from a source version this gateway cannot install with it.")
		}
	}
}

// Options are the checker's inputs; the zero value checks this host.
type Options struct {
	SourceDir       string
	ConfigDir       string
	AutheliaCompose string
	AdminCompose    string
	SourceChannel   string
	ImageChannel    string
	Branch          string
	Runner          Runner
	Now             time.Time
	// ArtifactPath maps the host paths the checker reads besides the
	// source; tests only.
	ArtifactPath func(string) string
	// AptRoot is the APT configuration the metadata record was taken for.
	AptRoot string
	// Fetch asks the registry about newer upstream releases; nil stays offline.
	Fetch          Fetcher
	IncludeHAProxy bool
	// Getenv reads EASY_HA_PROXY_BRANCH and EASY_HA_PROXY_REPOSITORY.
	Getenv func(string) string
}

// truthy is Python's truth value of a loaded YAML value.
func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case string:
		return x != ""
	case bool:
		return x
	case int:
		return x != 0
	case int64:
		return x != 0
	case float64:
		return x != 0
	case []any:
		return len(x) > 0
	case M:
		return len(x) > 0
	}
	return true
}

// firstTruthy is Python's `a or b or c` rendered with str().
func firstTruthy(values ...any) string {
	for _, v := range values {
		if truthy(v) {
			return pyStr(v)
		}
	}
	if len(values) == 0 {
		return ""
	}
	return pyStr(values[len(values)-1])
}

func or(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// BuildUpdatePlan returns the JSON-serialisable, read-only update plan.
func BuildUpdatePlan(o Options) (M, error) {
	sourceDir := or(o.SourceDir, DefaultSourceDir)
	configDir := or(o.ConfigDir, DefaultConfigDir)
	autheliaCompose := or(o.AutheliaCompose, DefaultAutheliaCompose)
	adminCompose := or(o.AdminCompose, DefaultAdminCompose)
	runner := o.Runner
	if runner == nil {
		runner = SubprocessRunner{}
	}
	getenv := o.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	mapPath := o.ArtifactPath
	if mapPath == nil {
		mapPath = func(path string) string { return path }
	}

	metadata, metadataError := readMapping(filepath.Join(configDir, "metadata.yml"))
	variables, variablesError := readMapping(filepath.Join(configDir, "vars.yml"))
	configuredImage := ""
	if s, ok := variables["haproxy_admin_image"].(string); ok {
		configuredImage = strings.TrimSpace(s)
	}
	inferredChannel := "latest"
	if configuredImage != "" {
		if reference := normalizedTaggedImage(configuredImage); reference != "" {
			inferredChannel = reference[strings.LastIndex(reference, ":")+1:]
		}
	}
	if !validImageChannels[inferredChannel] {
		inferredChannel = "latest"
	}
	configuredChannel := strings.ToLower(strings.TrimSpace(firstTruthy(metadata["image_channel"], inferredChannel)))
	sourceChannel := strings.ToLower(strings.TrimSpace(firstTruthy(orNil(o.SourceChannel), metadata["source_channel"], "github")))
	imageChannel := strings.ToLower(strings.TrimSpace(firstTruthy(orNil(o.ImageChannel), configuredChannel)))
	branch := strings.TrimSpace(firstTruthy(orNil(o.Branch), metadata["branch"], orNil(getenv("EASY_HA_PROXY_BRANCH")),
		defaultBranch))
	if !validSourceChannels[sourceChannel] {
		return nil, errors.New("source_channel must be github or local")
	}
	if !validImageChannels[imageChannel] {
		return nil, errors.New("image_channel must be latest or alpha")
	}
	if !validBranch(branch) {
		return nil, errors.New("branch contains unsupported characters")
	}
	repository := strings.TrimSpace(firstTruthy(orNil(getenv("EASY_HA_PROXY_REPOSITORY")), metadata["repository"],
		defaultRepository))

	source := probeSource(sourceDir, sourceChannel, branch, repository, runner)
	temporary, err := os.MkdirTemp("", "easy-ha-proxy-update-plan.")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(temporary)

	candidateSource, candidateError := "", ""
	localChanges, _ := source["_local_changes"].([]localChange)
	delete(source, "_local_changes")
	if source["state"] == "available" || (len(localChanges) > 0 && truthy(source["available_version"])) {
		candidateSource, candidateError = remoteCandidate(sourceDir, repository, branch, str(source["available_version"]),
			filepath.Join(temporary, "source"), runner)
	}
	if len(localChanges) > 0 && source["state"] == "blocked" {
		if candidateSource != "" && localChangesUpstream(sourceDir, candidateSource, localChanges) {
			changed, ok := details(source)["changed_files"]
			if !ok {
				changed = []any{}
			}
			// The usual words, so the page translates them; the details say
			// the local changes are already upstream.
			source = component("all", "available", "A different remote managed source revision is available.",
				source["current_version"], source["available_version"],
				M{"branch": branch, "local_changes": "in-candidate", "changed_files": changed})
		} else {
			candidateSource = ""
		}
	}
	comparisonSource := candidateSource
	if comparisonSource == "" {
		comparisonSource = sourceDir
	}
	// Every deployment runs the Go panel: its "go-<channel>" image. The
	// Flask panel is gone; a gateway still running its image is moved.
	const targetFlavour = "go-"
	goImage := ""
	if s, ok := variables["haproxy_admin_go_image"].(string); ok {
		goImage = strings.TrimSpace(s)
	}
	imageChanges := sourceImageChanges(sourceDir, candidateSource, variables)
	freshness := tools.AssessAptMetadata(mapPath(tools.AptMetadataState), or(o.AptRoot, "/etc/apt"), time.Now())
	var haproxy M
	protected := false
	if o.IncludeHAProxy {
		haproxy = probeHAProxy(runner, haproxyPaths{binary: mapPath(haproxyBinary), lastUpdate: mapPath(haproxyLastUpdate),
			lastMigration: mapPath(haproxyLastMigrate), protection: mapPath(haproxyProtection)}, freshness)
		d := details(haproxy)
		protected = d["qualified"] == true && d["protected"] == true
	}
	targetRevision := ""
	if truthy(source["available_version"]) || truthy(source["current_version"]) {
		targetRevision = firstTruthy(source["available_version"], source["current_version"], "")
	}
	var osFreshness M
	if o.IncludeHAProxy {
		osFreshness = freshness
	}
	excluded := map[string]bool{}
	if protected {
		excluded = haproxyPackages
	}
	components := []M{
		source,
		probeServices(source, sourceChannel, sourceDir, candidateSource, candidateError),
		probeDaemons(comparisonSource, daemonOptions{
			artifactPath:            o.ArtifactPath,
			remoteCandidateRequired: source["state"] == "available" && candidateSource == "",
			candidateError:          candidateError,
			installedSource:         sourceDir,
			targetRevision:          targetRevision,
		}),
		probeOS(runner, osFreshness, excluded),
		probeCompose("authelia-container", autheliaCompose, runner, imageChanges),
		probeAdminCompose(adminCompose, runner, adminOptions{
			configuredImage:   configuredImage,
			configuredChannel: configuredChannel,
			targetChannel:     imageChannel,
			targetFlavour:     targetFlavour,
			goImage:           goImage,
		}),
	}
	if o.IncludeHAProxy {
		components = append(components, haproxy)
	}
	if candidateSource != "" && components[0]["state"] == "available" {
		// What a "changes only" update of this candidate would run, measured
		// against the last complete update. Part of the signed details, so
		// the apply-time recheck refuses a scope that moved.
		details(components[0])["scope"] = updatescope.PlanScope(configDir, candidateSource)
		if log := changelog(sourceDir, repository, branch, truthyStr(components[0]["current_version"]),
			truthyStr(components[0]["available_version"]), filepath.Join(temporary, "history"), runner); log != nil {
			details(components[0])["changelog"] = log
		}
	}

	// The host and the web application must come from one source. A moving
	// source is judged by the candidate; a candidate that could not be read
	// leaves the fingerprint unknown, never the old one. The installed tree
	// is only read when an image update needs it.
	adminOffered := components[5]["state"] == "available"
	targetTree := ""
	if components[0]["state"] == "available" {
		if candidateSource != "" {
			targetTree = webTree(candidateSource, runner)
		}
	} else if adminOffered {
		targetTree = webTree(sourceDir, runner)
	}
	linkWebApplication(components, targetTree, true)

	if sourceChannel == "github" && (source["state"] == "blocked" || source["state"] == "unknown") {
		state := str(source["state"])
		reason := "source-unknown"
		if state == "blocked" {
			reason = "source-blocked"
		}
		components[2] = component("daemons", state,
			"Helper daemon updates cannot be trusted until the managed Git source state is resolved.",
			source["current_version"], source["available_version"], M{"reason": reason, "depends_on": "all"})
	}

	authelia := components[4]
	retargeted := M{}
	if images, _ := details(authelia)["images"].([]any); images != nil {
		for _, entry := range images {
			if item, ok := entry.(M); ok && truthy(item["target_image"]) {
				retargeted[pyStr(item["image"])] = pyStr(item["target_image"])
			}
		}
	}
	if len(retargeted) > 0 {
		// Only the complete update brings the source that re-pins these
		// images; the container update on its own keeps the old pins. So
		// the change is listed against the complete update, and the
		// component cannot be applied by itself until then.
		authelia["actionable"] = false
		details(authelia)["depends_on"] = "all"
		details(components[0])["image_changes"] = retargeted
	}

	// The web application check blocks the complete update when it cannot
	// pair the panel with the source. When the candidate could not be read,
	// or an image candidate not verified, that is the actual cause and
	// replaces its generic reason; the update stays blocked either way.
	pairedOnly := func() bool { return details(components[0])["reason"] == "web-application-not-published" }
	if candidateSource == "" && (components[0]["state"] == "available" || pairedOnly()) {
		// Only the candidate says what the complete update installs: which
		// services and daemons it changes, which images it re-pins. Without
		// it the update used to be offered anyway, and the check after it
		// failed on an image the plan had never named. Say it could not be
		// read, and offer nothing to install.
		checked := components[0]
		components[0] = component("all", "blocked",
			"The new version could not be downloaded to compare it with the installed one. Check for updates again.",
			checked["current_version"], checked["available_version"],
			merged(details(checked), M{"reason": "candidate-unavailable", "candidate_error": redact(candidateError)}))
	}
	if components[0]["actionable"] == true || pairedOnly() {
		unavailable := []string{}
		for _, item := range components {
			id := item["id"]
			if (id == "authelia-container" || id == "admin-container") && item["state"] != "current" && item["state"] != "available" {
				unavailable = append(unavailable, str(id))
			}
		}
		if len(unavailable) > 0 {
			checked := components[0]
			components[0] = component("all", "blocked",
				"The complete stack update is blocked until every managed image candidate can be verified.",
				checked["current_version"], checked["available_version"],
				merged(details(checked), M{"reason": "container-candidate-unavailable", "blocked_components": strList(unavailable)}))
		}
	}

	generatedAt := o.Now
	if generatedAt.IsZero() {
		generatedAt = time.Now()
	}
	warnings := []any{}
	for _, message := range []string{metadataError, variablesError} {
		if message != "" {
			warnings = append(warnings, redact(message))
		}
	}
	actionable := []any{}
	list := make([]any, len(components))
	for i, item := range components {
		list[i] = item
		if item["actionable"] == true {
			actionable = append(actionable, item["id"])
		}
	}
	upstream := []any{}
	if o.Fetch != nil {
		upstream = upstreamReleases(components, variables, o.Fetch)
	}
	return M{
		"schema_version": schemaVersion,
		"generated_at":   generatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		"source_channel": sourceChannel,
		"image_channel":  imageChannel,
		// Recorded so applying this plan can be held to the branch it was
		// checked against.
		"branch":                branch,
		"components":            list,
		"has_updates":           len(actionable) > 0,
		"actionable_components": actionable,
		"warnings":              warnings,
		// Newer upstream releases the project has not taken up: information
		// only, outside the components an installation is held to.
		"upstream": upstream,
	}, nil
}
