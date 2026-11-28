package updated

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/pyx"
)

// An upgrade from 1.1.x is applied by the Python broker of 1.1.x. Its check
// reviewed the panel as <repository>:<channel>, the Flask image, but the
// native source installs <repository>:go-<channel>. So after a faithful
// update the Python broker's check failed the job with legacyDigestError,
// and the page showed the upgrade as failed. The first native broker checks
// such a job again and completes it when the only difference is that panel.
//
// Since 1.2.0 the source carries no Python checker (installer/update_plan.py),
// so the Python broker cannot even start that check: it fails the job with
// legacyCheckerMissing instead, after every component was applied. The same
// recheck completes it.

const (
	legacyDigestError    = "an applied image digest differs from the reviewed update plan"
	legacyCheckerMissing = "the structured update checker is unavailable; run one controller update first"
)

// legacyRecheckAttempts and legacyRecheckDelay bound how long the broker
// waits for the maintenance lock before it leaves the job as it is.
const (
	legacyRecheckAttempts = 20
	legacyRecheckDelay    = 30 * time.Second
)

type legacyRecheck struct {
	jobID      string
	plan       map[string]any
	components []string
}

// pendingLegacyRecheck finds the job to check again. It runs at start, before
// a check of this broker can replace the reviewed plan the job applied.
func (d *Daemon) pendingLegacyRecheck() *legacyRecheck {
	var job map[string]any
	for _, candidate := range d.listJobs() {
		if candidate["operation"] == "apply" {
			job = candidate
			break
		}
	}
	if job == nil || job["status"] != "failed" || (job["error"] != legacyDigestError && job["error"] != legacyCheckerMissing) {
		return nil
	}
	jobID := pyx.StrOr(job["id"])
	path, err := d.statePath(jobID)
	if err != nil {
		return nil
	}
	raw, err := d.safeJSONFile(path)
	if err != nil || raw["legacy_recheck"] != nil {
		return nil
	}
	// The Python broker enters this phase after the last component and just
	// before its check; a job that failed earlier applied nothing to verify.
	if job["error"] == legacyCheckerMissing && pyx.StrOr(pyx.Map(raw["progress"])["phase"]) != "rechecking" {
		return nil
	}
	plan, err := d.loadLatestPlan()
	if err != nil || plan == nil || plan["id"] != job["plan_id"] {
		return nil
	}
	components, err := selectedComponents(job["components"])
	if err != nil || len(containerComponentsFor(components)) == 0 {
		return nil
	}
	if _, ok := reviewedLegacyPanel(plan); !ok {
		return nil
	}
	return &legacyRecheck{jobID: jobID, plan: plan, components: components}
}

// reviewedLegacyPanel is the panel image a 1.1.x check reviewed, by its tag.
// Only a 1.1.x planner names the Flask tag; this broker's names go-<channel>.
func reviewedLegacyPanel(plan map[string]any) (string, bool) {
	m, err := planComponentMap(plan)
	if err != nil {
		return "", false
	}
	for _, it := range pyx.List(pyx.Map(m["admin-container"]["details"])["images"]) {
		image := firstStr(pyx.Map(it)["target_image"], pyx.Map(it)["image"])
		if _, ok := nativePanelFor(image); ok {
			return image, true
		}
	}
	return "", false
}

// nativePanelFor maps <repository>:<channel> to <repository>:go-<channel>.
func nativePanelFor(image string) (string, bool) {
	slash := strings.LastIndex(image, "/")
	colon := strings.LastIndex(image, ":")
	if colon <= slash || strings.Contains(image, "@") {
		return "", false
	}
	repository, tag := image[:colon], image[colon+1:]
	if repository == "" || !imageChannels[tag] {
		return "", false
	}
	return repository + ":go-" + tag, true
}

// verifyLegacyApply holds the fresh check to the reviewed plan as the broker's
// own check after an update does, except that the reviewed Flask panel may now
// run as its native image, which this check must report current. It returns
// the reviewed and the installed panel image.
func verifyLegacyApply(stored, fresh map[string]any, components []string) (string, string, error) {
	revision, err := reviewedSourceRevision(stored, components)
	if err != nil {
		return "", "", err
	}
	freshMap, err := planComponentMap(fresh)
	if err != nil {
		return "", "", err
	}
	if revision != "" {
		installed := strings.ToLower(strings.TrimSpace(pyx.StrOr(freshMap["all"]["current_version"])))
		if installed != revision {
			return "", "", fmt.Errorf("the installed source %q is not the reviewed %s", installed, revision)
		}
	}
	expected, err := reviewedContainerDigests(stored, components, false)
	if err != nil {
		return "", "", err
	}
	actual, err := reviewedContainerDigests(fresh, components, true)
	if err != nil {
		return "", "", err
	}
	if len(actual) != len(expected) {
		return "", "", fmt.Errorf("the check reports %d images where the review had %d", len(actual), len(expected))
	}
	reviewedPanel, installedPanel := "", ""
	for key, digest := range expected {
		if actual[key] == digest {
			continue
		}
		component, image, _ := strings.Cut(key, "\x00")
		native, ok := nativePanelFor(image)
		if component != "admin-container" || !ok {
			return "", "", fmt.Errorf("%s now runs a different %s", component, image)
		}
		if _, ok := actual[component+"\x00"+native]; !ok {
			return "", "", fmt.Errorf("the panel runs neither %s nor %s", image, native)
		}
		if freshMap["admin-container"]["state"] != "current" {
			return "", "", fmt.Errorf("the check does not report %s current", native)
		}
		reviewedPanel, installedPanel = image, native
	}
	if reviewedPanel == "" {
		return "", "", fmt.Errorf("the reviewed panel image is still what runs")
	}
	if err := verifyRunningContainers(fresh, components); err != nil {
		return "", "", err
	}
	return reviewedPanel, installedPanel, nil
}

// runLegacyRecheck runs one check of this broker and completes the job when
// it verifies; otherwise it leaves the job failed and records why, once.
func (d *Daemon) runLegacyRecheck(pending *legacyRecheck) {
	for attempt := 1; ; attempt++ {
		lock, err := d.acquireOperation(false, false)
		if err == nil {
			defer d.releaseOperation(lock)
			break
		}
		if d.shuttingDown() || attempt >= legacyRecheckAttempts {
			log.Printf("Update job %s was not checked again: %v", pending.jobID, err)
			return
		}
		d.sleep(legacyRecheckDelay)
	}
	note := func(text string) {
		log.Printf("Update job %s: %s", pending.jobID, text)
		_, _ = d.updateJob(pending.jobID, map[string]any{"legacy_recheck": pyx.TruncRunes(text, 1000)})
	}
	check, err := d.newJob("check", map[string]any{"scheduled": true})
	if err != nil {
		note("not checked again: " + err.Error())
		return
	}
	if !d.runCheck(check["id"].(string), pyx.StrOr(pending.plan["image_channel"]),
		pyx.StrOr(pending.plan["source_channel"]), pyx.StrOr(pending.plan["branch"]), false) {
		note("not verified: the check after the upgrade failed")
		return
	}
	fresh, err := d.loadLatestPlan()
	if err != nil || fresh == nil {
		note("not verified: the check left no plan")
		return
	}
	reviewed, installed, err := verifyLegacyApply(pending.plan, fresh, pending.components)
	if err != nil {
		note("not verified: " + err.Error())
		return
	}
	job, err := d.loadJob(pending.jobID, true)
	if err != nil {
		note("not verified: " + err.Error())
		return
	}
	logText := pyx.StrOr(pyx.Map(job["output"])["log"])
	logText = d.sanitizeLog(logText + "\n" + fmt.Sprintf(
		"The native update broker checked this update again: the panel runs %s in place of the reviewed %s, "+
			"which the new version installs, and everything else matches the review.\n", installed, reviewed))
	components := make([]any, 0, len(pending.components))
	for _, c := range pending.components {
		components = append(components, c)
	}
	if _, err := d.updateJob(pending.jobID, map[string]any{
		"status": "completed", "error": nil, "legacy_recheck": "verified",
		"output": map[string]any{"log": logText},
		"result": map[string]any{
			"components": components, "reboot_required": exists(d.Opts.RebootRequiredPath),
			"refreshed_plan_id": fresh["id"],
		},
	}); err != nil {
		log.Printf("Update job %s was verified but could not be updated: %v", pending.jobID, err)
		return
	}
	log.Printf("Update job %s verified after the upgrade: %s runs in place of %s", pending.jobID, installed, reviewed)
}
