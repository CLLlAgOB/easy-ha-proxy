package updated

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/pyx"
)

func (d *Daemon) transientJobsSupported() bool {
	if os.Geteuid() != 0 {
		return false
	}
	if fi, err := os.Stat("/run/systemd/system"); err != nil || !fi.IsDir() {
		return false
	}
	fi, err := os.Stat(systemdRunPath)
	return err == nil && fi.Mode()&0o111 != 0
}

func (d *Daemon) systemctlProperties(unit string, names []string) map[string]string {
	args := []string{systemctlPath, "show", unit}
	for _, n := range names {
		args = append(args, "--property="+n)
	}
	_, out, _, _ := d.commandRunner(30*time.Second, nil, args...)
	props := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			props[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return props
}

func (d *Daemon) stopTransientUnit(unit string) {
	for _, args := range [][]string{{systemctlPath, "stop", unit}, {systemctlPath, "reset-failed", unit}} {
		if _, _, _, err := d.commandRunner((transientStopTimeout+15)*time.Second, nil, args...); err != nil {
			log.Printf("Could not clean up transient unit %s", unit)
		}
	}
}

// agentBinary is the installed agent: the transient jobs run its tools.
var agentBinary = "/usr/local/sbin/easy-ha-proxy-agent"

func (d *Daemon) python() string {
	if isRegular(d.Opts.PythonPath) {
		return d.Opts.PythonPath
	}
	return "/usr/bin/python3"
}

func (d *Daemon) runTransientCommand(jobID string, argv []string, timeout int, logPrefix string) (int, string, error) {
	unit := "easy-ha-proxy-updated-job-" + pyx.RandomHex(6) + ".service"
	outputPath := filepath.Join(d.Opts.JobsDir(), "."+jobID+".output")
	f, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|pyx.NoFollow, 0o600)
	if err != nil {
		return 0, "", err
	}
	if logPrefix != "" {
		_, _ = f.WriteString(logPrefix + "\n")
	}
	_ = f.Close()
	command := []string{systemdRunPath, "--quiet", "--no-block", "--unit", unit, "--service-type=oneshot",
		"-p", "RemainAfterExit=yes", "-p", "StandardOutput=append:" + outputPath, "-p", "StandardError=inherit",
		"-p", "KillMode=control-group", "-p", fmt.Sprintf("TimeoutStopSec=%d", transientStopTimeout)}
	if len(argv) > 1 && argv[0] == agentBinary && argv[1] == "apt-metadata" {
		command = append(command, "-p", "CPUQuota=100%", "-p", "MemoryMax=512M")
	}
	for _, kv := range childEnvironment() {
		command = append(command, "--setenv="+kv)
	}
	command = append(command, "--")
	command = append(command, argv...)
	rc, _, stderr, err := d.commandRunner(60*time.Second, nil, command...)
	if err != nil {
		_ = os.Remove(outputPath)
		return 0, "", uErr("invalid", "could not start the privileged update job: %v", err)
	}
	if rc != 0 {
		_ = os.Remove(outputPath)
		msg := "could not start the privileged update job"
		if detail := strings.TrimSpace(stderr); detail != "" {
			msg += ": " + detail
		}
		return 0, "", uErr("invalid", "%s", msg)
	}
	begun := time.Now()
	var lastPublish time.Time
	timedOut := false
	defer func() {
		d.stopTransientUnit(unit)
		if timedOut {
			_, _ = d.updateJob(jobID, map[string]any{"output": map[string]any{"log": d.readFileTail(outputPath)}})
		}
		_ = os.Remove(outputPath)
	}()
	for {
		props := d.systemctlProperties(unit, []string{"LoadState", "ActiveState", "SubState", "ExecMainStatus"})
		active := props["ActiveState"]
		if props["LoadState"] == "not-found" {
			return 0, d.readFileTail(outputPath), nil
		}
		if active == "failed" {
			code, err := strconv.Atoi(props["ExecMainStatus"])
			if err != nil || code == 0 {
				code = 1
			}
			return code, d.readFileTail(outputPath), nil
		}
		if active == "active" && props["SubState"] == "exited" {
			code, err := strconv.Atoi(props["ExecMainStatus"])
			if err != nil {
				code = 0
			}
			return code, d.readFileTail(outputPath), nil
		}
		if time.Since(begun) > time.Duration(timeout)*time.Second {
			timedOut = true
			return 0, "", uErr("invalid", "update command exceeded its timeout")
		}
		if time.Since(lastPublish) >= 2*time.Second {
			d.publishOutput(jobID, d.readFileTail(outputPath))
			lastPublish = time.Now()
		}
		d.sleep(500 * time.Millisecond)
	}
}

func (d *Daemon) publishOutput(jobID, logText string) {
	updates := map[string]any{"output": map[string]any{"log": logText}}
	if progress := parseProgress(logText); progress != nil {
		updates["progress"] = progress
	}
	_, _ = d.updateJob(jobID, updates)
}

func (d *Daemon) runCommand(jobID string, argv []string, timeout int, logPrefix string) (int, string, error) {
	if d.transient() {
		return d.runTransientCommand(jobID, argv, timeout, logPrefix)
	}
	return d.runDirectCommand(jobID, argv, timeout, logPrefix)
}

func (d *Daemon) runDirectCommand(jobID string, argv []string, timeout int, logPrefix string) (int, string, error) {
	out, err := os.CreateTemp("", "updated-out-")
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = out.Close(); _ = os.Remove(out.Name()) }()
	if logPrefix != "" {
		_, _ = out.WriteString(logPrefix + "\n")
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdout, cmd.Stderr = out, out
	cmd.Env = childEnvironment()
	cmd.SysProcAttr = pyx.SessionAttr()
	if err := cmd.Start(); err != nil {
		return 0, "", err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	started := time.Now()
	var lastPublish time.Time
	finished := func(werr error) (int, string, error) {
		code := 0
		var ee *exec.ExitError
		if errors.As(werr, &ee) {
			code = ee.ExitCode()
			if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
				code = -int(ws.Signal())
			}
		}
		return code, d.readFileTail(out.Name()), nil
	}
	first := true
	for {
		// poll() first, then publish, then sleep -- the order run_direct_command uses.
		if !first {
			select {
			case werr := <-done:
				return finished(werr)
			case <-time.After(250 * time.Millisecond):
			}
		}
		select {
		case werr := <-done:
			return finished(werr)
		default:
		}
		first = false
		if time.Since(started) > time.Duration(timeout)*time.Second {
			pyx.KillGroup(cmd.Process.Pid, syscall.SIGTERM)
			select {
			case <-done:
			case <-time.After(20 * time.Second):
				pyx.KillGroup(cmd.Process.Pid, syscall.SIGKILL)
				<-done
			}
			return 0, "", uErr("invalid", "update command exceeded its timeout")
		}
		if time.Since(lastPublish) >= 2*time.Second {
			d.publishOutput(jobID, d.readFileTail(out.Name()))
			lastPublish = time.Now()
		}
	}
}

func (d *Daemon) checkerCommand(imageChannel, sourceChannel, branch string) ([]string, error) {
	// The installed agent is the checker ("update-plan"); it always reports
	// the HAProxy component.
	if !isRegular(agentBinary) {
		return nil, uErr("not_found", "the structured update checker is unavailable; run one controller update first")
	}
	command := []string{agentBinary, "update-plan", "--format", "json", "--haproxy-status"}
	if imageChannel != "" {
		command = append(command, "--image-channel", imageChannel)
	}
	if sourceChannel != "" {
		command = append(command, "--source-channel", sourceChannel)
	}
	if branch != "" {
		command = append(command, "--branch", branch)
	}
	return command, nil
}

func parseCheckerOutput(raw string) (map[string]any, error) {
	start := strings.Index(raw, "{")
	if start < 0 {
		return nil, uErr("invalid", "the update checker returned an empty response")
	}
	v, err := pyx.Decode([]byte(raw[start:]))
	if err != nil {
		return nil, uErr("invalid", "the update checker returned invalid JSON")
	}
	payload := pyx.Map(v)
	if payload == nil {
		return nil, uErr("invalid", "the update checker returned an invalid plan")
	}
	components, ok := payload["components"].([]any)
	if !ok {
		return nil, uErr("invalid", "the update checker returned an invalid plan")
	}
	seen := map[string]bool{}
	for _, c := range components {
		comp := pyx.Map(c)
		if comp == nil {
			return nil, uErr("invalid", "the update checker returned an invalid component")
		}
		id, _ := comp["id"].(string)
		if !allowedComponents[id] || id == changesComponent || seen[id] {
			return nil, uErr("invalid", "the update checker returned an unsupported component")
		}
		seen[id] = true
		switch comp["state"] {
		case "available", "current", "unknown", "blocked":
		default:
			return nil, uErr("invalid", "the update checker returned an invalid component state")
		}
	}
	if s, _ := payload["source_channel"].(string); !sourceChannels[s] {
		return nil, uErr("invalid", "the update checker returned an invalid source channel")
	}
	if s, _ := payload["image_channel"].(string); !imageChannels[s] {
		return nil, uErr("invalid", "the update checker returned an invalid image channel")
	}
	return payload, nil
}

func (d *Daemon) trustedSource(filename string) (string, error) {
	path := filepath.Join(d.Opts.SourceDir, "installer", filename)
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return "", uErr("invalid", "Update the host services before using controlled HAProxy updates")
	}
	return path, nil
}

func (d *Daemon) refreshAptMetadata(jobID string) (retErr error) {
	// The agent's tool does it; without the installed agent there is nothing
	// to run it with (a host still being installed).
	if !isRegular(agentBinary) {
		return nil
	}
	defer func() {
		if retErr != nil {
			_ = os.Remove(d.Opts.LatestPlanPath())
		}
	}()
	if d.metadataFree {
		f, err := os.OpenFile(d.Opts.MaintenanceLockPath, os.O_RDWR|os.O_CREATE|pyx.NoFollow, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		if err := pyx.FlockTry(f); err != nil {
			return uErr("busy", "Another maintenance operation is active")
		}
	}
	if _, err := d.updateJob(jobID, map[string]any{"progress": map[string]any{"phase": "checking"}}); err != nil {
		return err
	}
	code, _, err := d.runCommand(jobID, []string{agentBinary, "apt-metadata", "refresh"}, 130,
		"Refreshing signed package metadata without installing packages…")
	if err != nil {
		return err
	}
	if code != 0 {
		return uErr("invalid", "APT metadata refresh helper could not complete")
	}
	return nil
}

func (d *Daemon) executeChecker(jobID, imageChannel, sourceChannel, branch string) (map[string]any, error) {
	if err := d.refreshAptMetadata(jobID); err != nil {
		return nil, err
	}
	command, err := d.checkerCommand(imageChannel, sourceChannel, branch)
	if err != nil {
		return nil, err
	}
	code, output, err := d.runCommand(jobID, command, d.Opts.CheckTimeoutSeconds,
		"Checking Git, managed Docker images, host daemons, and APT cache…")
	if err != nil {
		return nil, err
	}
	if code != 0 {
		msg := "the update checker failed"
		if output != "" {
			lines := strings.Split(output, "\n")
			if strings.HasSuffix(output, "\n") {
				lines = lines[:len(lines)-1]
			}
			if len(lines) > 0 {
				msg += ": " + lines[len(lines)-1]
			}
		}
		return nil, uErr("invalid", "%s", msg)
	}
	return parseCheckerOutput(output)
}

func planDigest(payload map[string]any) string {
	material := map[string]any{"source_channel": payload["source_channel"], "image_channel": payload["image_channel"],
		"components": payload["components"]}
	sum := sha256.Sum256(pyx.Compact(material, true))
	return hex.EncodeToString(sum[:])
}

func (d *Daemon) storePlan(payload map[string]any) (map[string]any, error) {
	now := time.Now().UTC()
	plan := pyx.Copy(payload)
	plan["id"] = pyx.UUIDHex()
	plan["protocol_version"] = protocolVersion
	plan["created_at"] = pyx.ISO(now)
	plan["expires_at"] = pyx.ISO(now.Add(time.Duration(d.Opts.PlanTTLSeconds) * time.Second))
	plan["digest"] = planDigest(plan)
	if err := d.atomicJSON(d.Opts.LatestPlanPath(), plan); err != nil {
		return nil, err
	}
	return plan, nil
}

func (d *Daemon) loadLatestPlan() (map[string]any, error) {
	if !exists(d.Opts.LatestPlanPath()) {
		return nil, nil
	}
	plan, err := d.safeJSONFile(d.Opts.LatestPlanPath())
	if err != nil {
		return nil, err
	}
	if !identifierRe.MatchString(pyx.StrOr(plan["id"])) {
		return nil, uErr("invalid", "the cached update plan is invalid")
	}
	return plan, nil
}

func planIsExpired(plan map[string]any) bool {
	raw, ok := plan["expires_at"]
	if !ok {
		return true
	}
	expires, aware, ok := pyx.ParseISO(pyx.Str(raw))
	if !ok || !aware {
		return true
	}
	return !time.Now().Before(expires)
}

func componentSignature(component map[string]any) string {
	material := map[string]any{}
	for _, key := range []string{"id", "state", "actionable", "installed", "available", "candidate", "count", "details"} {
		material[key] = component[key]
	}
	if details := pyx.Map(material["details"]); details != nil {
		details = pyx.Copy(details)
		if apt := pyx.Map(details["apt"]); apt != nil {
			details["apt"] = map[string]any{"fresh": apt["fresh"], "sources": apt["sources"]}
		}
		delete(details, "last_operation")
		material["details"] = details
	}
	sum := sha256.Sum256(pyx.Compact(material, true))
	return hex.EncodeToString(sum[:])
}

func selectedComponents(value any) ([]string, error) {
	list, ok := value.([]any)
	if !ok || len(list) == 0 || len(list) > len(allowedComponents) {
		return nil, uErr("invalid", "select at least one supported update component")
	}
	result := []string{}
	seen := map[string]bool{}
	for _, item := range list {
		s, ok := item.(string)
		if !ok || !allowedComponents[s] {
			return nil, uErr("invalid", "unsupported update component")
		}
		if seen[s] {
			return nil, uErr("invalid", "duplicate update component")
		}
		seen[s] = true
		result = append(result, s)
	}
	filter := func(drop func(string) bool) {
		kept := []string{}
		for _, s := range result {
			if !drop(s) {
				kept = append(kept, s)
			}
		}
		result = kept
	}
	if seen["all"] {
		filter(func(s string) bool { return (sourceComponents[s] && s != "all") || containerComponents[s] })
	} else if seen[changesComponent] {
		filter(func(s string) bool { return s == "services" || s == "daemons" })
	}
	sort.SliceStable(result, func(i, j int) bool { return componentOrder[result[i]] < componentOrder[result[j]] })
	return result, nil
}

func changesScope(component map[string]any) map[string]any {
	scope := pyx.Map(pyx.Map(component["details"])["scope"])
	if scope == nil || scope["ready"] != true {
		return nil
	}
	tags, ok := scope["tags"].([]any)
	if !ok {
		return nil
	}
	for _, t := range tags {
		if _, ok := t.(string); !ok {
			return nil
		}
	}
	return scope
}

func planSourceComponent(planMap map[string]map[string]any, componentID string) map[string]any {
	if componentID == changesComponent {
		source := planMap["all"]
		if changesScope(source) != nil {
			return source
		}
		return nil
	}
	return planMap[componentID]
}

func componentRequirements(entry map[string]any, componentID string) [][]string {
	details := pyx.Map(entry["details"])
	if details == nil {
		return nil
	}
	var clauses []any
	if componentID == changesComponent {
		clauses, _ = pyx.Map(details["scope"])["requires"].([]any)
	} else {
		clauses, _ = details["requires"].([]any)
	}
	out := [][]string{}
	for _, clause := range clauses {
		items, ok := clause.([]any)
		if !ok {
			continue
		}
		c := []string{}
		for _, it := range items {
			if s, ok := it.(string); ok && allowedComponents[s] {
				c = append(c, s)
			}
		}
		out = append(out, c)
	}
	return out
}

func validateRequirements(planMap map[string]map[string]any, components []string) error {
	satisfied := setOf(components...)
	if satisfied["all"] {
		satisfied["admin-container"] = true
	}
	for _, id := range components {
		for _, clause := range componentRequirements(planSourceComponent(planMap, id), id) {
			if len(clause) == 0 {
				continue
			}
			ok := false
			for _, c := range clause {
				if satisfied[c] {
					ok = true
				}
			}
			if !ok {
				return uErr("dependency", "%s has to be installed together with %s", id, strings.Join(clause, " or "))
			}
		}
	}
	return nil
}

func planComponentMap(plan map[string]any) (map[string]map[string]any, error) {
	components, ok := plan["components"].([]any)
	if !ok {
		return nil, uErr("invalid", "the cached update plan is invalid")
	}
	out := map[string]map[string]any{}
	for _, c := range components {
		if m := pyx.Map(c); m != nil {
			if id, ok := m["id"].(string); ok && allowedComponents[id] {
				out[id] = m
			}
		}
	}
	return out, nil
}

func (d *Daemon) validatePlanChannel(plan map[string]any) error {
	deployment := d.readDeployment()
	plannedSource := pyx.StrOr(plan["source_channel"])
	if plannedSource == "" {
		plannedSource = "github"
	}
	plannedImage := pyx.StrOr(plan["image_channel"])
	if plannedImage == "" {
		plannedImage = "latest"
	}
	get := func(k, def string) string {
		if v, ok := deployment[k]; ok {
			return v
		}
		return def
	}
	mismatch := plannedSource != get("source_channel", "github") || plannedImage != get("image_channel", "latest")
	if !mismatch && plannedSource != "local" && pyx.Truthy(plan["branch"]) {
		mismatch = pyx.Str(plan["branch"]) != get("branch", "main")
	}
	if mismatch {
		return uErr("channel_mismatch", "%s", channelMismatchMessage)
	}
	return nil
}

var configPendingRe = regexp.MustCompile(`(?mi)^configuration_pending:\s*(true|yes|1)\s*$`)

func (d *Daemon) validateSelection(plan map[string]any, components []string) error {
	if err := d.validatePlanChannel(plan); err != nil {
		return err
	}
	available, err := planComponentMap(plan)
	if err != nil {
		return err
	}
	for _, id := range components {
		comp := planSourceComponent(available, id)
		if comp == nil || comp["state"] != "available" || comp["actionable"] != true {
			return uErr("stale_plan", "component is not an actionable update: %s", id)
		}
	}
	if err := validateRequirements(available, components); err != nil {
		return err
	}
	needsMeta := false
	for _, id := range components {
		if sourceComponents[id] || id == "haproxy" {
			needsMeta = true
		}
	}
	if needsMeta {
		raw, err := os.ReadFile(filepath.Join(d.Opts.ConfigDir, "metadata.yml"))
		if err != nil {
			return uErr("conflict", "managed metadata is unavailable")
		}
		if configPendingRe.Match(raw) {
			return uErr("config_pending", "managed configuration is pending; apply or revert it before updating host source")
		}
		if d.haproxyTransactionActive() {
			return uErr("config_pending", "an HAProxy configuration confirmation is active")
		}
	}
	return nil
}

func (d *Daemon) haproxyTransactionActive() bool {
	if lexists(d.Opts.HAProxyTransactionMarker) {
		return true
	}
	if !lexists(d.Opts.HAProxyTransactionState) {
		return false
	}
	state, err := d.safeJSONFile(d.Opts.HAProxyTransactionState)
	if err != nil {
		log.Printf("HAProxy transaction state is unreadable; blocking source update")
		return true
	}
	name, _ := state["state"].(string)
	if haproxyTransactionActive[name] {
		return true
	}
	if haproxyTransactionSettled[name] {
		return false
	}
	log.Printf("HAProxy transaction state is unknown; blocking source update")
	return true
}

func validateFreshCandidates(stored, fresh map[string]any, components []string) error {
	oldMap, err := planComponentMap(stored)
	if err != nil {
		return err
	}
	newMap, err := planComponentMap(fresh)
	if err != nil {
		return err
	}
	for _, id := range components {
		old := planSourceComponent(oldMap, id)
		cur := planSourceComponent(newMap, id)
		if old == nil || cur == nil || cur["state"] != "available" || cur["actionable"] != true ||
			componentSignature(old) != componentSignature(cur) {
			return uErr("stale_plan", "the update candidate changed for %s; check again", id)
		}
	}
	return nil
}

func reviewedSourceRevision(plan map[string]any, components []string) (string, error) {
	any := false
	for _, c := range components {
		if sourceComponents[c] {
			any = true
		}
	}
	if !any || plan["source_channel"] != "github" {
		return "", nil
	}
	m, err := planComponentMap(plan)
	if err != nil {
		return "", err
	}
	candidate := strings.ToLower(strings.TrimSpace(pyx.StrOr(m["all"]["available"])))
	if !sourceRevisionRe.MatchString(candidate) {
		return "", uErr("stale_plan", "the checked source revision is unavailable; check again")
	}
	return candidate, nil
}

func containerComponentsFor(components []string) []string {
	set := map[string]bool{}
	for _, c := range components {
		if c == "all" {
			return []string{"admin-container", "authelia-container"}
		}
		if containerComponents[c] {
			set[c] = true
		}
	}
	out := []string{}
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

func reviewedContainerDigests(plan map[string]any, components []string, current bool) (map[string]string, error) {
	result := map[string]string{}
	m, err := planComponentMap(plan)
	if err != nil {
		return nil, err
	}
	field := "available_digest"
	if current {
		field = "current_digest"
	}
	for _, id := range containerComponentsFor(components) {
		images, ok := pyx.Map(m[id]["details"])["images"].([]any)
		if !ok || len(images) == 0 {
			return nil, uErr("stale_plan", "the checked image digests are unavailable for %s", id)
		}
		for _, it := range images {
			item := pyx.Map(it)
			if item == nil {
				return nil, uErr("stale_plan", "the checked image plan is invalid")
			}
			var image string
			if current {
				image = firstStr(item["current_image"], item["image"])
			} else {
				image = firstStr(item["target_image"], item["image"])
			}
			digest := strings.ToLower(pyx.StrOr(item[field]))
			if image == "" || len([]rune(image)) > 512 || controlRe.MatchString(image) || !imageDigestRe.MatchString(digest) {
				return nil, uErr("stale_plan", "the checked image digest is unavailable for %s", id)
			}
			key := id + "\x00" + image
			if _, dup := result[key]; dup {
				return nil, uErr("stale_plan", "the checked image plan contains duplicates")
			}
			result[key] = digest
		}
	}
	return result, nil
}

func firstStr(values ...any) string {
	for _, v := range values {
		if pyx.Truthy(v) {
			return pyx.Str(v)
		}
	}
	return ""
}

func sameDigests(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func validateReviewedContainerCandidates(stored, fresh map[string]any, components []string) error {
	expected, err := reviewedContainerDigests(stored, components, false)
	if err != nil || len(expected) == 0 {
		return err
	}
	current, err := reviewedContainerDigests(fresh, components, false)
	if err != nil {
		return err
	}
	if !sameDigests(current, expected) {
		return uErr("stale_plan", "a managed image candidate changed after the update check; check again")
	}
	return nil
}

func validateAppliedContainerDigests(stored, applied map[string]any, components []string) error {
	expected, err := reviewedContainerDigests(stored, components, false)
	if err != nil || len(expected) == 0 {
		return err
	}
	actual, err := reviewedContainerDigests(applied, components, true)
	if err != nil {
		return err
	}
	if !sameDigests(actual, expected) {
		return uErr("verification_failed", legacyDigestError)
	}
	return verifyRunningContainers(applied, components)
}

// verifyRunningContainers fails when the check after an update cannot show
// that every selected container runs the image it reports.
func verifyRunningContainers(applied map[string]any, components []string) error {
	m, _ := planComponentMap(applied)
	for _, id := range containerComponentsFor(components) {
		for _, it := range pyx.List(pyx.Map(m[id]["details"])["images"]) {
			image := pyx.Map(it)
			reason, _ := image["reason"].(string)
			running, _ := image["running"].(string)
			if image["state"] == "unknown" || reason == "running-older-image" || reason == "running-unchecked" ||
				reason == "running-image-unreadable" || running == "different-content" || running == "unchecked" ||
				running == "unreadable" || running == "not-running" {
				log.Printf("Installed container verification failed for %s", id)
				return uErr("verification_failed", "The container update could not be verified. Check the running containers and try again.")
			}
		}
	}
	return nil
}

// acquireOperation is acquire_operation over the lock shared with backupd.
func (d *Daemon) acquireOperation(allowScheduledReboot, allowSecurityRecovery bool) (*os.File, error) {
	if d.shuttingDown() {
		return nil, uErr("conflict", "the update broker is shutting down")
	}
	if d.haproxyPatchActive() {
		return nil, uErr("conflict", "An interrupted HAProxy update requires recovery before other maintenance")
	}
	if !allowSecurityRecovery && d.securityRecoveryPending() {
		return nil, uErr("conflict", "Restore system management after the interrupted OS security policy change")
	}
	if !allowScheduledReboot && d.rebootGuardPresent() {
		return nil, uErr("conflict", "a server reboot is scheduled")
	}
	if !d.opMu.TryLock() {
		return nil, uErr("busy", "another maintenance operation is active")
	}
	f, err := os.OpenFile(d.Opts.MaintenanceLockPath, os.O_RDWR|os.O_CREATE|pyx.NoFollow, 0o600)
	if err == nil {
		if err = pyx.FlockTry(f); err != nil {
			_ = f.Close()
		}
	}
	if err != nil {
		d.opMu.Unlock()
		return nil, uErr("busy", "another maintenance operation is active")
	}
	if !allowScheduledReboot && d.rebootGuardPresent() {
		d.releaseOperation(f)
		return nil, uErr("conflict", "a server reboot is scheduled")
	}
	return f, nil
}

func (d *Daemon) releaseOperation(f *os.File) {
	if f != nil {
		pyx.FlockRelease(f)
		_ = f.Close()
	}
	d.opMu.Unlock()
	if d.shuttingDown() {
		d.requestStop()
	}
}

func (d *Daemon) finishFailed(jobID string, err error, logText string, alert bool) {
	currentLog := ""
	if cur, lerr := d.loadJob(jobID, true); lerr == nil {
		if s, ok := pyx.Map(cur["output"])["log"].(string); ok {
			currentLog = d.sanitizeLog(s)
		}
	}
	candidate := d.sanitizeLog(logText)
	if len(currentLog) > len(candidate) {
		candidate = currentLog
	}
	message := err.Error()
	if message == "" {
		message = fmt.Sprintf("%T", err)
	}
	updates := map[string]any{"status": "failed", "completed_at": pyx.UTCNow(), "error": pyx.TruncRunes(message, 4096)}
	if candidate != "" {
		updates["output"] = map[string]any{"log": candidate}
	}
	_, _ = d.updateJob(jobID, updates)
	log.Printf("Update job %s failed: %s", jobID, message)
	if alert {
		d.reportAlert("update.failed", jobID, "A software update job failed", pyx.TruncRunes(message, 1000))
	}
}

func (d *Daemon) runCheck(jobID, imageChannel, sourceChannel, branch string, alertOnFailure bool) bool {
	fail := func(err error) bool {
		d.finishFailed(jobID, err, "", alertOnFailure)
		return false
	}
	if _, err := d.updateJob(jobID, map[string]any{"status": "running", "started_at": pyx.UTCNow(),
		"current_component": "check", "progress": map[string]any{"phase": "checking"}}); err != nil {
		return fail(err)
	}
	payload, err := d.executeChecker(jobID, imageChannel, sourceChannel, branch)
	if err != nil {
		return fail(err)
	}
	plan, err := d.storePlan(payload)
	if err != nil {
		return fail(err)
	}
	count := 0
	for _, it := range pyx.List(plan["components"]) {
		item := pyx.Map(it)
		if item["state"] == "available" && item["actionable"] == true {
			count++
		}
	}
	if _, err := d.updateJob(jobID, map[string]any{"status": "completed", "completed_at": pyx.UTCNow(),
		"current_component": nil, "plan_id": plan["id"],
		"result": map[string]any{"plan_id": plan["id"], "updates_available": count}}); err != nil {
		return fail(err)
	}
	d.reportAvailability(plan)
	return true
}

func (d *Daemon) maintenanceLockBusy() bool {
	f, err := os.OpenFile(d.Opts.MaintenanceLockPath, os.O_RDWR|os.O_CREATE|pyx.NoFollow, 0o600)
	if err != nil {
		return true
	}
	defer f.Close()
	if err := pyx.FlockTry(f); err != nil {
		return true
	}
	pyx.FlockRelease(f)
	return false
}

// autoCheckOnce is one scheduled check; only its APT refresh holds the lock.
func (d *Daemon) autoCheckOnce() string {
	if d.shuttingDown() || d.rebootGuardPresent() || exists(d.Opts.ActiveMarker) || d.haproxyPatchActive() {
		return "busy"
	}
	if !d.opMu.TryLock() {
		return "busy"
	}
	defer func() {
		d.opMu.Unlock()
		if d.shuttingDown() {
			d.requestStop()
		}
	}()
	if d.maintenanceLockBusy() {
		return "busy"
	}
	job, err := d.newJob("check", map[string]any{"scheduled": true})
	if err != nil {
		return "failed"
	}
	d.metadataFree = true
	done := d.runCheck(job["id"].(string), "", "", "", false)
	d.metadataFree = false
	if done {
		return "done"
	}
	return "failed"
}

func (d *Daemon) readSettings() map[string]any {
	if !exists(d.Opts.SettingsPath()) {
		return map[string]any{}
	}
	s, err := d.safeJSONFile(d.Opts.SettingsPath())
	if err != nil {
		log.Printf("Ignoring unreadable update settings settings.json")
		return map[string]any{}
	}
	return s
}

func (d *Daemon) autoCheckHours() int64 {
	v := d.readSettings()["auto_check_hours"]
	if n, ok := pyx.Int(v); ok {
		for _, c := range autoCheckChoices {
			if c == n {
				return n
			}
		}
	}
	return int64(d.Opts.AutoCheckHours)
}

func (d *Daemon) settingsPayload() map[string]any {
	d.autoMu.Lock()
	nextAt := d.autoNextAt
	d.autoMu.Unlock()
	var next any
	if nextAt > 0 {
		next = pyx.ISO(pyx.FromTimestamp(nextAt, time.UTC))
	}
	auto := d.autoInstallSettings()
	if last := d.lastAutoInstall(); last != nil {
		auto["last"] = last
	} else {
		auto["last"] = nil
	}
	return map[string]any{
		"auto_check_hours": d.autoCheckHours(), "default_auto_check_hours": d.Opts.AutoCheckHours,
		"choices": autoCheckChoices, "next_auto_check_at": next, "auto_install": auto,
	}
}
