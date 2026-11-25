package updated

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	legacyRevision = "d9c281516be4cf3ccf32bce5d36c6f694432e80f"
	flaskPanel     = "clllagob/haproxy-admin-ui:alpha"
	nativePanel    = "clllagob/haproxy-admin-ui:go-alpha"
)

func digestOf(c string) string { return "sha256:" + strings.Repeat(c, 64) }

// reviewedByPython is the plan a 1.1.x broker applied: the Flask panel tag.
func reviewedByPython() map[string]any {
	return map[string]any{
		"id": "b79175e9fdcd4767baf058e344cce87b", "source_channel": "github", "image_channel": "alpha", "branch": "alpha",
		"components": []any{
			map[string]any{"id": "all", "state": "available", "actionable": true, "available": legacyRevision,
				"current_version": "c31020b1c26b704a35d0cc535a1fb3a1e46fe123"},
			map[string]any{"id": "admin-container", "state": "available", "details": map[string]any{"images": []any{
				map[string]any{"image": "clllagob/haproxy-admin-ui:latest", "target_image": flaskPanel,
					"available_digest": digestOf("a"), "current_digest": digestOf("0")}}}},
			map[string]any{"id": "authelia-container", "state": "available", "details": map[string]any{"images": []any{
				map[string]any{"image": "authelia/authelia:4.39.28", "available_digest": digestOf("b"), "current_digest": digestOf("b")},
				map[string]any{"image": "redis:8.10.3-alpine", "target_image": "redis:8.12.0-alpine",
					"available_digest": digestOf("c"), "current_digest": digestOf("1")}}}},
		},
	}
}

// checkedAfterUpgrade is what this broker's check reports once the update ran.
func checkedAfterUpgrade() map[string]any {
	return map[string]any{
		"source_channel": "github", "image_channel": "alpha", "branch": "alpha",
		"components": []any{
			map[string]any{"id": "all", "state": "current", "current_version": legacyRevision},
			map[string]any{"id": "admin-container", "state": "current", "details": map[string]any{"images": []any{
				map[string]any{"current_image": nativePanel, "current_digest": digestOf("d"), "state": "current"}}}},
			map[string]any{"id": "authelia-container", "state": "current", "details": map[string]any{"images": []any{
				map[string]any{"current_image": "authelia/authelia:4.39.28", "current_digest": digestOf("b"), "state": "current"},
				map[string]any{"current_image": "redis:8.12.0-alpine", "current_digest": digestOf("c"), "state": "current"}}}},
		},
	}
}

func component(plan map[string]any, id string) map[string]any {
	for _, it := range plan["components"].([]any) {
		if c := it.(map[string]any); c["id"] == id {
			return c
		}
	}
	return nil
}

func firstImage(plan map[string]any, id string) map[string]any {
	return component(plan, id)["details"].(map[string]any)["images"].([]any)[0].(map[string]any)
}

// legacyFixture leaves what a 1.1.x broker leaves behind its failed check, and
// a stand-in for the installed planner that prints fresh.
func legacyFixture(t *testing.T, stored, fresh, jobValues map[string]any) (*Daemon, string) {
	t.Helper()
	d := newTestDaemon(t)
	if err := d.atomicJSON(d.Opts.LatestPlanPath(), stored); err != nil {
		t.Fatal(err)
	}
	values := map[string]any{"components": []any{"all"}, "plan_id": stored["id"], "status": "failed",
		"error": legacyDigestError, "output": map[string]any{"log": "PLAY RECAP failed=0\n"}}
	for k, v := range jobValues {
		values[k] = v
	}
	job, err := d.newJob("apply", values)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(fresh)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	planFile := filepath.Join(root, "fresh.json")
	checker := filepath.Join(root, "checker")
	if err := os.WriteFile(planFile, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(checker, []byte("#!/bin/sh\ncat '"+planFile+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d.Opts.SourceDir, "installer", "update_plan.py"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	d.Opts.PythonPath = checker
	return d, job["id"].(string)
}

func rawJob(t *testing.T, d *Daemon, id string) map[string]any {
	t.Helper()
	path, _ := d.statePath(id)
	raw, err := d.safeJSONFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestLegacyApplyIsCompletedOnceVerified(t *testing.T) {
	d, id := legacyFixture(t, reviewedByPython(), checkedAfterUpgrade(), nil)
	pending := d.pendingLegacyRecheck()
	if pending == nil || pending.jobID != id {
		t.Fatalf("the job the Python broker failed was not picked up: %+v", pending)
	}
	d.runLegacyRecheck(pending)

	job, err := d.loadJob(id, true)
	if err != nil {
		t.Fatal(err)
	}
	if job["status"] != "completed" || job["error"] != nil {
		t.Fatalf("job not completed: %v %v", job["status"], job["error"])
	}
	logText := job["output"].(map[string]any)["log"].(string)
	if !strings.HasPrefix(logText, "PLAY RECAP") || !strings.Contains(logText, nativePanel+" in place of the reviewed "+flaskPanel) {
		t.Fatalf("log does not keep the run and explain the check: %q", logText)
	}
	result := job["result"].(map[string]any)
	if result["refreshed_plan_id"] == nil || len(result["components"].([]any)) != 1 {
		t.Fatalf("result: %v", result)
	}
	if rawJob(t, d, id)["legacy_recheck"] != "verified" {
		t.Fatalf("marker: %v", rawJob(t, d, id)["legacy_recheck"])
	}
	checks := 0
	for _, j := range d.listJobs() {
		if j["operation"] == "check" && j["status"] == "completed" {
			checks++
		}
	}
	if checks != 1 {
		t.Fatalf("expected the one check that verified it, got %d", checks)
	}
	if d.pendingLegacyRecheck() != nil {
		t.Fatal("a verified job is checked again")
	}
}

func TestLegacyApplyStaysFailedWhenMoreThanThePanelDiffers(t *testing.T) {
	cases := map[string]func(fresh map[string]any){
		"redis digest": func(f map[string]any) {
			component(f, "authelia-container")["details"].(map[string]any)["images"].([]any)[1].(map[string]any)["current_digest"] = digestOf("e")
		},
		"panel not paired": func(f map[string]any) { component(f, "admin-container")["state"] = "available" },
		"another source":   func(f map[string]any) { component(f, "all")["current_version"] = strings.Repeat("f", 40) },
		"other panel": func(f map[string]any) {
			firstImage(f, "admin-container")["current_image"] = "clllagob/haproxy-admin-ui:go-latest"
		},
		"old panel runs": func(f map[string]any) { firstImage(f, "admin-container")["running"] = "different-content" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			fresh := checkedAfterUpgrade()
			change(fresh)
			d, id := legacyFixture(t, reviewedByPython(), fresh, nil)
			pending := d.pendingLegacyRecheck()
			if pending == nil {
				t.Fatal("not picked up")
			}
			d.runLegacyRecheck(pending)
			job, _ := d.loadJob(id, false)
			if job["status"] != "failed" || job["error"] != legacyDigestError {
				t.Fatalf("job changed: %v %v", job["status"], job["error"])
			}
			marker, _ := rawJob(t, d, id)["legacy_recheck"].(string)
			if !strings.HasPrefix(marker, "not verified") {
				t.Fatalf("marker: %q", marker)
			}
			if d.pendingLegacyRecheck() != nil {
				t.Fatal("checked again on the next start")
			}
		})
	}
}

func TestLegacyRecheckOnlyForTheJobAPythonReviewFailed(t *testing.T) {
	cases := map[string]struct {
		stored func(map[string]any)
		job    map[string]any
	}{
		"native review":     {stored: func(p map[string]any) { firstImage(p, "admin-container")["target_image"] = nativePanel }},
		"other error":       {job: map[string]any{"error": "component update failed: all (exit code 2)"}},
		"completed":         {job: map[string]any{"status": "completed", "error": nil}},
		"other plan":        {job: map[string]any{"plan_id": "0123456789abcdef0123456789abcdef"}},
		"no containers":     {job: map[string]any{"components": []any{"services"}}},
		"already looked at": {job: map[string]any{"legacy_recheck": "not verified: earlier"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			stored := reviewedByPython()
			if tc.stored != nil {
				tc.stored(stored)
			}
			d, _ := legacyFixture(t, stored, checkedAfterUpgrade(), tc.job)
			if pending := d.pendingLegacyRecheck(); pending != nil {
				t.Fatalf("picked up: %+v", pending)
			}
		})
	}
}

func TestNativePanelFor(t *testing.T) {
	for image, want := range map[string]string{
		"clllagob/haproxy-admin-ui:alpha":            "clllagob/haproxy-admin-ui:go-alpha",
		"registry.test:5000/team/ui:latest":          "registry.test:5000/team/ui:go-latest",
		"clllagob/haproxy-admin-ui:go-alpha":         "",
		"clllagob/haproxy-admin-ui:1.1.3":            "",
		"registry.test:5000/team/ui":                 "",
		"clllagob/haproxy-admin-ui@" + digestOf("a"): "",
	} {
		got, ok := nativePanelFor(image)
		if (want == "") == ok || got != want {
			t.Errorf("%s -> %q %v, want %q", image, got, ok, want)
		}
	}
}
