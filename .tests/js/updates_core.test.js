// Behaviour of the software-updates page's decisions (updates_core.js):
// what is installed together, what a click leaves checked, how far a job is
// and how long it has left. Run with: node --test .tests/js/
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const core = require(path.join(__dirname, "../../docker/app/haproxy_admin/static/js/updates_core.js"));

const PLAN_ID = "0123456789abcdef0123456789ABCDEF";

// The host services cannot go without the web application they were built
// with: the broker says so as a clause, "one of these".
function pairedComponents() {
  return [
    {id: "all", details: {}},
    {id: "services", details: {requires: [["admin-container"]]}},
    {id: "daemons", details: {}},
    {id: "admin-container", details: {}}
  ];
}

function boxes(checked, disabled = []) {
  return ["all", "services", "daemons", "admin-container"].map((id) => ({
    id,
    checked: checked.includes(id),
    disabled: disabled.includes(id)
  }));
}

function ids(set) {
  return Array.from(set).sort();
}

test("checking a component brings what it has to be installed with", () => {
  const result = core.selectionAfterClick(pairedComponents(), boxes(["services"]), "services");
  assert.deepEqual(ids(result.checked), ["admin-container", "services"]);
});

test("unchecking the web application takes along what cannot go without it", () => {
  const result = core.selectionAfterClick(
    pairedComponents(), boxes(["services"]), "admin-container"
  );
  assert.deepEqual(ids(result.checked), []);
});

test("a requirement that cannot be picked unchecks the row instead", () => {
  const result = core.selectionAfterClick(
    pairedComponents(), boxes(["services"], ["admin-container"]), "services"
  );
  assert.deepEqual(ids(result.checked), []);
});

test("the complete update covers the narrower rows and the web application", () => {
  const result = core.selectionAfterClick(
    pairedComponents(), boxes(["all", "services", "admin-container"]), "all"
  );
  assert.deepEqual(ids(result.checked), ["all"]);
  assert.deepEqual(ids(result.superseded), ["admin-container", "daemons", "services"]);
  // A clause naming the web application is met by the complete update.
  assert.equal(core.clauseMet(["admin-container"], new Set(["all"])), true);
  assert.equal(core.clauseMet(["admin-container"], new Set(["daemons"])), false);
});

test("picking a narrower row gives up the complete update", () => {
  const result = core.selectionAfterClick(pairedComponents(), boxes(["all", "daemons"]), "daemons");
  assert.deepEqual(ids(result.checked), ["daemons"]);
  assert.deepEqual(ids(result.superseded), []);
});

test("only what changed replaces services and daemons, not the containers", () => {
  const components = [
    {id: "all"}, {id: "changes", details: {}}, {id: "services"}, {id: "daemons"}, {id: "admin-container"}
  ];
  const rows = ["all", "changes", "services", "daemons", "admin-container"].map((id) => ({
    id, checked: ["all", "services", "admin-container", "changes"].includes(id), disabled: false
  }));
  const result = core.selectionAfterClick(components, rows, "changes");
  assert.deepEqual(ids(result.checked), ["admin-container", "changes"]);
  assert.deepEqual(ids(result.superseded), ["daemons", "services"]);
});

test("a plan's components are read in either shape", () => {
  const fromList = core.normalizeComponents({components: [
    {id: "services", state: "Available", current_version: "a", available_version: "b"},
    {component: "os", status: "current"},
    {id: "daemons", state: "current", update_available: true},
    {name: ""}
  ]});
  assert.deepEqual(fromList.map((item) => [item.id, item.state, item.actionable]), [
    ["services", "available", true],
    ["os", "current", false],
    ["daemons", "current", true]
  ]);
  assert.equal(fromList[0].current, "a");
  assert.equal(fromList[0].available, "b");
  assert.equal(fromList[0].impact, core.COMPONENT_IMPACTS.services);

  const fromObject = core.normalizeComponents({updates: {"admin-container": {state: "outdated", actionable: false}}});
  assert.deepEqual(fromObject.map((item) => [item.id, item.actionable]), [["admin-container", false]]);
  assert.deepEqual(core.normalizeComponents(null), []);
});

test("only what changed is offered next to the complete update when it is ready", () => {
  const scope = {ready: true, changed: 3, steps: ["services"], paths: ["a", "b"], requires: [["admin-container"]]};
  const components = [
    {id: "all", actionable: true, current: "1", available: "2", details: {scope}},
    {id: "services", actionable: true},
    {id: "admin-container", actionable: true}
  ];
  const rows = core.withChangesRow(components);
  assert.deepEqual(rows.map((row) => row.id), ["changes", "all", "admin-container"]);
  assert.equal(rows[0].actionable, true);
  assert.equal(rows[0].details.paths, "a, b");
  assert.deepEqual(rows[0].details.requires, [["admin-container"]]);
  assert.equal(rows[0].reason, "{count} changed file(s). Steps to run: {steps}");

  const blocked = core.withChangesRow([
    {id: "all", actionable: true, details: {scope: {ready: false, reason: "no-applied-record"}}},
    {id: "services", actionable: true}
  ], (text) => `[${text}]`);
  assert.deepEqual(blocked.map((row) => [row.id, row.state]), [
    ["changes", "blocked"], ["all", undefined], ["services", undefined]
  ]);
  assert.match(blocked[0].reason, /^\[Available after the next complete update/);

  assert.equal(core.withChangesRow(components.slice(1)).length, 2);
});

test("a plan is taken only with a well-formed id, from the answer or a job", () => {
  assert.equal(core.extractPlan({plan: {id: PLAN_ID}}).id, PLAN_ID.toLowerCase());
  assert.equal(core.extractPlan({plan: {id: "short"}}), null);
  assert.equal(core.extractPlan({}, [{state: "running"}, {result: {plan: {plan_id: PLAN_ID}}}]).id,
    PLAN_ID.toLowerCase());
  assert.equal(core.planRelease({source_channel: "local", image_channel: "alpha"}), "local");
  assert.equal(core.planRelease({image_channel: "alpha"}), "alpha");
  assert.equal(core.planRelease({}), "stable");
  assert.equal(core.planRelease(null), "");
});

test("values read as short text", () => {
  assert.equal(core.versionText(null), "—");
  assert.equal(core.versionText({display: "v1", version: "1"}), "v1");
  assert.equal(core.versionText({a: 1, b: "x", c: {}}), "a=1, b=x");
  assert.equal(core.versionText(Array.from({length: 14}, (_, i) => i)),
    "0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, … (+2)");
  assert.equal(core.detailsText({changed: 2, empty: "", list: ["a", "b"]}), "changed: 2; list: a, b");
  assert.equal(core.clock(125.9), "2:05");
  assert.equal(core.clock(-3), "0:00");
  assert.equal(core.taskText("guardd : Install script"), "Install script");
  assert.equal(core.taskText("Install script"), "Install script");
});

function finished(component, seconds, startedAt) {
  return {
    id: `job-${component}-${seconds}`, operation: "apply", status: "completed",
    started_at: startedAt, result: {component_seconds: {[component]: seconds}}
  };
}

test("the bar follows the playbook and never runs backwards", () => {
  const highest = {};
  const job = (phase, done, total, index = 0) => ({
    id: "a".repeat(32), operation: "apply", components: ["services", "daemons"],
    component_index: index, progress: {phase, done, total, task: "guardd : Install script"}
  });
  const options = {highest, history: [], now: 0};

  assert.equal(core.progressModel(job("verifying"), options).percent, 2);
  const halfway = core.progressModel(job("playbook", 5, 10), options);
  // 3 + 94 * ((0 + 0.15 + 0.85 * 0.5) / 2)
  assert.equal(halfway.percent, 30);
  assert.equal(halfway.step, "Install script");
  assert.equal(halfway.label, "Installing {component} ({index} of {total})");
  // An older poll arriving late does not move the bar back.
  assert.equal(core.progressModel(job("source", 0, 0), options).percent, 30);
  assert.equal(core.progressModel(job("playbook", 10, 10, 1), options).percent, 97);
  assert.equal(core.progressModel(job("rechecking"), options).percent, 97);

  const check = core.progressModel({operation: "check"}, options);
  assert.deepEqual(check, {percent: null, label: "Checking for updates…", step: "", eta: ""});
});

test("time left comes from the job's own pace, then from earlier installations", () => {
  const now = Date.parse("2026-10-27T10:00:00Z");
  const history = [
    finished("services", 100, "2026-10-26T10:00:00Z"),
    finished("services", 300, "2026-10-25T10:00:00Z"),
    finished("services", 200, "2026-10-24T10:00:00Z"),
    finished("daemons", 60, "2026-10-23T10:00:00Z"),
    {operation: "check", status: "completed", started_at: "2026-10-26T09:00:00Z", completed_at: "2026-10-26T09:00:30Z"}
  ];
  assert.equal(core.typicalSeconds(history, "services"), 200);
  assert.equal(core.typicalSeconds(history, "os"), null);
  assert.equal(core.typicalCheckSeconds(history), 30);
  assert.equal(core.typicalCheckSeconds([]), 45);

  const job = {
    operation: "apply", components: ["services", "daemons"],
    component_started_at: new Date(now - 50 * 1000).toISOString()
  };
  // A quarter done after 50 s: 150 s more of it, then daemons (60) and the check (30).
  assert.equal(core.remainingSeconds(job, 0, "playbook", 0.25, history, now), 240);
  // Before a quarter: history for this one (200 - 50), then the rest.
  assert.equal(core.remainingSeconds(job, 0, "source", 0.03, history, now), 240);
  // Nothing honest to say about a component never installed before.
  assert.equal(core.remainingSeconds({...job, components: ["services", "os"]}, 0, "playbook", 0.5, history, now), null);
  assert.equal(core.remainingSeconds(job, 0, "rechecking", 0.9, history, now), null);

  assert.equal(core.remainingText(240), "about {minutes} min left");
  assert.equal(core.remainingText(59), "less than a minute left");
  assert.equal(core.remainingText(null), "");
});

test("jobs are read whatever the broker called their fields", () => {
  const job = {job_id: "x", state: "Completed", kind: "apply", selected_components: ["os", 3]};
  assert.equal(core.jobId(job), "x");
  assert.equal(core.jobState(job), "completed");
  assert.equal(core.jobOperation(job), "apply");
  assert.deepEqual(core.jobComponents(job), ["os", "3"]);
  assert.equal(core.isTerminal(job), true);
  assert.equal(core.isTerminal({status: "running"}), false);
  assert.equal(core.jobState(null), "unknown");
});
