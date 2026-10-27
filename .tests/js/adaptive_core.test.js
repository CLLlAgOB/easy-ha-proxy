// Behaviour of the adaptive protection page's decisions (adaptive_core.js):
// the simulator's query, the ban ladder, what a mode switch will do, the
// score bands and how a finding is explained. Run with: node --test .tests/js/
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {russianCatalogue, recordingLabel} = require("./catalogue.js");

const core = require(path.join(__dirname, "../../docker/app/haproxy_admin/static/js/adaptive_core.js"));

const MINUTE = 60;
const HOUR = 3600;
const DAY = 86400;

/* ---------- simulator ---------- */

test("an untouched simulator asks for the configured weights", () => {
  assert.deepEqual(core.simulatorParams({}), {});
  assert.deepEqual(core.simulatorParams({weights: {scanner: "", rate: "  "}, cap: "", decayHours: ""}), {});
});

test("only the fields filled in are sent, trimmed", () => {
  assert.deepEqual(
    core.simulatorParams({weights: {scanner: " 40 ", rate: "", auth: "5"}, cap: " 60 "}),
    {"w.scanner": "40", "w.auth": "5", cap: "60"}
  );
});

test("decay is typed in hours and sent in seconds", () => {
  assert.deepEqual(core.simulatorParams({decayHours: "6"}), {decay: "21600"});
  assert.deepEqual(core.simulatorParams({decayHours: "1.5"}), {decay: "5400"});
  // Not a number: left for the configured value rather than sent as NaN.
  assert.deepEqual(core.simulatorParams({decayHours: "six"}), {});
});

/* ---------- ban ladder ---------- */

test("a step is shown in the largest unit that divides it exactly", () => {
  assert.deepEqual(core.splitDuration(7 * DAY), {value: 7, unit: "days"});
  assert.deepEqual(core.splitDuration(36 * HOUR), {value: 36, unit: "hr"});
  assert.deepEqual(core.splitDuration(90 * MINUTE), {value: 90, unit: "min"});
  assert.deepEqual(core.splitDuration(90 * DAY), {value: 90, unit: "days"});
  // Not a whole number of minutes: the nearest, never zero.
  assert.deepEqual(core.splitDuration(100), {value: 2, unit: "min"});
  assert.deepEqual(core.splitDuration(0), {value: 1, unit: "min"});
});

test("the ladder reads in the unit the editor shows", () => {
  // A step of 36 hours used to read "2 days" beside an editor saying 36 hr.
  assert.equal(core.ladderText(36 * HOUR), "36 hr");
  assert.equal(core.ladderText(90 * MINUTE), "90 min");
  assert.equal(core.ladderText(HOUR), "1 hr");
  // Months stay readable: ninety days, not 2160 hours.
  assert.equal(core.ladderText(90 * DAY), "90 days");
  assert.equal(core.ladderText(DAY, (key) => `<${key}>`), "1 <days>");
});

test("an edited step is never less than one of its unit", () => {
  assert.equal(core.stepSeconds("36", "hr"), 36 * HOUR);
  assert.equal(core.stepSeconds("7", "days"), 7 * DAY);
  for (const value of ["0", "-3", "", "abc"]) {
    assert.equal(core.stepSeconds(value, "days"), DAY, value);
  }
  // An unknown unit is minutes, the smallest the editor offers.
  assert.equal(core.stepSeconds("5", "weeks"), 5 * MINUTE);
});

test("a step shorter than the one before is named before it is sent", () => {
  assert.equal(core.ladderProblem([HOUR, DAY, 7 * DAY]), -1);
  assert.equal(core.ladderProblem([HOUR, HOUR]), -1);
  assert.equal(core.ladderProblem([DAY, HOUR, 7 * DAY]), 1);
  assert.equal(core.ladderProblem([HOUR, DAY, HOUR]), 2);
  assert.equal(core.ladderProblem([]), -1);
});

test("the ladder has one to six steps, and a new one repeats the last", () => {
  assert.equal(core.canAddStep([1, 2, 3, 4, 5]), true);
  assert.equal(core.canAddStep([1, 2, 3, 4, 5, 6]), false);
  assert.equal(core.canRemoveStep([HOUR]), false);
  assert.equal(core.canRemoveStep([HOUR, DAY]), true);
  // The only value that cannot break "never shorter than the step before".
  assert.equal(core.nextStep([HOUR, 7 * DAY]), 7 * DAY);
  assert.equal(core.nextStep([]), HOUR);
  const steps = [HOUR, DAY];
  assert.equal(core.ladderProblem(steps.concat(core.nextStep(steps))), -1);
});

/* ---------- mode ---------- */

test("switching to enforce says how many it will ban, and how many signed in later", () => {
  assert.deepEqual(
    core.modeConfirmation("enforce", "monitor", {would_ban: 12, likely_false_positive: 2}),
    {kind: "enforce", wouldBan: 12, suspects: 2}
  );
  assert.deepEqual(core.modeConfirmation("enforce", "off", undefined), {kind: "enforce", wouldBan: 0, suspects: 0});
});

test("leaving enforce says every ban it placed will be lifted", () => {
  assert.deepEqual(core.modeConfirmation("monitor", "enforce", {}), {kind: "lift"});
  assert.deepEqual(core.modeConfirmation("off", "enforce", {}), {kind: "lift"});
  assert.deepEqual(core.modeConfirmation("off", "monitor", {}), {kind: "change"});
});

/* ---------- scores ---------- */

test("each band says where it starts and ends, highest first", () => {
  const bands = [
    {state: "NORMAL", from: 0},
    {state: "HOSTILE", from: 60, bans: true},
    {state: "WATCH", from: 10},
    {state: "SUSPICIOUS", from: 25}
  ];
  assert.deepEqual(core.bandRanges(bands), [
    {state: "HOSTILE", bans: true, from: 60, upTo: null},
    {state: "SUSPICIOUS", bans: false, from: 25, upTo: 59},
    {state: "WATCH", bans: false, from: 10, upTo: 24},
    {state: "NORMAL", bans: false, from: 0, upTo: 9}
  ]);
  assert.deepEqual(core.bandRanges(undefined), []);
  assert.equal(bands[0].state, "NORMAL");
});

test("the summary lists the states present, worst first", () => {
  assert.deepEqual(
    core.statesPresent({NORMAL: 40, HOSTILE: 2, WATCH: 0, UNKNOWN: 5}),
    [["HOSTILE", 2], ["NORMAL", 40]]
  );
  assert.deepEqual(core.statesPresent(undefined), []);
});

test("time left on a ban reads in its two largest units", () => {
  assert.equal(core.formatLeft(0), "1min");
  assert.equal(core.formatLeft(30), "1min");
  assert.equal(core.formatLeft(59 * MINUTE), "59min");
  assert.equal(core.formatLeft(5 * HOUR + 10 * MINUTE), "5hr 10min");
  assert.equal(core.formatLeft(DAY + HOUR), "1days 1hr");
  assert.equal(core.formatLeft(DAY, (key) => ` ${key}`), "1 days 0 hr");
});

test("the second unit never reaches the first", () => {
  // Rounding the remainder on its own read "2 days 24 hr" and "5 hr 60 min".
  assert.equal(core.formatLeft(2 * DAY + 23.6 * HOUR), "3days 0hr");
  assert.equal(core.formatLeft(5 * HOUR + 59 * MINUTE + 40), "6hr 0min");
  assert.equal(core.formatLeft(HOUR - 10), "1hr 0min");
  assert.equal(core.formatLeft(DAY - 20), "1days 0hr");
  assert.equal(core.formatLeft(DAY - 60), "23hr 59min");
});

/* ---------- an address's findings ---------- */

test("findings are listed newest first", () => {
  const items = [{ts: 10}, {ts: 30}, {ts: 20}];
  assert.deepEqual(core.newestFirst(items).map((item) => item.ts), [30, 20, 10]);
  assert.deepEqual(items.map((item) => item.ts), [10, 30, 20]);
  assert.deepEqual(core.newestFirst(undefined), []);
});

test("a finding over a limit says by how much, and which setting moves it", () => {
  const bits = core.findingContext({
    site_domain: "shop.example", observed: 140, unit: "requests", limit: 100,
    window: "10s", over_by: 40, setting: "rate_limit", suggested: 160
  });
  assert.deepEqual(bits, ["shop.example", "140 requests / limit 100 / 10s", "+40 over", "raise rate_limit → 160"]);
});

test("a finding without a measurement shows its detail", () => {
  assert.deepEqual(core.findingContext({site_name: "shop", detail: "/wp-login.php"}), ["shop", "/wp-login.php"]);
  // A measurement wins over the detail, and one without a unit has no gap.
  assert.deepEqual(core.findingContext({observed: 3, limit: 2, detail: "ignored"}), ["3 / limit 2"]);
  assert.deepEqual(core.findingContext({}), []);
});

test("a finding that added nothing says why", () => {
  assert.equal(core.findingPoints({points: 15}), "+15");
  assert.equal(core.findingPoints({points: 0, reason: "category cap reached"}), "0 · category cap reached");
});

test("every word the page is given to translate is in Russian", () => {
  const russian = russianCatalogue();
  const label = recordingLabel();
  for (const seconds of [MINUTE, HOUR, DAY, 36 * HOUR]) {
    core.ladderText(seconds, label);
    core.formatLeft(seconds + 1234, label);
  }
  core.findingContext({observed: 1, limit: 1, over_by: 1, setting: "x"}, label);
  core.findingPoints({points: 0, reason: "counted"}, label);
  label.asked.delete("");
  for (const word of label.asked) {
    assert.ok(Object.prototype.hasOwnProperty.call(russian, word), word);
  }
});
