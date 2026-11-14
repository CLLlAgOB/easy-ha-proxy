// Behaviour of the request log page's decisions (request_log_core.js): what
// the address says about the search on screen, what a link may set, and
// what the server is asked. Run with: node --test .tests/js/
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const APP = path.join(__dirname, "../../docker/app/haproxy_admin");
const core = require(path.join(APP, "static/js/request_log_core.js"));

test("a fresh page keeps a plain address", () => {
  assert.deepEqual(core.viewQuery({range: core.DEFAULT_RANGE}), {});
  assert.deepEqual(core.viewQuery({}), {});
  assert.deepEqual(core.viewFromQuery(""), {});
});

test("the search goes into the address and comes back the same", () => {
  const view = {
    range: 3600, status: " 4xx, 500 ", client: "192.0.2.7", host: "shop.example", backend: "be_shop",
    path: "/api", request_id: "abc-123", agent: "curl", method: "propfind", refused: true, slower: 1500,
    admin: true
  };
  const query = core.viewQuery(view);
  assert.deepEqual(query, {
    range: "3600", status: "4xx, 500", client: "192.0.2.7", host: "shop.example", backend: "be_shop",
    path: "/api", request_id: "abc-123", agent: "curl", method: "PROPFIND", refused: "1", slower: "1500",
    admin: "1"
  });
  const back = core.viewFromQuery("?" + new URLSearchParams(query).toString());
  assert.deepEqual(back, {
    range: 3600, status: "4xx, 500", client: "192.0.2.7", host: "shop.example", backend: "be_shop",
    path: "/api", request_id: "abc-123", agent: "curl", method: "PROPFIND", refused: true, slower: 1500,
    admin: true
  });
  assert.ok(core.sameQuery(view, back));
});

test("a period from a link is kept as its times", () => {
  const view = core.viewFromQuery("?since=1000&until=4600&client=192.0.2.7");
  assert.deepEqual(view, {since: 1000, until: 4600, client: "192.0.2.7"});
  assert.deepEqual(core.viewQuery(view), {since: "1000", until: "4600", client: "192.0.2.7"});
  assert.deepEqual(core.searchParams(view, 99999), {since: "1000", until: "4600", client: "192.0.2.7", hide_admin: "1"});
});

test("an address the page did not write is checked, not trusted", () => {
  assert.deepEqual(core.viewFromQuery("?range=12345&since=50&until=60&method=GE T&slower=-5&refused=yes&admin=true"), {});
  assert.deepEqual(core.viewFromQuery("?slower=99999999999"), {});
  assert.equal(core.viewFromQuery("?path=" + "x".repeat(500)).path.length, 200);
  assert.deepEqual(core.viewFromQuery("?range=0"), {range: 0});
});

test("the server is asked for the period from now, without the panel's own requests", () => {
  assert.deepEqual(core.searchParams({}, 100000.7), {since: String(100000 - 86400), hide_admin: "1"});
  assert.deepEqual(core.searchParams({range: 3600}, 100000), {since: "96400", hide_admin: "1"});
  // Everything kept: no lower bound at all.
  assert.deepEqual(core.searchParams({range: 0, admin: true}, 100000), {});
  assert.deepEqual(core.searchParams({range: 0, refused: true, slower: "250", method: "post", status: " 404 "}, 1),
    {refused: "1", slower: "250", method: "POST", status: "404", hide_admin: "1"});
});

test("two views asking the same thing need no new address", () => {
  assert.ok(core.sameQuery({range: core.DEFAULT_RANGE}, {}));
  assert.ok(!core.sameQuery({client: "192.0.2.7"}, {}));
});

/* ---------- the overview (phase 3) ---------- */

test("the histogram stacks each bar's kinds, the busiest bar to the top", () => {
  const rects = core.histogramRects([[2, 1, 0, 1], [0, 0, 0, 0], [1, 0, 0, 0]], 300, 84);
  assert.deepEqual(rects.map((r) => [r.index, r.kind]), [[0, "ok"], [0, "client_errors"], [0, "refused"], [2, "ok"]]);
  const first = rects.filter((r) => r.index === 0);
  assert.equal(Math.round(first.reduce((sum, r) => sum + r.height, 0)), 80);
  assert.equal(first[0].y + first[0].height, 84);
  assert.deepEqual(core.histogramRects(undefined, 300, 84), []);
});

test("a point on the histogram is a bar", () => {
  assert.equal(core.barAt(0, 60), 0);
  assert.equal(core.barAt(0.5, 60), 30);
  assert.equal(core.barAt(1, 60), 59);
  assert.equal(core.barAt(-0.1, 60), -1);
  assert.equal(core.barAt(0.5, 0), -1);
});

test("bars clicked or dragged across become a period, never past now", () => {
  const summary = {start: 1000, bucket_seconds: 60};
  assert.deepEqual(core.barsSpan(2, 2, summary), {since: 1120, until: 1180});
  assert.deepEqual(core.barsSpan(5, 3, summary), {since: 1180, until: 1360});
  assert.deepEqual(core.barsSpan(5, 5, summary, 1310), {since: 1300, until: 1360});
});

test("the store line says how far back, and when the size cap decides it", () => {
  const now = 10 * 86400;
  assert.equal(core.historyReach({}, now), null);
  const days = {oldest_ts: now - 3 * 86400 + 60, retention_days: 3, database_bytes: 10, max_bytes: 100};
  assert.deepEqual(core.historyReach(days, now), {oldest: days.oldest_ts, cappedBySize: false});
  const capped = {oldest_ts: now - 86400, retention_days: 3, database_bytes: 95, max_bytes: 100};
  assert.deepEqual(core.historyReach(capped, now), {oldest: capped.oldest_ts, cappedBySize: true});
  // A young store that is far from its cap is just young.
  const young = {oldest_ts: now - 3600, retention_days: 3, database_bytes: 1, max_bytes: 100};
  assert.equal(core.historyReach(young, now).cappedBySize, false);
});

// The latest requests in memory (07.6): the slider says MB and roughly how
// many hours that holds at the current traffic, before anything is applied.
const MIB = 1048576;
const memory = (extra) => Object.assign({
  budget_mib: 0, applied_mib: 0, revision: 0,
  default: {records: 100000, seconds: 3600},
  limits: {min_mib: 16, max_mib: 128, step_mib: 8, max_seconds: 86400},
  buffer: {records: 20000, bytes: 11 * MIB, oldest: 1000, newest: 4600,
           rate: {bytes_per_hour: 11 * MIB, records_per_hour: 20000}}
}, extra || {});

test("the slider reaches what the gateway can give, and never hides the budget in force", () => {
  assert.deepEqual(core.budgetRange(memory()), {min: 16, max: 128, step: 8, usable: true});
  const tight = memory({applied_mib: 96, limits: {min_mib: 16, max_mib: 40, step_mib: 8}});
  assert.equal(core.budgetRange(tight).max, 96);
  assert.equal(core.budgetRange(memory({limits: {min_mib: 16, max_mib: 8, step_mib: 8}})).usable, false);
});

test("with the usual limit the slider starts at about what is held", () => {
  assert.equal(core.budgetStart(memory()), 16);
  assert.equal(core.budgetStart(memory({buffer: {bytes: 41 * MIB}})), 48);
  assert.equal(core.budgetStart(memory({applied_mib: 64})), 64);
  assert.equal(core.budgetStart(memory({buffer: {bytes: 900 * MIB}})), 128);
});

test("hours at the current traffic, at most a day", () => {
  const rate = {bytes_per_hour: 8 * MIB};
  assert.deepEqual(core.budgetReach(48, rate, 86400), {seconds: 6 * 3600, capped: false});
  assert.deepEqual(core.budgetReach(128, {bytes_per_hour: MIB}, 86400), {seconds: 86400, capped: true});
  assert.equal(core.budgetReach(48, {bytes_per_hour: 0}, 86400), null);
  assert.equal(core.budgetReach(0, rate, 86400), null);
});

test("a smaller budget says how much stays", () => {
  const buffer = {bytes: 40 * MIB, oldest: 0, newest: 8 * 3600};
  assert.deepEqual(core.budgetKeeps(16, buffer), {seconds: 8 * 3600 * 16 / 40, dropBytes: 24 * MIB});
  assert.equal(core.budgetKeeps(48, buffer), null);
});

test("sizes and durations as the page writes them", () => {
  assert.equal(core.megabytes(5.25 * MIB), 5.3);
  assert.equal(core.megabytes(41.6 * MIB), 42);
  assert.deepEqual(core.durationParts(90), {unit: "min", value: 2});
  assert.deepEqual(core.durationParts(20), {unit: "min", value: 1});
  assert.deepEqual(core.durationParts(5.5 * 3600), {unit: "h", value: 5.5});
  assert.deepEqual(core.durationParts(13.6 * 3600), {unit: "h", value: 14});
});
