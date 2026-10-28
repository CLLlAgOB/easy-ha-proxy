// Behaviour of the live activity page's decisions (live_activity_core.js):
// what a saved choice restores to, what the filters ask for, how the tables
// sort, which badges and which ban control a row gets, and what the note
// and the timeline show. Run with: node --test .tests/js/
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const {russianCatalogue, recordingLabel} = require("./catalogue.js");

const APP = path.join(__dirname, "../../docker/app/haproxy_admin");
const core = require(path.join(APP, "static/js/live_activity_core.js"));

const HOUR = 3600;
const DAY = 86400;

/* ---------- saved choices ---------- */

test("nothing saved, or something unreadable, means the defaults", () => {
  for (const saved of [undefined, null, {}, "x", 7, []]) {
    assert.deepEqual(core.restoreSettings(saved), core.defaults());
  }
  assert.deepEqual(core.defaults(), {
    window: 60,
    refresh: 5,
    tab: "addresses",
    admin: false,
    sort: {addresses: {key: "requests", dir: -1}, sites: {key: "requests", dir: -1}}
  });
});

test("a saved window is kept only if the page could have chosen it", () => {
  assert.equal(core.restoreSettings({window: 300}).window, 300);
  assert.equal(core.restoreSettings({window: "45"}).window, 45);
  assert.equal(core.restoreSettings({window: 3600}).window, 3600);
  assert.equal(core.restoreSettings({window: 12.4}).window, 12);
  for (const window of [4, 0, -60, 3601, 99999, "abc", null]) {
    assert.equal(core.restoreSettings({window}).window, 60, String(window));
  }
});

test("a saved refresh and tab are kept only if the page offers them", () => {
  assert.equal(core.restoreSettings({refresh: 30}).refresh, 30);
  assert.equal(core.restoreSettings({refresh: "10"}).refresh, 10);
  assert.equal(core.restoreSettings({refresh: 1}).refresh, 5);
  assert.equal(core.restoreSettings({tab: "banned"}).tab, "banned");
  assert.equal(core.restoreSettings({tab: "settings"}).tab, "addresses");
});

test("a saved sort order is kept only if it names a column", () => {
  const kept = core.restoreSettings({sort: {addresses: {key: "bytes", dir: 1}, sites: {key: "p95_ms", dir: -1}}});
  assert.deepEqual(kept.sort, {addresses: {key: "bytes", dir: 1}, sites: {key: "p95_ms", dir: -1}});
  // The average went: a sort saved by it falls back.
  assert.deepEqual(core.restoreSettings({sort: {sites: {key: "avg_ms", dir: -1}}}).sort, core.defaults().sort);
  // A damaged entry used to be taken as it was, and the table then sorted
  // by address alone. Each table falls back on its own.
  const damaged = core.restoreSettings({
    sort: {addresses: "x", sites: {key: "rate", dir: 1}, events: {key: "requests", dir: 1}}
  });
  assert.deepEqual(damaged.sort, core.defaults().sort);
  assert.deepEqual(core.restoreSettings({sort: {addresses: {key: "requests", dir: 2}}}).sort, core.defaults().sort);
});

test("the columns the page restores are the columns it can sort by", () => {
  const page = fs.readFileSync(path.join(APP, "templates/live_activity.html"), "utf8");
  for (const [table, keys] of Object.entries(core.SORT_KEYS)) {
    const panel = page.split(`data-panel="${table}"`)[1].split("data-panel=")[0];
    const headers = Array.from(panel.matchAll(/data-sort="([a-z0-9_]+)"/g), (match) => match[1]);
    assert.deepEqual(headers.sort(), keys.slice().sort(), table);
  }
});

test("a typed window is between 5 seconds and an hour", () => {
  assert.equal(core.customWindow("45"), 45);
  assert.equal(core.customWindow("12.6"), 13);
  for (const value of ["", "4", "3601", "abc", null]) {
    assert.equal(core.customWindow(value), null, String(value));
  }
  assert.equal(core.isPresetWindow(60), true);
  assert.equal(core.isPresetWindow(45), false);
});

/* ---------- filters ---------- */

test("only the filters that are set go to the server", () => {
  // The panel's own requests are left out unless asked for.
  assert.deepEqual(core.requestParams({window: 60}), {window: 60, hide_admin: "1"});
  assert.deepEqual(core.requestParams({window: 60, admin: true}), {window: 60});
  assert.deepEqual(
    core.requestParams({
      window: 300, ip: " 192.0.2.7 ", host: "shop.example", country: "NL",
      status: "4xx", q: "  wp-login ", blocked: true, banned: true, admin: true
    }),
    {window: 300, ip: "192.0.2.7", host: "shop.example", country: "NL", status: "4xx", q: "wp-login", blocked: "1", banned: "1"}
  );
  assert.deepEqual(core.requestParams({window: 60, ip: "   ", q: "", blocked: false, admin: true}), {window: 60});
});

test("a chosen site stays selectable after its last request leaves the window", () => {
  assert.deepEqual(core.selectValues(["a", "b"], "c"), ["a", "b", "c"]);
  assert.deepEqual(core.selectValues(["a", "b"], "a"), ["a", "b"]);
  assert.deepEqual(core.selectValues(["a"], ""), ["a"]);
  const values = ["a"];
  core.selectValues(values, "z");
  assert.deepEqual(values, ["a"]);
});

/* ---------- sorting ---------- */

const ROWS = [
  {ip: "192.0.2.9", requests: 5, bytes: 100},
  {ip: "192.0.2.1", requests: 50},
  {ip: "192.0.2.3", requests: 5, bytes: 900}
];

test("rows sort by the chosen column, ties by address", () => {
  const ips = (sort) => core.sortRows(ROWS, sort).map((row) => row.ip);
  assert.deepEqual(ips({key: "requests", dir: -1}), ["192.0.2.1", "192.0.2.3", "192.0.2.9"]);
  assert.deepEqual(ips({key: "requests", dir: 1}), ["192.0.2.3", "192.0.2.9", "192.0.2.1"]);
  // A row without the column counts as zero.
  assert.deepEqual(ips({key: "bytes", dir: -1}), ["192.0.2.3", "192.0.2.9", "192.0.2.1"]);
  assert.equal(ROWS[0].ip, "192.0.2.9");
});

test("sites tie by name", () => {
  const rows = [{host: "b.example", requests: 1}, {host: "a.example", requests: 1}];
  assert.deepEqual(core.sortRows(rows, {key: "requests", dir: -1}).map((row) => row.host), ["a.example", "b.example"]);
});

test("the same column again reverses it; another starts biggest first", () => {
  assert.deepEqual(core.sortAfterClick({key: "requests", dir: -1}, "requests"), {key: "requests", dir: 1});
  assert.deepEqual(core.sortAfterClick({key: "requests", dir: 1}, "requests"), {key: "requests", dir: -1});
  assert.deepEqual(core.sortAfterClick({key: "requests", dir: 1}, "bytes"), {key: "bytes", dir: -1});
});

/* ---------- rows ---------- */

test("a status is coloured by its class", () => {
  assert.equal(core.statusTone(200), "la-s2");
  assert.equal(core.statusTone(301), "la-s3");
  assert.equal(core.statusTone(451), "la-s4");
  assert.equal(core.statusTone(503), "la-s5");
  assert.equal(core.statusTone(undefined), "la-s2");
});

test("a row is marked refused only when every request was", () => {
  assert.equal(core.fullyRefused({requests: 4, blocked: 4}), true);
  assert.equal(core.fullyRefused({requests: 4, blocked: 3}), false);
  assert.equal(core.fullyRefused({requests: 0, blocked: 0}), false);
});

test("badges come in a fixed order, and only for what is true", () => {
  assert.deepEqual(core.badgeKinds({}), []);
  assert.deepEqual(
    core.badgeKinds({ban: {}, connection_limited: true, allow_listed: true, authorized: true, reason: "geo", blocked: 2}),
    ["banned", "limited", "allow-listed", "signed-in", "refused"]
  );
  // A reason with no refusal left in the window is not a badge.
  assert.deepEqual(core.badgeKinds({reason: "geo", blocked: 0}), []);
});

test("refused earlier and signed in now are shown together", () => {
  // Zero trust refused it, then the visitor signed in: both are true, of
  // different moments.
  assert.deepEqual(core.badgeKinds({authorized: true, reason: "zero_trust", blocked: 3}), ["signed-in", "refused"]);
});

test("each address gets the one ban control that works for it", () => {
  assert.equal(core.banAction(true, "host"), "unban");
  assert.equal(core.banAction(false, null), "ban");
  // A plain ban does nothing on an allow-listed address.
  assert.equal(core.banAction(false, "host"), "drop-and-ban");
  // Dropping a range would un-protect every other address in it.
  assert.equal(core.banAction(false, "range"), "in-allowed-range");
});

test("an older server that only says 'allow-listed' means the address itself", () => {
  assert.equal(core.allowEntryOf({allow_entry: "range", allow_listed: true}), "range");
  assert.equal(core.allowEntryOf({allow_listed: true}), "host");
  assert.equal(core.allowEntryOf({}), null);
});

/* ---------- summary ---------- */

test("a card warns from the first and turns red at its limit", () => {
  assert.equal(core.cardTone(0, 100), "");
  assert.equal(core.cardTone(5, 100), "warn");
  assert.equal(core.cardTone(100, 100), "bad");
  assert.equal(core.cardTone(0, 1), "");
  assert.equal(core.cardTone(1, 1), "bad");
});

test("the page says it is behind only when it is, by more than 15 seconds", () => {
  const base = {window: 60, bucket_seconds: 5};
  assert.deepEqual(core.summaryNote({...base, lag_bytes: 4096, lag_seconds: 40}), {kind: "behind", seconds: 40});
  // Unread bytes but a fresh newest line, or an old line with nothing left
  // to read: not behind.
  assert.equal(core.summaryNote({...base, lag_bytes: 4096, lag_seconds: 15}).kind, "window");
  assert.equal(core.summaryNote({...base, lag_bytes: 0, lag_seconds: 400}).kind, "window");
  assert.deepEqual(core.summaryNote({...base, truncated: true, covered_seconds: 42}), {kind: "partial", seconds: 42});
  assert.deepEqual(core.summaryNote(base), {kind: "window", seconds: 60, bucket: 5});
});

test("refusal reasons are listed most frequent first", () => {
  assert.deepEqual(core.refusalCounts({geo: 3, ban: 40, rate: 7}), [["ban", 40], ["rate", 7], ["geo", 3]]);
  assert.deepEqual(core.refusalCounts(undefined), []);
});

test("the timeline stacks answered, errors and refused, scaled to the busiest bar", () => {
  const rects = core.timelineRects(
    [{ok: 30, errors: 10, blocked: 20}, {ok: 0, errors: 0, blocked: 0}, {ok: 6, errors: 0, blocked: 0}],
    300, 64
  );
  // Nothing drawn for an empty part or an empty bucket.
  assert.deepEqual(rects.map((rect) => rect.part), ["ok", "errors", "blocked", "ok"]);
  const [ok, errors, blocked, small] = rects;
  const close = (actual, expected) => assert.ok(Math.abs(actual - expected) < 1e-9, `${actual} != ${expected}`);
  // The busiest bucket fills the height, less a margin of 4.
  close(ok.height + errors.height + blocked.height, 60);
  close(ok.y, 64 - 30);
  close(errors.y, ok.y - 10);
  close(blocked.y, errors.y - 20);
  close(small.height, 6);
  close(small.y, 64 - 6);
  assert.equal(small.x, 201);
  assert.equal(small.width, 98);
});

test("a timeline with no traffic draws nothing and does not divide by zero", () => {
  assert.deepEqual(core.timelineRects([], 1000, 70), []);
  assert.deepEqual(core.timelineRects([{ok: 0, errors: 0, blocked: 0}], 1000, 70), []);
});

/* ---------- formats ---------- */

test("durations are in the largest unit they have reached once rounded", () => {
  assert.equal(core.duration(0), "0 sec");
  assert.equal(core.duration(45), "45 sec");
  assert.equal(core.duration(59.6), "1 min");
  assert.equal(core.duration(3540), "59 min");
  // 59.5 minutes is an hour, not "60 min".
  assert.equal(core.duration(3570), "1 hr");
  assert.equal(core.duration(5 * HOUR), "5 hr");
  assert.equal(core.duration(DAY - 600), "1 days");
  assert.equal(core.duration(3 * DAY), "3 days");
  assert.equal(core.duration(-5), "0 sec");
  assert.equal(core.duration(90, (key) => `<${key}>`), "2 <min>");
});

test("traffic is given in the largest unit below 1024", () => {
  assert.equal(core.bytes(0), "0 B");
  assert.equal(core.bytes(undefined), "0 B");
  assert.equal(core.bytes(1023), "1023 B");
  assert.equal(core.bytes(1536), "1.5 KiB");
  assert.equal(core.bytes(5 * 1024 ** 3), "5.0 GiB");
  assert.equal(core.bytes(3 * 1024 ** 4), "3072.0 GiB");
});

test("every word the page is given to translate is in Russian", () => {
  const russian = russianCatalogue();
  const label = recordingLabel();
  for (const seconds of [5, 300, 7200, 3 * DAY]) core.duration(seconds, label);
  for (const word of label.asked) {
    assert.ok(Object.prototype.hasOwnProperty.call(russian, word), word);
  }
  assert.deepEqual(Array.from(label.asked).sort(), ["days", "hr", "min", "sec"]);
});

test("the admin panel's own requests stay hidden unless the viewer chose them", () => {
  assert.equal(core.restoreSettings({admin: true}).admin, true);
  for (const value of ["yes", 1, null, undefined]) {
    assert.equal(core.restoreSettings({admin: value}).admin, false, String(value));
  }
});

test("a point on the timeline is a bar, and a bar is a span of seconds", () => {
  assert.equal(core.timelineIndex(0, 60), 0);
  assert.equal(core.timelineIndex(0.5, 60), 30);
  assert.equal(core.timelineIndex(1, 60), 59);
  assert.equal(core.timelineIndex(-0.2, 60), 0);
  assert.equal(core.timelineIndex(0.5, 0), -1);
  const data = {now: 1000, window: 300, bucket_seconds: 5};
  assert.deepEqual(core.timelineSpan(0, data), {from: 700, to: 705});
  // The last bar ends now, not a bucket later.
  assert.deepEqual(core.timelineSpan(59, {now: 1002, window: 300, bucket_seconds: 5}), {from: 997, to: 1002});
});

test("the view goes into the address only where it differs, and comes back checked", () => {
  assert.deepEqual(core.viewQuery({window: 60, tab: "addresses"}), {});
  const query = core.viewQuery({
    window: 900, ip: " 192.0.2.7 ", host: "shop.example", country: "NL", status: "4xx",
    q: " wp-login ", blocked: true, banned: false, tab: "events", admin: true
  });
  assert.deepEqual(query, {window: "900", ip: "192.0.2.7", host: "shop.example", country: "NL",
    status: "4xx", q: "wp-login", blocked: "1", tab: "events", admin: "1"});
  const back = core.viewFromQuery("?" + new URLSearchParams(query).toString());
  assert.deepEqual(back, {window: 900, ip: "192.0.2.7", host: "shop.example", country: "NL",
    status: "4xx", q: "wp-login", blocked: true, tab: "events", admin: true});
});

test("an address the page did not write is checked, not trusted", () => {
  assert.deepEqual(core.viewFromQuery("?window=99999&ip=<script>&host=a b&country=NLD&status=6xx&tab=x&blocked=yes"), {});
  assert.deepEqual(core.viewFromQuery(""), {});
  assert.equal(core.viewFromQuery("?q=" + "x".repeat(500)).q.length, 120);
});

test("how a request ended is said in words", () => {
  assert.deepEqual(core.termination("----"), {normal: true, cause: "", phase: ""});
  assert.deepEqual(core.termination(""), {normal: true, cause: "", phase: ""});
  const aborted = core.termination("CD--");
  assert.equal(aborted.normal, false);
  assert.equal(aborted.cause, "The client closed the connection");
  assert.equal(aborted.phase, "while sending the data");
  assert.equal(core.termination("sH--").cause, "The server did not answer in time");
  assert.equal(core.termination("PR--").phase, "while receiving the request");
  // An unknown letter is left unsaid rather than guessed.
  assert.deepEqual(core.termination("Z?--"), {normal: false, cause: "", phase: ""});
});

test("where a request's time went", () => {
  assert.deepEqual(core.timers("11/0/0/30/47").map((timer) => [timer.key, timer.ms]),
    [["received", 11], ["queued", 0], ["connect", 0], ["answer", 30], ["total", 47]]);
  // A step that never happened -- no server, no answer -- is no time at all.
  assert.deepEqual(core.timers("0/-1/-1/-1/6").map((timer) => timer.ms), [0, null, null, null, 6]);
  assert.deepEqual(core.timers("1/2/3"), []);
  assert.deepEqual(core.timers(undefined), []);
});

test("a request keeps its key across refreshes", () => {
  const event = {ts: 100.5, ip: "192.0.2.7", request_id: "abc", path: "/x"};
  assert.equal(core.eventKey(event), core.eventKey(Object.assign({}, event, {status: 200})));
  assert.notEqual(core.eventKey(event), core.eventKey(Object.assign({}, event, {request_id: "abd"})));
});

/* ---------- top lists (phase 3) ---------- */

test("the paths, clients and slowest tabs can be opened and linked to", () => {
  for (const tab of ["paths", "agents", "slow"]) {
    assert.ok(core.TABS.includes(tab));
    assert.deepEqual(core.viewFromQuery(`?tab=${tab}`), {tab});
  }
});

test("a client filter is asked for, written into the address and read back", () => {
  assert.deepEqual(core.requestParams({window: 60, agent: " curl ", admin: true}), {window: 60, agent: "curl"});
  assert.deepEqual(core.requestParams({window: 60, agent: "   ", admin: true}), {window: 60});
  assert.deepEqual(core.viewQuery({window: 60, tab: "addresses", agent: " curl/8 "}), {agent: "curl/8"});
  assert.deepEqual(core.viewFromQuery("?agent=curl%2F8"), {agent: "curl/8"});
  assert.equal(core.viewFromQuery("?agent=" + "x".repeat(500)).agent.length, 120);
});

test("a site's line puts its busiest bar at the top and an idle one at the bottom", () => {
  const points = core.sparkPoints([0, 5, 10], 90, 22).split(" ").map((p) => p.split(",").map(Number));
  assert.deepEqual(points.map((p) => p[0]), [0, 45, 90]);
  assert.equal(points[2][1], 1);   // the busiest
  assert.equal(points[0][1], 21);  // nothing
  // Too little to draw a line: nothing, not a dot.
  assert.equal(core.sparkPoints([3], 90, 22), "");
  assert.equal(core.sparkPoints(undefined, 90, 22), "");
  // A quiet site is a flat line along the bottom, not a division by zero.
  assert.ok(core.sparkPoints([0, 0, 0], 90, 22).split(" ").every((p) => p.endsWith(",21.0")));
});
