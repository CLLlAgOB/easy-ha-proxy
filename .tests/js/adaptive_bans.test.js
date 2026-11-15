"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const core = require("../../docker/app/haproxy_admin/static/js/adaptive_core.js");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");

test("current bans filter and sort numeric values before pagination without changing source", () => {
  const rows = [{ip: "203.0.113.2", banned_at: 20, score: 9, strikes: 2, categories: ["secrets"]},
    {ip: "203.0.113.1", banned_at: 30, score: 80, strikes: 1, categories: ["vcs"]},
    {ip: "203.0.113.3", banned_at: 10, score: 100, strikes: 3, categories: ["secrets"]}];
  assert.deepEqual(core.banRows(rows, {sort: "score", direction: "desc"}).map((r) => r.score), [100, 80, 9]);
  assert.deepEqual(core.banRows(rows, {q: "SECRET", since: 15}).map((r) => r.ip), ["203.0.113.2"]);
  assert.equal(core.banRows(rows, {q: "113.1"})[0].ts, 30);
  assert.equal(rows[0].ts, undefined);
});

test("request search ends at the selected ban, includes admin traffic and stays bounded", () => {
  const ban = {ip: "203.0.113.1", ts: 1000000};
  assert.deepEqual(core.banRequestParams(ban, 6), {client: ban.ip, since: 978400, until: ban.ts, hide_admin: "0", limit: 100});
  assert.equal(core.banRequestParams(ban, 9999).since, 996400);
  assert.equal(core.banRequestParams({ip: ban.ip, ts: 10}, 1).since, 0);
});

function page(fetch) {
  const elements = new Map();
  const element = () => ({textContent: "", value: "1", children: [],
    appendChild(child) { this.children.push(child); }, replaceChildren() { this.children = []; },
    focus() {}, addEventListener() {}, setAttribute() {}});
  const document = {addEventListener() {}, querySelectorAll: () => [], createElement: element,
    getElementById(id) { if (!elements.has(id)) elements.set(id, element()); return elements.get(id); }};
  const window = {EasyHaProxyAdaptive: core, EasyHaProxyTime: {formatter: () => ({format: (date) => String(date.getTime())})}};
  const file = path.join(__dirname, "../../docker/app/haproxy_admin/static/js/adaptive_bans.js");
  const source = fs.readFileSync(file, "utf8").replace(/\}\)\(\);\s*$/, "window.testView = {openBan};})();");
  vm.runInNewContext(source, {window, document, URLSearchParams, fetch});
  return {window, elements};
}
const response = (payload, ok = true) => ({ok, json: async () => payload});
const settle = () => new Promise((resolve) => setImmediate(resolve));

test("a slow reply for a previous IP cannot replace the selected ban or its requests", async () => {
  let completeOld;
  const requests = [];
  const latest = {id: 2, ip: "203.0.113.2", ts: 20000, score: 95, strike: 2, reason: {evidence: []}};
  const view = page(async (url) => {
    if (url.includes("/ban?id=1")) return new Promise((resolve) => { completeOld = resolve; });
    if (url.includes("/ban?id=2")) return response({ban: latest});
    requests.push(url);
    return response({requests: [{ts: 19999, method: "GET", path: "<script>bad()</script>"}], next: 0});
  });
  const old = view.window.testView.openBan({id: 1, ip: "203.0.113.1", ts: 10000});
  await view.window.testView.openBan(latest);
  await settle();
  completeOld(response({ban: {ip: "203.0.113.1", ts: 10000, reason: {evidence: []}}}));
  await old;
  await settle();
  assert.match(view.elements.get("ab-detail-title").textContent, /203\.0\.113\.2/);
  assert.equal(requests.length, 1);
  assert.match(requests[0], /client=203.0.113.2/);
  assert.match(requests[0], /until=20000/);
  assert.equal(view.elements.get("ab-requests").children[0].children[3].textContent, "<script>bad()</script>");
});

test("pruned decision evidence still permits searching requests at that exact ban time", async () => {
  let search;
  const view = page(async (url) => {
    if (url.includes("/ban?")) return response({ok: false, error: "gone"}, false);
    search = url;
    return response({requests: [], source: "memory", reaches_back_to: 15000, next: 0});
  });
  await view.window.testView.openBan({id: 1, ip: "203.0.113.1", ts: 10000});
  await settle();
  assert.match(search, /until=10000/);
  assert.match(view.elements.get("ab-requests-note").textContent, /No retained requests/);
  assert.match(view.elements.get("ab-requests-note").textContent, /in-memory/);
});

test("unknown ban time never turns into an unbounded current request search", async () => {
  const calls = [];
  const view = page(async (url) => { calls.push(url); return response({ok: false, error: "gone"}, false); });
  await view.window.testView.openBan({ip: "203.0.113.1", ts: 0});
  await settle();
  assert.equal(calls.length, 1);
  assert.match(view.elements.get("ab-requests-note").textContent, /ban time is unknown/);
});
