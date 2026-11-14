"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const dir = path.join(__dirname, "../../docker/app/haproxy_admin/static/js");
const {russianCatalogue} = require("./catalogue.js");

function page(script, expose, payload = {}) {
  const elements = new Map();
  const document = {
    documentElement: {lang: "en"},
    addEventListener() {}, querySelector: () => null, querySelectorAll: () => [],
    getElementById(id) {
      if (!elements.has(id)) elements.set(id, {innerHTML: "", textContent: "", value: "", querySelectorAll: () => []});
      return elements.get(id);
    }
  };
  const window = {fetch: async () => ({ok: true, json: async () => payload}), location: {origin: "http://fixture.test", href: "http://fixture.test/"},
    EasyHaProxyLive: require(path.join(dir, "live_activity_core.js")),
    EasyHaProxyTime: {time: () => "12:00", formatter: () => new Intl.DateTimeFormat("en")}};
  const context = vm.createContext({window, document, console, URL, Headers, Intl, setTimeout, clearTimeout});
  vm.runInContext(fs.readFileSync(path.join(dir, "security.js"), "utf8"), context);
  context.fetch = window.fetch;
  context.escapeHtml = window.escapeHtml;
  const source = fs.readFileSync(path.join(dir, script), "utf8");
  vm.runInContext(expose(source), context);
  return {window, document, elements};
}

const live = () => page("live_activity.js", source => source.replace(/\}\)\(\);\s*$/, "window.testView = {stateBadges, renderRequestRows};})();"));

test("current IP grant and recent identities are labelled separately; names are escaped", () => {
  const {window} = live();
  const html = window.testView.stateBadges({authorized: true, authenticated_users: [{username: "alice"}, {username: '<img src=x onerror=alert(1)>'}]});
  assert.match(html, /IP authorized now/);
  assert.match(html, /Users observed \(last 24 hours\)/);
  assert.match(html, /alice/);
  assert.match(html, /&lt;img/);
  assert.doesNotMatch(html, /<img/);
});

test("expired grant does not become signed in because historical names exist", () => {
  const {window} = live();
  const html = window.testView.stateBadges({authorized: false, authenticated_users: [{username: "alice"}]});
  assert.doesNotMatch(html, /alice|IP authorized now/);
});

test("request rows identify only their own user, leaving a guest request unnamed", () => {
  const {window, document} = live();
  window.testView.renderRequestRows("rows", "empty", [{ip: "203.0.113.9", ts: 1, status: 200, method: "GET", path: "/", authenticated_user: "alice<script>"},
    {ip: "203.0.113.9", ts: 2, status: 200, method: "GET", path: "/"}]);
  const html = document.getElementById("rows").innerHTML;
  assert.equal((html.match(/Authenticated user/g) || []).length, 1);
  assert.match(html, /alice&lt;script&gt;/);
  assert.doesNotMatch(html, /<script>/);
});

test("dashboard renders several observed users safely without changing the IP/TTL columns", async () => {
  const payload = {headers: ["IP", "Flag", "TTL"], rows: [["203.0.113.9", 1, 60]], users_by_ip: {"203.0.113.9": [{username: "alice"}, {username: "<bob>"}]}};
  const {window, document} = page("dashboard.js", source => source.replace("    init,", "    init, loadIpAuth," ) + "\nwindow.testView = Dashboard;", payload);
  await window.testView.loadIpAuth();
  const html = document.getElementById("ip-auth").innerHTML;
  assert.match(html, /Users observed \(last 24 hours\)/);
  assert.match(html, /alice, &lt;bob&gt;/);
  assert.match(html, /203.0.113.9/);
  assert.match(html, /1 min/);
  assert.equal((html.match(/<td/g) || []).length, 4);
});

test("new monitoring labels are translated into Russian", () => {
  const messages = russianCatalogue();
  for (const key of ["IP authorized now", "Authenticated user", "Username not yet observed", "Users observed (last 24 hours)"]) {
    assert.ok(messages[key]);
    assert.notEqual(messages[key], key);
  }
});
