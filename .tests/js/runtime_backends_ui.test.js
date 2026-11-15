"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const {russianCatalogue} = require("./catalogue.js");

function page() {
  const catalogue = russianCatalogue();
  const document = {documentElement: {lang: "ru"}, addEventListener() {}, createElement() {
    return {children: [], attributes: {}, textContent: "", appendChild(child) { this.children.push(child); },
      setAttribute(key, value) { this.attributes[key] = value; }, addEventListener() {}};
  }};
  let requests = 0;
  const window = {t: (key) => catalogue[key] || key,
    EasyHaProxyTime: {formatter: () => new Intl.DateTimeFormat("en")}};
  const file = path.join(__dirname, "../../docker/app/haproxy_admin/static/js/haproxy_backends.js");
  const source = fs.readFileSync(file, "utf8").replace(/\}\)\(\);\s*$/, "window.testView = {serverStatus, renderServer, CHECK_FAILURES};})();");
  vm.runInNewContext(source, {window, document, Intl, fetch: async () => { ++requests; }});
  return {api: window.testView, catalogue, requests: () => requests};
}

test("partial UP checks become a warning with no server-count fraction in the label", () => {
  const {api} = page();
  for (const status of ["UP 1/3", "UP 2/3"]) {
    const state = api.serverStatus({status, admin_state: "ready", check_status: "L6TOUT"});
    assert.equal(state.label, "Available · check failures");
    assert.equal(state.tone, "rt-warning");
    assert.equal(state.failure, "Health check: TLS handshake timed out");
    assert.doesNotMatch(state.label, /\d+\/\d+/);
  }
});

test("DOWN stays unavailable while successful checks accumulate", () => {
  const {api} = page();
  assert.equal(api.serverStatus({status: "DOWN"}).label, "Server unavailable");
  const recovering = api.serverStatus({status: "DOWN 1/2", check_status: "L7OK"});
  assert.equal(recovering.label, "Unavailable · recovering");
  assert.equal(recovering.tone, "rt-down");
});

test("a completed healthy check is green and an in-progress check is not a failure", () => {
  const {api} = page();
  for (const check_status of ["L7OK", "* L7OK"]) {
    const state = api.serverStatus({status: "UP", check_status});
    assert.equal(state.label, "Server available");
    assert.equal(state.tone, "rt-ready");
    assert.equal(state.failure, "");
  }
});

test("maintenance, drain, missing and unknown states cannot be presented as healthy", () => {
  const {api} = page();
  assert.equal(api.serverStatus({status: "UP", admin_state: "maint"}).label, "Maintenance");
  assert.equal(api.serverStatus({status: "UP", admin_state: "drain"}).label, "Drain");
  for (const status of ["NOLB", "no check", "", "unexpected"]) {
    assert.notEqual(api.serverStatus({status}).tone, "rt-ready");
  }
});

test("the row shows Russian availability and cause, retaining raw status only in its explanation", () => {
  const {api, requests} = page();
  const row = api.renderServer({backend: "be_rdg"}, {server: "backup1", status: "UP 1/3",
    admin_state: "ready", check_status: "L6TOUT", weight: 100, sessions: 0});
  const state = row.children[1];
  assert.equal(state.children[0].textContent, "Доступен · сбои проверок");
  assert.equal(state.children[1].textContent, "Проверка: таймаут TLS-рукопожатия");
  assert.match(state.children[0].title, /UP 1\/3/);
  assert.match(state.children[0].title, /не к количеству бэкендов/);
  assert.equal(requests(), 0);
  const healthy = api.renderServer({backend: "be_rdg"}, {server: "srv1", status: "UP", check_status: "L7OK"});
  assert.equal(healthy.children[1].children[0].textContent, "Доступен");
});

test("all health-check explanations have Russian translations", () => {
  const {api, catalogue} = page();
  for (const value of Object.values(api.CHECK_FAILURES)) assert.ok(catalogue[value], value);
});
