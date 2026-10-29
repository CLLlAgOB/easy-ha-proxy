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
