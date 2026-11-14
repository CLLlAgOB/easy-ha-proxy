"use strict";
const test = require("node:test"), assert = require("node:assert/strict");
const create = require("../../docker/app/haproxy_admin/static/js/server_time.js");
const msk = create({zone: "Europe/Moscow"}, "en-GB");

test("server zone formats UTC backups, native timers and calendar filters consistently", () => {
  const original = process.env.TZ;
  try {
    for (const browser of ["America/Los_Angeles", "Europe/Warsaw", "UTC"]) {
      process.env.TZ = browser;
      assert.equal(msk.time("2026-11-07T00:20:25.949503+00:00"), "03:20:25");
      assert.equal(msk.time("20261107T002025Z"), "03:20:25");
      assert.equal(msk.parse("2026-11-07T03:20:25.949503").toISOString(), "2026-11-07T00:20:25.949Z");
      assert.equal(msk.parse("Sun 2026-11-08 03:39:53 MSK").toISOString(), "2026-11-08T00:39:53.000Z");
      assert.equal(msk.parse("Sun 2026-11-08 00:39:53 UTC").toISOString(), "2026-11-08T00:39:53.000Z");
      assert.equal(msk.toLocalInput(Date.parse("2026-11-07T00:20:00Z")), "2026-11-07T03:20");
      assert.equal(msk.fromLocalInput("2026-11-07T03:20"), Date.parse("2026-11-07T00:20:00Z"));
    }
  } finally { if (original === undefined) delete process.env.TZ; else process.env.TZ = original; }
});
test("calendar validation rejects impossible days and nonexistent DST hours", () => {
  const warsaw = create({zone: "Europe/Warsaw"});
  for (const value of ["2026-02-30T03:20", "2026-01-01T24:00", "2026-03-29T02:30", "wrong"]) assert.equal(warsaw.fromLocalInput(value), null);
  assert.equal(warsaw.fromLocalInput("2026-10-25T02:30"), Date.parse("2026-10-25T00:30Z"));
  assert.equal(warsaw.fromLocalInput("2026-03-29T03:30"), Date.parse("2026-03-29T01:30Z"));
});
test("invalid zones and absent instants have explicit fallbacks", () => {
  const utc = create({zone: "invalid-zone"}, "en-GB");
  assert.equal(utc.zone, "UTC"); assert.equal(utc.dateTime(null), "—");
  assert.equal(utc.dateTime("n/a"), "—"); assert.equal(msk.dateTime("2026-11-07").slice(0, 8), "07/11/20");
});
test("a date on the other side of midnight uses the server calendar date", () => {
  assert.equal(msk.date("2026-11-07T22:30:00Z"), "08/11/2026");
});
