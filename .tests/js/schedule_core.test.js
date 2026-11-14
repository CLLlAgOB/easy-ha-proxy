"use strict";
const test = require("node:test"), assert = require("node:assert/strict");
const create = require("../../docker/app/haproxy_admin/static/js/server_time.js");
const {build} = require("../../docker/app/haproxy_admin/static/js/schedule_core.js");
const clock = create({zone: "Europe/Moscow"}, "en-GB");
const now = Date.parse("2026-11-07T21:00:00Z"); // midnight MSK
const security = {available: true, policy: {mode: "daily", start: 2, end: 3, interval: 2},
  schedule: {next_check: now / 1000 + 1800, next_install: "2026-11-08T02:00:00+03:00"},
  automatic_reboot: {available: true, enabled: true, next_window: "2026-11-08T03:00:00+03:00"}};
test("disabled panel backups do not turn an inert timer firing into a backup", () => {
  const result = build({backups: {schedule: {enabled: false, timer: {next_run_at: now / 1000 + 3600},
    other_timers: [{unit: "example-backup.timer", active: true, next_run_at: now / 1000 + 12000}]}}}, clock, now);
  assert.equal(result.tasks.length, 1); assert.equal(result.tasks[0].detail, "example-backup.timer");
  assert.equal(result.disabled[0].label, "Panel backup");
});
test("nightly order follows real instants, with conditional reboot and installation windows", () => {
  const result = build({security, backups: {schedule: {enabled: true, timer: {next_run_at: now / 1000 + 12000, random_delay_seconds: 1200}}}}, clock, now);
  assert.deepEqual(result.tasks.map((v) => v.id), ["security-check", "security-install", "reboot", "backup"]);
  assert.equal(clock.time(result.tasks[1].start), "02:00:00");
  assert.equal(clock.time(result.tasks[1].end), "03:00:00");
  assert.match(result.tasks[2].condition, /Only when Linux requires/);
  assert.match(result.tasks[3].condition, /20 minutes/);
});
test("project installation windows cross midnight in the server zone", () => {
  const result = build({updates: {settings: {auto_check_hours: 2, next_auto_check_at: "2026-11-08T01:00:00+03:00",
    auto_install: {enabled: true, start: 23, end: 2}}}}, clock, now);
  const install = result.tasks.find((v) => v.id === "project-install");
  assert.equal(install.start, now); assert.equal(clock.time(install.end), "02:00:00");
});
test("pending reboot shows its actual countdown, recovery hides security installation", () => {
  const result = build({security: {...security, recovery_required: true, automatic_reboot: {
    enabled: true, pending: {due_at: "2026-11-08T00:01:00+03:00"}}}}, clock, now);
  assert.deepEqual(result.tasks.map((v) => v.id), ["reboot"]);
  assert.equal(result.tasks[0].start, now + 60000);
});
test("missing services and unknown next starts do not fabricate scheduled runs", () => {
  assert.deepEqual(build({}, clock, now).tasks, []);
  const result = build({updates: {settings: {auto_check_hours: 4}}, backups: {schedule: {enabled: true}}}, clock, now);
  assert.equal(result.tasks.length, 0); assert(result.disabled.some((v) => /not been verified/.test(v.condition)));
});
test("native security and GeoIP preserve systemd's actual scheduled time", () => {
  const result = build({security: {available: true, policy: {mode: "system"}, live_settings: {
    automatic_install: true, next_run_at: now / 1000 + 3600}}, geoip: {timer: {
    active_state: "active", next_run_at: "Sun 2026-11-08 05:20:00 MSK"}}}, clock, now);
  assert.deepEqual(result.visible.map((v) => v.id), ["native-security", "geoip"]);
  assert.equal(clock.time(result.tasks[1].start), "05:20:00");
});
test("independent service restarts appear between installation and conditional reboot", () => {
  const result = build({security: {...security,
    service_restarts: {available: true, enabled: true, next_window: "2026-11-08T02:15:00+03:00"},
    automatic_reboot: {...security.automatic_reboot, allow_service_reboot: true}}}, clock, now);
  assert.deepEqual(result.tasks.map((task) => task.id), ["security-check", "security-install", "service-restarts", "reboot"]);
  assert.match(result.tasks[2].condition, /protected services remain deferred/);
  assert.match(result.tasks[3].condition, /verified deferred services/);
});
test("recovery or an unreadable restart policy never invents a service restart time", () => {
  for (const extra of [{recovery_required: true}, {service_restarts: {available: true, enabled: true, error: "invalid policy"}}]) {
    const result = build({security: {...security, service_restarts: {available: true, enabled: true, next_window: "2026-11-08T02:15:00+03:00"}, ...extra}}, clock, now);
    assert(!result.tasks.some((task) => task.id === "service-restarts"));
  }
});
