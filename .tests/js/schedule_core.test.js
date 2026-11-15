"use strict";
const test = require("node:test"), assert = require("node:assert/strict");
const create = require("../../docker/app/haproxy_admin/static/js/server_time.js");
const {build} = require("../../docker/app/haproxy_admin/static/js/schedule_core.js");

test("one maintenance window replaces individual installation restart and reboot schedules", () => {
  const now = Date.parse("2026-11-08T00:00:00Z");
  const clock = {
    parse: (v) => new Date(v),
    toLocalInput: (v) => new Date(v).toISOString().slice(0, 16),
    fromLocalInput: (v) => Date.parse(v + "Z")
  };
  const result = build({updates: {settings: {auto_check_hours: 0, auto_install: {enabled: true, unified: true, start: 1, end: 2}}},
    security: {available: true, policy: {mode: "daily", start: 3, interval: 4}, schedule: {next_install: "2026-11-08T03:00:00Z"},
      service_restarts: {available: true, enabled: true, next_window: "2026-11-08T04:00:00Z"},
      automatic_reboot: {enabled: true, next_window: "2026-11-08T05:00:00Z"}}}, clock, now);
  assert.deepEqual(result.tasks.map((item) => item.id), ["project-install"]);
  assert.equal(result.tasks[0].label, "Unified software maintenance");
  assert.equal(result.tasks[0].start, Date.parse("2026-11-08T01:00:00Z"));
  assert.equal(result.tasks[0].end, Date.parse("2026-11-08T02:00:00Z"));
  assert.equal(result.maintenance.state, "enabled");
  assert.equal(result.maintenance.hours, "01:00–02:00");
});
const clock = create({zone: "Europe/Moscow"}, "en-GB");
const now = Date.parse("2026-11-07T21:00:00Z"); // midnight MSK
test("saving unified consent during a window displays the next full window", () => {
  const during = Date.parse("2026-11-08T01:30:00+03:00");
  const result = build({updates: {settings: {auto_install: {enabled: true, unified: true,
    start: 1, end: 2, updated_at: during / 1000}}}}, clock, during);
  const install = result.tasks.find((task) => task.id === "project-install");
  assert.equal(install.start, Date.parse("2026-11-09T01:00:00+03:00"));
  assert.equal(install.end, Date.parse("2026-11-09T02:00:00+03:00"));
  assert.equal(result.maintenance.state, "enabled");
  assert.equal(result.maintenance.next.opened, install.start);
});
const security = {available: true, policy: {mode: "daily", start: 2, end: 3, interval: 2},
  schedule: {next_check: now / 1000 + 1800, next_install: "2026-11-08T02:00:00+03:00"},
  automatic_reboot: {available: true, enabled: true, next_window: "2026-11-08T03:00:00+03:00"}};
test("a saved disabled common window remains visible without inventing a scheduled run", () => {
  const result = build({updates: {settings: {auto_install: {enabled: false, unified: true, start: 1, end: 2}}}, security}, clock, now);
  assert.deepEqual(result.maintenance, {state: "disabled", hours: "01:00–02:00", next: null});
  assert.deepEqual(result.tasks, []);
  assert(result.disabled.some((item) => item.label === "Unified software maintenance"));
  assert(!result.disabled.some((item) => item.label === "Project update installation"));
  // Drawn greyed on the chart at its configured hours, never as a start.
  assert.equal(result.inactive.length, 1);
  assert.equal(result.inactive[0].label, "Unified software maintenance");
  assert.equal(clock.time(result.inactive[0].end), "02:00:00");
  assert.match(result.inactive[0].condition, /nothing starts/);
  assert.match(result.disabled.find((item) => item.label === "Unified software maintenance").condition, /paused/);
});
test("an enabled or separate schedule has nothing greyed", () => {
  assert.deepEqual(build({updates: {settings: {auto_install: {enabled: true, unified: true, start: 1, end: 2}}}}, clock, now).inactive, []);
  assert.deepEqual(build({updates: {settings: {auto_install: {enabled: false, unified: false, start: 1, end: 2}}}}, clock, now).inactive, []);
});
test("the common window is still shown when update status fails but security status succeeds", () => {
  const result = build({security: {...security, maintenance_window: {
    enabled: true, start: 1, end: 2, updated_at: 1
  }}}, clock, now);
  assert.equal(result.maintenance.hours, "01:00–02:00");
  assert.equal(result.maintenance.state, "enabled");
  assert.deepEqual(result.tasks.map((task) => task.label), ["Unified software maintenance"]);
});
test("an explicit separate-schedule setting takes priority over a stale security response", () => {
  const result = build({updates: {settings: {auto_install: {enabled: true, unified: false, start: 1, end: 2}}},
    security: {...security, maintenance_window: {enabled: true, start: 3, end: 4}}}, clock, now);
  assert.equal(result.maintenance.state, "separate");
  assert.equal(result.maintenance.hours, null);
  assert(result.tasks.some((task) => task.label === "Project update installation"));
  assert(!result.tasks.some((task) => task.label === "Unified software maintenance"));
});
test("an open cross-midnight common window retains its full hours and opening instant", () => {
  const result = build({updates: {settings: {auto_install: {enabled: true, unified: true, start: 23, end: 2}}}}, clock, now);
  assert.equal(result.maintenance.hours, "23:00–02:00");
  assert.equal(result.maintenance.state, "open");
  assert.equal(result.maintenance.next.opened, Date.parse("2026-11-07T23:00:00+03:00"));
  assert.equal(result.tasks[0].start, now);
  assert.equal(clock.time(result.maintenance.next.end), "02:00:00");
});
test("missing or invalid common settings do not fabricate a window", () => {
  assert.equal(build({}, clock, now).maintenance.state, "unavailable");
  const result = build({updates: {settings: {auto_install: {enabled: true, unified: true, start: 1, end: 1}}}}, clock, now);
  assert.equal(result.maintenance.state, "invalid");
  assert.equal(result.maintenance.hours, null);
  assert.deepEqual(result.tasks, []);
});
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
test("project installation says when it takes the operating-system packages too", () => {
  const settings = (os) => ({updates: {settings: {auto_check_hours: 0, auto_install: {enabled: true, start: 23, end: 2, os}}}});
  const condition = (os) => build(settings(os), clock, now).tasks.find((v) => v.id === "project-install").condition;
  assert.match(condition(false), /verified updates only/);
  assert.match(condition(true), /verified updates and operating-system packages/);
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
