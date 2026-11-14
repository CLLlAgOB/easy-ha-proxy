/* Read-only projection of existing schedules. Times come from their owners;
 * installation windows are permissions, not promises of an exact start. */
(function (root, factory) {
  "use strict";
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.EasyHaProxySchedule = factory();
})(typeof window !== "undefined" ? window : globalThis, function () {
  "use strict";
  const HOUR = 3600000;
  function build(data, clock, now, translate) {
    const t = translate || ((text, params = {}) => text.replace(/\{(\w+)\}/g, (_, key) => params[key] ?? `{${key}}`));
    const tasks = [], disabled = [], until = now + 24 * HOUR;
    const stamp = (value) => clock.parse(value)?.getTime();
    const seconds = (value) => typeof value === "number" && value > 0 ? value * 1000 : null;
    function add(id, label, start, condition, page, end, detail) {
      if (!Number.isFinite(start)) {
        disabled.push({label: t(label), condition: t("Next start has not been verified"), page, detail}); return;
      }
      tasks.push({id, label: t(label), start, end: end > start ? end : null, condition, page, detail});
    }
    function off(label, page, condition = "Disabled") { disabled.push({label: t(label), page, condition: t(condition)}); }
    // Calendar arithmetic is done in the server's named zone, including
    // windows crossing midnight and changes of UTC offset.
    function windowFor(startHour, endHour, after = now) {
      if (![startHour, endHour].every((h) => Number.isInteger(h) && h >= 0 && h <= 23) || startHour === endHour) return null;
      const day = clock.toLocalInput(after).slice(0, 10);
      const dayAt = (offset) => new Date(Date.parse(day + "T12:00:00Z") + offset * 86400000).toISOString().slice(0, 10);
      const at = (offset, hour) => clock.fromLocalInput(`${dayAt(offset)}T${String(hour).padStart(2, "0")}:00`);
      for (let offset = -1; offset <= 2; offset++) {
        const start = at(offset, startHour), end = at(offset + (endHour <= startHour ? 1 : 0), endHour);
        if (start !== null && end !== null && end > after) return {start: Math.max(start, after), end};
      }
      return null;
    }
    const u = data.updates;
    if (u) {
      const settings = u.settings || {};
      if (settings.auto_check_hours > 0) add("project-check", "Project update check", stamp(settings.next_auto_check_at),
        t("Every {hours} hours", {hours: settings.auto_check_hours}), "updates");
      else off("Project update check", "updates", settings.auto_check_hours === 0 ? "Disabled" : "Next start has not been verified");
      const install = settings.auto_install;
      if (install?.enabled) {
        const window = windowFor(install.start, install.end);
        add("project-install", "Project update installation", window?.start, t("Allowed window; verified updates only"), "updates", window?.end);
      } else off("Project update installation", "updates", install ? "Disabled" : "Next start has not been verified");
    }
    const b = data.backups?.schedule;
    if (b) {
      const timer = b.timer || {};
      if (b.enabled) add("backup", "Panel backup", seconds(timer.next_run_at) || stamp(b.next_run),
        Number.isFinite(timer.random_delay_seconds) ? t("Systemd timer; delay up to {minutes} minutes", {minutes: timer.random_delay_seconds / 60}) : t("Systemd timer"), "backups");
      else off("Panel backup", "backups");
      for (const item of (b.other_timers || []).slice(0, 8)) if (item.active) {
        add("backup-" + item.unit, "Other backup timer", seconds(item.next_run_at) || stamp(item.next_run),
          t("Managed separately in Linux"), "backups", null, item.unit);
      }
      if (!b.timer) off("Other backup timers", "backups", "Update host services to discover other backup timers");
    }
    const s = data.security;
    if (s) {
      const policy = s.policy || {}, schedule = s.schedule || {}, reboot = s.automatic_reboot;
      if (!s.available || s.recovery_required || s.configuring) off("OS security maintenance", "security", "Security schedule is not ready");
      else if (policy.mode === "system") {
        const live = s.live_settings;
        if (live && !live.error && live.automatic_install) add("native-security", "Native Linux security installation",
          seconds(live.next_run_at) || stamp(live.next_run), t("Native Linux schedule; available fixes only"), "security");
        else off("Native Linux security installation", "security", live && !live.error ? "Disabled" : "Next start has not been verified");
      } else {
        add("security-check", policy.mode === "auto" ? "OS security check and installation" : "OS security check",
          seconds(schedule.next_check), t("Every {hours} hours", {hours: policy.interval}) + (policy.mode === "auto" ? " · " + t("Available security fixes only") : ""), "security");
        if (["daily", "window"].includes(policy.mode)) {
          const next = stamp(schedule.next_install);
          const window = Number.isFinite(next) ? windowFor(policy.start, policy.mode === "daily" ? (policy.start + 1) % 24 : policy.end, next) : null;
          add("security-install", "OS security installation", next, t("Allowed window; available security fixes only"), "security", window?.end);
        }
      }
      const restarts = s.service_restarts;
      if (restarts) {
        if (!restarts.available || restarts.error || s.recovery_required || s.configuring || policy.mode === "system")
          off("Scheduled service restarts", "security", "Security schedule is not ready");
        else if (restarts.enabled) add("service-restarts", "Scheduled service restarts", stamp(restarts.next_window),
          t("Pending services only; protected services remain deferred"), "security");
        else off("Scheduled service restarts", "security");
      }
      if (reboot?.pending) add("reboot", "Server reboot", stamp(reboot.pending.due_at), t("Reboot countdown is active"), "security");
      else if (reboot?.enabled) add("reboot", "Server reboot", stamp(reboot.next_window), t(reboot.allow_service_reboot
        ? "Linux requirement or verified deferred services; then a 60-second countdown"
        : "Only when Linux requires a reboot; then a 60-second countdown"), "security");
      else off("Server reboot", "security", reboot?.available ? "Disabled" : "Next start has not been verified");
    }
    const g = data.geoip?.timer;
    if (g) {
      if (g.enabled !== false && g.active_state === "active") add("geoip", "GeoIP database update", stamp(g.next_run_at), t("Systemd timer"), "geoip");
      else off("GeoIP database update", "geoip");
    }
    tasks.sort((a, b) => a.start - b.start || a.id.localeCompare(b.id));
    return {tasks, visible: tasks.filter((task) => task.start < until && (task.end || task.start) >= now - 60000), disabled, now, until};
  }
  return {build};
});
