/* The nightly schedule.
 *
 * The daemon and the systemd timer have both been in place since the
 * destinations were built; this is the part that lets anyone turn them on.
 * The passphrase field starts empty and an empty field means "keep the one
 * already stored", the same rule the destination keys follow.
 */
(function () {
  "use strict";

  const t = window.t || ((value) => String(value));
  const clock = window.EasyHaProxyTime;
  let dirty = false;

  function byId(id) {
    return document.getElementById(id);
  }

  function csrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute("content") || "" : "";
  }

  async function api(path, body) {
    const options = {
      headers: { Accept: "application/json" },
      credentials: "same-origin"
    };
    if (body !== undefined) {
      options.method = "POST";
      options.headers["Content-Type"] = "application/json";
      options.headers["X-CSRFToken"] = csrfToken();
      options.body = JSON.stringify(body);
    }
    const response = await fetch(`/system/backups${path}`, options);
    const payload = await response.json().catch(() => ({}));
    return { ok: response.ok && payload.ok !== false, payload };
  }

  function status(message) {
    const element = byId("schedule-status");
    if (element) element.textContent = message || "";
  }

  function reason(payload, fallback) {
    return payload.error || payload.description || t(fallback);
  }

  function chosen() {
    return Array.from(
      document.querySelectorAll("#schedule-destinations input:checked")
    ).map((input) => input.value);
  }

  function renderDestinations(destinations, selected) {
    const holder = byId("schedule-destinations");
    holder.textContent = "";
    if (!destinations.length) {
      const empty = document.createElement("p");
      empty.className = "muted";
      empty.textContent = t("Add a destination first, then choose it here.");
      holder.appendChild(empty);
      return;
    }
    destinations.forEach((destination) => {
      const label = document.createElement("label");
      label.className = "form-check";
      const input = document.createElement("input");
      input.type = "checkbox";
      input.value = destination.name;
      input.checked = selected.indexOf(destination.name) !== -1;
      label.appendChild(input);
      label.appendChild(
        document.createTextNode(` ${destination.name} — ${describe(destination)}`)
      );
      holder.appendChild(label);
    });
  }

  function describe(destination) {
    if (destination.type === "s3") {
      return `${destination.bucket || "?"}${destination.prefix ? "/" + destination.prefix : ""}`;
    }
    const port = destination.port && destination.port !== 22 ? `:${destination.port}` : "";
    return `${destination.user || "?"}@${destination.host || "?"}${port}${destination.path || ""}`;
  }

  function renderSchedule(schedule) {
    if (!dirty) {
      byId("schedule-enabled").checked = Boolean(schedule.enabled);
      byId("schedule-quiesce").checked = schedule.quiesce !== false;
      byId("schedule-include-ssh").checked = Boolean(schedule.include_ssh);
      if (schedule.time) byId("schedule-time").value = schedule.time;
      if (schedule.keep_local) byId("schedule-keep-local").value = String(schedule.keep_local);
    }
    const timer = schedule.timer || {};
    byId("schedule-next-run").textContent = schedule.enabled
      ? clock.dateTime(timer.next_run_at ? timer.next_run_at * 1000 : schedule.next_run) : t("Disabled");
    byId("schedule-last-run").textContent = clock.dateTime(schedule.last_run);
    byId("schedule-last-result").textContent = schedule.last_result || "—";
    byId("schedule-passphrase-state").textContent = schedule.passphrase_stored
      ? t("yes")
      : t("no — the schedule cannot run without one");
    byId("schedule-jitter").textContent = Number.isFinite(timer.random_delay_seconds)
      ? t("Start may be delayed by up to {minutes} minutes.", {minutes: timer.random_delay_seconds / 60}) : "";
    const others = byId("schedule-other-timers"); others.replaceChildren();
    for (const item of schedule.other_timers || []) {
      const row = document.createElement("li");
      row.textContent = `${item.unit} · ${clock.dateTime(item.next_run_at ? item.next_run_at * 1000 : item.next_run)}`;
      others.append(row);
    }
    byId("schedule-other-details").hidden = !others.childElementCount;
  }

  async function refresh() {
    const [scheduleReply, destinationReply] = await Promise.all([
      api("/api/schedule"),
      api("/api/destinations")
    ]);
    if (!scheduleReply.ok) {
      status(reason(scheduleReply.payload, "The backup service is not answering"));
      return;
    }
    const schedule = scheduleReply.payload.schedule || {};
    renderSchedule(schedule);
    if (!dirty) renderDestinations(
      (destinationReply.payload || {}).destinations || [],
      schedule.destinations || []
    );
  }

  async function save(event) {
    event.preventDefault();
    const body = {
      enabled: byId("schedule-enabled").checked,
      destinations: chosen(),
      time: byId("schedule-time").value,
      quiesce: byId("schedule-quiesce").checked,
      include_ssh: byId("schedule-include-ssh").checked,
      keep_local: Number(byId("schedule-keep-local").value)
    };
    const passphrase = byId("schedule-passphrase").value;
    // Empty means keep the stored one, so it must not be sent at all: an
    // empty string is how the daemon is told to forget it.
    if (passphrase) body.passphrase = passphrase;

    status(t("Saving…"));
    const { ok, payload } = await api("/api/schedule", body);
    if (!ok) {
      status(reason(payload, "It was not saved"));
      return;
    }
    byId("schedule-passphrase").value = "";
    dirty = false;
    status(t("Saved"));
    renderSchedule(payload.schedule || {});
    await refresh();
  }

  async function runNow() {
    const button = byId("schedule-run");
    button.disabled = true;
    status(t("Running. A full backup and its upload can take several minutes."));
    const { ok, payload } = await api("/api/schedule/run", {});
    button.disabled = false;
    if (!ok) {
      status(reason(payload, "It did not run"));
      return;
    }
    if (payload.skipped) {
      status(payload.skipped);
    } else {
      const uploads = (payload.uploads || []).length;
      status(
        t("Done. The archive was copied to N destination(s).").replace(
          "N",
          String(uploads)
        )
      );
    }
    refresh();
  }

  document.addEventListener("DOMContentLoaded", () => {
    const form = byId("backup-schedule-form");
    if (form) form.addEventListener("input", () => { dirty = true; });
    if (form) setInterval(refresh, 30000);
    if (!form) return;
    form.addEventListener("submit", save);
    byId("schedule-run").addEventListener("click", runNow);
    refresh();
  });
})();
