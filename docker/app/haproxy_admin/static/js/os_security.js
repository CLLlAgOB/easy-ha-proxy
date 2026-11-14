/* Durable, one-shot OS security actions. A lost reply is reconciled by GET;
 * neither polling nor a page reload re-sends a host mutation. */
(function () {
  "use strict";
  const app = document.getElementById("os-security-app");
  if (!app) return;
  const t = window.t || ((value) => String(value));
  const el = (name) => document.getElementById("oss-" + name);
  const KEY = "easy_ha_proxy_os_security_start";
  let snapshot = null, running = false, sending = false, dirty = false, timer = null, pending = null;
  let selectedJob = "", logText = "", submittedPolicyJob = "";
  let rebootDirty = false, rebootSending = false, rebootPending = null;
  const REBOOT_KEY = "easy_ha_proxy_auto_reboot_pending";
  let restartsDirty = false, restartsSending = false, restartsPending = null;
  const RESTARTS_KEY = "easy_ha_proxy_service_restarts_pending";
  function storeRestarts(value) {
    restartsPending = value;
    try { if (value) sessionStorage.setItem(RESTARTS_KEY, JSON.stringify(value)); else sessionStorage.removeItem(RESTARTS_KEY); } catch (_) { /* private browsing */ }
  }
  try { const value = JSON.parse(sessionStorage.getItem(RESTARTS_KEY) || "null"); if (value && typeof value.boot_id === "string" && Number.isFinite(value.started)) restartsPending = value; } catch (_) { storeRestarts(null); }
  function storeReboot(value) {
    rebootPending = value;
    try { if (value) sessionStorage.setItem(REBOOT_KEY, JSON.stringify(value)); else sessionStorage.removeItem(REBOOT_KEY); } catch (_) { /* private browsing */ }
  }
  try { const value = JSON.parse(sessionStorage.getItem(REBOOT_KEY) || "null"); if (value && typeof value.boot_id === "string" && Number.isFinite(value.started)) rebootPending = value; } catch (_) { storeReboot(null); }
  const known = new Set();
  const labels = {"security-check": "Security update check", "security-configure": "Security policy change",
    "security-install": "Security update installation", "security-cycle": "Scheduled security maintenance",
    "security-restart-check": "Service restart check", "security-restart": "Service restarts", "security-restart-cycle": "Scheduled service restarts"};
  const modeLabels = {system: "Existing Linux settings", notify: "Notify only", auto: "Automatically after each check",
    window: "Automatically in a time window", daily: "Every day at a set time"};
  const hour = (value) => String(value).padStart(2, "0") + ":00";
  const terminal = (job) => ["completed", "failed", "interrupted"].includes(job?.status);
  const date = (stamp) => stamp ? window.EasyHaProxyTime.dateTime(typeof stamp === "number" ? stamp * 1000 : stamp) : t("Never");
  function store(value) {
    pending = value;
    try { if (value) sessionStorage.setItem(KEY, JSON.stringify(value)); else sessionStorage.removeItem(KEY); } catch (_) { /* private browsing */ }
  }
  try {
    const saved = JSON.parse(sessionStorage.getItem(KEY) || "null");
    if (saved && Object.keys(labels).includes(saved.operation) && Number.isFinite(saved.started) && Array.isArray(saved.known)) pending = saved;
  } catch (_) { store(null); }
  function message(text, error = false) {
    el("message").textContent = t(text);
    el("message").classList.toggle("text-danger", error);
  }
  async function api(kind, body, jobId = "") {
    const response = await fetch(app.dataset[kind + "Url"] + (jobId ? "?job_id=" + encodeURIComponent(jobId) : ""), {
      method: body === undefined ? "GET" : "POST", credentials: "same-origin",
      headers: {Accept: "application/json", "Content-Type": "application/json",
        "X-CSRFToken": document.querySelector('meta[name="csrf-token"]')?.content || ""},
      ...(body === undefined ? {} : {body: JSON.stringify(body)})
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok || data.ok !== true) {
      const error = new Error(data.error || `HTTP ${response.status}`);
      error.transient = [502, 503, 504].includes(response.status);
      throw error;
    }
    return data;
  }
  function controls() {
    const blocked = sending || running || Boolean(pending) || restartsSending || Boolean(restartsPending) || rebootSending || Boolean(rebootPending) || !snapshot?.available || Boolean(snapshot?.automatic_reboot?.pending);
    const recovery = Boolean(snapshot?.recovery_required);
    el("mode").querySelector('option[value="daily"]').disabled = snapshot?.daily_supported !== true;
    const daily = el("mode").value === "daily";
    el("hours").hidden = !["window", "daily"].includes(el("mode").value);
    el("hours").classList.toggle("is-daily", daily);
    el("end-label").hidden = daily;
    el("daily-note").hidden = !daily;
    el("start-label").textContent = t(daily ? "Install at (server time)" : "Install from");
    el("interval").disabled = el("mode").value === "system" || blocked;
    el("mode").disabled = blocked;
    el("start").disabled = blocked; el("end").disabled = blocked;
    el("check").disabled = blocked || recovery;
    el("save").disabled = blocked || (recovery && el("mode").value !== "system");
    el("restore").hidden = !recovery;
    el("restore").disabled = blocked;
    el("unsaved").textContent = dirty ? t("Changes have not been saved.") : "";
    el("install").disabled = blocked || recovery || snapshot?.policy?.mode === "system" || !snapshot?.status?.eligible_count;
    const reboot = snapshot?.automatic_reboot;
    const rebootBlocked = rebootSending || Boolean(rebootPending) || restartsSending || Boolean(restartsPending) || sending || running || Boolean(pending) || !reboot?.available;
    el("reboot-enabled").disabled = rebootBlocked;
    el("reboot-enabled").querySelector('option[value="1"]').disabled = snapshot?.policy?.mode === "system";
    el("reboot-time").disabled = rebootBlocked || el("reboot-enabled").value === "0";
    el("reboot-services").disabled = rebootBlocked || el("reboot-enabled").value === "0";
    el("reboot-save").disabled = rebootBlocked || !rebootDirty;
    el("reboot-unsaved").textContent = rebootDirty ? t("Changes have not been saved.") : "";
    el("reboot-cancel").hidden = !reboot?.pending;
    el("reboot-cancel").disabled = rebootSending || Boolean(rebootPending) || sending || running;
    el("reboot-mode-note").hidden = snapshot?.policy?.mode !== "system";
    const restartsBlocked = blocked || !snapshot?.service_restarts?.available;
    el("restarts-enabled").disabled = restartsBlocked;
    el("restarts-enabled").querySelector('option[value="1"]').disabled = snapshot?.policy?.mode === "system";
    el("restarts-time").disabled = restartsBlocked || el("restarts-enabled").value === "0";
    el("restarts-save").disabled = restartsBlocked || !restartsDirty;
    el("restart-check").disabled = restartsBlocked || recovery;
    el("restart-now").disabled = restartsBlocked || recovery || snapshot?.policy?.mode === "system" || !snapshot?.status?.restart?.services?.length;
    el("restarts-unsaved").textContent = restartsDirty ? t("Changes have not been saved.") : "";
  }
  function currentSettings() {
    const policy = snapshot.policy || {}, live = snapshot.live_settings, schedule = snapshot.schedule || {};
    const verified = live && !live.error;
    el("settings-read").textContent = verified ? t("Linux settings read") + ": " + date(live.checked_at) : "";
    el("live-error").textContent = t(live?.error || (!live ? "Update host services to read current Linux settings" : ""));
    el("current-mode").textContent = t(snapshot.configuring ? "Applying security settings…" : snapshot.recovery_required
      ? "Security policy needs recovery" : modeLabels[policy.mode] || "Unknown");
    el("current-check").textContent = policy.mode === "system"
      ? verified ? (live.periodic_enabled && live.lists_interval !== "0" ? t("Every {days} days").replace("{days}", live.lists_interval) : t("Off")) : t("Unknown")
      : t("Every {hours} hours").replace("{hours}", policy.interval);
    const nativeSchedule = verified ? (live.calendar || []).map((value) => value.trim()).join(" / ") : "";
    const dailyNative = nativeSchedule.match(/^\*-\*-\* (\d{2}:\d{2})(?::00)?$/);
    let nativeSummary = dailyNative ? t("Every day at {time}").replace("{time}", dailyNative[1]) : t("Native Linux schedule");
    if (verified && live.upgrade_interval !== "1") nativeSummary += " · " + t("Installation interval: {days} days").replace("{days}", live.upgrade_interval);
    if (verified && live.random_delay && !["0", "0s"].includes(live.random_delay)) nativeSummary += " · " + t("Delay up to {delay}").replace("{delay}", live.random_delay);
    el("current-install").textContent = policy.mode === "system" ? (verified ? live.automatic_install ? nativeSummary : t("Off") : t("Unknown"))
      : policy.mode === "daily" ? t("Every day at {time}").replace("{time}", hour(policy.start))
        : policy.mode === "window" ? hour(policy.start) + " – " + hour(policy.end) : t(modeLabels[policy.mode] || "Unknown");
    el("next-install").textContent = snapshot.configuring || snapshot.recovery_required ? "—" : policy.mode === "system"
      ? (verified && live.automatic_install ? window.EasyHaProxyTime.dateTime(live.next_run_at ? live.next_run_at * 1000 : live.next_run) : "—")
      : schedule.next_install ? date(schedule.next_install) : policy.mode === "auto" ? date(schedule.next_check) : "—";
    // This value always comes from effective Linux configuration, even during
    // a partially applied policy. Never present the intended value as actual.
    el("current-reboot").textContent = snapshot.automatic_reboot?.error ? t("Unknown") : snapshot.automatic_reboot?.enabled
      ? t("When required at {time}").replace("{time}", snapshot.automatic_reboot.time)
      : verified ? t(live.automatic_reboot ? "On" : "Off") : t("Unknown");
    el("current-restarts").textContent = snapshot.service_restarts?.error ? t("Unknown") : snapshot.service_restarts?.enabled
      ? t("Every day at {time}").replace("{time}", snapshot.service_restarts.time) : t("Notify only");
    el("native-reboot").textContent = verified ? t(live.automatic_reboot ? "On" : "Off") : t("Unknown");
    el("native-auto").textContent = verified ? t(live.automatic_install ? "On" : "Off") : t("Unknown");
    el("native-interval").textContent = verified ? live.upgrade_interval : "—";
    el("native-calendar").textContent = nativeSchedule || "—";
    el("native-delay").textContent = verified ? live.random_delay || "—" : "—";
  }
  function rebootMessage(text, error = false) {
    el("reboot-message").textContent = t(text);
    el("reboot-message").classList.toggle("text-danger", error);
  }
  function renderReboot() {
    const reboot = snapshot.automatic_reboot || {};
    if (rebootPending) {
      const sameBoot = rebootPending.boot_id === snapshot.boot_id;
      const saved = rebootPending.cancel ? !reboot.pending : reboot.enabled === rebootPending.enabled && reboot.time === rebootPending.time && Boolean(reboot.allow_service_reboot) === Boolean(rebootPending.allow_service_reboot);
      if (!sameBoot || saved) {
        rebootMessage(!sameBoot ? "The server boot changed; current reboot settings were reloaded."
          : rebootPending.cancel ? "Reboot canceled." : "Reboot settings saved.");
        rebootDirty = false; storeReboot(null);
      } else if (Date.now() - rebootPending.started > 15000) {
        storeReboot(null); rebootMessage("The requested reboot change was not confirmed. Review the current settings before trying again.", true);
      }
    }
    if (!rebootDirty && !rebootSending && !rebootPending) {
      el("reboot-enabled").value = reboot.enabled ? "1" : "0";
      el("reboot-time").value = reboot.time || "03:00";
      el("reboot-services").checked = reboot.allow_service_reboot === true;
    }
    el("reboot-timezone").textContent = snapshot.server_timezone || "—";
    el("reboot-required").textContent = t(reboot.required === true ? "Yes" : reboot.required === false ? "No" : "Unknown");
    el("reboot-next").textContent = reboot.next_window ? date(reboot.next_window) : "—";
    const at = reboot.pending?.due_at;
    el("reboot-state").textContent = reboot.error ? t(reboot.error) : !reboot.available ? t("Update host services before configuring automatic reboots")
      : reboot.pending ? t("A reboot is pending for {time}. It can still be canceled.").replace("{time}", date(at))
        : reboot.attempt?.state === "deferred" ? t("The reboot was deferred because maintenance could not finish safely.") + " " + t(reboot.attempt.error || "")
          : reboot.attempt?.state === "canceled" ? t("The automatic reboot was canceled for this time window.")
            : reboot.enabled ? t(reboot.allow_service_reboot ? "Scheduled reboots also cover verified deferred services after successful restart maintenance."
              : "The server reboots in the selected window only if Linux requires it.") : t("Scheduled reboots are off.");
    el("reboot-state").classList.toggle("text-danger", Boolean(reboot.error));
  }
  async function changeReboot(kind, body) {
    if (rebootSending || rebootPending) return;
    rebootSending = true;
    storeReboot({...body, cancel: kind === "rebootCancel", boot_id: snapshot.boot_id, started: Date.now()}); controls();
    try {
      await api(kind, {...body, expected_boot_id: snapshot.boot_id});
      rebootDirty = false; storeReboot(null); rebootMessage(kind === "rebootCancel" ? "Reboot canceled." : "Reboot settings saved.");
    } catch (error) {
      if (error.transient || error instanceof TypeError) rebootMessage("The reply was lost. Reading the current reboot settings without repeating the request…");
      else { storeReboot(null); rebootMessage(error.message, true); }
    } finally { rebootSending = false; await poll(); }
  }
  function restartsMessage(text, error = false) {
    el("restarts-message").textContent = t(text);
    el("restarts-message").classList.toggle("text-danger", error);
  }
  function renderRestarts() {
    const restarts = snapshot.service_restarts || {}, status = restarts.status || {};
    if (restartsPending) {
      const sameBoot = restartsPending.boot_id === snapshot.boot_id;
      if (!sameBoot || (restarts.enabled === restartsPending.enabled && restarts.time === restartsPending.time)) {
        restartsMessage(!sameBoot ? "The server boot changed; current service restart settings were reloaded." : "Service restart settings saved.");
        restartsDirty = false; storeRestarts(null);
      } else if (Date.now() - restartsPending.started > 15000) {
        storeRestarts(null); restartsMessage("The requested service restart change was not confirmed. Review the current settings before trying again.", true);
      }
    }
    if (!restartsDirty && !restartsSending && !restartsPending) {
      el("restarts-enabled").value = restarts.enabled ? "1" : "0";
      el("restarts-time").value = restarts.time || "02:15";
    }
    el("restarts-timezone").textContent = snapshot.server_timezone || "—";
    el("restarts-next").textContent = restarts.next_window ? date(restarts.next_window) : "—";
    el("restarts-last").textContent = date(status.last_attempt);
    el("restarts-done").textContent = status.restarted ? String(status.restarted.length) : "—";
    el("restarts-state").textContent = t(restarts.error || status.error || (!restarts.available ? "Update host services before managing service restarts"
      : status.state === "running" ? "Service restart maintenance is running."
        : status.unresolved?.length ? "Some services remain unresolved. Automatic reboot fallback is blocked."
          : status.deferred?.length ? "Some services remain deliberately deferred. Review the service list and reboot policy."
            : status.state === "ready" ? "The last service restart run was verified." : "No service restart maintenance has run yet."));
    el("restarts-state").classList.toggle("text-danger", Boolean(restarts.error || status.error || status.unresolved?.length));
  }
  async function changeRestarts(body) {
    if (restartsSending || restartsPending) return;
    restartsSending = true;
    storeRestarts({...body, boot_id: snapshot.boot_id, started: Date.now()}); controls();
    try {
      await api("restartPolicy", {...body, expected_boot_id: snapshot.boot_id});
      restartsDirty = false; storeRestarts(null); restartsMessage("Service restart settings saved.");
    } catch (error) {
      if (error.transient || error instanceof TypeError) restartsMessage("The reply was lost. Reading the current service restart settings without repeating the request…");
      else { storeRestarts(null); restartsMessage(error.message, true); }
    } finally { restartsSending = false; await poll(); }
  }
  function render() {
    if (!snapshot) { controls(); return; }
    const policy = snapshot.policy || {}, status = snapshot.status || {};
    const jobs = snapshot.jobs || [], active = snapshot.active_job;
    running = Boolean(active && !terminal(active));
    if (submittedPolicyJob && jobs.some((job) => job.id === submittedPolicyJob && terminal(job))) {
      if (jobs.find((job) => job.id === submittedPolicyJob).status === "completed") dirty = false;
      submittedPolicyJob = "";
    }
    if (!dirty) for (const key of ["mode", "interval", "start", "end"]) if (policy[key] !== undefined) el(key).value = policy[key];
    el("checked").textContent = date(status.last_success);
    el("installed").textContent = date(status.last_install_attempt || status.last_install_at);
    el("count").textContent = status.state === "ready" && Number.isInteger(status.package_count) ? String(status.package_count) : "—";
    el("state").textContent = t(snapshot.configuring ? "Applying security settings…" : snapshot.recovery_required ? "Restore system management after the interrupted OS security policy change"
      : snapshot.error || status.error || (status.state === "ready" ? "Security package lists were checked successfully" : "Security update status has not been verified"));
    el("state").classList.toggle("text-danger", Boolean(snapshot.recovery_required || snapshot.error || status.state === "unknown"));
    el("native").textContent = snapshot.configuring || snapshot.recovery_required ? "" : t(policy.mode === "system"
      ? "The panel does not control automatic OS updates; existing system settings apply."
      : "The panel manages security updates. The native APT upgrade timer is paused.");
    const live = snapshot.live_settings;
    const drift = !snapshot.configuring && policy.mode !== "system" && live && !live.error &&
      (live.timer_active || live.upgrade_interval !== "0" || live.automatic_reboot || live.install_on_shutdown);
    if (drift) el("native").textContent = t("Linux update settings differ from the managed policy. Review the current settings before installing fixes.");
    el("native").classList.toggle("text-danger", Boolean(drift));
    currentSettings();
    renderReboot();
    renderRestarts();
    el("timezone").textContent = snapshot.server_timezone || "—";
    const tbody = el("packages"); tbody.replaceChildren();
    for (const row of status.packages || []) {
      const tr = document.createElement("tr");
      for (const value of [row.name, row.installed, row.candidate, t(row.protected ? "Controlled update required" : row.held ? "Package held by administrator" : "Ready for security installation")]) {
        const td = document.createElement("td"); td.textContent = String(value || "—"); tr.append(td);
      }
      tbody.append(tr);
    }
    el("package-note").textContent = t(status.state === "unknown" ? "The listed packages are from an earlier check; current security status is unknown."
      : status.package_count > 200 ? "Showing the first 200 security packages. The total includes all packages." : "");
    const restart = status.restart;
    el("restart").textContent = t(!restart ? "Not checked yet." : restart.error || (restart.reboot_required
      ? "A server reboot is required to activate installed updates." : restart.services?.length
        ? "Some services still use replaced files. Apply their controlled restart." : "No pending restart was found in the last check."));
    const actionLabels = {automatic: "Automatic restart in the maintenance window", protected: "Controlled maintenance required",
      deferred: "Deferred; scheduled reboot only with explicit permission", unknown: "Review this service before restarting it",
      unresolved: "Restart remains unresolved; automatic reboot fallback is blocked"};
    el("services").replaceChildren(...(restart?.services || []).map((service) => {
      const row = document.createElement("tr"), name = document.createElement("td"), action = document.createElement("td");
      name.textContent = service;
      const kind = snapshot.service_restarts?.status?.unresolved?.includes(service) ? "unresolved" : restart.details?.find((item) => item.service === service)?.kind;
      action.textContent = t(actionLabels[kind] || "Classification is checked before service restart maintenance");
      row.append(name, action); return row;
    }));
    if (pending) {
      const job = jobs.find((item) => item.operation === pending.operation && !pending.known.includes(item.id) &&
        new Date(item.created_at).getTime() >= (pending.serverStarted || 0) - 30000);
      if (job) { selectedJob = job.id; if (job.operation === "security-configure") submittedPolicyJob = job.id; store(null); }
      else if (!running && Date.now() - pending.started > 45000) {
        store(null); message("The security job was not found. Check its status before starting it again.", true);
      }
    }
    const job = jobs.find((item) => item.id === selectedJob) || jobs[0];
    if (job) {
      selectedJob = job.id;
      el("job").textContent = t(labels[job.operation] || job.operation) + " · " + t(job.status) +
        (job.error ? " · " + t(job.error) : job.result?.message ? " · " + t(job.result.message) : "");
      if (terminal(job) && !sending && !pending) message(job.error || job.result?.message || "", job.status !== "completed");
    } else el("job").textContent = t("No security maintenance jobs yet.");
    for (const item of jobs) known.add(item.id);
    controls();
  }
  function schedule(delay) { clearTimeout(timer); timer = setTimeout(poll, delay); }
  async function poll() {
    try {
      snapshot = await api("status"); render();
      if (el("log-details").open && selectedJob) {
        const details = await api("status", undefined, selectedJob);
        logText = details.job?.output?.log || ""; el("log").textContent = logText;
      }
      schedule(running || pending || rebootPending || restartsPending || snapshot?.automatic_reboot?.pending ? 1500 : 10000);
    } catch (error) { message(error.transient || error instanceof TypeError ? "The security service is unavailable. Reconnecting without restarting the operation…" : error.message, true); schedule(4000); }
  }
  async function start(kind, body, operation) {
    if (sending || running || pending) return;
    sending = true; store({operation, started: Date.now(), serverStarted: new Date(snapshot?.server_time || 0).getTime(), known: [...known]}); controls();
    try {
      const result = await api(kind, body);
      selectedJob = result.job_id || ""; store(null); message("Security maintenance job accepted.");
      if (kind === "policy") submittedPolicyJob = selectedJob;
    } catch (error) {
      if (error.transient || error instanceof TypeError) message("The connection was interrupted. Checking whether the security job was accepted…");
      else { store(null); message(error.message, true); }
    } finally { sending = false; await poll(); }
  }
  el("check").addEventListener("click", () => start("check", {}, "security-check"));
  el("restart-check").addEventListener("click", () => start("restartCheck", {}, "security-restart-check"));
  el("restart-now").addEventListener("click", () => {
    if (!el("restart-now").disabled && window.confirm(t("Restart eligible services now, outside the configured schedule? Connections handled by restarted services may be interrupted. Protected services remain deferred.")))
      start("restart", {confirmation: "SECURITY"}, "security-restart");
  });
  for (const key of ["restarts-enabled", "restarts-time"]) el(key).addEventListener("change", () => { restartsDirty = true; controls(); });
  el("restarts-form").addEventListener("submit", (event) => {
    event.preventDefault(); if (el("restarts-save").disabled) return;
    const enabled = el("restarts-enabled").value === "1", time = el("restarts-time").value;
    if (!window.confirm(t(enabled ? "Enable automatic service restarts when needed at {time} server time? Protected and network services remain deferred."
      : "Disable scheduled service restarts?").replace("{time}", time))) return;
    changeRestarts({enabled, time, confirmation: "SECURITY"});
  });
  el("policy-form").addEventListener("submit", (event) => {
    event.preventDefault(); if (el("save").disabled) return;
    if (!window.confirm(t("Apply this security update policy?"))) return;
    const startHour = Number(el("start").value);
    start("policy", {mode: el("mode").value, interval: Number(el("interval").value), start: Number(el("start").value),
      end: el("mode").value === "daily" ? (startHour + 1) % 24 : Number(el("end").value), confirmation: "SECURITY"}, "security-configure");
  });
  for (const key of ["mode", "interval", "start", "end"]) el(key).addEventListener("change", () => { dirty = true; controls(); });
  for (const key of ["reboot-enabled", "reboot-time", "reboot-services"]) el(key).addEventListener("change", () => { rebootDirty = true; controls(); });
  el("reboot-form").addEventListener("submit", (event) => {
    event.preventDefault(); if (el("reboot-save").disabled) return;
    const enabled = el("reboot-enabled").value === "1", time = el("reboot-time").value;
    const allow_service_reboot = el("reboot-services").checked;
    if (!window.confirm(t(enabled ? allow_service_reboot ? "Allow a reboot at {time} server time when Linux requires it or verified deferred services remain? All sites are briefly unavailable during a reboot."
      : "Enable daily automatic reboots when required at {time} server time? All sites are briefly unavailable during a reboot."
      : "Disable scheduled reboots? A pending automatic reboot will also be canceled.").replace("{time}", time))) return;
    changeReboot("rebootPolicy", {enabled, time, allow_service_reboot, confirmation: "REBOOT"});
  });
  el("reboot-cancel").addEventListener("click", () => {
    if (el("reboot-cancel").disabled || !window.confirm(t(snapshot?.automatic_reboot?.pending?.automatic
      ? "Cancel this reboot and its automatic retry for this time window?" : "Cancel the pending server reboot?"))) return;
    changeReboot("rebootCancel", {});
  });
  el("restore").addEventListener("click", () => {
    if (el("restore").disabled || !window.confirm(t("Restore the Linux update settings saved before panel management?"))) return;
    start("policy", {mode: "system", interval: 4, start: 3, end: 5, confirmation: "SECURITY"}, "security-configure");
  });
  el("install").addEventListener("click", () => {
    if (!el("install").disabled && window.confirm(t("Install available security fixes now, outside the configured schedule? Automatic reboots follow the separate reboot policy.")))
      start("install", {confirmation: "SECURITY"}, "security-install");
  });
  el("log-details").addEventListener("toggle", () => { if (el("log-details").open) poll(); });
  controls(); poll();
})();
