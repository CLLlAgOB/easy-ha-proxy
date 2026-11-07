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
  let selectedJob = "", logText = "";
  const known = new Set();
  const labels = {"security-check": "Security update check", "security-configure": "Security policy change",
    "security-install": "Security update installation", "security-cycle": "Scheduled security maintenance"};
  const terminal = (job) => ["completed", "failed", "interrupted"].includes(job?.status);
  const date = (stamp) => stamp ? new Date(typeof stamp === "number" ? stamp * 1000 : stamp).toLocaleString(document.documentElement.lang || undefined, {hour12: false}) : t("Never");
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
    const blocked = sending || running || Boolean(pending) || !snapshot?.available;
    const recovery = Boolean(snapshot?.recovery_required);
    el("hours").hidden = el("mode").value !== "window";
    el("interval").disabled = el("mode").value === "system" || blocked;
    el("mode").disabled = blocked;
    el("start").disabled = blocked; el("end").disabled = blocked;
    el("check").disabled = blocked || recovery;
    el("save").disabled = blocked || el("confirm").value !== "SECURITY" || (recovery && el("mode").value !== "system");
    el("install").disabled = blocked || recovery || snapshot?.policy?.mode === "system" || !snapshot?.status?.eligible_count;
    el("install-go").disabled = blocked || el("install-confirm").value !== "SECURITY";
  }
  function render() {
    if (!snapshot) { controls(); return; }
    const policy = snapshot.policy || {}, status = snapshot.status || {};
    if (!dirty) for (const key of ["mode", "interval", "start", "end"]) if (policy[key] !== undefined) el(key).value = policy[key];
    el("checked").textContent = date(status.last_success);
    el("installed").textContent = date(status.last_install_at);
    el("count").textContent = status.state === "ready" && Number.isInteger(status.package_count) ? String(status.package_count) : "—";
    el("state").textContent = t(snapshot.recovery_required ? "Restore system management after the interrupted OS security policy change"
      : snapshot.error || status.error || (status.state === "ready" ? "Security package lists were checked successfully" : "Security update status has not been verified"));
    el("state").classList.toggle("text-danger", Boolean(snapshot.recovery_required || snapshot.error || status.state === "unknown"));
    el("native").textContent = t(policy.mode === "system" ? "The panel does not control automatic OS updates; existing system settings apply."
      : "The panel manages security updates. The native APT upgrade timer is paused.");
    if (policy.mode === "system" && status.native_policy && status.native_timer) {
      const native = status.native_timer, settings = status.native_policy;
      el("native").textContent += " " + t(native.active && ["enabled", "enabled-runtime"].includes(native.enabled) && settings.periodic !== "0"
        ? "Native scheduled installation is enabled." : "Native scheduled installation is disabled or inactive.");
      if (settings.reboot) el("native").textContent += " " + t("The existing Linux policy allows automatic reboot.");
      if (settings.shutdown) el("native").textContent += " " + t("The existing Linux policy installs updates during shutdown.");
    }
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
    el("services").replaceChildren(...(restart?.services || []).map((service) => { const li = document.createElement("li"); li.textContent = service; return li; }));
    const jobs = snapshot.jobs || [], active = snapshot.active_job;
    running = Boolean(active && !terminal(active));
    if (pending) {
      const job = jobs.find((item) => item.operation === pending.operation && !pending.known.includes(item.id) &&
        new Date(item.created_at).getTime() >= (pending.serverStarted || 0) - 30000);
      if (job) { selectedJob = job.id; store(null); }
      else if (!running && Date.now() - pending.started > 45000) {
        store(null); message("The security job was not found. Check its status before starting it again.", true);
      }
    }
    const job = jobs.find((item) => item.id === selectedJob) || jobs[0];
    if (job) {
      selectedJob = job.id;
      el("job").textContent = t(labels[job.operation] || job.operation) + " · " + t(job.status) +
        (job.error ? " · " + t(job.error) : job.result?.message ? " · " + t(job.result.message) : "");
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
      schedule(running || pending ? 1500 : 10000);
    } catch (error) { message(error.transient || error instanceof TypeError ? "The security service is unavailable. Reconnecting without restarting the operation…" : error.message, true); schedule(4000); }
  }
  async function start(kind, body, operation) {
    if (sending || running || pending) return;
    sending = true; store({operation, started: Date.now(), serverStarted: new Date(snapshot?.server_time || 0).getTime(), known: [...known]}); controls();
    try {
      const result = await api(kind, body);
      selectedJob = result.job_id || ""; store(null); message("Security maintenance job accepted.");
      if (kind === "policy") { dirty = false; el("confirm").value = ""; }
      el("install-dialog").close();
    } catch (error) {
      if (error.transient || error instanceof TypeError) message("The connection was interrupted. Checking whether the security job was accepted…");
      else { store(null); message(error.message, true); }
    } finally { sending = false; await poll(); }
  }
  el("check").addEventListener("click", () => start("check", {}, "security-check"));
  el("policy-form").addEventListener("submit", (event) => {
    event.preventDefault(); if (el("save").disabled) return;
    start("policy", {mode: el("mode").value, interval: Number(el("interval").value), start: Number(el("start").value),
      end: Number(el("end").value), confirmation: el("confirm").value}, "security-configure");
  });
  for (const key of ["mode", "interval", "start", "end"]) el(key).addEventListener("change", () => { dirty = true; controls(); });
  el("confirm").addEventListener("input", controls);
  el("install-confirm").addEventListener("input", controls);
  el("install").addEventListener("click", () => { el("install-confirm").value = ""; controls(); el("install-dialog").showModal(); el("install-confirm").focus(); });
  el("install-cancel").addEventListener("click", () => el("install-dialog").close());
  el("install-go").addEventListener("click", () => { if (!el("install-go").disabled) start("install", {confirmation: el("install-confirm").value}, "security-install"); });
  el("log-details").addEventListener("toggle", () => { if (el("log-details").open) poll(); });
  controls(); poll();
})();
