/* Selective software-update workflow with durable host-side progress. */
(function () {
  "use strict";

  const t = window.t || ((value) => String(value));
  const app = document.getElementById("updates-app");
  if (!app) return;

  const endpoints = {
    status: app.dataset.statusUrl,
    check: app.dataset.checkUrl,
    apply: app.dataset.applyUrl,
    channels: app.dataset.channelsUrl,
    reboot: app.dataset.rebootUrl,
    rebootCancel: app.dataset.rebootCancelUrl
  };
  let rebootPending = false;
  let rebootWatchTimer = null;
  let rebootWatchDeadline = 0;
  let currentBootId = "";
  let rebootBootId = "";
  const BOOT_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  const REBOOT_WATCH_MS = 10 * 60 * 1000;
  const terminalStates = new Set([
    "completed", "failed", "cancelled", "interrupted", "partial", "skipped"
  ]);
  const availableStates = new Set(["available", "update", "outdated", "missing"]);
  const sourceSupersedes = new Set([
    "services", "daemons", "authelia-container", "admin-container"
  ]);
  const componentLabels = {
    source: "Source code and complete stack",
    all: "Source code and complete stack",
    services: "Host services and scripts",
    daemons: "Auxiliary daemons",
    "authelia-container": "Authelia containers",
    "admin-container": "Web application",
    os: "Operating-system packages"
  };
  const componentImpacts = {
    source: "Managed source, host services and application containers",
    all: "Managed source, host services and application containers",
    services: "Host services",
    daemons: "Auxiliary systemd services",
    "authelia-container": "Authelia and its supporting containers",
    "admin-container": "HAProxy Admin web application",
    os: "Operating-system packages; reboot may be required"
  };
  const ACTIVE_JOB_KEY = "easy_ha_proxy_update_job";
  const RELOADED_JOB_KEY = "easy_ha_proxy_update_reloaded_job";
  const SELECTED_JOB_KEY = "easy_ha_proxy_update_selected_job";
  const LOG_OPEN_KEY = "easy_ha_proxy_update_log_open";
  const dateFormat = new Intl.DateTimeFormat(document.documentElement.lang || undefined, {
    dateStyle: "medium",
    timeStyle: "medium"
  });

  let currentPlan = null;
  let currentJobId = storageGet(ACTIVE_JOB_KEY) || "";
  let currentJobOperation = "";
  let currentApplyComponents = [];
  let selectedJobId = storageGet(SELECTED_JOB_KEY) || "";
  let installedRelease = "stable";
  let activeJobSnapshot = null;
  let lastJobsHtml = "";
  let pollTimer = null;
  let requestRunning = false;
  let operationRunning = false;
  let logViewMode = "log";
  let renderedJobId = "";
  let renderedHadLog = false;

  function byId(id) { return document.getElementById(id); }
  function escape(value) { return window.escapeHtml(String(value == null ? "" : value)); }
  function storageGet(key) {
    try { return window.sessionStorage.getItem(key); }
    catch (_error) { return null; }
  }
  function storageSet(key, value) {
    try {
      if (value) window.sessionStorage.setItem(key, value);
      else window.sessionStorage.removeItem(key);
    } catch (_error) {
      // The server-side job list remains authoritative when storage is unavailable.
    }
  }
  function setMessage(id, message, ok, technical) {
    const element = byId(id);
    if (!element) return;
    element.textContent = message || "";
    element.classList.toggle("success", Boolean(message) && ok === true);
    element.classList.toggle("error", Boolean(message) && ok === false);
    element.classList.toggle("notranslate", technical === true);
    if (technical === true) {
      element.setAttribute("translate", "no");
      element.setAttribute("data-i18n-skip", "");
    } else {
      element.removeAttribute("translate");
      element.removeAttribute("data-i18n-skip");
    }
  }
  function formatDate(value) {
    if (!value) return t("Never");
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? String(value) : dateFormat.format(parsed);
  }
  async function requestJson(url, options) {
    const response = await fetch(url, options || {});
    let payload;
    try { payload = await response.json(); }
    catch (_error) { throw new Error(`${t("Unexpected server response")} (${response.status})`); }
    if (!response.ok || payload.ok === false) {
      const problem = new Error(payload.error || payload.message || `${t("Request failed")} (${response.status})`);
      problem.status = response.status;
      problem.payload = payload;
      throw problem;
    }
    return payload;
  }
  function postJson(url, payload) {
    return requestJson(url, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payload)
    });
  }
  function jobId(job) { return String(job && (job.id || job.job_id) || ""); }
  function jobState(job) { return String(job && (job.status || job.state) || "unknown").toLowerCase(); }
  function jobOperation(job) { return String(job && (job.operation || job.action || job.kind) || ""); }
  function operationLabel(value) {
    if (value === "check") return t("Update check");
    if (value === "apply") return t("Install updates");
    return t(value || "—");
  }
  function jobComponents(job) {
    const values = job && (job.components || job.selected_components || job.result?.components);
    return Array.isArray(values) ? values.map(String) : [];
  }
  function isTerminal(job) { return terminalStates.has(jobState(job)); }

  function versionText(value) {
    if (value == null || value === "") return "—";
    if (typeof value === "string" || typeof value === "number") return String(value);
    if (Array.isArray(value)) {
      const shown = value.slice(0, 12).map(versionText).join(", ");
      return value.length > 12 ? `${shown}, … (+${value.length - 12})` : shown;
    }
    if (typeof value === "object") {
      for (const key of ["display", "version", "revision", "commit", "digest", "value", "count"]) {
        if (value[key] != null && value[key] !== "") return String(value[key]);
      }
      const pairs = Object.entries(value)
        .filter(([, item]) => ["string", "number", "boolean"].includes(typeof item))
        .slice(0, 4)
        .map(([key, item]) => `${key}=${item}`);
      return pairs.length ? pairs.join(", ") : "—";
    }
    return String(value);
  }
  function detailsText(value) {
    if (!value) return "";
    if (typeof value === "string") return value;
    if (Array.isArray(value)) return value.map(detailsText).filter(Boolean).join("; ");
    if (typeof value === "object") {
      return Object.entries(value)
        .filter(([, item]) => item != null && item !== "")
        .slice(0, 8)
        .map(([key, item]) => `${key}: ${versionText(item)}`)
        .join("; ");
    }
    return String(value);
  }
  function outdatedArtifactLabels(component) {
    const artifacts = component && component.details && component.details.artifacts;
    if (!Array.isArray(artifacts)) return [];
    return artifacts
      .filter((item) => item && item.state === "available")
      .map((item) => item.label || item.id)
      .filter(Boolean);
  }
  function componentReason(component) {
    if (component.state !== "available") return t(String(component.reason));
    if (component.id === "all" || component.id === "source") {
      return t("A different remote managed source revision is available.");
    }
    if (component.id === "services") {
      const names = outdatedArtifactLabels(component);
      return names.length
        ? t("Host-service files to update: {names}", {names: names.join(", ")})
        : t("The remote source contains different host-service files.");
    }
    if (component.id === "daemons") {
      const names = outdatedArtifactLabels(component);
      return names.length
        ? t("Helper daemons to update: {names}", {names: names.join(", ")})
        : t("One or more helper daemons differ from the managed source.");
    }
    if (["authelia-container", "admin-container"].includes(component.id)) {
      const count = Number(component.available);
      return t("{count} managed Docker image update(s) are available.", {
        count: Number.isFinite(count) ? count : 1
      });
    }
    if (component.id === "os") {
      const count = Number(component.details?.package_count ?? component.available);
      return t("{count} operating-system package update(s) are available.", {
        count: Number.isFinite(count) ? count : "—"
      });
    }
    return t(String(component.reason));
  }
  function normalizeComponents(plan) {
    const raw = plan && (plan.components || plan.updates || plan.candidates);
    const values = Array.isArray(raw)
      ? raw
      : (raw && typeof raw === "object"
          ? Object.entries(raw).map(([id, value]) => Object.assign({id}, value || {}))
          : []);
    return values.map((item) => {
      const value = item && typeof item === "object" ? item : {id: String(item)};
      const id = String(value.id || value.component || value.name || "");
      const state = String(value.state || value.status || "unknown").toLowerCase();
      const actionable = value.actionable === true || (
        value.actionable !== false && (availableStates.has(state) || value.update_available === true)
      );
      return {
        id,
        state,
        actionable,
        current: value.current_version ?? value.current ?? value.installed ?? value.local_version,
        available: value.available_version ?? value.available ?? value.candidate ?? value.remote_version,
        reason: value.summary || value.reason || value.message || value.reason_code || "Update available",
        details: value.details,
        impact: value.impact || componentImpacts[id] || "Managed component restart"
      };
    }).filter((item) => item.id);
  }
  function planFrom(value) {
    if (!value || typeof value !== "object") return null;
    const candidates = [
      value.plan,
      value.latest_plan,
      value.update_plan,
      value.result && value.result.plan,
      value.result && value.result.update_plan
    ];
    const candidate = candidates.find((item) => item && typeof item === "object");
    if (!candidate) return null;
    const id = String(candidate.id || candidate.plan_id || "");
    if (!/^[a-f0-9]{32}$/i.test(id)) return null;
    return Object.assign({}, candidate, {id: id.toLowerCase()});
  }
  function extractPlan(payload, jobs) {
    const direct = planFrom(payload);
    if (direct) return direct;
    for (const job of jobs || []) {
      const fromJob = planFrom(job);
      if (fromJob) return fromJob;
    }
    return null;
  }

  function technicalCell(value) {
    return `<span class="mono notranslate" translate="no" data-i18n-skip>${escape(versionText(value))}</span>`;
  }
  function renderPlan(plan) {
    currentPlan = plan;
    resetConfirmation();
    const components = normalizeComponents(plan);
    const available = components.filter((item) => item.actionable && availableStates.has(item.state));
    // "blocked" means a check was intentionally skipped (e.g. the local source
    // channel, or a synced non-git source on the github channel) — that is
    // expected, not a failure, so keep it apart from genuinely-unknown results.
    const unknown = components.filter((item) => ["unknown", "error"].includes(item.state));
    const skipped = components.filter((item) => item.state === "blocked");
    const current = components.filter((item) => item.state === "current").length;
    const stale = Boolean(plan && (plan.stale === true || plan.expired === true || plan.valid === false));
    const warnings = Array.isArray(plan?.warnings) ? plan.warnings.filter(Boolean) : [];

    byId("updates-components-wrap").hidden = !available.length;
    byId("updates-no-updates").hidden = Boolean(available.length) || !plan;
    byId("updates-no-updates").textContent = unknown.length
      ? t("No actionable updates were found, but some components could not be checked.")
      : t("Everything is up to date.");
    byId("updates-confirm-panel").hidden = !available.length || stale;
    byId("updates-select-all").disabled = !available.length || stale;
    byId("updates-select-none").disabled = !available.length || stale;
    byId("updates-plan-summary").textContent = !plan
      ? t("Run a check to build a current update plan.")
      : t("{available} updates available; {current} components are current; {unknown} could not be checked; {skipped} checks skipped.", {
          available: available.length,
          current,
          unknown: unknown.length,
          skipped: skipped.length
        });
    const warning = byId("updates-plan-warning");
    warning.hidden = !stale && !warnings.length;
    warning.textContent = stale
      ? t("This update plan is stale. Check for updates again before applying it.")
      : warnings.map((item) => t(String(item))).join(" ");

    byId("updates-components-body").innerHTML = available.map((component) => {
      // Components whose candidates are already named in the reason (daemons,
      // host-service files) skip the raw digest dump to stay readable.
      const details = Array.isArray(component.details && component.details.artifacts)
        ? ""
        : detailsText(component.details);
      return `<tr data-component-row="${escape(component.id)}">
        <td class="updates-select-column">
          <input type="checkbox" data-update-component="${escape(component.id)}"
                 aria-label="${escape(t("Select {component}", {component: componentLabels[component.id] || component.id}))}">
        </td>
        <td><strong>${escape(t(componentLabels[component.id] || component.id))}</strong></td>
        <td>${technicalCell(component.current)}</td>
        <td>${technicalCell(component.available)}</td>
        <td>${escape(componentReason(component))}${details ? `<small class="notranslate" translate="no" data-i18n-skip>${escape(details)}</small>` : ""}</td>
        <td>${escape(t(String(component.impact)))}</td>
      </tr>`;
    }).join("");

    const unknownDetails = byId("updates-unknown-details");
    unknownDetails.hidden = !unknown.length;
    byId("updates-unknown-summary").textContent = t("{count} components could not be checked", {count: unknown.length});
    byId("updates-unknown-list").innerHTML = unknown.map((component) =>
      `<li><strong>${escape(t(componentLabels[component.id] || component.id))}</strong>: ${escape(t(String(component.reason)))}</li>`
    ).join("");

    const skippedDetails = byId("updates-skipped-details");
    skippedDetails.hidden = !skipped.length;
    byId("updates-skipped-summary").textContent = t("{count} checks skipped by design", {count: skipped.length});
    byId("updates-skipped-list").innerHTML = skipped.map((component) =>
      `<li><strong>${escape(t(componentLabels[component.id] || component.id))}</strong>: ${escape(t(String(component.reason)))}</li>`
    ).join("");

    byId("updates-checked-at").textContent = formatDate(
      plan && (plan.checked_at || plan.created_at || plan.generated_at)
    );
    updateSelection();
  }

  function selectedPlanComponents() {
    return Array.from(document.querySelectorAll("[data-update-component]:checked"))
      .map((element) => element.dataset.updateComponent);
  }
  function selectedApplyComponents() {
    return selectedPlanComponents().map((id) => id === "source" ? "all" : id);
  }
  function resetConfirmation() {
    byId("updates-impact-confirm").checked = false;
    byId("updates-confirmation").value = "";
  }
  function updateSelection(changedId) {
    const boxes = Array.from(document.querySelectorAll("[data-update-component]"));
    const planUsable = Boolean(currentPlan && !(
      currentPlan.stale === true || currentPlan.expired === true || currentPlan.valid === false
    ));
    const source = boxes.find((box) => ["source", "all"].includes(box.dataset.updateComponent));
    if (["source", "all"].includes(changedId) && source && source.checked) {
      boxes.forEach((box) => {
        if (sourceSupersedes.has(box.dataset.updateComponent)) box.checked = false;
      });
    } else if (changedId && sourceSupersedes.has(changedId)) {
      if (source) source.checked = false;
    }
    const sourceSelected = Boolean(source && source.checked);
    boxes.forEach((box) => {
      const superseded = sourceSupersedes.has(box.dataset.updateComponent);
      box.disabled = requestRunning || operationRunning || !planUsable || (sourceSelected && superseded);
      const row = box.closest("tr");
      if (row) row.classList.toggle("updates-row-superseded", sourceSelected && superseded);
    });
    const selected = selectedPlanComponents();
    byId("updates-self-restart-note").hidden = !(
      selected.includes("admin-container") || selected.includes("source") || selected.includes("all")
    );
    byId("updates-os-note").hidden = !selected.includes("os");
    byId("updates-apply").disabled = requestRunning || operationRunning || !(
      planUsable && selected.length &&
      byId("updates-impact-confirm").checked &&
      byId("updates-confirmation").value.trim() === "UPDATE"
    );
  }

  function normalizeJobs(payload) {
    const jobs = Array.isArray(payload.jobs) ? payload.jobs.slice() : [];
    if (payload.job && typeof payload.job === "object" &&
        !jobs.some((item) => jobId(item) === jobId(payload.job))) jobs.unshift(payload.job);
    if (payload.active_job && typeof payload.active_job === "object" &&
        !jobs.some((item) => jobId(item) === jobId(payload.active_job))) jobs.unshift(payload.active_job);
    return jobs;
  }
  function markSelectedRow() {
    document.querySelectorAll("[data-update-job]").forEach((row) => {
      row.classList.toggle("job-row-selected", row.dataset.updateJob === selectedJobId);
    });
  }
  function renderJobs(jobs) {
    const body = byId("updates-jobs-body");
    const active = jobs.find((job) => !isTerminal(job)) || null;
    activeJobSnapshot = active;
    let html;
    if (!jobs.length) {
      html = `<tr><td colspan="5" class="muted">${escape(t("No update jobs yet."))}</td></tr>`;
    } else {
      html = jobs.map((job) => {
        const state = jobState(job);
        const components = jobComponents(job);
        const result = job.error || job.message || job.result?.message || (state === "completed" ? t("Completed successfully") : "—");
        return `<tr data-update-job="${escape(jobId(job))}" tabindex="0">
          <td>${escape(formatDate(job.started_at || job.created_at))}</td>
          <td>${escape(operationLabel(jobOperation(job)))}</td>
          <td>${escape(components.map((id) => t(componentLabels[id] || id)).join(", ") || "—")}</td>
          <td><span class="backup-job-state backup-job-state--${escape(state)}">${escape(t(state))}</span></td>
          <td class="notranslate" translate="no" data-i18n-skip>${escape(String(result))}</td>
        </tr>`;
      }).join("");
    }
    // Re-rendering identical rows would destroy focus and text selection on
    // every poll, so only touch the DOM when the table content changed.
    if (html !== lastJobsHtml) {
      body.innerHTML = html;
      lastJobsHtml = html;
    }
    markSelectedRow();
    if (active) {
      const step = active.current_component || active.step || active.progress?.message || jobState(active);
      byId("updates-active-progress").textContent = t("Running: {step}", {
        step: t(componentLabels[step] || String(step))
      });
      byId("updates-active-progress").className = "config-status-pill config-status-pill--warning";
    } else {
      byId("updates-active-progress").textContent = t("No active job");
      byId("updates-active-progress").className = "config-status-pill config-status-pill--neutral";
    }
    renderProgress(active);
    return Boolean(active);
  }
  function componentProgress(job) {
    const components = jobComponents(job);
    if (jobOperation(job) !== "apply" || !components.length) return null;
    const current = String(job.current_component || "");
    const index = components.indexOf(current);
    if (index < 0) {
      return {done: jobState(job) === "running" ? components.length : 0, total: components.length, current};
    }
    return {done: index, total: components.length, current};
  }
  function renderProgress(active) {
    const wrap = byId("updates-progress");
    if (!active) {
      wrap.hidden = true;
      return;
    }
    wrap.hidden = false;
    const track = byId("updates-progress-track");
    const fill = byId("updates-progress-fill");
    const progress = componentProgress(active);
    if (progress && progress.total > 0) {
      track.classList.remove("job-progress-track--indeterminate");
      const percent = Math.min(100, Math.round((progress.done / progress.total) * 100));
      fill.style.width = `${Math.max(4, percent)}%`;
      byId("updates-progress-label").textContent = progress.current
        ? t("Component {done} of {total}: {component}", {
            done: Math.min(progress.done + 1, progress.total),
            total: progress.total,
            component: t(componentLabels[progress.current] || progress.current)
          })
        : t("Applying selected updates…");
    } else {
      track.classList.add("job-progress-track--indeterminate");
      fill.style.width = "";
      byId("updates-progress-label").textContent = jobOperation(active) === "check"
        ? t("Checking for updates…")
        : t("Working…");
    }
    renderElapsed();
  }
  function renderElapsed() {
    if (!activeJobSnapshot) return;
    const started = new Date(activeJobSnapshot.started_at || activeJobSnapshot.created_at || Date.now());
    const seconds = Math.max(0, Math.floor((Date.now() - started.getTime()) / 1000));
    const minutes = Math.floor(seconds / 60);
    byId("updates-progress-elapsed").textContent =
      `${minutes}:${String(seconds % 60).padStart(2, "0")}`;
  }
  function jobLogText(job) {
    const output = job.output && typeof job.output === "object" ? job.output : {};
    return [output.log, output.stdout, output.stderr, job.log, job.stdout, job.stderr]
      .filter(Boolean).join("\n").trim();
  }
  function jobDetailsText(job) {
    // Metadata view: everything except the bulky raw log streams.
    const clone = {};
    for (const [key, value] of Object.entries(job)) {
      if (key !== "output") clone[key] = value;
    }
    const output = job.output && typeof job.output === "object" ? job.output : null;
    if (output) {
      const meta = {};
      for (const [key, value] of Object.entries(output)) {
        if (!["log", "stdout", "stderr"].includes(key)) meta[key] = value;
      }
      if (Object.keys(meta).length) clone.output = meta;
    }
    return JSON.stringify(clone, null, 2);
  }
  function showJob(job) {
    if (!job) return;
    const log = byId("updates-job-log");
    const id = jobId(job);
    const text = jobLogText(job);
    // The job list strips logs; never downgrade an already shown log to the
    // empty placeholder for the same job.
    if (logViewMode === "log" && !text && renderedJobId === id && renderedHadLog) return;
    const next = logViewMode === "details"
      ? jobDetailsText(job)
      : (text || t("The job has not produced output yet."));
    const mode = byId("updates-log-mode");
    if (mode) {
      mode.textContent = logViewMode === "details"
        ? t("job details — click the job again for its log")
        : t("log output — click the job again for details");
    }
    renderedJobId = id;
    renderedHadLog = Boolean(text);
    if (log.textContent === next) return;
    const stick = log.scrollTop + log.clientHeight >= log.scrollHeight - 8;
    const keep = log.scrollTop;
    log.textContent = next;
    log.scrollTop = stick ? log.scrollHeight : keep;
  }
  const RELEASE_NOTES = {
    stable: "Stable follows the main branch and the release image.",
    alpha: "Alpha follows the development branch and the test image.",
    local: "Local applies the source you synchronized with install.sh; the UI image is not pulled automatically."
  };
  function renderDeployment(payload) {
    const plan = payload.plan && typeof payload.plan === "object" ? payload.plan : {};
    const deployment = payload.deployment || payload.channels || plan;
    const release = String(deployment.release_channel || payload.release_channel || "");
    installedRelease = ["stable", "alpha", "local"].includes(release) ? release : "stable";
    const select = byId("updates-release-channel");
    // Only snap the dropdown to the installed value when the operator is not
    // mid-selection (i.e. it currently matches the last known installed value).
    if (!select.dataset.dirty) select.value = installedRelease;
    updateChannelControls();
  }
  function selectedRelease() {
    return byId("updates-release-channel").value || installedRelease;
  }
  function updateChannelControls() {
    const selected = selectedRelease();
    byId("updates-local-source-note").hidden = selected !== "local";
    const note = byId("updates-release-note");
    note.hidden = false;
    note.textContent = t(RELEASE_NOTES[selected] || "");
    const changed = selected !== installedRelease;
    byId("updates-release-channel").dataset.dirty = changed ? "1" : "";
    byId("updates-save-channels").disabled =
      requestRunning || operationRunning || !changed;
  }
  async function saveChannels() {
    const selected = selectedRelease();
    if (selected === installedRelease) return;
    byId("updates-save-channels").disabled = true;
    setMessage("updates-channels-status", t("Saving channel…"));
    try {
      const response = await postJson(endpoints.channels, {release_channel: selected});
      delete byId("updates-release-channel").dataset.dirty;
      renderDeployment(response);
      setMessage("updates-channels-status", t("Channel saved. Run a new update check."), true);
      renderPlan(null);
      schedulePoll(400);
    } catch (error) {
      setMessage("updates-channels-status", error.message, false, true);
      updateChannelControls();
    }
  }
  function renderReboot(payload, job) {
    const required = Boolean(
      payload.reboot_required || job?.reboot_required || job?.result?.reboot_required
    );
    // The inline card is driven purely by the server-reported state so it can
    // never get stuck; the live "waiting to come back" experience is the modal.
    const ownedScheduled = Boolean(payload.reboot_scheduled);
    const externalScheduled = Boolean(payload.reboot_scheduled_elsewhere);
    const scheduled = ownedScheduled || externalScheduled;
    byId("updates-reboot-card").hidden = !(required || scheduled);
    byId("updates-reboot-idle").hidden = scheduled;
    byId("updates-reboot-pending").hidden = !scheduled;
    byId("updates-reboot-cancel").hidden = !ownedScheduled;
    updateRebootButton();
    // Reattach to a pending web-scheduled reboot after a tab reload. The boot
    // id makes this safe even if the host is reachable before the app is ready.
    if (ownedScheduled && !rebootPending && currentBootId) {
      startRebootWatch(currentBootId);
    }
  }
  function handleCurrentJob(job) {
    if (!job || jobId(job) !== currentJobId) return;
    currentJobOperation = jobOperation(job) || currentJobOperation;
    if (!isTerminal(job)) return;
    const state = jobState(job);
    if (state === "completed") {
      setMessage(
        currentJobOperation.includes("check") ? "updates-service-status" : "updates-apply-status",
        currentJobOperation.includes("check")
          ? t("Update check completed.")
          : t("Selected updates completed successfully."),
        true
      );
    } else {
      const message = `${t("Update operation failed")}: ${job.error || job.message || state}`;
      setMessage(
        currentJobOperation.includes("check") ? "updates-service-status" : "updates-apply-status",
        message,
        false,
        true
      );
    }
    storageSet(ACTIVE_JOB_KEY, "");
    const applied = currentApplyComponents.length ? currentApplyComponents : jobComponents(job);
    if (state === "completed" &&
        (applied.includes("admin-container") || applied.includes("all")) &&
        storageGet(RELOADED_JOB_KEY) !== currentJobId) {
      storageSet(RELOADED_JOB_KEY, currentJobId);
      window.setTimeout(() => window.location.reload(), 600);
    }
  }

  function setBusy(busy) {
    requestRunning = busy;
    byId("updates-check").disabled = busy || operationRunning;
    byId("updates-release-channel").disabled = busy || operationRunning;
    byId("updates-check").classList.toggle("loading", busy);
    const planUsable = Boolean(currentPlan && !(
      currentPlan.stale === true || currentPlan.expired === true || currentPlan.valid === false
    ));
    byId("updates-select-all").disabled = busy || operationRunning || !planUsable;
    byId("updates-select-none").disabled = busy || operationRunning || !planUsable;
    updateChannelControls();
    updateSelection();
  }
  async function refreshStatus(options) {
    const settings = options || {};
    try {
      const payload = await requestJson(endpoints.status);
      const reportedBootId = String(payload.boot_id || "").toLowerCase();
      if (BOOT_ID_RE.test(reportedBootId)) currentBootId = reportedBootId;
      const jobs = normalizeJobs(payload);
      renderDeployment(payload);
      const active = renderJobs(jobs);
      operationRunning = active;
      setBusy(requestRunning);
      const activeJob = jobs.find((job) => !isTerminal(job));
      if (currentJobId && !jobs.some((job) => jobId(job) === currentJobId)) {
        currentJobId = "";
        currentJobOperation = "";
        currentApplyComponents = [];
        storageSet(ACTIVE_JOB_KEY, "");
      }
      if (!currentJobId && activeJob) {
        currentJobId = jobId(activeJob);
        currentJobOperation = jobOperation(activeJob);
        currentApplyComponents = jobComponents(activeJob);
        storageSet(ACTIVE_JOB_KEY, currentJobId);
      }
      if (selectedJobId && !jobs.some((job) => jobId(job) === selectedJobId)) {
        selectedJobId = "";
        storageSet(SELECTED_JOB_KEY, "");
        markSelectedRow();
      }
      // A job explicitly opened by the user stays on screen; otherwise follow
      // the job this page started, then any active one, then the newest.
      const shown = jobs.find((job) => jobId(job) === selectedJobId) ||
        jobs.find((job) => jobId(job) === currentJobId) ||
        activeJob || jobs[0];
      if (shown) renderShownJob(shown);
      const tracked = jobs.find((job) => jobId(job) === currentJobId);
      if (tracked) handleCurrentJob(tracked);
      const relevant = shown;
      const plan = extractPlan(payload, jobs);
      if (plan && (
        !currentPlan || currentPlan.id !== plan.id ||
        Boolean(currentPlan.stale) !== Boolean(plan.stale)
      )) renderPlan(plan);
      if (!plan && relevant?.result?.recheck_error) {
        renderPlan(null);
        byId("updates-plan-summary").textContent = t(
          "Updates were applied, but the automatic recheck failed. Check for updates again to build a current plan."
        );
        const warning = byId("updates-plan-warning");
        warning.hidden = false;
        warning.textContent = t("The previous update plan is no longer valid.");
      }
      renderReboot(payload, relevant);
      if (!settings.quiet && !(relevant && jobId(relevant) === currentJobId && isTerminal(relevant))) {
        setMessage(
          "updates-service-status",
          active
            ? t("An update operation is running. Temporary connection errors are expected while services restart.")
            : t("Software-update service is ready."),
          true
        );
      }
      schedulePoll(active ? 1500 : 10000);
      return payload;
    } catch (error) {
      const reconnecting = Boolean(currentJobId) || rebootPending;
      setMessage(
        "updates-service-status",
        reconnecting
          ? t("The update service is temporarily unavailable. Reconnecting…")
          : error.message,
        false,
        !reconnecting
      );
      if (rebootPending) {
        setMessage(
          "updates-reboot-status",
          t("Rebooting… waiting for the server to come back."),
          false
        );
      }
      schedulePoll(reconnecting ? 2200 : 5000);
      return null;
    }
  }
  function schedulePoll(delay) {
    window.clearTimeout(pollTimer);
    pollTimer = null;
    if (rebootPending) return;
    pollTimer = window.setTimeout(() => refreshStatus({quiet: true}), delay);
  }

  function focusJobLog(id) {
    // A newly started job becomes the selected one and its live log is
    // brought into view immediately.
    if (id) {
      selectedJobId = id;
      storageSet(SELECTED_JOB_KEY, selectedJobId);
    }
    logViewMode = "log";
    markSelectedRow();
    const details = byId("updates-log-details");
    details.open = true;
    storageSet(LOG_OPEN_KEY, "1");
    details.scrollIntoView({behavior: "smooth", block: "start"});
  }

  let detailFetchId = "";
  async function renderShownJob(listJob) {
    showJob(listJob);
    // The list payload strips logs; fetch the full job for the log view.
    const id = jobId(listJob);
    if (logViewMode !== "log" || jobLogText(listJob) || detailFetchId === id) return;
    detailFetchId = id;
    try {
      const payload = await requestJson(`${endpoints.status}?job_id=${encodeURIComponent(id)}`);
      const job = normalizeJobs(payload).find((item) => jobId(item) === id);
      if (job) showJob(job);
    } catch (_error) {
      // The next poll retries; the placeholder stays meanwhile.
    } finally {
      detailFetchId = "";
    }
  }

  async function checkUpdates() {
    if (requestRunning) return;
    setBusy(true);
    renderPlan(null);
    setMessage("updates-service-status", t("Scheduling update check…"));
    try {
      // Preview whichever release channel is currently selected, even if it has
      // not been saved yet; the broker derives its branch and image.
      const request = {release_channel: selectedRelease()};
      const payload = await postJson(endpoints.check, request);
      currentJobId = String(payload.job_id || payload.id || "");
      currentJobOperation = "check";
      currentApplyComponents = [];
      operationRunning = true;
      storageSet(ACTIVE_JOB_KEY, currentJobId);
      setMessage("updates-service-status", t("Update check started."), true);
      schedulePoll(600);
    } catch (error) {
      setMessage("updates-service-status", error.message, false, true);
    } finally {
      setBusy(false);
    }
  }
  async function applyUpdates() {
    if (requestRunning || !currentPlan) return;
    const components = selectedApplyComponents();
    if (!components.length) return;
    if (!window.confirm(t("Apply the selected software updates now?"))) return;
    setBusy(true);
    setMessage("updates-apply-status", t("Scheduling selected updates…"));
    try {
      const payload = await postJson(endpoints.apply, {
        plan_id: currentPlan.id,
        components,
        confirmation: "UPDATE"
      });
      currentJobId = String(payload.job_id || payload.id || "");
      currentJobOperation = "apply";
      currentApplyComponents = components.slice();
      operationRunning = true;
      storageSet(ACTIVE_JOB_KEY, currentJobId);
      focusJobLog(currentJobId);
      resetConfirmation();
      setMessage(
        "updates-apply-status",
        components.includes("admin-container") || components.includes("all")
          ? t("Updates started. This page will reconnect after the web application restarts.")
          : t("Selected updates started."),
        true
      );
      schedulePoll(600);
    } catch (error) {
      if (error.payload?.error_code === "configuration_not_clean") {
        setMessage(
          "updates-apply-status",
          t("Resolve pending HAProxy configuration changes before updating source or host services."),
          false
        );
      } else {
        setMessage("updates-apply-status", error.message, false, true);
      }
    } finally {
      setBusy(false);
    }
  }

  function updateRebootButton() {
    const input = byId("updates-reboot-confirm");
    const button = byId("updates-reboot-now");
    if (button && input) {
      button.disabled = input.value.trim() !== "REBOOT" || !currentBootId;
    }
  }
  function rebootModalText(id, value) { const el = byId(id); if (el) el.textContent = value; }
  function formatMMSS(sec) {
    return `${Math.floor(sec / 60)}:${String(sec % 60).padStart(2, "0")}`;
  }
  function closeRebootModal() {
    if (rebootWatchTimer) { window.clearTimeout(rebootWatchTimer); rebootWatchTimer = null; }
    rebootPending = false;
    byId("updates-reboot-modal").hidden = true;
    schedulePoll(250);
  }
  async function rebootWatchTick() {
    rebootWatchTimer = null;
    const remaining = Math.max(0, Math.round((rebootWatchDeadline - Date.now()) / 1000));
    rebootModalText("updates-reboot-modal-timer", formatMMSS(remaining));
    let payload = null;
    try {
      const response = await fetch(endpoints.status, {
        cache: "no-store",
        headers: {"Accept": "application/json"}
      });
      const contentType = String(response.headers.get("Content-Type") || "").toLowerCase();
      // HAProxy can answer with an HTML 503 before the admin container is
      // ready. Only the authenticated broker JSON response proves readiness.
      if (response.ok && contentType.includes("application/json")) {
        const candidate = await response.json();
        if (candidate && candidate.ok === true && BOOT_ID_RE.test(String(candidate.boot_id || ""))) {
          payload = candidate;
        }
      }
    } catch (_error) { payload = null; }

    const responseBootId = String(payload?.boot_id || "").toLowerCase();
    if (payload && responseBootId !== rebootBootId) {
      // A different kernel boot plus a valid status response means the whole
      // admin path is ready. Reload the document and its versioned assets.
      byId("updates-reboot-modal-cancel").hidden = true;
      rebootModalText("updates-reboot-modal-title", t("Server is back online"));
      rebootModalText("updates-reboot-modal-text", t("The reboot finished successfully."));
      rebootModalText("updates-reboot-modal-timer", "");
      rebootWatchTimer = window.setTimeout(() => window.location.reload(), 1800);
      return;
    }
    if (payload && responseBootId === rebootBootId && !payload.reboot_scheduled) {
      // The same boot answered and our owned timer is gone: cancellation won.
      closeRebootModal();
      setMessage("updates-reboot-status", t("Reboot canceled."), true);
      return;
    }
    if (!payload) {
      byId("updates-reboot-modal-cancel").hidden = true;
      rebootModalText("updates-reboot-modal-title", t("Rebooting the server…"));
      rebootModalText("updates-reboot-modal-text", t("Waiting for the server to come back. This page reconnects automatically."));
    } else {
      byId("updates-reboot-modal-cancel").hidden = false;
      rebootModalText("updates-reboot-modal-title", t("Reboot scheduled"));
      rebootModalText("updates-reboot-modal-text", t("The server will restart in a moment. You can still cancel."));
    }
    if (remaining <= 0) {
      byId("updates-reboot-modal-cancel").hidden = true;
      rebootModalText("updates-reboot-modal-title", t("Server has not returned"));
      rebootModalText("updates-reboot-modal-text", t("The server did not come back within 10 minutes. Check your provider console."));
      rebootModalText("updates-reboot-modal-timer", "");
      byId("updates-reboot-modal-close").hidden = false;
      return;
    }
    rebootWatchTimer = window.setTimeout(rebootWatchTick, 3000);
  }
  function startRebootWatch(bootId) {
    const normalizedBootId = String(bootId || "").toLowerCase();
    if (!BOOT_ID_RE.test(normalizedBootId)) {
      setMessage("updates-reboot-status", t("The current server boot could not be verified."), false);
      return;
    }
    window.clearTimeout(pollTimer);
    pollTimer = null;
    rebootPending = true;
    rebootBootId = normalizedBootId;
    rebootWatchDeadline = Date.now() + REBOOT_WATCH_MS;
    byId("updates-reboot-modal-close").hidden = true;
    byId("updates-reboot-modal-cancel").hidden = false;
    rebootModalText("updates-reboot-modal-title", t("Reboot scheduled"));
    rebootModalText("updates-reboot-modal-text", t("The server will restart in a moment. You can still cancel."));
    rebootModalText("updates-reboot-modal-timer", formatMMSS(Math.round(REBOOT_WATCH_MS / 1000)));
    byId("updates-reboot-modal").hidden = false;
    rebootWatchTimer = window.setTimeout(rebootWatchTick, 2000);
  }
  async function requestReboot() {
    const input = byId("updates-reboot-confirm");
    if (!input || input.value.trim() !== "REBOOT") return;
    if (!window.confirm(t("Reboot the server now? It will be briefly unreachable."))) return;
    setMessage("updates-reboot-status", t("Scheduling reboot…"));
    try {
      const payload = await postJson(endpoints.reboot, {
        confirmation: "REBOOT",
        expected_boot_id: currentBootId
      });
      input.value = "";
      updateRebootButton();
      setMessage("updates-reboot-status", t(payload.message || "Reboot scheduled."), true);
      startRebootWatch(payload.boot_id || currentBootId);
    } catch (error) {
      setMessage("updates-reboot-status", `${t("Reboot was refused")}: ${error.message}`, false);
    }
  }
  async function cancelReboot() {
    const expectedBootId = rebootBootId || currentBootId;
    if (!BOOT_ID_RE.test(expectedBootId)) {
      setMessage("updates-reboot-status", t("The current server boot could not be verified."), false);
      return;
    }
    try {
      await postJson(endpoints.rebootCancel, {expected_boot_id: expectedBootId});
    } catch (error) {
      setMessage("updates-reboot-status", `${t("Failed to cancel the reboot")}: ${error.message}`, false);
      return;
    }
    rebootPending = false;
    closeRebootModal();
    setMessage("updates-reboot-status", t("Reboot canceled."), true);
    schedulePoll(1000);
  }

  byId("updates-check").addEventListener("click", checkUpdates);
  byId("updates-apply").addEventListener("click", applyUpdates);
  byId("updates-save-channels").addEventListener("click", saveChannels);
  byId("updates-reboot-confirm").addEventListener("input", updateRebootButton);
  byId("updates-reboot-now").addEventListener("click", requestReboot);
  byId("updates-reboot-cancel").addEventListener("click", cancelReboot);
  byId("updates-reboot-modal-cancel").addEventListener("click", cancelReboot);
  byId("updates-reboot-modal-close").addEventListener("click", closeRebootModal);
  byId("updates-release-channel").addEventListener("change", updateChannelControls);
  byId("updates-impact-confirm").addEventListener("change", () => updateSelection());
  byId("updates-confirmation").addEventListener("input", () => updateSelection());
  byId("updates-components-body").addEventListener("change", (event) => {
    const checkbox = event.target.closest("[data-update-component]");
    if (checkbox) updateSelection(checkbox.dataset.updateComponent);
  });
  byId("updates-select-none").addEventListener("click", () => {
    document.querySelectorAll("[data-update-component]").forEach((box) => { box.checked = false; });
    updateSelection();
  });
  byId("updates-select-all").addEventListener("click", () => {
    const boxes = Array.from(document.querySelectorAll("[data-update-component]"));
    const source = boxes.find((box) => ["source", "all"].includes(box.dataset.updateComponent));
    boxes.forEach((box) => {
      box.checked = source ? box === source || box.dataset.updateComponent === "os" : true;
    });
    updateSelection(source ? "source" : undefined);
  });
  byId("updates-jobs-body").addEventListener("click", (event) => {
    const row = event.target.closest("[data-update-job]");
    if (!row) return;
    if (selectedJobId === row.dataset.updateJob) {
      // Second click on the same job switches between log and details.
      logViewMode = logViewMode === "log" ? "details" : "log";
    } else {
      selectedJobId = row.dataset.updateJob;
      logViewMode = "log";
    }
    storageSet(SELECTED_JOB_KEY, selectedJobId);
    markSelectedRow();
    byId("updates-log-details").open = true;
    storageSet(LOG_OPEN_KEY, "1");
    requestJson(`${endpoints.status}?job_id=${encodeURIComponent(row.dataset.updateJob)}`)
      .then((payload) => {
        const job = normalizeJobs(payload).find((item) => jobId(item) === row.dataset.updateJob);
        if (job) showJob(job);
      })
      .catch((error) => setMessage("updates-service-status", error.message, false, true));
  });
  byId("updates-log-details").addEventListener("toggle", () => {
    storageSet(LOG_OPEN_KEY, byId("updates-log-details").open ? "1" : "");
  });
  if (storageGet(LOG_OPEN_KEY)) byId("updates-log-details").open = true;
  window.setInterval(renderElapsed, 1000);

  refreshStatus();
})();
