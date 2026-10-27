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
    settings: app.dataset.settingsUrl,
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
  // The decisions -- what a plan offers, what goes together, how far a job
  // is -- live in updates_core.js, where the tests in .tests/js/ reach them.
  const core = window.EasyHaProxyUpdates;
  const {
    jobId, jobState, jobOperation, jobComponents, isTerminal,
    versionText, detailsText, normalizeComponents, extractPlan, planRelease, clock
  } = core;
  const availableStates = core.AVAILABLE_STATES;
  const componentLabels = core.COMPONENT_LABELS;
  const componentImpacts = core.COMPONENT_IMPACTS;
  const ACTIVE_JOB_KEY = "easy_ha_proxy_update_job";
  const PENDING_START_KEY = "easy_ha_proxy_update_pending_start";
  const RELOADED_JOB_KEY = "easy_ha_proxy_update_reloaded_job";
  const SELECTED_JOB_KEY = "easy_ha_proxy_update_selected_job";
  const LOG_OPEN_KEY = "easy_ha_proxy_update_log_open";
  const RESULT_DISMISSED_KEY = "easy_ha_proxy_update_result_dismissed";
  const START_RECONCILE_GRACE_MS = 15 * 1000;
  // How long a finished installation stays summarised at the top.
  const RESULT_VISIBLE_MS = 30 * 60 * 1000;
  const dateFormat = new Intl.DateTimeFormat(document.documentElement.lang || undefined, {
    dateStyle: "medium",
    timeStyle: "medium"
  });

  let pendingStart = loadPendingStart();
  let knownJobIds = new Set(pendingStart?.knownJobIds || []);
  let currentPlan = null;
  let currentJobId = storageGet(ACTIVE_JOB_KEY) || "";
  let currentJobOperation = pendingStart?.operation || "";
  let currentApplyComponents = pendingStart?.components || [];
  let selectedJobId = storageGet(SELECTED_JOB_KEY) || "";
  let installedRelease = "stable";
  let activeJobSnapshot = null;
  let lastJobsHtml = "";
  let pollTimer = null;
  let requestRunning = false;
  let operationRunning = Boolean(pendingStart);
  let connectionFailureCount = 0;
  let connectionWasLost = false;
  let logViewMode = "log";
  let renderedJobId = "";
  let renderedHadLog = false;
  let detailsOpen = Boolean(storageGet(LOG_OPEN_KEY));
  let shownJobSnapshot = null;
  let resultJobSnapshot = null;
  let planHasContent = false;
  let planSummaryText = "";
  let preselectedPlanId = "";
  // The job list, kept for the time estimate: how long each part took before.
  let jobHistory = [];
  // The rows on screen, for what each one has to be installed with.
  let shownComponents = [];
  // The bar never runs backwards for a job, whatever order the polls arrive in.
  const highestPercent = {};

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
  function loadPendingStart() {
    const raw = storageGet(PENDING_START_KEY);
    if (!raw) return null;
    try {
      const value = JSON.parse(raw);
      const operation = String(value?.operation || "");
      const startedAt = Number(value?.startedAt);
      const components = Array.isArray(value?.components) ? value.components.map(String) : [];
      const planId = String(value?.planId || "");
      const knownJobIds = Array.isArray(value?.knownJobIds)
        ? value.knownJobIds.map(String).filter((item) => /^[a-f0-9]{32}$/i.test(item)).slice(0, 100)
        : [];
      if (!["check", "apply"].includes(operation) || !Number.isFinite(startedAt) ||
          startedAt <= 0 || startedAt > Date.now() + 60 * 1000 ||
          (operation === "apply" && !/^[a-f0-9]{32}$/i.test(planId))) {
        throw new Error("invalid pending update start");
      }
      return {operation, startedAt, components, planId, knownJobIds};
    } catch (_error) {
      storageSet(PENDING_START_KEY, "");
      return null;
    }
  }
  function storePendingStart(value) {
    pendingStart = value;
    storageSet(PENDING_START_KEY, value ? JSON.stringify(value) : "");
  }
  function beginPendingStart(operation, components, planId) {
    storePendingStart({
      operation,
      components: Array.isArray(components) ? components.map(String) : [],
      planId: String(planId || ""),
      knownJobIds: Array.from(knownJobIds).slice(0, 100),
      startedAt: Date.now()
    });
  }
  function isTransientRequestError(error) {
    const status = Number(error?.status || 0);
    return !status || status === 408 || status === 425 || status === 429 || status >= 500;
  }
  function reconnectDelay() {
    const exponent = Math.min(Math.max(connectionFailureCount - 1, 0), 4);
    return Math.min(15000, 1200 * (2 ** exponent)) + Math.floor(Math.random() * 300);
  }
  function markConnectionLost() {
    connectionWasLost = true;
    connectionFailureCount += 1;
  }
  function markConnectionRestored() {
    const restored = connectionWasLost;
    connectionWasLost = false;
    connectionFailureCount = 0;
    return restored;
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
  // A reassurance is worth a few seconds on screen, not a permanent box.
  function clearMessageLater(id) {
    const shown = byId(id)?.textContent || "";
    window.setTimeout(() => {
      if (byId(id)?.textContent === shown) setMessage(id, "");
    }, 6000);
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
    catch (_error) {
      const problem = new Error(`${t("Unexpected server response")} (${response.status})`);
      problem.status = response.status;
      throw problem;
    }
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
  function operationLabel(value) {
    if (value === "check") return t("Update check");
    if (value === "apply") return t("Install updates");
    return t(value || "—");
  }

  function pendingStartMatches(job) {
    if (!pendingStart || jobOperation(job) !== pendingStart.operation) return false;
    const id = jobId(job);
    if (!/^[a-f0-9]{32}$/i.test(id) || pendingStart.knownJobIds.includes(id)) return false;
    // A persisted baseline is immune to browser/server clock skew. The time
    // check is only a fallback for a click that raced the very first status poll.
    if (!pendingStart.knownJobIds.length) {
      const createdAt = new Date(job?.created_at || job?.started_at || 0).getTime();
      if (!Number.isFinite(createdAt) || createdAt < pendingStart.startedAt - 30000) return false;
    }
    if (pendingStart.operation !== "apply") return true;
    if (String(job?.plan_id || "") !== pendingStart.planId) return false;
    const actual = jobComponents(job).slice().sort();
    const expected = pendingStart.components.slice().sort();
    return actual.length === expected.length && actual.every((value, index) => value === expected[index]);
  }
  function reconcilePendingStart(jobs) {
    if (!pendingStart) return "none";
    const candidate = jobs.find(pendingStartMatches);
    if (candidate) {
      currentJobId = jobId(candidate);
      currentJobOperation = jobOperation(candidate);
      currentApplyComponents = jobComponents(candidate);
      storageSet(ACTIVE_JOB_KEY, currentJobId);
      storePendingStart(null);
      if (currentJobOperation === "apply") {
        focusJobLog(currentJobId);
        setMessage("updates-apply-status", t("Connection restored. The update job was accepted."), true);
      } else {
        setMessage("updates-service-status", t("Connection restored. The update job was accepted."), true);
      }
      return "matched";
    }
    if (Date.now() - pendingStart.startedAt < START_RECONCILE_GRACE_MS) return "waiting";
    const operation = pendingStart.operation;
    storePendingStart(null);
    currentJobOperation = "";
    currentApplyComponents = [];
    const message = t("Connection restored, but no matching update job was found. Review the job list before trying again.");
    setMessage(operation === "apply" ? "updates-apply-status" : "updates-service-status", message, false);
    return "missing";
  }

  function outdatedArtifactLabels(component) {
    const artifacts = component && component.details && component.details.artifacts;
    if (!Array.isArray(artifacts)) return [];
    return artifacts
      .filter((item) => item && item.state === "available")
      .map((item) => item.label || item.id)
      .filter(Boolean);
  }
  // The plan carries "only what changed" inside the source component, so a
  // broker that predates it still accepts the plan. The row is derived there.
  function withChangesRow(components) {
    return core.withChangesRow(components, t);
  }
  function componentReason(component) {
    if (component.id === "changes") return String(component.reason);
    if (component.state !== "available") return t(String(component.reason));
    if (component.id === "all" || component.id === "source") {
      // A source update can re-pin managed images (the Authelia stack's are
      // pinned in its role). Name them here: the container row itself is not
      // offered, because only the complete update brings the new pins.
      const changes = component.details && component.details.image_changes;
      const moves = changes && typeof changes === "object"
        ? Object.entries(changes).map(([from, to]) => `${from} → ${to}`)
        : [];
      return moves.length
        ? t("A different remote managed source revision is available. It also changes these images: {images}", {images: moves.join(", ")})
        : t("A different remote managed source revision is available.");
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
  function technicalCell(value) {
    return `<span class="mono notranslate" translate="no" data-i18n-skip>${escape(versionText(value))}</span>`;
  }
  // A check previews whichever channel is selected, saved or not. That
  // preview is worth having, but it cannot be applied: the broker refuses a
  // plan for a channel the gateway is not set to. Say so here, before the
  // operator types UPDATE, rather than after.
  function planForOtherChannel(plan) {
    const release = planRelease(plan);
    return Boolean(release) && release !== installedRelease;
  }

  function requirementNote(component) {
    const clauses = Array.isArray(component.details && component.details.requires)
      ? component.details.requires.filter((clause) => Array.isArray(clause) && clause.length)
      : [];
    if (!clauses.length) return "";
    // Name only what is on screen: a hidden narrower row is no help.
    const onScreen = new Set(shownComponents.map((item) => item.id));
    const names = clauses.map((clause) => {
      const visible = clause.filter((id) => onScreen.has(id));
      return (visible.length ? visible : clause).map((id) => t(componentLabels[id] || id)).join(` ${t("or")} `);
    }).join("; ");
    return `<div class="updates-row-requires">${escape(t("Installed together with: {components}", {components: names}))}</div>`;
  }
  function renderChangelog(components) {
    const source = components.find((item) => item.id === "all");
    const changelog = source && source.details && source.details.changelog;
    const box = byId("updates-changelog");
    const commits = changelog && Array.isArray(changelog.commits) ? changelog.commits : [];
    box.hidden = !commits.length;
    if (!commits.length) return;
    const count = Number(changelog.count) || commits.length;
    byId("updates-changelog-summary").textContent = changelog.complete
      ? t("What's new: {count} change(s)", {count})
      : t("What's new: more than {count} change(s)", {count});
    const items = commits.map((commit) =>
      `<li><code>${escape(commit.revision || "")}</code> ${escape(commit.subject || "")}</li>`
    );
    if (count > commits.length) {
      items.push(`<li class="muted">${escape(t("… and {count} more", {count: count - commits.length}))}</li>`);
    }
    byId("updates-changelog-list").innerHTML = items.join("");
  }
  function renderPlan(plan) {
    currentPlan = plan;
    resetConfirmation();
    const components = withChangesRow(normalizeComponents(plan));
    renderChangelog(components);
    const available = components.filter((item) => item.actionable && availableStates.has(item.state));
    shownComponents = available;
    // "blocked" means a check was intentionally skipped (e.g. the local source
    // channel, or a synced non-git source on the github channel) — that is
    // expected, not a failure, so keep it apart from genuinely-unknown results.
    const unknown = components.filter((item) => ["unknown", "error"].includes(item.state));
    // Held back so the host and the web application stay one version: said
    // once, plainly, instead of filed under "skipped by design".
    const pairingReasons = new Set(["web-application-not-published", "web-application-without-source"]);
    const heldBack = components.filter((item) =>
      item.state === "blocked" && pairingReasons.has(String(item.details && item.details.reason || ""))
    );
    const skipped = components.filter((item) => item.state === "blocked" && !heldBack.includes(item));
    const stale = Boolean(plan && (plan.stale === true || plan.expired === true || plan.valid === false));
    const otherChannel = planForOtherChannel(plan);
    const blocked = stale || otherChannel;
    const warnings = Array.isArray(plan?.warnings) ? plan.warnings.filter(Boolean) : [];

    byId("updates-components-wrap").hidden = !available.length;
    byId("updates-apply-bar").hidden = !available.length || blocked;
    planHasContent = Boolean(plan) && Boolean(
      available.length || unknown.length || skipped.length || heldBack.length || blocked || warnings.length
    );
    const pairing = byId("updates-pairing-note");
    pairing.hidden = !heldBack.length;
    pairing.textContent = heldBack.length
      ? `${heldBack.map((item) => t(componentLabels[item.id] || item.id)).join(", ")}: ${t(String(heldBack[0].reason))}`
      : "";
    planSummaryText = !plan
      ? t("Not checked yet. Check for updates to see what is new.")
      : stale
        ? t("The last check has expired. Check again before installing.")
        : available.length
          ? t("{count} update(s) available.", {count: available.length})
          : unknown.length
            ? t("No actionable updates were found, but some components could not be checked.")
            : t("Everything is up to date.");
    byId("updates-select-all").disabled = !available.length || blocked;
    byId("updates-select-none").disabled = !available.length || blocked;
    // The top card already says how many; this line only speaks up when part
    // of the check could not be done.
    byId("updates-plan-summary").textContent = unknown.length
      ? t("Some components could not be checked; they are listed below.")
      : "";
    const warning = byId("updates-plan-warning");
    warning.hidden = !blocked && !warnings.length;
    warning.textContent = otherChannel
      ? t("This check previews a release channel that is not saved on this gateway. Save the channel before applying these updates.")
      : stale
        ? t("This update plan is stale. Check for updates again before applying it.")
        : warnings.map((item) => t(String(item))).join(" ");

    byId("updates-components-body").innerHTML = available.map((component) => {
      // Components whose candidates are already named in the reason (daemons,
      // host-service files) skip the raw digest dump to stay readable.
      const shown = component.details && typeof component.details === "object" && !Array.isArray(component.details)
        ? Object.fromEntries(Object.entries(component.details).filter(([key]) => !["scope", "changelog", "requires"].includes(key)))
        : component.details;
      const details = Array.isArray(component.details && component.details.artifacts)
        ? ""
        : detailsText(shown);
      const pickId = `updates-pick-${String(component.id).replace(/[^a-z0-9-]/gi, "")}`;
      // One line to decide on; versions and the raw detail are a click away.
      return `<tr data-component-row="${escape(component.id)}">
        <td class="updates-select-column">
          <input type="checkbox" id="${escape(pickId)}" data-update-component="${escape(component.id)}"
                 aria-label="${escape(t("Select {component}", {component: t(componentLabels[component.id] || component.id)}))}">
        </td>
        <td>
          <label for="${escape(pickId)}" class="updates-choice-name">${escape(t(componentLabels[component.id] || component.id))}</label>
          ${component.id === "changes" ? `<span class="updates-badge">${escape(t("Recommended"))}</span>` : ""}
          <div class="updates-row-reason">${escape(componentReason(component))}</div>
          ${requirementNote(component)}
          <details class="updates-row-more">
            <summary>${escape(t("Versions and impact"))}</summary>
            <div>${technicalCell(component.current)} → ${technicalCell(component.available)}</div>
            <div>${escape(t(String(component.impact)))}</div>
            ${details ? `<div class="notranslate" translate="no" data-i18n-skip>${escape(details)}</div>` : ""}
          </details>
        </td>
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
      `<li><strong>${escape(t(componentLabels[component.id] || component.id))}</strong>: ${escape(component.id === "changes" ? String(component.reason) : t(String(component.reason)))}</li>`
    ).join("");

    byId("updates-checked-at").textContent = formatDate(
      plan && (plan.checked_at || plan.created_at || plan.generated_at)
    );
    if (plan && !blocked && preselectedPlanId !== plan.id) {
      preselectedPlanId = plan.id;
      const boxes = Array.from(document.querySelectorAll("[data-update-component]"));
      const ids = boxes.map((box) => box.dataset.updateComponent);
      const lead = ids.includes("changes") ? "changes" : (ids.includes("all") ? "all" : "");
      boxes.forEach((box) => {
        const id = box.dataset.updateComponent;
        box.checked = id === lead || (lead !== "all" && ["admin-container", "authelia-container"].includes(id)) ||
          (!lead && ["services", "daemons"].includes(id));
      });
      updateSelection(lead || undefined);
    }
    renderView();
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
    closeConfirm();
  }
  // The rows a click leaves checked, worked out from the rows as they stand
  // (see selectionAfterClick in updates_core.js), then shown.
  function updateSelection(changedId) {
    const boxes = Array.from(document.querySelectorAll("[data-update-component]"));
    const planUsable = Boolean(currentPlan && !(
      currentPlan.stale === true || currentPlan.expired === true || currentPlan.valid === false
    ) && !planForOtherChannel(currentPlan));
    const selection = core.selectionAfterClick(shownComponents, boxes.map((box) => ({
      id: box.dataset.updateComponent,
      checked: box.checked,
      disabled: box.disabled
    })), changedId);
    boxes.forEach((box) => {
      const id = box.dataset.updateComponent;
      const superseded = selection.superseded.has(id);
      box.checked = selection.checked.has(id);
      box.disabled = requestRunning || operationRunning || !planUsable || superseded;
      const row = box.closest("tr");
      if (row) row.classList.toggle("updates-row-superseded", superseded);
    });
    const selected = selectedPlanComponents();
    const apply = byId("updates-apply");
    apply.textContent = selected.length
      ? t("Install selected ({count})", {count: selected.length})
      : t("Install selected");
    apply.disabled = requestRunning || operationRunning || !(planUsable && selected.length);
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
          <td>${escape(job.scheduled ? t("Scheduled check") : operationLabel(jobOperation(job)))}</td>
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
    byId("updates-history-count").textContent = jobs.length ? String(jobs.length) : "";
    jobHistory = jobs;
    resultJobSnapshot = recentResult(jobs);
    renderProgress(active);
    return Boolean(active);
  }
  function jobSeconds(job, until) {
    return core.jobSeconds(job, until);
  }
  // The bar, its labels and the time left, judged against the jobs that
  // finished before (see progressModel in updates_core.js).
  function progressModel(job) {
    return core.progressModel(job, {history: jobHistory, highest: highestPercent, t});
  }
  function renderProgress(active) {
    const wrap = byId("updates-progress");
    if (!active) {
      wrap.hidden = true;
      renderView();
      return;
    }
    wrap.hidden = false;
    const track = byId("updates-progress-track");
    const fill = byId("updates-progress-fill");
    const model = progressModel(active);
    if (model.percent != null) {
      track.classList.remove("job-progress-track--indeterminate");
      fill.style.width = `${model.percent}%`;
      track.setAttribute("aria-valuenow", String(model.percent));
      byId("updates-progress-percent").textContent = `${model.percent}%`;
    } else {
      track.classList.add("job-progress-track--indeterminate");
      fill.style.width = "";
      track.removeAttribute("aria-valuenow");
      byId("updates-progress-percent").textContent = "";
    }
    byId("updates-progress-label").textContent = model.label;
    byId("updates-progress-eta").textContent = model.eta;
    byId("updates-progress-step").textContent = model.step;
    const components = jobComponents(active);
    byId("updates-self-restart-running").hidden = !(
      jobOperation(active) === "apply" &&
      (components.includes("admin-container") || components.includes("all"))
    );
    renderElapsed();
    renderView();
  }
  function renderElapsed() {
    if (!activeJobSnapshot) return;
    byId("updates-progress-elapsed").textContent = clock(jobSeconds(activeJobSnapshot));
  }
  // The newest installation, if it finished recently and was not dismissed.
  function recentResult(jobs) {
    const job = jobs.find((item) => jobOperation(item) === "apply");
    if (!job || !isTerminal(job)) return null;
    const finished = new Date(job.completed_at || job.started_at || 0).getTime();
    if (!Number.isFinite(finished) || Date.now() - finished > RESULT_VISIBLE_MS) return null;
    if (storageGet(RESULT_DISMISSED_KEY) === jobId(job)) return null;
    return job;
  }
  function renderResult() {
    const box = byId("updates-result");
    const job = activeJobSnapshot ? null : resultJobSnapshot;
    box.hidden = !job;
    if (!job) return;
    const ok = jobState(job) === "completed";
    box.classList.toggle("updates-result--ok", ok);
    box.classList.toggle("updates-result--failed", !ok);
    const took = clock(jobSeconds(job, job.completed_at));
    const reboot = Boolean(job.result?.reboot_required);
    // A failure ends in the broker's own words, so the line is translated
    // here and kept from the page-wide pass, as setMessage does for a failed
    // check: that pass swaps in any catalogue label the words happen to
    // contain, and "differs from" came out in Russian mid-sentence.
    setMessage(
      "updates-result-text",
      ok
        ? t("Updates installed in {time}.", {time: took}) +
          (reboot ? ` ${t("A server reboot is required.")}` : "")
        : `${t("The update failed")}: ${job.error || job.message || jobState(job)}`,
      undefined,
      !ok
    );
  }
  // Which parts of the page are on screen. A running job owns the page: the
  // list of updates waits until it has finished.
  function renderView() {
    const running = Boolean(activeJobSnapshot) || Boolean(pendingStart);
    const checking = running && (activeJobSnapshot ? jobOperation(activeJobSnapshot) : pendingStart?.operation) === "check";
    byId("updates-check").hidden = running;
    byId("updates-plan-card").hidden = running || !planHasContent;
    // While a job runs the bar's own label says what is happening.
    byId("updates-hero-summary").hidden = running;
    byId("updates-hero-meta").hidden = running;
    byId("updates-hero-summary").textContent = running
      ? (checking ? t("Checking for updates…") : t("Installing updates…"))
      : (planSummaryText || t("Not checked yet. Check for updates to see what is new."));
    renderResult();
    const hasLog = Boolean(shownJobSnapshot) && (running || Boolean(resultJobSnapshot) || Boolean(selectedJobId));
    const toggle = byId("updates-details-toggle");
    toggle.hidden = !hasLog;
    const open = hasLog && detailsOpen;
    toggle.textContent = open ? t("Hide details") : t("Show details");
    toggle.setAttribute("aria-expanded", open ? "true" : "false");
    byId("updates-log-wrap").hidden = !open;
  }
  function setDetailsOpen(open) {
    detailsOpen = Boolean(open);
    storageSet(LOG_OPEN_KEY, detailsOpen ? "1" : "");
    renderView();
    if (detailsOpen && shownJobSnapshot) renderShownJob(shownJobSnapshot);
  }
  function jobLogText(job) {
    const output = job.output && typeof job.output === "object" ? job.output : {};
    return [output.log, output.stdout, output.stderr, job.log, job.stdout, job.stderr]
      .filter(Boolean).join("\n")
      // The progress markers feed the bar; the log is for people.
      .split("\n").filter((line) => !line.startsWith("EHP-PROGRESS")).join("\n")
      .trim();
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
    const title = byId("updates-log-title");
    if (title) {
      title.textContent = `${operationLabel(jobOperation(job))} · ${formatDate(job.started_at || job.created_at)}` +
        (logViewMode === "details"
          ? ` — ${t("job details — click the job again for its log")}`
          : "");
    }
    renderedJobId = id;
    renderedHadLog = Boolean(text);
    if (log.textContent === next) return;
    const stick = log.scrollTop + log.clientHeight >= log.scrollHeight - 8;
    const keep = log.scrollTop;
    log.textContent = next;
    log.scrollTop = stick ? log.scrollHeight : keep;
  }
  const RELEASE_NAMES = {stable: "Stable", alpha: "Alpha", local: "Local"};
  // The intervals the broker accepts, and what they are called.
  const CHECK_INTERVALS = {
    0: "Off",
    6: "Every 6 hours",
    12: "Every 12 hours",
    24: "Every day",
    72: "Every 3 days",
    168: "Every week"
  };
  let checkSettings = null;
  function intervalName(hours) {
    return CHECK_INTERVALS[hours] ? t(CHECK_INTERVALS[hours]) : t("Every {hours} hours", {hours});
  }
  // The navigation's dot follows this page: a check that finds something
  // lights it, an installation that leaves nothing turns it off, with no
  // reload. The server renders the same dot on every other page.
  const NAV_DOT_TITLES = {
    product: "Software updates are available",
    os: "Operating-system package updates are available"
  };
  function syncNavDot(summary) {
    const level = summary && Object.prototype.hasOwnProperty.call(NAV_DOT_TITLES, summary.level)
      ? summary.level
      : "";
    const places = [
      document.querySelector('[data-nav-group="maintenance"] > summary'),
      document.querySelector('[data-nav-endpoint="system_updates.page"]')
    ];
    places.forEach((place) => {
      if (!place) return;
      let dot = place.querySelector(".nav-update-dot");
      if (!level) {
        if (dot) dot.remove();
        return;
      }
      if (!dot) {
        dot = document.createElement("span");
        dot.setAttribute("role", "img");
        place.insertBefore(dot, place.querySelector(".nav-caret"));
      }
      dot.className = `nav-update-dot nav-update-dot--${level}`;
      const title = t(NAV_DOT_TITLES[level]);
      dot.title = title;
      dot.setAttribute("aria-label", title);
    });
  }
  function renderSettings(settings) {
    if (!settings || typeof settings !== "object") return;
    checkSettings = settings;
    const select = byId("updates-auto-check");
    const hours = Number(settings.auto_check_hours);
    const choices = (Array.isArray(settings.choices) ? settings.choices : Object.keys(CHECK_INTERVALS))
      .map(Number).filter((value) => Number.isFinite(value));
    if (!choices.includes(hours)) choices.push(hours);
    const wanted = choices.join(",");
    if (select.dataset.choices !== wanted) {
      select.dataset.choices = wanted;
      select.innerHTML = choices.map((value) =>
        `<option value="${escape(value)}">${escape(intervalName(value))}</option>`
      ).join("");
    }
    if (!select.dataset.dirty) select.value = String(hours);
    const next = settings.next_auto_check_at;
    byId("updates-auto-check-note").textContent = hours <= 0
      ? t("Automatic checks are off. Updates are found only when you check.")
      : next
        ? t("Next automatic check: {time}", {time: formatDate(next)})
        : t("The next automatic check is being scheduled.");
    byId("updates-next-check").textContent = hours > 0 && next
      ? ` · ${t("next: {time}", {time: formatDate(next)})}`
      : "";
    updateSettingsSummary();
    updateAutoCheckControls();
  }
  function updateSettingsSummary() {
    const parts = [t(RELEASE_NAMES[installedRelease] || installedRelease)];
    if (checkSettings) {
      const hours = Number(checkSettings.auto_check_hours);
      parts.push(hours > 0 ? t("checks: {interval}", {interval: intervalName(hours).toLowerCase()}) : t("automatic checks off"));
    }
    byId("updates-channel-summary").textContent = parts.join(" · ");
  }
  function updateAutoCheckControls() {
    const select = byId("updates-auto-check");
    const saved = checkSettings ? String(checkSettings.auto_check_hours) : select.value;
    const dirty = select.value !== saved;
    select.dataset.dirty = dirty ? "1" : "";
    byId("updates-save-auto-check").disabled = !checkSettings || !dirty || requestRunning;
  }
  async function saveAutoCheck() {
    const select = byId("updates-auto-check");
    const value = Number(select.value);
    byId("updates-save-auto-check").disabled = true;
    setMessage("updates-auto-check-status", t("Saving…"));
    try {
      const response = await postJson(endpoints.settings, {auto_check_hours: value});
      delete select.dataset.dirty;
      renderSettings(response.settings);
      setMessage("updates-auto-check-status", t("Saved."), true);
      clearMessageLater("updates-auto-check-status");
      schedulePoll(1500);
    } catch (error) {
      setMessage("updates-auto-check-status", error.message, false, true);
      updateAutoCheckControls();
    }
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
    updateSettingsSummary();
    renderSettings(payload.settings);
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
    // An installation's outcome is the summary at the top; a check's is the
    // list it produced, so only its failure needs saying.
    if (currentJobOperation.includes("check")) {
      if (state !== "completed") {
        setMessage(
          "updates-service-status",
          `${t("Update operation failed")}: ${job.error || job.message || state}`,
          false,
          true
        );
      }
    } else {
      setMessage("updates-apply-status", "");
      // A failure is the one moment the log is wanted without asking.
      if (state !== "completed" && !detailsOpen) setDetailsOpen(true);
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
    ) && !planForOtherChannel(currentPlan));
    byId("updates-select-all").disabled = busy || operationRunning || !planUsable;
    byId("updates-select-none").disabled = busy || operationRunning || !planUsable;
    updateChannelControls();
    updateSelection();
  }
  async function refreshStatus(options) {
    const settings = options || {};
    try {
      const payload = await requestJson(endpoints.status);
      const connectionRestored = markConnectionRestored();
      const reportedBootId = String(payload.boot_id || "").toLowerCase();
      if (BOOT_ID_RE.test(reportedBootId)) currentBootId = reportedBootId;
      const jobs = normalizeJobs(payload);
      renderDeployment(payload);
      if (payload.summary && typeof payload.summary === "object") syncNavDot(payload.summary);
      const active = renderJobs(jobs);
      const pendingResult = reconcilePendingStart(jobs);
      knownJobIds = new Set(jobs.map(jobId).filter((id) => /^[a-f0-9]{32}$/i.test(id)));
      operationRunning = active || Boolean(pendingStart);
      setBusy(requestRunning);
      const activeJob = jobs.find((job) => !isTerminal(job));
      if (currentJobId && !pendingStart && !jobs.some((job) => jobId(job) === currentJobId)) {
        currentJobId = "";
        currentJobOperation = "";
        currentApplyComponents = [];
        storageSet(ACTIVE_JOB_KEY, "");
      }
      if (!currentJobId && !pendingStart && activeJob) {
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
      shownJobSnapshot = shown || null;
      if (shown) renderShownJob(shown);
      renderView();
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
      if (connectionRestored && pendingResult !== "missing" &&
          !(tracked && isTerminal(tracked))) {
        setMessage(
          "updates-service-status",
          active
            ? t("Connection restored. The update operation is still running.")
            : (pendingStart
                ? t("Connection restored. Checking whether the update job was accepted…")
                : t("Connection restored. Software-update service is ready.")),
          true
        );
        clearMessageLater("updates-service-status");
      } else if (pendingResult !== "missing" && !settings.quiet &&
                 !(relevant && jobId(relevant) === currentJobId && isTerminal(relevant))) {
        // Nothing to say while all is well: the top card shows the state.
        setMessage("updates-service-status", "");
      }
      schedulePoll(active || pendingStart ? 1500 : 10000);
      return payload;
    } catch (error) {
      const reconnecting = isTransientRequestError(error);
      markConnectionLost();
      setMessage(
        "updates-service-status",
        reconnecting
          ? t("The update service is temporarily unavailable. Reconnecting automatically…")
          : error.message,
        reconnecting ? undefined : false,
        !reconnecting
      );
      if (rebootPending) {
        setMessage(
          "updates-reboot-status",
          t("Rebooting… waiting for the server to come back."),
          false
        );
      }
      schedulePoll(reconnecting ? reconnectDelay() : 5000);
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
    // A newly started job is the one the top card follows. Its log stays
    // folded away: the bar says enough, and "Show details" is right there.
    if (id) {
      selectedJobId = "";
      storageSet(SELECTED_JOB_KEY, "");
      storageSet(RESULT_DISMISSED_KEY, "");
    }
    logViewMode = "log";
    markSelectedRow();
    byId("updates-hero-title").scrollIntoView({behavior: "smooth", block: "start"});
  }

  let detailFetchId = "";
  async function renderShownJob(listJob) {
    showJob(listJob);
    // The list payload strips logs; fetch the full job for the log view, and
    // only while the log is on screen: it can be a quarter of a megabyte.
    const id = jobId(listJob);
    if (!detailsOpen || logViewMode !== "log" || jobLogText(listJob) || detailFetchId === id) return;
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
    beginPendingStart("check", [], "");
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
      storePendingStart(null);
      setMessage("updates-service-status", t("Update check started."), true);
      schedulePoll(600);
    } catch (error) {
      if (isTransientRequestError(error)) {
        markConnectionLost();
        operationRunning = true;
        setMessage(
          "updates-service-status",
          t("The connection was interrupted while starting the update. Checking whether the job was accepted…")
        );
        schedulePoll(reconnectDelay());
      } else {
        storePendingStart(null);
        setMessage("updates-service-status", error.message, false, true);
      }
    } finally {
      setBusy(false);
    }
  }
  function openConfirm() {
    if (requestRunning || operationRunning || !currentPlan) return;
    const components = selectedApplyComponents();
    if (!components.length) return;
    byId("updates-confirm-list").innerHTML = components.map((id) =>
      `<li><strong>${escape(t(componentLabels[id] || id))}</strong>` +
      `<span>${escape(t(componentImpacts[id] || "Managed component restart"))}</span></li>`
    ).join("");
    byId("updates-self-restart-note").hidden = !(
      components.includes("admin-container") || components.includes("all")
    );
    byId("updates-os-note").hidden = !components.includes("os");
    byId("updates-confirm-modal").hidden = false;
    byId("updates-confirm-go").focus();
  }
  function closeConfirm() {
    const modal = byId("updates-confirm-modal");
    if (modal) modal.hidden = true;
  }
  async function applyUpdates() {
    if (requestRunning || !currentPlan) return;
    const components = selectedApplyComponents();
    if (!components.length) return;
    closeConfirm();
    setBusy(true);
    setMessage("updates-apply-status", t("Scheduling selected updates…"));
    beginPendingStart("apply", components, currentPlan.id);
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
      storePendingStart(null);
      focusJobLog(currentJobId);
      resetConfirmation();
      setMessage("updates-apply-status", "");
      renderView();
      schedulePoll(600);
    } catch (error) {
      if (error.payload?.error_code === "configuration_not_clean") {
        storePendingStart(null);
        setMessage(
          "updates-apply-status",
          t("Resolve pending HAProxy configuration changes before updating source or host services."),
          false
        );
      } else if (isTransientRequestError(error)) {
        markConnectionLost();
        operationRunning = true;
        setMessage(
          "updates-apply-status",
          t("The connection was interrupted while starting the update. Checking whether the job was accepted…")
        );
        schedulePoll(reconnectDelay());
      } else {
        storePendingStart(null);
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
  byId("updates-apply").addEventListener("click", openConfirm);
  byId("updates-confirm-go").addEventListener("click", applyUpdates);
  byId("updates-confirm-cancel").addEventListener("click", closeConfirm);
  byId("updates-confirm-modal").addEventListener("click", (event) => {
    if (event.target.classList.contains("config-modal-backdrop")) closeConfirm();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !byId("updates-confirm-modal").hidden) closeConfirm();
  });
  byId("updates-details-toggle").addEventListener("click", () => setDetailsOpen(!detailsOpen));
  byId("updates-result-dismiss").addEventListener("click", () => {
    if (resultJobSnapshot) storageSet(RESULT_DISMISSED_KEY, jobId(resultJobSnapshot));
    resultJobSnapshot = null;
    selectedJobId = "";
    storageSet(SELECTED_JOB_KEY, "");
    markSelectedRow();
    renderView();
  });
  byId("updates-save-channels").addEventListener("click", saveChannels);
  byId("updates-save-auto-check").addEventListener("click", saveAutoCheck);
  byId("updates-auto-check").addEventListener("change", updateAutoCheckControls);
  byId("updates-reboot-confirm").addEventListener("input", updateRebootButton);
  byId("updates-reboot-now").addEventListener("click", requestReboot);
  byId("updates-reboot-cancel").addEventListener("click", cancelReboot);
  byId("updates-reboot-modal-cancel").addEventListener("click", cancelReboot);
  byId("updates-reboot-modal-close").addEventListener("click", closeRebootModal);
  byId("updates-release-channel").addEventListener("change", updateChannelControls);
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
    const changes = boxes.find((box) => box.dataset.updateComponent === "changes");
    if (changes) {
      boxes.forEach((box) => {
        const id = box.dataset.updateComponent;
        box.checked = box === changes || ["authelia-container", "admin-container", "os"].includes(id);
      });
      updateSelection("changes");
      return;
    }
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
    // The history's log opens in the top card, where every log is read.
    if (!detailsOpen) setDetailsOpen(true);
    byId("updates-log-wrap").scrollIntoView({behavior: "smooth", block: "nearest"});
    requestJson(`${endpoints.status}?job_id=${encodeURIComponent(row.dataset.updateJob)}`)
      .then((payload) => {
        const job = normalizeJobs(payload).find((item) => jobId(item) === row.dataset.updateJob);
        if (job) showJob(job);
      })
      .catch((error) => {
        if (isTransientRequestError(error)) {
          markConnectionLost();
          setMessage(
            "updates-service-status",
            t("The update service is temporarily unavailable. Reconnecting automatically…")
          );
          schedulePoll(reconnectDelay());
        } else {
          setMessage("updates-service-status", error.message, false, true);
        }
      });
  });
  window.addEventListener("online", () => schedulePoll(100));
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible" && connectionWasLost) schedulePoll(100);
  });
  window.setInterval(renderElapsed, 1000);
  renderView();

  refreshStatus();
})();
