/* Software updates: the decisions behind the page, without the page.
 *
 * What a plan offers, which components must be installed together, how far a
 * running job is and how long it has left. Nothing here touches the DOM or
 * the network, so the same file is loaded by the page and by the tests in
 * .tests/js/. Translation is passed in: t(text, values) or the identity.
 */
(function (root, factory) {
  "use strict";
  const api = factory();
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  } else {
    root.EasyHaProxyUpdates = api;
  }
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const identity = (value) => String(value);

  const TERMINAL_STATES = new Set([
    "completed", "failed", "cancelled", "interrupted", "partial", "skipped"
  ]);
  const AVAILABLE_STATES = new Set(["available", "update", "outdated", "missing"]);
  // The complete update covers every narrower row.
  const SOURCE_SUPERSEDES = new Set([
    "changes", "services", "daemons", "authelia-container", "admin-container"
  ]);
  // "Only what changed" is the source update with fewer steps: it does what
  // the narrower source rows would, but not the containers, which keep their
  // own rows.
  const CHANGES_SUPERSEDES = new Set(["services", "daemons"]);
  const COMPONENT_LABELS = {
    source: "Source code and complete stack",
    all: "Source code and complete stack",
    changes: "Only what changed",
    services: "Host services and scripts",
    daemons: "Auxiliary daemons",
    "authelia-container": "Authelia containers",
    "admin-container": "Web application",
    os: "Operating-system packages"
  };
  const COMPONENT_IMPACTS = {
    source: "Managed source, host services and application containers",
    all: "Managed source, host services and application containers",
    changes: "Only the listed steps; containers update in their own rows",
    services: "Host services",
    daemons: "Auxiliary systemd services",
    "authelia-container": "Authelia and its supporting containers",
    "admin-container": "HAProxy Admin web application",
    os: "Operating-system packages; reboot may be required"
  };
  // What each step of a job is called, and how far into a component it is.
  // The playbook itself reports done/total tasks; the share before it covers
  // downloading the source and the checks around it.
  const PHASE_LABELS = {
    checking: "Checking for updates…",
    verifying: "Verifying the update plan…",
    starting: "Starting…",
    source: "Downloading the new version…",
    prepare: "Preparing…",
    syntax: "Checking the playbook…",
    playbook: "Installing…",
    rechecking: "Checking the result…"
  };
  const PHASE_SHARE = {starting: 0, source: 0.03, prepare: 0.08, syntax: 0.12, playbook: 0.15};
  // A check whose history is empty is guessed at this long.
  const DEFAULT_CHECK_SECONDS = 45;

  // --- Jobs ------------------------------------------------------------------

  function jobId(job) { return String(job && (job.id || job.job_id) || ""); }
  function jobState(job) { return String(job && (job.status || job.state) || "unknown").toLowerCase(); }
  function jobOperation(job) { return String(job && (job.operation || job.action || job.kind) || ""); }
  function jobComponents(job) {
    const values = job && (job.components || job.selected_components || job.result?.components);
    return Array.isArray(values) ? values.map(String) : [];
  }
  function isTerminal(job) { return TERMINAL_STATES.has(jobState(job)); }

  // --- Values as text -----------------------------------------------------------

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

  // --- Plans --------------------------------------------------------------------

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
        value.actionable !== false && (AVAILABLE_STATES.has(state) || value.update_available === true)
      );
      return {
        id,
        state,
        actionable,
        current: value.current_version ?? value.current ?? value.installed ?? value.local_version,
        available: value.available_version ?? value.available ?? value.candidate ?? value.remote_version,
        reason: value.summary || value.reason || value.message || value.reason_code || "Update available",
        details: value.details,
        impact: value.impact || COMPONENT_IMPACTS[id] || "Managed component restart"
      };
    }).filter((item) => item.id);
  }

  function changesScope(component) {
    const scope = component && component.details && component.details.scope;
    return scope && typeof scope === "object" ? scope : null;
  }
  function changesReason(scope, t = identity) {
    const steps = Array.isArray(scope.steps) ? scope.steps.map((step) => t(String(step))) : [];
    return steps.length
      ? t("{count} changed file(s). Steps to run: {steps}", {count: scope.changed, steps: steps.join(", ")})
      : t("{count} changed file(s); nothing on the host needs redeploying", {count: scope.changed});
  }
  function changesUnavailableReason(scope, t = identity) {
    if (scope.reason === "web-application-not-published") {
      return t("This version also changes the web application, and its image is not published yet. Check again once it is.");
    }
    if (scope.reason === "no-applied-record") {
      return t("Available after the next complete update: there is no record of the last one yet.");
    }
    const listed = Array.isArray(scope.unmapped) ? scope.unmapped.join(", ") : "";
    return t("These changes need the complete stack: {paths}", {paths: listed || "—"});
  }
  // The plan carries "only what changed" inside the source component, so a
  // broker that predates it still accepts the plan. The row is derived here.
  function withChangesRow(components, t = identity) {
    const source = components.find((item) => item.id === "all" && item.actionable);
    const scope = changesScope(source);
    if (!scope) return components;
    const row = {
      id: "changes",
      state: scope.ready === true ? "available" : "blocked",
      actionable: scope.ready === true,
      current: source.current,
      available: source.available,
      reason: scope.ready === true ? changesReason(scope, t) : changesUnavailableReason(scope, t),
      details: {
        paths: Array.isArray(scope.paths) ? scope.paths.join(", ") : "",
        requires: Array.isArray(scope.requires) ? scope.requires : []
      },
      impact: COMPONENT_IMPACTS.changes
    };
    const rest = components.filter((item) => !(row.actionable && CHANGES_SUPERSEDES.has(item.id)));
    const index = rest.indexOf(source);
    return rest.slice(0, index).concat([row], rest.slice(index));
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
  // The release channel a plan was checked for, derived the way the broker
  // derives it: local if the source is local, otherwise keyed off the image.
  function planRelease(plan) {
    if (!plan) return "";
    if (String(plan.source_channel || "github") === "local") return "local";
    return String(plan.image_channel || "latest") === "alpha" ? "alpha" : "stable";
  }

  // --- What is installed together -------------------------------------------------

  // What a component has to be installed with: clauses, each needing one of
  // its components. The full stack pulls the web application itself.
  function requiredClauses(components, id) {
    const component = components.find((item) => item.id === id);
    const clauses = component && component.details && component.details.requires;
    return Array.isArray(clauses) ? clauses.filter((clause) => Array.isArray(clause) && clause.length) : [];
  }
  function clauseMet(clause, checked) {
    return clause.some((id) => checked.has(id) || (id === "admin-container" && checked.has("all")));
  }
  // Keeps a selection installable. `boxes` are the rows in page order, each
  // {id, checked, disabled}; `changedId` is the row just clicked. Checking a
  // component brings what it needs (the first enabled choice of each unmet
  // clause); unchecking one takes along what cannot go without it. Returns
  // the ids that end up checked. The broker refuses anything else, so this
  // only saves the round trip.
  function resolveSelection(components, boxes, changedId) {
    const state = boxes.map((box) => ({id: box.id, checked: Boolean(box.checked), disabled: Boolean(box.disabled)}));
    const boxFor = Object.fromEntries(state.map((box) => [box.id, box]));
    const checked = () => new Set(state.filter((box) => box.checked).map((box) => box.id));
    const dropping = Boolean(changedId && boxFor[changedId] && !boxFor[changedId].checked);
    for (let round = 0; round < state.length + 1; round += 1) {
      let changed = false;
      const now = checked();
      for (const box of state) {
        if (!box.checked) continue;
        for (const clause of requiredClauses(components, box.id)) {
          if (clauseMet(clause, now)) continue;
          const pick = dropping ? null : clause.map((id) => boxFor[id]).find((candidate) => candidate && !candidate.disabled);
          if (pick) {
            pick.checked = true;
          } else {
            box.checked = false;
          }
          changed = true;
          break;
        }
        if (changed) break;
      }
      if (!changed) break;
    }
    return checked();
  }
  // What a click on the row `changedId` leaves checked, and which rows are
  // covered by a wider one (shown disabled). The complete update replaces
  // every narrower row; "only what changed" replaces services and daemons;
  // a narrower row, once picked, replaces the wider ones; and what has to be
  // installed together stays together.
  function selectionAfterClick(components, boxes, changedId) {
    const state = boxes.map((box) => ({id: box.id, checked: Boolean(box.checked), disabled: Boolean(box.disabled)}));
    const source = state.find((box) => ["source", "all"].includes(box.id));
    const changes = state.find((box) => box.id === "changes");
    if (["source", "all"].includes(changedId) && source && source.checked) {
      state.forEach((box) => {
        if (SOURCE_SUPERSEDES.has(box.id)) box.checked = false;
      });
    } else if (changedId === "changes" && changes && changes.checked) {
      if (source) source.checked = false;
      state.forEach((box) => {
        if (CHANGES_SUPERSEDES.has(box.id)) box.checked = false;
      });
    } else if (changedId && SOURCE_SUPERSEDES.has(changedId)) {
      if (source) source.checked = false;
      if (changes && CHANGES_SUPERSEDES.has(changedId)) changes.checked = false;
    }
    const resolved = resolveSelection(components, state, changedId);
    state.forEach((box) => { box.checked = resolved.has(box.id); });
    if (source && source.checked) {
      state.forEach((box) => {
        if (SOURCE_SUPERSEDES.has(box.id)) box.checked = false;
      });
    }
    const sourceSelected = Boolean(source && source.checked);
    const changesSelected = Boolean(changes && changes.checked);
    const superseded = new Set(state
      .filter((box) => (sourceSelected && SOURCE_SUPERSEDES.has(box.id)) ||
        (changesSelected && CHANGES_SUPERSEDES.has(box.id)))
      .map((box) => box.id));
    return {
      checked: new Set(state.filter((box) => box.checked).map((box) => box.id)),
      superseded
    };
  }

  // --- Progress and time left -------------------------------------------------------

  function clock(seconds) {
    const value = Math.max(0, Math.floor(seconds));
    return `${Math.floor(value / 60)}:${String(value % 60).padStart(2, "0")}`;
  }
  function jobSeconds(job, until, now = Date.now()) {
    const started = new Date(job.started_at || job.created_at || now).getTime();
    const ended = until ? new Date(until).getTime() : now;
    return Number.isFinite(started) && Number.isFinite(ended) ? (ended - started) / 1000 : 0;
  }
  function median(values) {
    const sorted = values.slice().sort((a, b) => a - b);
    const middle = Math.floor(sorted.length / 2);
    return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
  }
  // How long a component took in the last few installations that finished;
  // `history` is the job list, newest first.
  function typicalSeconds(history, component) {
    const values = [];
    for (const job of history) {
      if (jobOperation(job) !== "apply" || jobState(job) !== "completed") continue;
      const seconds = Number(job.result && job.result.component_seconds && job.result.component_seconds[component]);
      if (Number.isFinite(seconds) && seconds > 0) values.push(seconds);
      if (values.length >= 5) break;
    }
    return values.length ? median(values) : null;
  }
  function typicalCheckSeconds(history) {
    const values = [];
    for (const job of history) {
      if (jobOperation(job) !== "check" || jobState(job) !== "completed" || !job.completed_at) continue;
      const seconds = jobSeconds(job, job.completed_at);
      if (seconds > 0) values.push(seconds);
      if (values.length >= 5) break;
    }
    return values.length ? median(values) : DEFAULT_CHECK_SECONDS;
  }
  // Seconds left, or null when there is nothing honest to say. The current
  // component is judged by its own pace once it is a quarter done -- a
  // "changes only" run is as long as its changes, so history says little --
  // and by history before that; the components after it by history alone.
  function remainingSeconds(job, index, phase, fraction, history, now = Date.now()) {
    const components = jobComponents(job);
    if (phase === "rechecking" || !components.length) return null;
    const current = components[Math.min(index, components.length - 1)];
    const started = Date.parse(job.component_started_at || "");
    const elapsed = Number.isFinite(started) ? Math.max(0, (now - started) / 1000) : null;
    let left;
    if (phase === "verifying") {
      left = typicalSeconds(history, current);
    } else if (elapsed != null && fraction >= 0.25) {
      left = elapsed * (1 - fraction) / fraction;
    } else {
      const typical = typicalSeconds(history, current);
      left = typical == null || elapsed == null ? null : Math.max(typical - elapsed, 15);
    }
    if (left == null) return null;
    for (const later of components.slice(index + 1)) {
      const typical = typicalSeconds(history, later);
      if (typical == null) return null;
      left += typical;
    }
    return left + typicalCheckSeconds(history);
  }
  function remainingText(seconds, t = identity) {
    if (seconds == null || !Number.isFinite(seconds)) return "";
    if (seconds < 60) return t("less than a minute left");
    return t("about {minutes} min left", {minutes: Math.round(seconds / 60)});
  }
  // The task name without its role prefix: "guardd | Install script".
  function taskText(value) {
    return String(value || "").replace(/^[^:|]{1,60} : /, "");
  }
  // The bar, its labels and the time left for a job. `highest` remembers the
  // furthest each job got, so the bar never runs backwards whatever order
  // the polls arrive in.
  function progressModel(job, {history = [], highest = {}, now = Date.now(), t = identity} = {}) {
    const progress = job.progress && typeof job.progress === "object" ? job.progress : {};
    if (jobOperation(job) !== "apply") {
      return {percent: null, label: t("Checking for updates…"), step: "", eta: ""};
    }
    const components = jobComponents(job);
    const count = Math.max(1, components.length);
    let index = Number.isInteger(job.component_index)
      ? job.component_index
      : components.indexOf(String(job.current_component || ""));
    if (index < 0) index = 0;
    const phase = String(progress.phase || "verifying");
    let percent;
    let share = 0;
    if (phase === "verifying") {
      percent = 2;
    } else if (phase === "rechecking") {
      percent = 97;
    } else {
      share = PHASE_SHARE[phase] ?? 0;
      if (phase === "playbook" && Number(progress.total) > 0) {
        share = 0.15 + 0.85 * Math.min(1, Number(progress.done || 0) / Number(progress.total));
      }
      percent = 3 + 94 * ((index + share) / count);
    }
    const eta = remainingText(remainingSeconds(job, index, phase, share, history, now), t);
    const id = jobId(job);
    percent = Math.max(highest[id] || 0, Math.round(Math.min(99, Math.max(1, percent))));
    highest[id] = percent;
    const component = components[Math.min(index, components.length - 1)] || "";
    const name = t(COMPONENT_LABELS[component] || component);
    let label;
    if (phase === "verifying" || phase === "rechecking") {
      label = t(PHASE_LABELS[phase]);
    } else if (components.length > 1) {
      label = t("Installing {component} ({index} of {total})", {component: name, index: index + 1, total: components.length});
    } else {
      label = t("Installing {component}", {component: name});
    }
    const step = phase === "playbook" && progress.task
      ? taskText(progress.task)
      : t(PHASE_LABELS[phase] || "");
    return {percent, label, step, eta};
  }

  return {
    TERMINAL_STATES,
    AVAILABLE_STATES,
    SOURCE_SUPERSEDES,
    CHANGES_SUPERSEDES,
    COMPONENT_LABELS,
    COMPONENT_IMPACTS,
    PHASE_LABELS,
    PHASE_SHARE,
    jobId,
    jobState,
    jobOperation,
    jobComponents,
    isTerminal,
    versionText,
    detailsText,
    normalizeComponents,
    changesScope,
    withChangesRow,
    planFrom,
    extractPlan,
    planRelease,
    requiredClauses,
    clauseMet,
    resolveSelection,
    selectionAfterClick,
    clock,
    jobSeconds,
    median,
    typicalSeconds,
    typicalCheckSeconds,
    remainingSeconds,
    remainingText,
    taskText,
    progressModel
  };
});
