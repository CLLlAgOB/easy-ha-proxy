/* app/haproxy_admin/static/js/health.js */
/* global HA_IS_SUPERADMIN */

(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);

  const ICONS = {
    logs: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M16 13H8"/><path d="M16 17H8"/><path d="M10 9H8"/></svg>`,
    start: `<svg viewBox="0 0 24 24" aria-hidden="true"><polygon points="8,5 19,12 8,19"/></svg>`,
    stop: `<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="7" y="7" width="10" height="10" rx="2"/></svg>`,
    restart: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 12a9 9 0 0 1 15-6l2-2v6h-6l2-2a7 7 0 1 0 2 5"/><path d="M21 12a9 9 0 0 1-15 6l-2 2v-6h6l-2 2a7 7 0 1 0-2-5"/></svg>`,
    reload: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M21 12a9 9 0 0 0-15.5-6.5"/><path d="M3 4v6h6"/><path d="M3 12a9 9 0 0 0 15.5 6.5"/><path d="M21 20v-6h-6"/></svg>`,
  };

  const isSuperadmin = (window.HA_IS_SUPERADMIN === true);

  const btnRefresh = $("btnRefresh");
  const chkAuto = $("chkAuto");

  const tblSystemd = $("tblSystemd");
  const tblDocker = $("tblDocker");
  const tblRecent = $("tblRecent");
  const systemdSummary = $("systemd-summary");
  const dockerSummary = $("docker-summary");
  const recentSummary = $("recent-summary");
  const btnRecentRefresh = $("btnRecentRefresh");
  const recentLimit = $("recentLimit");
  const recentUnitsSummary = $("recentUnitsSummary");
  const recentUnitOptions = $("recentUnitOptions");
  const recentUnitsAll = $("recentUnitsAll");
  const recentUnitsNone = $("recentUnitsNone");
  const recentUnitsDefault = $("recentUnitsDefault");

  const cardLogs = $("card-logs");
  const logsTitleTarget = $("logs-title-target");
  const logsCmd = $("logs-cmd");
  const logsText = $("logs-text");
  const logsTail = $("logs-tail");
  const logsSince = $("logs-since");
  const logsMeta = $("logs-meta");
  const btnLogsClose = $("btn-logs-close");
  const btnLogsReload = $("btn-logs-reload");

  const controlMsg = $("control-msg");
  const controlResult = $("control-result");

  let CAPS = null;
  let timer = null;
  let selectedLogs = null; // { kind: systemd|docker, name }
  let recentAvailableUnits = [];

  const AUTO_KEY = "haproxy_health_auto_refresh"; // localStorage key
  const RECENT_LIMIT_KEY = "haproxy_health_recent_limit";
  const RECENT_EXCLUDED_KEY = "haproxy_health_recent_excluded_units";
  const RECENT_DEFAULT_EXCLUDED = new Set([
    "haproxy.service",
    "haproxy-healthd.service",
  ]);
  let recentExcludedUnits = new Set(RECENT_DEFAULT_EXCLUDED);

  function esc(s) {
    return String(s ?? "").replace(/[&<>"']/g, (c) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    }[c]));
  }

  async function apiGet(url) {
    const r = await fetch(url, { cache: "no-store", credentials: "same-origin" });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data && data.error ? data.error : `HTTP ${r.status}`);
    return data;
  }

  async function apiPost(url, body) {
    const r = await fetch(url, {
      method: "POST",
      cache: "no-store",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data && data.error ? data.error : `HTTP ${r.status}`);
    return data;
  }

  function showControlMsg(text, ok) {
    if (!controlMsg) return;
    if (!text) {
      controlMsg.style.display = "none";
      controlMsg.textContent = "";
      controlMsg.className = "tag";
      return;
    }
    controlMsg.style.display = "";
    controlMsg.textContent = text;
    controlMsg.className = ok ? "tag tag-ok" : "tag tag-bad";
  }

  function showResult(obj) {
    if (!controlResult) return;
    controlResult.style.display = "block";
    controlResult.textContent = JSON.stringify(obj, null, 2);
  }

  function globToRegex(glob) {
    const esc2 = glob.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
    return new RegExp("^" + esc2.replace(/\*/g, ".*") + "$");
  }

  function resolveActions(name, capsMap) {
    if (!capsMap) return [];
    if (Array.isArray(capsMap[name])) return capsMap[name];

    for (const [pattern, actions] of Object.entries(capsMap)) {
      if (pattern.includes("*")) {
        const rx = globToRegex(pattern);
        if (rx.test(name) && Array.isArray(actions)) return actions;
      }
    }
    return [];
  }

  function makeIconButton(iconKey, title, onClick, disabled = false) {
    const btn = document.createElement("button");
    btn.className = "icon-btn";
    btn.classList.add(iconKey);
    btn.type = "button";
    btn.title = title;
    btn.setAttribute("aria-label", title);
    btn.disabled = !!disabled;

    const EMOJI = {
      start: "▶",
      stop: "⏹",
      restart: "⟳",
      reload: "↻",
    };

    if (iconKey === "logs") {
      btn.innerHTML = ICONS.logs || "";
    } else if (EMOJI[iconKey]) {
      btn.textContent = EMOJI[iconKey];
    } else {
      btn.textContent = "•";
    }

    btn.addEventListener("click", (e) => {
      e.preventDefault();
      onClick();
    });

    return btn;
  }

  function statusIndicator(cls, state, title) {
    const wrap = document.createElement("span");
    wrap.className = "status-value mono notranslate";
    wrap.title = String(title || "");
    wrap.setAttribute("translate", "no");
    wrap.setAttribute("data-i18n-skip", "");

    const dot = document.createElement("span");
    dot.className = `status-dot ${cls}`;
    dot.setAttribute("aria-hidden", "true");

    const label = document.createElement("span");
    label.textContent = String(state || "?");

    wrap.appendChild(dot);
    wrap.appendChild(label);
    return { __node: wrap };
  }

  function technicalText(value, mono = false) {
    const span = document.createElement("span");
    span.className = mono ? "mono notranslate" : "notranslate";
    span.setAttribute("translate", "no");
    span.setAttribute("data-i18n-skip", "");
    span.textContent = String(value ?? "");
    return { __node: span };
  }

  function uiText(value) {
    const source = String(value ?? "");
    return (typeof window.t === "function") ? window.t(source) : source;
  }

  function storageGet(key) {
    try {
      return localStorage.getItem(key);
    } catch (_error) {
      return null;
    }
  }

  function storageSet(key, value) {
    try {
      localStorage.setItem(key, value);
    } catch (_error) {
      // Private browsing or a hardened browser may disable local storage.
    }
  }

  function clampRecentLimit(value) {
    const parsed = Number.parseInt(String(value ?? ""), 10);
    return Number.isFinite(parsed) ? Math.max(1, Math.min(parsed, 500)) : 50;
  }

  function loadRecentPreferences() {
    if (recentLimit) {
      recentLimit.value = String(clampRecentLimit(storageGet(RECENT_LIMIT_KEY) || 50));
    }

    const storedExcluded = storageGet(RECENT_EXCLUDED_KEY);
    if (storedExcluded === null) return;
    try {
      const parsed = JSON.parse(storedExcluded);
      if (Array.isArray(parsed) && parsed.every((unit) => typeof unit === "string")) {
        recentExcludedUnits = new Set(parsed);
      }
    } catch (_error) {
      recentExcludedUnits = new Set(RECENT_DEFAULT_EXCLUDED);
    }
  }

  function saveRecentPreferences() {
    if (recentLimit) {
      const limit = clampRecentLimit(recentLimit.value);
      recentLimit.value = String(limit);
      storageSet(RECENT_LIMIT_KEY, String(limit));
    }
    storageSet(
      RECENT_EXCLUDED_KEY,
      JSON.stringify(Array.from(recentExcludedUnits).sort())
    );
  }

  function selectedRecentUnits() {
    return recentAvailableUnits.filter((unit) => !recentExcludedUnits.has(unit));
  }

  function updateRecentUnitsSummary() {
    if (!recentUnitsSummary) return;
    recentUnitsSummary.textContent = `${selectedRecentUnits().length}/${recentAvailableUnits.length}`;
  }

  function renderRecentUnitOptions() {
    if (!recentUnitOptions) return;
    while (recentUnitOptions.firstChild) recentUnitOptions.removeChild(recentUnitOptions.firstChild);

    if (!recentAvailableUnits.length) {
      const empty = document.createElement("span");
      empty.className = "muted";
      empty.textContent = uiText("No monitored services");
      recentUnitOptions.appendChild(empty);
      updateRecentUnitsSummary();
      return;
    }

    for (const unit of recentAvailableUnits) {
      const label = document.createElement("label");
      label.className = "recent-service-option";

      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.checked = !recentExcludedUnits.has(unit);
      checkbox.addEventListener("change", () => {
        if (checkbox.checked) recentExcludedUnits.delete(unit);
        else recentExcludedUnits.add(unit);
        saveRecentPreferences();
        updateRecentUnitsSummary();
        loadRecentLogs();
      });

      label.appendChild(checkbox);
      label.appendChild(technicalText(unit, true).__node);
      recentUnitOptions.appendChild(label);
    }
    updateRecentUnitsSummary();
  }

  function setRecentAvailableUnits(units) {
    recentAvailableUnits = Array.from(new Set((units || []).filter(Boolean))).sort();
    renderRecentUnitOptions();
  }

  function setRecentUnitPreset(preset) {
    for (const unit of recentAvailableUnits) {
      if (preset === "none") recentExcludedUnits.add(unit);
      else if (preset === "default" && RECENT_DEFAULT_EXCLUDED.has(unit)) {
        recentExcludedUnits.add(unit);
      } else {
        recentExcludedUnits.delete(unit);
      }
    }
    saveRecentPreferences();
    renderRecentUnitOptions();
    loadRecentLogs();
  }

  function systemdHealthState(unit) {
    if (typeof unit.healthy === "boolean") return unit.healthy;
    if (unit.healthy === null) return null;
    const active = String(unit.active_state || "");
    if (active === "active") return true;
    if (active === "inactive" || active === "failed") return false;
    return null;
  }

  function systemdDot(unit) {
    const a = String(unit.active_state || "");
    const s = String(unit.sub_state || "");
    const display = String(unit.display_state || "");
    const titleParts = [`${a || "?"}${s ? "/" + s : ""}`];
    if (unit.result) titleParts.push(`result=${unit.result}`);
    if (unit.exec_main_status !== null && unit.exec_main_status !== undefined && unit.exec_main_status !== "") {
      titleParts.push(`exit=${unit.exec_main_status}`);
    }
    const title = titleParts.join("; ");
    if (a === "activating" || a === "deactivating" || s === "auto-restart" || s === "reload") {
      return statusIndicator("mid", display || a || "?", title);
    }
    if (unit.healthy === true) {
      return statusIndicator("ok", display || ((s === "exited") ? "loaded" : a), title);
    }
    if (unit.healthy === false) return statusIndicator("bad", display || a || "?", title);
    if (unit.healthy === null) return statusIndicator("mid", display || a || "?", title);
    if (a === "active") {
      return statusIndicator("ok", (s === "exited") ? "loaded" : a, title);
    }
    if (a === "inactive" || a === "failed") return statusIndicator("bad", a, title);
    return statusIndicator("mid", display || a || "?", title);
  }

  function dockerHealthState(container) {
    const st = String((container || {}).status || "");
    const health = String((container || {}).health || (container || {}).health_status || "");
    if (st === "running") {
      if (!health || health === "healthy") return true;
      if (health === "starting") return null;
      return false;
    }
    if (st === "exited" || st === "dead") return false;
    return null;
  }

  function dockerDot(container) {
    const st = String((container || {}).status || "");
    const health = String((container || {}).health || (container || {}).health_status || "");
    const state = dockerHealthState(container);
    const title = health ? `${st || "?"}/${health}` : (st || "?");
    if (state === true) return statusIndicator("ok", st || "?", title);
    if (state === false) return statusIndicator("bad", st || "?", title);
    if (st === "restarting" || st === "paused") return statusIndicator("mid", st, st);
    if (st === "created") return statusIndicator("mid", st, st);
    return statusIndicator("mid", st || "?", title);
  }

  function clearTable(tableEl) {
    const tb = tableEl ? tableEl.querySelector("tbody") : null;
    if (!tb) return null;
    while (tb.firstChild) tb.removeChild(tb.firstChild);
    return tb;
  }

  function addRow(tbody, cols) {
    const tr = document.createElement("tr");
    for (const c of cols) {
      const td = document.createElement("td");
      if (c && c.__html !== undefined) td.innerHTML = c.__html;
      else if (c && c.__node) td.appendChild(c.__node);
      else td.textContent = String(c ?? "");
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }

  function renderActionsCell(kind, name) {
    const wrap = document.createElement("div");
    wrap.className = "action-buttons";

    wrap.appendChild(makeIconButton("logs", "Logs", () => openLogs(kind, name)));

    if (!isSuperadmin) return wrap;
    if (!CAPS || CAPS.ok !== true) return wrap;

    const map = (kind === "systemd" ? CAPS.systemd : CAPS.docker) || {};
    const allowed = new Set(resolveActions(name, map));

    if (allowed.has("reload")) wrap.appendChild(makeIconButton("reload", "Reload", () => doControl(kind, name, "reload")));
    if (allowed.has("restart")) wrap.appendChild(makeIconButton("restart", "Restart", () => doControl(kind, name, "restart")));
    if (allowed.has("start")) wrap.appendChild(makeIconButton("start", "Start", () => doControl(kind, name, "start")));
    if (allowed.has("stop")) wrap.appendChild(makeIconButton("stop", "Stop", () => doControl(kind, name, "stop")));

    return wrap;
  }

  async function doControl(kind, name, action) {
    if (!isSuperadmin) {
      showControlMsg("permission denied", false);
      return;
    }
    const pretty = `${kind}:${name} → ${action}`;
    if (!confirm(`Run this action?\n${pretty}`)) return;

    showControlMsg("running…", true);
    try {
      const resp = await apiPost("/api/health/control", { kind, name, action });
      showResult(resp);
      const ok = (resp.ok === true) || (resp.scheduled === true);
      showControlMsg(resp.scheduled ? "scheduled" : (ok ? "ok" : "bad"), ok);
    } catch (e) {
      showControlMsg(e.message || "error", false);
      return;
    }

    await refreshAll(true);
  }

  function renderSystemd(units) {
    const tbody = clearTable(tblSystemd);
    if (!tbody) return;

    const names = Object.keys(units || {}).sort();
    const states = names.map((name) => systemdHealthState(units[name] || {}));
    const activeCount = states.filter((state) => state === true).length;
    const hasFailed = states.some((state) => state === false);
    if (systemdSummary) {
      systemdSummary.textContent = `${activeCount}/${names.length}`;
      systemdSummary.className = (
        names.length > 0 && activeCount === names.length
      ) ? "tag tag-ok" : (hasFailed ? "tag tag-bad" : "tag");
    }
    if (!names.length) {
      addRow(tbody, [{ __html: '<span class="muted">no data</span>' }, "", "", ""]);
      return;
    }

    for (const unit of names) {
      const u = units[unit] || {};
      const sub = Object.prototype.hasOwnProperty.call(u, "display_sub_state")
        ? String(u.display_sub_state ?? "")
        : String(u.sub_state || "");

      addRow(tbody, [
        technicalText(unit, true),
        systemdDot(u),
        technicalText(sub),
        { __node: renderActionsCell("systemd", unit) },
      ]);
    }
  }

  function renderDocker(containers, available) {
    const tbody = clearTable(tblDocker);
    if (!tbody) return;

    const names = Object.keys(containers || {}).sort();
    const states = names.map((name) => dockerHealthState(containers[name] || {}));
    const runningCount = states.filter((state) => state === true).length;
    const hasFailed = states.some((state) => state === false);
    if (dockerSummary) {
      dockerSummary.textContent = available === false
        ? "unavailable"
        : `${runningCount}/${names.length}`;
      dockerSummary.className = (
        available !== false && names.length > 0 && runningCount === names.length
      ) ? "tag tag-ok" : ((available === false || hasFailed) ? "tag tag-bad" : "tag");
    }

    if (available === false) {
      addRow(tbody, [{ __html: '<span class="muted">Docker unavailable</span>' }, "", "", ""]);
      return;
    }

    if (!names.length) {
      addRow(tbody, [{ __html: '<span class="muted">no data</span>' }, "", "", ""]);
      return;
    }

    for (const name of names) {
      const c = containers[name] || {};
      const st = c.status || "?";
      const health = c.health || c.health_status || "";

      addRow(tbody, [
        technicalText(name, true),
        dockerDot(c),
        technicalText(health),
        { __node: renderActionsCell("docker", name) },
      ]);
    }
  }

  function renderRecentLogs(data) {
    const tbody = clearTable(tblRecent);
    if (!tbody) return;

    const items = (data && data.items) ? data.items : [];
    if (recentSummary) {
      recentSummary.textContent = String(items.length);
      recentSummary.className = (data && data.ok === false)
        ? "tag tag-bad"
        : "tag";
    }

    if (data && data.ok === false) {
      addRow(tbody, [
        "",
        technicalText("healthd", true),
        technicalText(data.error || "journalctl failed", true),
      ]);
      return;
    }

    if (!items.length) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 3;
      td.className = "recent-empty muted";
      // The whole journal body is intentionally excluded from automatic DOM
      // translation. Translate this UI-only placeholder explicitly instead.
      td.textContent = uiText("No recent journal entries");
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    for (const e of items) {
      const tr = document.createElement("tr");
      const priority = Number.isInteger(e.priority) ? e.priority : 7;
      if (priority <= 3) tr.className = "recent-row recent-row-error";
      else if (priority === 4) tr.className = "recent-row recent-row-warning";

      const timeCell = document.createElement("td");
      timeCell.className = "recent-time";
      timeCell.appendChild(technicalText(e.ts_utc || "—", true).__node);

      const unitCell = document.createElement("td");
      unitCell.className = "recent-unit";
      unitCell.appendChild(technicalText(e.unit || "systemd", true).__node);

      const messageCell = document.createElement("td");
      messageCell.className = "recent-message";
      // raw_message is deliberately outside Flask's user-facing JSON
      // localization fields. Never fall back to `message`: older servers may
      // already have translated that field before it reaches the browser.
      messageCell.appendChild(technicalText(e.raw_message || "", true).__node);

      tr.appendChild(timeCell);
      tr.appendChild(unitCell);
      tr.appendChild(messageCell);
      tbody.appendChild(tr);
    }
  }

  async function loadRecentLogs() {
    if (recentSummary) {
      recentSummary.textContent = "…";
      recentSummary.className = "tag";
    }
    const limit = clampRecentLimit(recentLimit ? recentLimit.value : 50);
    if (recentLimit) recentLimit.value = String(limit);
    saveRecentPreferences();

    const units = selectedRecentUnits();
    if (!units.length) {
      renderRecentLogs({ ok: true, items: [] });
      return;
    }

    const query = new URLSearchParams({ limit: String(limit) });
    for (const unit of units) query.append("unit", unit);
    try {
      const data = await apiGet(`/api/health/recent-systemd?${query.toString()}`);
      if (!recentAvailableUnits.length && Array.isArray(data.available_units)) {
        setRecentAvailableUnits(data.available_units);
      }
      renderRecentLogs(data);
    } catch (e) {
      renderRecentLogs({ ok: false, error: e.message || "error", items: [] });
    }
  }

  async function refreshAll(force = false) {
    const status = await apiGet(`/api/health/status?refresh=${force ? "1" : "0"}`);
    if (!status || status.ok === false) throw new Error(status && status.error ? status.error : "status not ok");

    const systemdUnits = (status.systemd || {}).units || {};
    renderSystemd(systemdUnits);
    setRecentAvailableUnits(Object.keys(systemdUnits));
    renderDocker((status.docker || {}).containers || {}, (status.docker || {}).available);

    if (force) await loadRecentLogs();
  }

  async function loadCapabilities() {
    try {
      CAPS = await apiGet("/api/health/capabilities");
    } catch (e) {
      CAPS = null;
      console.error("capabilities load failed:", e);
    }
  }

  function openLogs(kind, name) {
    selectedLogs = { kind, name };
    if (!cardLogs) return;
    if (logsTitleTarget) logsTitleTarget.textContent = `${kind} / ${name}`;
    logsCmd.textContent = "";
    logsText.textContent = "loading…";
    logsMeta.textContent = "…";
    logsMeta.className = "tag";
    cardLogs.style.display = "";
    loadLogs();
  }

  async function loadLogs() {
    if (!selectedLogs) return;

    const tail = parseInt(logsTail.value || "200", 10);
    const since = parseInt(logsSince.value || "3600", 10);

    let url = "";
    if (selectedLogs.kind === "systemd") {
      url = `/api/health/logs/systemd?unit=${encodeURIComponent(selectedLogs.name)}&tail=${encodeURIComponent(tail)}&since=${encodeURIComponent(since)}`;
    } else {
      url = `/api/health/logs/docker?container=${encodeURIComponent(selectedLogs.name)}&tail=${encodeURIComponent(tail)}&since=${encodeURIComponent(since)}`;
    }

    try {
      const data = await apiGet(url);
      const ok = (data.ok === true);
      logsMeta.textContent = ok ? "ok" : "bad";
      logsMeta.className = ok ? "tag tag-ok" : "tag tag-bad";
      logsCmd.textContent = String(data.cmd || "");
      logsText.textContent = String(data.text || "");
    } catch (e) {
      logsMeta.textContent = "error";
      logsMeta.className = "tag tag-bad";
      logsText.textContent = e.message || "error";
    }
  }

  function setAuto(enabled) {
    if (timer) clearInterval(timer);
    timer = null;
    if (!enabled) return;
    timer = setInterval(() => {
      refreshAll(false).catch(() => { });
    }, 5000);
  }

  async function init() {
    loadRecentPreferences();
    await loadCapabilities();
    await refreshAll(true);

    if (btnRefresh) {
      btnRefresh.addEventListener("click", async () => {
        await loadCapabilities();
        await refreshAll(true);
      });
    }

    if (chkAuto) {
      const saved = (localStorage.getItem(AUTO_KEY) || "").trim();
      chkAuto.checked = (saved === "1"); // default OFF
      chkAuto.addEventListener("change", () => {
        localStorage.setItem(AUTO_KEY, chkAuto.checked ? "1" : "0");
        setAuto(chkAuto.checked);
      });
      setAuto(chkAuto.checked);
    }

    if (btnLogsClose) {
      btnLogsClose.addEventListener("click", () => {
        if (cardLogs) cardLogs.style.display = "none";
        selectedLogs = null;
      });
    }

    if (btnLogsReload) btnLogsReload.addEventListener("click", loadLogs);
    if (btnRecentRefresh) btnRecentRefresh.addEventListener("click", loadRecentLogs);
    if (recentLimit) {
      recentLimit.addEventListener("change", loadRecentLogs);
      recentLimit.addEventListener("keydown", (event) => {
        if (event.key === "Enter") {
          event.preventDefault();
          loadRecentLogs();
        }
      });
    }
    if (recentUnitsAll) recentUnitsAll.addEventListener("click", () => setRecentUnitPreset("all"));
    if (recentUnitsNone) recentUnitsNone.addEventListener("click", () => setRecentUnitPreset("none"));
    if (recentUnitsDefault) recentUnitsDefault.addEventListener("click", () => setRecentUnitPreset("default"));
  }

  document.addEventListener("DOMContentLoaded", () => {
    init().catch((e) => console.error(e));
  });

})();
