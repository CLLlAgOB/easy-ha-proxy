/* Applied bans and the evidence for one particular strike. Read-only. */
(function () {
  "use strict";
  const core = window.EasyHaProxyAdaptive;
  const t = window.t || ((text) => text);
  const byId = (id) => document.getElementById(id);
  const clock = window.EasyHaProxyTime.formatter({dateStyle: "short", timeStyle: "medium"});
  const when = (value) => Number(value) > 0 ? clock.format(new Date(Number(value) * 1000)) : "—";
  const pageSize = 50;
  let active = null;
  let rows = [];
  let page = 0;
  let total = 0;
  let snapshot = 0;
  let sequence = 0;
  let detailSequence = 0;
  let requestSequence = 0;
  let selected = null;
  let nextRequest = 0;
  let requestCount = 0;
  let filters = {mode: "active", q: "", since: 0, sort: "ts", direction: "desc"};

  function text(id, value) { byId(id).textContent = value; }
  function cell(row, value, className = "") {
    const td = document.createElement("td");
    td.textContent = value == null || value === "" ? "—" : String(value);
    td.className = className;
    row.appendChild(td);
    return td;
  }
  async function get(path, params) {
    const response = await fetch(`${path}?${new URLSearchParams(params)}`, {
      credentials: "same-origin", headers: {Accept: "application/json"}
    });
    const payload = await response.json();
    if (!response.ok || payload.ok === false) throw new Error(payload.error || `HTTP ${response.status}`);
    return payload;
  }
  function buttons(busy = false) {
    byId("ab-prev").disabled = busy || page === 0;
    byId("ab-next").disabled = busy || (page + 1) * pageSize >= total;
    byId("ab-refresh").disabled = busy;
  }
  function render() {
    const body = byId("ap-bans");
    body.replaceChildren();
    rows.forEach((ban) => {
      const row = document.createElement("tr");
      const address = cell(row, "");
      address.textContent = "";
      const button = document.createElement("button");
      button.type = "button";
      button.className = "ab-address";
      button.textContent = ban.ip;
      button.addEventListener("click", () => openBan(ban));
      address.appendChild(button);
      if (ban.likely_false_positive) {
        const flag = document.createElement("span");
        flag.className = "ap-flag fp";
        flag.textContent = t("Check this one");
        address.appendChild(flag);
      }
      cell(row, when(ban.ts));
      const end = cell(row, when(ban.until));
      if (filters.mode === "active") {
        const left = document.createElement("small");
        left.className = "ab-left";
        left.textContent = core.formatLeft(ban.seconds_left, t);
        end.appendChild(left);
      }
      cell(row, ban.strike);
      cell(row, ban.score);
      cell(row, (ban.categories || []).join(", "), "ab-wrap");
      body.appendChild(row);
    });
    text("ab-note", total ? `${t("Bans found")}: ${total}` : t("No bans match these filters"));
    text("ab-page", total ? `${page * pageSize + 1}–${Math.min(total, (page + 1) * pageSize)} / ${total}` : "0 / 0");
    document.querySelectorAll("[data-ab-sort]").forEach((button) => {
      button.parentElement.setAttribute("aria-sort", button.dataset.abSort === filters.sort ?
        (filters.direction === "asc" ? "ascending" : "descending") : "none");
    });
    buttons();
  }
  async function load() {
    const ticket = ++sequence;
    buttons(true);
    text("ab-note", t("Loading bans…"));
    byId("ap-bans").replaceChildren();
    try {
      if (filters.mode === "active") {
        if (active === null) throw new Error(t("Current bans are unavailable. Refresh to try again."));
        const found = core.banRows(active, filters);
        total = found.length;
        page = Math.min(page, Math.max(0, Math.ceil(total / pageSize) - 1));
        rows = found.slice(page * pageSize, (page + 1) * pageSize);
      } else {
        const payload = await get("/api/security/adaptive/bans", {...filters, offset: page * pageSize, snapshot});
        if (ticket !== sequence) return;
        rows = payload.bans || [];
        total = payload.total;
        snapshot = payload.snapshot;
      }
      render();
    } catch (error) {
      if (ticket !== sequence) return;
      text("ab-note", `${t("Could not load bans")}: ${t(error.message)}`);
      total = 0;
      text("ab-page", "—");
      buttons();
    }
  }
  function applyFilters() {
    const period = Number(byId("ab-period").value);
    filters = {...filters, mode: byId("ab-mode").value, q: byId("ab-query").value.trim(),
      since: period ? Math.floor(Date.now() / 1000) - period : 0};
    page = 0;
    snapshot = 0;
    load();
  }
  async function refresh() {
    if (filters.mode === "history") { applyFilters(); return; }
    const ticket = ++sequence;
    buttons(true);
    text("ab-note", t("Loading bans…"));
    try {
      const payload = await get("/api/security/adaptive/shadow", {});
      if (ticket !== sequence) return;
      active = payload.bans || [];
      applyFilters();
    } catch (error) {
      if (ticket !== sequence) return;
      active = null;
      load();
    }
  }
  async function openBan(ban) {
    const ticket = ++detailSequence;
    ++requestSequence;
    selected = null;
    byId("ab-detail").hidden = false;
    text("ab-detail-title", `${ban.ip} · ${when(ban.ts)}`);
    byId("ab-detail-title").focus();
    text("ab-detail-note", t("Loading ban details…"));
    text("ab-evidence-note", "");
    text("ab-requests-note", "");
    byId("ab-evidence").replaceChildren();
    byId("ab-requests").replaceChildren();
    byId("ab-more").hidden = true;
    byId("ab-explorer").hidden = true;
    byId("ab-ip-page").href = `/ip/${encodeURIComponent(ban.ip)}`;
    try {
      const payload = await get("/api/security/adaptive/ban", ban.id ? {id: ban.id} : {ip: ban.ip, at: ban.ts});
      if (ticket !== detailSequence) return;
      selected = payload.ban;
      text("ab-detail-note", `${t("Ban score")}: ${selected.score} · ${t("Ban step")}: ${selected.strike} · ${t("Scheduled end")}: ${when(selected.until)}`);
      const evidence = (selected.reason.evidence || []).slice().sort((a, b) => a.ts - b.ts);
      evidence.forEach((item) => {
        const row = document.createElement("tr");
        cell(row, when(item.ts));
        cell(row, `${item.event_type || ""}${item.category ? ` / ${item.category}` : ""}`);
        cell(row, item.site);
        cell(row, item.detail, "ab-wrap");
        cell(row, `+${item.points}`);
        byId("ab-evidence").appendChild(row);
      });
      text("ab-evidence-note", evidence.length ?
        `${t("Saved findings")}: ${evidence.length} / ${selected.reason.evidence_total || evidence.length}` :
        t("This older ban has no saved findings. The current score cannot explain a past decision."));
    } catch (error) {
      if (ticket !== detailSequence) return;
      // Older records can be pruned independently of the requests. Still
      // offer the real request log for the exact IP and time the row carried.
      selected = ban;
      text("ab-detail-note", `${t("Could not load ban findings")}: ${t(error.message)}`);
    }
    if (ticket === detailSequence) loadRequests(false);
  }
  async function loadRequests(append) {
    if (!selected) return;
    if (!Number.isFinite(Number(selected.ts)) || Number(selected.ts) <= 0) {
      text("ab-requests-note", t("The ban time is unknown. Use address details to inspect the available history."));
      return;
    }
    const ticket = ++requestSequence;
    const params = core.banRequestParams(selected, byId("ab-hours").value);
    if (!append) {
      nextRequest = 0;
      requestCount = 0;
      byId("ab-requests").replaceChildren();
    } else params.before = nextRequest;
    byId("ab-explorer").href = `/security/requests?${new URLSearchParams(params)}`;
    byId("ab-explorer").hidden = false;
    byId("ab-more").disabled = true;
    text("ab-requests-note", t("Loading requests…"));
    try {
      const payload = await get("/api/security/requests", params);
      if (ticket !== requestSequence) return;
      (payload.requests || []).forEach((item) => {
        const row = document.createElement("tr");
        cell(row, when(item.ts)); cell(row, item.method); cell(row, item.host || item.backend);
        cell(row, item.path, "ab-wrap"); cell(row, item.status); cell(row, item.user_agent, "ab-wrap");
        byId("ab-requests").appendChild(row);
        ++requestCount;
      });
      nextRequest = Number(payload.next || 0);
      let note = requestCount ? `${t("Requests shown")}: ${requestCount}` :
        t("No retained requests in this interval. Recording may have been disabled or older requests may have expired.");
      if (payload.source === "memory") note += ` ${t("Only the recent in-memory buffer is available.")} ${t("Available since")}: ${when(payload.reaches_back_to)}`;
      if (payload.timed_out) note += ` ${t("Search is incomplete. Load older requests to continue.")}`;
      text("ab-requests-note", note);
      byId("ab-more").hidden = !nextRequest;
    } catch (error) {
      if (ticket !== requestSequence) return;
      text("ab-requests-note", `${t("Request log is unavailable")}: ${t(error.message)}`);
      byId("ab-more").hidden = !nextRequest;
    } finally {
      if (ticket === requestSequence) byId("ab-more").disabled = false;
    }
  }
  window.EasyHaProxyBans = {
    setActive(value) { active = Array.isArray(value) ? value : null; if (filters.mode === "active") load(); }
  };
  document.addEventListener("DOMContentLoaded", () => {
    byId("ab-filters").addEventListener("submit", (event) => { event.preventDefault(); applyFilters(); });
    byId("ab-mode").addEventListener("change", applyFilters);
    byId("ab-period").addEventListener("change", applyFilters);
    byId("ab-refresh").addEventListener("click", refresh);
    byId("ab-reset").addEventListener("click", () => {
      byId("ab-query").value = "";
      byId("ab-period").value = "0";
      filters.sort = "ts"; filters.direction = "desc";
      applyFilters();
    });
    byId("ab-prev").addEventListener("click", () => { --page; load(); });
    byId("ab-next").addEventListener("click", () => { ++page; load(); });
    document.querySelectorAll("[data-ab-sort]").forEach((button) => button.addEventListener("click", () => {
      filters.direction = filters.sort === button.dataset.abSort && filters.direction === "desc" ? "asc" : "desc";
      filters.sort = button.dataset.abSort;
      page = 0;
      load();
    }));
    byId("ab-close").addEventListener("click", () => {
      ++detailSequence; ++requestSequence; selected = null;
      byId("ab-detail").hidden = true;
    });
    byId("ab-hours").addEventListener("change", () => loadRequests(false));
    byId("ab-more").addEventListener("click", () => loadRequests(true));
  });
})();
