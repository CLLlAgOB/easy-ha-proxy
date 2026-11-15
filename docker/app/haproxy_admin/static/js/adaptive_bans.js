/* Active and historical bans. The URL keeps the list when opening a decision. */
(function () {
  "use strict";
  const core = window.EasyHaProxyAdaptive;
  const t = window.t || ((text) => text);
  const byId = (id) => document.getElementById(id);
  const clock = window.EasyHaProxyTime.formatter({dateStyle: "short", timeStyle: "medium"});
  const when = (value) => Number(value) > 0 ? clock.format(new Date(Number(value) * 1000)) : "—";
  const pageSize = 25;
  let state = core.banListState(window.location.search);
  let active = null;
  let total = 0;
  let sequence = 0;

  function text(id, value) { byId(id).textContent = value; }
  function cell(row, value, className = "") {
    const td = document.createElement("td");
    td.textContent = value == null || value === "" ? "—" : String(value);
    td.className = className; row.appendChild(td); return td;
  }
  async function get(path, params) {
    const response = await fetch(`${path}?${new URLSearchParams(params)}`, {
      credentials: "same-origin", headers: {Accept: "application/json"}
    });
    const payload = await response.json();
    if (!response.ok || payload.ok === false) throw new Error(payload.error || `HTTP ${response.status}`);
    return payload;
  }
  function saveUrl() { window.history.replaceState(null, "", core.banListUrl(state)); }
  function buttons(busy = false) {
    byId("ab-prev").disabled = busy || state.page === 0;
    byId("ab-next").disabled = busy || (state.page + 1) * pageSize >= total;
    byId("ab-refresh").disabled = busy;
    document.querySelectorAll("[data-ab-sort]").forEach((button) => { button.disabled = busy; });
  }
  function syncControls() {
    byId("ab-mode").value = state.mode;
    byId("ab-query").value = state.q;
    byId("ab-period").value = String(state.period);
  }
  function render(rows) {
    const body = byId("ap-bans");
    body.replaceChildren();
    rows.forEach((ban) => {
      const row = document.createElement("tr");
      const address = cell(row, ""); address.textContent = "";
      const link = document.createElement("a");
      link.className = "ab-address";
      link.textContent = ban.ip;
      link.href = core.banDetailUrl(ban, core.banListUrl(state));
      address.appendChild(link);
      if (ban.likely_false_positive) {
        const flag = document.createElement("span"); flag.className = "ap-flag fp";
        flag.textContent = t("Check this one"); address.appendChild(flag);
      }
      cell(row, when(ban.ts), "ab-date");
      const end = cell(row, when(ban.until), "ab-date");
      if (state.mode === "active") {
        const left = document.createElement("small"); left.className = "ab-left";
        left.textContent = core.formatLeft(ban.seconds_left, t); end.appendChild(left);
      }
      cell(row, ban.strike > 0 ? ban.strike : "—");
      cell(row, ban.score);
      const categories = ban.categories || [];
      const why = cell(row, categories.length ? core.banReason(categories[0], t) : "—", "ab-reason");
      if (categories.length > 1) {
        const more = document.createElement("small"); more.className = "ab-left";
        more.textContent = `${t("Additional reasons")}: ${categories.length - 1}`;
        why.appendChild(more);
      }
      body.appendChild(row);
    });
    text("ab-note", total ? `${t("Bans found")}: ${total}` : t("No bans match these filters"));
    text("ab-page", total ? `${state.page * pageSize + 1}–${Math.min(total, (state.page + 1) * pageSize)} / ${total}` : "0 / 0");
    document.querySelectorAll("[data-ab-sort]").forEach((button) => {
      button.parentElement.setAttribute("aria-sort", button.dataset.abSort === state.sort ?
        (state.direction === "asc" ? "ascending" : "descending") : "none");
    });
    saveUrl(); buttons();
  }
  async function load(refresh = false) {
    const ticket = ++sequence;
    const selected = {...state};
    buttons(true); text("ab-note", t("Loading bans…"));
    byId("ap-bans").replaceChildren();
    try {
      let rows;
      if (selected.mode === "active") {
        if (active === null || refresh) {
          const payload = await get("/api/security/adaptive/shadow", {});
          if (ticket !== sequence) return;
          active = payload.bans || [];
        }
        const found = core.banRows(active, selected, t);
        total = found.length;
        state.page = Math.min(state.page, Math.max(0, Math.ceil(total / pageSize) - 1));
        rows = found.slice(state.page * pageSize, (state.page + 1) * pageSize);
      } else {
        const payload = await get("/api/security/adaptive/bans", {...selected, offset: selected.page * pageSize,
          terms: core.banSearchTerms(selected.q, t).join(",")});
        if (ticket !== sequence) return;
        total = Number(payload.total || 0);
        state.snapshot = payload.snapshot;
        const lastPage = Math.max(0, Math.ceil(total / pageSize) - 1);
        if (state.page > lastPage) { state.page = lastPage; return load(); }
        rows = payload.bans || [];
      }
      render(rows);
    } catch (error) {
      if (ticket !== sequence) return;
      text("ab-note", `${t("Could not load bans")}: ${t(error.message)}`);
      total = 0; text("ab-page", "—"); buttons();
    }
  }
  function applyFilters() {
    const period = Number(byId("ab-period").value);
    state = {...state, mode: byId("ab-mode").value, q: byId("ab-query").value.trim(), period,
      since: period ? Math.floor(Date.now() / 1000) - period : 0, page: 0, snapshot: 0};
    saveUrl(); load();
  }
  document.addEventListener("DOMContentLoaded", () => {
    syncControls();
    byId("ab-filters").addEventListener("submit", (event) => { event.preventDefault(); applyFilters(); });
    byId("ab-mode").addEventListener("change", applyFilters);
    byId("ab-period").addEventListener("change", applyFilters);
    byId("ab-refresh").addEventListener("click", () => {
      state.snapshot = 0;
      state.since = state.period ? Math.floor(Date.now() / 1000) - state.period : 0;
      load(true);
    });
    byId("ab-reset").addEventListener("click", () => {
      state = core.banListState(new URLSearchParams({mode: state.mode}));
      syncControls(); saveUrl(); load();
    });
    byId("ab-prev").addEventListener("click", () => { --state.page; load(); });
    byId("ab-next").addEventListener("click", () => { ++state.page; load(); });
    document.querySelectorAll("[data-ab-sort]").forEach((button) => button.addEventListener("click", () => {
      state.direction = state.sort === button.dataset.abSort && state.direction === "desc" ? "asc" : "desc";
      state.sort = button.dataset.abSort; state.page = 0; load();
    }));
    window.addEventListener("pageshow", (event) => { if (event.persisted) load(true); });
    load();
  });
})();
