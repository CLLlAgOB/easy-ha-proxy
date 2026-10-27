/* Live activity: who is hitting the gateway right now and what they get.
 *
 * One request every few seconds to /api/monitoring/live; everything else --
 * sorting, tabs, the timeline -- happens here on the answer. Filters that
 * change what is counted go back to the server; sorting does not.
 *
 * The decisions -- saved choices, filters, sort order, badges, the ban
 * action, the timeline's bars -- live in live_activity_core.js, where the
 * tests in .tests/js/ reach them.
 */
(function () {
  "use strict";

  const core = window.EasyHaProxyLive;
  const t = window.t || ((value) => String(value));
  const esc = window.escapeHtml;
  const flag = window.countryFlagMarkup;
  const STORE = "live-activity";

  const state = Object.assign(core.defaults(), {
    paused: false,
    data: null,
    timer: null,
    inFlight: false,
  });

  function byId(id) {
    return document.getElementById(id);
  }

  function load() {
    let saved = {};
    try {
      saved = JSON.parse(window.localStorage.getItem(STORE) || "{}");
    } catch (error) {
      // Private mode or a damaged entry: defaults.
    }
    Object.assign(state, core.restoreSettings(saved));
  }

  function save() {
    try {
      window.localStorage.setItem(STORE, JSON.stringify({
        window: state.window, refresh: state.refresh, tab: state.tab, sort: state.sort,
      }));
    } catch (error) {
      // The choice lasts for this page only.
    }
  }

  function csrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute("content") || "" : "";
  }

  function number(value) {
    return Number(value || 0).toLocaleString(document.documentElement.lang || undefined);
  }

  const bytes = core.bytes;

  function clock(epoch) {
    const date = new Date(Number(epoch) * 1000);
    return date.toLocaleTimeString(document.documentElement.lang || undefined, { hour12: false });
  }

  function duration(seconds) {
    return core.duration(seconds, t);
  }

  function statusBadge(status) {
    const code = Number(status) || 0;
    return `<span class="la-status ${core.statusTone(code)}">${esc(code || "—")}</span>`;
  }

  function countryCell(code) {
    return `${flag(code)} <span class="la-sub">${esc(code || "")}</span>`;
  }

  function ipLink(ip) {
    return `<button type="button" class="la-link la-mono" data-filter-ip="${esc(ip)}">${esc(ip)}</button>`;
  }

  function hostLink(host) {
    if (!host) return "—";
    return `<button type="button" class="la-link la-mono" data-filter-host="${esc(host)}">${esc(host)}</button>`;
  }

  function refusalLabel(name) {
    const labels = (state.data && state.data.refusal_labels) || {};
    return t(labels[name] || name);
  }

  /* ---------- request ---------- */

  function filters() {
    return core.requestParams({
      window: state.window,
      ip: byId("la-ip").value,
      host: byId("la-host").value,
      country: byId("la-country").value,
      status: byId("la-status").value,
      q: byId("la-q").value,
      blocked: byId("la-blocked").checked,
      banned: byId("la-banned-only").checked,
    });
  }

  async function refresh() {
    if (state.inFlight) return;
    state.inFlight = true;
    try {
      const query = new URLSearchParams(filters());
      const response = await fetch(`/api/monitoring/live?${query}`, {
        headers: { Accept: "application/json" }, credentials: "same-origin",
      });
      const payload = await response.json().catch(() => ({}));
      byId("la-unavailable").hidden = response.ok;
      if (!response.ok) {
        byId("la-note").textContent = payload.error || t("The access log cannot be read right now");
        return;
      }
      state.data = payload;
      render();
    } catch (error) {
      byId("la-note").textContent = String(error);
    } finally {
      state.inFlight = false;
    }
  }

  function schedule() {
    window.clearTimeout(state.timer);
    if (state.paused) return;
    state.timer = window.setTimeout(async () => {
      // A hidden tab does not need a fresh answer every two seconds.
      if (!document.hidden) await refresh();
      schedule();
    }, state.refresh * 1000);
  }

  /* ---------- rendering ---------- */

  function setText(id, value) {
    const element = byId(id);
    if (element) element.textContent = value;
  }

  function tone(id, value, warnAt) {
    const card = byId(id);
    if (!card) return;
    const level = core.cardTone(value, warnAt);
    card.classList.toggle("la-warn", level === "warn");
    card.classList.toggle("la-bad", level === "bad");
  }

  function renderSummary(data) {
    const totals = data.totals || {};
    setText("la-rate", Number(totals.rate || 0).toFixed(1));
    setText("la-requests", number(totals.requests));
    setText("la-errors", number(totals.errors));
    setText("la-blocked-count", number(totals.blocked));
    setText("la-addresses", number(totals.addresses));
    setText("la-banned", number(totals.banned_now));
    setText("la-limited", number(totals.connection_limited_now));
    setText("la-connections", number(data.current_connections));
    tone("la-card-blocked", Number(totals.blocked || 0), 100);
    tone("la-card-limited", Number(totals.connection_limited_now || 0), 1);
    setText("la-updated", `${t("Updated at")} ${clock(data.now)}`);

    const note = byId("la-note");
    // Reading the log is capped so that watching it can never compete with
    // HAProxy; under a flood the page falls behind instead, and says so.
    const said = core.summaryNote(data);
    if (said.kind === "behind") {
      note.textContent = `${t("Heavy traffic: the data is behind the log by")} ${duration(said.seconds)}. ` +
        t("Reading is capped so that watching cannot slow the gateway down.");
      note.classList.add("la-warn");
    } else if (said.kind === "partial") {
      note.textContent = `${t("Only the last")} ${duration(said.seconds)} ${t("of the window are in memory")}`;
      note.classList.add("la-warn");
    } else {
      note.textContent = `${t("Time window")}: ${duration(said.seconds)} · ${t("one bar per")} ${duration(said.bucket)}`;
      note.classList.remove("la-warn");
    }

    const reasons = byId("la-reasons");
    reasons.textContent = "";
    core.refusalCounts(data.refusals)
      .forEach(([name, count]) => {
        const chip = document.createElement("span");
        chip.className = "la-badge la-refused";
        chip.textContent = `${refusalLabel(name)}: ${number(count)}`;
        reasons.appendChild(chip);
      });
  }

  const TIMELINE_COLOURS = { ok: "#2e9e5b", errors: "#c8a13a", blocked: "#cc4b4b" };

  function renderTimeline(data) {
    const svg = byId("la-timeline");
    const width = 1000;
    const height = 70;
    const parts = core.timelineRects(data.timeline || [], width, height).map((rect) =>
      `<rect x="${rect.x.toFixed(1)}" y="${rect.y.toFixed(1)}" width="${rect.width.toFixed(1)}" height="${rect.height.toFixed(1)}" fill="${TIMELINE_COLOURS[rect.part]}" opacity=".85"></rect>`
    );
    svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
    svg.innerHTML = parts.join("");
  }

  function sorted(rows, table) {
    return core.sortRows(rows, state.sort[table]);
  }

  // Which badges a row gets, and in what order, is core.badgeKinds.
  function stateBadges(row) {
    const badges = core.badgeKinds(row).map((kind) => {
      if (kind === "banned") {
        return `<span class="la-badge la-ban" title="${esc(t(row.ban.label))}">${esc(t("Banned"))} · ${esc(duration(row.ban.expires_in))}</span>`;
      }
      if (kind === "limited") {
        const c = row.connections || {};
        return `<span class="la-badge la-limit">${esc(t("Connection limit"))} · ${esc(c.rate)}/${esc(c.cur)}</span>`;
      }
      if (kind === "allow-listed") return `<span class="la-badge la-allow">${esc(t("Allow-listed"))}</span>`;
      if (kind === "signed-in") {
        return `<span class="la-badge la-allow" title="${esc(t("Authorized through Authelia right now: zero-trust sites let it in"))}">${esc(t("Signed in now"))}</span>`;
      }
      return `<span class="la-badge la-refused" title="${esc(t("Refused in this window"))}: ${esc(row.reason)}">${esc(t("Refused"))} ×${esc(row.blocked)}: ${esc(refusalLabel(row.reason))}</span>`;
    });
    return badges.join("") || '<span class="la-sub">—</span>';
  }

  // Which control an address gets is core.banAction: "drop & ban" for an
  // address allow-listed by itself, nothing one-click inside an allowed
  // range. Kept short so it fits the same column as the ordinary button.
  function banButton(ip, banned, allowEntry) {
    switch (core.banAction(banned, allowEntry)) {
      case "unban":
        return `<button type="button" class="btn" data-unban="${esc(ip)}">${esc(t("Unban"))}</button>`;
      case "drop-and-ban":
        return `<button type="button" class="btn btn-danger" data-force-ban="${esc(ip)}" title="${esc(t("Remove from the allow list, then ban"))}">${esc(t("Drop & ban"))}</button>`;
      case "in-allowed-range":
        return `<span class="la-sub" title="${esc(t("Allowed by a network range: edit the allow list to ban it"))}">${esc(t("In an allowed range"))}</span>`;
      default:
        return `<button type="button" class="btn btn-danger" data-ban="${esc(ip)}">${esc(t("Ban address"))}</button>`;
    }
  }

  function renderAddresses(data) {
    const body = byId("la-addresses-body");
    const rows = sorted(data.addresses || [], "addresses");
    byId("la-addresses-empty").hidden = rows.length > 0;
    body.innerHTML = rows.map((row) => `
      <tr class="${core.fullyRefused(row) ? "la-row-blocked" : ""}">
        <td>${ipLink(row.ip)}<div>${countryCell(row.country)}</div></td>
        <td class="la-num">${number(row.requests)}</td>
        <td class="la-num">${Number(row.rate || 0).toFixed(2)}</td>
        <td class="la-num">${number(row.errors)}</td>
        <td class="la-num">${number(row.server_errors)}</td>
        <td class="la-num">${number(row.blocked)}</td>
        <td class="la-num">${bytes(row.bytes)}</td>
        <td>${hostLink(row.top_host)}${row.hosts > 1 ? ` <span class="la-sub">+${row.hosts - 1}</span>` : ""}</td>
        <td class="la-mono">${statusBadge(row.last_status)} <span class="la-path" title="${esc(row.last_method)} ${esc(row.last_path)}">${esc(row.last_method)} ${esc(row.last_path)}</span><div class="la-sub">${esc(clock(row.last))}</div></td>
        <td>${stateBadges(row)}</td>
        <td class="la-actions"><div class="la-actions-stack">
          ${banButton(row.ip, Boolean(row.ban), core.allowEntryOf(row))}
          <a class="la-link" href="/ip/${encodeURIComponent(row.ip)}" target="_blank" rel="noopener">${esc(t("Log lines"))}</a>
        </div></td>
      </tr>`).join("");
  }

  function renderSites(data) {
    const body = byId("la-sites-body");
    const rows = sorted(data.sites || [], "sites");
    byId("la-sites-empty").hidden = rows.length > 0;
    body.innerHTML = rows.map((row) => `
      <tr>
        <td>${hostLink(row.host)}</td>
        <td class="la-num">${number(row.requests)}</td>
        <td class="la-num">${number(row.errors)}</td>
        <td class="la-num">${number(row.server_errors)}</td>
        <td class="la-num">${number(row.blocked)}</td>
        <td class="la-num">${number(row.addresses)}</td>
        <td class="la-num">${number(row.avg_ms)} ms</td>
        <td class="la-mono">${esc(row.backend || "—")}</td>
      </tr>`).join("");
  }

  function renderEvents(data) {
    const body = byId("la-events-body");
    const rows = data.events || [];
    byId("la-events-empty").hidden = rows.length > 0;
    body.innerHTML = rows.map((row) => `
      <tr class="${row.refusal ? "la-row-blocked" : ""}">
        <td class="la-mono">${esc(clock(row.ts))}</td>
        <td>${ipLink(row.ip)} ${flag(row.country)}</td>
        <td>${hostLink(row.host)}</td>
        <td class="la-mono"><span class="la-path" title="${esc(row.method)} ${esc(row.path)}">${esc(row.method)} ${esc(row.path)}</span></td>
        <td>${statusBadge(row.status)}</td>
        <td class="la-num">${number(row.duration_ms)}</td>
        <td>${row.refusal ? `<span class="la-badge la-refused" title="${esc(row.ban_reason || "")}">${esc(refusalLabel(row.refusal))}</span>${row.ban_reason ? `<div class="la-sub">${esc(row.ban_reason)}</div>` : ""}` : ""}</td>
      </tr>`).join("");
  }

  function renderBanned(data) {
    const banned = data.banned || [];
    byId("la-banned-empty").hidden = banned.length > 0;
    byId("la-banned-body").innerHTML = banned.map((row) => `
      <tr>
        <td>${ipLink(row.ip)} ${countryCell(row.country)}</td>
        <td>${esc(t(row.label))}</td>
        <td class="la-num">${esc(duration(row.expires_in))}</td>
        <td class="la-num">${number(row.requests_in_window)}</td>
        <td class="la-actions">${banButton(row.ip, true)}</td>
      </tr>`).join("");
    const limits = data.connection_limits || {};
    byId("la-limits-note").textContent =
      `${t("New connections per window")}: ${limits.burst} · ${t("Open connections")}: ${limits.concurrent}. ` +
      t("Connections over the limit are dropped before HTTP and never reach the requests list.");
    const limited = data.connection_limited || [];
    byId("la-limited-empty").hidden = limited.length > 0;
    byId("la-limited-body").innerHTML = limited.map((row) => `
      <tr>
        <td>${ipLink(row.ip)} ${countryCell(row.country)}</td>
        <td class="la-num">${number(row.rate)}</td>
        <td class="la-num">${number(row.cur)}</td>
        <td class="la-actions">${banButton(row.ip, false)}</td>
      </tr>`).join("");
  }

  function fillSelect(id, values, label) {
    const select = byId(id);
    const current = select.value;
    // A choice that is no longer in the data stays selectable (selectValues).
    const options = [`<option value="">${esc(t(label))}</option>`]
      .concat(core.selectValues(values, current).map((value) => `<option value="${esc(value)}">${esc(value)}</option>`));
    select.innerHTML = options.join("");
    select.value = current;
  }

  function renderSorting() {
    document.querySelectorAll("[data-panel]").forEach((panel) => {
      const table = panel.dataset.panel;
      if (!state.sort[table]) return;
      panel.querySelectorAll("th[data-sort]").forEach((th) => {
        const active = th.dataset.sort === state.sort[table].key;
        th.setAttribute("aria-sort", active ? (state.sort[table].dir > 0 ? "ascending" : "descending") : "none");
      });
    });
  }

  function render() {
    const data = state.data;
    if (!data) return;
    renderSummary(data);
    renderTimeline(data);
    renderAddresses(data);
    renderSites(data);
    renderEvents(data);
    renderBanned(data);
    renderSorting();
    fillSelect("la-host", (data.sites || []).map((row) => row.host).filter(Boolean).sort(), "All sites");
    fillSelect("la-country", data.countries || [], "All countries");
  }

  /* ---------- actions ---------- */

  async function ban(ip) {
    if (!window.confirm(`${t("Ban address")} ${ip}?`)) return;
    const response = await fetch("/api/monitoring/live/ban", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken() },
      body: JSON.stringify({ ip }),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || !payload.ok) {
      window.alert(t(payload.error || "The ban was not placed"));
      return;
    }
    refresh();
  }

  async function forceBan(ip) {
    // Louder confirm than a plain ban: this also changes the allow list.
    if (!window.confirm(`${t("Remove from the allow list and ban")} ${ip}?`)) return;
    const response = await fetch("/api/monitoring/live/ban", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken() },
      body: JSON.stringify({ ip, drop_allowlist: true }),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || !payload.ok) {
      window.alert(t(payload.error || "The ban was not placed"));
      return;
    }
    refresh();
  }

  async function unban(ip) {
    if (!window.confirm(`${t("Unban")} ${ip}?`)) return;
    const response = await fetch("/api/unban", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/x-www-form-urlencoded", "X-CSRFToken": csrfToken() },
      body: `ip=${encodeURIComponent(ip)}`,
    });
    if (!response.ok) window.alert(await response.text());
    refresh();
  }

  function applyNow() {
    save();
    refresh();
    schedule();
  }

  function bind() {
    byId("la-windows").addEventListener("click", (event) => {
      const button = event.target.closest("[data-window]");
      if (!button) return;
      state.window = Number(button.dataset.window);
      byId("la-window-custom").value = "";
      markWindow();
      applyNow();
    });
    byId("la-window-custom").addEventListener("change", (event) => {
      const seconds = core.customWindow(event.target.value);
      if (seconds !== null) {
        state.window = seconds;
        markWindow();
        applyNow();
      }
    });
    byId("la-refresh").addEventListener("change", (event) => {
      state.refresh = Number(event.target.value) || 5;
      applyNow();
    });
    byId("la-pause").addEventListener("click", () => {
      state.paused = !state.paused;
      byId("la-pause").textContent = t(state.paused ? "Resume updates" : "Pause updates");
      if (!state.paused) refresh();
      schedule();
    });
    ["la-host", "la-country", "la-status", "la-blocked", "la-banned-only"].forEach((id) => {
      byId(id).addEventListener("change", applyNow);
    });
    ["la-ip", "la-q"].forEach((id) => {
      let pending = null;
      byId(id).addEventListener("input", () => {
        window.clearTimeout(pending);
        pending = window.setTimeout(applyNow, 500);
      });
    });
    byId("la-reset").addEventListener("click", () => {
      ["la-ip", "la-q"].forEach((id) => { byId(id).value = ""; });
      ["la-host", "la-country", "la-status"].forEach((id) => { byId(id).value = ""; });
      byId("la-blocked").checked = false;
      byId("la-banned-only").checked = false;
      applyNow();
    });
    byId("la-tabs").addEventListener("click", (event) => {
      const button = event.target.closest("[data-tab]");
      if (!button) return;
      state.tab = button.dataset.tab;
      markTab();
      save();
    });
    document.querySelectorAll("th[data-sort]").forEach((th) => {
      th.addEventListener("click", () => {
        const table = th.closest("[data-panel]").dataset.panel;
        state.sort[table] = core.sortAfterClick(state.sort[table], th.dataset.sort);
        save();
        render();
      });
    });
    document.addEventListener("click", (event) => {
      const ip = event.target.closest("[data-filter-ip]");
      if (ip) {
        byId("la-ip").value = ip.dataset.filterIp;
        applyNow();
        return;
      }
      const host = event.target.closest("[data-filter-host]");
      if (host) {
        fillSelect("la-host", [host.dataset.filterHost], "All sites");
        byId("la-host").value = host.dataset.filterHost;
        applyNow();
        return;
      }
      const banTarget = event.target.closest("[data-ban]");
      if (banTarget) {
        ban(banTarget.dataset.ban);
        return;
      }
      const forceBanTarget = event.target.closest("[data-force-ban]");
      if (forceBanTarget) {
        forceBan(forceBanTarget.dataset.forceBan);
        return;
      }
      const unbanTarget = event.target.closest("[data-unban]");
      if (unbanTarget) unban(unbanTarget.dataset.unban);
    });
  }

  function markWindow() {
    document.querySelectorAll("#la-windows [data-window]").forEach((button) => {
      button.setAttribute("aria-pressed", Number(button.dataset.window) === state.window ? "true" : "false");
    });
  }

  function markTab() {
    document.querySelectorAll("#la-tabs [data-tab]").forEach((button) => {
      button.setAttribute("aria-pressed", button.dataset.tab === state.tab ? "true" : "false");
    });
    document.querySelectorAll("[data-panel]").forEach((panel) => {
      panel.hidden = panel.dataset.panel !== state.tab;
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    load();
    byId("la-refresh").value = String(state.refresh);
    if (!core.isPresetWindow(state.window)) byId("la-window-custom").value = String(state.window);
    // An address in the address bar (?ip=...) is where the operator came from.
    const params = new URLSearchParams(window.location.search);
    if (params.get("ip")) byId("la-ip").value = params.get("ip");
    markWindow();
    markTab();
    bind();
    refresh();
    schedule();
  });
})();
