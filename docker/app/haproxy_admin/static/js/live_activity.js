/* Live activity: who is hitting the gateway right now and what they get.
 *
 * One request every few seconds to /api/monitoring/live; everything else --
 * sorting, tabs, the timeline -- happens here on the answer. Filters that
 * change what is counted go back to the server; sorting does not.
 */
(function () {
  "use strict";

  const t = window.t || ((value) => String(value));
  const esc = window.escapeHtml;
  const flag = window.countryFlagMarkup;
  const STORE = "live-activity";

  const state = {
    window: 60,
    refresh: 5,
    paused: false,
    tab: "addresses",
    sort: {
      addresses: { key: "requests", dir: -1 },
      sites: { key: "requests", dir: -1 },
    },
    data: null,
    timer: null,
    inFlight: false,
  };

  function byId(id) {
    return document.getElementById(id);
  }

  function load() {
    try {
      const saved = JSON.parse(window.localStorage.getItem(STORE) || "{}");
      if (Number(saved.window) >= 5) state.window = Number(saved.window);
      if ([2, 5, 10, 30].includes(Number(saved.refresh))) state.refresh = Number(saved.refresh);
      if (["addresses", "sites", "events", "banned"].includes(saved.tab)) state.tab = saved.tab;
      if (saved.sort && typeof saved.sort === "object") Object.assign(state.sort, saved.sort);
    } catch (error) {
      // Private mode or a damaged entry: defaults.
    }
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

  function bytes(value) {
    let size = Number(value || 0);
    const units = ["B", "KiB", "MiB", "GiB"];
    let index = 0;
    while (size >= 1024 && index < units.length - 1) {
      size /= 1024;
      index += 1;
    }
    return `${size.toFixed(index ? 1 : 0)} ${units[index]}`;
  }

  function clock(epoch) {
    const date = new Date(Number(epoch) * 1000);
    return date.toLocaleTimeString(document.documentElement.lang || undefined, { hour12: false });
  }

  function duration(seconds) {
    const value = Math.max(0, Number(seconds) || 0);
    if (value < 60) return `${value} ${t("sec")}`;
    if (value < 3600) return `${Math.round(value / 60)} ${t("min")}`;
    if (value < 86400) return `${Math.round(value / 3600)} ${t("hr")}`;
    return `${Math.round(value / 86400)} ${t("days")}`;
  }

  function statusBadge(status) {
    const code = Number(status) || 0;
    const tone = code >= 500 ? "la-s5" : code >= 400 ? "la-s4" : code >= 300 ? "la-s3" : "la-s2";
    return `<span class="la-status ${tone}">${esc(code || "—")}</span>`;
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
    const params = { window: state.window };
    const ip = byId("la-ip").value.trim();
    if (ip) params.ip = ip;
    const host = byId("la-host").value;
    if (host) params.host = host;
    const country = byId("la-country").value;
    if (country) params.country = country;
    const status = byId("la-status").value;
    if (status) params.status = status;
    const query = byId("la-q").value.trim();
    if (query) params.q = query;
    if (byId("la-blocked").checked) params.blocked = "1";
    return params;
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
    card.classList.toggle("la-warn", value > 0 && value < warnAt);
    card.classList.toggle("la-bad", value >= warnAt);
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
    const behind = Number(data.lag_bytes || 0) > 0 && Number(data.lag_seconds || 0) > 15;
    if (behind) {
      note.textContent = `${t("Heavy traffic: the data is behind the log by")} ${duration(data.lag_seconds)}. ` +
        t("Reading is capped so that watching cannot slow the gateway down.");
      note.classList.add("la-warn");
    } else if (data.truncated) {
      note.textContent = `${t("Only the last")} ${duration(data.covered_seconds)} ${t("of the window are in memory")}`;
      note.classList.add("la-warn");
    } else {
      note.textContent = `${t("Time window")}: ${duration(data.window)} · ${t("one bar per")} ${duration(data.bucket_seconds)}`;
      note.classList.remove("la-warn");
    }

    const reasons = byId("la-reasons");
    reasons.textContent = "";
    Object.entries(data.refusals || {})
      .sort((a, b) => b[1] - a[1])
      .forEach(([name, count]) => {
        const chip = document.createElement("span");
        chip.className = "la-badge la-refused";
        chip.textContent = `${refusalLabel(name)}: ${number(count)}`;
        reasons.appendChild(chip);
      });
  }

  function renderTimeline(data) {
    const svg = byId("la-timeline");
    const bars = data.timeline || [];
    const peak = Math.max(1, ...bars.map((bar) => bar.ok + bar.errors + bar.blocked));
    const width = 1000;
    const height = 70;
    const step = width / Math.max(1, bars.length);
    const parts = [];
    bars.forEach((bar, index) => {
      let y = height;
      [["ok", "#2e9e5b"], ["errors", "#c8a13a"], ["blocked", "#cc4b4b"]].forEach(([key, color]) => {
        const h = (bar[key] / peak) * (height - 4);
        if (h <= 0) return;
        y -= h;
        parts.push(`<rect x="${(index * step + 1).toFixed(1)}" y="${y.toFixed(1)}" width="${Math.max(1, step - 2).toFixed(1)}" height="${h.toFixed(1)}" fill="${color}" opacity=".85"></rect>`);
      });
    });
    svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
    svg.innerHTML = parts.join("");
  }

  function sorted(rows, table) {
    const { key, dir } = state.sort[table];
    return rows.slice().sort((a, b) => {
      const left = Number(a[key] || 0);
      const right = Number(b[key] || 0);
      return (left - right) * dir || String(a.ip || a.host).localeCompare(String(b.ip || b.host));
    });
  }

  function stateBadges(row) {
    const badges = [];
    if (row.ban) {
      badges.push(`<span class="la-badge la-ban" title="${esc(t(row.ban.label))}">${esc(t("Banned"))} · ${esc(duration(row.ban.expires_in))}</span>`);
    }
    if (row.connection_limited) {
      const c = row.connections || {};
      badges.push(`<span class="la-badge la-limit">${esc(t("Connection limit"))} · ${esc(c.rate)}/${esc(c.cur)}</span>`);
    }
    if (row.allow_listed) badges.push(`<span class="la-badge la-allow">${esc(t("Allow-listed"))}</span>`);
    if (row.authorized) badges.push(`<span class="la-badge la-allow">${esc(t("Signed in"))}</span>`);
    if (row.reason && row.blocked) {
      badges.push(`<span class="la-badge la-refused" title="${esc(row.reason)}">${esc(refusalLabel(row.reason))}</span>`);
    }
    return badges.join("") || '<span class="la-sub">—</span>';
  }

  function banButton(ip, banned) {
    return banned
      ? `<button type="button" class="btn" data-unban="${esc(ip)}">${esc(t("Unban"))}</button>`
      : `<button type="button" class="btn btn-danger" data-ban="${esc(ip)}">${esc(t("Ban address"))}</button>`;
  }

  function renderAddresses(data) {
    const body = byId("la-addresses-body");
    const rows = sorted(data.addresses || [], "addresses");
    byId("la-addresses-empty").hidden = rows.length > 0;
    body.innerHTML = rows.map((row) => `
      <tr class="${row.blocked && row.blocked === row.requests ? "la-row-blocked" : ""}">
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
          ${banButton(row.ip, Boolean(row.ban))}
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
    const options = [`<option value="">${esc(t(label))}</option>`]
      .concat(values.map((value) => `<option value="${esc(value)}">${esc(value)}</option>`));
    // A choice that is no longer in the data stays selectable, or the filter
    // would silently drop the moment its last request leaves the window.
    if (current && !values.includes(current)) {
      options.push(`<option value="${esc(current)}">${esc(current)}</option>`);
    }
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
      const value = Number(event.target.value);
      if (value >= 5 && value <= 3600) {
        state.window = Math.round(value);
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
    ["la-host", "la-country", "la-status", "la-blocked"].forEach((id) => {
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
        const current = state.sort[table];
        state.sort[table] = current.key === th.dataset.sort
          ? { key: current.key, dir: -current.dir }
          : { key: th.dataset.sort, dir: -1 };
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
    if (![30, 60, 300, 900].includes(state.window)) byId("la-window-custom").value = String(state.window);
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
