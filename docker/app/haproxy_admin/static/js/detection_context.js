/* Contextual detection controls. Preview input is never put in a URL, browser
 * storage or diagnostics; only the authenticated POST carries its query. */
(function () {
  "use strict";
  const t = window.t || ((v) => String(v));
  const el = (id) => document.getElementById(id);
  let state = null;
  let busy = false;
  const actions = { observe: "Observation", enforce: "Count towards bans", excepted: "Exception", trusted: "Trusted warning" };

  function message(value, error = false) {
    el("dc-message").textContent = value;
    el("dc-message").classList.toggle("error", error);
  }

  async function api(path, body) {
    const meta = document.querySelector('meta[name="csrf-token"]');
    const response = await fetch(`/api/security/detection-rules/${path}`, {
      method: body === undefined ? "GET" : "POST", credentials: "same-origin",
      headers: { Accept: "application/json", "Content-Type": "application/json", "X-CSRFToken": meta ? meta.content : "" },
      ...(body === undefined ? {} : { body: JSON.stringify(body) })
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok || data.ok === false) throw new Error(data.error || `HTTP ${response.status}`);
    return data;
  }

  function button(text, fn) {
    const node = document.createElement("button");
    node.type = "button";
    node.className = "btn";
    node.textContent = t(text);
    node.addEventListener("click", fn);
    return node;
  }

  function table(target, headings, rows) {
    const host = el(target);
    host.replaceChildren();
    if (!rows.length) { host.textContent = t("No observations or settings yet"); return; }
    const grid = document.createElement("table");
    const head = grid.createTHead().insertRow();
    headings.forEach((heading) => { const th = document.createElement("th"); th.textContent = t(heading); th.scope = "col"; head.appendChild(th); });
    const body = grid.createTBody();
    rows.forEach((cells) => {
      const row = body.insertRow();
      cells.forEach((value) => { const cell = row.insertCell(); if (value instanceof Node) cell.appendChild(value); else cell.textContent = String(value); });
    });
    host.appendChild(grid);
  }

  function choices(id, values, labels = new Map()) {
    const select = el(id), current = select.value;
    select.replaceChildren(...values.map((value) => { const option = document.createElement("option"); option.value = value; option.textContent = labels.get(value) || value; return option; }));
    if (values.includes(current)) select.value = current;
  }

  function modeFor(id) {
    const custom = state.config.rules.find((r) => r.id === id);
    return state.config.modes[id] || (custom ? custom.mode : (Object.hasOwn(state.new_rules, id) ? "observe" : "enforce"));
  }

  function modeLabel(id) { return t(actions[modeFor(id)]); }

  function siteLinks(row) {
    const links = document.createElement("span");
    Object.keys(row.hosts).forEach((host, index) => {
      if (index) links.appendChild(document.createTextNode(", "));
      const link = document.createElement("a");
      link.textContent = host;
      const query = new URLSearchParams({ host, since: Math.max(0, row.first - 60), until: row.last + 60 });
      link.href = row.id.startsWith("auth:") ? "/authelia/bans" : `/security/requests?${query}`;
      links.appendChild(link);
    });
    return links;
  }

  function showMode() {
    const id = el("dc-mode-rule").value;
    el("dc-mode-value").value = modeFor(id);
    el("dc-mode-value").querySelector('[value="enforce"]').disabled = (state.warning_only || []).includes(id);
  }

  function render() {
    const config = state.config;
    const ids = [...state.builtin_ids, ...config.rules.map((r) => r.id)].sort();
    const labels = new Map(config.rules.map((r) => [r.id, `${r.hosts.join(", ")} · ${r.value} (${r.id})`]));
    choices("dc-ex-rule", ids, labels);
    choices("dc-mode-rule", ids, labels);
    showMode();
    table("dc-rules", ["Rule", "Scope", "Category", "Mode", ""], config.rules.map((r) => [r.id, `${r.hosts.join(", ")} · ${r.methods.join(", ") || "*"} · ${r.match} ${r.value} · HTTP ${(r.statuses || []).join(", ") || "*"}`, r.category, modeLabel(r.id), button("Remove", () => change((next) => {
      next.rules = next.rules.filter((entry) => entry.id !== r.id);
      next.exceptions = next.exceptions.filter((entry) => entry.rule !== r.id);
      delete next.modes[r.id];
    }))]));
    table("dc-exceptions", ["Rule", "Scope", "Reason", "Expires", ""], config.exceptions.map((r) => [r.rule,
      `${r.hosts.join(", ")} · ${r.methods.join(", ") || "*"} · ${r.match} ${r.value} · HTTP ${(r.statuses || []).join(", ") || "*"}`, r.reason,
      r.expires ? new Date(r.expires * 1000).toLocaleDateString() : "—", button("Remove", () => change((next) => { next.exceptions = next.exceptions.filter((entry) => entry.id !== r.id); }))]));
    table("dc-profiles", ["Site", "Profile", "Methods", "Expected routes", ""], Object.entries(config.profiles).map(([host, name]) => [host, name, state.profiles[name].methods.join(", "), state.profiles[name].routes.join(", ") || "—", button("Remove", () => change((next) => { delete next.profiles[host]; }))]));
    table("dc-stats", ["Rule", "Hits", "Unique IPs", "Observation", "Trusted warning", "Exception", "Hits in scoring mode", "Sites"], state.stats.map((r) => [r.id, r.hits, `${r.unique_ips}${r.unique_ips_capped ? "+" : ""}`, r.observe, r.trusted, r.excepted, r.enforce, siteLinks(r)]));
    el("dc-capacity").textContent = `${t("Tracked IP/site pairs")}: ${state.limits.tracked_now}/${state.limits.tracked} · ${t("Capacity evictions")}: ${state.limits.evictions} · ${t("State errors")}: ${state.limits.state_errors || 0}`;
    if (state.login_source) {
      const source = state.login_source;
      el("dc-capacity").textContent += ` · Authelia: ${t(source.enabled ? (source.error ? "Log unavailable" : "JSON log enabled") : "Log disabled")} · ${t("Log lag, bytes")}: ${source.lag_bytes} · ${t("Dropped observations")}: ${source.dropped}`;
    }
    if (state.scoring) {
      let text = t("Score window: {window_hours} hours; linear decay to zero after {decay_hours} hours; ban threshold: {ban_score} points.");
      Object.entries(state.scoring).forEach(([key, value]) => { text = text.replace(`{${key}}`, String(value)); });
      el("dc-scoring").textContent = `${t("Protection mode")}: ${t(state.active_mode)} · ${text}`;
    }
    el("dc-behavior").replaceChildren(...Object.entries(state.new_rules).map(([id, description]) => {
      const card = document.createElement("div"); card.className = "dr-rule";
      const title = document.createElement("strong"); title.textContent = id;
      const note = document.createElement("p"); note.className = "mon-sub"; note.textContent = t(description);
      const mode = document.createElement("p"); mode.textContent = modeLabel(id);
      card.append(title, note, mode); return card;
    }));
    table("dc-existing", ["Rule", "Conditions"], (state.existing_behavior || []).map((rule) => {
      let text;
      if (rule.gap_hours) text = t("Another scanner finding after {gap_hours} hours, within {days} days");
      else if (rule.paths) text = t("At least {paths} distinct missing routes within {minutes} minutes");
      else if (rule.hits) text = t("At least {hits} scanner hits in total; {categories} categories in the last {hours} hours");
      else text = t("At least {categories} categories in the last {hours} hours");
      Object.entries(rule).forEach(([key, value]) => { text = text.replace(`{${key}}`, String(value)); });
      return [rule.id, text];
    }));
  }

  async function load() {
    if (busy) return;
    try { state = await api("context"); render(); message(t("Saved settings loaded")); }
    catch (error) { message(t(String(error.message)), true); }
  }

  async function change(edit) {
    if (busy || !state) return;
    const next = JSON.parse(JSON.stringify(state.config));
    edit(next);
    busy = true;
    const buttons = [...el("dc-settings").querySelectorAll("button")];
    buttons.forEach((node) => { node.disabled = true; });
    try { state = await api("context", next); render(); message(t("Saved")); }
    catch (error) { message(t(String(error.message)), true); }
    finally { busy = false; buttons.forEach((node) => { node.disabled = false; }); }
  }

  function scope(prefix) {
    return { hosts: [el(`${prefix}-host`).value.trim().toLowerCase()], methods: el(`${prefix}-methods`).value.toUpperCase().split(/[\s,]+/).filter(Boolean), statuses: el(`${prefix}-statuses`).value.split(/[\s,]+/).filter(Boolean).map(Number), match: el(`${prefix}-match`).value, value: el(`${prefix}-value`).value.trim() };
  }

  function identifier(prefix) { return `${prefix}:${Date.now()}-${Math.random().toString(36).slice(2, 8)}`; }

  function prepareException(row, host, method, path) {
    el("dc-ex-rule").value = row.id;
    el("dc-ex-host").value = host;
    el("dc-ex-methods").value = method;
    el("dc-ex-statuses").value = el("dc-status").value;
    el("dc-ex-match").value = "exact";
    el("dc-ex-value").value = path;
    el("dc-exception-section").open = true;
    el("dc-exception-section").scrollIntoView({ behavior: "smooth", block: "center" });
    el("dc-ex-reason").focus({ preventScroll: true });
  }

  async function preview(event) {
    event.preventDefault();
    const result = el("dc-preview-result"), submit = event.submitter;
    if (submit) submit.disabled = true;
    result.textContent = t("Checking request");
    const host = el("dc-host").value.trim(), method = el("dc-method").value.toUpperCase();
    try {
      const data = await api("preview", { host, method, url: el("dc-url").value, status: Number(el("dc-status").value), ip: el("dc-ip").value.trim(), user_agent: el("dc-agent").value });
      result.replaceChildren();
      const summary = document.createElement("p");
      summary.textContent = `${t("Nominal points for this request")}: ${data.nominal_points} · ${t("Profile")}: ${data.profile}`;
      if (data.active_mode) summary.textContent += ` · ${t("Protection mode")}: ${t(data.active_mode)}`;
      result.appendChild(summary);
      if (!data.matches.length) { const empty = document.createElement("p"); empty.textContent = t("No matching request rules. Behavioral rules require traffic history."); result.appendChild(empty); }
      data.matches.forEach((row) => {
        const node = document.createElement("div"), text = document.createElement("span");
        text.textContent = `${row.id} · ${t(actions[row.action] || row.action)} · ${row.points} ${t("points")}${row.exception ? ` · ${row.exception}` : ""}`;
        node.append(text, button("Prepare exception", () => prepareException(row, host, method, data.path)));
        result.appendChild(node);
      });
    } catch (error) { result.textContent = t(String(error.message)); }
    finally { if (submit) submit.disabled = false; }
  }

  // A suggestion fills a scoped observation rule for the operator to review;
  // it must never silently create a global blocking signature.
  window.detectionContextSuggestion = (item, category) => {
    el("dc-rule-host").value = item.host || (item.hosts || [])[0] || "";
    el("dc-rule-value").value = item.path;
    el("dc-rule-statuses").value = Object.keys(item.status || {}).join(", ");
    el("dc-rule-match").value = "exact";
    el("dc-rule-mode").value = "observe";
    el("dc-rule-category").value = category;
    el("dc-rule-form").parentElement.open = true;
    el("dc-rule-form").scrollIntoView({ behavior: "smooth", block: "center" });
  };

  document.addEventListener("DOMContentLoaded", () => {
    if (!el("dc-preview")) return;
    el("dc-preview").addEventListener("submit", preview);
    el("dc-refresh").addEventListener("click", load);
    el("dc-rule-form").addEventListener("submit", (event) => { event.preventDefault(); change((next) => next.rules.push({ id: identifier("custom"), ...scope("dc-rule"), category: el("dc-rule-category").value, mode: el("dc-rule-mode").value })); });
    el("dc-exception-form").addEventListener("submit", (event) => { event.preventDefault(); change((next) => next.exceptions.push({ id: identifier("exception"), rule: el("dc-ex-rule").value, ...scope("dc-ex"), reason: el("dc-ex-reason").value, expires: el("dc-ex-expires").value ? Math.floor(new Date(`${el("dc-ex-expires").value}T23:59:59`).getTime() / 1000) : 0 })); });
    el("dc-mode-form").addEventListener("submit", (event) => { event.preventDefault(); change((next) => { next.modes[el("dc-mode-rule").value] = el("dc-mode-value").value; }); });
    el("dc-mode-rule").addEventListener("change", () => { if (state) showMode(); });
    el("dc-profile-form").addEventListener("submit", (event) => { event.preventDefault(); change((next) => { next.profiles[el("dc-profile-host").value.trim().toLowerCase()] = el("dc-profile-name").value; }); });
    fetch("/api/security/detection-rules", { credentials: "same-origin" }).then((r) => r.json()).then((data) => choices("dc-rule-category", [...new Set(["custom", ...(data.categories || []).map((r) => r.name)])])).catch(() => choices("dc-rule-category", ["custom"]));
    load();
  });
})();
