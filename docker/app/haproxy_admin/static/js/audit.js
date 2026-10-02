/* Change log: filter the record, and open one entry to see what changed.
 *
 * Read-only by construction. The API offers no way to write or edit a record,
 * and this page has no control that would ask for one.
 */
(function () {
  "use strict";

  const t = window.t || ((value) => String(value));
  const numberFormat = new Intl.NumberFormat(document.documentElement.lang || undefined);
  const dateTimeFormat = new Intl.DateTimeFormat(document.documentElement.lang || undefined, {
    dateStyle: "short",
    timeStyle: "medium"
  });

  const PAGE_SIZE = 100;
  let offset = 0;
  let total = 0;

  function byId(id) {
    return document.getElementById(id);
  }

  function uiText(value) {
    return t(value);
  }

  function formatTime(seconds) {
    const numeric = Number(seconds);
    if (!Number.isFinite(numeric) || numeric <= 0) return "—";
    return dateTimeFormat.format(new Date(numeric * 1000));
  }

  function filters() {
    const params = new URLSearchParams();
    const range = byId("au-range");
    if (range && range.value) params.set("range", range.value);
    [
      ["au-actor", "actor"],
      ["au-action", "action"],
      ["au-object", "object_type"],
      ["au-result", "result"]
    ].forEach(([id, name]) => {
      const element = byId(id);
      if (element && element.value) params.set(name, element.value);
    });
    return params;
  }

  async function getJson(path, params) {
    const query = new URLSearchParams(params || {});
    const response = await fetch(`${path}?${query.toString()}`, {
      headers: { Accept: "application/json" },
      credentials: "same-origin"
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.error || `HTTP ${response.status}`);
    return payload;
  }

  function fillSelect(id, values, anyLabel) {
    const select = byId(id);
    if (!select) return;
    const current = select.value;
    select.textContent = "";
    const any = document.createElement("option");
    any.value = "";
    any.textContent = uiText(anyLabel);
    select.appendChild(any);
    (values || []).forEach((value) => {
      const option = document.createElement("option");
      option.value = value;
      option.textContent = value;
      // Actor names and action identifiers are data, not interface language.
      option.setAttribute("data-i18n-skip", "");
      select.appendChild(option);
    });
    if (current) select.value = current;
  }

  function showDetail(event) {
    const detail = byId("au-detail");
    if (!detail) return;
    detail.hidden = false;
    byId("au-detail-title").textContent = `${event.action} · ${event.object_id || "—"}`;

    const meta = [
      `${uiText("When")}: ${formatTime(event.ts)}`,
      `${uiText("Who")}: ${event.actor || event.actor_type}`,
      `${uiText("Outcome")}: ${event.result}`
    ];
    if (event.source_ip) meta.push(`${uiText("From")}: ${event.source_ip}`);
    if (event.detail) meta.push(event.detail);
    byId("au-detail-meta").textContent = meta.join(" · ");

    const bodies = byId("au-detail-bodies");
    bodies.textContent = "";
    [
      ["Before", event.before_json],
      ["After", event.after_json]
    ].forEach(([label, raw]) => {
      if (!raw) return;
      const heading = document.createElement("div");
      heading.textContent = uiText(label);
      bodies.appendChild(heading);
      const block = document.createElement("pre");
      block.setAttribute("data-i18n-skip", "");
      block.setAttribute("translate", "no");
      try {
        block.textContent = JSON.stringify(JSON.parse(raw), null, 2);
      } catch (error) {
        block.textContent = raw;
      }
      bodies.appendChild(block);
    });
  }

  function renderRows(events, append) {
    const body = byId("au-body");
    const empty = byId("au-empty");
    if (!body) return;
    if (!append) body.textContent = "";
    if (!events.length && !append) {
      if (empty) empty.hidden = false;
      return;
    }
    if (empty) empty.hidden = true;

    events.forEach((event) => {
      const row = document.createElement("tr");
      row.className = "au-row";
      row.addEventListener("click", () => showDetail(event));

      [
        formatTime(event.ts),
        event.actor || event.actor_type,
        event.action,
        event.object_id || event.object_type || "—",
        event.summary || event.detail || "—"
      ].forEach((value) => {
        const cell = document.createElement("td");
        cell.textContent = value;
        row.appendChild(cell);
      });

      const outcome = document.createElement("td");
      const pill = document.createElement("span");
      pill.className = `au-result au-${event.result}`;
      pill.textContent = event.result;
      outcome.appendChild(pill);
      row.appendChild(outcome);

      body.appendChild(row);
    });
  }

  async function load(append) {
    if (!append) offset = 0;
    const params = filters();
    params.set("limit", String(PAGE_SIZE));
    params.set("offset", String(offset));
    try {
      const payload = await getJson("/api/audit/events", params);
      total = Number(payload.total) || 0;
      const events = payload.events || [];
      renderRows(events, append);
      offset += events.length;
      const more = byId("au-more");
      if (more) more.hidden = offset >= total;
      const status = byId("au-status");
      if (status) {
        status.textContent = `${numberFormat.format(offset)} / ${numberFormat.format(total)}`;
      }
    } catch (error) {
      const status = byId("au-status");
      if (status) status.textContent = String(error.message || error);
    }
  }

  async function loadFilters() {
    try {
      const payload = await getJson("/api/audit/filters", {});
      fillSelect("au-actor", payload.actors, "Anyone");
      fillSelect("au-action", payload.actions, "Any action");
      fillSelect("au-object", payload.object_types, "Any object");
      fillSelect("au-result", payload.results, "Any outcome");
    } catch (error) {
      /* filters stay as the empty defaults */
    }
  }

  document.addEventListener("DOMContentLoaded", async () => {
    ["au-range", "au-actor", "au-action", "au-object", "au-result"].forEach((id) => {
      const element = byId(id);
      if (element) element.addEventListener("change", () => load(false));
    });
    const more = byId("au-more");
    if (more) more.addEventListener("click", () => load(true));
    await loadFilters();
    await load(false);
  });
})();
