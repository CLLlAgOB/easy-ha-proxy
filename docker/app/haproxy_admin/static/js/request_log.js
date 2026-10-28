/* Log Explorer: find one request again.
 *
 * Read-only. Everything shown here came out of the access log after the
 * engine's own normalization, so there is nothing to redact on this side --
 * the query string was dropped before it was stored.
 */
(function () {
  "use strict";

  const t = window.t || ((value) => String(value));
  const dateTimeFormat = new Intl.DateTimeFormat(document.documentElement.lang || undefined, {
    dateStyle: "short",
    timeStyle: "medium"
  });

  const PAGE_SIZE = 100;
  // The filters of the search on screen: "show more" carries on with these,
  // not with whatever has been typed since.
  let query = null;
  // Where "show more" carries on: below the last row, or below where a
  // search that ran out of time stopped. 0 when there is nothing further.
  let next = 0;
  // The newest search; an answer to an older one is dropped.
  let sequence = 0;

  function byId(id) {
    return document.getElementById(id);
  }

  function formatTime(seconds) {
    const numeric = Number(seconds);
    if (!Number.isFinite(numeric) || numeric <= 0) return "—";
    return dateTimeFormat.format(new Date(numeric * 1000));
  }

  function statusClass(status) {
    const numeric = Number(status) || 0;
    if (numeric >= 500) return "rq-5xx";
    if (numeric >= 400) return "rq-4xx";
    if (numeric >= 300) return "rq-3xx";
    if (numeric >= 200) return "rq-2xx";
    return "rq-4xx";
  }

  // A period a link brought (the monitoring page's charts link here): kept
  // as an extra choice in the period list until the filters are reset.
  let chosenPeriod = null;
  const LINK_FILTERS = [
    ["status", "rq-status"],
    ["client", "rq-client"],
    ["host", "rq-host"],
    ["backend", "rq-backend"],
    ["path", "rq-path"],
    ["request_id", "rq-request-id"]
  ];

  function applyLink() {
    const params = new URLSearchParams(window.location.search);
    LINK_FILTERS.forEach(([name, id]) => {
      const value = (params.get(name) || "").trim();
      const element = byId(id);
      if (element && value) element.value = value.slice(0, 200);
    });
    const since = Number(params.get("since"));
    const until = Number(params.get("until"));
    const select = byId("rq-range");
    if (!select || !Number.isInteger(since) || !Number.isInteger(until) || since <= 0 || until - since < 60) {
      return;
    }
    chosenPeriod = { since: since, until: until };
    const option = document.createElement("option");
    option.value = "chosen";
    option.setAttribute("data-i18n-skip", "");
    option.setAttribute("translate", "no");
    option.textContent = `${t("Chosen period")}: ${formatTime(since)} – ${formatTime(until)}`;
    select.insertBefore(option, select.firstChild);
    select.value = "chosen";
  }

  function forgetLink() {
    chosenPeriod = null;
    const select = byId("rq-range");
    const option = select && select.querySelector('option[value="chosen"]');
    if (option) {
      option.remove();
      select.value = "86400";
    }
  }

  function filters() {
    const params = new URLSearchParams();
    const choice = byId("rq-range").value;
    if (choice === "chosen" && chosenPeriod) {
      params.set("since", String(chosenPeriod.since));
      params.set("until", String(chosenPeriod.until));
    }
    const range = Number(choice || 0);
    if (range > 0) {
      params.set("since", String(Math.floor(Date.now() / 1000) - range));
    }
    [
      ["rq-status", "status"],
      ["rq-client", "client"],
      ["rq-host", "host"],
      ["rq-backend", "backend"],
      ["rq-path", "path"],
      ["rq-request-id", "request_id"]
    ].forEach(([id, name]) => {
      const element = byId(id);
      if (element && element.value.trim()) params.set(name, element.value.trim());
    });
    const admin = byId("rq-admin");
    if (!admin || !admin.checked) params.set("hide_admin", "1");
    return params;
  }

  async function getJson(path, params) {
    const query = new URLSearchParams(params || {});
    const response = await fetch(`${path}?${query.toString()}`, {
      headers: { Accept: "application/json" },
      credentials: "same-origin"
    });
    const payload = await response.json().catch(() => ({}));
    return { status: response.status, payload };
  }

  function cell(row, value, className) {
    const td = document.createElement("td");
    if (value instanceof Node) td.appendChild(value);
    else td.textContent = value == null || value === "" ? "—" : String(value);
    if (className) td.className = className;
    row.appendChild(td);
    return td;
  }

  function render(rows, append) {
    const body = byId("rq-body");
    if (!body) return;
    if (!append) body.textContent = "";
    rows.forEach((entry) => {
      const tr = document.createElement("tr");
      cell(tr, formatTime(entry.ts));

      const badge = document.createElement("span");
      badge.className = `rq-status ${statusClass(entry.status)}`;
      badge.textContent = entry.bad_request ? t("bad request") : String(entry.status);
      cell(tr, badge);

      cell(tr, entry.method);
      cell(tr, entry.host);
      cell(tr, entry.path, "rq-path");
      cell(
        tr,
        entry.server ? `${entry.backend} / ${entry.server}` : entry.backend
      );
      cell(tr, entry.client);
      // How soon the server answered; the whole request -- a download, a
      // long poll -- is in the tooltip. 0 ms is an answer, not a dash.
      const answered = Number(entry.response_ms);
      const timing = cell(tr, Number.isFinite(answered) && answered >= 0 ? `${answered} ${t("ms")}` : "—");
      if (Number.isFinite(Number(entry.duration_ms))) {
        timing.title = `${t("The whole request")}: ${entry.duration_ms} ${t("ms")}`;
      }
      cell(tr, entry.request_id, "rq-path");
      body.appendChild(tr);
    });
  }

  function renderFound(payload, append) {
    const body = byId("rq-body");
    const shown = body ? body.children.length : 0;
    const empty = byId("rq-empty");
    if (empty) empty.hidden = shown > 0 || Boolean(payload.timed_out);
    const more = byId("rq-more");
    if (more) more.hidden = !next;
    const found = byId("rq-found");
    if (found && !append && payload.total !== undefined) {
      const total = Number(payload.total || 0).toLocaleString(document.documentElement.lang || undefined);
      found.textContent = payload.total_exact === false
        ? `${t("Found, at least")}: ${total}`
        : `${t("Found")}: ${total}`;
    }
    const stopped = byId("rq-stopped");
    if (stopped) {
      stopped.hidden = !payload.timed_out;
      stopped.textContent = payload.timed_out
        ? `${t("The search stopped after a few seconds; it reached back to")} ${formatTime(payload.searched_to)}. ` +
          t("Show more carries on further back; a shorter period or a narrower filter answers sooner.")
        : "";
    }
  }

  function setBusy(busy) {
    const element = byId("rq-searching");
    if (element) element.hidden = !busy;
  }

  function setNotice(id, visible) {
    const element = byId(id);
    if (element) element.hidden = !visible;
  }

  async function search(append) {
    if (!append || !query) {
      query = filters();
      next = 0;
    }
    const params = new URLSearchParams(query);
    params.set("limit", String(PAGE_SIZE));
    if (append) {
      params.set("before", String(next));
      params.set("count", "0");
    }
    const mine = ++sequence;
    setBusy(true);
    let answer;
    try {
      answer = await getJson("/api/security/requests", params);
    } catch (error) {
      answer = { status: 0, payload: {} };
    }
    // A newer search is on its way; this answer is for filters no longer shown.
    if (mine !== sequence) return;
    setBusy(false);
    const { status, payload } = answer;
    if (status === 404 || payload.enabled === false) {
      // The daemon answers this when the store is switched off, which is a
      // different thing from the daemon being unreachable.
      setNotice("rq-disabled", true);
      setNotice("rq-unavailable", false);
      render([], false);
      return;
    }
    if (status === 0 || status >= 500 || payload.unavailable) {
      setNotice("rq-unavailable", true);
      setNotice("rq-disabled", false);
      return;
    }
    setNotice("rq-disabled", false);
    setNotice("rq-unavailable", false);

    next = Number(payload.next || 0);
    render(payload.requests || [], append);
    renderFound(payload, append);
  }

  async function setRecording(enabled) {
    const note = byId("rq-switch-status");
    if (note) note.textContent = "…";
    const meta = document.querySelector('meta[name="csrf-token"]');
    const response = await fetch("/api/security/requests/enabled", {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        "X-CSRFToken": meta ? meta.getAttribute("content") || "" : ""
      },
      body: JSON.stringify({ enabled: enabled })
    });
    const payload = await response.json().catch(function () { return {}; });
    if (!response.ok || payload.ok === false) {
      if (note) note.textContent = payload.error || "It was not changed";
      return;
    }
    if (note) note.textContent = "";
    await refreshStore();
    await search(false);
  }

  async function refreshStore() {
    const { status, payload } = await getJson("/api/security/requests/status", {});
    const element = byId("rq-store");
    const stop = byId("rq-disable");
    // 200 means the store exists; 404 is the daemon saying it is switched off.
    if (stop) stop.hidden = status !== 200;
    if (!element) return;
    if (status !== 200) {
      element.textContent = "";
      return;
    }
    const megabytes = Math.round((payload.database_bytes || 0) / 1048576);
    const cap = Math.round((payload.max_bytes || 0) / 1048576);
    const parts = [
      `${payload.rows || 0} ${t("records")}`,
      `${megabytes} / ${cap} MiB`,
      `${payload.retention_days || 0} ${t("days")}`
    ];
    if (payload.paused) parts.push(t("paused"));
    element.textContent = parts.join(" · ");
  }

  function wire() {
    const run = () => {
      search(false);
      refreshStore();
    };
    const button = byId("rq-search");
    if (button) button.addEventListener("click", run);
    const reset = byId("rq-reset");
    if (reset) {
      reset.addEventListener("click", () => {
        ["rq-status", "rq-client", "rq-host", "rq-backend", "rq-path", "rq-request-id"]
          .forEach((id) => {
            const element = byId(id);
            if (element) element.value = "";
          });
        const admin = byId("rq-admin");
        if (admin) admin.checked = false;
        forgetLink();
        run();
      });
    }
    const more = byId("rq-more");
    if (more) more.addEventListener("click", () => search(true));
    const enable = byId("rq-enable");
    if (enable) enable.addEventListener("click", () => setRecording(true));
    const stop = byId("rq-disable");
    if (stop) stop.addEventListener("click", () => setRecording(false));
    const range = byId("rq-range");
    if (range) range.addEventListener("change", run);
    const admin = byId("rq-admin");
    if (admin) admin.addEventListener("change", run);
    document.querySelectorAll(".rq-filters input").forEach((input) => {
      input.addEventListener("keydown", (event) => {
        if (event.key === "Enter") run();
      });
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    wire();
    applyLink();
    search(false);
    refreshStore();
  });
})();
