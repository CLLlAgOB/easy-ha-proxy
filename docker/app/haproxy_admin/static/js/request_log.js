/* Log Explorer: find one request again.
 *
 * Read-only. Everything shown here came out of the access log after the
 * engine's own normalization, so there is nothing to redact on this side --
 * the query string was dropped before it was stored.
 *
 * The search on screen is in the address: a reload, a bookmark or a link
 * opens the same search, and Back returns to the one before.
 */
(function () {
  "use strict";

  const t = window.t || ((value) => String(value));
  const core = window.EasyHaProxyRequestLog;
  // The live page's reading of how a request ended and where its time went.
  const live = window.EasyHaProxyLive;
  const dateTimeFormat = new Intl.DateTimeFormat(document.documentElement.lang || undefined, {
    dateStyle: "short",
    timeStyle: "medium"
  });

  const PAGE_SIZE = 100;
  const COLUMNS = 9;
  // Why the gateway itself turned a request away, as the live page says it.
  const REFUSALS = {
    banned: "Banned",
    "rate-limited": "Request rate limit",
    geo: "GeoIP",
    "zero-trust": "Zero trust: not signed in",
    denied: "Address not allowed",
    "invalid-request": "Unknown name or bad request",
    refused: "Refused by the gateway"
  };
  // A filter as the page writes it: the input that holds it.
  const INPUTS = {
    status: "rq-status",
    client: "rq-client",
    host: "rq-host",
    backend: "rq-backend",
    path: "rq-path",
    request_id: "rq-request-id",
    agent: "rq-agent",
    method: "rq-method",
    slower: "rq-slower"
  };

  // The filters of the search on screen: "show more" carries on with these,
  // not with whatever has been typed since.
  let query = null;
  // Where "show more" carries on: below the last row, or below where a
  // search that ran out of time stopped. 0 when there is nothing further.
  let next = 0;
  // The newest search; an answer to an older one is dropped.
  let sequence = 0;
  // A period a link brought (the charts and the live page link here): kept
  // as an extra choice in the period list until the filters are reset.
  let chosenPeriod = null;
  // The rows on screen by id, for their details.
  const shownRows = new Map();

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

  function ms(value) {
    return `${Number(value).toLocaleString(document.documentElement.lang || undefined)} ${t("ms")}`;
  }

  /* ---------- the view: inputs <-> address ---------- */

  function choosePeriod(period) {
    const select = byId("rq-range");
    const old = select.querySelector('option[value="chosen"]');
    if (old) old.remove();
    chosenPeriod = period;
    if (!period) return;
    const option = document.createElement("option");
    option.value = "chosen";
    option.setAttribute("data-i18n-skip", "");
    option.setAttribute("translate", "no");
    option.textContent = `${t("Chosen period")}: ${formatTime(period.since)} – ${formatTime(period.until)}`;
    select.insertBefore(option, select.firstChild);
    select.value = "chosen";
  }

  function readView() {
    const view = {};
    const choice = byId("rq-range").value;
    if (choice === "chosen" && chosenPeriod) {
      view.since = chosenPeriod.since;
      view.until = chosenPeriod.until;
    } else {
      view.range = Number(choice || 0);
    }
    Object.keys(INPUTS).forEach((name) => {
      const value = byId(INPUTS[name]).value.trim();
      if (value) view[name] = value;
    });
    if (byId("rq-refused").checked) view.refused = true;
    if (byId("rq-admin").checked) view.admin = true;
    return view;
  }

  // A value into its input; a method the list does not name is added to it.
  function setValue(input, value) {
    if (input.tagName === "SELECT" && value && !Array.from(input.options).some((option) => option.value === value)) {
      const option = document.createElement("option");
      option.value = value;
      option.textContent = value;
      input.appendChild(option);
    }
    input.value = value;
  }

  function fillInputs(view) {
    Object.keys(INPUTS).forEach((name) => {
      setValue(byId(INPUTS[name]), view[name] === undefined ? "" : String(view[name]));
    });
    byId("rq-refused").checked = Boolean(view.refused);
    byId("rq-admin").checked = Boolean(view.admin);
    if (view.since && view.until) {
      choosePeriod({ since: view.since, until: view.until });
    } else {
      choosePeriod(null);
      byId("rq-range").value = String(view.range === undefined ? core.DEFAULT_RANGE : view.range);
    }
  }

  // The search on screen into the address. A search someone asked for is a
  // step Back returns from; the first one on a visit only tidies the address.
  function writeAddress(view, push) {
    try {
      const url = new URL(window.location.href);
      const query = new URLSearchParams(core.viewQuery(view)).toString();
      url.search = query ? `?${query}` : "";
      if (url.toString() === window.location.href) return;
      if (push) window.history.pushState(null, "", url.toString());
      else window.history.replaceState(null, "", url.toString());
    } catch (error) {
      /* the address stays as it was */
    }
  }

  /* ---------- the table ---------- */

  function cell(row, value, className) {
    const td = document.createElement("td");
    if (value instanceof Node) td.appendChild(value);
    else td.textContent = value === null || value === undefined || value === "" ? "—" : String(value);
    if (className) td.className = className;
    row.appendChild(td);
    return td;
  }

  // A value that narrows the search to itself when clicked.
  function filterButton(name, value, text, className) {
    if (value === null || value === undefined || value === "") return "—";
    const button = document.createElement("button");
    button.type = "button";
    button.className = `rq-link ${className || ""}`.trim();
    button.dataset.filter = name;
    button.dataset.value = String(value);
    button.title = t("Search for only this");
    button.textContent = text === undefined ? String(value) : text;
    return button;
  }

  function statusCell(entry) {
    const wrap = document.createElement("div");
    const badge = filterButton("status", entry.bad_request ? "" : String(entry.status),
      entry.bad_request ? t("bad request") : String(entry.status), `rq-status ${statusClass(entry.status)}`);
    if (badge instanceof Node) wrap.appendChild(badge);
    else {
      const plain = document.createElement("span");
      plain.className = `rq-status ${statusClass(entry.status)}`;
      plain.textContent = entry.bad_request ? t("bad request") : String(entry.status);
      wrap.appendChild(plain);
    }
    if (entry.refusal) {
      const why = document.createElement("div");
      why.className = "rq-sub";
      why.textContent = t(REFUSALS[entry.refusal] || "Refused by the gateway");
      wrap.appendChild(why);
    }
    return wrap;
  }

  function render(rows, append) {
    const body = byId("rq-body");
    if (!append) {
      body.textContent = "";
      shownRows.clear();
    }
    rows.forEach((entry) => {
      shownRows.set(String(entry.id), entry);
      const tr = document.createElement("tr");
      tr.className = "rq-row";
      tr.dataset.row = String(entry.id);
      cell(tr, formatTime(entry.ts));
      cell(tr, statusCell(entry));
      cell(tr, filterButton("method", entry.method));
      cell(tr, filterButton("host", entry.host));
      cell(tr, filterButton("path", entry.path), "rq-path");
      cell(tr, filterButton("backend", entry.backend,
        entry.server ? `${entry.backend} / ${entry.server}` : entry.backend));
      cell(tr, filterButton("client", entry.client));
      // How soon the server answered; the whole request -- a download, a
      // long poll -- is in the tooltip. 0 ms is an answer, not a dash.
      const answered = Number(entry.response_ms);
      const timing = cell(tr, Number.isFinite(answered) && answered >= 0 ? ms(answered) : "—");
      if (Number.isFinite(Number(entry.duration_ms))) {
        timing.title = `${t("The whole request")}: ${ms(entry.duration_ms)}`;
      }
      const id = cell(tr, entry.request_id ? String(entry.request_id).slice(0, 8) : "—", "rq-path");
      if (entry.request_id) id.title = entry.request_id;
      body.appendChild(tr);
    });
  }

  // One request, opened: where its time went, how it ended, who asked.
  function detailsRow(entry) {
    const items = [];
    const add = (label, value) => items.push([label, value]);
    const mono = (text) => {
      const span = document.createElement("span");
      span.className = "rq-mono";
      span.textContent = text || "—";
      return span;
    };
    add("Request", mono(`${entry.method || ""} ${entry.path || ""}`.trim()));
    add("Site", mono(entry.host));
    add("Server", mono(entry.server ? `${entry.backend} / ${entry.server}` : entry.backend));
    add("Status", document.createTextNode(
      `${entry.bad_request ? t("bad request") : entry.status} · ${live ? live.bytes(entry.bytes_out) : entry.bytes_out}`
    ));
    if (entry.refusal) add("Refused because", document.createTextNode(t(REFUSALS[entry.refusal] || "Refused by the gateway")));
    if (live && entry.term) {
      const ending = live.termination(entry.term);
      const said = ending.normal
        ? t("Ended normally")
        : [ending.cause, ending.phase].filter(Boolean).map((part) => t(part)).join(", ") || t("Unknown");
      const span = document.createElement("span");
      span.textContent = `${said} `;
      span.appendChild(Object.assign(mono(entry.term), { className: "rq-mono rq-sub" }));
      add("How it ended", span);
    }
    if (live && entry.times) {
      const timers = document.createElement("div");
      timers.className = "rq-timers";
      live.timers(entry.times).forEach((timer) => {
        const part = document.createElement("span");
        part.textContent = `${t(timer.label)}: `;
        const value = document.createElement("b");
        value.textContent = timer.ms === null ? "—" : ms(timer.ms);
        part.appendChild(value);
        timers.appendChild(part);
      });
      add("Where the time went", timers);
    } else {
      add("Where the time went", document.createTextNode(
        `${t("The whole request")}: ${ms(entry.duration_ms || 0)}`
      ));
    }
    const agent = document.createElement("span");
    agent.appendChild(mono(entry.user_agent));
    if (entry.user_agent) {
      agent.appendChild(document.createTextNode(" "));
      agent.appendChild(filterButton("agent", entry.user_agent, t("Only this client")));
    }
    add("Client", agent);
    if (entry.ban_reason) add("Ban rule", mono(entry.ban_reason));
    const identity = document.createElement("span");
    identity.appendChild(mono(entry.request_id));
    add("Request id", identity);
    const now = document.createElement("a");
    now.className = "rq-link";
    now.href = `/monitoring/live?ip=${encodeURIComponent(entry.client)}&window=3600`;
    now.textContent = t("What this address is doing now");
    add("Address", (() => {
      const span = document.createElement("span");
      span.appendChild(mono(entry.client));
      span.appendChild(document.createTextNode(" "));
      span.appendChild(now);
      return span;
    })());

    const list = document.createElement("dl");
    list.className = "rq-details-grid";
    items.forEach(([label, value]) => {
      const dt = document.createElement("dt");
      dt.textContent = t(label);
      const dd = document.createElement("dd");
      dd.appendChild(value);
      list.appendChild(dt);
      list.appendChild(dd);
    });
    const tr = document.createElement("tr");
    tr.className = "rq-details";
    const td = document.createElement("td");
    td.colSpan = COLUMNS;
    td.appendChild(list);
    tr.appendChild(td);
    return tr;
  }

  function toggleDetails(tr) {
    const following = tr.nextElementSibling;
    if (following && following.classList.contains("rq-details")) {
      following.remove();
      tr.classList.remove("rq-open");
      return;
    }
    const entry = shownRows.get(tr.dataset.row);
    if (!entry) return;
    tr.after(detailsRow(entry));
    tr.classList.add("rq-open");
  }

  function renderFound(payload, append) {
    const body = byId("rq-body");
    const shown = body.querySelectorAll("tr.rq-row").length;
    byId("rq-empty").hidden = shown > 0 || Boolean(payload.timed_out);
    byId("rq-more").hidden = !next;
    const found = byId("rq-found");
    if (!append && payload.total !== undefined) {
      const total = Number(payload.total || 0).toLocaleString(document.documentElement.lang || undefined);
      found.textContent = payload.total_exact === false
        ? `${t("Found, at least")}: ${total}`
        : `${t("Found")}: ${total}`;
    }
    const stopped = byId("rq-stopped");
    stopped.hidden = !payload.timed_out;
    stopped.textContent = payload.timed_out
      ? `${t("The search stopped after a few seconds; it reached back to")} ${formatTime(payload.searched_to)}. ` +
        t("Show more carries on further back; a shorter period or a narrower filter answers sooner.")
      : "";
    const memory = byId("rq-memory");
    memory.hidden = payload.source !== "memory";
    memory.textContent = payload.source === "memory"
      ? `${t("Recording is off, so these are the requests guardd keeps in memory, back to")} ` +
        `${formatTime(payload.reaches_back_to)}.`
      : "";
  }

  function setNotice(id, visible) {
    byId(id).hidden = !visible;
  }

  function setBusy(busy) {
    byId("rq-searching").hidden = !busy;
  }

  /* ---------- searching ---------- */

  async function getJson(path, params) {
    const query = new URLSearchParams(params || {});
    const response = await fetch(`${path}?${query.toString()}`, {
      headers: { Accept: "application/json" },
      credentials: "same-origin"
    });
    const payload = await response.json().catch(() => ({}));
    return { status: response.status, payload };
  }

  async function search(append) {
    if (!append || !query) {
      query = core.searchParams(readView(), Date.now() / 1000);
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
    const fromMemory = payload.source === "memory";
    if (status === 404 || (payload.enabled === false && !fromMemory)) {
      // The daemon answers this when the store is switched off and has no
      // memory to answer from, which is different from being unreachable.
      setNotice("rq-disabled", true);
      setNotice("rq-unavailable", false);
      render([], false);
      renderFound({}, false);
      byId("rq-found").textContent = "";
      return;
    }
    if (status === 0 || status >= 500 || payload.unavailable) {
      setNotice("rq-unavailable", true);
      setNotice("rq-disabled", false);
      return;
    }
    // From memory the record is still off: the switch stays in sight.
    setNotice("rq-disabled", fromMemory);
    setNotice("rq-unavailable", false);

    next = Number(payload.next || 0);
    render(payload.requests || [], append);
    renderFound(payload, append);
  }

  // A search someone asked for: into the address, then asked.
  function run(push) {
    writeAddress(readView(), push);
    search(false);
    refreshStore();
  }

  async function setRecording(enabled) {
    const note = byId("rq-switch-status");
    note.textContent = "…";
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
      note.textContent = payload.error || "It was not changed";
      return;
    }
    note.textContent = "";
    await refreshStore();
    await search(false);
  }

  async function refreshStore() {
    const { status, payload } = await getJson("/api/security/requests/status", {});
    const element = byId("rq-store");
    // The panel passes the daemon's "switched off" on with a 200, so the
    // body says it, not the status: no stop button and no "0 records" then.
    const recording = status === 200 && payload.enabled !== false && payload.ok !== false;
    byId("rq-disable").hidden = !recording;
    if (!recording) {
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

  /* ---------- wiring ---------- */

  function wire() {
    byId("rq-search").addEventListener("click", () => run(true));
    byId("rq-reset").addEventListener("click", () => {
      fillInputs({});
      run(true);
    });
    byId("rq-more").addEventListener("click", () => search(true));
    byId("rq-enable").addEventListener("click", () => setRecording(true));
    byId("rq-disable").addEventListener("click", () => setRecording(false));
    ["rq-range", "rq-method", "rq-refused", "rq-admin"].forEach((id) => {
      byId(id).addEventListener("change", () => {
        if (id === "rq-range" && byId("rq-range").value !== "chosen") choosePeriod(null);
        run(true);
      });
    });
    document.querySelectorAll(".rq-filters input").forEach((input) => {
      input.addEventListener("keydown", (event) => {
        if (event.key === "Enter") run(true);
      });
    });
    byId("rq-body").addEventListener("click", (event) => {
      const button = event.target.closest("[data-filter]");
      if (button) {
        const input = byId(INPUTS[button.dataset.filter]);
        if (input) {
          setValue(input, button.dataset.value);
          run(true);
        }
        return;
      }
      // A row opens its details; a link inside it does what it says.
      const row = event.target.closest("tr.rq-row");
      if (row && !event.target.closest("a, button")) toggleDetails(row);
    });
    // Back and Forward: the search the address now names.
    window.addEventListener("popstate", () => {
      fillInputs(core.viewFromQuery(window.location.search));
      search(false);
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    const methods = byId("rq-method");
    core.METHODS.forEach((method) => {
      const option = document.createElement("option");
      option.value = method;
      option.textContent = method;
      methods.appendChild(option);
    });
    wire();
    fillInputs(core.viewFromQuery(window.location.search));
    run(false);
  });
})();
