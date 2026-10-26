/* Detection rules: what the engine matches, and what the operator changed.
 *
 * Every edit applies immediately rather than collecting into a Save button.
 * There is nothing here that cannot be undone with one more click -- a rule
 * switched off is switched back on the same way -- and a page that holds
 * pending edits is a page that can lose them.
 */
(function () {
  "use strict";

  const t = window.t || ((value) => String(value));
  let latest = null;

  function byId(id) {
    return document.getElementById(id);
  }

  function uiText(value) {
    return t(value);
  }

  function csrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute("content") || "" : "";
  }

  function say(message, isError) {
    const host = byId("dr-result");
    if (!host) return;
    host.textContent = message || "";
    host.classList.toggle("error", Boolean(isError));
  }

  /* ---------- drawing ---------- */

  // "needs company" said nothing to anyone who had not read the source. What
  // an operator actually wants to know is how many it takes, and that falls
  // out of the two numbers the daemon already sends.
  function costLabel(signatures, decisive) {
    if (decisive) {
      return `${signatures.decisive_weight} ${uiText("points — one request is enough")}`;
    }
    const each = Number(signatures.probable_weight) || 0;
    const line = Number(signatures.would_ban_score) || 0;
    const needed = each > 0 ? Math.ceil(line / each) : 0;
    return needed > 1
      ? `${each} ` + uiText("points — takes N different categories to ban")
          .replace("N", String(needed))
      : `${each} ${uiText("points")}`;
  }

  // A signature is data, not prose. The translator falls back to replacing
  // any catalogue word it finds inside a string it does not recognise whole,
  // and "backup", "database" and "custom" are all in the catalogue: without
  // this, backup.sql is shown as бэкап.sql and database.sql as БД.sql. The
  // containers are marked in the template too; this is here so that a
  // signature stays intact even if that attribute is ever lost, because a
  // rule the operator cannot read is a rule they cannot act on.
  function keepVerbatim(element) {
    element.setAttribute("data-i18n-skip", "");
    element.setAttribute("translate", "no");
    return element;
  }

  function token(text, disabled, onClick, title) {
    const chip = keepVerbatim(document.createElement("span"));
    chip.className = "dr-token" + (disabled ? " off" : "");
    const label = document.createElement("span");
    label.textContent = text;
    chip.appendChild(label);
    if (onClick) {
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = disabled ? "↺" : "×";
      button.title = title || "";
      button.setAttribute("aria-label", `${title || ""} ${text}`.trim());
      button.addEventListener("click", () => onClick(text));
      chip.appendChild(button);
    }
    return chip;
  }

  function ruleCard(name, note, extraClass, verbatimName) {
    const card = document.createElement("div");
    card.className = "dr-rule" + (extraClass ? ` ${extraClass}` : "");
    const head = document.createElement("div");
    head.className = "dr-rule-head";
    const title = document.createElement("span");
    title.className = "dr-rule-name";
    title.textContent = name;
    // A category name is the daemon's, except on the one card whose heading
    // is our own words.
    if (verbatimName !== false) keepVerbatim(title);
    head.appendChild(title);
    if (note) {
      const sub = document.createElement("span");
      sub.className = "mon-sub";
      sub.textContent = note;
      head.appendChild(sub);
    }
    card.appendChild(head);
    const tokens = document.createElement("div");
    tokens.className = "dr-tokens";
    card.appendChild(tokens);
    return { card, tokens };
  }

  function renderMine(signatures) {
    const host = byId("dr-mine");
    if (!host) return;
    host.textContent = "";

    const added = signatures.added || {};
    const disabled = signatures.disabled || [];
    if (!Object.keys(added).length && !disabled.length) {
      const empty = document.createElement("p");
      empty.className = "dr-empty";
      empty.textContent = uiText("You have not changed any rules yet");
      host.appendChild(empty);
      return;
    }

    if (Object.keys(added).length) {
      const byCategory = {};
      Object.keys(added).forEach((name) => {
        (byCategory[added[name]] = byCategory[added[name]] || []).push(name);
      });
      Object.keys(byCategory).sort().forEach((category) => {
        const decisive = (signatures.categories || []).some(
          (c) => c.name === category && c.decisive
        );
        const { card, tokens } = ruleCard(
          category, costLabel(signatures, decisive), "mine"
        );
        byCategory[category].sort().forEach((name) => {
          tokens.appendChild(
            token(name, false, removeAdded, uiText("Remove"))
          );
        });
        host.appendChild(card);
      });
    }

    if (disabled.length) {
      const { card, tokens } = ruleCard(
        uiText("Switched off"),
        uiText("not matched, and kept off across updates"),
        "",
        false
      );
      disabled.slice().sort().forEach((name) => {
        tokens.appendChild(token(name, true, enable, uiText("Switch back on")));
      });
      host.appendChild(card);
    }
  }

  function renderShipped(signatures) {
    const host = byId("dr-shipped");
    if (!host) return;
    host.textContent = "";

    const added = signatures.added || {};
    const off = new Set(signatures.disabled || []);
    const categories = (signatures.categories || []).slice().sort((a, b) => {
      if (a.decisive !== b.decisive) return a.decisive ? -1 : 1;
      return a.name.localeCompare(b.name);
    });

    let shown = 0;
    categories.forEach((category) => {
      const all = (category.paths || []).concat(category.segments || []);
      // Anything the operator has added or switched off is shown once, in
      // their own card above. Listing it here as well would offer two
      // different buttons for one signature.
      const shipped = all.filter((name) => !(name in added) && !off.has(name));
      shown += shipped.length;
      if (!shipped.length) return;
      const { card, tokens } = ruleCard(
        category.name,
        costLabel(signatures, category.decisive),
        category.decisive ? "decisive" : ""
      );
      shipped.forEach((name) => {
        tokens.appendChild(token(name, false, disable, uiText("Switch off")));
      });
      host.appendChild(card);
    });

    const counts = byId("dr-counts");
    if (counts) {
      // What is listed below, which is what the number is next to.
      counts.textContent = `${shown} ${uiText("signatures")}`;
    }

    const note = byId("dr-query-note");
    if (note) {
      const rules = signatures.query_rules || [];
      const lead = uiText("Query strings are checked by what the value looks like, never by the parameter name");
      note.textContent = rules.length
        ? `${lead}: ${rules.join(", ")} — ${signatures.query_weight} `
          + uiText("points each")
        : "";
    }
  }

  function renderAgents(signatures) {
    const host = byId("dr-agents");
    if (!host) return;
    host.textContent = "";
    const byCategory = {};
    (signatures.user_agents || []).forEach((rule) => {
      (byCategory[rule.category] = byCategory[rule.category] || { decisive: rule.decisive, tokens: [] })
        .tokens.push(rule.token);
    });
    Object.keys(byCategory).sort((a, b) => {
      if (byCategory[a].decisive !== byCategory[b].decisive) return byCategory[a].decisive ? -1 : 1;
      return a.localeCompare(b);
    }).forEach((category) => {
      const entry = byCategory[category];
      const { card, tokens } = ruleCard(
        category, costLabel(signatures, entry.decisive), entry.decisive ? "decisive" : ""
      );
      entry.tokens.sort().forEach((name) => tokens.appendChild(token(name, false)));
      host.appendChild(card);
    });
  }

  function renderCategories(signatures) {
    ["dr-category", "dr-suggest-category"].forEach((id) => fillCategories(byId(id), signatures));
  }

  function fillCategories(select, signatures) {
    if (!select || select.options.length) return;
    const names = (signatures.categories || []).map((c) => c.name);
    if (!names.includes(signatures.custom_category)) {
      names.unshift(signatures.custom_category);
    }
    names.forEach((name) => {
      const option = keepVerbatim(document.createElement("option"));
      option.value = name;
      const decisive = (signatures.categories || []).some(
        (c) => c.name === name && c.decisive
      );
      option.textContent = decisive
        ? `${name} — ${uiText("bans on one request")}`
        : name;
      select.appendChild(option);
    });
    select.value = signatures.custom_category;
  }

  function render(signatures) {
    latest = signatures;
    const version = byId("dr-version");
    if (version) {
      version.textContent = signatures.version
        ? `${uiText("Signature list")} ${signatures.version}`
        : "";
    }
    const source = byId("dr-source");
    if (source) source.textContent = signatures.source || "";
    renderCategories(signatures);
    renderMine(signatures);
    renderShipped(signatures);
    renderAgents(signatures);
  }

  /* ---------- suggestions ---------- */

  function clock(seconds) {
    const date = new Date(Number(seconds) * 1000);
    return Number.isFinite(date.getTime()) ? date.toLocaleString() : "";
  }

  function cell(row, text, className) {
    const td = keepVerbatim(document.createElement("td"));
    if (className) td.className = className;
    if (text instanceof Node) td.appendChild(text);
    else td.textContent = text;
    row.appendChild(td);
    return td;
  }

  function renderSuggestions(payload) {
    const host = byId("dr-suggestions");
    if (!host) return;
    host.textContent = "";
    const rows = (payload && payload.candidates) || [];
    const meta = byId("dr-suggest-meta");
    if (meta) {
      meta.textContent = payload
        ? t("last {days} days, at least {count} different addresses", {
          days: payload.window_days, count: payload.min_addresses
        })
        : "";
    }
    if (!rows.length) {
      const empty = document.createElement("p");
      empty.className = "dr-empty";
      empty.textContent = uiText("No suggestions right now");
      host.appendChild(empty);
      return;
    }
    const table = document.createElement("table");
    table.className = "dr-suggest";
    const head = document.createElement("tr");
    ["Path", "Addresses", "Client-like", "Sites", "Status codes", "Last seen", ""].forEach((title) => {
      const th = document.createElement("th");
      th.textContent = title ? uiText(title) : "";
      head.appendChild(th);
    });
    const thead = document.createElement("thead");
    thead.appendChild(head);
    table.appendChild(thead);
    const body = document.createElement("tbody");
    rows.forEach((item) => {
      const row = document.createElement("tr");
      const code = document.createElement("code");
      code.textContent = item.path;
      cell(row, code);
      cell(row, String(item.addresses), "num");
      const clients = cell(row, String(item.clients), "num");
      if (item.clients > 0) {
        clients.classList.add("dr-client-warn");
        clients.title = uiText("Ordinary clients asked for this too: more likely a broken link");
      }
      cell(row, (item.hosts || []).slice(0, 3).join(", "));
      cell(row, Object.keys(item.status || {}).sort().join(", "));
      cell(row, clock(item.last));
      const actions = document.createElement("td");
      const add = document.createElement("button");
      add.type = "button";
      add.className = "btn";
      add.textContent = uiText("Add");
      add.addEventListener("click", () => addSuggestion(item.path));
      const hide = document.createElement("button");
      hide.type = "button";
      hide.className = "btn";
      hide.textContent = uiText("Hide");
      hide.addEventListener("click", () => hideSuggestion(item.path));
      actions.appendChild(add);
      actions.appendChild(hide);
      row.appendChild(actions);
      body.appendChild(row);
    });
    table.appendChild(body);
    host.appendChild(table);
  }

  async function loadSuggestions() {
    try {
      const response = await fetch("/api/security/detection-rules/candidates", {
        headers: { Accept: "application/json" },
        credentials: "same-origin"
      });
      if (!response.ok) return;
      renderSuggestions(await response.json());
    } catch (error) {
      /* the rules above still work without suggestions */
    }
  }

  function addSuggestion(path) {
    const select = byId("dr-suggest-category");
    const next = current();
    next.added[path] = select ? select.value : (latest || {}).custom_category;
    save(next, `${uiText("Added")}: ${path}`).then((ok) => { if (ok) loadSuggestions(); });
  }

  async function hideSuggestion(path) {
    try {
      const response = await fetch("/api/security/detection-rules/candidates/dismiss", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken() },
        body: JSON.stringify({ path: path })
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok || payload.ok === false) {
        say(payload.error || `HTTP ${response.status}`, true);
        return;
      }
      say(`${uiText("Hidden")}: ${path}`, false);
      loadSuggestions();
    } catch (error) {
      say(String(error), true);
    }
  }

  /* ---------- trap names ---------- */

  let trapState = null;

  function renderTraps(payload) {
    trapState = payload;
    const chips = byId("dr-traps");
    const table = byId("dr-unknown-hosts");
    if (!chips || !table) return;
    chips.textContent = "";
    table.textContent = "";
    const traps = (payload && payload.trap_hosts) || [];
    const { card, tokens } = ruleCard(
      uiText("Trap names"), uiText("a request bans the address"), "decisive", false
    );
    if (!traps.length) {
      const empty = document.createElement("span");
      empty.className = "mon-sub";
      empty.textContent = uiText("No trap names yet");
      tokens.appendChild(empty);
    }
    traps.forEach((name) => tokens.appendChild(token(name, false, removeTrap, uiText("Remove"))));
    chips.appendChild(card);

    const rows = ((payload && payload.unknown_hosts) || []).filter((r) => !traps.includes(r.host));
    const meta = byId("dr-trap-meta");
    if (meta) {
      meta.textContent = payload
        ? t("names without a site, last {days} days", { days: payload.window_days })
        : "";
    }
    if (payload && payload.site_names_known === false) {
      const note = document.createElement("p");
      note.className = "dr-empty";
      note.textContent = uiText("The list of site names could not be read, so unknown names are not counted");
      table.appendChild(note);
      return;
    }
    if (!rows.length) {
      const empty = document.createElement("p");
      empty.className = "dr-empty";
      empty.textContent = uiText("No requests for names without a site");
      table.appendChild(empty);
      return;
    }
    const grid = document.createElement("table");
    grid.className = "dr-suggest";
    const head = document.createElement("tr");
    ["Name", "Requests", "Addresses", "Client-like", "Last seen", ""].forEach((title) => {
      const th = document.createElement("th");
      th.textContent = title ? uiText(title) : "";
      head.appendChild(th);
    });
    const thead = document.createElement("thead");
    thead.appendChild(head);
    grid.appendChild(thead);
    const body = document.createElement("tbody");
    rows.forEach((item) => {
      const row = document.createElement("tr");
      const code = document.createElement("code");
      code.textContent = item.host;
      cell(row, code);
      cell(row, String(item.requests), "num");
      cell(row, String(item.addresses), "num");
      const clients = cell(row, String(item.clients), "num");
      if (item.clients > 0) {
        clients.classList.add("dr-client-warn");
        clients.title = uiText("Ordinary clients use this name too: they would be spared, but check first");
      }
      cell(row, clock(item.last));
      const actions = document.createElement("td");
      const make = document.createElement("button");
      make.type = "button";
      make.className = "btn";
      make.textContent = uiText("Make a trap");
      make.addEventListener("click", () => addTrap(item));
      actions.appendChild(make);
      row.appendChild(actions);
      body.appendChild(row);
    });
    grid.appendChild(body);
    table.appendChild(grid);
  }

  async function loadTraps() {
    try {
      const response = await fetch("/api/security/traps", {
        headers: { Accept: "application/json" },
        credentials: "same-origin"
      });
      if (!response.ok) return;
      renderTraps(await response.json());
    } catch (error) {
      /* the rules above still work without the trap card */
    }
  }

  async function saveTraps(hosts, message) {
    try {
      const response = await fetch("/api/security/traps", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken() },
        body: JSON.stringify({ hosts: hosts })
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok || payload.ok === false) {
        say(payload.error || `HTTP ${response.status}`, true);
        return;
      }
      say(message, false);
      loadTraps();
    } catch (error) {
      say(String(error), true);
    }
  }

  function addTrap(item) {
    if (item.clients > 0 && !window.confirm(
      `${item.host}: ${uiText("Ordinary clients use this name too: they would be spared, but check first")}`
    )) return;
    const hosts = ((trapState && trapState.trap_hosts) || []).slice();
    if (!hosts.includes(item.host)) hosts.push(item.host);
    saveTraps(hosts, `${uiText("Trap added")}: ${item.host}`);
  }

  function removeTrap(name) {
    const hosts = ((trapState && trapState.trap_hosts) || []).filter((h) => h !== name);
    saveTraps(hosts, `${uiText("Removed")}: ${name}`);
  }

  /* ---------- editing ---------- */

  async function save(overrides, message) {
    const buttons = document.querySelectorAll("#dr-add, .dr-token button");
    buttons.forEach((button) => { button.disabled = true; });
    try {
      const response = await fetch("/api/security/detection-rules", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": csrfToken()
        },
        body: JSON.stringify(overrides)
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok || payload.ok === false) {
        say(payload.error || `HTTP ${response.status}`, true);
        return false;
      }
      render(payload);
      say(message || uiText("Saved"), false);
      return true;
    } catch (error) {
      say(String(error), true);
      return false;
    } finally {
      buttons.forEach((button) => { button.disabled = false; });
    }
  }

  function current() {
    return {
      added: Object.assign({}, (latest || {}).added || {}),
      disabled: ((latest || {}).disabled || []).slice()
    };
  }

  function disable(name) {
    const next = current();
    if (!next.disabled.includes(name)) next.disabled.push(name);
    save(next, `${uiText("Switched off")}: ${name}`);
  }

  function enable(name) {
    const next = current();
    next.disabled = next.disabled.filter((entry) => entry !== name);
    save(next, `${uiText("Switched back on")}: ${name}`);
  }

  function removeAdded(name) {
    const next = current();
    delete next.added[name];
    save(next, `${uiText("Removed")}: ${name}`);
  }

  function add() {
    const field = byId("dr-token");
    const select = byId("dr-category");
    if (!field || !select) return;
    const name = field.value.trim();
    if (!name) {
      say(uiText("Type a signature first"), true);
      return;
    }
    const next = current();
    next.added[name] = select.value;
    save(next, `${uiText("Added")}: ${name}`).then((ok) => {
      // Only clear the field on success, or a rejected signature would have
      // to be retyped from memory to find the typo.
      if (ok) field.value = "";
    });
  }

  /* ---------- loading ---------- */

  async function load() {
    try {
      const response = await fetch("/api/security/detection-rules", {
        headers: { Accept: "application/json" },
        credentials: "same-origin"
      });
      const payload = await response.json().catch(() => ({}));
      const notice = byId("dr-unavailable");
      if (!response.ok) {
        if (notice) notice.hidden = false;
        return;
      }
      if (notice) notice.hidden = true;
      render(payload);
    } catch (error) {
      const notice = byId("dr-unavailable");
      if (notice) notice.hidden = false;
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    const button = byId("dr-add");
    if (button) button.addEventListener("click", add);
    const field = byId("dr-token");
    if (field) {
      field.addEventListener("keydown", (event) => {
        if (event.key === "Enter") {
          event.preventDefault();
          add();
        }
      });
    }
    load();
    loadSuggestions();
    loadTraps();
  });
})();
