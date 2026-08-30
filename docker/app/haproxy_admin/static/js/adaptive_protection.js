/* Adaptive protection: mode, shadow review, weight simulator and
 * per-address evidence. The rules themselves are their own page.
 *
 * The only thing here that changes anything is the mode switch, and it asks
 * before it does. Everything else reads.
 */
(function () {
  "use strict";

  const t = window.t || ((value) => String(value));
  const numberFormat = new Intl.NumberFormat(document.documentElement.lang || undefined);
  const dateTimeFormat = new Intl.DateTimeFormat(document.documentElement.lang || undefined, {
    dateStyle: "short",
    timeStyle: "medium"
  });

  const STATES = ["HOSTILE", "HIGH_RISK", "SUSPICIOUS", "WATCH", "NORMAL"];

  let configuredPolicy = null;
  let selectedAddress = "";
  let currentMode = "";
  let pendingMode = "";
  // The ban ladder as the daemon last reported it, and the copy being edited.
  let ladder = [];
  let draft = [];
  let lastSummary = {};

  function csrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute("content") || "" : "";
  }

  function byId(id) {
    return document.getElementById(id);
  }

  function setText(id, value) {
    const element = byId(id);
    if (element) element.textContent = value == null || value === "" ? "—" : String(value);
  }

  function uiText(value) {
    return t(value);
  }

  function formatCount(value) {
    const numeric = Number(value);
    return Number.isFinite(numeric) ? numberFormat.format(numeric) : "—";
  }

  function formatTime(seconds) {
    const numeric = Number(seconds);
    if (!Number.isFinite(numeric) || numeric <= 0) return "—";
    return dateTimeFormat.format(new Date(numeric * 1000));
  }

  function simulatorParams() {
    const params = new URLSearchParams();
    document.querySelectorAll("input[data-weight]").forEach((input) => {
      const value = input.value.trim();
      if (value !== "") params.set(`w.${input.dataset.weight}`, value);
    });
    const cap = byId("ap-cap");
    if (cap && cap.value.trim() !== "") params.set("cap", cap.value.trim());
    const decay = byId("ap-decay");
    if (decay && decay.value.trim() !== "") {
      // The field is in hours because that is how an operator thinks about how
      // long a finding should still count.
      const hours = Number(decay.value.trim());
      if (Number.isFinite(hours)) params.set("decay", String(Math.round(hours * 3600)));
    }
    return params;
  }

  async function getJson(path, params) {
    const query = new URLSearchParams(params || {});
    const response = await fetch(`${path}?${query.toString()}`, {
      headers: { Accept: "application/json" },
      credentials: "same-origin"
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const error = new Error(payload.error || `HTTP ${response.status}`);
      error.unavailable = Boolean(payload.unavailable) || response.status === 503;
      throw error;
    }
    return payload;
  }

  function showUnavailable(visible) {
    const notice = byId("ap-unavailable");
    if (notice) notice.hidden = !visible;
  }

  /* ---------- mode ---------- */

  function renderMode(payload) {
    currentMode = payload.mode || "";
    document.querySelectorAll("button[data-mode]").forEach((button) => {
      button.setAttribute(
        "aria-pressed",
        button.dataset.mode === currentMode ? "true" : "false"
      );
      button.disabled = false;
    });

    setText(
      "ap-mode-source",
      payload.mode_overridden
        ? `${uiText("Set here, overriding the configured")} ${payload.configured_mode}`
        : uiText("From the deployed configuration")
    );

    const banner = byId("ap-mode");
    if (banner) {
      banner.textContent =
        currentMode === "enforce"
          ? uiText(
              "Enforce mode — addresses above the threshold are banned through the same table HAProxy uses."
            )
          : currentMode === "off"
          ? uiText("Off — nothing is collected, scored or blocked.")
          : uiText(
              "Monitor mode — findings are recorded and scored, but nothing is blocked. HAProxy keeps enforcing its own rules unchanged."
            );
      banner.classList.toggle("error", currentMode === "enforce");
    }

    ladder = payload.ban_durations_seconds || ladder;
    renderLadder();
    const durations = ladder;
    setText(
      "ap-mode-effect",
      currentMode === "enforce"
        ? `${uiText("Ban lengths escalate with repeat findings")}: ${durations
            .map((seconds) => formatDuration(seconds))
            .join(" → ")}`
        : ""
    );
  }

  function formatDuration(seconds) {
    const total = Number(seconds) || 0;
    // Days matter now that a step can be months long: "2160h" is a number
    // nobody reads as ninety days.
    if (total >= 86400) return `${Math.round(total / 86400)} ${unitLabel("days")}`;
    if (total >= 3600) return `${Math.round(total / 3600)} ${unitLabel("hr")}`;
    return `${Math.round(total / 60)} ${unitLabel("min")}`;
  }

  /* ---------- how long a ban lasts ---------- */

  // The abbreviations the rest of the application already uses, rather than
  // single letters of my own. A one-letter catalogue key would be a trap:
  // the DOM translator substitutes catalogue words inside strings it did
  // not match whole, so "d" would sit waiting for the first page that
  // prints a lone "d" in some other sense. Abbreviations also sidestep
  // Russian numeral agreement, which is why these are not "7 days".
  const UNITS = [
    { key: "min", seconds: 60 },
    { key: "hr", seconds: 3600 },
    { key: "days", seconds: 86400 }
  ];

  function unitLabel(key) {
    return uiText(key);
  }

  function splitDuration(seconds) {
    // Show it in the largest unit that divides exactly, so a stored 604800
    // comes back as "7 d" rather than "10080 m".
    const total = Number(seconds) || 0;
    for (const unit of [...UNITS].reverse()) {
      if (total >= unit.seconds && total % unit.seconds === 0) {
        return { value: total / unit.seconds, unit: unit.key };
      }
    }
    return { value: Math.max(1, Math.round(total / 60)), unit: "min" };
  }

  function renderLadder() {
    const host = byId("ap-ladder");
    if (!host) return;
    host.textContent = "";
    ladder.forEach((seconds, index) => {
      const chip = document.createElement("span");
      chip.setAttribute("data-i18n-skip", "");
      chip.setAttribute("translate", "no");
      chip.textContent =
        `${index + 1}. ${formatDuration(seconds)}`;
      host.appendChild(chip);
    });
  }

  function renderLadderRows() {
    const host = byId("ap-ladder-rows");
    if (!host) return;
    host.textContent = "";
    draft.forEach((seconds, index) => {
      const parts = splitDuration(seconds);
      const row = document.createElement("div");
      row.className = "ap-ladder-row";

      const label = document.createElement("label");
      label.setAttribute("data-i18n-skip", "");
      label.setAttribute("translate", "no");
      label.textContent = `${uiText("Strike")} ${index + 1}`;
      row.appendChild(label);

      const number = document.createElement("input");
      number.type = "number";
      number.min = "1";
      number.value = String(parts.value);
      row.appendChild(number);

      const unit = document.createElement("select");
      unit.setAttribute("data-i18n-skip", "");
      unit.setAttribute("translate", "no");
      UNITS.forEach((entry) => {
        const option = document.createElement("option");
        option.value = entry.key;
        option.textContent = unitLabel(entry.key);
        if (entry.key === parts.unit) option.selected = true;
        unit.appendChild(option);
      });
      row.appendChild(unit);

      function update() {
        const chosen = UNITS.find((entry) => entry.key === unit.value) || UNITS[0];
        draft[index] = Math.max(1, Number(number.value) || 1) * chosen.seconds;
      }
      number.addEventListener("input", update);
      unit.addEventListener("change", update);

      if (draft.length > 1) {
        const remove = document.createElement("button");
        remove.type = "button";
        remove.className = "btn-small";
        remove.textContent = uiText("Remove");
        remove.addEventListener("click", () => {
          draft.splice(index, 1);
          renderLadderRows();
        });
        row.appendChild(remove);
      }

      host.appendChild(row);
    });

    const add = byId("ap-ladder-add");
    if (add) add.disabled = draft.length >= 6;
  }

  function openLadderEditor(open) {
    const editor = byId("ap-ladder-editor");
    if (!editor) return;
    editor.hidden = !open;
    if (open) {
      draft = ladder.slice();
      setText("ap-ladder-result", "");
      renderLadderRows();
    }
  }

  async function saveLadder() {
    setText("ap-ladder-result", "");
    // Checked here so an obvious mistake is named before it becomes a
    // request; the daemon checks again and its answer is the one that holds.
    for (let i = 1; i < draft.length; i += 1) {
      if (draft[i] < draft[i - 1]) {
        setText(
          "ap-ladder-result",
          uiText("Each step must be at least as long as the one before")
        );
        return;
      }
    }
    try {
      const response = await fetch("/api/security/adaptive/durations", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": csrfToken()
        },
        body: JSON.stringify({ durations: draft })
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok || payload.ok === false) {
        setText("ap-ladder-result", payload.error || `HTTP ${response.status}`);
        return;
      }
      ladder = payload.ban_durations_seconds || draft.slice();
      renderLadder();
      openLadderEditor(false);
      await load();
    } catch (error) {
      setText("ap-ladder-result", String(error));
    }
  }

  function askToSwitch(mode) {
    pendingMode = mode;
    const confirm = byId("ap-confirm");
    const text = byId("ap-confirm-text");
    if (!confirm || !text) return;
    if (mode === "enforce") {
      const would = Number((lastSummary || {}).would_ban) || 0;
      const suspects = Number((lastSummary || {}).likely_false_positive) || 0;
      text.textContent =
        `${uiText("Enabling enforcement will ban")} ${formatCount(would)} ` +
        `${uiText("address(es) on the next cycle.")} ` +
        (suspects
          ? `${formatCount(suspects)} ${uiText(
              "scored address(es) later authenticated — review them first."
            )}`
          : uiText("No scored address has authenticated since."));
    } else if (currentMode === "enforce") {
      text.textContent = uiText(
        "Every ban this engine applied will be lifted."
      );
    } else {
      text.textContent = uiText("Change the protection mode?");
    }
    confirm.hidden = false;
  }

  async function commitMode() {
    const confirm = byId("ap-confirm");
    if (confirm) confirm.hidden = true;
    if (!pendingMode) return;
    document.querySelectorAll("button[data-mode]").forEach((button) => {
      button.disabled = true;
    });
    try {
      const response = await fetch("/api/security/adaptive/mode", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": csrfToken()
        },
        body: JSON.stringify({ mode: pendingMode })
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok || payload.ok === false) {
        setText("ap-mode-result", payload.error || `HTTP ${response.status}`);
      } else {
        const applied = (payload.applied || []).length;
        const lifted = (payload.lifted || []).length;
        setText(
          "ap-mode-result",
          `${payload.previous} → ${payload.mode} · ` +
            `${uiText("banned")} ${applied} · ${uiText("lifted")} ${lifted}`
        );
      }
    } catch (error) {
      setText("ap-mode-result", String(error));
    } finally {
      pendingMode = "";
      await load();
    }
  }

  function renderPolicy(policy) {
    if (!policy) return;
    const note = byId("ap-sim-note");
    const custom = simulatorParams().toString() !== "";
    if (note) {
      note.textContent = custom
        ? uiText("Showing simulated weights")
        : uiText("Showing configured weights");
    }
    if (configuredPolicy) return;
    configuredPolicy = policy;
    document.querySelectorAll("input[data-weight]").forEach((input) => {
      const value = (policy.weights || {})[input.dataset.weight];
      if (value != null) input.placeholder = String(value);
    });
    const cap = byId("ap-cap");
    if (cap) cap.placeholder = String(policy.category_cap);
    const decay = byId("ap-decay");
    if (decay) decay.placeholder = String(Math.round((policy.decay_seconds || 0) / 3600));
    renderBands(policy);
  }

  // The page told the operator it would "ban what crosses the threshold" and
  // never said what the threshold was, so a score of 43 carried no meaning.
  // The daemon owns the numbers; this only draws them.
  function renderBands(policy) {
    const host = byId("ap-bands");
    if (!host) return;
    const bands = policy.bands || [];
    if (!bands.length) return;
    host.textContent = "";
    const ordered = bands.slice().sort((a, b) => b.from - a.from);
    ordered.forEach((band, index) => {
      const upper = index === 0 ? "" : ordered[index - 1].from - 1;
      const item = document.createElement("div");
      item.className = "ap-band" + (band.bans ? " bans" : "");
      const range = document.createElement("span");
      range.className = "ap-band-range";
      range.textContent = upper === "" ? `${band.from}+` : `${band.from}–${upper}`;
      const name = document.createElement("span");
      name.className = `ap-state ap-${band.state}`;
      name.textContent = band.state;
      item.appendChild(range);
      item.appendChild(name);
      if (band.bans) {
        const mark = document.createElement("span");
        mark.className = "mon-sub";
        mark.textContent = uiText("bans from here");
        item.appendChild(mark);
      }
      host.appendChild(item);
    });
  }

  function formatLeft(seconds) {
    const total = Math.max(0, Number(seconds) || 0);
    if (total >= 86400) {
      const days = Math.floor(total / 86400);
      const hours = Math.round((total % 86400) / 3600);
      return `${days}${unitLabel("days")} ${hours}${unitLabel("hr")}`;
    }
    if (total >= 3600) {
      const hours = Math.floor(total / 3600);
      const minutes = Math.round((total % 3600) / 60);
      return `${hours}${unitLabel("hr")} ${minutes}${unitLabel("min")}`;
    }
    return `${Math.max(1, Math.round(total / 60))}${unitLabel("min")}`;
  }

  function renderBans(bans) {
    const card = byId("ap-bans-card");
    const host = byId("ap-bans");
    if (!card || !host) return;
    const rows = bans || [];
    card.hidden = rows.length === 0;
    setText("ap-bans-note", rows.length ? String(rows.length) : "");
    if (!rows.length) return;

    host.textContent = "";
    rows.forEach((ban) => {
      const tr = document.createElement("tr");

      const address = document.createElement("td");
      address.setAttribute("data-i18n-skip", "");
      address.setAttribute("translate", "no");
      address.textContent = ban.ip;
      if (ban.likely_false_positive) {
        const flag = document.createElement("span");
        flag.className = "badge warn";
        flag.style.marginLeft = "6px";
        flag.textContent = uiText("Check this one");
        address.appendChild(flag);
      }
      tr.appendChild(address);

      const left = document.createElement("td");
      left.setAttribute("data-i18n-skip", "");
      left.setAttribute("translate", "no");
      left.textContent = formatLeft(ban.seconds_left);
      tr.appendChild(left);

      const strike = document.createElement("td");
      strike.setAttribute("data-i18n-skip", "");
      strike.setAttribute("translate", "no");
      strike.textContent = String(ban.strikes || 1);
      tr.appendChild(strike);

      const score = document.createElement("td");
      score.setAttribute("data-i18n-skip", "");
      score.setAttribute("translate", "no");
      score.textContent = String(ban.score == null ? "" : ban.score);
      tr.appendChild(score);

      const why = document.createElement("td");
      why.setAttribute("data-i18n-skip", "");
      why.setAttribute("translate", "no");
      why.textContent = (ban.categories || []).join(", ") || "—";
      tr.appendChild(why);

      host.appendChild(tr);
    });
  }

  function renderSummary(summary) {
    if (!summary) return;
    // The heading and this label were written when monitor was the only
    // mode there was. Left alone they claim nothing has happened while the
    // engine is banning addresses -- which is precisely the moment the
    // operator most needs the page to be telling the truth.
    const enforcing = currentMode === "enforce";
    setText(
      "ap-review-title",
      enforcing ? uiText("Enforcement review") : uiText("Shadow review")
    );
    setText(
      "ap-wouldban-label",
      enforcing ? uiText("Banned") : uiText("Would be banned")
    );

    setText("ap-scored", formatCount(summary.scored));
    setText("ap-wouldban", formatCount(summary.would_ban));
    setText("ap-falsepos", formatCount(summary.likely_false_positive));
    setText("ap-unenforceable", formatCount(summary.unenforceable));
    setText("ap-excluded", formatCount(summary.excluded));

    const host = byId("ap-states");
    if (!host) return;
    host.textContent = "";
    const byState = summary.by_state || {};
    STATES.forEach((state) => {
      const count = byState[state];
      if (!count) return;
      const item = document.createElement("span");
      const pill = document.createElement("b");
      pill.className = `ap-pill ap-${state}`;
      pill.textContent = state;
      item.appendChild(pill);
      const value = document.createElement("span");
      value.textContent = ` ${formatCount(count)}`;
      item.appendChild(value);
      host.appendChild(item);
    });
  }

  function renderTable(addresses) {
    const body = byId("ap-table");
    const empty = byId("ap-table-empty");
    if (!body) return;
    body.textContent = "";
    if (!addresses || !addresses.length) {
      if (empty) empty.hidden = false;
      return;
    }
    if (empty) empty.hidden = true;

    addresses.forEach((entry) => {
      const row = document.createElement("tr");
      row.className = "ap-row-link";
      row.addEventListener("click", () => loadDetail(entry.ip));

      const address = document.createElement("td");
      address.className = "ip-cell";
      address.textContent = entry.ip;
      if (!entry.enforceable) {
        const flag = document.createElement("span");
        flag.className = "ap-flag noenforce";
        flag.textContent = "IPv6";
        address.appendChild(flag);
      }
      row.appendChild(address);

      const country = document.createElement("td");
      country.textContent = entry.country || "—";
      row.appendChild(country);

      const score = document.createElement("td");
      score.textContent = formatCount(entry.score);
      row.appendChild(score);

      const state = document.createElement("td");
      const pill = document.createElement("b");
      pill.className = `ap-pill ap-${entry.state}`;
      pill.textContent = entry.state;
      state.appendChild(pill);
      if (entry.would_ban) {
        const flag = document.createElement("span");
        flag.className = "ap-flag fp";
        flag.textContent = "would ban";
        state.appendChild(flag);
      }
      if (entry.likely_false_positive) {
        const flag = document.createElement("span");
        flag.className = "ap-flag fp";
        flag.textContent = "authenticated";
        state.appendChild(flag);
      }
      row.appendChild(state);

      const categories = document.createElement("td");
      categories.textContent = Object.keys(entry.categories || {}).join(", ") || "—";
      row.appendChild(categories);

      const events = document.createElement("td");
      events.textContent = formatCount(entry.event_count);
      row.appendChild(events);

      const seen = document.createElement("td");
      seen.textContent = formatTime(entry.last_seen);
      row.appendChild(seen);

      body.appendChild(row);
    });
  }

  function renderDetail(payload) {
    const detail = byId("ap-detail");
    if (!detail) return;
    detail.hidden = false;
    setText("ap-detail-title", payload.ip);

    const parts = [
      `${uiText("Score")}: ${formatCount(payload.score)}`,
      `${uiText("State")}: ${payload.state}`,
      `${uiText("Recommended action")}: ${uiText(payload.recommended_action)}`
    ];
    if (payload.excluded) {
      parts.push(`${uiText("Exempt")}: ${uiText(payload.exclusion_reason || "")}`);
    }
    if (payload.authenticated_at) {
      parts.push(
        `${uiText("Authenticated at")}: ${formatTime(payload.authenticated_at)}`
      );
    }
    if (!payload.enforceable) {
      parts.push(uiText("Cannot be banned: IPv6"));
    }
    setText("ap-detail-summary", parts.join(" · "));

    const timeline = byId("ap-detail-timeline");
    if (!timeline) return;
    timeline.textContent = "";
    const contributions = payload.contributions || [];
    if (!contributions.length) {
      const empty = document.createElement("div");
      empty.className = "ap-empty";
      empty.textContent = uiText("No findings for this address");
      timeline.appendChild(empty);
      return;
    }
    contributions
      .slice()
      .sort((a, b) => Number(b.ts) - Number(a.ts))
      .forEach((item) => {
        const entry = document.createElement("div");
        entry.className = Number(item.points) > 0 ? "ap-entry" : "ap-entry zero";

        const when = document.createElement("span");
        when.textContent = formatTime(item.ts);
        entry.appendChild(when);

        const what = document.createElement("span");
        what.textContent = item.category
          ? `${item.event_type} (${item.category})`
          : item.event_type;
        entry.appendChild(what);

        // What was measured, against what, and which setting moves it. Without
        // this the page can say a limit was hit but not which one or by how
        // much, which is exactly what an operator needs to decide whether the
        // limit is wrong.
        const bits = [];
        if (item.site_domain || item.site_name) {
          bits.push(item.site_domain || item.site_name);
        }
        if (item.observed != null && item.limit != null) {
          bits.push(
            `${item.observed} ${uiText(item.unit || "")} / ${uiText("limit")} ` +
            `${item.limit}${item.window ? " / " + item.window : ""}`
          );
          if (item.over_by > 0) bits.push(`+${item.over_by} ${uiText("over")}`);
        } else if (item.detail) {
          bits.push(item.detail);
        }
        if (item.setting) {
          bits.push(
            `${uiText("raise")} ${item.setting}` +
            (item.suggested ? ` → ${item.suggested}` : "")
          );
        }
        if (bits.length) {
          const context = document.createElement("span");
          context.className = "ap-context";
          context.setAttribute("data-i18n-skip", "");
          context.textContent = bits.join(" · ");
          entry.appendChild(context);
        }

        const points = document.createElement("span");
        points.className = "ap-points";
        points.textContent =
          Number(item.points) > 0 ? `+${item.points}` : `0 · ${uiText(item.reason)}`;
        entry.appendChild(points);

        timeline.appendChild(entry);
      });
  }

  async function loadDetail(address) {
    if (!address) return;
    selectedAddress = address;
    const params = simulatorParams();
    params.set("ip", address);
    try {
      const payload = await getJson("/api/security/adaptive/ip", params);
      renderDetail(payload);
    } catch (error) {
      showUnavailable(Boolean(error.unavailable));
    }
  }

  async function load() {
    try {
      const payload = await getJson(
        "/api/security/adaptive/shadow",
        simulatorParams()
      );
      showUnavailable(false);
      lastSummary = payload.summary || {};
      renderMode(payload);
      renderPolicy(payload.policy);
      renderSummary(payload.summary);
      renderBans(payload.bans);
      renderTable(payload.addresses);
      setText("ap-updated", payload.ts ? formatTime(payload.ts) : "");
      if (selectedAddress) await loadDetail(selectedAddress);
    } catch (error) {
      showUnavailable(Boolean(error.unavailable));
      renderTable([]);
    }
  }

  function bind() {
    const edit = byId("ap-ladder-edit");
    if (edit) edit.addEventListener("click", () => openLadderEditor(true));
    const cancel = byId("ap-ladder-cancel");
    if (cancel) cancel.addEventListener("click", () => openLadderEditor(false));
    const save = byId("ap-ladder-save");
    if (save) save.addEventListener("click", saveLadder);
    const add = byId("ap-ladder-add");
    if (add) {
      add.addEventListener("click", () => {
        // A new step starts at the last one, which is the only value that
        // cannot break the "never shorter than the step before" rule.
        draft.push(draft.length ? draft[draft.length - 1] : 3600);
        renderLadderRows();
      });
    }

    const modes = byId("ap-mode-switch");
    if (modes) {
      modes.addEventListener("click", (event) => {
        const button = event.target.closest("button[data-mode]");
        if (!button || button.disabled) return;
        if (button.dataset.mode === currentMode) return;
        askToSwitch(button.dataset.mode);
      });
    }
    const yes = byId("ap-confirm-yes");
    if (yes) yes.addEventListener("click", () => commitMode());
    const no = byId("ap-confirm-no");
    if (no) {
      no.addEventListener("click", () => {
        pendingMode = "";
        const confirm = byId("ap-confirm");
        if (confirm) confirm.hidden = true;
      });
    }

    const apply = byId("ap-apply");
    if (apply) apply.addEventListener("click", () => load());
    const reset = byId("ap-reset");
    if (reset) {
      reset.addEventListener("click", () => {
        document.querySelectorAll("input[data-weight]").forEach((input) => {
          input.value = "";
        });
        const cap = byId("ap-cap");
        if (cap) cap.value = "";
        const decay = byId("ap-decay");
        if (decay) decay.value = "";
        load();
      });
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    bind();
    load();
  });
})();
