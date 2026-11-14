/* Adaptive protection: mode, shadow review, weight simulator and
 * per-address evidence. The rules themselves are their own page.
 *
 * The only thing here that changes anything is the mode switch, and it asks
 * before it does. Everything else reads.
 *
 * The decisions -- simulator query, ban ladder, mode confirmation, score
 * bands, how a finding is explained -- live in adaptive_core.js, where the
 * tests in .tests/js/ reach them.
 */
(function () {
  "use strict";

  const core = window.EasyHaProxyAdaptive;
  const t = window.t || ((value) => String(value));
  const numberFormat = new Intl.NumberFormat(document.documentElement.lang || undefined);
  const dateTimeFormat = window.EasyHaProxyTime.formatter({
    dateStyle: "short",
    timeStyle: "medium"
  });

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
    const weights = {};
    document.querySelectorAll("input[data-weight]").forEach((input) => {
      weights[input.dataset.weight] = input.value;
    });
    const cap = byId("ap-cap");
    const decay = byId("ap-decay");
    return new URLSearchParams(core.simulatorParams({
      weights: weights,
      cap: cap ? cap.value : "",
      decayHours: decay ? decay.value : ""
    }));
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

  // A step reads in the unit the editor shows it in (see ladderText):
  // "36 hr", not "2 days".
  function formatDuration(seconds) {
    return core.ladderText(seconds, unitLabel);
  }

  /* ---------- how long a ban lasts ---------- */

  // "min", "hr", "days": abbreviations, never single letters (see UNITS in
  // adaptive_core.js).
  const UNITS = core.UNITS;

  function unitLabel(key) {
    return uiText(key);
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
      const parts = core.splitDuration(seconds);
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
        draft[index] = core.stepSeconds(number.value, unit.value);
      }
      number.addEventListener("input", update);
      unit.addEventListener("change", update);

      if (core.canRemoveStep(draft)) {
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
    if (add) add.disabled = !core.canAddStep(draft);
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
    if (core.ladderProblem(draft) !== -1) {
      setText(
        "ap-ladder-result",
        uiText("Each step must be at least as long as the one before")
      );
      return;
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
    const said = core.modeConfirmation(mode, currentMode, lastSummary);
    if (said.kind === "enforce") {
      text.textContent =
        `${uiText("Enabling enforcement will ban")} ${formatCount(said.wouldBan)} ` +
        `${uiText("address(es) on the next cycle.")} ` +
        (said.suspects
          ? `${formatCount(said.suspects)} ${uiText(
              "scored address(es) later authenticated — review them first."
            )}`
          : uiText("No scored address has authenticated since."));
    } else if (said.kind === "lift") {
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
    core.bandRanges(bands).forEach((band) => {
      const item = document.createElement("div");
      item.className = "ap-band" + (band.bans ? " bans" : "");
      const range = document.createElement("span");
      range.className = "ap-band-range";
      range.textContent = band.upTo === null ? `${band.from}+` : `${band.from}–${band.upTo}`;
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
    return core.formatLeft(seconds, unitLabel);
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
      address.className = "ip-cell";
      address.textContent = ban.ip;
      if (ban.likely_false_positive) {
        const flag = document.createElement("span");
        flag.className = "ap-flag fp";
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
    core.statesPresent(summary.by_state).forEach(([state, count]) => {
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
    core.newestFirst(contributions)
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

        // What was measured, against what, and which setting moves it
        // (see findingContext).
        const bits = core.findingContext(item, uiText);
        if (bits.length) {
          const context = document.createElement("span");
          context.className = "ap-context";
          context.setAttribute("data-i18n-skip", "");
          context.textContent = bits.join(" · ");
          entry.appendChild(context);
        }

        const points = document.createElement("span");
        points.className = "ap-points";
        points.textContent = core.findingPoints(item, uiText);
        entry.appendChild(points);

        timeline.appendChild(entry);
      });
  }

  /* ---------- trusted addresses over a site's limit ---------- */

  const TRUST_LABELS = {
    "signed-in": "Signed in",
    whitelist: "Whitelist",
    admin: "Admin list",
    "geo-whitelist": "GeoIP whitelist",
    "trusted-network": "Trusted network",
    "site-allow-list": "Allowed on the site"
  };

  function formatSpan(seconds) {
    const total = Math.max(0, Math.round(Number(seconds) || 0));
    if (total < 60) return `${total}${uiText("sec")}`;
    return formatLeft(total);
  }

  function cell(text) {
    const td = document.createElement("td");
    td.setAttribute("data-i18n-skip", "");
    td.setAttribute("translate", "no");
    td.textContent = text == null || text === "" ? "—" : String(text);
    return td;
  }

  function badge(td, text, kind) {
    const flag = document.createElement("span");
    flag.className = `ap-flag ${kind}`;
    flag.textContent = text;
    td.appendChild(flag);
  }

  function renderWarnings(payload) {
    const card = byId("ap-warnings-card");
    const host = byId("ap-warnings");
    const empty = byId("ap-warnings-empty");
    if (!card || !host) return;
    // A daemon from before these warnings does not know the request: the
    // card stays away rather than claiming there is nothing to show.
    card.hidden = !payload;
    if (!payload) return;
    const rows = (payload.open || []).concat(payload.recent || []);
    setText("ap-warnings-note", rows.length ? String(rows.length) : "");
    host.textContent = "";
    if (empty) empty.hidden = rows.length > 0;
    rows.forEach((row) => {
      const tr = document.createElement("tr");

      // "??" is "country unknown" (a private address, say): beside the
      // address it reads as a question, so it is left out.
      const known = row.country && row.country !== "??";
      const address = cell(known ? `${row.ip} ${row.country}` : row.ip);
      address.className = "ip-cell";
      tr.appendChild(address);

      tr.appendChild(cell(uiText(TRUST_LABELS[row.trust] || row.trust)));

      const site = cell(row.site_domain || row.site_name || row.site);
      if (row.site_name && row.site_domain && row.site_name !== row.site_domain) {
        site.title = row.site_name;
      }
      tr.appendChild(site);

      const peak = cell(
        `${formatCount(row.peak)} / ${formatCount(row.limit)} · ${formatSpan(row.window)}`
      );
      if (row.enforced === false) badge(peak, uiText("Limit not applied"), "noenforce");
      tr.appendChild(peak);

      tr.appendChild(cell(formatCount(row.over_limit)));

      const parts = [];
      if (Number(row.rate_limited) > 0) parts.push(`429 × ${formatCount(row.rate_limited)}`);
      if (Number(row.banned) > 0) parts.push(`423 × ${formatCount(row.banned)}`);
      const refused = cell(parts.join(", "));
      if (row.rate_ban) badge(refused, uiText("Banned for its request rate"), "ban");
      tr.appendChild(refused);

      const when = cell(
        `${formatTime(row.started)} · ${formatSpan(Number(row.ended) - Number(row.started))}`
      );
      if (row.open) badge(when, uiText("Going on now"), "fp");
      tr.appendChild(when);

      host.appendChild(tr);
    });
  }

  async function loadWarnings() {
    try {
      renderWarnings(await getJson("/api/security/adaptive/rate-warnings", { limit: 100 }));
    } catch (error) {
      renderWarnings(null);
    }
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

  // How the protection is doing: numbers from the engine's own records.
  function renderQuality(report) {
    const card = byId("ap-quality-card");
    const box = byId("ap-quality");
    if (!card || !box) return;
    card.hidden = false;
    const days = Math.max(1, Math.round((report.covered_seconds || 0) / 86400));
    setText("ap-quality-period", uiText("Last {days} days").replace("{days}", formatCount(Math.min(days, report.days || days))));
    const of = (part, whole) => `${formatCount(part)} / ${formatCount(whole)}`;
    const tiles = [
      [uiText("Bans"), formatCount(report.bans),
        report.bans_per_day == null ? "" : uiText("{count} a day").replace("{count}", formatCount(report.bans_per_day))],
      [uiText("Decided within 15 seconds"), of(report.decided_at_once, report.bans),
        uiText("of the first finding")],
      [uiText("Came back after a ban"), of(report.came_back_after_a_ban, report.first_bans_ended),
        uiText("of the bans that ended")],
      [uiText("Lifted by an operator"), formatCount(report.lifted_by_operator),
        uiText("the sign of a false ban")],
      [uiText("Probers never banned"), formatCount(report.probers_never_banned),
        uiText("one probable signature each")]
    ];
    box.textContent = "";
    tiles.forEach(([label, value, note]) => {
      const tile = document.createElement("div");
      tile.className = "ap-card";
      const name = document.createElement("div");
      name.className = "ap-label";
      name.textContent = label;
      const number = document.createElement("div");
      number.className = "ap-value";
      number.setAttribute("data-i18n-skip", "");
      number.setAttribute("translate", "no");
      number.textContent = value;
      const sub = document.createElement("div");
      sub.className = "mon-sub";
      sub.textContent = note;
      tile.append(name, number, sub);
      box.appendChild(tile);
    });
    const networks = byId("ap-quality-networks");
    if (networks) {
      const rows = report.networks || [];
      networks.textContent = rows.length
        ? `${uiText("Networks with several banned addresses")}: ` +
          rows.map((row) => `${row.network} (${formatCount(row.addresses)})`).join(", ") +
          ` · ${of(report.addresses_in_networks, report.banned_addresses)}`
        : "";
    }
    const waiting = byId("ap-quality-waiting");
    if (waiting) {
      waiting.textContent = "";
      const parts = [];
      if (report.signature_candidates) {
        parts.push(uiText("Signature candidates waiting for a decision: {count}").replace("{count}", formatCount(report.signature_candidates)));
      }
      if (report.trap_candidates) {
        parts.push(uiText("Host names that look like traps: {count}").replace("{count}", formatCount(report.trap_candidates)));
      }
      if (parts.length) {
        const text = document.createElement("span");
        text.textContent = parts.join(" · ") + " — ";
        const link = document.createElement("a");
        link.href = "/security/detection-rules";
        link.textContent = uiText("Open detection rules");
        waiting.append(text, link);
      }
    }
  }

  async function loadQuality() {
    try {
      const payload = await getJson("/api/security/adaptive/quality", { days: 7 });
      if (payload.quality) renderQuality(payload.quality);
    } catch (error) {
      /* the review below still loads */
    }
  }

  // The first step of the ladder: a page instead of a dropped connection.
  let pageEnabled = null;

  function renderFirstStep(state) {
    const box = byId("ap-page-state");
    const toggle = byId("ap-page-toggle");
    if (!box || !toggle) return;
    pageEnabled = Boolean(state.enabled);
    box.textContent = state.enabled
      ? uiText("On: the first step is answered with a page. Addresses shown the page now: {count}").replace("{count}", formatCount(state.showing_page))
      : uiText("Off: the first step is cut off like every other.");
    toggle.textContent = uiText(state.enabled ? "Cut the first step off" : "Show a page on the first step");
    toggle.hidden = false;
    toggle.disabled = false;
  }

  async function toggleFirstStep() {
    const toggle = byId("ap-page-toggle");
    const detail = byId("ap-page-detail");
    if (!toggle || pageEnabled === null) return;
    toggle.disabled = true;
    try {
      const response = await fetch("/api/security/adaptive/first-step-page", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken() },
        body: JSON.stringify({ enabled: !pageEnabled })
      });
      const payload = await response.json().catch(() => ({}));
      if (response.ok && payload.first_step_page) {
        renderFirstStep(payload.first_step_page);
        if (detail) detail.textContent = "";
      } else {
        if (detail) detail.textContent = payload.error || `HTTP ${response.status}`;
        toggle.disabled = false;
      }
    } catch (error) {
      if (detail) detail.textContent = String(error);
      toggle.disabled = false;
    }
  }

  // The first-request shield: what HAProxy refuses by itself.
  let shieldEnabled = null;

  function renderShield(state) {
    const box = byId("ap-shield-state");
    const toggle = byId("ap-shield-toggle");
    const detail = byId("ap-shield-detail");
    if (!box || !toggle) return;
    shieldEnabled = Boolean(state.enabled);
    let text;
    if (!state.enabled) {
      text = uiText("The shield is off.");
    } else if (!state.configured) {
      text = uiText("The running HAProxy configuration does not have the shield yet. Apply the HAProxy configuration once.");
    } else if (state.error) {
      text = uiText("The shield lists could not be updated in HAProxy.");
    } else if (state.mode !== "enforce") {
      text = uiText("The shield is on and waiting: it acts only in Enforce mode.");
    } else {
      text = uiText("The shield is on: HAProxy refuses {segments} file and directory names and {paths} exact paths.")
        .replace("{segments}", formatCount(state.segments))
        .replace("{paths}", formatCount(state.paths));
    }
    box.textContent = text;
    if (detail) {
      const notes = [];
      if (state.enabled && state.error) notes.push(String(state.error));
      if (state.enabled && state.exempt_hosts) {
        notes.push(uiText("Sites left out because of an exception: {count}").replace("{count}", formatCount(state.exempt_hosts)));
      }
      detail.textContent = notes.join(" · ");
    }
    toggle.textContent = uiText(state.enabled ? "Switch the shield off" : "Switch the shield on");
    toggle.hidden = false;
    toggle.disabled = false;
  }

  async function loadShield() {
    try {
      const payload = await getJson("/api/security/adaptive/health", {});
      const engine = payload.engine || payload;
      if (engine.path_shield) renderShield(engine.path_shield);
      if (engine.first_step_page) renderFirstStep(engine.first_step_page);
    } catch (error) {
      /* the mode card already says when the engine is unreachable */
    }
  }

  async function toggleShield() {
    const toggle = byId("ap-shield-toggle");
    if (!toggle || shieldEnabled === null) return;
    toggle.disabled = true;
    try {
      const response = await fetch("/api/security/adaptive/shield", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken() },
        body: JSON.stringify({ enabled: !shieldEnabled })
      });
      const payload = await response.json().catch(() => ({}));
      if (response.ok && payload.path_shield) {
        renderShield(payload.path_shield);
      } else {
        const detail = byId("ap-shield-detail");
        if (detail) detail.textContent = payload.error || `HTTP ${response.status}`;
        toggle.disabled = false;
      }
    } catch (error) {
      const detail = byId("ap-shield-detail");
      if (detail) detail.textContent = String(error);
      toggle.disabled = false;
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
      loadShield();
      loadQuality();
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
        // A new step starts at the last one (see nextStep).
        draft.push(core.nextStep(draft));
        renderLadderRows();
      });
    }

    const shield = byId("ap-shield-toggle");
    if (shield) shield.addEventListener("click", toggleShield);
    const firstStep = byId("ap-page-toggle");
    if (firstStep) firstStep.addEventListener("click", toggleFirstStep);

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
    loadWarnings();
  });
})();
