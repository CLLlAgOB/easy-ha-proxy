/* Adaptive protection: shadow review, weight simulator, per-address evidence.
 *
 * Read-only. The engine cannot ban in this release, and this page has no
 * control that would ask it to.
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

    const durations = payload.ban_durations_seconds || [];
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
    if (total >= 3600) return `${Math.round(total / 3600)}h`;
    return `${Math.round(total / 60)}m`;
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
  }

  function renderSummary(summary) {
    if (!summary) return;
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
      renderTable(payload.addresses);
      setText("ap-updated", payload.ts ? formatTime(payload.ts) : "");
      if (selectedAddress) await loadDetail(selectedAddress);
    } catch (error) {
      showUnavailable(Boolean(error.unavailable));
      renderTable([]);
    }
  }

  function bind() {
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
