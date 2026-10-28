/* Alerts: what is firing now, what was sent, and what gets sent at all.
 *
 * The page never holds a secret. The webhook URL and its header value come
 * back from the daemon already shortened, so the fields below start empty or
 * masked and are only sent when the operator actually types something.
 */
(function () {
  "use strict";

  const t = window.t || ((value) => String(value));
  const dateTimeFormat = new Intl.DateTimeFormat(document.documentElement.lang || undefined, {
    dateStyle: "short",
    timeStyle: "medium"
  });

  const REFRESH_MS = 20000;
  const MASK = "***";
  const HISTORY_PAGE = 100;
  const MUTE_CHOICES = [
    [3600, "1 hour"],
    [8 * 3600, "8 hours"],
    [86400, "1 day"],
    [7 * 86400, "7 days"]
  ];
  const SUPERADMIN = (document.getElementById("al-role") || { dataset: {} }).dataset.superadmin === "true";
  let catalogue = [];
  let historyRows = [];
  let historyTotal = 0;

  function byId(id) {
    return document.getElementById(id);
  }

  function csrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute("content") || "" : "";
  }

  function formatTime(seconds) {
    const numeric = Number(seconds);
    if (!Number.isFinite(numeric) || numeric <= 0) return "—";
    return dateTimeFormat.format(new Date(numeric * 1000));
  }

  function formatAge(seconds) {
    const numeric = Math.max(0, Math.floor(Date.now() / 1000 - Number(seconds || 0)));
    if (numeric < 60) return `${numeric}s`;
    if (numeric < 3600) return `${Math.floor(numeric / 60)}m`;
    if (numeric < 86400) return `${Math.floor(numeric / 3600)}h`;
    return `${Math.floor(numeric / 86400)}d`;
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
      error.unavailable = Boolean(payload.unavailable);
      throw error;
    }
    return payload;
  }

  async function postJson(path, body) {
    const response = await fetch(path, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        "X-CSRFToken": csrfToken()
      },
      credentials: "same-origin",
      body: JSON.stringify(body || {})
    });
    const payload = await response.json().catch(() => ({}));
    return { ok: response.ok && payload.ok !== false, payload };
  }

  // A phrase from the daemon is translated whole or not at all: the general
  // translator replaces the words it knows one by one, which turned "the rule
  // is switched off" into half a sentence in each language.
  const STORM = /^more than (\d+) notifications in (\d+) minutes$/;

  function known(text) {
    const value = String(text == null ? "" : text);
    const messages = (window.HAPROXY_ADMIN_I18N && window.HAPROXY_ADMIN_I18N.messages) || {};
    if (Object.prototype.hasOwnProperty.call(messages, value)) return messages[value];
    if (value.startsWith("muted until ")) {
      return `${known("Muted until")} ${value.slice("muted until ".length)}`;
    }
    const storm = STORM.exec(value);
    if (storm) {
      return t("more than {count} notifications in {minutes} minutes", { count: storm[1], minutes: storm[2] });
    }
    return value;
  }

  function badge(kind, text) {
    const span = document.createElement("span");
    span.className = `al-badge al-${kind}`;
    span.textContent = known(text);
    span.setAttribute("data-i18n-skip", "");
    span.setAttribute("translate", "no");
    return span;
  }

  function cell(row, value) {
    const td = document.createElement("td");
    if (value instanceof Node) td.appendChild(value);
    else td.textContent = value == null || value === "" ? "—" : String(value);
    row.appendChild(td);
    return td;
  }

  // Tell the header of this page that what it shows has changed.
  function announceChange() {
    window.dispatchEvent(new CustomEvent("easy-ha-proxy:alerts-changed"));
  }

  async function act(path, body) {
    const { ok, payload } = await postJson(path, body);
    const status = byId("al-status");
    if (!ok && status) status.textContent = payload.error || t("The action failed");
    await refresh();
    announceChange();
    return ok;
  }

  function smallButton(label, handler) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "btn";
    button.textContent = t(label);
    button.addEventListener("click", handler);
    return button;
  }

  // What an operator can do with an alert that fires: acknowledge it (quiet
  // until it recovers), mute it for a while, or -- for an event, which no
  // producer will ever report as over -- dismiss it.
  function actionsCell(entry, kinds) {
    const td = document.createElement("td");
    td.className = "al-row-actions";
    if (entry.kind !== "firing") {
      td.textContent = "—";
      return td;
    }
    const key = { rule: entry.rule, subject: entry.subject };
    const now = Date.now() / 1000;
    const mutedUntil = Number(entry.muted_until) || 0;
    const acknowledged = Number(entry.acknowledged_ts) || 0;
    const note = (text) => {
      const small = document.createElement("small");
      small.textContent = text;
      td.appendChild(small);
    };
    if (mutedUntil > now) {
      note(`${t("Muted until")} ${formatTime(mutedUntil)}`);
      td.appendChild(smallButton("Unmute", () => act("/api/alerts/quieten", { ...key, mode: "clear" })));
    } else if (acknowledged && !mutedUntil) {
      note(`${t("Acknowledged")}${entry.acknowledged_by ? ` · ${entry.acknowledged_by}` : ""}`);
      td.appendChild(smallButton("Undo", () => act("/api/alerts/quieten", { ...key, mode: "clear" })));
    } else {
      td.appendChild(smallButton("Acknowledge", () => act("/api/alerts/quieten", { ...key, mode: "acknowledge" })));
      const choice = document.createElement("select");
      choice.setAttribute("aria-label", t("Mute"));
      MUTE_CHOICES.forEach(([seconds, label]) => {
        const option = document.createElement("option");
        option.value = String(seconds);
        option.textContent = t(label);
        choice.appendChild(option);
      });
      td.appendChild(choice);
      td.appendChild(smallButton("Mute", () =>
        act("/api/alerts/quieten", { ...key, mode: "mute", seconds: Number(choice.value) })
      ));
    }
    if (kinds[entry.rule] === "event") {
      td.appendChild(smallButton("Dismiss", () => act("/api/alerts/dismiss", key)));
    }
    // Mail held back waits up to an hour between attempts; once the cause is
    // fixed there is no reason to wait for that.
    if (entry.rule === "mail.delivery_failed") {
      td.appendChild(smallButton("Retry sending now", async () => {
        const ok = await act("/api/alerts/mail/retry", {});
        const status = byId("al-status");
        if (ok && status) status.textContent = t("The relay is sending what it held; this alert is checked again in half a minute");
      }));
    }
    return td;
  }

  function renderActive(active, pending, rules) {
    const body = byId("al-active-body");
    const empty = byId("al-active-empty");
    if (!body) return;
    body.textContent = "";
    const kinds = {};
    (rules || []).forEach((rule) => {
      kinds[rule.name] = rule.kind;
    });
    const rows = (active || [])
      .map((row) => ({ ...row, kind: "firing" }))
      .concat((pending || []).map((row) => ({ ...row, kind: "pending" })));
    const now = Date.now() / 1000;
    rows.forEach((entry) => {
      const tr = document.createElement("tr");
      // Acknowledged or muted: still true, so still listed, but quiet.
      const muted = Number(entry.muted_until) > now;
      const acknowledged = Number(entry.acknowledged_ts) > 0 && !Number(entry.muted_until);
      if (entry.kind === "firing" && (muted || acknowledged)) tr.className = "al-quiet";
      cell(tr, entry.rule);
      cell(tr, entry.subject);
      cell(tr, badge(entry.severity || "info", entry.severity || "info"));
      cell(
        tr,
        badge(
          entry.kind === "firing" ? "critical" : "warning",
          entry.kind === "firing" ? "firing" : "waiting"
        )
      );
      cell(tr, formatAge(entry.since_ts));
      cell(tr, entry.summary);
      tr.appendChild(actionsCell(entry, kinds));
      body.appendChild(tr);
    });
    if (empty) empty.hidden = rows.length > 0;
  }

  function selectedHistory() {
    return Array.from(document.querySelectorAll("#al-history-body input[data-id]:checked"))
      .map((box) => Number(box.dataset.id))
      .filter((id) => Number.isInteger(id));
  }

  function updateDeleteButton() {
    const button = byId("al-history-delete");
    if (button) button.disabled = selectedHistory().length === 0;
  }

  function renderHistory(events) {
    const body = byId("al-history-body");
    const empty = byId("al-history-empty");
    if (!body) return;
    body.textContent = "";
    (events || []).forEach((event) => {
      const tr = document.createElement("tr");
      if (SUPERADMIN) {
        const pick = document.createElement("td");
        const box = document.createElement("input");
        box.type = "checkbox";
        box.dataset.id = String(event.id);
        box.setAttribute("aria-label", t("Select"));
        box.addEventListener("change", updateDeleteButton);
        pick.appendChild(box);
        tr.appendChild(pick);
      }
      cell(tr, formatTime(event.ts));
      cell(tr, event.rule);
      cell(tr, event.subject);
      cell(tr, known(event.transition));
      cell(tr, badge(event.severity || "info", event.severity || "info"));
      const delivery = event.delivered
        ? badge("ok", event.delivered)
        : badge("warning", event.delivery_error || t("not sent"));
      cell(tr, delivery);
      body.appendChild(tr);
    });
    if (empty) empty.hidden = (events || []).length > 0;
    const more = byId("al-history-more");
    if (more) more.hidden = (events || []).length >= historyTotal;
    const count = byId("al-history-count");
    if (count) count.textContent = historyTotal ? `${(events || []).length} / ${historyTotal}` : "";
    const all = byId("al-history-all");
    if (all) all.checked = false;
    updateDeleteButton();
  }

  // The history is read on its own, filtered and a page at a time, so a
  // refresh does not throw away what the operator scrolled to or ticked.
  async function loadHistory(append) {
    const params = { limit: HISTORY_PAGE, offset: append ? historyRows.length : 0 };
    const severity = (byId("al-history-severity") || {}).value;
    const rule = (byId("al-history-rule") || {}).value;
    if (severity) params.severity = severity;
    if (rule) params.rule = rule;
    const page = await getJson("/api/alerts/history", params);
    historyTotal = Number(page.total) || 0;
    historyRows = append ? historyRows.concat(page.events || []) : page.events || [];
    renderHistory(historyRows);
  }

  function historyBusy() {
    return historyRows.length > HISTORY_PAGE || selectedHistory().length > 0;
  }

  function renderRuleFilter(rules) {
    const select = byId("al-history-rule");
    if (!select || select.options.length > 1) return;
    (rules || []).forEach((rule) => {
      const option = document.createElement("option");
      option.value = rule.name;
      option.textContent = t(rule.title || rule.name);
      select.appendChild(option);
    });
  }

  function renderRules(rules) {
    const body = byId("al-rules-body");
    if (!body) return;
    catalogue = rules || [];
    body.textContent = "";
    catalogue.forEach((rule) => {
      const tr = document.createElement("tr");
      tr.dataset.rule = rule.name;

      const name = document.createElement("td");
      name.textContent = rule.name;
      name.setAttribute("data-i18n-skip", "");
      name.setAttribute("translate", "no");
      tr.appendChild(name);

      cell(tr, rule.kind === "event" ? t("event") : t("level"));
      cell(tr, badge(rule.severity, rule.severity));

      const enabledCell = document.createElement("td");
      const enabled = document.createElement("input");
      enabled.type = "checkbox";
      enabled.checked = rule.enabled !== false;
      enabled.className = "al-rule-enabled";
      enabledCell.appendChild(enabled);
      tr.appendChild(enabledCell);

      const delayCell = document.createElement("td");
      const delay = document.createElement("input");
      delay.type = "number";
      delay.min = "0";
      delay.value = String(rule.trigger_delay ?? 0);
      delay.className = "al-rule-delay";
      // An event has already happened; a delay there would only postpone the
      // one message that matters.
      delay.disabled = rule.kind === "event";
      delayCell.appendChild(delay);
      tr.appendChild(delayCell);

      const repeatCell = document.createElement("td");
      const repeat = document.createElement("input");
      repeat.type = "number";
      repeat.min = "300";
      repeat.value = String(rule.repeat_after ?? 21600);
      repeat.className = "al-rule-repeat";
      repeatCell.appendChild(repeat);
      tr.appendChild(repeatCell);

      body.appendChild(tr);
    });
  }

  function renderConfig(config) {
    if (!config) return;
    const set = (id, value) => {
      const element = byId(id);
      if (element) element.value = value;
    };
    set("al-enabled", config.enabled === false ? "false" : "true");
    set("al-email-enabled", config.email_enabled === false ? "false" : "true");
    set("al-min-severity", config.min_severity || "warning");
    set("al-portal-min-severity", config.portal_min_severity || "warning");
    set("al-recipient", config.recipient || "");
    set("al-webhook-header-name", config.webhook_header_name || "");
    set(
      "al-webhook-allow-private",
      config.webhook_allow_private ? "true" : "false"
    );
    // Both of these arrive shortened. Showing the shortened form as the field
    // value would let a save write the mask back as the real setting.
    const url = byId("al-webhook-url");
    if (url) {
      url.value = "";
      url.placeholder = config.webhook_url || "https://hooks.example.com/...";
    }
    const secret = byId("al-webhook-header-value");
    if (secret) {
      secret.value = "";
      secret.placeholder = config.webhook_header_value ? MASK : "";
    }
  }

  function renderChannels(health) {
    const element = byId("al-channels");
    if (!element) return;
    const channels = (health && health.channels) || {};
    const ready = Object.keys(channels).filter((name) => channels[name]);
    element.textContent = ready.length ? ready.join(", ") : t("none");
  }

  function setUnavailable(unavailable) {
    const notice = byId("al-unavailable");
    if (notice) notice.hidden = !unavailable;
  }

  async function refresh() {
    const status = byId("al-status");
    try {
      const state = await getJson("/api/alerts/state", { limit: 1 });
      setUnavailable(false);
      renderActive(state.active, state.pending, state.catalogue);
      renderRuleFilter(state.catalogue);
      if (!historyBusy()) await loadHistory(false);
      renderRules(state.catalogue);
      renderConfig(state.config);
      const firing = (state.active || []).length;
      const pending = (state.pending || []).length;
      byId("al-count-firing").textContent = String(firing);
      byId("al-count-pending").textContent = String(pending);
      if (status) status.textContent = formatTime(state.ts);
    } catch (error) {
      setUnavailable(Boolean(error.unavailable));
      if (status) status.textContent = error.message;
      return;
    }
    try {
      renderChannels(await getJson("/api/alerts/health"));
    } catch (error) {
      renderChannels(null);
    }
  }

  function deliveryPayload() {
    const payload = {
      enabled: byId("al-enabled").value === "true",
      email_enabled: byId("al-email-enabled").value === "true",
      min_severity: byId("al-min-severity").value,
      portal_min_severity: byId("al-portal-min-severity").value,
      recipient: byId("al-recipient").value.trim(),
      webhook_header_name: byId("al-webhook-header-name").value.trim(),
      webhook_allow_private: byId("al-webhook-allow-private").value === "true"
    };
    // An untouched field means "leave it alone", which is not the same as
    // "clear it": the daemon never told us what is there.
    const url = byId("al-webhook-url").value.trim();
    if (url) payload.webhook_url = url;
    const secret = byId("al-webhook-header-value").value;
    if (secret) payload.webhook_header_value = secret;
    return payload;
  }

  function rulesPayload() {
    const rules = {};
    document.querySelectorAll("#al-rules-body tr").forEach((row) => {
      const name = row.dataset.rule;
      if (!name) return;
      rules[name] = {
        enabled: row.querySelector(".al-rule-enabled").checked,
        trigger_delay: Number(row.querySelector(".al-rule-delay").value || 0),
        repeat_after: Number(row.querySelector(".al-rule-repeat").value || 21600)
      };
    });
    return { rules };
  }

  async function save(payload, resultId) {
    const target = byId(resultId);
    if (target) target.textContent = t("Saving…");
    const { ok, payload: response } = await postJson("/api/alerts/config", payload);
    if (target) {
      target.textContent = ok
        ? t("Saved")
        : response.error || t("The settings were not saved");
    }
    if (ok) await refresh();
  }

  function wireHistory() {
    ["al-history-severity", "al-history-rule"].forEach((id) => {
      const select = byId(id);
      if (select) select.addEventListener("change", () => loadHistory(false));
    });
    const more = byId("al-history-more");
    if (more) more.addEventListener("click", () => loadHistory(true));
    const all = byId("al-history-all");
    if (all) {
      all.addEventListener("change", () => {
        document.querySelectorAll("#al-history-body input[data-id]").forEach((box) => {
          box.checked = all.checked;
        });
        updateDeleteButton();
      });
    }
    const remove = byId("al-history-delete");
    if (remove) {
      remove.addEventListener("click", async () => {
        const ids = selectedHistory();
        if (!ids.length || !window.confirm(t("Delete the selected entries?"))) return;
        await act("/api/alerts/history/delete", { ids: ids });
        await loadHistory(false);
      });
    }
    const clear = byId("al-history-clear");
    if (clear) {
      clear.addEventListener("click", async () => {
        if (!window.confirm(t("Delete the whole alert history?"))) return;
        await act("/api/alerts/history/delete", { all: true });
        await loadHistory(false);
      });
    }
  }

  function wire() {
    wireHistory();
    const saveDelivery = byId("al-save");
    if (saveDelivery) {
      saveDelivery.addEventListener("click", () =>
        save(deliveryPayload(), "al-save-result")
      );
    }
    const saveRules = byId("al-save-rules");
    if (saveRules) {
      saveRules.addEventListener("click", () =>
        save(rulesPayload(), "al-rules-result")
      );
    }
    const test = byId("al-test");
    if (test) {
      test.addEventListener("click", async () => {
        const target = byId("al-save-result");
        if (target) target.textContent = t("Sending…");
        const { ok, payload } = await postJson("/api/alerts/test", {});
        if (!target) return;
        if (ok) {
          target.textContent = `${t("Sent through")}: ${(payload.delivered || []).join(", ")}`;
        } else {
          target.textContent =
            (payload.errors || []).join("; ") ||
            payload.error ||
            t("Nothing was delivered");
        }
      });
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    wire();
    refresh();
    window.setInterval(refresh, REFRESH_MS);
  });
})();
