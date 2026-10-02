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
  let catalogue = [];

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

  function badge(kind, text) {
    const span = document.createElement("span");
    span.className = `al-badge al-${kind}`;
    span.textContent = text;
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

  function renderActive(active, pending) {
    const body = byId("al-active-body");
    const empty = byId("al-active-empty");
    if (!body) return;
    body.textContent = "";
    const rows = (active || [])
      .map((row) => ({ ...row, kind: "firing" }))
      .concat((pending || []).map((row) => ({ ...row, kind: "pending" })));
    rows.forEach((entry) => {
      const tr = document.createElement("tr");
      cell(tr, entry.rule);
      cell(tr, entry.subject);
      cell(tr, badge(entry.severity || "info", entry.severity || "info"));
      cell(
        tr,
        badge(
          entry.kind === "firing" ? "critical" : "warning",
          entry.kind === "firing" ? t("firing") : t("waiting")
        )
      );
      cell(tr, formatAge(entry.since_ts));
      cell(tr, entry.summary);
      body.appendChild(tr);
    });
    if (empty) empty.hidden = rows.length > 0;
  }

  function renderHistory(events) {
    const body = byId("al-history-body");
    const empty = byId("al-history-empty");
    if (!body) return;
    body.textContent = "";
    (events || []).forEach((event) => {
      const tr = document.createElement("tr");
      cell(tr, formatTime(event.ts));
      cell(tr, event.rule);
      cell(tr, event.subject);
      cell(tr, event.transition);
      cell(tr, badge(event.severity || "info", event.severity || "info"));
      const delivery = event.delivered
        ? badge("ok", event.delivered)
        : badge("warning", event.delivery_error || t("not sent"));
      cell(tr, delivery);
      body.appendChild(tr);
    });
    if (empty) empty.hidden = (events || []).length > 0;
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
    set("al-min-severity", config.min_severity || "info");
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
      const state = await getJson("/api/alerts/state", { limit: 100 });
      setUnavailable(false);
      renderActive(state.active, state.pending);
      renderHistory(state.history);
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

  function wire() {
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
