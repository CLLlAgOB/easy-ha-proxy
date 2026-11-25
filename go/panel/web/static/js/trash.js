/* Trash: deleted sites, forwards, certificates and their settings.
 *
 * Two keepers answer through one list: the panel keeps sites, TCP proxies
 * and UDP forwards; certd on the host keeps certificates, authorities, DNS
 * profiles and delivery targets. Each row carries which one holds it, and
 * the page sends that back unchanged. Nothing secret ever reaches the page:
 * certd answers with names and dates only.
 */
(function () {
  "use strict";

  const t = window.t || ((value) => String(value));
  const KINDS = {
    site: "HTTP site",
    tcp: "TCP proxy",
    udp: "UDP forward",
    haproxy_cert: "HAProxy certificate",
    letsencrypt: "Let's Encrypt certificate",
    standby: "Standby certificate",
    external_ca: "External certificate authority",
    internal_ca: "Internal certificate authority",
    dns_provider: "DNS profile",
    cert_delivery: "Certificate delivery target"
  };
  let items = [];
  let busy = false;
  let keepDays = 0;
  let certdKeepDays = null;

  function byId(id) {
    return document.getElementById(id);
  }

  function csrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute("content") || "" : "";
  }

  function say(message, isError) {
    const host = byId("tr-result");
    if (!host) return;
    host.textContent = message || "";
    host.style.color = isError ? "var(--error)" : "";
  }

  function when(seconds) {
    const numeric = Number(seconds);
    if (!Number.isFinite(numeric) || numeric <= 0) return "—";
    return window.EasyHaProxyTime.dateTime(numeric * 1000);
  }

  function kindLabel(kind) {
    return KINDS[kind] ? t(KINDS[kind]) : kind;
  }

  function cell(row, text) {
    const td = document.createElement("td");
    td.textContent = text;
    row.appendChild(td);
    return td;
  }

  function button(label, extra, handler) {
    const element = document.createElement("button");
    element.type = "button";
    element.className = "btn btn-small" + (extra ? ` ${extra}` : "");
    element.textContent = t(label);
    element.addEventListener("click", handler);
    return element;
  }

  function render() {
    const body = byId("tr-body");
    const count = byId("tr-count");
    const empty = byId("tr-empty");
    if (count) count.textContent = items.length ? String(items.length) : "";
    if (empty) empty.disabled = busy || !items.length;
    if (!body) return;
    body.textContent = "";
    if (!items.length) {
      const row = document.createElement("tr");
      const td = cell(row, t("The trash is empty"));
      td.colSpan = 7;
      td.className = "muted";
      body.appendChild(row);
      return;
    }
    items.forEach((item) => {
      const row = document.createElement("tr");
      cell(row, kindLabel(item.kind));
      cell(row, item.name || "—").className = "mono";
      const detail = [item.detail, item.not_after ? `${t("valid until")} ${item.not_after}` : ""]
        .filter(Boolean)
        .join(" · ");
      cell(row, detail || "—");
      cell(row, when(item.deleted_at));
      cell(row, item.deleted_by || "—");
      cell(row, Number(item.expires_at) > 0 ? when(item.expires_at) : t("When the trash is emptied"));
      const actions = cell(row, "");
      const holder = document.createElement("div");
      holder.className = "cd-actions";
      holder.appendChild(button("Restore", "", () => restore(item)));
      holder.appendChild(button("Delete for good", "btn-danger", () => removeForGood(item)));
      actions.appendChild(holder);
      body.appendChild(row);
    });
  }

  function showErrors(errors) {
    const banner = byId("tr-errors");
    if (!banner) return;
    const list = (errors || []).map((message) => t(message));
    banner.textContent = list.join(" · ");
    banner.hidden = !list.length;
  }

  async function load() {
    try {
      const response = await fetch("/api/haproxy/trash", {
        headers: { Accept: "application/json" },
        credentials: "same-origin"
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok || payload.ok === false) {
        throw new Error(payload.error || `HTTP ${response.status}`);
      }
      items = Array.isArray(payload.items) ? payload.items : [];
      keepDays = Number(payload.keep_days) || 0;
      certdKeepDays = Number.isInteger(payload.certd_keep_days) ? payload.certd_keep_days : null;
      showErrors(payload.errors);
      showSettings();
    } catch (error) {
      showErrors([String(error.message || error)]);
    }
    render();
  }

  async function post(path, body) {
    const response = await fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": csrfToken()
      },
      body: JSON.stringify(body || {})
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || payload.ok === false) {
      const error = new Error(payload.error || `HTTP ${response.status}`);
      error.payload = payload;
      throw error;
    }
    return payload;
  }

  async function run(work) {
    if (busy) return;
    busy = true;
    render();
    try {
      await work();
    } catch (error) {
      say(t(String(error.message || error)), true);
    } finally {
      busy = false;
      await load();
    }
  }

  function restore(item) {
    if (!window.confirm(`${t("Restore")} ${kindLabel(item.kind)} ${item.name}?`)) return;
    run(async () => {
      const payload = await post("/api/haproxy/trash/restore", { source: item.source, id: item.id });
      let message = `${t("Restored")}: ${item.name}.`;
      let warn = Boolean(payload.warning);
      if (payload.warning) {
        message += " " + t(payload.warning);
      }
      if (payload.apply_needed) {
        message += " " + t("Apply the configuration to put it into HAProxy.");
      }
      if (payload.access_page === "gone") {
        message += " " + t("Its access page had already been removed for good.");
      } else if (payload.access_page === "failed") {
        message += " " + t("Its access page could not be restored.");
        warn = true;
      }
      (payload.notes || []).forEach((note) => {
        message += ` ${note}.`;
      });
      say(message, warn);
      if (payload.apply_needed) {
        document.dispatchEvent(new CustomEvent("easy-ha-proxy:config-state-changed"));
      }
    });
  }

  function removeForGood(item) {
    if (!window.confirm(`${t("Delete for good, with no way back:")} ${item.name}?`)) return;
    run(async () => {
      await post("/api/haproxy/trash/delete", { source: item.source, id: item.id });
      say(`${t("Deleted for good")}: ${item.name}.`, false);
    });
  }

  function emptyTrash() {
    if (!items.length) return;
    if (!window.confirm(t("Delete everything in the trash for good? This cannot be undone."))) return;
    run(async () => {
      try {
        const payload = await post("/api/haproxy/trash/empty", {});
        say(`${t("Items deleted for good")}: ${payload.removed || 0}.`, false);
      } catch (error) {
        const removed = Number(error?.payload?.removed || 0);
        const detail = t(String(error.message || error));
        say(
          removed > 0
            ? `${t("Items deleted for good")}: ${removed}. ${detail}`
            : detail,
          true
        );
      }
    });
  }

  let settingsTouched = false;

  function sayAboutSettings(message, isError) {
    const host = byId("tr-settings-result");
    if (!host) return;
    host.textContent = message || "";
    host.style.color = isError ? "var(--error)" : "";
  }

  function showTerm() {
    const term = byId("tr-keep-term");
    const group = byId("tr-term-group");
    if (group) group.hidden = !(term && term.checked);
  }

  function showSettings() {
    if (settingsTouched) return;
    const forever = byId("tr-keep-forever");
    const term = byId("tr-keep-term");
    const days = byId("tr-keep-days");
    if (forever) forever.checked = keepDays <= 0;
    if (term) term.checked = keepDays > 0;
    if (days && keepDays > 0) days.value = String(keepDays);
    showTerm();
    if (certdKeepDays !== null && certdKeepDays !== keepDays) {
      sayAboutSettings(
        t("The certificate service keeps its items on another term. Save the setting again to align it."),
        true
      );
    }
  }

  function saveSettings(event) {
    event.preventDefault();
    const term = byId("tr-keep-term");
    const input = byId("tr-keep-days");
    let wanted = 0;
    if (term && term.checked) {
      wanted = Number(input ? input.value : "");
      if (!Number.isInteger(wanted) || wanted < 1 || wanted > Number(input.max || 3650)) {
        sayAboutSettings(t("The term must be a whole number of days from 1 to 3650."), true);
        return;
      }
      const shorter = keepDays <= 0 || wanted < keepDays;
      if (shorter && !window.confirm(t("Items older than the term are deleted for good at once. Save?"))) {
        return;
      }
    }
    run(async () => {
      try {
        const payload = await post("/api/haproxy/trash/settings", { keep_days: wanted });
        keepDays = Number(payload.keep_days) || 0;
        certdKeepDays = keepDays;
        settingsTouched = false;
        sayAboutSettings(t("Saved."), false);
      } catch (error) {
        sayAboutSettings(t(String(error.message || error)), true);
      }
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    const empty = byId("tr-empty");
    if (empty) empty.addEventListener("click", emptyTrash);
    const form = byId("tr-settings");
    if (form) {
      form.addEventListener("submit", saveSettings);
      form.addEventListener("change", () => {
        settingsTouched = true;
        showTerm();
      });
    }
    load();
  });
})();
