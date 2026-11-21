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
      cell(row, when(item.expires_at));
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
      showErrors(payload.errors);
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
      throw new Error(payload.error || `HTTP ${response.status}`);
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
      say(String(error.message || error), true);
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
      if (payload.apply_needed) {
        message += " " + t("Apply the configuration to put it into HAProxy.");
      }
      if (payload.access_page === "gone") {
        message += " " + t("Its access page had already been removed for good.");
      }
      (payload.notes || []).forEach((note) => {
        message += ` ${note}.`;
      });
      say(message, false);
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
      const payload = await post("/api/haproxy/trash/empty", {});
      say(`${t("Items deleted for good")}: ${payload.removed || 0}.`, false);
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    const empty = byId("tr-empty");
    if (empty) empty.addEventListener("click", emptyTrash);
    load();
  });
})();
