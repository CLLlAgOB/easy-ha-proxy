/* Runtime server operations: Ready / Drain / Maintenance and weight.
 *
 * Every change is a named operation on a server the server side re-validates
 * against what HAProxy currently reports; the browser never sends runtime API
 * command text.
 */
(function () {
  "use strict";

  const t = window.t || ((value) => String(value));
  const numberFormat = new Intl.NumberFormat(document.documentElement.lang || undefined);
  const timeFormat = new Intl.DateTimeFormat(document.documentElement.lang || undefined, {
    timeStyle: "medium"
  });

  const STATES = [
    { key: "ready", label: "Ready" },
    { key: "drain", label: "Drain" },
    { key: "maint", label: "Maintenance" }
  ];
  const REFRESH_INTERVAL_MS = 10000;

  let superadmin = false;
  let busy = false;

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

  function showError(message) {
    const notice = byId("rt-error");
    if (!notice) return;
    notice.textContent = message || "";
    notice.hidden = !message;
  }

  function stateClass(server) {
    const status = (server.status || "").toUpperCase();
    if (server.admin_state === "maint") return "rt-maint";
    if (server.admin_state === "drain") return "rt-drain";
    if (status.startsWith("DOWN")) return "rt-down";
    return "rt-ready";
  }

  async function post(path, body) {
    const response = await fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": csrfToken()
      },
      body: JSON.stringify(body)
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || payload.ok === false) {
      throw new Error(payload.error || `HTTP ${response.status}`);
    }
    return payload;
  }

  async function change(action, body) {
    if (busy) return;
    busy = true;
    showError("");
    try {
      await post(`/api/haproxy/backends/${action}`, body);
      await load();
    } catch (error) {
      showError(String(error.message || error));
    } finally {
      busy = false;
    }
  }

  function renderServer(backend, server) {
    const row = document.createElement("div");
    row.className = "rt-server";

    const name = document.createElement("div");
    name.className = "rt-name";
    const label = document.createElement("span");
    label.setAttribute("data-i18n-skip", "");
    label.setAttribute("translate", "no");
    label.textContent = server.server;
    name.appendChild(label);
    const address = document.createElement("small");
    address.setAttribute("data-i18n-skip", "");
    address.setAttribute("translate", "no");
    address.textContent = server.address || "";
    name.appendChild(address);
    row.appendChild(name);

    const state = document.createElement("div");
    const pill = document.createElement("span");
    pill.className = `rt-state ${stateClass(server)}`;
    pill.setAttribute("data-i18n-skip", "");
    pill.setAttribute("translate", "no");
    pill.textContent = server.status || "—";
    state.appendChild(pill);
    row.appendChild(state);

    const sessions = document.createElement("div");
    sessions.className = "rt-sessions";
    sessions.textContent = `${uiText("Sessions")}: ${numberFormat.format(
      Number(server.sessions) || 0
    )}`;
    row.appendChild(sessions);

    const weight = document.createElement("div");
    weight.className = "rt-weight";
    const weightLabel = document.createElement("span");
    weightLabel.textContent = uiText("Weight");
    weight.appendChild(weightLabel);
    const input = document.createElement("input");
    input.type = "number";
    input.min = "0";
    input.max = "256";
    input.value = String(Number(server.weight) || 0);
    input.disabled = !superadmin;
    input.addEventListener("change", () => {
      change("weight", {
        backend: backend.backend,
        server: server.server,
        weight: input.value
      });
    });
    weight.appendChild(input);
    row.appendChild(weight);

    const actions = document.createElement("div");
    actions.className = "rt-actions";
    STATES.forEach((entry) => {
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = uiText(entry.label);
      button.setAttribute(
        "aria-pressed",
        server.admin_state === entry.key ? "true" : "false"
      );
      button.disabled = !superadmin || server.admin_state === entry.key;
      button.addEventListener("click", () => {
        change("state", {
          backend: backend.backend,
          server: server.server,
          state: entry.key
        });
      });
      actions.appendChild(button);
    });
    row.appendChild(actions);

    return row;
  }

  function render(backends) {
    const host = byId("rt-list");
    const empty = byId("rt-empty");
    if (!host) return;
    host.textContent = "";
    if (!backends || !backends.length) {
      if (empty) empty.hidden = false;
      return;
    }
    if (empty) empty.hidden = true;

    backends.forEach((backend) => {
      const section = document.createElement("div");
      section.className = "rt-backend";

      const heading = document.createElement("h3");
      heading.setAttribute("data-i18n-skip", "");
      heading.setAttribute("translate", "no");
      heading.textContent = backend.label || backend.backend;
      section.appendChild(heading);

      const identifier = document.createElement("div");
      identifier.className = "rt-id";
      identifier.setAttribute("data-i18n-skip", "");
      identifier.setAttribute("translate", "no");
      identifier.textContent = backend.backend;
      section.appendChild(identifier);

      (backend.servers || []).forEach((server) => {
        section.appendChild(renderServer(backend, server));
      });

      host.appendChild(section);
    });
  }

  async function load() {
    try {
      const response = await fetch("/api/haproxy/backends", {
        headers: { Accept: "application/json" },
        credentials: "same-origin"
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok || payload.ok === false) {
        showError(payload.error || `HTTP ${response.status}`);
        return;
      }
      render(payload.backends);
      const updated = byId("rt-updated");
      if (updated) updated.textContent = timeFormat.format(new Date());
    } catch (error) {
      showError(String(error.message || error));
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    const host = byId("rt-list");
    superadmin = Boolean(host && host.dataset.superadmin === "1");
    load();
    window.setInterval(() => {
      // Skip while a change is in flight so a refresh cannot overwrite the
      // row the operator is interacting with.
      if (!document.hidden && !busy) load();
    }, REFRESH_INTERVAL_MS);
  });
})();
