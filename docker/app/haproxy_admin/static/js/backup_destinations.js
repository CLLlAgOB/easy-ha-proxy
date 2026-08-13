/* Off-host backup destinations.
 *
 * The page never holds the private key or the host key: the daemon reports
 * only whether each is installed, so the fields start empty and an empty
 * field on save means "keep what is stored".
 */
(function () {
  "use strict";

  const t = window.t || ((value) => String(value));

  function byId(id) {
    return document.getElementById(id);
  }

  function csrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute("content") || "" : "";
  }

  async function api(path, body) {
    const options = {
      headers: { Accept: "application/json" },
      credentials: "same-origin"
    };
    if (body !== undefined) {
      options.method = "POST";
      options.headers["Content-Type"] = "application/json";
      options.headers["X-CSRFToken"] = csrfToken();
      options.body = JSON.stringify(body);
    }
    const response = await fetch(`/system/backups${path}`, options);
    const payload = await response.json().catch(() => ({}));
    return { ok: response.ok && payload.ok !== false, payload };
  }

  function status(message) {
    const element = byId("dest-status");
    if (element) element.textContent = message || "";
  }

  function cell(row, value) {
    const td = document.createElement("td");
    if (value instanceof Node) td.appendChild(value);
    else td.textContent = value == null || value === "" ? "—" : String(value);
    row.appendChild(td);
    return td;
  }

  function button(label, handler, className) {
    const element = document.createElement("button");
    element.type = "button";
    element.className = className || "btn";
    element.textContent = t(label);
    element.addEventListener("click", handler);
    return element;
  }

  function fill(destination) {
    byId("dest-name").value = destination.name || "";
    byId("dest-host").value = destination.host || "";
    byId("dest-port").value = String(destination.port || 22);
    byId("dest-user").value = destination.user || "";
    byId("dest-path").value = destination.path || "";
    byId("dest-keep-daily").value = String(destination.keep_daily ?? 7);
    byId("dest-keep-weekly").value = String(destination.keep_weekly ?? 4);
    byId("dest-keep-monthly").value = String(destination.keep_monthly ?? 6);
    // Both are stored root-only and never returned; leaving them empty keeps
    // what is already there.
    byId("dest-key").value = "";
    byId("dest-host-key").value = "";
    status(`${t("Editing")}: ${destination.name}`);
  }

  async function remove(name) {
    status(t("Deleting…"));
    const { ok, payload } = await api("/api/destinations/delete", { name });
    status(ok ? t("Deleted") : payload.error || t("Could not delete it"));
    refresh();
  }

  async function test(name) {
    status(`${t("Testing")} ${name}…`);
    const { ok, payload } = await api("/api/destinations/test", { name });
    status(ok ? t("The destination answered and the path is writable")
              : payload.error || t("The destination did not answer"));
  }

  function render(destinations) {
    const body = byId("backup-destinations-body");
    if (!body) return;
    body.textContent = "";
    if (!destinations.length) {
      const row = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 4;
      td.className = "muted";
      td.textContent = t("No destination yet");
      row.appendChild(td);
      body.appendChild(row);
      return;
    }
    destinations.forEach((destination) => {
      const row = document.createElement("tr");
      cell(row, destination.name);
      cell(
        row,
        `${destination.user}@${destination.host}:${destination.port}${destination.path}`
      );
      cell(
        row,
        `${destination.keep_daily}/${destination.keep_weekly}/${destination.keep_monthly}`
      );
      const actions = document.createElement("td");
      actions.appendChild(button("Test", () => test(destination.name)));
      actions.appendChild(button("Edit", () => fill(destination)));
      actions.appendChild(button("Delete", () => remove(destination.name)));
      row.appendChild(actions);
      body.appendChild(row);
    });
  }

  async function refresh() {
    const { ok, payload } = await api("/api/destinations");
    if (!ok) {
      status(payload.error || t("The backup service is not answering"));
      return;
    }
    render(payload.destinations || []);
  }

  async function save(event) {
    event.preventDefault();
    const body = {
      name: byId("dest-name").value.trim().toLowerCase(),
      type: "sftp",
      host: byId("dest-host").value.trim(),
      port: Number(byId("dest-port").value || 22),
      user: byId("dest-user").value.trim(),
      path: byId("dest-path").value.trim(),
      keep_daily: Number(byId("dest-keep-daily").value || 0),
      keep_weekly: Number(byId("dest-keep-weekly").value || 0),
      keep_monthly: Number(byId("dest-keep-monthly").value || 0)
    };
    const key = byId("dest-key").value.trim();
    if (key) body.private_key = key;
    const hostKey = byId("dest-host-key").value.trim();
    if (hostKey) body.host_key = hostKey;

    status(t("Saving…"));
    const { ok, payload } = await api("/api/destinations", body);
    if (ok) {
      status(t("Saved"));
      byId("dest-key").value = "";
      byId("dest-host-key").value = "";
      refresh();
    } else {
      status(payload.error || payload.description || t("It was not saved"));
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    const form = byId("backup-destination-form");
    if (!form) return;
    form.addEventListener("submit", save);
    refresh();
  });
})();
