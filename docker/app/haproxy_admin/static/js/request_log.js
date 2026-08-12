/* Log Explorer: find one request again.
 *
 * Read-only. Everything shown here came out of the access log after the
 * engine's own normalization, so there is nothing to redact on this side --
 * the query string was dropped before it was stored.
 */
(function () {
  "use strict";

  const t = window.t || ((value) => String(value));
  const dateTimeFormat = new Intl.DateTimeFormat(document.documentElement.lang || undefined, {
    dateStyle: "short",
    timeStyle: "medium"
  });

  const PAGE_SIZE = 100;
  let offset = 0;
  let total = 0;

  function byId(id) {
    return document.getElementById(id);
  }

  function formatTime(seconds) {
    const numeric = Number(seconds);
    if (!Number.isFinite(numeric) || numeric <= 0) return "—";
    return dateTimeFormat.format(new Date(numeric * 1000));
  }

  function statusClass(status) {
    const numeric = Number(status) || 0;
    if (numeric >= 500) return "rq-5xx";
    if (numeric >= 400) return "rq-4xx";
    if (numeric >= 300) return "rq-3xx";
    if (numeric >= 200) return "rq-2xx";
    return "rq-4xx";
  }

  function filters() {
    const params = new URLSearchParams();
    const range = Number(byId("rq-range").value || 0);
    if (range > 0) {
      params.set("since", String(Math.floor(Date.now() / 1000) - range));
    }
    [
      ["rq-status", "status"],
      ["rq-client", "client"],
      ["rq-host", "host"],
      ["rq-backend", "backend"],
      ["rq-path", "path"],
      ["rq-request-id", "request_id"]
    ].forEach(([id, name]) => {
      const element = byId(id);
      if (element && element.value.trim()) params.set(name, element.value.trim());
    });
    return params;
  }

  async function getJson(path, params) {
    const query = new URLSearchParams(params || {});
    const response = await fetch(`${path}?${query.toString()}`, {
      headers: { Accept: "application/json" },
      credentials: "same-origin"
    });
    const payload = await response.json().catch(() => ({}));
    return { status: response.status, payload };
  }

  function cell(row, value, className) {
    const td = document.createElement("td");
    if (value instanceof Node) td.appendChild(value);
    else td.textContent = value == null || value === "" ? "—" : String(value);
    if (className) td.className = className;
    row.appendChild(td);
    return td;
  }

  function render(rows, append) {
    const body = byId("rq-body");
    if (!body) return;
    if (!append) body.textContent = "";
    rows.forEach((entry) => {
      const tr = document.createElement("tr");
      cell(tr, formatTime(entry.ts));

      const badge = document.createElement("span");
      badge.className = `rq-status ${statusClass(entry.status)}`;
      badge.textContent = entry.bad_request ? t("bad request") : String(entry.status);
      cell(tr, badge);

      cell(tr, entry.method);
      cell(tr, entry.host);
      cell(tr, entry.path, "rq-path");
      cell(
        tr,
        entry.server ? `${entry.backend} / ${entry.server}` : entry.backend
      );
      cell(tr, entry.client);
      cell(tr, entry.duration_ms ? `${entry.duration_ms} ms` : "—");
      cell(tr, entry.request_id, "rq-path");
      body.appendChild(tr);
    });
    const empty = byId("rq-empty");
    if (empty) empty.hidden = body.children.length > 0;
    const more = byId("rq-more");
    if (more) more.hidden = body.children.length >= total;
  }

  function setNotice(id, visible) {
    const element = byId(id);
    if (element) element.hidden = !visible;
  }

  async function search(append) {
    if (!append) offset = 0;
    const params = filters();
    params.set("limit", String(PAGE_SIZE));
    params.set("offset", String(offset));

    const { status, payload } = await getJson("/api/security/requests", params);
    if (status === 404 || payload.enabled === false) {
      // The daemon answers this when the store is switched off, which is a
      // different thing from the daemon being unreachable.
      setNotice("rq-disabled", true);
      setNotice("rq-unavailable", false);
      render([], false);
      return;
    }
    if (status >= 500 || payload.unavailable) {
      setNotice("rq-unavailable", true);
      setNotice("rq-disabled", false);
      return;
    }
    setNotice("rq-disabled", false);
    setNotice("rq-unavailable", false);

    total = Number(payload.total || 0);
    render(payload.requests || [], append);
    offset += (payload.requests || []).length;
  }

  async function refreshStore() {
    const { status, payload } = await getJson("/api/security/requests/status", {});
    const element = byId("rq-store");
    if (!element) return;
    if (status !== 200) {
      element.textContent = "";
      return;
    }
    const megabytes = Math.round((payload.database_bytes || 0) / 1048576);
    const cap = Math.round((payload.max_bytes || 0) / 1048576);
    const parts = [
      `${payload.rows || 0} ${t("records")}`,
      `${megabytes} / ${cap} MiB`,
      `${payload.retention_days || 0} ${t("days")}`
    ];
    if (payload.paused) parts.push(t("paused"));
    element.textContent = parts.join(" · ");
  }

  function wire() {
    const run = () => {
      search(false);
      refreshStore();
    };
    const button = byId("rq-search");
    if (button) button.addEventListener("click", run);
    const reset = byId("rq-reset");
    if (reset) {
      reset.addEventListener("click", () => {
        ["rq-status", "rq-client", "rq-host", "rq-backend", "rq-path", "rq-request-id"]
          .forEach((id) => {
            const element = byId(id);
            if (element) element.value = "";
          });
        run();
      });
    }
    const more = byId("rq-more");
    if (more) more.addEventListener("click", () => search(true));
    const range = byId("rq-range");
    if (range) range.addEventListener("change", run);
    document.querySelectorAll(".rq-filters input").forEach((input) => {
      input.addEventListener("keydown", (event) => {
        if (event.key === "Enter") run();
      });
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    wire();
    search(false);
    refreshStore();
  });
})();
