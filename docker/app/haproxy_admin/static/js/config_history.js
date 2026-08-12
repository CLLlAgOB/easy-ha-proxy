/* Configuration history: which versions exist, and what changed between them.
 *
 * Read-only. Versions are created by confirming a configuration change; this
 * page has no control that writes one.
 */
(function () {
  "use strict";

  const t = window.t || ((value) => String(value));
  const dateTimeFormat = new Intl.DateTimeFormat(document.documentElement.lang || undefined, {
    dateStyle: "short",
    timeStyle: "medium"
  });

  const CURRENT = "current";
  let versions = [];
  let selected = "";

  function byId(id) {
    return document.getElementById(id);
  }

  function uiText(value) {
    return t(value);
  }

  function formatTime(seconds) {
    const numeric = Number(seconds);
    if (!Number.isFinite(numeric) || numeric <= 0) return "—";
    return dateTimeFormat.format(new Date(numeric * 1000));
  }

  async function getJson(path, params) {
    const query = new URLSearchParams(params || {});
    const response = await fetch(`${path}?${query.toString()}`, {
      headers: { Accept: "application/json" },
      credentials: "same-origin"
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || payload.ok === false) {
      throw new Error(payload.error || `HTTP ${response.status}`);
    }
    return payload;
  }

  function label(version) {
    return `${formatTime(version.ts)} · ${String(version.generation || "").slice(0, 8)}`;
  }

  function fillSelects() {
    [
      ["ch-left", CURRENT],
      ["ch-right", CURRENT]
    ].forEach(([id, fallback]) => {
      const select = byId(id);
      if (!select) return;
      const previous = select.value;
      select.textContent = "";
      const now = document.createElement("option");
      now.value = CURRENT;
      now.textContent = uiText("Applied now");
      select.appendChild(now);
      versions.forEach((version) => {
        const option = document.createElement("option");
        option.value = version.id;
        option.textContent = label(version);
        select.appendChild(option);
      });
      select.value = previous || fallback;
    });
  }

  function renderVersions() {
    const host = byId("ch-list");
    const empty = byId("ch-list-empty");
    if (!host) return;
    host.textContent = "";
    if (!versions.length) {
      if (empty) empty.hidden = false;
      return;
    }
    if (empty) empty.hidden = true;

    versions.forEach((version) => {
      const entry = document.createElement("div");
      entry.className = "ch-version";
      entry.setAttribute("role", "button");
      entry.setAttribute("aria-selected", version.id === selected ? "true" : "false");

      const when = document.createElement("b");
      when.textContent = formatTime(version.ts);
      entry.appendChild(when);

      const detail = document.createElement("small");
      detail.textContent = String(version.generation || "").slice(0, 12);
      entry.appendChild(detail);

      entry.addEventListener("click", () => {
        selected = version.id;
        const left = byId("ch-left");
        // Comparing a version with what is applied now is the question people
        // actually have; picking one from the list sets that up.
        if (left) left.value = version.id;
        const right = byId("ch-right");
        if (right) right.value = CURRENT;
        renderVersions();
        loadDiff();
      });

      host.appendChild(entry);
    });

    const count = byId("ch-count");
    if (count) count.textContent = String(versions.length);
  }

  function renderDiff(payload) {
    const host = byId("ch-diff");
    const empty = byId("ch-diff-empty");
    if (!host) return;
    host.textContent = "";
    const changes = (payload && payload.changes) || [];
    if (!changes.length) {
      if (empty) {
        empty.hidden = false;
        empty.textContent = payload
          ? uiText("These two versions are identical")
          : uiText("Select a version to see what changed");
      }
      return;
    }
    if (empty) empty.hidden = true;

    changes.forEach((change) => {
      const entry = document.createElement("div");
      entry.className = "ch-change";

      const kind = document.createElement("span");
      kind.className = "ch-kind";
      kind.textContent = uiText(change.kind);
      entry.appendChild(kind);

      const name = document.createElement("span");
      name.setAttribute("data-i18n-skip", "");
      name.setAttribute("translate", "no");
      name.textContent = change.name || "";
      entry.appendChild(name);

      const state = document.createElement("span");
      state.className = `ch-${change.change}`;
      state.textContent = ` ${uiText(change.change)}`;
      entry.appendChild(state);

      if (change.fields && change.fields.length) {
        const fields = document.createElement("div");
        fields.className = "ch-fields";
        fields.setAttribute("data-i18n-skip", "");
        fields.setAttribute("translate", "no");
        change.fields.forEach((line) => {
          const item = document.createElement("div");
          item.textContent = line;
          fields.appendChild(item);
        });
        entry.appendChild(fields);
      }

      host.appendChild(entry);
    });
  }

  function csrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute("content") || "" : "";
  }

  function showRestore(versionId) {
    const block = byId("ch-restore");
    // Restoring means "make this the running configuration", which only makes
    // sense when the comparison is against what is running now.
    const right = byId("ch-right");
    const offered = Boolean(versionId) && versionId !== CURRENT
      && (!right || right.value === CURRENT);
    if (block) block.hidden = !offered;
    const confirm = byId("ch-confirm");
    if (confirm && !offered) confirm.hidden = true;
  }

  function askRestore() {
    const left = byId("ch-left");
    const confirm = byId("ch-confirm");
    const text = byId("ch-confirm-text");
    if (!left || !confirm || !text) return;
    const version = versions.find((item) => item.id === left.value);
    text.textContent =
      `${uiText("Replace the running configuration with the version from")} ` +
      `${version ? formatTime(version.ts) : left.value}?`;
    confirm.hidden = false;
  }

  async function commitRestore() {
    const left = byId("ch-left");
    const confirm = byId("ch-confirm");
    const result = byId("ch-restore-result");
    if (confirm) confirm.hidden = true;
    if (!left || !left.value || left.value === CURRENT) return;
    const button = byId("ch-restore-start");
    if (button) button.disabled = true;
    try {
      const response = await fetch("/api/haproxy/config/versions/restore", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": csrfToken()
        },
        body: JSON.stringify({ version: left.value })
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok || payload.ok === false) {
        if (result) result.textContent = payload.error || `HTTP ${response.status}`;
        return;
      }
      if (result) {
        result.textContent = uiText(
          "Applied and awaiting confirmation — confirm it on the HAProxy configuration page before the deadline."
        );
      }
    } catch (error) {
      if (result) result.textContent = String(error.message || error);
    } finally {
      if (button) button.disabled = false;
      await load();
    }
  }

  async function loadDiff() {
    const left = byId("ch-left");
    const right = byId("ch-right");
    if (!left || !left.value) return;
    try {
      const payload = await getJson("/api/haproxy/config/versions/diff", {
        left: left.value,
        right: right ? right.value : CURRENT
      });
      renderDiff(payload);
      showRestore(left.value);
    } catch (error) {
      const empty = byId("ch-diff-empty");
      if (empty) {
        empty.hidden = false;
        empty.textContent = String(error.message || error);
      }
      const host = byId("ch-diff");
      if (host) host.textContent = "";
    }
  }

  async function load() {
    try {
      const payload = await getJson("/api/haproxy/config/versions", { limit: 50 });
      versions = payload.versions || [];
      renderVersions();
      fillSelects();
      if (versions.length) {
        selected = versions[0].id;
        const left = byId("ch-left");
        if (left) left.value = selected;
        renderVersions();
        await loadDiff();
      }
    } catch (error) {
      const empty = byId("ch-list-empty");
      if (empty) {
        empty.hidden = false;
        empty.textContent = String(error.message || error);
      }
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    ["ch-left", "ch-right"].forEach((id) => {
      const element = byId(id);
      if (element) element.addEventListener("change", () => loadDiff());
    });
    const start = byId("ch-restore-start");
    if (start) start.addEventListener("click", () => askRestore());
    const yes = byId("ch-confirm-yes");
    if (yes) yes.addEventListener("click", () => commitRestore());
    const no = byId("ch-confirm-no");
    if (no) {
      no.addEventListener("click", () => {
        const confirm = byId("ch-confirm");
        if (confirm) confirm.hidden = true;
      });
    }
    load();
  });
})();
