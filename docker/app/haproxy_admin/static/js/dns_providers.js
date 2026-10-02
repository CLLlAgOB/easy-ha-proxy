/* DNS provider profiles for DNS-01 issuance.
 *
 * A saved credential is never sent back by the server, so the fields always
 * start empty: entering one replaces it, leaving them blank changes nothing.
 */
(function () {
  "use strict";

  const t = window.t || ((value) => String(value));
  const dateTimeFormat = new Intl.DateTimeFormat(document.documentElement.lang || undefined, {
    dateStyle: "short",
    timeStyle: "short"
  });

  let providers = {};

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
    const notice = byId("dp-error");
    if (!notice) return;
    notice.textContent = message || "";
    notice.hidden = !message;
  }

  function formatTime(seconds) {
    const numeric = Number(seconds);
    if (!Number.isFinite(numeric) || numeric <= 0) return "—";
    return dateTimeFormat.format(new Date(numeric * 1000));
  }

  async function request(path, options) {
    const response = await fetch(path, options);
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || payload.ok === false) {
      throw new Error(payload.error || `HTTP ${response.status}`);
    }
    return payload;
  }

  function renderCredentialFields() {
    const host = byId("dp-credentials");
    const select = byId("dp-provider");
    if (!host || !select) return;
    host.textContent = "";
    const spec = providers[select.value];
    (spec ? spec.keys : []).forEach((key) => {
      const label = document.createElement("label");
      const caption = document.createElement("span");
      caption.setAttribute("data-i18n-skip", "");
      caption.setAttribute("translate", "no");
      caption.textContent = key;
      label.appendChild(caption);
      const input = document.createElement("input");
      // A saved value is never returned, so a password field with no value is
      // the honest representation.
      input.type = "password";
      input.autocomplete = "new-password";
      input.dataset.credential = key;
      input.placeholder = uiText("unchanged");
      label.appendChild(input);
      host.appendChild(label);
    });

    const note = byId("dp-plugin-note");
    if (note) {
      note.textContent = spec && !spec.available
        ? `${uiText("The certbot plugin for this provider is not installed.")} ` +
          `${uiText("Add it to dns_plugins_enabled and apply, or install")} ` +
          `${spec.snap}.`
        : "";
    }
  }

  function renderProfiles(profiles) {
    const host = byId("dp-list");
    const empty = byId("dp-empty");
    if (!host) return;
    host.textContent = "";
    if (!profiles || !profiles.length) {
      if (empty) empty.hidden = false;
      return;
    }
    if (empty) empty.hidden = true;

    profiles.forEach((profile) => {
      const row = document.createElement("div");
      row.className = "dp-profile";

      const name = document.createElement("div");
      name.className = "dp-name";
      name.textContent = profile.name;
      row.appendChild(name);

      const provider = document.createElement("div");
      provider.textContent = profile.provider || "—";
      row.appendChild(provider);

      const state = document.createElement("div");
      const pill = document.createElement("span");
      pill.className = `dp-state ${profile.plugin_available ? "dp-ready" : "dp-missing"}`;
      pill.textContent = profile.plugin_available
        ? uiText("plugin ready")
        : uiText("plugin missing");
      state.appendChild(pill);
      const when = document.createElement("small");
      when.textContent = ` ${formatTime(profile.updated_ts)}`;
      state.appendChild(when);
      row.appendChild(state);

      const actions = document.createElement("div");
      const remove = document.createElement("button");
      remove.className = "btn";
      remove.type = "button";
      remove.textContent = uiText("Delete");
      remove.addEventListener("click", () => deleteProfile(profile.name));
      actions.appendChild(remove);
      row.appendChild(actions);

      host.appendChild(row);
    });
  }

  async function load() {
    try {
      const payload = await request("/api/haproxy/dns-providers", {
        headers: { Accept: "application/json" },
        credentials: "same-origin"
      });
      providers = payload.providers || {};
      renderProfiles(payload.profiles);
      renderCredentialFields();
      showError("");
    } catch (error) {
      showError(String(error.message || error));
      renderProfiles([]);
    }
  }

  async function save() {
    const name = byId("dp-name");
    const provider = byId("dp-provider");
    const result = byId("dp-result");
    if (!name || !provider) return;
    const credentials = {};
    document.querySelectorAll("input[data-credential]").forEach((input) => {
      if (input.value) credentials[input.dataset.credential] = input.value;
    });
    try {
      await request("/api/haproxy/dns-providers/save", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": csrfToken()
        },
        body: JSON.stringify({
          name: name.value.trim().toLowerCase(),
          provider: provider.value,
          credentials
        })
      });
      if (result) result.textContent = uiText("Saved");
      name.value = "";
      document.querySelectorAll("input[data-credential]").forEach((input) => {
        input.value = "";
      });
      await load();
    } catch (error) {
      if (result) result.textContent = String(error.message || error);
    }
  }

  async function deleteProfile(name) {
    try {
      await request("/api/haproxy/dns-providers/delete", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": csrfToken()
        },
        body: JSON.stringify({ name })
      });
      await load();
    } catch (error) {
      showError(String(error.message || error));
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    const provider = byId("dp-provider");
    if (provider) provider.addEventListener("change", () => renderCredentialFields());
    const button = byId("dp-save");
    if (button) button.addEventListener("click", () => save());
    load();
  });
})();
