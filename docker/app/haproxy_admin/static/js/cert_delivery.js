/* Certificate delivery: the machines that hold the same certificate.
 *
 * Nothing secret comes back from the daemon -- not the private key, not the
 * host key, not the PKCS#12 password. The page only ever learns whether each
 * is set, which is why editing a target leaves the key fields empty and
 * saving with them empty keeps what is already stored.
 */
(function () {
  "use strict";

  const t = window.t || ((value) => String(value));
  let targets = [];
  let available = [];

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

  function say(message, isError) {
    const host = byId("cd-result");
    if (!host) return;
    host.textContent = message || "";
    host.style.color = isError ? "#cc4b4b" : "";
  }

  function cell(row, text, verbatim) {
    const td = document.createElement("td");
    td.textContent = text;
    if (verbatim) {
      td.setAttribute("data-i18n-skip", "");
      td.setAttribute("translate", "no");
    }
    row.appendChild(td);
    return td;
  }

  function formatLabel(value) {
    if (value === "pem-pair") return uiText("PEM pair");
    if (value === "pem-combined") return uiText("PEM combined");
    return "PKCS#12";
  }

  function lastRun(target) {
    const last = target.last_result || {};
    if (!last.at) return uiText("never");
    const when = new Date(last.at * 1000).toLocaleString();
    return (last.ok ? uiText("delivered") : uiText("failed")) + " · " + when;
  }

  /* ---------- drawing ---------- */

  function render(payload) {
    targets = payload.targets || [];
    available = payload.available || [];

    const legacy = payload.legacy_hooks || [];
    const card = byId("cd-legacy-card");
    if (card) {
      card.hidden = legacy.length === 0;
      const list = byId("cd-legacy-list");
      if (list) list.textContent = legacy.join(", ");
    }

    const count = byId("cd-count");
    if (count) {
      count.textContent = `${targets.length} ${uiText("targets")}`;
    }

    const body = byId("cd-body");
    if (!body) return;
    body.textContent = "";

    if (!targets.length) {
      const row = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 6;
      td.className = "muted";
      td.textContent = uiText("No delivery targets yet");
      row.appendChild(td);
      body.appendChild(row);
    }

    targets.forEach((target) => {
      const row = document.createElement("tr");
      if (!target.enabled) row.style.opacity = ".55";
      cell(row, target.name, true);
      cell(row, (target.domains || []).join(", "), true);
      cell(row, `${target.user}@${target.host}:${target.port} → ${target.remote_path}`, true);
      cell(row, formatLabel(target.format) + " · " + String(target.transport).toUpperCase(), false);
      cell(row, lastRun(target), false);

      const actions = document.createElement("td");
      actions.appendChild(button(uiText("Edit"), () => edit(target)));
      actions.appendChild(button(uiText("Send now"), () => sendNow(target.name)));
      actions.appendChild(
        button(uiText("Delete"), () => remove(target.name), "btn-danger")
      );
      row.appendChild(actions);
      body.appendChild(row);
    });

    fillDomainChoices();
  }

  function button(label, onClick, extra) {
    const element = document.createElement("button");
    element.type = "button";
    element.className = "btn btn-small" + (extra ? ` ${extra}` : "");
    element.style.marginRight = "6px";
    element.textContent = label;
    element.addEventListener("click", onClick);
    return element;
  }

  function fillDomainChoices(selected) {
    const box = byId("cd-domains");
    if (!box) return;
    const chosen = new Set(selected || currentSelection());
    box.textContent = "";
    available.forEach((item) => {
      const option = document.createElement("option");
      option.value = item.name;
      option.textContent = item.expires
        ? `${item.name} — ${item.expires}`
        : item.name;
      option.selected = chosen.has(item.name);
      box.appendChild(option);
    });
    // A target may name a certificate that has since been removed. Keeping
    // it visible is the only way the operator finds out.
    chosen.forEach((name) => {
      if (available.some((item) => item.name === name)) return;
      const option = document.createElement("option");
      option.value = name;
      option.textContent = `${name} — ${uiText("no certificate issued")}`;
      option.selected = true;
      box.appendChild(option);
    });
  }

  function currentSelection() {
    const box = byId("cd-domains");
    if (!box) return [];
    return Array.from(box.selectedOptions || []).map((o) => o.value);
  }

  function showFieldsFor(format) {
    const pfx = format === "pfx";
    const pair = format === "pem-pair";
    const password = byId("cd-password-label");
    const help = byId("cd-password-help");
    if (password) password.hidden = !pfx;
    if (help) help.hidden = !pfx;
    const pathHelp = byId("cd-path-help");
    if (pathHelp) {
      pathHelp.textContent = pair
        ? uiText("The directory the two files go into. It must already exist.")
        : uiText("Where the file lands on the far side. A relative path is resolved wherever the account starts, which for a chrooted SFTP account is its own directory.");
    }
  }

  /* ---------- the form ---------- */

  function edit(target) {
    byId("cd-name").value = target.name;
    byId("cd-transport").value = target.transport || "sftp";
    byId("cd-format").value = target.format || "pfx";
    byId("cd-host").value = target.host || "";
    byId("cd-port").value = target.port || 22;
    byId("cd-user").value = target.user || "";
    byId("cd-path").value = target.remote_path || "";
    byId("cd-post").value = target.post_command || "";
    byId("cd-enabled").checked = target.enabled !== false;
    // Left empty on purpose: the daemon never returns them, and an empty
    // field means "keep what is stored".
    byId("cd-key").value = "";
    byId("cd-host-key").value = "";
    byId("cd-password").value = "";
    fillDomainChoices(target.domains || []);
    showFieldsFor(target.format || "pfx");

    const editing = byId("cd-editing");
    if (editing) {
      const missing = [];
      if (!target.key_present) missing.push(uiText("private key"));
      if (!target.host_key_present) missing.push(uiText("host key"));
      editing.textContent = missing.length
        ? `${uiText("editing")} ${target.name} — ${uiText("still needs")}: ${missing.join(", ")}`
        : `${uiText("editing")} ${target.name}`;
    }
    say("");
    window.scrollTo({ top: document.body.scrollHeight, behavior: "smooth" });
  }

  function clearForm() {
    const form = byId("cd-form");
    if (form) form.reset();
    fillDomainChoices([]);
    showFieldsFor(byId("cd-format").value);
    const editing = byId("cd-editing");
    if (editing) editing.textContent = "";
    say("");
  }

  async function post(path, payload) {
    const response = await fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": csrfToken()
      },
      body: JSON.stringify(payload)
    });
    const data = await response.json().catch(() => ({}));
    return { ok: response.ok && data.ok !== false, data };
  }

  async function save(event) {
    event.preventDefault();
    const domains = currentSelection();
    if (!domains.length) {
      say(uiText("Choose at least one certificate to send"), true);
      return;
    }
    const payload = {
      name: byId("cd-name").value.trim().toLowerCase(),
      enabled: byId("cd-enabled").checked,
      domains: domains,
      transport: byId("cd-transport").value,
      format: byId("cd-format").value,
      host: byId("cd-host").value.trim(),
      port: Number(byId("cd-port").value) || 22,
      user: byId("cd-user").value.trim(),
      remote_path: byId("cd-path").value.trim(),
      post_command: byId("cd-post").value.trim()
    };
    // Only send what was typed. An empty field must not wipe a stored secret.
    const key = byId("cd-key").value.trim();
    if (key) payload.private_key = key;
    const hostKey = byId("cd-host-key").value.trim();
    if (hostKey) payload.host_key = hostKey;
    const password = byId("cd-password").value;
    if (password !== "") payload.pfx_password = password.trim();

    say(uiText("Saving…"));
    const { ok, data } = await post("/api/haproxy/cert-delivery/save", payload);
    if (!ok) {
      say(data.error || uiText("Could not save"), true);
      return;
    }
    say(`${uiText("Saved")}: ${payload.name}`);
    await load();
  }

  async function remove(name) {
    if (!window.confirm(`${uiText("Remove the delivery target")} ${name}?`)) {
      return;
    }
    const { ok, data } = await post("/api/haproxy/cert-delivery/delete", { name });
    if (!ok) {
      say(data.error || uiText("Could not remove it"), true);
      return;
    }
    say(`${uiText("Removed")}: ${name}`);
    await load();
  }

  async function sendNow(name) {
    say(`${uiText("Sending to")} ${name}…`);
    const { ok, data } = await post("/api/haproxy/cert-delivery/test", { name });
    // The daemon's own output, which is the useful part when it fails.
    const detail = String(data.output || data.error || "").trim();
    if (!ok) {
      say(detail || uiText("Delivery failed"), true);
    } else {
      say(`${uiText("Delivered")}: ${name}${detail ? " · " + detail.split("\n").pop() : ""}`);
    }
    await load();
  }

  /* ---------- loading ---------- */

  async function load() {
    try {
      const response = await fetch("/api/haproxy/cert-delivery", {
        headers: { Accept: "application/json" },
        credentials: "same-origin"
      });
      const payload = await response.json().catch(() => ({}));
      const notice = byId("cd-unavailable");
      if (!response.ok) {
        if (notice) notice.hidden = false;
        return;
      }
      if (notice) notice.hidden = true;
      render(payload);
    } catch (error) {
      const notice = byId("cd-unavailable");
      if (notice) notice.hidden = false;
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    const form = byId("cd-form");
    if (form) form.addEventListener("submit", save);
    const clear = byId("cd-clear");
    if (clear) clear.addEventListener("click", clearForm);
    const format = byId("cd-format");
    if (format) {
      format.addEventListener("change", () => showFieldsFor(format.value));
      showFieldsFor(format.value);
    }
    load();
  });
})();
