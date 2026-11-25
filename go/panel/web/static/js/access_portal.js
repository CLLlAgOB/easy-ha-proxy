(function () {
  "use strict";
  const app = document.getElementById("portal-editor"); if (!app) return;
  const t = window.t || ((text) => text), byId = (id) => document.getElementById("portal-" + id);
  let snapshot, busy = false, dirty = false;
  function status(text, error = false) { byId("status").textContent = text; byId("status").className = error ? "text-danger" : "text-muted"; }
  async function api(url, options) {
    const response = await fetch(url, {credentials: "same-origin", ...options, headers: {Accept: "application/json", ...options?.headers}});
    const body = await response.json(); if (!response.ok || body.ok === false) throw new Error(body.error || t("Request failed"));
    return body.settings;
  }
  function controls() {
    app.querySelectorAll("input, textarea, select").forEach((input) => { input.disabled = busy || !snapshot; });
    byId("save").disabled = busy || !snapshot; byId("upload").disabled = busy || !snapshot;
    app.querySelectorAll("button[data-delete]").forEach((button) => { button.disabled = busy; });
  }
  function element(tag, text, className) { const node = document.createElement(tag); if (text !== undefined) node.textContent = text; if (className) node.className = className; return node; }
  function size(bytes) {
    const divisor = bytes < 1024 ? 1 : bytes < 1048576 ? 1024 : 1048576;
    const unit = divisor === 1 ? "B" : divisor === 1024 ? "KiB" : "MiB";
    return `${(bytes / divisor).toLocaleString(document.documentElement.lang, {maximumFractionDigits: 1})} ${unit}`;
  }
  function render(value) {
    snapshot = value; dirty = false; byId("text").value = value.text;
    byId("language").value = value.language || "auto";
    byId("files").replaceChildren();
    for (const file of value.files) {
      const card = element("div", undefined, "portal-file card"); card.dataset.id = file.id;
      card.append(element("p", `${file.filename} · ${size(file.size)}`, "text-muted"));
      for (const [field, title, limit] of [["title", "Download title", 160], ["description", "Description", 2000]]) {
        const label = element("label", t(title), "form-group"), input = document.createElement(field === "description" ? "textarea" : "input");
        input.value = file[field]; input.maxLength = limit; input.dataset.field = field; label.append(input); card.append(label);
      }
      const button = element("button", t("Delete attachment"), "btn btn-danger btn-small");
      button.type = "button"; button.dataset.delete = file.id;
      button.addEventListener("click", async () => {
        if (!window.confirm(t("Delete this attachment?"))) return;
        if (dirty) { status(t("Save page changes before changing attachments."), true); return; }
        busy = true; controls();
        try { render(await api(`${app.dataset.uploadUrl}/${file.id}/delete`, {method: "POST"})); status(t("Attachment deleted")); }
        catch (error) { status(error.message, true); } finally { busy = false; controls(); }
      }); card.append(button); byId("files").append(card);
    }
    controls();
  }
  byId("settings-form").addEventListener("input", () => { dirty = true; status(t("Changes have not been saved.")); });
  byId("settings-form").addEventListener("submit", async (event) => {
    event.preventDefault(); if (!snapshot || busy) return;
    busy = true; controls();
    const files = [...app.querySelectorAll(".portal-file")].map((card) => ({id: card.dataset.id,
      title: card.querySelector('[data-field="title"]').value, description: card.querySelector('[data-field="description"]').value}));
    try {
      const value = await api(app.dataset.settingsUrl, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({enabled: true, language: byId("language").value, text: byId("text").value, files, revision: snapshot.revision})});
      render(value); status(t(value.routing_changed ? "Page saved. Apply the HAProxy configuration to change routing." : "Saved"));
    }
    catch (error) { status(error.message, true); } finally { busy = false; controls(); }
  });
  byId("upload").addEventListener("change", async () => {
    if (dirty) { status(t("Save page changes before changing attachments."), true); byId("upload").value = ""; return; }
    const files = [...byId("upload").files]; if (!files.length || busy) return;
    if (snapshot.files.length + files.length > snapshot.max_files || files.some((file) => file.size > snapshot.max_file_bytes) ||
        snapshot.files.reduce((sum, file) => sum + file.size, 0) + files.reduce((sum, file) => sum + file.size, 0) > snapshot.max_total_bytes) {
      status(t("Attachment storage limit exceeded"), true); byId("upload").value = ""; return;
    }
    busy = true; controls();
    try {
      for (let index = 0; index < files.length; index++) {
        byId("upload-status").textContent = `${t("Uploading")}: ${index + 1}/${files.length} · ${files[index].name}`;
        render(await api(`${app.dataset.uploadUrl}?filename=${encodeURIComponent(files[index].name)}`, {method: "POST", headers: {"Content-Type": "application/octet-stream"}, body: files[index]}));
      }
      byId("upload-status").textContent = t("Attachments uploaded. Edit their titles and descriptions, then save the page.");
    } catch (error) { status(error.message, true); byId("upload-status").textContent = t("Upload interrupted. Files already listed were saved."); }
    finally { byId("upload").value = ""; busy = false; controls(); }
  });
  controls(); api(app.dataset.settingsUrl).then(render).catch((error) => status(error.message, true));
})();
