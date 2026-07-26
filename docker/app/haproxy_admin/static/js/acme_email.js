/* Let's Encrypt account email editor, shared by the Certificates and Mail pages. */
(function () {
  "use strict";

  const ENDPOINT = "/haproxy/certs/api/acme-email";
  const t = window.t || ((value) => String(value));
  let revision = "";
  let busy = false;

  function byId(id) { return document.getElementById(id); }

  function setResult(message, ok) {
    const element = byId("acme-email-result");
    if (!element) return;
    element.textContent = message || "";
    element.classList.toggle("success", Boolean(message) && ok === true);
    element.classList.toggle("error", Boolean(message) && ok === false);
  }

  async function requestJson(url, options) {
    const response = await fetch(url, options || {});
    let payload;
    try { payload = await response.json(); }
    catch (_error) { throw new Error(`${t("Unexpected server response")} (${response.status})`); }
    if (!response.ok || payload.ok === false) {
      const problem = new Error(payload.error || payload.message || `${t("Request failed")} (${response.status})`);
      problem.payload = payload;
      throw problem;
    }
    return payload;
  }

  async function load() {
    try {
      const payload = await requestJson(ENDPOINT);
      revision = payload.revision || "";
      byId("acme-email-input").value = payload.email || "";
    } catch (error) {
      setResult(`${t("Failed to load the Let's Encrypt email")}: ${t(error.message)}`, false);
    }
  }

  async function save(event) {
    event.preventDefault();
    if (busy) return;
    busy = true;
    byId("acme-email-save").disabled = true;
    setResult(t("Saving…"));
    try {
      const payload = await requestJson(ENDPOINT, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
          email: byId("acme-email-input").value.trim(),
          revision
        })
      });
      revision = payload.revision || revision;
      if (payload.email !== undefined) byId("acme-email-input").value = payload.email;
      setResult(t(payload.message || "Saved."), true);
    } catch (error) {
      if (error.payload?.conflict) {
        setResult(t("Settings changed in another session. Reloading the current value…"), false);
        load();
      } else {
        setResult(t(error.message), false);
      }
    } finally {
      busy = false;
      byId("acme-email-save").disabled = false;
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    const form = byId("acme-email-form");
    if (!form) return;
    form.addEventListener("submit", save);
    load();
  });
})();
