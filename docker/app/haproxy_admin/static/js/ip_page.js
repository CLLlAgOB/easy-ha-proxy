/* IP page: ban, unban, or drop from the allow list and ban -- whichever of
 * the three will actually work for this address. The server decides which
 * button is shown; this only sends the request and reloads the state. */
(function () {
  "use strict";

  const t = window.t || ((value) => String(value));

  function csrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute("content") || "" : "";
  }

  async function postBan(ip, dropAllowlist) {
    const response = await fetch("/api/monitoring/live/ban", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken() },
      body: JSON.stringify({ ip: ip, drop_allowlist: dropAllowlist }),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || !payload.ok) {
      window.alert(t(payload.error || "The ban was not placed"));
      return false;
    }
    return true;
  }

  async function postUnban(ip) {
    const response = await fetch("/api/unban", {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-CSRFToken": csrfToken(),
      },
      body: `ip=${encodeURIComponent(ip)}`,
    });
    if (!response.ok) {
      window.alert(await response.text());
      return false;
    }
    return true;
  }

  document.addEventListener("DOMContentLoaded", () => {
    const box = document.getElementById("ipp-status");
    if (!box) return;
    const ip = box.dataset.ip;
    box.addEventListener("click", async (event) => {
      const button = event.target.closest("[data-ipp-action]");
      if (!button) return;
      const action = button.dataset.ippAction;
      let done = false;
      if (action === "ban") {
        if (!window.confirm(`${t("Ban address")} ${ip}?`)) return;
        done = await postBan(ip, false);
      } else if (action === "drop-ban") {
        if (!window.confirm(`${t("Remove from the allow list and ban")} ${ip}?`)) return;
        done = await postBan(ip, true);
      } else if (action === "unban") {
        if (!window.confirm(`${t("Unban")} ${ip}?`)) return;
        done = await postUnban(ip);
      }
      if (done) window.location.reload();
    });
  });
})();
