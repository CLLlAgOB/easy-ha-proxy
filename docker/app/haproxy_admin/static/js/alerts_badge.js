/* The open alerts in every page's header.
 *
 * Asks the panel once a minute, and at once when a page says it changed
 * something. A single failed answer is not shown -- the alert service
 * restarts with every update -- two in a row are.
 */
(function () {
  "use strict";

  const POLL_INTERVAL_MS = 60000;
  const MIN_REFRESH_GAP_MS = 3000;
  const CHANGE_EVENT = "easy-ha-proxy:alerts-changed";
  const LABEL_CHARS = 64;
  let failures = 0;
  let timer = null;
  let running = false;
  let lastRefreshAt = 0;

  function t(value, params) {
    return typeof window.t === "function" ? window.t(value, params) : String(value);
  }

  function short(text) {
    const value = String(text || "");
    return value.length > LABEL_CHARS ? `${value.slice(0, LABEL_CHARS - 1)}…` : value;
  }

  function schedule() {
    if (timer !== null) window.clearTimeout(timer);
    timer = window.setTimeout(refresh, POLL_INTERVAL_MS);
  }

  function render(badge, payload) {
    const label = document.getElementById("global-alerts-label");
    const items = (payload && payload.items) || [];
    const total = Number(payload && payload.total) || 0;
    badge.hidden = total === 0;
    if (!total) return;
    badge.dataset.level = Number(payload.critical) > 0 ? "critical" : "warning";
    // One alert says what it is; several say how many.
    const text = total === 1
      ? short(items[0] && (items[0].summary || items[0].title))
      : t("Alerts: {count}", { count: total });
    if (label) label.textContent = text;
    badge.title = items.slice(0, 5).map((item) => `• ${item.summary || item.title}`).join("\n");
  }

  function renderSilent(badge) {
    const label = document.getElementById("global-alerts-label");
    badge.hidden = false;
    badge.dataset.level = "unknown";
    badge.title = "";
    if (label) label.textContent = t("The alert service is not answering");
  }

  async function refresh() {
    const badge = document.getElementById("global-alerts");
    if (!badge || running) return;
    running = true;
    lastRefreshAt = Date.now();
    try {
      const response = await fetch(badge.dataset.endpoint, {
        headers: { Accept: "application/json" },
        credentials: "same-origin"
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok || payload.ok === false) throw new Error(`HTTP ${response.status}`);
      failures = 0;
      render(badge, payload);
    } catch (error) {
      failures += 1;
      if (failures >= 2) renderSilent(badge);
    } finally {
      running = false;
      schedule();
    }
  }

  function refreshIfStale() {
    if (Date.now() - lastRefreshAt < MIN_REFRESH_GAP_MS) return;
    refresh();
  }

  document.addEventListener("DOMContentLoaded", () => {
    if (!document.getElementById("global-alerts")) return;
    refresh();
    window.addEventListener(CHANGE_EVENT, refresh);
    document.addEventListener("visibilitychange", () => {
      if (!document.hidden) refreshIfStale();
    });
  });
})();
