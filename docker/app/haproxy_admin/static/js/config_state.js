/* Server-authoritative HAProxy saved/apply status shared by superadmin pages. */
(function () {
  "use strict";

  const POLL_INTERVAL_MS = 20000;
  // Load, focus and visibilitychange all fire around a navigation, so the
  // status was fetched several times in a row; on a high-latency link each of
  // those is a full round-trip that competes with the page's own requests.
  const MIN_REFRESH_GAP_MS = 3000;
  const CHANGE_EVENT = "easy-ha-proxy:config-state-changed";
  let requestRunning = false;
  let refreshQueued = false;
  let pollTimer = null;
  let lastRefreshAt = 0;

  // Passive triggers settle for a recent result; an explicit change still
  // refreshes immediately.
  function refreshStateIfStale() {
    if (Date.now() - lastRefreshAt < MIN_REFRESH_GAP_MS) return;
    refreshState();
  }

  function t(value, params) {
    return typeof window.t === "function" ? window.t(value, params) : String(value);
  }

  function scheduleRefresh() {
    if (pollTimer !== null) window.clearTimeout(pollTimer);
    pollTimer = window.setTimeout(refreshState, POLL_INTERVAL_MS);
  }

  function renderState(indicator, payload) {
    const label = document.getElementById("global-config-state-label");
    if (!label) return;

    const state = String(payload && payload.state || "unknown");
    const total = Number(payload && payload.changes && payload.changes.total || 0);
    let text;

    if (state === "clean") {
      indicator.hidden = true;
      indicator.dataset.state = state;
      return;
    }
    if (state === "unapplied") {
      text = total > 0
        ? t("Unapplied HAProxy changes ({count})", {count: total})
        : t("Unapplied HAProxy changes");
    } else if (state === "runtime_drift") {
      text = t("HAProxy configuration differs from the server");
    } else if (state === "pending_confirmation") {
      text = t("HAProxy configuration confirmation pending");
    } else if (state === "rollback_failed") {
      text = t("HAProxy configuration rollback requires attention");
    } else {
      text = t("Configuration status unavailable");
    }

    label.textContent = text;
    indicator.dataset.state = state;
    indicator.title = `${text}. ${t("Open HAProxy configuration")}`;
    indicator.hidden = false;
  }

  async function refreshState() {
    const indicator = document.getElementById("global-config-state");
    if (!indicator) return;
    if (requestRunning) {
      refreshQueued = true;
      return;
    }
    if (document.hidden) {
      scheduleRefresh();
      return;
    }

    requestRunning = true;
    try {
      const response = await fetch(indicator.dataset.stateEndpoint, {
        method: "GET",
        credentials: "same-origin",
        cache: "no-store",
        headers: {Accept: "application/json"}
      });
      const payload = await response.json();
      renderState(
        indicator,
        response.ok && payload && payload.ok !== false
          ? payload
          : {state: "unknown"}
      );
    } catch (_error) {
      renderState(indicator, {state: "unknown"});
    } finally {
      requestRunning = false;
      lastRefreshAt = Date.now();
      if (refreshQueued) {
        refreshQueued = false;
        window.setTimeout(refreshState, 0);
      } else {
        scheduleRefresh();
      }
    }
  }

  document.addEventListener("DOMContentLoaded", refreshState);
  document.addEventListener("visibilitychange", function () {
    if (!document.hidden) refreshStateIfStale();
  });
  window.addEventListener("focus", refreshStateIfStale);
  document.addEventListener(CHANGE_EVENT, refreshState);
})();
