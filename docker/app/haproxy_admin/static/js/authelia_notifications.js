/* Latest-only local Authelia notification fallback. */
(function () {
  "use strict";

  const ENDPOINT = "/authelia/settings/notifications/latest";
  const REVEAL_TTL_MS = 60 * 1000;
  const t = window.t || ((value) => String(value));
  const elements = {};
  let current = null;
  let revealedText = "";
  let revealTimer = null;
  let revealController = null;
  let revealGeneration = 0;
  let requestRunning = false;
  let filesystemActive = false;

  function byId(id) {
    return document.getElementById(id);
  }

  function setResult(message, state) {
    if (!elements.result) return;
    elements.result.textContent = message || "";
    elements.result.classList.toggle("success", Boolean(message) && state === true);
    elements.result.classList.toggle("error", Boolean(message) && state === false);
    elements.result.classList.toggle("warning", Boolean(message) && state === "warning");
  }

  function setStatus(message, state) {
    if (!elements.status) return;
    elements.status.textContent = message;
    elements.status.className = "config-status-pill";
    elements.status.classList.add(
      state === "success"
        ? "config-status-pill--success"
        : state === "warning"
          ? "config-status-pill--warning"
          : "config-status-pill--neutral"
    );
  }

  function setBusy(value) {
    requestRunning = Boolean(value);
    [elements.refresh, elements.reveal, elements.handled].forEach((button) => {
      if (!button) return;
      const alreadyHandled = button === elements.handled && Boolean(current?.handled);
      button.disabled = requestRunning || alreadyHandled || !current && button !== elements.refresh;
      button.classList.toggle("loading", requestRunning);
      button.setAttribute("aria-busy", requestRunning ? "true" : "false");
    });
  }

  async function requestJson(url, options) {
    const response = await fetch(url, options || {});
    let payload;
    try {
      payload = await response.json();
    } catch (_error) {
      throw new Error(`${t("Unexpected server response")} (${response.status})`);
    }
    if (!response.ok || payload.ok === false) {
      const problem = new Error(
        payload.error || payload.message || `${t("Request failed")} (${response.status})`
      );
      problem.status = response.status;
      problem.payload = payload;
      throw problem;
    }
    return payload;
  }

  function clearReveal(showMessage) {
    revealGeneration += 1;
    if (revealController) {
      revealController.abort();
      revealController = null;
    }
    if (revealTimer !== null) {
      window.clearTimeout(revealTimer);
      revealTimer = null;
    }
    revealedText = "";
    if (elements.content) elements.content.textContent = "";
    if (elements.preview) elements.preview.hidden = true;
    if (showMessage) {
      setResult(t("Plaintext preview was hidden automatically."), "warning");
    }
  }

  function displayTime(value) {
    const date = new Date(String(value || ""));
    if (Number.isNaN(date.getTime())) return "—";
    return new Intl.DateTimeFormat(undefined, {
      dateStyle: "medium",
      timeStyle: "medium"
    }).format(date);
  }

  function displaySize(value) {
    const bytes = Number(value);
    if (!Number.isFinite(bytes) || bytes < 0) return "—";
    if (bytes < 1024) return `${bytes} B`;
    return `${(bytes / 1024).toFixed(1)} KiB`;
  }

  function renderLatest(payload) {
    clearReveal(false);
    const latest = payload?.latest;
    current = latest && typeof latest === "object" ? latest : null;
    if (elements.empty) elements.empty.hidden = Boolean(current);
    if (elements.metadata) elements.metadata.hidden = !current;
    if (!current) {
      setStatus(t("No pending notification"), "neutral");
      setBusy(false);
      return;
    }

    elements.received.textContent = displayTime(current.received_at);
    elements.recipient.textContent = current.recipient_masked || "—";
    elements.size.textContent = displaySize(current.size);
    elements.itemStatus.textContent = current.handled ? t("Handled") : t("Pending");
    setStatus(
      current.handled ? t("Handled") : t("Action required"),
      current.handled ? "success" : "warning"
    );
    setBusy(false);
  }

  async function loadLatest(force) {
    if (!filesystemActive || (requestRunning && force !== true)) return;
    setBusy(true);
    setResult(t("Loading local notification metadata…"));
    try {
      const payload = await requestJson(ENDPOINT);
      if (payload.mode !== "filesystem") {
        filesystemActive = false;
        elements.card.hidden = true;
        clearReveal(false);
        return;
      }
      renderLatest(payload);
      setResult("");
    } catch (error) {
      current = null;
      clearReveal(false);
      if (elements.empty) elements.empty.hidden = true;
      if (elements.metadata) elements.metadata.hidden = true;
      setStatus(t("Status unavailable"), "warning");
      setResult(`${t("Failed to load local notification")}: ${t(error.message)}`, false);
    } finally {
      setBusy(false);
    }
  }

  async function revealLatest() {
    if (!current || requestRunning) return;
    clearReveal(false);
    const generation = revealGeneration;
    const controller = new AbortController();
    revealController = controller;
    setBusy(true);
    setResult(t("Revealing the current notification…"));
    try {
      const payload = await requestJson(`${ENDPOINT}/reveal`, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({id: current.id, revision: current.revision}),
        signal: controller.signal
      });
      if (
        generation !== revealGeneration
        || document.visibilityState === "hidden"
      ) return;
      if (typeof payload.content !== "string") {
        throw new Error(t("Unexpected server response"));
      }
      revealController = null;
      revealedText = payload.content;
      elements.content.textContent = revealedText;
      elements.preview.hidden = false;
      revealTimer = window.setTimeout(() => clearReveal(true), REVEAL_TTL_MS);
      setResult(t("Plaintext revealed. It will be hidden after 60 seconds."), "warning");
    } catch (error) {
      if (error.name === "AbortError" || generation !== revealGeneration) return;
      clearReveal(false);
      if (error.status === 409 && error.payload?.conflict) {
        await loadLatest(true);
        setResult(t("The notification changed. Metadata has been refreshed."), "warning");
      } else if (error.status === 429 && error.payload?.rate_limited) {
        setResult(t("Please wait before revealing the notification again."), false);
      } else {
        setResult(`${t("Failed to reveal local notification")}: ${t(error.message)}`, false);
      }
    } finally {
      if (revealController === controller) revealController = null;
      setBusy(false);
    }
  }

  async function copyFullNotification() {
    if (!revealedText) return;
    try {
      await navigator.clipboard.writeText(revealedText);
      setResult(t("Full notification copied to the clipboard."), true);
    } catch (_error) {
      setResult(t("Clipboard access failed. Select the plaintext manually."), false);
    }
  }

  async function markHandled() {
    if (!current || current.handled || requestRunning) return;
    setBusy(true);
    setResult(t("Marking the notification handled…"));
    try {
      await requestJson(`${ENDPOINT}/handled`, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
          id: current.id,
          revision: current.revision
        })
      });
      clearReveal(false);
      await loadLatest(true);
      setResult(t("Notification marked handled."), true);
    } catch (error) {
      clearReveal(false);
      if (error.status === 409 && error.payload?.conflict) {
        await loadLatest(true);
        setResult(t("The notification changed. Metadata has been refreshed."), "warning");
      } else {
        setResult(`${t("Failed to update notification status")}: ${t(error.message)}`, false);
      }
    } finally {
      setBusy(false);
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    const ids = {
      card: "authelia-notification-card",
      status: "authelia-notification-status",
      result: "authelia-notification-result",
      refresh: "authelia-notification-refresh",
      empty: "authelia-notification-empty",
      metadata: "authelia-notification-metadata",
      received: "authelia-notification-received",
      recipient: "authelia-notification-recipient",
      size: "authelia-notification-size",
      itemStatus: "authelia-notification-item-status",
      reveal: "authelia-notification-reveal",
      handled: "authelia-notification-handled",
      preview: "authelia-notification-preview",
      content: "authelia-notification-content",
      copy: "authelia-notification-copy",
      hide: "authelia-notification-hide"
    };
    Object.entries(ids).forEach(([key, id]) => { elements[key] = byId(id); });
    if (!elements.card) return;

    elements.refresh?.addEventListener("click", () => loadLatest());
    elements.reveal?.addEventListener("click", revealLatest);
    elements.copy?.addEventListener("click", copyFullNotification);
    elements.hide?.addEventListener("click", () => clearReveal(false));
    elements.handled?.addEventListener("click", markHandled);

    document.addEventListener("authelia-mail-mode-applied", (event) => {
      filesystemActive = event.detail?.mode === "filesystem";
      elements.card.hidden = !filesystemActive;
      current = null;
      clearReveal(false);
      if (filesystemActive) loadLatest();
    });
    window.addEventListener("pagehide", () => clearReveal(false));
    document.addEventListener("visibilitychange", () => {
      if (document.visibilityState === "hidden") clearReveal(false);
    });
  });
})();
