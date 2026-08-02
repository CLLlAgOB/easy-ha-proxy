// Guided vars.yml editing and transactional HAProxy configuration apply.
(function () {
  "use strict";

  const VALIDATION_RESULT_STORAGE_KEY = "easy-ha-proxy.haproxy-config.validation-result.v1";
  const APPLY_RESULT_STORAGE_KEY = "easy-ha-proxy.haproxy-config.apply-result.v1";
  const APPLY_RESULT_MAX_AGE_MS = 24 * 60 * 60 * 1000;
  const PENDING_TRANSACTION_STORAGE_KEY = "easy-ha-proxy.haproxy-config.pending-transaction.v1";
  const TRANSACTION_POLL_INTERVAL_MS = 1000;

  let pendingTransaction = null;
  let transactionPollTimer = null;
  let transactionPollGeneration = 0;
  let transactionActionInFlight = false;
  let transactionActionNotice = "";
  let modalPreviousFocus = null;
  let initialGuidedValues = "";
  let initialRawYaml = "";

  function uiText(value, params) {
    const source = String(value == null ? "" : value);
    return typeof window.t === "function" ? window.t(source, params) : source;
  }

  function setStatus(element, ok, text) {
    if (!element) return;
    element.textContent = text || "";
    element.classList.remove("success", "error");
    if (!text) {
      element.style.display = "none";
      return;
    }
    element.style.display = "inline-block";
    element.classList.add(ok ? "success" : "error");
  }

  function setButtonLoading(button, loading) {
    if (!button) return;
    button.disabled = !!loading;
    button.classList.toggle("loading", !!loading);
    button.setAttribute("aria-busy", loading ? "true" : "false");
  }

  function storageGet(key) {
    try {
      return window.sessionStorage.getItem(key);
    } catch (_error) {
      return null;
    }
  }

  function storageSet(key, value) {
    try {
      window.sessionStorage.setItem(key, value);
    } catch (error) {
      console.warn("Could not preserve HAProxy configuration state:", error);
    }
  }

  function storageRemove(key) {
    try {
      window.sessionStorage.removeItem(key);
    } catch (error) {
      console.warn("Could not clear HAProxy configuration state:", error);
    }
  }

  async function requestJson(url, options) {
    const response = await fetch(url, options || {});
    const raw = await response.text();
    let data;
    try {
      data = raw ? JSON.parse(raw) : {};
    } catch (_error) {
      const problem = new Error(
        uiText("Response is not JSON ({status}): {body}", {
          status: response.status,
          body: raw.slice(0, 200),
        })
      );
      problem.response = response;
      problem.raw = raw;
      throw problem;
    }
    return { response, data };
  }

  function applyResultMessage(data) {
    const safety = data && data.safety && typeof data.safety === "object"
      ? data.safety
      : null;
    const state = String((data && (data.status || data.state)) || "").toLowerCase();

    if (data && data.ok && ["confirmed", "committed", "applied", "success"].includes(state)) {
      return uiText("Configuration confirmed and kept successfully.");
    }
    if (data && data.ok) {
      return uiText("Configuration applied successfully. Critical service checks passed.");
    }
    if (state === "cancelled") {
      return uiText("Apply cancelled. The active configuration was not changed.");
    }
    if (state === "rollback_failed") {
      return uiText("Automatic rollback failed. Use the server console to inspect and restore HAProxy immediately.");
    }
    if (state === "failed") {
      return uiText("The configuration transaction failed. Check the technical details before trying again.");
    }
    if (state === "expired") {
      return uiText("Confirmation time expired. The previous configuration was restored automatically.");
    }
    if (safety && safety.rolled_back && safety.rollback_ok) {
      return uiText("Configuration was not kept. The previous configuration was restored successfully.");
    }
    if (safety && safety.rolled_back) {
      return uiText("Configuration was not kept. Automatic rollback could not be verified.");
    }
    return uiText("Apply failed: {error}", {
      error: (data && data.error) || uiText("Unknown error"),
    });
  }

  function resultWarnings(data) {
    if (!data || typeof data !== "object") return [];
    const source = data.warnings != null ? data.warnings : data.warning;
    const values = Array.isArray(source) ? source : (source == null ? [] : [source]);
    return values.map((item) => {
      if (item && typeof item === "object") return item.message || item.warning || JSON.stringify(item);
      return String(item || "");
    }).filter(Boolean);
  }

  function renderApplyWarnings(data) {
    const container = document.getElementById("apply-warnings");
    if (!container) return;
    container.replaceChildren();
    const warnings = resultWarnings(data);
    if (!warnings.length) {
      container.style.display = "none";
      return;
    }
    const title = document.createElement("strong");
    title.textContent = uiText("Warnings:");
    const list = document.createElement("ul");
    warnings.forEach((warning) => {
      const item = document.createElement("li");
      item.textContent = uiText(warning);
      list.appendChild(item);
    });
    container.append(title, list);
    container.style.display = "block";
  }

  function renderApplyResult(data, completedAt) {
    const statusElement = document.getElementById("apply-status");
    const timeElement = document.getElementById("apply-result-time");
    const stdoutElement = document.getElementById("apply-stdout");
    const stderrElement = document.getElementById("apply-stderr");
    const ok = !!(data && data.ok);

    setStatus(statusElement, ok, applyResultMessage(data || {}));
    renderApplyWarnings(data || {});
    if (stdoutElement) stdoutElement.textContent = (data && data.stdout) || "";
    if (stderrElement) stderrElement.textContent = (data && data.stderr) || "";

    if (!timeElement) return;
    const parsed = completedAt ? new Date(completedAt) : null;
    if (parsed && !Number.isNaN(parsed.getTime())) {
      const formatted = new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "medium",
      }).format(parsed);
      timeElement.textContent = uiText("Completed: {time}", { time: formatted });
      timeElement.style.display = "block";
    } else {
      timeElement.textContent = "";
      timeElement.style.display = "none";
    }
  }

  function clearDisplayedApplyResult() {
    setStatus(document.getElementById("apply-status"), true, "");
    renderApplyWarnings({});
    const timeElement = document.getElementById("apply-result-time");
    const stdoutElement = document.getElementById("apply-stdout");
    const stderrElement = document.getElementById("apply-stderr");
    if (timeElement) {
      timeElement.textContent = "";
      timeElement.style.display = "none";
    }
    if (stdoutElement) stdoutElement.textContent = "";
    if (stderrElement) stderrElement.textContent = "";
  }

  function persistApplyResult(data, completedAt) {
    storageSet(APPLY_RESULT_STORAGE_KEY, JSON.stringify({ completedAt, data }));
  }

  function clearPersistedApplyResult() {
    storageRemove(APPLY_RESULT_STORAGE_KEY);
  }

  function restoreApplyResult() {
    const raw = storageGet(APPLY_RESULT_STORAGE_KEY);
    if (!raw) return;
    try {
      const saved = JSON.parse(raw);
      const completedAt = new Date(saved.completedAt || "");
      if (
        !saved.data
        || Number.isNaN(completedAt.getTime())
        || Date.now() - completedAt.getTime() > APPLY_RESULT_MAX_AGE_MS
      ) {
        clearPersistedApplyResult();
        return;
      }
      renderApplyResult(saved.data, saved.completedAt);
    } catch (error) {
      clearPersistedApplyResult();
      console.warn("Could not restore the HAProxy apply result:", error);
    }
  }

  function validationResultMessage(data) {
    if (data && data.ok) {
      return uiText("Configuration is valid (rc={rc})", {
        rc: data.rc == null ? 0 : data.rc,
      });
    }
    if (data && data.request_error) {
      return uiText("Request error: {error}", {
        error: data.error || uiText("Unknown error"),
      });
    }
    if (data && data.unsaved_settings && data.error) {
      return uiText(data.error);
    }
    return uiText("Configuration validation failed (rc={rc})", {
      rc: data && data.rc != null ? data.rc : "—",
    });
  }

  function renderResultTime(elementId, completedAt) {
    const timeElement = document.getElementById(elementId);
    if (!timeElement) return;
    const parsed = completedAt ? new Date(completedAt) : null;
    if (parsed && !Number.isNaN(parsed.getTime())) {
      const formatted = new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "medium",
      }).format(parsed);
      timeElement.textContent = uiText("Completed: {time}", { time: formatted });
      timeElement.style.display = "block";
      return;
    }
    timeElement.textContent = "";
    timeElement.style.display = "none";
  }

  function renderValidationResult(data, completedAt) {
    const result = data || {};
    setStatus(
      document.getElementById("check-status"),
      !!result.ok,
      validationResultMessage(result)
    );
    const stdoutElement = document.getElementById("check-stdout");
    const stderrElement = document.getElementById("check-stderr");
    if (stdoutElement) stdoutElement.textContent = result.stdout || "";
    if (stderrElement) stderrElement.textContent = result.stderr || result.error || "";
    renderResultTime("check-result-time", completedAt);
  }

  function persistValidationResult(data, completedAt) {
    storageSet(VALIDATION_RESULT_STORAGE_KEY, JSON.stringify({ completedAt, data }));
  }

  function restoreValidationResult() {
    const raw = storageGet(VALIDATION_RESULT_STORAGE_KEY);
    if (!raw) return;
    try {
      const saved = JSON.parse(raw);
      const completedAt = new Date(saved.completedAt || "");
      if (
        !saved.data
        || Number.isNaN(completedAt.getTime())
        || Date.now() - completedAt.getTime() > APPLY_RESULT_MAX_AGE_MS
      ) {
        storageRemove(VALIDATION_RESULT_STORAGE_KEY);
        return;
      }
      renderValidationResult(saved.data, saved.completedAt);
    } catch (error) {
      storageRemove(VALIDATION_RESULT_STORAGE_KEY);
      console.warn("Could not restore the HAProxy validation result:", error);
    }
  }

  function currentRevision() {
    const form = document.getElementById("vars-guided-form");
    const editor = document.getElementById("vars-yaml-editor");
    return (form && form.dataset.revision) || (editor && editor.dataset.revision) || "";
  }

  function updateRevision(data) {
    const revision = data && (data.revision || data.vars_revision);
    if (!revision) return;
    const form = document.getElementById("vars-guided-form");
    const editor = document.getElementById("vars-yaml-editor");
    if (form) form.dataset.revision = revision;
    if (editor) editor.dataset.revision = revision;
  }

  function fieldValue(field) {
    const type = String(field.dataset.fieldType || "text").toLowerCase();
    if (type === "boolean" || type === "bool") return !!field.checked;
    if (["integer", "int"].includes(type)) {
      return field.value.trim() === "" ? null : Number.parseInt(field.value, 10);
    }
    if (["number", "float"].includes(type)) {
      return field.value.trim() === "" ? null : Number(field.value);
    }
    return field.value;
  }

  function updateSwitchState(field) {
    const type = String(field.dataset.fieldType || "").toLowerCase();
    if (type !== "boolean" && type !== "bool") return;

    const wrapper = field.closest(".vars-field");
    const label = wrapper && wrapper.querySelector("[data-switch-label]");
    if (label) label.textContent = uiText(field.checked ? "Enabled" : "Disabled");

    if (field.dataset.fieldPath === "admin_authelia_enabled") {
      const inheritedNote = wrapper && wrapper.querySelector("[data-authelia-inherited-note]");
      const effectiveWarning = wrapper && wrapper.querySelector("[data-authelia-effective-warning]");
      if (inheritedNote) inheritedNote.hidden = field.dataset.touched === "true";
      if (effectiveWarning) effectiveWarning.hidden = !field.checked;
    }
  }

  function adminIpEntries() {
    const field = document.querySelector('[data-field-path="admin_allowed_ips"]');
    if (!field) return [];
    return String(field.value || "")
      .split(/[\n,]+/)
      .map((value) => value.trim())
      .filter(Boolean);
  }

  function updateAdminIpAccessState() {
    const toggle = document.querySelector('[data-field-path="admin_ips_enabled"]');
    const count = adminIpEntries().length;
    const countElement = document.querySelector("[data-admin-ip-count]");
    const listWarning = document.querySelector("[data-admin-ip-warning-list]");
    const emptyWarning = document.querySelector("[data-admin-ip-warning-empty]");
    if (countElement) countElement.textContent = String(count);
    if (listWarning) listWarning.hidden = !toggle || !toggle.checked || count === 0;
    if (emptyWarning) emptyWarning.hidden = !toggle || !toggle.checked || count !== 0;
  }

  function addCurrentAdminIp(button) {
    const field = document.querySelector('[data-field-path="admin_allowed_ips"]');
    const currentIp = String(button.dataset.currentIp || "").trim();
    if (!field || !currentIp) return;
    const entries = adminIpEntries();
    if (!entries.includes(currentIp)) entries.push(currentIp);
    field.value = entries.join("\n");
    field.dispatchEvent(new Event("input", { bubbles: true }));
    field.focus();
  }

  function collectGuidedValues() {
    const values = {};
    document.querySelectorAll("[data-vars-field]").forEach((field) => {
      if (field.dataset.readonly === "true") return;
      if (field.dataset.fieldPresent !== "true" && field.dataset.touched !== "true") return;
      values[field.dataset.fieldPath] = fieldValue(field);
    });
    return values;
  }

  function guidedSnapshot() {
    return JSON.stringify(collectGuidedValues());
  }

  function guidedHasUnsavedChanges() {
    return guidedSnapshot() !== initialGuidedValues;
  }

  function rawHasUnsavedChanges() {
    const editor = document.getElementById("vars-yaml-editor");
    return !!editor && editor.value !== initialRawYaml;
  }

  function updateGuidedDirtyState() {
    const button = document.getElementById("btn-save-vars");
    const notice = document.getElementById("vars-unsaved-notice");
    const dirty = guidedHasUnsavedChanges();
    if (notice) notice.hidden = !dirty;
    if (!button || button.getAttribute("aria-busy") === "true") return;
    button.disabled = !dirty;
  }

  function updateRawDirtyState() {
    const editor = document.getElementById("vars-yaml-editor");
    const button = document.getElementById("btn-save-vars-raw");
    if (!editor || !button || button.getAttribute("aria-busy") === "true") return;
    button.disabled = editor.value === initialRawYaml;
  }

  function clearFieldErrors() {
    document.querySelectorAll("[data-field-error]").forEach((element) => {
      element.textContent = "";
    });
    document.querySelectorAll(".vars-field--invalid").forEach((element) => {
      element.classList.remove("vars-field--invalid");
    });
  }

  function showFieldErrors(data) {
    clearFieldErrors();
    const errors = data && (data.field_errors || data.errors);
    if (!errors || Array.isArray(errors) || typeof errors !== "object") return;
    Object.entries(errors).forEach(([path, message]) => {
      const errorElement = Array.from(document.querySelectorAll("[data-field-error]"))
        .find((element) => element.dataset.fieldError === path);
      if (!errorElement) return;
      errorElement.textContent = uiText(String(message));
      const fieldWrapper = errorElement.closest(".vars-field");
      if (fieldWrapper) fieldWrapper.classList.add("vars-field--invalid");
    });
  }

  function updateRawYaml(data) {
    const yaml = data && (data.vars_yaml || data.content || data.yaml);
    const editor = document.getElementById("vars-yaml-editor");
    if (typeof yaml !== "string" || !editor) return;
    editor.value = yaml;
    initialRawYaml = yaml;
    updateRawDirtyState();
  }

  function invalidateRenderedPreview() {
    const container = document.getElementById("cfg-preview-container");
    const diff = document.getElementById("cfg-diff");
    const button = document.getElementById("btn-preview");
    if (container) container.hidden = true;
    if (diff) diff.textContent = "";
    if (button) {
      button.setAttribute("aria-expanded", "false");
      const label = button.querySelector(".icon");
      if (label) label.textContent = uiText("Show preview");
    }
  }

  function updateStatusPill(element, text, modifier) {
    if (!element) return;
    element.hidden = false;
    element.textContent = uiText(text);
    element.classList.remove(
      "config-status-pill--success",
      "config-status-pill--warning",
      "config-status-pill--neutral"
    );
    element.classList.add(`config-status-pill--${modifier}`);
  }

  function appendSummaryValues(list, label, values) {
    if (!Array.isArray(values) || !values.length) return;
    const item = document.createElement("li");
    item.append(`${uiText(label)} `);
    const value = document.createElement("span");
    value.className = "mono notranslate";
    value.setAttribute("translate", "no");
    value.dataset.i18nSkip = "";
    value.textContent = values.join(", ");
    item.append(value);
    list.append(item);
  }

  function appendChangedEntries(list, label, entries) {
    if (!entries || Array.isArray(entries) || typeof entries !== "object") return;
    const names = Object.keys(entries);
    if (!names.length) return;
    const item = document.createElement("li");
    item.append(uiText(label));
    const nested = document.createElement("ul");
    names.sort().forEach((name) => {
      const row = document.createElement("li");
      const nameElement = document.createElement("span");
      nameElement.className = "mono notranslate";
      nameElement.setAttribute("translate", "no");
      nameElement.dataset.i18nSkip = "";
      nameElement.textContent = name;
      const keysElement = document.createElement("span");
      keysElement.className = "mono notranslate";
      keysElement.setAttribute("translate", "no");
      keysElement.dataset.i18nSkip = "";
      const changedKeys = entries[name] && entries[name].changed_keys;
      keysElement.textContent = Array.isArray(changedKeys) ? changedKeys.join(", ") : "";
      row.append(nameElement, ": ", keysElement);
      nested.append(row);
    });
    item.append(nested);
    list.append(item);
  }

  function renderConfigurationSummary(summary) {
    if (!summary || typeof summary !== "object") return;
    const serverStatus = document.getElementById("config-server-status");
    const pendingStatus = document.getElementById("config-pending-status");
    updateStatusPill(
      serverStatus,
      summary.server_differs ? "Server configuration differs" : "Server configuration is current",
      summary.server_differs ? "warning" : "success"
    );
    if (!summary.has_applied_state) {
      updateStatusPill(pendingStatus, "No apply history", "neutral");
    } else if (summary.source_has_changes) {
      updateStatusPill(pendingStatus, "Unapplied changes", "warning");
    } else {
      updateStatusPill(pendingStatus, "No pending changes", "neutral");
    }

    const details = document.getElementById("config-change-details");
    const list = document.getElementById("config-change-list");
    if (!details || !list) return;
    const showDetails = !!(summary.has_applied_state && summary.source_has_changes);
    details.hidden = !showDetails;
    list.replaceChildren();
    if (!showDetails) return;
    appendSummaryValues(list, "Added sites:", summary.sites_added);
    appendSummaryValues(list, "Removed sites:", summary.sites_removed);
    appendChangedEntries(list, "Changed sites:", summary.sites_changed);
    appendSummaryValues(list, "Added TCP proxies:", summary.tcp_added);
    appendSummaryValues(list, "Removed TCP proxies:", summary.tcp_removed);
    appendChangedEntries(list, "Changed TCP proxies:", summary.tcp_changed);
    appendSummaryValues(list, "Changed global settings:", summary.global_changed_keys);
  }

  function notifyConfigStateChanged() {
    document.dispatchEvent(new CustomEvent("easy-ha-proxy:config-state-changed"));
  }

  async function refreshConfigurationSummary() {
    try {
      const { response, data } = await requestJson("/haproxy/config/diff", {
        method: "GET",
        cache: "no-store",
      });
      if (response.ok && data.ok && data.diff_summary) {
        renderConfigurationSummary(data.diff_summary);
      }
    } catch (error) {
      console.warn("Could not refresh HAProxy configuration status:", error);
    }
  }

  async function saveGuidedVars(event) {
    if (event) event.preventDefault();
    const button = document.getElementById("btn-save-vars");
    const statusElement = document.getElementById("vars-status");
    clearFieldErrors();
    setStatus(statusElement, true, uiText("Saving settings…"));
    setButtonLoading(button, true);

    try {
      const { response, data } = await requestJson("/haproxy/config/vars", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          revision: currentRevision(),
          values: collectGuidedValues(),
        }),
      });
      if (!response.ok || !data.ok) {
        showFieldErrors(data);
        setStatus(statusElement, false, uiText(data.error || "Failed to save settings"));
        return null;
      }

      updateRevision(data);
      updateRawYaml(data);
      initialGuidedValues = guidedSnapshot();
      setStatus(
        statusElement,
        true,
        uiText(data.message || "Settings saved. Validate and apply the pending configuration when ready.")
      );
      invalidateRenderedPreview();
      notifyConfigStateChanged();
      await refreshConfigurationSummary();
      return data;
    } catch (error) {
      setStatus(statusElement, false, uiText("Request error: {error}", { error: error.message || error }));
      return null;
    } finally {
      setButtonLoading(button, false);
      updateGuidedDirtyState();
    }
  }

  async function savePendingGuidedSettingsBeforeValidation() {
    const guidedDirty = guidedHasUnsavedChanges();
    const rawDirty = rawHasUnsavedChanges();
    if (!guidedDirty && !rawDirty) return { ok: true };

    if (rawDirty) {
      const message = uiText(
        "The advanced YAML editor has unsaved changes. Save or discard them before validation or apply."
      );
      setStatus(document.getElementById("vars-raw-status"), false, message);
      const editor = document.getElementById("vars-yaml-editor");
      const advanced = document.getElementById("vars-advanced");
      if (advanced) advanced.open = true;
      if (editor) {
        editor.scrollIntoView({ behavior: "smooth", block: "center" });
        editor.focus();
      }
      return { ok: false, error: message };
    }

    const approved = window.confirm(uiText(
      "There are unsaved global settings. Save them and continue with validation?"
    ));
    if (!approved) {
      const message = uiText(
        "Validation and apply were cancelled because settings are still unsaved."
      );
      setStatus(document.getElementById("vars-status"), false, message);
      const saveButton = document.getElementById("btn-save-vars");
      if (saveButton) {
        saveButton.scrollIntoView({ behavior: "smooth", block: "center" });
        saveButton.focus();
      }
      return { ok: false, error: message, cancelled: true };
    }

    const saved = await saveGuidedVars(null);
    if (!saved || !saved.ok) {
      return {
        ok: false,
        error: uiText(
          "Unable to save the pending settings. Validation and apply were not started."
        ),
      };
    }
    return { ok: true, saved: true };
  }

  async function saveRawVars() {
    const editor = document.getElementById("vars-yaml-editor");
    const button = document.getElementById("btn-save-vars-raw");
    const statusElement = document.getElementById("vars-raw-status");
    if (!editor) return;
    setStatus(statusElement, true, uiText("Saving raw YAML…"));
    setButtonLoading(button, true);

    try {
      const { response, data } = await requestJson("/haproxy/config/vars/raw", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ revision: currentRevision(), content: editor.value }),
      });
      if (!response.ok || !data.ok) {
        setStatus(statusElement, false, uiText(data.error || "Failed to save raw YAML"));
        return;
      }
      updateRevision(data);
      updateRawYaml(data);
      initialRawYaml = editor.value;
      setStatus(
        statusElement,
        true,
        uiText(data.message || "Raw vars.yml saved. Reload this page to refresh the guided fields.")
      );
      invalidateRenderedPreview();
      notifyConfigStateChanged();
      await refreshConfigurationSummary();
      window.setTimeout(() => window.location.reload(), 700);
    } catch (error) {
      setStatus(statusElement, false, uiText("Request error: {error}", { error: error.message || error }));
    } finally {
      setButtonLoading(button, false);
      updateRawDirtyState();
    }
  }

  async function refreshPreview() {
    const container = document.getElementById("cfg-preview-container");
    const diffElement = document.getElementById("cfg-diff");
    const button = document.getElementById("btn-preview");
    if (!container || !diffElement || !button) return;

    if (!container.hidden) {
      container.hidden = true;
      button.setAttribute("aria-expanded", "false");
      const label = button.querySelector(".icon");
      if (label) label.textContent = uiText("Show preview");
      return;
    }

    setButtonLoading(button, true);
    try {
      const { response, data } = await requestJson("/haproxy/config/diff", {
        method: "GET",
        cache: "no-store",
      });
      if (!response.ok || !data.ok) {
        diffElement.textContent = data.error || uiText("Failed to load diff");
      } else if (typeof data.html_diff === "string") {
        diffElement.innerHTML = data.html_diff;
      } else {
        diffElement.textContent = data.rendered_cfg || "";
      }
      container.hidden = false;
      button.setAttribute("aria-expanded", "true");
      const label = button.querySelector(".icon");
      if (label) label.textContent = uiText("Hide preview");
    } catch (error) {
      diffElement.textContent = uiText("Diff request failed: {error}", { error: error.message || error });
      container.hidden = false;
      button.setAttribute("aria-expanded", "true");
    } finally {
      setButtonLoading(button, false);
    }
  }

  async function checkConfig(options) {
    const settings = options && typeof options === "object" ? options : {};
    const statusElement = document.getElementById("check-status");
    const button = settings.button || document.getElementById("btn-check");
    const manageLoading = settings.manageLoading !== false;
    const applyButton = document.getElementById("btn-apply");
    const pendingSettings = await savePendingGuidedSettingsBeforeValidation();
    if (!pendingSettings.ok) {
      const result = {
        ok: false,
        unsaved_settings: true,
        cancelled: pendingSettings.cancelled === true,
        error: pendingSettings.error,
      };
      const completedAt = new Date().toISOString();
      renderValidationResult(result, completedAt);
      persistValidationResult(result, completedAt);
      return result;
    }
    setStatus(statusElement, true, uiText("Starting validation…"));
    if (manageLoading) {
      setButtonLoading(button, true);
      if (applyButton && applyButton !== button) applyButton.disabled = true;
    }

    try {
      const { response, data } = await requestJson("/haproxy/config/check", { method: "POST" });
      const ok = response.ok && !!data.ok;
      const result = Object.assign({}, data || {}, { ok });
      const completedAt = new Date().toISOString();
      renderValidationResult(result, completedAt);
      persistValidationResult(result, completedAt);
      return result;
    } catch (error) {
      const result = {
        ok: false,
        request_error: true,
        error: error.message || String(error),
      };
      const completedAt = new Date().toISOString();
      renderValidationResult(result, completedAt);
      persistValidationResult(result, completedAt);
      return result;
    } finally {
      if (manageLoading) {
        setButtonLoading(button, false);
        if (applyButton && applyButton !== button && !pendingTransaction) applyButton.disabled = false;
      }
    }
  }

  async function revertConfig() {
    const statusElement = document.getElementById("apply-status");
    const button = document.getElementById("btn-revert");
    if (!button || pendingTransaction) return;
    if (!window.confirm(uiText("Discard all unapplied changes and restore the last applied settings?"))) return;

    clearDisplayedApplyResult();
    clearPersistedApplyResult();
    setStatus(statusElement, true, uiText("Reverting changes…"));
    setButtonLoading(button, true);
    try {
      const { response, data } = await requestJson("/haproxy/config/revert", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      if (!response.ok || !data.ok) {
        setStatus(statusElement, false, uiText(data.error || "Failed to revert changes"));
        return;
      }
      setStatus(statusElement, true, uiText(data.message || "Changes reverted; YAML files restored."));
      notifyConfigStateChanged();
      await refreshConfigurationSummary();
      window.setTimeout(() => window.location.reload(), 700);
    } catch (error) {
      setStatus(statusElement, false, uiText("Request error: {error}", { error: error.message || error }));
    } finally {
      setButtonLoading(button, false);
    }
  }

  function transactionState(data) {
    if (!data || typeof data !== "object") return "";
    if (typeof data.pending_confirmation === "string") return data.pending_confirmation.toLowerCase();
    if (data.pending_confirmation === true) return "pending_confirmation";
    return String(data.status || data.state || data.result || "").toLowerCase();
  }

  function pendingPayload(data) {
    const nested = data && typeof data.pending_confirmation === "object"
      ? data.pending_confirmation
      : {};
    const combined = Object.assign({}, data || {}, nested);
    const transactionId = combined.transaction_id;
    const candidateSha256 = combined.candidate_sha256;
    if (!transactionId || !candidateSha256) return null;
    return {
      transaction_id: String(transactionId),
      candidate_sha256: String(candidateSha256),
      confirm_by: combined.confirm_by || "",
      remaining_seconds: combined.remaining_seconds,
      candidate_reachable: combined.candidate_reachable === true,
    };
  }

  function isPendingState(state) {
    return ["pending", "pending_confirmation", "awaiting_confirmation"].includes(state);
  }

  function isConfirmedState(state) {
    return ["confirmed", "committed", "applied", "success", "kept"].includes(state);
  }

  function isRolledBackState(state) {
    return ["rolled_back", "rollback", "expired", "auto_rolled_back", "reverted"].includes(state);
  }

  function isFailedState(state) {
    // A generic daemon/protocol error is not authoritative: the transaction
    // may still be pending or may already have rolled back. Keep polling until
    // the persisted server state reports a terminal outcome.
    return ["rollback_failed", "failed"].includes(state);
  }

  function renderServerCountdown(value) {
    const countdown = document.getElementById("apply-confirm-countdown");
    if (!countdown) return;
    const seconds = Number(value);
    countdown.textContent = Number.isFinite(seconds)
      ? uiText("{seconds} s", { seconds: Math.max(0, Math.ceil(seconds)) })
      : "—";
  }

  function waitingForCandidateMessage() {
    return uiText("Waiting for a fresh connection through the candidate HAProxy configuration…");
  }

  function updateConfirmationAvailability() {
    const confirmButton = document.getElementById("btn-confirm-apply");
    const reachable = !!(pendingTransaction && pendingTransaction.candidate_reachable);
    if (confirmButton && !transactionActionInFlight) {
      confirmButton.disabled = !reachable;
    }
    return reachable;
  }

  function persistPendingTransaction() {
    if (!pendingTransaction) return;
    storageSet(PENDING_TRANSACTION_STORAGE_KEY, JSON.stringify(pendingTransaction));
  }

  function clearPendingTransaction() {
    pendingTransaction = null;
    transactionActionNotice = "";
    storageRemove(PENDING_TRANSACTION_STORAGE_KEY);
    pauseTransactionPolling();
  }

  function pauseTransactionPolling() {
    transactionPollGeneration += 1;
    if (transactionPollTimer !== null) {
      window.clearTimeout(transactionPollTimer);
      transactionPollTimer = null;
    }
  }

  function showConfirmationModal() {
    const modal = document.getElementById("apply-confirm-modal");
    const panel = modal && modal.querySelector(".config-modal-panel");
    const confirmButton = document.getElementById("btn-confirm-apply");
    const rollbackButton = document.getElementById("btn-rollback-pending");
    const applyButton = document.getElementById("btn-apply");
    const checkButton = document.getElementById("btn-check");
    const revertButton = document.getElementById("btn-revert");
    if (!modal) return;
    if (!transactionActionInFlight) {
      setButtonLoading(confirmButton, false);
      setButtonLoading(rollbackButton, false);
    }
    const candidateReachable = updateConfirmationAvailability();
    modalPreviousFocus = document.activeElement;
    modal.hidden = false;
    document.body.classList.add("config-modal-open");
    if (applyButton) applyButton.disabled = true;
    if (checkButton) checkButton.disabled = true;
    if (revertButton) revertButton.disabled = true;
    renderServerCountdown(pendingTransaction && pendingTransaction.remaining_seconds);
    if (!candidateReachable) {
      setStatus(
        document.getElementById("apply-confirm-status"),
        true,
        waitingForCandidateMessage()
      );
    }
    window.setTimeout(
      () => ((confirmButton && !confirmButton.disabled ? confirmButton : rollbackButton) || panel).focus(),
      0
    );
  }

  function hideConfirmationModal() {
    const modal = document.getElementById("apply-confirm-modal");
    const applyButton = document.getElementById("btn-apply");
    const checkButton = document.getElementById("btn-check");
    const revertButton = document.getElementById("btn-revert");
    const confirmButton = document.getElementById("btn-confirm-apply");
    const rollbackButton = document.getElementById("btn-rollback-pending");
    if (modal) modal.hidden = true;
    document.body.classList.remove("config-modal-open");
    if (applyButton) setButtonLoading(applyButton, false);
    if (checkButton) checkButton.disabled = false;
    if (revertButton) revertButton.disabled = false;
    setButtonLoading(confirmButton, false);
    setButtonLoading(rollbackButton, false);
    if (modalPreviousFocus && typeof modalPreviousFocus.focus === "function") {
      modalPreviousFocus.focus();
    }
    modalPreviousFocus = null;
  }

  function finishTransaction(kind, responseData) {
    const state = transactionState(responseData);
    clearPendingTransaction();
    hideConfirmationModal();
    setStatus(document.getElementById("apply-confirm-status"), true, "");

    const completedAt = new Date().toISOString();
    let data;
    if (kind === "confirmed") {
      data = Object.assign({}, responseData || {}, {
        ok: true,
        status: isConfirmedState(state) ? state : "confirmed",
      });
    } else {
      data = Object.assign({}, responseData || {}, {
        ok: false,
        status: state || "rolled_back",
        safety: Object.assign({}, (responseData && responseData.safety) || {}, {
          rolled_back: true,
          rollback_ok: !responseData || responseData.rollback_ok !== false,
        }),
      });
    }
    renderApplyResult(data, completedAt);
    persistApplyResult(data, completedAt);
    notifyConfigStateChanged();
    void refreshConfigurationSummary();
  }

  function failTransaction(data) {
    const state = transactionState(data) || "failed";
    clearPendingTransaction();
    hideConfirmationModal();
    setStatus(document.getElementById("apply-confirm-status"), true, "");
    const result = Object.assign({}, data || {}, {
      ok: false,
      status: state,
      error: (data && data.error) || (
        state === "rollback_failed"
          ? uiText("Automatic rollback failed; immediate server-side recovery is required.")
          : uiText("Configuration transaction failed.")
      ),
      safety: Object.assign({}, (data && data.safety) || {}, {
        rolled_back: false,
        rollback_ok: false,
      }),
    });
    const completedAt = new Date().toISOString();
    renderApplyResult(result, completedAt);
    persistApplyResult(result, completedAt);
    notifyConfigStateChanged();
    void refreshConfigurationSummary();
  }

  function acceptPendingTransaction(data) {
    const payload = pendingPayload(data);
    if (!payload) {
      const failed = Object.assign({}, data || {}, {
        ok: false,
        error: (data && data.error) || uiText("Apply response did not contain a valid confirmation transaction."),
      });
      const completedAt = new Date().toISOString();
      renderApplyResult(failed, completedAt);
      persistApplyResult(failed, completedAt);
      notifyConfigStateChanged();
      void refreshConfigurationSummary();
      return false;
    }
    pendingTransaction = payload;
    persistPendingTransaction();
    clearPersistedApplyResult();
    setStatus(
      document.getElementById("apply-status"),
      true,
      uiText("Candidate configuration is active and awaiting confirmation.")
    );
    showConfirmationModal();
    scheduleTransactionPoll(0);
    notifyConfigStateChanged();
    void refreshConfigurationSummary();
    return true;
  }

  function updatePendingFromServer(data) {
    if (!pendingTransaction) return;
    const updated = pendingPayload(Object.assign({}, pendingTransaction, data || {}));
    if (updated) pendingTransaction = updated;
    if (data && data.remaining_seconds != null) {
      pendingTransaction.remaining_seconds = data.remaining_seconds;
    }
    if (data && data.confirm_by) pendingTransaction.confirm_by = data.confirm_by;
    persistPendingTransaction();
    renderServerCountdown(pendingTransaction.remaining_seconds);
    updateConfirmationAvailability();
  }

  function scheduleTransactionPoll(delay) {
    if (!pendingTransaction || transactionActionInFlight) return;
    pauseTransactionPolling();
    transactionPollTimer = window.setTimeout(pollTransactionStatus, delay);
  }

  async function pollTransactionStatus() {
    if (!pendingTransaction || transactionActionInFlight) return;
    transactionPollTimer = null;
    const pollGeneration = transactionPollGeneration;
    const transactionId = pendingTransaction.transaction_id;
    const statusElement = document.getElementById("apply-confirm-status");
    const url = "/haproxy/config/apply-status?transaction_id="
      + encodeURIComponent(transactionId);
    try {
      const { data } = await requestJson(url, { method: "GET", cache: "no-store" });
      // A confirm/rollback click can happen while this request is in flight.
      // Its response must not overwrite the action status or consume a final
      // transaction result that belongs to the active request.
      if (
        transactionActionInFlight
        || pollGeneration !== transactionPollGeneration
        || !pendingTransaction
        || pendingTransaction.transaction_id !== transactionId
      ) return;
      const state = transactionState(data);
      if (isFailedState(state)) {
        failTransaction(data);
        return;
      }
      if (isConfirmedState(state)) {
        finishTransaction("confirmed", data);
        return;
      }
      if (isRolledBackState(state)) {
        finishTransaction("rolled_back", data);
        return;
      }
      if (isPendingState(state) || data.pending_confirmation) {
        updatePendingFromServer(data);
        if (transactionActionNotice) {
          setStatus(statusElement, false, transactionActionNotice);
        } else if (!pendingTransaction.candidate_reachable) {
          setStatus(statusElement, true, waitingForCandidateMessage());
        } else {
          setStatus(statusElement, true, "");
        }
      } else if (data.ok === false) {
        setStatus(statusElement, false, uiText(data.error || "Unable to read confirmation status. Automatic rollback remains active."));
      }
    } catch (error) {
      if (
        transactionActionInFlight
        || pollGeneration !== transactionPollGeneration
        || !pendingTransaction
      ) return;
      setStatus(
        statusElement,
        false,
        uiText("Unable to refresh confirmation status. Automatic rollback remains active.")
      );
    }
    if (!transactionActionInFlight && pendingTransaction) {
      scheduleTransactionPoll(TRANSACTION_POLL_INTERVAL_MS);
    }
  }

  async function confirmPendingConfiguration() {
    if (!pendingTransaction || transactionActionInFlight) return;
    if (!pendingTransaction.candidate_reachable) {
      updateConfirmationAvailability();
      setStatus(
        document.getElementById("apply-confirm-status"),
        true,
        waitingForCandidateMessage()
      );
      scheduleTransactionPoll(0);
      return;
    }
    const confirmButton = document.getElementById("btn-confirm-apply");
    const rollbackButton = document.getElementById("btn-rollback-pending");
    const statusElement = document.getElementById("apply-confirm-status");
    transactionActionInFlight = true;
    transactionActionNotice = "";
    pauseTransactionPolling();
    setButtonLoading(confirmButton, true);
    if (rollbackButton) rollbackButton.disabled = true;
    setStatus(statusElement, true, uiText("Confirming configuration…"));
    try {
      const { response, data } = await requestJson("/haproxy/config/confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          transaction_id: pendingTransaction.transaction_id,
          candidate_sha256: pendingTransaction.candidate_sha256,
        }),
      });
      const state = transactionState(data);
      if (isFailedState(state)) {
        failTransaction(data);
      } else if (isRolledBackState(state)) {
        finishTransaction("rolled_back", data);
      } else if (response.ok && data.ok !== false && !isPendingState(state)) {
        finishTransaction("confirmed", data);
      } else if (isPendingState(state)) {
        updatePendingFromServer(data);
        if (data.candidate_reachable === false) {
          transactionActionNotice = "";
          setStatus(statusElement, true, waitingForCandidateMessage());
        } else {
          transactionActionNotice = data.retryable
            ? uiText("Another HAProxy configuration operation is running. Try again shortly.")
            : uiText(data.error || "Confirmation is still pending.");
          setStatus(statusElement, false, transactionActionNotice);
        }
      } else {
        transactionActionNotice = uiText(data.error || "Failed to confirm configuration");
        setStatus(statusElement, false, transactionActionNotice);
      }
    } catch (error) {
      transactionActionNotice = uiText("Request error: {error}", { error: error.message || error });
      setStatus(statusElement, false, transactionActionNotice);
    } finally {
      transactionActionInFlight = false;
      setButtonLoading(confirmButton, false);
      if (pendingTransaction) {
        if (rollbackButton) rollbackButton.disabled = false;
        updateConfirmationAvailability();
        scheduleTransactionPoll(0);
      }
    }
  }

  async function rollbackPendingConfiguration() {
    if (!pendingTransaction || transactionActionInFlight) return;
    const confirmButton = document.getElementById("btn-confirm-apply");
    const rollbackButton = document.getElementById("btn-rollback-pending");
    const statusElement = document.getElementById("apply-confirm-status");
    transactionActionInFlight = true;
    transactionActionNotice = "";
    pauseTransactionPolling();
    setButtonLoading(rollbackButton, true);
    if (confirmButton) confirmButton.disabled = true;
    setStatus(statusElement, true, uiText("Restoring the previous configuration…"));
    try {
      const { response, data } = await requestJson("/haproxy/config/rollback-pending", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ transaction_id: pendingTransaction.transaction_id }),
      });
      const state = transactionState(data);
      if (isFailedState(state)) {
        failTransaction(data);
      } else if (response.ok && data.ok !== false && !isPendingState(state)) {
        finishTransaction("rolled_back", data);
      } else if (isRolledBackState(state)) {
        finishTransaction("rolled_back", data);
      } else {
        transactionActionNotice = data.retryable
          ? uiText("Another HAProxy configuration operation is running. Try again shortly.")
          : uiText(data.error || "Failed to roll back the pending configuration");
        setStatus(statusElement, false, transactionActionNotice);
      }
    } catch (error) {
      transactionActionNotice = uiText("Request error: {error}", { error: error.message || error });
      setStatus(statusElement, false, transactionActionNotice);
    } finally {
      transactionActionInFlight = false;
      setButtonLoading(rollbackButton, false);
      if (pendingTransaction) {
        if (confirmButton) confirmButton.disabled = false;
        scheduleTransactionPoll(0);
      }
    }
  }

  function restorePendingTransaction() {
    const raw = storageGet(PENDING_TRANSACTION_STORAGE_KEY);
    if (!raw) return false;
    try {
      const saved = JSON.parse(raw);
      if (!saved.transaction_id || !saved.candidate_sha256) throw new Error("invalid transaction");
      pendingTransaction = saved;
      setStatus(
        document.getElementById("apply-status"),
        true,
        uiText("Restoring pending configuration confirmation…")
      );
      showConfirmationModal();
      scheduleTransactionPoll(0);
      return true;
    } catch (error) {
      clearPendingTransaction();
      console.warn("Could not restore pending HAProxy transaction:", error);
      return false;
    }
  }

  async function applyConfig(options) {
    const settings = options && typeof options === "object" ? options : {};
    if (pendingTransaction) {
      showConfirmationModal();
      return false;
    }
    const button = settings.button || document.getElementById("btn-apply");
    const manageLoading = settings.manageLoading !== false;
    setStatus(document.getElementById("apply-status"), true, uiText("Applying candidate configuration…"));
    if (manageLoading) setButtonLoading(button, true);

    try {
      const requestBody = settings.allowExternalDrift
        ? {
            allow_external_drift: true,
            active_cfg_sha256: settings.activeCfgSha256 || "",
          }
        : {};
      const { response, data } = await requestJson("/haproxy/config/apply", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(requestBody),
      });
      if (
        data
        && data.error_code === "haproxy_config_unknown_drift"
        && data.external_drift_confirmation_required
        && /^[0-9a-f]{64}$/i.test(String(data.active_cfg_sha256 || ""))
      ) {
        const approved = window.confirm(uiText(
          "The active haproxy.cfg contains changes made outside this interface. Applying will overwrite them. If validation, health checks, or confirmation fails, the exact currently active configuration will be restored. Continue?"
        ));
        if (!approved) {
          const cancelled = {
            ok: false,
            status: "cancelled",
            error: uiText("Apply cancelled. The active configuration was not changed."),
          };
          const cancelledAt = new Date().toISOString();
          renderApplyResult(cancelled, cancelledAt);
          persistApplyResult(cancelled, cancelledAt);
          return false;
        }
        setStatus(
          document.getElementById("apply-status"),
          true,
          uiText("Applying after explicit confirmation of external changes…")
        );
        return applyConfig({
          button,
          manageLoading: false,
          allowExternalDrift: true,
          activeCfgSha256: String(data.active_cfg_sha256).toLowerCase(),
        });
      }
      const state = transactionState(data);
      if (isPendingState(state) || data.pending_confirmation) {
        acceptPendingTransaction(data);
        return true;
      }

      const completedAt = new Date().toISOString();
      const result = Object.assign({}, data, { ok: response.ok && !!data.ok });
      renderApplyResult(result, completedAt);
      persistApplyResult(result, completedAt);
      // A failed begin may already have rolled HAProxy back (or reported that
      // rollback needs attention) without ever entering the confirmation
      // phase. Refresh both status views immediately instead of waiting for
      // the page-wide polling interval.
      notifyConfigStateChanged();
      void refreshConfigurationSummary();
      return result.ok;
    } catch (error) {
      const result = { ok: false, error: error.message || String(error) };
      const completedAt = new Date().toISOString();
      renderApplyResult(result, completedAt);
      persistApplyResult(result, completedAt);
      // The request outcome is ambiguous after a transport failure. Ask the
      // authoritative endpoints now in case a transaction was started.
      notifyConfigStateChanged();
      void refreshConfigurationSummary();
      return false;
    } finally {
      if (manageLoading && !pendingTransaction) setButtonLoading(button, false);
    }
  }

  async function validateAndApplyConfig() {
    if (pendingTransaction) {
      showConfirmationModal();
      return;
    }

    const applyButton = document.getElementById("btn-apply");
    const checkButton = document.getElementById("btn-check");
    setButtonLoading(applyButton, true);
    if (checkButton) checkButton.disabled = true;

    try {
      const validation = await checkConfig({ button: applyButton, manageLoading: false });
      if (!validation || !validation.ok) {
        const result = {
          ok: false,
          status: "validation_failed",
          error: validationResultMessage(validation || {}),
          stdout: validation && validation.stdout,
          stderr: validation && (validation.stderr || validation.error),
        };
        const completedAt = new Date().toISOString();
        renderApplyResult(result, completedAt);
        persistApplyResult(result, completedAt);
        return;
      }

      setStatus(
        document.getElementById("apply-status"),
        true,
        uiText("Applying candidate configuration…")
      );
      await applyConfig({ button: applyButton, manageLoading: false });
    } finally {
      if (!pendingTransaction) {
        setButtonLoading(applyButton, false);
        if (checkButton) checkButton.disabled = false;
      }
    }
  }

  function trapModalKeyboard(event) {
    const modal = document.getElementById("apply-confirm-modal");
    if (!modal || modal.hidden) return;
    if (event.key === "Escape") {
      event.preventDefault();
      setStatus(
        document.getElementById("apply-confirm-status"),
        false,
        uiText("Confirm the candidate or roll it back before closing this dialog.")
      );
      return;
    }
    if (event.key !== "Tab") return;
    const focusable = Array.from(modal.querySelectorAll("button:not([disabled]), [tabindex='0']"));
    if (!focusable.length) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  function initializeVarsEditor() {
    const guidedForm = document.getElementById("vars-guided-form");
    const rawEditor = document.getElementById("vars-yaml-editor");
    initialGuidedValues = guidedSnapshot();
    initialRawYaml = rawEditor ? rawEditor.value : "";
    updateGuidedDirtyState();
    updateRawDirtyState();

    if (guidedForm) guidedForm.addEventListener("submit", saveGuidedVars);
    document.querySelectorAll("[data-vars-field]").forEach((field) => {
      const markTouched = function () {
        field.dataset.touched = "true";
        updateSwitchState(field);
        if (["admin_ips_enabled", "admin_allowed_ips"].includes(field.dataset.fieldPath)) {
          updateAdminIpAccessState();
        }
        updateGuidedDirtyState();
      };
      updateSwitchState(field);
      field.addEventListener("input", markTouched);
      field.addEventListener("change", markTouched);
    });
    updateAdminIpAccessState();
    document.querySelectorAll("[data-add-current-admin-ip]").forEach((button) => {
      button.addEventListener("click", function () { addCurrentAdminIp(button); });
    });
    if (rawEditor) rawEditor.addEventListener("input", updateRawDirtyState);
    const rawSaveButton = document.getElementById("btn-save-vars-raw");
    if (rawSaveButton) rawSaveButton.addEventListener("click", saveRawVars);
  }

  document.addEventListener("DOMContentLoaded", function () {
    restoreValidationResult();
    restoreApplyResult();
    initializeVarsEditor();

    const previewButton = document.getElementById("btn-preview");
    const checkButton = document.getElementById("btn-check");
    const applyButton = document.getElementById("btn-apply");
    const revertButton = document.getElementById("btn-revert");
    const confirmButton = document.getElementById("btn-confirm-apply");
    const rollbackButton = document.getElementById("btn-rollback-pending");
    if (previewButton) previewButton.addEventListener("click", refreshPreview);
    if (checkButton) checkButton.addEventListener("click", function () { checkConfig(); });
    if (applyButton) applyButton.addEventListener("click", validateAndApplyConfig);
    if (revertButton) revertButton.addEventListener("click", revertConfig);
    if (confirmButton) confirmButton.addEventListener("click", confirmPendingConfiguration);
    if (rollbackButton) rollbackButton.addEventListener("click", rollbackPendingConfiguration);
    document.addEventListener("keydown", trapModalKeyboard);

    restorePendingTransaction();
  });

  window.HaproxyConfig = {
    refreshPreview,
    checkConfig,
    applyConfig: validateAndApplyConfig,
    revertConfig,
    confirmPendingConfiguration,
    rollbackPendingConfiguration,
  };
})();
