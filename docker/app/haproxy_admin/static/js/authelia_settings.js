/* Authelia email notifier and SMTP relay settings. */
(function () {
  "use strict";

  const ENDPOINT = "/authelia/settings/mail";
  const t = window.t || ((value) => String(value));
  const elements = {};
  let relayAvailable = false;
  let settingsRevision = "";
  let requestRunning = false;
  let settingsDirty = false;

  function byId(id) {
    return document.getElementById(id);
  }

  function selectedMode() {
    return document.querySelector('input[name="mail_mode"]:checked')?.value || "filesystem";
  }

  function setResult(message, ok) {
    const element = elements.result;
    if (!element) return;
    element.textContent = message || "";
    element.classList.toggle("success", Boolean(message) && ok === true);
    element.classList.toggle("error", Boolean(message) && ok === false);
    element.classList.toggle("warning", Boolean(message) && ok === "warning");
  }

  function setBusy(busy) {
    requestRunning = Boolean(busy);
    [elements.apply, elements.test].forEach((button) => {
      if (!button) return;
      const relayCannotApply = selectedMode() === "relay"
        && !relayAvailable;
      const testUnavailable = button === elements.test
        && (selectedMode() === "filesystem" || settingsDirty);
      button.disabled = requestRunning || relayCannotApply || testUnavailable;
      if (button === elements.test) {
        button.title = settingsDirty
          ? t("Save and apply email changes before sending a test message.")
          : "";
      }
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
      const problem = new Error(payload.error || payload.message || `${t("Request failed")} (${response.status})`);
      problem.status = response.status;
      problem.payload = payload;
      throw problem;
    }
    return payload;
  }

  function setModeStatus(mode, state) {
    const labels = {
      filesystem: t("Email disabled"),
      relay: t("Internal mail relay enabled")
    };
    const status = elements.modeStatus;
    if (!status) return;
    if (state === "dirty") {
      status.textContent = t("Unsaved email changes");
    } else if (state === "legacy") {
      status.textContent = t("Legacy direct SMTP active");
    } else {
      status.textContent = labels[mode] || t("Status unavailable");
    }
    status.classList.remove(
      "config-status-pill--neutral",
      "config-status-pill--success",
      "config-status-pill--warning"
    );
    if (state === "dirty" || state === "legacy") {
      status.classList.add("config-status-pill--warning");
    } else {
      status.classList.add(
        mode === "filesystem" ? "config-status-pill--neutral" : "config-status-pill--success"
      );
    }
  }

  function updateVisibleFields() {
    const mode = selectedMode();
    const smtpEnabled = mode !== "filesystem";
    if (elements.smtpFields) elements.smtpFields.hidden = !smtpEnabled;
    if (elements.testControls) elements.testControls.hidden = !smtpEnabled;
    if (elements.relayUnavailable) {
      elements.relayUnavailable.hidden = relayAvailable || mode !== "relay";
    }

    [elements.host, elements.port, elements.sender, elements.recipient, elements.subject, elements.timeout]
      .filter(Boolean)
      .forEach((field) => { field.required = smtpEnabled; });

    if (elements.routeNote) {
      elements.routeNote.textContent = t("The external SMTP settings below configure the internal mail_relay container. Authelia and certificate hooks send to it locally.");
    }

    if (elements.tlsSkipVerify) {
      elements.tlsSkipVerify.disabled = !smtpEnabled
        || elements.tlsMode?.value === "plain";
    }
    if (elements.tlsWarning) {
      elements.tlsWarning.hidden = !smtpEnabled
        || elements.tlsMode?.value === "plain"
        || !elements.tlsSkipVerify?.checked;
    }
    if (elements.relayTlsWarning) {
      elements.relayTlsWarning.hidden = mode !== "relay"
        || elements.tlsMode?.value === "plain";
      const relaySkipsVerification = Boolean(elements.tlsSkipVerify?.checked);
      elements.relayTlsWarning.textContent = relaySkipsVerification
        ? t("mail_relay will require encrypted transport but will not verify the external SMTP server certificate identity.")
        : t("mail_relay verifies the external SMTP server certificate with the CA bundle installed in the relay container.");
      elements.relayTlsWarning.classList.toggle("alert-warning", relaySkipsVerification);
      elements.relayTlsWarning.classList.toggle("alert-info", !relaySkipsVerification);
    }
    if (!requestRunning && elements.apply) {
      elements.apply.disabled = mode === "relay" && !relayAvailable;
    }
    if (!requestRunning && elements.test) {
      elements.test.disabled = mode === "filesystem"
        || (mode === "relay" && !relayAvailable)
        || settingsDirty;
      elements.test.title = settingsDirty
        ? t("Save and apply email changes before sending a test message.")
        : "";
    }
  }

  function renderSettings(settings, capabilities, revision, preserveTestRecipient, statusState) {
    const values = settings && typeof settings === "object" ? settings : {};
    relayAvailable = Boolean(capabilities?.relay_available);
    if (elements.legacyDirect) {
      elements.legacyDirect.hidden = !Boolean(capabilities?.legacy_direct);
    }
    if (typeof revision === "string" && revision) settingsRevision = revision;
    settingsDirty = false;
    const mode = ["filesystem", "relay"].includes(values.mode)
      ? values.mode
      : "filesystem";

    const modeInput = byId(`authelia-mail-mode-${mode}`);
    if (modeInput) modeInput.checked = true;

    const relayInput = byId("authelia-mail-mode-relay");
    if (relayInput) {
      relayInput.disabled = false;
      relayInput.closest(".authelia-mail-mode-option")?.classList.remove(
        "authelia-mail-mode-option--disabled"
      );
    }

    elements.host.value = values.host || "";
    elements.port.value = values.port == null ? "" : String(values.port);
    elements.username.value = values.username || "";
    elements.sender.value = values.sender || "";
    elements.recipient.value = values.recipient || "";
    if (elements.testRecipient && !preserveTestRecipient) {
      elements.testRecipient.value = values.recipient || "";
    }
    elements.subject.value = values.subject || "";
    elements.timeout.value = values.timeout || "10s";
    elements.tlsMode.value = ["smtps", "starttls", "plain"].includes(values.tls_mode)
      ? values.tls_mode
      : "starttls";
    elements.tlsSkipVerify.checked = Boolean(values.tls_skip_verify);

    // Secrets are write-only. A refresh always clears the password input.
    elements.password.value = "";
    elements.clearPassword.checked = false;
    elements.password.disabled = false;
    elements.passwordStatus.textContent = values.password_configured
      ? t("Password configured")
      : t("No password configured");
    elements.passwordStatus.classList.toggle(
      "authelia-mail-password-status--configured",
      Boolean(values.password_configured)
    );

    updateVisibleFields();
    setModeStatus(
      mode,
      statusState || (capabilities?.legacy_direct ? "legacy" : "active")
    );
    document.dispatchEvent(new CustomEvent("authelia-mail-mode-applied", {
      detail: {mode}
    }));
  }

  function passwordPayload() {
    if (elements.clearPassword.checked) {
      return {password_action: "clear", password: ""};
    }
    if (elements.password.value) {
      return {password_action: "replace", password: elements.password.value};
    }
    return {password_action: "keep", password: ""};
  }

  function collectSettings() {
    const password = passwordPayload();
    return {
      mode: selectedMode(),
      host: elements.host.value.trim(),
      port: Number(elements.port.value || 25),
      username: elements.username.value.trim(),
      password_action: password.password_action,
      password: password.password,
      sender: elements.sender.value.trim(),
      recipient: elements.recipient.value.trim(),
      subject: elements.subject.value.trim(),
      timeout: elements.timeout.value.trim(),
      tls_mode: elements.tlsMode.value,
      tls_skip_verify: elements.tlsMode.value === "plain"
        ? false
        : elements.tlsSkipVerify.checked
    };
  }

  async function loadSettings() {
    setBusy(true);
    setResult(t("Loading email settings…"));
    try {
      const payload = await requestJson(ENDPOINT);
      renderSettings(payload.settings, payload.capabilities, payload.revision);
      setResult("");
    } catch (error) {
      setResult(`${t("Failed to load email settings")}: ${error.message}`, false);
      document.dispatchEvent(new CustomEvent("authelia-mail-mode-applied", {
        detail: {mode: null}
      }));
      if (elements.modeStatus) {
        elements.modeStatus.textContent = t("Status unavailable");
        elements.modeStatus.className = "config-status-pill config-status-pill--warning";
      }
    } finally {
      setBusy(false);
    }
  }

  async function saveSettings() {
    if (requestRunning) return;
    updateVisibleFields();

    // The test-only address must not prevent saving the SMTP settings. It is
    // validated independently by sendTestEmail().
    const testRecipientWasDisabled = Boolean(elements.testRecipient?.disabled);
    if (elements.testRecipient) elements.testRecipient.disabled = true;
    const formIsValid = elements.form.reportValidity();
    if (elements.testRecipient) {
      elements.testRecipient.disabled = testRecipientWasDisabled;
    }
    if (!formIsValid) return;

    const settings = collectSettings();
    setBusy(true);
    setResult(t("Saving and applying email settings…"));
    try {
      const payload = await requestJson(ENDPOINT, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
          settings,
          apply: true,
          revision: settingsRevision
        })
      });
      renderSettings(
        payload.settings,
        {relay_available: relayAvailable},
        payload.revision,
        true,
        "active"
      );
      const successMessage = payload.message
        || t("Email settings saved and applied successfully.");
      setResult(
        payload.warning ? `${successMessage} ${payload.warning}` : successMessage,
        true
      );
    } catch (error) {
      if (error.status === 409 && error.payload?.relay_unavailable) {
        setResult(t("The mail relay is not installed yet. Run a full software update, then retry."), false);
      } else if (error.status === 409 && error.payload?.conflict) {
        setResult(t("Email settings changed in another session. Reload them before saving."), false);
      } else {
        const prefix = error.status === 400
          ? t("Check the email settings")
          : t("Failed to save email settings");
        setResult(`${prefix}: ${error.message}`, false);
      }
    } finally {
      setBusy(false);
    }
  }

  async function sendTestEmail() {
    if (requestRunning) return;
    if (settingsDirty) {
      setResult(t("Save and apply email changes before sending a test message."), false);
      updateVisibleFields();
      return;
    }
    if (selectedMode() === "filesystem" || !elements.testRecipient) return;

    const testRecipientWasRequired = elements.testRecipient.required;
    elements.testRecipient.required = true;
    const recipientIsValid = elements.testRecipient.reportValidity();
    elements.testRecipient.required = testRecipientWasRequired;
    if (!recipientIsValid) return;

    const testRecipient = elements.testRecipient.value.trim();
    setBusy(true);
    setResult(t("Sending a test message with the applied email settings…"));
    try {
      const payload = await requestJson(`${ENDPOINT}/test`, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
          revision: settingsRevision,
          recipient: testRecipient
        })
      });
      settingsRevision = payload.revision || settingsRevision;
      const resultState = ["deferred", "queued"].includes(payload.delivery_status)
        ? "warning"
        : true;
      setResult(t(payload.message), resultState);
    } catch (error) {
      if (error.status === 429 && error.payload?.rate_limited) {
        setResult(t("Please wait before sending another test message."), false);
      } else if (error.status === 409 && error.payload?.relay_unavailable) {
        setResult(t("The mail relay is not installed yet. Run a full software update, then retry."), false);
      } else if (error.status === 409 && error.payload?.conflict) {
        setResult(t("Email settings changed in another session. Reload them before saving."), false);
      } else {
        setResult(`${t("Failed to send the test message")}: ${t(error.message)}`, false);
      }
    } finally {
      setBusy(false);
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    const ids = {
      form: "authelia-mail-form",
      modeStatus: "authelia-mail-mode-status",
      relayUnavailable: "authelia-mail-relay-unavailable",
      legacyDirect: "authelia-mail-legacy-direct",
      smtpFields: "authelia-mail-smtp-fields",
      routeNote: "authelia-mail-route-note",
      host: "authelia-mail-host",
      port: "authelia-mail-port",
      username: "authelia-mail-username",
      password: "authelia-mail-password",
      passwordStatus: "authelia-mail-password-status",
      clearPassword: "authelia-mail-clear-password",
      tlsMode: "authelia-mail-tls-mode",
      tlsSkipVerify: "authelia-mail-tls-skip-verify",
      tlsWarning: "authelia-mail-tls-warning",
      relayTlsWarning: "authelia-mail-relay-tls-warning",
      sender: "authelia-mail-sender",
      recipient: "authelia-mail-recipient",
      testControls: "authelia-mail-test-controls",
      testRecipient: "authelia-mail-test-recipient",
      subject: "authelia-mail-subject",
      timeout: "authelia-mail-timeout",
      apply: "authelia-mail-apply",
      test: "authelia-mail-test",
      result: "authelia-mail-result"
    };
    Object.entries(ids).forEach(([key, id]) => { elements[key] = byId(id); });
    if (!elements.form) return;

    elements.form.addEventListener("submit", (event) => {
      event.preventDefault();
      saveSettings();
    });
    elements.test?.addEventListener("click", sendTestEmail);
    const markSettingsDirty = (event) => {
      if (event.target === elements.testRecipient) return;
      settingsDirty = true;
      setModeStatus(selectedMode(), "dirty");
      updateVisibleFields();
    };
    elements.form.addEventListener("input", markSettingsDirty);
    elements.form.addEventListener("change", markSettingsDirty);
    elements.form.querySelectorAll('input[name="mail_mode"]').forEach((input) => {
      input.addEventListener("change", updateVisibleFields);
    });
    elements.tlsMode?.addEventListener("change", updateVisibleFields);
    elements.tlsSkipVerify?.addEventListener("change", updateVisibleFields);
    elements.clearPassword?.addEventListener("change", () => {
      elements.password.disabled = elements.clearPassword.checked;
      if (elements.clearPassword.checked) elements.password.value = "";
    });
    elements.password?.addEventListener("input", () => {
      if (elements.password.value) elements.clearPassword.checked = false;
    });

    loadSettings();
  });
})();
