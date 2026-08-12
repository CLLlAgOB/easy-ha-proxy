"""Static regression checks for the Authelia email settings interface."""

from __future__ import annotations

import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "docker/app/haproxy_admin"
TEMPLATE = (APP / "templates/mail_settings.html").read_text(encoding="utf-8")
JAVASCRIPT = (APP / "static/js/authelia_settings.js").read_text(encoding="utf-8")
STYLES = (APP / "static/css/styles.css").read_text(encoding="utf-8")


class AutheliaMailSettingsUITests(unittest.TestCase):
    def test_page_exposes_only_disabled_and_internal_relay_modes(self) -> None:
        for mode in ("filesystem", "relay"):
            self.assertRegex(
                TEMPLATE,
                rf'<input[^>]+name="mail_mode"[^>]+value="{mode}"',
            )
        self.assertNotRegex(
            TEMPLATE,
            r'<input[^>]+name="mail_mode"[^>]+value="direct"',
        )
        self.assertNotIn("<strong>Direct SMTP</strong>", TEMPLATE)
        self.assertIn("send locally to mail_relay", TEMPLATE)
        self.assertIn('id="authelia-mail-relay-unavailable"', TEMPLATE)
        self.assertIn('id="authelia-mail-legacy-direct"', TEMPLATE)

    def test_password_is_write_only_and_empty_means_keep(self) -> None:
        match = re.search(
            r'<input[^>]+id="authelia-mail-password"[^>]*>', TEMPLATE
        )
        self.assertIsNotNone(match)
        password_tag = match.group(0)
        self.assertIn('type="password"', password_tag)
        self.assertIn('autocomplete="new-password"', password_tag)
        self.assertNotIn(" value=", password_tag)

        self.assertIn('return {password_action: "keep", password: ""}', JAVASCRIPT)
        self.assertIn('return {password_action: "replace", password: elements.password.value}', JAVASCRIPT)
        self.assertIn('return {password_action: "clear", password: ""}', JAVASCRIPT)
        self.assertIn('elements.password.value = ""', JAVASCRIPT)
        self.assertNotIn("elements.password.value = values.password", JAVASCRIPT)
        self.assertIn("password_configured", JAVASCRIPT)

    def test_api_requests_are_revision_safe_and_distinguish_apply(self) -> None:
        self.assertIn('const ENDPOINT = "/authelia/settings/mail"', JAVASCRIPT)
        self.assertIn('let settingsRevision = ""', JAVASCRIPT)
        self.assertIn("payload.revision", JAVASCRIPT)
        self.assertIn("revision: settingsRevision", JAVASCRIPT)
        self.assertIn("apply: true", JAVASCRIPT)
        self.assertIn("error.payload?.conflict", JAVASCRIPT)
        self.assertIn("error.payload?.relay_unavailable", JAVASCRIPT)
        self.assertLess(
            JAVASCRIPT.index("error.payload?.relay_unavailable"),
            JAVASCRIPT.index("error.payload?.conflict"),
        )
        self.assertIn(
            "Email settings changed in another session. Reload them before saving.",
            JAVASCRIPT,
        )
        self.assertIn('`${ENDPOINT}/test`', JAVASCRIPT)
        self.assertIn("recipient: testRecipient", JAVASCRIPT)
        self.assertIn('id="authelia-mail-test"', TEMPLATE)
        self.assertIn('id="authelia-mail-test-recipient"', TEMPLATE)
        self.assertIn("async function saveSettings()", JAVASCRIPT)
        self.assertIn("async function sendTestEmail()", JAVASCRIPT)
        self.assertIn('elements.test?.addEventListener("click", sendTestEmail)', JAVASCRIPT)
        self.assertNotIn("saveSettings(true)", JAVASCRIPT)
        self.assertNotIn("Boolean(sendTest)", JAVASCRIPT)
        self.assertIn("revision: settingsRevision", JAVASCRIPT)
        self.assertIn("!preserveTestRecipient", JAVASCRIPT)

    def test_relay_capability_and_security_warnings_are_visible(self) -> None:
        self.assertIn("capabilities?.relay_available", JAVASCRIPT)
        self.assertIn(
            'elements.relayUnavailable.hidden = relayAvailable || mode !== "relay"',
            JAVASCRIPT,
        )
        self.assertIn('id="authelia-mail-tls-skip-verify"', TEMPLATE)
        self.assertIn('id="authelia-mail-tls-warning"', TEMPLATE)
        self.assertIn('id="authelia-mail-relay-tls-warning"', TEMPLATE)
        self.assertNotIn('elements.tlsMode.disabled = mode === "relay"', JAVASCRIPT)
        self.assertNotIn('|| mode === "relay"', JAVASCRIPT)
        self.assertIn("relaySkipsVerification", JAVASCRIPT)
        self.assertIn(".authelia-mail-mode-grid", STYLES)
        self.assertIn(".authelia-mail-fields-grid", STYLES)
        self.assertIn("relayInput.disabled = false", JAVASCRIPT)

    def test_test_only_recipient_cannot_block_normal_save(self) -> None:
        self.assertIn(
            "elements.testRecipient.disabled = true",
            JAVASCRIPT,
        )
        self.assertIn(
            "elements.testRecipient.disabled = testRecipientWasDisabled",
            JAVASCRIPT,
        )
        self.assertIn(
            "elements.testRecipient.required = true",
            JAVASCRIPT,
        )
        self.assertIn(
            "const recipientIsValid = elements.testRecipient.reportValidity()",
            JAVASCRIPT,
        )
        self.assertNotIn(
            "elements.testRecipient.required = smtpEnabled",
            JAVASCRIPT,
        )

    def test_apply_is_primary_and_mode_changes_are_not_reported_as_active(self) -> None:
        self.assertRegex(
            TEMPLATE,
            r'<button type="submit" class="btn" id="authelia-mail-apply">Save and apply</button>',
        )
        self.assertNotIn('id="authelia-mail-save"', TEMPLATE)
        self.assertNotIn("Save draft", TEMPLATE)
        self.assertIn('setModeStatus(selectedMode(), "dirty")', JAVASCRIPT)
        self.assertIn("let settingsDirty = false", JAVASCRIPT)
        self.assertIn('selectedMode() === "filesystem" || settingsDirty', JAVASCRIPT)
        self.assertIn("if (settingsDirty)", JAVASCRIPT)
        self.assertNotIn('state === "saved"', JAVASCRIPT)
        self.assertNotIn("setModeStatus(mode);", JAVASCRIPT)

    def test_mail_test_is_separate_from_save_and_apply(self) -> None:
        save_function = JAVASCRIPT[JAVASCRIPT.index("async function saveSettings()"):
                                   JAVASCRIPT.index("async function sendTestEmail()")]
        test_function = JAVASCRIPT[JAVASCRIPT.index("async function sendTestEmail()"):
                                   JAVASCRIPT.index('document.addEventListener("DOMContentLoaded"')]
        self.assertNotIn("/test", save_function)
        self.assertIn('requestJson(`${ENDPOINT}/test`', test_function)
        self.assertIn("revision: settingsRevision", test_function)
        self.assertNotIn("collectSettings()", test_function)
        self.assertIn(
            '>Send test email</button>',
            TEMPLATE,
        )
        self.assertNotIn(
            '>Save, apply and send test email</button>',
            TEMPLATE,
        )

    def test_critical_dynamic_messages_have_russian_translations(self) -> None:
        messages = json.loads(
            (APP / "translations/ru.json").read_text(encoding="utf-8")
        )["messages"]
        for source in (
            "Email notifications",
            "Email disabled",
            "Internal mail relay",
            "Password configured",
            "No password configured",
            "Leave blank to keep the current password",
            "Email settings saved and applied successfully.",
            "Email settings changed in another session. Reload them before saving.",
            "Mail settings saved and applied safely.",
            "Unsaved email changes",
            "Legacy direct SMTP active",
            "Test email recipient",
            "Defaults to the startup-check recipient. Changing it here affects only the next test message and is not saved.",
            "The test uses the last applied SMTP settings. Save and apply any pending changes before sending it.",
            "Send test email",
            "Save and apply activates the displayed settings. Send test email is a separate action that uses the last applied settings and briefly waits for the external SMTP relay result. Acceptance by the external relay still does not guarantee final inbox delivery.",
            "Save and apply email changes before sending a test message.",
            "Sending a test message with the applied email settings…",
            "The configured external SMTP relay accepted the test message. Final inbox delivery still cannot be guaranteed.",
            "The internal relay queued the test message after a temporary external delivery failure and will retry it.",
            "The internal relay queued the test message, but no definitive external delivery result was available within the bounded check window.",
            "The internal relay accepted the test message, but the configured external SMTP relay rejected it. Check the SMTP credentials, sender policy, and mail_relay logs.",
            "STARTTLS and SMTPS require encrypted transport. mail_relay verifies the external server certificate unless Skip verification is selected.",
            "mail_relay verifies the external SMTP server certificate with the CA bundle installed in the relay container.",
            "mail_relay will require encrypted transport but will not verify the external SMTP server certificate identity.",
            "Failed to send the test message",
            "Please wait before sending another test message.",
            "Test message was accepted by the internal mail relay. Final inbox delivery is asynchronous and is not guaranteed.",
        ):
            with self.subTest(source=source):
                self.assertIn(source, messages)
                self.assertNotEqual(messages[source], source)


if __name__ == "__main__":
    unittest.main()
