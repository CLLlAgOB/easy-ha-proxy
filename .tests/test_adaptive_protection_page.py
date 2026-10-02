"""Regression checks for the adaptive protection page and its guardd client."""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
APP_DIR = ROOT / "docker" / "app" / "haproxy_admin"
sys.path.insert(0, str(ROOT / "docker" / "app"))

from haproxy_admin import services_security as security  # noqa: E402
from haproxy_admin.guardd_client import GuarddUnavailable  # noqa: E402


class SimulatorParameterTests(unittest.TestCase):
    def test_only_known_event_types_are_forwarded(self):
        params = security.simulator_params(
            {"w.SCANNER_PATH": "40", "w.MADE_UP_EVENT": "99"}
        )
        self.assertEqual(params, {"w.SCANNER_PATH": 40})

    def test_weights_are_clamped(self):
        self.assertEqual(
            security.simulator_params({"w.SCANNER_PATH": "9999"}),
            {"w.SCANNER_PATH": 100},
        )
        self.assertEqual(
            security.simulator_params({"w.SCANNER_PATH": "-5"}),
            {"w.SCANNER_PATH": 0},
        )

    def test_nonsense_values_are_dropped_not_guessed(self):
        self.assertEqual(security.simulator_params({"w.SCANNER_PATH": "abc"}), {})
        self.assertEqual(security.simulator_params({"cap": "'; DROP TABLE"}), {})
        self.assertEqual(security.simulator_params({"w.SCANNER_PATH": ""}), {})

    def test_window_and_decay_are_bounded(self):
        params = security.simulator_params({"window": "1", "decay": "999999999"})
        self.assertEqual(params["window"], 3600)
        self.assertEqual(params["decay"], 30 * 86400)

    def test_an_empty_request_asks_for_the_configured_policy(self):
        self.assertEqual(security.simulator_params({}), {})


class ModeSwitchTests(unittest.TestCase):
    def test_only_the_three_modes_are_accepted(self):
        with mock.patch.object(
            security, "guardd_set_mode", return_value={"ok": True}
        ) as call:
            for mode in ("off", "monitor", "enforce", "ENFORCE", " monitor "):
                security.set_mode(mode)
        self.assertEqual(call.call_count, 5)

    def test_anything_else_is_refused_before_reaching_the_daemon(self):
        with mock.patch.object(security, "guardd_set_mode") as call:
            for value in ("aggressive", "", None, "enforce; rm -rf /", 1):
                with self.assertRaises(ValueError):
                    security.set_mode(value)
        call.assert_not_called()


class AddressValidationTests(unittest.TestCase):
    def test_valid_addresses_pass_through(self):
        self.assertEqual(security.valid_ip("203.0.113.9"), "203.0.113.9")
        self.assertEqual(security.valid_ip(" 2001:db8::1 "), "2001:db8::1")

    def test_anything_else_is_refused(self):
        for value in ("", None, "not-an-ip", "203.0.113.9; DROP", "1.2.3.4/24"):
            self.assertEqual(security.valid_ip(value), "", repr(value))


class AnnotationTests(unittest.TestCase):
    def test_country_comes_from_the_local_database(self):
        with (
            mock.patch.object(
                security,
                "guardd_shadow",
                return_value={"addresses": [{"ip": "203.0.113.9"}]},
            ),
            mock.patch.object(
                security, "get_country_code", return_value="NL"
            ) as lookup,
        ):
            payload = security.shadow({})
        self.assertEqual(payload["addresses"][0]["country"], "NL")
        lookup.assert_called_once_with("203.0.113.9")

    def test_an_unreachable_engine_produces_a_typed_payload(self):
        payload = security.unavailable_payload(GuarddUnavailable("refused"))
        self.assertFalse(payload["ok"])
        self.assertTrue(payload["unavailable"])


class PageAssetTests(unittest.TestCase):
    def setUp(self):
        self.template = (
            APP_DIR / "templates" / "adaptive_protection.html"
        ).read_text(encoding="utf-8")
        self.javascript = (
            APP_DIR / "static" / "js" / "adaptive_protection.js"
        ).read_text(encoding="utf-8")

    def test_every_element_the_script_writes_to_exists(self):
        referenced = set(re.findall(r'byId\("([a-z0-9-]+)"\)', self.javascript))
        referenced |= set(re.findall(r'setText\(\s*"([a-z0-9-]+)"', self.javascript))
        template_ids = set(re.findall(r'id="([a-z0-9-]+)"', self.template))
        missing = sorted(referenced - template_ids)
        self.assertEqual(missing, [], f"script writes to unknown ids: {missing}")

    def test_the_page_states_that_nothing_is_blocked(self):
        self.assertIn("Monitor mode", self.template)
        self.assertIn("nothing is blocked", self.template)
        self.assertIn("HAProxy traffic is not affected", self.template)

    def test_switching_to_enforce_needs_a_confirmation(self):
        # The one control that changes what happens to traffic must not be a
        # single stray click.
        self.assertIn('id="ap-confirm"', self.template)
        self.assertIn("askToSwitch", self.javascript)
        self.assertIn("commitMode", self.javascript)
        self.assertIn('id="ap-confirm-yes"', self.template)

    def test_the_mode_request_carries_the_csrf_token(self):
        self.assertIn('"X-CSRFToken": csrfToken()', self.javascript)
        self.assertIn('method: "POST"', self.javascript)
        self.assertIn('credentials: "same-origin"', self.javascript)

    def test_the_page_spells_out_what_can_never_be_banned(self):
        for guarantee in (
            "authenticated before",
            "admin allow-list",
            "IPv4 only",
            "lifts every ban it applied",
        ):
            self.assertIn(guarantee, self.template, guarantee)

    def test_the_page_has_no_direct_ban_control(self):
        # Banning is a consequence of the mode plus the score, never a button
        # aimed at one address.
        # Matched as whole paths. As a bare prefix this also caught
        # /adaptive/durations, which bans nobody -- and a guarantee that
        # fires on innocent names is one that gets edited away.
        for forbidden in ("/api/security/adaptive/ban", "/api/security/adaptive/unban"):
            pattern = re.escape(forbidden) + r"(?![-\w])"
            self.assertIsNone(
                re.search(pattern, self.template), forbidden
            )
            self.assertIsNone(
                re.search(pattern, self.javascript), forbidden
            )

    def test_the_simulator_covers_every_event_type(self):
        for event_type in security.EVENT_TYPES:
            self.assertIn(event_type, str(security.EVENT_TYPES))
        self.assertIn('data-weight="{{ event_type }}"', self.template)
        self.assertIn("{% for event_type in event_types %}", self.template)

    def test_technical_readouts_are_excluded_from_dom_translation(self):
        for element_id in (
            "ap-scored",
            "ap-wouldban",
            "ap-falsepos",
            "ap-table",
            "ap-detail-title",
            "ap-detail-timeline",
        ):
            tag = re.search(rf'<[^>]+id="{element_id}"[^>]*>', self.template)
            self.assertIsNotNone(tag, element_id)
            self.assertIn("data-i18n-skip", tag.group(0))
            self.assertIn('translate="no"', tag.group(0))

    def test_no_external_script_host_is_referenced(self):
        self.assertNotIn("https://", self.javascript)
        self.assertIn(
            "url_for('static', filename='js/adaptive_protection.js')", self.template
        )


class CatalogCoverageTests(unittest.TestCase):
    def test_every_translated_string_resolves_in_russian(self):
        shared = set()
        for path in (APP_DIR / "translations").rglob("*.json"):
            data = json.loads(path.read_text(encoding="utf-8"))
            if data["meta"]["code"] == "ru":
                shared |= set(data["messages"])
        javascript = (
            APP_DIR / "static" / "js" / "adaptive_protection.js"
        ).read_text(encoding="utf-8")
        for source in re.findall(r'uiText\(\s*"([^"]+)"', javascript):
            self.assertIn(source, shared, f"missing Russian translation: {source}")

    def test_the_engine_vocabulary_is_translated(self):
        catalog = json.loads(
            (APP_DIR / "translations" / "ru" / "adaptive_protection.json").read_text(
                encoding="utf-8"
            )
        )["messages"]
        # Values the daemon returns verbatim and the page renders.
        for token in (
            "counted",
            "category cap reached",
            "already refused by the gateway",
            "none",
            "observe",
            "throttle",
            "temporary_ban",
            "long_ban",
            "authenticated",
            "whitelisted",
        ):
            self.assertIn(token, catalog, token)


if __name__ == "__main__":
    unittest.main()
