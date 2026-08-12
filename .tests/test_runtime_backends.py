"""Regression checks for runtime server operations."""

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

from haproxy_admin import services_runtime as runtime  # noqa: E402


STAT_HEADER = (
    "# pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,status,weight,"
    "addr,check_status"
)


def stat(rows):
    lines = [STAT_HEADER]
    for row in rows:
        lines.append(",".join(str(cell) for cell in row))
    return "\n".join(lines) + "\n"


SAMPLE = stat(
    [
        ("fe_https", "FRONTEND", 0, 0, 3, 0, 0, 0, 0, 0, "OPEN", "", "", ""),
        ("be_shop", "BACKEND", 0, 0, 2, 0, 0, 0, 0, 0, "UP", 100, "", ""),
        ("be_shop", "srv1", 0, 0, 2, 0, 0, 0, 0, 0, "UP", 100, "10.0.0.1:443", "L7OK"),
        ("be_shop", "srv2", 0, 0, 0, 0, 0, 0, 0, 0, "DRAIN", 60, "10.0.0.2:443", "L7OK"),
        ("be_blog", "srv1", 0, 0, 1, 0, 0, 0, 0, 0, "MAINT", 100, "10.0.0.3:443", ""),
        ("be_admin", "ui", 0, 0, 1, 0, 0, 0, 0, 0, "UP", 100, "127.0.0.1:5000", ""),
        ("authelia_backend", "authelia", 0, 0, 0, 0, 0, 0, 0, 0, "UP", 100, "", ""),
        ("tbl_ban", "BACKEND", 0, 0, 0, 0, 0, 0, 0, 0, "UP", 0, "", ""),
    ]
)


class ListingTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(runtime, "_show_stat", return_value=SAMPLE)
        patcher.start()
        self.addCleanup(patcher.stop)
        names = mock.patch.object(
            runtime, "_load_display_map_from_cfg", return_value={}
        )
        names.start()
        self.addCleanup(names.stop)

    def test_only_operable_backends_are_listed(self):
        names = {entry["backend"] for entry in runtime.list_backends()}
        self.assertEqual(names, {"be_shop", "be_blog"})

    def test_the_admin_and_authelia_backends_are_never_offered(self):
        # Draining either one would cut off the interface issuing the request.
        for protected in ("be_admin", "authelia_backend", "be_access_granted"):
            self.assertIn(protected, runtime.PROTECTED_BACKENDS, protected)

    def test_server_rows_carry_the_state_the_ui_needs(self):
        shop = next(
            entry for entry in runtime.list_backends() if entry["backend"] == "be_shop"
        )
        srv1, srv2 = shop["servers"]
        self.assertEqual(srv1["server"], "srv1")
        self.assertEqual(srv1["admin_state"], "ready")
        self.assertEqual(srv1["weight"], 100)
        self.assertEqual(srv1["sessions"], 2)
        self.assertEqual(srv1["address"], "10.0.0.1:443")
        self.assertEqual(srv2["admin_state"], "drain")

    def test_maintenance_is_recognised(self):
        blog = next(
            entry for entry in runtime.list_backends() if entry["backend"] == "be_blog"
        )
        self.assertEqual(blog["servers"][0]["admin_state"], "maint")

    def test_a_transitional_status_still_reads_as_ready(self):
        self.assertEqual(runtime._admin_state("UP 1/3"), "ready")
        self.assertEqual(runtime._admin_state("DOWN 2/3"), "ready")
        self.assertEqual(runtime._admin_state("MAINT (via be/srv)"), "maint")


class CommandTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(runtime, "_show_stat", return_value=SAMPLE)
        patcher.start()
        self.addCleanup(patcher.stop)
        names = mock.patch.object(
            runtime, "_load_display_map_from_cfg", return_value={}
        )
        names.start()
        self.addCleanup(names.stop)
        self.runtime_call = mock.patch.object(
            runtime, "haproxy_runtime_command", return_value=""
        )
        self.call = self.runtime_call.start()
        self.addCleanup(self.runtime_call.stop)

    def test_state_changes_build_the_expected_command(self):
        result = runtime.set_state("be_shop", "srv1", "drain")
        self.assertTrue(result["ok"])
        self.call.assert_called_once()
        self.assertEqual(
            self.call.call_args.args[0], "set server be_shop/srv1 state drain"
        )

    def test_weight_changes_build_the_expected_command(self):
        runtime.set_weight("be_shop", "srv1", "80")
        self.assertEqual(
            self.call.call_args.args[0], "set server be_shop/srv1 weight 80"
        )

    def test_an_unknown_state_never_reaches_haproxy(self):
        for value in ("nonsense", "", None, "drain; show env"):
            with self.assertRaises(runtime.RuntimeError_):
                runtime.set_state("be_shop", "srv1", value)
        self.call.assert_not_called()

    def test_an_unknown_server_never_reaches_haproxy(self):
        for backend, server in (
            ("be_shop", "srv9"),
            ("nosuch", "srv1"),
            ("be_shop/srv1 state maint", "srv1"),
            ("", ""),
        ):
            with self.assertRaises(runtime.RuntimeError_):
                runtime.set_state(backend, server, "drain")
        self.call.assert_not_called()

    def test_a_protected_backend_cannot_be_operated(self):
        # It is filtered out of the listing, so resolution refuses it.
        for backend, server in (
            ("be_admin", "ui"),
            ("authelia_backend", "authelia"),
            ("tbl_ban", "BACKEND"),
        ):
            with self.assertRaises(runtime.RuntimeError_):
                runtime.set_state(backend, server, "maint")
        self.call.assert_not_called()

    def test_weight_bounds_are_enforced_before_the_call(self):
        for value in (-1, 257, "abc", None, "10; set server x"):
            with self.assertRaises(runtime.RuntimeError_):
                runtime.set_weight("be_shop", "srv1", value)
        self.call.assert_not_called()

    def test_the_boundary_weights_are_allowed(self):
        runtime.set_weight("be_shop", "srv1", 0)
        runtime.set_weight("be_shop", "srv1", 256)
        self.assertEqual(self.call.call_count, 2)

    def test_a_refusal_from_haproxy_is_surfaced_not_swallowed(self):
        self.call.return_value = "No such server.\n"
        with self.assertRaises(runtime.RuntimeError_) as caught:
            runtime.set_state("be_shop", "srv1", "drain")
        self.assertIn("No such server", str(caught.exception))


class PageAssetTests(unittest.TestCase):
    def setUp(self):
        self.template = (
            APP_DIR / "templates" / "haproxy_backends.html"
        ).read_text(encoding="utf-8")
        self.javascript = (
            APP_DIR / "static" / "js" / "haproxy_backends.js"
        ).read_text(encoding="utf-8")

    def test_the_page_states_that_the_change_persists(self):
        # The state file makes these operations survive a reload, so the page
        # must not still describe them as temporary.
        for phrase in ("saved and restored", "after a reboot"):
            self.assertIn(phrase, self.template, phrase)
        self.assertNotIn("no server state file", self.template)

    def test_mutating_requests_carry_the_csrf_token(self):
        self.assertIn('"X-CSRFToken": csrfToken()', self.javascript)
        self.assertIn('method: "POST"', self.javascript)

    def test_the_browser_never_sends_runtime_command_text(self):
        # Only named fields; the command is assembled server side.
        self.assertNotIn("set server", self.javascript)
        self.assertIn("backend: backend.backend", self.javascript)
        self.assertIn("state: entry.key", self.javascript)

    def test_controls_are_disabled_without_the_superadmin_role(self):
        self.assertIn('data-superadmin="{{', self.template)
        self.assertIn("input.disabled = !superadmin", self.javascript)
        self.assertIn("button.disabled = !superadmin", self.javascript)

    def test_identifiers_are_excluded_from_dom_translation(self):
        for marker in ("rt-name", "rt-state", "rt-id"):
            self.assertIn(marker, self.javascript)
        self.assertIn('setAttribute("data-i18n-skip", "")', self.javascript)

    def test_every_element_the_script_writes_to_exists(self):
        referenced = set(re.findall(r'byId\("([a-z0-9-]+)"\)', self.javascript))
        template_ids = set(re.findall(r'id="([a-z0-9-]+)"', self.template))
        self.assertEqual(sorted(referenced - template_ids), [])


class CatalogTests(unittest.TestCase):
    def test_the_page_vocabulary_is_translated(self):
        shared = set()
        for path in (APP_DIR / "translations").rglob("*.json"):
            data = json.loads(path.read_text(encoding="utf-8"))
            if data["meta"]["code"] == "ru":
                shared |= set(data["messages"])
        for token in ("Ready", "Drain", "Maintenance", "Weight", "Sessions",
                      "Backends", "Servers"):
            self.assertIn(token, shared, token)


if __name__ == "__main__":
    unittest.main()
