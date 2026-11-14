"""Exercise the real API handlers without a live daemon or gateway."""
import ast
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_guardd import EngineTestCase, guardd  # noqa: E402
from test_ban_table_writes import Handler  # noqa: E402


class DaemonBoundary(EngineTestCase):
    def setUp(self):
        super().setUp()
        patch = mock.patch.object(guardd, "CONTROL_TOKEN", "test-control-token")
        patch.start()
        self.addCleanup(patch.stop)

    def call(self, path, body, token="test-control-token"):
        return Handler(self.engine, "POST", "/api/v1/guard/" + path, body, token).sent

    def test_settings_and_preview_require_the_control_token(self):
        for path in ("detection-context", "detection-preview"):
            self.assertEqual(self.call(path, {}, token="bad")[0], 403)
        self.assertEqual(self.engine.detection.config["revision"], 0)

    def test_settings_round_trip_and_revision_conflict(self):
        code, data = self.call("detection-context", {"version": 1})
        self.assertEqual((code, data["config"]["revision"]), (200, 1))
        self.assertIn("login_source", data)
        self.assertEqual(self.call("detection-context", {"version": 1})[0], 400)
        read = Handler(self.engine, "GET", "/api/v1/guard/detection-context").sent
        self.assertEqual(read[1]["config"]["revision"], 1)

    def test_preview_never_records_a_secret_or_a_finding(self):
        body = {"host": "app.example.test", "url": "/.env?token=private-preview-value"}
        code, data = self.call("detection-preview", body)
        self.assertEqual((code, data["nominal_points"]), (200, 60))
        self.assertNotIn("private-preview-value", str(data))
        self.assertFalse(self.events())
        self.assertFalse(self.engine.detection.stats)

    def test_size_and_schema_errors_are_generic(self):
        for body in (["private-preview-value"], {"host": "app.example.test", "url": "/" + "x" * 9000}):
            code, data = self.call("detection-preview", body)
            self.assertEqual(code, 400)
            self.assertNotIn("private-preview-value", str(data))
        self.assertEqual(self.call("detection-context", {"version": 1, "modes": []})[0], 400)


class WebBoundary(unittest.TestCase):
    def setUp(self):
        self.request = types.SimpleNamespace(content_length=100, get_json=lambda **_: {"url": "/?token=private-preview-value"})
        self.audit = mock.Mock()
        self.security = mock.Mock()
        self.g = types.SimpleNamespace(is_superadmin=False)
        self.unavailable = type("Unavailable", (RuntimeError,), {})
        self.namespace = {"request": self.request, "g": self.g, "security": self.security,
                          "jsonify": lambda value: value, "record_request": self.audit,
                          "GuarddUnavailable": self.unavailable, "RESULT_SUCCESS": "success", "RESULT_DENIED": "denied"}
        path = Path(__file__).resolve().parents[1] / "docker/app/haproxy_admin/routes_security.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for function in tree.body:
            if isinstance(function, ast.FunctionDef) and function.name in ("api_set_detection_context", "api_detection_preview"):
                function.decorator_list = []
                exec(compile(ast.Module(body=[function], type_ignores=[]), str(path), "exec"), self.namespace)

    def test_operator_cannot_change_rules_or_probe_trust(self):
        for name in ("api_set_detection_context", "api_detection_preview"):
            self.assertEqual(self.namespace[name]()[1], 403)
        self.security.assert_not_called()
        self.assertFalse(self.security.mock_calls)

    def test_allowed_preview_is_never_audited_even_on_error(self):
        self.g.is_superadmin = True
        self.security.detection_preview.return_value = {"ok": True}
        self.assertEqual(self.namespace["api_detection_preview"](), {"ok": True})
        self.security.detection_preview.side_effect = ValueError("private-preview-value")
        data, code = self.namespace["api_detection_preview"]()
        self.assertEqual(code, 400)
        self.assertNotIn("private-preview-value", str(data))
        self.audit.assert_not_called()

    def test_settings_changes_have_before_and_after_audit(self):
        self.g.is_superadmin = True
        self.security.detection_context.return_value = {"config": {"revision": 1}}
        self.security.set_detection_context.return_value = {"config": {"revision": 2}}
        self.namespace["api_set_detection_context"]()
        self.assertEqual(self.audit.call_args.kwargs["before"], {"revision": 1})
        self.assertEqual(self.audit.call_args.kwargs["after"], {"revision": 2})

    def test_body_limits_apply_before_parsing(self):
        self.g.is_superadmin = True
        self.request.content_length = 200000
        for name in ("api_set_detection_context", "api_detection_preview"):
            self.assertEqual(self.namespace[name]()[1], 413)
        self.assertFalse(self.security.mock_calls)
