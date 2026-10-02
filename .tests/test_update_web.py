"""Focused regression tests for the superadmin software-update web workflow."""

from __future__ import annotations

import ast
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = ROOT / "docker/app/haproxy_admin"
ROUTES_PATH = APP_ROOT / "routes_updates.py"
CLIENT_PATH = APP_ROOT / "updated_client.py"
TEMPLATE_PATH = APP_ROOT / "templates/system_updates.html"
JAVASCRIPT_PATH = APP_ROOT / "static/js/system_updates.js"
NAVIGATION_PATH = APP_ROOT / "templates/_haproxy_nav.html"
SECURITY_PATH = APP_ROOT / "security.py"
INITIALIZER_PATH = APP_ROOT / "__init__.py"
RU_TRANSLATIONS_PATH = APP_ROOT / "translations/ru.json"

ROUTES_SOURCE = ROUTES_PATH.read_text(encoding="utf-8")
CLIENT_SOURCE = CLIENT_PATH.read_text(encoding="utf-8")
TEMPLATE = TEMPLATE_PATH.read_text(encoding="utf-8")
JAVASCRIPT = JAVASCRIPT_PATH.read_text(encoding="utf-8")


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class AbortCalled(RuntimeError):
    def __init__(self, status: int, description: str | None):
        super().__init__(f"abort {status}: {description}")
        self.status = status
        self.description = description


class FakeBlueprint:
    def __init__(self, *_args, **_kwargs):
        pass

    @staticmethod
    def _decorator(*_args, **_kwargs):
        def decorate(function):
            return function

        return decorate

    get = _decorator
    post = _decorator


def load_routes_module():
    package_name = "easy_ha_update_routes_test"
    package = types.ModuleType(package_name)
    package.__path__ = [str(APP_ROOT)]
    request = types.SimpleNamespace(args={}, get_json=lambda silent=True: None)

    def abort(status, description=None):
        raise AbortCalled(status, description)

    flask = types.ModuleType("flask")
    flask.Blueprint = FakeBlueprint
    flask.abort = abort
    flask.g = types.SimpleNamespace(remote_user="test-admin")
    flask.jsonify = lambda payload: payload
    flask.render_template = lambda *args, **kwargs: (args, kwargs)
    flask.request = request

    config_service = types.ModuleType(
        f"{package_name}.services_haproxy_config"
    )
    config_service.get_haproxy_configuration_state = mock.Mock(
        return_value={"ok": True, "state": "clean"}
    )
    modules = {
        package_name: package,
        "flask": flask,
        f"{package_name}.services_haproxy_config": config_service,
    }
    with mock.patch.dict(sys.modules, modules):
        client = load_module(f"{package_name}.updated_client", CLIENT_PATH)
        routes = load_module(f"{package_name}.routes_updates", ROUTES_PATH)
    return routes, request, client, config_service.get_haproxy_configuration_state


def load_security_module():
    package_name = "easy_ha_update_security_test"
    package = types.ModuleType(package_name)
    package.__path__ = []
    flask = types.ModuleType("flask")
    flask.request = types.SimpleNamespace(
        headers={}, method="GET", path="/", is_json=True
    )
    flask.g = types.SimpleNamespace()
    flask.jsonify = lambda payload: payload

    def abort(status, description=None):
        raise AbortCalled(status, description)

    flask.abort = abort
    i18n = types.ModuleType(f"{package_name}.i18n")
    i18n.translate = lambda value: value
    with mock.patch.dict(
        sys.modules,
        {
            package_name: package,
            "flask": flask,
            f"{package_name}.i18n": i18n,
        },
    ):
        security = load_module(f"{package_name}.security", SECURITY_PATH)
    return security, flask.request, flask.g


ROUTES, REQUEST, WEB_CLIENT, CONFIG_STATE = load_routes_module()


class UpdateWebSecurityBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.security, cls.request, cls.identity = load_security_module()

    def enforce(self):
        with mock.patch.dict(
            os.environ,
            {"HAPROXY_ADMIN_PROXY_SECRET": "test-proxy-secret"},
        ):
            return self.security.enforce_proxy_and_role()

    def test_every_update_path_requires_superadmin(self) -> None:
        self.assertIn("/system/updates", self.security.SUPERADMIN_PREFIXES)
        for path in (
            "/system/updates",
            "/system/updates/",
            "/system/updates/api/status",
            "/system/updates/api/check",
            "/system/updates/api/apply",
        ):
            with self.subTest(path=path):
                self.request.path = path
                self.request.method = "GET"
                self.request.is_json = path.endswith(("check", "apply"))
                self.request.headers = {
                    "X-Easy-HA-Proxy-Secret": "test-proxy-secret",
                    "Remote-User": "administrator",
                    "Remote-Groups": "admins",
                }
                if "/api/" in path:
                    response, status = self.enforce()
                    self.assertEqual(status, 403)
                    self.assertFalse(response["ok"])
                else:
                    with self.assertRaises(AbortCalled) as caught:
                        self.enforce()
                    self.assertEqual(caught.exception.status, 403)
                self.request.headers["Remote-Groups"] = "superadmin"
                self.assertIsNone(self.enforce())

    def test_system_update_api_errors_remain_json(self) -> None:
        security_source = SECURITY_PATH.read_text(encoding="utf-8")
        initializer = INITIALIZER_PATH.read_text(encoding="utf-8")
        self.assertIn('"/system/updates/api/"', security_source)
        # The initializer no longer carries the list itself: both of its
        # error handlers ask api_errors, which is where the prefixes live.
        api_errors = (APP_ROOT / "api_errors.py").read_text(encoding="utf-8")
        self.assertIn('"/system/updates/api/"', api_errors)
        self.assertIn("caller_parses_json", initializer)


class UpdateRouteContractTests(unittest.TestCase):
    def setUp(self) -> None:
        REQUEST.args = {}
        REQUEST.get_json = lambda silent=True: None
        CONFIG_STATE.reset_mock(return_value=True, side_effect=True)
        CONFIG_STATE.return_value = {"ok": True, "state": "clean"}

    def test_status_uses_only_the_fixed_status_action(self) -> None:
        with mock.patch.object(
            ROUTES,
            "updated_request",
            return_value={"ok": True, "jobs": []},
        ) as daemon:
            response, status = ROUTES.status_view()
        self.assertEqual(status, 200)
        self.assertTrue(response["ok"])
        daemon.assert_called_once_with({"action": "status"})

    def test_status_fetches_one_log_only_for_a_fixed_job_identifier(self) -> None:
        REQUEST.args = {"job_id": "A" * 32}
        with mock.patch.object(
            ROUTES,
            "updated_request",
            return_value={"ok": True, "jobs": []},
        ) as daemon:
            _response, status = ROUTES.status_view()
        self.assertEqual(status, 200)
        daemon.assert_called_once_with(
            {"action": "status", "job_id": "a" * 32}
        )

        REQUEST.args = {"job_id": "../job"}
        with self.assertRaises(AbortCalled):
            ROUTES.status_view()

    def test_check_accepts_only_optional_fixed_channels(self) -> None:
        for payload in (
            {},
            {"image_channel": "latest"},
            {"image_channel": "alpha"},
            {"source_channel": "github"},
            {"source_channel": "local"},
            {"image_channel": "latest", "source_channel": "local"},
        ):
            REQUEST.get_json = lambda silent=True, value=payload: dict(value)
            with self.subTest(payload=payload), mock.patch.object(
                ROUTES,
                "updated_request",
                return_value={"ok": True, "job_id": "a" * 32},
            ) as daemon:
                _response, status = ROUTES.start_check()
            self.assertEqual(status, 202)
            daemon.assert_called_once_with({"action": "start_check", **payload})

        for payload in (
            {"image_channel": "nightly"},
            {"image_channel": 1},
            {"source_channel": "gitlab"},
            {"source_channel": 1},
            {"command": "sh"},
        ):
            REQUEST.get_json = lambda silent=True, value=payload: value
            with self.subTest(payload=payload), self.assertRaises(AbortCalled):
                ROUTES.start_check()

    def test_save_channels_persists_only_fixed_channel_values(self) -> None:
        for payload in (
            {"source_channel": "github"},
            {"source_channel": "local", "image_channel": "latest"},
            {"image_channel": "alpha"},
        ):
            REQUEST.get_json = lambda silent=True, value=payload: dict(value)
            with self.subTest(payload=payload), mock.patch.object(
                ROUTES,
                "updated_request",
                return_value={"ok": True, "deployment": {}},
            ) as daemon:
                _response, status = ROUTES.save_channels()
            self.assertEqual(status, 200)
            daemon.assert_called_once_with({"action": "set_channels", **payload})

        for payload in (
            {},
            {"source_channel": "gitlab"},
            {"image_channel": "nightly"},
            {"command": "sh"},
        ):
            REQUEST.get_json = lambda silent=True, value=payload: value
            with self.subTest(payload=payload), self.assertRaises(AbortCalled):
                ROUTES.save_channels()

    def test_apply_has_a_fixed_component_allowlist_and_exact_confirmation(self) -> None:
        base = {
            "plan_id": "a" * 32,
            "components": ["admin-container", "os"],
            "confirmation": "UPDATE",
        }
        for payload in (
            {**base, "confirmation": "update"},
            {**base, "components": []},
            {**base, "components": ["admin-container", "admin-container"]},
            {**base, "components": ["../../bin/sh"]},
            {**base, "plan_id": "../plan"},
            {**base, "command": "id"},
        ):
            REQUEST.get_json = lambda silent=True, value=payload: value
            with self.subTest(payload=payload), self.assertRaises(AbortCalled):
                ROUTES.start_apply()

        REQUEST.get_json = lambda silent=True: dict(base)
        with mock.patch.object(
            ROUTES,
            "updated_request",
            return_value={"ok": True, "job_id": "b" * 32},
        ) as daemon:
            response, status = ROUTES.start_apply()
        self.assertEqual(status, 202)
        self.assertTrue(response["ok"])
        daemon.assert_called_once_with(
            {
                "action": "start_apply",
                "plan_id": "a" * 32,
                "components": ["admin-container", "os"],
                "confirmation": "UPDATE",
            }
        )
        CONFIG_STATE.assert_not_called()

    def test_source_and_host_updates_require_clean_haproxy_configuration(self) -> None:
        for component in ("all", "services", "daemons"):
            REQUEST.get_json = lambda silent=True, selected=component: {
                "plan_id": "a" * 32,
                "components": [selected],
                "confirmation": "UPDATE",
            }
            CONFIG_STATE.return_value = {"ok": True, "state": "unapplied"}
            with self.subTest(component=component), mock.patch.object(
                ROUTES, "updated_request"
            ) as daemon:
                response, status = ROUTES.start_apply()
            self.assertEqual(status, 409)
            self.assertEqual(response["error_code"], "configuration_not_clean")
            self.assertEqual(response["configuration_state"], "unapplied")
            daemon.assert_not_called()

    def test_unavailable_config_state_fails_closed_for_sensitive_components(self) -> None:
        REQUEST.get_json = lambda silent=True: {
            "plan_id": "a" * 32,
            "components": ["services"],
            "confirmation": "UPDATE",
        }
        CONFIG_STATE.side_effect = OSError("socket missing")
        with mock.patch.object(ROUTES, "updated_request") as daemon:
            response, status = ROUTES.start_apply()
        self.assertEqual(status, 503)
        self.assertEqual(response["error_code"], "configuration_state_unavailable")
        self.assertNotIn("socket missing", repr(response))
        daemon.assert_not_called()

    def test_daemon_errors_have_bounded_http_statuses(self) -> None:
        cases = {
            "busy": 409,
            "config_pending": 409,
            "stale_plan": 409,
            "not_found": 404,
            "invalid": 400,
            "internal": 502,
        }
        for code, expected in cases.items():
            with self.subTest(code=code):
                response, status = ROUTES._daemon_response(
                    {"ok": False, "error_code": code, "error": "failed"}
                )
                self.assertEqual(status, expected)
                self.assertFalse(response["ok"])


class UpdatedClientTests(unittest.TestCase):
    def test_client_sends_one_bounded_json_line(self) -> None:
        sent = []

        class WorkingSocket:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def settimeout(self, _timeout):
                pass

            def connect(self, _path):
                pass

            def sendall(self, payload):
                sent.append(payload)

            def recv(self, _size):
                return b'{"ok":true}\n'

        payload = {"action": "start_apply", "confirmation": "UPDATE"}
        with mock.patch.object(
            WEB_CLIENT.socket,
            "socket",
            return_value=WorkingSocket(),
        ):
            result = WEB_CLIENT.updated_request(payload)
        self.assertTrue(result["ok"])
        self.assertTrue(sent[0].endswith(b"\n"))
        self.assertEqual(json.loads(sent[0]), payload)

    def test_client_does_not_log_requests(self) -> None:
        tree = ast.parse(CLIENT_SOURCE)
        self.assertNotIn("logging", {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        })
        self.assertNotIn("print(", CLIENT_SOURCE)


class UpdateWebUiTests(unittest.TestCase):
    def test_page_is_registered_and_linked_from_navigation(self) -> None:
        initializer = INITIALIZER_PATH.read_text(encoding="utf-8")
        navigation = NAVIGATION_PATH.read_text(encoding="utf-8")
        self.assertIn("bp_system_updates", initializer)
        self.assertIn("app.register_blueprint(bp_system_updates)", initializer)
        self.assertIn("system_updates.page", navigation)

    def test_ui_checks_first_then_submits_a_fixed_plan(self) -> None:
        self.assertIn('data-check-url=', TEMPLATE)
        self.assertIn('data-apply-url=', TEMPLATE)
        self.assertIn('id="updates-components-body"', TEMPLATE)
        self.assertIn('id="updates-confirmation"', TEMPLATE)
        self.assertIn('placeholder="UPDATE"', TEMPLATE)
        self.assertIn("async function checkUpdates()", JAVASCRIPT)
        self.assertIn("async function applyUpdates()", JAVASCRIPT)
        self.assertIn("plan_id: currentPlan.id", JAVASCRIPT)
        self.assertIn('confirmation: "UPDATE"', JAVASCRIPT)
        self.assertNotIn("/bin/sh", JAVASCRIPT)
        self.assertIn(
            "No actionable updates were found, but some components could not be checked.",
            JAVASCRIPT,
        )

    def test_full_source_selection_supersedes_overlapping_components(self) -> None:
        self.assertIn('"services", "daemons", "authelia-container", "admin-container"', JAVASCRIPT)
        self.assertIn('["source", "all"].includes(changedId)', JAVASCRIPT)
        self.assertIn('box.dataset.updateComponent === "os"', JAVASCRIPT)

    def test_self_update_reconnects_and_progress_is_durable(self) -> None:
        self.assertIn("schedulePoll(active || pendingStart ? 1500 : 10000)", JAVASCRIPT)
        self.assertIn("Reconnecting automatically…", JAVASCRIPT)
        self.assertIn("markConnectionRestored()", JAVASCRIPT)
        self.assertIn("connectionFailureCount", JAVASCRIPT)
        self.assertIn('window.addEventListener("online"', JAVASCRIPT)
        self.assertIn('document.addEventListener("visibilitychange"', JAVASCRIPT)
        self.assertIn("window.location.reload()", JAVASCRIPT)
        self.assertIn("payload.active_job", JAVASCRIPT)
        self.assertIn("payload.jobs", JAVASCRIPT)
        self.assertIn("easy_ha_proxy_update_job", JAVASCRIPT)
        self.assertIn('applied.includes("all")', JAVASCRIPT)

    def test_interrupted_start_is_reconciled_without_reposting_the_mutation(self) -> None:
        self.assertIn("easy_ha_proxy_update_pending_start", JAVASCRIPT)
        self.assertIn('beginPendingStart("check", [], "")', JAVASCRIPT)
        self.assertIn('beginPendingStart("apply", components, currentPlan.id)', JAVASCRIPT)
        self.assertIn("reconcilePendingStart(jobs)", JAVASCRIPT)
        self.assertIn("pendingStartMatches", JAVASCRIPT)
        self.assertIn("knownJobIds", JAVASCRIPT)
        self.assertIn("START_RECONCILE_GRACE_MS", JAVASCRIPT)
        self.assertIn("Checking whether the job was accepted", JAVASCRIPT)
        # An ambiguous POST is reconciled through the read-only status endpoint;
        # neither mutation is ever submitted a second time automatically.
        self.assertEqual(JAVASCRIPT.count("postJson(endpoints.check"), 1)
        self.assertEqual(JAVASCRIPT.count("postJson(endpoints.apply"), 1)

    def test_ui_matches_broker_plan_channels_and_job_log_shape(self) -> None:
        self.assertIn('payload.plan && typeof payload.plan === "object"', JAVASCRIPT)
        self.assertIn("payload.deployment || payload.channels || plan", JAVASCRIPT)
        self.assertIn("output.log, output.stdout, output.stderr", JAVASCRIPT)
        self.assertIn("?job_id=${encodeURIComponent(row.dataset.updateJob)}", JAVASCRIPT)
        self.assertIn("relevant?.result?.recheck_error", JAVASCRIPT)
        self.assertIn("renderPlan(null);", JAVASCRIPT)

    def test_raw_versions_and_job_logs_are_not_translated(self) -> None:
        for element_id in ("updates-job-log", "updates-confirmation"):
            tag = re.search(rf'<[^>]+id="{element_id}"[^>]*>', TEMPLATE)
            self.assertIsNotNone(tag, element_id)
            self.assertIn("notranslate", tag.group(0))
            self.assertIn('translate="no"', tag.group(0))
            self.assertIn("data-i18n-skip", tag.group(0))
        self.assertIn('class="mono notranslate" translate="no" data-i18n-skip', JAVASCRIPT)
        # The job log must be rendered with textContent (never innerHTML).
        self.assertIn('const log = byId("updates-job-log");', JAVASCRIPT)
        self.assertIn("log.textContent = next;", JAVASCRIPT)
        self.assertIn(
            '<td class="notranslate" translate="no" data-i18n-skip>${escape(String(result))}</td>',
            JAVASCRIPT,
        )
        self.assertIn('element.setAttribute("data-i18n-skip", "")', JAVASCRIPT)

    def test_english_is_source_and_russian_catalog_covers_update_workflow(self) -> None:
        self.assertIsNone(re.search(r"[А-Яа-яЁё]", TEMPLATE))
        self.assertIsNone(re.search(r"[А-Яа-яЁё]", JAVASCRIPT))
        messages = json.loads(RU_TRANSLATIONS_PATH.read_text(encoding="utf-8"))[
            "messages"
        ]
        for key in (
            "Software updates",
            "Check for updates",
            "Apply selected updates",
            "Web application",
            "Operating-system packages",
            "The update service is temporarily unavailable. Reconnecting…",
            "The update service is temporarily unavailable. Reconnecting automatically…",
            "Connection restored. Software-update service is ready.",
            "The connection was interrupted while starting the update. Checking whether the job was accepted…",
            "Server reboot required",
        ):
            with self.subTest(key=key):
                self.assertTrue(messages.get(key))


if __name__ == "__main__":
    unittest.main()
