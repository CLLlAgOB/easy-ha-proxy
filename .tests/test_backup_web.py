"""Focused security regressions for the full-backup web workflow."""

from __future__ import annotations

import ast
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import sys
import tempfile
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = ROOT / "docker/app/haproxy_admin"
ROUTES_PATH = APP_ROOT / "routes_backup.py"
CLIENT_PATH = APP_ROOT / "backupd_client.py"
TEMPLATE_PATH = APP_ROOT / "templates/system_backups.html"
JAVASCRIPT_PATH = APP_ROOT / "static/js/system_backups.js"
SECURITY_JAVASCRIPT_PATH = APP_ROOT / "static/js/security.js"
BASE_TEMPLATE_PATH = APP_ROOT / "templates/base.html"
RU_TRANSLATIONS_PATH = APP_ROOT / "translations/ru.json"

ROUTES_SOURCE = ROUTES_PATH.read_text(encoding="utf-8")
CLIENT_SOURCE = CLIENT_PATH.read_text(encoding="utf-8")
TEMPLATE = TEMPLATE_PATH.read_text(encoding="utf-8")
JAVASCRIPT = JAVASCRIPT_PATH.read_text(encoding="utf-8")
SECURITY_JAVASCRIPT = SECURITY_JAVASCRIPT_PATH.read_text(encoding="utf-8")
BASE_TEMPLATE = BASE_TEMPLATE_PATH.read_text(encoding="utf-8")


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
    route = _decorator


def load_routes_module():
    package_name = "easy_ha_backup_routes_test"
    package = types.ModuleType(package_name)
    package.__path__ = [str(APP_ROOT)]

    request = types.SimpleNamespace(
        args={},
        content_length=None,
        max_content_length=None,
        mimetype="",
        stream=None,
        get_json=lambda silent=True: None,
    )

    def abort(status, description=None):
        raise AbortCalled(status, description)

    def send_file(path, **kwargs):
        return {"path": Path(path), **kwargs}

    flask = types.ModuleType("flask")
    flask.Blueprint = FakeBlueprint
    flask.abort = abort
    flask.jsonify = lambda payload: payload
    flask.render_template = lambda *args, **kwargs: (args, kwargs)
    flask.request = request
    flask.send_file = send_file

    modules = {package_name: package, "flask": flask}
    with mock.patch.dict(sys.modules, modules):
        client = load_module(
            f"{package_name}.backupd_client",
            CLIENT_PATH,
        )
        routes = load_module(
            f"{package_name}.routes_backup",
            ROUTES_PATH,
        )
    return routes, request, client


def load_security_module():
    package_name = "easy_ha_backup_security_test"
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
    modules = {
        package_name: package,
        f"{package_name}.i18n": i18n,
        "flask": flask,
    }
    with mock.patch.dict(sys.modules, modules):
        security = load_module(
            f"{package_name}.security",
            APP_ROOT / "security.py",
        )
    return security, flask.request, flask.g


ROUTES, REQUEST, WEB_CLIENT = load_routes_module()


class BackupWebSecurityBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.security, cls.request, cls.identity = load_security_module()

    def enforce(self):
        with mock.patch.dict(
            os.environ,
            {"HAPROXY_ADMIN_PROXY_SECRET": "test-proxy-secret"},
        ):
            return self.security.enforce_proxy_and_role()

    def test_every_backup_path_requires_superadmin(self) -> None:
        self.assertIn("/system/backups", self.security.SUPERADMIN_PREFIXES)
        for path in (
            "/system/backups",
            "/system/backups/",
            "/system/backups/api/status",
            "/system/backups/api/backups/" + "c" * 32 + "/stage",
            "/system/backups/api/uploads/" + "a" * 32 + "/inspect",
            "/system/backups/download/" + "b" * 32,
        ):
            with self.subTest(path=path):
                self.request.path = path
                self.request.method = "GET"
                self.request.is_json = True
                self.request.headers = {
                    "X-Easy-HA-Proxy-Secret": "test-proxy-secret",
                    "Remote-User": "administrator",
                    "Remote-Groups": "admins",
                }
                response, status = self.enforce()
                self.assertEqual(status, 403)
                self.assertFalse(response["ok"])

                self.request.headers["Remote-Groups"] = "superadmin"
                self.assertIsNone(self.enforce())
                self.assertTrue(self.identity.is_superadmin)


class StreamingUploadAndDownloadTests(unittest.TestCase):
    def setUp(self) -> None:
        REQUEST.args = {}
        REQUEST.content_length = None
        REQUEST.max_content_length = None
        REQUEST.mimetype = ""
        REQUEST.stream = None
        REQUEST.get_json = lambda silent=True: None

    def test_upload_requires_content_length(self) -> None:
        response, status = ROUTES.upload_archive()
        self.assertEqual(status, 411)
        self.assertFalse(response["ok"])
        self.assertEqual(REQUEST.max_content_length, ROUTES.MAX_UPLOAD_BYTES)

    def test_upload_streams_bounded_chunks_to_nofollow_temp_then_renames(self) -> None:
        class ChunkStream:
            def __init__(self, chunks):
                self.chunks = list(chunks)
                self.read_sizes = []

            def read(self, size):
                self.read_sizes.append(size)
                return self.chunks.pop(0) if self.chunks else b""

        upload_id = "a" * 32
        body = ChunkStream([b"first", b"second"])
        REQUEST.content_length = 11
        REQUEST.mimetype = "application/octet-stream"
        REQUEST.stream = body

        with tempfile.TemporaryDirectory() as temporary:
            upload_root = Path(temporary) / "dedicated-spool" / "uploads"
            upload_root.mkdir(parents=True)
            captured_flags = []
            replacements = []
            real_open = os.open
            real_replace = os.replace

            def checked_open(path, flags, mode=0o777):
                captured_flags.append(flags)
                return real_open(path, flags, mode)

            def checked_replace(source, destination):
                replacements.append((Path(source), Path(destination)))
                return real_replace(source, destination)

            with (
                mock.patch.object(ROUTES, "UPLOAD_ROOT", upload_root),
                mock.patch.object(ROUTES, "MAX_UPLOAD_BYTES", 1024 * 1024),
                mock.patch.object(
                    ROUTES.shutil,
                    "disk_usage",
                    return_value=types.SimpleNamespace(free=4 * 1024**3),
                ),
                mock.patch.object(
                    ROUTES.uuid,
                    "uuid4",
                    return_value=types.SimpleNamespace(hex=upload_id),
                ),
                mock.patch.object(ROUTES.os, "open", side_effect=checked_open),
                mock.patch.object(ROUTES.os, "replace", side_effect=checked_replace),
            ):
                response, status = ROUTES.upload_archive()

            self.assertEqual(status, 201)
            self.assertEqual(response["upload_id"], upload_id)
            self.assertEqual(response["size"], 11)
            self.assertEqual(
                (upload_root / f"{upload_id}.tar.gz.enc").read_bytes(),
                b"firstsecond",
            )
            self.assertTrue(body.read_sizes)
            self.assertTrue(all(size == 1024 * 1024 for size in body.read_sizes))
            self.assertEqual(REQUEST.max_content_length, 1024 * 1024)
            self.assertEqual(len(replacements), 1)
            self.assertEqual(
                replacements[0][1],
                upload_root / f"{upload_id}.tar.gz.enc",
            )
            self.assertTrue(captured_flags[0] & os.O_EXCL)
            if hasattr(os, "O_NOFOLLOW"):
                self.assertTrue(captured_flags[0] & os.O_NOFOLLOW)

    def test_upload_code_never_uses_unbounded_flask_body_helpers(self) -> None:
        tree = ast.parse(ROUTES_SOURCE)
        upload = next(
            node
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == "upload_archive"
        )
        attributes = {
            node.attr
            for node in ast.walk(upload)
            if isinstance(node, ast.Attribute)
        }
        self.assertIn("stream", attributes)
        self.assertIn("max_content_length", attributes)
        self.assertIn("content_length", attributes)
        self.assertNotIn("data", attributes)
        self.assertNotIn("files", attributes)
        self.assertNotIn("get_data", attributes)
        self.assertIn("os.replace(temporary, destination)", ROUTES_SOURCE)

    def test_spools_are_dedicated_and_identifiers_are_fixed(self) -> None:
        self.assertEqual(ROUTES.UPLOAD_ROOT.parent, ROUTES.BACKUP_EXCHANGE_ROOT)
        self.assertEqual(ROUTES.DOWNLOAD_ROOT.parent, ROUTES.BACKUP_EXCHANGE_ROOT)
        self.assertEqual(ROUTES.UPLOAD_ROOT.name, "uploads")
        self.assertEqual(ROUTES.DOWNLOAD_ROOT.name, "backups")
        self.assertNotEqual(ROUTES.BACKUP_EXCHANGE_ROOT, Path("/tmp"))

        self.assertEqual(ROUTES._identifier("A" * 32, "test"), "a" * 32)
        for invalid in (
            "",
            "a" * 31,
            "a" * 33,
            "../" + "a" * 32,
            "550e8400-e29b-41d4-a716-446655440000",
            "g" * 32,
        ):
            with self.subTest(invalid=invalid), self.assertRaises(AbortCalled):
                ROUTES._identifier(invalid, "test")

    def test_download_resolves_regular_single_link_and_streams_conditionally(self) -> None:
        backup_id = "b" * 32
        filename = f"{backup_id}.tar.gz.enc"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "backups"
            root.mkdir(parents=True)
            archive = root / filename
            archive.write_bytes(b"encrypted")
            with mock.patch.object(ROUTES, "DOWNLOAD_ROOT", root):
                resolved, safe_name = ROUTES._download_path(
                    backup_id,
                    {"archive_name": filename},
                    False,
                )
            self.assertEqual(resolved, archive.resolve())
            self.assertEqual(safe_name, filename)

            with (
                mock.patch.object(
                    ROUTES,
                    "_backup_record",
                    return_value={"archive_name": filename},
                ),
                mock.patch.object(
                    ROUTES,
                    "_download_path",
                    return_value=(archive, filename),
                ),
            ):
                response = ROUTES.download_backup(backup_id)
            self.assertEqual(response["path"], archive)
            self.assertTrue(response["as_attachment"])
            self.assertTrue(response["conditional"])
            self.assertEqual(response["download_name"], filename)
            self.assertEqual(response["max_age"], 0)

    def test_download_rejects_unsafe_names_symlinks_and_hardlinks(self) -> None:
        backup_id = "c" * 32
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "backups"
            root.mkdir(parents=True)
            archive = root / f"{backup_id}.tar.gz.enc"
            archive.write_bytes(b"encrypted")
            symlink = root / f"{backup_id}.symlink.enc"
            symlink.symlink_to(archive)
            hardlink = root / f"{backup_id}.hardlink.enc"
            os.link(archive, hardlink)

            with mock.patch.object(ROUTES, "DOWNLOAD_ROOT", root):
                for name in ("../backup.enc", "/etc/shadow", "bad name.enc"):
                    with self.subTest(name=name), self.assertRaises(AbortCalled):
                        ROUTES._download_path(
                            backup_id,
                            {"archive_name": name},
                            False,
                        )
                for name in (
                    f"{backup_id}.symlink.enc",
                    f"{backup_id}.tar.gz.enc",
                    f"{backup_id}.hardlink.enc",
                ):
                    with self.subTest(name=name), self.assertRaises(AbortCalled):
                        ROUTES._download_path(
                            backup_id,
                            {"archive_name": name},
                            False,
                        )


class BackupDaemonClientTests(unittest.TestCase):
    def test_request_and_response_are_bounded(self) -> None:
        self.assertLessEqual(WEB_CLIENT.MAX_REQUEST_BYTES, 64 * 1024)
        self.assertLessEqual(WEB_CLIENT.MAX_RESPONSE_BYTES, 4 * 1024 * 1024)
        with self.assertRaises(WEB_CLIENT.BackupdError):
            WEB_CLIENT.backupd_request(
                {"passphrase": "x" * WEB_CLIENT.MAX_REQUEST_BYTES}
            )

        class OversizedSocket:
            def __init__(self):
                self.remaining = WEB_CLIENT.MAX_RESPONSE_BYTES // (64 * 1024) + 2

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def settimeout(self, _timeout):
                pass

            def connect(self, _path):
                pass

            def sendall(self, _payload):
                pass

            def recv(self, _size):
                if self.remaining <= 0:
                    return b""
                self.remaining -= 1
                return b"x" * (64 * 1024)

        with (
            mock.patch.object(WEB_CLIENT.socket, "socket", return_value=OversizedSocket()),
            self.assertRaisesRegex(WEB_CLIENT.BackupdError, "response is too large"),
        ):
            WEB_CLIENT.backupd_request({"action": "status"})

    def test_client_sends_compact_json_and_never_echoes_secret_on_transport_error(self) -> None:
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

        payload = {"action": "start_backup", "passphrase": "very-secret-value"}
        with mock.patch.object(
            WEB_CLIENT.socket,
            "socket",
            return_value=WorkingSocket(),
        ):
            result = WEB_CLIENT.backupd_request(payload)
        self.assertTrue(result["ok"])
        self.assertTrue(sent[0].endswith(b"\n"))
        self.assertEqual(json.loads(sent[0]), payload)
        self.assertNotIn(b" ", sent[0])

        class FailingSocket(WorkingSocket):
            def connect(self, _path):
                raise OSError("unavailable")

        with mock.patch.object(
            WEB_CLIENT.socket,
            "socket",
            return_value=FailingSocket(),
        ):
            with self.assertRaises(WEB_CLIENT.BackupdError) as caught:
                WEB_CLIENT.backupd_request(payload)
        self.assertNotIn("very-secret-value", str(caught.exception))

    def test_client_has_no_logging_or_print_calls(self) -> None:
        tree = ast.parse(CLIENT_SOURCE)
        imported = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        self.assertNotIn("logging", imported)
        forbidden_calls = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name) and node.func.id == "print":
                forbidden_calls.append("print")
            if isinstance(node.func, ast.Attribute) and node.func.attr in {
                "debug",
                "info",
                "warning",
                "error",
                "exception",
                "log",
            }:
                forbidden_calls.append(node.func.attr)
        self.assertEqual(forbidden_calls, [])


class RestoreContractTests(unittest.TestCase):
    def setUp(self) -> None:
        REQUEST.get_json = lambda silent=True: None

    def test_restore_requires_verified_job_fixed_ids_and_exact_word(self) -> None:
        base = {
            "upload_id": "a" * 32,
            "inspection_job_id": "b" * 32,
            "passphrase": "correct horse battery",
            "restore_ssh": False,
            "confirmation": "RESTORE",
        }

        for invalid_confirmation in ("", "restore", "RESTORE ", " RESTORE"):
            REQUEST.get_json = lambda silent=True, value={
                **base,
                "confirmation": invalid_confirmation,
            }: value
            with self.subTest(value=invalid_confirmation), self.assertRaises(AbortCalled):
                ROUTES.start_restore()

        for key in ("upload_id", "inspection_job_id"):
            REQUEST.get_json = lambda silent=True, value={
                **base,
                key: "../invalid",
            }: value
            with self.subTest(key=key), self.assertRaises(AbortCalled):
                ROUTES.start_restore()

        REQUEST.get_json = lambda silent=True: dict(base)
        with mock.patch.object(
            ROUTES,
            "backupd_request",
            return_value={"ok": True, "job_id": "c" * 32},
        ) as daemon:
            response, status = ROUTES.start_restore()
        self.assertEqual(status, 202)
        self.assertTrue(response["ok"])
        sent = daemon.call_args.args[0]
        self.assertEqual(sent["upload_id"], base["upload_id"])
        self.assertEqual(sent["inspection_job_id"], base["inspection_job_id"])
        self.assertEqual(sent["confirmation"], "RESTORE")

    def test_routes_keep_inspection_and_restore_as_separate_actions(self) -> None:
        self.assertIn('@bp_system_backups.post("/api/backups/<backup_id>/stage")', ROUTES_SOURCE)
        self.assertIn('@bp_system_backups.post("/api/uploads/<upload_id>/inspect")', ROUTES_SOURCE)
        self.assertIn('@bp_system_backups.post("/api/jobs/restore")', ROUTES_SOURCE)
        self.assertIn('"action": "stage_backup"', ROUTES_SOURCE)
        self.assertIn('"action": "start_inspect"', ROUTES_SOURCE)
        self.assertIn('"action": "start_restore"', ROUTES_SOURCE)
        self.assertIn('"inspection_job_id"', ROUTES_SOURCE)
        self.assertNotIn("csrf.exempt", ROUTES_SOURCE)

    def test_stored_backup_stage_uses_a_fixed_id_and_never_sends_a_passphrase(self) -> None:
        backup_id = "a" * 32
        upload_id = "b" * 32
        with mock.patch.object(
            ROUTES,
            "backupd_request",
            return_value={"ok": True, "upload_id": upload_id},
        ) as daemon:
            response, status = ROUTES.stage_backup(backup_id.upper())

        self.assertEqual(status, 200)
        self.assertEqual(response["upload_id"], upload_id)
        daemon.assert_called_once_with(
            {"action": "stage_backup", "backup_id": backup_id},
            timeout=10.0,
        )
        self.assertNotIn("passphrase", daemon.call_args.args[0])

        for invalid_id in ("../backup", "a" * 31, "g" * 32):
            with (
                self.subTest(invalid_id=invalid_id),
                mock.patch.object(ROUTES, "backupd_request") as invalid_daemon,
                self.assertRaises(AbortCalled),
            ):
                ROUTES.stage_backup(invalid_id)
            invalid_daemon.assert_not_called()


class BackupWebUITests(unittest.TestCase):
    @staticmethod
    def input_tag(element_id: str) -> str:
        match = re.search(
            rf'<input\b[^>]*\bid="{re.escape(element_id)}"[^>]*>',
            TEMPLATE,
        )
        if match is None:
            raise AssertionError(f"missing input {element_id}")
        return match.group(0)

    def test_passwords_are_password_fields_and_never_persisted_in_browser_storage(self) -> None:
        for element_id in (
            "backup-passphrase",
            "backup-restore-passphrase",
        ):
            with self.subTest(element_id=element_id):
                tag = self.input_tag(element_id)
                self.assertIn('type="password"', tag)
                self.assertNotRegex(tag, r"\svalue=")
                self.assertIn("autocomplete=", tag)

        self.assertNotIn("localStorage", JAVASCRIPT)
        # sessionStorage is allowed only through the storageGet/storageSet
        # helpers and only for job identifiers and UI state, never secrets.
        raw_uses = re.findall(r"window\.sessionStorage\.\w+\([^)]*\)", JAVASCRIPT)
        self.assertEqual(
            sorted(set(raw_uses)),
            [
                "window.sessionStorage.getItem(key)",
                "window.sessionStorage.removeItem(key)",
                "window.sessionStorage.setItem(key, value)",
            ],
        )
        storage_keys = set(
            re.findall(r"storage(?:Get|Set)\(\s*([A-Z_]+)", JAVASCRIPT)
        )
        self.assertEqual(
            storage_keys,
            {
                "OPERATION_JOB_KEY",
                "INSPECTION_JOB_KEY",
                "SELECTED_JOB_KEY",
                "LOG_OPEN_KEY",
            },
        )
        self.assertNotRegex(JAVASCRIPT, r"storageSet\([^)]*[Pp]assphrase")
        self.assertIn('byId("backup-restore-passphrase").value = ""', JAVASCRIPT)
        self.assertIn("clearPasswords();", JAVASCRIPT)

    def test_ui_is_two_step_and_requires_explicit_replace_confirmation(self) -> None:
        self.assertIn("async function uploadAndInspect", JAVASCRIPT)
        self.assertIn("const inspection = await postJson(inspectUrl, {passphrase})", JAVASCRIPT)
        self.assertIn("currentInspectionJobId = inspection.job_id", JAVASCRIPT)
        self.assertIn("inspection_job_id: currentInspectionJobId", JAVASCRIPT)
        self.assertIn('confirmation: "RESTORE"', JAVASCRIPT)
        self.assertIn('id="backup-replace-confirm"', TEMPLATE)
        self.assertIn('id="backup-restore-confirmation"', TEMPLATE)
        self.assertIn('placeholder="RESTORE"', TEMPLATE)
        self.assertIn('payload["confirmation"] != "RESTORE"', ROUTES_SOURCE)

    def test_stored_backup_restore_stages_without_a_secret_then_uses_normal_inspection(self) -> None:
        self.assertIn("data-stage-url-template=", TEMPLATE)
        self.assertIn("data-restore-backup=", JAVASCRIPT)
        self.assertIn('t("Restore")', JAVASCRIPT)
        self.assertIn("async function stageStoredBackup", JAVASCRIPT)
        stage_source = JAVASCRIPT.split("async function stageStoredBackup", 1)[1].split(
            "async function uploadAndInspect", 1
        )[0]
        self.assertIn("const staged = await postJson(stageUrl, {});", stage_source)
        self.assertNotIn("postJson(stageUrl, {passphrase", stage_source)
        self.assertIn("fileInput.required = !stagedBackupId;", JAVASCRIPT)
        self.assertIn('const useStoredBackup = Boolean(stagedBackupId && currentUploadId);', JAVASCRIPT)
        self.assertIn("const inspection = await postJson(inspectUrl, {passphrase});", JAVASCRIPT)
        self.assertIn("function adoptInspection(job)", JAVASCRIPT)
        self.assertIn("function showJob(job)", JAVASCRIPT)
        self.assertIn("function resetRestoreConfirmation()", JAVASCRIPT)
        self.assertIn('byId("backup-replace-confirm").checked = false;', JAVASCRIPT)
        self.assertIn('byId("backup-restore-confirmation").value = "";', JAVASCRIPT)
        self.assertIn(
            "if ((job.operation === \"inspect\" || job.action === \"inspect\") && jobState(job) === \"completed\" && manifest)",
            JAVASCRIPT,
        )
        self.assertIn(
            "adoptInspection(jobs.find((job) => jobId(job) === currentInspectionJobId))",
            JAVASCRIPT,
        )
        self.assertIn("showJob(payload.job || (payload.jobs || [])[0] || payload)", JAVASCRIPT)

        messages = json.loads(RU_TRANSLATIONS_PATH.read_text(encoding="utf-8"))["messages"]
        for key in (
            "Restore",
            "Verify stored backup",
            "Staging stored backup…",
            "Stored backup staged. Enter its passphrase and click Verify stored backup.",
            "Verifying stored backup…",
            "interrupted",
        ):
            with self.subTest(key=key):
                self.assertTrue(messages.get(key))

    def test_interrupted_jobs_are_terminal(self) -> None:
        terminal_state_source = re.search(
            r"const terminalStates = new Set\(\[(.*?)\]\);",
            JAVASCRIPT,
        )
        self.assertIsNotNone(terminal_state_source)
        self.assertIn('"interrupted"', terminal_state_source.group(1))

    def test_mutating_requests_use_shared_csrf_fetch_wrapper(self) -> None:
        self.assertIn("const response = await fetch(url, options || {});", JAVASCRIPT)
        self.assertNotIn("XMLHttpRequest", JAVASCRIPT)
        self.assertIn('headers.set("X-CSRFToken", token())', SECURITY_JAVASCRIPT)
        self.assertIn(
            "![\"GET\", \"HEAD\", \"OPTIONS\", \"TRACE\"].includes(method)",
            SECURITY_JAVASCRIPT,
        )
        self.assertIn("filename='js/security.js'", BASE_TEMPLATE)

    def test_status_polling_recovers_after_expected_disconnects(self) -> None:
        self.assertIn("async function refreshStatus", JAVASCRIPT)
        self.assertIn("schedulePoll(active ? 1800 : 10000)", JAVASCRIPT)
        self.assertIn("schedulePoll(2500)", JAVASCRIPT)
        self.assertIn("window.setTimeout(() => refreshStatus({quiet: true}), delay)", JAVASCRIPT)
        self.assertRegex(JAVASCRIPT.rstrip(), r"refreshStatus\(\);\s*\}\)\(\);$")
        self.assertIn("Temporary disconnects are expected", JAVASCRIPT)

    def test_started_backup_and_restore_jobs_report_their_terminal_result(self) -> None:
        self.assertIn(
            'let currentOperationJobId = storageGet(OPERATION_JOB_KEY) || "";',
            JAVASCRIPT,
        )
        self.assertIn("function showOperationResult(job)", JAVASCRIPT)
        self.assertIn(
            "jobs.find((job) => jobId(job) === currentOperationJobId)",
            JAVASCRIPT,
        )
        self.assertIn("Backup completed successfully.", JAVASCRIPT)
        self.assertIn("Restore completed successfully.", JAVASCRIPT)

    def test_english_is_the_source_and_technical_job_output_is_not_translated(self) -> None:
        self.assertIsNone(re.search(r"[А-Яа-яЁё]", TEMPLATE))
        self.assertIsNone(re.search(r"[А-Яа-яЁё]", JAVASCRIPT))
        log_tag = re.search(
            r'<pre\b[^>]*\bid="backup-job-log"[^>]*>',
            TEMPLATE,
        )
        self.assertIsNotNone(log_tag)
        tag = log_tag.group(0)
        self.assertIn("notranslate", tag)
        self.assertIn('translate="no"', tag)
        self.assertIn("data-i18n-skip", tag)
        self.assertIn('byId("backup-job-log").textContent', JAVASCRIPT)
        self.assertIn(
            '<td class="notranslate" translate="no" data-i18n-skip>${escape(result)}</td>',
            JAVASCRIPT,
        )
        self.assertIn(
            'setMessage(target, `${t("Operation failed")}: ${job.error || state}`, false, true)',
            JAVASCRIPT,
        )
        self.assertIn('element.setAttribute("data-i18n-skip", "")', JAVASCRIPT)


if __name__ == "__main__":
    unittest.main()
