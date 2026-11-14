"""The web application's two ways of talking to the host daemons.

Five clients carried their own copy of the socket code: backupd and the
update broker one line of JSON each way, alertd, metricsd and guardd JSON
over HTTP on a Unix socket -- guardd alone seven times over. The copies are
gone into daemon_transport.py, and these tests hold the behaviour the copies
had, against real sockets rather than by reading the source:

* a daemon that cannot be reached, or answers something unusable, is the
  client's own "unavailable" error, worded as before;
* a setting the daemon refuses comes back as ValueError with the daemon's
  reason -- the operator's typo, not an outage;
* the token travels only on calls that change something;
* a request is never repeated in an error, because it may carry a secret.
"""

from __future__ import annotations

import http.server
import importlib
import json
import os
from pathlib import Path
import socketserver
import sys
import tempfile
import threading
import types
import unittest


ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "docker/app/haproxy_admin"
PACKAGE = "daemon_transport_test_app"

try:
    import requests_unixsocket  # noqa: F401
    HAVE_UNIXSOCKET = True
except Exception:  # pylint: disable=broad-except
    HAVE_UNIXSOCKET = False


def load(name: str):
    if PACKAGE not in sys.modules:
        package = types.ModuleType(PACKAGE)
        package.__path__ = [str(APP)]
        sys.modules[PACKAGE] = package
    return importlib.import_module(f"{PACKAGE}.{name}")


transport = load("daemon_transport")


class Error(RuntimeError):
    pass


class SocketDirectory(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = os.path.join(directory.name, "daemon.sock")

    def serve(self, server_class, handler):
        server = server_class(self.path, handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server


# --------------------------------------------------------------- one JSON line

class LineServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    answer = b'{"ok": true}\n'
    received: list = []


class LineHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.server.received.append(self.rfile.readline())
        self.wfile.write(self.server.answer)


class OneJsonLine(SocketDirectory):
    def request(self, payload=None, **overrides):
        options = dict(service="full-backup", error=Error, timeout=5,
                       max_request=1024, max_response=4096)
        options.update(overrides)
        return transport.json_line_request(self.path, payload or {"action": "status"}, **options)

    def test_one_compact_line_each_way(self):
        server = self.serve(LineServer, LineHandler)
        server.received = []
        server.answer = b'{"ok": true, "state": "idle"}\n{"ignored": 1}\n'
        self.assertEqual(self.request({"action": "status", "n": 1}), {"ok": True, "state": "idle"})
        self.assertEqual(server.received, [b'{"action":"status","n":1}\n'])

    def test_what_is_not_an_answer(self):
        server = self.serve(LineServer, LineHandler)
        server.received = []
        cases = {
            b"": "the full-backup service returned an empty response",
            b"not json\n": "the full-backup service returned invalid JSON",
            b"[1, 2]\n": "the full-backup service returned an invalid response",
            b"x" * 5000: "the full-backup service response is too large",
        }
        for answer, message in cases.items():
            with self.subTest(message=message):
                server.answer = answer
                with self.assertRaises(Error) as caught:
                    self.request()
                self.assertEqual(str(caught.exception), message)

    def test_limits_and_absence_never_repeat_the_request(self):
        secret = {"action": "start_backup", "passphrase": "very-secret-value"}
        with self.assertRaises(Error) as caught:
            self.request(secret)  # nothing listens on the socket
        self.assertTrue(str(caught.exception).startswith("the full-backup service is unavailable: "))
        self.assertNotIn("very-secret-value", str(caught.exception))

        with self.assertRaises(Error) as caught:
            self.request({"passphrase": "x" * 2000})
        self.assertEqual(str(caught.exception), "the full-backup request is too large")

        with self.assertRaises(Error) as caught:
            transport.json_line_request("", {}, service="software-update", error=Error,
                                        timeout=1, max_request=10, max_response=10)
        self.assertEqual(str(caught.exception), "the software-update service socket is not configured")

    def test_the_two_clients_keep_their_wording_and_limits(self):
        backupd = load("backupd_client")
        updated = load("updated_client")
        for module, function, error, service in (
            (backupd, backupd.backupd_request, backupd.BackupdError, "full-backup"),
            (updated, updated.updated_request, updated.UpdatedError, "software-update"),
        ):
            with self.subTest(service=service):
                self.assertLessEqual(module.MAX_REQUEST_BYTES, 64 * 1024)
                self.assertLessEqual(module.MAX_RESPONSE_BYTES, 4 * 1024 * 1024)
                with self.assertRaises(error) as caught:
                    function({"pad": "x" * module.MAX_REQUEST_BYTES})
                self.assertEqual(str(caught.exception), f"the {service} request is too large")


# --------------------------------------------------------------- HTTP on a socket

class HttpServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    routes: dict = {}
    seen: list = []


class HttpHandler(http.server.BaseHTTPRequestHandler):
    def address_string(self):
        return "unix"

    def log_message(self, *_args):
        pass

    def _answer(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        path = self.path.split("?", 1)[0]
        self.server.seen.append({
            "method": self.command, "path": self.path,
            "headers": {key.lower(): value for key, value in self.headers.items()},
            "body": json.loads(body) if body else None,
        })
        status, payload = self.server.routes.get((self.command, path), (404, {"error": "no route"}))
        raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    do_GET = _answer
    do_POST = _answer


@unittest.skipUnless(HAVE_UNIXSOCKET, "requests-unixsocket is not installed")
class JsonOverHttp(SocketDirectory):
    def setUp(self):
        super().setUp()
        self.server = self.serve(HttpServer, HttpHandler)
        self.server.routes = {}
        self.server.seen = []

    def client(self, name, socket_attribute, token_attribute=None, token="the-token"):
        module = load(name)
        originals = {socket_attribute: getattr(module, socket_attribute)}
        setattr(module, socket_attribute, self.path)
        if token_attribute:
            originals[token_attribute] = getattr(module, token_attribute)
            setattr(module, token_attribute, token)
        self.addCleanup(lambda: [setattr(module, key, value) for key, value in originals.items()])
        return module

    def test_guardd_reads_without_the_token_and_changes_with_it(self):
        guardd = self.client("guardd_client", "GUARDD_SOCKET_PATH", "GUARDD_TOKEN")
        self.server.routes = {
            ("GET", "/api/v1/guard/ip"): (200, {"ip": "192.0.2.7", "score": 3}),
            ("POST", "/api/v1/guard/traps"): (200, {"ok": True}),
        }
        self.assertEqual(guardd.guardd_ip("192.0.2.7", {"window": "1h"})["score"], 3)
        self.assertEqual(guardd.guardd_set_traps(["trap.test"]), {"ok": True})
        read, change = self.server.seen
        self.assertEqual(read["method"], "GET")
        self.assertIn("ip=192.0.2.7", read["path"])
        self.assertIn("window=1h", read["path"])
        self.assertNotIn("x-guardd-token", read["headers"])
        self.assertEqual(change["headers"]["x-guardd-token"], "the-token")
        self.assertEqual(change["body"], {"hosts": ["trap.test"]})

    def test_a_refused_setting_is_the_daemons_reason_not_an_outage(self):
        guardd = self.client("guardd_client", "GUARDD_SOCKET_PATH", "GUARDD_TOKEN")
        metricsd = self.client("metricsd_client", "METRICSD_SOCKET_PATH")
        self.server.routes = {
            ("POST", "/api/v1/guard/ban-durations"): (400, {"error": "durations must grow"}),
            ("POST", "/api/v1/guard/signatures"): (400, b"not json"),
            ("POST", "/api/v1/metrics/channel-labels"): (400, {"error": "label too long"}),
        }
        with self.assertRaisesRegex(ValueError, "^durations must grow$"):
            guardd.guardd_set_ban_durations([60, 30])
        with self.assertRaisesRegex(ValueError, "^rejected$"):
            guardd.guardd_set_signatures({"rules": []})
        with self.assertRaisesRegex(ValueError, "^label too long$"):
            metricsd.metricsd_channel_labels_save({"a": "x" * 500})

    def test_an_unusable_answer_is_unavailable(self):
        guardd = self.client("guardd_client", "GUARDD_SOCKET_PATH", "GUARDD_TOKEN")
        self.server.routes = {
            ("GET", "/api/v1/guard/health"): (500, {"error": "boom"}),
            ("GET", "/api/v1/guard/shadow"): (200, b"<html>"),
            ("POST", "/api/v1/guard/mode"): (200, b"<html>"),
        }
        with self.assertRaises(guardd.GuarddUnavailable):
            guardd.guardd_health()
        with self.assertRaisesRegex(guardd.GuarddUnavailable, "^guardd returned a non-JSON response$"):
            guardd.guardd_shadow()
        with self.assertRaisesRegex(guardd.GuarddUnavailable, "^guardd returned a non-JSON response$"):
            guardd.guardd_set_mode("enforce")

    def test_the_request_log_answers_with_its_body_even_when_switched_off(self):
        # 404 with a body means "the log is off", which the page shows as such;
        # only a body that is not an object means the daemon is broken.
        guardd = self.client("guardd_client", "GUARDD_SOCKET_PATH", "GUARDD_TOKEN")
        self.server.routes = {
            ("GET", "/api/v1/guard/requests/status"): (404, {"enabled": False}),
            ("GET", "/api/v1/guard/live"): (200, [1, 2]),
            ("POST", "/api/v1/guard/requests/enabled"): (409, {"ok": False, "error": "busy"}),
        }
        self.assertEqual(guardd.guardd_requests_status(), {"enabled": False})
        with self.assertRaisesRegex(guardd.GuarddUnavailable, "unexpected payload"):
            guardd.guardd_live()
        self.assertEqual(guardd.guardd_set_request_log(True), {"ok": False, "error": "busy"})
        self.assertEqual(self.server.seen[-1]["headers"]["x-guardd-token"], "the-token")

    def test_alertd_reads_a_rejected_setting_as_its_message(self):
        alertd = self.client("alertd_client", "ALERTD_SOCKET_PATH", "ALERTD_TOKEN")
        self.server.routes = {
            ("GET", "/api/v1/alerts/health"): (200, {"ok": True}),
            ("POST", "/api/v1/alerts/config"): (400, {"ok": False, "error": "the URL must be https"}),
        }
        self.assertEqual(alertd.alertd_health(), {"ok": True})
        self.assertEqual(alertd.alertd_save_config({"webhook": "http://x"}),
                         {"ok": False, "error": "the URL must be https"})
        read, change = self.server.seen
        self.assertNotIn("x-alertd-token", read["headers"])
        self.assertEqual(change["headers"]["x-alertd-token"], "the-token")

    def test_no_daemon_is_unavailable_and_no_token_is_no_header(self):
        guardd = self.client("guardd_client", "GUARDD_SOCKET_PATH", "GUARDD_TOKEN", token="")
        self.server.routes = {("POST", "/api/v1/guard/traps"): (200, {"ok": True})}
        guardd.guardd_set_traps([])
        self.assertNotIn("x-guardd-token", self.server.seen[-1]["headers"])

        metricsd = self.client("metricsd_client", "METRICSD_SOCKET_PATH")
        metricsd.METRICSD_SOCKET_PATH = self.path + ".absent"
        with self.assertRaises(metricsd.MetricsdUnavailable):
            metricsd.metricsd_health()


if __name__ == "__main__":
    unittest.main()
