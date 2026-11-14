"""The panel's JSON answers are gzip-compressed for a browser that accepts it.

The monitoring page pulled up to half a megabyte of uncompressed JSON per
refresh. These run a real Flask app with the panel's hook on it, and a
stand-in for the translation hook, registered in the panel's order.
"""

from __future__ import annotations

import gzip
import importlib.util
import json
import os
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

try:
    import flask
except ImportError:  # pragma: no cover - the web requirements are not installed
    flask = None


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "docker/app/haproxy_admin"


def load_compression():
    package = types.ModuleType("compression_test_package")
    package.__path__ = []
    with mock.patch.dict(sys.modules, {"compression_test_package": package}):
        spec = importlib.util.spec_from_file_location(
            "compression_test_package.compression", PACKAGE / "compression.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module


@unittest.skipUnless(flask, "Flask is not installed")
class JsonIsCompressed(unittest.TestCase):
    def setUp(self):
        compression = load_compression()
        app = flask.Flask(__name__)
        # Chart-like: the same handful of numbers over and over.
        big = {"points": [index % 60 for index in range(5000)], "message": "Saved"}

        @app.get("/big")
        def big_json():
            return flask.jsonify(big)

        @app.get("/small")
        def small_json():
            return flask.jsonify({"ok": True})

        @app.get("/page")
        def page():
            return "x" * 5000

        # Random text barely compresses, so the encoded body stays well past
        # the size the hook would otherwise compress again.
        noisy = {"blob": os.urandom(4096).hex()}

        @app.get("/encoded")
        def encoded():
            response = flask.jsonify(noisy)
            response.set_data(gzip.compress(response.get_data()))
            response.headers["Content-Encoding"] = "gzip"
            return response

        def translate(response):
            # The panel's translation hook rewrites JSON bodies; it must run
            # before the compression, on plain JSON.
            if response.is_json:
                payload = response.get_json(silent=True)
                if isinstance(payload, dict) and payload.get("message") == "Saved":
                    payload["message"] = "Сохранено"
                    response.set_data(json.dumps(payload))
            return response

        # The panel's order: compression first, translation last.
        app.after_request(compression.compress_json_response)
        app.after_request(translate)
        self.client = app.test_client()
        self.big = big
        self.noisy = noisy

    def test_a_large_answer_is_compressed_after_it_was_translated(self):
        response = self.client.get("/big", headers={"Accept-Encoding": "gzip, deflate, br"})
        self.assertEqual(response.headers["Content-Encoding"], "gzip")
        self.assertIn("Accept-Encoding", response.headers["Vary"])
        body = response.get_data()
        self.assertEqual(int(response.headers["Content-Length"]), len(body))
        payload = json.loads(gzip.decompress(body))
        self.assertEqual(payload["points"], self.big["points"])
        self.assertEqual(payload["message"], "Сохранено")
        self.assertLess(len(body), len(json.dumps(self.big)) / 3)

    def test_a_browser_that_does_not_accept_gzip_gets_plain_json(self):
        for header in ({}, {"Accept-Encoding": "identity"}, {"Accept-Encoding": "gzip;q=0, br"}):
            with self.subTest(header=header):
                response = self.client.get("/big", headers=header)
                self.assertNotIn("Content-Encoding", response.headers)
                self.assertEqual(json.loads(response.get_data())["points"], self.big["points"])

    def test_small_answers_pages_and_encoded_bodies_are_left_alone(self):
        gzip_ok = {"Accept-Encoding": "gzip"}
        self.assertNotIn("Content-Encoding", self.client.get("/small", headers=gzip_ok).headers)
        self.assertNotIn("Content-Encoding", self.client.get("/page", headers=gzip_ok).headers)
        encoded = self.client.get("/encoded", headers=gzip_ok)
        self.assertGreater(len(encoded.get_data()), 1024)
        # Once, not twice.
        self.assertEqual(json.loads(gzip.decompress(encoded.get_data())), self.noisy)


class ThePanelRegistersItFirst(unittest.TestCase):
    def test_compression_is_the_first_after_request_hook(self):
        source = (PACKAGE / "__init__.py").read_text(encoding="utf-8")
        hooks = [line.strip() for line in source.splitlines() if line.strip().startswith("app.after_request(")]
        self.assertEqual(hooks[0], "app.after_request(compress_json_response)")
        self.assertIn("app.after_request(localize_json_response)", hooks[1:])


if __name__ == "__main__":
    unittest.main()
