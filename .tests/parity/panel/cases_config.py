"""Configuration page and endpoints: state, preview, diff, check, apply, vars, upload, revert, downloads."""
import base64
import re

B = lambda s: base64.b64encode(s.encode()).decode()
REPLIES = {
    "haproxy": {"show info": "Version: 2.8.16-0ubuntu0.24.04.1\n"},
    "controld": {
        "config-transaction-status": {"b64json": {"ok": True, "state": "none"}},
        "check-config": "OK 0\n%s\n%s\n" % (B("Configuration file is valid\n"), B("[WARNING] something\n")),
        "rollback-config-transaction": {"b64json": {"ok": False, "state": "none", "error": "no transaction"}},
    },
    "haproxy-certd": {"POST /api/v1/certs/renewal-pauses": {"ok": True}, "POST /api/v1/certs/status": {"items": {}}},
}
IGNORE_FILES = ()


def normalize_body(label, body):
    body = re.sub(r'"(active_cfg_sha256|revision)": "[0-9a-f]{64}"', r'"\1": "H"', body)
    body = re.sub(r'value="[0-9a-f]{64}"', 'value="H"', body)
    body = re.sub(r'Active SHA256: [0-9a-f]{64}', 'Active SHA256: H', body)
    if label.startswith("download all"):
        return "zip"
    return body


def j(body):
    return {"json_body": body}


def vars_rev():
    return "REV"


STEPS = [
    ("config page", "GET", "/haproxy/config"),
    ("config state", "GET", "/haproxy/config/state"),
    ("config preview", "GET", "/haproxy/config/preview"),
    ("config diff", "GET", "/haproxy/config/diff"),
    ("download rendered", "GET", "/haproxy/config/download-cfg/rendered"),
    ("download server", "GET", "/haproxy/config/download-cfg/server"),
    ("download bad", "GET", "/haproxy/config/download-cfg/zzz"),
    ("download vars", "GET", "/haproxy/config/download/vars"),
    ("download kind bad", "GET", "/haproxy/config/download/nope"),
    ("download all", "GET", "/haproxy/config/download-all"),
    ("config check", "POST", "/haproxy/config/check", {"headers": {"X-CSRFToken": "CSRF"}}),
    ("apply drift", "POST", "/haproxy/config/apply", j({})),
    ("apply bad hash", "POST", "/haproxy/config/apply", j({"allow_external_drift": True, "active_cfg_sha256": "x"})),
    ("apply not object", "POST", "/haproxy/config/apply", j([1])),
    ("apply status", "GET", "/haproxy/config/apply-status?transaction_id=abcdefabcdefabcdef"),
    ("confirm unreachable", "POST", "/haproxy/config/confirm", j({"transaction_id": "abcdefabcdefabcdef",
                                                                 "candidate_sha256": "0" * 64})),
    ("rollback", "POST", "/haproxy/config/rollback-pending", j({"transaction_id": "abcdefabcdefabcdef"})),
    ("vars stale", "POST", "/haproxy/config/vars", j({"values": {"enable_http80": True}, "revision": "0" * 64})),
    ("vars unknown", "POST", "/haproxy/config/vars", j({"values": {"root_domain": "x"}, "revision": "0" * 64})),
    ("vars raw bad rev", "POST", "/haproxy/config/vars/raw", j({"content": "a: 1\n", "revision": "short"})),
    ("upload no kind", "POST", "/haproxy/config/upload",
     {"raw": "--B--\r\n", "headers": {"Content-Type": "multipart/form-data; boundary=B", "X-CSRFToken": "CSRF"}}),
    ("upload tcp", "POST", "/haproxy/config/upload",
     {"raw": "--B\r\nContent-Disposition: form-data; name=\"kind\"\r\n\r\ntcp\r\n--B\r\nContent-Disposition: form-data; "
             "name=\"file\"; filename=\"tcp.yml\"\r\n\r\ntcp_proxies:\n- name: up\n  bind_port: 7777\n  backend_host: a.lan\n"
             "  backend_port: 7\n\r\n--B--\r\n",
      "headers": {"Content-Type": "multipart/form-data; boundary=B", "X-CSRFToken": "CSRF"}}),
    ("upload bad yaml", "POST", "/haproxy/config/upload",
     {"raw": "--B\r\nContent-Disposition: form-data; name=\"kind\"\r\n\r\ntcp\r\n--B\r\nContent-Disposition: form-data; "
             "name=\"file\"; filename=\"tcp.yml\"\r\n\r\n- just a list\n\r\n--B--\r\n",
      "headers": {"Content-Type": "multipart/form-data; boundary=B", "X-CSRFToken": "CSRF"}}),
    ("config state after upload", "GET", "/haproxy/config/state"),
    ("revert", "POST", "/haproxy/config/revert", {"headers": {"X-CSRFToken": "CSRF"}}),
    ("config page after", "GET", "/haproxy/config"),
]
