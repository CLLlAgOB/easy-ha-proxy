"""Trash API, backend sets page, configuration history API."""
import base64
import re

B = lambda s: base64.b64encode(s.encode()).decode()
V1 = {"id": "v-0001", "created_at": "2026-11-20T10:00:00Z",
      "sources": {"vars.yml": B("a: 1\nb: [1, 2]\n"), "websites.yml": B("sites:\n- name: s1\n  domain: s1.example.com\n"),
                  "tcp.yml": B("tcp_proxies: []\n")}}
REPLIES = {
    "haproxy": {"show info": "Version: 2.8.16-0ubuntu0.24.04.1\n"},
    "controld": {
        "config-transaction-status": {"b64json": {"ok": True, "state": "none"}},
        "config-versions": {"b64json": {"ok": True, "versions": [{"id": "v-0001", "created_at": "2026-11-20T10:00:00Z"}]}},
        "config-version v-0001": {"b64json": {"ok": True, "version": V1}},
        "config-version": {"b64json": {"ok": False, "error": "no such version"}},
        "udp-apply-json": {"b64json": {"ok": True, "forwards": 1, "ports": 1, "applied_at": "x"}},
    },
    "haproxy-certd": {
        "POST /api/v1/certs/trash/settings": {"ok": True},
        "POST /api/v1/certs/trash/restore": {"ok": True, "kind": "haproxy_cert", "name": "a.pem"},
        "POST /api/v1/certs/trash/purge": {"ok": True, "removed": 2},
        "POST /api/v1/certs/trash": {"ok": True, "keep_days": 30, "items": [
            {"id": "c1", "kind": "haproxy_cert", "name": "a.pem", "deleted_at": 1700000000, "deleted_by": "x",
             "details": {"domains": ["a.example.com", ""], "not_after": "2027-01-01"}},
            {"id": "c2", "kind": "dns_profile", "name": "cf", "deleted_at": "1700000001", "details": {"provider": "cloudflare"}},
            "junk"]},
        "POST /api/v1/certs/status": {"items": {}},
    },
}


def setup():
    with open("/opt/haproxy-admin/config/udp.yml", "w") as fh:
        fh.write("udp_forwards:\n- name: wg\n  listen_port: 51820\n  backend_host: 10.0.0.9\n  backend_port: 51820\n"
                 "  servers_preset: Pair\n")


def normalize_file(path, body):
    return re.sub(r"- id: [0-9a-f]{12}", "- id: PID", body)


def normalize_body(label, body):
    body = re.sub(r"'id': '[0-9a-f]{12}'", "'id': 'PID'", body)
    body = re.sub(r'"(id|deleted_at|expires_at)": ("?)[0-9]{9,12}-[0-9a-f]{12}("?)', r'"\1": "TID"', body)
    body = re.sub(r'"deleted_at": 1[0-9]{9}', '"deleted_at": T', body)
    body = re.sub(r'"expires_at": 1[0-9]{9}', '"expires_at": T', body)
    body = re.sub(r'"set_aside": "backups/before-restore-[0-9]+"', '"set_aside": "X"', body)
    body = re.sub(r'value="[0-9a-f]{64}"', 'value="H"', body)
    return body


def form(**kw):
    kw.setdefault("csrf_token", "CSRF")
    return {"form": kw}


def j(body):
    return {"json_body": body}


STEPS = [
    ("presets page", "GET", "/haproxy/backend-sets"),
    ("preset create", "POST", "/haproxy/backend-sets", {"form": {"csrf_token": "CSRF", "name": "Pair",
                                                                 "server_host": ["10.0.0.1", "10.0.0.2", ""],
                                                                 "server_role": ["primary", "backup", "primary"],
                                                                 "server_weight": ["3", "", ""],
                                                                 "server_note": ["main  line", "", ""]}}),
    ("presets page 2", "GET", "/haproxy/backend-sets"),
    ("preset edit", "GET", "/haproxy/backend-sets?edit=Pair"),
    ("preset edit missing", "GET", "/haproxy/backend-sets?edit=Nope"),
    ("preset bad", "POST", "/haproxy/backend-sets", {"form": {"csrf_token": "CSRF", "name": "_bad",
                                                              "server_host": ["10.0.0.1"], "server_role": ["primary"]}}),
    ("preset delete used", "POST", "/haproxy/backend-sets", form(action="delete", name="Pair")),
    ("trash list", "GET", "/api/haproxy/trash"),
    ("trash settings bad", "POST", "/api/haproxy/trash/settings", j({"keep_days": "x"})),
    ("trash settings", "POST", "/api/haproxy/trash/settings", j({"keep_days": 30})),
    ("udp delete into trash", "POST", "/haproxy/udp/wg/delete", {"headers": {"X-CSRFToken": "CSRF"}}),
    ("trash list 2", "GET", "/api/haproxy/trash"),
    ("trash restore bad", "POST", "/api/haproxy/trash/restore", j({"source": "x", "id": "1"})),
    ("trash restore unknown", "POST", "/api/haproxy/trash/restore", j({"source": "panel", "id": "123-abcdefabcdef"})),
    ("trash restore certd", "POST", "/api/haproxy/trash/restore", j({"source": "certd", "id": "c1"})),
    ("trash delete certd", "POST", "/api/haproxy/trash/delete", j({"source": "certd", "id": "c2"})),
    ("trash empty", "POST", "/api/haproxy/trash/empty", j({})),
    ("history page", "GET", "/haproxy/config/history"),
    ("versions", "GET", "/api/haproxy/config/versions?limit=x"),
    ("version diff applied", "GET", "/api/haproxy/config/versions/diff?left=v-0001"),
    ("version diff current", "GET", "/api/haproxy/config/versions/diff?left=v-0001&right=current"),
    ("version diff missing", "GET", "/api/haproxy/config/versions/diff?left=v-9999&right=current"),
    ("version diff no left", "GET", "/api/haproxy/config/versions/diff"),
    ("restore no version", "POST", "/api/haproxy/config/versions/restore", j({})),
    ("restore", "POST", "/api/haproxy/config/versions/restore", j({"version": "v-0001"})),
]
STEPS.insert(0, ("csrf", "GET", "/system/alerts"))
