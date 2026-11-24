"""TCP proxy JSON endpoints, backend set expansion, trash on delete."""

REPLIES = {
    "haproxy": {"show info": "Version: 2.8.16-0ubuntu0.24.04.1\n"},
    "controld": {"config-transaction-status": {"b64json": {"ok": True, "state": "none"}}},
}


def setup():
    with open("/opt/haproxy-admin/config/vars.yml", "a") as fh:
        fh.write("backend_presets:\n- id: 0123456789ab\n  name: Pair\n  servers:\n  - host: 10.0.0.1\n    role: primary\n"
                 "  - host: 10.0.0.2\n    role: backup\n    weight: 5\n")
    with open("/opt/haproxy-admin/config/tcp.yml", "w") as fh:
        fh.write("tcp_proxies:\n- name: ssh\n  bind_port: 2222\n  backend_host: 10.0.0.3\n  backend_port: 22\n")


def j(body):
    return {"json_body": body}


STEPS = [
    ("tcp add", "POST", "/haproxy/tcp/save", j({"tcp": {"name": "db", "bind_port": "5432", "backend_host": "db.lan",
                                                     "backend_port": 5432, "inter": "5s", "zero_trust": 1}})),
    ("tcp add servers", "POST", "/haproxy/tcp/save", j({"tcp": {"name": "web", "bind_port": 8443, "balance": "leastconn",
                                                             "servers": [{"host": "10.0.0.4", "port": 443},
                                                                         {"host": "", "port": 1},
                                                                         {"host": "10.0.0.5", "port": "443", "backup": True}]}})),
    ("tcp add preset", "POST", "/haproxy/tcp/save", j({"tcp": {"name": "pp", "bind_port": 9000, "servers_preset": "Pair",
                                                            "servers_preset_port": 9000}})),
    ("tcp port taken", "POST", "/haproxy/tcp/save", j({"tcp": {"name": "dup", "bind_port": 2222, "backend_host": "x.lan",
                                                            "backend_port": 1}})),
    ("tcp bad balance", "POST", "/haproxy/tcp/save", j({"tcp": {"name": "b", "bind_port": 1, "balance": "magic"}})),
    ("tcp bad inter", "POST", "/haproxy/tcp/save", j({"tcp": {"name": "b", "bind_port": 1, "inter": "5x"}})),
    ("tcp bad name", "POST", "/haproxy/tcp/save", j({"tcp": {"name": "-x", "bind_port": 1}})),
    ("tcp not object", "POST", "/haproxy/tcp/save", j({"tcp": [1]})),
    ("tcp stale", "POST", "/haproxy/tcp/save", j({"tcp": {"name": "ssh", "bind_port": 2222}, "original_name": "ssh",
                                                 "revision": "a" * 64})),
    ("tcp rename", "POST", "/haproxy/tcp/save", j({"tcp": {"name": "ssh2", "bind_port": 2223, "backend_host": "10.0.0.3",
                                                        "backend_port": 22}, "original_name": "ssh"})),
    ("tcp missing", "POST", "/haproxy/tcp/save", j({"tcp": {"name": "q", "bind_port": 3}, "original_name": "nope"})),
    ("tcp delete", "POST", "/haproxy/tcp/db/delete", {"headers": {"X-CSRFToken": "CSRF"}}),
    ("tcp delete missing", "POST", "/haproxy/tcp/zz/delete", {"headers": {"X-CSRFToken": "CSRF"}}),
]
STEPS.insert(0, ("csrf page", "GET", "/system/alerts"))
