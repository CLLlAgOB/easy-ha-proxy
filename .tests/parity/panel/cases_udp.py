"""UDP forwards page and JSON endpoints, backend set expansion, trash on delete."""

TX_NONE = {"b64json": {"ok": True, "state": "none"}}
REPLIES = {
    "haproxy": {"show info": "Version: 2.8.16-0ubuntu0.24.04.1\n"},
    "controld": {
        "config-transaction-status": TX_NONE,
        "udp-status": {"b64json": {"ok": True, "forwards": 1, "ports": 3, "applied_at": "2026-11-23T10:00:00Z",
                                   "active": [{"name": "wg", "primary_ok": True}]}},
        "udp-apply-json": {"b64json": {"ok": True, "forwards": 2, "ports": 4, "applied_at": "2026-11-23T10:01:00Z"}},
        "udp-port-check 5300": "OK busy 5300",
        "udp-port-check": "OK free",
    },
}

VARS_EXTRA = """backend_presets:
- id: 0123456789ab
  name: Pair
  servers:
  - host: 10.0.0.1
    role: primary
  - host: 10.0.0.2
    role: backup
"""


def setup():
    with open("/opt/haproxy-admin/config/vars.yml", "a") as fh:
        fh.write(VARS_EXTRA)
    with open("/opt/haproxy-admin/config/udp.yml", "w") as fh:
        fh.write("udp_forwards:\n- name: wg\n  listen_port: 51820\n  backend_host: 10.0.0.9\n  backend_port: 51820\n"
                 "  ban_check: true\n  zero_trust: false\n  enabled: true\n")


def form(**kw):
    kw.setdefault("csrf_token", "CSRF")
    return {"form": kw}


STEPS = [
    ("udp page", "GET", "/haproxy/udp"),
    ("udp edit", "GET", "/haproxy/udp?edit=wg"),
    ("udp edit missing", "GET", "/haproxy/udp?edit=nope"),
    ("udp add", "POST", "/haproxy/udp", form(name="dns", listen_port="53-54", backend_host="10.0.0.5",
                                            backend_port="5353-5354", ban_check="on", enabled="on")),
    ("udp page after add", "GET", "/haproxy/udp"),
    ("udp add busy", "POST", "/haproxy/udp", form(name="busy", listen_port="5300", backend_host="10.0.0.5",
                                                 backend_port="5300", enabled="on")),
    ("udp add bad range", "POST", "/haproxy/udp", form(name="bad", listen_port="10-5", backend_host="10.0.0.5",
                                                      backend_port="10")),
    ("udp add loopback", "POST", "/haproxy/udp", form(name="lo", listen_port="700", backend_host="127.0.0.1",
                                                     backend_port="700", enabled="on")),
    ("udp add overlap", "POST", "/haproxy/udp", form(name="ov", listen_port="54", backend_host="10.0.0.7",
                                                    backend_port="54", enabled="on")),
    ("udp add preset", "POST", "/haproxy/udp", form(name="pr", listen_port="6000", backend_port="6000",
                                                   servers_preset="Pair", enabled="on")),
    ("udp add preset missing", "POST", "/haproxy/udp", form(name="pm", listen_port="6100", backend_port="6100",
                                                           servers_preset="Nope", enabled="on")),
    ("udp save json", "POST", "/haproxy/udp/save", {"json_body": {"udp": {"name": "js", "listen_port": 7000,
                                                                         "backend_host": "lan-host", "backend_port": 7000,
                                                                         "backup_host": "10.0.0.8", "health_check": "tcp",
                                                                         "health_port": "22"}}}),
    ("udp save json bad", "POST", "/haproxy/udp/save", {"json_body": {"udp": "x"}}),
    ("udp save json list", "POST", "/haproxy/udp/save", {"json_body": [1]}),
    ("udp save stale", "POST", "/haproxy/udp/save", {"json_body": {"udp": {"name": "wg", "listen_port": 51820,
                                                                          "backend_host": "10.0.0.9", "backend_port": 51820},
                                                                  "original_name": "wg", "revision": "0" * 64}}),
    ("udp edit save", "POST", "/haproxy/udp", form(original_name="wg", name="wg2", listen_port="51820",
                                                  backend_host="10.0.0.10", backend_port="51820", enabled="on")),
    ("udp delete json", "POST", "/haproxy/udp/js/delete", {"headers": {"X-CSRFToken": "CSRF"}}),
    ("udp delete form", "POST", "/haproxy/udp", form(action="delete", name="dns")),
    ("udp delete missing", "POST", "/haproxy/udp", form(action="delete", name="zzz")),
    ("udp page final", "GET", "/haproxy/udp"),
]
