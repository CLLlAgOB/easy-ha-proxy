"""Site list/editor pages, TCP pages, certificate issue, ACME email, mail page."""
import re

REPLIES = {
    "haproxy": {"show info": "Version: 2.8.16-0ubuntu0.24.04.1\n"},
    "controld": {"config-transaction-status": {"b64json": {"ok": True, "state": "none"}}},
    "haproxy-certd": {
        "POST /api/v1/certs/renewal-pauses": {"ok": True, "without_lineage": ["shop.example.com"]},
        "POST /api/v1/certs/status": {"items": {"shop.example.com": {"state": "ok", "short": "ok 80d",
                                                                      "tooltip": "fine", "le_has": True}}},
        "GET /api/v1/certs/list": {"ok": True, "haproxy": [], "letsencrypt": [],
                                   "certificate_authorities": {"internal": {"id": "internal", "client_auth": True},
                                                               "external": [{"id": "corp", "name": "Corp"}]}},
        "POST /api/v1/certs/dns-providers": {"ok": True, "profiles": [{"name": "cf", "provider": "cloudflare"}, {"x": 1}]},
        "POST /api/v1/certs/issue": {"ok": False, "results": [{"rc": 1, "lineage": "shop.example.com",
                                                                "stderr": "Detail: no\nHint: try", "stdout": "x"}]},
        "POST /api/v1/certs/ca/internal/issue": {"ok": True, "message": "issued"},
    },
}


def setup():
    with open("/opt/haproxy-admin/config/vars.yml", "a") as fh:
        fh.write("certbot_email: a@b.example\nbackend_presets:\n- id: 0123456789ab\n  name: Pair\n  servers:\n"
                 "  - host: 10.0.0.1\n    role: primary\n")


def normalize_body(label, body):
    return re.sub(r'"revision": "[0-9a-f]{64}"', '"revision": "H"', body)


def form(**kw):
    kw.setdefault("csrf_token", "CSRF")
    return {"form": kw}


def j(body):
    return {"json_body": body}


STEPS = [
    ("sites page", "GET", "/haproxy/sites"),
    ("site add", "POST", "/haproxy/sites", form(domain="shop.example.com", backend_ip="10.2.2.2", backend_port="8080")),
    ("site add missing", "POST", "/haproxy/sites", form(domain="", backend_ip="1.1.1.1", backend_port="1")),
    ("site add bad port", "POST", "/haproxy/sites", form(domain="b.example.com", backend_ip="1.1.1.1", backend_port="x")),
    ("site add preset", "POST", "/haproxy/sites", form(domain="p.example.com", servers_preset="Pair", backend_port="443")),
    ("site add preset missing", "POST", "/haproxy/sites", form(domain="q.example.com", servers_preset="Nope", backend_port="1")),
    ("sites page 2", "GET", "/haproxy/sites"),
    ("site edit", "GET", "/haproxy/sites/shop.example.com/edit"),
    ("site edit missing", "GET", "/haproxy/sites/nope/edit"),
    ("site pause", "POST", "/haproxy/sites", form(action="pause", name="shop.example.com")),
    ("site pause renewal", "POST", "/haproxy/sites", form(action="pause_renewal", name="shop.example.com")),
    ("site resume", "POST", "/haproxy/sites", form(action="resume", name="shop.example.com")),
    ("site pause no name", "POST", "/haproxy/sites", form(action="pause", name="")),
    ("site edit form save", "POST", "/haproxy/sites/shop.example.com/edit",
     form(action="save", domain="shop.example.com", backend_ip="10.2.2.3", backend_port="8081",
          alt_names="www.shop.example.com\n", redirect_to_https="false", max_req_rate="50", hsts="", acme_challenge="http-01")),
    ("site edit form stale", "POST", "/haproxy/sites/shop.example.com/edit",
     form(action="save", domain="shop.example.com", backend_ip="10.2.2.3", backend_port="8081", revision="c" * 64)),
    ("issue le", "POST", "/haproxy/sites/shop.example.com/issue-cert", j({})),
    ("issue internal", "POST", "/haproxy/sites/shop.example.com/issue-cert", j({"source": "internal"})),
    ("issue external", "POST", "/haproxy/sites/shop.example.com/issue-cert", j({"source": "external"})),
    ("issue missing", "POST", "/haproxy/sites/zz/issue-cert", j({})),
    ("site edit delete", "POST", "/haproxy/sites/p.example.com/edit", form(action="delete")),
    ("site list delete", "POST", "/haproxy/sites", form(action="delete", name="nope")),
    ("tcp page", "GET", "/haproxy/tcp"),
    ("tcp add", "POST", "/haproxy/tcp", form(name="db", bind_port="5432", backend_host="db.lan", backend_port="5432",
                                             zero_trust="on")),
    ("tcp add bad", "POST", "/haproxy/tcp", form(name="db2", bind_port="x", backend_host="db.lan", backend_port="1")),
    ("tcp add preset", "POST", "/haproxy/tcp", form(name="pp", bind_port="9000", servers_preset="Pair", backend_port="9000")),
    ("tcp edit", "GET", "/haproxy/tcp/db/edit"),
    ("tcp edit missing", "GET", "/haproxy/tcp/zz/edit"),
    ("tcp edit delete", "POST", "/haproxy/tcp/pp/edit", form(action="delete")),
    ("tcp list delete", "POST", "/haproxy/tcp", form(action="delete", name="db")),
    ("acme get", "GET", "/haproxy/certs/api/acme-email"),
    ("acme bad", "POST", "/haproxy/certs/api/acme-email", j({"email": "x"})),
    ("acme invalid", "POST", "/haproxy/certs/api/acme-email", j({"email": "bad", "revision": "r"})),
    ("acme stale", "POST", "/haproxy/certs/api/acme-email", j({"email": "c@d.example", "revision": "r"})),
    ("mail page", "GET", "/haproxy/mail"),
]
