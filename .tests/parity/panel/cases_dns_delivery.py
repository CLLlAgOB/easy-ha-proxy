"""DNS provider profiles and certificate delivery targets (both proxied to certd)."""
import copy

TARGET = {"name": "nas", "lineage": "example.com", "host": "10.0.0.9", "port": 22, "user": "cert",
          "path": "/certs/x.pfx", "format": "pfx", "transport": "sftp", "private_key": "set", "host_key": "set"}
BASE = {
    "haproxy-certd": {
        "POST /api/v1/certs/dns-providers/save": {"ok": True, "profile": {"name": "cf", "provider": "cloudflare"}},
        "POST /api/v1/certs/dns-providers/delete": {"ok": True},
        "POST /api/v1/certs/dns-providers": {"ok": True, "profiles": [{"name": "cf", "provider": "cloudflare",
                                                                       "fields": {"api_token": "set"}}],
                                             "providers": {"cloudflare": ["api_token"]}},
        "POST /api/v1/certs/deliveries/save": {"ok": True, "target": TARGET},
        "POST /api/v1/certs/deliveries/delete": {"ok": True},
        "POST /api/v1/certs/deliveries/test": {"ok": True, "output": "sent " + "x" * 500},
        "POST /api/v1/certs/deliveries": {"ok": True, "targets": [TARGET], "available": "replaced"},
        "GET /api/v1/certs/list": {"letsencrypt": [{"lineage": "example.com", "not_after": "2027-01-01"},
                                                   {"lineage": " ", "not_after": "x"}, {"lineage": "b.org"},
                                                   {"lineage": None}, {"lineage": "c.net", "not_after": None}]},
    },
}
REPLIES = BASE


def with_(key, value):
    r = copy.deepcopy(BASE)
    table = r["haproxy-certd"]
    table[key] = value
    # pick() takes the first prefix that matches: keep the specific keys first.
    r["haproxy-certd"] = dict(sorted(table.items(), key=lambda kv: -len(kv[0])))
    return r


def j(body, **kw):
    return dict({"json_body": body}, **kw)


ADMIN = {"groups": "admins"}

STEPS = [
    ("csrf", "GET", "/system/alerts"),
    ("dns page", "GET", "/haproxy/certs/dns-providers"),
    ("delivery page", "GET", "/haproxy/certs/delivery"),
    ("dns list", "GET", "/api/haproxy/dns-providers"),
    ("dns list admin", "GET", "/api/haproxy/dns-providers", ADMIN),
    ("dns save admin", "POST", "/api/haproxy/dns-providers/save", j({"name": " CF ", "provider": "cloudflare"}, **ADMIN)),
    ("dns save bad name", "POST", "/api/haproxy/dns-providers/save", j({"name": "-cf", "provider": "cloudflare"})),
    ("dns save no name", "POST", "/api/haproxy/dns-providers/save", j({})),
    ("dns save bad provider", "POST", "/api/haproxy/dns-providers/save", j({"name": "cf", "provider": "godaddy"})),
    ("dns save no creds", "POST", "/api/haproxy/dns-providers/save", j({"name": "cf", "provider": "cloudflare"})),
    ("dns save list creds", "POST", "/api/haproxy/dns-providers/save", j({"name": "cf", "provider": "Cloudflare",
                                                                          "credentials": ["a"]})),
    ("dns save empty creds", "POST", "/api/haproxy/dns-providers/save", j({"name": "cf", "provider": "cloudflare",
                                                                           "credentials": {"a": "", "b": None}})),
    ("dns save long", "POST", "/api/haproxy/dns-providers/save", j({"name": "cf", "provider": "cloudflare",
                                                                    "credentials": {"a": "", "tok": "x" * 4097, "z": "y" * 5000}})),
    ("dns save ok", "POST", "/api/haproxy/dns-providers/save", j({"name": "cf", "provider": " ROUTE53 ",
                                                                  "credentials": {"key": "k", "n": 5, "e": "", "d": {"x": 1}}})),
    ("dns save refused", "POST", "/api/haproxy/dns-providers/save", j({"name": "cf", "provider": "rfc2136", "credentials": {"k": "v"}},
                                                                      replies=with_("POST /api/v1/certs/dns-providers/save",
                                                                                    {"ok": False, "error": "bad key"}))),
    ("dns save refused noerr", "POST", "/api/haproxy/dns-providers/save", j({"name": "cf", "provider": "rfc2136",
                                                                             "credentials": {"k": "v"}},
                                                                            replies=with_("POST /api/v1/certs/dns-providers/save",
                                                                                          {"ok": False, "error": None}))),
    ("dns save not dict", "POST", "/api/haproxy/dns-providers/save", j({"name": "cf", "provider": "rfc2136", "credentials": {"k": "v"}},
                                                                       replies=with_("POST /api/v1/certs/dns-providers/save", [1]))),
    ("dns save list body", "POST", "/api/haproxy/dns-providers/save", j([], replies=BASE)),
    ("dns delete admin", "POST", "/api/haproxy/dns-providers/delete", j({"name": "cf"}, **ADMIN)),
    ("dns delete bad", "POST", "/api/haproxy/dns-providers/delete", j({"name": "c_f"})),
    ("dns delete ok", "POST", "/api/haproxy/dns-providers/delete", j({"name": " CF "})),
    ("dns delete refused", "POST", "/api/haproxy/dns-providers/delete", j({"name": "cf"}, replies=with_(
        "POST /api/v1/certs/dns-providers/delete", {"ok": False, "error": "in use by site a"}))),
    ("dns list refused", "GET", "/api/haproxy/dns-providers", {"replies": with_("POST /api/v1/certs/dns-providers",
                                                                                 {"ok": False, "error": "x"})}),
    ("dns list text", "GET", "/api/haproxy/dns-providers", {"replies": with_("POST /api/v1/certs/dns-providers", "plain")}),

    ("delivery list", "GET", "/api/haproxy/cert-delivery", {"replies": BASE}),
    ("delivery list admin", "GET", "/api/haproxy/cert-delivery", ADMIN),
    ("delivery list bad certs", "GET", "/api/haproxy/cert-delivery", {"replies": with_(
        "GET /api/v1/certs/list", {"letsencrypt": [{"lineage": "a.org"}, "junk", {"lineage": "b.org"}]})}),
    ("delivery list certs dict", "GET", "/api/haproxy/cert-delivery", {"replies": with_(
        "GET /api/v1/certs/list", {"letsencrypt": {"lineage": "a.org"}})}),
    ("delivery list certs down", "GET", "/api/haproxy/cert-delivery", {"replies": with_(
        "GET /api/v1/certs/list", {"__status": 500, "x": 1})}),
    ("delivery save admin", "POST", "/api/haproxy/cert-delivery/save", j({"name": "NAS"}, replies=BASE, **ADMIN)),
    ("delivery save long key", "POST", "/api/haproxy/cert-delivery/save", j({"name": "nas", "private_key": "k" * 16385})),
    ("delivery save long host key", "POST", "/api/haproxy/cert-delivery/save", j({"name": "nas", "host_key": "h" * 16385})),
    ("delivery save ok", "POST", "/api/haproxy/cert-delivery/save", j(dict(TARGET, name=" NAS ", private_key="-----BEGIN-----",
                                                                           extra={"a": [1, 2]}))),
    ("delivery save refused", "POST", "/api/haproxy/cert-delivery/save", j({"name": "nas"}, replies=with_(
        "POST /api/v1/certs/deliveries/save", {"ok": False, "error": "unknown lineage"}))),
    ("delivery save refused none", "POST", "/api/haproxy/cert-delivery/save", j({"name": "nas"}, replies=with_(
        "POST /api/v1/certs/deliveries/save", {"ok": False, "error": None}))),
    ("delivery save refused noerr", "POST", "/api/haproxy/cert-delivery/save", j({"name": "nas"}, replies=with_(
        "POST /api/v1/certs/deliveries/save", {"ok": False}))),
    ("delivery delete admin", "POST", "/api/haproxy/cert-delivery/delete", j({"name": "nas"}, replies=BASE, **ADMIN)),
    ("delivery delete ok", "POST", "/api/haproxy/cert-delivery/delete", j({"name": " Nas "})),
    ("delivery delete empty", "POST", "/api/haproxy/cert-delivery/delete", j({})),
    ("delivery delete refused", "POST", "/api/haproxy/cert-delivery/delete", j({"name": "x"}, replies=with_(
        "POST /api/v1/certs/deliveries/delete", {"ok": False, "error": "no such target"}))),
    ("delivery test admin", "POST", "/api/haproxy/cert-delivery/test", j({"name": "nas"}, replies=BASE, **ADMIN)),
    ("delivery test ok", "POST", "/api/haproxy/cert-delivery/test", j({"name": "nas"})),
    ("delivery test fail", "POST", "/api/haproxy/cert-delivery/test", j({"name": "nas"}, replies=with_(
        "POST /api/v1/certs/deliveries/test", {"ok": False, "output": None, "error": "refused"}))),
    ("delivery test no output", "POST", "/api/haproxy/cert-delivery/test", j({"name": "nas"}, replies=with_(
        "POST /api/v1/certs/deliveries/test", {"ok": True}))),
]
