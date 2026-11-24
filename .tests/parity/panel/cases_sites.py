"""Site JSON endpoints: save (create/edit/rename/stale), delete, upload refusal, pause sync."""

REPLIES = {
    "haproxy": {"show info": "Version: 2.8.16-0ubuntu0.24.04.1\n"},
    "controld": {"config-transaction-status": {"b64json": {"ok": True, "state": "none"}}},
    "haproxy-certd": {"POST /api/v1/certs/renewal-pauses": {"ok": True},
                      "POST /api/v1/certs/status": {"items": {}}},
}


def setup():
    with open("/opt/haproxy-admin/config/vars.yml", "a") as fh:
        fh.write("geoip_country_codes: [RU, DE]\nbackend_presets:\n- id: 0123456789ab\n  name: Pair\n  servers:\n"
                 "  - host: 10.0.0.1\n    role: primary\n    weight: 3\n  - host: 10.0.0.2\n    role: backup\n")


def j(body):
    return {"json_body": body}


SITE = {"name": "shop", "domain": "Shop.Example.COM", "backend_ip": "10.1.1.1", "backend_port": "8080",
        "alt_names": "www.shop.example.com, shop.example.com", "geo_countries": ["de", "ru"],
        "allow_ips": "10.0.0.5/24; 192.168.1.1", "certificate_source": "", "le_managed": True,
        "cert_alt_names": ["api.shop.example.com"], "dns_profile": "", "mtls_mode": "disabled"}

STEPS = [
    ("csrf page", "GET", "/system/alerts"),
    ("site create", "POST", "/haproxy/sites/save", j({"site": SITE})),
    ("site create dup", "POST", "/haproxy/sites/save", j({"site": dict(SITE, name="shop2")})),
    ("site geo bad", "POST", "/haproxy/sites/save", j({"site": dict(SITE, name="g", domain="g.example.com",
                                                                    geo_countries=["FR"])})),
    ("site wildcard bad", "POST", "/haproxy/sites/save", j({"site": dict(SITE, name="w", domain="w.example.com",
                                                                         cert_alt_names=["*.w.example.com"])})),
    ("site dns wildcard ok", "POST", "/haproxy/sites/save", j({"site": dict(SITE, name="w", domain="w.example.com",
                                                                            alt_names=[], geo_countries=None,
                                                                            dns_profile="cf",
                                                                            cert_alt_names=["*.w.example.com"])})),
    ("site preset", "POST", "/haproxy/sites/save", j({"site": {"name": "p", "domain": "p.example.com",
                                                              "servers_preset": "Pair", "servers_preset_port": 443}})),
    ("site servers", "POST", "/haproxy/sites/save", j({"site": {"name": "m", "domain": "m.example.com",
                                                               "backend_ip": "10.9.9.9", "backend_port": 1,
                                                               "servers": [{"host": "10.0.0.7", "port": 80, "weight": "x"},
                                                                           {"host": "10.0.0.8", "port": "81", "backup": 1,
                                                                            "weight": "7"}]}})),
    ("site external no ca", "POST", "/haproxy/sites/save", j({"site": {"name": "e", "domain": "e.example.com",
                                                                      "certificate_source": "external"}})),
    ("site mtls no ca", "POST", "/haproxy/sites/save", j({"site": {"name": "t", "domain": "t.example.com",
                                                                  "mtls_mode": "required"}})),
    ("site gate refused", "POST", "/haproxy/sites/save", j({"site": {"name": "gate", "domain": "gate.example.com",
                                                                    "access_gate": True}})),
    ("site stale", "POST", "/haproxy/sites/save", j({"site": dict(SITE, backend_port=9000), "original_name": "shop",
                                                    "revision": "b" * 64})),
    ("site pause renewal", "POST", "/haproxy/sites/save", j({"site": dict(SITE, cert_renewal_paused=True),
                                                            "original_name": "shop"})),
    ("site rename", "POST", "/haproxy/sites/save", j({"site": dict(SITE, name="shop-new"), "original_name": "shop"})),
    ("site bad json", "POST", "/haproxy/sites/save", {"raw": "{", "headers": {"Content-Type": "application/json",
                                                                              "X-CSRFToken": "CSRF"}}),
    ("site upload not external", "POST", "/haproxy/sites/m/upload-cert",
     {"raw": "--B\r\nContent-Disposition: form-data; name=\"cert_file\"; filename=\"c.pem\"\r\n\r\nPEM\r\n--B--\r\n",
      "headers": {"Content-Type": "multipart/form-data; boundary=B", "X-CSRFToken": "CSRF"}}),
    ("site upload no file", "POST", "/haproxy/sites/m/upload-cert",
     {"raw": "--B--\r\n", "headers": {"Content-Type": "multipart/form-data; boundary=B", "X-CSRFToken": "CSRF"}}),
    ("site delete", "POST", "/haproxy/sites/m/delete", {"headers": {"X-CSRFToken": "CSRF"}}),
    ("site delete missing", "POST", "/haproxy/sites/zz/delete", {"headers": {"X-CSRFToken": "CSRF"}}),
]
