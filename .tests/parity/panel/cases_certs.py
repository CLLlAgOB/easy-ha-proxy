"""Certificates page actions, material inspect/import, CA download, backup and restore."""
import base64

REPLIES = {
    "haproxy": {"show info": "Version: 2.8.16-0ubuntu0.24.04.1\n"},
    "controld": {"config-transaction-status": {"b64json": {"ok": True, "state": "none"}}},
    "haproxy-certd": {
        "GET /api/v1/certs/list": {"ok": True, "haproxy": [{"path": "/etc/haproxy/certs/a.pem", "domains": ["a.example.com"],
                                                             "not_after": "2027-01-01", "days_left": 400, "source": "letsencrypt"}],
                                   "letsencrypt": [{"lineage": "a.example.com", "domains": ["a.example.com"], "days_left": 60}],
                                   "certificate_authorities": {"internal": {"id": "internal", "subject": "CN=x", "client_auth": False},
                                                               "external": [{"id": "corp", "name": "Corp", "client_auth": True}],
                                                               "revoked_client_certificates": ["AB:CD"]}},
        "POST /api/v1/certs/standby/store-all": {"ok": True, "domains": ["a.example.com", "b.example.com"]},
        "POST /api/v1/certs/standby/store": {"ok": False, "error": "unusable certificate"},
        "POST /api/v1/certs/standby/activate": {"ok": True, "issuer": None},
        "POST /api/v1/certs/standby/adopt": {"ok": True, "domains": ["a.example.com"]},
        "POST /api/v1/certs/standby/release": {"ok": True, "restored": False},
        "POST /api/v1/certs/standby/delete": {"ok": True},
        "POST /api/v1/certs/standby": {"ok": True, "domains": [{"domain": "a.example.com", "slots": []}]},
        "POST /api/v1/certs/delete-haproxy": {"ok": True},
        "POST /api/v1/certs/delete-le": {"error": "certbot failed"},
        "POST /api/v1/certs/ca/internal/ensure": {"ok": True, "message": "Ready"},
        "POST /api/v1/certs/ca/internal/issue": {"ok": False, "error": "no CA"},
        "POST /api/v1/certs/ca/internal/rotate": {"ok": False, "error": "Type the phrase", "client_trust": {"sites": ["s1", "s2"]}},
        "POST /api/v1/certs/ca/internal/delete": {"ok": False, "error": "In use",
                                                  "blocking_certificates": [{"domains": ["x.example.com"]}, {"path": "/p.pem"}]},
        "POST /api/v1/certs/ca/upload": {"ok": True},
        "POST /api/v1/certs/ca/delete-external": {"ok": True, "message": "gone"},
        "POST /api/v1/certs/ca/client-auth": {"ok": True, "reload_error": "reload failed"},
        "POST /api/v1/certs/ca/revoked": {"ok": True},
        "POST /api/v1/certs/ca/export": {"ok": True, "certificate_b64": base64.b64encode(b"PEMDATA").decode(), "filename": "corp.pem"},
        "POST /api/v1/certs/inspect": {"ok": True, "kind": "bundle"},
        "POST /api/v1/certs/import": {"ok": True, "completed": ["authority corp", "certificate a"]},
        "POST /api/v1/certs/backup": {"ok": True, "archive_b64": base64.b64encode(b"ZIPDATA").decode()},
        "POST /api/v1/certs/restore": {"ok": False, "results": [{"rc": 2, "stderr": "bad zip"}]},
        "POST /api/v1/certs/status": {"items": {}},
    },
}


def normalize_body(label, body):
    return body


def form(**kw):
    kw.setdefault("csrf_token", "CSRF")
    return {"form": kw}


def mp(fields, files):
    parts = []
    for k, v in fields.items():
        parts.append('--B\r\nContent-Disposition: form-data; name="%s"\r\n\r\n%s\r\n' % (k, v))
    for k, (fn, data) in files.items():
        parts.append('--B\r\nContent-Disposition: form-data; name="%s"; filename="%s"\r\n\r\n%s\r\n' % (k, fn, data))
    return {"raw": "".join(parts) + "--B--\r\n", "headers": {"Content-Type": "multipart/form-data; boundary=B", "X-CSRFToken": "CSRF"}}


STEPS = [
    ("certs page", "GET", "/haproxy/certs"),
    ("delete haproxy", "POST", "/haproxy/certs", form(action="delete_haproxy", path="/etc/haproxy/certs/a.pem")),
    ("delete le", "POST", "/haproxy/certs", form(action="delete_le", lineage="a.example.com")),
    ("create ca", "POST", "/haproxy/certs", form(action="create_internal_ca")),
    ("issue internal", "POST", "/haproxy/certs", form(action="issue_internal_cert", domain="x.lan", alt_names="a.lan, b.lan")),
    ("rotate ca", "POST", "/haproxy/certs", form(action="rotate_internal_ca", confirmation="no")),
    ("delete ca", "POST", "/haproxy/certs", form(action="delete_internal_ca", confirmation="x")),
    ("import ca no file", "POST", "/haproxy/certs", form(action="import_external_ca")),
    ("import ca", "POST", "/haproxy/certs", mp({"action": "import_external_ca", "ca_name": "Corp"}, {"ca_file": ("ca.pem", "PEM")})),
    ("store standby all", "POST", "/haproxy/certs", mp({"action": "store_standby", "standby_domain": "*", "standby_slot": "spare"},
                                                       {"standby_cert": ("c.pem", "CERT  "), "standby_key": ("k.pem", " KEY")})),
    ("store standby one", "POST", "/haproxy/certs", mp({"action": "store_standby", "standby_domain": "a.example.com",
                                                        "standby_slot": "s"}, {"standby_cert": ("c.pem", "CERT")})),
    ("store standby no file", "POST", "/haproxy/certs", form(action="store_standby", standby_domain="a", standby_slot="s")),
    ("activate standby", "POST", "/haproxy/certs", form(action="activate_standby", standby_domain="a.example.com", standby_slot="s")),
    ("adopt standby", "POST", "/haproxy/certs", form(action="adopt_standby", standby_domain="a.example.com", standby_slot="")),
    ("release standby", "POST", "/haproxy/certs", form(action="release_standby", standby_domain="a.example.com")),
    ("delete standby", "POST", "/haproxy/certs", form(action="delete_standby", standby_domain="a.example.com", standby_slot="s")),
    ("delete external", "POST", "/haproxy/certs", form(action="delete_external_ca", ca_id="corp")),
    ("client auth", "POST", "/haproxy/certs", {"form": {"csrf_token": "CSRF", "action": "set_client_auth_cas",
                                                        "client_auth_ca": ["Corp ", "internal", ""]}}),
    ("revoked", "POST", "/haproxy/certs", form(action="set_revoked_client_certs", fingerprints="AA; BB, CC")),
    ("unknown", "POST", "/haproxy/certs", form(action="zzz")),
    ("inspect no file", "POST", "/haproxy/certs/inspect", mp({}, {})),
    ("inspect", "POST", "/haproxy/certs/inspect", mp({"password": "p", "name": " n "}, {"file": ("b.p12", "DATA")})),
    ("import", "POST", "/haproxy/certs/import", mp({"domain": "a.example.com", "replace": "on"}, {"file": ("b.pem", "DATA")})),
    ("ca download", "GET", "/haproxy/certs/ca/corp/download"),
    ("backup", "GET", "/haproxy/certs/backup"),
    ("restore", "POST", "/haproxy/certs/restore", mp({}, {"archive": ("b.zip", "ZIP")})),
    ("restore empty", "POST", "/haproxy/certs/restore", mp({}, {})),
]
STEPS.insert(0, ("csrf", "GET", "/system/alerts"))
