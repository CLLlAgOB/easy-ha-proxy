"""Access portal: service sites, the portal settings API, attachments, the public page and downloads."""
import re
import urllib.parse

RULES_YAML = "- domain: app.example.com\n  policy: two_factor\n"
REPLIES = {
    "haproxy": {"show info": "Version: 2.8.16-0ubuntu0.24.04.1\n"},
    "controld": {"config-transaction-status": {"b64json": {"ok": True, "state": "none"}}},
    "haproxy-certd": {"POST /api/v1/certs/renewal-pauses": {"ok": True}, "POST /api/v1/certs/status": {"items": {}}},
    "authelia-configd": {"rules_get": {"ok": True, "rules_yaml": RULES_YAML},
                         "rules_set": {"ok": True, "message": "Rules saved."}, "restart": {"ok": True}},
}

CAPTURE = {
    "REV": r'"revision": ?"([0-9a-f]{64})"',
    "FID": r'"id": ?"([0-9a-f]{32})"',
    "SREV": r'name="revision" value="([0-9a-f]{64})"',
    "TID": r'"id": ?"([0-9]{9,12}-[0-9a-f]{12})"',
}

GATE = "/haproxy/sites/gate.example.com/portal"
PORTAL = {"X-Easy-HA-Proxy-Portal-Host": "gate.example.com"}
OTHER = {"X-Easy-HA-Proxy-Portal-Host": "docker.example.test"}


def form(**kw):
    kw.setdefault("csrf_token", "CSRF")
    return {"form": kw}


def j(body):
    return {"json_body": body}


def up(name, data, ctype="application/octet-stream"):
    return ("POST", GATE + "/files?filename=" + urllib.parse.quote(name),
            {"raw": data, "headers": {"Content-Type": ctype, "X-CSRFToken": "CSRF"}})


def visitor(extra=None):
    return {"user": "visitor", "groups": "", "headers": dict(PORTAL, **(extra or {}))}


def labels(enabled, text="Read me", language=None, files=None, revision="REV#0"):
    body = {"enabled": enabled, "text": text, "revision": revision,
            "files": files if files is not None else [{"id": "FID#0", "title": " First ", "description": "One\nTwo"},
                                                      {"id": "FID#1", "title": "", "description": ""}]}
    if language is not None:
        body["language"] = language
    return j(body)


def normalize_body(label, body):
    body = re.sub(r'"(id|deleted_at|expires_at)": ("?)[0-9]{9,12}-[0-9a-f]{12}("?)', r'"": "TID"', body)
    body = re.sub(r'"(deleted_at|expires_at)": 1[0-9]{9}', r'"": T', body)
    body = re.sub(r'("revision": ?")[0-9a-f]{64}"', r'\1REV"', body)
    body = re.sub(r"[0-9a-f]{32}", "FID", body)
    return body


def normalize_key(key):
    key = re.sub(r"[0-9a-f]{32}\.bin$", "FID.bin", key)
    return re.sub(r"([0-9a-f]{64})-[0-9]{9,12}-[0-9a-f]{8}", r"\1-TS-U8", key)


def normalize_file(path, body):
    body = re.sub(r"([0-9a-f]{64})-[0-9]{9,12}-[0-9a-f]{8}", r"\1-TS-U8", body)
    return re.sub(r"(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])", "FID", body)


IGNORE_FILES = ("/.settings-",)

STEPS = [
    ("csrf", "GET", "/system/alerts"),
    ("sites page", "GET", "/haproxy/access-sites"),
    ("create bad", "POST", "/haproxy/access-sites", form(domain="bad domain")),
    ("create ok", "POST", "/haproxy/access-sites", form(domain="gate.example.com")),
    ("create dup", "POST", "/haproxy/access-sites", form(domain="gate.example.com")),
    ("sites page after", "GET", "/haproxy/access-sites"),
    ("edit page", "GET", GATE),
    ("edit not gate", "GET", "/haproxy/sites/docker.example.test/portal"),
    ("edit missing", "GET", "/haproxy/sites/nope/portal"),
    ("settings get", "GET", GATE + "/settings"),
    ("settings not gate", "GET", "/haproxy/sites/docker.example.test/portal/settings"),
    ("public before", "GET", "/access-portal/", visitor()),
    ("upload wrong type", *up("a.txt", b"x", "text/plain")),
    ("upload no type", "POST", GATE + "/files?filename=a.txt", {"raw": b"x", "headers": {"X-CSRFToken": "CSRF"}}),
    ("upload empty", *up("a.txt", b"")),
    ("upload slash", *up("a/b.txt", b"x")),
    ("upload dots", *up("..", b"x")),
    ("upload blank", *up("   ", b"x")),
    ("upload ctrl", *up("a\x01b", b"x")),
    ("upload tab", *up("a\tb", b"x")),
    ("upload long", *up("x" * 181, b"x")),
    ("upload ok", *up(" report (final).pdf ", b"hello world\n" * 100)),
    ("upload ok 2", *up("отчёт über.txt", "данные".encode())),
    ("upload ok 3", *up("big.bin", b"\x00\xff" * 70000)),
    ("settings after uploads", "GET", GATE + "/settings"),
    ("conf bad fields", "POST", GATE + "/settings", j({"x": 1})),
    ("conf not json", "POST", GATE + "/settings", {"raw": "{", "headers": {"Content-Type": "application/json",
                                                                            "X-CSRFToken": "CSRF"}}),
    ("conf bad enabled", "POST", GATE + "/settings", j({"enabled": 1, "text": "", "files": [], "revision": "x"})),
    ("conf bad lang", "POST", GATE + "/settings", labels(True, language="de")),
    ("conf bad text", "POST", GATE + "/settings", labels(True, text="a\x07b")),
    ("conf long text", "POST", GATE + "/settings", labels(True, text="x" * 12001)),
    ("conf stale", "POST", GATE + "/settings", labels(True, revision="b" * 64)),
    ("conf missing file", "POST", GATE + "/settings", labels(True, files=[{"id": "FID#0", "title": "", "description": ""}])),
    ("conf dup file", "POST", GATE + "/settings", labels(True, files=[{"id": "FID#0", "title": "", "description": ""},
                                                                     {"id": "FID#0", "title": "", "description": ""}])),
    ("conf unknown file", "POST", GATE + "/settings", labels(True, files=[{"id": "f" * 32, "title": "", "description": ""}])),
    ("conf extra key", "POST", GATE + "/settings", labels(True, files=[{"id": "FID#0", "title": "", "description": "",
                                                                       "x": 1}])),
    ("conf bad title", "POST", GATE + "/settings", labels(True, files=[{"id": "FID#0", "title": 5, "description": ""}])),
    ("settings refresh", "GET", GATE + "/settings"),
    ("conf ok", "POST", GATE + "/settings", dict(labels(True, text="  Привет\n  world  ", language="ru",
                                                        files=[{"id": "FID#2", "title": " Big ", "description": "B"},
                                                               {"id": "FID#0", "title": "First", "description": "One\nTwo"},
                                                               {"id": "FID#1", "title": "", "description": ""}]))),
    ("conf ok again stale", "POST", GATE + "/settings", labels(True)),
    ("public page", "GET", "/access-portal/", visitor()),
    ("public other host", "GET", "/access-portal/", dict(visitor(), headers=OTHER)),
    ("public bad host", "GET", "/access-portal/", dict(visitor(), headers={"X-Easy-HA-Proxy-Portal-Host": "bad host"})),
    ("public no header", "GET", "/access-portal/", {"user": "visitor", "groups": ""}),
    ("public post", "POST", "/access-portal/", visitor()),
    ("settings for ids", "GET", GATE + "/settings"),
    ("download 0", "GET", "/access-portal/downloads/FID#0", visitor()),
    ("download 1", "GET", "/access-portal/downloads/FID#1", visitor()),
    ("download 2", "GET", "/access-portal/downloads/FID#2", visitor()),
    ("download unknown", "GET", "/access-portal/downloads/" + "e" * 32, visitor()),
    ("download bad id", "GET", "/access-portal/downloads/xyz", visitor()),
    ("download other host", "GET", "/access-portal/downloads/FID#0", dict(visitor(), headers=OTHER)),
    ("delete bad id", "POST", GATE + "/files/xyz/delete", {"headers": {"X-CSRFToken": "CSRF"}}),
    ("delete 1", "POST", GATE + "/files/FID#1/delete", {"headers": {"X-CSRFToken": "CSRF"}}),
    ("delete again", "POST", GATE + "/files/" + "e" * 32 + "/delete", {"headers": {"X-CSRFToken": "CSRF"}}),
    ("settings after delete", "GET", GATE + "/settings"),
    ("conf disable", "POST", GATE + "/settings", labels(False, text="", files=[
        {"id": "FID#0", "title": "", "description": ""}, {"id": "FID#1", "title": "", "description": ""}])),
    ("settings again", "GET", GATE + "/settings"),
    ("conf enable", "POST", GATE + "/settings", labels(True, text="t", files=[
        {"id": "FID#0", "title": "", "description": ""}, {"id": "FID#1", "title": "", "description": ""}])),
    ("settings 3", "GET", GATE + "/settings"),
    ("conf disable 2", "POST", GATE + "/settings", labels(False, text="t", files=[
        {"id": "FID#0", "title": "", "description": ""}, {"id": "FID#1", "title": "", "description": ""}])),
    ("download disabled", "GET", "/access-portal/downloads/FID#0", visitor()),
    ("public disabled", "GET", "/access-portal/", visitor()),

    ("edit page 2", "GET", GATE),
    ("edit extra field", "POST", GATE, form(action="save_identity", domain="gate.example.com", revision="SREV#0", x="1")),
    ("edit no action", "POST", GATE, form(domain="gate.example.com", revision="SREV#0")),
    ("edit bad action", "POST", GATE, form(action="zap", revision="SREV#0")),
    ("edit bad paused", "POST", GATE, form(action="save_identity", paused="maybe", revision="SREV#0")),
    ("edit backend refused", "POST", GATE, form(action="save_identity", domain="gate.example.com", backend_ip="1.2.3.4",
                                                revision="SREV#0")),
    ("edit no revision", "POST", GATE, form(action="save_identity", domain="gate.example.com")),
    ("edit stale", "POST", GATE, form(action="save_identity", domain="gate.example.com", revision="c" * 64)),
    ("edit bad domain", "POST", GATE, form(action="save_identity", domain="bad domain", revision="SREV#0")),
    ("edit pause", "POST", GATE, form(action="save_identity", domain="gate.example.com", paused="true",
                                      revision="SREV#0")),
    ("edit page 3", "GET", GATE),
    ("edit domain", "POST", GATE, form(action="save_identity", domain="door.example.com", paused="false",
                                       revision="SREV#0")),
    ("edit page 4", "GET", GATE),
    ("public old host", "GET", "/access-portal/", visitor()),
    ("public new host", "GET", "/access-portal/", dict(visitor(), headers={"X-Easy-HA-Proxy-Portal-Host": "Door.Example.com"})),
    ("edit delete", "POST", GATE, form(action="delete", revision="SREV#0")),
    ("trash list", "GET", "/api/haproxy/trash"),
    ("trash restore", "POST", "/api/haproxy/trash/restore", j({"source": "panel", "id": "TID#0"})),
    ("settings restored", "GET", GATE + "/settings"),
    ("edit page 5", "GET", GATE),
    ("edit delete 2", "POST", GATE, form(action="delete", revision="SREV#0")),
    ("trash list 2", "GET", "/api/haproxy/trash"),
    ("trash forget", "POST", "/api/haproxy/trash/delete", j({"source": "panel", "id": "TID#0"})),
    ("edit after delete", "GET", GATE),
    ("sites after delete", "GET", "/haproxy/access-sites"),
    ("recreate", "POST", "/haproxy/access-sites", form(domain="gate.example.com")),
    ("settings fresh", "GET", GATE + "/settings"),
]
