"""Authelia access rules page and settings page (with mail and notifications)."""
import copy

RULES_YAML = """- domain:
  - app.example.com
  - '*.app.example.com'
  policy: two_factor
  subject:
  - group:admins
  - - user:bob
    - group:ops
- domain: open.example.com
  policy: bypass
  resources:
  - ^/public/.*$
  - ^/health$
- domain: app.example.com
  policy: one_factor
  subject: user:alice
- domain_regex: ^(?P<User>\\\\w+)\\\\.example\\\\.com$
  policy: one_factor
- domain: anon.example.com
  policy: deny
  subject: anonymous
"""

CONFIG = {
    "server": {"address": "tcp://0.0.0.0:9091/"},
    "log": {"level": "info", "format": "text", "keep_stdout": False},
    "session": {"name": "sess", "same_site": "strict", "expiration": "1h", "inactivity": "5m", "remember_me": "1M",
                "cookies": [{"domain": "example.com", "authelia_url": "https://auth.example.com",
                             "default_redirection_url": "https://www.example.com", "name": "c1", "same_site": "lax"},
                            {"domain": "other.org", "authelia_url": "https://auth.other.org"}, "junk"]},
    "storage": {"local": {"path": "/config/db.sqlite3"}},
    "authentication_backend": {"refresh_interval": "5m", "file": {"path": "/config/users.yml", "watch": False,
                                                                 "password": {"algorithm": "bcrypt"}}},
    "regulation": {"modes": ["ip", "user"], "max_retries": 3, "find_time": "10m", "ban_time": "12h"},
    "totp": {"issuer": "Example", "period": 30, "skew": 2},
}
REV = "a" * 64
MAIL = {"mode": "relay", "host": "smtp.example.com", "port": 587, "username": "u", "password": "SECRET",
        "sender": "a@example.com", "recipient": "b@example.com", "subject": "S", "timeout": "10s",
        "tls_mode": "starttls", "tls_skip_verify": False}
LATEST = {"id": "b" * 64, "revision": "c" * 64, "received_at": "2026-11-20T10:00:00Z", "recipient_masked": "b***@example.com",
          "size": 100, "handled": False, "handled_at": None, "body": "PLAINTEXT", "path": "/x"}

BASE = {
    "authelia-configd": {
        "rules_get": {"ok": True, "rules_yaml": RULES_YAML},
        "rules_set": {"ok": True, "message": "Rules saved."},
        "restart": {"ok": True},
        "config_view": {"ok": True, "config": CONFIG},
        "settings_update": {"ok": True},
        "mail_view": {"ok": True, "settings": MAIL, "capabilities": {"relay": True}, "revision": REV},
        "mail_update": {"ok": True, "settings": MAIL, "revision": REV},
        "mail_test": {"ok": True, "message": "sent"},
        "notification_latest": {"ok": True, "mode": "filesystem", "status": "ready", "latest": LATEST, "extra": 1},
        "notification_reveal": {"ok": True, "text": "PLAINTEXT"},
        "notification_handle": {"ok": True, "status": "handled", "latest": LATEST, "secret": "x"},
    },
}
REPLIES = BASE


def with_(**kw):
    r = copy.deepcopy(BASE)
    r["authelia-configd"].update(kw)
    return r


def form(**kw):
    kw.setdefault("csrf_token", "CSRF")
    return {"form": kw}


def rules_form(rows, **kw):
    f = {"csrf_token": "CSRF", "acl_snapshot": "SNAP", "total_rules": str(len(rows))}
    for i, r in enumerate(rows):
        for k, v in r.items():
            f["rule-%d-%s" % (i, k)] = v
    f.update(kw)
    return {"form": f}


ORIG = [
    {"domains": "app.example.com, *.app.example.com", "policy": "two_factor", "groups": "admins", "users": "",
     "resources": "", "source_index": "0"},
    {"domains": "open.example.com", "policy": "bypass", "resources": "^/public/.*$\n^/health$", "source_index": "1"},
    {"domains": "app.example.com", "policy": "one_factor", "users": "alice", "source_index": "2"},
    {"domains": "", "policy": "one_factor", "source_index": "3"},
    {"domains": "anon.example.com", "policy": "deny", "flag_anonymous": "on", "source_index": "4"},
]


def edited(i, **kw):
    rows = copy.deepcopy(ORIG)
    rows[i].update(kw)
    return rows


SETTINGS = dict(log_level="debug", session_name=" s2 ", session_same_site="", session_expiration="2h",
                session_inactivity="", session_remember_me="", cookie_domain="example.net",
                cookie_authelia_url="https://auth.example.net", cookie_default_redirection_url="",
                reg_modes="user, ,ip", reg_max_retries="7", reg_find_time="", reg_ban_time="2h",
                totp_issuer=" X ", totp_period="", totp_skew="3")
M = dict(MAIL, password="", password_action="keep")


def mail(**kw):
    s = dict(M)
    s.update(kw)
    return s


def mail_post(settings, **kw):
    body = {"settings": settings, "apply": True, "revision": REV}
    body.update(kw)
    return {"json_body": body}


STEPS = [
    ("csrf", "GET", "/system/alerts"),
    ("acl page", "GET", "/authelia/acl/"),
    ("acl add", "POST", "/authelia/acl/", rules_form(ORIG, add_rule="1", active_group_domain="x")),
    ("acl delete", "POST", "/authelia/acl/", rules_form(ORIG, delete_rule="1", active_group_domain="open.example.com")),
    ("acl delete bad", "POST", "/authelia/acl/", rules_form(ORIG, delete_rule="x")),
    ("acl up", "POST", "/authelia/acl/", rules_form(ORIG, move_rule_up="2")),
    ("acl down", "POST", "/authelia/acl/", rules_form(ORIG, move_rule_down="0")),
    ("acl down last", "POST", "/authelia/acl/", rules_form(ORIG, move_rule_down="4")),
    ("acl noop", "POST", "/authelia/acl/", rules_form(ORIG)),
    ("acl save same", "POST", "/authelia/acl/", rules_form(ORIG, submit_action="save")),
    ("acl after save", "GET", "/authelia/acl/"),
    ("acl save edit", "POST", "/authelia/acl/", rules_form(edited(2, users="alice, carol", groups="dev"), submit_action="save")),
    ("acl add again", "POST", "/authelia/acl/", rules_form(ORIG, add_rule="1")),
    ("acl save new", "POST", "/authelia/acl/", rules_form(ORIG + [{"domains": "new.example.com, x.example.com", "policy": "",
                                                                   "resources": "^/a$\r\n^/b$", "groups": "g1,g2",
                                                                   "flag_authenticated": "on", "source_index": ""}],
                                                          submit_action="save")),
    ("acl add 1", "POST", "/authelia/acl/", rules_form(ORIG, add_rule="1")),
    ("acl add 2", "POST", "/authelia/acl/", rules_form(ORIG + [{"source_index": ""}], add_rule="1")),
    ("acl save nodomain", "POST", "/authelia/acl/", rules_form(ORIG + [{"groups": "admins", "source_index": ""},
                                                                       {"domains": " ", "source_index": ""}], submit_action="save")),
    ("acl edit advanced", "POST", "/authelia/acl/", rules_form(edited(3, domains="z.example.com"), submit_action="save")),
    ("acl edit nested", "POST", "/authelia/acl/", rules_form(edited(0, groups="admins, ops"), submit_action="save")),
    ("acl save reject", "POST", "/authelia/acl/", dict(rules_form(ORIG, submit_action="save"),
                                                       replies=with_(rules_set={"ok": False, "error": "stale revision"}))),
    ("acl apply", "POST", "/authelia/acl/", dict(rules_form(edited(1, policy="one_factor"), submit_action="apply"), replies=BASE)),
    ("acl apply page", "GET", "/authelia/acl/"),
    ("acl apply restart fail", "POST", "/authelia/acl/", dict(rules_form(ORIG, submit_action="apply"),
                                                              replies=with_(restart={"ok": False}))),
    ("acl flashes", "GET", "/authelia/acl/", {"replies": BASE}),
    ("acl bad total", "POST", "/authelia/acl/", rules_form(ORIG, total_rules="x", submit_action="save")),
    ("acl too many", "POST", "/authelia/acl/", rules_form(ORIG, total_rules="501", submit_action="save")),
    ("acl stale", "POST", "/authelia/acl/", rules_form(ORIG, acl_snapshot="bogus", submit_action="save")),
    ("acl stale sources", "POST", "/authelia/acl/", rules_form(edited(0, source_index="9"), submit_action="save")),
    ("acl load error", "GET", "/authelia/acl/", {"replies": with_(rules_get={"ok": False, "error": "socket down"})}),
    ("acl rules list", "GET", "/authelia/acl/", {"replies": with_(rules_get={"ok": True, "rules": [{"domain": "a.example.com",
                                                                                                    "policy": "bypass"}]})}),
    ("acl rules empty", "GET", "/authelia/acl/", {"replies": with_(rules_get={"ok": True, "rules_yaml": ""})}),
]
CHAINED = {"acl save new", "acl add 2", "acl save nodomain"}
_acl = []
for _st in STEPS:
    if _st[1] == "POST" and _st[2] == "/authelia/acl/" and _st[0] not in CHAINED:
        _acl.append(("refresh " + _st[0], "GET", "/authelia/acl/"))
    _acl.append(_st)
STEPS = _acl + [
    ("settings page", "GET", "/authelia/settings/", {"replies": BASE}),
    ("settings slash", "GET", "/authelia/settings"),
    ("settings save", "POST", "/authelia/settings/", form(**SETTINGS)),
    ("settings after save", "GET", "/authelia/settings/"),
    ("settings apply", "POST", "/authelia/settings/", form(submit_action="apply", **SETTINGS)),
    ("settings after apply", "GET", "/authelia/settings/"),
    ("settings bad int", "POST", "/authelia/settings/", form(reg_max_retries="7x")),
    ("settings bad int page", "GET", "/authelia/settings/"),
    ("settings apply restart fail", "POST", "/authelia/settings/", dict(form(submit_action="apply"),
                                                                       replies=with_(restart={"ok": False, "error": "boom"}))),
    ("settings update fail", "POST", "/authelia/settings/", dict(form(), replies=with_(settings_update={"ok": False, "error": "bad"}))),
    ("settings fail page", "GET", "/authelia/settings/", {"replies": BASE}),
    ("settings no cookies", "POST", "/authelia/settings/", dict(form(),
                                                               replies=with_(config_view={"ok": True, "config": {"session": {}}}))),
    ("settings unreadable", "POST", "/authelia/settings/", dict(form(), replies=with_(config_view={"ok": False, "error": "x"}))),
    ("settings load error", "GET", "/authelia/settings/"),
    ("settings load error noerr", "GET", "/authelia/settings/", {"replies": with_(config_view={"ok": False})}),
    ("settings odd config", "GET", "/authelia/settings/", {"replies": with_(config_view={"ok": True, "config": {
        "regulation": {"modes": "ip"}, "session": {"cookies": []}, "log": {"keep_stdout": 0}}})}),
    ("settings modes none", "GET", "/authelia/settings/", {"replies": with_(config_view={"ok": True, "config": None})}),

    ("mail get", "GET", "/authelia/settings/mail", {"replies": BASE}),
    ("mail get bad", "GET", "/authelia/settings/mail", {"replies": with_(mail_view={"ok": True, "settings": []})}),
    ("mail get fail", "GET", "/authelia/settings/mail", {"replies": with_(mail_view={"ok": False})}),
    ("mail post keys", "POST", "/authelia/settings/mail", {"json_body": {"settings": {}, "apply": True}, "replies": BASE}),
    ("mail post apply", "POST", "/authelia/settings/mail", mail_post(M, apply=1)),
    ("mail post nonobj", "POST", "/authelia/settings/mail", mail_post([1])),
    ("mail post fields", "POST", "/authelia/settings/mail", mail_post({"mode": "relay", "zzz": 1, "aaa": 2})),
    ("mail mode", "POST", "/authelia/settings/mail", mail_post(mail(mode="x"))),
    ("mail tls", "POST", "/authelia/settings/mail", mail_post(mail(tls_mode=None))),
    ("mail pa", "POST", "/authelia/settings/mail", mail_post(mail(password_action="REPLACE"))),
    ("mail host bad", "POST", "/authelia/settings/mail", mail_post(mail(host="bad_host"))),
    ("mail host ipv6", "POST", "/authelia/settings/mail", mail_post(mail(host="[2001:DB8::1]", port="25"))),
    ("mail host int", "POST", "/authelia/settings/mail", mail_post(mail(host=5))),
    ("mail host empty", "POST", "/authelia/settings/mail", mail_post(mail(host=" "))),
    ("mail fs", "POST", "/authelia/settings/mail", mail_post(mail(mode="filesystem", host="", port="", sender=" ",
                                                                  recipient="", subject="", tls_mode="PLAIN"))),
    ("mail port bool", "POST", "/authelia/settings/mail", mail_post(mail(port=True))),
    ("mail port float", "POST", "/authelia/settings/mail", mail_post(mail(port=25.9))),
    ("mail port str", "POST", "/authelia/settings/mail", mail_post(mail(port="x"))),
    ("mail port range", "POST", "/authelia/settings/mail", mail_post(mail(port=70000))),
    ("mail pw type", "POST", "/authelia/settings/mail", mail_post(mail(password=None))),
    ("mail pw replace empty", "POST", "/authelia/settings/mail", mail_post(mail(password_action="replace"))),
    ("mail pw keep set", "POST", "/authelia/settings/mail", mail_post(mail(password="p"))),
    ("mail pw ctrl", "POST", "/authelia/settings/mail", mail_post(mail(password="a\tb", password_action="replace"))),
    ("mail skip", "POST", "/authelia/settings/mail", mail_post(mail(tls_skip_verify="no"))),
    ("mail sender", "POST", "/authelia/settings/mail", mail_post(mail(sender="nope"))),
    ("mail recipient", "POST", "/authelia/settings/mail", mail_post(mail(recipient=7))),
    ("mail subject", "POST", "/authelia/settings/mail", mail_post(mail(subject="  "))),
    ("mail timeout", "POST", "/authelia/settings/mail", mail_post(mail(timeout="10"))),
    ("mail timeout long", "POST", "/authelia/settings/mail", mail_post(mail(timeout="x" * 17))),
    ("mail username", "POST", "/authelia/settings/mail", mail_post(mail(username="ü" * 321))),
    ("mail revision", "POST", "/authelia/settings/mail", mail_post(M, revision="A" * 64)),
    ("mail ok", "POST", "/authelia/settings/mail", mail_post(mail(password="новый", password_action="replace", host="SMTP.Example.com."))),
    ("mail conflict", "POST", "/authelia/settings/mail", dict(mail_post(M), replies=with_(mail_update={"ok": False, "conflict": True,
                                                                                                      "error": "changed"}))),
    ("mail relay", "POST", "/authelia/settings/mail", dict(mail_post(M), replies=with_(mail_update={"ok": False, "relay_unavailable": 1}))),
    ("mail daemon val", "POST", "/authelia/settings/mail", dict(mail_post(M), replies=with_(mail_update={"ok": False,
                                                                                                        "validation_error": True}))),
    ("mail 502", "POST", "/authelia/settings/mail", dict(mail_post(M), replies=with_(mail_update={"ok": False, "error": "e" * 600}))),
    ("mail test keys", "POST", "/authelia/settings/mail/test", {"json_body": {"revision": REV}, "replies": BASE}),
    ("mail test rev", "POST", "/authelia/settings/mail/test", {"json_body": {"revision": 1, "recipient": "a@b.c"}}),
    ("mail test rcpt", "POST", "/authelia/settings/mail/test", {"json_body": {"revision": REV, "recipient": "bad"}}),
    ("mail test ok", "POST", "/authelia/settings/mail/test", {"json_body": {"revision": REV, "recipient": " a@example.com "}}),
    ("mail test rate", "POST", "/authelia/settings/mail/test", {"json_body": {"revision": REV, "recipient": "a@example.com"},
                                                                "replies": with_(mail_test={"ok": False, "rate_limited": True})}),
    ("mail test unsupported", "POST", "/authelia/settings/mail/test", {"json_body": {"revision": REV, "recipient": "a@example.com"},
                                                                       "replies": with_(mail_test={"ok": False, "unsupported": True})}),
    ("mail test val", "POST", "/authelia/settings/mail/test", {"json_body": {"revision": REV, "recipient": "a@example.com"},
                                                               "replies": with_(mail_test={"ok": False, "validation_error": 1})}),
    ("mail test 502", "POST", "/authelia/settings/mail/test", {"json_body": {"revision": REV, "recipient": "a@example.com"},
                                                               "replies": with_(mail_test={"ok": False})}),
    ("mail test form", "POST", "/authelia/settings/mail/test", {"form": {"revision": REV}, "headers": {"X-CSRFToken": "CSRF"},
                                                                "replies": BASE}),
    ("notif latest", "GET", "/authelia/settings/notifications/latest"),
    ("notif latest none", "GET", "/authelia/settings/notifications/latest",
     {"replies": with_(notification_latest={"ok": True, "latest": "x", "status": "empty"})}),
    ("notif latest conflict", "GET", "/authelia/settings/notifications/latest",
     {"replies": with_(notification_latest={"ok": False, "conflict": True})}),
    ("notif latest val", "GET", "/authelia/settings/notifications/latest",
     {"replies": with_(notification_latest={"ok": False, "validation_error": True})}),
    ("notif latest 502", "GET", "/authelia/settings/notifications/latest", {"replies": with_(notification_latest={"error": "x"})}),
    ("notif reveal keys", "POST", "/authelia/settings/notifications/latest/reveal", {"json_body": {"id": "b" * 64}, "replies": BASE}),
    ("notif reveal bad id", "POST", "/authelia/settings/notifications/latest/reveal", {"json_body": {"id": "b", "revision": "c" * 64}}),
    ("notif reveal ok", "POST", "/authelia/settings/notifications/latest/reveal", {"json_body": {"id": "b" * 64, "revision": "c" * 64}}),
    ("notif reveal rate", "POST", "/authelia/settings/notifications/latest/reveal",
     {"json_body": {"id": "b" * 64, "revision": "c" * 64}, "replies": with_(notification_reveal={"ok": False, "rate_limited": 1})}),
    ("notif reveal conflict", "POST", "/authelia/settings/notifications/latest/reveal",
     {"json_body": {"id": "b" * 64, "revision": "c" * 64}, "replies": with_(notification_reveal={"ok": False, "conflict": 1})}),
    ("notif handle keys", "POST", "/authelia/settings/notifications/latest/handled", {"json_body": {}, "replies": BASE}),
    ("notif handle bad", "POST", "/authelia/settings/notifications/latest/handled", {"json_body": {"id": 1, "revision": 2}}),
    ("notif handle ok", "POST", "/authelia/settings/notifications/latest/handled", {"json_body": {"id": "b" * 64, "revision": "c" * 64}}),
    ("notif handle val", "POST", "/authelia/settings/notifications/latest/handled",
     {"json_body": {"id": "b" * 64, "revision": "c" * 64},
      "replies": with_(notification_handle={"ok": False, "validation_error": True, "error": "x", "secret": 1})}),
    ("notif handle forbidden", "POST", "/authelia/settings/notifications/latest/handled",
     {"json_body": {"id": "b" * 64, "revision": "c" * 64}, "replies": with_(notification_handle={"ok": False, "forbidden": True})}),
    ("notif reveal no user", "POST", "/authelia/settings/notifications/latest/reveal",
     {"json_body": {"id": "b" * 64, "revision": "c" * 64}, "user": None, "replies": BASE}),
]
