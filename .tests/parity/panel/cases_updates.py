"""Software updates, OS security and SSH security through the update broker."""
import copy

PLAN = "b" * 32
BOOT = "58eacc1c-f8a0-4c2f-86f4-45f4aaaaaaaa"


def ordered(table):
    return dict(sorted(table.items(), key=lambda kv: -len(kv[0])))


UPDATED = ordered({
    "status": {"ok": True, "summary": {"level": "os", "build": {"revision": "abc"}}, "jobs": []},
    "start_check": {"ok": True, "job_id": "c" * 32},
    "set_channels": {"ok": True},
    "set_settings": {"ok": True},
    "set_auto_install": {"ok": True},
    "start_apply": {"ok": True, "job_id": "d" * 32},
    "reboot": {"ok": True},
    "cancel_reboot": {"ok": False, "error": "nothing scheduled", "error_code": "not_required"},
    "prepare_haproxy_migration": {"ok": True},
    "apply_haproxy_migration": {"ok": True},
    "start_haproxy_transition": {"ok": True},
    "os_security_status": {"ok": True, "available": True},
    "os_security_check": {"ok": True, "job_id": "e" * 32},
    "os_security_configure": {"ok": True},
    "os_security_install": {"ok": True},
    "os_security_restart_check": {"ok": True},
    "os_security_restart": {"ok": True},
    "set_auto_reboot": {"ok": True},
    "set_service_restarts": {"ok": True},
    "ssh_protection_status": {"ok": True, "installed": False},
    "ssh_protection_connection": {"ok": True},
    "ssh_protection_monitor": {"ok": True},
    "ssh_protection_configure": {"ok": True, "job_id": "f" * 32},
    "ssh_protection_unban": {"ok": True},
})
BASE = {"easy-ha-proxy-updated": UPDATED,
        "controld": {"config-transaction-status": {"b64json": {"ok": True, "state": "none"}}}}
REPLIES = BASE


def with_(key, value):
    r = copy.deepcopy(BASE)
    r["easy-ha-proxy-updated"][key] = value
    r["easy-ha-proxy-updated"] = ordered(r["easy-ha-proxy-updated"])
    return r


def j(body, **kw):
    return dict({"json_body": body}, **kw)


U = "/system/updates/api"
O = "/system/os-security/api"
S = "/system/ssh-security/api"

STEPS = [
    ("csrf", "GET", "/system/alerts"),
    ("status", "GET", U + "/status"),
    ("status job", "GET", U + "/status?job_id=%20" + "A" * 32 + "%20"),
    ("status bad job", "GET", U + "/status?job_id=zz"),
    ("status error", "GET", U + "/status", {"replies": with_("status", {"ok": False, "error": "x", "error_code": "missing"})}),
    ("status bad code", "GET", U + "/status", {"replies": with_("status", {"ok": False, "error_code": "weird"})}),
    ("status validation", "GET", U + "/status", {"replies": with_("status", {"ok": False, "validation_error": True})}),
    ("check none", "POST", U + "/check", j({}, replies=BASE)),
    ("check channels", "POST", U + "/check", j({"source_channel": "local", "release_channel": "alpha", "image_channel": "latest"})),
    ("check bad channel", "POST", U + "/check", j({"image_channel": "beta"})),
    ("check extra", "POST", U + "/check", j({"x": 1})),
    ("check not object", "POST", U + "/check", j([1])),
    ("channels none", "POST", U + "/channels", j({})),
    ("channels ok", "POST", U + "/channels", j({"release_channel": "stable"})),
    ("settings bad", "POST", U + "/settings", j({"auto_check_hours": True})),
    ("settings odd", "POST", U + "/settings", j({"auto_check_hours": 5})),
    ("settings ok", "POST", U + "/settings", j({"auto_check_hours": 0})),
    ("auto bad enabled", "POST", U + "/auto-install", j({"enabled": 1, "start": 3, "end": 5})),
    ("auto bad os", "POST", U + "/auto-install", j({"enabled": True, "start": 3, "end": 5, "os": "yes"})),
    ("auto bad hour", "POST", U + "/auto-install", j({"enabled": True, "start": 24, "end": 5})),
    ("auto same", "POST", U + "/auto-install", j({"enabled": True, "start": 3, "end": 3})),
    ("auto ok", "POST", U + "/auto-install", j({"enabled": False, "start": 3, "end": 5, "unified": True})),
    ("apply no confirm", "POST", U + "/apply", j({"plan_id": PLAN, "components": ["os"], "confirmation": "update"})),
    ("apply bad plan", "POST", U + "/apply", j({"plan_id": "x", "components": ["os"], "confirmation": "UPDATE"})),
    ("apply empty", "POST", U + "/apply", j({"plan_id": PLAN, "components": [], "confirmation": "UPDATE"})),
    ("apply unknown", "POST", U + "/apply", j({"plan_id": PLAN, "components": ["os", "x"], "confirmation": "UPDATE"})),
    ("apply dup", "POST", U + "/apply", j({"plan_id": PLAN, "components": ["os", "os"], "confirmation": "UPDATE"})),
    ("apply os", "POST", U + "/apply", j({"plan_id": PLAN.upper(), "components": ["os", "admin-container"], "confirmation": "UPDATE"})),
    ("apply sensitive", "POST", U + "/apply", j({"plan_id": PLAN, "components": ["services", "changes"], "confirmation": "UPDATE"})),
    ("transition bad", "POST", U + "/haproxy/migration/start", j({"target_branch": "3.4", "confirmed": 1})),
    ("transition", "POST", U + "/haproxy/migration/start", j({"target_branch": "3.4", "confirmed": True})),
    ("prepare bad", "POST", U + "/haproxy/migration/prepare", j({"target_branch": "3.2"})),
    ("prepare", "POST", U + "/haproxy/migration/prepare", j({"target_branch": "3.4"})),
    ("migrate bad", "POST", U + "/haproxy/migration/apply", j({"plan_id": PLAN, "confirmation": "MIGRATE"})),
    ("migrate", "POST", U + "/haproxy/migration/apply", j({"plan_id": PLAN, "confirmation": "MIGRATE 3.4"})),
    ("reboot bad", "POST", U + "/reboot", j({"confirmation": "reboot", "expected_boot_id": BOOT})),
    ("reboot bad boot", "POST", U + "/reboot", j({"confirmation": "REBOOT", "expected_boot_id": "x"})),
    ("reboot", "POST", U + "/reboot", j({"confirmation": "REBOOT", "expected_boot_id": " " + BOOT.upper()})),
    ("reboot bad actor", "POST", U + "/reboot", j({"confirmation": "REBOOT", "expected_boot_id": BOOT}, user="bad user")),
    ("cancel reboot", "POST", U + "/reboot/cancel", j({"expected_boot_id": BOOT})),
    ("broker down", "POST", U + "/settings", j({"auto_check_hours": 6}, replies=with_("set_settings", "not json"))),

    ("os status", "GET", O + "/status?job_id=" + "e" * 32, {"replies": BASE}),
    ("os status blank job", "GET", O + "/status?job_id=%20"),
    ("os check", "POST", O + "/check", j({})),
    ("os check extra", "POST", O + "/check", j({"a": 1})),
    ("os policy bad", "POST", O + "/policy", j({"mode": "auto", "interval": 3, "start": 1, "end": 2, "confirmation": "SECURITY"})),
    ("os policy same", "POST", O + "/policy", j({"mode": "auto", "interval": 6, "start": 1, "end": 1, "confirmation": "SECURITY"})),
    ("os policy ok", "POST", O + "/policy", j({"mode": "window", "interval": 24, "start": 1, "end": 5, "confirmation": "SECURITY"})),
    ("os install bad", "POST", O + "/install", j({"confirmation": "security"})),
    ("os install", "POST", O + "/install", j({"confirmation": "SECURITY"})),
    ("os reboot bad time", "POST", O + "/automatic-reboot", j({"enabled": True, "time": "24:00", "confirmation": "REBOOT",
                                                              "expected_boot_id": BOOT})),
    ("os reboot bad allow", "POST", O + "/automatic-reboot", j({"enabled": True, "time": "03:30", "confirmation": "REBOOT",
                                                               "expected_boot_id": BOOT, "allow_service_reboot": 1})),
    ("os reboot off", "POST", O + "/automatic-reboot", j({"enabled": False, "time": "03:30", "confirmation": "REBOOT",
                                                         "expected_boot_id": BOOT, "allow_service_reboot": True})),
    ("os reboot on", "POST", O + "/automatic-reboot", j({"expected_boot_id": BOOT, "enabled": True, "time": "03:30",
                                                        "confirmation": "REBOOT"})),
    ("os restart policy", "POST", O + "/restart-policy", j({"time": "04:00", "enabled": False, "confirmation": "SECURITY",
                                                           "expected_boot_id": BOOT.upper()})),
    ("os restart policy bad boot", "POST", O + "/restart-policy", j({"time": "04:00", "enabled": False, "confirmation": "SECURITY",
                                                                    "expected_boot_id": "nope"})),
    ("os restart check", "POST", O + "/restart-check", j({})),
    ("os restart bad", "POST", O + "/restart", j({"confirmation": "x"})),
    ("os restart", "POST", O + "/restart", j({"confirmation": "SECURITY"})),

    ("ssh status", "GET", S + "/status"),
    ("ssh connection", "POST", S + "/connection", j({"user": "root", "ip": "203.0.113.5", "port": 22})),
    ("ssh connection missing", "POST", S + "/connection", j({"user": "root"})),
    ("ssh monitoring bad", "POST", S + "/monitoring", j({"enabled": "on"})),
    ("ssh monitoring", "POST", S + "/monitoring", j({"enabled": True})),
    ("ssh protection bad", "POST", S + "/protection", j({"operation": "zap", "trusted": []})),
    ("ssh protection", "POST", S + "/protection", j({"operation": "install", "trusted": ["10.0.0.0/8"], "policy": {"bantime": 600}})),
    ("ssh unban", "POST", S + "/unban", j({"ip": "203.0.113.5"})),
    ("ssh unban failed", "POST", S + "/unban", j({"ip": "203.0.113.6"}, replies=with_("ssh_protection_unban",
                                                                                      {"ok": False, "error": "not banned"}))),
    ("ssh history", "GET", S + "/unblock-history"),
]


def normalize_body(label, body):
    import re
    return re.sub(r'"ts": 1[0-9]{9}', '"ts": T', body)
