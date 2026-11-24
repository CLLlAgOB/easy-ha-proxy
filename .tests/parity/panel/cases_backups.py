"""Full backups and disaster recovery through backupd: jobs, uploads, downloads, destinations, schedule."""
import copy
import os
import re

ROOT = "/var/lib/easy-ha-proxy/backup-web"
B1 = "1" * 32
B2 = "2" * 32
B3 = "3" * 32
B4 = "4" * 32
B5 = "5" * 32
PASS = "correct horse battery"


def ordered(table):
    return dict(sorted(table.items(), key=lambda kv: -len(kv[0])))


BACKUPS = [
    {"id": B1, "archive_name": B1 + ".tar.gz.enc", "checksum_name": B1 + ".sha256"},
    {"backup_id": B2.upper(), "archive_name": B2 + ".tar.gz.enc"},
    {"id": B3, "archive_name": "../etc/passwd"},
    {"id": B4, "archive_name": B1 + ".tar.gz.enc"},
    {"id": B5, "archive_name": B5 + ".tar.gz.enc", "checksum_name": B5 + ".sha256"},
    "junk",
]
BACKUPD = ordered({
    "status": {"ok": True, "backups": BACKUPS, "jobs": []},
    "start_backup": {"ok": True, "job_id": "a" * 32},
    "start_inspect": {"ok": True, "job_id": "b" * 32},
    "stage_backup": {"ok": True, "upload_id": "c" * 32},
    "start_restore": {"ok": True, "job_id": "d" * 32},
    "delete": {"ok": False, "error": "in use", "error_code": "busy"},
    "destinations": {"ok": True, "destinations": []},
    "destination_save": {"ok": True},
    "destination_delete": {"ok": False, "error_code": "not_found"},
    "destination_test": {"ok": False, "error_code": "too_large"},
    "destination_retrust": {"ok": False, "error_code": "insufficient_space"},
    "upload": {"ok": True},
    "schedule": {"ok": True, "enabled": False},
    "schedule_save": {"ok": True},
    "run_scheduled": {"ok": True, "job_id": "e" * 32},
})
BASE = {"easy-ha-proxy-backupd": BACKUPD}
REPLIES = BASE


def setup():
    for d in ("uploads", "backups"):
        os.makedirs(os.path.join(ROOT, d), exist_ok=True)
    b = os.path.join(ROOT, "backups")
    with open(os.path.join(b, B1 + ".tar.gz.enc"), "wb") as fh:
        fh.write(b"\x00encrypted" * 100)
    with open(os.path.join(b, B1 + ".sha256"), "w") as fh:
        fh.write("abc  " + B1 + ".tar.gz.enc\n")
    with open(os.path.join(b, B5 + ".tar.gz.enc"), "wb") as fh:
        fh.write(b"x")
    if os.path.exists("/srv/hardlink.bin"):
        os.unlink("/srv/hardlink.bin")
    os.link(os.path.join(b, B5 + ".tar.gz.enc"), "/srv/hardlink.bin")
    os.symlink(os.path.join(b, B1 + ".sha256"), os.path.join(b, B5 + ".sha256"))


def with_(key, value):
    r = copy.deepcopy(BASE)
    r["easy-ha-proxy-backupd"][key] = value
    r["easy-ha-proxy-backupd"] = ordered(r["easy-ha-proxy-backupd"])
    return r


def j(body, **kw):
    return dict({"json_body": body}, **kw)


def up(data, ctype="application/octet-stream"):
    return {"raw": data, "headers": {"Content-Type": ctype, "X-CSRFToken": "CSRF"}}


def normalize_body(label, body):
    return re.sub(r'"upload_id": "[0-9a-f]{32}"', '"upload_id": "U"', body)


def normalize_key(key):
    return re.sub(r"/uploads/[0-9a-f]{32}\.tar\.gz\.enc$", "/uploads/U.tar.gz.enc", key)


A = "/system/backups/api"

STEPS = [
    ("csrf", "GET", "/system/alerts"),
    ("status", "GET", A + "/status"),
    ("status job", "GET", A + "/status?job_id=" + "A" * 32),
    ("status bad job", "GET", A + "/status?job_id=x"),
    ("backup bad bool", "POST", A + "/jobs/backup", j({"passphrase": PASS, "include_ssh": 1, "quiesce": True})),
    ("backup short pass", "POST", A + "/jobs/backup", j({"passphrase": "short", "include_ssh": True, "quiesce": True})),
    ("backup newline pass", "POST", A + "/jobs/backup", j({"passphrase": PASS + "\n", "include_ssh": True, "quiesce": True})),
    ("backup ok", "POST", A + "/jobs/backup", j({"passphrase": PASS, "include_ssh": False, "quiesce": True})),
    ("backup extra", "POST", A + "/jobs/backup", j({"passphrase": PASS, "include_ssh": False, "quiesce": True, "x": 1})),
    ("upload empty", "POST", A + "/uploads", up(b"")),
    ("upload wrong type", "POST", A + "/uploads", up(b"abc", "text/plain")),
    ("upload ok", "POST", A + "/uploads", up(b"\x01\x02archive" * 1000)),
    ("inspect bad id", "POST", A + "/uploads/zz/inspect", j({"passphrase": PASS})),
    ("inspect ok", "POST", A + "/uploads/" + "C" * 32 + "/inspect", j({"passphrase": PASS})),
    ("stage", "POST", A + "/backups/" + B1 + "/stage", {"headers": {"X-CSRFToken": "CSRF"}}),
    ("stage bad", "POST", A + "/backups/x/stage", {"headers": {"X-CSRFToken": "CSRF"}}),
    ("restore no confirm", "POST", A + "/jobs/restore", j({"upload_id": B1, "inspection_job_id": B2, "passphrase": PASS,
                                                         "restore_ssh": False, "confirmation": "restore"})),
    ("restore bad ssh", "POST", A + "/jobs/restore", j({"upload_id": B1, "inspection_job_id": B2, "passphrase": PASS,
                                                       "restore_ssh": "no", "confirmation": "RESTORE"})),
    ("restore bad scope", "POST", A + "/jobs/restore", j({"upload_id": B1, "inspection_job_id": B2, "passphrase": PASS,
                                                         "restore_ssh": False, "confirmation": "RESTORE", "scope": "x"})),
    ("restore config ssh", "POST", A + "/jobs/restore", j({"upload_id": B1, "inspection_job_id": B2, "passphrase": PASS,
                                                          "restore_ssh": True, "confirmation": "RESTORE", "scope": "config"})),
    ("restore ok", "POST", A + "/jobs/restore", j({"upload_id": " " + B1.upper(), "inspection_job_id": B2, "passphrase": PASS,
                                                  "restore_ssh": True, "confirmation": "RESTORE"})),
    ("delete bad kind", "POST", A + "/delete", j({"kind": "job", "id": B1, "confirmation": "DELETE"})),
    ("delete busy", "POST", A + "/delete", j({"kind": "backup", "id": B1, "confirmation": "DELETE"})),
    ("download", "GET", "/system/backups/download/" + B1),
    ("download checksum", "GET", "/system/backups/download/" + B1 + "?checksum=1"),
    ("download upper id", "GET", "/system/backups/download/" + B2),
    ("download unsafe name", "GET", "/system/backups/download/" + B3),
    ("download wrong prefix", "GET", "/system/backups/download/" + B4),
    ("download hardlinked", "GET", "/system/backups/download/" + B5),
    ("download symlink", "GET", "/system/backups/download/" + B5 + "?checksum=1"),
    ("download unknown", "GET", "/system/backups/download/" + "9" * 32),
    ("download bad id", "GET", "/system/backups/download/x"),
    ("download daemon error", "GET", "/system/backups/download/" + B1, {"replies": with_("status", {"ok": False, "error": "down"})}),
    ("destinations", "GET", A + "/destinations", {"replies": BASE}),
    ("dest save bad name", "POST", A + "/destinations", j({"name": "-bad", "type": "sftp"})),
    ("dest save", "POST", A + "/destinations", j({"type": "sftp", "password": "pw", "name": " NAS ", "host": "10.0.0.5",
                                                "user": "bk", "port": 22})),
    ("dest save extra", "POST", A + "/destinations", j({"name": "nas", "type": "sftp", "zzz": 1})),
    ("dest delete", "POST", A + "/destinations/delete", j({"name": "nas"})),
    ("dest test", "POST", A + "/destinations/test", j({"name": "nas"})),
    ("dest retrust", "POST", A + "/destinations/trust-host-key", j({"name": "nas"})),
    ("dest upload", "POST", A + "/destinations/upload", j({"backup_id": B1, "destination": "nas"})),
    ("schedule", "GET", A + "/schedule"),
    ("schedule bad enabled", "POST", A + "/schedule", j({"enabled": 1})),
    ("schedule bad quiesce", "POST", A + "/schedule", j({"quiesce": "y"})),
    ("schedule bad time", "POST", A + "/schedule", j({"time": "3:00"})),
    ("schedule bad keep", "POST", A + "/schedule", j({"keep_local": True})),
    ("schedule bad dests", "POST", A + "/schedule", j({"destinations": "nas"})),
    ("schedule bad dest name", "POST", A + "/schedule", j({"destinations": ["nas", "Bad_Name"]})),
    ("schedule forget pass", "POST", A + "/schedule", j({"passphrase": ""})),
    ("schedule ok", "POST", A + "/schedule", j({"time": " 29:59 ", "keep_local": 5, "destinations": [" NAS ", "s3"],
                                               "enabled": True, "include_ssh": False, "passphrase": PASS})),
    ("schedule daemon down", "POST", A + "/schedule", j({"enabled": False}, replies=with_("schedule_save", "x"))),
    ("schedule run", "POST", A + "/schedule/run", {"headers": {"X-CSRFToken": "CSRF"}, "replies": BASE}),
]
