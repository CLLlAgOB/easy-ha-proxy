"""Health API (healthd proxy, service control) and alerts API (alertd proxy)."""
import copy

ENV = {"HEALTHD_TOKEN": " tok-h ", "ALERTD_TOKEN": "tok-a"}

CAPS = {"ok": True, "systemd": {"haproxy.service": ["restart", "reload"], "easy-ha-proxy-*.service": ["restart", 5],
                                "x[ab].service": ["stop"], "[!z]*.timer": ["start"], "broken[.service": ["stop"],
                                "nolist.service": "restart"},
        "docker": {"haproxy-admin": ["restart"]}}
BASE = {
    "haproxy-healthd": {
        "GET /api/v1/health/status": {"ok": True, "services": [{"name": "haproxy", "active": True}], "ts": 1},
        "GET /api/v1/health/events": {"ok": True, "events": []},
        "GET /api/v1/health/logs/systemd": {"ok": True, "lines": ["a", "b"]},
        "GET /api/v1/health/recent-systemd": {"ok": True, "entries": []},
        "GET /api/v1/health/logs/docker": {"ok": True, "lines": []},
        "GET /api/v1/control/capabilities": CAPS,
        "POST /api/v1/control": {"ok": True, "stdout": "done\n", "stderr": ""},
    },
    "easy-ha-proxy-alertd": {
        "GET /api/v1/alerts/state": {"ok": True, "alerts": [{"rule": "r", "subject": "s"}]},
        "GET /api/v1/alerts/health": {"ok": True, "uptime": 5},
        "GET /api/v1/alerts/history": {"ok": True, "items": [], "total": 0},
        "GET /api/v1/alerts/portal": {"ok": True, "open": 1},
        "POST /api/v1/alerts/config": {"ok": True, "config": {"webhook": "https://x/…"}},
        "POST /api/v1/alerts/quieten": {"ok": True},
        "POST /api/v1/alerts/dismiss": {"ok": True},
        "POST /api/v1/alerts/history/delete": {"ok": True, "deleted": 3},
        "POST /api/v1/alerts/mail/retry": {"ok": True},
        "POST /api/v1/alerts/test": {"ok": True, "delivered": ["mail", "webhook"], "errors": []},
    },
}
REPLIES = BASE


def with_(daemon, key, value):
    r = copy.deepcopy(BASE)
    table = r[daemon]
    table[key] = value
    r[daemon] = dict(sorted(table.items(), key=lambda kv: -len(kv[0])))
    return r


def j(body, **kw):
    return dict({"json_body": body}, **kw)


H = "haproxy-healthd"
A = "easy-ha-proxy-alertd"
ADMIN = {"groups": "admins"}

STEPS = [
    ("csrf", "GET", "/system/alerts"),
    ("cp health", "GET", "/api/control-plane-health"),
    ("status", "GET", "/api/health/status"),
    ("status refresh", "GET", "/api/health/status?refresh=1"),
    ("status refresh other", "GET", "/api/health/status?refresh=yes"),
    ("status 500", "GET", "/api/health/status", {"replies": with_(H, "GET /api/v1/health/status", {"__status": 500, "x": 1})}),
    ("status 404", "GET", "/api/health/status?refresh=1", {"replies": with_(H, "GET /api/v1/health/status", {"__status": 404})}),
    ("status raw", "GET", "/api/health/status", {"replies": with_(H, "GET /api/v1/health/status", {"__raw": "<html>" + "x" * 2100})}),
    ("status list", "GET", "/api/health/status", {"replies": with_(H, "GET /api/v1/health/status", [1, 2])}),
    ("events", "GET", "/api/health/events", {"replies": BASE}),
    ("events limit", "GET", "/api/health/events?limit=700"),
    ("events limit low", "GET", "/api/health/events?limit=-3"),
    ("events limit bad", "GET", "/api/health/events?limit=x"),
    ("events limit space", "GET", "/api/health/events?limit=%2012%20"),
    ("logs no unit", "GET", "/api/health/logs/systemd"),
    ("logs blank unit", "GET", "/api/health/logs/systemd?unit=%20"),
    ("logs unit", "GET", "/api/health/logs/systemd?unit=%20haproxy.service%20&tail=50&since=60"),
    ("logs bad tail", "GET", "/api/health/logs/systemd?unit=a%20b&tail=50&since=x"),
    ("docker no container", "GET", "/api/health/logs/docker"),
    ("docker", "GET", "/api/health/logs/docker?container=haproxy-admin&tail=x"),
    ("recent", "GET", "/api/health/recent-systemd"),
    ("recent units", "GET", "/api/health/recent-systemd?unit=a.service,b.service&units=%20b.service,c.service%20&unit=&limit=9999"),
    ("recent empty units", "GET", "/api/health/recent-systemd?units=&limit=0"),
    ("recent invalid", "GET", "/api/health/recent-systemd?unit=bad", {"replies": with_(
        H, "GET /api/v1/health/recent-systemd", {"__status": 400, "ok": False, "invalid_units": ["bad"]})}),
    ("recent 400 plain", "GET", "/api/health/recent-systemd?unit=bad", {"replies": with_(
        H, "GET /api/v1/health/recent-systemd", {"__status": 400, "ok": False, "error": "x"})}),
    ("recent 500", "GET", "/api/health/recent-systemd", {"replies": with_(H, "GET /api/v1/health/recent-systemd", {"__status": 503})}),
    ("recent list", "GET", "/api/health/recent-systemd", {"replies": with_(H, "GET /api/v1/health/recent-systemd", ["a"])}),
    ("caps", "GET", "/api/health/capabilities", {"replies": BASE}),
    ("control admin", "POST", "/api/health/control", j({"kind": "systemd", "name": "haproxy.service", "action": "restart"}, **ADMIN)),
    ("control bad kind", "POST", "/api/health/control", j({"kind": "vm", "name": "x", "action": "start"})),
    ("control no name", "POST", "/api/health/control", j({"kind": " SystemD ", "name": " ", "action": "start"})),
    ("control bad action", "POST", "/api/health/control", j({"kind": "docker", "name": "x", "action": "kill"})),
    ("control int kind", "POST", "/api/health/control", j({"kind": 5, "name": "x", "action": "start"})),
    ("control exact", "POST", "/api/health/control", j({"kind": "systemd", "name": "haproxy.service", "action": " RELOAD "})),
    ("control glob", "POST", "/api/health/control", j({"kind": "systemd", "name": "easy-ha-proxy-guardd.service", "action": "restart"})),
    ("control glob seq", "POST", "/api/health/control", j({"kind": "systemd", "name": "xb.service", "action": "stop"})),
    ("control glob neg", "POST", "/api/health/control", j({"kind": "systemd", "name": "apt.timer", "action": "start"})),
    ("control glob neg miss", "POST", "/api/health/control", j({"kind": "systemd", "name": "zz.timer", "action": "start"})),
    ("control not allowed", "POST", "/api/health/control", j({"kind": "systemd", "name": "easy-ha-proxy-x.service", "action": "stop"})),
    ("control broken pattern", "POST", "/api/health/control", j({"kind": "systemd", "name": "broken[.service", "action": "stop"})),
    ("control nolist", "POST", "/api/health/control", j({"kind": "systemd", "name": "nolist.service", "action": "restart"})),
    ("control docker", "POST", "/api/health/control", j({"kind": "docker", "name": "haproxy-admin", "action": "restart"})),
    ("control docker unknown", "POST", "/api/health/control", j({"kind": "docker", "name": "other", "action": "restart"})),
    ("control failed", "POST", "/api/health/control", j({"kind": "docker", "name": "haproxy-admin", "action": "restart"},
                                                         replies=with_(H, "POST /api/v1/control", {"ok": False, "stdout": "o", "stderr": "e"}))),
    ("control failed error", "POST", "/api/health/control", j({"kind": "docker", "name": "haproxy-admin", "action": "restart"},
                                                               replies=with_(H, "POST /api/v1/control", {"ok": False, "error": "boom", "text": "t"}))),
    ("control scheduled", "POST", "/api/health/control", j({"kind": "docker", "name": "haproxy-admin", "action": "restart"},
                                                            replies=with_(H, "POST /api/v1/control", {"scheduled": True, "text": "later"}))),
    ("control http 500", "POST", "/api/health/control", j({"kind": "docker", "name": "haproxy-admin", "action": "restart"},
                                                           replies=with_(H, "POST /api/v1/control", {"__status": 500}))),
    ("control caps not ok", "POST", "/api/health/control", j({"kind": "docker", "name": "haproxy-admin", "action": "restart"},
                                                              replies=with_(H, "GET /api/v1/control/capabilities", {"ok": 1}))),
    ("control caps list", "POST", "/api/health/control", j({"kind": "docker", "name": "haproxy-admin", "action": "restart"},
                                                            replies=with_(H, "GET /api/v1/control/capabilities", [1]))),
    ("control caps empty kind", "POST", "/api/health/control", j({"kind": "docker", "name": "haproxy-admin", "action": "restart"},
                                                                  replies=with_(H, "GET /api/v1/control/capabilities", {"ok": True}))),

    ("alerts state", "GET", "/api/alerts/state", {"replies": BASE}),
    ("alerts state limit", "GET", "/api/alerts/state?limit=0"),
    ("alerts state limit big", "GET", "/api/alerts/state?limit=9000"),
    ("alerts state limit bad", "GET", "/api/alerts/state?limit=1.5"),
    ("alerts health", "GET", "/api/alerts/health"),
    ("alerts history", "GET", "/api/alerts/history?offset=-5&rule=%20disk%20&severity="),
    ("alerts history big", "GET", "/api/alerts/history?limit=50&offset=99999999&severity=critical"),
    ("alerts portal", "GET", "/api/alerts/portal"),
    ("alerts portal 500", "GET", "/api/alerts/portal", {"replies": with_(A, "GET /api/v1/alerts/portal", {"__status": 500})}),
    ("alerts portal raw", "GET", "/api/alerts/portal", {"replies": with_(A, "GET /api/v1/alerts/portal", {"__raw": "nope"})}),
    ("alerts portal list", "GET", "/api/alerts/portal", {"replies": with_(A, "GET /api/v1/alerts/portal", [1])}),
    ("alerts config list", "POST", "/api/alerts/config", j([1], replies=BASE)),
    ("alerts config admin", "POST", "/api/alerts/config", j({"webhook": "x"}, **ADMIN)),
    ("alerts config", "POST", "/api/alerts/config", j({"webhook": "https://hook", "mail": True, "a": None})),
    ("alerts config empty", "POST", "/api/alerts/config", j({})),
    ("alerts config refused", "POST", "/api/alerts/config", j({"webhook": "bad"}, replies=with_(
        A, "POST /api/v1/alerts/config", {"__status": 400, "ok": False, "error": "invalid webhook"}))),
    ("alerts config list answer", "POST", "/api/alerts/config", j({"webhook": "bad"}, replies=with_(
        A, "POST /api/v1/alerts/config", [1]))),
    ("alerts config raw", "POST", "/api/alerts/config", j({"webhook": "bad"}, replies=with_(
        A, "POST /api/v1/alerts/config", {"__raw": "x", "__status": 500}))),
    ("alerts quieten", "POST", "/api/alerts/quieten", j({"rule": " disk.full ", "subject": "/" * 300, "mode": "mute", "seconds": 3600},
                                                         replies=BASE)),
    ("alerts quieten no seconds", "POST", "/api/alerts/quieten", j({"rule": 5, "subject": {"a": 1}, "mode": None})),
    ("alerts quieten none seconds", "POST", "/api/alerts/quieten", j({"rule": "r", "seconds": None})),
    ("alerts quieten list", "POST", "/api/alerts/quieten", j(["x"])),
    ("alerts quieten refused", "POST", "/api/alerts/quieten", j({"rule": "r", "mode": "zzz", "seconds": 1.5}, replies=with_(
        A, "POST /api/v1/alerts/quieten", {"ok": False, "error": "unknown mode " + "y" * 400}))),
    ("alerts dismiss", "POST", "/api/alerts/dismiss", j({"rule": "r", "subject": "s"}, replies=BASE)),
    ("alerts dismiss refused", "POST", "/api/alerts/dismiss", j({}, replies=with_(A, "POST /api/v1/alerts/dismiss", {"ok": False}))),
    ("alerts retry", "POST", "/api/alerts/mail/retry", {"headers": {"X-CSRFToken": "CSRF"}, "replies": BASE}),
    ("alerts retry refused", "POST", "/api/alerts/mail/retry", {"headers": {"X-CSRFToken": "CSRF"}, "replies": with_(
        A, "POST /api/v1/alerts/mail/retry", {"ok": False, "error": "nothing held"})}),
    ("alerts hist delete admin", "POST", "/api/alerts/history/delete", j({"all": True}, replies=BASE, **ADMIN)),
    ("alerts hist delete list", "POST", "/api/alerts/history/delete", j(["x"])),
    ("alerts hist delete all", "POST", "/api/alerts/history/delete", j({"all": True, "ids": [1]})),
    ("alerts hist delete all1", "POST", "/api/alerts/history/delete", j({"all": 1, "ids": list(range(1200))})),
    ("alerts hist delete none", "POST", "/api/alerts/history/delete", j({"ids": "1,2"})),
    ("alerts hist delete refused", "POST", "/api/alerts/history/delete", j({"ids": [1]}, replies=with_(
        A, "POST /api/v1/alerts/history/delete", {"ok": False, "error": "locked"}))),
    ("alerts test admin", "POST", "/api/alerts/test", {"headers": {"X-CSRFToken": "CSRF"}, "groups": "admins", "replies": BASE}),
    ("alerts test", "POST", "/api/alerts/test", {"headers": {"X-CSRFToken": "CSRF"}}),
    ("alerts test none", "POST", "/api/alerts/test", {"headers": {"X-CSRFToken": "CSRF"}, "replies": with_(
        A, "POST /api/v1/alerts/test", {"ok": False, "delivered": [], "errors": ["mail: refused", "hook: 500"]})}),
    ("alerts test bad delivered", "POST", "/api/alerts/test", {"headers": {"X-CSRFToken": "CSRF"}, "replies": with_(
        A, "POST /api/v1/alerts/test", {"ok": True, "delivered": [1]})}),
]
