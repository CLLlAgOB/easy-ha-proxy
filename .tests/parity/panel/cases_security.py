"""Adaptive protection, detection rules and Log Explorer (all through guardd)."""
import copy


def ordered(table):
    return dict(sorted(table.items(), key=lambda kv: -len(kv[0])))


GUARDD = ordered({
    "GET /api/v1/guard/signatures/candidates": {"ok": True, "candidates": [{"path": "/x.php", "count": 9}]},
    "GET /api/v1/guard/signatures": {"ok": True, "added": {"wp": ["/wp-x"]}, "disabled": ["env"], "rules": [1, 2]},
    "GET /api/v1/guard/traps": {"ok": True, "trap_hosts": ["trap.example.com"], "unknown_hosts": ["x.example.org"]},
    "GET /api/v1/guard/detection-context": {"ok": True, "config": {"enabled": True, "paths": ["/admin"]}},
    "GET /api/v1/guard/health": {"ok": True, "mode": "monitor"},
    "GET /api/v1/guard/quality": {"ok": True, "days": 7},
    "GET /api/v1/guard/shadow": {"ok": True, "addresses": [{"ip": "203.0.113.5", "score": 50}, {"ip": "", "score": 1},
                                                            {"score": 2}]},
    "GET /api/v1/guard/rate-warnings": {"ok": True, "open": [{"ip": "203.0.113.6", "site": "docker_example_test"}],
                                        "recent": [{"ip": "203.0.113.7", "site": "nope"}]},
    "GET /api/v1/guard/ip": {"ok": True, "ip": "203.0.113.5", "contributions": [
        {"event_type": "RATE_EXCEEDED", "site": "docker_example_test", "detail": "req_rate=900 limit=200"},
        {"event_type": "RATE_EXCEEDED", "site": "docker_example_test", "detail": "req_rate=900"},
        {"event_type": "ERROR_RATE_EXCEEDED", "site": "nc_example_test", "detail": "err_rate=7"},
        {"event_type": "NOT_FOUND_ENUMERATION", "detail": "n=6"}]},
    "GET /api/v1/guard/adaptive/bans": {"ok": True, "bans": []},
    "GET /api/v1/guard/adaptive/ban": {"ok": True, "ban": {"id": 1}},
    "GET /api/v1/guard/requests/summary": {"ok": True, "over_time": []},
    "GET /api/v1/guard/requests/status": {"ok": True, "enabled": True},
    "GET /api/v1/guard/requests": {"ok": True, "requests": [
        {"ts": 1700000000.9999996, "status": 200, "method": "GET", "host": "a.example.com", "path": "/=cmd,\"x\"",
         "client": "203.0.113.5", "response_ms": 12.5, "duration_ms": -3, "bytes_out": 100, "term": "-----",
         "times": "0/0/1", "user_agent": "-x", "request_id": "r1"},
        {"ts": 1700000001, "status": 404, "path": "@evil\nline", "term": "--", "refusal": None}], "next": ""},
    "GET /api/v1/guard/live/memory": {"ok": True, "budget_mib": 64},
    "POST /api/v1/guard/signatures/candidates/dismiss": {"ok": True},
    "POST /api/v1/guard/signatures": {"ok": True, "added": {"a": [1], "b": [2]}, "disabled": ["x"]},
    "POST /api/v1/guard/traps": {"ok": True, "trap_hosts": ["t1.example.com", "t2.example.com"]},
    "POST /api/v1/guard/detection-context": {"ok": True, "config": {"enabled": False}},
    "POST /api/v1/guard/detection-preview": {"ok": True, "matches": []},
    "POST /api/v1/guard/first-step-page": {"ok": True, "first_step_page": {"enabled": True, "changed": 3}},
    "POST /api/v1/guard/shield": {"ok": True, "path_shield": {"enabled": False, "segments": 4}},
    "POST /api/v1/guard/ban-durations": {"ok": True, "ban_durations_seconds": [60, 3600]},
    "POST /api/v1/guard/mode": {"ok": True, "mode": "enforce", "previous": "monitor", "applied": ["a", "b"], "lifted": []},
    "POST /api/v1/guard/requests/enabled": {"ok": True, "enabled": False},
    "POST /api/v1/guard/live/memory": {"ok": True, "budget_mib": 128, "dropped": 7},
})
BASE = {"easy-ha-proxy-guardd": GUARDD}
REPLIES = BASE


def with_(key, value):
    r = copy.deepcopy(BASE)
    r["easy-ha-proxy-guardd"][key] = value
    r["easy-ha-proxy-guardd"] = ordered(r["easy-ha-proxy-guardd"])
    return r


def j(body, **kw):
    return dict({"json_body": body}, **kw)


def normalize_body(label, body):
    return body


ADMIN = {"groups": "admins"}
W = "&w.SCANNER_PATH=150&w.RATE_EXCEEDED=%20-3%20&w.BOGUS=5&w.QUERY_INJECTION=x&cap=0&window=99&decay=99999999&w.NOSNI_PROBING="

STEPS = [
    ("csrf", "GET", "/system/alerts"),
    ("rules", "GET", "/api/security/detection-rules"),
    ("traps", "GET", "/api/security/traps"),
    ("context", "GET", "/api/security/detection-rules/context"),
    ("candidates", "GET", "/api/security/detection-rules/candidates"),
    ("health", "GET", "/api/security/adaptive/health"),
    ("health down", "GET", "/api/security/adaptive/health", {"replies": with_("GET /api/v1/guard/health", {"__status": 500})}),
    ("quality", "GET", "/api/security/adaptive/quality?days=90", {"replies": BASE}),
    ("quality bad", "GET", "/api/security/adaptive/quality?days=x"),
    ("quality none", "GET", "/api/security/adaptive/quality"),
    ("shadow", "GET", "/api/security/adaptive/shadow?x=1" + W),
    ("rate warnings", "GET", "/api/security/adaptive/rate-warnings?limit=9999"),
    ("rate warnings bad", "GET", "/api/security/adaptive/rate-warnings?limit=abc"),
    ("ip bad", "GET", "/api/security/adaptive/ip?ip=nope"),
    ("ip none", "GET", "/api/security/adaptive/ip"),
    ("ip", "GET", "/api/security/adaptive/ip?ip=%202001:DB8::0001%20" + W),
    ("ip hostile", "GET", "/api/security/adaptive/ip?ip=203.0.113.5", {"replies": with_("GET /api/v1/guard/ip", {
        "ok": True, "ip": "203.0.113.5", "contributions": [
            {"event_type": "RATE_EXCEEDED", "detail": "req_rate=50 limit=10"},
            {"event_type": "SCANNER_PATH", "detail": "/phpunit"}]})}),
    ("bans", "GET", "/api/security/adaptive/bans?q=x&terms=" + "t" * 3000 + "&sort=ts&junk=1", {"replies": BASE}),
    ("bans refused", "GET", "/api/security/adaptive/bans?offset=-1", {"replies": with_(
        "GET /api/v1/guard/adaptive/bans", {"__status": 400, "ok": False, "error": "bad offset"})}),
    ("ban detail", "GET", "/api/security/adaptive/ban?id=5&ip=203.0.113.5&at=" + "9" * 120, {"replies": BASE}),
    ("ban detail missing", "GET", "/api/security/adaptive/ban?id=6", {"replies": with_(
        "GET /api/v1/guard/adaptive/ban", {"__status": 404, "ok": False})}),
    ("ctx admin", "POST", "/api/security/detection-rules/context", j({"enabled": True}, replies=BASE, **ADMIN)),
    ("ctx too large", "POST", "/api/security/detection-rules/context", j({"x": "y" * 140000})),
    ("ctx not object", "POST", "/api/security/detection-rules/context", j([1])),
    ("ctx ok", "POST", "/api/security/detection-rules/context", j({"enabled": False})),
    ("ctx refused", "POST", "/api/security/detection-rules/context", j({"enabled": 5}, replies=with_(
        "POST /api/v1/guard/detection-context", {"__status": 400, "error": "enabled must be true or false"}))),
    ("preview admin", "POST", "/api/security/detection-rules/preview", j({"path": "/x"}, replies=BASE, **ADMIN)),
    ("preview large", "POST", "/api/security/detection-rules/preview", j({"q": "z" * 9000})),
    ("preview not object", "POST", "/api/security/detection-rules/preview", j("x")),
    ("preview ok", "POST", "/api/security/detection-rules/preview", j({"path": "/reset?token=SECRET"})),
    ("preview refused", "POST", "/api/security/detection-rules/preview", j({"path": 1}, replies=with_(
        "POST /api/v1/guard/detection-preview", {"__status": 400, "error": "bad"}))),
    ("preview down", "POST", "/api/security/detection-rules/preview", j({"path": "/"}, replies=with_(
        "POST /api/v1/guard/detection-preview", {"__raw": "x"}))),
    ("traps admin", "POST", "/api/security/traps", j({"hosts": []}, replies=BASE, **ADMIN)),
    ("traps bad", "POST", "/api/security/traps", j({"hosts": "a"})),
    ("traps ok", "POST", "/api/security/traps", j({"hosts": ["t1.example.com", "t2.example.com"]})),
    ("traps refused", "POST", "/api/security/traps", j({"hosts": ["bad name"]}, replies=with_(
        "POST /api/v1/guard/traps", {"__status": 400, "error": "bad name " + "n" * 400}))),
    ("dismiss admin", "POST", "/api/security/detection-rules/candidates/dismiss", j({"path": "/x"}, replies=BASE, **ADMIN)),
    ("dismiss list", "POST", "/api/security/detection-rules/candidates/dismiss", j(["/x"])),
    ("dismiss no slash", "POST", "/api/security/detection-rules/candidates/dismiss", j({"path": " x.php"})),
    ("dismiss ok", "POST", "/api/security/detection-rules/candidates/dismiss", j({"path": " /x.php ", "restore": 1, "host": None})),
    ("dismiss hide", "POST", "/api/security/detection-rules/candidates/dismiss", j({"path": "/y", "host": "h.example.com"})),
    ("rules set admin", "POST", "/api/security/detection-rules", j({}, replies=BASE, **ADMIN)),
    ("rules set list", "POST", "/api/security/detection-rules", j(["x"])),
    ("rules set ok", "POST", "/api/security/detection-rules", j({"added": {"a": ["/a"]}, "disabled": None})),
    ("rules set refused", "POST", "/api/security/detection-rules", j({"added": {"a": "bad"}}, replies=with_(
        "POST /api/v1/guard/signatures", {"__status": 400, "error": "rule a: bad"}))),
    ("rules set down", "POST", "/api/security/detection-rules", j({}, replies=with_(
        "POST /api/v1/guard/signatures", {"__status": 500}))),
    ("durations admin", "POST", "/api/security/adaptive/durations", j({"durations": [60]}, replies=BASE, **ADMIN)),
    ("durations empty", "POST", "/api/security/adaptive/durations", j({"durations": []})),
    ("durations many", "POST", "/api/security/adaptive/durations", j({"durations": [60] * 7})),
    ("durations bool", "POST", "/api/security/adaptive/durations", j({"durations": [True]})),
    ("durations str", "POST", "/api/security/adaptive/durations", j({"durations": ["6.0"]})),
    ("durations short", "POST", "/api/security/adaptive/durations", j({"durations": [30]})),
    ("durations order", "POST", "/api/security/adaptive/durations", j({"durations": [3600, 60]})),
    ("durations ok", "POST", "/api/security/adaptive/durations", j({"durations": [60, " 3600 ", 7200.9]})),
    ("durations list body", "POST", "/api/security/adaptive/durations", j([1])),
    ("first step bad", "POST", "/api/security/adaptive/first-step-page", j({"enabled": 1})),
    ("first step ok", "POST", "/api/security/adaptive/first-step-page", j({"enabled": True})),
    ("shield ok", "POST", "/api/security/adaptive/shield", j({"enabled": False})),
    ("shield down", "POST", "/api/security/adaptive/shield", j({"enabled": False}, replies=with_(
        "POST /api/v1/guard/shield", {"__raw": "x"}))),
    ("mode admin", "POST", "/api/security/adaptive/mode", j({"mode": "enforce"}, replies=BASE, **ADMIN)),
    ("mode bad", "POST", "/api/security/adaptive/mode", j({"mode": "ban"})),
    ("mode ok", "POST", "/api/security/adaptive/mode", j({"mode": " Enforce "})),
    ("mode daemon 400", "POST", "/api/security/adaptive/mode", j({"mode": "off"}, replies=with_(
        "POST /api/v1/guard/mode", {"__status": 400, "error": "busy"}))),
    ("requests", "GET", "/api/security/requests?client=%20203.0.113.5%20&limit=50&junk=1&path=" + "p" * 300, {"replies": BASE}),
    ("requests summary", "GET", "/api/security/requests/summary?limit=5&status=404"),
    ("requests status", "GET", "/api/security/requests/status"),
    ("requests off", "GET", "/api/security/requests", {"replies": with_("GET /api/v1/guard/requests",
                                                                         {"__status": 404, "ok": False, "error": "off"})}),
    ("requests export", "GET", "/api/security/requests/export?host=a.example.com", {"replies": BASE}),
    ("requests export down", "GET", "/api/security/requests/export", {"replies": with_("GET /api/v1/guard/requests", {"__raw": "x"})}),
    ("log enabled admin", "POST", "/api/security/requests/enabled", j({"enabled": True}, replies=BASE, **ADMIN)),
    ("log enabled", "POST", "/api/security/requests/enabled", j({"enabled": 0})),
    ("log enabled list", "POST", "/api/security/requests/enabled", j([1])),
    ("memory", "GET", "/api/security/requests/memory"),
    ("memory set admin", "POST", "/api/security/requests/memory", j({"budget_mib": 5}, **ADMIN)),
    ("memory set list", "POST", "/api/security/requests/memory", j([1])),
    ("memory set bad", "POST", "/api/security/requests/memory", j({"budget_mib": True, "revision": 1})),
    ("memory set ok", "POST", "/api/security/requests/memory", j({"budget_mib": 128, "revision": 3})),
    ("memory set profile", "POST", "/api/security/requests/memory", j({"budget_mib": 0, "revision": 3}, replies=with_(
        "POST /api/v1/guard/live/memory", {"ok": True, "budget_mib": 0}))),
    ("memory set conflict", "POST", "/api/security/requests/memory", j({"budget_mib": 1, "revision": 2}, replies=with_(
        "POST /api/v1/guard/live/memory", {"__status": 409, "ok": False, "conflict": True, "error": "changed"}))),
    ("memory set refused", "POST", "/api/security/requests/memory", j({"budget_mib": 99999, "revision": 3}, replies=with_(
        "POST /api/v1/guard/live/memory", {"__status": 400, "ok": False}))),
]
