"""Monitoring page API (metricsd proxy, uplinks from haproxy.cfg, events, attention)."""
import copy
import re

CFG = """global
    log stdout format raw local0

backend be_app_example_com
    # display-name: app.example.com, www.app.example.com
    server main 10.0.0.1:80 check
    server bkp 10.0.0.2:80 check backup

backend be_shop_example_com
    server main 10.0.0.1:8080 check
    server main 10.0.0.1:8081 check
    server bkp 10.0.0.2:8080 backup

backend be_api
    # display-name:   Апи шлюз  \r
    server srv1 [2001:db8::5]:443 check
    server loc 127.0.0.1:9000
    server loc6 [::1]:9001
    server lh localhost:9002

backend be_reserve_only
    server r1 10.9.9.9:80 backup

backend authelia_backend
    server authelia 127.0.0.1:9091
"""


def setup():
    with open("/etc/haproxy/haproxy.cfg", "w") as fh:
        fh.write(CFG)


SITES = {"ok": True, "sites": [{"proxy": "be_shop_example_com"}, {"proxy": "be_app_example_com"}, {"proxy": ""},
                               {"proxy": "be_api"}, {"proxy": " be_zeta_x "}]}
SERVERS = {"ok": True, "range": "24h", "since": 100, "until": 200,
           "labels": {"10.0.0.1": "Main link", "10.9.9.9": 7}, "hidden": ["10.0.0.2", 5],
           "servers": [
               {"proxy": "be_app_example_com", "server": "main", "bytes_in": 1000, "bytes_out": 2000, "sessions": 3},
               {"proxy": "be_app_example_com", "server": "bkp", "bytes_in": 10, "bytes_out": 0, "sessions": 1},
               {"proxy": "be_shop_example_com", "server": "main", "bytes_in": 500.7, "bytes_out": "250", "sessions": None},
               {"proxy": "be_api", "server": "srv1", "bytes_in": 3333, "bytes_out": 1, "sessions": 2},
               {"proxy": "be_api", "server": "loc", "bytes_in": 99, "bytes_out": 1, "sessions": 2},
               {"proxy": "", "server": "x", "bytes_in": 5},
               {"proxy": "be_reserve_only", "server": "r1", "bytes_in": 0, "bytes_out": 0},
           ]}
BACKENDS = {"ok": True, "since": 1, "backends": [
    {"proxy": "be_app_example_com", "requests": 300, "resp_2xx": 200, "resp_3xx": 50, "resp_4xx": 30, "resp_5xx": 20,
     "response_ms_avg": 12.9, "response_ms_max": 400, "bytes_in": 10, "bytes_out": 20},
    {"proxy": "be_api", "requests": 300, "resp_2xx": 1, "resp_4xx": 2, "response_ms_avg": None},
    {"proxy": "be_shop_example_com", "requests": 0},
    {"proxy": "be_zero", "requests": 5},
    {"proxy": "", "requests": 9},
]}
STATES = {"ok": True, "objects": [
    {"proxy": "be_app_example_com"}, {"proxy": "be_app_example_com", "server": "main"},
    {"proxy": "be_shop_example_com"}, {"proxy": "be_shop_example_com", "server": "main"},
    {"proxy": "be_shop_example_com", "server": "bkp"}, {"proxy": "be_api", "server": "srv1"}]}
STATE = {"ok": True, "catalogue": [{"name": "site.down", "title": "Site down"}, {"name": "disk.full", "title": ""},
                                   "junk", {"title": "no name"}],
         "active": [{"rule": "site.down", "subject": "be_api", "severity": "critical", "since_ts": 100, "summary": "down"},
                    {"rule": "disk.full", "subject": "/", "severity": "warning", "since_ts": 300},
                    {"rule": "info.x", "severity": "info"}],
         "pending": [{"rule": "site.down", "subject": "be_x", "severity": "critical", "since_ts": 500},
                     {"rule": "z", "severity": "warning", "since_ts": None}]}
HISTORY = {"ok": True, "events": [
    {"ts": 1700000600, "transition": "recovered", "rule": "site.down", "subject": "be_api", "severity": "critical", "summary": "up"},
    {"ts": 1700000500, "transition": "fired", "rule": "site.down", "subject": "be_api", "severity": "critical", "summary": "down"},
    {"ts": 1700000550, "transition": "reminded", "rule": "site.down"},
    {"ts": 1600000000, "transition": "fired", "rule": "old"},
    {"ts": 1700000700, "transition": "escalated", "rule": "custom.rule", "subject": "s" * 200},
]}
BASE = {
    "easy-ha-proxy-metricsd": {
        "GET /api/v1/metrics/sites": SITES,
        "GET /api/v1/metrics/servers": SERVERS,
        "GET /api/v1/metrics/backends": BACKENDS,
        "GET /api/v1/metrics/summary": {"ok": True, "health": {"backends": [{"proxy": "be_api"}], "servers": [{"proxy": "be_x_y"}]}},
        "GET /api/v1/metrics/series": {"ok": True, "components": [{"name": "easy-ha-proxy-guardd", "group": "service"},
                                                                  {"name": "haproxy-", "group": "service"},
                                                                  {"name": "haproxy-healthd", "group": "container"}]},
        "GET /api/v1/metrics/states": STATES,
        "GET /api/v1/metrics/storage": {"ok": True, "bytes": 5},
        "POST /api/v1/metrics/channel-labels": {"ok": True, "labels": {"10.0.0.1": "Main"}},
        "POST /api/v1/metrics/monitors": {"ok": True, "monitors": {"disk": False}},
    },
    "easy-ha-proxy-alertd": {
        "GET /api/v1/alerts/state": STATE,
        "GET /api/v1/alerts/history": HISTORY,
    },
    "haproxy-healthd": {
        "GET /api/v1/control/capabilities": {"ok": True, "systemd": {"haproxy.service": ["reload"]}},
        "POST /api/v1/control": {"ok": True, "text": "ok"},
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


def normalize_body(label, body):
    return re.sub(r'"(ts|since|until)": 1[78][0-9]{8}', r'"\1": NOW', body)


def normalize_log_line(line):
    return re.sub(r"(since|until)=1[78][0-9]{8}", r"\1=NOW", line)


M = "easy-ha-proxy-metricsd"
A = "easy-ha-proxy-alertd"
ADMIN = {"groups": "admins"}
CONTROL = j({"kind": "systemd", "name": "haproxy.service", "action": "reload"})

STEPS = [
    ("csrf", "GET", "/system/alerts"),
    ("sites", "GET", "/api/monitoring/sites"),
    ("sites down", "GET", "/api/monitoring/sites", {"replies": with_(M, "GET /api/v1/metrics/sites", {"__status": 500})}),
    ("sites list", "GET", "/api/monitoring/sites", {"replies": with_(M, "GET /api/v1/metrics/sites", [1])}),
    ("channels", "GET", "/api/monitoring/channels", {"replies": BASE}),
    ("channels window", "GET", "/api/monitoring/channels?range=7D&since=1700000000&until=1700086400"),
    ("channels window long", "GET", "/api/monitoring/channels?since=1000&until=1800000000"),
    ("channels window short", "GET", "/api/monitoring/channels?since=1000&until=1030&range=bogus"),
    ("channels window bad", "GET", "/api/monitoring/channels?since=x&until=1030"),
    ("channels no labels", "GET", "/api/monitoring/channels", {"replies": with_(M, "GET /api/v1/metrics/servers",
                                                                               {"servers": [], "labels": None})}),
    ("backends", "GET", "/api/monitoring/backends", {"replies": BASE}),
    ("backends empty", "GET", "/api/monitoring/backends", {"replies": with_(M, "GET /api/v1/metrics/servers", {"ok": True})}),
    ("backend requests", "GET", "/api/monitoring/backend-requests", {"replies": BASE}),
    ("backend requests bad", "GET", "/api/monitoring/backend-requests", {"replies": with_(
        M, "GET /api/v1/metrics/backends", {"backends": [{"proxy": "be", "requests": "lots"}]})}),
    ("summary", "GET", "/api/monitoring/summary?site=be_api&range=1h", {"replies": BASE}),
    ("summary all", "GET", "/api/monitoring/summary?site=ALL"),
    ("summary unknown site", "GET", "/api/monitoring/summary?site=be_nope&since=1700000000&until=1700086400"),
    ("series bad chart", "GET", "/api/monitoring/series?chart=bogus"),
    ("series", "GET", "/api/monitoring/series?chart=%20CPU%20&site=be_app_example_com"),
    ("series no components", "GET", "/api/monitoring/series?chart=memory&components=%20No%20"),
    ("series components blank", "GET", "/api/monitoring/series?chart=memory&components="),
    ("states", "GET", "/api/monitoring/states"),
    ("storage", "GET", "/api/monitoring/storage"),
    ("storage list", "GET", "/api/monitoring/storage", {"replies": with_(M, "GET /api/v1/metrics/storage", [1, 2])}),
    ("attention", "GET", "/api/monitoring/attention", {"replies": BASE}),
    ("attention down", "GET", "/api/monitoring/attention", {"replies": with_(A, "GET /api/v1/alerts/state", {"__status": 503})}),
    ("control for events", "POST", "/api/health/control", dict(CONTROL, replies=BASE)),
    ("events", "GET", "/api/monitoring/events"),
    ("events window", "GET", "/api/monitoring/events?since=1700000000&until=1700086400"),
    ("events alerts down", "GET", "/api/monitoring/events?since=1700000000&until=1700086400", {"replies": with_(
        A, "GET /api/v1/alerts/history", {"__status": 500})}),
    ("events titles down", "GET", "/api/monitoring/events?since=1700000000&until=1700086400", {"replies": with_(
        A, "GET /api/v1/alerts/state", {"__raw": "x"})}),
    ("labels admin", "POST", "/api/monitoring/channels/labels", j({"labels": {}}, replies=BASE, **ADMIN)),
    ("labels not object", "POST", "/api/monitoring/channels/labels", j({"labels": ["a"]})),
    ("labels hidden bad", "POST", "/api/monitoring/channels/labels", j({"labels": {}, "hidden": "x"})),
    ("labels ok", "POST", "/api/monitoring/channels/labels", j({"labels": {"10.0.0.1": "Main"}, "hidden": ["10.0.0.2"]})),
    ("labels ok no hidden", "POST", "/api/monitoring/channels/labels", j({"labels": {"10.0.0.1": "Main"}, "hidden": None})),
    ("labels refused", "POST", "/api/monitoring/channels/labels", j({"labels": {"x": "y" * 300}}, replies=with_(
        M, "POST /api/v1/metrics/channel-labels", {"__status": 400, "ok": False, "error": "label too long"}))),
    ("labels refused noerr", "POST", "/api/monitoring/channels/labels", j({"labels": {}}, replies=with_(
        M, "POST /api/v1/metrics/channel-labels", {"__status": 400, "ok": False}))),
    ("monitors admin", "POST", "/api/monitoring/monitors", j({"monitors": {"disk": False}}, replies=BASE, **ADMIN)),
    ("monitors empty", "POST", "/api/monitoring/monitors", j({"monitors": {}})),
    ("monitors unknown", "POST", "/api/monitoring/monitors", j({"monitors": {"disk": True, "x" * 60: True}})),
    ("monitors not bool", "POST", "/api/monitoring/monitors", j({"monitors": {"disk": 1}})),
    ("monitors ok", "POST", "/api/monitoring/monitors", j({"monitors": {"disk": False, "uplinks": True}})),
    ("monitors refused", "POST", "/api/monitoring/monitors", j({"monitors": {"disk": False}}, replies=with_(
        M, "POST /api/v1/metrics/monitors", {"__status": 400, "error": "disk is locked"}))),
    ("monitors list body", "POST", "/api/monitoring/monitors", j([1], replies=BASE)),
]
