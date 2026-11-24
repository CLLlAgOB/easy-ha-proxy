"""The /metrics exposition (token-gated) and its six sources."""
import copy
import re

ENV = {"METRICS_EXPORT_ENABLED": " Yes ", "METRICS_EXPORT_TOKEN": "s3cret"}
STAT = ("# pxname,svname,qcur,scur,weight,status,addr,check_status,\n"
        "be_app_example_com,main,0,3,100,UP,10.0.0.1:80,L4OK,\n"
        "be_app_example_com,bkp,0,2,1,no check,10.0.0.2:80,,\n"
        "be_tcp_db,db,0,x,1,DOWN,10.0.0.9:5432,,\n"
        "be_q\"x,s,0,1,1,UP 1/2,1.1.1.1:1,,\n")
BASE = {
    "haproxy": {"show stat": STAT},
    "easy-ha-proxy-metricsd": {"GET /api/v1/metrics/storage": {"ok": True, "storage": {
        "state": "warning", "writes_paused": 0, "total_bytes": 1234567, "filesystem_free_bytes": "9999995"}}},
    "easy-ha-proxy-guardd": {"GET /api/v1/guard/health": {"ok": True, "mode": "enforce", "states": {"watch": 3, "banned": 1.5,
                                                                                                  "z": None, "a\nb": True},
                                                            "database": {"bans_active": 7, "events": 1700000000}}},
    "easy-ha-proxy-alertd": {"GET /api/v1/alerts/health": {"ok": True, "firing": 2, "pending": "x",
                                                            "channels": {"mail": True, "webhook": 0, "tg": "yes"}}},
    "haproxy-certd": {"POST /api/v1/certs/status": {"items": {
        "docker.example.test": {"haproxy_days_left": 41}, "nc.example.test": {"haproxy_days_left": None, "le_days_left": -2.5}}}},
    "easy-ha-proxy-backupd": {"status": {"ok": True, "job": {"status": "Completed", "completed_at": 1699999999}}},
    "easy-ha-proxy-updated": {"status": {"ok": True, "last_job": {"status": "failed", "completed_at": "2026-11-20T10:00:00Z"}}},
}
REPLIES = BASE


def with_(daemon, key, value):
    r = copy.deepcopy(BASE)
    r[daemon][key] = value
    return r


def normalize_body(label, body):
    return re.sub(r"easy_ha_proxy_scrape_timestamp_seconds [0-9.e+]+", "easy_ha_proxy_scrape_timestamp_seconds T", body)


M = {"user": "easy-ha-proxy-metrics", "groups": "metrics"}


def scrape(token=None, **kw):
    headers = {"Authorization": token} if token is not None else {}
    return dict(M, headers=headers, **kw)


STEPS = [
    ("no token", "GET", "/metrics", scrape()),
    ("wrong scheme", "GET", "/metrics", scrape("Basic s3cret")),
    ("wrong token", "GET", "/metrics", scrape("Bearer nope")),
    ("scrape", "GET", "/metrics", scrape("bearer   s3cret  ")),
    ("sources down", "GET", "/metrics", scrape("Bearer s3cret", replies={
        "haproxy": {"show stat": ""}, "easy-ha-proxy-metricsd": {"GET /api/v1/metrics/storage": {"__status": 500}},
        "easy-ha-proxy-guardd": {"GET /api/v1/guard/health": [1]},
        "easy-ha-proxy-alertd": {"GET /api/v1/alerts/health": {"__raw": "x"}},
        "haproxy-certd": {"POST /api/v1/certs/status": {"__status": 500}},
        "easy-ha-proxy-backupd": {"status": {"ok": True}}, "easy-ha-proxy-updated": {"status": {"ok": False}}})),
    ("storage flat", "GET", "/metrics", scrape("Bearer s3cret", replies=with_(
        "easy-ha-proxy-metricsd", "GET /api/v1/metrics/storage", {"state": "CRITICAL", "writes_paused": True}))),
]
