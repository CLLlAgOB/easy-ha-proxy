"""Live activity: snapshot enrichment, decision feed, manual ban."""
import copy

BAN = ("# table: tbl_ban, type: ip, size:1048576, used:2\n"
       "0x1: key=203.0.113.5 use=0 exp=600000 shard=0 gpc0=1 gpt0=40\n"
       "0x2: key=198.51.100.7 use=0 exp=1234567 shard=0 gpc0=1 gpt0=99\n")
EDGE = ("# table: tbl_conn_edge, type: ip, size:100, used:3\n"
        "0x1: key=203.0.113.5 use=0 exp=1 conn_rate(10000)=900 conn_cur=4\n"
        "0x2: key=10.20.30.40 use=0 exp=1 conn_rate(10000)=999 conn_cur=999\n"
        "0x3: key=192.0.2.8 use=0 exp=1 conn_rate(10000)=5 conn_cur=600\n"
        "0x4: key=198.51.100.1 use=0 exp=1 conn_rate(10000)=1 conn_cur=1\n")
IP_AUTH = ("# table: tbl_ip_auth, type: ip, size:204800, used:1\n"
           "0x7: key=198.51.100.20 use=0 exp=32301965 shard=0 gpc0=106\n")
HAPROXY = {
    "show table tbl_ban": BAN,
    "show table tbl_ip_auth": IP_AUTH,
    "show table tbl_conn_edge": EDGE,
    "show table fe_https": "# table: fe_https\n0x9: key=127.0.0.1 use=0 exp=1 conn_rate(10000)=1 conn_cur=1\n",
    "show table": "# table: tbl_ban, type: ip, size:1, used:1\n",
    "show acl": "1 (/etc/haproxy/whitelist.ip) pattern\n",
    "del acl": "",
    "set table tbl_ban": "",
}
SNAP = {"ok": True, "window": 60, "totals": {"requests": 10},
        "addresses": [{"ip": "203.0.113.5", "requests": 7}, {"ip": "10.20.30.40", "requests": 1},
                      {"ip": "198.51.100.20"}, {"ip": "2001:db8::1", "requests": 2}],
        "events": [{"ip": "203.0.113.5", "status": 404}, {"ip": "10.20.30.40", "status": 200}],
        "slow": [{"ip": "198.51.100.20", "ms": 900}]}
FEED = {"ok": True, "next": "17", "sources": ["guardd", 5], "decisions": [
    {"id": 20, "ts": 1700000000, "ip": "203.0.113.5", "action": "applied", "source": "adaptive", "outcome": "applied",
     "code": 40, "until": 1700003600, "score": 150, "strike": 1,
     "summary": {"categories": ["wp", "env", "git", "php", "x"], "over": [{"site": "shop", "counter": "http_req_rate",
                                                                      "value": 500, "limit": 200},
                                                                     {"site": "other", "counter": "zz", "value": "3"}]}},
    {"id": 19, "ts": 1699990000, "ip": "198.51.100.7", "action": "lifted", "source": "operator", "until": 1700000000},
    {"id": 18, "ts": 0, "ip": "", "action": "ended", "source": "haproxy", "outcome": "pending", "summary": None},
]}
GUARDD = {
    "GET /api/v1/guard/live": SNAP,
    "GET /api/v1/guard/decisions/feed": FEED,
    "GET /api/v1/guard/identities": {"ok": True, "users_by_ip": {"198.51.100.20": ["alice"]}},
    "GET /api/v1/guard/bans/schedule": {"ok": True, "enforcing": False},
    "POST /api/v1/guard/ban/manual": {"ok": True, "remembered": True},
}
BASE = {"haproxy": HAPROXY, "easy-ha-proxy-guardd": GUARDD}
REPLIES = BASE


def setup():
    with open("/etc/haproxy/whitelist.ip", "w") as fh:
        fh.write("# global\n10.20.30.0/24\n203.0.113.50\n203.0.113.60/32 # host\n192.0.2.0/30\n192.0.2.1/32\nbogus\n")
    with open("/opt/haproxy-admin/config/vars.yml", "a") as fh:
        fh.write("\n")


def with_(daemon, key, value):
    r = copy.deepcopy(BASE)
    table = r[daemon]
    table[key] = value
    r[daemon] = dict(sorted(table.items(), key=lambda kv: -len(kv[0])))
    return r


def snap(**kw):
    s = copy.deepcopy(SNAP)
    s.update(kw)
    return with_(G, "GET /api/v1/guard/live", s)


def j(body, **kw):
    return dict({"json_body": body}, **kw)


G = "easy-ha-proxy-guardd"
H = "haproxy"

STEPS = [
    ("csrf", "GET", "/system/alerts"),
    ("live", "GET", "/api/monitoring/live"),
    ("live filters", "GET", "/api/monitoring/live?window=9999&ip=203.0.113.5&host=Shop.Example.COM&q=" + "z" * 130 +
     "&status=4xx&blocked=yes&banned=0&hide_admin=ON&agent=%01Mozilla%09%20x%20&country=zz"),
    ("live bad values", "GET", "/api/monitoring/live?window=abc&ip=bad!&host=a_b&status=6xx&country=xyz"),
    ("live small window", "GET", "/api/monitoring/live?window=1"),
    ("live country filter", "GET", "/api/monitoring/live?country=%20??%20"),
    ("live refused", "GET", "/api/monitoring/live", {"replies": snap(ok=False, error="request log off")}),
    ("live refused noerr", "GET", "/api/monitoring/live", {"replies": with_(G, "GET /api/v1/guard/live", {"__status": 404})}),
    ("live down", "GET", "/api/monitoring/live", {"replies": with_(G, "GET /api/v1/guard/live", {"__raw": "x"})}),
    ("live no totals", "GET", "/api/monitoring/live", {"replies": with_(G, "GET /api/v1/guard/live",
                                                                         {"ok": True, "addresses": []})}),
    ("live no ip", "GET", "/api/monitoring/live", {"replies": snap(addresses=[{"requests": 1}])}),
    ("live no edge table", "GET", "/api/monitoring/live", {"replies": with_(H, "show table tbl_conn_edge", "No such table\n")}),
    ("decisions", "GET", "/api/monitoring/live/decisions", {"replies": BASE}),
    ("decisions kinds", "GET", "/api/monitoring/live/decisions?kind=bans&before=25"),
    ("decisions bad", "GET", "/api/monitoring/live/decisions?kind=zz&before=-4"),
    ("decisions bad before", "GET", "/api/monitoring/live/decisions?before=x"),
    ("decisions down", "GET", "/api/monitoring/live/decisions", {"replies": with_(G, "GET /api/v1/guard/decisions/feed", {"__status": 500})}),
    ("ban invalid", "POST", "/api/monitoring/live/ban", j({"ip": "2001:db8::1"}, replies=BASE)),
    ("ban bad octet", "POST", "/api/monitoring/live/ban", j({"ip": "300.1.1.1"})),
    ("ban own", "POST", "/api/monitoring/live/ban", j({"ip": "203.0.113.9"}, headers={"X-Forwarded-For": " 203.0.113.9 , 10.0.0.1"})),
    ("ban allow listed", "POST", "/api/monitoring/live/ban", j({"ip": "10.20.30.40"})),
    ("ban range drop", "POST", "/api/monitoring/live/ban", j({"ip": "10.20.30.40", "drop_allowlist": 1})),
    ("ban host drop", "POST", "/api/monitoring/live/ban", j({"ip": "203.0.113.50", "drop_allowlist": True})),
    ("ban host and range", "POST", "/api/monitoring/live/ban", j({"ip": "192.0.2.1", "drop_allowlist": True})),
    ("ban host 32 drop", "POST", "/api/monitoring/live/ban", j({"ip": "203.0.113.60", "drop_allowlist": "yes"})),
    ("ban ok", "POST", "/api/monitoring/live/ban", j({"ip": " 198.51.100.77 "})),
    ("ban not remembered", "POST", "/api/monitoring/live/ban", j({"ip": "198.51.100.78"}, replies=with_(
        G, "POST /api/v1/guard/ban/manual", {"ok": True, "remembered": False}))),
    ("ban refused", "POST", "/api/monitoring/live/ban", j({"ip": "198.51.100.79"}, replies=with_(
        G, "POST /api/v1/guard/ban/manual", {"__status": 409, "ok": False, "error": "busy " + "e" * 400}))),
    ("ban engine down", "POST", "/api/monitoring/live/ban", j({"ip": "198.51.100.80"}, replies=with_(
        G, "POST /api/v1/guard/ban/manual", {"__raw": "nope"}))),
    ("ban engine down haproxy no", "POST", "/api/monitoring/live/ban", j({"ip": "198.51.100.81"}, replies=dict(
        with_(G, "POST /api/v1/guard/ban/manual", {"__raw": "nope"}),
        haproxy=dict(HAPROXY, **{"set table tbl_ban": "Unknown table\n"})))),
    ("ban list body", "POST", "/api/monitoring/live/ban", j([1], replies=BASE)),
    ("live after bans", "GET", "/api/monitoring/live"),
]
