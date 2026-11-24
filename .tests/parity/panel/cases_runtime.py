"""HAProxy runtime group: tables, unban, allow lists, attackers, connections, the address page,
country batch, backend status, IP authorization, server state and weight."""
import copy
import os

CFG = """global
backend be_app_example_com
    # display-name: app.example.com, www.app.example.com, 10.1.2.3, *.wild.example.com
    server main 10.0.0.1:80 check
backend be_tcp_db
    server db 10.0.0.9:5432
"""

TABLES = ("# table: tbl_ban, type: ip, size:1048576, used:3\n"
          "# table: tbl_err_shop, type: ip, size:100, used:2\n"
          "# table: tbl_err_nosni, type: ip, size:100, used:1\n"
          "# table: tbl_ip_auth, type: ip, size:204800, used:2\n"
          "# table: fe_https, type: ip, size:10, used:1\n")
BAN = ("# table: tbl_ban, type: ip, size:1048576, used:3\n"
       "0x1: key=203.0.113.5 use=0 exp=600000 shard=0 gpc0=1 gpt0=40\n"
       "0x2: key=198.51.100.7 use=0 exp=1234567 shard=0 gpc0=1 gpt0=10\n"
       "0x3: key=192.0.2.9 use=0 exp=5000 shard=0 gpc0=0 gpt0=20\n")
ERR_SHOP = ("# table: tbl_err_shop, type: ip, size:100, used:2\n"
            "0x4: key=203.0.113.5 use=0 exp=30000 shard=0 http_err_rate(10000)=7\n"
            "0x5: key=192.0.2.44 use=0 exp=90000 shard=0 http_err_rate(10000)=12\n")
ERR_NOSNI = ("# table: tbl_err_nosni, type: ip, size:100, used:1\n"
             "0x6: key=203.0.113.5 use=0 exp=99000 shard=0 http_err_rate(10000)=3\n")
IP_AUTH = ("# table: tbl_ip_auth, type: ip, size:204800, used:2\n"
           "0x7: key=198.51.100.20 use=0 exp=32301965 shard=0 gpc0=106\n"
           "0x8: key=198.51.100.21 use=0 exp=-5 shard=0 gpc0=0\n"
           "0x9: key=2001:db8::1 use=0 exp=4999 shard=0 gpc0=x\n")
ACL = ("# id (file) description\n"
       "1 (/etc/haproxy/whitelist.ip) pattern loaded from file '/etc/haproxy/whitelist.ip' used by map at file 'x' line 1\n"
       "2 (/etc/haproxy/geoip/whitelist.geo) pattern loaded\n")
SESS = ("0x55a1: proto=tcpv4 src=203.0.113.5:51000 fe=fe_https be=be_app srv=main ts=00 age=10s\n"
        "0x55a2: proto=tcpv4 src=203.0.113.5:51001 fe=fe_https be=be_app age_ms=4000\n"
        "0x55a3: proto=tcpv4 src=192.0.2.1:4000 fe=fe_https age=1m\n"
        "0x55a4: proto=unix_stream src=unix:1 fe=GLOBAL\n"
        "0x55a5: proto=tcpv4 src=198.51.100.9:1 fe=GLOBAL\n"
        "0x55a6: proto=tcpv6 src=2001:db8::5:443 fe=fe_https\n")
STAT = ("# pxname,svname,qcur,scur,weight,status,addr,check_status,\n"
        "fe_https,FRONTEND,,5,,OPEN,,,\n"
        "be_app_example_com,main,0,3,100,UP,10.0.0.1:80,L4OK,\n"
        "be_app_example_com,bkp,0,0,1,DOWN,10.0.0.2:80,L4CON,\n"
        "be_app_example_com,BACKEND,0,3,101,UP,,,\n"
        "be_tcp_db,db,0,1,1,MAINT,10.0.0.9:5432,,\n"
        "authelia_backend,authelia,0,0,1,UP,127.0.0.1:9091,L7OK,\n"
        "be_access_granted,x,0,0,1,DOWN,127.0.0.1:1,,\n"
        "be_admin,web,0,0,1,UP,127.0.0.1:5000,,\n"
        "tbl_x,y,0,0,1,UP,,,\n"
        "be_short,s1,0\n"
        "be_drain,d1,0,0,abc,DRAIN (agent),10.9.9.9:80,,\n")

HAPROXY = {
    "show table tbl_ban": BAN,
    "show table tbl_err_shop": ERR_SHOP,
    "show table tbl_err_nosni": ERR_NOSNI,
    "show table tbl_ip_auth": IP_AUTH,
    "show table tbl_err": "",
    "show table": TABLES,
    "show acl #1": "0x1 10.0.0.0/8\n0x2 203.0.113.99/32\n",
    "show acl #2": "\n",
    "show acl": ACL,
    "add acl": "",
    "del acl": "",
    "set table tbl_ban": "",
    "show sess": SESS,
    "show stat": STAT,
    "set server": "",
}
GUARDD = {
    "GET /api/v1/guard/bans/schedule": {"ok": True, "enforcing": True, "now": 1000, "bans": {"203.0.113.5": 4600}},
    "GET /api/v1/guard/identities": {"ok": True, "users_by_ip": {"198.51.100.20": ["alice", "bob"]}},
    "GET /api/v1/guard/attackers": {"ok": True, "since": 1, "code_400": {"203.0.113.5": 9, "192.0.2.1": 3},
                                    "code_451": [{"ip": "198.51.100.7", "cnt": "4", "country": "DE"}, {"ip": None, "hits": 2},
                                                 {"ip": " ", "count": 1}, "junk", {"ip": "203.0.113.9", "count": "x"}]},
    "GET /api/v1/guard/decisions/feed": {"ok": True, "decisions": []},
    "GET /api/v1/guard/decisions": {"ok": True, "decisions": [
        {"ts": 1700000000, "action": "lifted", "source": "expiry", "code": 40, "until": 1700003600},
        {"ts": 1699990000, "action": "applied", "source": "adaptive", "outcome": "applied", "code": 40, "until": 1700000000,
         "score": 120, "strike": 2, "policy": "u02",
         "reason": {"evidence": [{"ts": 1699989000, "event_type": "SCANNER_PATH", "category": "wp", "site": "shop",
                                  "detail": "/wp-login.php", "points": 40},
                                 {"ts": 1699989100, "event_type": "RATE_EXCEEDED", "points": 5.5}],
                    "evidence_total": 7}},
        {"ts": 1699980000, "action": "applied", "source": "operator", "outcome": "failed", "code": 50},
    ]},
    "POST /api/v1/guard/ban/forget": {"ok": True, "cleared": True},
}
BASE = {"haproxy": HAPROXY, "easy-ha-proxy-guardd": GUARDD,
        "controld": {"logs-attackers": {"b64json": {"code_400": [{"ip": "203.0.113.5", "count": 2}], "diagnostic": {"lines": 5}}}}}
REPLIES = BASE

ENV = {"HAPROXY_CFG": "/etc/haproxy/haproxy.cfg"}


def setup():
    with open("/etc/haproxy/haproxy.cfg", "w") as fh:
        fh.write(CFG)
    os.makedirs("/var/log", exist_ok=True)
    with open("/var/log/haproxy.log", "w") as fh:
        fh.write("Nov 20 10:00:00 gw haproxy[1]: 203.0.113.5:51000 [20/Nov/2026:10:00:00.000] fe_https be/main 0/0/1 200 1 - - ---- \"GET / HTTP/1.1\"\n")


def with_(daemon, key, value):
    r = copy.deepcopy(BASE)
    table = r[daemon]
    table[key] = value
    r[daemon] = dict(sorted(table.items(), key=lambda kv: -len(kv[0])))
    return r


def without(daemon, key):
    r = copy.deepcopy(BASE)
    r[daemon].pop(key, None)
    return r


def form(**kw):
    kw.setdefault("csrf_token", "CSRF")
    return {"form": kw}


def j(body, **kw):
    return dict({"json_body": body}, **kw)


IGNORE_FILES = ()
G = "easy-ha-proxy-guardd"
H = "haproxy"
ADMIN = {"groups": "admins"}

STEPS = [
    ("csrf", "GET", "/system/alerts"),
    ("tables", "GET", "/api/tables"),
    ("tables bans view", "GET", "/api/tables?view=bans"),
    ("tables raw", "GET", "/api/tables_raw"),
    ("ip auth", "GET", "/api/ip_auth"),
    ("ip auth guardd down", "GET", "/api/ip_auth", {"replies": without(G, "GET /api/v1/guard/identities")}),
    ("ip auth missing", "GET", "/api/ip_auth", {"replies": with_(H, "show table tbl_ip_auth", "Unknown table tbl_ip_auth\n")}),
    ("whitelists before", "GET", "/api/whitelists", {"replies": BASE}),
    ("unban no ip", "POST", "/api/unban", form(ip=" ")),
    ("unban bad", "POST", "/api/unban", form(ip="2001:db8::1")),
    ("unban cleared", "POST", "/api/unban", form(ip="203.0.113.5")),
    ("tables after unban", "GET", "/api/tables"),
    ("unban refused", "POST", "/api/unban", dict(form(ip="203.0.113.5"), replies=with_(
        G, "POST /api/v1/guard/ban/forget", {"ok": False, "refused": "No such table " + "x" * 300}))),
    ("unban engine old", "POST", "/api/unban", dict(form(ip="203.0.113.5"), replies=with_(
        G, "POST /api/v1/guard/ban/forget", {"ok": True}))),
    ("unban engine down", "POST", "/api/unban", dict(form(ip="203.0.113.5"), replies=with_(
        G, "POST /api/v1/guard/ban/forget", {"__status": 500}))),
    ("unban haproxy says no", "POST", "/api/unban", dict(form(ip="203.0.113.5"), replies=with_(
        H, "set table tbl_ban", "No such table: tbl_ban\n"))),
    ("wl no ip", "POST", "/api/whitelist", form()),
    ("wl bad", "POST", "/api/whitelist", dict(form(ip="nope"), replies=BASE)),
    ("wl add", "POST", "/api/whitelist", form(ip=" 10.1.2.3 ")),
    ("wl add net", "POST", "/api/whitelist", form(ip="10.9.8.7/16")),
    ("wl remove", "POST", "/api/whitelist", form(ip="10.1.2.3/32")),
    ("wl v6", "POST", "/api/whitelist", form(ip="2001:DB8::1")),
    ("wlg add", "POST", "/api/whitelist-global", form(ip="203.0.113.77")),
    ("wlg add runtime refused", "POST", "/api/whitelist-global", dict(form(ip="203.0.113.78"), replies=with_(
        H, "add acl", "Unknown ACL\n"))),
    ("wlg remove", "POST", "/api/whitelist-global", dict(form(ip="203.0.113.77"), replies=BASE)),
    ("wlg no acl", "POST", "/api/whitelist-global", dict(form(ip="203.0.113.79"), replies=with_(H, "show acl", "# none\n"))),
    ("whitelists after", "GET", "/api/whitelists", {"replies": BASE}),
    ("attackers guardd", "GET", "/api/attackers"),
    ("attackers fresh guardd", "GET", "/api/attackers", {"replies": with_(G, "GET /api/v1/guard/attackers",
                                                                          {"ok": True, "since": 9999999999})}),
    ("attackers controld error", "GET", "/api/attackers", {"replies": dict(without(G, "GET /api/v1/guard/attackers"), controld={
        "logs-attackers": {"b64json": {"error": "log unreadable", "diagnostic": {"path": "/var/log/haproxy.log"}}}})}),
    ("connections", "GET", "/api/connections", {"replies": BASE}),
    ("connections command error", "GET", "/api/connections", {"replies": with_(H, "show sess", "Command not allowed\n")}),
    ("backends", "GET", "/api/backends", {"replies": BASE}),
    ("haproxy backends", "GET", "/api/haproxy/backends"),
    ("haproxy backends admin", "GET", "/api/haproxy/backends", ADMIN),
    ("state admin", "POST", "/api/haproxy/backends/state", j({"backend": "be_tcp_db"}, **ADMIN)),
    ("state bad", "POST", "/api/haproxy/backends/state", j({"backend": "be_tcp_db", "server": "db", "state": "off"})),
    ("state unknown", "POST", "/api/haproxy/backends/state", j({"backend": "be_x", "server": "db", "state": "drain"})),
    ("state protected", "POST", "/api/haproxy/backends/state", j({"backend": "authelia_backend", "server": "authelia", "state": "drain"})),
    ("state ok", "POST", "/api/haproxy/backends/state", j({"backend": " be_tcp_db ", "server": "db", "state": " DRAIN "})),
    ("state refused", "POST", "/api/haproxy/backends/state", j({"backend": "be_tcp_db", "server": "db", "state": "ready"},
                                                               replies=with_(H, "set server", "No such server.\nmore\n"))),
    ("weight bad", "POST", "/api/haproxy/backends/weight", j({"backend": "be_tcp_db", "server": "db", "weight": "1.5"}, replies=BASE)),
    ("weight range", "POST", "/api/haproxy/backends/weight", j({"backend": "be_tcp_db", "server": "db", "weight": 300})),
    ("weight ok", "POST", "/api/haproxy/backends/weight", j({"backend": "be_app_example_com", "server": "main", "weight": " 50 "})),
    ("weight list body", "POST", "/api/haproxy/backends/weight", j([1])),
    ("country batch", "POST", "/api/country-batch", j({"ips": ["8.8.8.8", " 10.0.0.1 ", "8.8.8.8", "bad", 5, None]})),
    ("country batch not list", "POST", "/api/country-batch", j({"ips": "8.8.8.8"})),
    ("country batch too many", "POST", "/api/country-batch", j({"ips": ["1.1.1.1"] * 513})),
    ("country batch empty", "POST", "/api/country-batch", j({})),
    ("ip page bad", "GET", "/ip/not-an-ip"),
    ("ip page", "GET", "/ip/203.0.113.5", {"replies": BASE}),
    ("ip page v6", "GET", "/ip/2001:db8::1"),
    ("ip page allow listed", "GET", "/ip/10.20.30.40"),
    ("ip page no history", "GET", "/ip/198.51.100.7", {"replies": with_(G, "GET /api/v1/guard/decisions", {"__status": 500})}),
]
