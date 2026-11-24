"""Template-only pages and the request boundary."""

REPLIES = {
    "haproxy": {"show info": "Name: HAProxy\nVersion: 2.8.16-0ubuntu0.24.04.1\nRelease_date: 2025/01/01\n"},
    "easy-ha-proxy-updated": {"summary": {"ok": True, "level": "os", "build": {
        "revision": "fedcba9876543210fedcba9876543210fedcba98", "committed_at": "2026-11-21T08:30:00Z",
        "web_tree": "a" * 64, "version": "1.1.3-alpha"}}},
}

PAGES = ["/", "/monitoring", "/monitoring/live", "/system/health", "/system/alerts", "/system/audit",
         "/security/adaptive", "/security/adaptive/bans", "/security/detection-rules", "/security/requests",
         "/haproxy/backends", "/haproxy/stats", "/haproxy/certs/dns-providers", "/haproxy/geoip",
         "/haproxy/config/history", "/haproxy/trash", "/system/os-security/", "/system/ssh-security/",
         "/system/schedule/", "/system/updates/", "/system/backups/", "/debug/"]

STEPS = []
for p in PAGES:
    STEPS.append(("page " + p, "GET", p))
STEPS += [
    ("page as admin user", "GET", "/", {"groups": "admins"}),
    ("ban detail ok", "GET", "/security/adaptive/ban?ip=1.2.3.4&id=7&at=1700000000"),
    ("ban detail ipv6", "GET", "/security/adaptive/ban?ip=2001:DB8::1"),
    ("ban detail bad", "GET", "/security/adaptive/ban?id=x"),
    ("ban detail empty", "GET", "/security/adaptive/ban"),
    ("strict slash", "GET", "/system/backups?x=1"),
    ("no user", "GET", "/", {"user": None}),
    ("not admin", "GET", "/", {"groups": "users"}),
    ("superadmin page as admin", "GET", "/haproxy/trash", {"groups": "admins"}),
    ("debug headers off", "GET", "/debug/headers"),
    ("unknown", "GET", "/nope"),
    ("ru page", "GET", "/system/alerts", {"headers": {"Cookie": "haproxy_admin_language=ru"}}),
]
