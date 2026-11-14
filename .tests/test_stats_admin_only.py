"""HAProxy's statistics page is the admin host's, not every site's.

Found in the 30 October review and confirmed live on the test gateway:
`stats enable` sat on the shared HTTPS frontend, so /stats on any public
site answered with the full statistics report -- backend names, server
addresses, traffic -- to anyone (200, 123 KB, no sign-in), and a site's own
/stats path never reached the site. The statistics now live in a backend of
their own, reached only through the admin host after its authentication.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".tests"))

from test_site_allow_ips import render, site  # noqa: E402
from test_request_log import StoreTestCase, guardd, line  # noqa: E402


def section(config: str, header: str) -> str:
    """The lines of one section, up to the next section header."""
    lines = config.splitlines()
    start = next(i for i, text in enumerate(lines) if text.strip() == header)
    body = []
    for text in lines[start + 1:]:
        if re.match(r"^(frontend|backend|listen|global|defaults|userlist|peers|resolvers)\b", text):
            break
        body.append(text)
    return "\n".join(body)


class TheStatisticsPage(unittest.TestCase):
    def config(self, **extra):
        return render([site("shop", "shop.example.test")], **extra)

    def test_the_shared_frontend_does_not_serve_it(self):
        frontend = section(self.config(), "frontend fe_https")
        self.assertNotIn("stats enable", frontend)
        self.assertNotIn("stats uri", frontend)
        self.assertNotIn("stats admin", frontend)

    def test_only_the_admin_host_reaches_it(self):
        config = self.config()
        self.assertIn("use_backend be_stats if host_admin path_stats", config)
        backend = section(config, "backend be_stats")
        self.assertIn("stats enable", backend)
        self.assertIn("stats uri /stats", backend)
        # Behind Authelia's check of the admin host, as before.
        self.assertIn("stats admin if TRUE", backend)
        # Every route to it names the admin host.
        for text in config.splitlines():
            if "be_stats" in text and text.strip().startswith("use_backend"):
                self.assertIn("host_admin", text)

    def test_with_the_stats_password_the_check_comes_first(self):
        config = self.config(authelia_enabled=False, admin_password="secret")
        frontend = section(config, "frontend fe_https")
        auth = frontend.index('http-request auth realm "HAProxy Stats" if host_admin path_stats !AuthOK')
        route = frontend.index("use_backend be_stats if host_admin path_stats")
        self.assertLess(auth, route)
        self.assertIn("stats admin if TRUE", section(config, "backend be_stats"))

    def test_no_admin_host_no_statistics_page(self):
        import test_site_allow_ips as helper

        environment = helper.Environment(
            loader=helper.FileSystemLoader(str(helper.TEMPLATE_DIR)),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        environment.filters["regex_replace"] = helper.jinja_regex_replace
        environment.filters["combine"] = helper.jinja_combine
        config = environment.get_template("haproxy.cfg.j2").render(
            sites=[site("shop", "shop.example.test")], tcp_proxies=[], tcp=[], site_defaults={},
            aut_domain="auth.example.test", authelia_enabled=True, enable_geoip=True,
            easy_ha_proxy_runtime_vars={}, easy_ha_proxy_runtime_websites={},
            easy_ha_proxy_runtime_tcp={},
        )
        self.assertNotIn("be_stats", config)
        # Nor anywhere else on the shared frontend.
        self.assertNotIn("stats enable", section(config, "frontend fe_https"))

    def test_no_admin_actions_without_any_sign_in(self):
        config = self.config(authelia_enabled=False, admin_password="")
        self.assertNotIn("stats admin", section(config, "backend be_stats"))


class ThePanelsOwnTraffic(StoreTestCase):
    def test_the_statistics_frame_is_hidden_with_the_panel(self):
        self.ingest(backend="be_stats/<STATS>", extra="id=stats")
        self.ingest(backend="be_admin/ui", extra="id=panel")
        self.ingest(extra="id=shop")
        ids = [row["request_id"] for row in self.store.search(hide_admin=True)["requests"]]
        self.assertEqual(ids, ["shop"])
        record = guardd.live_record(guardd.parse_access_line(line(backend="be_stats/<STATS>")), time.time())
        self.assertFalse(guardd.RequestQuery.build(hide_admin=True).matches(record))
        self.assertFalse(guardd._live_matches(record, {"hide_admin": True}))

    def test_monitoring_and_the_panel_leave_it_out(self):
        defaults = (ROOT / "ansible/roles/haproxy-admin/defaults/main.yml").read_text(encoding="utf-8")
        self.assertIn("be_stats", defaults.split("ui_exclude_backends_exact:")[1].split("\n")[1])
        metricsd = (ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-metricsd.py").read_text(encoding="utf-8")
        self.assertIn('"be_stats"', metricsd.split("DEFAULT_EXCLUDE_EXACT = (")[1].split(")")[0])


if __name__ == "__main__":
    unittest.main()
