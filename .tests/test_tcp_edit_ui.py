"""Regression checks for the TCP proxy edit action."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = ROOT / "docker" / "app" / "haproxy_admin"


class TcpEditUiTests(unittest.TestCase):
    def test_tcp_list_has_an_explicit_edit_button(self):
        template = (
            APP_ROOT / "templates" / "haproxy_tcp.html"
        ).read_text(encoding="utf-8")

        self.assertRegex(
            template,
            re.compile(
                r'<a class="btn btn-small"\s+'
                r'href="{{ url_for\(\'routes\.haproxy_tcp_edit\', '
                r'name=t\.name\) }}">\s*Edit\s*</a>',
                re.DOTALL,
            ),
        )

    def test_edit_button_targets_the_existing_edit_route(self):
        routes = (
            APP_ROOT / "routes_haproxy_config.py"
        ).read_text(encoding="utf-8")
        javascript = (
            APP_ROOT / "static" / "js" / "haproxy_tcp.js"
        ).read_text(encoding="utf-8")

        self.assertIn(
            '@bp.route("/haproxy/tcp/<name>/edit", methods=["GET", "POST"])',
            routes,
        )
        self.assertIn(
            'fetch("/haproxy/tcp/save"',
            javascript,
        )
        self.assertIn("original_name:", javascript)


if __name__ == "__main__":
    unittest.main()
