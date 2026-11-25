"""Regression checks for the TCP proxy edit action."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = ROOT / "docker" / "app" / "haproxy_admin"
_WEB_DIR = Path(__file__).resolve().parents[1] / "go" / "panel" / "web"


class TcpEditUiTests(unittest.TestCase):
    def test_tcp_list_has_an_explicit_edit_button(self):
        template = (
            _WEB_DIR / "templates" / "haproxy_tcp.html"
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


if __name__ == "__main__":
    unittest.main()
