"""A site that asks for the HTTP -> HTTPS redirect gets port 80 (F13).

From the 30 October review, confirmed by rendering: the template set
need_http80 inside a Jinja for loop, and a `set` there does not leave the
loop. With the global enable_http80 off, a site's redirect_to_https never
opened :80, so the redirect it asked for did not exist.
"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".tests"))

from test_site_allow_ips import render, site  # noqa: E402

LISTENER = "frontend fe_http80"


class PortEighty(unittest.TestCase):
    def test_a_site_redirect_opens_it_with_the_global_switch_off(self):
        config = render([site("shop", "shop.example.test", redirect_to_https=True)], enable_http80=False)
        self.assertIn(LISTENER, config)

    def test_nothing_asks_for_it_nothing_opens_it(self):
        config = render([site("shop", "shop.example.test")], enable_http80=False)
        self.assertNotIn(LISTENER, config)

    def test_the_global_switch_alone_opens_it(self):
        config = render([site("shop", "shop.example.test")], enable_http80=True)
        self.assertIn(LISTENER, config)

    def test_one_redirecting_site_among_others_is_enough(self):
        config = render([
            site("shop", "shop.example.test"),
            site("blog", "blog.example.test", redirect_to_https=True),
            site("api", "api.example.test"),
        ], enable_http80=False)
        self.assertIn(LISTENER, config)


if __name__ == "__main__":
    unittest.main()
