"""A generic TCP proxy honours its backup servers and its TLS check (F14).

From the 30 October review: the TCP editor saved a server's `backup` flag
and the proxy's `ssl_check`, but the generic TCP backend wrote every server
as a plain `check` -- a backup server took its share of the traffic, and the
TLS check the form promised never ran.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".tests"))

from test_site_allow_ips import render  # noqa: E402


def proxy(**extra):
    base = {
        "name": "files",
        "bind_port": 6690,
        "servers": [
            {"name": "main", "host": "10.0.0.10", "port": 6690},
            {"name": "spare", "host": "10.0.0.11", "port": 6690, "backup": True},
        ],
    }
    base.update(extra)
    return base


def server_lines(config):
    start = config.index("\nbackend be_tcp_files\n") + 1
    block = config[start:].split("\n#", 1)[0]
    return [line.strip() for line in block.splitlines() if line.strip().startswith("server ")]


class TheBackend(unittest.TestCase):
    def test_a_backup_server_is_written_as_backup(self):
        lines = server_lines(render([], tcp_proxies=[proxy()]))
        self.assertEqual(lines, ["server main 10.0.0.10:6690 check",
                                 "server spare 10.0.0.11:6690 check backup"])

    def test_the_tls_check_is_a_check_only(self):
        lines = server_lines(render([], tcp_proxies=[proxy(ssl_check=True)]))
        self.assertEqual(lines, ["server main 10.0.0.10:6690 check check-ssl verify none",
                                 "server spare 10.0.0.11:6690 check check-ssl verify none backup"])
        for line in lines:
            # `ssl` on its own would encrypt the traffic too
            self.assertIsNone(re.search(r"\sssl(\s|$)", line))

    def test_the_single_server_form_gets_the_tls_check(self):
        single = proxy(ssl_check=True, backend_host="10.0.0.12", backend_port=443)
        single.pop("servers")
        self.assertEqual(server_lines(render([], tcp_proxies=[single])),
                         ["server srv1 10.0.0.12:443 check check-ssl verify none"])


if __name__ == "__main__":
    unittest.main()
