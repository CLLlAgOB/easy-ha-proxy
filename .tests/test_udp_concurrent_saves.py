"""Saving UDP forwards from two places at once (R04).

From the 4 November post-implementation review: the lock and revisions that
sites and TCP proxies got (F17) did not cover udp.yml. Two forms saving at
once both read the same file; both answered "saved" and only one forward was
left. A failed apply's rollback could also put back a file without a save
made meanwhile. Save, delete, apply and rollback now hold the lock beside
udp.yml from the read to the end, and an edit form carries the forward's
fingerprint.
"""

from __future__ import annotations

import concurrent.futures
import importlib
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "docker" / "app"))


def forward(index, port=None):
    return {"name": f"probe{index}", "listen_port": port or 5100 + index,
            "backend_host": "10.0.0.8", "backend_port": 53, "enabled": True}


@unittest.skipIf(sys.platform == "win32", "the panel imports need a POSIX host")
class TwoSaves(unittest.TestCase):
    def setUp(self):
        self.udp = importlib.import_module("haproxy_admin.services_haproxy_udp")
        self.config = importlib.import_module("haproxy_admin.services_haproxy_config")
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "udp.yml"
        self.path.write_text("udp_forwards: []\n", encoding="utf-8")
        for target in (self.udp, self.config):
            patcher = mock.patch.object(target, "UDP_YAML", self.path)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch.object(self.udp, "udp_listen_port_conflict", return_value=None)
        patcher.start()
        self.addCleanup(patcher.stop)

    def names(self):
        return sorted(f["name"] for f in yaml.safe_load(self.path.read_text())["udp_forwards"])

    def slow_apply(self, results):
        """An apply that takes a moment, answering from `results` in turn."""
        answers = iter(results)

        def apply():
            time.sleep(0.2)
            return next(answers)
        return apply

    def test_two_new_forwards_both_stay(self):
        real_load = self.config._load_yaml
        loaded = threading.Event()

        def load(path):
            data = real_load(path)
            loaded.set()
            time.sleep(0.1)  # the other save has every chance to read now
            return data

        with mock.patch.object(self.udp, "_load_yaml", side_effect=load), \
                mock.patch.object(self.udp, "apply_udp_forwards",
                                  side_effect=self.slow_apply([(True, {}, "")] * 2)):
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                saved = list(pool.map(lambda i: self.udp.save_udp_from_json(forward(i)), [1, 2]))
        self.assertTrue(all(ok for ok, _ in saved), saved)
        self.assertEqual(self.names(), ["probe1", "probe2"])

    def test_a_failed_apply_rolls_back_without_losing_a_save_made_meanwhile(self):
        # A's apply fails and is rolled back; B saves while A is still applying.
        results = [(False, {}, "iptables said no"), (True, {}, ""), (True, {}, "")]
        with mock.patch.object(self.udp, "apply_udp_forwards", side_effect=self.slow_apply(results)):
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                first = pool.submit(self.udp.save_udp_from_json, forward(1))
                time.sleep(0.05)
                second = pool.submit(self.udp.save_udp_from_json, forward(2))
                a, b = first.result(), second.result()
        self.assertFalse(a[0])
        self.assertTrue(b[0], b)
        self.assertEqual(self.names(), ["probe2"])

    def test_an_edit_from_a_stale_form_is_refused(self):
        with mock.patch.object(self.udp, "apply_udp_forwards", return_value=(True, {}, "")):
            self.assertTrue(self.udp.save_udp_from_json(forward(1))[0])
            stored = yaml.safe_load(self.path.read_text())["udp_forwards"][0]
            loaded_with = self.udp.udp_revision(stored)
            # Another tab changes it first.
            self.assertTrue(self.udp.save_udp_from_json(forward(1, port=5301), "probe1", loaded_with)[0])
            ok, message = self.udp.save_udp_from_json(forward(1, port=5302), "probe1", loaded_with)
        self.assertFalse(ok)
        self.assertIn("changed in another session", message)
        self.assertEqual(str(yaml.safe_load(self.path.read_text())["udp_forwards"][0]["listen_port"]), "5301")

    def test_a_delete_waits_for_a_save(self):
        with mock.patch.object(self.udp, "apply_udp_forwards",
                               side_effect=self.slow_apply([(True, {}, "")] * 3)):
            self.udp.save_udp_from_json(forward(1))
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                saving = pool.submit(self.udp.save_udp_from_json, forward(2))
                time.sleep(0.05)
                deleting = pool.submit(self.udp.delete_udp_forward, "probe1")
                self.assertTrue(saving.result()[0])
                self.assertTrue(deleting.result()[0])
        self.assertEqual(self.names(), ["probe2"])


class ThePage(unittest.TestCase):
    def test_the_edit_form_carries_the_revision(self):
        template = (ROOT / "docker/app/haproxy_admin/templates/haproxy_udp.html").read_text(encoding="utf-8")
        self.assertIn('name="revision" value="{{ revision }}"', template)
        routes = (ROOT / "docker/app/haproxy_admin/routes_haproxy_udp.py").read_text(encoding="utf-8")
        self.assertIn("revision = udp_revision(edit_forward)", routes)
        self.assertIn('request.form.get("revision")', routes)


if __name__ == "__main__":
    unittest.main()
