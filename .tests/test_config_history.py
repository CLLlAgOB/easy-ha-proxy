"""Regression checks for retained configuration versions."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_controld():
    path = ROOT / "ansible/roles/haproxy-admin/files/haproxy-controld.py"
    spec = importlib.util.spec_from_file_location("easy_ha_proxy_controld", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


controld = load_controld()


class HistoryTestCase(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)

        self.sources = root / "config"
        self.sources.mkdir()
        self.history = root / "history"

        self._patchers = [
            mock.patch.object(controld, "CONFIG_HISTORY_DIR", self.history),
            mock.patch.object(controld, "CONFIG_SOURCE_DIR", str(self.sources)),
        ]
        for patcher in self._patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

        self.write(websites="sites: []\n", tcp="tcp: []\n", variables="a: 1\n")

    def write(self, websites=None, tcp=None, variables=None):
        if websites is not None:
            (self.sources / "websites.yml").write_text(websites, encoding="utf-8")
        if tcp is not None:
            (self.sources / "tcp.yml").write_text(tcp, encoding="utf-8")
        if variables is not None:
            (self.sources / "vars.yml").write_text(variables, encoding="utf-8")


class RecordingTests(HistoryTestCase):
    def test_a_version_keeps_every_managed_source(self):
        version_id = controld.record_config_version({"id": "tx-1"})
        self.assertTrue(version_id)
        stored = self.history / version_id
        for name in ("websites.yml", "tcp.yml", "vars.yml", "meta.json"):
            self.assertTrue((stored / name).is_file(), name)
        meta = json.loads((stored / "meta.json").read_text(encoding="utf-8"))
        self.assertEqual(meta["transaction_id"], "tx-1")
        self.assertEqual(sorted(meta["files"]), ["tcp.yml", "vars.yml", "websites.yml"])

    def test_each_version_points_at_the_one_before_it(self):
        first = controld.record_config_version()
        self.write(websites="sites: [a]\n")
        second = controld.record_config_version()
        meta = json.loads(
            (self.history / second / "meta.json").read_text(encoding="utf-8")
        )
        self.assertEqual(meta["parent"], first)

    def test_confirming_a_change_that_changed_nothing_adds_no_version(self):
        first = controld.record_config_version()
        again = controld.record_config_version()
        self.assertEqual(first, again)
        self.assertEqual(len(controld.list_config_versions()), 1)

    def test_history_is_pruned_to_the_configured_depth(self):
        with mock.patch.object(controld, "CONFIG_HISTORY_KEEP", 3):
            for index in range(6):
                self.write(websites=f"sites: [{index}]\n")
                controld.record_config_version()
        self.assertEqual(len(controld.list_config_versions()), 3)

    def test_a_reader_never_sees_a_half_written_version(self):
        # Every version is assembled elsewhere and renamed into place, so a
        # failure part-way through leaves nothing behind.
        with mock.patch.object(
            controld.os, "replace", side_effect=OSError("no space")
        ):
            self.assertEqual(controld.record_config_version(), "")
        self.assertEqual(controld.list_config_versions(), [])
        self.assertEqual(
            [p.name for p in self.history.iterdir() if p.name.startswith(".staging")],
            [],
        )

    def test_recording_never_fails_the_change_that_already_succeeded(self):
        with mock.patch.object(
            controld, "_read_current_config_sources", side_effect=OSError("gone")
        ):
            self.assertEqual(controld.record_config_version(), "")

    def test_missing_sources_produce_no_version_rather_than_an_empty_one(self):
        for name in ("websites.yml", "tcp.yml", "vars.yml"):
            (self.sources / name).unlink()
        self.assertEqual(controld.record_config_version(), "")
        self.assertEqual(controld.list_config_versions(), [])


class ReadingTests(HistoryTestCase):
    def test_versions_are_listed_newest_first(self):
        ids = []
        for index in range(3):
            self.write(websites=f"sites: [{index}]\n")
            ids.append(controld.record_config_version())
        listed = [entry["id"] for entry in controld.list_config_versions()]
        self.assertEqual(listed, list(reversed(ids)))

    def test_one_version_comes_back_with_its_sources(self):
        self.write(websites="sites: [shop]\n")
        version_id = controld.record_config_version()
        payload = controld.get_config_version(version_id)
        import base64

        decoded = base64.b64decode(payload["sources"]["websites.yml"]).decode()
        self.assertEqual(decoded, "sites: [shop]\n")

    def test_an_unknown_identifier_is_refused(self):
        controld.record_config_version()
        for hostile in (
            "",
            "nope",
            "../../etc/passwd",
            "..",
            "/etc",
        ):
            with self.assertRaises(ValueError, msg=hostile):
                controld.get_config_version(hostile)

    def test_a_traversal_cannot_escape_the_history_directory(self):
        outside = Path(self.directory.name) / "secret.yml"
        outside.write_text("password: hunter2\n", encoding="utf-8")
        controld.record_config_version()
        with self.assertRaises(ValueError):
            controld.get_config_version("../secret.yml")

    def test_the_listing_limit_is_bounded(self):
        for index in range(3):
            self.write(websites=f"sites: [{index}]\n")
            controld.record_config_version()
        self.assertLessEqual(len(controld.list_config_versions(100000)), 3)


class IntegrationPointTests(unittest.TestCase):
    def test_the_version_is_recorded_where_the_change_is_confirmed(self):
        source = (
            ROOT / "ansible/roles/haproxy-admin/files/haproxy-controld.py"
        ).read_text(encoding="utf-8")
        confirmed = source.index('state["state"] = "confirmed"')
        recorded = source.index("record_config_version(state)", confirmed)
        # The rollback path drops the same field, so look only after the
        # confirmation for the one that matters here.
        dropped = source.index('state.pop("previous_sources", None)', confirmed)
        # Recorded after the change is confirmed, and before the rollback
        # material is thrown away.
        self.assertLess(confirmed, recorded)
        self.assertLess(recorded, dropped)

    def test_the_socket_exposes_reading_but_no_way_to_forge_a_version(self):
        source = (
            ROOT / "ansible/roles/haproxy-admin/files/haproxy-controld.py"
        ).read_text(encoding="utf-8")
        self.assertIn('cmd == "config-versions"', source)
        self.assertIn('cmd.startswith("config-version ")', source)
        # History is written by confirming a change, never by a command.
        self.assertNotIn('cmd.startswith("config-version-write', source)
        self.assertNotIn('cmd == "config-version-delete"', source)


if __name__ == "__main__":
    unittest.main()
