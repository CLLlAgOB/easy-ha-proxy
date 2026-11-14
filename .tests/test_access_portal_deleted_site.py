"""A deleted site's access page does not come back with a new site of that name (N03).

The instructions and attachments of an access page are stored under the
site's name. Deleting the site left them in place -- up to half a gigabyte,
carried in every backup -- and a site created later with the same name was
born with the old instructions and files, already published.

Held here: deleting a site moves its storage aside at once, a new site starts
with nothing, what was set aside is removed after thirty days, and none of
this can fail the change to the site itself.
"""

from __future__ import annotations

import copy
from contextlib import nullcontext
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "docker" / "app"))
if sys.platform != "win32":
    from haproxy_admin import access_portal as store
    from haproxy_admin import services_haproxy_sites as sites
else:
    store = sites = None

DAY = 86400
NOW = 1_800_000_000


@unittest.skipUnless(store, "Linux file locking")
class TheStorage(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name) / "portals"
        env = patch.dict(os.environ, {"HAPROXY_ADMIN_PORTAL_DIR": str(self.root)})
        env.start()
        self.addCleanup(env.stop)

    def publish(self, site="support"):
        value = store.upload(site, "helper.exe", io.BytesIO(b"attachment bytes"))
        value = store.configure(site, {
            "enabled": True, "text": "Old instructions",
            "files": [{k: f[k] for k in ("id", "title", "description")} for f in value["files"]],
            "revision": value["revision"]})
        return value["files"][0]["id"]

    def trash(self):
        folder = self.root / store.TRASH
        return sorted(folder.iterdir()) if folder.is_dir() else []

    def test_a_deleted_site_publishes_nothing_and_a_new_one_starts_empty(self):
        identifier = self.publish()
        self.assertTrue(store.discard("support", now=NOW))
        again = store.settings("support")
        self.assertEqual((again["enabled"], again["text"], again["files"]), (False, "", []))
        with self.assertRaises(FileNotFoundError):
            store.open_download("support", identifier)

    def test_the_files_are_set_aside_not_destroyed(self):
        self.publish()
        store.discard("support", now=NOW)
        kept = self.trash()
        self.assertEqual(len(kept), 1)
        self.assertTrue(any(path.suffix == ".bin" for path in kept[0].iterdir()))
        self.assertTrue((kept[0] / "settings.json").is_file())

    def test_another_site_is_left_alone(self):
        self.publish("support")
        other = self.publish("other")
        store.discard("support", now=NOW)
        stream, item = store.open_download("other", other)
        stream.close()
        self.assertEqual(item["filename"], "helper.exe")

    def test_a_site_with_no_access_page_costs_nothing(self):
        self.assertFalse(store.discard("plain-site", now=NOW))
        self.assertFalse(self.root.exists())

    def test_what_was_set_aside_is_removed_after_thirty_days(self):
        self.publish()
        store.discard("support", now=NOW)
        self.assertEqual(store.purge(now=NOW + 29 * DAY), 0)
        self.assertEqual(len(self.trash()), 1)
        self.assertEqual(store.purge(now=NOW + 30 * DAY), 1)
        self.assertEqual(self.trash(), [])

    def test_the_same_name_deleted_twice_keeps_both_until_their_own_term(self):
        self.publish()
        store.discard("support", now=NOW)
        self.publish()
        store.discard("support", now=NOW + DAY)
        self.assertEqual(len(self.trash()), 2)
        store.purge(now=NOW + 30 * DAY)
        self.assertEqual(len(self.trash()), 1)

    def test_only_what_this_module_put_there_is_ever_removed(self):
        self.publish()
        store.discard("support", now=NOW)
        stranger = self.root / store.TRASH / "notes"
        stranger.mkdir()
        (self.root / store.TRASH / "readme.txt").write_text("keep")
        store.purge(now=NOW + 400 * DAY)
        self.assertTrue(stranger.is_dir())
        self.assertTrue((self.root / store.TRASH / "readme.txt").is_file())

    def test_a_download_in_progress_keeps_its_file(self):
        identifier = self.publish()
        stream, _item = store.open_download("support", identifier)
        self.addCleanup(stream.close)
        store.discard("support", now=NOW)
        self.assertEqual(stream.read(), b"attachment bytes")


@unittest.skipUnless(store, "Linux application imports")
class TheSite(unittest.TestCase):
    def setUp(self):
        self.data = {"sites": [{"name": "support", "domain": "support.example.test", "access_gate": True}]}
        self.addCleanup(patch.stopall)
        patch.object(sites, "source_lock", side_effect=lambda _kind: nullcontext()).start()
        patch.object(sites, "_load_yaml", side_effect=lambda _path: copy.deepcopy(self.data)).start()
        self.write = patch.object(sites, "update_yaml_file", side_effect=self.save).start()
        patch.object(sites, "_ensure_access_gate_authelia_rule", return_value=(True, "")).start()
        self.discard = patch.object(store, "discard").start()

    def save(self, _kind, text):
        self.data = yaml.safe_load(text)
        return True, "saved"

    def test_deleting_a_site_sets_its_access_page_aside(self):
        self.assertTrue(sites.delete_site_by_name("support")[0])
        self.discard.assert_called_once_with("support")

    def test_a_refused_delete_sets_nothing_aside(self):
        self.write.side_effect = lambda _kind, _text: (False, "locked")
        self.assertFalse(sites.delete_site_by_name("support")[0])
        self.discard.assert_not_called()

    def test_a_missing_site_sets_nothing_aside(self):
        self.assertFalse(sites.delete_site_by_name("nobody")[0])
        self.discard.assert_not_called()

    def test_a_new_service_site_starts_with_nothing_left_under_its_name(self):
        self.data = {"sites": []}
        self.assertTrue(sites.add_site_minimal("new.example.test", "new.example.test", "", "")[0])
        self.discard.assert_called_once_with("new.example.test")

    def test_a_name_already_in_use_touches_no_storage(self):
        self.assertFalse(sites.add_site_minimal("support", "support.example.test", "", "")[0])
        self.discard.assert_not_called()

    def test_storage_that_cannot_be_moved_does_not_fail_the_delete(self):
        self.discard.side_effect = OSError("read-only file system")
        with self.assertLogs("haproxy-admin", level="WARNING"):
            self.assertTrue(sites.delete_site_by_name("support")[0])
        self.assertEqual(self.data["sites"], [])


class ThePage(unittest.TestCase):
    def test_the_operator_is_told_before_deleting(self):
        page = (ROOT / "docker/app/haproxy_admin/templates/access_portal_settings.html").read_text(encoding="utf-8")
        sentence = "Its instructions and attachments stop being published at once and are removed for good after 30 days."
        self.assertIn(sentence, page)
        import json

        catalogue = json.loads((ROOT / "docker/app/haproxy_admin/translations/ru/access_portal.json").read_text(encoding="utf-8"))
        self.assertIn(sentence, catalogue["messages"])


if __name__ == "__main__":
    unittest.main()
