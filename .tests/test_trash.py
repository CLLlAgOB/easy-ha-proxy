"""A deletion can be undone until the trash is emptied, or for a term.

Deleting a site, a TCP proxy or a UDP forward used to rewrite its YAML
without the entry, and deleting a certificate, an authority, a DNS profile
or a delivery target removed its files on the host: in both cases the only
copy was gone. Held here:

* what a deletion removes is set aside first -- by the panel for the YAML
  entries, by certd for the files; when it cannot be, nothing is deleted;
  a deletion that fails having removed nothing leaves nothing behind in the
  trash, and one that stopped part-way keeps its copy;
* restoring puts it back through the rules a new entry would meet, and is
  refused, with the item kept, when something of the same name has taken
  its place;
* files come back where they were, symlinks as symlinks, and certd never
  restores outside its own directories even from a tampered item;
* items stay until the trash is emptied unless a term is set; past the term
  an item is gone, from the list and for a restore by its id, and nothing
  secret ever leaves certd in the listing;
* a restore never deadlocks against a deletion, never leaves half a file in
  place, and a service site restored without its login rule says so.
"""

from __future__ import annotations

import copy
from contextlib import contextmanager, nullcontext
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "docker" / "app"))
if sys.platform != "win32":
    from haproxy_admin import access_portal
    from haproxy_admin import services_haproxy_sites as sites
    from haproxy_admin import services_haproxy_tcp as tcp
    from haproxy_admin import services_haproxy_udp as udp
    from haproxy_admin import trash
else:  # fcntl
    access_portal = sites = tcp = udp = trash = None

CERTD_PATH = ROOT / "ansible/roles/haproxy-admin/files/haproxy-certd.py"
SPEC = importlib.util.spec_from_file_location("haproxy_certd_trash", CERTD_PATH)
assert SPEC and SPEC.loader
CERTD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CERTD)

DAY = 86400


class PanelFixture(unittest.TestCase):
    """The three YAML sources in memory, the trash in a throwaway directory."""

    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        env = mock.patch.dict(os.environ, {
            "HAPROXY_ADMIN_TRASH_DIR": str(self.root / "trash"),
            "HAPROXY_ADMIN_PORTAL_DIR": str(self.root / "portals"),
        })
        env.start()
        self.addCleanup(env.stop)
        self.addCleanup(mock.patch.stopall)
        self.data = {
            "websites": {"sites": [
                {"name": "shop", "domain": "shop.example.test", "backend_ip": "192.0.2.10",
                 "backend_port": 8080, "alt_names": ["www.shop.example.test"]},
                {"name": "blog", "domain": "blog.example.test", "backend_ip": "192.0.2.11",
                 "backend_port": 80},
            ]},
            "tcp": {"tcp_proxies": [
                {"name": "db", "bind_ip": "0.0.0.0", "bind_port": 5432,
                 "backends": [{"ip": "192.0.2.20", "port": 5432}]},
            ]},
            "udp": {"udp_forwards": [
                {"name": "dns", "listen_port": 5353, "backend_ip": "192.0.2.30",
                 "backend_port": 53, "enabled": True},
            ]},
        }
        for module, kind in ((sites, "websites"), (tcp, "tcp"), (udp, "udp")):
            mock.patch.object(module, "source_lock", side_effect=lambda _k: nullcontext()).start()
            mock.patch.object(
                module, "_load_yaml",
                side_effect=lambda _p, kind=kind: copy.deepcopy(self.data[kind]),
            ).start()
        mock.patch.object(sites, "update_yaml_file", side_effect=self.save).start()
        mock.patch.object(tcp, "update_yaml_file", side_effect=self.save).start()
        mock.patch.object(udp, "_write_and_apply", side_effect=self.apply_udp).start()
        mock.patch.object(udp, "udp_listen_port_conflict", return_value=None).start()
        self.gate_rule = mock.patch.object(
            sites, "_ensure_access_gate_authelia_rule", return_value=(True, "")
        ).start()

    def save(self, kind, text):
        self.data[kind] = yaml.safe_load(text)
        return True, "saved"

    def apply_udp(self, data):
        self.data["udp"] = copy.deepcopy(data)
        return True, "applied"

    def names(self, kind, key):
        return [entry["name"] for entry in self.data[kind][key]]


@unittest.skipUnless(trash, "Linux file locking")
class DeletedEntriesAreKept(PanelFixture):
    def test_a_deleted_site_waits_in_the_trash_and_comes_back_as_it_was(self):
        original = copy.deepcopy(self.data["websites"]["sites"][0])
        ok, message = sites.delete_site_by_name("shop")
        self.assertTrue(ok)
        self.assertIn("trash", message)
        self.assertEqual(self.names("websites", "sites"), ["blog"])

        listed = trash.items()
        self.assertEqual([(i["kind"], i["name"]) for i in listed], [("site", "shop")])
        self.assertIn("www.shop.example.test", listed[0]["detail"])
        self.assertEqual(listed[0]["expires_at"], 0, "kept until the trash is emptied")

        result = trash.restore(listed[0]["id"])
        self.assertTrue(result["ok"], result)
        self.assertEqual(self.data["websites"]["sites"][-1], original)
        self.assertEqual(trash.items(), [])

    def test_a_site_whose_name_was_taken_meanwhile_stays_in_the_trash(self):
        sites.delete_site_by_name("shop")
        item = trash.items()[0]
        self.data["websites"]["sites"].append(
            {"name": "shop", "domain": "other.example.test", "backend_ip": "192.0.2.99",
             "backend_port": 80})
        result = trash.restore(item["id"])
        self.assertFalse(result["ok"])
        self.assertEqual(len(trash.items()), 1, "a refused restore keeps the item")

    def test_a_restored_service_site_gets_its_login_rule(self):
        self.data["websites"]["sites"].append(
            {"name": "door", "domain": "door.example.test", "access_gate": True})
        sites.delete_site_by_name("door")
        trash.restore(trash.items()[0]["id"])
        self.gate_rule.assert_called_once_with(["door.example.test"])

    def test_a_refused_delete_keeps_nothing(self):
        with mock.patch.object(sites, "update_yaml_file", return_value=(False, "locked")):
            self.assertFalse(sites.delete_site_by_name("shop")[0])
        self.assertEqual(trash.items(), [])

    def test_tcp_and_udp_entries_come_back_too(self):
        self.assertTrue(tcp.delete_tcp_proxy("db")[0])
        self.assertTrue(udp.delete_udp_forward("dns")[0])
        self.assertEqual(self.data["tcp"]["tcp_proxies"], [])
        self.assertEqual(self.data["udp"]["udp_forwards"], [])
        for item in trash.items():
            self.assertTrue(trash.restore(item["id"])["ok"])
        self.assertEqual(self.names("tcp", "tcp_proxies"), ["db"])
        self.assertEqual(self.names("udp", "udp_forwards"), ["dns"])

    def test_a_udp_forward_whose_port_was_taken_stays_in_the_trash(self):
        udp.delete_udp_forward("dns")
        self.data["udp"]["udp_forwards"].append(
            {"name": "other", "listen_port": 5353, "backend_ip": "192.0.2.31",
             "backend_port": 53, "enabled": True})
        result = trash.restore(trash.items()[0]["id"])
        self.assertFalse(result["ok"])
        self.assertEqual(len(trash.items()), 1)

    def test_a_tcp_proxy_on_a_taken_port_stays_in_the_trash(self):
        tcp.delete_tcp_proxy("db")
        self.data["tcp"]["tcp_proxies"].append(
            {"name": "db2", "bind_ip": "0.0.0.0", "bind_port": 5432,
             "backends": [{"ip": "192.0.2.21", "port": 5432}]})
        self.assertFalse(trash.restore(trash.items()[0]["id"])["ok"])

    def test_items_stay_until_emptied_unless_a_term_is_set(self):
        sites.delete_site_by_name("shop")
        item = trash.items()[0]
        self.assertEqual(trash.keep_days(), 0)
        self.assertEqual(len(trash.items(now=item["deleted_at"] + 400 * DAY)), 1)
        self.assertEqual(trash.set_keep_days(30, now=item["deleted_at"] + DAY), 30)
        self.assertEqual(trash.items(now=item["deleted_at"] + DAY)[0]["expires_at"],
                         item["deleted_at"] + 30 * DAY)
        self.assertEqual(trash.items(now=item["deleted_at"] + 30 * DAY), [])

    def test_an_item_past_its_term_cannot_be_restored_by_its_id(self):
        sites.delete_site_by_name("shop")
        item = trash.items()[0]
        trash.set_keep_days(30, now=item["deleted_at"])
        with self.assertRaises(trash.TrashError):
            trash.restore(item["id"], now=item["deleted_at"] + 31 * DAY)
        self.assertEqual(self.names("websites", "sites"), ["blog"])
        self.assertEqual(trash.items(now=item["deleted_at"]), [], "and it is gone")

    def test_a_shorter_term_takes_older_items_at_once_and_bad_terms_are_refused(self):
        sites.delete_site_by_name("shop")
        item = trash.items()[0]
        trash.set_keep_days(10, now=item["deleted_at"] + 11 * DAY)
        self.assertEqual(trash.items(now=item["deleted_at"]), [])
        for bad in (-1, 3651, "ten", None, 1.5):
            with self.subTest(bad=bad), self.assertRaises(trash.TrashError):
                trash.set_keep_days(bad)
        self.assertEqual(trash.keep_days(), 10)
        trash.set_keep_days(0)
        self.assertEqual(trash.keep_days(), 0)

    def test_items_can_be_deleted_for_good(self):
        sites.delete_site_by_name("shop")
        sites.delete_site_by_name("blog")
        first = trash.items()[0]
        trash.remove(first["id"])
        self.assertEqual(len(trash.items()), 1)
        self.assertEqual(trash.empty(), 1)
        self.assertEqual(trash.items(), [])
        with self.assertRaises(trash.TrashError):
            trash.restore(first["id"])

    def test_ids_are_never_paths(self):
        for bad in ("../x", "", "1-2", "../../etc/passwd"):
            with self.assertRaises(trash.TrashError):
                trash.restore(bad)

    def test_an_entry_that_cannot_be_kept_is_not_deleted(self):
        # A full disk used to lose the entry: the YAML was rewritten first and
        # the page still said it could be restored.
        os.environ["HAPROXY_ADMIN_TRASH_DIR"] = "/proc/no-such-place/trash"
        with self.assertLogs("haproxy-admin", level="WARNING"):
            for ok, message in (sites.delete_site_by_name("shop"), tcp.delete_tcp_proxy("db"),
                                udp.delete_udp_forward("dns")):
                self.assertFalse(ok)
                self.assertIn("nothing was deleted", message)
        self.assertEqual(self.names("websites", "sites"), ["shop", "blog"])
        self.assertEqual(self.names("tcp", "tcp_proxies"), ["db"])
        self.assertEqual(self.names("udp", "udp_forwards"), ["dns"])

    def test_a_failed_tcp_or_udp_write_keeps_nothing(self):
        with mock.patch.object(tcp, "update_yaml_file", return_value=(False, "locked")), \
                mock.patch.object(udp, "_write_and_apply", return_value=(False, "apply failed")):
            self.assertFalse(tcp.delete_tcp_proxy("db")[0])
            self.assertFalse(udp.delete_udp_forward("dns")[0])
        self.assertEqual(trash.items(), [])

    def test_a_failed_restore_puts_the_item_back(self):
        sites.delete_site_by_name("shop")
        item = trash.items()[0]
        with mock.patch.object(sites, "update_yaml_file", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                trash.restore(item["id"])
        self.assertEqual([i["id"] for i in trash.items()], [item["id"]])

    def test_an_abandoned_claim_is_offered_again(self):
        sites.delete_site_by_name("shop")
        item = trash.items()[0]
        directory = self.root / "trash"
        claim = directory / f"{item['id']}{trash.CLAIM}"
        os.replace(directory / f"{item['id']}.json", claim)
        self.assertEqual(trash.items(), [])
        old = item["deleted_at"] - 3600
        os.utime(claim, (old, old))
        self.assertEqual([i["id"] for i in trash.items()], [item["id"]])

    def test_a_restore_of_an_old_item_is_not_taken_for_an_abandoned_one(self):
        # The claim is a rename, which keeps the item's mtime: a listing during
        # the restore of an item older than ten minutes took it back.
        sites.delete_site_by_name("shop")
        item = trash.items()[0]
        stored = self.root / "trash" / f"{item['id']}.json"
        old = time.time() - DAY
        os.utime(stored, (old, old))
        seen = []

        def save_while_listing(kind, text):
            seen.append(trash.items())
            return self.save(kind, text)

        with mock.patch.object(sites, "update_yaml_file", side_effect=save_while_listing):
            self.assertTrue(trash.restore(item["id"])["ok"])
        self.assertEqual(seen, [[]], "invisible while it is being restored")
        self.assertEqual(trash.items(), [])
        self.assertEqual(self.names("websites", "sites"), ["blog", "shop"])

    def test_emptying_the_trash_during_a_deletion_cannot_take_the_copy(self):
        def save_after_someone_empties(kind, text):
            trash.empty()
            return self.save(kind, text)

        with mock.patch.object(sites, "update_yaml_file", side_effect=save_after_someone_empties):
            self.assertTrue(sites.delete_site_by_name("shop")[0])
        self.assertEqual([(i["kind"], i["name"]) for i in trash.items()], [("site", "shop")])

    def test_a_udp_forward_gone_after_a_failed_rollback_stays_in_the_trash(self):
        def apply_then_fail_to_roll_back(data):
            self.data["udp"] = copy.deepcopy(data)  # the new udp.yml stays
            return False, "Applying the UDP rules failed and restoring udp.yml also failed"

        with mock.patch.object(udp, "_write_and_apply", side_effect=apply_then_fail_to_roll_back):
            ok, message = udp.delete_udp_forward("dns")
        self.assertFalse(ok)
        self.assertIn("kept in the trash", message)
        self.assertEqual(self.data["udp"]["udp_forwards"], [])
        self.assertEqual([(i["kind"], i["name"]) for i in trash.items()], [("udp", "dns")])

    def test_a_term_switched_off_just_before_a_listing_is_honoured(self):
        sites.delete_site_by_name("shop")
        item = trash.items()[0]
        trash.set_keep_days(30, now=item["deleted_at"])
        locked = trash._locked

        @contextmanager
        def another_request_switched_it_off_first():
            with locked() as directory:
                (directory / trash.SETTINGS).write_text('{"keep_days": 0}', encoding="utf-8")
                yield directory

        with mock.patch.object(trash, "_locked", another_request_switched_it_off_first):
            listed = trash.items(now=item["deleted_at"] + 31 * DAY)
        self.assertEqual([i["id"] for i in listed], [item["id"]])

    def test_changes_of_the_term_take_turns(self):
        order = []

        def change(label, hold):
            with trash.settings_lock():
                order.append(f"{label} in")
                time.sleep(hold)
                order.append(f"{label} out")

        first = threading.Thread(target=change, args=("first", 0.3))
        first.start()
        time.sleep(0.1)
        second = threading.Thread(target=change, args=("second", 0))
        second.start()
        first.join(5)
        second.join(5)
        self.assertEqual(order, ["first in", "first out", "second in", "second out"])

    def test_a_service_site_restored_without_its_login_rule_says_so(self):
        self.gate_rule.return_value = (False, "authelia is down")
        self.data["websites"]["sites"].append(
            {"name": "door", "domain": "door.example.test", "access_gate": True})
        sites.delete_site_by_name("door")
        result = trash.restore(trash.items()[0]["id"])
        self.assertTrue(result["ok"])
        self.assertEqual(result["warning"], sites.GATE_RULE_WARNING)


@unittest.skipUnless(trash, "Linux file locking")
class TheAccessPageComesBack(PanelFixture):
    def test_a_restored_service_site_gets_its_page_back(self):
        self.data["websites"]["sites"].append(
            {"name": "door", "domain": "door.example.test", "access_gate": True})
        access_portal.upload("door", "helper.exe", io.BytesIO(b"attachment bytes"))
        sites.delete_site_by_name("door")
        self.assertEqual(access_portal.settings("door")["files"], [])
        result = trash.restore(trash.items()[0]["id"])
        self.assertEqual(result.get("access_page"), "restored")
        self.assertEqual(len(access_portal.settings("door")["files"]), 1)

    def test_a_page_removed_for_good_is_reported(self):
        self.data["websites"]["sites"].append(
            {"name": "door", "domain": "door.example.test", "access_gate": True})
        access_portal.upload("door", "helper.exe", io.BytesIO(b"attachment bytes"))
        sites.delete_site_by_name("door")
        shutil.rmtree(self.root / "portals" / access_portal.TRASH)
        result = trash.restore(trash.items()[0]["id"])
        self.assertTrue(result["ok"])
        self.assertEqual(result.get("access_page"), "gone")

    def door(self):
        self.data["websites"]["sites"].append(
            {"name": "door", "domain": "door.example.test", "access_gate": True})
        access_portal.upload("door", "helper.exe", io.BytesIO(b"attachment bytes"))
        sites.delete_site_by_name("door")
        return self.root / "portals" / access_portal.TRASH

    def test_the_page_comes_back_while_the_site_is_still_locked(self):
        # Done after the site's restore released the lock, the page could land
        # on a new site of the same name created in between.
        kept = self.door()
        state = {"locked": False, "seen": None}

        @contextmanager
        def websites_lock(_kind):
            state["locked"] = True
            try:
                yield
            finally:
                state["locked"] = False

        real = trash.restore_access_page

        def restore_page(name, stored):
            state["seen"] = state["locked"]
            return real(name, stored)

        with mock.patch.object(sites, "source_lock", websites_lock), \
                mock.patch.object(trash, "restore_access_page", side_effect=restore_page):
            result = trash.restore(trash.items()[0]["id"])
        self.assertEqual(result.get("access_page"), "restored")
        self.assertIs(state["seen"], True)
        self.assertEqual(list(kept.iterdir()), [])

    def test_a_page_that_cannot_be_recorded_goes_back_and_nothing_is_deleted(self):
        self.data["websites"]["sites"].append(
            {"name": "door", "domain": "door.example.test", "access_gate": True})
        access_portal.upload("door", "helper.exe", io.BytesIO(b"attachment bytes"))
        with mock.patch.object(trash, "annotate", side_effect=trash.TrashError("disk full")):
            ok, message = sites.delete_site_by_name("door")
        self.assertFalse(ok)
        self.assertIn("nothing was deleted", message)
        self.assertIn("door", self.names("websites", "sites"))
        self.assertEqual(len(access_portal.settings("door")["files"]), 1)
        self.assertEqual(trash.items(), [])

    def test_deleting_a_site_for_good_deletes_its_attachments(self):
        kept = self.door()
        self.assertEqual(len(list(kept.iterdir())), 1)
        trash.remove(trash.items()[0]["id"])
        self.assertEqual(list(kept.iterdir()), [])

    def test_emptying_the_trash_deletes_the_attachments_too(self):
        kept = self.door()
        trash.empty()
        self.assertEqual(list(kept.iterdir()), [])

    def test_a_page_waits_as_long_as_its_site_and_goes_with_its_term(self):
        kept = self.door()
        later = time.time() + 400 * DAY
        access_portal.purge(later)
        self.assertEqual(len(list(kept.iterdir())), 1, "its site is still in the trash")
        trash.set_keep_days(30, now=later)
        self.assertEqual(list(kept.iterdir()), [])

    def test_a_page_no_item_names_goes_after_the_old_term(self):
        kept = self.door()
        trash.empty()
        access_portal.upload("door", "helper.exe", io.BytesIO(b"attachment bytes"))
        access_portal.discard("door")
        self.assertEqual(len(list(kept.iterdir())), 1)
        access_portal.purge(time.time() + 31 * DAY)
        self.assertEqual(list(kept.iterdir()), [])


class CertdFixture(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        root = Path(folder.name).resolve()
        self.root = root
        patches = {
            "HAPROXY_CERTS_DIR": root / "certs",
            "CERTS_AVAILABLE_DIR": root / "certs-available",
            "LETSENCRYPT_ROOT_DIR": root / "letsencrypt",
            "CA_ROOT_DIR": root / "ca",
            "DNS_CREDENTIALS_DIR": root / "dns",
            "DELIVERY_DIR": root / "deliveries",
            "TRASH_DIR": root / "trash",
        }
        for name, value in patches.items():
            patcher = mock.patch.object(CERTD, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        (root / "certs").mkdir()

    def pem(self, name="shop.example.test"):
        from datetime import datetime, timedelta, timezone

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(timezone.utc)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        cert = (
            x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=90))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
            .sign(key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.PEM) + key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())


class CertdKeepsWhatItDeletes(CertdFixture):
    def test_a_haproxy_certificate_waits_in_the_trash_and_comes_back(self):
        target = self.root / "certs" / "shop.example.test.pem"
        data = self.pem()
        target.write_bytes(data)
        os.chmod(target, 0o640)
        status, answer = CERTD.handle_delete_haproxy({"path": str(target), "actor": "alice"})
        self.assertTrue(answer["ok"], answer)
        self.assertFalse(target.exists())

        listed = CERTD.list_trash()["items"]
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0]["kind"], "haproxy_cert")
        self.assertEqual(listed[0]["deleted_by"], "alice")
        self.assertEqual(listed[0]["details"]["domains"], ["shop.example.test"])
        self.assertNotIn("PRIVATE KEY", json.dumps(listed))

        status, answer = CERTD.handle_trash_restore({"id": listed[0]["id"]})
        self.assertEqual(status, 200, answer)
        self.assertEqual(target.read_bytes(), data)
        self.assertEqual(target.stat().st_mode & 0o777, 0o640)
        self.assertEqual(CERTD.list_trash()["items"], [])

    def test_restoring_over_a_file_of_the_same_name_is_refused(self):
        target = self.root / "certs" / "shop.example.test.pem"
        target.write_bytes(self.pem())
        CERTD.handle_delete_haproxy({"path": str(target)})
        target.write_bytes(b"replacement")
        item = CERTD.list_trash()["items"][0]
        status, answer = CERTD.handle_trash_restore({"id": item["id"]})
        self.assertEqual(status, 400)
        self.assertEqual(target.read_bytes(), b"replacement")
        self.assertEqual(len(CERTD.list_trash()["items"]), 1)

    def lineage(self, name="shop.example.test"):
        le = self.root / "letsencrypt"
        archive = le / "archive" / name
        live = le / "live" / name
        archive.mkdir(parents=True)
        live.mkdir(parents=True)
        (le / "renewal").mkdir()
        (archive / "cert1.pem").write_bytes(self.pem(name))
        (archive / "privkey1.pem").write_bytes(b"key")
        os.symlink(f"../../archive/{name}/cert1.pem", live / "cert.pem")
        os.symlink(f"../../archive/{name}/privkey1.pem", live / "privkey.pem")
        (le / "renewal" / f"{name}.conf").write_text("version = 2\n")
        return le

    def certbot_delete(self, name, rc=0):
        def run(_cmd, timeout=None):
            if rc == 0:
                le = self.root / "letsencrypt"
                shutil.rmtree(le / "live" / name)
                shutil.rmtree(le / "archive" / name)
                (le / "renewal" / f"{name}.conf").unlink()
            return mock.Mock(returncode=rc, stdout="", stderr="")
        return mock.patch.object(CERTD, "_run_bounded", side_effect=run)

    def test_a_lets_encrypt_lineage_comes_back_with_its_links(self):
        le = self.lineage()
        with self.certbot_delete("shop.example.test"):
            status, answer = CERTD.handle_delete_le({"lineage": "shop.example.test"})
        self.assertTrue(answer["ok"], answer)
        self.assertTrue(answer["trash_id"])
        self.assertFalse((le / "live" / "shop.example.test").exists())

        CERTD.restore_trash_item(answer["trash_id"])
        cert = le / "live" / "shop.example.test" / "cert.pem"
        self.assertTrue(cert.is_symlink())
        self.assertEqual(os.readlink(cert), "../../archive/shop.example.test/cert1.pem")
        self.assertTrue(cert.read_bytes().startswith(b"-----BEGIN CERTIFICATE"))
        self.assertTrue((le / "renewal" / "shop.example.test.conf").is_file())

    def test_a_certbot_delete_that_fails_keeps_nothing(self):
        self.lineage()
        with self.certbot_delete("shop.example.test", rc=1):
            status, answer = CERTD.handle_delete_le({"lineage": "shop.example.test"})
        self.assertFalse(answer["ok"])
        self.assertEqual(CERTD.list_trash()["items"], [])

    def test_a_certbot_delete_that_stops_part_way_keeps_its_copy(self):
        # certbot removes the renewal settings first; failing after that used
        # to throw away the only copy of them.
        le = self.lineage()

        def run(_cmd, timeout=None):
            (le / "renewal" / "shop.example.test.conf").unlink()
            return mock.Mock(returncode=1, stdout="", stderr="archive busy")

        with mock.patch.object(CERTD, "_run_bounded", side_effect=run):
            status, answer = CERTD.handle_delete_le({"lineage": "shop.example.test"})
        self.assertFalse(answer["ok"])
        self.assertTrue(answer["trash_id"])
        self.assertIn("part-way", answer["error"])
        self.assertEqual([i["id"] for i in CERTD.list_trash()["items"]], [answer["trash_id"]])

    def test_restoring_puts_the_whole_lineage_back_over_what_certbot_left(self):
        le = self.lineage()

        def run(_cmd, timeout=None):
            (le / "renewal" / "shop.example.test.conf").unlink()
            return mock.Mock(returncode=1, stdout="", stderr="archive busy")

        with mock.patch.object(CERTD, "_run_bounded", side_effect=run):
            _, answer = CERTD.handle_delete_le({"lineage": "shop.example.test"})
        status, restored = CERTD.handle_trash_restore({"id": answer["trash_id"]})
        self.assertEqual(status, 200, restored)
        self.assertTrue((le / "renewal" / "shop.example.test.conf").is_file())
        cert = le / "live" / "shop.example.test" / "cert.pem"
        self.assertTrue(cert.is_symlink() and cert.read_bytes().startswith(b"-----BEGIN CERTIFICATE"))
        names = [p.name for p in (le / "live").iterdir()] + [p.name for p in (le / "archive").iterdir()]
        self.assertEqual(sorted(names), ["shop.example.test", "shop.example.test"], "nothing set aside left over")

    def test_leftovers_that_changed_since_are_not_replaced(self):
        le = self.lineage()

        def run(_cmd, timeout=None):
            (le / "renewal" / "shop.example.test.conf").unlink()
            return mock.Mock(returncode=1, stdout="", stderr="archive busy")

        with mock.patch.object(CERTD, "_run_bounded", side_effect=run):
            _, answer = CERTD.handle_delete_le({"lineage": "shop.example.test"})
        newer = le / "archive" / "shop.example.test" / "cert2.pem"
        newer.write_bytes(b"issued since")
        status, refused = CERTD.handle_trash_restore({"id": answer["trash_id"]})
        self.assertEqual(status, 400, refused)
        self.assertEqual(newer.read_bytes(), b"issued since")
        self.assertEqual(len(CERTD.list_trash()["items"]), 1)

    def test_a_certificate_created_during_a_restore_is_not_overwritten(self):
        target = self.root / "certs" / "shop.example.test.pem"
        target.write_bytes(self.pem())
        _, answer = CERTD.handle_delete_haproxy({"path": str(target)})
        copy_owned = CERTD._copy_owned

        def copy_while_another_request_writes(source, destination):
            copy_owned(source, destination)
            target.write_bytes(b"issued meanwhile")

        with mock.patch.object(CERTD, "_copy_owned", side_effect=copy_while_another_request_writes):
            status, refused = CERTD.handle_trash_restore({"id": answer["trash_id"]})
        self.assertEqual(status, 400, refused)
        self.assertEqual(target.read_bytes(), b"issued meanwhile")
        self.assertEqual([p.name for p in target.parent.iterdir()], [target.name])
        self.assertEqual(len(CERTD.list_trash()["items"]), 1)

    def test_rename_noreplace_without_renameat2_still_refuses(self):
        source = self.root / "certs" / "new.pem"
        source.write_bytes(b"new")
        taken = self.root / "certs" / "taken.pem"
        taken.write_bytes(b"in service")
        with mock.patch.object(CERTD.ctypes, "CDLL", side_effect=OSError("no libc")):
            with self.assertRaises(FileExistsError):
                CERTD._rename_noreplace(source, taken)
            self.assertEqual(taken.read_bytes(), b"in service")
            CERTD._rename_noreplace(source, self.root / "certs" / "free.pem")
        self.assertEqual((self.root / "certs" / "free.pem").read_bytes(), b"new")
        self.assertFalse(source.exists())

    def test_emptying_during_a_deletion_cannot_take_the_copy(self):
        target = self.root / "certs" / "shop.example.test.pem"
        target.write_bytes(self.pem())
        kept = CERTD._trash_put("haproxy_cert", target.name, [target])
        self.assertEqual(CERTD.handle_trash_purge({"all": True})[1]["removed"], 0)
        self.assertEqual(CERTD.list_trash()["items"], [], "a pending copy is not listed")
        target.unlink()
        CERTD._trash_commit(kept)
        self.assertEqual([i["id"] for i in CERTD.list_trash()["items"]], [kept])

    def test_a_pending_copy_left_by_a_crash_is_listed_after_an_hour(self):
        target = self.root / "certs" / "shop.example.test.pem"
        target.write_bytes(self.pem())
        kept = CERTD._trash_put("haproxy_cert", target.name, [target])
        with CERTD.TRASH_LOCK:
            CERTD._trash_purge_locked(time.time() + 3601)
        self.assertEqual([i["id"] for i in CERTD.list_trash()["items"]], [kept])

    def test_emptying_reports_what_it_could_not_delete(self):
        for name in ("a", "b"):
            target = self.root / "certs" / f"{name}.pem"
            target.write_bytes(self.pem(f"{name}.example.test"))
            CERTD.handle_delete_haproxy({"path": str(target)})
        stuck = CERTD.list_trash()["items"][0]["id"]
        real_rmtree = shutil.rmtree

        def rmtree(path, *args, **kwargs):
            if Path(path).name == stuck and not kwargs.get("ignore_errors"):
                raise PermissionError("immutable")
            return real_rmtree(path, *args, **kwargs)

        with mock.patch.object(CERTD.shutil, "rmtree", side_effect=rmtree):
            status, answer = CERTD.handle_trash_purge({"all": True})
        self.assertEqual(status, 500)
        self.assertFalse(answer["ok"])
        self.assertEqual(answer["removed"], 1)
        self.assertIn("immutable", answer["error"])
        self.assertEqual([i["id"] for i in CERTD.list_trash()["items"]], [stuck])

    def test_a_failed_deletion_that_removed_nothing_drops_its_copy(self):
        target = self.root / "certs" / "shop.example.test.pem"
        target.write_bytes(self.pem())
        real_unlink = Path.unlink

        def refuse(path, *args, **kwargs):
            if path == target:
                raise PermissionError("read-only")
            return real_unlink(path, *args, **kwargs)

        with mock.patch.object(Path, "unlink", refuse):
            status, answer = CERTD.handle_delete_haproxy({"path": str(target)})
        self.assertFalse(answer["ok"])
        self.assertTrue(target.exists())
        self.assertEqual(CERTD.list_trash()["items"], [])

    def test_a_half_removed_tree_keeps_its_copy(self):
        tree = self.root / "ca" / "internal"
        tree.mkdir(parents=True)
        (tree / "ca.key").write_text("key")
        (tree / "ca.crt").write_text("crt")
        kept = CERTD._trash_put("internal_ca", "internal", [tree])
        before = CERTD._trash_listing([tree])
        (tree / "ca.key").unlink()
        self.assertEqual(CERTD._trash_settle(kept, before, [tree]), kept)
        self.assertEqual([i["id"] for i in CERTD.list_trash()["items"]], [kept])
        untouched = CERTD._trash_put("internal_ca", "internal", [tree])
        self.assertIsNone(CERTD._trash_settle(untouched, CERTD._trash_listing([tree]), [tree]))
        self.assertEqual([i["id"] for i in CERTD.list_trash()["items"]], [kept])

    def test_a_restore_cut_short_leaves_no_half_file_and_can_be_retried(self):
        target = self.root / "certs" / "shop.example.test.pem"
        data = self.pem()
        target.write_bytes(data)
        status, answer = CERTD.handle_delete_haproxy({"path": str(target)})

        def disk_full(source, destination):
            Path(destination).write_bytes(b"-----BEGIN CERT")
            raise OSError(28, "No space left on device")

        with mock.patch.object(CERTD, "_copy_owned", side_effect=disk_full):
            status, failed = CERTD.handle_trash_restore({"id": answer["trash_id"]})
        self.assertEqual(status, 500, failed)
        self.assertFalse(os.path.lexists(target))
        self.assertEqual(list(target.parent.iterdir()), [], "no temporary file left behind")
        status, restored = CERTD.handle_trash_restore({"id": answer["trash_id"]})
        self.assertEqual(status, 200, restored)
        self.assertEqual(target.read_bytes(), data)

    def test_a_ca_restore_takes_the_locks_in_the_order_deletions_do(self):
        # A CA deletion holds CA_LOCK and then takes TRASH_LOCK; a restore that
        # held TRASH_LOCK while waiting for CA_LOCK deadlocked against it.
        external = self.root / "ca" / "external"
        external.mkdir(parents=True)
        pem = external / "partner.pem"
        pem.write_bytes(self.pem("partner.example.test").split(b"-----BEGIN PRIVATE")[0])
        kept = CERTD._trash_put("external_ca", "partner", [pem])
        pem.unlink()
        CERTD._trash_commit(kept)
        outcome = {}

        def restore():
            try:
                outcome["result"] = CERTD.restore_trash_item(kept)
            except Exception as exc:  # pragma: no cover - reported below
                outcome["error"] = exc

        with mock.patch.object(CERTD, "_load_client_auth_ids", return_value=[]):
            CERTD.CA_LOCK.acquire()
            try:
                worker = threading.Thread(target=restore)
                worker.start()
                time.sleep(0.3)
                self.assertTrue(worker.is_alive(), "waits for CA_LOCK")
                got = CERTD.TRASH_LOCK.acquire(blocking=False)
                self.assertTrue(got, "without holding TRASH_LOCK meanwhile")
                CERTD.TRASH_LOCK.release()
            finally:
                CERTD.CA_LOCK.release()
            worker.join(10)
        self.assertNotIn("error", outcome)
        self.assertTrue(pem.is_file())

    def test_the_term_is_a_setting_and_an_expired_item_cannot_be_restored(self):
        self.assertEqual(CERTD.handle_trash_settings({})[1]["keep_days"], 0)
        target = self.root / "certs" / "a.pem"
        target.write_bytes(self.pem("a.example.test"))
        status, answer = CERTD.handle_delete_haproxy({"path": str(target)})
        self.assertEqual(CERTD.list_trash()["items"][0]["expires_at"], 0)
        self.assertEqual(CERTD.handle_trash_settings({"keep_days": 30})[1]["keep_days"], 30)
        self.assertEqual(CERTD.list_trash()["keep_days"], 30)
        self.assertEqual(CERTD.handle_trash_settings({"keep_days": -1})[0], 400)
        self.assertEqual(CERTD.handle_trash_settings({"keep_days": "x"})[0], 400)
        later = time.time() + 31 * DAY
        with mock.patch.object(CERTD.time, "time", return_value=later):
            status, refused = CERTD.handle_trash_restore({"id": answer["trash_id"]})
        self.assertEqual(status, 400)
        self.assertFalse(target.exists())
        self.assertEqual(CERTD.list_trash()["items"], [])

    def test_dns_profiles_and_delivery_targets_come_back(self):
        CERTD.DNS_CREDENTIALS_DIR.mkdir()
        profile = CERTD.DNS_CREDENTIALS_DIR / "cloud.ini"
        profile.write_text("# provider: cloudflare\ndns_cloudflare_api_token = secret-token\n")
        os.chmod(profile, 0o600)
        with mock.patch.object(CERTD, "_dns_profile_lineages", return_value=[]):
            removed = CERTD.delete_dns_provider("cloud", "alice")
        self.assertFalse(profile.exists())

        CERTD.DELIVERY_DIR.mkdir()
        record, key, hosts = CERTD._delivery_paths("rdg")
        record.write_text(json.dumps({"lineage": "shop.example.test", "host": "203.0.113.5"}))
        key.write_text("private key")
        hosts.write_text("pinned")
        delivery = CERTD.delete_cert_delivery("rdg", "bob")
        self.assertFalse(record.exists() or key.exists() or hosts.exists())

        listed = CERTD.list_trash()["items"]
        self.assertNotIn("secret-token", json.dumps(listed))
        self.assertNotIn("private key", json.dumps(listed))
        CERTD.restore_trash_item(removed["trash_id"])
        CERTD.restore_trash_item(delivery["trash_id"])
        self.assertIn("secret-token", profile.read_text())
        self.assertEqual(profile.stat().st_mode & 0o777, 0o600)
        self.assertTrue(record.exists() and key.exists() and hosts.exists())

    def test_a_standby_comes_back_into_its_own_folder(self):
        with mock.patch.object(CERTD, "read_pin", return_value=""):
            path = CERTD._standby_path("shop.example.test", "spare")
            path.parent.mkdir(parents=True)
            path.write_bytes(self.pem())
            answer = CERTD.delete_standby_certificate("shop.example.test", "spare")
        self.assertTrue(answer["ok"])
        self.assertFalse(path.parent.exists(), "the empty holder goes, as before")
        item = CERTD.list_trash()["items"][0]
        CERTD.restore_trash_item(item["id"])
        self.assertTrue(path.is_file())

    def test_a_tampered_item_is_never_restored_outside_the_certificate_folders(self):
        target = self.root / "certs" / "shop.example.test.pem"
        target.write_bytes(self.pem())
        status, answer = CERTD.handle_delete_haproxy({"path": str(target)})
        meta_path = CERTD.TRASH_DIR / answer["trash_id"] / "meta.json"
        meta = json.loads(meta_path.read_text())
        meta["paths"][0]["path"] = str(self.root / "elsewhere" / "evil.pem")
        meta_path.write_text(json.dumps(meta))
        status, answer = CERTD.handle_trash_restore({"id": answer["trash_id"]})
        self.assertEqual(status, 400)
        self.assertFalse((self.root / "elsewhere").exists())

    def test_nothing_is_kept_past_its_term_and_ids_are_not_paths(self):
        target = self.root / "certs" / "a.pem"
        target.write_bytes(self.pem("a.example.test"))
        CERTD.handle_delete_haproxy({"path": str(target)})
        item = CERTD.list_trash()["items"][0]
        with CERTD.TRASH_LOCK:
            CERTD._trash_purge_locked(item["deleted_at"] + 400 * DAY)
        self.assertEqual(len(CERTD.list_trash()["items"]), 1, "kept until emptied by default")
        CERTD.set_trash_keep_days(30)
        with CERTD.TRASH_LOCK:
            CERTD._trash_purge_locked(item["deleted_at"] + 30 * DAY)
        self.assertEqual(CERTD.list_trash()["items"], [])
        for bad in ("../../etc", "", "x"):
            status, _ = CERTD.handle_trash_restore({"id": bad})
            self.assertEqual(status, 400)

    def test_purging_one_item_or_all(self):
        for name in ("a", "b", "c"):
            target = self.root / "certs" / f"{name}.pem"
            target.write_bytes(self.pem(f"{name}.example.test"))
            CERTD.handle_delete_haproxy({"path": str(target)})
        first = CERTD.list_trash()["items"][0]
        self.assertEqual(CERTD.handle_trash_purge({"id": first["id"]})[1]["removed"], 1)
        self.assertEqual(CERTD.handle_trash_purge({"all": True})[1]["removed"], 2)
        self.assertEqual(CERTD.handle_trash_purge({})[0], 400)

    def test_the_trash_is_never_inside_the_crt_directory(self):
        # One file there that is not a certificate stops HAProxy from starting.
        default = Path("/var/lib/easy-ha-proxy/cert-trash")
        source = CERTD_PATH.read_text(encoding="utf-8")
        self.assertIn(f'"HAPROXY_CERTD_TRASH_DIR", "{default}"', source)


class ThePage(unittest.TestCase):
    APP = ROOT / "docker" / "app" / "haproxy_admin"

    def test_every_deletion_that_now_goes_to_the_trash_says_so(self):
        edit = (self.APP / "templates" / "haproxy_site_edit.html").read_text(encoding="utf-8")
        self.assertNotIn("This action cannot be undone.", edit)
        self.assertIn("It goes to the trash and can be restored from there.", edit)
        certs = (self.APP / "static" / "js" / "haproxy_certs.js").read_text(encoding="utf-8")
        self.assertNotIn("Permanently delete", certs)

    def test_the_page_and_its_api_are_superadmin_only(self):
        routes = (self.APP / "routes_trash.py").read_text(encoding="utf-8")
        for handler in ("api_trash_list", "api_trash_restore", "api_trash_delete", "api_trash_empty",
                        "api_trash_settings"):
            body = routes.split(f"def {handler}(")[1].split("\n@bp.")[0]
            self.assertIn("_superadmin()", body, handler)


if __name__ == "__main__":
    unittest.main()
