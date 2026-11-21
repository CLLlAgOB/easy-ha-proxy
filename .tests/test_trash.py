"""A deletion can be undone for thirty days.

Deleting a site, a TCP proxy or a UDP forward used to rewrite its YAML
without the entry, and deleting a certificate, an authority, a DNS profile
or a delivery target removed its files on the host: in both cases the only
copy was gone. Held here:

* what a deletion removes is set aside first -- by the panel for the YAML
  entries, by certd for the files -- and a deletion that fails leaves
  nothing behind in the trash;
* restoring puts it back through the rules a new entry would meet, and is
  refused, with the item kept, when something of the same name has taken
  its place;
* files come back where they were, symlinks as symlinks, and certd never
  restores outside its own directories even from a tampered item;
* nothing is kept longer than thirty days, and nothing secret ever leaves
  certd in the listing.
"""

from __future__ import annotations

import copy
from contextlib import nullcontext
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
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
        self.assertEqual(listed[0]["expires_at"] - listed[0]["deleted_at"], 30 * DAY)

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

    def test_nothing_is_kept_past_its_term(self):
        sites.delete_site_by_name("shop")
        item = trash.items()[0]
        self.assertEqual(trash.items(now=item["deleted_at"] + 30 * DAY), [])

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

    def test_a_trash_that_cannot_be_written_does_not_fail_the_delete(self):
        os.environ["HAPROXY_ADMIN_TRASH_DIR"] = "/proc/no-such-place/trash"
        with self.assertLogs("haproxy-admin", level="WARNING"):
            self.assertTrue(sites.delete_site_by_name("shop")[0])
        self.assertEqual(self.names("websites", "sites"), ["blog"])

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
        self.assertIn("It goes to the trash and can be restored there for 30 days.", edit)
        certs = (self.APP / "static" / "js" / "haproxy_certs.js").read_text(encoding="utf-8")
        self.assertNotIn("Permanently delete", certs)

    def test_the_page_and_its_api_are_superadmin_only(self):
        routes = (self.APP / "routes_trash.py").read_text(encoding="utf-8")
        for handler in ("api_trash_list", "api_trash_restore", "api_trash_delete", "api_trash_empty"):
            body = routes.split(f"def {handler}(")[1].split("\n@bp.")[0]
            self.assertIn("_superadmin()", body, handler)


if __name__ == "__main__":
    unittest.main()
