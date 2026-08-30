"""A second certificate for a name, held ready but not in play.

The question this answers is the operator's: if a site has both a Let's
Encrypt certificate and one from another authority, which does HAProxy use,
and can the second stand in when the first expires or is revoked?

Measured on HAProxy 2.8, the version the gateways run, rather than assumed:

  * Two files claiming the same name in one crt directory. The configuration
    checks clean, nothing is warned about, and the first in alphabetical
    order is served.
  * An expired certificate beside a perfectly good one. HAProxy serves the
    expired one. It never looks at the dates and it never falls back.

So a passive backup does not exist and cannot be made to. A spare left where
HAProxy can see it does not stand by -- it competes, on filename order, and
may well shadow the good one. It has to wait outside the crt directory, and
something has to deliberately put it in.

That something is a person, not this daemon. A spare is usually signed by an
authority most clients do not carry, so swapping to it unasked would trade
one broken page for another without anybody having decided that was the
better trade. What the daemon does is keep the spare safely, check it is
real before accepting it, put it in when asked, and say in the expiry
warning that there is one ready.
"""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
CERTD_PATH = ROOT / "ansible/roles/haproxy-admin/files/haproxy-certd.py"
SPEC = importlib.util.spec_from_file_location("haproxy_certd_standby", CERTD_PATH)
assert SPEC and SPEC.loader
CERTD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CERTD)


class StandbyFixture(unittest.TestCase):
    """Throwaway certificate directories and material to fill them with.

    Separate from the tests so the classes below can reuse the setup without
    also re-running every test above them -- which they did, three times
    over, until this was split out.
    """

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        CERTD.HAPROXY_CERTS_DIR = (root / "certs").resolve()
        CERTD.CERTS_AVAILABLE_DIR = (root / "certs-available").resolve()
        CERTD.LETSENCRYPT_ROOT_DIR = (root / "letsencrypt").resolve()
        CERTD.HAPROXY_CERTS_DIR.mkdir(parents=True, exist_ok=True)

        self.reloads = []

        def fake_reload():
            self.reloads.append(True)
            return 0, "", ""

        patcher = mock.patch.object(CERTD, "_reload_haproxy", fake_reload)
        patcher.start()
        self.addCleanup(patcher.stop)
        # Ownership is a live gateway's concern; the test user is not root.
        perms = mock.patch.object(CERTD, "_set_cert_permissions", lambda path: None)
        perms.start()
        self.addCleanup(perms.stop)

    def make_pem(self, name, issuer_cn, days=365, not_before_days=1):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(timezone.utc)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=not_before_days))
            .not_valid_after(now + timedelta(days=days))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False
            )
            .sign(key, hashes.SHA256())
        )
        return (
            cert.public_bytes(serialization.Encoding.PEM)
            + key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        ).decode("ascii")

    def deploy_active(self, domain, pem):
        (CERTD.HAPROXY_CERTS_DIR / f"{domain}.pem").write_text(pem, encoding="ascii")


class StandbyCertificateTests(StandbyFixture):
    """A second certificate for a name, held ready but not in play.

    The reason it cannot simply be dropped in beside the first is HAProxy,
    measured on the version the gateways run. Two files claiming one name:
    it loads the first in alphabetical order, warns about nothing -- the
    configuration checks clean -- and serves that one. It never reads the
    dates. Given an expired certificate and a good one side by side it
    serves the expired one, so the site is down for everybody while the
    replacement sits unused a directory listing away.

    There is therefore no such thing as a passive backup. A spare waits
    outside the directory HAProxy reads, and somebody puts it in.

    Deliberately somebody, not this daemon: a spare is usually signed by an
    authority most clients do not carry, so swapping to it unasked would
    trade one broken page for another without anyone having decided that was
    the better trade.
    """

    # -- it is kept out of HAProxy's way -----------------------------------

    def test_a_standby_is_not_written_where_haproxy_would_find_it(self):
        # The single most important property here. Anywhere inside the crt
        # directory and it would silently start competing for the name.
        pem = self.make_pem("site.example.com", "Some Other CA")
        CERTD.store_standby_certificate("site.example.com", "other-ca", pem)
        self.assertEqual(list(CERTD.HAPROXY_CERTS_DIR.glob("*.pem")), [])

    def test_it_is_kept_where_the_daemon_can_find_it(self):
        pem = self.make_pem("site.example.com", "Some Other CA")
        CERTD.store_standby_certificate("site.example.com", "other-ca", pem)
        stored = CERTD.CERTS_AVAILABLE_DIR / "site.example.com" / "other-ca.pem"
        self.assertTrue(stored.is_file())

    # -- what it refuses ---------------------------------------------------

    def test_a_certificate_for_another_name_is_refused(self):
        # Discovered now rather than at the moment it is needed.
        pem = self.make_pem("elsewhere.example.com", "Some Other CA")
        with self.assertRaises(ValueError):
            CERTD.store_standby_certificate("site.example.com", "other-ca", pem)

    def test_a_certificate_without_its_key_is_refused(self):
        pem = self.make_pem("site.example.com", "Some Other CA")
        only_cert = pem.split("-----BEGIN RSA PRIVATE KEY-----")[0]
        with self.assertRaises(ValueError):
            CERTD.store_standby_certificate("site.example.com", "other-ca", only_cert)

    def test_a_mismatched_key_is_refused(self):
        first = self.make_pem("site.example.com", "CA One")
        second = self.make_pem("site.example.com", "CA Two")
        frankenstein = (
            first.split("-----BEGIN RSA PRIVATE KEY-----")[0]
            + "-----BEGIN RSA PRIVATE KEY-----"
            + second.split("-----BEGIN RSA PRIVATE KEY-----")[1]
        )
        with self.assertRaises(ValueError):
            CERTD.store_standby_certificate("site.example.com", "x", frankenstein)

    def test_nothing_at_all_is_refused(self):
        with self.assertRaises(ValueError):
            CERTD.store_standby_certificate("site.example.com", "x", "")

    def test_the_renewing_slot_name_is_reserved(self):
        pem = self.make_pem("site.example.com", "Some Other CA")
        with self.assertRaises(ValueError):
            CERTD.store_standby_certificate("site.example.com", "letsencrypt", pem)

    def test_a_slot_name_cannot_escape_its_directory(self):
        pem = self.make_pem("site.example.com", "Some Other CA")
        CERTD.store_standby_certificate("site.example.com", "../../escape", pem)
        escaped = CERTD.CERTS_AVAILABLE_DIR.parent / "escape.pem"
        self.assertFalse(escaped.exists())

    # -- putting one in ----------------------------------------------------

    def test_activating_replaces_what_haproxy_serves(self):
        self.deploy_active("site.example.com", self.make_pem("site.example.com", "Original CA"))
        standby = self.make_pem("site.example.com", "Standby CA")
        CERTD.store_standby_certificate("site.example.com", "standby", standby)

        result = CERTD.activate_standby_certificate("site.example.com", "standby")
        self.assertTrue(result["ok"])
        self.assertEqual(result["issuer"], "Standby CA")
        active = (CERTD.HAPROXY_CERTS_DIR / "site.example.com.pem").read_text()
        self.assertEqual(active, standby)

    def test_activating_reloads_haproxy(self):
        # A certificate on disk that HAProxy has not read is not in service,
        # which is the exact failure a hook in this project once had.
        self.deploy_active("site.example.com", self.make_pem("site.example.com", "Original CA"))
        CERTD.store_standby_certificate(
            "site.example.com", "standby", self.make_pem("site.example.com", "Standby CA")
        )
        CERTD.activate_standby_certificate("site.example.com", "standby")
        self.assertEqual(len(self.reloads), 1)

    def test_the_standby_stays_available_after_being_used(self):
        # Putting it in is not spending it: the operator may well need to
        # put it in again after the next failed renewal.
        self.deploy_active("site.example.com", self.make_pem("site.example.com", "Original CA"))
        CERTD.store_standby_certificate(
            "site.example.com", "standby", self.make_pem("site.example.com", "Standby CA")
        )
        CERTD.activate_standby_certificate("site.example.com", "standby")
        stored = CERTD.CERTS_AVAILABLE_DIR / "site.example.com" / "standby.pem"
        self.assertTrue(stored.is_file())

    def test_an_expired_standby_is_not_put_in(self):
        # It would be swapping a broken certificate for a broken certificate.
        self.deploy_active("site.example.com", self.make_pem("site.example.com", "Original CA"))
        expired = self.make_pem(
            "site.example.com", "Standby CA", days=-30, not_before_days=400
        )
        path = CERTD.CERTS_AVAILABLE_DIR / "site.example.com"
        path.mkdir(parents=True, exist_ok=True)
        (path / "standby.pem").write_text(expired, encoding="ascii")
        with self.assertRaises(ValueError):
            CERTD.activate_standby_certificate("site.example.com", "standby")

    def test_a_standby_that_does_not_exist_is_refused(self):
        with self.assertRaises(ValueError):
            CERTD.activate_standby_certificate("site.example.com", "nothing")

    # -- what the page is shown --------------------------------------------

    def test_the_listing_pairs_each_name_with_its_spares(self):
        self.deploy_active("site.example.com", self.make_pem("site.example.com", "Original CA"))
        CERTD.store_standby_certificate(
            "site.example.com", "standby", self.make_pem("site.example.com", "Standby CA")
        )
        listing = CERTD.list_standby_certificates()
        entry = [d for d in listing["domains"] if d["domain"] == "site.example.com"][0]
        self.assertEqual(entry["active"]["issuer"], "Original CA")
        self.assertEqual([s["slot"] for s in entry["standbys"]], ["standby"])
        self.assertTrue(entry["has_usable_standby"])

    def test_a_name_with_no_spare_says_so(self):
        self.deploy_active("site.example.com", self.make_pem("site.example.com", "Original CA"))
        listing = CERTD.list_standby_certificates()
        entry = [d for d in listing["domains"] if d["domain"] == "site.example.com"][0]
        self.assertFalse(entry["has_usable_standby"])

    def test_an_unreadable_spare_is_reported_not_hidden(self):
        # A standby nobody can see is broken is worse than no standby: it
        # will be discovered at the one moment it was supposed to help.
        self.deploy_active("site.example.com", self.make_pem("site.example.com", "Original CA"))
        holder = CERTD.CERTS_AVAILABLE_DIR / "site.example.com"
        holder.mkdir(parents=True, exist_ok=True)
        (holder / "broken.pem").write_text("not a certificate", encoding="ascii")
        listing = CERTD.list_standby_certificates()
        entry = [d for d in listing["domains"] if d["domain"] == "site.example.com"][0]
        broken = [s for s in entry["standbys"] if s["slot"] == "broken"][0]
        self.assertFalse(broken["usable"])
        self.assertIn("error", broken)
        self.assertFalse(entry["has_usable_standby"])

    def test_the_issuer_is_reported_because_that_is_the_point(self):
        # A spare is only worth holding if it comes from a different
        # authority, and the operator has to be able to see that it does.
        self.deploy_active("site.example.com", self.make_pem("site.example.com", "Let's Encrypt"))
        CERTD.store_standby_certificate(
            "site.example.com", "other", self.make_pem("site.example.com", "Another Root CA")
        )
        listing = CERTD.list_standby_certificates()
        entry = [d for d in listing["domains"] if d["domain"] == "site.example.com"][0]
        self.assertEqual(entry["active"]["issuer"], "Let's Encrypt")
        self.assertEqual(entry["standbys"][0]["issuer"], "Another Root CA")

    # -- the warning should name the way out -------------------------------

    def test_the_expiry_warning_mentions_a_ready_standby(self):
        CERTD.store_standby_certificate(
            "site.example.com", "standby", self.make_pem("site.example.com", "Standby CA")
        )
        hint = CERTD._standby_hint("site.example.com")
        self.assertIn("standby", hint)
        self.assertIn("Standby CA", hint)

    def test_it_says_nothing_when_there_is_nothing_to_say(self):
        self.assertEqual(CERTD._standby_hint("site.example.com"), "")

    def test_an_unusable_standby_is_not_offered_as_a_way_out(self):
        holder = CERTD.CERTS_AVAILABLE_DIR / "site.example.com"
        holder.mkdir(parents=True, exist_ok=True)
        (holder / "broken.pem").write_text("not a certificate", encoding="ascii")
        self.assertEqual(CERTD._standby_hint("site.example.com"), "")

    # -- removing one ------------------------------------------------------

    def test_deleting_a_standby_leaves_the_active_certificate_alone(self):
        active = self.make_pem("site.example.com", "Original CA")
        self.deploy_active("site.example.com", active)
        CERTD.store_standby_certificate(
            "site.example.com", "standby", self.make_pem("site.example.com", "Standby CA")
        )
        CERTD.delete_standby_certificate("site.example.com", "standby")
        self.assertEqual(
            (CERTD.HAPROXY_CERTS_DIR / "site.example.com.pem").read_text(), active
        )


class HoldingANameOnAStandby(StandbyFixture):
    """A switch the next renewal undoes is not a switch.

    Putting a standby in and leaving it at that would last exactly until
    certbot next succeeded, and the operator would find out from a browser.
    So the name is held: every writer of the certificate directory checks
    the hold and leaves it alone until the name is handed back.

    Four of them, found by reading rather than assumed -- the renewal deploy
    hook, the Ansible build handlers, the orphan sweep, and this daemon's own
    installer. The last one is the reason the check lives inside
    _activate_server_pem: issuing, importing, uploading and restoring all go
    through that single function, so there is no fifth caller that forgot.
    """

    def hold(self, domain="site.example.com", slot="standby", issuer="Standby CA"):
        self.deploy_active(domain, self.make_pem(domain, "Original CA"))
        CERTD.store_standby_certificate(domain, slot, self.make_pem(domain, issuer))
        return CERTD.activate_standby_certificate(domain, slot)

    def test_putting_one_in_holds_the_name(self):
        self.hold()
        self.assertEqual(CERTD.read_pin("site.example.com"), "standby")

    def test_a_name_not_switched_is_not_held(self):
        self.deploy_active("site.example.com", self.make_pem("site.example.com", "Original CA"))
        self.assertEqual(CERTD.read_pin("site.example.com"), "")

    def test_the_installer_refuses_to_overwrite_a_held_name(self):
        # The guarantee. Renewal, import, upload and restore all arrive here.
        self.hold()
        destination = CERTD.HAPROXY_CERTS_DIR / "site.example.com.pem"
        with self.assertRaises(CERTD.PinnedCertificate):
            CERTD._activate_server_pem(
                destination, self.make_pem("site.example.com", "Renewed LE").encode()
            )

    def test_the_held_certificate_is_left_exactly_as_it_was(self):
        self.hold()
        before = (CERTD.HAPROXY_CERTS_DIR / "site.example.com.pem").read_bytes()
        with self.assertRaises(CERTD.PinnedCertificate):
            CERTD._activate_server_pem(
                CERTD.HAPROXY_CERTS_DIR / "site.example.com.pem",
                self.make_pem("site.example.com", "Renewed LE").encode(),
            )
        after = (CERTD.HAPROXY_CERTS_DIR / "site.example.com.pem").read_bytes()
        self.assertEqual(before, after)

    def test_another_name_is_unaffected(self):
        # The hold is per name, not a global freeze on certificates.
        self.hold()
        other = CERTD.HAPROXY_CERTS_DIR / "other.example.com.pem"
        ok, _rc, _out, _err = CERTD._activate_server_pem(
            other, self.make_pem("other.example.com", "Any CA").encode()
        )
        self.assertTrue(ok)

    def test_swapping_between_two_standbys_is_allowed(self):
        self.hold()
        CERTD.store_standby_certificate(
            "site.example.com", "second",
            self.make_pem("site.example.com", "Second CA"),
        )
        result = CERTD.activate_standby_certificate("site.example.com", "second")
        self.assertTrue(result["ok"])
        self.assertEqual(CERTD.read_pin("site.example.com"), "second")

    # -- handing it back ---------------------------------------------------

    def test_handing_back_lifts_the_hold(self):
        self.hold()
        live = CERTD._get_le_live_dir() / "site.example.com"
        live.mkdir(parents=True, exist_ok=True)
        renewed = self.make_pem("site.example.com", "Let's Encrypt")
        cert, _, key = renewed.partition("-----BEGIN RSA PRIVATE KEY-----")
        (live / "fullchain.pem").write_text(cert, encoding="ascii")
        (live / "privkey.pem").write_text(
            "-----BEGIN RSA PRIVATE KEY-----" + key, encoding="ascii"
        )

        result = CERTD.release_to_letsencrypt("site.example.com")
        self.assertTrue(result["ok"])
        self.assertTrue(result["restored"])
        self.assertEqual(CERTD.read_pin("site.example.com"), "")
        active = (CERTD.HAPROXY_CERTS_DIR / "site.example.com.pem").read_text()
        self.assertIn("Let's Encrypt", CERTD._describe_pem(active.encode())["issuer"])

    def test_handing_back_with_nothing_to_restore_still_lifts_the_hold(self):
        # Otherwise the name would stay locked against the very issue that
        # is needed to give it a certificate again.
        self.hold()
        result = CERTD.release_to_letsencrypt("site.example.com")
        self.assertTrue(result["ok"])
        self.assertFalse(result["restored"])
        self.assertEqual(CERTD.read_pin("site.example.com"), "")

    def test_handing_back_a_name_that_was_never_held_is_refused(self):
        with self.assertRaises(ValueError):
            CERTD.release_to_letsencrypt("site.example.com")

    def test_renewal_works_again_once_it_is_handed_back(self):
        self.hold()
        CERTD.release_to_letsencrypt("site.example.com")
        ok, _rc, _out, _err = CERTD._activate_server_pem(
            CERTD.HAPROXY_CERTS_DIR / "site.example.com.pem",
            self.make_pem("site.example.com", "Renewed LE").encode(),
        )
        self.assertTrue(ok)

    def test_the_standby_in_service_cannot_be_deleted(self):
        # Deleting it would leave the name held on a file that is gone.
        self.hold()
        with self.assertRaises(ValueError):
            CERTD.delete_standby_certificate("site.example.com", "standby")

    def test_a_standby_not_in_service_can_still_be_deleted(self):
        self.hold()
        CERTD.store_standby_certificate(
            "site.example.com", "spare", self.make_pem("site.example.com", "Third CA")
        )
        CERTD.delete_standby_certificate("site.example.com", "spare")
        self.assertFalse(
            (CERTD.CERTS_AVAILABLE_DIR / "site.example.com" / "spare.pem").exists()
        )

    def test_the_listing_says_a_name_is_held(self):
        self.hold()
        entry = [
            d for d in CERTD.list_standby_certificates()["domains"]
            if d["domain"] == "site.example.com"
        ][0]
        self.assertEqual(entry["pinned"], "standby")
        self.assertTrue(entry["renewal_paused"])


class DualKeySitesAreFiledByFileName(StandbyFixture):
    """The apex of a dual-key site is deployed as two files.

    oreol-style installations issue <domain>-ecdsa and <domain>-rsa, so the
    stem of the deployed file is not a hostname and no certificate covers it
    literally. Everything that addresses a file uses the stem; the coverage
    check uses the hostname inside it. Getting this wrong would have made a
    standby impossible for exactly the site that has two certificates.
    """

    def test_the_hostname_is_taken_out_of_the_file_name(self):
        self.assertEqual(CERTD._stem_domain("example.com-ecdsa"), "example.com")
        self.assertEqual(CERTD._stem_domain("example.com-rsa"), "example.com")
        self.assertEqual(CERTD._stem_domain("site.example.com"), "site.example.com")

    def test_a_standby_can_be_stored_for_a_key_suffixed_name(self):
        pem = self.make_pem("example.com", "Another CA")
        CERTD.store_standby_certificate("example.com-ecdsa", "other", pem)
        stored = CERTD.CERTS_AVAILABLE_DIR / "example.com-ecdsa" / "other.pem"
        self.assertTrue(stored.is_file())

    def test_it_is_still_checked_against_the_real_hostname(self):
        pem = self.make_pem("elsewhere.example.com", "Another CA")
        with self.assertRaises(ValueError):
            CERTD.store_standby_certificate("example.com-ecdsa", "other", pem)

    def test_the_two_key_types_are_stored_separately(self):
        # Stored apart, one directory each. Whether they *switch* together is
        # a different question, answered in ADualKeySiteMovesAsOne: they do,
        # because leaving one behind rebuilds the shadowing.
        for stem in ("example.com-ecdsa", "example.com-rsa"):
            self.deploy_active(stem, self.make_pem("example.com", "Original CA"))
            CERTD.store_standby_certificate(
                stem, "other", self.make_pem("example.com", "Another CA")
            )
        for stem in ("example.com-ecdsa", "example.com-rsa"):
            self.assertTrue(
                (CERTD.CERTS_AVAILABLE_DIR / stem / "other.pem").is_file(), stem
            )

    def test_a_name_with_no_sibling_holds_only_itself(self):
        self.deploy_active("site.example.com", self.make_pem("site.example.com", "LE"))
        CERTD.store_standby_certificate(
            "site.example.com", "other", self.make_pem("site.example.com", "Another CA")
        )
        CERTD.activate_standby_certificate("site.example.com", "other")
        self.assertEqual(CERTD.read_pin("site.example.com"), "other")
        self.assertEqual(CERTD.read_pin("example.com-rsa"), "")


class EveryWriterOfTheCertificateDirectoryChecksTheHold(unittest.TestCase):
    """Read the other three writers, because they are not Python.

    The hold is only worth anything if all of them honour it, and three live
    outside this daemon: the certbot deploy hook, the Ansible build handlers
    and the orphan sweep. The sweep is the one that would hurt most -- a held
    certificate looks orphaned precisely when its Let's Encrypt lineage has
    been removed, which is a thing an operator might well do after moving a
    site to another authority, and deleting it would take the site down.
    """

    def read(self, relative):
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_the_renewal_hook_checks_it(self):
        hook = self.read(
            "ansible/roles/cert/templates/905-haproxy-pems-reload.sh.j2"
        )
        self.assertIn(".pinned", hook)
        self.assertIn("is_pinned", hook)

    def test_the_hook_checks_it_where_it_writes(self):
        # Inside build_pem, which is the only thing in that script that
        # writes into the certificate directory.
        hook = self.read(
            "ansible/roles/cert/templates/905-haproxy-pems-reload.sh.j2"
        )
        body = hook.split("build_pem() {")[1].split("\nMANIFEST=")[0]
        self.assertIn("is_pinned", body)

    def test_both_ansible_handlers_check_it(self):
        handlers = self.read("ansible/roles/cert/handlers/main.yml")
        self.assertEqual(handlers.count(".pinned"), 2)

    def test_the_orphan_sweep_spares_held_names(self):
        sweep = self.read("ansible/roles/cert/tasks/remove_orphans.yml")
        self.assertIn("pinned_pems", sweep)
        self.assertIn("difference(pinned_pems", sweep)

    def test_the_daemon_enforces_it_in_one_place(self):
        # Not in each caller. A guarantee spread over five call sites is one
        # the sixth will miss.
        certd = self.read("ansible/roles/haproxy-admin/files/haproxy-certd.py")
        body = certd.split("def _activate_server_pem(")[1].split("\ndef ")[0]
        self.assertIn("read_pin", body)
        self.assertIn("PinnedCertificate", body)

    def test_the_path_is_configured_from_one_variable(self):
        for relative in (
            "ansible/roles/cert/defaults/main.yml",
            "ansible/roles/haproxy/defaults/main.yml",
            "ansible/roles/haproxy-admin/templates/haproxy-certd.service.j2",
        ):
            self.assertIn("certs_available", self.read(relative).lower(), relative)

    def test_nothing_puts_a_marker_where_haproxy_would_read_it(self):
        # Measured on 2.8: a single non-certificate file in the crt directory
        # is a fatal configuration error and the gateway will not start.
        certd = self.read("ansible/roles/haproxy-admin/files/haproxy-certd.py")
        body = certd.split("def _pin_path(")[1].split("\ndef ")[0]
        self.assertIn("_certs_available_root", body)
        self.assertNotIn("_get_haproxy_certs_dir", body)

    def test_reading_the_hold_creates_nothing(self):
        # Every certificate installed now passes the hold check on its way
        # in. If reading the hold created a directory, installing a
        # certificate would depend on being able to create one, and would
        # start failing on hosts that never use a standby at all. Eight
        # existing tests caught this the first time.
        certd = self.read("ansible/roles/haproxy-admin/files/haproxy-certd.py")
        body = certd.split("def _certs_available_root(")[1].split("\ndef ")[0]
        self.assertNotIn("mkdir", body)


class TwoCertificatesForOneNameAreRefused(StandbyFixture):
    """What happened on a live gateway, and must not happen again.

    A wildcard for domain and *.domain was imported into the certificate
    directory alongside the existing per-host certificates. HAProxy said
    nothing, the configuration checked clean, and the result was decided by
    how the file names happened to sort: the apex kept Let's Encrypt purely
    by luck, while every hostname without a certificate of its own quietly
    started presenting the new one instead.

    That is not a spare and not a replacement. It is a coin toss whose loser
    is invisible, which is exactly why the standby directory exists.
    """

    def install(self, stem, pem, **kwargs):
        return CERTD._activate_server_pem(
            CERTD.HAPROXY_CERTS_DIR / f"{stem}.pem", pem.encode(), **kwargs
        )

    def wildcard_pem(self, base, issuer, days=365):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(timezone.utc)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, base)])
        issuer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=days))
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName(base), x509.DNSName(f"*.{base}")]
                ),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        return (
            cert.public_bytes(serialization.Encoding.PEM)
            + key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        ).decode("ascii")

    def test_a_second_certificate_for_a_name_is_refused(self):
        self.install("site.example.com", self.make_pem("site.example.com", "CA One"))
        with self.assertRaises(CERTD.ShadowedCertificate):
            self.install(
                "site.example.com-other", self.make_pem("site.example.com", "CA Two")
            )

    def test_the_refusal_names_the_file_it_would_fight(self):
        self.install("site.example.com", self.make_pem("site.example.com", "CA One"))
        with self.assertRaises(CERTD.ShadowedCertificate) as caught:
            self.install(
                "site.example.com-other", self.make_pem("site.example.com", "CA Two")
            )
        self.assertIn("site.example.com.pem", str(caught.exception))

    def test_the_refusal_points_at_the_standby_directory(self):
        # An error that only says no leaves the operator to do the wrong
        # thing again, more forcefully.
        self.install("site.example.com", self.make_pem("site.example.com", "CA One"))
        with self.assertRaises(CERTD.ShadowedCertificate) as caught:
            self.install(
                "site.example.com-other", self.make_pem("site.example.com", "CA Two")
            )
        self.assertIn("standby", str(caught.exception).lower())

    def test_a_wildcard_over_existing_hosts_is_refused(self):
        # The live case exactly: per-host certificates already deployed, then
        # a wildcard dropped in beside them.
        self.install("example.com", self.make_pem("example.com", "LE"))
        with self.assertRaises(CERTD.ShadowedCertificate):
            self.install("wildcard", self.wildcard_pem("example.com", "Another CA"))

    def test_replacing_the_same_file_is_not_a_conflict(self):
        # A renewal writes the same destination; that is the normal path and
        # must stay open.
        self.install("site.example.com", self.make_pem("site.example.com", "CA One"))
        ok, _rc, _out, _err = self.install(
            "site.example.com", self.make_pem("site.example.com", "CA One renewed")
        )
        self.assertTrue(ok)

    def test_the_dual_key_pattern_is_not_a_conflict(self):
        # <domain>-ecdsa and <domain>-rsa claim the same name on purpose:
        # the client picks by what it supports. Refusing that would break
        # every dual-key site on the gateway.
        rsa_pem = self.make_pem("example.com", "LE")
        self.install("example.com-rsa", rsa_pem)

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=90))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("example.com")]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        ecdsa_pem = (
            cert.public_bytes(serialization.Encoding.PEM)
            + key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        ).decode("ascii")

        ok, _rc, _out, _err = self.install("example.com-ecdsa", ecdsa_pem)
        self.assertTrue(ok)

    def test_an_unrelated_name_is_not_a_conflict(self):
        self.install("site.example.com", self.make_pem("site.example.com", "CA One"))
        ok, _rc, _out, _err = self.install(
            "other.example.com", self.make_pem("other.example.com", "CA Two")
        )
        self.assertTrue(ok)

    def test_putting_a_standby_in_is_still_allowed(self):
        # The whole point of a standby is to take a name another file holds.
        # It goes through the same installer and must not be refused by this.
        self.deploy_active("site.example.com", self.make_pem("site.example.com", "LE"))
        CERTD.store_standby_certificate(
            "site.example.com", "other", self.make_pem("site.example.com", "Another CA")
        )
        result = CERTD.activate_standby_certificate("site.example.com", "other")
        self.assertTrue(result["ok"])

    def test_nothing_is_written_when_it_is_refused(self):
        self.install("site.example.com", self.make_pem("site.example.com", "CA One"))
        with self.assertRaises(CERTD.ShadowedCertificate):
            self.install(
                "site.example.com-other", self.make_pem("site.example.com", "CA Two")
            )
        self.assertFalse(
            (CERTD.HAPROXY_CERTS_DIR / "site.example.com-other.pem").exists()
        )


class OneWildcardCoversEveryNameItCovers(StandbyFixture):
    """Filing a wildcard by hand, once per hostname, is a chore done nine
    times out of twelve.

    The gateway that prompted this has twelve deployed certificates and a
    wildcard that covers all of them. Which names it lands on is decided by
    the certificate, checked against what is actually deployed, so it cannot
    be filed against a name it could not serve.
    """

    def wildcard(self, base="example.com", issuer="Another CA"):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(timezone.utc)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, base)])
        issuer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName(base), x509.DNSName(f"*.{base}")]
                ),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        return (
            cert.public_bytes(serialization.Encoding.PEM)
            + key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        ).decode("ascii")

    def gateway(self):
        """The shape of the real one: subdomains plus a dual-key apex."""

        for stem, name in (
            ("a.example.com", "a.example.com"),
            ("rdg.example.com", "rdg.example.com"),
            ("example.com-ecdsa", "example.com"),
            ("example.com-rsa", "example.com"),
            ("other.test", "other.test"),
        ):
            self.deploy_active(stem, self.make_pem(name, "LE"))

    def test_it_lands_on_every_name_it_covers(self):
        self.gateway()
        result = CERTD.store_standby_for_covered_names("other-ca", self.wildcard())
        self.assertEqual(
            sorted(result["domains"]),
            ["a.example.com", "example.com-ecdsa", "example.com-rsa",
             "rdg.example.com"],
        )

    def test_it_leaves_alone_a_name_it_does_not_cover(self):
        self.gateway()
        result = CERTD.store_standby_for_covered_names("other-ca", self.wildcard())
        self.assertIn("other.test", result["not_covered"])
        self.assertFalse(
            (CERTD.CERTS_AVAILABLE_DIR / "other.test" / "other-ca.pem").exists()
        )

    def test_the_apex_is_matched_through_its_key_suffixed_file_names(self):
        # The file stem is example.com-ecdsa, which no certificate covers
        # literally; the hostname inside it is what is checked.
        self.gateway()
        CERTD.store_standby_for_covered_names("other-ca", self.wildcard())
        for stem in ("example.com-ecdsa", "example.com-rsa"):
            self.assertTrue(
                (CERTD.CERTS_AVAILABLE_DIR / stem / "other-ca.pem").is_file(), stem
            )

    def test_each_one_can_be_put_into_service_on_its_own(self):
        self.gateway()
        CERTD.store_standby_for_covered_names("other-ca", self.wildcard())
        result = CERTD.activate_standby_certificate("rdg.example.com", "other-ca")
        self.assertTrue(result["ok"])
        self.assertEqual(CERTD.read_pin("rdg.example.com"), "other-ca")
        self.assertEqual(CERTD.read_pin("a.example.com"), "")

    def test_a_certificate_covering_nothing_deployed_is_refused(self):
        self.gateway()
        with self.assertRaises(ValueError):
            CERTD.store_standby_for_covered_names(
                "other-ca", self.wildcard("nowhere.invalid")
            )

    def test_nothing_at_all_is_refused(self):
        self.gateway()
        with self.assertRaises(ValueError):
            CERTD.store_standby_for_covered_names("other-ca", "")


class ADualKeySiteMovesAsOne(StandbyFixture):
    """Two files, one name. Moving one and not the other rebuilds the trap.

    <domain>-ecdsa.pem and <domain>-rsa.pem both claim the same hostname. Put
    a standby into only one of them and the other goes on claiming that name
    with the old certificate -- which is the shadowing this whole feature
    exists to prevent, recreated by the act of preventing it, and decided as
    always by whichever file name sorts first.
    """

    def setup_pair(self):
        for stem in ("example.com-ecdsa", "example.com-rsa"):
            self.deploy_active(stem, self.make_pem("example.com", "LE"))
            CERTD.store_standby_certificate(
                stem, "other-ca", self.make_pem("example.com", "Another CA")
            )

    def test_the_sibling_comes_along(self):
        self.setup_pair()
        result = CERTD.activate_standby_certificate("example.com-ecdsa", "other-ca")
        self.assertTrue(result["ok"])
        self.assertEqual(result["also_switched"], ["example.com-rsa"])
        self.assertEqual(CERTD.read_pin("example.com-rsa"), "other-ca")

    def test_both_files_are_actually_replaced(self):
        self.setup_pair()
        CERTD.activate_standby_certificate("example.com-ecdsa", "other-ca")
        for stem in ("example.com-ecdsa", "example.com-rsa"):
            deployed = (CERTD.HAPROXY_CERTS_DIR / f"{stem}.pem").read_bytes()
            self.assertEqual(CERTD._describe_pem(deployed)["issuer"], "Another CA")

    def test_the_sibling_is_left_alone_when_it_holds_no_such_standby(self):
        # Only what the operator actually filed moves.
        self.deploy_active("example.com-ecdsa", self.make_pem("example.com", "LE"))
        self.deploy_active("example.com-rsa", self.make_pem("example.com", "LE"))
        CERTD.store_standby_certificate(
            "example.com-ecdsa", "other-ca", self.make_pem("example.com", "Another CA")
        )
        result = CERTD.activate_standby_certificate("example.com-ecdsa", "other-ca")
        self.assertEqual(result["also_switched"], [])
        self.assertEqual(CERTD.read_pin("example.com-rsa"), "")

    def test_both_come_back_together(self):
        self.setup_pair()
        CERTD.activate_standby_certificate("example.com-ecdsa", "other-ca")
        result = CERTD.release_to_letsencrypt("example.com-ecdsa")
        self.assertTrue(result["ok"])
        self.assertEqual(result["also_released"], ["example.com-rsa"])
        self.assertEqual(CERTD.read_pin("example.com-ecdsa"), "")
        self.assertEqual(CERTD.read_pin("example.com-rsa"), "")

    def test_an_ordinary_name_has_no_sibling(self):
        self.assertEqual(CERTD._sibling_stem("site.example.com"), "")
        self.assertEqual(CERTD._sibling_stem("example.com-ecdsa"), "example.com-rsa")
        self.assertEqual(CERTD._sibling_stem("example.com-rsa"), "example.com-ecdsa")


class AWildcardCoversExactlyOneLabel(unittest.TestCase):
    """The matcher was wrong in both directions at once.

    `host.count(".") > suffix.count(".")` refused a.domain.local -- the only
    thing a *.domain.local certificate exists to cover -- and accepted
    a.b.domain.local, which it does not cover. Since endswith already rules
    out the bare domain, the comparison had nothing left to do but be wrong.

    It blocked the feature that found it: filing a wildcard against the names
    it covers matched none of the subdomains. It also means uploading a
    wildcard for a subdomain was refused as not covering that subdomain.
    """

    def check(self, host, pattern):
        return CERTD._hostname_matches_pattern(host, pattern)

    def test_one_label_matches(self):
        self.assertTrue(self.check("a.example.com", "*.example.com"))

    def test_two_labels_do_not(self):
        self.assertFalse(self.check("a.b.example.com", "*.example.com"))

    def test_the_bare_domain_does_not(self):
        self.assertFalse(self.check("example.com", "*.example.com"))

    def test_an_exact_name_still_matches_itself(self):
        self.assertTrue(self.check("example.com", "example.com"))

    def test_a_subdomain_does_not_match_the_bare_domain(self):
        self.assertFalse(self.check("a.example.com", "example.com"))

    def test_it_is_case_insensitive(self):
        self.assertTrue(self.check("A.Example.COM", "*.example.com"))


class TakingADeployedCertificateOutOfService(StandbyFixture):
    """The obvious thing to want after putting one in the wrong place.

    A certificate imported into the live directory is already on the gateway
    with its key. Telling the operator to go and find the original files and
    upload them a second time is a poor answer, so it can be moved where it
    belongs in one step.

    Only when nothing depends on it. Every ordinary name it answers for has
    to still be answered by another deployed file once it is gone, or taking
    it away would take that name down with it.
    """

    def wildcard(self, base="example.com", issuer="Another CA"):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(timezone.utc)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, base)])
        issuer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName(base), x509.DNSName(f"*.{base}")]
                ),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        return (
            cert.public_bytes(serialization.Encoding.PEM)
            + key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        ).decode("ascii")

    def gateway(self):
        """The live one: per-host certificates, a dual-key apex, and the
        wildcard that was imported into the middle of them."""

        for stem, name in (
            ("a.example.com", "a.example.com"),
            ("rdg.example.com", "rdg.example.com"),
            ("example.com-ecdsa", "example.com"),
            ("example.com-rsa", "example.com"),
        ):
            self.deploy_active(stem, self.make_pem(name, "LE"))
        self.deploy_active("example.com", self.wildcard())

    def test_it_leaves_the_live_directory(self):
        self.gateway()
        CERTD.adopt_deployed_as_standby("example.com", "imported")
        self.assertFalse((CERTD.HAPROXY_CERTS_DIR / "example.com.pem").exists())

    def test_it_becomes_the_standby_for_every_name_it_covers(self):
        self.gateway()
        result = CERTD.adopt_deployed_as_standby("example.com", "imported")
        self.assertEqual(
            sorted(result["domains"]),
            ["a.example.com", "example.com-ecdsa", "example.com-rsa",
             "rdg.example.com"],
        )
        for stem in result["domains"]:
            self.assertTrue(
                (CERTD.CERTS_AVAILABLE_DIR / stem / "imported.pem").is_file(), stem
            )

    def test_haproxy_is_reloaded_so_it_stops_serving_it(self):
        # Removing the file changes nothing until HAProxy re-reads.
        self.gateway()
        before = len(self.reloads)
        CERTD.adopt_deployed_as_standby("example.com", "imported")
        self.assertGreater(len(self.reloads), before)

    def test_the_names_it_was_serving_are_still_served(self):
        self.gateway()
        CERTD.adopt_deployed_as_standby("example.com", "imported")
        for stem in ("a.example.com", "rdg.example.com",
                     "example.com-ecdsa", "example.com-rsa"):
            self.assertTrue((CERTD.HAPROXY_CERTS_DIR / f"{stem}.pem").is_file(), stem)

    def test_it_does_not_file_itself_under_a_name_it_is_leaving(self):
        # Its own stem is about to stop existing; a standby filed there
        # would stand by for nothing.
        self.gateway()
        CERTD.adopt_deployed_as_standby("example.com", "imported")
        self.assertFalse(
            (CERTD.CERTS_AVAILABLE_DIR / "example.com" / "imported.pem").exists()
        )

    # -- when it must refuse ----------------------------------------------

    def test_the_only_certificate_for_a_name_is_not_taken_away(self):
        # This is the whole safety of it. Removing it would take the site
        # down, which is a strange way to arrange a backup.
        self.deploy_active("alone.example.com",
                           self.make_pem("alone.example.com", "Some CA"))
        with self.assertRaises(ValueError):
            CERTD.adopt_deployed_as_standby("alone.example.com", "imported")

    def test_the_refusal_names_what_would_be_left_bare(self):
        self.deploy_active("alone.example.com",
                           self.make_pem("alone.example.com", "Some CA"))
        with self.assertRaises(ValueError) as caught:
            CERTD.adopt_deployed_as_standby("alone.example.com", "imported")
        self.assertIn("alone.example.com", str(caught.exception))

    def test_nothing_is_removed_when_it_refuses(self):
        self.deploy_active("alone.example.com",
                           self.make_pem("alone.example.com", "Some CA"))
        with self.assertRaises(ValueError):
            CERTD.adopt_deployed_as_standby("alone.example.com", "imported")
        self.assertTrue((CERTD.HAPROXY_CERTS_DIR / "alone.example.com.pem").is_file())

    def test_a_certificate_without_its_key_is_refused(self):
        # It would be half a standby, discovered at the worst moment.
        self.gateway()
        pem = self.wildcard()
        only_cert = pem.split("-----BEGIN RSA PRIVATE KEY-----")[0]
        (CERTD.HAPROXY_CERTS_DIR / "keyless.example.com.pem").write_text(
            only_cert, encoding="ascii"
        )
        with self.assertRaises(ValueError):
            CERTD.adopt_deployed_as_standby("keyless.example.com", "imported")

    def test_a_name_that_is_not_deployed_is_refused(self):
        self.gateway()
        with self.assertRaises(ValueError):
            CERTD.adopt_deployed_as_standby("nothing.example.com", "imported")

    def test_the_listing_says_which_ones_could_be_put_away(self):
        # The page offers the action only where it would work; a certificate
        # that is the only thing serving its name must not sprout a button
        # that always refuses.
        self.gateway()
        listing = CERTD.list_standby_certificates()
        flags = {d["domain"]: d["can_be_put_away"] for d in listing["domains"]}
        self.assertTrue(flags["example.com"], "the wildcard duplicates the rest")
        self.assertFalse(flags["a.example.com"], "nothing else serves that name")

    def test_a_lone_certificate_is_not_offered(self):
        self.deploy_active("alone.example.com",
                           self.make_pem("alone.example.com", "Some CA"))
        listing = CERTD.list_standby_certificates()
        flags = {d["domain"]: d["can_be_put_away"] for d in listing["domains"]}
        self.assertFalse(flags["alone.example.com"])

    def test_a_wildcard_entry_does_not_block_it(self):
        # *.example.com answers for hostnames that have no file of their own,
        # and those had no certificate before this one arrived either.
        self.gateway()
        result = CERTD.adopt_deployed_as_standby("example.com", "imported")
        self.assertTrue(result["ok"])


class MaterialArrivesInWhateverShapeTheAuthorityChose(StandbyFixture):
    """A certificate authority does not ask how you would like it.

    The form used to demand exactly two files. The commonest shape is one
    file with the key and the whole chain in it, so that one file went into
    both fields, arrived as two copies, and was refused with "PEM must
    contain exactly one unencrypted private key" -- being told that a file
    with one key in it has two keys, which is not a useful thing to be told.
    """

    def parts(self, name="site.example.com"):
        pem = self.make_pem(name, "Another CA")
        head, _, tail = pem.partition("-----BEGIN RSA PRIVATE KEY-----")
        return head, "-----BEGIN RSA PRIVATE KEY-----" + tail

    def test_one_file_with_the_key_first(self):
        # Exactly the shape the operator had.
        cert, key = self.parts()
        combined = key + "\n" + cert
        CERTD.store_standby_certificate("site.example.com", "other", combined)
        stored = CERTD.CERTS_AVAILABLE_DIR / "site.example.com" / "other.pem"
        self.assertTrue(stored.is_file())

    def test_one_file_with_the_certificate_first(self):
        cert, key = self.parts()
        CERTD.store_standby_certificate("site.example.com", "other", cert + key)
        self.assertTrue(
            (CERTD.CERTS_AVAILABLE_DIR / "site.example.com" / "other.pem").is_file()
        )

    def test_the_same_file_given_twice_is_not_two_keys(self):
        # What two required fields and one combined file produce.
        cert, key = self.parts()
        combined = key + "\n" + cert
        CERTD.store_standby_certificate(
            "site.example.com", "other", combined + "\n" + combined
        )
        self.assertTrue(
            (CERTD.CERTS_AVAILABLE_DIR / "site.example.com" / "other.pem").is_file()
        )

    def test_two_genuinely_different_keys_are_still_refused(self):
        # Dropping duplicates must not become dropping mistakes.
        _cert_a, key_a = self.parts()
        cert_b, key_b = self.parts()
        with self.assertRaises(ValueError) as caught:
            CERTD.normalise_uploaded_pem((cert_b + key_a + key_b).encode())
        self.assertIn("private keys", str(caught.exception))

    def test_a_certificate_with_no_key_says_which_half_is_missing(self):
        cert, _key = self.parts()
        with self.assertRaises(ValueError) as caught:
            CERTD.normalise_uploaded_pem(cert.encode())
        self.assertIn("private key", str(caught.exception))

    def test_a_key_with_no_certificate_says_so_too(self):
        _cert, key = self.parts()
        with self.assertRaises(ValueError) as caught:
            CERTD.normalise_uploaded_pem(key.encode())
        self.assertIn("certificate", str(caught.exception))

    def test_the_whole_chain_is_kept(self):
        # Three certificates came in the operator's file; dropping the
        # intermediates would break the chain for every client that needs it.
        cert, key = self.parts()
        second, _ = self.parts("other.example.com")
        third, _ = self.parts("third.example.com")
        result = CERTD.normalise_uploaded_pem((key + cert + second + third).encode())
        self.assertEqual(result.count(b"BEGIN CERTIFICATE"), 3)
        # BEGIN only: the marker appears in the END line as well.
        self.assertEqual(result.count(b"-----BEGIN RSA PRIVATE KEY-----"), 1)

    def test_the_leaf_stays_first(self):
        # HAProxy takes the first certificate as the one it is serving.
        cert, key = self.parts()
        intermediate, _ = self.parts("issuer.example.com")
        result = CERTD.normalise_uploaded_pem((key + cert + intermediate).encode())
        first = CERTD._load_pem_certificates(result)[0]
        self.assertEqual(CERTD._certificate_label(first), "site.example.com")

    def test_two_separate_files_still_work(self):
        cert, key = self.parts()
        result = CERTD.normalise_uploaded_pem(cert.encode(), key.encode())
        self.assertIn(b"BEGIN CERTIFICATE", result)
        self.assertIn(b"PRIVATE KEY", result)

    def test_the_pieces_may_arrive_in_either_order(self):
        cert, key = self.parts()
        result = CERTD.normalise_uploaded_pem(key.encode(), cert.encode())
        self.assertIn(b"BEGIN CERTIFICATE", result)

    def test_an_empty_second_file_is_ignored(self):
        cert, key = self.parts()
        result = CERTD.normalise_uploaded_pem((cert + key).encode(), b"")
        self.assertIn(b"BEGIN CERTIFICATE", result)


if __name__ == "__main__":
    unittest.main()
