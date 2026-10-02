"""Regression tests for the authelia-usersd atomic write.

Guards against the race that made web user edits silently ignored by Authelia:
the users file was briefly root-owned/unreadable between os.replace() and the
post-rename chown/chmod, so Authelia's `watch: true` reload hit "permission
denied" and kept serving the stale in-memory database.
"""

from __future__ import annotations

import importlib.util
import os
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DAEMON = ROOT / "ansible/roles/authelia/files/authelia-usersd.py"
SOURCE = DAEMON.read_text(encoding="utf-8")


class UsersdSourceContractTests(unittest.TestCase):
    def test_ownership_and_mode_are_set_before_the_rename(self) -> None:
        save = SOURCE.split("def _save_users_data", 1)[1].split("\ndef ", 1)[0]
        chown_at = save.find("os.chown(tmp_path")
        chmod_at = save.find("os.chmod(tmp_path")
        replace_at = save.find("os.replace(tmp_path")
        self.assertGreater(chown_at, 0, "temp file must be chowned")
        self.assertGreater(chmod_at, 0, "temp file must be chmodded")
        self.assertGreater(replace_at, 0)
        self.assertLess(chown_at, replace_at, "chown must precede os.replace")
        self.assertLess(chmod_at, replace_at, "chmod must precede os.replace")

    def test_no_post_rename_chown_on_the_live_file(self) -> None:
        save = SOURCE.split("def _save_users_data", 1)[1].split("\ndef ", 1)[0]
        # The live path must never be adjusted after the rename; doing so is what
        # reintroduced the readable-window race.
        self.assertNotIn("os.chown(USERS_FILE", save)
        self.assertNotIn("os.chmod(USERS_FILE", save)

    def test_debug_logging_never_contains_the_full_request(self) -> None:
        self.assertNotIn('LOG.debug("Request: %s", line)', SOURCE)


class UsersdWriteBehaviorTests(unittest.TestCase):
    def setUp(self) -> None:
        try:
            import yaml  # noqa: F401
            from argon2 import PasswordHasher  # noqa: F401
        except Exception as exc:  # noqa: BLE001
            self.skipTest(f"daemon dependencies unavailable: {exc}")

    def _load_module(self, users_file: Path):
        os.environ["AUTHELIA_USERS_FILE"] = str(users_file)
        os.environ["AUTHELIA_USERS_SOCKET"] = str(users_file) + ".sock"
        spec = importlib.util.spec_from_file_location("eha_usersd", DAEMON)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        return module

    def test_live_path_is_readable_at_the_moment_of_replace(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            users_file = Path(tmp) / "users_database.yml"
            users_file.write_text("users:\n  admin:\n    email: a@b.test\n")
            module = self._load_module(users_file)

            observed: dict = {}
            real_replace = os.replace

            def spying_replace(src, dst, *args, **kwargs):
                # Capture the mode of the temp file right before it becomes the
                # live file; group/other must never be able to see a 000 mode.
                observed["mode"] = os.stat(src).st_mode & 0o777
                return real_replace(src, dst, *args, **kwargs)

            module.os.replace = spying_replace
            try:
                module._save_users_data({"users": {"admin": {"email": "a@b.test"}}})
            finally:
                module.os.replace = real_replace

            self.assertIn("mode", observed)
            # Owner-readable and not a root-only 0600/0660-for-root exposure:
            # the final mode is 0640 so the owning Authelia account can read it.
            self.assertEqual(observed["mode"], 0o640)
            self.assertEqual(users_file.stat().st_mode & 0o777, 0o640)

    def test_password_whitespace_is_preserved(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            users_file = Path(tmp) / "users_database.yml"
            users_file.write_text(
                "users:\n"
                "  admin:\n"
                "    displayname: Admin\n"
                "    email: admin@example.test\n"
                "    groups: [superadmin]\n"
                "    password: old\n",
                encoding="utf-8",
            )
            module = self._load_module(users_file)
            observed: list[str] = []
            module._hash_password = lambda value: observed.append(value) or "new-hash"

            result = module.handle_request(
                {
                    "action": "update",
                    "username": "admin",
                    "fields": {},
                    "password_plain": "  keep these spaces  ",
                }
            )

            self.assertTrue(result["ok"])
            self.assertEqual(observed, ["  keep these spaces  "])

    def test_last_enabled_superadmin_cannot_be_removed(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            users_file = Path(tmp) / "users_database.yml"
            users_file.write_text(
                "users:\n"
                "  admin:\n"
                "    displayname: Admin\n"
                "    email: admin@example.test\n"
                "    groups: [superadmin]\n"
                "    password: hash\n",
                encoding="utf-8",
            )
            module = self._load_module(users_file)

            deleted = module.handle_request(
                {"action": "delete", "username": "admin"}
            )
            demoted = module.handle_request(
                {
                    "action": "update",
                    "username": "admin",
                    "fields": {"groups": ["admins"]},
                }
            )

            self.assertFalse(deleted["ok"])
            self.assertIn("last enabled superadmin", deleted["error"])
            self.assertFalse(demoted["ok"])
            self.assertIn("last enabled superadmin", demoted["error"])

    def test_user_email_is_validated_by_the_privileged_daemon(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            users_file = Path(tmp) / "users_database.yml"
            users_file.write_text("users: {}\n", encoding="utf-8")
            module = self._load_module(users_file)

            result = module.handle_request(
                {
                    "action": "create",
                    "username": "audit-user",
                    "fields": {
                        "displayname": "Audit User",
                        "email": "not-an-email",
                        "groups": [],
                    },
                    "password_plain": "a-valid-test-password",
                }
            )
            self.assertFalse(result["ok"])
            self.assertEqual(result["error"], "email is invalid")


if __name__ == "__main__":
    unittest.main()
