"""The helper and the bootstrap follow the branch the gateway was set up on.

An alpha gateway records ``branch: alpha`` in metadata.yml. The helper used to
compare such a host with main, and install-local.sh (run by "configure" and
"repair") fetched main into its source checkout.
"""

from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ("easy-ha-proxy-helper.sh", "install-local.sh")


def gateway_branch_function(name):
    source = (ROOT / name).read_text(encoding="utf-8")
    match = re.search(r"^gateway_branch\(\) \{\n.*?^\}\n", source, re.M | re.S)
    if match is None:
        raise AssertionError(f"{name} has no gateway_branch function")
    return match.group(0)


@unittest.skipIf(shutil.which("bash") is None, "bash is required")
class GatewayBranch(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.config = Path(temporary.name)

    def resolve(self, name, metadata=None, override=None):
        if metadata is not None:
            (self.config / "metadata.yml").write_text(metadata, encoding="utf-8")
        env = {k: v for k, v in os.environ.items() if k != "EASY_HA_PROXY_BRANCH"}
        if override is not None:
            env["EASY_HA_PROXY_BRANCH"] = override
        script = "set -Eeuo pipefail\n" + gateway_branch_function(name) + "gateway_branch\n"
        result = subprocess.run(
            ["bash", "-c", script],
            env={**env, "config_dir": str(self.config)},
            text=True, capture_output=True, check=True,
        )
        return result.stdout.strip()

    def test_both_scripts_resolve_the_branch_the_same_way(self):
        self.assertEqual(gateway_branch_function(SCRIPTS[0]), gateway_branch_function(SCRIPTS[1]))

    def test_recorded_branch_wins_over_the_main_default(self):
        cases = [
            (None, "main"),
            ("product: easy-ha-proxy\n", "main"),
            ("product: easy-ha-proxy\nbranch: alpha\nimage_channel: alpha\n", "alpha"),
            ("branch: 'alpha'\n", "alpha"),
            ('branch: "release/2.0"\n', "release/2.0"),
            ("nested:\n  branch: alpha\n", "main"),
            ("branch: --upload-pack=touch\n", "main"),
            ("branch: a..b\n", "main"),
            ("branch: alpha.lock\n", "main"),
            ("branch:\n", "main"),
        ]
        for name in SCRIPTS:
            for metadata, expected in cases:
                with self.subTest(script=name, metadata=metadata):
                    self.assertEqual(self.resolve(name, metadata), expected)

    def test_an_explicit_branch_still_overrides_the_recorded_one(self):
        for name in SCRIPTS:
            with self.subTest(script=name):
                self.assertEqual(self.resolve(name, "branch: alpha\n", override="feature"), "feature")

    def test_both_scripts_use_the_resolved_branch(self):
        helper = (ROOT / "easy-ha-proxy-helper.sh").read_text(encoding="utf-8")
        bootstrap = (ROOT / "install-local.sh").read_text(encoding="utf-8")
        self.assertNotIn('branch="${EASY_HA_PROXY_BRANCH:-main}"', helper)
        self.assertNotIn('branch="${EASY_HA_PROXY_BRANCH:-main}"', bootstrap)
        # The helper resolves it as root, after the sudo re-run.
        self.assertLess(helper.index('exec sudo env "${sudo_environment[@]}"'),
                        helper.index('branch="$(gateway_branch)"'))
        self.assertLess(bootstrap.index('branch="$(gateway_branch)"'),
                        bootstrap.index('fetch --depth=1 origin "${branch}"'))


@unittest.skipIf(shutil.which("bash") is None, "bash is required")
@unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "the sudo re-run happens only for non-root users")
class HelperSudoRerun(unittest.TestCase):
    """A non-root user may not read metadata.yml: the re-run must let root resolve it."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        self.record = self.root / "sudo-args"
        fake_sudo = bin_dir / "sudo"
        fake_sudo.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$SUDO_RECORD"\n', encoding="utf-8")
        fake_sudo.chmod(0o755)
        self.path = f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}"

    def rerun_arguments(self, **extra):
        env = {k: v for k, v in os.environ.items()
               if not k.startswith("EASY_HA_PROXY_")}
        env.update(PATH=self.path, SUDO_RECORD=str(self.record),
                   EASY_HA_PROXY_CONFIG_DIR=str(self.root / "config"), **extra)
        subprocess.run(["bash", str(ROOT / "easy-ha-proxy-helper.sh"), "--action", "status"],
                       env=env, text=True, capture_output=True, check=True, timeout=60)
        return self.record.read_text(encoding="utf-8").splitlines()

    def test_no_branch_is_forced_when_none_was_given(self):
        arguments = self.rerun_arguments()
        self.assertEqual(arguments[0], "env")
        self.assertFalse([a for a in arguments if a.startswith("EASY_HA_PROXY_BRANCH=")], arguments)
        self.assertFalse([a for a in arguments if a.startswith("EASY_HA_PROXY_RAW_BASE=")], arguments)
        self.assertEqual(arguments[-2:], ["--action", "status"])

    def test_a_given_branch_reaches_root(self):
        arguments = self.rerun_arguments(EASY_HA_PROXY_BRANCH="feature")
        self.assertIn("EASY_HA_PROXY_BRANCH=feature", arguments)


if __name__ == "__main__":
    unittest.main()
