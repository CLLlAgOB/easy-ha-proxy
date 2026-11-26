"""installer/agent-fetch.sh: how a host without an agent gets its first one.

Run with bash and a stand-in curl and uname on PATH; the "release" is a
directory the stand-in curl serves from.
"""
from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FETCH = ROOT / "installer/agent-fetch.sh"
REVISION = "0123456789abcdef0123456789abcdef01234567"
AGENT = b"#!/bin/sh\necho agent\n"

FAKE_CURL = """#!/bin/sh
# Records its arguments; serves -o FILE URL from $RELEASE by the URL's name.
echo "$@" >> "$CALLS"
out="" url=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -*) case "$1" in --retry|--connect-timeout) shift ;; esac; shift ;;
    *) url="$1"; shift ;;
  esac
done
file="$RELEASE/${url##*/}"
[ -f "$file" ] || exit 22
cp "$file" "$out"
"""


@unittest.skipUnless(os.name == "posix" and all(shutil.which(t) for t in ("bash", "tar", "sha256sum")),
                     "needs bash, tar and sha256sum")
class AgentFetchTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="ehp-agent-fetch-"))
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        (self.bin / "curl").write_text(FAKE_CURL)
        (self.bin / "uname").write_text("#!/bin/sh\necho x86_64\n")
        for tool in ("curl", "uname"):
            (self.bin / tool).chmod(0o755)
        self.release = self.root / "release"
        self.release.mkdir()
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / ".easy-ha-proxy-source-revision").write_text(f"revision={REVISION}\n")
        self.config = self.root / "etc"
        self.config.mkdir()
        self.calls = self.root / "calls"
        self.destination = self.root / "staging/bootstrap/easy-ha-proxy-agent"

    def publish(self, binary: bytes = AGENT, checksum: str | None = None):
        name = f"easy-ha-proxy-agent-{REVISION}-linux-amd64"
        (self.release / name).write_bytes(binary)
        digest = checksum or hashlib.sha256(binary).hexdigest()
        (self.release / f"{name}.sha256").write_text(f"{digest}  {name}\n")

    def fetch(self) -> subprocess.CompletedProcess:
        env = {
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "RELEASE": str(self.release),
            "CALLS": str(self.calls),
            "EASY_HA_PROXY_CONFIG_DIR": str(self.config),
        }
        script = f'source "{FETCH}"; easy_ha_proxy_fetch_agent "$1" "$2"'
        return subprocess.run(["bash", "-c", script, "fetch", str(self.source), str(self.destination)],
                              env=env, capture_output=True, text=True, timeout=30, check=False)

    def curl_calls(self) -> list[str]:
        return self.calls.read_text().splitlines() if self.calls.exists() else []

    def test_the_agent_of_the_source_revision_is_downloaded_and_checked(self):
        self.publish()
        result = self.fetch()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.destination.read_bytes(), AGENT)
        self.assertEqual(self.destination.stat().st_mode & 0o777, 0o755)
        self.assertFalse(Path(f"{self.destination}.partial").exists())
        urls = [call.split()[-1] for call in self.curl_calls()]
        base = "https://github.com/CLLlAgOB/easy-ha-proxy/releases/download/agent-builds"
        self.assertEqual(urls, [f"{base}/easy-ha-proxy-agent-{REVISION}-linux-amd64",
                                f"{base}/easy-ha-proxy-agent-{REVISION}-linux-amd64.sha256"])
        self.assertIn(REVISION[:12], result.stderr)

    def test_a_binary_that_does_not_match_its_checksum_is_not_installed(self):
        for checksum in ("0" * 64, "not-a-checksum"):
            with self.subTest(checksum=checksum):
                self.publish(checksum=checksum)
                result = self.fetch()
                self.assertEqual(result.returncode, 1)
                self.assertIn("does not match its published SHA-256", result.stderr)
                self.assertFalse(self.destination.exists())

    def test_a_build_not_yet_published_says_so(self):
        result = self.fetch()
        self.assertEqual(result.returncode, 1)
        self.assertIn("could not be downloaded", result.stderr)
        self.assertIn("CI publishes it", result.stderr)
        self.assertFalse(self.destination.exists())

    def test_a_source_of_unknown_revision_is_refused(self):
        (self.source / ".easy-ha-proxy-source-revision").write_text("revision=main\n")
        result = self.fetch()
        self.assertEqual(result.returncode, 1)
        self.assertIn("cannot tell which revision", result.stderr)
        self.assertEqual(self.curl_calls(), [])

    def test_a_host_with_a_local_bundle_takes_the_agent_from_it(self):
        bundles = self.root / "bundles"
        bundles.mkdir()
        payload = io.BytesIO()
        with tarfile.open(fileobj=payload, mode="w:gz") as archive:
            for name, data in (("./sbin/easy-ha-proxy-agent", AGENT), ("./sbin/guardd-core", b"guardd\n")):
                member = tarfile.TarInfo(name)
                member.size, member.mode = len(data), 0o755
                archive.addfile(member, io.BytesIO(data))
        (bundles / "easy-ha-proxy-native-linux-amd64.tar.gz").write_bytes(payload.getvalue())
        (self.config / "vars.yml").write_text(f'haproxy_admin_image: x\nnative_local_bundle_dir: "{bundles}"  # offline\n')
        # Neither the revision nor the network is needed.
        (self.source / ".easy-ha-proxy-source-revision").unlink()
        result = self.fetch()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.destination.read_bytes(), AGENT)
        self.assertEqual(self.curl_calls(), [])

    def test_a_local_bundle_without_the_agent_is_refused(self):
        bundles = self.root / "bundles"
        bundles.mkdir()
        payload = io.BytesIO()
        with tarfile.open(fileobj=payload, mode="w:gz") as archive:
            member = tarfile.TarInfo("sbin/guardd-core")
            member.size = 1
            archive.addfile(member, io.BytesIO(b"x"))
        (bundles / "easy-ha-proxy-native-linux-amd64.tar.gz").write_bytes(payload.getvalue())
        (self.config / "vars.yml").write_text(f"native_local_bundle_dir: {bundles}\n")
        result = self.fetch()
        self.assertEqual(result.returncode, 1)
        self.assertIn("holds no sbin/easy-ha-proxy-agent", result.stderr)
        self.assertFalse(self.destination.exists())


if __name__ == "__main__":
    unittest.main()
