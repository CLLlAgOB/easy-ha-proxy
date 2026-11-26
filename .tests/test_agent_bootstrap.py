"""The agent fetched from the registry is the one built for this revision."""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "installer"))
import agent_bootstrap

REVISION = "0123456789abcdef0123456789abcdef01234567"


def layer(files: dict[str, bytes]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz") as archive:
        for name, body in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(body)
            archive.addfile(info, io.BytesIO(body))
    return raw.getvalue()


def digest(body: bytes) -> str:
    return "sha256:" + hashlib.sha256(body).hexdigest()


class FakeRegistry:
    def __init__(self, agent: bytes, sums: bytes, revision: str = REVISION) -> None:
        blob = layer({"sbin/easy-ha-proxy-agent": agent, "SHA256SUMS": sums})
        config = json.dumps({"config": {"Labels": {"org.opencontainers.image.revision": revision}}}).encode()
        image = json.dumps({"config": {"digest": digest(config)}, "layers": [{"digest": digest(blob)}]}).encode()
        index = json.dumps({"manifests": [{"digest": digest(image), "platform": {"os": "linux", "architecture": "arm64"}}]}).encode()
        self.bodies = {"manifests/native-alpha-0123456789ab": index, f"manifests/{digest(image)}": image,
                       f"blobs/{digest(config)}": config, f"blobs/{digest(blob)}": blob}

    def urlopen(self, request, timeout=None):
        url = request.full_url
        if url.startswith(agent_bootstrap.AUTH.split("?")[0]):
            body = b'{"token": "t"}'
        else:
            body = self.bodies[url.split("/clllagob/haproxy-admin-ui/", 1)[1]]
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.read.side_effect = lambda *a: body
        response.headers.get.return_value = ""
        return response


class Bootstrap(unittest.TestCase):
    def test_the_reference_is_the_pinned_native_image_of_the_channel(self) -> None:
        self.assertEqual(agent_bootstrap.image_reference({"haproxy_admin_image": "clllagob/haproxy-admin-ui:alpha"}, REVISION),
                         "clllagob/haproxy-admin-ui:native-alpha-0123456789ab")
        self.assertEqual(agent_bootstrap.image_reference({}, REVISION), "clllagob/haproxy-admin-ui:native-latest-0123456789ab")
        self.assertIsNone(agent_bootstrap.image_reference({"native_release_base_url": "https://x"}, REVISION))

    def test_a_verified_agent_is_returned(self) -> None:
        agent = b"\x7fELF agent"
        sums = f"{hashlib.sha256(agent).hexdigest()}  sbin/easy-ha-proxy-agent\n".encode()
        with mock.patch.object(agent_bootstrap.urllib.request, "urlopen", FakeRegistry(agent, sums).urlopen):
            got = agent_bootstrap.fetch_agent("clllagob/haproxy-admin-ui:native-alpha-0123456789ab", REVISION, "arm64")
        self.assertEqual(got, agent)

    def test_another_revision_or_a_bad_checksum_is_refused(self) -> None:
        agent = b"\x7fELF agent"
        good = f"{hashlib.sha256(agent).hexdigest()}  sbin/easy-ha-proxy-agent\n".encode()
        with mock.patch.object(agent_bootstrap.urllib.request, "urlopen", FakeRegistry(agent, good, "f" * 40).urlopen):
            with self.assertRaisesRegex(agent_bootstrap.BootstrapError, "built from"):
                agent_bootstrap.fetch_agent("clllagob/haproxy-admin-ui:native-alpha-0123456789ab", REVISION, "arm64")
        bad = ("0" * 64 + "  sbin/easy-ha-proxy-agent\n").encode()
        with mock.patch.object(agent_bootstrap.urllib.request, "urlopen", FakeRegistry(agent, bad).urlopen):
            with self.assertRaisesRegex(agent_bootstrap.BootstrapError, "SHA256SUMS"):
                agent_bootstrap.fetch_agent("clllagob/haproxy-admin-ui:native-alpha-0123456789ab", REVISION, "arm64")
        with mock.patch.object(agent_bootstrap.urllib.request, "urlopen", FakeRegistry(agent, good).urlopen):
            with self.assertRaisesRegex(agent_bootstrap.BootstrapError, "no linux/amd64"):
                agent_bootstrap.fetch_agent("clllagob/haproxy-admin-ui:native-alpha-0123456789ab", REVISION, "amd64")

    def test_a_local_bundle_supplies_the_agent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "easy-ha-proxy-native-linux-arm64.tar.gz").write_bytes(layer({"./sbin/easy-ha-proxy-agent": b"local"}))
            self.assertEqual(agent_bootstrap.bundle_agent({"native_local_bundle_dir": directory}, "arm64"), b"local")
        self.assertIsNone(agent_bootstrap.bundle_agent({}, "arm64"))
        with self.assertRaisesRegex(agent_bootstrap.BootstrapError, "no SHA-256"):
            agent_bootstrap.bundle_agent({"native_release_base_url": "https://x"}, "arm64")

    def test_the_agent_is_installed_atomically_and_executable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "sub" / "agent"
            agent_bootstrap.install_agent(b"binary", target)
            self.assertEqual(target.read_bytes(), b"binary")
            self.assertEqual(target.stat().st_mode & 0o777, 0o755)


if __name__ == "__main__":
    unittest.main()
