"""Verify dual-arch native Rust + Go packaging and the native-only daemon units."""

from __future__ import annotations

from pathlib import Path
import re
import unittest

from jinja2 import Environment
import yaml


ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "ansible/roles/haproxy-admin"
TEMPLATES = ROLE / "templates"


NATIVE_UNITS: tuple[tuple[str, str], ...] = (
    ("easy-ha-proxy-guardd.service.j2", "guardd-core') }} serve"),
    ("haproxy-healthd.service.j2", "easy-ha-proxy-agent') }} healthd"),
    ("easy-ha-proxy-metricsd.service.j2", "easy-ha-proxy-agent') }} metricsd"),
    ("easy-ha-proxy-alertd.service.j2", "easy-ha-proxy-agent') }} alertd"),
    ("haproxy-controld.service.j2", "easy-ha-proxy-agent') }} controld"),
    ("haproxy-certd.service.j2", "easy-ha-proxy-agent') }} certd"),
    ("easy-ha-proxy-backupd.service.j2", "easy-ha-proxy-agent') }} backupd"),
    ("easy-ha-proxy-updated.service.j2", "easy-ha-proxy-agent') }} updated"),
)


class NativePackagingTests(unittest.TestCase):
    def test_the_native_binaries_are_the_only_implementation(self):
        defaults = yaml.safe_load((ROLE / "defaults/main.yml").read_text(encoding="utf-8"))
        self.assertEqual(defaults["native_agent_bin"], "/usr/local/sbin/easy-ha-proxy-agent")
        self.assertEqual(defaults["native_guardd_bin"], "/usr/local/sbin/guardd-core")
        # No switch back to a Python implementation or the Flask panel.
        for key in defaults:
            self.assertFalse(key.startswith("native_") and key.endswith("_enabled"), key)
        self.assertNotIn("haproxy_admin_use_go_panel", defaults)
        self.assertNotIn("native_guardd_lib", defaults)
        for template, command in NATIVE_UNITS:
            with self.subTest(template=template):
                text = (TEMPLATES / template).read_text(encoding="utf-8")
                self.assertIn(command, text)
                self.assertNotIn("python3", text)
                self.assertNotIn("EASY_HA_PROXY_DAEMON_VERSION", text)

        compose = (TEMPLATES / "docker-compose.yml.j2").read_text(encoding="utf-8")
        self.assertIn('image: "{{ haproxy_admin_go_image }}"', compose)
        self.assertIn("/usr/local/bin/easy-ha-proxy-panel", compose)
        self.assertNotIn("python", compose)

        installer = (ROOT / "go/agent/internal/cli/config.go").read_text(encoding="utf-8")
        for bundle in ("InstallTags", "UpdateTags", "UITags", "DaemonTags", "HostServiceTags"):
            self.assertIn(bundle, installer)
        self.assertGreaterEqual(installer.count("ha-adm-native"), 5)

    def test_daemon_tokens_are_rendered_before_the_first_consumer(self):
        plays = yaml.safe_load((ROOT / "ansible/easy-ha-proxy.yml").read_text())
        roles = [role for play in plays for role in play.get("roles", [])
                 if isinstance(role, dict) and role.get("role") == "haproxy-admin"]
        stages = [role.get("task_stage") for role in roles]
        stage = stages.index("daemons_env")
        for consumer in ("install", "daemons", "healthd", "controld", "backupd",
                         "updated", "alertd", "metricsd", "guardd"):
            pos = stages.index(consumer)
            self.assertLess(stage, pos)
            tags = roles[pos]["tags"]
            tags = [tags] if isinstance(tags, str) else tags
            self.assertTrue(set(tags) - {"never"} <= set(roles[stage]["tags"]))

    def test_native_images_follow_the_configured_channel(self):
        defaults = yaml.safe_load((ROLE / "defaults/main.yml").read_text(encoding="utf-8"))
        jinja = Environment()
        jinja.filters["regex_replace"] = lambda value, pattern, replacement: re.sub(pattern, replacement, value)
        for channel in ("alpha", "latest"):
            with self.subTest(channel=channel):
                image = f"registry.example:5000/panel:{channel}"
                context = {"haproxy_admin_image": image}
                context["haproxy_admin_image_channel"] = jinja.from_string(
                    defaults["haproxy_admin_image_channel"]
                ).render(context)
                self.assertEqual(
                    jinja.from_string(defaults["haproxy_admin_go_image"]).render(context),
                    f"registry.example:5000/panel:go-{channel}",
                )
                self.assertEqual(
                    jinja.from_string(defaults["native_release_image"]).render(context),
                    f"clllagob/haproxy-admin-ui:native-{channel}",
                )

    def test_ci_assembles_dual_arch_native_release_bundles_with_sha256(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
        jobs = workflow["jobs"]
        self.assertIn("rust-guardd", jobs)
        self.assertIn("go-agent", jobs)
        self.assertIn("go-panel", jobs)
        self.assertIn("go-panel-image", jobs)
        self.assertIn("native-release-image", jobs)
        go_img = jobs["go-panel-image"]
        self.assertLessEqual({"go-panel", "go-parity", "go-vulnerabilities", "javascript", "secrets"}, set(go_img["needs"]))
        self.assertIn("go-vulnerabilities", jobs["native-release-image"]["needs"])
        self.assertIn("rust-vulnerabilities", jobs["native-release-image"]["needs"])
        self.assertIn("go-parity", jobs["native-release-image"]["needs"])
        self.assertEqual(set(jobs["go-parity"]["needs"]), {"go-panel", "go-agent", "rust-guardd"})
        self.assertEqual(
            {item["arch"] for item in jobs["go-parity"]["strategy"]["matrix"]["include"]},
            {"amd64", "arm64"},
        )
        publish_step = next(s for s in go_img["steps"] if s.get("name") == "Publish Go panel image")
        self.assertIn("--platform linux/amd64,linux/arm64", publish_step["run"])
        self.assertIn("-f go/panel/Dockerfile", publish_step["run"])
        self.assertIn("go-agent", jobs)
        self.assertIn("native-release", jobs)
        self.assertEqual(set(jobs["native-release"]["needs"]), {"rust-guardd", "go-agent"})

        assemble = next(
            step["run"]
            for step in jobs["native-release"]["steps"]
            if "tarballs" in step.get("name", "")
        )
        self.assertIn("for arch in amd64 arm64", assemble)
        self.assertIn("easy-ha-proxy-native-linux-${arch}.tar.gz", assemble)
        self.assertIn("sha256sum -c SHA256SUMS", assemble)


if __name__ == "__main__":
    unittest.main()
