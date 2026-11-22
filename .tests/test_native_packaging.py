"""Verify dual-arch native Rust + Go packaging and opt-in Ansible daemon toggles."""

from __future__ import annotations

from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "ansible/roles/haproxy-admin"
TEMPLATES = ROLE / "templates"


SERVICE_TOGGLES: tuple[tuple[str, str, str, str], ...] = (
    (
        "easy-ha-proxy-guardd.service.j2",
        "native_guardd_enabled",
        "guardd-core') }} serve",
        "ExecStart=/usr/bin/python3 /usr/local/sbin/easy-ha-proxy-guardd.py",
    ),
    (
        "haproxy-healthd.service.j2",
        "native_healthd_enabled",
        "easy-ha-proxy-agent') }} healthd",
        "ExecStart=/usr/bin/python3 /usr/local/sbin/haproxy-healthd.py",
    ),
    (
        "easy-ha-proxy-metricsd.service.j2",
        "native_metricsd_enabled",
        "easy-ha-proxy-agent') }} metricsd",
        "ExecStart=/usr/bin/python3 /usr/local/sbin/easy-ha-proxy-metricsd.py",
    ),
    (
        "easy-ha-proxy-alertd.service.j2",
        "native_alertd_enabled",
        "easy-ha-proxy-agent') }} alertd",
        "ExecStart=/usr/bin/python3 /usr/local/sbin/easy-ha-proxy-alertd.py",
    ),
    (
        "haproxy-controld.service.j2",
        "native_controld_enabled",
        "easy-ha-proxy-agent') }} controld",
        "ExecStart=/usr/bin/python3 /usr/local/sbin/haproxy-controld.py",
    ),
    (
        "haproxy-certd.service.j2",
        "native_certd_enabled",
        "easy-ha-proxy-agent') }} certd",
        "ExecStart=/usr/bin/python3 /usr/local/sbin/haproxy-certd.py",
    ),
    (
        "easy-ha-proxy-backupd.service.j2",
        "native_backupd_enabled",
        "easy-ha-proxy-agent') }} backupd",
        "ExecStart=/usr/bin/python3 /usr/local/sbin/easy-ha-proxy-backupd.py",
    ),
    (
        "easy-ha-proxy-updated.service.j2",
        "native_updated_enabled",
        "easy-ha-proxy-agent') }} updated",
        "ExecStart=/usr/bin/python3 /usr/local/sbin/easy-ha-proxy-updated.py",
    ),
)


class NativePackagingTests(unittest.TestCase):
    def test_defaults_keep_native_daemons_opt_in(self):
        defaults = yaml.safe_load((ROLE / "defaults/main.yml").read_text(encoding="utf-8"))
        self.assertIs(defaults["native_daemons_enabled"], False)
        self.assertEqual(defaults["native_agent_bin"], "/usr/local/sbin/easy-ha-proxy-agent")
        self.assertEqual(defaults["native_guardd_bin"], "/usr/local/sbin/guardd-core")
        self.assertEqual(
            defaults["native_guardd_lib"],
            "/usr/local/lib/easy-ha-proxy/libguardd_core.so",
        )
        for _tpl, flag, _native_cmd, _py_cmd in SERVICE_TOGGLES:
            self.assertIn(flag, defaults)

    def test_all_eight_service_templates_support_opt_in_and_python_fallback(self):
        for tpl_name, flag, native_fragment, py_exec in SERVICE_TOGGLES:
            text = (TEMPLATES / tpl_name).read_text(encoding="utf-8")
            self.assertIn(flag, text, tpl_name)
            self.assertIn(native_fragment, text, tpl_name)
            self.assertIn(py_exec, text, tpl_name)

        guardd_tpl = (TEMPLATES / "easy-ha-proxy-guardd.service.j2").read_text(encoding="utf-8")
        self.assertIn("native_guardd_ffi_enabled", guardd_tpl)
        self.assertIn("GUARDD_NATIVE_LIB=", guardd_tpl)

        extra_toggles = (
            (ROOT / "ansible/roles/authelia/templates/authelia-bansd.service.j2", "native_authelia_bansd_enabled", "authelia-bansd", "ExecStart=/usr/local/sbin/authelia-bansd.py"),
            (ROOT / "ansible/roles/authelia/templates/authelia-usersd.service.j2", "native_authelia_usersd_enabled", "authelia-usersd", "ExecStart=/usr/local/sbin/authelia-usersd.py"),
            (ROOT / "ansible/roles/authelia/templates/authelia-configd.service.j2", "native_authelia_configd_enabled", "authelia-configd", "ExecStart=/usr/local/sbin/authelia-configd.py"),
            (TEMPLATES / "easy-ha-proxy-unit-failed@.service.j2", "native_tools_enabled", "unit-failed %i", "ExecStart=/usr/bin/python3 /usr/local/sbin/easy-ha-proxy-unit-failed.py %i"),
            (TEMPLATES / "easy-ha-proxy-backup.service.j2", "native_tools_enabled", "backup-run", "ExecStart=/usr/bin/python3 /usr/local/sbin/easy-ha-proxy-backup-run.py"),
            (TEMPLATES / "iptables-haproxy-udp.service.j2", "native_tools_enabled", "udp-forward", "ExecStart=/usr/bin/python3 /usr/local/sbin/haproxy-udp-forward.py"),
            (ROOT / "ansible/roles/geoip_acl/templates/update-geoip.sh.j2", "native_tools_enabled", "update-geoip", 'exec "${PYTHON}" "${UPDATER}" "${args[@]}" "$@"'),
        )
        for path, flag, subcmd, py_exec in extra_toggles:
            text = path.read_text(encoding="utf-8")
            self.assertIn(flag, text, path.name)
            self.assertIn(subcmd, text, path.name)
            self.assertIn(py_exec, text, path.name)

    def test_native_task_enforces_https_and_sha256_verification(self):
        tasks_text = (ROLE / "tasks/native.yml").read_text(encoding="utf-8")
        parsed = yaml.safe_load(tasks_text)
        self.assertIsInstance(parsed, list)
        self.assertIn("x86_64", tasks_text)
        self.assertIn("aarch64", tasks_text)
        self.assertIn("^https://", tasks_text)
        self.assertIn("checksum: \"sha256:", tasks_text)
        self.assertIn("easy-ha-proxy-native-linux-", tasks_text)

    def test_ci_assembles_dual_arch_native_release_bundles_with_sha256(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
        jobs = workflow["jobs"]
        self.assertIn("rust-guardd", jobs)
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
