"""Regression tests for the privileged monitoring daemon."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]


def load_healthd():
    path = ROOT / "ansible/roles/haproxy-admin/files/haproxy-healthd.py"
    spec = importlib.util.spec_from_file_location("easy_ha_proxy_healthd", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class HealthJavascriptSourceTests(unittest.TestCase):
    def test_summaries_use_tri_state_health(self) -> None:
        source = (
            ROOT / "go/panel/web/static/js/health.js"
        ).read_text(encoding="utf-8")

        self.assertIn("function systemdHealthState(unit)", source)
        self.assertIn("if (unit.healthy === null) return null;", source)
        self.assertIn("function dockerHealthState(container)", source)
        self.assertIn('if (!health || health === "healthy") return true;', source)
        self.assertIn('if (health === "starting") return null;', source)
        self.assertIn("const hasFailed = states.some", source)
        self.assertIn('hasOwnProperty.call(u, "display_sub_state")', source)
        self.assertIn('titleParts.push(`result=${unit.result}`)', source)


if __name__ == "__main__":
    unittest.main()
