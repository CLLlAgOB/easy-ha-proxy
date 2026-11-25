"""Regression tests for the privileged GeoIP management API boundary."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import types
import unittest



ROOT = Path(__file__).resolve().parents[1]
UPDATER_PATH = ROOT / "ansible/roles/geoip_acl/files/update_geoip.py"
CONTROLD_PATH = ROOT / "ansible/roles/haproxy-admin/files/haproxy-controld.py"


class FakeReader:
    def metadata(self):
        return types.SimpleNamespace(
            database_type="DBIP-Country-Lite", node_count=20_000, build_epoch=1
        )

    def close(self):
        return None


def load_module(name: str, path: Path, replacements=None):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    if replacements:
        previous = {key: sys.modules.get(key) for key in replacements}
        sys.modules.update(replacements)
    else:
        previous = {}
    try:
        assert spec.loader is not None
        spec.loader.exec_module(module)
    finally:
        for key, value in previous.items():
            if value is None:
                sys.modules.pop(key, None)
            else:
                sys.modules[key] = value
    return module


def fake_maxminddb():
    return types.SimpleNamespace(
        MODE_AUTO=0,
        open_database=lambda *_args, **_kwargs: FakeReader(),
    )


class GeoIPDeploymentAssertions(unittest.TestCase):

    def test_geoip_page_exposes_status_country_management_and_async_updates(self):
        template = (
            ROOT / "go/panel/web/templates/haproxy_geoip.html"
        ).read_text()
        javascript = (
            ROOT / "go/panel/web/static/js/geoip.js"
        ).read_text()
        navigation = (
            ROOT / "go/panel/web/templates/_haproxy_nav.html"
        ).read_text()

        self.assertIn('id="geoip-db-records"', template)
        self.assertIn('id="geoip-allowed-networks"', template)
        self.assertIn('id="geoip-save-countries"', template)
        self.assertIn('id="geoip-next-run"', template)
        self.assertIn('id="geoip-journal"', template)
        self.assertIn('/haproxy/geoip/status', javascript)
        self.assertIn('/haproxy/geoip/update', javascript)
        self.assertIn('/haproxy/geoip/countries', javascript)
        self.assertIn('revision: selectionRevision', javascript)
        self.assertIn('UPDATE_POLL_INTERVAL_MS', javascript)
        self.assertIn('payload.update_running', javascript)
        self.assertIn("routes.haproxy_geoip_page", navigation)


    def test_confirmation_pauses_status_polling_while_commit_is_in_flight(self):
        javascript = (
            ROOT / "go/panel/web/static/js/haproxy_config.js"
        ).read_text()
        confirm_source = javascript.split(
            "async function confirmPendingConfiguration()", 1
        )[1].split("async function rollbackPendingConfiguration()", 1)[0]
        poll_source = javascript.split(
            "async function pollTransactionStatus()", 1
        )[1].split("async function confirmPendingConfiguration()", 1)[0]

        self.assertLess(
            confirm_source.index("transactionActionInFlight = true"),
            confirm_source.index('requestJson("/haproxy/config/confirm"'),
        )
        self.assertLess(
            confirm_source.index("pauseTransactionPolling()"),
            confirm_source.index('requestJson("/haproxy/config/confirm"'),
        )
        self.assertIn(
            "if (!pendingTransaction || transactionActionInFlight) return",
            poll_source,
        )
        self.assertIn(
            "pollGeneration !== transactionPollGeneration",
            poll_source,
        )
        self.assertIn(
            'return ["rollback_failed", "failed"].includes(state)',
            javascript,
        )
        self.assertIn("setButtonLoading(rollbackButton, false)", javascript)
        self.assertIn("scheduleTransactionPoll(0)", confirm_source)


if __name__ == "__main__":
    unittest.main()
