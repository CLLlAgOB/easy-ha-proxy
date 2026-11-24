"""Alert history survives the switch between the Python and the Go alertd.

Usage: python3 alertd_upgrade_rollback.py --agent <easy-ha-proxy-agent>

Both daemons run in turn on one alerts.db, as a gateway does across an update
to the native agent and a rollback: Python records two alerts, acknowledges
one and mutes the other; Go must show both as they were and add an event of
its own; Python, started again, must show all of it. Runs unprivileged.
"""

from __future__ import annotations

import argparse
import grp
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
PYTHON_ALERTD = ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-alertd.py"
TOKEN = "upgrade-rollback-token"


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path: str) -> None:
        super().__init__("localhost", timeout=10)
        self.unix_path = path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.connect(self.unix_path)


def call(sock: str, method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
    conn = UnixHTTP(sock)
    headers = {"X-Alertd-Token": TOKEN, "Content-Type": "application/json"}
    conn.request(method, path, body=json.dumps(body) if body is not None else None, headers=headers)
    response = conn.getresponse()
    return response.status, json.loads(response.read() or b"{}")


def alerts(sock: str) -> dict[tuple[str, str], dict]:
    status, state = call(sock, "GET", "/api/v1/alerts/state?limit=100")
    assert status == 200, (status, state)
    found = {}
    for key in ("open", "active"):
        for row in state.get(key) or []:
            found[(row["rule"], row["subject"])] = row
    return found


def history(sock: str) -> list[dict]:
    status, data = call(sock, "GET", "/api/v1/alerts/history?limit=500")
    assert status == 200, (status, data)
    return data.get("events") or data.get("history") or []


class Daemon:
    def __init__(self, argv: list[str], env: dict[str, str], sock: str) -> None:
        self.sock = sock
        if os.path.exists(sock):
            os.unlink(sock)
        self.proc = subprocess.Popen(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for _ in range(100):
            if os.path.exists(sock):
                try:
                    if call(sock, "GET", "/api/v1/alerts/health")[0] == 200:
                        return
                except OSError:
                    pass
            if self.proc.poll() is not None:
                break
            time.sleep(0.1)
        raise SystemExit(f"{argv[0]} did not start:\n{self.stop()}")

    def stop(self) -> str:
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        return self.proc.stdout.read() if self.proc.stdout else ""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent", required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="alertd-switch-") as directory:
        root = Path(directory)
        sock = str(root / "alertd.sock")
        env = dict(
            os.environ,
            ALERTD_SOCKET_PATH=sock,
            ALERTD_SOCKET_GROUP=grp.getgrgid(os.getgid()).gr_name,
            ALERTD_DATABASE=str(root / "alerts" / "alerts.db"),
            ALERTD_CONFIG=str(root / "alertd.json"),
            ALERTD_TOKEN=TOKEN,
            ALERTD_MAIL_STATE=str(root / "mail-notify.json"),
            ALERTD_MAIL_LOCK=str(root / "mail.lock"),
            ALERTD_GATEWAY_NAME="gw.example.test",
        )
        python = [sys.executable, str(PYTHON_ALERTD)]
        go = [args.agent, "alertd"]

        # Python records, acknowledges and mutes.
        daemon = Daemon(python, env, sock)
        assert call(sock, "POST", "/api/v1/alerts/notify", {"rule": "backup.failed", "subject": "nightly"})[0] == 200
        assert call(sock, "POST", "/api/v1/alerts/quieten",
                    {"rule": "backup.failed", "subject": "nightly", "mode": "acknowledge", "by": "ops"})[0] == 200
        assert call(sock, "POST", "/api/v1/alerts/notify", {"rule": "site.down", "subject": "app.example.test",
                                                            "active": True, "trigger_delay": 0})[0] == 200
        status, muted = call(sock, "POST", "/api/v1/alerts/quieten",
                             {"rule": "site.down", "subject": "app.example.test", "mode": "mute", "seconds": 3600})
        assert status == 200, muted
        before = alerts(sock)
        events_before = len(history(sock))
        daemon.stop()

        # The Go agent sees both exactly as they were, and adds an event.
        daemon = Daemon(go, env, sock)
        seen = alerts(sock)
        for key in (("backup.failed", "nightly"), ("site.down", "app.example.test")):
            assert key in seen, (key, seen)
            for field in ("state", "acknowledged_ts", "acknowledged_by", "muted_until", "first_seen_ts"):
                assert seen[key][field] == before[key][field], (key, field, seen[key][field], before[key][field])
        assert seen[("backup.failed", "nightly")]["acknowledged_by"] == "ops"
        assert seen[("site.down", "app.example.test")]["muted_until"] == muted["muted_until"]
        assert len(history(sock)) == events_before, "the Go agent does not show the Python history"
        assert call(sock, "POST", "/api/v1/alerts/notify", {"rule": "backup.failed", "subject": "weekly"})[0] == 200
        events_go = len(history(sock))
        daemon.stop()

        # Rolled back to Python: everything, including what Go recorded.
        daemon = Daemon(python, env, sock)
        back = alerts(sock)
        assert ("backup.failed", "weekly") in back, back
        assert back[("backup.failed", "nightly")]["acknowledged_by"] == "ops"
        assert back[("site.down", "app.example.test")]["muted_until"] == muted["muted_until"]
        assert len(history(sock)) == events_go, "Python does not show the Go agent's history"
        daemon.stop()
    print(f"alertd switch: {events_go} events and both quieted alerts kept across Python -> Go -> Python")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
