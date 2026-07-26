#!/usr/bin/env python3
import os
import socket
import json
import subprocess
import logging
import sys
import signal
import grp
import errno

SOCKET_PATH = os.environ.get(
    "AUTHELIA_BANS_SOCKET",
    "{{ authelia_bans_socket_path | default('/run/authelia-bansd.sock') }}"
)
SCRIPT_PATH = os.environ.get(
    "AUTHELIA_BANS_SCRIPT",
    "{{ authelia_bans_script_path | default('/usr/local/sbin/authelia-bans.sh') }}"
)
SOCKET_GROUP = os.environ.get(
    "AUTHELIA_BANS_SOCKET_GROUP",
    "{{ authelia_bans_socket_group | default('haproxy-admin') }}"
)
LOG_LEVEL = os.environ.get("AUTHELIA_BANS_LOG_LEVEL", "INFO").upper()

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("authelia-bansd")


def ensure_socket_dir(path: str) -> None:
    d = os.path.dirname(path) or "."
    if not os.path.exists(d):
        os.makedirs(d, mode=0o750, exist_ok=True)


def set_socket_perms(path: str) -> None:
    try:
        gid = grp.getgrnam(SOCKET_GROUP).gr_gid
    except KeyError:
        log.warning("group %s not found, leaving socket group as root", SOCKET_GROUP)
        gid = os.getgid()
    os.chown(path, 0, gid)  # root:gid
    os.chmod(path, 0o660)   # rw-rw----


def run_cmd(args):
    try:
        res = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        return res.returncode, res.stdout, res.stderr
    except Exception as e:  # noqa: BLE001
        return 1, "", f"exception: {e}"


def handle_request(req: dict) -> dict:
    if not isinstance(req, dict):
        return {"ok": False, "error": "request must be JSON object"}

    action = req.get("action")

    if action == "ping":
        return {"ok": True, "pong": True}

    if not os.path.exists(SCRIPT_PATH):
        return {"ok": False, "error": f"script {SCRIPT_PATH} not found"}

    if action == "list":
        rc_u, out_u, err_u = run_cmd([SCRIPT_PATH, "list-users"])
        rc_i, out_i, err_i = run_cmd([SCRIPT_PATH, "list-ips"])
        if rc_u != 0 or rc_i != 0:
            return {
                "ok": False,
                "error": "list failed",
                "rc_users": rc_u,
                "rc_ips": rc_i,
                "stderr_users": err_u,
                "stderr_ips": err_i,
            }
        return {"ok": True, "users": out_u, "ips": out_i}

    if action == "revoke-user":
        username = (req.get("username") or "").strip()
        if not username:
            return {"ok": False, "error": "username is required"}
        rc, out, err = run_cmd([SCRIPT_PATH, "revoke-user", username])
        if rc != 0:
            return {"ok": False, "error": err or out or f"rc={rc}"}
        return {"ok": True, "message": out}

    if action == "revoke-ip":
        ip = (req.get("ip") or "").strip()
        if not ip:
            return {"ok": False, "error": "ip is required"}
        rc, out, err = run_cmd([SCRIPT_PATH, "revoke-ip", ip])
        if rc != 0:
            return {"ok": False, "error": err or out or f"rc={rc}"}
        return {"ok": True, "message": out}

    return {"ok": False, "error": f"unknown action {action}"}


def serve() -> None:
    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)

    ensure_socket_dir(SOCKET_PATH)

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(SOCKET_PATH)
    set_socket_perms(SOCKET_PATH)
    sock.listen(5)
    log.info("listening on %s", SOCKET_PATH)

    def shutdown(signum, frame):  # noqa: ANN001, D401, ARG001
        log.info("shutting down on signal %s", signum)
        try:
            sock.close()
        except Exception:  # noqa: BLE001
            pass
        try:
            if os.path.exists(SOCKET_PATH):
                os.unlink(SOCKET_PATH)
        except Exception:  # noqa: BLE001
            pass
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    while True:
        try:
            conn, _ = sock.accept()
        except OSError as e:
            if e.errno == errno.EINTR:
                continue
            raise
        with conn:
            try:
                conn.settimeout(15)
                data = b""
                # читаем до перевода строки или EOF
                while b"\n" not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > 1024 * 1024:
                        raise ValueError("request is too large")
                if not data:
                    continue
                line = data.split(b"\n", 1)[0]
                try:
                    req = json.loads(line.decode("utf-8"))
                except json.JSONDecodeError as e:
                    resp = {"ok": False, "error": f"invalid json: {e}"}
                else:
                    resp = handle_request(req)
            except Exception as e:  # noqa: BLE001
                log.exception("error handling request: %s", e)
                resp = {"ok": False, "error": f"exception: {e}"}
            out = json.dumps(resp, ensure_ascii=False) + "\n"
            try:
                conn.sendall(out.encode("utf-8"))
            except Exception:  # noqa: BLE001
                pass


if __name__ == "__main__":
    serve()
