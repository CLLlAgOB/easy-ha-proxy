"""Check TLS/port changes with isolated HAProxy processes, no live reload.

Usage: python3 server_state_tls_smoke.py --template haproxy-state-dump.sh.j2
"""
import argparse
from contextlib import contextmanager
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time


def rpc(path, command):
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(3)
        client.connect(str(path))
        client.sendall((command + "\n").encode())
        data = b""
        while True:
            chunk = client.recv(65536)
            if not chunk:
                return data.decode()
            data += chunk


def state(path):
    text = rpc(path, "show servers state")
    lines = text.splitlines()
    header = next(line[2:].split() for line in lines if line.startswith("# "))
    row = next(line.split() for line in lines if " target " in line)
    return text, dict(zip(header, row, strict=True))


@contextmanager
def running(root, tls, load, backend_port=9, *, backend_host="127.0.0.1",
            server_options="", backend_options="", weight=100):
    control = root / "admin.sock"
    if control.exists():
        control.unlink()
    with socket.socket() as port_probe:
        port_probe.bind(("127.0.0.1", 0))
        port = port_probe.getsockname()[1]
    config = (
        f"global\n stats socket {control} level admin\n"
        + (f" server-state-file {root / 'state'}\n" if load else "")
        + "defaults\n mode http\n timeout connect 1s\n timeout client 1s\n timeout server 1s\n"
        + (" load-server-state-from-file global\n" if load else "")
        + f"frontend probe\n bind 127.0.0.1:{port}\n default_backend target\n"
        + "backend target\n default-server check-ssl verify none\n" + backend_options
        + f" server main {backend_host}:{backend_port} weight {weight} {server_options}" + (" ssl" if tls else "") + "\n"
    )
    (root / "haproxy.cfg").write_text(config)
    process = subprocess.Popen(["haproxy", "-db", "-f", "/dev/stdin"],
                               stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.DEVNULL)
    try:
        process.stdin.write(config.encode())
        process.stdin.close()
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError(process.stderr.read().decode())
            if control.exists():
                try:
                    state(control)
                    break
                except OSError:
                    pass
            time.sleep(.05)
        else:
            raise RuntimeError("HAProxy socket not ready")
        yield control
    finally:
        process.terminate()
        process.wait(timeout=5)
        process.stderr.close()


def main(template, normalizer):
    results = []
    cases = [(False, True, "maint", 1025, 1025), (True, False, "drain", 1025, 1025),
             (True, True, "drain", 1025, 1026), (False, True, "maint", 1026, 1025)]
    for old_tls, wanted_tls, admin, old_port, wanted_port in cases:
        with tempfile.TemporaryDirectory(prefix="ehp-state-tls-") as directory:
            root = Path(directory)
            script = template.read_text().replace(
                "{{ haproxy_socket | default('/run/haproxy/admin.sock') }}", str(root / "admin.sock")
            ).replace(
                "{{ haproxy_server_state_file | default('/var/lib/haproxy/server-state') }}", str(root / "state")
            )
            assert "{{" not in script
            (root / "dump.sh").write_text(script)
            with running(root, old_tls, False, old_port) as control:
                rpc(control, "set server target/main weight 17")
                rpc(control, "set server target/main state " + admin)
                original, expected = state(control)
                (root / "state").write_text(original)
                # A save writes the new config before asking the old worker to dump.
                config_path = root / "haproxy.cfg"
                config_path.write_text(config_path.read_text().replace(f":{old_port} weight", f":{wanted_port} weight"))
                subprocess.run(["sh", str(root / "dump.sh"), str(config_path), str(normalizer)], check=True, timeout=5)
                filtered = (root / "state").read_text()
            # Observe the raw behavior for diagnostics. Upstream versions can
            # fix this behavior too; only the normalized postconditions below
            # are requirements, not the presence of a bug in an upstream build.
            (root / "state").write_text(original)
            with running(root, wanted_tls, True, wanted_port) as control:
                _, restored = state(control)
                unfiltered = restored
            # Then exercise the real updated dumper's output.
            (root / "state").write_text(filtered)
            with running(root, wanted_tls, True, wanted_port) as control:
                _, restored = state(control)
                if "srv_use_ssl" in restored:
                    assert restored["srv_use_ssl"] == str(int(wanted_tls)), restored
                assert restored["srv_port"] == str(wanted_port), restored
                for key in ["srv_admin_state", "srv_uweight", "srv_iweight"]:
                    assert restored[key] == expected[key], (key, expected, restored)
            results.append({"tls_before": old_tls, "tls_after": wanted_tls,
                            "port_before": old_port, "port_after": wanted_port,
                            "unfiltered_tls": unfiltered.get("srv_use_ssl"),
                            "unfiltered_port": unfiltered["srv_port"],
                            "admin_state_preserved": admin, "weight_preserved": 17})
    print(json.dumps({"passed": results}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--normalizer", type=Path, default=Path(__file__).resolve().parents[2] / "installer/haproxy_server_state.py")
    options = parser.parse_args()
    main(options.template, options.normalizer)
