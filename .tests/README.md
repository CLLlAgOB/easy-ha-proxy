# Regression tests

The Python regression tests of the project: the installer and the host tools
the update and backup brokers run, the Ansible templates, and the panel's
templates, translations and scripts. The Go agent and panel and the Rust
guardd-core keep their unit tests next to their code (`go test`, `cargo test`).

These tests are hermetic: no network, no Docker, no running easy-ha-proxy
stack, no root. They read the installer from `installer/`, the playbook from
`ansible/` and the panel's assets from `go/panel/web/`, so they must be run
from the repository root.

`test_rust_guardd.py` needs a built guardd-core (`GUARDD_RUST_BIN`) and skips
without one. The scripts in `integration/` exercise real HAProxy, iptables or
the built binaries; CI runs them in disposable containers or runners, never
on a host that matters.

## Running

Everything the Python job of CI runs, in the same order:

```bash
pip install -r installer/requirements.txt
python -m py_compile installer/easy_ha_proxy.py
python -m compileall -q installer ansible/roles
PYTHONPATH=installer python -m unittest discover -s .tests -p 'test_*.py'
```

A single module:

```bash
PYTHONPATH=installer python3 -m unittest discover -s .tests -p 'test_update_scope.py' -v
```

## Supported interpreters

CI runs the suite on 3.10 to 3.14, because the installer and the host tools
execute on the platform interpreter rather than a bundled one: 3.10 is
Ubuntu 22.04, 3.11 Debian 12, 3.12 Ubuntu 24.04, 3.13 Debian 13 and 3.14
Ubuntu 26.04.

## Writing tests

`systemctl` is expected to exist but not to work: several code paths call it
with `check=False` and must tolerate a failure. Do not assume the calling user
can talk to systemd.
