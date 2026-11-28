# Regression tests

The Python contract tests of the project: the Ansible templates, the shell
entry points, the CI workflow and the panel's templates, translations and
scripts. Nothing on a gateway runs Python: the installer, the brokers and the
host tools are the Go agent, which keeps its unit tests next to its code
(`go test`), as do the Go panel and the Rust guardd-core (`cargo test`).

These tests are hermetic: no network, no Docker, no running easy-ha-proxy
stack, no root. They read the playbook from `ansible/`, the entry points from
the repository root and `installer/`, and the panel's assets from
`go/panel/web/`, so they must be run from the repository root.

`test_rust_guardd.py` needs a built guardd-core (`GUARDD_RUST_BIN`) and skips
without one. The scripts in `integration/` exercise real HAProxy, iptables or
the built binaries; CI runs them in disposable containers or runners, never
on a host that matters.

## Running

Everything the Python job of CI runs:

```bash
pip install -r .tests/requirements.txt
python -m unittest discover -s .tests -p 'test_*.py'
```

A single module:

```bash
python3 -m unittest discover -s .tests -p 'test_update_scope.py' -v
```

CI runs them on one interpreter, 3.12: they test files, not code that runs
on a gateway.

## Writing tests

`systemctl` is expected to exist but not to work: several code paths call it
with `check=False` and must tolerate a failure. Do not assume the calling user
can talk to systemd.
