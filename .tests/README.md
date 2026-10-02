# Regression tests

Every test in the project: the installer, the helper daemons, the Ansible side
and the admin UI. There is no second location.

These tests are hermetic: no network, no Docker, no running easy-ha-proxy
stack, no root. They reach the application and the daemons by path, from
`docker/app/`, `ansible/roles/haproxy-admin/files/` and
`ansible/roles/authelia/files/`, so they must be run from the repository root.

A test that needs the Flask application uses the same three lines:

```python
ROOT = Path(__file__).resolve().parents[1]
APP_DIR = ROOT / "docker" / "app" / "haproxy_admin"
sys.path.insert(0, str(ROOT / "docker" / "app"))
```

## Running

Everything CI runs, in the same order:

```bash
pip install -r docker/app/requirements.txt -r installer/requirements.txt
python -m py_compile installer/easy_ha_proxy.py
python -m compileall -q docker/app ansible/roles/authelia/files ansible/roles/haproxy-admin/files
PYTHONPATH=installer python -m unittest discover -s .tests -p 'test_*.py'
bash -n install.sh install-local.sh install-remote.sh easy-ha-proxy-helper.sh installer/easy-ha-proxy
ansible-galaxy collection install -r ansible/requirements.yml
ansible-playbook --syntax-check -i localhost, ansible/easy-ha-proxy.yml
```

Just this directory:

```bash
PYTHONPATH=installer python3 -m unittest discover -s .tests -p 'test_*.py' -v
```

A single module:

```bash
PYTHONPATH=installer python3 -m unittest discover -s .tests -p 'test_healthd.py' -v
```

## Supported interpreters

CI runs the suite on 3.10, 3.11 and 3.12, because the host daemons execute on
the platform interpreter rather than a bundled one:

| Interpreter | Where it comes from                    |
| ----------- | -------------------------------------- |
| 3.10        | Ubuntu 22.04                           |
| 3.11        | Debian 12                              |
| 3.12        | Ubuntu 24.04 and the admin UI image    |

## Writing tests

Some daemon modules call `logging.basicConfig()` at import time, which
configures the *root* logger for the rest of the process. A test that patches a
global such as `time.time` with a finite `side_effect` sequence can therefore
be broken by an unrelated module that merely got imported first: the now-live
`LOG.info()` call builds a `LogRecord`, which reads the clock and consumes a
scripted value. Silence the logger under test (see `SiteAlertStateTests.setUp`)
instead of sizing the sequence for one particular execution order.

`systemctl` is expected to exist but not to work: several code paths call it
with `check=False` and must tolerate a failure. Do not assume the calling user
can talk to systemd.
