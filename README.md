# easy-ha-proxy

[English](README.md) | [Русский](README.ru.md)

Start with the [Quick Start guide](QUICKSTART.md).

easy-ha-proxy is a production-oriented, single-server stack for HAProxy, Let's
Encrypt, GeoIP ACLs, Authelia, and a web administration UI. It installs and
maintains the host services, container workloads, certificates, access rules,
and encrypted disaster-recovery backups from one assistant.

## What it provides

- HAProxy for HTTP/HTTPS and TCP proxying, health checks, rate limits, bans,
  maintenance pages, and optional GeoIP filtering. One local DB-IP Country Lite
  database supplies both UI country lookups and the IPv4/IPv6 HAProxy ACL;
  country flags are bundled, so neither feature calls a public API at runtime.
- Kernel-NAT UDP forwarding (iptables DNAT) for services HAProxy cannot proxy,
  such as WireGuard, honoring the same ban set and an optional zero-trust
  (authorized-IP) access control.
- Automatic Let's Encrypt issuance and renewal, an internal CA with a
  downloadable public root certificate, and verified external CA chains.
- Authelia authentication with Redis and a file-backed user database.
- A web UI for sites, TCP proxies, UDP forwarding, certificates, Authelia users
  and policies, runtime bans, health information, and safe HAProxy configuration
  changes.
  The interface supports English and Russian and remembers the selected
  language.
- A local and SSH-based installer with inspection, check mode, targeted updates,
  repair, domain migration, and legacy-configuration migration. An argument-free
  start asks for English or Russian; English is the default.
- Encrypted full backup and restore for disaster recovery.

The UI and Authelia are intended to be reached through HAProxy. Their internal
ports must not be exposed directly to untrusted networks.

## Architecture

    Clients
       |
       v
    HAProxy on the host (:80/:443 and configured TCP ports)
       |-- HTTP/HTTPS application backends
       |-- configured TCP frontends --> TCP application backends
       |-- authentication request --> Authelia (127.0.0.1:9091) --> Redis
       \-- administration domain --> UI (127.0.0.1:5000)
                                      |
                                      \-- constrained UNIX-socket helpers

    Clients (UDP) --> iptables DNAT (kernel) --> UDP application backends

Ansible in `/opt/easy-ha-proxy/venv` manages host packages, systemd units,
HAProxy configuration, certificates, and Docker Compose services. The
unprivileged UI uses the HAProxy runtime socket for runtime operations and
constrained helper APIs under `/run/easy-ha-proxy` for host/configuration
changes.

## Requirements

The managed server must have:

- Debian 12 or newer, or Ubuntu 22.04 or newer;
- systemd;
- an `amd64` or `arm64` CPU;
- root access, or a user with working `sudo`;
- inbound TCP ports 80 and 443, plus every configured TCP proxy port and UDP
  forward port;
- production DNS A/AAAA records resolving the administration and Authelia
  domains to this server;
- outbound access to the configured OS package repositories, GitHub, the
  Python package index, Ansible Galaxy, container registry, Snap, Let's Encrypt,
  and the DB-IP GeoIP data source during installation and monthly updates.

For remote installation, the workstation only needs `bash`, `curl`, `ssh`, and
`scp`. Ansible is installed into the project's private virtual environment on
the managed server.

## Quick start

Download the installer to a file so it can be inspected before execution:

```bash
curl -fsSLo /tmp/easy-ha-proxy-install.sh \
  https://raw.githubusercontent.com/CLLlAgOB/easy-ha-proxy/main/install.sh
bash /tmp/easy-ha-proxy-install.sh
```

The first prompt selects English or Russian. Press Enter to keep English. For
non-interactive or explicit commands, set `EASY_HA_PROXY_LANGUAGE=en` or `ru`.
You can also pass `--language ru` after `local` or `remote`.

Inspect the saved script with your preferred editor or pager before the last
command.

The assistant detects whether the machine is clean, partially configured, or
already managed, then offers only the applicable actions. After installation,
the same menu is available as:

```bash
sudo easy-ha-proxy-assistant
```

Detailed installer, migration, backup, and recovery behavior is documented in
[INSTALLER_README.md](INSTALLER_README.md).

### Install or manage the current server

```bash
bash /tmp/easy-ha-proxy-install.sh local
```

On a clean server, the assistant offers production mode and test mode. On an
existing installation, its primary action checks source, helper daemons,
Docker image digests, and cached OS updates, then offers only the updates it
found. Component-specific operations are kept in an advanced submenu.

### Manage a remote server

Using normal SSH configuration:

```bash
bash /tmp/easy-ha-proxy-install.sh remote admin@server.example.com
```

Using an SSH password prompt:

```bash
bash /tmp/easy-ha-proxy-install.sh remote \
  --host 192.0.2.10 --user admin --ask-pass
```

The password is read by OpenSSH from a hidden terminal prompt. There is
deliberately no command-line password option.

Using a private key:

```bash
bash /tmp/easy-ha-proxy-install.sh remote \
  --host 192.0.2.10 --user admin \
  --port 2222 --identity ~/.ssh/server
```

Using an Ansible INI inventory:

```bash
bash /tmp/easy-ha-proxy-install.sh remote \
  --inventory ./ansible/inventory.ini --limit proxy01
```

The inventory parser supports `ansible_host`, `ansible_user`, `ansible_port`,
`ansible_ssh_port`, and `ansible_ssh_private_key_file`. It intentionally ignores
`ansible_password`; use `--ask-pass` instead. Resolve the connection without
opening SSH by adding `--dry-run`.

### Test mode without public DNS

Test mode uses the internal CA for the initial control-plane certificate and
skips only public DNS validation and initial Let's Encrypt issuance. Certbot,
its renewal timer, deploy hooks, and notifications remain installed so sites
can be switched to Let's Encrypt later:

```bash
sudo easy-ha-proxy install --test-mode
```

For the first installation, it can also be selected through the downloaded
assistant:

```bash
bash /tmp/easy-ha-proxy-install.sh local --test-mode
```

Or on a remote test machine:

```bash
bash /tmp/easy-ha-proxy-install.sh remote \
  --test-mode admin@192.0.2.10
```

Test mode uses `ha.easy-ha-proxy.test` and `aut.easy-ha-proxy.test`, creates a
local CA and SAN certificate, skips public DNS checks, and prints a ready-to-use
hosts-file entry. Copy `/tmp/easy-ha-proxy-internal-ca.crt` from the server and
import it only on clients that should trust this CA. Its private key remains
root-only under `/etc/haproxy/certificate-authorities/internal`.

A successful test installation can be promoted without reinstalling. The
promotion backs up the managed configuration, migrates control-plane and site
domains, preserves users, secrets, backends, and TCP proxies, runs check mode,
and applies only after `PROMOTE` confirmation:

```bash
sudo easy-ha-proxy promote-production --new-domain example.com \
  --certificate-source internal --image latest
```

Use `letsencrypt` instead of `internal` when public DNS and ports 80/443 are
ready. Missing DNS records produce a warning and skip initial ACME issuance;
they no longer abort installation.

## Initial configuration

The wizard asks for:

- the initial certificate source: public **Let's Encrypt** or the built-in
  **internal CA**;
- the root, administration, and Authelia domains;
- a Let's Encrypt or administrator email address and timezone;
- optional allowed IP/CIDR ranges and GeoIP countries;
- the first `superadmin` login, display name, email, and password;
- optional email notifications through the managed internal mail relay; one
  upstream SMTP configuration is shared by Authelia and certificate-renewal
  notifications.

The administrator password is stored as an Argon2id hash. Generated Authelia
secrets, the internal proxy secret, and an optional SMTP password are written to
`/etc/easy-ha-proxy/secrets.yml` with mode `0600`.

Authelia and Certbot never connect to the upstream SMTP server directly. They
submit messages to the internal Postfix relay, whose persistent queue absorbs
temporary upstream network failures. The upstream host, credentials, TLS mode,
sender, and notification recipient can later be changed from **Authelia
settings** in the administration UI. Its test action queues a message locally;
receipt in the destination inbox confirms the external path.

When email delivery is disabled, Authelia keeps only its latest local
notification. A `superadmin` can reveal and copy that notification from
**Authelia settings** after verifying the requester through a trusted channel.
The next request overwrites it and an Authelia restart can clear it; the contained
reset link or one-time code is short-lived and must be completed by the user,
not approved by the administrator on the user's behalf.

The installer downloads DB-IP Country Lite to
`/etc/haproxy/geoip/releases/` and atomically activates a matching MMDB and
HAProxy country ACL. A systemd timer checks daily but downloads at most once per
published month. Failed downloads, validation, reloads, or control-plane checks
leave the last working release active. GeoIP is an approximate access signal,
not a substitute for authentication.

The same choice can be supplied explicitly with
`--certificate-source letsencrypt` or `--certificate-source internal`. This
selects only the initial certificate for the administration UI and Authelia.
The internal option skips public DNS validation and initial public issuance,
but Certbot is installed and remains available. If you use a corporate/external CA,
complete the first installation with either initial source, then import its
public root/intermediate bundle on `/haproxy/certs` and upload/select the
matching server certificate in the site editor.

## Day-to-day management

The local GeoIP updater can be run and inspected independently:

```bash
sudo systemctl start easy-ha-proxy-geoip-update.service
sudo journalctl -u easy-ha-proxy-geoip-update.service -n 50 --no-pager
sudo cat /etc/haproxy/geoip/current/state.json
```

The database is used by the UI even when HAProxy GeoIP access filtering is
disabled. No visitor IP address is sent to an external geolocation or flag
service.

UDP forwards are edited on **UDP forwarding**. Saving is synchronous: the page
reports success only after the systemd loader has installed the complete
iptables ruleset; a failed apply restores the previous `udp.yml` and active
rules. A rule accepts either one port or paired inclusive ranges of the same
size, for example `19999-20010` to `9999-10010` (up to 1024 ports per rule).
IPv4 backends must be on another LAN address or in a container; loopback
addresses (`127.0.0.0/8`) are intentionally rejected. Backends see the proxy
address because of MASQUERADE. For a one-host smoke test, place the echo
backend in a temporary container or network namespace so the test exercises
the real routed path. GeoIP filtering is not currently applied to UDP.

Every full install or update has two independent channels:

- `--source github|local` selects GitHub `main` or the source already
  synchronized to `/opt/easy-ha-proxy/source`;
- `--image latest|alpha` selects the release or test HAProxy Admin image.

The interactive update menu asks for both. To atomically upload uncommitted
controller changes and apply them with the test image in one operation:

```bash
./install.sh remote --inventory ./inventory.ini --limit my_server \
  --sync-source . --apply --image alpha
```

For a normal release update, use `--action update --source github --image
latest`. The selected channels are saved and can be changed by the next
update. The `alpha` image must already exist in the configured container
registry; source synchronization does not build or publish an image.

```bash
sudo easy-ha-proxy status
sudo easy-ha-proxy-assistant inspect
sudo easy-ha-proxy-assistant check-updates
sudo easy-ha-proxy-assistant smart-update
sudo easy-ha-proxy plan
sudo easy-ha-proxy update
sudo easy-ha-proxy update --component daemons
sudo easy-ha-proxy update --component services
sudo easy-ha-proxy update --ui-only
sudo easy-ha-proxy configure
sudo easy-ha-proxy configure --apply
sudo easy-ha-proxy language --language ru --apply
```

From the controller repository, the equivalent remote command is:

```bash
./install.sh remote --language ru --inventory ./inventory.ini \
  --limit my_server --action language
```

For this action the controller first replaces the managed source atomically
with the current local tree and keeps the previous tree as a server-side
backup. This also upgrades older installations whose CLI predates the
`language` command.

- `status` checks current service health; it does not query registries for new
  Docker images.
- `check-updates` compares source, daemons, Docker registry digests, and cached
  OS updates without applying them.
- `smart-update` performs the same checks and offers the updates it found.
- `plan` runs Ansible check mode without applying changes.
- `update` refreshes the managed checkout, dependencies, and complete stack.
- `update --component daemons` updates only managed helper daemons.
- `update --component services` applies the host-side service layer without
  refreshing container images.
- `update --ui-only` updates the UI and its compatible HAProxy/helper security
  layer while preserving sites, users, and certificates.
- Normal updates replace source/runtime artifacts, not the root-owned managed
  YAML. Missing options use code defaults until explicitly changed.
- `configure` reruns the wizard, backs up the previous configuration, and
  preserves values outside the fields explicitly changed by the wizard.
- `language --language en|ru --apply` saves and applies the assistant language,
  default UI language, and Authelia notification language.

### Software updates from the web interface

A `superadmin` can open **Software updates** in HAProxy Admin. The page runs an
explicit read-only check and separates updates for the managed source/full
stack, host services, helper daemons, Authelia containers, the HAProxy Admin
container itself, and cached operating-system packages. Nothing is selected or
installed merely by opening the page.

Applying selected components creates a durable job in
`easy-ha-proxy-updated.service`. The root broker accepts only fixed component
IDs; the browser cannot supply commands, Ansible tags, paths, repository URLs,
or image references. Progress survives recreation of the web container and the
page reconnects automatically after a self-update. Source/host updates are
blocked while HAProxy configuration changes are pending, and update jobs share
a maintenance lock with full backup/restore. OS packages run last; a required
reboot is reported but never started automatically from the browser.

An installation that predates this page needs one normal full controller/CLI
update first so the host broker and its socket are installed. A locally
synchronized source tree cannot be copied from a workstation by the web page;
run `./install.sh remote --sync-source . --apply ...` for that workflow.

Certificate sources are selected per site in the web UI:

- **Let's Encrypt** issues and renews the public certificate automatically.
- **External certificate authority** requires importing the public root and
  intermediate CA bundle on `/haproxy/certs`, then uploading a matching server
  certificate, private key, and chain from the site editor.
- **Internal certificate authority** creates a root CA once and issues a
  private certificate by button. Download its public root from
  `/haproxy/certs` and install it only in the client trust stores you control.

For installations created before 2026-07-04, perform one complete
`sudo easy-ha-proxy update` before using targeted updates.

### Important paths

- `/etc/easy-ha-proxy` — managed configuration and secrets;
- `/opt/easy-ha-proxy/source` — managed source checkout;
- `/opt/easy-ha-proxy/venv` — private Python and Ansible environment;
- `/etc/haproxy` — HAProxy configuration and certificates;
- `/etc/haproxy/certificate-authorities` — imported CA bundles and the
  root-only internal CA private key;
- `/opt/authelia` and `/opt/haproxy-admin` — container configuration and data;
- `/run/easy-ha-proxy` — constrained helper sockets;
- `/run/haproxy/admin.sock` — HAProxy runtime socket.

### Encrypted backup and restore

Superadmins can open **Backup & restore** in the web interface to create,
download, verify, and restore a full encrypted snapshot. A snapshot retained on
the same server can be selected with **Restore** directly; on another server,
upload the downloaded `.enc` file. Backup and restore run
as durable host jobs, so the page can reconnect after the application container
is briefly paused or recreated. Restore always performs a read-only archive
inspection first and requires the exact `RESTORE` confirmation before managed
configuration, secrets, Authelia users/data, certificates, and application data
are replaced. The inspection measures expanded payload size and checks capacity
for extraction plus automatic rollback before services are stopped. SSH keys
remain excluded unless they are enabled separately.

Web restore is intended for the current server or another server where a fresh
easy-ha-proxy stack is already installed. For a completely empty Debian/Ubuntu
host, use the controller workflow below. If extraction or reconciliation fails,
the protected pre-restore snapshot is applied automatically. This short-lived
local safety snapshot is removed after a successful restore or rollback and is
retained only when automatic rollback itself fails.

From a controller checkout:

```bash
bash ./install.sh backup-full inventory.ini proxy01
bash ./install.sh restore-full \
  /path/to/easy-ha-proxy-full-YYYYMMDDTHHMMSSZ.tar.gz.enc \
  inventory-new.ini proxy-new fresh
```

SSH keys are included and restored only after separate confirmations. Even an
encrypted backup contains sensitive production material and must not be
committed or placed in a public artifact store. The passphrase is never stored;
download the `.enc` archive and its `.sha256` file, and keep the passphrase in a
separate password manager.

## Manual Ansible workflow

The supported assistant is the preferred interface. After creating the ignored
local inventory and configuration files described in
[ansible/README.md](ansible/README.md) (Russian), direct remote Ansible use
remains available:

```bash
cd ansible
ansible-galaxy collection install -r requirements.yml
ansible-playbook --syntax-check -i inventory.ini easy-ha-proxy.yml
ansible-playbook -i inventory.ini easy-ha-proxy.yml -t status
```

An untagged playbook run includes OS package upgrades. A local Ansible
connection is never rebooted by the playbook: the easy-ha-proxy assistant asks
after the upgrade and defaults to deferring the reboot. Direct playbook users
must reboot manually, or explicitly set
`easy_ha_proxy_reboot_after_upgrade=true` for an SSH-managed target. Review the
plan and tags before applying it to production.

Inventory, host variables, and secrets are intentionally not supplied by the
public repository.

## Development checks

The public translation regression check `docker/app/test_i18n.py` is excluded
from the runtime Docker image by `.dockerignore`.

```bash
python3 -m py_compile installer/easy_ha_proxy.py
python3 -m compileall -q docker/app \
  ansible/roles/authelia/files \
  ansible/roles/haproxy-admin/files
python3 docker/app/test_i18n.py -v

bash -n install.sh install-local.sh install-remote.sh \
  easy-ha-proxy-helper.sh installer/easy-ha-proxy
```

UI translations are JSON catalogs under
[`docker/app/haproxy_admin/translations/`](docker/app/haproxy_admin/translations/README.md).
Adding a catalog automatically adds its language to the interface selector;
templates do not need to be copied. English is the canonical source language;
other languages map English strings to translations.

## Security notes

- Do not expose UI port `5000` or Authelia port `9091` directly.
- Keep `/etc/easy-ha-proxy` root-owned and preserve `0600` on `secrets.yml`.
- Restrict administrative access with Authelia and, where practical, IP/CIDR
  allowlists.
- Review downloaded installation scripts and planned Ansible changes before
  applying them to production.
- If a private key or credential leaks, rotate it. Removing the file from the
  latest commit is not sufficient.
- The local test CA is for isolated testing only.

No automated check replaces a deployment-specific security review.

## License

Unless a file states otherwise, the project's original code and documentation
are licensed under the [GNU General Public License v3.0 or later](LICENSE)
(`GPL-3.0-or-later`).

Vendored Lua files retain their own notices, as summarized in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md):

- `ansible/roles/authelia/files/lua/auth-request.lua` — MIT;
- `ansible/roles/authelia/files/lua/json.lua` — MIT;
- `ansible/roles/authelia/files/lua/http.lua` — Apache-2.0;
- adapted Authelia notification templates under
  `ansible/roles/authelia/templates/` — Apache-2.0.

External packages and container images are distributed under their respective
licenses and are not relicensed by this repository.
