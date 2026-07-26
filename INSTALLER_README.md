# easy-ha-proxy interactive assistant

[English](INSTALLER_README.md) | [Русский](INSTALLER_README.ru.md) | [Quick Start](QUICKSTART.md)

`install.sh` is the single entry point for installing, diagnosing, and updating
easy-ha-proxy. It supports a clean server, an existing managed installation, a
partially configured system, and controlled adoption of a legacy deployment.

## Quick start

```bash
curl -fsSLo /tmp/easy-ha-proxy-install.sh \
  https://raw.githubusercontent.com/CLLlAgOB/easy-ha-proxy/main/install.sh
bash /tmp/easy-ha-proxy-install.sh
```

Without arguments, the assistant:

1. Asks for English or Russian; pressing Enter selects English.
2. Looks for the installed CLI, managed configuration, private Python/Ansible
   venv, playbook, and system components.
3. Classifies the system as clean, partially installed, legacy, or managed.
4. Detects production or test mode.
5. Shows only applicable actions and asks for confirmation before changes.

Explicit commands default to English. Set `EASY_HA_PROXY_LANGUAGE=ru` to use
Russian. The language selected during first configuration is also used for
Authelia notification templates. It is stored as
`authelia_notification_language: en` or `ru` in `authelia.yml` and can be
changed later by editing that value and applying the configuration.

If `inventory.ini` is found beside the script or in the current directory,
`ansible/inventory.ini` is also checked and offered as the default for remote
operations.

For a shorter first-install path, see [QUICKSTART.md](QUICKSTART.md).

## Clean server

On a clean machine the menu offers:

- local production installation;
- test installation without public IP or DNS;
- connection to a remote machine;
- diagnostic mode.

Explicit actions:

```bash
bash /tmp/easy-ha-proxy-install.sh install
bash /tmp/easy-ha-proxy-install.sh install-test
```

Test mode uses `.test` domains, the built-in internal CA, and a hosts-file
entry. Public DNS validation and initial public issuance are skipped, but
Certbot, its renewal timer, and deploy hooks are installed. During a normal
installation the wizard offers `letsencrypt` (default) or `internal` for the
initial administration UI and Authelia certificate; the choice can also be
passed as `--certificate-source internal`.
After the first installation, import an external CA root/intermediate bundle
and its server certificates from `/haproxy/certs`.

For a remote first deployment, select both the source and image explicitly:

```bash
# Published release: clone GitHub and deploy latest.
bash ./install.sh remote --inventory ./inventory.ini --limit proxy01 \
  --action install --source github --image latest

# Test the current controller tree and deploy the existing alpha image.
bash ./install.sh remote --inventory ./inventory.ini --limit proxy01 \
  --action install-test --source local --source-root . --image alpha
```

Without these flags, the installation uses GitHub by default and asks for the
Docker image channel. The test image must already exist in the configured
registry.

## Installed system

Open the local management menu:

```bash
bash /tmp/easy-ha-proxy-install.sh local
```

After the first installation, the permanent command is also available:

```bash
sudo easy-ha-proxy-assistant
```

The installed-system menu puts the normal workflow first: check all update
sources and install selected items. Read-only update checks, status,
configuration, and stack language are also in the main menu. Component-only
updates and maintenance operations are in the advanced submenu.

The assistant can:

- show complete systemd and container status;
- verify managed configuration files;
- validate `haproxy.cfg` and Docker Compose;
- run Ansible check mode;
- compare the installed source with `main` by commit or fingerprint;
- compare the canonical HAProxy template with the UI runtime copy;
- compare local and registry digests for all container images, including a
  republished `latest` tag;
- show the number of upgradeable packages from the current APT cache;
- update the complete stack or only selected components;
- rerun the configuration wizard;
- repair missing or damaged components;
- create an encrypted full backup.

Actions can also be run without the menu:

| Command | Purpose | Changes the system |
| --- | --- | --- |
| `bash /tmp/easy-ha-proxy-install.sh inspect` | Detects installation type, production/test mode, paths, source version, and short SHA-256 versions of helper daemons. | No |
| `bash /tmp/easy-ha-proxy-install.sh status` | Checks systemd services/timers, oneshot results, managed scripts/hooks/Lua hashes, APT/Snap versions, and containers; shows logs for failures. | No |
| `bash /tmp/easy-ha-proxy-install.sh check-config` | Checks YAML files, `secrets.yml` permissions, HAProxy, and Docker Compose configuration. | No |
| `bash /tmp/easy-ha-proxy-install.sh plan` | Runs Ansible check mode and previews an update without applying it. | No |
| `bash /tmp/easy-ha-proxy-install.sh check-updates` | Compares source, helper daemons, the UI template, container digests, and cached APT updates. | No; uses the network |
| `bash /tmp/easy-ha-proxy-install.sh smart-update` | Performs the full update check and offers only components with detected updates. | Yes, after selection and confirmation |
| `sudo easy-ha-proxy language --language ru --apply` | Saves and applies the assistant, default UI, and Authelia notification language. | Yes |
| `bash /tmp/easy-ha-proxy-install.sh update` | Fetches current source, updates dependencies, and applies the complete managed stack. | Yes, after confirmation |
| `bash /tmp/easy-ha-proxy-install.sh apply-current` | Applies already installed or synchronized source without fetching GitHub. | Yes, after confirmation |
| `bash /tmp/easy-ha-proxy-install.sh update-ui` | Applies the UI and compatible HAProxy/Authelia helper components without updating source. | Yes, after confirmation |
| `bash /tmp/easy-ha-proxy-install.sh reboot` | Schedules a previously deferred required reboot on the current server and lets the current session exit cleanly. | Yes, after confirmation |
| `bash /tmp/easy-ha-proxy-install.sh backup-full` | Creates an encrypted DR backup and separately asks about SSH keys and a consistency pause. | Creates an archive; may briefly pause managed components |
| `sudo easy-ha-proxy restore-full ARCHIVE --mode auto --apply` | Restores on a server where the CLI is installed. For a clean server, use the controller command documented below. | Yes, after `RESTORE`; creates rollback first |
| `bash /tmp/easy-ha-proxy-install.sh configure` | Reruns the wizard, backs up the old configuration, and applies the result. | Yes, after confirmation |
| `bash /tmp/easy-ha-proxy-install.sh migrate-domain` | Previews, validates, and then applies a managed root-domain replacement. | Only after confirmation |
| `sudo easy-ha-proxy promote-production` | Promotes a test stack in place while preserving sites, TCP proxies, users, secrets, and backends. | Only after `PROMOTE` |
| `bash /tmp/easy-ha-proxy-install.sh repair` | Reapplies the current production/test installation while preserving configuration. | Yes, after confirmation |
| `bash /tmp/easy-ha-proxy-install.sh install-reset` | Restarts the production wizard after backing up the current configuration and preserving managed data. | Yes, after confirmation |

Mutating actions request confirmation. Diagnostic actions do not change
configuration. `check-updates` contacts GitHub and registries but does not run
`git pull` or `docker pull`; APT information comes from the local cache.
`status` is intentionally health-only and does not query container registries.
After an OS-package update, the assistant asks whether to reboot and defaults to
No. If deferred, use the `reboot` action later or run `sudo systemctl reboot`.

Normal updates replace program files under `/opt/easy-ha-proxy/source` and
re-render generated runtime files from the existing root-owned configuration in
`/etc/easy-ha-proxy`; they do not replace that managed configuration with files
from GitHub or from `--sync-source`. Settings changed in the web UI are first
synchronized back into the managed HAProxy subset. A newly introduced option
may remain absent from an older YAML file: its role/template default is used
until the administrator explicitly saves a different value. Explicit migration,
restore, language, domain, channel, and configuration commands change only the
settings owned by that operation and create a configuration backup first.

To schedule the deferred reboot from the controller and monitor the remote
server, run:

```bash
./install.sh remote \
  --inventory ./ansible/inventory.ini \
  --limit proxy01 \
  --action reboot
```

With SSH key or agent authentication available without another password prompt,
the controller waits until the server reports a different boot ID and SSH is
available again. In password-only mode it only confirms that the reboot was
scheduled; reconnect or run the assistant again after the server starts.

### UI diagnostic page

The technical `/debug/` page is disabled by default, so the dashboard hides its
Diagnostics button. Direct access returns a safe instruction page and
`/debug/headers` remains unavailable.

Temporarily enable it in `/etc/easy-ha-proxy/vars.yml`:

```yaml
haproxy_admin_debug_routes: true
```

Apply the installed source:

```bash
sudo easy-ha-proxy update --no-fetch
```

Return the setting to `false` and reapply after diagnostics.

## Remote machine

Launch the assistant over SSH:

```bash
bash /tmp/easy-ha-proxy-install.sh remote admin@192.0.2.10
```

The controller temporarily copies the local installer and helper to the server,
runs them through `sudo`, and removes the temporary files afterward. When
started from a checkout, local script versions are used, so unpublished
diagnostic changes do not have to be pushed first.

### SSH password

```bash
bash /tmp/easy-ha-proxy-install.sh remote \
  --host 192.0.2.10 --user admin --ask-pass
```

OpenSSH reads the password from a hidden terminal prompt. The script neither
accepts it as an argument nor stores it.

### Private key

```bash
bash /tmp/easy-ha-proxy-install.sh remote \
  --host 192.0.2.10 --user admin \
  --port 2222 --identity ~/.ssh/server
```

### Ansible INI inventory

```bash
bash /tmp/easy-ha-proxy-install.sh remote \
  --inventory ./ansible/inventory.ini --limit proxy01
```

Supported fields:

- `ansible_host`;
- `ansible_user`;
- `ansible_port` and `ansible_ssh_port`;
- `ansible_ssh_private_key_file`;
- inline host variables, `[group:vars]`, and `[all:vars]`.

`--limit` is optional when the inventory has one host. `ansible_password` is
deliberately ignored; use `--ask-pass`.

Resolve connection settings without opening SSH:

```bash
bash /tmp/easy-ha-proxy-install.sh remote \
  --inventory ./ansible/inventory.ini --limit proxy01 --dry-run
```

Run one remote action without the menu:

```bash
bash /tmp/easy-ha-proxy-install.sh remote \
  --inventory ./ansible/inventory.ini --limit proxy01 \
  --action status
```

Start a remote test installation immediately:

```bash
bash /tmp/easy-ha-proxy-install.sh remote \
  --test-mode admin@192.0.2.10
```

### Automatic legacy snapshot download

After a remote snapshot is created, the archive is normally:

1. Packed in a temporary server file with mode `0600`.
2. Downloaded to `$HOME/easy-ha-proxy-backups/legacy-<date>/`.
3. Verified against `SHA256SUMS`.
4. Extracted into `live/`.
5. Removed from the server's temporary directory.

One command is sufficient:

```bash
bash /tmp/easy-ha-proxy-install.sh remote \
  --inventory ./inventory.ini \
  --action snapshot-legacy
```

Choose another local root:

```bash
bash /tmp/easy-ha-proxy-install.sh remote \
  --inventory ./inventory.ini \
  --action snapshot-legacy \
  --snapshot-dir "$HOME/my-protected-backups"
```

Keep the snapshot only on the server:

```bash
bash /tmp/easy-ha-proxy-install.sh remote \
  --inventory ./inventory.ini \
  --action snapshot-legacy \
  --no-fetch-snapshot
```

A snapshot contains certificates, private keys, and configuration secrets. Do
not place it inside a Git repository and keep the directory mode at `0700`.

### Prepare configuration from a legacy snapshot

After downloading the snapshot:

```bash
bash ./install.sh prepare-legacy
```

The latest snapshot is selected automatically. To use an explicit `live/`
directory:

```bash
bash ./install.sh prepare-legacy \
  "$HOME/easy-ha-proxy-backups/legacy-<date>/live"
```

`prepared-config/` is created beside the snapshot with directory mode `0700`
and file mode `0600`. Preparation:

- takes `vars.yml`, `websites.yml`, and `tcp.yml` from the live UI runtime
  configuration;
- converts the current user database to `authelia_users_initial.yml`;
- restores non-secret Authelia settings;
- transfers existing Authelia and SMTP secrets without printing them;
- creates a local inventory and migration metadata.

This is a local operation: nothing is sent to the server, Ansible is not run,
and services are not changed. `prepared-config` contains secrets and must never
be committed.

### Check mode for prepared legacy configuration

After `prepared-config` exists:

```bash
bash ./install.sh plan-legacy
```

The command selects the newest prepared configuration and discovered remote
inventory, prints their paths, and requests confirmation. It then runs:

1. `ansible-playbook --syntax-check`;
2. a restricted set of update/configuration tags with `--check`;
3. read-only status tasks.

`--diff` is deliberately omitted so secret-bearing templates do not enter the
output. The full log is stored beside the snapshot as
`legacy-plan-<date>.log` with mode `0600`. Nothing is applied.

Explicit paths:

```bash
bash ./install.sh plan-legacy \
  "$HOME/easy-ha-proxy-backups/legacy-<date>/prepared-config" \
  ./inventory.ini
```

If the plan reports `Copy HAProxy configuration`, inspect a separate protected
diff before applying anything:

```bash
bash ./install.sh diff-legacy-haproxy
```

This runs only `ha-cfg` with `--check --diff`, validates the rendered
configuration with `haproxy -c`, and saves
`legacy-haproxy-diff-<date>.log` with mode `0600`. HAProxy is not reloaded.

### Adopt a legacy server

After `plan-legacy` succeeds and the HAProxy diff has been reviewed:

```bash
bash ./install.sh stage-legacy
```

The latest prepared configuration and inventory are selected automatically.
Explicit paths and host alias:

```bash
bash ./install.sh stage-legacy \
  "$HOME/easy-ha-proxy-backups/legacy-<date>/prepared-config" \
  ./inventory.ini \
  proxy01
```

The target and paths are shown before the exact `STAGE` confirmation. The
command:

- transfers reviewed local source without controller inventory, Vault, backups,
  obsolete PEM files, or archives;
- installs prepared configuration under `/etc/easy-ha-proxy` with `0700/0600`
  permissions;
- creates `/opt/easy-ha-proxy/source`, the private Python venv, and the
  `easy-ha-proxy`/`easy-ha-proxy-assistant` commands;
- stops when target directories already exist.

No playbook runs at this stage. Images are not downloaded, services are not
restarted, and active HAProxy/Authelia/UI configuration remains unchanged.
After staging, run the read-only server plan:

```bash
sudo easy-ha-proxy plan
```

If it completes with `failed=0`, services remain healthy, and the only real
configuration change is synchronization of `haproxy.cfg.j2` for the UI,
finalize adoption:

```bash
bash ./install.sh finalize-legacy
```

The command requires `APPLY`, runs only `ha-adm-cfg,status`, and saves
`legacy-finalize-<date>.log`. It does not update Docker, download images, or
replace active `/etc/haproxy/haproxy.cfg`. It synchronizes the template the UI
will use for later site changes.

### Synchronize local source

Source and image channels are independent. `github` refreshes the managed
checkout from `main`; `local` applies the tree already synchronized to the
server. `latest` is the release UI image and `alpha` is the test image.

To test changes that are not published yet and immediately apply them with an
already published `alpha` image:

```bash
bash ./install.sh remote \
  --inventory ./inventory.ini \
  --limit proxy01 \
  --sync-source . \
  --apply \
  --image alpha
```

After `SYNC` confirmation, the existing source is atomically moved to
`source.before-sync.<date>` and the new source becomes
`/opt/easy-ha-proxy/source`. With `--apply`, the installer saves the `local`
source channel, switches the UI to `alpha`, refreshes runtime dependencies, and
applies the complete stack. Without `--apply`, configuration, images, and
services do not change and no playbook runs.

Then inspect and plan remotely:

```bash
bash ./install.sh remote \
  --inventory ansible/inventory.ini \
  --limit proxy01 \
  --action check-updates

bash ./install.sh remote \
  --inventory ansible/inventory.ini \
  --limit proxy01 \
  --action plan
```

A normal release update explicitly returns to GitHub and `latest`:

```bash
bash ./install.sh remote --inventory ./inventory.ini --limit proxy01 \
  --action update --source github --image latest
```

The selected channels are stored in managed metadata. `apply-current` remains
an alias for applying synchronized source without contacting GitHub.
`update-ui` also does not update source; it fetches the selected UI image and
applies only the compatible protection layer: HAProxy admin header, internal
secret, and helper daemons.

For a remote menu connection, `repair`, or wizard restart, the controller
compares a content fingerprint of its installer files with
`/opt/easy-ha-proxy/source`. If they differ, it offers to upload the current
local version atomically before continuing; the previous tree is preserved as
`source.before-<action>.<timestamp>`. `--source local` selects this
synchronization explicitly, while `--source github` makes `repair` refresh the
managed GitHub checkout first.

### Local GeoIP database

The UI and HAProxy country ACL use the same DB-IP Country Lite MMDB release in
`/etc/haproxy/geoip/current/`. A daily persistent systemd timer retries at the
start of a month but performs no download once that month's release is active.
The updater validates IPv4/IPv6 data, atomically switches MMDB and ACL together,
reloads HAProxy only when the ACL changed, and rolls back if HAProxy or its
administration/Authelia HTTPS checks fail.

```bash
sudo systemctl status easy-ha-proxy-geoip-update.timer
sudo systemctl start easy-ha-proxy-geoip-update.service
sudo journalctl -u easy-ha-proxy-geoip-update.service -n 50 --no-pager
```

The local database remains enabled for UI country display when access filtering
is disabled. GeoIP is approximate and must not replace authentication or an IP
allow list.

Quick GeoIP update FAQ:

- **Is the MMDB committed to Git or baked into the image?** No. `*.mmdb` and
  `*.mmdb.gz` are ignored; the managed server downloads the licensed data.
- **What happens to the old GitHub/IPdeny updater?** The next full apply removes
  its Ansible cron entry and installs the DB-IP systemd timer. The old
  `allowed.geo` stays usable until the new release passes validation.
- **Does the daily timer download and rebuild daily?** No. An unchanged current
  month and country selection exits after a local state and checksum check. A
  full pass happens
  for a new monthly database or a changed country list.
- **How do I force a check?** Run
  `sudo /usr/local/bin/update-geoip.sh --force-download` and inspect its journal.
- **What happens on an outage or bad release?** Existing installs keep their
  active release. A first install can continue without country display only
  when HAProxy GeoIP access filtering is disabled.
- **What about a very old unmanaged installation?** Do not run a full apply
  directly. Use `snapshot-legacy`, `prepare-legacy`, `plan-legacy`,
  `stage-legacy`, and `finalize-legacy` first; after adoption, run a normal full
  update to migrate the GeoIP updater and UI.

## Selective updates in HAProxy Admin

After one current full installation/update, a `superadmin` can open
**Software updates**. A check is read-only and contacts only the configured Git
remote, registries for the two managed Compose stacks, and the current APT
cache. The result lists actionable source, host-service, daemon, Authelia,
HAProxy Admin, and OS-package components; unknown registry/network states are
shown but cannot be selected.

Apply requires a fresh expiring plan, a service-restart acknowledgement, and
the exact `UPDATE` confirmation. `easy-ha-proxy-updated.service` runs the fixed
CLI component allowlist asynchronously, stores bounded progress on the host,
and remains available while the HAProxy Admin container updates itself. A full
source selection supersedes its nested service/container choices; OS packages
always run last. The broker neither accepts arbitrary commands nor reboots the
server. It also refuses source/host updates during a pending HAProxy apply and
shares the backup/restore operation lock.

The web page cannot upload a developer checkout. For uncommitted local changes,
continue to use controller `--sync-source . --apply`; the web page then manages
the already synchronized source and published `alpha`/`latest` image channel.

## Full encrypted backup and migration to a new server

### Web interface

After a normal installation, a `superadmin` can open **Backup & restore** in the
HAProxy Admin interface. The page supports two common operations:

1. Create a consistent encrypted snapshot, wait for the durable host job, then
   download the `.enc` archive and its `.sha256` checksum.
2. On the same server, select a retained snapshot with **Restore**. On another
   freshly installed easy-ha-proxy server, upload the downloaded `.enc` file.
   Enter its passphrase to inspect and validate it without changing the host,
   review the source hostname/date/SSH metadata, and type `RESTORE` to replace
   the managed state and run full reconciliation.

`easy-ha-proxy-backupd.service` owns the privileged work. The application can
only submit fixed job IDs and stream files through a dedicated spool outside the
backup payload; it cannot pass arbitrary root paths or commands. Jobs and
server-side artifacts survive an application-container restart. Only one
backup/inspect/restore job runs at a time, orphan uploads expire automatically,
and passphrases are passed to the worker over stdin but are never written to job
state, process arguments, environment variables, or logs.

The browser workflow requires an installed easy-ha-proxy control plane. Use the
controller `restore-full ... fresh` command below for a truly empty OS. Web
restore uses exact replacement only for fixed easy-ha-proxy-managed roots; it
does not delete unrelated OS, SSH, home, or third-party Docker data. A protected
pre-restore snapshot is created while managed services are quiesced and is
automatically reapplied if extraction or reconciliation fails. It is deleted
after success or a successful rollback and is preserved in
`/var/backups/easy-ha-proxy/pre-restore-*` only if automatic rollback fails.

Create a disaster-recovery backup from the controller:

```bash
bash ./install.sh backup-full inventory-production.ini proxy01
```

The command asks:

1. Whether to include SSH host/private/authorized keys.
2. Whether a short managed-container and helper-daemon pause is allowed for a
   consistent snapshot.
3. For an encryption passphrase of at least 12 characters, entered twice.

The server creates `/var/backups/easy-ha-proxy/full-<date>/`. The encrypted
archive and `.sha256` file are downloaded automatically to
`$HOME/easy-ha-proxy-backups/full-<date>/`.

The core payload contains:

- `/etc/easy-ha-proxy` configuration, metadata, and secrets;
- the exact `/opt/easy-ha-proxy/source` version without its disposable venv;
- HAProxy, GeoIP, managed iptables ban rules, AppArmor, rsyslog, logrotate, and
  sysctl configuration;
- all of `/etc/letsencrypt`, including accounts, renewal configuration, and
  `renewal-hooks/pre`, `deploy`, and `post` scripts;
- Authelia configuration, user database, Redis data, templates, and logs;
- HAProxy Admin runtime configuration, data, and backups;
- systemd units/drop-ins and all managed helper scripts;
- OS, package, systemd, container, and image-digest manifests.

Container images, system packages, and the Python venv are not copied; the
installer reproduces them for the new server architecture.

`/etc/iptables/rules.v4` and `rules.v6` are runtime snapshots rather than
portable configuration on a Docker host. When found in an old backup, restore
renames them to `*.restored-disabled.*` and does not apply them through
`iptables-persistent`.

### Restore to a clean server

The target needs Debian/Ubuntu with systemd, SSH access, and `sudo`. An existing
easy-ha-proxy installation is not required:

```bash
bash ./install.sh restore-full \
  "$HOME/easy-ha-proxy-backups/full-<date>/easy-ha-proxy-full-<date>.tar.gz.enc" \
  inventory-new.ini \
  proxy-new \
  fresh
```

### Restore over an existing server

```bash
bash ./install.sh restore-full \
  "$HOME/easy-ha-proxy-backups/full-<date>/easy-ha-proxy-full-<date>.tar.gz.enc" \
  inventory-production.ini \
  proxy01 \
  overlay
```

The default `auto` mode selects `overlay` for a managed installation and
`fresh` otherwise. Upload requires `UPLOAD` confirmation and extraction
requires `RESTORE`.

Restore:

1. Checks the external SHA-256, decrypts the archive, and validates internal
   checksums, path allowlists, expanded sizes, and available space before
   stopping managed services.
2. Creates short-lived protected rollback data in
   `/var/backups/easy-ha-proxy/pre-restore-<date>-<pid>/`. It is removed after
   success and retained for console recovery only if automatic rollback fails.
3. Separately asks whether to apply the SSH payload.
4. Merges existing `authorized_keys` and does not restart sshd.
5. Restores data, preserves archived source as
   `/opt/easy-ha-proxy/source.from-backup.<date>.<pid>`, activates current
   recovery source from the controller, rebuilds the venv, installs
   dependencies, and applies configuration. Restored iptables runtime snapshots
   are disabled before Ansible starts.
6. Does not reissue certificates automatically; restored certificates and
   Certbot renewal state are used.

The passphrase is never stored or restored. Keep it separately from the `.enc`
and `.sha256` files. If SSH host keys are restored, the new server fingerprint
becomes identical to the source server; remove the old `known_hosts` entry only
after verifying the fingerprint through a trusted channel.

## Change the root domain

Run managed root-domain migration remotely:

```bash
bash ./install.sh remote \
  --inventory ansible/inventory.ini \
  --limit proxy01 \
  --action migrate-domain
```

Or directly on the server:

```bash
sudo easy-ha-proxy migrate-domain
```

For a migration from `old.example.com` to `new.example.net`, the command:

1. Uses current UI runtime `vars.yml`, `websites.yml`, and `tcp.yml` so recently
   added sites are preserved.
2. Replaces the old suffix in HAProxy sites, alternate names, backend hosts,
   Authelia domain/cookie/ACL values, metadata, and service URLs.
3. Does not change `secrets.yml` or the Authelia user database.
4. Displays every replacement.
5. Checks new A/AAAA records with public DNS resolvers. Missing records are
   warnings; Let's Encrypt issuance for unresolved names is postponed.
6. Builds temporary configuration and runs syntax-check plus Ansible check mode
   without `--diff`.
7. Only after exact `MIGRATE` confirmation creates a protected backup, issues
   new certificates, and applies the domain configuration.
8. Restores previous managed/runtime configuration and attempts to reapply the
   old domain on failure.

Old certificates are not removed immediately, allowing manual rollback.
Authelia sessions bound to the previous cookie domain may require login again.

Plan only from the workstation:

```bash
bash ./install.sh remote \
  --inventory ansible/inventory.ini \
  --limit proxy01 \
  --action migrate-domain \
  --new-domain new.example.net \
  --plan-only
```

Create public DNS records before using Let's Encrypt. Internal CA production
deployments can use private DNS or hosts entries. An unresolved name is shown
as a warning and does not stop installation or migration; `--skip-dns-check`
also suppresses this diagnostic.

### Promote test mode to production

Test mode is not a disposable installation. Promote it in place:

```bash
sudo easy-ha-proxy promote-production \
  --new-domain example.com \
  --certificate-source internal \
  --image latest
```

Or remotely:

```bash
bash ./install.sh remote --inventory ./inventory.ini --limit proxy01 \
  --action promote-production --new-domain example.com \
  --certificate-source internal --image latest
```

The command reads current UI runtime sites and TCP proxies, replaces the old
test suffix, preserves users, secrets and backend settings, changes the mode
and image channel, runs Ansible check mode, and requires exact `PROMOTE`
confirmation. Select `letsencrypt` when public DNS is ready, or keep `internal`
for a private production network. `--plan-only` performs no writes.

## Installation-state detection

A complete managed installation requires all of:

- `/usr/local/bin/easy-ha-proxy` or the internal CLI;
- `/etc/easy-ha-proxy/metadata.yml`;
- `/opt/easy-ha-proxy/venv/bin/python`;
- `/opt/easy-ha-proxy/source/ansible/easy-ha-proxy.yml`.

The configuration also records completion only after the main playbook
succeeds. If preparation or installation is interrupted, the next assistant
run shows a recovery menu with:

- continue using the saved configuration and already prepared source;
- restart the production or test wizard after backing up the old config;
- configuration and service diagnostics.

If the local installer differs from the source prepared on the server, the
controller offers to update it before showing the recovery menu. The check is
content-based, so it also detects local changes that have not been committed.

Restarting the wizard preserves current sites, TCP proxies, users, secrets,
Authelia rules, mail settings, unknown future options, and values that the
wizard did not explicitly change. Existing YAML is parsed before a backup or
write; invalid managed YAML stops the operation without rotating secrets.
The status screen lists host services separately as informational
prerequisites; active systemd journal, AppArmor, cron, or rsyslog do not mean
that easy-ha-proxy is installed.

When working HAProxy, Authelia, and haproxy-admin configuration exists without
the new CLI, the assistant reports a working legacy installation. Missing
`/etc/easy-ha-proxy` alone is not treated as an error.

Only safe legacy actions are offered:

- validation of live HAProxy and Compose configuration;
- systemd, Docker, and port 80/443/5000/9091 diagnostics;
- protected snapshot creation under `/var/backups/easy-ha-proxy`;
- migration-plan display;
- update checks without installation.

Production/test installation is deliberately hidden from the legacy menu.
First preserve a snapshot, convert the original Ansible/Vault data, run check
mode, and review the protected diff.

If only some components are found and a healthy legacy stack cannot be
confirmed, the state is reported as partial/incomplete.

## Limitations

- Target: Debian 12+ or Ubuntu 22.04+, systemd, `amd64` or `arm64`.
- Let's Encrypt requires correct public A/AAAA records and reachable ports
  80/443. Internal CA production can use private DNS.
- Remote control requires `bash`, `curl`, `ssh`, and `scp`; controller-side
  Ansible is not required.
- The target must be able to reach the configured repository. Anonymous GitHub
  raw downloads require a public repository.
- Container checks compare local `RepoDigest` with the remote manifest through
  `docker buildx imagetools inspect`. Images are pulled only by `update` or
  `update-ui`.
- Status output includes all server containers and their names. Full `update`
  refreshes only easy-ha-proxy Compose stacks (UI and Authelia); unrelated
  containers are informational and are not changed automatically.
