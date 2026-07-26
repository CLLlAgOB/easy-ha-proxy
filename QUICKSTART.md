# easy-ha-proxy Quick Start

[English](QUICKSTART.md) | [Русский](QUICKSTART.ru.md)

This guide covers the shortest supported path to a first installation. For
maintenance, migration, backup, and recovery, continue with the full
[installer guide](INSTALLER_README.md).

## Before you start

The target must be Debian 12+ or Ubuntu 22.04+, use systemd, and have an
`amd64` or `arm64` CPU. You need root or working `sudo` access.

For production:

- point the administration and Authelia DNS A/AAAA records to the server;
- allow inbound TCP 80 and 443;
- allow outbound access to package repositories, GitHub, Python package index,
  Ansible Galaxy, the container registry, Snap, Let's Encrypt, and DB-IP GeoIP
  data during installation and periodic database updates.

For a remote installation, the workstation needs `bash`, `curl`, `ssh`, and
`scp`.

## 1. Download and inspect the assistant

```bash
curl -fsSLo /tmp/easy-ha-proxy-install.sh \
  https://raw.githubusercontent.com/CLLlAgOB/easy-ha-proxy/main/install.sh
```

Review the saved file with your preferred editor or pager, then run it:

```bash
bash /tmp/easy-ha-proxy-install.sh
```

Choose English or Russian at the first prompt. Press Enter to use the default,
English. That selection is also used for Authelia notification emails created
by the initial configuration wizard.

The assistant detects whether the current machine is clean, partially
configured, or already managed.

## 2. Choose an installation path

Install or manage the current server:

```bash
bash /tmp/easy-ha-proxy-install.sh local
```

Manage a remote server through existing SSH configuration:

```bash
bash /tmp/easy-ha-proxy-install.sh remote admin@server.example.com
```

Use a private key and a non-default port:

```bash
bash /tmp/easy-ha-proxy-install.sh remote \
  --host 192.0.2.10 --user admin \
  --port 2222 --identity ~/.ssh/server
```

Use an SSH password prompt without exposing the password in shell history:

```bash
bash /tmp/easy-ha-proxy-install.sh remote \
  --host 192.0.2.10 --user admin --ask-pass
```

## 3. Use test mode when public DNS is unavailable

```bash
bash /tmp/easy-ha-proxy-install.sh local --test-mode
```

Test mode uses `.test` domains and a local CA. It skips public DNS validation
and initial public issuance, while installing Certbot for later per-site use.
The assistant prints a hosts-file entry and the path of the public root CA
export after installation.

Promote a working test stack without reinstalling:

```bash
sudo easy-ha-proxy promote-production --new-domain example.com \
  --certificate-source internal --image latest
```

Choose `letsencrypt` when public DNS is ready. Unresolved DNS names are warnings
and only postpone initial Let's Encrypt issuance.

## 4. Complete the wizard

Prepare these values:

- initial administration certificate source: `letsencrypt` or `internal`;
- root, administration, and Authelia domains;
- Let's Encrypt or administrator email and timezone;
- optional allowed IP/CIDR ranges and GeoIP countries;
- the first `superadmin` login, display name, email, and password;
- optional SMTP settings.

Generated secrets are stored under `/etc/easy-ha-proxy` with root-only
permissions.

Country lookup and HAProxy GeoIP filtering use one local DB-IP Country Lite
database. The installer derives IPv4/IPv6 ACLs locally and bundles country
flags; visitor addresses are not sent to public GeoIP or flag services.

For a non-public/private installation you may run the local installer with
`--certificate-source internal`. After the first installation, an external CA
root/intermediate bundle and its server certificates can be imported from
`/haproxy/certs`.

## 5. Verify and maintain the installation

Release update from GitHub:

```bash
./install.sh remote --inventory ./inventory.ini --limit my_server \
  --action update --source github --image latest
```

Test synchronized local changes with an already published `alpha` image:

```bash
./install.sh remote --inventory ./inventory.ini --limit my_server \
  --sync-source . --apply --image alpha
```

```bash
sudo easy-ha-proxy status
sudo easy-ha-proxy plan
sudo easy-ha-proxy update
sudo easy-ha-proxy-assistant check-updates
```

After the first current full update, a `superadmin` can also open **Software
updates** in HAProxy Admin, check individual components, and install selected
updates. The page reconnects when it updates its own container and never
reboots the server automatically.

Do not expose UI port `5000` or Authelia port `9091` directly. Continue with
the [full installer guide](INSTALLER_README.md) before performing backup,
restore, domain migration, or legacy adoption.
