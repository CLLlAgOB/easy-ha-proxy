# Deploying easy-ha-proxy by hand

The main playbook `easy-ha-proxy.yml` installs and configures HAProxy, Certbot, the GeoIP ACL, Authelia, the Docker build of `haproxy-admin` and the helper systemd daemons.

For a single server the `easy-ha-proxy` command is the recommended way: it installs a local Ansible in a venv and runs this same playbook. This document describes the manual remote mode. [Русская версия](README.ru.md).

## Requirements

- a control machine with Ansible;
- a Debian/Ubuntu target host with SSH and `sudo`;
- the `ansible.posix` and `community.docker` collections;
- Docker Compose v2 on the target host for the container services;
- the Ansible Vault password for the `group_vars/all/*.yml` files.

Installing the collections:

```bash
cd ansible
ansible-galaxy collection install -r requirements.yml
```

## Local configuration

By default `easy-ha-proxy.yml` expects the group `easy_ha_proxy` in a manual `inventory.ini` and loads:

- `vars.yml` -- domains, HAProxy, Certbot, SMTP and general settings;
- `authelia.yml` -- Authelia's non-secret settings;
- `authelia_users_initial.yml` -- the initial users;
- `websites.yml` -- the HTTP/HTTPS sites;
- `tcp.yml` -- the TCP proxies.

`inventory.ini`, `vars.yml`, `websites.yml`, `tcp.yml`,
`authelia_users_initial.yml` and the whole of `group_vars/` are local files
and are kept out of Git. Not even Vault-encrypted files are published: a Vault
password can leak or be guessed separately.

A minimal inventory:

```ini
[easy_ha_proxy]
proxy01 ansible_host=203.0.113.10 ansible_user=ansible
```

Before the first run, replace the initial users and the Argon2 hashes in `authelia_users_initial.yml`. Do not keep comments with the original passwords next to them.

## Checking and running

From the `ansible/` directory:

```bash
ansible-playbook --syntax-check -i inventory.ini easy-ha-proxy.yml
ansible-playbook -i inventory.ini easy-ha-proxy.yml --list-tags
ansible-playbook -i inventory.ini easy-ha-proxy.yml
```

A full run updates packages, issues certificates and changes the system
configuration. With `ansible_connection=local` a reboot is always left to the
helper or the administrator to decide. An automatic reboot of a host managed
over SSH is switched on only explicitly: `-e easy_ha_proxy_reboot_after_upgrade=true`.
For targeted operations use the tags:

| Purpose | Tag |
| --- | --- |
| OS update | `upgrade` |
| Installing Certbot and issuing certificates | `cert` |
| Installing Certbot | `crt-install` |
| Certbot hooks | `crt-hooks` |
| Renewing/issuing | `crt-renew` |
| Installing HAProxy | `ha-install` |
| HAProxy configuration | `ha-cfg` |
| AppArmor | `apparmor` |
| GeoIP ACL | `geo` |
| Installing Docker Engine/Compose | `docker` |
| Installing Authelia | `aut-install` or `authelia` |
| Installing the UI and the daemons | `ha-adm-install` |
| UI configuration | `ha-adm-cfg` |
| Starting the UI | `ha-adm-start` |
| Health daemon | `ha-adm-healthd` |
| Control daemon | `ha-adm-controld` |
| Every helper daemon (a targeted update) | `ha-adm-daemons,aut-daemons` |
| The whole host-side service layer | CLI: `update --component services` |
| State check | `status` |
| Adding a site | `addsite` |

Examples:

```bash
ansible-playbook -i inventory.ini easy-ha-proxy.yml -t ha-install,ha-cfg
ansible-playbook -i inventory.ini easy-ha-proxy.yml -t aut-install
ansible-playbook -i inventory.ini easy-ha-proxy.yml -t ha-adm-install,ha-adm-cfg,ha-adm-start
ansible-playbook -i inventory.ini easy-ha-proxy.yml -t addsite
ansible-playbook -i inventory.ini easy-ha-proxy.yml -t ha-adm-daemons,aut-daemons,status
ansible-playbook -i inventory.ini easy-ha-proxy.yml -t status
```

The targeted daemon stage copies every managed daemon script idempotently:
services whose files did not change are not restarted. The full status check
also covers the iptables loader, the systemd timers, journald, Certbot,
cron/logrotate, the APT/Snap versions and the checksums of the other managed
scripts, hooks and Lua files.

Dangerous or rare scenarios carry the `never` tag and run only when named: `remove_site`, `aut-remove`, `aut-cfg`, `aut-users`, `ha-adm-update`, `ha-add-adm-ip`, `crt-rdg`, `crt-test`.

## Components

### HAProxy

The `haproxy` role installs the service, the runtime socket, the ACLs, the GeoIP filtering and the rate/error limits, and renders `/etc/haproxy/haproxy.cfg`. The configuration is validated with `haproxy -c` before it is applied.

### Certificates

The `cert` role uses the snap build of Certbot, joins `fullchain.pem + privkey.pem` for HAProxy and reloads the service. The joined PEMs hold the private key and must have a mode no wider than `0640`.

### Authelia

Authelia and Redis run through Compose in `/opt/authelia`. Ansible creates the configuration, the users and the SMTP `.env`. Secrets must come from the Vault.

### haproxy-admin

The UI listens only on `127.0.0.1:5000` and is published through HAProxy. The container talks to root daemons over UNIX sockets, among them:

- `haproxy-controld`, `haproxy-certd`, `haproxy-healthd`;
- `easy-ha-proxy-guardd`, `easy-ha-proxy-metricsd`, `easy-ha-proxy-alertd`,
  `easy-ha-proxy-backupd`, `easy-ha-proxy-updated`;
- `authelia-configd`, `authelia-usersd`, `authelia-bansd`.

The `/debug/` and `/debug/headers` routes are off by default and the
diagnostics button is hidden. Opening `/debug/` directly shows instructions.
To switch them on for a while, add to the managed `vars.yml`:

```yaml
haproxy_admin_debug_routes: true
```

Then run `sudo easy-ha-proxy update --no-fetch`. After the diagnostics, set it
back to `false` and apply the configuration again.

## Diagnostics

```bash
haproxy -c -f /etc/haproxy/haproxy.cfg
systemctl status haproxy haproxy-controld haproxy-certd haproxy-healthd
journalctl -u haproxy -u haproxy-controld -u haproxy-certd -n 200
docker compose -f /opt/authelia/docker-compose.yml ps
docker compose -f /opt/haproxy-admin/docker-compose.yml ps
```

The main paths:

- HAProxy: `/etc/haproxy/haproxy.cfg`;
- HAProxy certificates: `/etc/haproxy/certs/`;
- Authelia: `/opt/authelia/`;
- UI: `/opt/haproxy-admin/`;
- HAProxy runtime socket: `/run/haproxy/admin.sock`.

## Security

- Do not expose ports `5000` and `9091`: authorisation is designed around coming in through HAProxy/Authelia.
- After a private key leaks, deleting the PEM from Git is not enough -- reissue the certificate and treat the old key as compromised.
- The UI's state-changing requests are protected by CSRF tokens; independently of that, access to the UI must be limited to trusted users and a trusted domain.
