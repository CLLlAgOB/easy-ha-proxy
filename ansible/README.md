# The playbook and the roles

`easy-ha-proxy.yml` and the roles under `roles/` describe the gateway:
HAProxy, Certbot, the GeoIP ACL, Authelia, the `haproxy-admin` container and
the helper systemd daemons. The installer agent (`easy-ha-proxy-agent apply
playbook`) reads them on the server -- the playbook's entries and tags, the
roles' defaults, templates and files -- and changes only what differs from
the host. Ansible is not involved. [Русская версия](README.ru.md).

The `easy-ha-proxy` command is the way to install and update. The managed
configuration lives in `/etc/easy-ha-proxy` (`vars.yml`, `authelia.yml`,
`authelia_users_initial.yml`, `websites.yml`, `tcp.yml`, `secrets.yml`,
`inventory.ini`) and never in Git.

## Running entries

A targeted run takes the playbook's tags; `--check` shows what would change
and changes nothing:

```bash
sudo easy-ha-proxy-agent apply playbook --check --tags status \
  --source /opt/easy-ha-proxy/source --config /etc/easy-ha-proxy
sudo easy-ha-proxy-agent apply playbook --tags ha-install,ha-cfg \
  --source /opt/easy-ha-proxy/source --config /etc/easy-ha-proxy
```

An untagged run includes OS package upgrades and never reboots: the
assistant asks after an upgrade and defaults to deferring the reboot.

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

The targeted daemon stage copies every managed daemon script idempotently:
services whose files did not change are not restarted. The full status check
also covers the iptables loader, the systemd timers, journald, Certbot,
cron/logrotate, the APT/Snap versions and the checksums of the other managed
scripts, hooks and Lua files.

Scenarios outside a normal update carry the `never` tag and run only when named: `aut-cfg`, `aut-daemons`, `aut-update`, `ha-adm-daemons`, `ha-adm-update`. The installer only installs and updates; sites, users, admin addresses and every other setting are changed in the web panel (the main domain with `easy-ha-proxy migrate-domain`).

## Components

### HAProxy

The `haproxy` role installs the service, the runtime socket, the ACLs, the GeoIP filtering and the rate/error limits, and renders `/etc/haproxy/haproxy.cfg`. The configuration is validated with `haproxy -c` before it is applied.

### Certificates

The `cert` role uses the snap build of Certbot, joins `fullchain.pem + privkey.pem` for HAProxy and reloads the service. The joined PEMs hold the private key and must have a mode no wider than `0640`.

### Authelia

Authelia and Redis run through Compose in `/opt/authelia`. The installer creates the configuration, the initial users and the SMTP `.env`; secrets come from the managed `secrets.yml`.

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
