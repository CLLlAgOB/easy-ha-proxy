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

#### DNS-01 and wildcard certificates

A Let's Encrypt site answers the ACME challenge over HTTP-01 on port 80 by
default. Where that port is unreachable -- and always for a wildcard -- the
site can validate over **DNS-01** instead.

Save the provider credentials once on `/haproxy/certs/dns-providers` as a named
profile. Cloudflare, DigitalOcean, Route 53, and RFC 2136 are supported.
Credentials are written root-only under `/etc/easy-ha-proxy/dns-providers` and
are never sent back to the browser: to change one, enter it again. Each
provider needs its Certbot plugin, which is a snap here because Certbot itself
is; list the ones you use in `dns_plugins_enabled` and the installer adds them.

Then, in the site editor, switch **Validation** to DNS-01 and pick the profile.
Two name lists apply:

- **Alt names (SAN)** are routing names. HAProxy matches them literally, so a
  wildcard is refused here -- it would build a configuration that validates and
  then routes nothing.
- **Extra certificate names** only widen the certificate. `*.example.com`
  belongs here, and afterwards new subdomains can be added to alt names without
  reissuing anything.

Certbot records the chosen plugin and credentials path in its own renewal
configuration, so renewals continue unattended. The install-time Ansible path
only knows HTTP-01; it leaves DNS-01 sites to the gateway, which issues them
when you press the button or apply the configuration.

For installations created before 2026-07-04, perform one complete
`sudo easy-ha-proxy update` before using targeted updates.

### Alerts

Every part of the gateway reports what it sees; one daemon decides what is
worth telling you about. Before it existed, a full metrics disk or the security
engine starting to ban people was something you found by reading the journal.

A condition is either a **level** or an **event**, and the difference is what
makes the rest work. A backend being down is a level: it stays true, it can
recover, and waiting five minutes before shouting is right. A failed backup is
an event: it already happened, there is no "still failing" to observe and no
recovery to wait for.

What the engine holds back is the point:

- nothing is sent until a level has held for its delay;
- a firing condition stays quiet until its repeat window;
- a burst is capped, so one bad minute cannot become forty messages -- the
  held-back ones stay in the history;
- recovery is announced, and is never held back by the cap;
- a condition that gets worse says so at once instead of waiting.

A level nobody reports any more is treated as resolved. A producer that dies
must not leave an alert pinned open.

Delay and recipient can also belong to the object rather than the rule: a site
keeps its own `alert_after` and `alert_email` from its settings.

Email uses the same notification settings as certificate notices. The optional
**webhook** posts one JSON object per notification over HTTPS only. The host is
resolved once and the connection is made to exactly that address, so a name
that answers differently on the second lookup cannot redirect the request into
your network; loopback and link-local are refused, private addresses only with
an explicit switch, and redirects are never followed. The URL and the secret
header are stored root-only and are never sent back to the browser.

Reporting is best effort by contract. A stopped alert daemon costs a
notification -- never a metrics sample, a ban, or a reload.

### Off-host backup copies

An encrypted archive sitting on the server it would be used to rebuild is not
a backup of that server. A **destination** on `/system/backups` pushes the
finished archive somewhere else over SFTP. Only the already-encrypted file
moves: the passphrase stays on the gateway and nothing is unpacked on the way.

Two rules make this safe rather than merely convenient.

The far end must be the one you pinned. The host key is saved with the
destination and strict checking stays on -- copying to whoever answers on that
address is a way to hand someone an archive to attack at their leisure. Saving
a destination without a host key is refused, not defaulted. Take it from
`ssh-keyscan` and check it against what the far end reports.

Nothing older is deleted until the new copy is proven. Verification asks the
far end to hash the file, and falls back to reading it back and hashing it
here when there is no shell there. If neither works, the copy is reported as
unverified and the retention policy does not run at all. The archive is also
uploaded under a `.part` name and renamed, so an interrupted transfer cannot
look like a finished backup to whatever prunes next.

A **schedule** can make and send a backup unattended. That needs a passphrase
stored on this host, which is a real weakening and is treated as one: the
schedule refuses to arm without it rather than quietly producing a weaker
archive, and it protects the archive wherever it is sent rather than against
someone who already owns the gateway. The timer only asks the daemon to run,
so a scheduled backup takes the same maintenance lock as everything else and
cannot race a restore or an update.

**S3-compatible storage** works the same way, with a better proof. The
upload carries the archive's SHA-256 inside its SigV4 signature, so the
storage service refuses a body that does not hash to it -- a successful upload
is already evidence the far end holds exactly these bytes, with no second
transfer. Signing is done against the standard library rather than by adding
an SDK to the gateway, and it is verified against a real S3 implementation
rather than only against itself. A plain `http://` endpoint needs an explicit
opt-in.

### Request identifier

Every request gets one identifier, minted at the edge. It is written to the
access log, forwarded upstream as `X-Request-ID`, and returned to the client
in the same header -- so a user can quote one string from a failed page and it
can be found in the log and in the application behind it.

A client-supplied `X-Request-ID` is discarded, not echoed. Trusting it would
let anyone make two unrelated requests share an identifier, and a log search
that returns two different requests is worse than one that returns none.

The identifier is placed before the request line in the log format on purpose:
the adaptive protection engine anchors its parser on the request line at the
end, so this stays out of its way. Set `request_id_enabled: false` to turn the
whole thing off.

### Log Explorer

Off by default. When it is on, the security engine writes every request it
already reads into a separate bounded store, and the **Request log** page
searches it by time, status, client address, host, backend, path prefix and
request identifier -- so a user quoting one `X-Request-ID` is enough to find
what happened.

It is a window, not a log pipeline, and the numbers say why: a day of traffic
on a small production gateway is about 310,000 records. The size cap is
therefore what actually holds the store down, not the retention window, and
the oldest rows are dropped to stay inside it. Below that sits the same rule
the metrics collector follows -- writing stops before the filesystem
free-space reserve is touched, because diagnostics must never be the reason
the gateway runs out of disk.

What is never stored: the query string, which the engine drops before anything
reaches the store, and any header, cookie or body, which the access log does
not contain in the first place. There is no list of sensitive parameters to
keep up to date because there are no parameters.

The store rides on the same read of the same file the security engine already
does, so it costs no extra I/O -- but it is independent of it: requests from
allow-listed addresses are excluded from scoring and still recorded here, and
the explorer keeps working with adaptive protection switched off.

### Prometheus export

Off by default, because Prometheus is not a required service here. When it is
switched on, `/metrics` on the administration domain serves what the gateway
already knows: backend health, monitoring storage state, adaptive protection
counts, alert state, certificate days remaining, and whether the last backup
and update succeeded.

A scraper cannot complete an Authelia login, so this is the only path besides
the local readiness probe that HAProxy lets past it -- and it is let past only
for an address in `metrics_scrape_sources`, which defaults to this host alone.
That is one gate. The endpoint itself demands a bearer token, which is the
other, and enabling the export without setting one stops the installation
rather than quietly publishing the metrics. The request is marked with a
least-privilege identity that the application accepts for that single GET and
refuses everywhere else.

No visitor address appears anywhere in the output. Reputation is exported as
counts per state, not per address, and every label is bounded and stripped of
anything that could end a line.

A daemon that is not answering costs its own metrics and nothing else;
`easy_ha_proxy_source_up` says which one it was.

### Configuration history

Applying a configuration change is already guarded: the gateway snapshots the
running configuration, applies the candidate, verifies that the control plane
still answers, and restores the previous one automatically if anything fails --
with a confirmation window, after which an unconfirmed change rolls itself
back. **Configuration history** adds the part that was missing: every confirmed
version is kept, so a change from last week can still be inspected.

What is compared is the managed model -- sites, TCP proxies and variables --
not the generated HAProxy file. A moved backend reads as

```text
site  shop      modified
        backend_ip: 192.168.1.10 → 192.168.1.11
site  docs      added
```

rather than as a thousand-line diff of generated output. Reordering entries in
a file is not reported as a change, because the order carries no meaning and
would bury the edit that does.

Versions live in `/var/lib/easy-ha-proxy/config-history/`, each holding the
three managed YAML files plus metadata: when, which transaction, the parent
version and a content hash. The last 50 are kept. Recording is best-effort --
a change that already succeeded is never undone because its history could not
be written -- and confirming a change that altered nothing adds no duplicate.

Restoring a version puts its files back and applies them through the ordinary
guarded path -- nothing about the restore is special. The configuration is
rendered and validated, the guard that stops you removing your own
administrative access runs against your current address, and the change still
has to be confirmed before its deadline or it rolls itself back. If any of that
refuses, the managed files are returned to exactly what they were, so a
rejected restore leaves nothing behind.

Nothing writes or deletes history itself: a version exists because a change was
confirmed.

### Change log

**Change log** answers who changed what, when, from what to what, and whether
it worked. A record is written when the action is taken and is never edited
afterwards; the interface offers no way to write or delete one, because the API
has none.

Refused attempts are recorded too. An operator without the superadmin role who
tries to drain a server produces a `denied` record with their name on it --
that is precisely what the log exists for.

Secrets never reach the file. Values under key names that look sensitive --
password, token, secret, passphrase, private key, session, credential -- are
replaced before anything is stored, recursively, so a secret nested inside a
site definition is caught too. A changed password is recorded as
`password: changed`: the comparison is made on the real values so the change is
noticed, but only the fact is kept.

The log is stored at `/var/lib/easy-ha-proxy/audit/audit.db`, is included in
the encrypted disaster-recovery archive, and is kept for a year with a hard row
cap so it cannot grow without limit. If the log itself cannot be written the
operation still proceeds -- auditing must not become a way to break the
gateway -- and the failure count is visible rather than silent.

Every administrative change made through the interface is recorded: sites, TCP
proxies and UDP forwards; certificates, certificate authorities and DNS
provider profiles; Authelia users, settings and unbans; manual bans and
allow-list entries; GeoIP selection and schedule; the configuration apply,
confirm, rollback, revert and restore path; the vars editors; service
start/stop/restart; backup, restore and software-update jobs; and runtime
backend operations.

What is still outside the trail: actions the privileged helpers take on their
own timers rather than on an operator's request -- automatic certificate
renewal, the GeoIP update timer, and adaptive bans applied by the security
engine. Those have their own logs and, for bans, their own page.

### DNS-01 and wildcard certificates

A wildcard certificate cannot be validated over HTTP, and HTTP-01 is useless
when port 80 is unreachable. **DNS providers** holds the credentials that let
Certbot answer the DNS-01 challenge instead.

Certbot is installed from snap on this platform, so its DNS plugins are snaps
too and must be at the same version. List the providers you need in
`dns_plugins_enabled` (`cloudflare`, `digitalocean`, `route53`, `rfc2136`) and
apply; nothing is installed for a provider you have not asked for. The page
shows, per provider, whether Certbot can actually see its plugin, so a missing
one is visible before an issuance fails rather than after.

Credentials live in `/etc/easy-ha-proxy/dns-providers/`, directory `0700` and
files `0600`, written by the root certificate daemon. They are never returned
to the browser: the form always starts empty, and saving replaces what is
stored. A value containing a line break is refused, because the file is read by
Certbot as root and one value must not be able to introduce another directive.

Only the profile name travels from the browser. The plugin name, the
credentials path and every Certbot argument come from a fixed table, and a
profile whose plugin is not installed is refused with the snap to install. A
wildcard name without a DNS profile is refused before Certbot runs, so it
cannot waste a rate-limited attempt discovering that HTTP-01 will not do.

### Backend maintenance

**Backends** lists every proxied backend and its servers with the current
state, weight and session count, and offers three operations per server:
Ready, Drain and Maintenance, plus a runtime weight. Drain stops new traffic
while existing work finishes; Maintenance takes the server out immediately.

The state survives. HAProxy keeps administrative server state only in the
running process, so before this existed a server put into maintenance quietly
returned to service the next time any unrelated site was saved -- saving
reloads HAProxy. The gateway now writes `show servers state` to
`/var/lib/haproxy/server-state` before every reload it performs, and on a
timer for anything it does not perform itself, and HAProxy reads it back at
startup.

The consequence is worth knowing: maintenance is now sticky **across a reboot
too**. A server left in maintenance stays there until someone puts it back.
Set `haproxy_server_state_enabled: false` to return to the old behaviour, where
every reload resets each server to the generated configuration.

The browser never sends runtime API command text. It names an operation and a
server, and the application re-validates both against what HAProxy currently
reports before assembling the command. Backends that keep the gateway
reachable -- the administration interface, Authelia, the ACME challenge and
maintenance responders, and the stick tables -- are not offered at all, because
draining the one serving the page you are clicking in would lock you out.
Changing a state requires the superadmin role.

### Adaptive protection (monitor only)

`easy-ha-proxy-guardd.service` watches for behaviour the existing rate limits
cannot see. HAProxy's stick tables measure intensity over short windows, so a
scanner that requests `/.env`, then `/.git/config`, then `/phpmyadmin` a few
minutes apart never trips them; the access log shows exactly that pattern. The
engine therefore reads both -- the log for what an address did, the runtime
tables for how hard it is pushing and whether it is already banned.

It ships observing. **Adaptive protection** offers three modes -- off, observe
and enforce -- and the choice made there overrides the deployed default and
survives a restart. Start in observe, read the shadow review below, and only
then decide.

Enforcing bans through the same `tbl_ban` the HAProxy rules already use, with
its own reason code, so an adaptive ban appears in the existing ban list and
can be lifted with the existing unban button. Stick-table entries carry the
table's expiry rather than a per-key one, so the engine owns the schedule:
repeat findings escalate 5 minutes, 30 minutes, 6 hours, 24 hours, and each ban
is lifted when its time is up. An expired ban is not reapplied on the same
evidence -- fresh findings are required -- so the ladder counts repeat
behaviour rather than how long one scan stays in the window.

Four things are never banned, whatever the score, and none of them are
configurable:

- an address that has **ever** completed authentication, not merely one holding
  a live session -- the runtime authorization expires, and a lapsed session
  must not turn a real user into a ban candidate;
- anything the HAProxy ACLs already exempt;
- IPv6, because the ban path cannot reach it;
- an address whose ban HAProxy placed itself -- the engine re-reads the reason
  code before removing anything, so lifting an adaptive ban never clears a
  rate-limit one.

Turning enforcement back off lifts every ban the engine applied. Bans left
behind by a crash are swept up on the next cycle, because a stick-table entry
outlives the process that placed it.

The engine never acts on anything HAProxy already exempts. It mirrors the same
four ACLs -- the global whitelist, the admin allow-list, the GeoIP whitelist,
and addresses that completed Authelia authentication -- and it treats a 451 as
a request GeoIP already refused. Bans, when they eventually arrive, will be
IPv4 only: `tbl_ban` is an IPv4 stick table and the firewall ruleset is `inet`,
so addresses that cannot be acted upon are recorded as such instead of
accumulating a score nothing can use.

Only significant events are stored, never the traffic itself. Query strings are
removed while the line is parsed -- an access log genuinely contains things
like `?token=...` -- and paths are normalised and length-capped before they
reach the database. The per-address working set is bounded in both directions:
a capped number of addresses, and a capped path history each.

Findings come in three strengths. A request for a path only a scanner wants --
`/.env`, `/.git/config`, `/phpmyadmin` -- is high confidence and carries a
category. Weaker signals are enumeration of distinct missing paths, repeated
requests with no valid host, and the short-window rate and error counters
HAProxy already keeps. A missing stylesheet or image is not a signal at all.
Scores combine these with each category capped, because fifty different
WordPress URLs are one finding -- "looked for WordPress" -- rather than fifty,
and the interesting case is an address that tried several unrelated
technologies. `LOW_AND_SLOW_SCANNER` is deliberately rate-blind: the slower a
scan is, the less the existing limits can see it.

Contributions fade with age rather than being decremented on a timer, so the
score is a pure function of the stored events. Retuning any weight re-scores
the whole history immediately instead of requiring another week of
observation.

Measured over one full day of real traffic on a two-core gateway -- 310,697 log
lines, 308,251 requests:

| | |
| --- | --- |
| Parsing and detection | 37.7 µs per request, 11.7 s of CPU for the day |
| Cost at 100 requests/second | 0.38% of one core |
| Peak memory | 26 MiB |
| Requests reduced to events | 308,251 → 285 (0.9 per 1000 requests) |
| Addresses that would reach HIGH_RISK | 1 of 90 scored |

That single address had tried two unrelated technology categories, probed
without a valid host, and matched the slow-scanner rule -- the profile the
engine exists to find.

#### Shadow review

**Adaptive protection** in the HAProxy navigation is where that review happens.
It reports how many addresses were scored, how many enforcement *would* have
banned, and -- the number that decides whether enforcement is safe to enable --
how many of those later completed authentication. An address the engine wanted
to act on that turns out to belong to a real user is the failure mode worth
catching before anything is blocked.

Selecting an address shows every finding that contributed to its score, when it
happened, how many points it was worth and why: `counted`, `category cap
reached`, or `already refused by the gateway`. Nothing on the page can ban
anything; there is no control for it, because the engine cannot.

A weight simulator re-scores the stored history against different weights,
caps and decay without saving anything, so a proposed change can be judged
against traffic that already happened instead of waiting another week. Lowering
the category cap below an event's own weight has no effect by design -- the cap
limits repetition of a finding, not the value of a single one.

### Monitoring page

**Monitoring** in the HAProxy navigation shows what the collector recorded.
The overview cards report requests per second, current connections, traffic,
the 2xx/3xx/4xx/5xx split and backend health for the selected period; below
them are graphs for requests, traffic, response classes, response time and
connections. Periods run from 1 hour to 1 year, and the site filter switches
between the edge totals -- every frontend added together -- and a single
backend.

Resolution is chosen server-side: minute rows for a day or less, hourly rows
above that, grouped further for the longest periods so a chart never returns
more than 1500 points. The page states which resolution it is showing.

An availability section draws one bar per backend and per server: green while
up, red while down, amber for maintenance and drain states, with the current
state, availability percentage and total unavailable time for the period.
State changes are stored as transitions rather than as a sample per minute, so
a server that has been up for a month costs one row, and the bar still covers
the whole window.

A storage card reports the database, WAL and total size against the configured
limit, filesystem free space against the reserve, measured growth over the last
week and the retention currently in force. Growth is labelled as a measurement
of the past, not a forecast.

The page is read-only and degrades honestly: if the collector is not answering
it says so instead of drawing zeroes, and while history writes are paused it
shows why. Neither state affects HAProxy.

### Historical metrics collection

`easy-ha-proxy-metricsd.service` records how the gateway behaved over time. It
polls the HAProxy runtime socket every 10 seconds, keeps the samples in memory,
and writes one row per proxy object per minute to a local SQLite database. It
reads HAProxy and writes its own files -- nothing else -- so a collector that
is stopped, broken, or disabled has no effect on traffic.

Data is kept at two resolutions. Minute rows cover the last 7 days for
frontends and backends and the last 24 hours for individual servers; hourly
rollups cover a year. Server rows dominate the table on a host with many
backends, which is why they lose minute resolution first. Backend and server
`UP`/`DOWN` changes are stored as transitions rather than as a status sample
per minute.

Defaults live in the `metricsd_*` variables of the `haproxy-admin` role and are
rendered into `/opt/haproxy-admin/metricsd.json`. Setting `metricsd_enabled` to
`false` leaves the service installed and idle. The database is deliberately
outside the disaster-recovery archive: it can grow large and is not needed to
restore a working gateway.

The collector exposes a read-only Unix socket for the administration UI:

```text
/run/easy-ha-proxy/easy-ha-proxy-metricsd.sock
  GET /api/v1/metrics/health    collector and database status
  GET /api/v1/metrics/storage   sizes, limits, storage state and growth trend
```

#### Storage safety

Monitoring is never allowed to be the reason the disk fills up. Two limits are
enforced against the filesystem the database actually sits on, which may be a
dedicated volume rather than the root filesystem:

- a cap on everything monitoring owns -- the database, its write-ahead log and
  its shared-memory file together. `auto` resolves to the smaller of 5 GiB and
  a tenth of the filesystem;
- a free-space reserve that is enforced even when the cap is lifted. `auto`
  resolves to at least 2 GiB, at most 10 GiB, otherwise a tenth of the
  filesystem.

As either limit is approached the collector reports `WARNING`, then
`PRESSURE`, and trims retention one step at a time -- minute rows down to 3
days and then 1 day, hourly rows down to 180, 90 and finally 30 days -- always
rolling minutes up into hours before deleting them. Losing resolution comes
before losing long-term visibility.

If trimming is not enough the state becomes `CRITICAL` and history writes stop:

```text
Historical monitoring paused.
Disk free-space safety threshold reached.
HAProxy traffic is not affected.
```

While paused the collector keeps polling and keeps counting in memory, so no
traffic is double-counted when it resumes; the affected minutes are dropped
rather than queued. Writing resumes only once free space is back above the
reserve by a clear margin, so the collector cannot flap around the threshold.

Reclaiming space always uses incremental vacuum. A full `VACUUM` is never
issued: it needs room for a second copy of the database, which is exactly what
is missing when the disk is under pressure.

The service is reported on the **Health** page like every other helper. A
collector whose last successful poll is too old is shown as degraded even while
the process itself is running.

### Important paths

- `/etc/easy-ha-proxy` — managed configuration and secrets;
- `/opt/easy-ha-proxy/source` — managed source checkout;
- `/opt/easy-ha-proxy/venv` — private Python and Ansible environment;
- `/etc/haproxy` — HAProxy configuration and certificates;
- `/etc/haproxy/certificate-authorities` — imported CA bundles and the
  root-only internal CA private key;
- `/opt/authelia` and `/opt/haproxy-admin` — container configuration and data;
- `/run/easy-ha-proxy` — constrained helper sockets;
- `/run/haproxy/admin.sock` — HAProxy runtime socket;
- `/var/lib/easy-ha-proxy/metrics/metrics.db` — historical metrics, excluded
  from the encrypted backup.

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

Every test lives in `.tests/`, which is outside the Docker build context, so
none of it reaches the runtime image. `.github/workflows/ci.yml` runs exactly
the commands below on Python 3.10, 3.11 and 3.12.

```bash
python3 -m py_compile installer/easy_ha_proxy.py
python3 -m compileall -q docker/app \
  ansible/roles/authelia/files \
  ansible/roles/haproxy-admin/files
PYTHONPATH=installer python3 -m unittest discover -s .tests -p 'test_*.py'

bash -n install.sh install-local.sh install-remote.sh \
  easy-ha-proxy-helper.sh installer/easy-ha-proxy

ansible-galaxy collection install -r ansible/requirements.yml
ansible-playbook --syntax-check -i localhost, ansible/easy-ha-proxy.yml
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
