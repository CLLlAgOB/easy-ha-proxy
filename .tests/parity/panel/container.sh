#!/bin/sh
# One panel suite inside the parity container: the panel's state from the
# fixtures, the fake daemons, then run.py on both panels. Usage: container.sh
# cases_x.py [filter]. Started by .tests/parity/run.sh.
set -eu
R=${REPO:-/repo}
P="$R/.tests/parity/panel"
mkdir -p /srv/state/opt/haproxy-admin/config /srv/state/opt/haproxy-admin/backups /srv/state/etc/haproxy/geoip \
  /srv/state/var/lib/haproxy-admin /srv/state/var/lib/easy-ha-proxy/audit
cp "$P"/fixtures/*.yml /srv/state/opt/haproxy-admin/config/
cp "$R/ansible/roles/haproxy/templates/haproxy.cfg.j2" /srv/state/opt/haproxy-admin/config/
echo global > /srv/state/etc/haproxy/haproxy.cfg
python3 "$P/fakes.py" &
sleep 1
exec python3 "$P/run.py" "$P/$1" "${2:-}"
