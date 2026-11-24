#!/usr/bin/env bash
# certd: the Go daemon against haproxy-certd.py on one 87-step sequence, with
# fake certbot, haproxy and systemctl and test certificates made on the fly.
# Runs inside the throwaway container .tests/parity/run.sh starts: REPO is
# the checkout, AGENT_BIN the Go agent built from it. Exits 1 on any diff.
HERE=$(cd "$(dirname "$0")" && pwd)
R=${REPO:-/repo}
AGENT=${AGENT_BIN:-/work/agent}
set -e
groupadd -f haproxy; groupadd -f hadmin
mkdir -p /fakebin
cat > /fakebin/systemctl <<'EOS'
#!/bin/sh
exit 0
EOS
cat > /fakebin/haproxy <<'EOS'
#!/bin/sh
exit 0
EOS
cat > /fakebin/certbot <<'EOS'
#!/bin/sh
cmd="$1"; shift
case "$cmd" in
plugins) echo "* standalone"; echo "* dns-cloudflare"; exit 0;;
delete) name=""; cfg=""
  while [ $# -gt 0 ]; do case "$1" in --cert-name) name="$2"; shift;; --config-dir) cfg="$2"; shift;; esac; shift; done
  rm -rf "$cfg/live/$name" "$cfg/archive/$name" "$cfg/renewal/$name.conf"; echo "deleted $name"; exit 0;;
certonly) name=""; cfg=""; doms=""
  while [ $# -gt 0 ]; do case "$1" in --cert-name) name="$2"; shift;; --config-dir) cfg="$2"; shift;; -d) doms="$doms $2"; shift;; esac; shift; done
  mkdir -p "$cfg/live/$name" "$cfg/renewal"
  python3 "$HERE/mkcert.py" "$cfg/live/$name" $doms
  printf '[renewalparams]\nauthenticator = standalone\n' > "$cfg/renewal/$name.conf"
  echo "issued $name"; exit 0;;
esac
exit 1
EOS
cat > /fakebin/deliver <<'EOS'
#!/bin/sh
echo "delivered $*"
EOS
chmod 755 /fakebin/*
start() {
  side=$1; shift
  r=/srv/$side
  mkdir -p $r/certs $r/le $r/etc/config $r/run
  env PATH=/fakebin:/usr/local/bin:/usr/bin:/bin HAPROXY_CERTD_SOCKET=$r/run/certd.sock HAPROXY_CERTD_SOCKET_GROUP=hadmin \
    HAPROXY_VARS_YAML=$r/etc/config/vars.yml CERTBOT_BIN=/fakebin/certbot HAPROXY_CERTS_DIR=$r/certs LETSENCRYPT_ROOT_DIR=$r/le \
    HAPROXY_CA_ROOT_DIR=$r/ca HAPROXY_MTLS_DIR=$r/mtls HAPROXY_CERTS_AVAILABLE_DIR=$r/avail HAPROXY_DNS_CREDENTIALS_DIR=$r/dns \
    CERT_DESTINATIONS_DIR=$r/deliver HAPROXY_CERTD_TRASH_DIR=$r/trash HAPROXY_BIN=/fakebin/haproxy HAPROXY_CFG=$r/haproxy.cfg \
    HAPROXY_PEMS_SCRIPT=$r/no-hook HAPROXY_APPLIED_WEBSITES=$r/applied.yml HAPROXY_APPLIED_VARS=$r/applied-vars.yml \
    "$@" > /tmp/$side.log 2>&1 &
  touch $r/haproxy.cfg
}
F=$R/ansible/roles/haproxy-admin/files
mkdir -p /usr/local/sbin && ln -sf /fakebin/deliver /usr/local/sbin/easy-ha-proxy-cert-deliver
start py python3 $F/haproxy-certd.py
start go "$AGENT" certd
for _ in $(seq 100); do [ -S /srv/py/run/certd.sock ] && [ -S /srv/go/run/certd.sock ] && break; sleep 0.2; done
rc=0
python3 "$HERE/client.py" /srv/py/run/certd.sock /srv/go/run/certd.sock /srv/py /srv/go || rc=1
echo "--- logs"; tail -5 /tmp/py.log; tail -5 /tmp/go.log
exit $rc
