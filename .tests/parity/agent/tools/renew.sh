#!/usr/bin/env bash
# certd --renew: the agent against haproxy-certd.py --renew on the same lineages
# (one due, one failing Route53, one webroot): same certbot calls, log and status,
# and neither may open certd's socket.
# Runs inside the throwaway container .tests/parity/run.sh starts: REPO is
# the checkout, AGENT_BIN the Go agent built from it. Exits 1 on any diff.
R=${REPO:-/repo}
AGENT=${AGENT_BIN:-/work/agent}
set -u
mkdir -p /fakebin
cat > /fakebin/certbot <<'EOS'
#!/bin/sh
echo "certbot $*" >> /tmp/certbot.calls
case "$*" in *broken*) echo "renewal failed: boom" >&2; exit 1;; esac
exit 0
EOS
chmod 755 /fakebin/certbot
for side in py go; do
  r=/srv/$side; mkdir -p $r/le/renewal $r/dns
  printf '[renewalparams]\nauthenticator = standalone\n' > $r/le/renewal/a.example.conf
  printf '[renewalparams]\nauthenticator = dns-route53\n' > $r/le/renewal/broken.example.conf
  printf '[renewalparams]\nauthenticator = webroot\n' > $r/le/renewal/c.example.conf
done
run() {
  side=$1; shift; r=/srv/$side
  : > /tmp/certbot.calls
  env CERTBOT_BIN=/fakebin/certbot LETSENCRYPT_ROOT_DIR=$r/le HAPROXY_DNS_CREDENTIALS_DIR=$r/dns \
    HAPROXY_CERTD_SOCKET=$r/certd.sock timeout 60 "$@" --renew > /tmp/$side.out 2>&1
  echo "rc=$?" >> /tmp/$side.out
  sed "s#/srv/$side#/srv/X#g" /tmp/certbot.calls > /tmp/$side.calls
  [ -S $r/certd.sock ] && echo "SOCKET CREATED" >> /tmp/$side.out
}
F=$R/ansible/roles/haproxy-admin/files
run py python3 $F/haproxy-certd.py
run go "$AGENT" certd
for side in py go; do echo "--- $side"; cat /tmp/$side.out /tmp/$side.calls; done
for side in py go; do grep -q "SOCKET CREATED" /tmp/$side.out && { echo "$side opened the daemon socket"; exit 1; }; done
cmp /tmp/py.out /tmp/go.out && cmp /tmp/py.calls /tmp/go.calls && echo "renew: identical"
