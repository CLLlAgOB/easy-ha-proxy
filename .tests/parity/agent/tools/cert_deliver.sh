#!/usr/bin/env bash
# cert-deliver: the agent against easy-ha-proxy-cert-deliver.py on 27 invocations over
# 21 delivery targets, with fake sftp/scp/ssh and real openssl.
# Runs inside the throwaway container .tests/parity/run.sh starts: REPO is
# the checkout, AGENT_BIN the Go agent built from it. Exits 1 on any diff.
HERE=$(cd "$(dirname "$0")" && pwd)
R=${REPO:-/repo}
AGENT=${AGENT_BIN:-/work/agent}
set -u
for b in sftp scp ssh; do cp "$HERE/fake.py" /usr/bin/$b; chmod 755 /usr/bin/$b; done
install -m 755 $R/ansible/roles/haproxy-admin/files/easy-ha-proxy-cert-deliver.py /usr/local/sbin/easy-ha-proxy-cert-deliver
L=/srv/live/app.example.com; mkdir -p $L
openssl req -x509 -newkey rsa:2048 -nodes -keyout $L/privkey.pem -out $L/fullchain.pem -days 30 -subj /CN=app.example.com \
  -addext "subjectAltName=DNS:app.example.com,DNS:www.example.com,DNS:*.svc.example.com" 2>/dev/null
D=/srv/dest; mkdir -p $D
rec() { printf '%s\n' "$2" > $D/$1.json; if [ "${3:-keys}" = keys ]; then echo k > $D/$1.key; echo h > $D/$1.known_hosts; fi; }
rec a '{"host":"rdg.example","user":"deploy","format":"pfx","pfx_password":"s3cret","remote_path":"C:/certs/rdg.pfx","domains":["app.example.com"],"post_command":"reload"}'
rec b '{"host":"10.0.0.5","port":"2222","user":"root","transport":"scp","format":"pem-pair","remote_path":"/etc/ssl/app/","domains":["app.example.com"]}'
rec c '{"enabled":false,"host":"x.example","user":"u","format":"pem-combined","remote_path":"/x.pem","domains":["app.example.com"]}'
rec d '{"user":"u","remote_path":"/x","domains":["app.example.com"]}'
rec e '{"host":"e.example","user":"u","remote_path":"/x","domains":["app.example.com"]}' nokeys
rec f '{"host":"f.example","user":"u","remote_path":"/x","domains":["app.example.com","x.other.org"]}'
rec g '{"host":"g.example","user":"u","format":"der","remote_path":"/x","domains":["app.example.com"]}'
rec h '{"host":"h.example","user":"bad user","format":"pem-combined","remote_path":"/x","domains":["app.example.com"]}'
rec i '{"host":"i.example","port":22,"user":"u","format":"pem-combined","remote_path":"/x.pem","domains":["www.example.com"],"post_command":"fail"}'
rec j '{"host":"fail.example","user":"u","format":"pem-combined","remote_path":"/x.pem","domains":["www.example.com"]}'
echo '{not json' > $D/k.json
rec l '{"host":"l.example","user":"u","format":"pem-combined","remote_path":"/srv/my \"certs\"/a b.pem","domains":["api.svc.example.com"]}'
rec m '{"host":"[fe80::1]","user":"u","format":"pem-pair","transport":"sftp","remote_path":"/etc/ssl/m","domains":["api.svc.example.com"]}'
rec n '{"host":"n.example","user":"u","transport":"ftp","format":"pem-combined","remote_path":"/x","domains":["APP.EXAMPLE.COM "]}'
rec o '{"host":"silent.example","user":"u","format":"pem-combined","remote_path":"/x","domains":["silent.example.com"]}'
rec p '{"host":"p.example","user":"u","format":"pem-combined","remote_path":"/x","domains":["www.example.com"],"post_command":"quiet-fail","enabled":1}'
rec q '{"host":"-oProxyCommand=x","user":"u","format":"pem-combined","remote_path":"/x","domains":["q.example.com"]}'
rec r '{"host":"slow.example","user":"u","format":"pem-combined","remote_path":"/x","domains":["slow.example.com"]}'
rec s '{"host":"s.example","user":"u","format":"pem-combined","remote_path":"/bad\u0001path","domains":["s.example.com"]}'
rec t '{"host":"t.example","user":"u","format":"pfx","pfx_password":"a\nb","remote_path":"/x","domains":["t.example.com"]}'
rec u '{"host":"u.example","user":"u","format":"pem-combined","domains":["u.example.com"]}'
for x in silent s t u slow q; do mkdir -p /srv/live/$x.example.com; cp $L/* /srv/live/$x.example.com/; done
cases() {
  echo "none|"
  echo "emptyl|--lineage|"
  echo "nodom|--lineage|$L|--domains|"
  echo "app|--lineage|$L|--domains|app.example.com"
  echo "comma|--lineage|$L|--domains|app.example.com,www.example.com"
  echo "nobody|--lineage|$L|--domains|nothing.example"
  echo "svc|--lineage|$L|--domains|api.svc.example.com"
  echo "silent|--lineage|/srv/live/silent.example.com|--domains|silent.example.com"
  echo "q|--lineage|/srv/live/q.example.com|--domains|q.example.com"
  echo "s|--lineage|/srv/live/s.example.com|--domains|s.example.com"
  echo "t|--lineage|/srv/live/t.example.com|--domains|t.example.com"
  echo "u|--lineage|/srv/live/u.example.com|--domains|u.example.com"
  echo "nochain|--lineage|/srv/live/none|--domains|app.example.com"
  echo "ta|--target|a|--lineage|$L"
  echo "tA|--target|A|--lineage=$L"
  echo "tc|--target|c|--lineage|$L"
  echo "tmissing|--target|zz|--lineage|$L"
  echo "tbad|--target|Bad_Name|--lineage|$L"
  echo "tnolin|--target|a"
  echo "tj|--tar|j|--lin|$L"
  echo "bogus|--bogus"
  echo "bogus200|--bogus"
  echo "bogus50|--bogus"
  echo "bogus30|--bogus"
  echo "noval|--lineage"
  echo "timeout|--lineage|/srv/live/slow.example.com|--domains|slow.example.com"
  echo "envonly|"
}
run_side() {
  side=$1; shift
  cases | while IFS= read -r line; do
    name=${line%%|*}; rest=${line#*|}
    args=()
    if [ -n "$rest" ]; then IFS='|' read -r -a args <<< "$rest"; fi
    case $name in emptyl) args=(--lineage "");; nodom) args=(--lineage "$L" --domains "");; esac
    envs=("CERT_DESTINATIONS_DIR=$D" "FAKE_LOG=/tmp/$side.$name.fake")
    [ $name = envonly ] && envs+=("RENEWED_LINEAGE=$L" "RENEWED_DOMAINS=www.example.com app.example.com")
    [ $name = timeout ] && envs+=(CERT_DELIVER_TIMEOUT=1)
    case $name in bogus200) envs+=(COLUMNS=200);; bogus50) envs+=(COLUMNS=50);; bogus30) envs+=(COLUMNS=30);; esac
    : > /tmp/$side.$name.fake
    env "${envs[@]}" "$@" "${args[@]}" > /tmp/$side.$name.out 2> /tmp/$side.$name.err
    echo $? > /tmp/$side.$name.rc
  done
}
run_side py /usr/local/sbin/easy-ha-proxy-cert-deliver
run_side go "$AGENT" cert-deliver
for f in /tmp/py.*.err /tmp/go.*.err; do sed -i -E 's/^[0-9A-F]{12,16}:error/X:error/; s#cannot read /srv/dest/k.json \(.*\); skipping#cannot read /srv/dest/k.json (DECODE); skipping#' $f; done
diffs=0
for name in $(cases | cut -d'|' -f1); do
  for k in rc out err fake; do
    if ! cmp -s /tmp/py.$name.$k /tmp/go.$name.$k; then
      diffs=$((diffs+1)); echo "=== $name.$k"; diff /tmp/py.$name.$k /tmp/go.$name.$k | head -12
    fi
  done
done
echo "cases: $(cases | wc -l)  diffs: $diffs"
[ "$diffs" -eq 0 ]
