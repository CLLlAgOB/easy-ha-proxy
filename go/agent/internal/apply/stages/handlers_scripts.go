package stages

// The cert handlers' PEM assembly scripts, word for word (templated like
// the handler tasks, with lineage and dest as their loop variables).
const (
	pemExplicit = `set -euo pipefail
umask 077
lineage={{ lineage | quote }}
dest={{ dest | quote }}
available={{ (haproxy_certs_available_dir | default('/etc/haproxy/certs-available')) | quote }}
certs_dir="$(realpath -m -- {{ (haproxy_certs_dir | default('/etc/haproxy/certs')) | quote }})"

# cert_path comes from websites.yml, which the panel writes; this runs as
# root, so it may only name a .pem file in the HAProxy certificate directory.
case "$(realpath -m -- "$dest")" in
  "$certs_dir"/*.pem) ;;
  *) echo "Skip $lineage: $dest is not a .pem file in $certs_dir" >&2; exit 0 ;;
esac

full="/etc/letsencrypt/live/$lineage/fullchain.pem"
key="/etc/letsencrypt/live/$lineage/privkey.pem"

# If the certificate has not been issued yet, just skip it;
# NO temporary file is created
if [ ! -r "$full" ] || [ ! -r "$key" ]; then
  echo "Skip $lineage: certificate files not ready" >&2
  exit 0
fi

# A name the operator put on a standby certificate is held there until
# they hand it back. Without this, a config apply would undo the switch
# silently -- and this handler runs on far more than renewals.
stem="$(basename "$dest" .pem)"
pin="$available/$stem/.pinned"
if [ -s "$pin" ]; then
  echo "Held: $stem is on a standby certificate ($(cat "$pin")); not replacing it" >&2
  exit 0
fi

tmp="$dest.tmp.$$"
cat "$full" "$key" > "$tmp"
if [ -f "$dest" ] && cmp -s "$tmp" "$dest" \
    && [ "$(stat -c '%a %U:%G' "$dest")" = "600 root:root" ]; then
  rm -f "$tmp"
  exit 0
fi
chown root:root "$tmp"
chmod 0600 "$tmp"
mv -f "$tmp" "$dest"
echo "PEM written: $dest"
`

	pemSingle = `set -euo pipefail
umask 077
lineage={{ lineage | quote }}
dest={{ dest | quote }}
available={{ (haproxy_certs_available_dir | default('/etc/haproxy/certs-available')) | quote }}
certs_dir="$(realpath -m -- {{ (haproxy_certs_dir | default('/etc/haproxy/certs')) | quote }})"

# cert_path comes from websites.yml, which the panel writes; this runs as
# root, so it may only name a .pem file in the HAProxy certificate directory.
case "$(realpath -m -- "$dest")" in
  "$certs_dir"/*.pem) ;;
  *) echo "Skip $lineage: $dest is not a .pem file in $certs_dir" >&2; exit 0 ;;
esac

full="/etc/letsencrypt/live/$lineage/fullchain.pem"
key="/etc/letsencrypt/live/$lineage/privkey.pem"

if [ ! -r "$full" ] || [ ! -r "$key" ]; then
  echo "Skip $lineage: certificate files not ready" >&2
  exit 0
fi

# A name the operator put on a standby certificate is held there until
# they hand it back. Without this, a config apply would undo the switch
# silently -- and this handler runs on far more than renewals.
stem="$(basename "$dest" .pem)"
pin="$available/$stem/.pinned"
if [ -s "$pin" ]; then
  echo "Held: $stem is on a standby certificate ($(cat "$pin")); not replacing it" >&2
  exit 0
fi

tmp="$dest.tmp.$$"
cat "$full" "$key" > "$tmp"
if [ -f "$dest" ] && cmp -s "$tmp" "$dest" \
    && [ "$(stat -c '%a %U:%G' "$dest")" = "600 root:root" ]; then
  rm -f "$tmp"
  exit 0
fi
chown root:root "$tmp"
chmod 0600 "$tmp"
mv -f "$tmp" "$dest"
echo "PEM written: $dest"
`
)
