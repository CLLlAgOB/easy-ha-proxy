package stages

// The rdg copy tasks' content:, word for word (templated like the tasks).
const (
	rdgEnv = `RDG_DOMAIN={{ rdg_domain | quote }}
RDG_HOST={{ rdg_host | quote }}
SSH_USER={{ rdg_ssh_user | quote }}
SSH_KEY={{ rdg_ssh_key | quote }}
SSH_PORT={{ rdg_ssh_port | string | quote }}
PFX_PASSWORD={{ rdg_pfx_password | default('') | quote }}
REMOTE_PATH={{ rdg_remote_path | default('C:/SFTP/upload/rdg_cert.pfx') | quote }}
KNOWN_HOSTS={{ rdg_ssh_known_hosts | default('/etc/letsencrypt/rdg.known_hosts') | quote }}
`

	rdgPostHook = `#!/usr/bin/env bash
set -euo pipefail
umask 077
source /etc/letsencrypt/rdg.env

# Certbot provides the environment variables:
#  RENEWED_LINEAGE (the live/... path), RENEWED_DOMAINS (space-separated)
if ! echo " ${RENEWED_DOMAINS:-} " | grep -Fq " ${RDG_DOMAIN} "; then
  exit 0
fi

LIVE_DIR="${RENEWED_LINEAGE}"
if [ ! -f "${LIVE_DIR}/fullchain.pem" ] || [ ! -f "${LIVE_DIR}/privkey.pem" ]; then
  exit 0
fi

TMP_PFX="$(mktemp /tmp/rdg_cert.XXXXXX.pfx)"
SFTP_BATCH="$(mktemp /tmp/sftp.XXXXXX.batch)"
trap 'rm -f "${TMP_PFX}" "${SFTP_BATCH}"' EXIT

if [ -n "${PFX_PASSWORD:-}" ]; then
  PFX_PASSWORD="${PFX_PASSWORD}" openssl pkcs12 -export \
    -inkey  "${LIVE_DIR}/privkey.pem" \
    -in     "${LIVE_DIR}/fullchain.pem" \
    -out    "${TMP_PFX}" \
    -passout env:PFX_PASSWORD
else
  openssl pkcs12 -export \
    -inkey  "${LIVE_DIR}/privkey.pem" \
    -in     "${LIVE_DIR}/fullchain.pem" \
    -out    "${TMP_PFX}" \
    -passout pass:
fi

cat > "${SFTP_BATCH}" <<EOF
put "${TMP_PFX}" "${REMOTE_PATH}"
EOF

KNOWN_HOSTS_FILE="${KNOWN_HOSTS:-/etc/letsencrypt/rdg.known_hosts}"
if [ ! -s "${KNOWN_HOSTS_FILE}" ]; then
  echo "ERROR: RDG SSH host key file ${KNOWN_HOSTS_FILE} is missing or empty" >&2
  exit 1
fi

sftp -b "${SFTP_BATCH}" -i "${SSH_KEY}" -P "${SSH_PORT}" \
  -o BatchMode=yes \
  -o IdentitiesOnly=yes \
  -o StrictHostKeyChecking=yes \
  -o "UserKnownHostsFile=${KNOWN_HOSTS_FILE}" \
  -- "${SSH_USER}@${RDG_HOST}"

systemctl reload haproxy 2>/dev/null || true
`
)
