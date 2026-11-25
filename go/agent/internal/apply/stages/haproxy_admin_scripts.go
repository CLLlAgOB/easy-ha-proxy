package stages

// The shell tasks' scripts, word for word (templated like the tasks).
const (
	nativeOCIPull = `set -euo pipefail
img={{ native_release_image | quote }}
rev={{ ((_native_source_revision.stdout | default('') | trim)
        if (_native_source_revision.rc | default(1)) == 0 else '') | quote }}
stage="/var/lib/easy-ha-proxy/native-staging"
if [ -n "${rev}" ]; then
  img="${img}-${rev:0:12}"
fi
prev_digest=""
if [ -f "${stage}/image.json" ]; then
  prev_digest="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1], encoding="utf-8")).get("digest", ""))' "${stage}/image.json" 2>/dev/null || true)"
fi
{% if not (easy_ha_proxy_offline_restore | default(false) | bool) %}
if ! docker pull "${img}"; then
  echo "The native binaries are not published or could not be pulled (${img})." >&2
  exit 1
fi
{% endif %}
# Resolve the tag once. Check the label on the same immutable
# image that will supply the files, even if the tag moves.
ref="$(docker image inspect --format '{% raw %}{{if .RepoDigests}}{{index .RepoDigests 0}}{{else}}{{.Id}}{{end}}{% endraw %}' "${img}")"
if [ -n "${rev}" ]; then
  built="$(docker image inspect --format '{% raw %}{{ index .Config.Labels "org.opencontainers.image.revision" }}{% endraw %}' "${ref}")"
  if [ "${built}" != "${rev}" ]; then
    echo "${img} was built from ${built:-an unknown revision}, not ${rev}." >&2
    exit 1
  fi
fi
{% if (native_release_verify_signature | default(false) | bool) and not (easy_ha_proxy_offline_restore | default(false) | bool) %}
if ! command -v cosign >/dev/null 2>&1; then
  echo "native_release_verify_signature is enabled, but cosign is not installed." >&2
  exit 1
fi
cosign verify \
  --certificate-identity-regexp {{ native_release_cosign_identity_regexp | default('^https://github\\.com/CLLlAgOB/easy-ha-proxy/\\.github/workflows/ci\\.yml@refs/heads/(main|alpha)$') | quote }} \
  --certificate-oidc-issuer {{ native_release_cosign_oidc_issuer | default('https://token.actions.githubusercontent.com') | quote }} \
  "${ref}"
{% endif %}
cid="$(docker create --pull=never "${ref}")"
trap 'docker rm -f "${cid}" >/dev/null 2>&1 || true' EXIT
rm -rf "${stage}/sbin" "${stage}/lib" "${stage}/SHA256SUMS"
docker cp "${cid}:/sbin" "${stage}/sbin"
docker cp "${cid}:/SHA256SUMS" "${stage}/SHA256SUMS"
(cd "${stage}" && sha256sum -c SHA256SUMS)
python3 -c 'import json, sys; open(sys.argv[1], "w", encoding="utf-8").write(json.dumps({"image": sys.argv[2], "digest": sys.argv[3], "revision": sys.argv[4]}) + "\n")' \
  "${stage}/image.json" "${img}" "${ref}" "${rev}"
if [ "${prev_digest}" != "${ref}" ]; then
  echo "NATIVE_BUNDLE_CHANGED"
fi
`

	nativeCleanup = `set -euo pipefail
present=()
found=0
named=""
for path in {{ native_legacy_paths | map('quote') | join(' ') }}; do
  [ -e "$path" ] || [ -L "$path" ] || continue
  present+=("$path")
  found=$((found + 1))
  if grep -rqsF -- "$path" /etc/systemd/system /run/systemd/system /usr/lib/systemd/system; then
    named="$named $path"
  fi
done
if [ -n "$named" ]; then
  echo "kept the former Python daemons: installed units still name$named" >&2
  exit 0
fi
if [ "$found" -gt 0 ]; then
  rm -rf -- "${present[@]}"
  echo "removed: ${present[*]}"
fi
`
)

// nativeLegacyPaths is native-cleanup's native_legacy_paths.
var nativeLegacyPaths = []string{
	"/usr/local/sbin/easy-ha-proxy-alertd.py",
	"/usr/local/sbin/easy_ha_proxy_alert_client.py",
	"/usr/local/sbin/easy-ha-proxy-backupd.py",
	"/usr/local/sbin/easy-ha-proxy-backup-run.py",
	"/usr/local/sbin/easy-ha-proxy-unit-failed.py",
	"/usr/local/sbin/easy-ha-proxy-guardd.py",
	"/usr/local/sbin/easy-ha-proxy-metricsd.py",
	"/usr/local/sbin/easy-ha-proxy-updated.py",
	"/usr/local/sbin/haproxy-certd.py",
	"/usr/local/sbin/haproxy-controld.py",
	"/usr/local/sbin/haproxy-healthd.py",
	"/usr/local/sbin/haproxy-udp-forward.py",
	"/usr/local/sbin/authelia-bansd.py",
	"/usr/local/sbin/authelia-configd.py",
	"/usr/local/sbin/authelia-usersd.py",
	"/usr/local/sbin/backupd",
	"/usr/local/sbin/certd",
	"/usr/local/sbin/controld",
	"/usr/local/sbin/guardd",
	"/usr/local/sbin/metricsd",
	"/usr/local/sbin/updated",
	"/usr/local/sbin/__pycache__",
	"/usr/local/lib/easy-ha-proxy/libguardd_core.so",
}
