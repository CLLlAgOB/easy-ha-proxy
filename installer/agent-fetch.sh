# shellcheck shell=bash
# The host agent built for a source revision, from the project's GitHub
# release "agent-builds", a signed OCI release when Cosign is enabled, or
# a configured local or HTTPS bundle. A host gets its first
# agent this way (a fresh install, or the first update from a release whose
# installer was still Python); later updates install the agent pinned to the
# source in the native stage. Nothing here needs Python.
#
# Sourced by installer/easy-ha-proxy and install-local.sh.

easy_ha_proxy_agent_release_url="${EASY_HA_PROXY_AGENT_RELEASE_URL:-https://github.com/CLLlAgOB/easy-ha-proxy/releases/download/agent-builds}"

# The full Git revision of a source tree: its checkout, else the marker a
# staged source bundle carries.
easy_ha_proxy_source_revision() {
  local source="$1" revision=""
  if [[ -e "${source}/.git" ]]; then
    revision="$(git -c "safe.directory=${source}" -C "${source}" rev-parse HEAD 2>/dev/null || true)"
  fi
  if [[ ! "${revision}" =~ ^[0-9a-f]{40}$ && -r "${source}/.easy-ha-proxy-source-revision" ]]; then
    revision="$(awk -F= '$1 == "revision" {print $2; exit}' "${source}/.easy-ha-proxy-source-revision" | tr -d '[:space:]')"
  fi
  [[ "${revision}" =~ ^[0-9a-f]{40}$ ]] || return 1
  printf '%s\n' "${revision}"
}

easy_ha_proxy_agent_arch() {
  case "$(uname -m)" in
    x86_64 | amd64) printf 'amd64\n' ;;
    aarch64 | arm64) printf 'arm64\n' ;;
    *) return 1 ;;
  esac
}

# A host agent that runs the installer ("cli").
easy_ha_proxy_agent_runs_cli() {
  [[ -x "$1" ]] && "$1" cli --probe >/dev/null 2>&1
}

easy_ha_proxy_agent_matches_source() {
  local binary="$1" revision="$2" built
  easy_ha_proxy_agent_runs_cli "${binary}" || return 1
  if [[ -n "${revision}" ]]; then
    built="$("${binary}" cli --revision 2>/dev/null)" && [[ "${built}" == "${revision}" ]]
  fi
}

# A top-level scalar of the host's vars.yml, unquoted; empty when unset.
easy_ha_proxy_config_value() {
  local file="${EASY_HA_PROXY_CONFIG_DIR:-/etc/easy-ha-proxy}/vars.yml"
  [[ -r "${file}" ]] || return 0
  awk -v key="$1" '
    BEGIN { field = "(" key "|\"" key "\"|\047" key "\047)[[:space:]]*:" }
    /^[[:space:]]*#/ { next }
    $0 ~ "^" field {
      value = substr($0, index($0, ":") + 1)
      sub(/[[:space:]]+#.*$/, "", value)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
      if (value ~ /^".*"$/) {
        value = substr(value, 2, length(value) - 2)
        gsub(/\\\\/, sprintf("%c", 92), value)
      } else if (value ~ /^\047.*\047$/) {
        value = substr(value, 2, length(value) - 2)
        gsub(/\047\047/, "\047", value)
      }
      count++
      next
    }
    $0 ~ "(^|[[:space:]{,])" field { ambiguous = 1 }
    END {
      if (count > 1 || ambiguous) exit 2
      if (count == 1) print value
    }' "${file}" || {
    echo "easy-ha-proxy: could not read ${1} as a top-level scalar in ${file}." >&2
    return 1
  }
}

easy_ha_proxy_install_agent() {
  local binary="$1" destination="$2" partial
  install -d -m 0755 "$(dirname "${destination}")" || return 1
  partial="$(mktemp "${destination}.partial.XXXXXX")" || return 1
  if ! install -m 0755 "${binary}" "${partial}" || ! mv -fT "${partial}" "${destination}"; then
    rm -f -- "${partial}"
    return 1
  fi
}

easy_ha_proxy_bundle_checksum() {
  local file="${EASY_HA_PROXY_CONFIG_DIR:-/etc/easy-ha-proxy}/vars.yml"
  [[ -r "${file}" ]] || return 0
  awk -v arch="$1" '
    function checksum(entry, fields, key, value) {
      split(entry, fields, ":")
      key = fields[1]
      value = fields[2]
      gsub(/[[:space:]"\047]/, "", key)
      sub(/[[:space:]]+#.*$/, "", value)
      gsub(/[[:space:]"\047]/, "", value)
      if (key == arch) { print tolower(value); exit }
    }
    /^native_release_checksums[[:space:]]*:/ {
      inline = $0
      sub(/^[^{]*\{/, "", inline)
      if (inline != $0) {
        sub(/\}.*/, "", inline)
        count = split(inline, entries, ",")
        for (i = 1; i <= count; i++) checksum(entries[i])
        exit
      }
      reading = 1
      next
    }
    reading && /^[[:space:]]+[^[:space:]#].*:/ { checksum($0); next }
    reading && /^[^[:space:]#]/ { exit }
  ' "${file}"
}

easy_ha_proxy_extract_agent() {
  local bundle="$1" binary="$2"
  if { tar -xOzf "${bundle}" sbin/easy-ha-proxy-agent >"${binary}" 2>/dev/null ||
       tar -xOzf "${bundle}" ./sbin/easy-ha-proxy-agent >"${binary}" 2>/dev/null; } && [[ -s "${binary}" ]]; then
    return 0
  fi
  echo "easy-ha-proxy: ${bundle} holds no sbin/easy-ha-proxy-agent." >&2
  return 1
}

easy_ha_proxy_fetch_signed_agent() (
  local revision="$1" work="$2" image panel_image channel pin ref built container identity issuer expected actual
  if ! command -v cosign >/dev/null 2>&1 || ! command -v docker >/dev/null 2>&1; then
    echo "easy-ha-proxy: native_release_verify_signature requires cosign and Docker for the first agent." >&2
    return 1
  fi
  channel=latest
  panel_image="$(easy_ha_proxy_config_value haproxy_admin_image)" || return 1
  case "${panel_image}" in
    *:alpha | *:go-alpha) channel=alpha ;;
  esac
  image="$(easy_ha_proxy_config_value native_release_image)" || return 1
  if [[ -z "${image}" || "${image}" == *'{{'* ]]; then
    image="clllagob/haproxy-admin-ui:native-${channel}"
  fi
  pin="$(easy_ha_proxy_config_value native_release_pin_revision)" || return 1
  case "${pin,,}" in
    false | 0 | no | off) ;;
    *) image="${image}-${revision:0:12}" ;;
  esac
  identity="$(easy_ha_proxy_config_value native_release_cosign_identity_regexp)" || return 1
  issuer="$(easy_ha_proxy_config_value native_release_cosign_oidc_issuer)" || return 1
  identity="${identity:-^https://github\.com/CLLlAgOB/easy-ha-proxy/\.github/workflows/ci\.yml@refs/heads/(main|alpha)$}"
  issuer="${issuer:-https://token.actions.githubusercontent.com}"

  docker pull -- "${image}" >&2 || return 1
  ref="$(docker image inspect --format '{{if .RepoDigests}}{{index .RepoDigests 0}}{{end}}' -- "${image}")" || return 1
  if [[ ! "${ref}" =~ ^[^[:space:]@]+@sha256:[0-9a-f]{64}$ ]]; then
    echo "easy-ha-proxy: could not resolve a signed OCI digest for ${image}." >&2
    return 1
  fi
  cosign verify --certificate-identity-regexp "${identity}" --certificate-oidc-issuer "${issuer}" -- "${ref}" >&2 || return 1
  built="$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' -- "${ref}")" || return 1
  if [[ "${built}" != "${revision}" ]]; then
    echo "easy-ha-proxy: ${image} was built from ${built:-an unknown revision}, expected ${revision}." >&2
    return 1
  fi
  container="$(docker create --pull=never -- "${ref}")" || return 1
  trap 'docker rm -f -- "${container}" >/dev/null 2>&1 || true' EXIT
  docker cp "${container}:/sbin/easy-ha-proxy-agent" "${work}/agent" || return 1
  docker cp "${container}:/SHA256SUMS" "${work}/SHA256SUMS" || return 1
  expected="$(awk '$2 == "sbin/easy-ha-proxy-agent" || $2 == "./sbin/easy-ha-proxy-agent" {print $1; exit}' "${work}/SHA256SUMS")"
  actual="$(sha256sum "${work}/agent" | awk '{print $1}')"
  if [[ ! "${expected}" =~ ^[0-9a-f]{64}$ || "${actual}" != "${expected}" ]]; then
    echo 'easy-ha-proxy: the agent does not match SHA256SUMS from the verified image.' >&2
    return 1
  fi
)

# easy_ha_proxy_fetch_agent SOURCE_DIR DESTINATION: install the agent built
# for SOURCE_DIR's revision. A host that takes the native binaries from a
# local bundle (native_local_bundle_dir, a host without Internet access) gets
# it from there. A host that requires signed OCI images verifies an immutable
# digest before extraction. The HTTPS and GitHub routes check SHA-256.
easy_ha_proxy_fetch_agent() (
  local source="$1" destination="$2" revision arch name base work expected actual bundle_dir bundle verify
  local -a curl_release=(curl -fsSL --proto '=https' --proto-redir '=https' --retry 3 --connect-timeout 20 --max-time 180)
  if ! arch="$(easy_ha_proxy_agent_arch)"; then
    echo "easy-ha-proxy: unsupported architecture $(uname -m); the host agent exists for amd64 and arm64." >&2
    return 1
  fi
  work="$(mktemp -d)" || return 1
  trap 'rm -rf -- "${work}"' EXIT
  bundle_dir="$(easy_ha_proxy_config_value native_local_bundle_dir)" || return 1
  if [[ -n "${bundle_dir}" ]]; then
    bundle="${bundle_dir%/}/easy-ha-proxy-native-linux-${arch}.tar.gz"
    easy_ha_proxy_extract_agent "${bundle}" "${work}/agent" || return 1
    easy_ha_proxy_install_agent "${work}/agent" "${destination}" || return 1
    echo "Installed the host agent from ${bundle}." >&2
    return 0
  fi
  base="$(easy_ha_proxy_config_value native_release_base_url)" || return 1
  if [[ -n "${base}" ]]; then
    expected="$(easy_ha_proxy_bundle_checksum "${arch}")"
    if [[ "${base}" != https://* || ! "${expected}" =~ ^[0-9a-f]{64}$ ]]; then
      echo "easy-ha-proxy: an HTTPS native_release_base_url requires native_release_checksums for ${arch}." >&2
      return 1
    fi
    name="easy-ha-proxy-native-linux-${arch}.tar.gz"
    "${curl_release[@]}" -o "${work}/bundle" "${base%/}/${name}" || return 1
    actual="$(sha256sum "${work}/bundle" | awk '{print $1}')"
    if [[ "${actual}" != "${expected}" ]]; then
      echo "easy-ha-proxy: ${name} does not match native_release_checksums." >&2
      return 1
    fi
    easy_ha_proxy_extract_agent "${work}/bundle" "${work}/agent" || return 1
    easy_ha_proxy_install_agent "${work}/agent" "${destination}" || return 1
    echo "Installed the host agent from ${base%/}/${name}." >&2
    return 0
  fi
  if ! revision="$(easy_ha_proxy_source_revision "${source}")"; then
    echo "easy-ha-proxy: cannot tell which revision ${source} is, so the matching host agent cannot be fetched." >&2
    return 1
  fi
  verify="$(easy_ha_proxy_config_value native_release_verify_signature)" || return 1
  case "${verify,,}" in
    true | 1 | yes | on)
      easy_ha_proxy_fetch_signed_agent "${revision}" "${work}" || return 1
      easy_ha_proxy_install_agent "${work}/agent" "${destination}" || return 1
      echo "Fetched and verified the signed host agent built from ${revision:0:12} (${arch})." >&2
      return 0
      ;;
    '' | false | 0 | no | off) ;;
    *) echo 'easy-ha-proxy: native_release_verify_signature must be a boolean.' >&2; return 1 ;;
  esac
  base="${easy_ha_proxy_agent_release_url%/}"
  name="easy-ha-proxy-agent-${revision}-linux-${arch}"
  if ! "${curl_release[@]}" -o "${work}/agent" "${base}/${name}" ||
    ! "${curl_release[@]}" -o "${work}/agent.sha256" "${base}/${name}.sha256"; then
    echo "easy-ha-proxy: the host agent built from ${revision:0:12} could not be downloaded from ${base}/${name}." >&2
    echo "CI publishes it a few minutes after each alpha and main commit; try again then." >&2
    return 1
  fi
  expected="$(awk '{print $1; exit}' "${work}/agent.sha256")"
  actual="$(sha256sum "${work}/agent" | awk '{print $1}')"
  if [[ ! "${expected}" =~ ^[0-9a-f]{64}$ || "${actual}" != "${expected}" ]]; then
    echo "easy-ha-proxy: the downloaded host agent does not match its published SHA-256; it was not installed." >&2
    return 1
  fi
  easy_ha_proxy_install_agent "${work}/agent" "${destination}" || return 1
  echo "Fetched the host agent built from ${revision:0:12} (${arch})." >&2
)
