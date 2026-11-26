# shellcheck shell=bash
# The host agent built for a source revision, from the project's GitHub
# release "agent-builds" (CI uploads the agent of every published alpha and
# main commit there, each binary beside its SHA-256) or, on a host without
# Internet access, from its local native bundle. A host gets its first
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
  if [[ -d "${source}/.git" ]]; then
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

# A top-level scalar of the host's vars.yml, unquoted; empty when unset.
easy_ha_proxy_config_value() {
  local file="${EASY_HA_PROXY_CONFIG_DIR:-/etc/easy-ha-proxy}/vars.yml"
  [[ -r "${file}" ]] || return 0
  awk -v key="$1" '
    index($0, key ":") == 1 {
      value = substr($0, length(key) + 2)
      sub(/[[:space:]]+#.*$/, "", value)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
      if (value ~ /^".*"$/ || value ~ /^\047.*\047$/) value = substr(value, 2, length(value) - 2)
      print value
      exit
    }' "${file}"
}

easy_ha_proxy_install_agent() {
  local binary="$1" destination="$2"
  install -d -m 0755 "$(dirname "${destination}")"
  install -m 0755 "${binary}" "${destination}.partial"
  mv -f "${destination}.partial" "${destination}"
}

# easy_ha_proxy_fetch_agent SOURCE_DIR DESTINATION: install the agent built
# for SOURCE_DIR's revision. A host that takes the native binaries from a
# local bundle (native_local_bundle_dir, a host without Internet access) gets
# it from there, as the native stage does; any other downloads it and checks
# it against its published SHA-256.
easy_ha_proxy_fetch_agent() {
  local source="$1" destination="$2" revision arch name base work expected actual bundle_dir bundle
  if ! arch="$(easy_ha_proxy_agent_arch)"; then
    echo "easy-ha-proxy: unsupported architecture $(uname -m); the host agent exists for amd64 and arm64." >&2
    return 1
  fi
  bundle_dir="$(easy_ha_proxy_config_value native_local_bundle_dir)"
  if [[ -n "${bundle_dir}" ]]; then
    bundle="${bundle_dir%/}/easy-ha-proxy-native-linux-${arch}.tar.gz"
    work="$(mktemp -d)"
    if ! tar -xzf "${bundle}" -C "${work}" sbin/easy-ha-proxy-agent 2>/dev/null &&
      ! tar -xzf "${bundle}" -C "${work}" ./sbin/easy-ha-proxy-agent 2>/dev/null; then
      rm -rf "${work}"
      echo "easy-ha-proxy: ${bundle} (native_local_bundle_dir) holds no sbin/easy-ha-proxy-agent." >&2
      return 1
    fi
    easy_ha_proxy_install_agent "${work}/sbin/easy-ha-proxy-agent" "${destination}"
    rm -rf "${work}"
    echo "Installed the host agent from ${bundle}." >&2
    return 0
  fi
  if ! revision="$(easy_ha_proxy_source_revision "${source}")"; then
    echo "easy-ha-proxy: cannot tell which revision ${source} is, so the matching host agent cannot be fetched." >&2
    return 1
  fi
  base="${easy_ha_proxy_agent_release_url%/}"
  name="easy-ha-proxy-agent-${revision}-linux-${arch}"
  work="$(mktemp -d)"
  if ! curl -fsSL --retry 3 --connect-timeout 20 -o "${work}/agent" "${base}/${name}" ||
    ! curl -fsSL --retry 3 --connect-timeout 20 -o "${work}/agent.sha256" "${base}/${name}.sha256"; then
    rm -rf "${work}"
    echo "easy-ha-proxy: the host agent built from ${revision:0:12} could not be downloaded from ${base}/${name}." >&2
    echo "CI publishes it a few minutes after each alpha and main commit; try again then." >&2
    return 1
  fi
  expected="$(awk '{print $1; exit}' "${work}/agent.sha256")"
  actual="$(sha256sum "${work}/agent" | awk '{print $1}')"
  if [[ ! "${expected}" =~ ^[0-9a-f]{64}$ || "${actual}" != "${expected}" ]]; then
    rm -rf "${work}"
    echo "easy-ha-proxy: the downloaded host agent does not match its published SHA-256; it was not installed." >&2
    return 1
  fi
  easy_ha_proxy_install_agent "${work}/agent" "${destination}"
  rm -rf "${work}"
  echo "Fetched the host agent built from ${revision:0:12} (${arch})." >&2
}
