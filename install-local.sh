#!/usr/bin/env bash
set -Eeuo pipefail

product="easy-ha-proxy"
repository="${EASY_HA_PROXY_REPOSITORY:-https://github.com/CLLlAgOB/easy-ha-proxy.git}"
config_dir="${EASY_HA_PROXY_CONFIG_DIR:-/etc/easy-ha-proxy}"
install_root="${EASY_HA_PROXY_HOME:-/opt/easy-ha-proxy}"
source_dir="${install_root}/source"
agent_bin="${EASY_HA_PROXY_AGENT_BIN:-/usr/local/sbin/easy-ha-proxy-agent}"
staged_agent="${EASY_HA_PROXY_STAGED_AGENT:-/var/lib/easy-ha-proxy/native-staging/bootstrap/easy-ha-proxy-agent}"
prepare_only=false
skip_bootstrap_dependencies=false
use_existing_source="${EASY_HA_PROXY_USE_EXISTING_SOURCE:-false}"

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --prepare-only)
      prepare_only=true
      shift
      ;;
    --skip-bootstrap-dependencies)
      skip_bootstrap_dependencies=true
      shift
      ;;
    *)
      break
      ;;
  esac
done

log() {
  printf '\n[%s] %s\n' "${product}" "$*"
}

die() {
  printf '\n[%s] ERROR: %s\n' "${product}" "$*" >&2
  exit 1
}

# The branch this gateway follows, which checks compare with and updates
# fetch: an explicit EASY_HA_PROXY_BRANCH, else the branch the installer
# recorded in metadata.yml (the alpha channel records alpha), else main.
# easy-ha-proxy-helper.sh and install-local.sh resolve it the same way.
gateway_branch() {
  local recorded=""
  if [[ -n "${EASY_HA_PROXY_BRANCH:-}" ]]; then
    printf '%s\n' "${EASY_HA_PROXY_BRANCH}"
    return
  fi
  if [[ -r "${config_dir}/metadata.yml" ]]; then
    recorded="$(
      awk -F':[[:space:]]*' '$1 == "branch" {gsub(/["\047[:space:]]/, "", $2); print $2; exit}' \
        "${config_dir}/metadata.yml" 2>/dev/null || true
    )"
  fi
  # Only a plain branch name is taken from the file.
  if [[ "${recorded}" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$ &&
        "${recorded}" != *..* && "${recorded}" != *//* &&
        "${recorded}" != */ && "${recorded}" != *.lock ]]; then
    printf '%s\n' "${recorded}"
  else
    printf 'main\n'
  fi
}
branch="$(gateway_branch)"

if [[ "${EUID}" -ne 0 ]]; then
  die "Run as root, for example: sudo bash /tmp/easy-ha-proxy-install-local.sh"
fi

if [[ "${skip_bootstrap_dependencies}" == "true" ]]; then
  if [[ "${prepare_only}" != "true" ]]; then
    die "--skip-bootstrap-dependencies is only valid with --prepare-only"
  fi
  if [[ "${use_existing_source}" != "true" ]]; then
    die "--skip-bootstrap-dependencies requires EASY_HA_PROXY_USE_EXISTING_SOURCE=true"
  fi
fi

if [[ ! -r /etc/os-release ]]; then
  die "Cannot detect the operating system."
fi

# shellcheck disable=SC1091
source /etc/os-release
case "${ID:-}" in
  debian|ubuntu)
    ;;
  *)
    die "Supported operating systems: Debian and Ubuntu (detected: ${ID:-unknown})."
    ;;
esac

if [[ ! -d /run/systemd/system ]]; then
  die "A systemd-based host is required; containers and WSL are not supported targets."
fi

architecture="$(dpkg --print-architecture 2>/dev/null || true)"
case "${architecture}" in
  amd64|arm64)
    ;;
  *)
    die "Supported architectures: amd64 and arm64 (detected: ${architecture:-unknown})."
    ;;
esac

if [[ "${ID}" == "debian" ]] && ! dpkg --compare-versions "${VERSION_ID}" ge "12"; then
  die "Debian 12 or newer is required."
fi
if [[ "${ID}" == "ubuntu" ]] && ! dpkg --compare-versions "${VERSION_ID}" ge "22.04"; then
  die "Ubuntu 22.04 or newer is required."
fi

if [[ "${skip_bootstrap_dependencies}" != "true" ]]; then
  export DEBIAN_FRONTEND=noninteractive
  log "Installing bootstrap dependencies"
  apt-get update
  apt-get install -y --no-install-recommends ca-certificates curl git openssl
fi

install -d -m 0755 "${install_root}"

if [[ "${use_existing_source}" == "true" ]]; then
  for required in \
    installer/easy-ha-proxy \
    installer/agent-fetch.sh \
    ansible/easy-ha-proxy.yml; do
    [[ -f "${source_dir}/${required}" ]] ||
      die "Staged source is incomplete: ${source_dir}/${required}"
  done
  log "Using the source already staged in ${source_dir}"
elif [[ -d "${source_dir}/.git" ]]; then
  log "Updating source checkout"
  git -C "${source_dir}" fetch --depth=1 origin "${branch}"
  # A shallow clone only tracks its original branch. Fetching another branch
  # need not create origin/<branch>, so use the commit this fetch delivered.
  fetched_revision="$(git -C "${source_dir}" rev-parse --verify 'FETCH_HEAD^{commit}')"
  git -C "${source_dir}" reset --hard "${fetched_revision}"
elif [[ -e "${source_dir}" ]]; then
  backup="${source_dir}.before-install.$(date -u +%Y%m%dT%H%M%SZ)"
  log "Moving the existing unmanaged source directory to ${backup}"
  mv "${source_dir}" "${backup}"
  git clone --depth=1 --branch "${branch}" "${repository}" "${source_dir}"
else
  log "Downloading ${repository} (${branch})"
  git clone --depth=1 --branch "${branch}" "${repository}" "${source_dir}"
fi

# The installer is the host agent's "cli". A host without an agent that runs
# it gets the one built for this source from the project's GitHub release.
# shellcheck source=installer/agent-fetch.sh
source "${source_dir}/installer/agent-fetch.sh"
if easy_ha_proxy_agent_runs_cli "${agent_bin}" || easy_ha_proxy_agent_runs_cli "${staged_agent}"; then
  log "The host agent is ready"
elif [[ "${skip_bootstrap_dependencies}" == "true" ]]; then
  die "The prepared host agent is missing: ${agent_bin}"
else
  log "Fetching the host agent"
  easy_ha_proxy_fetch_agent "${source_dir}" "${staged_agent}" ||
    die "The host agent could not be fetched."
  easy_ha_proxy_agent_runs_cli "${staged_agent}" ||
    die "The fetched host agent cannot run the installer; it is older than this source."
fi

chmod 0755 \
  "${source_dir}/install.sh" \
  "${source_dir}/install-local.sh" \
  "${source_dir}/install-remote.sh" \
  "${source_dir}/easy-ha-proxy-helper.sh" \
  "${source_dir}/installer/easy-ha-proxy"
ln -sfn "${source_dir}/installer/easy-ha-proxy" /usr/local/bin/easy-ha-proxy
ln -sfn "${source_dir}/install.sh" /usr/local/bin/easy-ha-proxy-assistant

log "Local installer preparation completed"
if [[ "${prepare_only}" == true ]]; then
  log "Control plane is ready; no playbook was applied and no application service was changed"
  exit 0
fi
if [[ "$#" -eq 0 ]]; then
  exec /usr/local/bin/easy-ha-proxy install
fi
if [[ "$1" == -* ]]; then
  exec /usr/local/bin/easy-ha-proxy install "$@"
fi
exec /usr/local/bin/easy-ha-proxy "$@"
