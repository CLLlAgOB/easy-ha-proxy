#!/usr/bin/env bash
set -Eeuo pipefail

product="easy-ha-proxy"
repository="${EASY_HA_PROXY_REPOSITORY:-https://github.com/CLLlAgOB/easy-ha-proxy.git}"
branch="${EASY_HA_PROXY_BRANCH:-main}"
install_root="${EASY_HA_PROXY_HOME:-/opt/easy-ha-proxy}"
source_dir="${install_root}/source"
venv_dir="${install_root}/venv"
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
  apt-get install -y --no-install-recommends \
    ca-certificates curl git openssl python3 python3-apt python3-pip python3-venv
fi

install -d -m 0755 "${install_root}"

if [[ "${use_existing_source}" == "true" ]]; then
  for required in \
    installer/easy-ha-proxy \
    installer/easy_ha_proxy.py \
    installer/requirements.txt \
    ansible/easy-ha-proxy.yml \
    ansible/requirements.yml; do
    [[ -f "${source_dir}/${required}" ]] ||
      die "Staged source is incomplete: ${source_dir}/${required}"
  done
  log "Using the source already staged in ${source_dir}"
elif [[ -d "${source_dir}/.git" ]]; then
  log "Updating source checkout"
  git -C "${source_dir}" fetch --depth=1 origin "${branch}"
  git -C "${source_dir}" reset --hard "origin/${branch}"
elif [[ -e "${source_dir}" ]]; then
  backup="${source_dir}.before-install.$(date -u +%Y%m%dT%H%M%SZ)"
  log "Moving the existing unmanaged source directory to ${backup}"
  mv "${source_dir}" "${backup}"
  git clone --depth=1 --branch "${branch}" "${repository}" "${source_dir}"
else
  log "Downloading ${repository} (${branch})"
  git clone --depth=1 --branch "${branch}" "${repository}" "${source_dir}"
fi

if [[ "${skip_bootstrap_dependencies}" == "true" ]]; then
  log "Reusing the prepared Python and Ansible control plane"
  [[ -x "${venv_dir}/bin/python" ]] ||
    die "Prepared Python environment is missing: ${venv_dir}/bin/python"
  [[ -x "${venv_dir}/bin/ansible-playbook" ]] ||
    die "Prepared Ansible executable is missing: ${venv_dir}/bin/ansible-playbook"
else
  log "Creating isolated Python environment"
  python3 -m venv "${venv_dir}"
  "${venv_dir}/bin/pip" install --disable-pip-version-check --upgrade pip
  "${venv_dir}/bin/pip" install \
    --disable-pip-version-check \
    -r "${source_dir}/installer/requirements.txt"

  log "Installing Ansible collections"
  ANSIBLE_LOCAL_TEMP=/tmp/easy-ha-proxy-ansible \
    "${venv_dir}/bin/ansible-galaxy" collection install \
    -r "${source_dir}/ansible/requirements.yml"
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
