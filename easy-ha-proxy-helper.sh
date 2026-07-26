#!/usr/bin/env bash
set -Eeuo pipefail

product="easy-ha-proxy"
helper_version="2026.07.19-web-updates1"
branch="${EASY_HA_PROXY_BRANCH:-main}"
raw_base="${EASY_HA_PROXY_RAW_BASE:-https://raw.githubusercontent.com/CLLlAgOB/easy-ha-proxy/${branch}}"
install_home="${EASY_HA_PROXY_HOME:-/opt/easy-ha-proxy}"
config_dir="${EASY_HA_PROXY_CONFIG_DIR:-/etc/easy-ha-proxy}"
reboot_schedule_marker="/run/easy-ha-proxy/reboot-scheduled"
local_installer="${EASY_HA_PROXY_LOCAL_INSTALLER:-}"
helper_path="${BASH_SOURCE[0]}"
action="menu"
skip_dns_check=false
certificate_source=""
source_channel=""
image_channel=""
new_domain=""
plan_only=false
temporary_installer=""
temporary_update_checkout=""
remote_source_snapshot=""
input_fd=0
language_from_env="${EASY_HA_PROXY_LANGUAGE:-}"
language="${language_from_env:-en}"
requested_language=""
case "${language}" in
  en|ru) ;;
  *) language="en" ;;
esac
if { exec 3</dev/tty; } 2>/dev/null; then
  input_fd=3
fi

usage() {
  cat <<'EOF'
Usage:
  easy-ha-proxy-helper.sh [--action ACTION] [options]

Actions:
  menu             Detect the system and show an interactive menu (default)
  inspect          Show detected installation and configuration
  status           Run the full application health check
  check-config     Validate managed files, HAProxy and Compose configuration
  plan             Preview managed changes with Ansible check mode
  check-updates    Compare source with GitHub and show cached OS updates
  smart-update     Check updates, then update only selected found items
  update           Update source, dependencies and the complete stack
  apply-current    Apply installed source without fetching GitHub
  update-ui        Update only the web UI container
  update-containers
                   Update easy-ha-proxy Docker Compose images/stacks
  reboot           Reboot the server when operating-system updates require it
  configure        Run the configuration wizard and apply changes
  migrate-domain   Preview and safely replace the managed root domain
  promote-production
                   Promote test mode to production without reinstalling
  install          Install in production mode
  install-test     Install on a VM without public IP or DNS
  install-reset    Restart production configuration, preserving a backup
  install-test-reset
                   Restart test configuration, preserving a backup
  repair           Reapply the complete installation
  backup-full      Create an encrypted full disaster-recovery backup
  test-info        Show test-mode access information
  snapshot-legacy  Back up a working legacy installation
  migration-plan   Show the safe legacy adoption sequence

Options:
      --language CODE  Use en or ru; with --action language, save it
      --certificate-source SOURCE
                       Use letsencrypt or internal for install/configure
      --source-channel CHANNEL
                       Use github or the already synchronized local source
      --image-channel CHANNEL
                       Use latest (release) or alpha (test build)
      --skip-dns-check  Skip DNS preflight during production installation
      --new-domain NAME New root domain for migrate-domain
      --plan-only       Preview domain migration without applying it
  -h, --help            Show this help
EOF
}

log() {
  printf '\n[%s] %s\n' "${product}" "$*"
}

warn() {
  printf '[%s] WARNING: %s\n' "${product}" "$*" >&2
}

die() {
  printf '[%s] ERROR: %s\n' "${product}" "$*" >&2
  exit 1
}

message() {
  local english="$1"
  local russian="$2"
  if [[ "${language}" == "ru" ]]; then
    printf '%s' "${russian}"
  else
    printf '%s' "${english}"
  fi
}

cleanup() {
  if [[ -n "${temporary_installer}" ]]; then
    rm -f "${temporary_installer}"
  fi
  if [[ -n "${temporary_update_checkout}" ]]; then
    rm -rf "${temporary_update_checkout}"
  fi
}
trap cleanup EXIT

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --action)
      [[ "$#" -ge 2 ]] || die "Missing action after --action."
      action="$2"
      shift 2
      ;;
    --test-mode)
      action="install-test"
      shift
      ;;
    --language)
      [[ "$#" -ge 2 ]] || die "Missing language code."
      requested_language="${2,,}"
      case "${requested_language}" in
        en|ru) language="${requested_language}" ;;
        *) die "Language must be en or ru." ;;
      esac
      shift 2
      ;;
    --skip-dns-check)
      skip_dns_check=true
      shift
      ;;
    --certificate-source)
      [[ "$#" -ge 2 ]] || die "The certificate source was not provided."
      certificate_source="${2,,}"
      case "${certificate_source}" in
        letsencrypt|internal) ;;
        *) die "Certificate source must be letsencrypt or internal." ;;
      esac
      shift 2
      ;;
    --source-channel|--source)
      [[ "$#" -ge 2 ]] || die "The source channel was not provided."
      source_channel="${2,,}"
      case "${source_channel}" in
        github|local) ;;
        *) die "Source channel must be github or local." ;;
      esac
      shift 2
      ;;
    --image-channel|--image)
      [[ "$#" -ge 2 ]] || die "The image channel was not provided."
      image_channel="${2,,}"
      case "${image_channel}" in
        latest|alpha) ;;
        *) die "Image channel must be latest or alpha." ;;
      esac
      shift 2
      ;;
    --new-domain)
      [[ "$#" -ge 2 ]] || die "The new domain was not provided."
      new_domain="$2"
      shift 2
      ;;
    --plan-only)
      plan_only=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "Unknown option: $1"
      ;;
  esac
done

case "${action}" in
  menu|inspect|status|check-config|plan|check-updates|smart-update|update|apply-current|update-ui|update-containers|reboot|configure|language|migrate-domain|promote-production|install|install-test|install-reset|install-test-reset|repair|backup-full|test-info|snapshot-legacy|migration-plan)
    ;;
  *)
    die "Unknown action: ${action}"
    ;;
esac

if [[ -z "${language_from_env}" && -r "${config_dir}/metadata.yml" ]]; then
  remembered_language="$(
    awk -F':[[:space:]]*' '$1 == "installer_language" {gsub(/["\047[:space:]]/, "", $2); print tolower($2); exit}' \
      "${config_dir}/metadata.yml" 2>/dev/null || true
  )"
  case "${remembered_language}" in
    en|ru) language="${remembered_language}" ;;
  esac
fi
export EASY_HA_PROXY_LANGUAGE="${language}"

if [[ "${EUID}" -ne 0 ]]; then
  if [[ "${EASY_HA_PROXY_HELPER_ALLOW_NON_ROOT:-0}" == "1" ]]; then
    :
  else
    command -v sudo >/dev/null 2>&1 ||
      die "Root or sudo is required for diagnostics and management."
    sudo_arguments=(bash "${helper_path}" --action "${action}")
    [[ -n "${requested_language}" ]] && sudo_arguments+=(--language "${requested_language}")
    if [[ "${skip_dns_check}" == true ]]; then
      sudo_arguments+=(--skip-dns-check)
    fi
    [[ -n "${certificate_source}" ]] &&
      sudo_arguments+=(--certificate-source "${certificate_source}")
    [[ -n "${source_channel}" ]] &&
      sudo_arguments+=(--source-channel "${source_channel}")
    [[ -n "${image_channel}" ]] &&
      sudo_arguments+=(--image-channel "${image_channel}")
    [[ -n "${new_domain}" ]] && sudo_arguments+=(--new-domain "${new_domain}")
    [[ "${plan_only}" == true ]] && sudo_arguments+=(--plan-only)
    exec sudo \
      env \
        EASY_HA_PROXY_HOME="${install_home}" \
        EASY_HA_PROXY_CONFIG_DIR="${config_dir}" \
        EASY_HA_PROXY_BRANCH="${branch}" \
        EASY_HA_PROXY_RAW_BASE="${raw_base}" \
        EASY_HA_PROXY_LOCAL_INSTALLER="${local_installer}" \
        EASY_HA_PROXY_LANGUAGE="${language}" \
        "${sudo_arguments[@]}"
  fi
fi

metadata_file="${config_dir}/metadata.yml"
source_dir="${install_home}/source"
venv_python="${install_home}/venv/bin/python"
playbook_file="${source_dir}/ansible/easy-ha-proxy.yml"
legacy_haproxy_config="${EASY_HA_PROXY_LEGACY_HAPROXY_CONFIG:-/etc/haproxy/haproxy.cfg}"
legacy_authelia_compose="${EASY_HA_PROXY_LEGACY_AUTHELIA_COMPOSE:-/opt/authelia/docker-compose.yml}"
legacy_admin_compose="${EASY_HA_PROXY_LEGACY_ADMIN_COMPOSE:-/opt/haproxy-admin/docker-compose.yml}"

daemon_units=(
  haproxy-certd.service
  haproxy-controld.service
  haproxy-healthd.service
  easy-ha-proxy-backupd.service
  easy-ha-proxy-updated.service
  authelia-configd.service
  authelia-usersd.service
  authelia-bansd.service
)
daemon_labels=(
  "HAProxy certificate daemon"
  "HAProxy control daemon"
  "HAProxy health daemon"
  "Full backup and restore daemon"
  "Software update broker"
  "Authelia config daemon"
  "Authelia users daemon"
  "Authelia bans daemon"
)
daemon_scripts=(
  /usr/local/sbin/haproxy-certd.py
  /usr/local/sbin/haproxy-controld.py
  /usr/local/sbin/haproxy-healthd.py
  /usr/local/sbin/easy-ha-proxy-backupd.py
  /usr/local/sbin/easy-ha-proxy-updated.py
  /usr/local/sbin/authelia-configd.py
  /usr/local/sbin/authelia-usersd.py
  /usr/local/sbin/authelia-bansd.py
)
daemon_sources=(
  ansible/roles/haproxy-admin/files/haproxy-certd.py
  ansible/roles/haproxy-admin/files/haproxy-controld.py
  ansible/roles/haproxy-admin/files/haproxy-healthd.py
  ansible/roles/haproxy-admin/files/easy-ha-proxy-backupd.py
  ansible/roles/haproxy-admin/files/easy-ha-proxy-updated.py
  ansible/roles/authelia/files/authelia-configd.py
  ansible/roles/authelia/files/authelia-usersd.py
  ansible/roles/authelia/files/authelia-bansd.py
)
managed_unit_units=(
  iptables-haproxy-ban.service
  update-admin-rt.timer
  journal-vacuum.timer
  easy-ha-proxy-geoip-update.service
  easy-ha-proxy-geoip-update.timer
  snap.certbot.renew.timer
)
managed_unit_labels=(
  "HAProxy iptables ban loader"
  "Dynamic admin IP timer"
  "Journal vacuum timer"
  "Local GeoIP database updater"
  "Local GeoIP database update timer"
  "Certbot renewal timer"
)
host_unit_units=(
  docker.service
  systemd-journald.service
  systemd-timesyncd.service
  apparmor.service
  rsyslog.service
  logrotate.timer
)
host_unit_labels=(
  "Docker"
  "systemd journal"
  "Time synchronization"
  "AppArmor"
  "rsyslog"
  "Authelia logrotate timer"
)

repair_managed_entrypoints() {
  local path=""
  local -a executables=(
    "${source_dir}/install.sh"
    "${source_dir}/install-local.sh"
    "${source_dir}/install-remote.sh"
    "${source_dir}/easy-ha-proxy-helper.sh"
    "${source_dir}/installer/easy-ha-proxy"
  )

  [[ -d "${source_dir}" ]] || return 0
  for path in "${executables[@]}"; do
    if [[ -f "${path}" && ! -x "${path}" ]]; then
      chmod 0755 "${path}" 2>/dev/null ||
        warn "Не удалось восстановить executable bit: ${path}"
    fi
  done

  if [[ -f "${source_dir}/installer/easy-ha-proxy" ]]; then
    if [[ -L /usr/local/bin/easy-ha-proxy ||
          ! -e /usr/local/bin/easy-ha-proxy ]]; then
      ln -sfn "${source_dir}/installer/easy-ha-proxy" \
        /usr/local/bin/easy-ha-proxy 2>/dev/null ||
        warn "Не удалось восстановить symlink /usr/local/bin/easy-ha-proxy"
    fi
  fi
  if [[ -f "${source_dir}/install.sh" ]]; then
    if [[ -L /usr/local/bin/easy-ha-proxy-assistant ||
          ! -e /usr/local/bin/easy-ha-proxy-assistant ]]; then
      ln -sfn "${source_dir}/install.sh" \
        /usr/local/bin/easy-ha-proxy-assistant 2>/dev/null ||
        warn "Не удалось восстановить symlink /usr/local/bin/easy-ha-proxy-assistant"
    fi
  fi
}

repair_managed_entrypoints

cli_path=""
if [[ -x /usr/local/bin/easy-ha-proxy ]]; then
  cli_path="/usr/local/bin/easy-ha-proxy"
elif [[ -x "${source_dir}/installer/easy-ha-proxy" ]]; then
  cli_path="${source_dir}/installer/easy-ha-proxy"
fi

installation_state="clean"
control_plane_ready=false
if [[ -n "${cli_path}" &&
      -f "${metadata_file}" &&
      -x "${venv_python}" &&
      -f "${playbook_file}" ]]; then
  control_plane_ready=true
fi
if [[ "${control_plane_ready}" == true ]]; then
  if grep -Eq '^[[:space:]]*configuration_pending:[[:space:]]*true([[:space:]]|$)' \
      "${metadata_file}" ||
     grep -Eq '^[[:space:]]*installation_complete:[[:space:]]*false([[:space:]]|$)' \
      "${metadata_file}"; then
    installation_state="partial"
  elif grep -Eq '^[[:space:]]*installation_complete:[[:space:]]*true([[:space:]]|$)' \
      "${metadata_file}"; then
    installation_state="installed"
  elif [[ -e /etc/systemd/system/haproxy-certd.service &&
          -e /etc/systemd/system/haproxy-controld.service &&
          -e /etc/haproxy/haproxy.cfg &&
          -e /opt/haproxy-admin/docker-compose.yml &&
          -e /opt/authelia/docker-compose.yml ]]; then
    # Backward compatibility for installations created before completion
    # metadata was introduced.
    installation_state="installed"
  else
    installation_state="partial"
  fi
elif [[ -f "${legacy_haproxy_config}" &&
        -f "${legacy_authelia_compose}" &&
        -f "${legacy_admin_compose}" ]]; then
  installation_state="legacy"
elif [[ -e "${install_home}" ||
        -e "${config_dir}" ||
        -e /usr/local/bin/easy-ha-proxy ||
        -L /usr/local/bin/easy-ha-proxy ||
        -e /opt/authelia ||
        -e /opt/haproxy-admin ||
        -e /etc/systemd/system/haproxy-healthd.service ]]; then
  installation_state="partial"
fi

configuration_mode="unknown"
if [[ -r "${metadata_file}" ]]; then
  if grep -Eq '^[[:space:]]*test_mode:[[:space:]]*true([[:space:]]|$)' \
    "${metadata_file}"; then
    configuration_mode="test"
  else
    configuration_mode="production"
  fi
fi

yaml_scalar() {
  local key="$1"
  local file="$2"
  awk -F':[[:space:]]*' -v wanted="${key}" '
    $1 == wanted {
      value = substr($0, index($0, ":") + 1)
      sub(/^[[:space:]]+/, "", value)
      gsub(/^["\047]|["\047]$/, "", value)
      print value
      exit
    }
  ' "${file}" 2>/dev/null || true
}

configured_certificate_source=""
if [[ -r "${metadata_file}" ]]; then
  configured_certificate_source="$(yaml_scalar certificate_source "${metadata_file}")"
fi

state_label() {
  case "${installation_state}" in
    clean) message 'clean system' 'чистая система' ;;
    partial) message 'partial/incomplete installation' 'частичная/незавершённая установка' ;;
    legacy) message 'working legacy installation (not managed yet)' 'работающая legacy-установка (ещё не принята под управление)' ;;
    installed) message 'installed and managed by easy-ha-proxy' 'установлено и управляется easy-ha-proxy' ;;
  esac
}

mode_label() {
  case "${configuration_mode}" in
    test) message 'test (local CA, no public DNS)' 'тестовая (локальная CA, без публичного DNS)' ;;
    production)
      if [[ "${configured_certificate_source}" == "internal" ]]; then
        message \
          'production (internal CA; private or public DNS)' \
          'production (внутренний CA; приватный или публичный DNS)'
      else
        message \
          "production (Let's Encrypt; public DNS required for issuance)" \
          'production (Let'\''s Encrypt; для выпуска нужен публичный DNS)'
      fi
      ;;
    *) message 'unknown' 'не определена' ;;
  esac
}

print_service_line() {
  local unit="$1"
  local label="$2"
  local script="${3:-}"
  local source_relative="${4:-}"
  local state="not-installed"
  local installed_version=""
  local source_version=""
  local version_text=""
  if command -v systemctl >/dev/null 2>&1 &&
     systemctl cat "${unit}" >/dev/null 2>&1; then
    state="$(systemctl is-active "${unit}" 2>/dev/null || true)"
    [[ -n "${state}" ]] || state="unknown"
  fi
  if [[ -n "${script}" && -f "${script}" ]] &&
     command -v sha256sum >/dev/null 2>&1; then
    installed_version="$(
      sha256sum "${script}" | awk '{ print substr($1, 1, 12) }'
    )"
    version_text=" | version=${installed_version}"
    if [[ -n "${source_relative}" &&
          -f "${source_dir}/${source_relative}" ]]; then
      source_version="$(
        sha256sum "${source_dir}/${source_relative}" |
          awk '{ print substr($1, 1, 12) }'
      )"
      if [[ "${installed_version}" == "${source_version}" ]]; then
        version_text+=" (current)"
      else
        version_text+=" -> ${source_version} (update available)"
      fi
    fi
  fi
  printf '  %-30s %-13s%s\n' "${label}:" "${state}" "${version_text}"
}

inspect_system() {
  local admin_domain=""
  local authelia_domain=""
  local configured_at=""
  local source_revision="none"
  local source_branch="none"
  local unit=""
  local ignored=""
  local -A known_daemons=()

  if [[ -r "${metadata_file}" ]]; then
    admin_domain="$(yaml_scalar admin_domain "${metadata_file}")"
    authelia_domain="$(yaml_scalar authelia_domain "${metadata_file}")"
    configured_at="$(yaml_scalar configured_at "${metadata_file}")"
  fi
  if [[ -d "${source_dir}/.git" ]] && command -v git >/dev/null 2>&1; then
    source_revision="$(git -C "${source_dir}" rev-parse --short HEAD 2>/dev/null || printf 'unknown')"
    source_branch="$(git -C "${source_dir}" branch --show-current 2>/dev/null || printf 'unknown')"
  fi

  printf '\n=== easy-ha-proxy: %s ===\n' "$(message 'detected state' 'обнаруженное состояние')"
  printf '%s: %s\n' "$(message 'Assistant' 'Помощник')" "${helper_version}"
  printf '%s: %s\n' "$(message 'State' 'Состояние')" "$(state_label)"
  printf '%s: %s\n' "$(message 'Mode' 'Режим')" "$(mode_label)"
  printf '%s: %s\n' "$(message 'Install directory' 'Каталог системы')" "${install_home}"
  printf '%s: %s\n' "$(message 'Configuration directory' 'Каталог конфигурации')" "${config_dir}"
  printf 'CLI: %s\n' "${cli_path:-$(message 'not found' 'не найден')}"
  printf 'Git:             branch=%s, commit=%s\n' "${source_branch}" "${source_revision}"
  [[ -n "${configured_at}" ]] &&
    printf '%s: %s\n' "$(message 'Configured at' 'Настроено')" "${configured_at}"
  [[ -n "${admin_domain}" ]] &&
    printf '%s: %s\n' "$(message 'Admin domain' 'Домен админки')" "${admin_domain}"
  [[ -n "${authelia_domain}" ]] &&
    printf '%s: %s\n' "$(message 'Authelia domain' 'Домен Authelia')" "${authelia_domain}"

  printf '\n%s:\n' "$(message 'Component status' 'Быстрый статус компонентов')"
  print_service_line haproxy.service "HAProxy"
  for i in "${!daemon_units[@]}"; do
    known_daemons["${daemon_units[i]}"]=1
    print_service_line \
      "${daemon_units[i]}" \
      "${daemon_labels[i]}" \
      "${daemon_scripts[i]}" \
      "${daemon_sources[i]}"
  done
  for i in "${!managed_unit_units[@]}"; do
    print_service_line \
      "${managed_unit_units[i]}" \
      "${managed_unit_labels[i]}"
  done
  printf '\n%s:\n' "$(message \
    'Host prerequisites (informational; they do not mean easy-ha-proxy is installed)' \
    'Системные службы (справочно; их наличие не означает, что easy-ha-proxy установлен)')"
  for i in "${!host_unit_units[@]}"; do
    print_service_line \
      "${host_unit_units[i]}" \
      "${host_unit_labels[i]}"
  done
  if command -v systemctl >/dev/null 2>&1; then
    while read -r unit ignored; do
      [[ -n "${unit}" ]] || continue
      if [[ -z "${known_daemons[${unit}]+x}" ]]; then
        print_service_line "${unit}" "${unit} (discovered)"
      fi
    done < <(
      systemctl list-unit-files \
        --type=service \
        --no-legend \
        'haproxy-*d.service' \
        'authelia-*d.service' 2>/dev/null ||
        true
    )
  fi
}

basic_health() {
  local unit=""
  local state=""
  local -a units=(
    haproxy.service
    "${daemon_units[@]}"
    "${managed_unit_units[@]}"
    "${host_unit_units[@]}"
  )

  printf '\n=== %s ===\n' "$(message 'Basic legacy/partial installation check' 'Базовая проверка старой/частичной установки')"
  if command -v systemctl >/dev/null 2>&1; then
    for unit in "${units[@]}"; do
      systemctl cat "${unit}" >/dev/null 2>&1 || continue
      state="$(systemctl is-active "${unit}" 2>/dev/null || true)"
      printf '  %-32s %s\n' "${unit}" "${state:-unknown}"
    done
  else
    printf '[INFO] %s\n' "$(message 'systemctl was not found' 'systemctl не найден')"
  fi

  if command -v docker >/dev/null 2>&1; then
    printf '\n%s:\n' "$(message 'Docker containers' 'Docker-контейнеры')"
    docker ps -a \
      --format '  {{.Names}} | {{.Status}} | {{.Image}}' 2>/dev/null ||
      printf '  %s\n' "$(message 'Failed to query Docker.' 'Не удалось прочитать Docker.')"
  else
    printf '\n[INFO] %s\n' "$(message 'Docker was not found' 'Docker не найден')"
  fi

  if command -v ss >/dev/null 2>&1; then
    printf '\n%s 80/443/5000/9091:\n' "$(message 'Listening ports' 'Слушающие порты')"
    ss -ltnp 2>/dev/null |
      awk 'NR == 1 || $4 ~ /:(80|443|5000|9091)$/ { print "  " $0 }'
  fi
}

ensure_installed() {
  if [[ "${installation_state}" != "installed" ]]; then
    die "$(message 'A complete managed installation was not detected. Current state' 'Полная управляемая установка не обнаружена. Текущее состояние'): $(state_label)."
  fi
}

ensure_local_installer() {
  if [[ -n "${local_installer}" && -r "${local_installer}" ]]; then
    return
  fi
  if [[ -r "$(dirname -- "${helper_path}")/install-local.sh" ]]; then
    local_installer="$(dirname -- "${helper_path}")/install-local.sh"
    return
  fi
  command -v curl >/dev/null 2>&1 ||
    die "$(message 'install-local.sh was not found and curl is unavailable for downloading it.' 'install-local.sh не найден, а curl для его загрузки недоступен.')"
  temporary_installer="$(mktemp -t easy-ha-proxy-install-local.XXXXXX.sh)"
  log "$(message 'Downloading the local installer' 'Загружаю локальный установщик')"
  curl -fsSL "${raw_base}/install-local.sh" -o "${temporary_installer}"
  chmod 0700 "${temporary_installer}"
  local_installer="${temporary_installer}"
}

run_install() {
  local mode="$1"
  local reconfigure="${2:-false}"
  local status=0
  local -a arguments=()
  ensure_local_installer

  [[ "${reconfigure}" == true ]] && arguments+=(--reconfigure)
  if [[ "${mode}" == "test" ]]; then
    arguments+=(--test-mode)
  elif [[ "${skip_dns_check}" == true ]]; then
    arguments+=(--skip-dns-check)
  fi
  if [[ -n "${certificate_source}" ]]; then
    arguments+=(--certificate-source "${certificate_source}")
  fi
  if [[ -n "${source_channel}" ]]; then
    arguments+=(--source-channel "${source_channel}")
  fi
  if [[ -n "${image_channel}" ]]; then
    arguments+=(--image-channel "${image_channel}")
  fi

  if [[ "${mode}" == "test" ]]; then
    log "$(message 'Starting test installation' 'Запускаю тестовую установку')"
  else
    log "$(message 'Starting production installation' 'Запускаю production-установку')"
  fi
  if [[ "${source_channel}" == "github" ]]; then
    log "$(message \
      'Refreshing the managed source from GitHub before continuing' \
      'Обновляю управляемые исходники из GitHub перед продолжением')"
    bash "${local_installer}" "${arguments[@]}" || status=$?
  elif [[ -f "${source_dir}/installer/easy_ha_proxy.py" &&
          -f "${source_dir}/ansible/easy-ha-proxy.yml" ]]; then
    log "$(message \
      'Continuing with the source already prepared on this server' \
      'Продолжаю с исходниками, уже подготовленными на этом сервере')"
    EASY_HA_PROXY_USE_EXISTING_SOURCE=true \
      bash "${local_installer}" "${arguments[@]}" || status=$?
  else
    bash "${local_installer}" "${arguments[@]}" || status=$?
  fi
  if [[ "${status}" -eq 0 && -f "${reboot_schedule_marker}" ]]; then
    exit 0
  fi
  return "${status}"
}

run_cli() {
  local status=0
  ensure_installed
  [[ -n "${cli_path}" ]] || die "$(message 'The easy-ha-proxy command was not found.' 'Команда easy-ha-proxy не найдена.')"
  "${cli_path}" "$@" || status=$?
  if [[ "${status}" -eq 0 && -f "${reboot_schedule_marker}" ]]; then
    exit 0
  fi
  return "${status}"
}

choose_deployment_channels() {
  local choice=""
  local current_source=""
  local current_image=""

  if [[ -z "${source_channel}" ]]; then
    current_source="$(yaml_scalar source_channel "${metadata_file}")"
    [[ "${current_source}" == local ]] || current_source="github"
    printf '\n%s\n' "$(message 'Source code for this update:' 'Исходный код для этого обновления:')"
    printf '  1) GitHub main\n'
    printf '  2) %s\n' "$(message 'Already synchronized local source' 'Уже синхронизированные локальные исходники')"
    choice="$(read_menu_choice "$(message 'Choose source' 'Выберите источник')")"
    if [[ -z "${choice}" ]]; then
      source_channel="${current_source}"
    elif [[ "${choice}" == "2" || "${choice,,}" == "local" ]]; then
      source_channel="local"
    else
      source_channel="github"
    fi
  fi

  if [[ -z "${image_channel}" ]]; then
    current_image="$(yaml_scalar image_channel "${metadata_file}")"
    [[ "${current_image}" == alpha ]] || current_image="latest"
    printf '\n%s\n' "$(message 'HAProxy Admin image:' 'Образ HAProxy Admin:')"
    printf '  1) latest (%s)\n' "$(message 'release' 'релиз')"
    printf '  2) alpha (%s)\n' "$(message 'test build' 'тестовая сборка')"
    choice="$(read_menu_choice "$(message 'Choose image channel' 'Выберите канал образа')")"
    if [[ -z "${choice}" ]]; then
      image_channel="${current_image}"
    elif [[ "${choice}" == "2" || "${choice,,}" == "alpha" ]]; then
      image_channel="alpha"
    else
      image_channel="latest"
    fi
  fi
}

cli_supports_update_component() {
  ensure_installed
  [[ -n "${cli_path}" ]] || return 1
  "${cli_path}" update --help 2>/dev/null | grep -q -- '--component'
}

cli_supports_language() {
  ensure_installed
  [[ -n "${cli_path}" ]] || return 1
  "${cli_path}" language --help >/dev/null 2>&1
}

cli_supports_daemon_component() {
  cli_supports_update_component &&
    "${cli_path}" update --help 2>/dev/null | grep -q -- 'daemons'
}

cli_supports_service_component() {
  cli_supports_update_component &&
    "${cli_path}" update --help 2>/dev/null | grep -q -- 'services'
}

check_file() {
  local path="$1"
  local description="$2"
  if [[ -f "${path}" ]]; then
    printf '[ OK ] %s: %s\n' "${description}" "${path}"
    return 0
  fi
  printf '[FAIL] %s: %s %s\n' "${description}" "$(message 'missing' 'отсутствует')" "${path}"
  return 1
}

check_configs() {
  local failures=0
  local file
  local mode=""
  local mode_value=0

  printf '\n=== %s ===\n' "$(message 'File and configuration validation' 'Проверка файлов и конфигурации')"
  if [[ "${installation_state}" == "legacy" ]]; then
    printf '[INFO] %s\n' "$(message 'The new management layer does not exist yet; this is expected for legacy installations.' 'Новый управляющий слой ещё не создан; для legacy это ожидаемо.')"
    printf '[INFO] %s\n' "$(message 'Only active configuration files will be validated.' 'Проверяются только реально используемые конфиги.')"
  else
    for file in \
      metadata.yml \
      inventory.ini \
      vars.yml \
      secrets.yml \
      authelia.yml \
      authelia_users_initial.yml \
      websites.yml \
      tcp.yml; do
      check_file "${config_dir}/${file}" "${file}" || ((failures += 1))
    done
    check_file "${playbook_file}" "Ansible playbook" || ((failures += 1))
    if [[ -x "${venv_python}" ]]; then
      printf '[ OK ] Python venv: %s\n' "${venv_python}"
      if "${venv_python}" -c \
        'import pathlib, sys, yaml; [yaml.safe_load(pathlib.Path(p).read_text()) for p in sys.argv[1:]]' \
        "${config_dir}/metadata.yml" \
        "${config_dir}/vars.yml" \
        "${config_dir}/secrets.yml" \
        "${config_dir}/authelia.yml" \
        "${config_dir}/authelia_users_initial.yml" \
        "${config_dir}/websites.yml" \
        "${config_dir}/tcp.yml"; then
        printf '[ OK ] %s\n' "$(message 'YAML files have valid syntax' 'YAML-файлы читаются без синтаксических ошибок')"
      else
        printf '[FAIL] %s\n' "$(message 'One or more YAML files are invalid' 'Один или несколько YAML-файлов повреждены')"
        ((failures += 1))
      fi
    else
      printf '[FAIL] Python venv: %s\n' "${venv_python}"
      ((failures += 1))
    fi
  fi

  if [[ "${installation_state}" != "legacy" &&
        -f "${config_dir}/secrets.yml" ]]; then
    mode="$(stat -c '%a' "${config_dir}/secrets.yml" 2>/dev/null || true)"
    if [[ "${mode}" =~ ^[0-7]{3,4}$ ]]; then
      mode_value=$((8#${mode}))
      if (( (mode_value & 63) == 0 )); then
        printf '[ OK ] %s: %s\n' "$(message 'secrets.yml permissions' 'Права secrets.yml')" "${mode}"
      else
        printf '[FAIL] %s: %s (%s 600)\n' "$(message 'secrets.yml permissions are too broad' 'Слишком широкие права secrets.yml')" \
          "${mode}" "$(message 'expected' 'ожидается')"
        ((failures += 1))
      fi
    fi
  fi

  if [[ -f "${legacy_haproxy_config}" ]] &&
     command -v haproxy >/dev/null 2>&1; then
    if haproxy -c -f "${legacy_haproxy_config}"; then
      printf '[ OK ] %s\n' "$(message 'HAProxy configuration is valid' 'Конфигурация HAProxy валидна')"
    else
      printf '[FAIL] %s\n' "$(message 'HAProxy configuration is invalid' 'Конфигурация HAProxy невалидна')"
      ((failures += 1))
    fi
  else
    printf '[INFO] %s\n' "$(message 'HAProxy is not installed yet or its configuration is missing' 'HAProxy ещё не установлен или конфигурация отсутствует')"
  fi

  if command -v docker >/dev/null 2>&1; then
    for file in "${legacy_authelia_compose}" "${legacy_admin_compose}"; do
      [[ -f "${file}" ]] || continue
      if docker compose -f "${file}" config --quiet; then
        printf '[ OK ] Compose: %s\n' "${file}"
      else
        printf '[FAIL] Compose: %s\n' "${file}"
        ((failures += 1))
      fi
    done
  fi

  if [[ "${failures}" -eq 0 ]]; then
    printf '\n%s\n' "$(message 'Result: no obvious configuration errors were found.' 'Итог: явных ошибок конфигурации не найдено.')"
  else
    printf '\n%s: %s\n' "$(message 'Result: problems found' 'Итог: найдено проблем')" "${failures}"
    return 1
  fi
}

show_migration_plan() {
  cat <<'EOF'

=== Безопасное принятие legacy-сервера под управление ===

1. Создать защищённый snapshot текущих HAProxy, сертификатов, Authelia,
   haproxy-admin, systemd units и служебных скриптов.
2. Использовать исходные Ansible-файлы с управляющего компьютера как источник
   переменных: vars.yml, authelia.yml, websites.yml, tcp.yml.
3. Отдельно расшифровать Ansible Vault и перенести только нужные секреты в
   /etc/easy-ha-proxy/secrets.yml с правами 0600.
4. Сохранить текущую /opt/authelia/users_database.yml: режим selfservice не
   должен перезаписывать живую базу пользователей.
5. Установить только управляющий source/venv и сформировать конфигурацию,
   ничего не применяя к сервисам.
6. Выполнить syntax-check и Ansible check mode, сохранить diff и проверить его.
7. Сначала применить безопасные точечные теги, затем — остальной стек.

Автоматическое применение новой конфигурации для legacy намеренно отключено:
сначала нужен snapshot и проверенный импорт исходных переменных/Vault.
EOF
}

create_legacy_snapshot() {
  local timestamp=""
  local backup_root="${EASY_HA_PROXY_BACKUP_ROOT:-/var/backups/easy-ha-proxy}"
  local backup_dir=""
  local archive=""
  local path=""
  local -a paths=()
  local -a relative_paths=()

  [[ "${installation_state}" == "legacy" ]] ||
    die "Legacy-установка не обнаружена."
  if ! confirm "Создать защищённый snapshot работающей legacy-установки?"; then
    printf 'Действие отменено.\n'
    return
  fi

  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  backup_dir="${backup_root}/legacy-${timestamp}"
  archive="${backup_dir}/live-config.tar.gz"
  install -d -m 0700 "${backup_dir}"

  for path in \
    /etc/haproxy \
    /etc/letsencrypt \
    /etc/iptables \
    /etc/msmtprc \
    /opt/authelia \
    /opt/haproxy-admin \
    /var/lib/haproxy; do
    [[ -e "${path}" ]] && paths+=("${path}")
  done
  while IFS= read -r -d '' path; do
    paths+=("${path}")
  done < <(
    find /etc/systemd/system /usr/local/sbin \
      -maxdepth 1 \
      \( -type f -o -type l \) \
      \( -name 'haproxy*' -o -name 'authelia*' \) \
      -print0 2>/dev/null
  )

  [[ "${#paths[@]}" -gt 0 ]] || die "Не найдены файлы для snapshot."
  for path in "${paths[@]}"; do
    relative_paths+=("${path#/}")
  done

  tar --acls --xattrs --numeric-owner -czpf "${archive}" \
    -C / "${relative_paths[@]}"
  chmod 0600 "${archive}"
  sha256sum "${archive}" >"${backup_dir}/SHA256SUMS"
  chmod 0600 "${backup_dir}/SHA256SUMS"

  {
    printf 'created_at=%s\n' "${timestamp}"
    printf 'hostname=%s\n' "$(hostname -f 2>/dev/null || hostname)"
    printf 'state=%s\n' "${installation_state}"
    systemctl --no-pager --plain list-units \
      'haproxy*' 'authelia*' 'docker.service' 2>/dev/null || true
    docker ps -a --no-trunc 2>/dev/null || true
  } >"${backup_dir}/manifest.txt"
  chmod 0600 "${backup_dir}/manifest.txt"

  printf '\nSnapshot создан: %s\n' "${backup_dir}"
  printf 'Архив: %s\n' "${archive}"
  printf 'Перед миграцией скопируйте snapshot с сервера в отдельное хранилище.\n'
  printf 'EASY_HA_PROXY_SNAPSHOT_DIR=%s\n' "${backup_dir}"
}

source_fingerprint() {
  local root="$1"
  (
    cd -- "${root}" || exit 1
    {
      find ansible installer -type f \
        ! -path 'ansible/backups/*' \
        ! -path 'ansible/cache/*' \
        ! -path 'ansible/group_vars/*' \
        ! -path '*/__pycache__/*' \
        ! -path '*.pyc' \
        ! -path 'ansible/inventory.ini' \
        ! -path 'ansible/vars.yml' \
        ! -path 'ansible/websites.yml' \
        ! -path 'ansible/tcp.yml' \
        ! -path 'ansible/authelia_users_initial.yml' \
        ! -path 'ansible/roles/cert/files/*.pem' \
        ! -path 'ansible/roles/haproxy-admin.zip' \
        -print0
      for file in \
        install.sh \
        install-local.sh \
        install-remote.sh \
        easy-ha-proxy-helper.sh; do
        [[ -f "${file}" ]] && printf '%s\0' "${file}"
      done
    } |
      sort -z |
      xargs -0 -r sha256sum |
      sha256sum |
      awk '{ print $1 }'
  )
}

image_update_state() {
  local image="$1"
  local local_digest=""
  local remote_digest=""

  if [[ "${image}" == *@sha256:* ]]; then
    printf 'pinned|||\n'
    return
  fi
  if [[ "${image}" == sha256:* ||
        "${image}" =~ ^[0-9a-f]{12,64}$ ]]; then
    printf 'unknown|||невозможно определить registry reference\n'
    return
  fi
  if ! docker buildx version >/dev/null 2>&1; then
    printf 'unknown|||docker buildx недоступен\n'
    return
  fi

  local_digest="$(
    docker image inspect "${image}" \
      --format '{{range .RepoDigests}}{{println .}}{{end}}' 2>/dev/null |
      awk -F@ '/@sha256:/ { print $2; exit }' ||
      true
  )"
  remote_digest="$(
    docker buildx imagetools inspect "${image}" 2>/dev/null |
      awk '$1 == "Digest:" && $2 ~ /^sha256:[0-9a-f]{64}$/ {
        print $2
        exit
      }' ||
      true
  )"

  if [[ -z "${remote_digest}" ]]; then
    printf 'unknown|%s||registry digest недоступен\n' "${local_digest}"
  elif [[ -z "${local_digest}" ]]; then
    printf 'unknown||%s|локальный RepoDigest отсутствует\n' "${remote_digest}"
  elif [[ "${local_digest}" == "${remote_digest}" ]]; then
    printf 'ok|%s|%s|\n' "${local_digest}" "${remote_digest}"
  else
    printf 'update|%s|%s|\n' "${local_digest}" "${remote_digest}"
  fi
}

compose_stack_state="unknown"
compose_stack_update_state() {
  local label="$1"
  local compose_file="$2"
  local config_output=""
  local image=""
  local state=""
  local local_digest=""
  local remote_digest=""
  local note=""
  local has_update=false
  local has_unknown=false
  local -a images=()
  local -A seen_images=()

  compose_stack_state="unknown"
  printf '\n=== Проверка Docker-стека: %s ===\n' "${label}"
  printf 'Compose: %s\n' "${compose_file}"

  if [[ ! -f "${compose_file}" ]]; then
    printf '[INFO] compose-файл не найден\n'
    compose_stack_state="missing"
    return 0
  fi
  if ! config_output="$(docker compose -f "${compose_file}" config --images 2>/dev/null)"; then
    printf '[WARN] не удалось прочитать список образов из compose\n'
    compose_stack_state="unknown"
    return 0
  fi
  while IFS= read -r image; do
    [[ -n "${image}" ]] || continue
    if [[ -z "${seen_images[${image}]+x}" ]]; then
      images+=("${image}")
      seen_images["${image}"]=1
    fi
  done <<< "${config_output}"

  if [[ "${#images[@]}" -eq 0 ]]; then
    printf '[INFO] в compose не найдено образов\n'
    compose_stack_state="unknown"
    return 0
  fi

  for image in "${images[@]}"; do
    IFS='|' read -r state local_digest remote_digest note < <(
      image_update_state "${image}"
    )
    case "${state}" in
      update)
        has_update=true
        printf '[UPD ] %s: %s -> %s\n' \
          "${image}" "${local_digest:0:19}" "${remote_digest:0:19}"
        ;;
      ok)
        printf '[ OK ] %s актуален (%s)\n' \
          "${image}" "${local_digest:0:19}"
        ;;
      pinned)
        printf '[PIN ] %s закреплён по digest\n' "${image}"
        ;;
      *)
        has_unknown=true
        printf '[WARN] %s: %s\n' "${image}" "${note:-статус неизвестен}"
        ;;
    esac
  done

  if [[ "${has_update}" == true ]]; then
    compose_stack_state="update"
  elif [[ "${has_unknown}" == true ]]; then
    compose_stack_state="unknown"
  else
    compose_stack_state="ok"
  fi
}

apt_upgradable_count() {
  command -v apt-get >/dev/null 2>&1 || return 0
  apt-get -s upgrade 2>/dev/null |
    awk '/^Inst / { count++ } END { print count + 0 }' ||
    true
}

source_update_state() {
  local local_revision=""
  local remote_revision=""
  local origin=""
  local installed_fingerprint=""
  local remote_fingerprint=""
  local git_dirty=""

  if [[ -d "${source_dir}/.git" ]] && command -v git >/dev/null 2>&1; then
    local_revision="$(git -C "${source_dir}" rev-parse HEAD 2>/dev/null || true)"
    git_dirty="$(
      git -C "${source_dir}" -c core.fileMode=false \
        status --porcelain 2>/dev/null ||
        true
    )"
    origin="$(git -C "${source_dir}" remote get-url origin 2>/dev/null || true)"
    if [[ -z "${origin}" ]]; then
      printf 'unknown|%s||origin не настроен\n' "${local_revision}"
      return
    fi
    remote_revision="$(
      GIT_TERMINAL_PROMPT=0 git ls-remote \
        "${origin}" "refs/heads/${branch}" 2>/dev/null |
        awk 'NR == 1 { print $1 }' ||
        true
    )"
    if [[ -z "${remote_revision}" ]]; then
      printf 'unknown|%s||GitHub недоступен\n' "${local_revision}"
    elif [[ "${local_revision}" == "${remote_revision}" &&
            -z "${git_dirty}" ]]; then
      printf 'ok|%s|%s|\n' "${local_revision}" "${remote_revision}"
    elif [[ "${local_revision}" == "${remote_revision}" ]]; then
      printf 'local-changes|%s|%s|есть локальные изменения\n' \
        "${local_revision}" "${remote_revision}"
    else
      printf 'update|%s|%s|\n' "${local_revision}" "${remote_revision}"
    fi
    return
  fi

  origin="${EASY_HA_PROXY_REPOSITORY:-$(yaml_scalar repository "${metadata_file}")}"
  origin="${origin:-https://github.com/CLLlAgOB/easy-ha-proxy.git}"
  installed_fingerprint="$(source_fingerprint "${source_dir}" 2>/dev/null || true)"
  temporary_update_checkout="$(mktemp -d -t easy-ha-proxy-update-check.XXXXXX)"
  if command -v git >/dev/null 2>&1 &&
     GIT_TERMINAL_PROMPT=0 git clone --quiet --depth=1 --branch "${branch}" \
       "${origin}" "${temporary_update_checkout}/source" 2>/dev/null; then
    remote_revision="$(
      git -C "${temporary_update_checkout}/source" rev-parse HEAD 2>/dev/null ||
        true
    )"
    remote_fingerprint="$(
      source_fingerprint "${temporary_update_checkout}/source" 2>/dev/null ||
        true
    )"
    if [[ -n "${installed_fingerprint}" &&
          "${installed_fingerprint}" == "${remote_fingerprint}" ]]; then
      printf 'ok|%s|%s|\n' "${installed_fingerprint}" "${remote_fingerprint}"
    elif [[ -n "${remote_fingerprint}" ]]; then
      printf 'update|%s|%s|commit %s\n' \
        "${installed_fingerprint}" "${remote_fingerprint}" "${remote_revision:0:12}"
    else
      printf 'unknown|%s||fingerprint GitHub не вычислен\n' \
        "${installed_fingerprint}"
    fi
  else
    printf 'unknown|%s||не удалось скачать source для сравнения\n' \
      "${installed_fingerprint}"
  fi
}

ensure_remote_source_snapshot() {
  local origin=""

  if [[ -n "${remote_source_snapshot}" &&
        -d "${remote_source_snapshot}" ]]; then
    return 0
  fi
  if [[ -n "${temporary_update_checkout}" &&
        -d "${temporary_update_checkout}/source" ]]; then
    remote_source_snapshot="${temporary_update_checkout}/source"
    return 0
  fi
  origin="$(
    git -C "${source_dir}" remote get-url origin 2>/dev/null ||
      true
  )"
  if [[ -z "${origin}" ]]; then
    origin="${EASY_HA_PROXY_REPOSITORY:-$(yaml_scalar repository "${metadata_file}")}"
    origin="${origin:-https://github.com/CLLlAgOB/easy-ha-proxy.git}"
  fi
  command -v git >/dev/null 2>&1 || return 1
  temporary_update_checkout="$(mktemp -d -t easy-ha-proxy-update-check.XXXXXX)"
  if ! GIT_TERMINAL_PROMPT=0 git clone --quiet --depth=1 --branch "${branch}" \
    "${origin}" "${temporary_update_checkout}/source" 2>/dev/null; then
    return 1
  fi
  remote_source_snapshot="${temporary_update_checkout}/source"
}

daemon_updates_available() {
  local comparison_root="${1:-${source_dir}}"
  local installed=""
  local source=""
  local i=""

  command -v sha256sum >/dev/null 2>&1 || return 1
  for i in "${!daemon_units[@]}"; do
    [[ -f "${comparison_root}/${daemon_sources[i]}" ]] || continue
    if command -v systemctl >/dev/null 2>&1 &&
       ! systemctl cat "${daemon_units[i]}" >/dev/null 2>&1; then
      return 0
    fi
    if [[ ! -f "${daemon_scripts[i]}" ]]; then
      return 0
    fi
    installed="$(sha256sum "${daemon_scripts[i]}" | awk '{ print $1 }')"
    source="$(
      sha256sum "${comparison_root}/${daemon_sources[i]}" | awk '{ print $1 }'
    )"
    [[ "${installed}" == "${source}" ]] || return 0
  done
  return 1
}

show_daemon_versions() {
  local comparison_root="${1:-${source_dir}}"
  local comparison_label="${2:-current source}"
  local installed=""
  local source=""
  local state=""
  local i=""

  printf '\nВспомогательные systemd-демоны (сравнение: %s; версия = SHA-256):\n' \
    "${comparison_label}"
  if ! command -v sha256sum >/dev/null 2>&1; then
    printf '[WARN] sha256sum недоступен, версии демонов не проверены.\n'
    return
  fi
  for i in "${!daemon_units[@]}"; do
    state="not-installed"
    if command -v systemctl >/dev/null 2>&1 &&
       systemctl cat "${daemon_units[i]}" >/dev/null 2>&1; then
      state="$(systemctl is-active "${daemon_units[i]}" 2>/dev/null || true)"
      state="${state:-unknown}"
    else
      printf '[INFO] %-27s не установлен\n' "${daemon_units[i]}"
      continue
    fi
    if [[ ! -f "${daemon_scripts[i]}" ]]; then
      printf '[MISS] %-27s state=%s, скрипт отсутствует\n' \
        "${daemon_units[i]}" "${state}"
      continue
    fi
    installed="$(sha256sum "${daemon_scripts[i]}" | awk '{ print $1 }')"
    if [[ ! -f "${comparison_root}/${daemon_sources[i]}" ]]; then
      printf '[WARN] %-27s state=%s, installed=%s, source отсутствует\n' \
        "${daemon_units[i]}" "${state}" "${installed:0:12}"
      continue
    fi
    source="$(
      sha256sum "${comparison_root}/${daemon_sources[i]}" | awk '{ print $1 }'
    )"
    if [[ "${installed}" == "${source}" ]]; then
      printf '[ OK ] %-27s state=%s, version=%s\n' \
        "${daemon_units[i]}" "${state}" "${installed:0:12}"
    else
      printf '[UPD ] %-27s state=%s, %s -> %s\n' \
        "${daemon_units[i]}" "${state}" \
        "${installed:0:12}" "${source:0:12}"
    fi
  done
}

is_easy_ha_proxy_container() {
  local name="$1"
  local config_files=""

  config_files="$(
    docker inspect \
      --format '{{ index .Config.Labels "com.docker.compose.project.config_files" }}' \
      "${name}" 2>/dev/null ||
      true
  )"
  if [[ "${config_files}" == *"${legacy_authelia_compose}"* ||
        "${config_files}" == *"${legacy_admin_compose}"* ]]; then
    return 0
  fi
  case "${name}" in
    haproxy-admin|authelia|authelia-redis|mail_relay)
      return 0
      ;;
  esac
  return 1
}

check_container_updates() {
  local image=""
  local local_digest=""
  local remote_digest=""
  local state=""
  local note=""
  local -a images=()
  local name=""
  local managed=""
  declare -A containers_by_image=()
  declare -A managed_by_image=()

  command -v docker >/dev/null 2>&1 || return
  while IFS='|' read -r name image; do
    [[ -n "${name}" && -n "${image}" ]] || continue
    managed=false
    if is_easy_ha_proxy_container "${name}"; then
      managed=true
    fi
    if [[ -z "${containers_by_image[${image}]+x}" ]]; then
      images+=("${image}")
      containers_by_image["${image}"]="${name}"
      managed_by_image["${image}"]="${managed}"
    else
      containers_by_image["${image}"]+=",${name}"
      [[ "${managed}" == true ]] && managed_by_image["${image}"]=true
    fi
  done < <(docker ps -a --format '{{.Names}}|{{.Image}}' 2>/dev/null)
  if [[ "${#images[@]}" -eq 0 ]]; then
    printf '[INFO] Docker-контейнеры не найдены.\n'
    return
  fi

  printf '\nКонтейнерные образы (registry digest без pull):\n'
  printf 'easy-ha-proxy проверяет обновления только для своих Compose-стеков.\n'
  for image in "${images[@]}"; do
    [[ -n "${image}" ]] || continue
    name="${containers_by_image[${image}]}"
    if [[ "${managed_by_image[${image}]:-false}" != true ]]; then
      printf '[INFO] %s (%s): внешний контейнер, пропущен\n' \
        "${image}" "${name}"
      continue
    fi
    if [[ "${image}" == *@sha256:* ]]; then
      printf '[PIN ] %s (%s) закреплён по digest\n' "${image}" "${name}"
      continue
    fi
    if [[ "${image}" == sha256:* ||
          "${image}" =~ ^[0-9a-f]{12,64}$ ]]; then
      printf '[INFO] %s (%s): невозможно определить registry reference\n' \
        "${image}" "${name}"
      continue
    fi

    IFS='|' read -r state local_digest remote_digest note < <(
      image_update_state "${image}"
    )
    if [[ "${state}" == "unknown" ]]; then
      printf '[WARN] %s (%s): %s\n' "${image}" "${name}" \
        "${note:-статус неизвестен}"
    elif [[ "${state}" == "ok" ]]; then
      printf '[ OK ] %s (%s) актуален (%s)\n' \
        "${image}" "${name}" "${local_digest:0:19}"
    elif [[ "${state}" == "update" ]]; then
      printf '[UPD ] %s (%s): %s -> %s\n' \
        "${image}" "${name}" \
        "${local_digest:0:19}" "${remote_digest:0:19}"
    fi
  done
}

update_compose_stack_images() {
  local label="$1"
  local compose_file="$2"
  local project_dir=""

  if [[ ! -f "${compose_file}" ]]; then
    warn "${label}: compose-файл не найден: ${compose_file}"
    return 0
  fi
  project_dir="$(dirname -- "${compose_file}")"

  printf '\n=== Обновление контейнеров: %s ===\n' "${label}"
  printf 'Compose: %s\n' "${compose_file}"
  docker compose -f "${compose_file}" config --quiet
  docker compose -f "${compose_file}" pull
  docker compose -f "${compose_file}" up -d
  docker compose -f "${compose_file}" ps
  printf '[ OK ] %s обновлён через %s\n' "${label}" "${project_dir}"
}

update_legacy_containers() {
  [[ "${installation_state}" == "legacy" ||
     "${installation_state}" == "installed" ]] ||
    die "Точечное обновление Docker-контейнеров доступно только для installed или legacy установки."
  command -v docker >/dev/null 2>&1 ||
    die "Docker не найден."
  docker compose version >/dev/null 2>&1 ||
    die "Docker Compose v2 не найден."

  printf '\n=== Обновление Docker-контейнеров easy-ha-proxy ===\n'
  printf 'Конфигурационные файлы и Ansible не применяются.\n'
  printf 'Будут обновлены только образы из существующих Compose-файлов.\n'

  check_container_updates || true
  update_compose_stack_images "Authelia" "${legacy_authelia_compose}"
  update_compose_stack_images "HAProxy Admin" "${legacy_admin_compose}"

  printf '\n=== Проверка после обновления контейнеров ===\n'
  basic_health
  check_container_updates || true
}

selected_update_indexes=()
prompt_update_selection() {
  local max="$1"
  local answer=""
  local token=""
  local -A seen=()

  selected_update_indexes=()
  if [[ "${input_fd}" -eq 0 && ! -t 0 ]]; then
    return 1
  fi
  read -r -u "${input_fd}" \
    -p "Что обновить? Номера через пробел/запятую, all — всё, 0 — отмена: " \
    answer || return 1
  answer="${answer//,/ }"
  case "${answer,,}" in
    ""|0|q|quit|exit|отмена)
      return 1
      ;;
    all|a|все|всё)
      for ((token = 1; token <= max; token++)); do
        selected_update_indexes+=("${token}")
      done
      return 0
      ;;
  esac

  for token in ${answer}; do
    if [[ ! "${token}" =~ ^[0-9]+$ ||
          "${token}" -lt 1 ||
          "${token}" -gt "${max}" ]]; then
      warn "Некорректный номер: ${token}"
      return 1
    fi
    if [[ -z "${seen[${token}]+x}" ]]; then
      selected_update_indexes+=("${token}")
      seen["${token}"]=1
    fi
  done

  [[ "${#selected_update_indexes[@]}" -gt 0 ]]
}

smart_update_legacy() {
  local choice=""
  local selected=""
  local file=""
  local -a option_labels=()
  local -a option_files=()

  [[ "${installation_state}" == "legacy" ]] ||
    die "Legacy-установка не обнаружена."
  command -v docker >/dev/null 2>&1 ||
    die "Docker не найден."
  docker compose version >/dev/null 2>&1 ||
    die "Docker Compose v2 не найден."

  printf '\n=== Проверка для точечного Docker-обновления ===\n'
  printf 'Ansible и конфигурационные файлы применяться не будут.\n'

  compose_stack_update_state "Authelia" "${legacy_authelia_compose}"
  if [[ "${compose_stack_state}" == "update" ]]; then
    option_labels+=("Authelia Docker stack")
    option_files+=("${legacy_authelia_compose}")
  fi
  compose_stack_update_state "HAProxy Admin" "${legacy_admin_compose}"
  if [[ "${compose_stack_state}" == "update" ]]; then
    option_labels+=("HAProxy Admin Docker stack")
    option_files+=("${legacy_admin_compose}")
  fi

  if [[ "${#option_labels[@]}" -eq 0 ]]; then
    printf '\nТочных Docker-обновлений для legacy easy-ha-proxy не найдено.\n'
    printf 'Если registry digest недоступен, можно запустить обычный пункт update-containers вручную.\n'
    return
  fi

  printf '\nНайдены варианты для точечного обновления:\n'
  for choice in "${!option_labels[@]}"; do
    printf '  %s) %s\n' "$((choice + 1))" "${option_labels[choice]}"
  done

  if ! prompt_update_selection "${#option_labels[@]}"; then
    printf 'Действие отменено.\n'
    return
  fi
  if ! confirm "Применить выбранные точечные обновления"; then
    printf 'Действие отменено.\n'
    return
  fi

  for selected in "${selected_update_indexes[@]}"; do
    choice=$((selected - 1))
    file="${option_files[choice]}"
    update_compose_stack_images "${option_labels[choice]}" "${file}"
  done

  printf '\n=== Проверка после точечного обновления ===\n'
  basic_health
  check_container_updates || true
}

run_smart_managed_action() {
  local action_name="$1"
  local -a update_arguments=()
  case "${action_name}" in
    full)
      update_arguments=(
        update
        --source-channel "${source_channel:-github}"
      )
      [[ -n "${image_channel}" ]] &&
        update_arguments+=(--image-channel "${image_channel}")
      run_cli "${update_arguments[@]}"
      ;;
    os)
      run_cli update --component os --no-fetch
      ;;
    daemons)
      run_cli update --component daemons --no-fetch
      ;;
    daemons-fetch)
      run_cli update --component daemons
      ;;
    services)
      run_cli update --component services
      ;;
    authelia-container)
      update_compose_stack_images "Authelia" "${legacy_authelia_compose}"
      ;;
    admin-container)
      update_compose_stack_images "HAProxy Admin" "${legacy_admin_compose}"
      ;;
    containers)
      update_compose_stack_images "Authelia" "${legacy_authelia_compose}"
      update_compose_stack_images "HAProxy Admin" "${legacy_admin_compose}"
      ;;
    ui)
      run_cli update --ui-only --no-fetch
      ;;
    image-channel)
      run_cli update \
        --component admin-container \
        --source-channel local \
        --image-channel "${image_channel}"
      ;;
    *)
      die "Unknown smart update action: ${action_name}"
      ;;
  esac
}

smart_update_installed() {
  local state=""
  local local_value=""
  local remote_value=""
  local note=""
  local apt_count=""
  local choice=""
  local selected=""
  local action_name=""
  local daemon_action="daemons"
  local daemon_comparison_label="current source"
  local daemon_comparison_root="${source_dir}"
  local has_full=false
  local ran_direct_docker=false
  local os_update_selected=false
  local configured_image_channel=""
  local -a option_labels=()
  local -a option_actions=()

  [[ "${installation_state}" == "installed" ]] ||
    die "Управляемая установка не обнаружена."

  printf '\n=== Проверка для точечного обновления ===\n'

  configured_image_channel="$(yaml_scalar image_channel "${metadata_file}")"
  if [[ -n "${image_channel}" && "${configured_image_channel}" != "${image_channel}" ]]; then
    printf '[UPD ] HAProxy Admin image channel: %s -> %s\n' \
      "${configured_image_channel:-latest}" "${image_channel}"
    option_labels+=("HAProxy Admin image channel -> ${image_channel}")
    option_actions+=("image-channel")
  fi

  IFS='|' read -r state local_value remote_value note < <(source_update_state)
  case "${state}" in
    update)
      printf '[UPD ] Исходники easy-ha-proxy: %s -> %s\n' \
        "${local_value:0:12}" "${remote_value:0:12}"
      option_labels+=("Весь стек из новой source-версии")
      option_actions+=("full")
      if cli_supports_service_component; then
        option_labels+=("Только host-side services/scripts из новой source-версии")
        option_actions+=("services")
      fi
      ;;
    ok)
      printf '[ OK ] Исходники easy-ha-proxy актуальны (%s)\n' \
        "${local_value:0:12}"
      ;;
    local-changes)
      printf '[WARN] Исходники имеют локальные изменения (%s)\n' \
        "${local_value:0:12}"
      ;;
    *)
      printf '[WARN] Исходники: %s\n' "${note:-статус неизвестен}"
      ;;
  esac

  if [[ "${state}" == "update" ]]; then
    if ensure_remote_source_snapshot; then
      daemon_action="daemons-fetch"
      daemon_comparison_label="GitHub ${branch}"
      daemon_comparison_root="${remote_source_snapshot}"
    else
      printf '[WARN] Не удалось скачать удалённый source для сравнения демонов.\n'
    fi
  fi
  show_daemon_versions "${daemon_comparison_root}" "${daemon_comparison_label}"
  if daemon_updates_available "${daemon_comparison_root}"; then
    if cli_supports_daemon_component; then
      option_labels+=("Только изменившиеся вспомогательные systemd-демоны")
      option_actions+=("${daemon_action}")
    else
      printf '       Точечное обновление демонов появится после обновления managed source.\n'
    fi
  fi

  apt_count="$(apt_upgradable_count)"
  if [[ "${apt_count}" =~ ^[0-9]+$ && "${apt_count}" -gt 0 ]]; then
    if cli_supports_update_component; then
      printf '[UPD ] Пакеты ОС через apt: %s\n' "${apt_count}"
      option_labels+=("Только пакеты ОС через apt upgrade")
      option_actions+=("os")
    else
      printf '[INFO] Пакеты ОС через apt: %s\n' "${apt_count}"
      printf '       Точечное apt-обновление появится после обновления managed source.\n'
    fi
  elif [[ "${apt_count}" =~ ^[0-9]+$ ]]; then
    printf '[ OK ] Обновляемых apt-пакетов по текущему кэшу: 0\n'
  fi

  if command -v docker >/dev/null 2>&1 &&
     docker compose version >/dev/null 2>&1; then
    compose_stack_update_state "Authelia" "${legacy_authelia_compose}"
    if [[ "${compose_stack_state}" == "update" ]]; then
      option_labels+=("Только Docker-образы Authelia")
      option_actions+=("authelia-container")
    fi

    compose_stack_update_state "HAProxy Admin" "${legacy_admin_compose}"
    if [[ "${compose_stack_state}" == "update" ]]; then
      option_labels+=("Только Docker-образ HAProxy Admin")
      option_actions+=("admin-container")
    fi
  else
    printf '[INFO] Docker Compose недоступен, Docker-образы не проверялись.\n'
  fi

  if [[ "${#option_labels[@]}" -eq 0 ]]; then
    printf '\nНичего точечно обновлять не нужно: доступных обновлений не найдено.\n'
    return
  fi

  printf '\nНайдены варианты для точечного обновления:\n'
  for choice in "${!option_labels[@]}"; do
    printf '  %s) %s\n' "$((choice + 1))" "${option_labels[choice]}"
  done

  if ! prompt_update_selection "${#option_labels[@]}"; then
    printf 'Действие отменено.\n'
    return
  fi
  if ! confirm "Применить выбранные точечные обновления"; then
    printf 'Действие отменено.\n'
    return
  fi

  for selected in "${selected_update_indexes[@]}"; do
    action_name="${option_actions[$((selected - 1))]}"
    if [[ "${action_name}" == "os" ]]; then
      os_update_selected=true
    fi
    if [[ "${action_name}" == "full" ]]; then
      has_full=true
    fi
  done
  if [[ "${has_full}" == true ]]; then
    printf '\nВыбран полный update из новой source-версии; отдельные компоненты приложения уже входят в него.\n'
    run_smart_managed_action full
    if [[ "${os_update_selected}" == true ]]; then
      printf '\n%s\n' "$(message \
        'Applying the selected operating-system update last so a required reboot cannot interrupt other updates.' \
        'Применяю выбранное обновление ОС последним, чтобы требуемая перезагрузка не прервала остальные обновления.')"
      run_smart_managed_action os
    fi
    return
  fi

  for selected in "${selected_update_indexes[@]}"; do
    action_name="${option_actions[$((selected - 1))]}"
    if [[ "${action_name}" == "os" ]]; then
      os_update_selected=true
      continue
    fi
    case "${action_name}" in
      authelia-container|admin-container|containers)
        ran_direct_docker=true
        ;;
    esac
    run_smart_managed_action "${action_name}"
  done
  if [[ "${ran_direct_docker}" == true ]]; then
    printf '\n=== Проверка после точечного Docker-обновления ===\n'
    basic_health
    check_container_updates || true
  fi
  if [[ "${os_update_selected}" == true ]]; then
    printf '\n%s\n' "$(message \
      'Applying the selected operating-system update last so a required reboot cannot interrupt other updates.' \
      'Применяю выбранное обновление ОС последним, чтобы требуемая перезагрузка не прервала остальные обновления.')"
    run_smart_managed_action os
  fi
}

smart_update() {
  case "${installation_state}" in
    installed)
      smart_update_installed
      ;;
    legacy)
      smart_update_legacy
      ;;
    *)
      check_updates
      printf '\nТочечное обновление доступно для installed или legacy установки.\n'
      ;;
  esac
}

check_updates() {
  local local_revision=""
  local remote_revision=""
  local origin=""
  local installed_fingerprint=""
  local remote_fingerprint=""
  local git_dirty=""
  local upgradable_count="unknown"
  local daemon_comparison_label="current source"
  local daemon_comparison_root="${source_dir}"

  printf '\n=== Проверка доступных обновлений ===\n'
  if [[ -d "${source_dir}/.git" ]] && command -v git >/dev/null 2>&1; then
    local_revision="$(git -C "${source_dir}" rev-parse HEAD 2>/dev/null || true)"
    git_dirty="$(
      git -C "${source_dir}" -c core.fileMode=false \
        status --porcelain 2>/dev/null ||
        true
    )"
    origin="$(git -C "${source_dir}" remote get-url origin 2>/dev/null || true)"
    if [[ -n "${origin}" ]]; then
      remote_revision="$(
        GIT_TERMINAL_PROMPT=0 git ls-remote \
          "${origin}" "refs/heads/${branch}" 2>/dev/null |
          awk 'NR == 1 { print $1 }' ||
          true
      )"
    fi
    if [[ -z "${remote_revision}" ]]; then
      warn "Не удалось проверить GitHub. Проверьте сеть или доступ к репозиторию."
    elif [[ "${local_revision}" == "${remote_revision}" &&
            -z "${git_dirty}" ]]; then
      printf '[ OK ] Исходники easy-ha-proxy актуальны (%s)\n' \
        "${local_revision:0:12}"
    elif [[ "${local_revision}" == "${remote_revision}" ]]; then
      printf '[WARN] Исходники имеют локальные изменения поверх commit %s\n' \
        "${local_revision:0:12}"
    else
      printf '[UPD ] Доступно обновление easy-ha-proxy: %s -> %s\n' \
        "${local_revision:0:12}" "${remote_revision:0:12}"
    fi
  else
    origin="${EASY_HA_PROXY_REPOSITORY:-$(yaml_scalar repository "${metadata_file}")}"
    origin="${origin:-https://github.com/CLLlAgOB/easy-ha-proxy.git}"
    installed_fingerprint="$(source_fingerprint "${source_dir}" 2>/dev/null || true)"
    temporary_update_checkout="$(mktemp -d -t easy-ha-proxy-update-check.XXXXXX)"
    if command -v git >/dev/null 2>&1 &&
       GIT_TERMINAL_PROMPT=0 git clone --quiet --depth=1 --branch "${branch}" \
         "${origin}" "${temporary_update_checkout}/source" 2>/dev/null; then
      remote_revision="$(
        git -C "${temporary_update_checkout}/source" rev-parse HEAD 2>/dev/null ||
          true
      )"
      remote_fingerprint="$(
        source_fingerprint "${temporary_update_checkout}/source" 2>/dev/null ||
          true
      )"
      if [[ -n "${installed_fingerprint}" &&
            "${installed_fingerprint}" == "${remote_fingerprint}" ]]; then
        printf '[ OK ] Исходники easy-ha-proxy совпадают с GitHub (%s)\n' \
          "${remote_revision:0:12}"
      elif [[ -n "${remote_fingerprint}" ]]; then
        printf '[UPD ] Исходники отличаются от GitHub commit %s\n' \
          "${remote_revision:0:12}"
        printf '       installed=%s remote=%s\n' \
          "${installed_fingerprint:0:12}" "${remote_fingerprint:0:12}"
      else
        warn "Не удалось вычислить fingerprint исходников."
      fi
    else
      warn "Не удалось скачать ${origin} для сравнения исходников."
    fi
  fi

  if [[ -f "${source_dir}/ansible/roles/haproxy/templates/haproxy.cfg.j2" ]]; then
    if cmp -s \
      "${source_dir}/ansible/roles/haproxy/templates/haproxy.cfg.j2" \
      /opt/haproxy-admin/config/haproxy.cfg.j2 2>/dev/null; then
      printf '[ OK ] UI использует актуальный HAProxy-шаблон\n'
    elif [[ -f /opt/haproxy-admin/config/haproxy.cfg.j2 ]]; then
      printf '[UPD ] HAProxy-шаблон в source отличается от используемого UI\n'
      printf '       Выполните plan перед применением обновления.\n'
    else
      printf '[INFO] Развёрнутый UI-шаблон HAProxy пока не найден\n'
    fi
  fi

  if command -v apt-get >/dev/null 2>&1; then
    upgradable_count="$(
      apt-get -s upgrade 2>/dev/null |
        awk '/^Inst / { count++ } END { print count + 0 }' ||
        true
    )"
    upgradable_count="${upgradable_count:-unknown}"
    printf '[INFO] Обновляемых пакетов ОС по текущему APT-кэшу: %s\n' \
      "${upgradable_count}"
    printf '       Для свежих данных перед обновлением будет выполнен apt update.\n'
  fi

  if [[ -n "${remote_revision}" &&
        "${local_revision}" != "${remote_revision}" ]] &&
     ensure_remote_source_snapshot; then
    daemon_comparison_label="GitHub ${branch}"
    daemon_comparison_root="${remote_source_snapshot}"
  fi
  show_daemon_versions "${daemon_comparison_root}" "${daemon_comparison_label}"
  check_container_updates
}

show_test_info() {
  local admin_domain=""
  local authelia_domain=""
  local server_ip=""
  [[ "${configuration_mode}" == "test" ]] ||
    die "$(message 'The current configuration is not in test mode.' 'Текущая конфигурация не является тестовой.')"
  admin_domain="$(yaml_scalar admin_domain "${metadata_file}")"
  authelia_domain="$(yaml_scalar authelia_domain "${metadata_file}")"
  server_ip="$(yaml_scalar test_server_ip "${metadata_file}")"
  printf '\n%s:\n\n' "$(message 'Add this line to the hosts file on your workstation' 'Добавьте на рабочем компьютере в hosts')"
  printf '%s %s %s\n\n' "${server_ip:-<SERVER_IP>}" "${admin_domain}" "${authelia_domain}"
  printf '%s: https://%s/\n' "$(message 'Open' 'Откройте')" "${admin_domain}"
  printf '%s: /tmp/easy-ha-proxy-internal-ca.crt\n' \
    "$(message 'Public internal CA export on the server' 'Публичный сертификат внутреннего CA на сервере')"
}

confirm() {
  local prompt="$1"
  local answer=""
  [[ "${input_fd}" -ne 0 || -t 0 ]] || return 1
  read -r -u "${input_fd}" -p "${prompt} [y/N]: " answer || return 1
  case "${answer,,}" in
    y|yes|д|да) return 0 ;;
    *) return 1 ;;
  esac
}

confirm_default_yes() {
  local prompt="$1"
  local answer=""
  [[ "${input_fd}" -ne 0 || -t 0 ]] || return 1
  read -r -u "${input_fd}" -p "${prompt} [Y/n]: " answer || return 1
  case "${answer,,}" in
    ""|y|yes|д|да) return 0 ;;
    *) return 1 ;;
  esac
}

perform_action() {
  local selected="$1"
  local -a domain_arguments=()
  local -a configure_arguments=()
  case "${selected}" in
    inspect)
      inspect_system
      ;;
    status)
      if [[ "${installation_state}" == "installed" ]]; then
        run_cli status
        printf '\n%s\n' "$(message 'Status checks service health only. Use Check updates to compare source, Docker images, daemons, and OS packages.' 'Status проверяет только работоспособность. Используйте «Проверить обновления» для сравнения source, Docker-образов, демонов и пакетов ОС.')"
      else
        inspect_system
        basic_health
      fi
      ;;
    reboot)
      run_cli reboot
      ;;
    check-config)
      check_configs
      ;;
    plan)
      run_cli plan
      ;;
    check-updates)
      check_updates
      ;;
    smart-update)
      choose_deployment_channels
      if [[ "${source_channel}" == "local" ]]; then
        if confirm "$(message 'Apply synchronized local source and the selected image channel?' 'Применить синхронизированные локальные исходники и выбранный канал образа?')"; then
          run_cli update \
            --source-channel local \
            --image-channel "${image_channel}"
        else
          printf '%s\n' "$(message 'Action cancelled.' 'Действие отменено.')"
        fi
      else
        smart_update
      fi
      ;;
    update)
      choose_deployment_channels
      if confirm "$(message 'Update source and dependencies, then apply the complete stack?' 'Обновить исходники, зависимости и применить весь стек?')"; then
        run_cli update \
          --source-channel "${source_channel}" \
          --image-channel "${image_channel}"
      else
        printf '%s\n' "$(message 'Action cancelled.' 'Действие отменено.')"
      fi
      ;;
    apply-current)
      source_channel="local"
      choose_deployment_channels
      if confirm "$(message 'Apply the already uploaded source without contacting GitHub?' 'Применить уже загруженные исходники без обращения к GitHub?')"; then
        run_cli update \
          --source-channel local \
          --image-channel "${image_channel}"
      else
        printf '%s\n' "$(message 'Action cancelled.' 'Действие отменено.')"
      fi
      ;;
    update-ui)
      source_channel="local"
      choose_deployment_channels
      if confirm "$(message 'Update only the web interface container?' 'Обновить только контейнер веб-интерфейса?')"; then
        run_cli update --ui-only \
          --source-channel local \
          --image-channel "${image_channel}"
      else
        printf '%s\n' "$(message 'Action cancelled.' 'Действие отменено.')"
      fi
      ;;
    update-containers)
      if confirm "$(message 'Update only easy-ha-proxy Docker containers without applying Ansible?' 'Обновить только Docker-контейнеры easy-ha-proxy без применения Ansible?')"; then
        update_legacy_containers
      else
        printf '%s\n' "$(message 'Action cancelled.' 'Действие отменено.')"
      fi
      ;;
    configure)
      if confirm "$(message 'Run the configuration wizard and apply the result?' 'Запустить мастер изменения конфигурации и применить результат?')"; then
        configure_arguments=(configure --apply)
        [[ -n "${certificate_source}" ]] &&
          configure_arguments+=(--certificate-source "${certificate_source}")
        run_cli "${configure_arguments[@]}"
      else
        printf '%s\n' "$(message 'Action cancelled.' 'Действие отменено.')"
      fi
      ;;
    language)
      local language_choice=""
      local language_default="1"
      if [[ "${action}" == "language" && -n "${requested_language}" ]]; then
        language_choice="${requested_language}"
      else
        [[ "${language}" == "ru" ]] && language_default="2"
        printf '\n%s: %s\n' "$(message 'Current language' 'Текущий язык')" "${language}"
        printf '  1) English\n  2) Русский\n'
        language_choice="$(read_menu_choice "$(message "Choose language [${language_default}]" "Выберите язык [${language_default}]")")"
        [[ -n "${language_choice}" ]] || language_choice="${language_default}"
        case "${language_choice,,}" in
          2|ru|rus|рус|русский) language_choice="ru" ;;
          *) language_choice="en" ;;
        esac
      fi
      if ! cli_supports_language; then
        die "$(message \
          'The installed CLI is too old for language switching. Synchronize the current source first.' \
          'Установленный CLI слишком старый для смены языка. Сначала синхронизируйте текущие исходники.')"
      fi
      run_cli language --language "${language_choice}" --apply
      language="${language_choice}"
      export EASY_HA_PROXY_LANGUAGE="${language}"
      ;;
    migrate-domain)
      domain_arguments=(migrate-domain)
      [[ -n "${new_domain}" ]] &&
        domain_arguments+=(--new-domain "${new_domain}")
      [[ "${skip_dns_check}" == true ]] &&
        domain_arguments+=(--skip-dns-check)
      [[ "${plan_only}" == true ]] &&
        domain_arguments+=(--plan-only)
      run_cli "${domain_arguments[@]}"
      ;;
    promote-production)
      domain_arguments=(promote-production)
      [[ -n "${new_domain}" ]] &&
        domain_arguments+=(--new-domain "${new_domain}")
      [[ -n "${certificate_source}" ]] &&
        domain_arguments+=(--certificate-source "${certificate_source}")
      [[ -n "${image_channel}" ]] &&
        domain_arguments+=(--image-channel "${image_channel}")
      [[ "${skip_dns_check}" == true ]] &&
        domain_arguments+=(--skip-dns-check)
      [[ "${plan_only}" == true ]] &&
        domain_arguments+=(--plan-only)
      run_cli "${domain_arguments[@]}"
      ;;
    install)
      if confirm "$(message 'Start a production installation on this machine?' 'Начать production-установку на этой машине?')"; then
        run_install production
      else
        printf '%s\n' "$(message 'Action cancelled.' 'Действие отменено.')"
      fi
      ;;
    install-test)
      if confirm "$(message 'Start a test installation without a public IP or DNS?' 'Начать тестовую установку без публичного IP и DNS?')"; then
        run_install test
      else
        printf '%s\n' "$(message 'Action cancelled.' 'Действие отменено.')"
      fi
      ;;
    install-reset)
      if confirm "$(message 'Restart production configuration? The current configuration is backed up first.' 'Начать production-конфигурацию заново? Текущая конфигурация сначала сохраняется в backup.')"; then
        run_install production true
      else
        printf '%s\n' "$(message 'Action cancelled.' 'Действие отменено.')"
      fi
      ;;
    install-test-reset)
      if confirm "$(message 'Restart test configuration? The current configuration is backed up first.' 'Начать тестовую конфигурацию заново? Текущая конфигурация сначала сохраняется в backup.')"; then
        run_install test true
      else
        printf '%s\n' "$(message 'Action cancelled.' 'Действие отменено.')"
      fi
      ;;
    repair)
      if confirm "$(message 'Reapply the complete installation while preserving the existing configuration?' 'Повторно применить полную установку, сохранив существующую конфигурацию?')"; then
        run_install "$([[ "${configuration_mode}" == test ]] && printf test || printf production)"
      else
        printf '%s\n' "$(message 'Action cancelled.' 'Действие отменено.')"
      fi
      ;;
    backup-full)
      local -a backup_arguments=(backup-full)
      if confirm "$(message 'Include SSH host/private/authorized keys in the encrypted archive?' 'Включить в зашифрованный архив SSH host/private/authorized keys?')"; then
        backup_arguments+=(--include-ssh)
      else
        backup_arguments+=(--exclude-ssh)
      fi
      if ! confirm_default_yes "$(message 'Briefly stop managed containers and helper daemons for a consistent backup?' 'Кратко приостановить managed-контейнеры и helper-демоны для консистентного backup?')"; then
        backup_arguments+=(--no-quiesce)
        warn "$(message 'The backup will be created without pausing services; changing data may be inconsistent.' 'Backup создаётся без паузы; изменяемые в этот момент данные могут быть несогласованными.')"
      fi
      run_cli "${backup_arguments[@]}"
      ;;
    test-info)
      show_test_info
      ;;
    snapshot-legacy)
      create_legacy_snapshot
      ;;
    migration-plan)
      show_migration_plan
      ;;
  esac
}

read_menu_choice() {
  local prompt="$1"
  local choice=""
  if [[ "${input_fd}" -eq 0 && ! -t 0 ]]; then
    choice="0"
  else
    read -r -u "${input_fd}" -p "${prompt}: " choice || choice="0"
  fi
  printf '%s' "${choice}"
}

menu_clean() {
  local choice=""
  while true; do
    inspect_system
    if [[ "${language}" == "ru" ]]; then
      cat <<'EOF'

Доступные действия:
  1) Установить production-версию
  2) Тестовая установка на VM без публичного IP/DNS
  3) Проверить найденные файлы и конфигурацию
  0) Выход
EOF
      choice="$(read_menu_choice "Выберите действие")"
    else
      cat <<'EOF'

Available actions:
  1) Install the production version
  2) Test installation on a VM without public IP/DNS
  3) Validate detected files and configuration
  0) Exit
EOF
      choice="$(read_menu_choice "Choose an action")"
    fi
    case "${choice}" in
      1) perform_action install; return ;;
      2) perform_action install-test; return ;;
      3) perform_action check-config || true ;;
      0) return ;;
      *) [[ "${language}" == "ru" ]] && printf 'Неизвестный пункт.\n' || printf 'Unknown menu item.\n' ;;
    esac
  done
}

menu_partial() {
  local choice=""
  while true; do
    inspect_system
    if [[ "${language}" == "ru" ]]; then
      cat <<'EOF'

Обнаружена незавершённая или старая установка.
  1) Продолжить установку с сохранённой конфигурацией
  2) Начать production-конфигурацию заново (старая попадёт в backup)
  3) Начать тестовую конфигурацию заново (старая попадёт в backup)
  4) Проверить файлы и конфигурацию
  5) Проверить найденные systemd-сервисы, контейнеры и порты
  0) Выход
EOF
      choice="$(read_menu_choice "Выберите действие")"
    else
      cat <<'EOF'

An incomplete or older installation was detected.
  1) Continue installation with the saved configuration
  2) Restart production configuration (the old configuration is backed up)
  3) Restart test configuration (the old configuration is backed up)
  4) Validate files and configuration
  5) Check detected systemd services, containers, and ports
  0) Exit
EOF
      choice="$(read_menu_choice "Choose an action")"
    fi
    case "${choice}" in
      1) perform_action repair; return ;;
      2) perform_action install-reset; return ;;
      3) perform_action install-test-reset; return ;;
      4) perform_action check-config || true ;;
      5) basic_health ;;
      0) return ;;
      *) [[ "${language}" == "ru" ]] && printf 'Неизвестный пункт.\n' || printf 'Unknown menu item.\n' ;;
    esac
  done
}

menu_legacy() {
  local choice=""
  while true; do
    inspect_system
    if [[ "${language}" == "ru" ]]; then
      cat <<'EOF'

Обнаружена работающая установка, созданная старым Ansible/вручную.
Новая конфигурация не будет применяться автоматически.
  1) Проверить используемые HAProxy и Compose-конфиги
  2) Проверить systemd-сервисы, контейнеры и порты
  3) Создать защищённый snapshot перед миграцией
  4) Показать безопасный план принятия под управление
  5) Проверить доступные обновления без установки
  6) Проверить и точечно обновить найденное
  7) Обновить только Docker-контейнеры easy-ha-proxy
  0) Выход
EOF
      choice="$(read_menu_choice "Выберите действие")"
    else
      cat <<'EOF'

A working installation created by older Ansible/manual steps was detected.
The new configuration will not be applied automatically.
  1) Validate the active HAProxy and Compose configuration
  2) Check systemd services, containers, and ports
  3) Create a protected snapshot before migration
  4) Show the safe adoption plan
  5) Check for updates without installing
  6) Detect and apply selected updates
  7) Update only easy-ha-proxy Docker containers
  0) Exit
EOF
      choice="$(read_menu_choice "Choose an action")"
    fi
    case "${choice}" in
      1) perform_action check-config || true ;;
      2) basic_health ;;
      3) perform_action snapshot-legacy ;;
      4) perform_action migration-plan ;;
      5) perform_action check-updates ;;
      6) perform_action smart-update ;;
      7) perform_action update-containers ;;
      0) return ;;
      *) [[ "${language}" == "ru" ]] && printf 'Неизвестный пункт.\n' || printf 'Unknown menu item.\n' ;;
    esac
  done
}

menu_installed_advanced() {
  local choice=""
  while true; do
    inspect_system
    if [[ "${language}" == "ru" ]]; then
      cat <<'EOF'

Дополнительные операции:
  1) Полная проверка статуса приложения
  2) Проверить конфигурационные файлы
  3) Предварительный план изменений (Ansible check mode)
  4) Проверить доступные обновления
  5) Проверить и точечно обновить найденное
  6) Обновить весь стек до последней версии
  7) Обновить только веб-интерфейс
  8) Обновить только Docker-контейнеры
  9) Применить уже загруженную local source-версию
  10) Изменить конфигурацию и применить
  11) Повторно применить установку/восстановить компоненты
  12) Сменить основной домен
  13) Создать зашифрованный полный backup для переноса/DR
EOF
    else
      cat <<'EOF'

Advanced operations:
  1) Run the full application status check
  2) Validate configuration files
  3) Preview changes (Ansible check mode)
  4) Check for available updates
  5) Detect and apply selected updates
  6) Update the complete stack to the latest version
  7) Update only the web interface
  8) Update only Docker containers
  9) Apply the already uploaded local source version
  10) Change configuration and apply it
  11) Reapply the installation/repair components
  12) Change the root domain
  13) Create an encrypted full backup for migration/DR
EOF
    fi
    if [[ "${configuration_mode}" == "test" ]]; then
      if [[ "${language}" == "ru" ]]; then
        printf '  14) Показать адреса и hosts для тестового режима\n'
      else
        printf '  14) Show test-mode addresses and hosts entries\n'
      fi
    fi
    if [[ "${language}" == "ru" ]]; then
      printf '  0) Выход\n'
      choice="$(read_menu_choice "Выберите действие")"
    else
      printf '  0) Exit\n'
      choice="$(read_menu_choice "Choose an action")"
    fi
    case "${choice}" in
      1) perform_action status ;;
      2) perform_action check-config || true ;;
      3) perform_action plan ;;
      4) perform_action check-updates ;;
      5) perform_action smart-update ;;
      6) perform_action update ;;
      7) perform_action update-ui ;;
      8) perform_action update-containers ;;
      9) perform_action apply-current ;;
      10) perform_action configure ;;
      11) perform_action repair ;;
      12) perform_action migrate-domain ;;
      13) perform_action backup-full ;;
      14)
        [[ "${configuration_mode}" == "test" ]] &&
          perform_action test-info ||
          [[ "${language}" == "ru" ]] && printf 'Неизвестный пункт.\n' || printf 'Unknown menu item.\n'
        ;;
      0) return ;;
      *) [[ "${language}" == "ru" ]] && printf 'Неизвестный пункт.\n' || printf 'Unknown menu item.\n' ;;
    esac
  done
}

menu_installed() {
  local choice=""
  while true; do
    inspect_system
    if [[ "${language}" == "ru" ]]; then
      cat <<'EOF'

Управление установленным стеком:
  1) Проверить обновления и установить выбранные
  2) Только проверить обновления
  3) Проверить статус сервисов
  4) Изменить конфигурацию и применить
  5) Изменить язык всего стека
  6) Дополнительные операции
  7) Перевести тестовую установку в production без переустановки
  8) Перезагрузить сервер для завершения обновлений
  0) Выход
EOF
      choice="$(read_menu_choice "Выберите действие")"
    else
      cat <<'EOF'

Manage the installed stack:
  1) Check for updates and install selected items
  2) Check for updates only
  3) Check service status
  4) Change configuration and apply it
  5) Change the complete stack language
  6) Advanced operations
  7) Promote the test installation to production without reinstalling
  8) Reboot the server to finish applying operating-system updates
  0) Exit
EOF
      choice="$(read_menu_choice "Choose an action")"
    fi
    case "${choice}" in
      1) perform_action smart-update ;;
      2) perform_action check-updates ;;
      3) perform_action status ;;
      4) perform_action configure ;;
      5) perform_action language ;;
      6) menu_installed_advanced ;;
      7)
        if [[ "${configuration_mode}" == "test" ]]; then
          perform_action promote-production
        else
          printf '%s\n' "$(message 'This action is available only in test mode.' 'Это действие доступно только в тестовом режиме.')"
        fi
        ;;
      8) perform_action reboot ;;
      0) return ;;
      *) [[ "${language}" == "ru" ]] && printf 'Неизвестный пункт.\n' || printf 'Unknown menu item.\n' ;;
    esac
  done
}

if [[ "${action}" != "menu" ]]; then
  perform_action "${action}"
  exit $?
fi

case "${installation_state}" in
  clean) menu_clean ;;
  partial) menu_partial ;;
  legacy) menu_legacy ;;
  installed) menu_installed ;;
esac
