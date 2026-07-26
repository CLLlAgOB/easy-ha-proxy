#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

product="easy-ha-proxy"
branch="${EASY_HA_PROXY_BRANCH:-main}"
raw_base="${EASY_HA_PROXY_RAW_BASE:-https://raw.githubusercontent.com/CLLlAgOB/easy-ha-proxy/${branch}}"
temporary_components=()
component=""
inventory_candidates=()
input_fd=0
language_from_env="${EASY_HA_PROXY_LANGUAGE:-}"
language="${language_from_env:-en}"
case "${language}" in
  en|ru) ;;
  *) language="en" ;;
esac
if { exec 3</dev/tty; } 2>/dev/null; then
  input_fd=3
fi

usage() {
  cat <<'EOF'
easy-ha-proxy smart installer and maintenance assistant

Usage:
  install.sh                         Detect the system and open an interactive menu
  install.sh local                  Manage/install this machine
  install.sh remote [options]       Manage/install a machine over SSH
  install.sh ACTION                 Run a local maintenance action
  install.sh prepare-legacy [LIVE]  Build a local config from a legacy snapshot
  install.sh plan-legacy [CONFIG]   Check prepared config against the server
  install.sh diff-legacy-haproxy    Show the protected HAProxy config diff
  install.sh stage-legacy [CONFIG]  Stage the new control plane without apply
  install.sh finalize-legacy        Sync the safe UI template and verify status
  install.sh sync-source [INVENTORY] Upload local source without applying it
  install.sh backup-full [INVENTORY] Create/download encrypted full backup
  install.sh restore-full BACKUP [INVENTORY] [HOST] [MODE]
                                      Restore backup (MODE: auto/fresh/overlay)

Local actions:
  inspect, status, check-config, plan, check-updates, smart-update, update, reboot,
  apply-current, update-ui, update-containers, configure, migrate-domain,
  promote-production, repair,
  install, install-test, install-reset, install-test-reset,
  test-info, backup-full, snapshot-legacy, migration-plan, prepare-legacy, plan-legacy,
  diff-legacy-haproxy,
  stage-legacy, finalize-legacy, sync-source

Examples:
  ./install.sh
  ./install.sh local
  ./install.sh local --language ru
  ./install.sh install-test
  ./install.sh check-updates
  ./install.sh remote admin@192.0.2.10
  ./install.sh remote --host 192.0.2.10 --user admin --ask-pass
  ./install.sh remote --host 192.0.2.10 --user admin --identity ~/.ssh/server
  ./install.sh remote --inventory ansible/inventory.ini --limit my_server
  ./install.sh remote --language ru --inventory ansible/inventory.ini --limit my_server

Run "install.sh remote --help" for all remote connection options.
EOF
}

die() {
  printf '[%s] ERROR: %s\n' "${product}" "$*" >&2
  exit 1
}

cleanup() {
  local path
  for path in "${temporary_components[@]}"; do
    rm -f "${path}"
  done
}
trap cleanup EXIT

component_path() {
  local name="$1"
  local source_path="${BASH_SOURCE[0]}"
  local source_dir=""
  local temporary=""
  local safe_name=""

  source_path="$(readlink -f "${source_path}" 2>/dev/null || printf '%s' "${source_path}")"
  if [[ -f "${source_path}" ]]; then
    source_dir="$(cd -- "$(dirname -- "${source_path}")" && pwd)"
    if [[ -r "${source_dir}/${name}" ]]; then
      component="${source_dir}/${name}"
      return
    fi
  fi

  command -v curl >/dev/null 2>&1 ||
    die "curl is required to download ${name}."
  safe_name="${name//\//-}"
  temporary="$(mktemp -t "easy-ha-proxy-${safe_name}.XXXXXX")"
  temporary_components+=("${temporary}")
  printf '[%s] Downloading %s\n' "${product}" "${name}" >&2
  curl -fsSL "${raw_base}/${name}" -o "${temporary}"
  chmod 0700 "${temporary}"
  component="${temporary}"
}

prepare_legacy_config() {
  local backup_root="${EASY_HA_PROXY_BACKUP_DIR:-${HOME:-${PWD}}/easy-ha-proxy-backups}"
  local live_dir="${1:-}"
  local controller_dir=""
  local output_dir=""
  local preparer=""
  local source_path=""

  if [[ -z "${live_dir}" ]]; then
    live_dir="$(
      find "${backup_root}" \
        -mindepth 2 -maxdepth 2 -type d -name live \
        -printf '%T@ %p\n' 2>/dev/null |
        sort -nr |
        awk 'NR == 1 {$1=""; sub(/^ /, ""); print}'
    )"
  fi
  [[ -n "${live_dir}" && -d "${live_dir}" ]] ||
    die "Legacy snapshot live/ directory not found."

  source_path="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s' "${BASH_SOURCE[0]}")"
  controller_dir="${EASY_HA_PROXY_CONTROLLER_DIR:-$(cd -- "$(dirname -- "${source_path}")" && pwd)}"
  [[ -f "${controller_dir}/ansible/authelia.yml" ]] ||
    die "Controller Ansible files not found under ${controller_dir}."

  output_dir="$(dirname -- "${live_dir}")/prepared-config"
  component_path installer/prepare_legacy_config.py
  preparer="${component}"
  command -v python3 >/dev/null 2>&1 || die "python3 is required."
  python3 "${preparer}" \
    --live-dir "${live_dir}" \
    --controller-dir "${controller_dir}" \
    --output-dir "${output_dir}"
}

plan_legacy_config() {
  local backup_root="${EASY_HA_PROXY_BACKUP_DIR:-${HOME:-${PWD}}/easy-ha-proxy-backups}"
  local prepared_dir="${1:-}"
  local inventory="${2:-}"
  local plan_mode="${3:-full}"
  local controller_dir=""
  local source_path=""
  local log_file=""
  local timestamp=""
  local status=0
  local answer=""
  local -a command=()
  local -a pipeline_status=()
  local update_tags=""

  if [[ -z "${prepared_dir}" ]]; then
    prepared_dir="$(
      find "${backup_root}" \
        -mindepth 2 -maxdepth 2 -type d -name prepared-config \
        -printf '%T@ %p\n' 2>/dev/null |
        sort -nr |
        awk 'NR == 1 {$1=""; sub(/^ /, ""); print}'
    )"
  fi
  [[ -n "${prepared_dir}" && -d "${prepared_dir}" ]] ||
    die "Prepared legacy configuration not found."
  for required in \
    vars.yml \
    authelia.yml \
    authelia_users_initial.yml \
    websites.yml \
    tcp.yml \
    secrets.yml \
    metadata.yml; do
    [[ -f "${prepared_dir}/${required}" ]] ||
      die "Prepared configuration is incomplete: ${required}"
  done

  source_path="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s' "${BASH_SOURCE[0]}")"
  controller_dir="${EASY_HA_PROXY_CONTROLLER_DIR:-$(cd -- "$(dirname -- "${source_path}")" && pwd)}"
  [[ -f "${controller_dir}/ansible/easy-ha-proxy.yml" ]] ||
    die "Controller playbook not found under ${controller_dir}."

  if [[ -z "${inventory}" ]]; then
    discover_inventory_files
    [[ "${#inventory_candidates[@]}" -gt 0 ]] ||
      die "Remote inventory.ini not found."
    inventory="${inventory_candidates[0]}"
  fi
  [[ -r "${inventory}" ]] || die "Cannot read inventory: ${inventory}"
  command -v ansible-playbook >/dev/null 2>&1 ||
    die "ansible-playbook is required on the controller."

  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  if [[ "${plan_mode}" == "haproxy-diff" ]]; then
    log_file="$(dirname -- "${prepared_dir}")/legacy-haproxy-diff-${timestamp}.log"
    update_tags="ha-cfg"
  elif [[ "${plan_mode}" == "finalize" ]]; then
    log_file="$(dirname -- "${prepared_dir}")/legacy-finalize-${timestamp}.log"
    update_tags="ha-adm-cfg,status"
  else
    log_file="$(dirname -- "${prepared_dir}")/legacy-plan-${timestamp}.log"
    update_tags="crt-hooks,crt-notify,ha-install,apparmor,geo,ha-cfg,docker,aut-install,"
    update_tags+="ha-adm-install,ha-adm-healthd,ha-adm-cfg,ha-adm-controld,"
    update_tags+="ha-adm-journald,ha-adm-update,ha-adm-start,status"
  fi

  command=(
    ansible-playbook
    -i "${inventory}"
    "${controller_dir}/ansible/easy-ha-proxy.yml"
    --extra-vars "easy_ha_proxy_config_dir=${prepared_dir}"
    --extra-vars "easy_ha_proxy_target=easy_ha_proxy"
    --tags "${update_tags}"
  )

  printf 'Prepared config: %s\n' "${prepared_dir}"
  printf 'Remote inventory: %s\n' "${inventory}"
  printf 'Plan log: %s\n' "${log_file}"
  if [[ "${plan_mode}" == "haproxy-diff" ]]; then
    if [[ "${language}" == "ru" ]]; then
      answer="$(read_tty "Показать защищённый HAProxy diff через check mode? [y/N]: ")"
    else
      answer="$(read_tty "Show the protected HAProxy diff using check mode? [y/N]: ")"
    fi
  elif [[ "${plan_mode}" == "finalize" ]]; then
    if [[ "${language}" == "ru" ]]; then
      answer="$(read_tty "Введите APPLY для синхронизации UI-шаблона: ")"
    else
      answer="$(read_tty "Enter APPLY to synchronize the UI template: ")"
    fi
  else
    if [[ "${language}" == "ru" ]]; then
      answer="$(read_tty "Запустить syntax-check и удалённый Ansible check mode? [y/N]: ")"
    else
      answer="$(read_tty "Run syntax-check and remote Ansible check mode? [y/N]: ")"
    fi
  fi
  if [[ "${plan_mode}" == "finalize" ]]; then
    [[ "${answer}" == "APPLY" ]] || {
      [[ "${language}" == "ru" ]] && printf 'Действие отменено.\n' || printf 'Action cancelled.\n'
      return
    }
  else
    case "${answer,,}" in
      y|yes|д|да) ;;
      *)
        [[ "${language}" == "ru" ]] && printf 'Действие отменено.\n' || printf 'Action cancelled.\n'
        return
        ;;
    esac
  fi

  set +e
  {
    printf '=== syntax-check ===\n'
    ANSIBLE_CONFIG="${controller_dir}/ansible/ansible.cfg" \
    ANSIBLE_VARS_ENABLED='' \
    ANSIBLE_LOCAL_TEMP=/tmp/easy-ha-proxy-ansible \
      "${command[@]}" --syntax-check
    if [[ "${plan_mode}" == "finalize" ]]; then
      printf '\n=== targeted apply (ha-adm-cfg,status) ===\n'
    else
      printf '\n=== check mode ===\n'
    fi
    if [[ "${plan_mode}" == "haproxy-diff" ]]; then
      ANSIBLE_CONFIG="${controller_dir}/ansible/ansible.cfg" \
      ANSIBLE_VARS_ENABLED='' \
      ANSIBLE_LOCAL_TEMP=/tmp/easy-ha-proxy-ansible \
        "${command[@]}" --check --diff
    elif [[ "${plan_mode}" == "finalize" ]]; then
      ANSIBLE_CONFIG="${controller_dir}/ansible/ansible.cfg" \
      ANSIBLE_VARS_ENABLED='' \
      ANSIBLE_LOCAL_TEMP=/tmp/easy-ha-proxy-ansible \
        "${command[@]}"
    else
      ANSIBLE_CONFIG="${controller_dir}/ansible/ansible.cfg" \
      ANSIBLE_VARS_ENABLED='' \
      ANSIBLE_LOCAL_TEMP=/tmp/easy-ha-proxy-ansible \
        "${command[@]}" --check
    fi
  } 2>&1 | tee "${log_file}"
  pipeline_status=("${PIPESTATUS[@]}")
  status="${pipeline_status[0]}"
  set -e
  chmod 0600 "${log_file}"

  if [[ "${status}" -ne 0 ]]; then
    die "Legacy plan failed with exit code ${status}. Review ${log_file}"
  fi
  if [[ "${plan_mode}" == "finalize" ]]; then
    printf '\nLegacy control-plane finalization completed.\n'
    printf 'Only ha-adm-cfg and read-only status tags were run.\n'
    printf 'Review log: %s\n' "${log_file}"
  else
    printf '\nLegacy check mode completed. No apply was performed.\n'
    printf 'Review log: %s\n' "${log_file}"
  fi
}

stage_legacy_control_plane() {
  local backup_root="${EASY_HA_PROXY_BACKUP_DIR:-${HOME:-${PWD}}/easy-ha-proxy-backups}"
  local prepared_dir="${1:-}"
  local inventory="${2:-}"
  local limit_host="${3:-}"
  local controller_dir=""
  local source_path=""
  local -a arguments=()

  if [[ -z "${prepared_dir}" ]]; then
    prepared_dir="$(
      find "${backup_root}" \
        -mindepth 2 -maxdepth 2 -type d -name prepared-config \
        -printf '%T@ %p\n' 2>/dev/null |
        sort -nr |
        awk 'NR == 1 {$1=""; sub(/^ /, ""); print}'
    )"
  fi
  [[ -n "${prepared_dir}" && -d "${prepared_dir}" ]] ||
    die "Prepared legacy configuration not found."

  source_path="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s' "${BASH_SOURCE[0]}")"
  controller_dir="${EASY_HA_PROXY_CONTROLLER_DIR:-$(cd -- "$(dirname -- "${source_path}")" && pwd)}"
  [[ -f "${controller_dir}/installer/easy_ha_proxy.py" ]] ||
    die "Controller source tree not found under ${controller_dir}."

  if [[ -z "${inventory}" ]]; then
    discover_inventory_files
    [[ "${#inventory_candidates[@]}" -gt 0 ]] ||
      die "Remote inventory.ini not found."
    inventory="${inventory_candidates[0]}"
  fi
  [[ -r "${inventory}" ]] || die "Cannot read inventory: ${inventory}"

  arguments=(
    --inventory "${inventory}"
    --stage-legacy "${prepared_dir}"
    --source-root "${controller_dir}"
  )
  [[ -n "${limit_host}" ]] && arguments+=(--limit "${limit_host}")
  run_remote_helper "${arguments[@]}"
}

sync_managed_source() {
  local inventory="${1:-}"
  local limit_host="${2:-}"
  local controller_dir=""
  local source_path=""
  local -a arguments=()

  source_path="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s' "${BASH_SOURCE[0]}")"
  controller_dir="${EASY_HA_PROXY_CONTROLLER_DIR:-$(cd -- "$(dirname -- "${source_path}")" && pwd)}"
  [[ -f "${controller_dir}/installer/easy_ha_proxy.py" ]] ||
    die "Controller source tree not found under ${controller_dir}."

  if [[ -z "${inventory}" ]]; then
    discover_inventory_files
    [[ "${#inventory_candidates[@]}" -gt 0 ]] ||
      die "Remote inventory.ini not found."
    inventory="${inventory_candidates[0]}"
  fi
  [[ -r "${inventory}" ]] || die "Cannot read inventory: ${inventory}"

  arguments=(
    --inventory "${inventory}"
    --sync-source "${controller_dir}"
  )
  [[ -n "${limit_host}" ]] && arguments+=(--limit "${limit_host}")
  run_remote_helper "${arguments[@]}"
}

backup_full_remote() {
  local inventory="${1:-}"
  local limit_host="${2:-}"
  local -a arguments=()

  if [[ -z "${inventory}" ]]; then
    discover_inventory_files
    [[ "${#inventory_candidates[@]}" -gt 0 ]] ||
      die "Remote inventory.ini not found."
    inventory="${inventory_candidates[0]}"
  fi
  [[ -r "${inventory}" ]] || die "Cannot read inventory: ${inventory}"
  arguments=(--inventory "${inventory}" --action backup-full)
  [[ -n "${limit_host}" ]] && arguments+=(--limit "${limit_host}")
  run_remote_helper "${arguments[@]}"
}

restore_full_remote() {
  local backup="${1:-}"
  local inventory="${2:-}"
  local limit_host="${3:-}"
  local restore_mode="${4:-auto}"
  local controller_dir=""
  local source_path=""
  local -a arguments=()

  [[ -n "${backup}" && -r "${backup}" ]] ||
    die "Encrypted full backup not found: ${backup:-<missing>}"
  source_path="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s' "${BASH_SOURCE[0]}")"
  controller_dir="${EASY_HA_PROXY_CONTROLLER_DIR:-$(cd -- "$(dirname -- "${source_path}")" && pwd)}"
  [[ -f "${controller_dir}/installer/full_backup.py" ]] ||
    die "Controller recovery source not found under ${controller_dir}."
  if [[ -z "${inventory}" ]]; then
    discover_inventory_files
    [[ "${#inventory_candidates[@]}" -gt 0 ]] ||
      die "Remote inventory.ini not found."
    inventory="${inventory_candidates[0]}"
  fi
  [[ -r "${inventory}" ]] || die "Cannot read inventory: ${inventory}"
  arguments=(
    --inventory "${inventory}"
    --restore-full "${backup}"
    --restore-mode "${restore_mode}"
    --source-root "${controller_dir}"
  )
  [[ -n "${limit_host}" ]] && arguments+=(--limit "${limit_host}")
  run_remote_helper "${arguments[@]}"
}

runtime_copy() {
  local source="$1"
  local name="$2"
  local temporary=""
  temporary="$(mktemp -t "easy-ha-proxy-runtime-${name}.XXXXXX")"
  temporary_components+=("${temporary}")
  cp -- "${source}" "${temporary}"
  chmod 0700 "${temporary}"
  component="${temporary}"
}

run_local_helper() {
  local helper=""
  local helper_source=""
  local local_installer=""
  local installer_source=""
  component_path easy-ha-proxy-helper.sh
  helper_source="${component}"
  component_path install-local.sh
  installer_source="${component}"
  runtime_copy "${helper_source}" helper.sh
  helper="${component}"
  runtime_copy "${installer_source}" install-local.sh
  local_installer="${component}"
  if [[ -n "${language_from_env}" ]]; then
    EASY_HA_PROXY_LOCAL_INSTALLER="${local_installer}" \
    EASY_HA_PROXY_RAW_BASE="${raw_base}" \
    EASY_HA_PROXY_LANGUAGE="${language}" \
      bash "${helper}" "$@"
  else
    EASY_HA_PROXY_LOCAL_INSTALLER="${local_installer}" \
    EASY_HA_PROXY_RAW_BASE="${raw_base}" \
      bash "${helper}" "$@"
  fi
}

run_remote_helper() {
  local remote_installer=""
  local local_installer=""
  local helper=""
  component_path install-remote.sh
  remote_installer="${component}"
  component_path install-local.sh
  local_installer="${component}"
  component_path easy-ha-proxy-helper.sh
  helper="${component}"
  if [[ -n "${language_from_env}" ]]; then
    EASY_HA_PROXY_INSTALLER_FILE="${local_installer}" \
    EASY_HA_PROXY_HELPER_FILE="${helper}" \
    EASY_HA_PROXY_RAW_BASE="${raw_base}" \
    EASY_HA_PROXY_LANGUAGE="${language}" \
      bash "${remote_installer}" "$@"
  else
    EASY_HA_PROXY_INSTALLER_FILE="${local_installer}" \
    EASY_HA_PROXY_HELPER_FILE="${helper}" \
    EASY_HA_PROXY_RAW_BASE="${raw_base}" \
      bash "${remote_installer}" "$@"
  fi
}

discover_inventory_files() {
  local source_path="${BASH_SOURCE[0]}"
  local source_dir=""
  local candidate=""
  local canonical=""
  local -a possible=()
  declare -A seen=()

  inventory_candidates=()
  possible=(
    "${PWD}/inventory.ini"
    "${PWD}"/inventory*.ini
    "${PWD}/ansible/inventory.ini"
    "${PWD}/ansible"/inventory*.ini
  )
  if [[ -f "${source_path}" ]]; then
    source_dir="$(cd -- "$(dirname -- "${source_path}")" && pwd)"
    possible+=(
      "${source_dir}/inventory.ini"
      "${source_dir}"/inventory*.ini
      "${source_dir}/ansible/inventory.ini"
      "${source_dir}/ansible"/inventory*.ini
    )
  fi

  for candidate in "${possible[@]}"; do
    [[ -f "${candidate}" ]] || continue
    canonical="$(
      cd -- "$(dirname -- "${candidate}")" &&
        printf '%s/%s' "$(pwd -P)" "$(basename -- "${candidate}")"
    )"
    [[ -z "${seen[${canonical}]+x}" ]] || continue
    seen["${canonical}"]=1
    inventory_candidates+=("${canonical}")
  done
}

read_tty() {
  local prompt="$1"
  local default="${2:-}"
  local answer=""
  if [[ "${input_fd}" -eq 0 && ! -t 0 ]]; then
    die "Interactive mode requires a terminal."
  fi
  if ! read -r -u "${input_fd}" -p "${prompt}" answer; then
    die "Interactive mode requires a terminal."
  fi
  printf '%s' "${answer:-${default}}"
}

select_language() {
  local choice=""
  cat <<'EOF'

Select language / Выберите язык:
  1) English
  2) Русский
EOF
  choice="$(read_tty "Language / Язык [1]: " "1")"
  case "${choice,,}" in
    2|ru|rus|рус|русский) language="ru" ;;
    *) language="en" ;;
  esac
  language_from_env="${language}"
  export EASY_HA_PROXY_LANGUAGE="${language}"
}

print_inventory_choices() {
  local index=1
  local inventory=""

  if [[ "${language}" == "ru" ]]; then
    printf '\nНайдены inventory-файлы:\n' >&2
  else
    printf '\nDetected inventory files:\n' >&2
  fi
  for inventory in "${inventory_candidates[@]}"; do
    printf '  %d. %s\n' "${index}" "${inventory}" >&2
    index=$((index + 1))
  done
}

resolve_inventory_choice() {
  local choice="$1"
  local index=0
  local candidate=""
  local basename_choice=""
  local matches=()

  [[ -n "${choice}" ]] || return 1
  if [[ "${choice}" =~ ^[0-9]+$ ]]; then
    index=$((10#${choice} - 1))
    if (( index >= 0 && index < ${#inventory_candidates[@]} )); then
      printf '%s' "${inventory_candidates[${index}]}"
      return 0
    fi
    return 1
  fi

  if [[ -r "${choice}" ]]; then
    printf '%s' "${choice}"
    return 0
  fi

  basename_choice="$(basename -- "${choice}")"
  for candidate in "${inventory_candidates[@]}"; do
    if [[ "${candidate}" == "${choice}" ||
          "$(basename -- "${candidate}")" == "${basename_choice}" ]]; then
      matches+=("${candidate}")
    fi
  done
  if [[ "${#matches[@]}" -eq 1 ]]; then
    printf '%s' "${matches[0]}"
    return 0
  fi
  return 1
}

prompt_inventory_path() {
  local answer=""
  local resolved=""
  local default_inventory="${inventory_candidates[0]:-}"

  if [[ "${#inventory_candidates[@]}" -gt 0 ]]; then
    print_inventory_choices
    while true; do
      if [[ "${language}" == "ru" ]]; then
        answer="$(read_tty "Inventory: номер, путь или имя файла [1]: " "1")"
      else
        answer="$(read_tty "Inventory number, path, or filename [1]: " "1")"
      fi
      if resolved="$(resolve_inventory_choice "${answer}")"; then
        printf '%s' "${resolved}"
        return 0
      fi
      if [[ "${language}" == "ru" ]]; then
        printf 'Не удалось найти inventory по вводу: %s\n' "${answer}" >&2
      else
        printf 'Could not resolve inventory from input: %s\n' "${answer}" >&2
      fi
    done
  fi

  if [[ "${language}" == "ru" ]]; then
    answer="$(read_tty "Путь к inventory.ini: ")"
    [[ -n "${answer}" ]] || die "Не указан inventory.ini."
  else
    answer="$(read_tty "Path to inventory.ini: ")"
    [[ -n "${answer}" ]] || die "inventory.ini was not specified."
  fi
  if [[ -r "${answer}" ]]; then
    printf '%s' "${answer}"
    return 0
  fi
  if [[ -n "${default_inventory}" ]]; then
    printf '%s' "${default_inventory}"
    return 0
  fi
  die "Cannot read inventory: ${answer}"
}

prompt_remote_connection() {
  local choice=""
  local inventory=""
  local alias=""
  local host=""
  local user=""
  local port=""
  local identity=""
  local -a arguments=()

  if [[ "${language}" == "ru" ]]; then
    cat <<'EOF'

Как подключиться к удалённой машине?
  1) Использовать Ansible INI inventory
  2) Логин и пароль SSH
  3) Логин и приватный SSH-ключ
  0) Назад
EOF
    choice="$(read_tty "Выберите вариант: ")"
  else
    cat <<'EOF'

How should the remote machine be accessed?
  1) Use an Ansible INI inventory
  2) SSH username and password
  3) SSH username and private key
  0) Back
EOF
    choice="$(read_tty "Choose a connection method: ")"
  fi
  case "${choice}" in
    1)
      discover_inventory_files
      inventory="$(prompt_inventory_path)"
      if [[ "${language}" == "ru" ]]; then
        alias="$(read_tty "Alias хоста (--limit), если хост один — Enter: ")"
      else
        alias="$(read_tty "Host alias (--limit); press Enter when inventory has one host: ")"
      fi
      arguments=(--inventory "${inventory}")
      [[ -n "${alias}" ]] && arguments+=(--limit "${alias}")
      ;;
    2)
      if [[ "${language}" == "ru" ]]; then
        host="$(read_tty "IP или hostname: ")"
        user="$(read_tty "SSH-пользователь: ")"
        port="$(read_tty "SSH-порт [22]: " "22")"
      else
        host="$(read_tty "IP or hostname: ")"
        user="$(read_tty "SSH user: ")"
        port="$(read_tty "SSH port [22]: " "22")"
      fi
      [[ -n "${host}" && -n "${user}" ]] ||
        die "Необходимо указать адрес и SSH-пользователя."
      arguments=(--host "${host}" --user "${user}" --port "${port}" --ask-pass)
      ;;
    3)
      if [[ "${language}" == "ru" ]]; then
        host="$(read_tty "IP или hostname: ")"
        user="$(read_tty "SSH-пользователь: ")"
        port="$(read_tty "SSH-порт [22]: " "22")"
        identity="$(read_tty "Путь к приватному ключу: ")"
      else
        host="$(read_tty "IP or hostname: ")"
        user="$(read_tty "SSH user: ")"
        port="$(read_tty "SSH port [22]: " "22")"
        identity="$(read_tty "Private key path: ")"
      fi
      [[ -n "${host}" && -n "${user}" && -n "${identity}" ]] ||
        die "Необходимо указать адрес, пользователя и ключ."
      arguments=(
        --host "${host}"
        --user "${user}"
        --port "${port}"
        --identity "${identity}"
      )
      ;;
    0)
      return
      ;;
    *)
      [[ "${language}" == "ru" ]] && die "Неизвестный вариант подключения."
      die "Unknown connection method."
      ;;
  esac
  run_remote_helper "${arguments[@]}"
}

has_local_installation_markers() {
  [[ -e "${EASY_HA_PROXY_HOME:-/opt/easy-ha-proxy}" ||
     -e "${EASY_HA_PROXY_CONFIG_DIR:-/etc/easy-ha-proxy}" ||
     -e /usr/local/bin/easy-ha-proxy ||
     -L /usr/local/bin/easy-ha-proxy ||
     -e /opt/authelia ||
     -e /opt/haproxy-admin ]]
}

initial_menu() {
  local choice=""

  if has_local_installation_markers; then
    run_local_helper --action menu
    return
  fi

  discover_inventory_files

  if [[ "${language}" == "ru" ]]; then
    cat <<'EOF'

easy-ha-proxy на этой машине не обнаружен.

Что нужно сделать?
  1) Установить production-версию локально
  2) Установить тестовую версию локально (VM без публичного IP/DNS)
  3) Подключиться к удалённой машине
  4) Открыть локальный диагностический помощник
  0) Выход
EOF
  else
    cat <<'EOF'

easy-ha-proxy was not detected on this machine.

What would you like to do?
  1) Install the production version locally
  2) Install the test version locally (VM without public IP/DNS)
  3) Connect to a remote machine
  4) Open the local diagnostic assistant
  0) Exit
EOF
  fi
  if [[ "${#inventory_candidates[@]}" -gt 0 ]]; then
    if [[ "${language}" == "ru" ]]; then
      printf '\nНайден inventory для удалённого подключения: %s\n' "${inventory_candidates[0]}"
    else
      printf '\nRemote inventory detected: %s\n' "${inventory_candidates[0]}"
    fi
  fi
  if [[ "${language}" == "ru" ]]; then
    choice="$(read_tty "Выберите действие: ")"
  else
    choice="$(read_tty "Choose an action: ")"
  fi
  case "${choice}" in
    1) run_local_helper --action install ;;
    2) run_local_helper --action install-test ;;
    3) prompt_remote_connection ;;
    4) run_local_helper --action menu ;;
    0) return ;;
    *)
      [[ "${language}" == "ru" ]] && die "Неизвестный пункт меню."
      die "Unknown menu item."
      ;;
  esac
}

mode="${1:-}"
if [[ -z "${mode}" && -z "${language_from_env}" ]]; then
  select_language
fi
case "${mode}" in
  "")
    initial_menu
    ;;
  local)
    shift
    run_local_helper "$@"
    ;;
  remote)
    shift
    run_remote_helper "$@"
    ;;
  prepare-legacy)
    shift
    prepare_legacy_config "${1:-}"
    ;;
  plan-legacy)
    shift
    plan_legacy_config "${1:-}" "${2:-}" full
    ;;
  diff-legacy-haproxy)
    shift
    plan_legacy_config "${1:-}" "${2:-}" haproxy-diff
    ;;
  stage-legacy)
    shift
    stage_legacy_control_plane "${1:-}" "${2:-}" "${3:-}"
    ;;
  finalize-legacy)
    shift
    plan_legacy_config "${1:-}" "${2:-}" finalize
    ;;
  sync-source)
    shift
    sync_managed_source "${1:-}" "${2:-}"
    ;;
  backup-full)
    shift
    if [[ "$#" -eq 0 ]]; then
      run_local_helper --action backup-full
    else
      backup_full_remote "${1:-}" "${2:-}"
    fi
    ;;
  restore-full)
    shift
    restore_full_remote "${1:-}" "${2:-}" "${3:-}" "${4:-}"
    ;;
  inspect|status|check-config|plan|check-updates|smart-update|update|apply-current|update-ui|update-containers|reboot|configure|language|migrate-domain|promote-production|repair|install|install-test|install-reset|install-test-reset|test-info|snapshot-legacy|migration-plan)
    shift
    run_local_helper --action "${mode}" "$@"
    ;;
  -h|--help)
    usage
    ;;
  *)
    die "Unknown mode or action: ${mode}. Run with --help."
    ;;
esac
