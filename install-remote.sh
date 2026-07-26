#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

product="easy-ha-proxy"
branch="${EASY_HA_PROXY_BRANCH:-main}"
local_installer_url="${EASY_HA_PROXY_INSTALLER_URL:-https://raw.githubusercontent.com/CLLlAgOB/easy-ha-proxy/${branch}/install-local.sh}"
helper_url="${EASY_HA_PROXY_HELPER_URL:-https://raw.githubusercontent.com/CLLlAgOB/easy-ha-proxy/${branch}/easy-ha-proxy-helper.sh}"
local_installer_file="${EASY_HA_PROXY_INSTALLER_FILE:-}"
helper_file="${EASY_HA_PROXY_HELPER_FILE:-}"
language_from_env="${EASY_HA_PROXY_LANGUAGE:-}"
language="${language_from_env:-en}"
case "${language}" in
  en|ru) ;;
  *) language="en" ;;
esac
script_path="${BASH_SOURCE[0]}"
script_dir=""
if [[ -f "${script_path}" ]]; then
  script_dir="$(cd -- "$(dirname -- "${script_path}")" && pwd)"
  if [[ -z "${local_installer_file}" &&
        -r "${script_dir}/install-local.sh" ]]; then
    local_installer_file="${script_dir}/install-local.sh"
  fi
  if [[ -z "${helper_file}" &&
        -r "${script_dir}/easy-ha-proxy-helper.sh" ]]; then
    helper_file="${script_dir}/easy-ha-proxy-helper.sh"
  fi
fi
input_fd=0
if { exec 3</dev/tty; } 2>/dev/null; then
  input_fd=3
fi

usage() {
  cat <<'EOF'
Usage:
  install-remote.sh [options] [user@host]
  install-remote.sh --host HOST --user USER [connection options]
  install-remote.sh --inventory FILE [--limit HOST_ALIAS]

Connection options:
      --host HOST          SSH hostname or IP address
  -u, --user USER          SSH user
  -p, --port PORT          SSH port (default: 22)
  -i, --identity FILE      SSH private key
      --ask-pass           Force SSH password authentication and prompt securely
      --inventory FILE     Read connection data from an Ansible INI inventory
  -l, --limit HOST_ALIAS   Select an inventory host
      --dry-run            Resolve connection settings without connecting
      --snapshot-dir DIR   Local root for downloaded legacy snapshots
      --no-fetch-snapshot  Do not download a snapshot created in this session
      --stage-legacy DIR   Stage source and prepared legacy config without apply
      --sync-source DIR    Atomically replace managed source from a local tree
      --apply              With --sync-source, immediately apply synchronized source
      --restore-full FILE  Restore an encrypted full backup on the target
      --restore-mode MODE  auto, fresh or overlay (default: auto)
      --source-root DIR    Local project root used for staging/sync; with a
                           clean install, test these exact local sources
      --source-channel CH  github or local
      --image-channel CH   latest (release) or alpha (test build)

Installer options:
      --language CODE      Use and save en or ru
      --certificate-source SOURCE
                           Use letsencrypt or internal for install/configure
      --action ACTION      Run menu, inspect, status, check-config, plan,
                           check-updates, smart-update, update, apply-current,
                           update-ui, update-containers, reboot, configure, language,
                           migrate-domain, promote-production, repair,
                           install, install-test, install-reset, install-test-reset,
                           test-info, backup-full, snapshot-legacy or
                           migration-plan
      --test-mode          Start a test installation immediately
      --skip-dns-check     Skip public DNS lookup during production installation
      --new-domain NAME    New root domain for migrate-domain
      --plan-only          Preview migrate-domain without applying it
  -h, --help               Show this help

Supported inventory variables:
  ansible_host, ansible_user, ansible_port, ansible_ssh_port,
  ansible_ssh_private_key_file

Examples:
  ./install-remote.sh admin@192.0.2.10
  ./install-remote.sh --host 192.0.2.10 --user admin --ask-pass
  ./install-remote.sh --host 192.0.2.10 --user admin -i ~/.ssh/server
  ./install-remote.sh --inventory ansible/inventory.ini --limit my_server
  ./install-remote.sh --language ru --inventory ansible/inventory.ini --limit my_server
  ./install-remote.sh --action status admin@192.0.2.10
  ./install-remote.sh --test-mode root@192.168.56.10
EOF
}

die() {
  printf '[%s] ERROR: %s\n' "${product}" "$*" >&2
  exit 1
}

write_source_revision_marker() {
  # Record the exact commit the tarball was built from so the server can, on the
  # github source channel, compare it against the remote branch without keeping a
  # .git checkout. A dirty working tree is marked so the update planner reports it
  # as unverifiable rather than falsely "up to date".
  local root="$1"
  local marker="${root}/.easy-ha-proxy-source-revision"
  local revision="unknown"
  local dirty="false"
  if git -C "${root}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    revision="$(git -C "${root}" rev-parse HEAD 2>/dev/null || printf 'unknown')"
    # Only committed *content* of tracked files ends up in the tarball, so
    # "dirty" must reflect that alone. Ignore untracked local files (inventories,
    # .env, editor scratch) and permission-only drift (common when the repo is
    # accessed from WSL over a Windows mount) to avoid a false "dirty" that
    # would needlessly block the github update channel.
    if [[ -n "$(git -C "${root}" -c core.fileMode=false status --porcelain --untracked-files=no 2>/dev/null)" ]]; then
      dirty="true"
    fi
  fi
  printf 'revision=%s\ndirty=%s\n' "${revision}" "${dirty}" > "${marker}"
}

build_source_archive() {
  local root="$1"
  local destination="$2"
  write_source_revision_marker "${root}"
  tar -C "${root}" -czf "${destination}" \
    --exclude='.git' \
    --exclude='.agents' \
    --exclude='.codex' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='ansible/backups' \
    --exclude='ansible/cache' \
    --exclude='ansible/group_vars' \
    --exclude='ansible/inventory.ini' \
    --exclude='ansible/vars.yml' \
    --exclude='ansible/websites.yml' \
    --exclude='ansible/tcp.yml' \
    --exclude='ansible/authelia_users_initial.yml' \
    --exclude='ansible/roles/cert/files/*.pem' \
    --exclude='ansible/roles/haproxy-admin.zip' \
    ansible installer install.sh install-local.sh install-remote.sh \
    easy-ha-proxy-helper.sh .easy-ha-proxy-source-revision
  # The marker is generated only for packaging; never leave it in the repo.
  rm -f "${root}/.easy-ha-proxy-source-revision"
}

installer_fingerprint() {
  local root="$1"
  local -a files=(
    installer/easy_ha_proxy.py
    installer/easy-ha-proxy
    installer/requirements.txt
    install-local.sh
  )
  local file=""
  for file in "${files[@]}"; do
    [[ -f "${root}/${file}" ]] || return 1
  done
  (
    cd -- "${root}"
    sha256sum "${files[@]}" | sha256sum | awk '{ print $1 }'
  )
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "${value}"
}

unquote() {
  local value="$1"
  if [[ "${value}" == \"*\" && "${value}" == *\" ]] ||
     [[ "${value}" == \'*\' && "${value}" == *\' ]]; then
    value="${value:1:${#value}-2}"
  fi
  printf '%s' "${value}"
}

inventory_value_from_line() {
  local line="$1"
  local wanted="$2"
  local field key value
  local -a fields=()

  read -r -a fields <<<"${line}"
  for field in "${fields[@]:1}"; do
    [[ "${field}" == *=* ]] || continue
    key="${field%%=*}"
    value="${field#*=}"
    if [[ "${key}" == "${wanted}" ]]; then
      unquote "${value}"
      return
    fi
  done
}

load_inventory() {
  local file="$1"
  local requested_alias="$2"
  local raw line section="" group="" alias key value selected_alias=""
  local -a aliases=()
  declare -A host_lines=()
  declare -A host_groups=()
  declare -A group_vars=()

  [[ -r "${file}" ]] || die "Cannot read inventory: ${file}"

  while IFS= read -r raw || [[ -n "${raw}" ]]; do
    line="$(trim "${raw}")"
    [[ -n "${line}" ]] || continue
    [[ "${line}" == \#* || "${line}" == \;* ]] && continue

    if [[ "${line}" =~ ^\[([^]]+)\]$ ]]; then
      section="${BASH_REMATCH[1]}"
      continue
    fi

    if [[ "${section}" == *:vars ]]; then
      group="${section%:vars}"
      [[ "${line}" == *=* ]] || continue
      key="$(trim "${line%%=*}")"
      value="$(unquote "$(trim "${line#*=}")")"
      group_vars["${group}|${key}"]="${value}"
      continue
    fi
    [[ "${section}" == *:* ]] && continue

    line="${line%%[[:space:]]#*}"
    line="$(trim "${line}")"
    [[ -n "${line}" ]] || continue
    read -r alias _ <<<"${line}"
    [[ -n "${alias}" ]] || continue

    if [[ -z "${host_lines[${alias}]+x}" ]]; then
      aliases+=("${alias}")
      host_lines["${alias}"]="${line}"
      host_groups["${alias}"]="${section}"
    fi
  done <"${file}"

  if [[ -n "${requested_alias}" ]]; then
    [[ -n "${host_lines[${requested_alias}]+x}" ]] ||
      die "Inventory host not found: ${requested_alias}"
    selected_alias="${requested_alias}"
  elif [[ "${#aliases[@]}" -eq 1 ]]; then
    selected_alias="${aliases[0]}"
  elif [[ "${#aliases[@]}" -eq 0 ]]; then
    die "No hosts found in inventory: ${file}"
  else
    printf '[%s] Inventory contains multiple hosts: %s\n' \
      "${product}" "${aliases[*]}" >&2
    die "Select one with --limit HOST_ALIAS."
  fi

  inventory_alias="${selected_alias}"
  inventory_group="${host_groups[${selected_alias}]}"
  inventory_line="${host_lines[${selected_alias}]}"

  for key in \
    ansible_host \
    ansible_user \
    ansible_port \
    ansible_ssh_port \
    ansible_ssh_private_key_file; do
    value="$(inventory_value_from_line "${inventory_line}" "${key}")"
    if [[ -z "${value}" ]]; then
      value="${group_vars["${inventory_group}|${key}"]:-}"
    fi
    if [[ -z "${value}" ]]; then
      value="${group_vars["all|${key}"]:-}"
    fi
    printf -v "inventory_${key}" '%s' "${value}"
  done
}

ssh_host=""
ssh_user=""
ssh_port=""
identity_file=""
identity_from_cli=false
inventory_file=""
limit_host=""
positional_target=""
ask_pass=false
dry_run=false
remote_action="menu"
language_explicit=false
[[ -n "${language_from_env}" ]] && language_explicit=true
skip_dns_check=false
certificate_source=""
source_channel=""
image_channel=""
apply_after_sync=false
new_domain=""
plan_only=false
fetch_snapshot=true
prepared_config_dir=""
source_root=""
restore_archive=""
restore_mode="auto"
local_snapshot_root="${EASY_HA_PROXY_BACKUP_DIR:-${HOME:-${PWD}}/easy-ha-proxy-backups}"

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --host)
      [[ "$#" -ge 2 ]] || die "Missing SSH host."
      ssh_host="$2"
      shift 2
      ;;
    -u|--user)
      [[ "$#" -ge 2 ]] || die "Missing SSH user."
      ssh_user="$2"
      shift 2
      ;;
    -p|--port)
      [[ "$#" -ge 2 ]] || die "Missing SSH port."
      ssh_port="$2"
      shift 2
      ;;
    -i|--identity)
      [[ "$#" -ge 2 ]] || die "Missing identity file."
      identity_file="$2"
      identity_from_cli=true
      shift 2
      ;;
    --ask-pass)
      ask_pass=true
      shift
      ;;
    --inventory)
      [[ "$#" -ge 2 ]] || die "Missing inventory path."
      inventory_file="$2"
      shift 2
      ;;
    -l|--limit)
      [[ "$#" -ge 2 ]] || die "Missing inventory host alias."
      limit_host="$2"
      shift 2
      ;;
    --dry-run)
      dry_run=true
      shift
      ;;
    --snapshot-dir)
      [[ "$#" -ge 2 ]] || die "Missing local snapshot directory."
      local_snapshot_root="$2"
      shift 2
      ;;
    --no-fetch-snapshot)
      fetch_snapshot=false
      shift
      ;;
    --stage-legacy)
      [[ "$#" -ge 2 ]] || die "Missing prepared legacy config directory."
      prepared_config_dir="$2"
      remote_action="stage-legacy"
      shift 2
      ;;
    --sync-source)
      [[ "$#" -ge 2 ]] || die "Missing local project root."
      source_root="$2"
      remote_action="sync-source"
      shift 2
      ;;
    --apply)
      apply_after_sync=true
      shift
      ;;
    --restore-full)
      [[ "$#" -ge 2 ]] || die "Missing encrypted full-backup file."
      restore_archive="$2"
      remote_action="restore-full"
      shift 2
      ;;
    --restore-mode)
      [[ "$#" -ge 2 ]] || die "Missing restore mode."
      restore_mode="$2"
      shift 2
      ;;
    --source-root)
      [[ "$#" -ge 2 ]] || die "Missing local project root."
      source_root="$2"
      shift 2
      ;;
    --action)
      [[ "$#" -ge 2 ]] || die "Missing remote action."
      remote_action="$2"
      shift 2
      ;;
    --language)
      [[ "$#" -ge 2 ]] || die "Missing language code."
      language="${2,,}"
      case "${language}" in
        en|ru) ;;
        *) die "Language must be en or ru." ;;
      esac
      language_explicit=true
      shift 2
      ;;
    --test-mode)
      remote_action="install-test"
      shift
      ;;
    --skip-dns-check)
      skip_dns_check=true
      shift
      ;;
    --certificate-source)
      [[ "$#" -ge 2 ]] || die "Missing certificate source."
      certificate_source="${2,,}"
      case "${certificate_source}" in
        letsencrypt|internal) ;;
        *) die "Certificate source must be letsencrypt or internal." ;;
      esac
      shift 2
      ;;
    --source-channel|--source)
      [[ "$#" -ge 2 ]] || die "Missing source channel."
      source_channel="${2,,}"
      case "${source_channel}" in
        github|local) ;;
        *) die "Source channel must be github or local." ;;
      esac
      shift 2
      ;;
    --image-channel|--image)
      [[ "$#" -ge 2 ]] || die "Missing image channel."
      image_channel="${2,,}"
      case "${image_channel}" in
        latest|alpha) ;;
        *) die "Image channel must be latest or alpha." ;;
      esac
      shift 2
      ;;
    --new-domain)
      [[ "$#" -ge 2 ]] || die "Missing new root domain."
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
    -*)
      die "Unknown option: $1"
      ;;
    *)
      [[ -z "${positional_target}" ]] ||
        die "Only one positional SSH target may be specified."
      positional_target="$1"
      shift
      ;;
  esac
done

case "${remote_action}" in
  menu|inspect|status|check-config|plan|check-updates|smart-update|update|apply-current|update-ui|update-containers|reboot|configure|language|migrate-domain|promote-production|repair|install|install-test|install-reset|install-test-reset|test-info|backup-full|snapshot-legacy|migration-plan|stage-legacy|sync-source|restore-full)
    ;;
  *)
    die "Unknown remote action: ${remote_action}"
    ;;
esac

case "${restore_mode}" in
  auto|fresh|overlay)
    ;;
  *)
    die "Restore mode must be auto, fresh or overlay."
    ;;
esac

if [[ "${remote_action}" == "sync-source" ]]; then
  source_channel="local"
elif [[ -n "${source_root}" && -z "${source_channel}" &&
        ( "${remote_action}" == "install" || "${remote_action}" == "install-test" ) ]]; then
  source_channel="local"
fi
if [[ "${apply_after_sync}" == true && "${remote_action}" != "sync-source" ]]; then
  die "--apply is currently supported only with --sync-source."
fi

if [[ -n "${inventory_file}" ]]; then
  [[ -z "${positional_target}" ]] ||
    die "Do not combine --inventory with a positional user@host target."

  inventory_alias=""
  inventory_group=""
  inventory_line=""
  inventory_ansible_host=""
  inventory_ansible_user=""
  inventory_ansible_port=""
  inventory_ansible_ssh_port=""
  inventory_ansible_ssh_private_key_file=""
  load_inventory "${inventory_file}" "${limit_host}"

  [[ -n "${ssh_host}" ]] ||
    ssh_host="${inventory_ansible_host:-${inventory_alias}}"
  [[ -n "${ssh_user}" ]] ||
    ssh_user="${inventory_ansible_user}"
  [[ -n "${ssh_port}" ]] ||
    ssh_port="${inventory_ansible_port:-${inventory_ansible_ssh_port}}"
  if [[ "${identity_from_cli}" == false && "${ask_pass}" == false ]]; then
    identity_file="${inventory_ansible_ssh_private_key_file}"
  fi
elif [[ -n "${limit_host}" ]]; then
  die "--limit requires --inventory."
fi

if [[ -n "${positional_target}" ]]; then
  if [[ "${positional_target}" == *@* ]]; then
    [[ -n "${ssh_user}" ]] ||
      ssh_user="${positional_target%@*}"
    [[ -n "${ssh_host}" ]] ||
      ssh_host="${positional_target##*@}"
  else
    [[ -n "${ssh_host}" ]] || ssh_host="${positional_target}"
  fi
fi

[[ -n "${ssh_host}" ]] || {
  usage
  exit 2
}
ssh_port="${ssh_port:-22}"
[[ "${ssh_port}" =~ ^[0-9]+$ ]] || die "SSH port must be numeric."
((ssh_port >= 1 && ssh_port <= 65535)) || die "SSH port is out of range."

if [[ "${identity_file}" == "~/"* ]]; then
  identity_file="${HOME}/${identity_file#~/}"
fi
if [[ -n "${identity_file}" && ! -r "${identity_file}" ]]; then
  die "Cannot read identity file: ${identity_file}"
fi
if [[ "${ask_pass}" == true && -n "${identity_file}" ]]; then
  die "Use either --ask-pass or --identity, not both."
fi
if [[ -n "${new_domain}" &&
      ! "${new_domain}" =~ ^[A-Za-z0-9.-]+$ ]]; then
  die "New root domain contains unsafe characters."
fi

if [[ "${remote_action}" == "stage-legacy" ||
      "${remote_action}" == "sync-source" ||
      "${remote_action}" == "language" ||
      "${remote_action}" == "promote-production" ||
      "${remote_action}" == "restore-full" ]]; then
  source_root="${source_root:-${script_dir:-${PWD}}}"
  [[ -d "${source_root}/ansible/roles" &&
     -f "${source_root}/installer/easy_ha_proxy.py" &&
     -f "${source_root}/install-local.sh" ]] ||
    die "easy-ha-proxy source tree not found under: ${source_root}"
fi
if [[ "${source_channel}" == "local" &&
      ( "${remote_action}" == "install" || "${remote_action}" == "install-test" ) &&
      -z "${source_root}" ]]; then
  source_root="${script_dir:-${PWD}}"
fi
if [[ -n "${source_root}" ]]; then
  [[ -d "${source_root}/ansible/roles" &&
     -f "${source_root}/installer/easy_ha_proxy.py" &&
     -f "${source_root}/install-local.sh" ]] ||
    die "easy-ha-proxy source tree not found under: ${source_root}"
fi
stage_install_source=false
if [[ "${source_channel}" == "local" && -n "${source_root}" &&
      ( "${remote_action}" == "install" || "${remote_action}" == "install-test" ) ]]; then
  stage_install_source=true
fi
if [[ "${remote_action}" == "restore-full" ]]; then
  [[ -n "${restore_archive}" && -r "${restore_archive}" ]] ||
    die "Encrypted full backup not found: ${restore_archive}"
fi
if [[ "${remote_action}" == "stage-legacy" ]]; then
  [[ -n "${prepared_config_dir}" && -d "${prepared_config_dir}" ]] ||
    die "Prepared legacy config directory not found: ${prepared_config_dir}"
  for required in \
    vars.yml \
    authelia.yml \
    authelia_users_initial.yml \
    websites.yml \
    tcp.yml \
    secrets.yml \
    metadata.yml \
    inventory.ini; do
    [[ -f "${prepared_config_dir}/${required}" ]] ||
      die "Prepared legacy config is incomplete: ${required}"
  done
fi

target="${ssh_host}"
if [[ -n "${ssh_user}" ]]; then
  target="${ssh_user}@${ssh_host}"
fi

if [[ "${dry_run}" == true ]]; then
  printf '[%s] Target: %s\n' "${product}" "${target}"
  printf '[%s] SSH port: %s\n' "${product}" "${ssh_port}"
  printf '[%s] Action: %s\n' "${product}" "${remote_action}"
  printf '[%s] Source channel: %s\n' "${product}" "${source_channel:-interactive/default}"
  printf '[%s] Image channel: %s\n' "${product}" "${image_channel:-interactive/current}"
  if [[ "${remote_action}" == "migrate-domain" ]]; then
    printf '[%s] New root domain: %s\n' \
      "${product}" "${new_domain:-interactive prompt}"
    printf '[%s] Domain migration mode: %s\n' \
      "${product}" "$([[ "${plan_only}" == true ]] && printf plan-only || printf plan-and-confirm)"
  fi
  if [[ "${remote_action}" == "stage-legacy" ]]; then
    printf '[%s] Prepared config: %s\n' "${product}" "${prepared_config_dir}"
    printf '[%s] Source root: %s\n' "${product}" "${source_root}"
  elif [[ "${remote_action}" == "sync-source" ]]; then
    printf '[%s] Source root: %s\n' "${product}" "${source_root}"
    printf '[%s] Apply after sync: %s\n' \
      "${product}" "$([[ "${apply_after_sync}" == true ]] && printf yes || printf no)"
  elif [[ "${remote_action}" == "restore-full" ]]; then
    printf '[%s] Full backup: %s\n' "${product}" "${restore_archive}"
    printf '[%s] Restore mode: %s\n' "${product}" "${restore_mode}"
    printf '[%s] Recovery source: %s\n' "${product}" "${source_root}"
  fi
  if [[ "${fetch_snapshot}" == true ]]; then
    printf '[%s] Snapshot download root: %s\n' \
      "${product}" "${local_snapshot_root}"
  fi
  if [[ "${ask_pass}" == true ]]; then
    printf '[%s] Authentication: SSH password prompt\n' "${product}"
  elif [[ -n "${identity_file}" ]]; then
    printf '[%s] Authentication: key %s\n' "${product}" "${identity_file}"
  else
    printf '[%s] Authentication: SSH defaults (password prompt if needed)\n' \
      "${product}"
  fi
  exit 0
fi

for command in ssh scp; do
  command -v "${command}" >/dev/null 2>&1 ||
    die "Required command not found: ${command}"
done
if [[ ! -r "${local_installer_file}" || ! -r "${helper_file}" ]]; then
  command -v curl >/dev/null 2>&1 ||
    die "curl is required when local helper files are unavailable."
fi

temporary_installer="$(mktemp -t easy-ha-proxy-install-local.XXXXXX.sh)"
temporary_helper="$(mktemp -t easy-ha-proxy-helper.XXXXXX.sh)"
remote_output_file="$(mktemp -t easy-ha-proxy-remote-output.XXXXXX.log)"
temporary_source_archive=""
temporary_config_archive=""
activate_current_source=false
control_path="/tmp/easy-ha-proxy-ssh.$$.sock"
remote_installer="/tmp/easy-ha-proxy-install-local.sh"
remote_helper="/tmp/easy-ha-proxy-helper.sh"
remote_source_archive="/tmp/easy-ha-proxy-source.$$.tgz"
remote_config_archive="/tmp/easy-ha-proxy-config.$$.tgz"
remote_restore_archive="/tmp/easy-ha-proxy-full-restore.$$.tar.gz.enc"
remote_recovery_root="/tmp/easy-ha-proxy-recovery.$$"
staged_remote_export=""
ssh_options=()
scp_options=()
reboot_probe_options=()
reboot_monitor_available=false
reboot_monitor_boot_id=""

remote_cleanup_as_root() {
  local command_text="$1"
  ssh "${ssh_options[@]}" "${target}" \
    "if [ \"\$(id -u)\" -eq 0 ]; then ${command_text}; elif command -v sudo >/dev/null 2>&1; then sudo sh -c '${command_text}'; else ${command_text}; fi" \
    </dev/null >/dev/null 2>&1 || true
}

prepare_remote_reboot_monitoring() {
  reboot_probe_options=(
    -p "${ssh_port}"
    -o "BatchMode=yes"
    -o "ConnectTimeout=5"
    -o "ConnectionAttempts=1"
    -o "ControlMaster=no"
    -o "ControlPath=none"
  )
  [[ -n "${identity_file}" ]] && reboot_probe_options+=(-i "${identity_file}")

  [[ "${ask_pass}" != true ]] || return 0
  if reboot_monitor_boot_id="$(
    ssh "${reboot_probe_options[@]}" "${target}" \
      "cat /proc/sys/kernel/random/boot_id" \
      </dev/null 2>/dev/null
  )"; then
    reboot_monitor_boot_id="${reboot_monitor_boot_id//$'\r'/}"
    reboot_monitor_boot_id="${reboot_monitor_boot_id//$'\n'/}"
    if [[ "${reboot_monitor_boot_id}" =~ ^[0-9a-fA-F-]{36}$ ]]; then
      reboot_monitor_available=true
      return 0
    fi
  fi
  reboot_monitor_boot_id=""
}

wait_for_remote_reboot() {
  local went_down=false
  local deadline=0
  local current_boot_id=""

  if [[ "${reboot_monitor_available}" != true ||
        -z "${reboot_monitor_boot_id}" ]]; then
    if [[ "${language}" == "ru" ]]; then
      printf '[%s] Перезагрузка запланирована, но неинтерактивные SSH-учётные данные недоступны. Подключитесь или запустите помощник снова после загрузки сервера.\n' "${product}"
    else
      printf '[%s] Reboot scheduled, but non-interactive SSH credentials are unavailable. Reconnect or run the assistant again after the server starts.\n' "${product}"
    fi
    return 0
  fi

  ssh -S "${control_path}" -O exit "${target}" </dev/null >/dev/null 2>&1 || true
  if [[ "${language}" == "ru" ]]; then
    printf '[%s] Ожидаю перезагрузку и смену boot_id сервера...\n' "${product}"
  else
    printf '[%s] Waiting for the server to reboot and report a new boot_id...\n' "${product}"
  fi
  deadline=$((SECONDS + 420))
  while ((SECONDS < deadline)); do
    current_boot_id=""
    if current_boot_id="$(
      ssh "${reboot_probe_options[@]}" "${target}" \
        "cat /proc/sys/kernel/random/boot_id" \
        </dev/null 2>/dev/null
    )"; then
      current_boot_id="${current_boot_id//$'\r'/}"
      current_boot_id="${current_boot_id//$'\n'/}"
      if [[ "${current_boot_id}" =~ ^[0-9a-fA-F-]{36}$ &&
            "${current_boot_id}" != "${reboot_monitor_boot_id}" ]]; then
        if [[ "${language}" == "ru" ]]; then
          printf '[%s] Сервер снова доступен по SSH с новым boot_id. Перезагрузка подтверждена.\n' "${product}"
        else
          printf '[%s] The server is reachable over SSH with a new boot_id. Reboot confirmed.\n' "${product}"
        fi
        return 0
      fi
    elif [[ "${went_down}" != true ]]; then
      went_down=true
      if [[ "${language}" == "ru" ]]; then
        printf '[%s] SSH отключился; ожидаю загрузки сервера...\n' "${product}"
      else
        printf '[%s] SSH went down; waiting for the server to start...\n' "${product}"
      fi
    fi
    sleep 3
  done

  printf '[%s] WARNING: reboot was scheduled, but a new server boot_id was not observed within 420 seconds.\n' "${product}" >&2
  return 0
}

cleanup() {
  if [[ "${remote_action}" == "stage-legacy" ||
        "${remote_action}" == "sync-source" ||
        "${remote_action}" == "language" ||
        "${remote_action}" == "promote-production" ||
        "${remote_action}" == "restore-full" ||
        "${activate_current_source}" == true ||
        "${stage_install_source}" == true ]]; then
    remote_cleanup_as_root \
      "rm -rf ${remote_recovery_root}; rm -f ${remote_source_archive} ${remote_config_archive} ${remote_restore_archive} ${remote_restore_archive}.sha256 ${remote_installer} ${remote_helper}"
  fi
  if [[ -n "${staged_remote_export}" ]]; then
    remote_cleanup_as_root \
      "rm -f ${staged_remote_export} ${staged_remote_export}.sha256"
  fi
  ssh -S "${control_path}" -O exit "${target}" </dev/null >/dev/null 2>&1 || true
  rm -f \
    "${temporary_installer}" \
    "${temporary_helper}" \
    "${temporary_source_archive}" \
    "${temporary_config_archive}" \
    "${remote_output_file}" \
    "${control_path}"
}
trap cleanup EXIT

if [[ -r "${local_installer_file}" ]]; then
  printf '[%s] Using local installer: %s\n' "${product}" "${local_installer_file}"
  cp -- "${local_installer_file}" "${temporary_installer}"
else
  printf '[%s] Downloading local installer\n' "${product}"
  curl -fsSL "${local_installer_url}" -o "${temporary_installer}"
fi
chmod 0700 "${temporary_installer}"
if [[ -r "${helper_file}" ]]; then
  printf '[%s] Using local maintenance helper: %s\n' "${product}" "${helper_file}"
  cp -- "${helper_file}" "${temporary_helper}"
else
  printf '[%s] Downloading maintenance helper\n' "${product}"
  curl -fsSL "${helper_url}" -o "${temporary_helper}"
fi
chmod 0700 "${temporary_helper}"

common_options=(
  -o "ControlMaster=auto"
  -o "ControlPersist=60"
  -o "ControlPath=${control_path}"
)
ssh_options=(-p "${ssh_port}" "${common_options[@]}")
scp_options=(-P "${ssh_port}" "${common_options[@]}")
if [[ -n "${identity_file}" ]]; then
  ssh_options+=(-i "${identity_file}")
  scp_options+=(-i "${identity_file}")
fi
if [[ "${ask_pass}" == true ]]; then
  password_options=(
    -o "PubkeyAuthentication=no"
    -o "PreferredAuthentications=keyboard-interactive,password"
  )
  ssh_options+=("${password_options[@]}")
  scp_options+=("${password_options[@]}")
fi

controller_source_root="${source_root:-${script_dir}}"
case "${remote_action}" in
  language|promote-production)
    activate_current_source=true
    ;;
  menu|repair|install-reset|install-test-reset)
    if [[ "${source_channel}" == "local" ]]; then
      activate_current_source=true
    elif [[ -n "${controller_source_root}" &&
            -f "${controller_source_root}/installer/easy_ha_proxy.py" ]]; then
      local_installer_fingerprint="$(
        installer_fingerprint "${controller_source_root}" 2>/dev/null || true
      )"
      remote_installer_fingerprint="$(
        ssh "${ssh_options[@]}" "${target}" \
          "if test -f /opt/easy-ha-proxy/source/installer/easy_ha_proxy.py && \
              test -f /opt/easy-ha-proxy/source/installer/easy-ha-proxy && \
              test -f /opt/easy-ha-proxy/source/installer/requirements.txt && \
              test -f /opt/easy-ha-proxy/source/install-local.sh; then \
             cd /opt/easy-ha-proxy/source && \
             sha256sum installer/easy_ha_proxy.py installer/easy-ha-proxy \
               installer/requirements.txt install-local.sh | \
             sha256sum | awk '{ print \$1 }'; fi" \
          </dev/null 2>/dev/null | tr -d '\r' | tail -n 1
      )"
      if [[ -n "${local_installer_fingerprint}" &&
            -n "${remote_installer_fingerprint}" &&
            "${local_installer_fingerprint}" != "${remote_installer_fingerprint}" ]]; then
        printf '\n[%s] WARNING: the installer source on the server differs from this local project.\n' \
          "${product}" >&2
        printf '[%s] Local:  %s\n' "${product}" "${local_installer_fingerprint:0:12}" >&2
        printf '[%s] Server: %s\n' "${product}" "${remote_installer_fingerprint:0:12}" >&2
        if [[ "${input_fd}" -ne 0 || -t 0 ]]; then
          update_answer=""
          if [[ "${language}" == "ru" ]]; then
            read -r -u "${input_fd}" \
              -p "Загрузить текущие локальные исходники перед продолжением? [Y/n]: " \
              update_answer || true
          else
            read -r -u "${input_fd}" \
              -p "Upload the current local source before continuing? [Y/n]: " \
              update_answer || true
          fi
          case "${update_answer,,}" in
            ""|y|yes|д|да) activate_current_source=true ;;
            *)
              printf '[%s] Continuing with the installer source already present on the server.\n' \
                "${product}"
              ;;
          esac
        else
          printf '[%s] Re-run interactively or use --source local to synchronize it.\n' \
            "${product}" >&2
        fi
      fi
    fi
    ;;
esac

if [[ "${activate_current_source}" == true ]]; then
  source_root="${controller_source_root}"
  [[ -n "${source_root}" &&
     -d "${source_root}/ansible/roles" &&
     -f "${source_root}/installer/easy_ha_proxy.py" &&
     -f "${source_root}/install-local.sh" ]] ||
    die "The current local source tree is unavailable; use --source-root DIR."
  source_channel="local"
fi

if [[ "${stage_install_source}" == true ]]; then
  temporary_source_archive="$(mktemp -t easy-ha-proxy-source.XXXXXX.tgz)"
  build_source_archive "${source_root}" "${temporary_source_archive}"
  chmod 0600 "${temporary_source_archive}"
  printf '[%s] Uploading the exact local source for this clean installation\n' \
    "${product}"
  scp "${scp_options[@]}" \
    "${temporary_source_archive}" \
    "${target}:${remote_source_archive}" <&"${input_fd}"

  stage_command="set -eu; umask 077; "
  stage_command+="test ! -e /opt/easy-ha-proxy/source; "
  stage_command+="test ! -e /etc/easy-ha-proxy; "
  stage_command+="install -d -m 0755 /opt/easy-ha-proxy/source; "
  stage_command+="tar -xzf ${remote_source_archive} -C /opt/easy-ha-proxy/source; "
  stage_command+="test -f /opt/easy-ha-proxy/source/installer/easy_ha_proxy.py; "
  stage_command+="test -f /opt/easy-ha-proxy/source/ansible/easy-ha-proxy.yml; "
  stage_command+="chown -R root:root /opt/easy-ha-proxy/source"
  remote_command="if [ \"\$(id -u)\" -eq 0 ]; then sh -c '${stage_command}'; "
  remote_command+="elif command -v sudo >/dev/null 2>&1; then sudo sh -c '${stage_command}'; "
  remote_command+="else echo 'easy-ha-proxy: root or sudo is required' >&2; exit 1; fi"
  ssh -tt "${ssh_options[@]}" "${target}" "${remote_command}" <&"${input_fd}"
  ssh "${ssh_options[@]}" "${target}" \
    "rm -f ${remote_source_archive}" </dev/null || true
fi

if [[ "${remote_action}" == "stage-legacy" ]]; then
  printf '\n[%s] Legacy adoption staging\n' "${product}"
  printf '  target:          %s\n' "${target}"
  printf '  prepared config: %s\n' "${prepared_config_dir}"
  printf '  source:          %s\n' "${source_root}"
  cat <<'EOF'

This creates /opt/easy-ha-proxy and /etc/easy-ha-proxy, installs the isolated
control-plane dependencies and CLI, but does not run the playbook, pull
application images, restart services or alter the live HAProxy configuration.
The operation aborts if either destination already exists.
EOF
  if [[ "${input_fd}" -eq 0 && ! -t 0 ]]; then
    die "Legacy staging requires an interactive terminal."
  fi
  confirmation=""
  if [[ "${language}" == "ru" ]]; then
    read -r -u "${input_fd}" -p "Введите STAGE для продолжения: " confirmation || true
  else
    read -r -u "${input_fd}" -p "Enter STAGE to continue: " confirmation || true
  fi
  [[ "${confirmation}" == "STAGE" ]] || die "Legacy staging cancelled."

  temporary_source_archive="$(mktemp -t easy-ha-proxy-source.XXXXXX.tgz)"
  temporary_config_archive="$(mktemp -t easy-ha-proxy-config.XXXXXX.tgz)"

  build_source_archive "${source_root}" "${temporary_source_archive}"
  tar -C "${prepared_config_dir}" -czf "${temporary_config_archive}" \
    vars.yml authelia.yml authelia_users_initial.yml websites.yml tcp.yml \
    secrets.yml metadata.yml inventory.ini
  chmod 0600 "${temporary_source_archive}" "${temporary_config_archive}"

  printf '[%s] Uploading protected control-plane bundle to %s\n' \
    "${product}" "${target}"
  scp "${scp_options[@]}" \
    "${temporary_installer}" \
    "${target}:${remote_installer}" <&"${input_fd}"
  scp "${scp_options[@]}" \
    "${temporary_source_archive}" \
    "${target}:${remote_source_archive}" <&"${input_fd}"
  scp "${scp_options[@]}" \
    "${temporary_config_archive}" \
    "${target}:${remote_config_archive}" <&"${input_fd}"

  stage_command="set -eu; umask 077; "
  stage_command+="if [ -e /opt/easy-ha-proxy/source ] || [ -e /etc/easy-ha-proxy ]; then "
  stage_command+="echo \"easy-ha-proxy: destination already exists; refusing to overwrite\" >&2; exit 1; fi; "
  stage_command+="install -d -m 0755 /opt/easy-ha-proxy; "
  stage_command+="install -d -m 0755 /opt/easy-ha-proxy/source; "
  stage_command+="install -d -m 0700 /etc/easy-ha-proxy; "
  stage_command+="tar -xzf ${remote_source_archive} -C /opt/easy-ha-proxy/source; "
  stage_command+="tar -xzf ${remote_config_archive} -C /etc/easy-ha-proxy; "
  stage_command+="chown -R root:root /opt/easy-ha-proxy/source /etc/easy-ha-proxy; "
  stage_command+="find /etc/easy-ha-proxy -type d -exec chmod 0700 {} +; "
  stage_command+="find /etc/easy-ha-proxy -type f -exec chmod 0600 {} +; "
  stage_command+="chmod 0700 ${remote_installer}; "
  stage_command+="EASY_HA_PROXY_USE_EXISTING_SOURCE=true bash ${remote_installer} --prepare-only"
  remote_command="if [ \"\$(id -u)\" -eq 0 ]; then sh -c '${stage_command}'; "
  remote_command+="elif command -v sudo >/dev/null 2>&1; then sudo sh -c '${stage_command}'; "
  remote_command+="else echo 'easy-ha-proxy: root or sudo is required' >&2; exit 1; fi"

  printf '[%s] Staging control plane on %s\n' "${product}" "${target}"
  ssh -tt "${ssh_options[@]}" "${target}" "${remote_command}" <&"${input_fd}"
  ssh "${ssh_options[@]}" "${target}" \
    "rm -f ${remote_source_archive} ${remote_config_archive} ${remote_installer}" \
    </dev/null || true
  printf '\n[%s] Legacy control plane staged successfully.\n' "${product}"
  printf '[%s] No playbook was applied and application services were not changed.\n' \
    "${product}"
  printf '[%s] Next read-only check: sudo easy-ha-proxy plan\n' "${product}"
  exit 0
fi

if [[ "${remote_action}" == "sync-source" ]]; then
  printf '\n[%s] Managed source synchronization\n' "${product}"
  printf '  target: %s\n' "${target}"
  printf '  source: %s\n' "${source_root}"
  cat <<'EOF'

The current managed source is backed up and replaced atomically. Configuration,
Docker images and application services are not changed unless --apply is used.
EOF
  if [[ "${input_fd}" -eq 0 && ! -t 0 ]]; then
    die "Source synchronization requires an interactive terminal."
  fi
  confirmation=""
  if [[ "${language}" == "ru" ]]; then
    read -r -u "${input_fd}" -p "Введите SYNC для продолжения: " confirmation || true
  else
    read -r -u "${input_fd}" -p "Enter SYNC to continue: " confirmation || true
  fi
  [[ "${confirmation}" == "SYNC" ]] || die "Source synchronization cancelled."

  temporary_source_archive="$(mktemp -t easy-ha-proxy-source.XXXXXX.tgz)"
  build_source_archive "${source_root}" "${temporary_source_archive}"
  chmod 0600 "${temporary_source_archive}"
  printf '[%s] Uploading protected source bundle to %s\n' "${product}" "${target}"
  scp "${scp_options[@]}" \
    "${temporary_source_archive}" \
    "${target}:${remote_source_archive}" <&"${input_fd}"

  next_source="/opt/easy-ha-proxy/.source.next.$$"
  backup_source="/opt/easy-ha-proxy/source.before-sync.$(date -u +%Y%m%dT%H%M%SZ)"
  sync_command="set -eu; umask 077; "
  sync_command+="test -d /opt/easy-ha-proxy/source; "
  sync_command+="test ! -e ${next_source}; test ! -e ${backup_source}; "
  sync_command+="install -d -m 0755 ${next_source}; "
  sync_command+="tar -xzf ${remote_source_archive} -C ${next_source}; "
  sync_command+="test -f ${next_source}/installer/easy_ha_proxy.py; "
  sync_command+="test -f ${next_source}/ansible/easy-ha-proxy.yml; "
  sync_command+="chown -R root:root ${next_source}; "
  sync_command+="chmod 0755 ${next_source}/install.sh ${next_source}/install-local.sh "
  sync_command+="${next_source}/install-remote.sh ${next_source}/easy-ha-proxy-helper.sh "
  sync_command+="${next_source}/installer/easy-ha-proxy; "
  sync_command+="mv /opt/easy-ha-proxy/source ${backup_source}; "
  sync_command+="if mv ${next_source} /opt/easy-ha-proxy/source; then :; "
  sync_command+="else mv ${backup_source} /opt/easy-ha-proxy/source; exit 1; fi"
  remote_command="if [ \"\$(id -u)\" -eq 0 ]; then sh -c '${sync_command}'; "
  remote_command+="elif command -v sudo >/dev/null 2>&1; then sudo sh -c '${sync_command}'; "
  remote_command+="else echo 'easy-ha-proxy: root or sudo is required' >&2; exit 1; fi"

  printf '[%s] Replacing managed source on %s\n' "${product}" "${target}"
  ssh -tt "${ssh_options[@]}" "${target}" "${remote_command}" <&"${input_fd}"
  ssh "${ssh_options[@]}" "${target}" \
    "rm -f ${remote_source_archive}" </dev/null || true
  printf '\n[%s] Managed source synchronized.\n' "${product}"
  printf '[%s] Backup on server: %s\n' "${product}" "${backup_source}"
  if [[ "${apply_after_sync}" == true ]]; then
    apply_command="/usr/local/bin/easy-ha-proxy update --source-channel local"
    if [[ -n "${image_channel}" ]]; then
      apply_command+=" --image-channel ${image_channel}"
    fi
    remote_command="if [ \"\$(id -u)\" -eq 0 ]; then ${apply_command}; "
    remote_command+="elif command -v sudo >/dev/null 2>&1; then sudo ${apply_command}; "
    remote_command+="else echo 'easy-ha-proxy: root or sudo is required' >&2; exit 1; fi"
    printf '[%s] Applying synchronized source (image channel: %s)\n' \
      "${product}" "${image_channel:-current}"
    ssh -tt "${ssh_options[@]}" "${target}" "${remote_command}" <&"${input_fd}"
  else
    printf '[%s] No playbook was applied and application services were not changed.\n' \
      "${product}"
  fi
  exit 0
fi

if [[ "${remote_action}" == "restore-full" ]]; then
  printf '\n[%s] Full disaster-recovery restore\n' "${product}"
  printf '  target:  %s\n' "${target}"
  printf '  archive: %s\n' "${restore_archive}"
  printf '  mode:    %s\n' "${restore_mode}"
  cat <<'EOF'

The encrypted archive will be verified and restored on the target. Existing
managed files are preserved in a protected pre-restore rollback archive.
The restore asks separately whether archived SSH keys should be applied.
After extraction, the installer reconciles packages, services and containers.
EOF
  if [[ "${input_fd}" -eq 0 && ! -t 0 ]]; then
    die "Full restore requires an interactive terminal."
  fi
  confirmation=""
  if [[ "${language}" == "ru" ]]; then
    read -r -u "${input_fd}" -p "Введите UPLOAD для передачи backup на целевой сервер: " confirmation || true
  else
    read -r -u "${input_fd}" -p "Enter UPLOAD to transfer the backup to the target server: " confirmation || true
  fi
  [[ "${confirmation}" == "UPLOAD" ]] || die "Full restore cancelled."

  if [[ -r "${restore_archive}.sha256" ]]; then
    expected_hash="$(awk 'NR == 1 { print $1 }' "${restore_archive}.sha256")"
    actual_hash="$(sha256sum "${restore_archive}" | awk '{ print $1 }')"
    [[ -n "${expected_hash}" && "${expected_hash}" == "${actual_hash}" ]] ||
      die "Local encrypted backup checksum verification failed."
  else
    printf '[%s] WARNING: checksum sidecar not found; encrypted and internal payload checks will still run.\n' \
      "${product}" >&2
  fi

  temporary_source_archive="$(mktemp -t easy-ha-proxy-source.XXXXXX.tgz)"
  build_source_archive "${source_root}" "${temporary_source_archive}"
  chmod 0600 "${temporary_source_archive}"
  scp "${scp_options[@]}" \
    "${temporary_installer}" "${target}:${remote_installer}" <&"${input_fd}"
  scp "${scp_options[@]}" \
    "${temporary_source_archive}" "${target}:${remote_source_archive}" <&"${input_fd}"
  scp "${scp_options[@]}" \
    "${restore_archive}" "${target}:${remote_restore_archive}" <&"${input_fd}"
  if [[ -r "${restore_archive}.sha256" ]]; then
    scp "${scp_options[@]}" \
      "${restore_archive}.sha256" \
      "${target}:${remote_restore_archive}.sha256" <&"${input_fd}"
  fi

  recovery_command="set -eu; umask 077; "
  recovery_command+="test ! -e ${remote_recovery_root}; "
  recovery_command+="install -d -m 0700 ${remote_recovery_root}; "
  recovery_command+="tar -xzf ${remote_source_archive} -C ${remote_recovery_root}; "
  recovery_command+="test -f ${remote_recovery_root}/installer/full_backup.py; "
  recovery_command+="if test -x /opt/easy-ha-proxy/venv/bin/python && test -f /etc/easy-ha-proxy/metadata.yml; then "
  recovery_command+="recovery_python=/opt/easy-ha-proxy/venv/bin/python; "
  recovery_command+="recovery_source=${remote_recovery_root}; "
  recovery_command+="else "
  recovery_command+="install -d -m 0755 /opt/easy-ha-proxy; "
  recovery_command+="if test -e /opt/easy-ha-proxy/source; then "
  recovery_command+="mv /opt/easy-ha-proxy/source /opt/easy-ha-proxy/source.before-restore.$(date -u +%Y%m%dT%H%M%SZ); fi; "
  recovery_command+="cp -a ${remote_recovery_root} /opt/easy-ha-proxy/source; "
  recovery_command+="chmod 0755 /opt/easy-ha-proxy/source; "
  recovery_command+="chmod 0700 ${remote_installer}; "
  recovery_command+="EASY_HA_PROXY_USE_EXISTING_SOURCE=true bash ${remote_installer} --prepare-only; "
  recovery_command+="recovery_python=/opt/easy-ha-proxy/venv/bin/python; "
  recovery_command+="recovery_source=${remote_recovery_root}; "
  recovery_command+="fi; "
  recovery_command+="EASY_HA_PROXY_SOURCE_DIR=\${recovery_source} "
  recovery_command+="\${recovery_python} \${recovery_source}/installer/easy_ha_proxy.py "
  recovery_command+="restore-full ${remote_restore_archive} --mode ${restore_mode} --apply"
  remote_command="if [ \"\$(id -u)\" -eq 0 ]; then sh -c '${recovery_command}'; "
  remote_command+="elif command -v sudo >/dev/null 2>&1; then sudo sh -c '${recovery_command}'; "
  remote_command+="else echo 'easy-ha-proxy: root or sudo is required' >&2; exit 1; fi"

  printf '[%s] Starting protected restore on %s\n' "${product}" "${target}"
  ssh -tt "${ssh_options[@]}" "${target}" "${remote_command}" <&"${input_fd}"
  remote_cleanup_as_root \
    "rm -rf ${remote_recovery_root}; rm -f ${remote_source_archive} ${remote_restore_archive} ${remote_restore_archive}.sha256 ${remote_installer}"
  printf '\n[%s] Full restore completed successfully.\n' "${product}"
  exit 0
fi

if [[ "${activate_current_source}" == true ]]; then
  temporary_source_archive="$(mktemp -t easy-ha-proxy-source.XXXXXX.tgz)"
  build_source_archive "${source_root}" "${temporary_source_archive}"
  chmod 0600 "${temporary_source_archive}"

  printf '[%s] Uploading the current source before %s to %s\n' \
    "${product}" "${remote_action}" "${target}"
  scp "${scp_options[@]}" \
    "${temporary_source_archive}" \
    "${target}:${remote_source_archive}" <&"${input_fd}"

  next_source="/opt/easy-ha-proxy/.source.next.$$"
  backup_source="/opt/easy-ha-proxy/source.before-${remote_action}.$(date -u +%Y%m%dT%H%M%SZ).$$"
  sync_command="set -eu; umask 077; "
  sync_command+="test -d /opt/easy-ha-proxy/source; "
  sync_command+="test ! -e ${next_source}; test ! -e ${backup_source}; "
  sync_command+="install -d -m 0755 ${next_source}; "
  sync_command+="tar -xzf ${remote_source_archive} -C ${next_source}; "
  sync_command+="test -f ${next_source}/installer/easy_ha_proxy.py; "
  sync_command+="test -f ${next_source}/ansible/easy-ha-proxy.yml; "
  sync_command+="chown -R root:root ${next_source}; "
  sync_command+="chmod 0755 ${next_source}/install.sh ${next_source}/install-local.sh "
  sync_command+="${next_source}/install-remote.sh ${next_source}/easy-ha-proxy-helper.sh "
  sync_command+="${next_source}/installer/easy-ha-proxy; "
  sync_command+="mv /opt/easy-ha-proxy/source ${backup_source}; "
  sync_command+="if mv ${next_source} /opt/easy-ha-proxy/source; then :; "
  sync_command+="else mv ${backup_source} /opt/easy-ha-proxy/source; exit 1; fi"
  remote_command="if [ \"\$(id -u)\" -eq 0 ]; then sh -c '${sync_command}'; "
  remote_command+="elif command -v sudo >/dev/null 2>&1; then sudo sh -c '${sync_command}'; "
  remote_command+="else echo 'easy-ha-proxy: root or sudo is required' >&2; exit 1; fi"

  printf '[%s] Activating the current source before %s\n' \
    "${product}" "${remote_action}"
  ssh -tt "${ssh_options[@]}" "${target}" "${remote_command}" <&"${input_fd}"
  ssh "${ssh_options[@]}" "${target}" \
    "rm -f ${remote_source_archive}" </dev/null || true
  printf '[%s] Previous managed source backup: %s\n' \
    "${product}" "${backup_source}"
fi

printf '[%s] Uploading installer to %s\n' "${product}" "${target}"
scp "${scp_options[@]}" \
  "${temporary_installer}" \
  "${target}:${remote_installer}" <&"${input_fd}"
scp "${scp_options[@]}" \
  "${temporary_helper}" \
  "${target}:${remote_helper}" <&"${input_fd}"

helper_command="env EASY_HA_PROXY_LOCAL_INSTALLER=${remote_installer} "
if [[ "${stage_install_source}" == true ]]; then
  helper_command+="EASY_HA_PROXY_USE_EXISTING_SOURCE=true "
fi
if [[ "${language_explicit}" == true ]]; then
  helper_command+="EASY_HA_PROXY_LANGUAGE=${language} "
fi
helper_command+="bash ${remote_helper} --action ${remote_action}"
if [[ -n "${source_channel}" ]]; then
  helper_command+=" --source-channel ${source_channel}"
fi
if [[ "${language_explicit}" == true ]]; then
  helper_command+=" --language ${language}"
fi
if [[ "${skip_dns_check}" == true ]]; then
  helper_command+=" --skip-dns-check"
fi
if [[ -n "${certificate_source}" ]]; then
  helper_command+=" --certificate-source ${certificate_source}"
fi
if [[ -n "${image_channel}" ]]; then
  helper_command+=" --image-channel ${image_channel}"
fi
if [[ -n "${new_domain}" ]]; then
  helper_command+=" --new-domain ${new_domain}"
fi
if [[ "${plan_only}" == true ]]; then
  helper_command+=" --plan-only"
fi
remote_command="chmod 0700 ${remote_installer} ${remote_helper} && "
remote_command+="if [ \"\$(id -u)\" -eq 0 ]; then ${helper_command}; "
remote_command+="elif command -v sudo >/dev/null 2>&1; then sudo ${helper_command}; "
remote_command+="else echo 'easy-ha-proxy: root or sudo is required' >&2; exit 1; fi"

prepare_remote_reboot_monitoring
printf '[%s] Starting remote assistant on %s\n' "${product}" "${target}"
set +e
ssh -tt "${ssh_options[@]}" "${target}" "${remote_command}" <&"${input_fd}" |
  tee "${remote_output_file}"
pipeline_status=("${PIPESTATUS[@]}")
install_status="${pipeline_status[0]}"
set -e

ssh "${ssh_options[@]}" "${target}" \
  "rm -f ${remote_installer} ${remote_helper}" </dev/null || true
if [[ "${install_status}" -ne 0 ]]; then
  die "Remote assistant failed with exit code ${install_status}."
fi

reboot_scheduled="$(
  tr -d '\r' <"${remote_output_file}" |
    awk -F= '/^EASY_HA_PROXY_REBOOT_SCHEDULED=/{value=$2} END{print value}'
)"
if [[ "${reboot_scheduled}" == "1" ]]; then
  wait_for_remote_reboot
fi

snapshot_path="$(
  tr -d '\r' <"${remote_output_file}" |
    awk -F= '/^EASY_HA_PROXY_SNAPSHOT_DIR=/{value=$2} END{print value}'
)"
if [[ -n "${snapshot_path}" && "${fetch_snapshot}" == true ]]; then
  if [[ ! "${snapshot_path}" =~ ^/var/backups/easy-ha-proxy/legacy-[0-9TZ]+$ ]]; then
    die "Remote helper returned an unsafe snapshot path: ${snapshot_path}"
  fi

  snapshot_name="${snapshot_path##*/}"
  local_snapshot_dir="${local_snapshot_root%/}/${snapshot_name}"
  local_export="${local_snapshot_dir}/legacy-export.tgz"
  staged_remote_export="/tmp/easy-ha-proxy-${snapshot_name}-export.$$.tgz"

  install -d -m 0700 "${local_snapshot_root}" "${local_snapshot_dir}"
  chmod 0700 "${local_snapshot_root}" "${local_snapshot_dir}"
  printf '[%s] Preparing protected snapshot export on %s\n' \
    "${product}" "${target}"
  stage_command="sudo sh -c 'umask 077; "
  stage_command+="tar -C ${snapshot_path} -czf ${staged_remote_export} "
  stage_command+="live-config.tar.gz SHA256SUMS manifest.txt' && "
  stage_command+="sudo chown \"\$(id -u):\$(id -g)\" ${staged_remote_export} && "
  stage_command+="chmod 0600 ${staged_remote_export}"
  ssh -tt "${ssh_options[@]}" "${target}" "${stage_command}" <&"${input_fd}"

  printf '[%s] Downloading snapshot to %s\n' \
    "${product}" "${local_snapshot_dir}"
  scp "${scp_options[@]}" \
    "${target}:${staged_remote_export}" \
    "${local_export}" <&"${input_fd}"
  chmod 0600 "${local_export}"
  ssh "${ssh_options[@]}" "${target}" \
    "rm -f ${staged_remote_export}" </dev/null || true
  staged_remote_export=""

  tar -xzf "${local_export}" -C "${local_snapshot_dir}"
  expected_hash="$(
    awk 'NR == 1 { print $1 }' "${local_snapshot_dir}/SHA256SUMS"
  )"
  actual_hash="$(
    sha256sum "${local_snapshot_dir}/live-config.tar.gz" |
      awk '{ print $1 }'
  )"
  if [[ -z "${expected_hash}" || "${expected_hash}" != "${actual_hash}" ]]; then
    die "Downloaded snapshot checksum verification failed."
  fi

  live_dir="${local_snapshot_dir}/live"
  [[ ! -e "${live_dir}" ]] ||
    die "Refusing to overwrite existing extracted snapshot: ${live_dir}"
  install -d -m 0700 "${live_dir}"
  tar -xzf "${local_snapshot_dir}/live-config.tar.gz" -C "${live_dir}"
  printf '[%s] Snapshot verified and extracted: %s\n' \
    "${product}" "${live_dir}"
elif [[ -n "${snapshot_path}" ]]; then
  printf '[%s] Snapshot left on server: %s\n' "${product}" "${snapshot_path}"
fi

full_backup_path="$(
  tr -d '\r' <"${remote_output_file}" |
    awk -F= '/^EASY_HA_PROXY_FULL_BACKUP_FILE=/{value=$2} END{print value}'
)"
if [[ -n "${full_backup_path}" && "${fetch_snapshot}" == true ]]; then
  if [[ ! "${full_backup_path}" =~ ^/var/backups/easy-ha-proxy/full-[0-9TZ]+/easy-ha-proxy-full-[0-9TZ]+\.tar\.gz\.enc$ ]]; then
    die "Remote helper returned an unsafe full-backup path: ${full_backup_path}"
  fi
  full_backup_name="${full_backup_path##*/}"
  full_backup_dir_name="${full_backup_path%/*}"
  full_backup_dir_name="${full_backup_dir_name##*/}"
  local_full_backup_dir="${local_snapshot_root%/}/${full_backup_dir_name}"
  local_full_backup="${local_full_backup_dir}/${full_backup_name}"
  staged_remote_export="/tmp/${full_backup_name}.$$"
  install -d -m 0700 "${local_snapshot_root}" "${local_full_backup_dir}"
  chmod 0700 "${local_snapshot_root}" "${local_full_backup_dir}"
  stage_command="sudo cp ${full_backup_path} ${staged_remote_export} && "
  stage_command+="sudo cp ${full_backup_path}.sha256 ${staged_remote_export}.sha256 && "
  stage_command+="sudo chown \"\$(id -u):\$(id -g)\" ${staged_remote_export} ${staged_remote_export}.sha256 && "
  stage_command+="chmod 0600 ${staged_remote_export} ${staged_remote_export}.sha256"
  ssh -tt "${ssh_options[@]}" "${target}" "${stage_command}" <&"${input_fd}"
  scp "${scp_options[@]}" \
    "${target}:${staged_remote_export}" "${local_full_backup}" <&"${input_fd}"
  scp "${scp_options[@]}" \
    "${target}:${staged_remote_export}.sha256" \
    "${local_full_backup}.sha256" <&"${input_fd}"
  chmod 0600 "${local_full_backup}" "${local_full_backup}.sha256"
  ssh "${ssh_options[@]}" "${target}" \
    "rm -f ${staged_remote_export} ${staged_remote_export}.sha256" \
    </dev/null || true
  staged_remote_export=""
  expected_hash="$(awk 'NR == 1 { print $1 }' "${local_full_backup}.sha256")"
  actual_hash="$(sha256sum "${local_full_backup}" | awk '{ print $1 }')"
  [[ -n "${expected_hash}" && "${expected_hash}" == "${actual_hash}" ]] ||
    die "Downloaded full-backup checksum verification failed."
  printf '[%s] Encrypted full backup verified: %s\n' \
    "${product}" "${local_full_backup}"
elif [[ -n "${full_backup_path}" ]]; then
  printf '[%s] Full backup left on server: %s\n' "${product}" "${full_backup_path}"
fi
printf '[%s] Remote assistant completed\n' "${product}"
