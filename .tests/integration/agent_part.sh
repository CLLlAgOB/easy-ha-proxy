#!/bin/bash
# Run one installer-agent part on a disposable CI runner with an empty managed
# configuration, as the HAProxy 3.4 package workflow does.
#
#   agent_part.sh AGENT PART [PROVIDER]
#
# PROVIDER sets haproxy_package_provider (haproxy-technologies by default).
# The output ends with the agent's JSON summary line; the exit code is the
# agent's.
set -euo pipefail
agent="$1"
part="$2"
provider="${3:-haproxy-technologies}"
config="$(mktemp -d)"
trap 'rm -rf -- "${config}"' EXIT
printf '[easy_ha_proxy]\nlocalhost ansible_connection=local\n' > "${config}/inventory.ini"
for name in vars.yml authelia.yml authelia_users_initial.yml websites.yml tcp.yml secrets.yml; do
  printf '{}\n' > "${config}/${name}"
done
sudo "${agent}" apply run --part "${part}" --source "${PWD}" --config "${config}" \
  --extra "haproxy_package_provider=${provider}"
