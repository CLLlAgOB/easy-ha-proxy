#!/usr/bin/env bash
# Differential parity runs: the Go web panel and the Go host agent against the
# Python implementations they replace, request for request, on the same state
# and the same fake daemons and host tools. The Python code is the
# specification; any difference fails the run.
#
#   .tests/parity/run.sh [all|panel|agent] [panel suite, e.g. cases_sites.py]
#
# Needs Docker. Builds both Go binaries in golang:1.24 and runs every suite in
# its own throwaway container, PARITY_JOBS (default 4) at a time.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WHAT=${1:-all}
ONLY=${2:-}
JOBS=${PARITY_JOBS:-4}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
GO_IMAGE=golang:1.24
PY_IMAGE=ehp-parity-python

echo "Building the Go panel and agent"
docker run --rm -v "$ROOT/go:/src:ro" -v "$WORK:/out" -e CGO_ENABLED=0 -e GOFLAGS=-buildvcs=false \
  -e GOCACHE=/tmp/gocache -e GOMODCACHE=/tmp/gomod "$GO_IMAGE" sh -c \
  'cd /src/panel && go build -o /out/panel ./cmd/easy-ha-proxy-panel &&
   cd /src/agent && go build -o /out/agent ./cmd/easy-ha-proxy-agent'

echo "Building the Python image"
mkdir -p "$WORK/context" && cp "$ROOT/docker/app/requirements.txt" "$WORK/context/"
docker build -q -t "$PY_IMAGE" -f - "$WORK/context" >/dev/null <<'EOF'
FROM python:3.12-slim-bookworm
RUN apt-get -o Acquire::Retries=3 update -qq \
 && apt-get install -y --no-install-recommends openssl >/dev/null \
 && rm -rf /var/lib/apt/lists/*
COPY requirements.txt /tmp/requirements.txt
RUN pip install -q --no-cache-dir -r /tmp/requirements.txt pyyaml cryptography
EOF

run_in() {  # name, command...
  local name=$1; shift
  if docker run --rm -e PYTHONDONTWRITEBYTECODE=1 -e REPO=/repo -e PANEL_BIN=/work/panel -e AGENT_BIN=/work/agent \
      -v "$ROOT:/repo:ro" -v "$WORK:/work:ro" "$PY_IMAGE" "$@" > "$WORK/$name.log" 2>&1; then
    echo "ok    $name: $(grep -E '^(steps|cases:|renew:)' "$WORK/$name.log" | tail -1)"
  else
    echo "FAIL  $name"
    tail -n 60 "$WORK/$name.log" | sed 's/^/      /'
    return 1
  fi
}
export -f run_in
export WORK ROOT PY_IMAGE

jobs=()
if [[ $WHAT == all || $WHAT == panel ]]; then
  for suite in "$ROOT"/.tests/parity/panel/cases_*.py; do
    suite=$(basename "$suite")
    [[ -z $ONLY || $suite == "$ONLY" ]] && jobs+=("panel-${suite%.py} sh /repo/.tests/parity/panel/container.sh $suite")
  done
fi
if [[ $WHAT == all || $WHAT == agent ]]; then
  jobs+=("agent-certd bash /repo/.tests/parity/agent/certd/run.sh"
         "agent-cert-deliver bash /repo/.tests/parity/agent/tools/cert_deliver.sh"
         "agent-server-state python3 /repo/.tests/parity/agent/tools/server_state.py"
         "agent-renew bash /repo/.tests/parity/agent/tools/renew.sh")
fi

printf '%s\n' "${jobs[@]}" | xargs -P "$JOBS" -I{} bash -c 'run_in {}' && status=0 || status=1
[[ $status -eq 0 ]] && echo "parity: all ${#jobs[@]} runs identical" || echo "parity: differences found"
exit $status
