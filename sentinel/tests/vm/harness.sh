#!/usr/bin/env bash
# Usage: harness.sh <scenario>   (scenario = tests/vm/scenarios/<scenario>.sh)
set -euo pipefail
SCEN="${1:?scenario}"
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH:$ROOT/build/hosttools/root/usr/bin"
( cd "$ROOT/sentinel" && cargo build -p ebpf-loadtest -p sentineld -p sentinel )
cd "$ROOT"
# virtme-ng shares the host fs at identical absolute paths; the scenario runs as root.
uvx --from virtme-ng vng --run "$(uname -r)" --user root \
    --exec "sh $ROOT/sentinel/tests/vm/scenarios/${SCEN}.sh"
