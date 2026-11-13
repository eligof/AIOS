#!/bin/sh
# Runs inside the VM as root. The host filesystem is shared at identical
# absolute paths, so derive the sentinel dir from this script's location.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
SENTINEL=$(cd "$HERE/../../.." && pwd)
# shellcheck disable=SC1091
. "$SENTINEL/tests/vm/lib.sh"
cd "$SENTINEL"
OUT=$(mktemp)
./target/debug/ebpf-loadtest selftest | tee "$OUT"
assert_contains "$OUT" 'loaded object with'
