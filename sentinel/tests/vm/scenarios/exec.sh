#!/bin/sh
# Runs inside the VM as root. The host filesystem is shared at identical
# absolute paths, so derive the sentinel dir from this script's location.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
SENTINEL=$(cd "$HERE/../../.." && pwd)
# shellcheck disable=SC1091
. "$SENTINEL/tests/vm/lib.sh"
cd "$SENTINEL"
CC=$(command -v cc || command -v clang)
"$CC" -o /tmp/memfd_run tests/vm/payloads/memfd_run.c
./target/debug/ebpf-loadtest load >/tmp/ev.jsonl 2>/tmp/ev.err &
LOADER=$!
sleep 1
/tmp/memfd_run || true
/bin/true
sleep 1
kill -INT "$LOADER" 2>/dev/null || true
wait "$LOADER" || { echo "loader failed"; cat /tmp/ev.err; exit 1; }
cat /tmp/ev.jsonl
assert_contains /tmp/ev.jsonl '"kind":0'
assert_contains /tmp/ev.jsonl '"flags_memfd":true'
assert_contains /tmp/ev.jsonl '"flags_memfd":false'
