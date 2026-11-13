#!/bin/sh
# Runs inside the VM as root. Fork + exit observers feed S3's process table.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
SENTINEL=$(cd "$HERE/../../.." && pwd)
# shellcheck disable=SC1091
. "$SENTINEL/tests/vm/lib.sh"
cd "$SENTINEL"
./target/debug/ebpf-loadtest load >/tmp/ev.jsonl 2>/tmp/ev.err &
LOADER=$!
sleep 1
sh -c 'sleep 0; true'
sleep 1
kill -INT "$LOADER" 2>/dev/null || true
wait "$LOADER" || { echo "loader failed"; cat /tmp/ev.err; exit 1; }
cat /tmp/ev.jsonl
# EventKind::Fork = 1, Exit = 2
assert_contains /tmp/ev.jsonl '"kind":1'
assert_contains /tmp/ev.jsonl '"kind":2'
# some fork event (nonzero child_pid) must have a matching exit event for that pid
FOUND=""
for FPID in $(grep '"kind":1,' /tmp/ev.jsonl | grep -o '"child_pid":[1-9][0-9]*' | cut -d: -f2); do
    if grep '"kind":2,' /tmp/ev.jsonl | grep -q "\"pid\":$FPID,"; then
        FOUND=$FPID
        break
    fi
done
[ -n "$FOUND" ] || { echo "no fork event with a matching exit event"; exit 1; }
echo "proctree: PASS (child_pid=$FOUND)"
