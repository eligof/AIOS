#!/bin/sh
# Runs inside the VM as root.
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
sleep 1
kill -INT "$LOADER" 2>/dev/null || true
wait "$LOADER" || { echo "loader failed"; cat /tmp/ev.err; exit 1; }
cat /tmp/ev.jsonl
EXEC=$(grep -F '"kind":0,' /tmp/ev.jsonl | grep -F '"flags_memfd":true' | head -n1)
[ -n "$EXEC" ] || { echo "ASSERT FAIL: no memfd exec event"; exit 1; }
IDX=$(printf '%s' "$EXEC" | sed -n 's/.*"matched_rule":\(-\?[0-9]*\).*/\1/p')
echo "exec matched_rule=$IDX"
[ -n "$IDX" ] && [ "$IDX" -ge 0 ] || { echo "ASSERT FAIL: matched_rule=$IDX"; cat /tmp/ev.err; exit 1; }
grep -qF "rule $IDX -> exec-memfd" /tmp/ev.err || { echo "ASSERT FAIL: rule $IDX is not exec-memfd"; cat /tmp/ev.err; exit 1; }
echo "rules: PASS"
