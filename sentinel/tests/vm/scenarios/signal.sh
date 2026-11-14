#!/bin/sh
# Runs inside the VM as root. A signal to the loader (sentineld_tgid) is reported; one to an unrelated pid is not.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
SENTINEL=$(cd "$HERE/../../.." && pwd)
# shellcheck disable=SC1091
. "$SENTINEL/tests/vm/lib.sh"
cd "$SENTINEL"
./target/debug/ebpf-loadtest load >/tmp/ev.jsonl 2>/tmp/ev.err &
LPID=$!
sleep 1
sleep 30 &
UPID=$!
kill -WINCH "$LPID"
kill -WINCH "$UPID"
sleep 1
kill "$LPID" "$UPID" 2>/dev/null || true
wait "$LPID" || { echo "loader failed"; cat /tmp/ev.err; exit 1; }
grep '"kind":11' /tmp/ev.jsonl >/tmp/ev_sig.jsonl || true
cat /tmp/ev_sig.jsonl
assert_contains /tmp/ev_sig.jsonl "\"target_pid\":$LPID,"
if grep -q "\"target_pid\":$UPID," /tmp/ev_sig.jsonl; then
  echo "unexpected signal event for unrelated pid"; exit 1
fi
