#!/bin/sh
# Runs inside the VM as root. With --selfguard, a user signal to the loader (daemon) from a non-pid-1 sender gets EPERM.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
SENTINEL=$(cd "$HERE/../../.." && pwd)
# shellcheck disable=SC1091
. "$SENTINEL/tests/vm/lib.sh"
cd "$SENTINEL"
echo "scenario pid=$$"
./target/debug/ebpf-loadtest load --enforce --selfguard >/tmp/ev.jsonl 2>/tmp/ev.err &
LPID=$!
sleep 1
# child shell: pid != 1 and != daemon
rc=0
sh -c 'echo "sender pid=$$"; kill -TERM '"$LPID" || rc=$?
echo "kill rc=$rc"
[ "$rc" -ne 0 ] || { echo "kill unexpectedly succeeded"; exit 1; }
sleep 1
test -d "/proc/$LPID" || { echo "loader died"; cat /tmp/ev.err; exit 1; }
grep '"kind":11' /tmp/ev.jsonl >/tmp/ev_sig.jsonl || true
cat /tmp/ev_sig.jsonl
assert_contains /tmp/ev_sig.jsonl "\"target_pid\":$LPID,"
assert_contains /tmp/ev_sig.jsonl '"kverdict":1'
echo "guard_kill OK: loader alive, kill denied"
