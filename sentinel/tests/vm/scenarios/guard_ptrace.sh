#!/bin/sh
# Runs inside the VM as root. With --selfguard, PTRACE_ATTACH on the loader (daemon) from a non-pid-1 process gets EPERM.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
SENTINEL=$(cd "$HERE/../../.." && pwd)
# shellcheck disable=SC1091
. "$SENTINEL/tests/vm/lib.sh"
cd "$SENTINEL"
echo "scenario pid=$$"
CC=$(command -v cc || command -v clang)
"$CC" -o /tmp/ptrace_probe tests/vm/payloads/ptrace_probe.c
./target/debug/ebpf-loadtest load --enforce --selfguard >/tmp/ev.jsonl 2>/tmp/ev.err &
LPID=$!
sleep 1
rc=0
timeout 10 /tmp/ptrace_probe pid "$LPID" || rc=$?
echo "attach rc=$rc"
[ "$rc" -ne 0 ] || { echo "attach unexpectedly succeeded"; exit 1; }
sleep 1
test -d "/proc/$LPID" || { echo "loader died"; cat /tmp/ev.err; exit 1; }
grep '"kind":8' /tmp/ev.jsonl >/tmp/ev_pt.jsonl || true
cat /tmp/ev_pt.jsonl
assert_contains /tmp/ev_pt.jsonl "\"target_pid\":$LPID,"
assert_contains /tmp/ev_pt.jsonl '"kverdict":1'
echo "guard_ptrace OK: loader alive, attach denied"
