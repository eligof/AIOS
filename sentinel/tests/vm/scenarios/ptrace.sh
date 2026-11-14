#!/bin/sh
# Runs inside the VM as root. PTRACE_ATTACH of an unrelated pid vs. our own child.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
SENTINEL=$(cd "$HERE/../../.." && pwd)
# shellcheck disable=SC1091
. "$SENTINEL/tests/vm/lib.sh"
cd "$SENTINEL"
CC=$(command -v cc || command -v clang)
"$CC" -o /tmp/ptrace_probe tests/vm/payloads/ptrace_probe.c
./target/debug/ebpf-loadtest load >/tmp/ev.jsonl 2>/tmp/ev.err &
LOADER=$!
sleep 1
sleep 30 &
VICTIM=$!
timeout 10 /tmp/ptrace_probe pid "$VICTIM" || true
sleep 1
grep '"kind":8' /tmp/ev.jsonl >/tmp/ev_pid.jsonl || true
timeout 10 /tmp/ptrace_probe child || true
sleep 1
kill "$VICTIM" 2>/dev/null || true
kill -INT "$LOADER" 2>/dev/null || true
wait "$LOADER" || { echo "loader failed"; cat /tmp/ev.err; exit 1; }
cat /tmp/ev.jsonl
grep '"kind":8' /tmp/ev.jsonl >/tmp/ev_ptrace.jsonl || true
assert_contains /tmp/ev_pid.jsonl '"p_non_descendant":true'
assert_contains /tmp/ev_ptrace.jsonl '"p_any":true,"p_other_uid":false,"p_non_descendant":false'
