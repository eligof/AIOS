#!/bin/sh
# Runs inside the VM as root. With --selfguard, a non-daemon write/rm of a guarded file gets EPERM.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
SENTINEL=$(cd "$HERE/../../.." && pwd)
# shellcheck disable=SC1091
. "$SENTINEL/tests/vm/lib.sh"
cd "$SENTINEL"
mkdir -p /tmp/g
: > /tmp/g/alerts.jsonl
./target/debug/ebpf-loadtest load --enforce --selfguard --guard-dir /tmp/g >/tmp/ev.jsonl 2>/tmp/ev.err &
# Do NOT kill/wait the loader: selfguard denies our signals; VM teardown reaps it.
sleep 1
rc=0
timeout 5 sh -c 'echo x > /tmp/g/alerts.jsonl' || rc=$?
echo "write rc=$rc"
[ "$rc" -ne 0 ] || { echo "write unexpectedly succeeded"; exit 1; }
rc=0
timeout 5 rm /tmp/g/alerts.jsonl || rc=$?
echo "rm rc=$rc"
[ "$rc" -ne 0 ] || { echo "rm unexpectedly succeeded"; exit 1; }
test -f /tmp/g/alerts.jsonl || { echo "guarded file vanished"; exit 1; }
sleep 1
grep '"kind":5' /tmp/ev.jsonl | grep '"kverdict":1' >/tmp/ev_g.jsonl || true
cat /tmp/ev_g.jsonl
assert_contains /tmp/ev_g.jsonl '"kverdict":1'
echo "guard_files OK: write+rm denied, file intact"
