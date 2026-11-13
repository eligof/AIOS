#!/bin/sh
# Runs inside the VM as root. exe_on rules: exec-shm (Deny) and exec-tmp (audit).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
SENTINEL=$(cd "$HERE/../../.." && pwd)
# shellcheck disable=SC1091
. "$SENTINEL/tests/vm/lib.sh"
cd "$SENTINEL"
./target/debug/ebpf-loadtest load --enforce >/tmp/ev.jsonl 2>/tmp/ev.err &
LOADER=$!
sleep 1
cp /bin/true /dev/shm/t
RC=0
/dev/shm/t || RC=$?
echo "/dev/shm/t exit=$RC"
cp /bin/true /tmp/t2
RC2=0
/tmp/t2 || RC2=$?
echo "/tmp/t2 exit=$RC2"
sleep 1
kill -INT "$LOADER" 2>/dev/null || true
wait "$LOADER" || { echo "loader failed"; cat /tmp/ev.err; exit 1; }
cat /tmp/ev.err
cat /tmp/ev.jsonl
SHM=$(sed -n 's/^rule \([0-9]*\) -> exec-shm$/\1/p' /tmp/ev.err)
TMP=$(sed -n 's/^rule \([0-9]*\) -> exec-tmp$/\1/p' /tmp/ev.err)
[ -n "$SHM" ] && [ -n "$TMP" ] || { echo "ASSERT FAIL: rule indices not found"; exit 1; }
[ "$RC" -ne 0 ] || { echo "ASSERT FAIL: /dev/shm/t was not denied"; exit 1; }
grep -F '"kind":0,' /tmp/ev.jsonl | grep -F "\"matched_rule\":$SHM," | grep -qF '"kverdict":1' \
  || { echo "ASSERT FAIL: no Denied exec-shm event"; exit 1; }
[ "$RC2" -eq 0 ] || { echo "ASSERT FAIL: /tmp/t2 did not run (exit $RC2)"; exit 1; }
grep -F '"kind":0,' /tmp/ev.jsonl | grep -F "\"matched_rule\":$TMP," | grep -qF '"kverdict":2' \
  || { echo "ASSERT FAIL: no WouldDeny exec-tmp event"; exit 1; }
echo "exe_on: PASS"
