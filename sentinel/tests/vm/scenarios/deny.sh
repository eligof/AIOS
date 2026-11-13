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
./target/debug/ebpf-loadtest load --enforce >/tmp/ev.jsonl 2>/tmp/ev.err &
LOADER=$!
sleep 1
RC=0
/tmp/memfd_run || RC=$?
echo "memfd_run exit=$RC"
cp /bin/true /tmp/t
RC2=0
/tmp/t || RC2=$?
echo "/tmp/t exit=$RC2"
sleep 1
kill -INT "$LOADER" 2>/dev/null || true
wait "$LOADER" || { echo "loader failed"; cat /tmp/ev.err; exit 1; }
cat /tmp/ev.err
cat /tmp/ev.jsonl
[ "$RC" -ne 0 ] || { echo "ASSERT FAIL: memfd exec not denied"; exit 1; }
grep -F '"kind":0,' /tmp/ev.jsonl | grep -qF '"kverdict":1' || { echo "ASSERT FAIL: no Denied exec event"; exit 1; }
[ "$RC2" -eq 0 ] || { echo "ASSERT FAIL: /tmp/t did not run (exit $RC2)"; exit 1; }
# exec-tmp is an audit rule keyed on exe_on(/tmp): runs, but is a WouldDeny.
grep -F '"kind":0,' /tmp/ev.jsonl | grep -qF '"kverdict":2' || { echo "ASSERT FAIL: no WouldDeny exec event"; exit 1; }
echo "deny: PASS"
