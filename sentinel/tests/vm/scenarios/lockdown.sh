#!/bin/sh
# Runs inside the VM as root. Heartbeat lockdown: after the loader stops
# refreshing the heartbeat (SIGUSR1), non-loopback connect and non-/usr exec are denied.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
SENTINEL=$(cd "$HERE/../../.." && pwd)
# shellcheck disable=SC1091
. "$SENTINEL/tests/vm/lib.sh"
cd "$SENTINEL"
CC=$(command -v cc || command -v clang)
# /usr is a writable overlay in the VM; the probe must live on it to exec under lockdown.
"$CC" -o /usr/bin/connect_probe tests/vm/payloads/connect_probe.c
cp /bin/true /tmp/lt && chmod +x /tmp/lt
./target/debug/ebpf-loadtest load --enforce >/tmp/ev.jsonl 2>/tmp/ev.err &
LPID=$!
sleep 1

rc=0; timeout 5 /usr/bin/connect_probe 10.0.2.2 9 || rc=$?
echo "pre-connect errno=$rc"
[ "$rc" -ne 1 ] || { echo "FAIL: pre-lockdown connect was EPERM"; exit 1; }
rc=0; timeout 5 /tmp/lt || rc=$?
echo "pre-exec rc=$rc"
[ "$rc" -eq 0 ] || { echo "FAIL: pre-lockdown exec failed"; exit 1; }

kill -USR1 "$LPID"
sleep 3
MARK=$(wc -l </tmp/ev.jsonl)

rc=0; timeout 5 /usr/bin/connect_probe 10.0.2.2 9 || rc=$?
echo "post-connect errno=$rc"
[ "$rc" -eq 1 ] || { echo "FAIL: post-lockdown connect not EPERM"; exit 1; }
rc=0; timeout 5 /tmp/lt || rc=$?
echo "post-exec rc=$rc"
[ "$rc" -ne 0 ] || { echo "FAIL: post-lockdown non-/usr exec ran"; exit 1; }
rc=0; timeout 5 /bin/true || rc=$?
echo "usr rc=$rc"
[ "$rc" -eq 0 ] || { echo "FAIL: /bin/true blocked under lockdown"; exit 1; }
sleep 1

tail -n +"$((MARK + 1))" /tmp/ev.jsonl >/tmp/post.jsonl
echo "--- post-lockdown events"; cat /tmp/post.jsonl
grep '"kind":3' /tmp/post.jsonl | grep -qF '"kverdict":1' || { echo "FAIL: no denied Connect event"; exit 1; }
grep '"kind":0,' /tmp/post.jsonl | grep -qF '"kverdict":1' || { echo "FAIL: no denied Exec event"; exit 1; }
echo "lockdown: PASS"
