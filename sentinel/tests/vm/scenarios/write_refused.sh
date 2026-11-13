#!/bin/sh
# Runs inside the VM as root. A fresh read-only tmpfs reproduces the -EROFS
# open failure that a read-only /usr bind produces on the ISO.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
SENTINEL=$(cd "$HERE/../../.." && pwd)
# shellcheck disable=SC1091
. "$SENTINEL/tests/vm/lib.sh"
cd "$SENTINEL"
mkdir -p /tmp/ro
mount -t tmpfs -o ro,size=1m tmpfs /tmp/ro
./target/debug/ebpf-loadtest load >/tmp/ev.jsonl 2>/tmp/ev.err &
LOADER=$!
sleep 1
cat /dev/null > /tmp/ro/x 2>/dev/null || true
touch /tmp/ro/y 2>/dev/null || true
sleep 1
kill -INT "$LOADER" 2>/dev/null || true
wait "$LOADER" || { echo "loader failed"; cat /tmp/ev.err; umount /tmp/ro; exit 1; }
umount /tmp/ro
cat /tmp/ev.jsonl
assert_contains /tmp/ev.jsonl '"kind":6'
assert_contains /tmp/ev.jsonl '"path":"/tmp/ro/x"'
