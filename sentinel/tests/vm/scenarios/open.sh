#!/bin/sh
# Runs inside the VM as root. Uses mknod'd device nodes so it does not depend
# on QEMU-provided devices. file_open fires before the driver's open().
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
SENTINEL=$(cd "$HERE/../../.." && pwd)
# shellcheck disable=SC1091
. "$SENTINEL/tests/vm/lib.sh"
cd "$SENTINEL"
mknod /tmp/cam c 81 0
mknod /tmp/inp c 13 64
./target/debug/ebpf-loadtest load >/tmp/ev.jsonl 2>/tmp/ev.err &
LOADER=$!
sleep 1
echo step-cam; timeout 5 cat /tmp/cam 2>/dev/null || true
echo step-inp; timeout 5 cat /tmp/inp 2>/dev/null || true
cat /etc/hostname >/dev/null
sleep 1
kill -INT "$LOADER" 2>/dev/null || true
wait "$LOADER" || { echo "loader failed"; cat /tmp/ev.err; exit 1; }
cat /tmp/ev.jsonl
assert_contains /tmp/ev.jsonl '"kind":5'
assert_contains /tmp/ev.jsonl '"device":"camera"'
assert_contains /tmp/ev.jsonl '"device":"input"'
if grep -q '"name":"hostname"' /tmp/ev.jsonl; then echo "regular file produced Open event"; exit 1; fi
