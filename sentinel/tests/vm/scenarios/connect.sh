#!/bin/sh
# Runs inside the VM as root. connect() ATTEMPTS fire the LSM hook even if they fail.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
SENTINEL=$(cd "$HERE/../../.." && pwd)
# shellcheck disable=SC1091
. "$SENTINEL/tests/vm/lib.sh"
cd "$SENTINEL"
CC=$(command -v cc || command -v clang)
"$CC" -o /tmp/connect_probe tests/vm/payloads/connect_probe.c
./target/debug/ebpf-loadtest load >/tmp/ev.jsonl 2>/tmp/ev.err &
LOADER=$!
sleep 1
/tmp/connect_probe 10.0.2.2 9 || true
/tmp/connect_probe 127.0.0.1 9 || true
sleep 1
kill -INT "$LOADER" 2>/dev/null || true
wait "$LOADER" || { echo "loader failed"; cat /tmp/ev.err; exit 1; }
cat /tmp/ev.jsonl
assert_contains /tmp/ev.jsonl '"kind":3'
assert_contains /tmp/ev.jsonl '"addr":"10.0.2.2","port":9'
if grep -q '"addr":"127\.' /tmp/ev.jsonl; then echo "FAIL: loopback connect event"; exit 1; fi
