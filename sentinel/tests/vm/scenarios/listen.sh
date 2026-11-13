#!/bin/sh
# Runs inside the VM as root.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
SENTINEL=$(cd "$HERE/../../.." && pwd)
# shellcheck disable=SC1091
. "$SENTINEL/tests/vm/lib.sh"
cd "$SENTINEL"
CC=$(command -v cc || command -v clang)
"$CC" -o /tmp/listen_probe tests/vm/payloads/listen_probe.c
./target/debug/ebpf-loadtest load >/tmp/ev.jsonl 2>/tmp/ev.err &
LOADER=$!
sleep 1
/tmp/listen_probe 0.0.0.0 8888
/tmp/listen_probe 127.0.0.1 8889
sleep 1
kill -INT "$LOADER" 2>/dev/null || true
wait "$LOADER" || { echo "loader failed"; cat /tmp/ev.err; exit 1; }
cat /tmp/ev.jsonl
assert_contains /tmp/ev.jsonl '"kind":4'
assert_contains /tmp/ev.jsonl '"flags_listen_nonloopback":true'
assert_contains /tmp/ev.jsonl '"laddr":"0.0.0.0","port":8888'
if grep '"kind":4' /tmp/ev.jsonl | grep -q '"laddr":"127\.'; then echo "FAIL: loopback listen event"; exit 1; fi
