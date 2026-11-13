#!/bin/sh
# Runs inside the VM as root.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
SENTINEL=$(cd "$HERE/../../.." && pwd)
# shellcheck disable=SC1091
. "$SENTINEL/tests/vm/lib.sh"
cd "$SENTINEL"
./target/debug/ebpf-loadtest load >/tmp/ev.jsonl 2>/tmp/ev.err &
LOADER=$!
sleep 1
# The LSM hook fires on the load ATTEMPT, so success is not required.
timeout 20 modprobe dummy 2>&1 || echo "modprobe dummy failed"
timeout 10 rmmod dummy 2>/dev/null || true
sleep 1
kill -INT "$LOADER" 2>/dev/null || true
wait "$LOADER" || { echo "loader failed"; cat /tmp/ev.err; exit 1; }
cat /tmp/ev.jsonl
grep '"kind":9' /tmp/ev.jsonl >/tmp/ev_mod.jsonl || true
# READING_MODULE=2, or READING_MODULE_COMPRESSED=7 for .ko.zst (in-kernel decompress).
grep -Eq '"read_id":(2|7),' /tmp/ev_mod.jsonl || { echo "ASSERT FAIL: read_id 2|7"; exit 1; }
assert_contains /tmp/ev_mod.jsonl '"module_name":"'
if grep -q '"module_name":""' /tmp/ev_mod.jsonl && ! grep -q '"module_name":"[^"]' /tmp/ev_mod.jsonl; then
  echo "empty module_name"; exit 1
fi
