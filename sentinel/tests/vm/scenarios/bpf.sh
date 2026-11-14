#!/bin/sh
# Runs inside the VM as root. One BPF_PROG_LOAD of a socket filter must surface as a Bpf event.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
SENTINEL=$(cd "$HERE/../../.." && pwd)
# shellcheck disable=SC1091
. "$SENTINEL/tests/vm/lib.sh"
cd "$SENTINEL"
CC=$(command -v cc || command -v clang)
"$CC" -o /tmp/bpf_probe tests/vm/payloads/bpf_probe.c
./target/debug/ebpf-loadtest load >/tmp/ev.jsonl 2>/tmp/ev.err &
LOADER=$!
sleep 1
timeout 10 /tmp/bpf_probe || true
sleep 1
kill -INT "$LOADER" 2>/dev/null || true
wait "$LOADER" || { echo "loader failed"; cat /tmp/ev.err; exit 1; }
grep '"kind":10' /tmp/ev.jsonl | grep '"bpf_cmd":5,"prog_type":1' >/tmp/ev_bpf.jsonl || true
cat /tmp/ev_bpf.jsonl
assert_contains /tmp/ev_bpf.jsonl '"bpf_cmd":5,"prog_type":1'
