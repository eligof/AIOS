#!/bin/sh
# Runs inside the VM as root. With --selfguard, a kprobe BPF_PROG_LOAD gets EPERM; a socket-filter load is allowed.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
SENTINEL=$(cd "$HERE/../../.." && pwd)
# shellcheck disable=SC1091
. "$SENTINEL/tests/vm/lib.sh"
cd "$SENTINEL"
CC=$(command -v cc || command -v clang)
"$CC" -o /tmp/kprobe_load tests/vm/payloads/kprobe_load.c
"$CC" -o /tmp/bpf_probe tests/vm/payloads/bpf_probe.c
./target/debug/ebpf-loadtest load --enforce --selfguard >/tmp/ev.jsonl 2>/tmp/ev.err &
LOADER=$!
sleep 1
rc=0
timeout 10 /tmp/kprobe_load >/tmp/kp.out || rc=$?
cat /tmp/kp.out
echo "kprobe_load rc=$rc"
[ "$rc" -ne 0 ] || { echo "kprobe load unexpectedly succeeded"; exit 1; }
assert_contains /tmp/kp.out "errno=1"
timeout 10 /tmp/bpf_probe || { echo "socket-filter load failed"; exit 1; }
sleep 1
# No kill/wait: self-guard denies signals to the daemon from non-daemon/non-pid-1; VM teardown reaps it.
test -d "/proc/$LOADER" || { echo "loader died"; cat /tmp/ev.err; exit 1; }
grep '"kind":10' /tmp/ev.jsonl >/tmp/ev_bpf.jsonl || true
cat /tmp/ev_bpf.jsonl
grep '"bpf_cmd":5,"prog_type":2' /tmp/ev_bpf.jsonl >/tmp/ev_kp.jsonl || true
assert_contains /tmp/ev_kp.jsonl '"kverdict":1'
grep '"bpf_cmd":5,"prog_type":1' /tmp/ev_bpf.jsonl >/tmp/ev_sf.jsonl || true
assert_contains /tmp/ev_sf.jsonl '"bpf_cmd":5,"prog_type":1'
! grep -qF '"kverdict":1' /tmp/ev_sf.jsonl || { echo "socket filter was denied"; exit 1; }
echo "guard_bpf OK: kprobe load denied, socket filter allowed"
