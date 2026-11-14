#!/bin/sh
# Runs inside the VM as root. Single-process: the loader forks a child into a
# quarantined cgroup; the child's connect must be EPERM, the parent's not.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
SENTINEL=$(cd "$HERE/../../.." && pwd)
# shellcheck disable=SC1091
. "$SENTINEL/tests/vm/lib.sh"
cd "$SENTINEL"
timeout 30 ./target/debug/ebpf-loadtest quarantine-selftest 2>&1 | tee /tmp/q.out
assert_contains /tmp/q.out 'quarantine: PASS'
