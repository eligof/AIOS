#!/bin/sh
# A freeze rule really freezes: the cgroup exists, is frozen, is quarantined,
# and `release` puts the process back (spec 6).
#
# The rule is keyed on `exe`, which also makes this the regression test for
# the exec path coming from the kernel: the hook runs at bprm_check_security,
# before the new image is installed, so resolving the executable from
# /proc/<pid>/exe matched every exec against the forking shell instead. The
# path now comes from bprm->filename.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
SENTINEL=$(cd "$HERE/../../.." && pwd)
# shellcheck disable=SC1091
. "$SENTINEL/tests/vm/lib.sh"
cd "$SENTINEL"

# virtme boots without bpffs; systemd mounts it in production (spec 8.1).
grep -q " /sys/fs/bpf " /proc/mounts || mount -t bpf bpffs /sys/fs/bpf

mkdir -p /tmp/fz/rules /tmp/fz/alerts
cat > /tmp/fz/rules/freeze.toml <<'RULES'
[[rule]]
id       = "freeze-marker"
desc     = "Freeze anything exec'ing the marker binary"
on       = "exec"
severity = "high"
action   = "freeze"
match    = { exe = ["/tmp/marker"] }
RULES

cp /bin/sleep /tmp/marker

./target/debug/sentineld \
    --config /nonexistent/sentinel.toml \
    --rules /tmp/fz/rules \
    --alerts /tmp/fz/alerts \
    --socket /tmp/fz/sock \
    --state /tmp/fz/state \
    >/tmp/fz/out 2>/tmp/fz/err &
DAEMON=$!
sleep 3
grep -qF "sentineld: ready" /tmp/fz/err || { echo "ASSERT FAIL: not ready"; cat /tmp/fz/err; exit 1; }

/tmp/marker 60 &
VICTIM=$!
sleep 3

./target/debug/sentinel --socket /tmp/fz/sock quarantine list >/tmp/fz/q 2>&1
cat /tmp/fz/q
grep -qF "root pid" /tmp/fz/q || {
    echo "ASSERT FAIL: nothing quarantined"
    cat /tmp/fz/err
    # Whether the rule matched at all, and what exe the exec resolved to.
    ./target/debug/sentinel --socket /tmp/fz/sock alerts --json || true
    exit 1
}
QID=$(awk '{print $1; exit}' /tmp/fz/q)
echo "quarantine $QID"

# The alert must name the program that was executed, not the shell that
# forked it.
./target/debug/sentinel --socket /tmp/fz/sock show "$QID" >/tmp/fz/show 2>&1
assert_contains /tmp/fz/show '"exe": "/tmp/marker"'

CG="/sys/fs/cgroup/aios-sentinel.slice/q-$QID"
[ -d "$CG" ] || { echo "ASSERT FAIL: $CG missing"; exit 1; }
grep -q 1 "$CG/cgroup.freeze" || { echo "ASSERT FAIL: cgroup not frozen"; exit 1; }
grep -qw "$VICTIM" "$CG/cgroup.procs" || { echo "ASSERT FAIL: victim not in the cgroup"; cat "$CG/cgroup.procs"; exit 1; }

./target/debug/sentinel --socket /tmp/fz/sock quarantine release "$QID" >/tmp/fz/rel 2>&1 || {
    echo "ASSERT FAIL: release failed"; cat /tmp/fz/rel; exit 1; }
assert_contains /tmp/fz/rel "released"
[ -d "$CG" ] && { echo "ASSERT FAIL: cgroup survived the release"; exit 1; }

kill -9 "$VICTIM" 2>/dev/null || true
kill -TERM "$DAEMON" 2>/dev/null || true
echo "freeze: PASS"
