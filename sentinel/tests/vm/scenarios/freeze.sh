#!/bin/sh
# A freeze rule really freezes: the cgroup exists, is frozen, is quarantined,
# and `release` puts the process back (spec 6).
#
# The rule fires on `listen` rather than on `exec`. A rule keyed on `exe`
# cannot be triggered reliably today: the daemon resolves an exec event's
# executable from /proc/<pid>/exe, and the LSM hook runs at
# bprm_check_security -- before the new image is installed -- so the glob is
# matched against the pre-exec image (the forking shell). `listen` facts come
# from the kernel's own payload, so this scenario tests the freeze path
# itself rather than that race.
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
id       = "freeze-listener"
desc     = "Freeze a listener this shell started"
on       = "listen"
severity = "high"
action   = "freeze"
# `**` so the rule does not depend on which shell the harness uses;
# `parent` is a user-space predicate, resolved from the process table.
match    = { parent = ["**"] }
RULES

CC=$(command -v cc || command -v clang)
"$CC" -o /tmp/listen_hold tests/vm/payloads/listen_hold.c

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

/tmp/listen_hold 8899 60 &
VICTIM=$!
sleep 3

./target/debug/sentinel --socket /tmp/fz/sock quarantine list >/tmp/fz/q 2>&1
cat /tmp/fz/q
grep -qF "root pid" /tmp/fz/q || {
    echo "ASSERT FAIL: nothing quarantined"
    cat /tmp/fz/err
    # Whether the rule matched at all, and what the action said if it did.
    ./target/debug/sentinel --socket /tmp/fz/sock alerts --json || true
    exit 1
}
QID=$(awk '{print $1; exit}' /tmp/fz/q)
echo "quarantine $QID"

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
