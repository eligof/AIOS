#!/bin/sh
# After a daemon dies and a new one starts, the gap and the per-hook denial
# counts are reported as a critical alert (spec 8.3).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
SENTINEL=$(cd "$HERE/../../.." && pwd)
# shellcheck disable=SC1091
. "$SENTINEL/tests/vm/lib.sh"
cd "$SENTINEL"

# virtme boots without bpffs; systemd mounts it in production (spec 8.1).
grep -q " /sys/fs/bpf " /proc/mounts || mount -t bpf bpffs /sys/fs/bpf

mkdir -p /tmp/lk/rules /tmp/lk/alerts
cp ../manifest/sentinel/rules/*.toml /tmp/lk/rules/

# During the gap, lockdown allows exec only from the read-only /usr mount, so
# the replacement daemon has to live there -- which it does in production
# (/usr/bin/sentineld). The build tree is on another mount, so copy both
# binaries over before the lockdown starts.
cp ./target/debug/sentineld /usr/bin/sentineld-test || {
    echo "ASSERT FAIL: cannot install the daemon on the /usr mount"; exit 1; }
cp ./target/debug/sentinel /usr/bin/sentinel-test || {
    echo "ASSERT FAIL: cannot install the CLI on the /usr mount"; exit 1; }
DAEMON_BIN=/usr/bin/sentineld-test
CLI=/usr/bin/sentinel-test

start() {
    # --no-selfguard: with the self-guard on, nothing may signal the daemon
    # (spec 8.2), so the gap this scenario is about could not be created.
    "$DAEMON_BIN" \
        --no-selfguard \
        --config /nonexistent/sentinel.toml \
        --rules /tmp/lk/rules \
        --alerts /tmp/lk/alerts \
        --socket "/tmp/lk/sock$1" \
        --state /tmp/lk/state \
        >"/tmp/lk/out$1" 2>"/tmp/lk/err$1" &
    echo $!
}

D1=$(start 1)
sleep 3
grep -qF "sentineld: ready" /tmp/lk/err1 || { echo "ASSERT FAIL: first daemon not ready"; cat /tmp/lk/err1; exit 1; }

# SIGKILL: no clean-up, so the heartbeat goes stale and the kernel locks down.
kill -9 "$D1"
sleep 8

# During the gap, a non-/usr exec must be refused (spec 8.3).
cp /bin/true /tmp/gap_test
if /tmp/gap_test 2>/dev/null; then
    echo "ASSERT FAIL: a non-/usr exec ran during the lockdown"
    exit 1
fi
echo "lockdown refused the /tmp exec"

D2=$(start 2)
sleep 3
grep -qF "sentineld: ready" /tmp/lk/err2 || { echo "ASSERT FAIL: second daemon not ready"; cat /tmp/lk/err2; exit 1; }

"$CLI" --socket /tmp/lk/sock2 alerts --json >/tmp/lk/alerts.json 2>&1
cat /tmp/lk/alerts.json
assert_contains /tmp/lk/alerts.json "lockdown-gap"
assert_contains /tmp/lk/alerts.json "critical"

# The chain spans both daemons.
"$CLI" --socket /tmp/lk/sock2 verify >/tmp/lk/verify 2>&1 || {
    echo "ASSERT FAIL: chain broken across the restart"; cat /tmp/lk/verify; exit 1; }
assert_contains /tmp/lk/verify "alert chain is intact"

kill -TERM "$D2" 2>/dev/null || true
echo "lockdown_report: PASS"
