#!/bin/sh
# Runs inside the VM as root.
# The daemon starts, pins, serves varlink, and the CLI can read it.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
SENTINEL=$(cd "$HERE/../../.." && pwd)
# shellcheck disable=SC1091
. "$SENTINEL/tests/vm/lib.sh"
cd "$SENTINEL"

# virtme boots without bpffs; systemd mounts it in production (spec 8.1).
grep -q " /sys/fs/bpf " /proc/mounts || mount -t bpf bpffs /sys/fs/bpf

mkdir -p /tmp/sd/rules /tmp/sd/alerts
cp ../manifest/sentinel/rules/*.toml /tmp/sd/rules/

./target/debug/sentineld \
    --config /nonexistent/sentinel.toml \
    --rules /tmp/sd/rules \
    --alerts /tmp/sd/alerts \
    --socket /tmp/sd/sock \
    --state /tmp/sd/state \
    >/tmp/sd/out 2>/tmp/sd/err &
DAEMON=$!
sleep 3

cat /tmp/sd/err
grep -qF "sentineld: ready" /tmp/sd/err || { echo "ASSERT FAIL: never became ready"; exit 1; }
[ "$(cat /tmp/sd/state)" = "ok" ] || { echo "ASSERT FAIL: state is $(cat /tmp/sd/state), want ok"; exit 1; }

# Pins outlive the process, so the kernel side keeps enforcing (spec 8.1).
for m in EVENTS HEARTBEAT RULES CONFIG QUARANTINE; do
    [ -e "/sys/fs/bpf/aios-sentinel/maps/$m" ] || { echo "ASSERT FAIL: map $m not pinned"; exit 1; }
done
[ -e /sys/fs/bpf/aios-sentinel/links/exec ] || { echo "ASSERT FAIL: exec link not pinned"; exit 1; }

./target/debug/sentinel --socket /tmp/sd/sock status >/tmp/sd/status 2>&1 || {
    echo "ASSERT FAIL: status failed"; cat /tmp/sd/status; exit 1; }
cat /tmp/sd/status
assert_contains /tmp/sd/status "health         ok"

# An exec that trips a rule must show up as an alert. The process has to
# outlive the daemon's resolution of its exec event: env_ld is a user-space
# predicate read from /proc/<pid>/environ, so a process that has already
# exited carries no environment to read. `/bin/true` is gone too soon.
LD_PRELOAD=/nonexistent.so sleep 5 2>/dev/null &
PRELOADED=$!
sleep 2
./target/debug/sentinel --socket /tmp/sd/sock alerts --json >/tmp/sd/alerts.json 2>&1 || {
    echo "ASSERT FAIL: alerts failed"; cat /tmp/sd/alerts.json; exit 1; }
cat /tmp/sd/alerts.json
assert_contains /tmp/sd/alerts.json "ld-preload"

./target/debug/sentinel --socket /tmp/sd/sock verify >/tmp/sd/verify 2>&1 || {
    echo "ASSERT FAIL: verify failed"; cat /tmp/sd/verify; exit 1; }
assert_contains /tmp/sd/verify "alert chain is intact"

kill -9 "$PRELOADED" 2>/dev/null || true
kill -TERM "$DAEMON" 2>/dev/null || true
echo "daemon: PASS"
