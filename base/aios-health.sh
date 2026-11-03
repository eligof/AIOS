#!/bin/sh
# aios-health.sh: boot health check for the booted generation (spec §3 step 11).
# Run by aios-health.service, which boot-complete.target requires. Exit 0 lets
# systemd-bless-boot mark the boot entry good. Exit 1 leaves the boot counter running,
# so after 3 failed boots systemd-boot falls back to the previous entry.
#
# Environment overrides (tests only):
#   AIOS_CMDLINE_FILE  kernel cmdline         (default /proc/cmdline)
#   AIOS_GEN_FILE      generation metadata    (default /etc/aios/generation.toml)
#   AIOS_FINDMNT       findmnt executable     (default findmnt)
set -eu

CMDLINE_FILE="${AIOS_CMDLINE_FILE:-/proc/cmdline}"
GEN_FILE="${AIOS_GEN_FILE:-/etc/aios/generation.toml}"
FINDMNT="${AIOS_FINDMNT:-findmnt}"

fail() {
    printf 'aios-health: %s\n' "$*" >&2
    exit 1
}

# has_opt OPTIONS WANT: true if the comma-separated mount OPTIONS contain WANT exactly.
has_opt() {
    case ",$1," in
        *",$2,"*) return 0 ;;
        *) return 1 ;;
    esac
}

# is_gen VALUE: true if VALUE is a generation as aios.gen= carries it (4 digits, not 0000).
is_gen() {
    case "$1" in
        0000) return 1 ;;
        [0-9][0-9][0-9][0-9]) return 0 ;;
        *) return 1 ;;
    esac
}

# strip_zeros DIGITS: "0007" -> "7", "0000" -> "0".
strip_zeros() {
    n=$1
    while [ "${n#0}" != "$n" ] && [ -n "${n#0}" ]; do
        n=${n#0}
    done
    printf '%s\n' "$n"
}

[ -r "$CMDLINE_FILE" ] || fail "cannot read $CMDLINE_FILE"
cmdline=$(cat "$CMDLINE_FILE")
gen=""
forced=no
set -f
for arg in $cmdline; do
    case "$arg" in
        aios.gen=*)
            # Like gen_from_cmdline in aios-gen: one invalid value means no generation.
            value="${arg#aios.gen=}"
            is_gen "$value" || fail "no generation on cmdline"
            if [ -n "$gen" ] && [ "$gen" != "$value" ]; then
                fail "conflicting aios.gen= values on cmdline"
            fi
            gen="$value"
            ;;
        aios.test.fail_health=1) forced=yes ;;
    esac
done
set +f

[ "$forced" = no ] || fail "forced failure (aios.test.fail_health=1 on the cmdline)"

[ -n "$gen" ] || fail "no generation on cmdline"

# -M matches the mount point exactly; -f takes the first mount there, so a mount stacked
# on top cannot turn the options into several lines that never match.
usr_opts=$("$FINDMNT" -fno OPTIONS -M /usr) || fail "/usr is not mounted"
has_opt "$usr_opts" ro || fail "/usr is not mounted read-only ($usr_opts)"
has_opt "$usr_opts" "subvol=/@usr-gen-$gen" ||
    fail "/usr is not subvolume @usr-gen-$gen ($usr_opts)"

etc_opts=$("$FINDMNT" -fno OPTIONS -M /etc) || fail "/etc is not mounted"
has_opt "$etc_opts" "subvol=/@etc-live" || fail "/etc is not subvolume @etc-live ($etc_opts)"

for mountpoint in /persist /home /var/log; do
    "$FINDMNT" -n "$mountpoint" >/dev/null || fail "$mountpoint is not mounted"
done

[ -r "$GEN_FILE" ] || fail "cannot read $GEN_FILE"
id=$(sed -n 's/^id[[:space:]]*=[[:space:]]*\([0-9][0-9]*\)[[:space:]]*$/\1/p' "$GEN_FILE" | head -n 1)
[ -n "$id" ] || fail "no id in $GEN_FILE"
[ "$(strip_zeros "$id")" = "$(strip_zeros "$gen")" ] ||
    fail "$GEN_FILE has id $id but the cmdline says aios.gen=$gen"

printf 'aios-health: generation %s is healthy\n' "$gen"
