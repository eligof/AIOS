#!/bin/sh
# aios-root.sh: runs in the initrd via aios-root.service, before sysroot.mount (spec §3 step 6).
# Recreates @root-live from @blank and @etc-live from @etc-gen-N for the generation named by
# aios.gen=N, after deleting stale live subvolumes and leftover apply candidates.
#
# Environment overrides (tests only):
#   AIOS_CMDLINE_FILE  kernel cmdline        (default /proc/cmdline)
#   AIOS_DEVICE        unlocked LUKS device  (default /dev/mapper/aios)
#   AIOS_TOP           btrfs top-level mount (default /run/aios/top)
set -eu

CMDLINE_FILE="${AIOS_CMDLINE_FILE:-/proc/cmdline}"
DEVICE="${AIOS_DEVICE:-/dev/mapper/aios}"
TOP="${AIOS_TOP:-/run/aios/top}"

log() {
    printf 'aios: %s\n' "$*" >&2
}

die() {
    log "$*"
    exit 1
}

# Print the 4-digit generation from aios.gen= (repeats must agree), or fail.
generation_from_cmdline() {
    [ -r "$CMDLINE_FILE" ] || die "cannot read $CMDLINE_FILE"
    cmdline=$(cat "$CMDLINE_FILE")
    found=""
    set -f
    for arg in $cmdline; do
        case "$arg" in
            aios.gen=*)
                value="${arg#aios.gen=}"
                if [ -n "$found" ] && [ "$found" != "$value" ]; then
                    set +f
                    die "conflicting aios.gen= values on cmdline"
                fi
                found="$value"
                ;;
        esac
    done
    set +f
    case "$found" in
        0000) die "no generation on cmdline" ;;
        [0-9][0-9][0-9][0-9]) printf '%s\n' "$found" ;;
        *) die "no generation on cmdline" ;;
    esac
}

# delete_subvol NAME: delete $TOP/NAME (if present) and every subvolume nested inside it.
# `btrfs subvolume list -o` prints paths relative to the top level in its last field.
# Children are handled deepest first (`sort -r`), recursively, because btrfs refuses to
# delete a subvolume that still contains another one (systemd creates
# /var/lib/machines and /var/lib/portables as subvolumes inside @root-live).
# The body is a subshell so the recursion's variables stay local.
delete_subvol() (
    target="$TOP/$1"
    [ -d "$target" ] || exit 0
    btrfs subvolume list -o "$target" | awk '{ print $NF }' | sort -r |
        while IFS= read -r nested; do
            if [ -n "$nested" ]; then
                delete_subvol "$nested"
            fi
        done
    log "deleting $1"
    btrfs subvolume delete "$target"
)

gen=$(generation_from_cmdline)
log "preparing generation $gen"

mkdir -p "$TOP"
mount -t btrfs -o subvolid=5 "$DEVICE" "$TOP"
trap 'umount "$TOP" || log "warning: could not unmount $TOP"' EXIT

if [ ! -d "$TOP/@usr-gen-$gen" ] || [ ! -d "$TOP/@etc-gen-$gen" ]; then
    die "generation $gen missing — pick another boot entry"
fi

for stale in @root-live @etc-live @usr-cand @etc-cand @root-cand; do
    delete_subvol "$stale"
done

log "snapshot @blank -> @root-live"
btrfs subvolume snapshot "$TOP/@blank" "$TOP/@root-live"
log "snapshot @etc-gen-$gen -> @etc-live"
btrfs subvolume snapshot "$TOP/@etc-gen-$gen" "$TOP/@etc-live"
log "generation $gen ready"
