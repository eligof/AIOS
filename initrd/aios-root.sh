#!/bin/sh
# aios-root.sh: runs in the initrd via aios-root.service, before sysroot.mount (spec §3 step 6).
# Recreates @root-live from @blank and @etc-live from @etc-gen-N for the generation named by
# aios.gen=N, after deleting stale live subvolumes and leftover apply candidates.
# Needs only sh, cat and mkdir (busybox from the base hook), mount and umount, and btrfs.
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

# is_gen VALUE: true if VALUE is a generation as aios.gen= carries it (4 digits, not 0000).
is_gen() {
    case "$1" in
        0000) return 1 ;;
        [0-9][0-9][0-9][0-9]) return 0 ;;
        *) return 1 ;;
    esac
}

# Print the 4-digit generation from aios.gen=, or fail. Like gen_from_cmdline in aios-gen,
# every aios.gen= value must be a valid generation and all of them must agree.
generation_from_cmdline() {
    [ -r "$CMDLINE_FILE" ] || die "cannot read $CMDLINE_FILE"
    cmdline=$(cat "$CMDLINE_FILE")
    found=""
    set -f
    for arg in $cmdline; do
        case "$arg" in
            aios.gen=*)
                value="${arg#aios.gen=}"
                is_gen "$value" || die "no generation on cmdline"
                if [ -n "$found" ] && [ "$found" != "$value" ]; then
                    die "conflicting aios.gen= values on cmdline"
                fi
                found="$value"
                ;;
        esac
    done
    set +f
    [ -n "$found" ] || die "no generation on cmdline"
    printf '%s\n' "$found"
}

# delete_subvol NAME: delete the subvolume $TOP/NAME, if present, with every subvolume
# nested inside it (systemd creates /var/lib/machines and /var/lib/portables as subvolumes
# inside @root-live). btrfs walks the nesting itself; subvolume names are never parsed,
# so a nested subvolume named "x @home" cannot make this delete @home. Anything at NAME
# that is not a subvolume stops the boot rather than being guessed at. That includes a
# symlink, even a dangling one: btrfs resolves the path, so it would delete the target.
# The body is a subshell so its variables stay local.
delete_subvol() (
    target="$TOP/$1"
    if [ -L "$target" ]; then
        die "$1 is a symlink, not a subvolume"
    fi
    [ -e "$target" ] || exit 0
    btrfs subvolume show "$target" >/dev/null || die "$1 exists but is not a subvolume"
    log "deleting $1"
    btrfs subvolume delete --recursive "$target" >/dev/null
)

# On every exit once mounted. A failed unmount is retried lazily, so the top level does
# not stay reachable under /run, which survives switch-root.
unmount_top() {
    if ! umount "$TOP"; then
        log "warning: could not unmount $TOP, retrying with umount -l"
        umount -l "$TOP" || log "warning: umount -l $TOP failed too"
    fi
}

gen=$(generation_from_cmdline)
log "preparing generation $gen"

mkdir -p "$TOP"
mount -t btrfs -o subvolid=5 "$DEVICE" "$TOP"
trap unmount_top EXIT

# A symlink at a generation's name or at @blank (even a dangling one) stops the boot:
# btrfs resolves the path, so it would boot or copy another subvolume's content.
for name in "@usr-gen-$gen" "@etc-gen-$gen" @blank; do
    if [ -L "$TOP/$name" ]; then
        die "$name is a symlink, not a subvolume"
    fi
done
if [ ! -d "$TOP/@usr-gen-$gen" ] || [ ! -d "$TOP/@etc-gen-$gen" ]; then
    die "generation $gen missing — pick another boot entry"
fi
# Checked before anything is deleted: without @blank there is no root to rebuild.
btrfs subvolume show "$TOP/@blank" >/dev/null 2>&1 || die "@blank missing — reinstall required"

for stale in @root-live @etc-live @usr-cand @etc-cand @root-cand; do
    delete_subvol "$stale"
done

log "snapshot @blank -> @root-live"
btrfs subvolume snapshot "$TOP/@blank" "$TOP/@root-live"
log "snapshot @etc-gen-$gen -> @etc-live"
btrfs subvolume snapshot "$TOP/@etc-gen-$gen" "$TOP/@etc-live"
log "generation $gen ready"
