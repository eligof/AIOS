# shellcheck shell=bash
# disk.sh: the target disk (spec §6.2 steps 1 and 3).
#
# Environment overrides (tests only):
#   AIOS_LIVE_MNT  where archiso mounts the boot medium (default /run/archiso/bootmnt)

AIOS_MIN_DISK_BYTES=$((16 * 1024 * 1024 * 1024))

# part_path DISK N: partition N of DISK (/dev/vda -> /dev/vda1, /dev/nvme0n1 -> /dev/nvme0n1p1).
part_path() {
    if [[ $1 =~ [0-9]$ ]]; then
        printf '%sp%s\n' "$1" "$2"
    else
        printf '%s%s\n' "$1" "$2"
    fi
}

# live_medium_disk: the whole disk the live system booted from, or nothing (copytoram, PXE).
live_medium_disk() {
    local src parent
    src=$(findmnt -nro SOURCE "${AIOS_LIVE_MNT:-/run/archiso/bootmnt}") || return 0
    [[ -n $src ]] || return 0
    parent=$(lsblk -ndro PKNAME "$src" 2>/dev/null) || parent=""
    if [[ -n $parent ]]; then
        printf '/dev/%s\n' "$parent"
    else
        printf '%s\n' "$src"
    fi
}

# validate_disk DISK: DISK is a whole, writable disk of at least 16 GiB that holds neither
# the live medium nor any mounted filesystem.
validate_disk() {
    local disk=$1 type ro size mounts
    if ! type=$(lsblk -ndro TYPE "$disk" 2>/dev/null); then
        log "error: $disk is not a block device"
        return 1
    fi
    if [[ $type != disk ]]; then
        log "error: $disk is a $type, not a whole disk"
        return 1
    fi
    if [[ $disk == "$(live_medium_disk)" ]]; then
        log "error: $disk holds the live medium this system booted from"
        return 1
    fi
    ro=$(lsblk -ndro RO "$disk")
    if [[ $ro != 0 ]]; then
        log "error: $disk is read-only"
        return 1
    fi
    mounts=$(lsblk -nro MOUNTPOINTS "$disk")
    if [[ -n ${mounts//[[:space:]]/} ]]; then
        log "error: $disk has mounted filesystems: $(printf '%s' "$mounts" | tr -s '\n' ' ')"
        return 1
    fi
    size=$(lsblk -ndbro SIZE "$disk")
    if ((size < AIOS_MIN_DISK_BYTES)); then
        log "error: $disk has $((size / 1024 / 1024 / 1024)) GiB, AIOS needs at least 16 GiB"
        return 1
    fi
}
