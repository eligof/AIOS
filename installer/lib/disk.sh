# shellcheck shell=bash
# disk.sh: the target disk (spec §6.2 steps 1-3).
#
# Environment overrides (tests only):
#   AIOS_LIVE_MNT   where archiso mounts the boot medium (default /run/archiso/bootmnt)
#   AIOS_SYS_BLOCK  the sysfs block device directory (default /sys/class/block)

AIOS_MIN_DISK_BYTES=$((16 * 1024 * 1024 * 1024))
# What validate_disk saw: shown before the wipe, and the diskseq checked again right before it.
DISK_SEQ=""
DISK_SIZE=0
DISK_MODEL=""
DISK_SERIAL=""

# part_path DISK N: partition N of DISK (/dev/vda -> /dev/vda1, /dev/nvme0n1 -> /dev/nvme0n1p1).
part_path() {
    if [[ $1 =~ [0-9]$ ]]; then
        printf '%sp%s\n' "$1" "$2"
    else
        printf '%s%s\n' "$1" "$2"
    fi
}

# live_medium_disks: the whole disks below the live system's boot medium, one per line. The
# device stack is walked down (lsblk -s), so a partition, or a device-mapper target such as
# Ventoy's, leads to its disk. Prints the medium itself when no disk is below it (a CD-ROM),
# and nothing when there is no medium device (copytoram, PXE).
live_medium_disks() {
    local src disks
    src=$(findmnt -nro SOURCE "${AIOS_LIVE_MNT:-/run/archiso/bootmnt}") || return 0
    [[ -n $src ]] || return 0
    disks=$(lsblk -nrso NAME,TYPE "$src" 2>/dev/null | awk '$2 == "disk" { print "/dev/" $1 }') ||
        disks=""
    printf '%s\n' "${disks:-$src}"
}

# disk_holder DISK: a device that sits on DISK or one of its partitions (LVM, MD RAID,
# dm-crypt, multipath), or nothing. Both lsblk's tree and the sysfs holders/ directories
# count. Fails if lsblk does.
disk_holder() {
    local disk=$1 name=${1##*/} sys=${AIOS_SYS_BLOCK:-/sys/class/block} child h
    child=$(lsblk -nro NAME,TYPE "$disk" | awk 'NR > 1 && $2 != "part" && !found++ { print $1 }') ||
        return 1
    if [[ -n $child ]]; then
        printf '%s\n' "$child"
        return 0
    fi
    for h in "$sys/$name"/holders/* "$sys/$name/$name"*/holders/*; do
        if [[ -e $h || -L $h ]]; then
            printf '%s\n' "${h##*/}"
            return 0
        fi
    done
}

# disk_seq DISK: the kernel's sequence number for DISK. A different disk (or medium) that
# appears under the same name gets a new one.
disk_seq() {
    local seq
    { read -r seq <"${AIOS_SYS_BLOCK:-/sys/class/block}/${1##*/}/diskseq"; } 2>/dev/null || return 1
    [[ $seq =~ ^[0-9]+$ ]] || return 1
    printf '%s\n' "$seq"
}

# lsblk_value COLUMN DISK: one lsblk column of DISK, without surrounding blanks.
lsblk_value() {
    local value=""
    read -r value < <(lsblk -ndo "$1" "$2" 2>/dev/null) || true
    printf '%s\n' "$value"
}

# validate_disk DISK: DISK is a whole, writable disk of at least 16 GiB that holds neither
# the live medium, nor any mounted filesystem, nor anything else in use (LVM, MD, dm).
# Records its diskseq, size, model and serial in DISK_SEQ, DISK_SIZE, DISK_MODEL and
# DISK_SERIAL.
validate_disk() {
    local disk=$1 type ro size mounts holder
    if ! type=$(lsblk -ndro TYPE "$disk" 2>/dev/null); then
        log "error: $disk is not a block device"
        return 1
    fi
    if [[ $type != disk ]]; then
        log "error: $disk is a $type, not a whole disk"
        return 1
    fi
    if grep -qxF -- "$disk" <<<"$(live_medium_disks)"; then
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
    if ! holder=$(disk_holder "$disk"); then
        log "error: cannot list the devices on $disk"
        return 1
    fi
    if [[ -n $holder ]]; then
        log "error: $disk is in use by $holder (LVM/MD/dm); deactivate it first"
        return 1
    fi
    size=$(lsblk -ndbro SIZE "$disk")
    if ((size < AIOS_MIN_DISK_BYTES)); then
        log "error: $disk has $((size / 1024 / 1024 / 1024)) GiB, AIOS needs at least 16 GiB"
        return 1
    fi
    if ! DISK_SEQ=$(disk_seq "$disk"); then
        log "error: cannot read the disk sequence number of $disk" \
            "(${AIOS_SYS_BLOCK:-/sys/class/block}/${disk##*/}/diskseq)"
        return 1
    fi
    DISK_SIZE=$size
    DISK_MODEL=$(lsblk_value MODEL "$disk")
    DISK_SERIAL=$(lsblk_value SERIAL "$disk")
}

# disk_identity: what validate_disk recorded, for the confirmation.
disk_identity() {
    printf 'model %s, serial %s, %s GiB (%s bytes), diskseq %s\n' "${DISK_MODEL:-unknown}" \
        "${DISK_SERIAL:-unknown}" "$((DISK_SIZE / 1024 / 1024 / 1024))" "$DISK_SIZE" "$DISK_SEQ"
}

# disk_unchanged DISK SEQ: DISK still has the diskseq SEQ that validate_disk recorded.
disk_unchanged() {
    local now
    now=$(disk_seq "$1") || now=none
    if [[ $now != "$2" ]]; then
        log "error: $1: disk changed since validation (diskseq $2, now $now)"
        return 1
    fi
}

# check_partitions DISK: after partitioning, DISK has exactly its partitions 1 and 2.
check_partitions() {
    local disk=$1 parts want has
    parts=$(lsblk -nro NAME,TYPE "$disk" | awk '$2 == "part" { print "/dev/" $1 }') || parts=""
    want=$(part_path "$disk" 1 && part_path "$disk" 2)
    if [[ $parts != "$want" ]]; then
        has=${parts//$'\n'/ }
        log "error: $disk should now have exactly the partitions ${want//$'\n'/ }," \
            "but has: ${has:-none}"
        return 1
    fi
}
