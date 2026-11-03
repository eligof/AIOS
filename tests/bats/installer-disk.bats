#!/usr/bin/env bats
# installer/lib/disk.sh, cpu.sh and network.sh: target disk validation, x86-64-v3 detection,
# the pacman.conf v3 strip and the network check (spec §6.2 steps 1-3, §9).
# Literal $ in single quotes is test data (mirrorlists).
# shellcheck disable=SC2016

setup() {
    LIB="$BATS_TEST_DIRNAME/../../installer/lib"
    # shellcheck source=/dev/null
    source "$LIB/common.sh"
    # shellcheck source=/dev/null
    source "$LIB/disk.sh"
    # shellcheck source=/dev/null
    source "$LIB/cpu.sh"
    # shellcheck source=/dev/null
    source "$LIB/network.sh"
    BIN="$BATS_TEST_TMPDIR/bin"
    mkdir -p "$BIN"
    ln -s "$BATS_TEST_DIRNAME/fakes/installer" "$BIN/lsblk"
    ln -s "$BATS_TEST_DIRNAME/fakes/installer" "$BIN/findmnt"
    ln -s "$BATS_TEST_DIRNAME/fakes/installer" "$BIN/curl"
    ln -s "$BATS_TEST_DIRNAME/fakes/record" "$BIN/udevadm"
    PATH="$BIN:$PATH"
    export FAKE_SYS="$BATS_TEST_TMPDIR/sys" CALLS="$BATS_TEST_TMPDIR/calls"
    export AIOS_SYS_BLOCK="$BATS_TEST_TMPDIR/sysfs"
    mkdir -p "$FAKE_SYS" "$AIOS_SYS_BLOCK"
    : >"$CALLS"
    GIB=$((1024 * 1024 * 1024))
    blk vda disk $((20 * GIB)) 0 ""
    blk sr0 rom $((1 * GIB)) 1 "/run/archiso/bootmnt"
    live /dev/sr0
    PACMAN_CONF="$BATS_TEST_DIRNAME/../../manifest/files/pacman.conf"
    export AIOS_CACHYOS_MIRRORLIST="$BATS_TEST_TMPDIR/cachyos-mirrorlist"
    printf '%s\n' '## CachyOS mirrors' '# Server = https://old.example/repo/$arch/$repo' '' \
        'Server = https://cdn77.cachyos.org/repo/$arch/$repo' \
        'Server = https://mirror.cachyos.org/repo/$arch/$repo' >"$AIOS_CACHYOS_MIRRORLIST"
    ARCH_PROBE="curl -fsI --max-time 20 --retry 3 --retry-connrefused https://geo.mirror.pkgbuild.com"
    CACHY_PROBE="curl -fsI --max-time 20 --retry 3 --retry-connrefused https://cdn77.cachyos.org/repo/x86_64/cachyos/cachyos.db"
}

# blk NAME TYPE SIZE RO MOUNTPOINTS: a fake block device /dev/NAME with nothing on it: lsblk
# answers for it (also its tree, and with -s its stack, both just itself), and sysfs has its
# diskseq and an empty holders/.
blk() {
    local d="$FAKE_SYS/blk/$1"
    mkdir -p "$d" "$AIOS_SYS_BLOCK/$1/holders"
    printf '%s\n' "$2" >"$d/TYPE"
    printf '%s\n' "$3" >"$d/SIZE"
    printf '%s\n' "$4" >"$d/RO"
    printf '%s\n' "$5" >"$d/MOUNTPOINTS"
    printf '%s %s\n' "$1" "$2" >"$d/NAME,TYPE"
    printf '%s %s\n' "$1" "$2" >"$d/NAME,TYPE.inverse"
    printf 'QEMU HARDDISK\n' >"$d/MODEL"
    printf '\n' >"$d/SERIAL"
    echo 9 >"$AIOS_SYS_BLOCK/$1/diskseq"
}

# part DISK NAME [MOUNTPOINTS]: partition NAME of DISK.
part() {
    blk "$2" part $((2 * GIB)) 0 "${3:-}"
    printf '%s part\n' "$2" >>"$FAKE_SYS/blk/$1/NAME,TYPE"
    printf '%s disk\n' "$1" >>"$FAKE_SYS/blk/$2/NAME,TYPE.inverse"
    mkdir -p "$AIOS_SYS_BLOCK/$1/$2/holders"
}

# live SOURCE: the archiso boot medium is mounted from SOURCE.
live() {
    mkdir -p "$FAKE_SYS/mnt/run/archiso"
    printf '%s\n' "$1" >"$FAKE_SYS/mnt/run/archiso/bootmnt"
}

# ldso OUTPUT: a fake dynamic loader whose --help prints OUTPUT.
ldso() {
    export AIOS_LDSO="$BATS_TEST_TMPDIR/ld.so"
    printf '#!/bin/sh\ncat <<"EOF"\n%s\nEOF\n' "$1" >"$AIOS_LDSO"
    chmod +x "$AIOS_LDSO"
}

@test "partition names follow the kernel's naming" {
    [ "$(part_path /dev/vda 1)" = /dev/vda1 ]
    [ "$(part_path /dev/sda 2)" = /dev/sda2 ]
    [ "$(part_path /dev/nvme0n1 1)" = /dev/nvme0n1p1 ]
    [ "$(part_path /dev/mmcblk0 2)" = /dev/mmcblk0p2 ]
}

@test "a whole, unmounted 20 GiB disk is accepted" {
    run validate_disk /dev/vda

    [ "$status" -eq 0 ]
    [ "$output" = "" ]
}

@test "partitions, optical drives and missing devices are refused" {
    part vda vda1

    run validate_disk /dev/vda1
    [ "$status" -eq 1 ]
    [ "$output" = "aios-install: error: /dev/vda1 is a part, not a whole disk" ]

    run validate_disk /dev/sr0
    [ "$status" -eq 1 ]

    run validate_disk /dev/vdz
    [ "$status" -eq 1 ]
    [ "$output" = "aios-install: error: /dev/vdz is not a block device" ]
}

@test "the disk holding the live medium is refused" {
    blk sdb disk $((32 * GIB)) 0 ""
    live /dev/sdb1
    part sdb sdb1 /run/archiso/bootmnt

    run validate_disk /dev/sdb

    [ "$status" -eq 1 ]
    [ "$output" = "aios-install: error: /dev/sdb holds the live medium this system booted from" ]
}

@test "a live medium written to the whole disk is refused too" {
    blk sdc disk $((32 * GIB)) 0 ""
    live /dev/sdc

    run validate_disk /dev/sdc

    [ "$status" -eq 1 ]
    [[ "$output" == *"holds the live medium"* ]]
}

@test "a live medium on a device-mapper target (Ventoy) is traced down to its disk" {
    blk sdd disk $((32 * GIB)) 0 ""
    part sdd sdd1
    mkdir -p "$FAKE_SYS/blk/mapper/ventoy"
    printf '%s\n' "ventoy dm" "sdd1 part" "sdd disk" >"$FAKE_SYS/blk/mapper/ventoy/NAME,TYPE.inverse"
    live /dev/mapper/ventoy

    run validate_disk /dev/sdd

    [ "$status" -eq 1 ]
    [ "$output" = "aios-install: error: /dev/sdd holds the live medium this system booted from" ]
    [ "$(live_medium_disks)" = /dev/sdd ]
    grep -qx 'lsblk -nrso NAME,TYPE /dev/mapper/ventoy' "$CALLS"
}

@test "without a live medium device (copytoram, PXE) every disk may be used" {
    rm "$FAKE_SYS/mnt/run/archiso/bootmnt"

    [ -z "$(live_medium_disks)" ]
    run validate_disk /dev/vda
    [ "$status" -eq 0 ]
}

@test "a live medium mounted twice is traced from every source" {
    blk sdb disk $((32 * GIB)) 0 ""
    part sdb sdb1
    printf '%s\n' /dev/sr0 /dev/sdb1 >"$FAKE_SYS/mnt/run/archiso/bootmnt"

    run validate_disk /dev/sdb

    [ "$status" -eq 1 ]
    [[ "$output" == *"/dev/sdb holds the live medium"* ]]
}

@test "a disk whose mount points cannot be listed is refused" {
    rm "$FAKE_SYS/blk/vda/MOUNTPOINTS"

    run validate_disk /dev/vda

    [ "$status" -eq 1 ]
    [[ "$output" == *"error: cannot list the mount points on /dev/vda"* ]]
}

@test "a disk with mounted filesystems is refused" {
    blk vdb disk $((20 * GIB)) 0 "$(printf '\n/mnt/data\n')"

    run validate_disk /dev/vdb

    [ "$status" -eq 1 ]
    [[ "$output" == *"/dev/vdb has mounted filesystems: "*"/mnt/data"* ]]
}

@test "read-only and small disks are refused" {
    blk vdc disk $((20 * GIB)) 1 ""
    run validate_disk /dev/vdc
    [ "$status" -eq 1 ]
    [ "$output" = "aios-install: error: /dev/vdc is read-only" ]

    blk vdd disk $((8 * GIB)) 0 ""
    run validate_disk /dev/vdd
    [ "$status" -eq 1 ]
    [ "$output" = "aios-install: error: /dev/vdd has 8 GiB, AIOS needs at least 16 GiB" ]
}

@test "a disk with LVM, MD RAID or dm-crypt on it is refused" {
    blk vdb disk $((20 * GIB)) 0 ""
    part vdb vdb1
    printf '%s\n' "vg0-root lvm" >>"$FAKE_SYS/blk/vdb/NAME,TYPE"

    run validate_disk /dev/vdb

    [ "$status" -eq 1 ]
    [ "$output" = "aios-install: error: /dev/vdb is in use by vg0-root (LVM/MD/dm); deactivate it first" ]
}

@test "a sysfs holder of the disk or of a partition is refused too" {
    blk vdb disk $((20 * GIB)) 0 ""
    mkdir "$AIOS_SYS_BLOCK/vdb/holders/dm-3"
    run validate_disk /dev/vdb
    [ "$status" -eq 1 ]
    [ "$output" = "aios-install: error: /dev/vdb is in use by dm-3 (LVM/MD/dm); deactivate it first" ]

    blk nvme0n1 disk $((20 * GIB)) 0 ""
    part nvme0n1 nvme0n1p1
    part nvme0n1 nvme0n1p2
    ln -s ../../md127 "$AIOS_SYS_BLOCK/nvme0n1/nvme0n1p2/holders/md127"
    run validate_disk /dev/nvme0n1
    [ "$status" -eq 1 ]
    [ "$output" = "aios-install: error: /dev/nvme0n1 is in use by md127 (LVM/MD/dm); deactivate it first" ]
}

@test "plain partitions are no reason to refuse a disk" {
    part vda vda1
    part vda vda2

    run validate_disk /dev/vda

    [ "$status" -eq 0 ]
}

@test "validation records the disk's identity for the confirmation" {
    printf 'Samsung SSD 990 PRO 1TB   \n' >"$FAKE_SYS/blk/vda/MODEL"
    printf 'S6Z1NJ0W\n' >"$FAKE_SYS/blk/vda/SERIAL"
    echo 42 >"$AIOS_SYS_BLOCK/vda/diskseq"

    validate_disk /dev/vda

    [ "$DISK_SEQ" = 42 ]
    [ "$(disk_identity)" = "model Samsung SSD 990 PRO 1TB, serial S6Z1NJ0W, 20 GiB (21474836480 bytes), diskseq 42" ]
    blk vdb disk $((20 * GIB)) 0 ""
    printf '\n' >"$FAKE_SYS/blk/vdb/MODEL"
    validate_disk /dev/vdb
    [ "$(disk_identity)" = "model unknown, serial unknown, 20 GiB (21474836480 bytes), diskseq 9" ]
}

@test "a disk without a readable diskseq is refused" {
    rm "$AIOS_SYS_BLOCK/vda/diskseq"

    run validate_disk /dev/vda

    [ "$status" -eq 1 ]
    [[ "$output" == *"cannot read the disk sequence number of /dev/vda"* ]]
}

@test "a different disk under the same name is noticed before the wipe" {
    disk_unchanged /dev/vda 9

    echo 10 >"$AIOS_SYS_BLOCK/vda/diskseq"
    run disk_unchanged /dev/vda 9
    [ "$status" -eq 1 ]
    [ "$output" = "aios-install: error: /dev/vda: disk changed since validation (diskseq 9, now 10)" ]

    rm "$AIOS_SYS_BLOCK/vda/diskseq"
    run disk_unchanged /dev/vda 9
    [ "$status" -eq 1 ]
    [[ "$output" == *"disk changed since validation (diskseq 9, now none)"* ]]
}

@test "a busy partition table re-read (udev still probing) is retried" {
    # This blockdev fails once, like BLKRRPART while udev's blkid has a partition open.
    printf '#!/bin/sh\necho "blockdev $*" >>"$CALLS"\n[ -e "%s" ] && exit 0\n: >"%s"\nexit 1\n' \
        "$BATS_TEST_TMPDIR/tried" "$BATS_TEST_TMPDIR/tried" >"$BIN/blockdev"
    chmod +x "$BIN/blockdev"

    run reread_partitions /dev/vda

    [ "$status" -eq 0 ]
    [ "$(paste -sd'|' "$CALLS")" = "blockdev --rereadpt /dev/vda|udevadm settle|blockdev --rereadpt /dev/vda" ]

    # It gives up after five tries.
    export AIOS_INSTALL_DRYRUN=1 AIOS_INSTALL_DRYRUN_FAILS="$BATS_TEST_TMPDIR/fails"
    echo "blockdev --rereadpt /dev/vda" >"$AIOS_INSTALL_DRYRUN_FAILS"
    run reread_partitions /dev/vda
    [ "$status" -eq 1 ]
    [ "$(grep -c '^DRYRUN blockdev --rereadpt /dev/vda$' <<<"$output")" -eq 5 ]
}

@test "after partitioning the disk must have exactly the two new partitions" {
    part vda vda1
    part vda vda2
    check_partitions /dev/vda

    part vda vda3
    run check_partitions /dev/vda
    [ "$status" -eq 1 ]
    [ "$output" = "aios-install: error: /dev/vda should now have exactly the partitions /dev/vda1 /dev/vda2, but has: /dev/vda1 /dev/vda2 /dev/vda3" ]

    blk nvme0n1 disk $((20 * GIB)) 0 ""
    part nvme0n1 nvme0n1p1
    run check_partitions /dev/nvme0n1
    [ "$status" -eq 1 ]
    [[ "$output" == *"exactly the partitions /dev/nvme0n1p1 /dev/nvme0n1p2, but has: /dev/nvme0n1p1" ]]
    part nvme0n1 nvme0n1p2
    check_partitions /dev/nvme0n1

    blk vdb disk $((20 * GIB)) 0 ""
    run check_partitions /dev/vdb
    [[ "$output" == *"but has: none" ]]
}

@test "the network check asks Arch's mirror and the first CachyOS mirror, failing on HTTP errors" {
    run check_network

    [ "$status" -eq 0 ]
    [ "$(cat "$CALLS")" = "$ARCH_PROBE"$'\n'"$CACHY_PROBE" ]
}

@test "an unreachable Arch or CachyOS mirror fails the network check" {
    echo https://cdn77.cachyos.org/repo/x86_64/cachyos/cachyos.db >"$FAKE_SYS/curl.fail"
    run check_network
    [ "$status" -eq 1 ]
    [ "$output" = "aios-install: error: the CachyOS mirror https://cdn77.cachyos.org/repo/x86_64/cachyos/cachyos.db is unreachable (the first Server in $AIOS_CACHYOS_MIRRORLIST)" ]

    echo https://geo.mirror.pkgbuild.com >"$FAKE_SYS/curl.fail"
    : >"$CALLS"
    run check_network
    [ "$status" -eq 1 ]
    [ "$output" = "aios-install: error: no network: https://geo.mirror.pkgbuild.com is unreachable (Wi-Fi: iwctl)" ]
    [ "$(cat "$CALLS")" = "$ARCH_PROBE" ]
}

@test "a CachyOS mirrorlist without an https Server fails the network check" {
    printf '%s\n' '# Server = https://x.example/$arch/$repo' 'Server = http://plain.example/$arch/$repo' \
        >"$AIOS_CACHYOS_MIRRORLIST"
    run check_network
    [ "$status" -eq 1 ]
    [ "$output" = "aios-install: error: no https Server line in $AIOS_CACHYOS_MIRRORLIST" ]

    rm "$AIOS_CACHYOS_MIRRORLIST"
    run check_network
    [ "$status" -eq 1 ]
    [ "$output" = "aios-install: error: no https Server line in $AIOS_CACHYOS_MIRRORLIST" ]
}

@test "x86-64-v3 is detected from the loader's hwcaps list" {
    ldso "$(printf 'Subdirectories of glibc-hwcaps directories, in priority order:\n  x86-64-v4\n  x86-64-v3 (supported, searched)\n  x86-64-v2 (supported, searched)')"
    cpu_supports_v3

    ldso "$(printf 'Subdirectories of glibc-hwcaps directories, in priority order:\n  x86-64-v4 (supported, searched)\n  x86-64-v3 (supported, searched)\n  x86-64-v2 (supported, searched)')"
    cpu_supports_v3
}

@test "a v2-only CPU, odd output or a failing loader count as no v3" {
    ldso "$(printf 'Subdirectories of glibc-hwcaps directories, in priority order:\n  x86-64-v4\n  x86-64-v3\n  x86-64-v2 (supported, searched)')"
    run cpu_supports_v3
    [ "$status" -eq 1 ]

    ldso "  x86-64-v3 (supported, searched) maybe"
    run cpu_supports_v3
    [ "$status" -eq 1 ]

    export AIOS_LDSO=/bin/false
    run cpu_supports_v3
    [ "$status" -eq 1 ]
}

@test "the host's real loader answers (either way)" {
    [ -x /lib/ld-linux-x86-64.so.2 ] || skip "no /lib/ld-linux-x86-64.so.2"
    unset AIOS_LDSO
    run cpu_supports_v3
    [ "$status" -eq 0 ] || [ "$status" -eq 1 ]
}

@test "strip_v3 removes the v3 architecture and repos from the default pacman.conf" {
    run strip_v3 <"$PACMAN_CONF"

    [ "$status" -eq 0 ]
    [ "$(grep -c -e x86_64_v3 -e cachyos-v3-mirrorlist -e '^# BEGIN v3$' -e '^# END v3$' <<<"$output")" -eq 0 ]
    [ "$(grep '^\[' <<<"$output" | paste -sd' ')" = "[options] [cachyos] [core] [extra] [aios-local]" ]
    [ "$(grep -c '^Architecture = x86_64$' <<<"$output")" -eq 1 ]
    [ "$(diff <(strip_v3 <"$PACMAN_CONF") <(sed '/^# BEGIN v3$/,/^# END v3$/d' "$PACMAN_CONF") && echo same)" = same ]
}

@test "pacman reads the stripped config as generic x86_64 (if pacman-conf is installed)" {
    command -v pacman-conf >/dev/null || skip "pacman-conf not installed"
    mkdir -p "$BATS_TEST_TMPDIR/db"
    strip_v3 <"$PACMAN_CONF" | sed "s|^DBPath .*|DBPath = $BATS_TEST_TMPDIR/db/|" >"$BATS_TEST_TMPDIR/generic.conf"

    [ "$(pacman-conf -c "$BATS_TEST_TMPDIR/generic.conf" Architecture)" = x86_64 ]
    [ "$(pacman-conf -c "$BATS_TEST_TMPDIR/generic.conf" --repo-list | paste -sd' ')" = "cachyos core extra aios-local" ]
}

@test "unbalanced v3 markers fail instead of dropping the rest of the file" {
    run strip_v3 <<<"$(printf 'a\n# BEGIN v3\nb\n')"
    [ "$status" -eq 1 ]
    [[ "$output" == *"# BEGIN v3 is never closed"* ]]

    run strip_v3 <<<"$(printf 'a\n# END v3\nb\n')"
    [ "$status" -eq 1 ]
    [[ "$output" == *"line 2: # END v3 without # BEGIN v3"* ]]

    run strip_v3 <<<"$(printf '# BEGIN v3\n# BEGIN v3\n# END v3\n')"
    [ "$status" -eq 1 ]
    [[ "$output" == *"line 2: nested # BEGIN v3"* ]]
}
