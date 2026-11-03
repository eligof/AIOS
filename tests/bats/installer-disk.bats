#!/usr/bin/env bats
# installer/lib/disk.sh and cpu.sh: target disk validation, x86-64-v3 detection and the
# pacman.conf v3 strip (spec §6.2 steps 1 and 3, §9).

setup() {
    LIB="$BATS_TEST_DIRNAME/../../installer/lib"
    # shellcheck source=/dev/null
    source "$LIB/common.sh"
    # shellcheck source=/dev/null
    source "$LIB/disk.sh"
    # shellcheck source=/dev/null
    source "$LIB/cpu.sh"
    BIN="$BATS_TEST_TMPDIR/bin"
    mkdir -p "$BIN"
    ln -s "$BATS_TEST_DIRNAME/fakes/installer" "$BIN/lsblk"
    ln -s "$BATS_TEST_DIRNAME/fakes/installer" "$BIN/findmnt"
    PATH="$BIN:$PATH"
    export FAKE_SYS="$BATS_TEST_TMPDIR/sys" CALLS="$BATS_TEST_TMPDIR/calls"
    mkdir -p "$FAKE_SYS"
    : >"$CALLS"
    GIB=$((1024 * 1024 * 1024))
    blk vda disk $((20 * GIB)) 0 "" ""
    blk sr0 rom $((1 * GIB)) 1 "/run/archiso/bootmnt" ""
    live /dev/sr0
    PACMAN_CONF="$BATS_TEST_DIRNAME/../../manifest/files/pacman.conf"
}

# blk NAME TYPE SIZE RO MOUNTPOINTS PKNAME: a fake block device /dev/NAME.
blk() {
    local d="$FAKE_SYS/blk/$1"
    mkdir -p "$d"
    printf '%s\n' "$2" >"$d/TYPE"
    printf '%s\n' "$3" >"$d/SIZE"
    printf '%s\n' "$4" >"$d/RO"
    printf '%s\n' "$5" >"$d/MOUNTPOINTS"
    printf '%s\n' "$6" >"$d/PKNAME"
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
    blk vda1 part $((20 * GIB)) 0 "" vda

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
    blk sdb disk $((32 * GIB)) 0 "" ""
    live /dev/sdb1
    blk sdb1 part $((2 * GIB)) 0 "/run/archiso/bootmnt" sdb

    run validate_disk /dev/sdb

    [ "$status" -eq 1 ]
    [ "$output" = "aios-install: error: /dev/sdb holds the live medium this system booted from" ]
}

@test "a live medium written to the whole disk is refused too" {
    blk sdc disk $((32 * GIB)) 0 "" ""
    live /dev/sdc

    run validate_disk /dev/sdc

    [ "$status" -eq 1 ]
    [[ "$output" == *"holds the live medium"* ]]
}

@test "a disk with mounted filesystems is refused" {
    blk vdb disk $((20 * GIB)) 0 "$(printf '\n/mnt/data\n')" ""

    run validate_disk /dev/vdb

    [ "$status" -eq 1 ]
    [[ "$output" == *"/dev/vdb has mounted filesystems: "*"/mnt/data"* ]]
}

@test "read-only and small disks are refused" {
    blk vdc disk $((20 * GIB)) 1 "" ""
    run validate_disk /dev/vdc
    [ "$status" -eq 1 ]
    [ "$output" = "aios-install: error: /dev/vdc is read-only" ]

    blk vdd disk $((8 * GIB)) 0 "" ""
    run validate_disk /dev/vdd
    [ "$status" -eq 1 ]
    [ "$output" = "aios-install: error: /dev/vdd has 8 GiB, AIOS needs at least 16 GiB" ]
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
