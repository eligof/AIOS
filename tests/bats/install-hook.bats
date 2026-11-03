#!/usr/bin/env bats
# initrd/install/aios: what the mkinitcpio hook puts into the initrd (spec §3, §4.6).

setup() {
    HOOK="$BATS_TEST_DIRNAME/../../initrd/install/aios"
}

# Source the hook with mkinitcpio's add_* functions replaced by recorders, then call $1.
hook() {
    bash -c '
        add_binary() { echo "add_binary $*"; }
        add_file() { echo "add_file $*"; }
        add_symlink() { echo "add_symlink $*"; }
        . "$1"
        "$2"
    ' _ "$HOOK" "$1"
}

@test "build adds btrfs, the script, both units and their initrd enablement" {
    run hook build

    [ "$status" -eq 0 ]
    [ "${#lines[@]}" -eq 6 ]
    [ "${lines[0]}" = "add_binary btrfs" ]
    [ "${lines[1]}" = "add_file /usr/lib/aios/initrd/aios-root.sh /usr/lib/aios/initrd/aios-root.sh 755" ]
    [ "${lines[2]}" = "add_file /usr/lib/aios/initrd/aios-root.service /usr/lib/systemd/system/aios-root.service" ]
    [ "${lines[3]}" = "add_file /usr/lib/aios/initrd/sysroot-etc.mount /usr/lib/systemd/system/sysroot-etc.mount" ]
    [ "${lines[4]}" = "add_symlink /usr/lib/systemd/system/sysroot.mount.requires/aios-root.service /usr/lib/systemd/system/aios-root.service" ]
    [ "${lines[5]}" = "add_symlink /usr/lib/systemd/system/initrd-fs.target.wants/sysroot-etc.mount /usr/lib/systemd/system/sysroot-etc.mount" ]
}

@test "help explains the hook" {
    run hook help

    [ "$status" -eq 0 ]
    [[ "$output" == *"aios.gen="* ]]
    [[ "$output" == *"systemd hook"* ]]
}
