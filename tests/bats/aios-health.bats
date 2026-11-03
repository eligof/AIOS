#!/usr/bin/env bats
# base/aios-health.sh against a fake findmnt (spec §3 step 11, §9).

BTRFS_OPTS="relatime,compress=zstd:3,ssd,discard=async,space_cache=v2"

setup() {
    SCRIPT="$BATS_TEST_DIRNAME/../../base/aios-health.sh"
    export AIOS_FINDMNT="$BATS_TEST_DIRNAME/fakes/findmnt"
    export FAKE_MOUNTS="$BATS_TEST_TMPDIR/mounts"
    export AIOS_CMDLINE_FILE="$BATS_TEST_TMPDIR/cmdline"
    export AIOS_GEN_FILE="$BATS_TEST_TMPDIR/generation.toml"

    mkdir -p "$FAKE_MOUNTS/var"
    mnt /usr "ro,$BTRFS_OPTS,subvolid=261,subvol=/@usr-gen-0007"
    mnt /etc "rw,$BTRFS_OPTS,subvolid=263,subvol=/@etc-live"
    mnt /persist "rw,$BTRFS_OPTS,subvolid=257,subvol=/@persist"
    mnt /home "rw,$BTRFS_OPTS,subvolid=258,subvol=/@home"
    mnt /var/log "rw,$BTRFS_OPTS,subvolid=259,subvol=/@log"
    cmdline "root=/dev/mapper/aios mount.usrflags=subvol=@usr-gen-0007,ro,compress=zstd aios.gen=0007 quiet"
    gen_file 7
}

# mnt MOUNTPOINT OPTIONS: make the fake findmnt report MOUNTPOINT as mounted.
mnt() {
    printf '%s\n' "$2" >"$FAKE_MOUNTS$1"
}

unmnt() {
    rm -f "$FAKE_MOUNTS$1"
}

# stack MOUNTPOINT OPTIONS: mount something else on top of MOUNTPOINT.
stack() {
    printf '%s\n' "$2" >>"$FAKE_MOUNTS$1"
}

cmdline() {
    printf '%s\n' "$*" >"$AIOS_CMDLINE_FILE"
}

gen_file() {
    cat >"$AIOS_GEN_FILE" <<TOML
id = $1
parent = 6
created = "2026-11-03T21:14:05Z"
manifest_commit = "3f9c2a1"
kernels = ["linux-cachyos 7.3.0-4"]
package_set_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
TOML
}

@test "healthy generation passes" {
    run "$SCRIPT"

    [ "$status" -eq 0 ]
    [ "$output" = "aios-health: generation 0007 is healthy" ]
}

@test "/usr mounted read-write fails" {
    mnt /usr "rw,$BTRFS_OPTS,subvolid=261,subvol=/@usr-gen-0007"

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [[ "$output" == "aios-health: /usr is not mounted read-only"* ]]
}

@test "/usr from another generation fails" {
    mnt /usr "ro,$BTRFS_OPTS,subvolid=260,subvol=/@usr-gen-0006"

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [[ "$output" == "aios-health: /usr is not subvolume @usr-gen-0007"* ]]
}

@test "/usr subvolume match is exact, not a prefix" {
    mnt /usr "ro,$BTRFS_OPTS,subvolid=262,subvol=/@usr-gen-00070"

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [[ "$output" == "aios-health: /usr is not subvolume @usr-gen-0007"* ]]
}

@test "/etc not from @etc-live fails" {
    mnt /etc "rw,$BTRFS_OPTS,subvolid=262,subvol=/@etc-gen-0007"

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [[ "$output" == "aios-health: /etc is not subvolume @etc-live"* ]]
}

@test "missing /persist fails" {
    unmnt /persist

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [ "$output" = "aios-health: /persist is not mounted" ]
}

@test "missing /var/log fails" {
    unmnt /var/log

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [ "$output" = "aios-health: /var/log is not mounted" ]
}

@test "generation.toml id mismatch fails" {
    gen_file 6

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [ "$output" = "aios-health: $AIOS_GEN_FILE has id 6 but the cmdline says aios.gen=0007" ]
}

@test "aios.test.fail_health=1 forces failure" {
    cmdline "root=/dev/mapper/aios aios.gen=0007 aios.test.fail_health=1"

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [ "$output" = "aios-health: forced failure (aios.test.fail_health=1 on the cmdline)" ]
}

@test "no aios.gen on the cmdline fails" {
    cmdline "root=/dev/mapper/aios quiet"

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [ "$output" = "aios-health: no generation on cmdline" ]
}

@test "conflicting aios.gen values fail" {
    cmdline "aios.gen=0007 aios.gen=0008"

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [ "$output" = "aios-health: conflicting aios.gen= values on cmdline" ]
}

@test "an empty aios.gen= fails even next to a valid one" {
    cmdline "aios.gen= aios.gen=0007"

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [ "$output" = "aios-health: no generation on cmdline" ]
}

@test "a mount stacked on /usr does not hide the generation's /usr" {
    stack /usr "rw,nosuid,nodev,size=1024k,mode=755,inode64"

    run "$SCRIPT"

    [ "$status" -eq 0 ]
    [ "$output" = "aios-health: generation 0007 is healthy" ]
}

@test "a mount stacked on /etc does not hide @etc-live" {
    stack /etc "rw,nosuid,nodev,size=1024k,mode=755,inode64"

    run "$SCRIPT"

    [ "$status" -eq 0 ]
    [ "$output" = "aios-health: generation 0007 is healthy" ]
}

@test "aios.gen=0100 matches id = 100" {
    cmdline "root=/dev/mapper/aios aios.gen=0100 quiet"
    mnt /usr "ro,$BTRFS_OPTS,subvolid=361,subvol=/@usr-gen-0100"
    gen_file 100

    run "$SCRIPT"

    [ "$status" -eq 0 ]
    [ "$output" = "aios-health: generation 0100 is healthy" ]
}

@test "/usr not mounted fails" {
    unmnt /usr

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [ "$output" = "aios-health: /usr is not mounted" ]
}

@test "missing /home fails" {
    unmnt /home

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [ "$output" = "aios-health: /home is not mounted" ]
}

@test "generation.toml without an id line fails" {
    gen_file 7
    sed -i '/^id = /d' "$AIOS_GEN_FILE"

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [ "$output" = "aios-health: no id in $AIOS_GEN_FILE" ]
}
