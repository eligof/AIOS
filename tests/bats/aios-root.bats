#!/usr/bin/env bats
# initrd/aios-root.sh against fake btrfs/mount/umount (spec §3 step 6, §9).

setup() {
    SCRIPT="$BATS_TEST_DIRNAME/../../initrd/aios-root.sh"
    FAKES="$BATS_TEST_DIRNAME/fakes"
    BIN="$BATS_TEST_TMPDIR/bin"
    mkdir -p "$BIN"
    ln -s "$FAKES/btrfs" "$BIN/btrfs"
    ln -s "$FAKES/record" "$BIN/mount"
    ln -s "$FAKES/record" "$BIN/umount"
    PATH="$BIN:$PATH"

    export AIOS_TOP="$BATS_TEST_TMPDIR/top"
    export AIOS_CMDLINE_FILE="$BATS_TEST_TMPDIR/cmdline"
    export AIOS_DEVICE=/dev/mapper/fake-aios
    export CALLS="$BATS_TEST_TMPDIR/calls"
    : >"$CALLS"

    mkdir -p "$AIOS_TOP"
    subvol @blank
    mkdir -p "$AIOS_TOP/@blank/etc" "$AIOS_TOP/@blank/usr" "$AIOS_TOP/@blank/persist"
    subvol @usr-gen-0007
    subvol @etc-gen-0007
    mkdir -p "$AIOS_TOP/@etc-gen-0007/aios"
    echo "id = 7" >"$AIOS_TOP/@etc-gen-0007/aios/generation.toml"
    cmdline "root=/dev/mapper/aios rootflags=subvol=@root-live aios.gen=0007 quiet"
}

# subvol NAME: create a fake subvolume at $AIOS_TOP/NAME.
subvol() {
    mkdir -p "$AIOS_TOP/$1"
    : >"$AIOS_TOP/$1/.subvol"
}

cmdline() {
    printf '%s\n' "$*" >"$AIOS_CMDLINE_FILE"
}

# called LINE: LINE appears verbatim in $CALLS.
called() {
    grep -qxF -- "$1" "$CALLS" || { echo "not called: $1" >&2; cat "$CALLS" >&2; return 1; }
}

# call_index LINE: 1-based position of LINE in $CALLS.
call_index() {
    grep -nxF -- "$1" "$CALLS" | cut -d: -f1
}

@test "normal boot recreates @root-live and @etc-live and deletes the stale ones" {
    subvol @root-live
    touch "$AIOS_TOP/@root-live/runtime-junk"
    subvol @etc-live
    touch "$AIOS_TOP/@etc-live/runtime-edit"

    run "$SCRIPT"

    [ "$status" -eq 0 ]
    called "mount -t btrfs -o subvolid=5 /dev/mapper/fake-aios $AIOS_TOP"
    called "btrfs subvolume delete $AIOS_TOP/@root-live"
    called "btrfs subvolume delete $AIOS_TOP/@etc-live"
    called "btrfs subvolume snapshot $AIOS_TOP/@blank $AIOS_TOP/@root-live"
    called "btrfs subvolume snapshot $AIOS_TOP/@etc-gen-0007 $AIOS_TOP/@etc-live"
    [ "$(tail -n 1 "$CALLS")" = "umount $AIOS_TOP" ]
    [ "$(grep -c "^umount " "$CALLS")" -eq 1 ]
    [ -d "$AIOS_TOP/@root-live/etc" ]
    [ ! -e "$AIOS_TOP/@root-live/runtime-junk" ]
    [ -f "$AIOS_TOP/@etc-live/aios/generation.toml" ]
    [ ! -e "$AIOS_TOP/@etc-live/runtime-edit" ]
    [ -f "$AIOS_TOP/@usr-gen-0007/.subvol" ]
    [ -f "$AIOS_TOP/@etc-gen-0007/.subvol" ]
    [[ "$output" == *"aios: generation 0007 ready"* ]]
}

@test "first boot without live subvolumes deletes nothing" {
    run "$SCRIPT"

    [ "$status" -eq 0 ]
    [ "$(grep -c ' delete ' "$CALLS")" -eq 0 ]
    [ -f "$AIOS_TOP/@root-live/.subvol" ]
    [ -f "$AIOS_TOP/@etc-live/.subvol" ]
}

@test "stale candidates from an interrupted apply are deleted" {
    subvol @usr-cand
    subvol @etc-cand
    subvol @root-cand

    run "$SCRIPT"

    [ "$status" -eq 0 ]
    called "btrfs subvolume delete $AIOS_TOP/@usr-cand"
    called "btrfs subvolume delete $AIOS_TOP/@etc-cand"
    called "btrfs subvolume delete $AIOS_TOP/@root-cand"
    [ ! -e "$AIOS_TOP/@usr-cand" ]
    [ ! -e "$AIOS_TOP/@etc-cand" ]
    [ ! -e "$AIOS_TOP/@root-cand" ]
}

@test "nested subvolumes are deleted before their parent" {
    subvol @root-live
    subvol @root-live/var/lib/machines
    subvol @root-live/var/lib/machines/inner
    subvol @root-live/var/lib/portables

    run "$SCRIPT"

    [ "$status" -eq 0 ]
    inner=$(call_index "btrfs subvolume delete $AIOS_TOP/@root-live/var/lib/machines/inner")
    machines=$(call_index "btrfs subvolume delete $AIOS_TOP/@root-live/var/lib/machines")
    portables=$(call_index "btrfs subvolume delete $AIOS_TOP/@root-live/var/lib/portables")
    parent=$(call_index "btrfs subvolume delete $AIOS_TOP/@root-live")
    [ -n "$inner" ]
    [ -n "$machines" ]
    [ -n "$portables" ]
    [ -n "$parent" ]
    [ "$inner" -lt "$machines" ]
    [ "$machines" -lt "$parent" ]
    [ "$portables" -lt "$parent" ]
    [ ! -e "$AIOS_TOP/@root-live/var" ]
}

@test "missing generation fails with a clear message and still unmounts" {
    cmdline "root=/dev/mapper/aios aios.gen=0008"

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [[ "$output" == *"aios: generation 0008 missing — pick another boot entry"* ]]
    [ "$(grep -c ' snapshot ' "$CALLS")" -eq 0 ]
    [ "$(tail -n 1 "$CALLS")" = "umount $AIOS_TOP" ]
}

@test "half a generation (no @etc-gen-N) counts as missing" {
    subvol @usr-gen-0008
    cmdline "aios.gen=0008"

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [[ "$output" == *"aios: generation 0008 missing — pick another boot entry"* ]]
}

@test "no aios.gen on the cmdline fails before mounting" {
    cmdline "root=/dev/mapper/aios quiet"

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [[ "$output" == *"aios: no generation on cmdline"* ]]
    [ ! -s "$CALLS" ]
}

@test "aios.gen=42 (not 4 digits) fails" {
    cmdline "aios.gen=42"

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [[ "$output" == *"aios: no generation on cmdline"* ]]
    [ ! -s "$CALLS" ]
}

@test "aios.gen=0000 fails" {
    cmdline "aios.gen=0000"

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [[ "$output" == *"aios: no generation on cmdline"* ]]
    [ ! -s "$CALLS" ]
}

@test "conflicting aios.gen values fail before mounting" {
    cmdline "aios.gen=0007 quiet aios.gen=0008"

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [[ "$output" == *"aios: conflicting aios.gen= values on cmdline"* ]]
    [ ! -s "$CALLS" ]
}
