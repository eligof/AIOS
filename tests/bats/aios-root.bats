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
    export FAILS="$BATS_TEST_TMPDIR/fails"
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

# fail_call LINE: the fake whose call matches LINE verbatim exits 1 instead of acting.
fail_call() {
    printf '%s\n' "$1" >>"$FAILS"
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
    called "btrfs subvolume show $AIOS_TOP/@blank"
    called "btrfs subvolume show $AIOS_TOP/@root-live"
    called "btrfs subvolume delete --recursive $AIOS_TOP/@root-live"
    called "btrfs subvolume show $AIOS_TOP/@etc-live"
    called "btrfs subvolume delete --recursive $AIOS_TOP/@etc-live"
    [ "$(call_index "btrfs subvolume show $AIOS_TOP/@blank")" -lt \
        "$(call_index "btrfs subvolume delete --recursive $AIOS_TOP/@root-live")" ]
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
    called "btrfs subvolume delete --recursive $AIOS_TOP/@usr-cand"
    called "btrfs subvolume delete --recursive $AIOS_TOP/@etc-cand"
    called "btrfs subvolume delete --recursive $AIOS_TOP/@root-cand"
    [ ! -e "$AIOS_TOP/@usr-cand" ]
    [ ! -e "$AIOS_TOP/@etc-cand" ]
    [ ! -e "$AIOS_TOP/@root-cand" ]
}

@test "nested subvolumes go with @root-live in one recursive delete" {
    subvol @root-live
    subvol @root-live/var/lib/machines
    subvol @root-live/var/lib/machines/inner
    subvol @root-live/var/lib/portables

    run "$SCRIPT"

    [ "$status" -eq 0 ]
    [ "$(grep -c ' delete ' "$CALLS")" -eq 1 ]
    called "btrfs subvolume delete --recursive $AIOS_TOP/@root-live"
    [ "$(call_index "btrfs subvolume show $AIOS_TOP/@root-live")" -lt \
        "$(call_index "btrfs subvolume delete --recursive $AIOS_TOP/@root-live")" ]
    [ ! -e "$AIOS_TOP/@root-live/var" ]
    [ -f "$AIOS_TOP/@root-live/.subvol" ]
}

@test "a nested subvolume named like a top-level one cannot redirect the delete" {
    subvol @home
    touch "$AIOS_TOP/@home/user-file"
    subvol @persist
    touch "$AIOS_TOP/@persist/state"
    subvol @root-live
    subvol "@root-live/var/tmp/x @home"
    subvol "@root-live/var/tmp/y @persist"

    run "$SCRIPT"

    [ "$status" -eq 0 ]
    [ "$(grep -c ' delete ' "$CALLS")" -eq 1 ]
    called "btrfs subvolume delete --recursive $AIOS_TOP/@root-live"
    [ -f "$AIOS_TOP/@home/.subvol" ]
    [ -f "$AIOS_TOP/@home/user-file" ]
    [ -f "$AIOS_TOP/@persist/.subvol" ]
    [ -f "$AIOS_TOP/@persist/state" ]
    [ -f "$AIOS_TOP/@root-live/.subvol" ]
    [ -d "$AIOS_TOP/@root-live/etc" ]
    [ ! -e "$AIOS_TOP/@root-live/var" ]
}

@test "a plain directory at @root-live fails without deleting anything" {
    mkdir -p "$AIOS_TOP/@root-live/var"
    touch "$AIOS_TOP/@root-live/var/data"
    subvol @etc-live
    subvol @usr-cand

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [[ "$output" == *"aios: @root-live exists but is not a subvolume"* ]]
    [ "$(grep -c ' delete ' "$CALLS")" -eq 0 ]
    [ "$(grep -c ' snapshot ' "$CALLS")" -eq 0 ]
    [ -f "$AIOS_TOP/@root-live/var/data" ]
    [ -f "$AIOS_TOP/@etc-live/.subvol" ]
    [ -f "$AIOS_TOP/@usr-cand/.subvol" ]
    [ "$(tail -n 1 "$CALLS")" = "umount $AIOS_TOP" ]
}

@test "a symlink at a live name fails without following it" {
    subvol @home
    touch "$AIOS_TOP/@home/user-file"
    ln -s @home "$AIOS_TOP/@root-live"

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [[ "$output" == *"aios: @root-live is a symlink, not a subvolume"* ]]
    [ "$(grep -c ' delete ' "$CALLS")" -eq 0 ]
    [ "$(grep -c ' snapshot ' "$CALLS")" -eq 0 ]
    [ -f "$AIOS_TOP/@home/.subvol" ]
    [ -f "$AIOS_TOP/@home/user-file" ]
    [ -L "$AIOS_TOP/@root-live" ]
    [ "$(tail -n 1 "$CALLS")" = "umount $AIOS_TOP" ]
}

@test "a dangling symlink at a candidate name fails too" {
    ln -s /nonexistent "$AIOS_TOP/@etc-cand"

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [[ "$output" == *"aios: @etc-cand is a symlink, not a subvolume"* ]]
    [ "$(grep -c ' snapshot ' "$CALLS")" -eq 0 ]
    [ -L "$AIOS_TOP/@etc-cand" ]
}

# A symlink at a generation's name or at @blank would boot another subvolume's content
# (btrfs resolves the path), so it stops the boot before anything is deleted.
@test "a symlinked @usr-gen-N or @etc-gen-N fails before anything is deleted" {
    for name in @usr-gen-0008 @etc-gen-0008; do
        rm -rf "$AIOS_TOP/@usr-gen-0008" "$AIOS_TOP/@etc-gen-0008"
        subvol @usr-gen-0008
        subvol @etc-gen-0008
        rm -r "${AIOS_TOP:?}/$name"
        ln -s "${name%-0008}-0007" "$AIOS_TOP/$name"
        subvol @root-live
        cmdline "aios.gen=0008"
        : >"$CALLS"

        run "$SCRIPT"

        [ "$status" -eq 1 ]
        [[ "$output" == *"aios: $name is a symlink, not a subvolume"* ]]
        [ "$(grep -c ' delete ' "$CALLS")" -eq 0 ]
        [ "$(grep -c ' snapshot ' "$CALLS")" -eq 0 ]
        [ -f "$AIOS_TOP/@root-live/.subvol" ]
        [ "$(tail -n 1 "$CALLS")" = "umount $AIOS_TOP" ]
    done
}

@test "a dangling symlink at a generation name fails as a symlink, not as missing" {
    ln -s /nonexistent "$AIOS_TOP/@etc-gen-0008"
    subvol @usr-gen-0008
    cmdline "aios.gen=0008"

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [[ "$output" == *"aios: @etc-gen-0008 is a symlink, not a subvolume"* ]]
    [ "$(grep -c ' snapshot ' "$CALLS")" -eq 0 ]
}

@test "a symlinked @blank fails before anything is deleted" {
    mv "$AIOS_TOP/@blank" "$AIOS_TOP/@other"
    ln -s @other "$AIOS_TOP/@blank"
    subvol @root-live

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [[ "$output" == *"aios: @blank is a symlink, not a subvolume"* ]]
    [ "$(grep -c ' delete ' "$CALLS")" -eq 0 ]
    [ "$(grep -c ' snapshot ' "$CALLS")" -eq 0 ]
    [ -f "$AIOS_TOP/@root-live/.subvol" ]
    [ "$(tail -n 1 "$CALLS")" = "umount $AIOS_TOP" ]
}

@test "missing @blank fails before deleting anything" {
    rm -r "$AIOS_TOP/@blank"
    subvol @root-live
    subvol @etc-live

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [[ "$output" == *"aios: @blank missing — reinstall required"* ]]
    [ "$(grep -c ' delete ' "$CALLS")" -eq 0 ]
    [ -f "$AIOS_TOP/@root-live/.subvol" ]
    [ -f "$AIOS_TOP/@etc-live/.subvol" ]
    [ "$(tail -n 1 "$CALLS")" = "umount $AIOS_TOP" ]
}

@test "a failed top-level mount touches no subvolume and unmounts nothing" {
    subvol @root-live
    fail_call "mount -t btrfs -o subvolid=5 /dev/mapper/fake-aios $AIOS_TOP"

    run "$SCRIPT"

    [ "$status" -ne 0 ]
    [ "$(grep -c '^umount ' "$CALLS")" -eq 0 ]
    [ "$(grep -c '^btrfs ' "$CALLS")" -eq 0 ]
    [ -f "$AIOS_TOP/@root-live/.subvol" ]
}

@test "a failed snapshot fails the boot and unmounts exactly once" {
    fail_call "btrfs subvolume snapshot $AIOS_TOP/@blank $AIOS_TOP/@root-live"

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [ "$(grep -c ' snapshot ' "$CALLS")" -eq 1 ]
    [ "$(grep -c '^umount ' "$CALLS")" -eq 1 ]
    [ "$(tail -n 1 "$CALLS")" = "umount $AIOS_TOP" ]
}

@test "a failed unmount of the top level is retried lazily" {
    fail_call "umount $AIOS_TOP"

    run "$SCRIPT"

    [ "$status" -eq 0 ]
    [[ "$output" == *"aios: warning: could not unmount $AIOS_TOP, retrying with umount -l"* ]]
    [ "$(tail -n 2 "$CALLS")" = "umount $AIOS_TOP
umount -l $AIOS_TOP" ]
}

@test "a failed unmount keeps the script's failure status" {
    cmdline "aios.gen=0008"
    fail_call "umount $AIOS_TOP"

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [[ "$output" == *"aios: generation 0008 missing — pick another boot entry"* ]]
    [ "$(tail -n 1 "$CALLS")" = "umount -l $AIOS_TOP" ]
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

@test "an empty aios.gen= fails even next to a valid one" {
    cmdline "aios.gen= aios.gen=0007"

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [[ "$output" == *"aios: no generation on cmdline"* ]]
    [ ! -s "$CALLS" ]
}

@test "fake btrfs: a plain delete refuses nested subvolumes, --recursive takes them" {
    subvol @root-live
    subvol @root-live/var/lib/machines
    mkdir "$AIOS_TOP/plain"

    run btrfs subvolume delete "$AIOS_TOP/@root-live"
    [ "$status" -eq 1 ]
    [ -f "$AIOS_TOP/@root-live/var/lib/machines/.subvol" ]

    run btrfs subvolume delete --recursive "$AIOS_TOP/plain"
    [ "$status" -eq 1 ]
    [ -d "$AIOS_TOP/plain" ]

    run btrfs subvolume show "$AIOS_TOP/plain"
    [ "$status" -eq 1 ]

    run btrfs subvolume delete --recursive "$AIOS_TOP/@root-live"
    [ "$status" -eq 0 ]
    [ ! -e "$AIOS_TOP/@root-live" ]
}

@test "fake btrfs: like btrfs-progs, show and delete resolve a symlink" {
    subvol @home
    ln -s @home "$AIOS_TOP/link"

    run btrfs subvolume show "$AIOS_TOP/link"
    [ "$status" -eq 0 ]

    run btrfs subvolume delete --recursive "$AIOS_TOP/link"
    [ "$status" -eq 0 ]
    [ ! -e "$AIOS_TOP/@home" ]
}
