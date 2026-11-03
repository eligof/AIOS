#!/usr/bin/env bats
# installer/lib/keyring.sh, installer/gen-keys.sh and installer/lib/cleanup.sh: the pinned
# CachyOS key and the failure cleanup (spec §6.2 step 9, §7, §9).

FPR=882DCFE48E2051D48E2562ABF3B607488DB35A47
OTHER=0123456789ABCDEF0123456789ABCDEF01234567

setup() {
    ROOT="$BATS_TEST_DIRNAME/../.."
    LIB="$ROOT/installer/lib"
    for f in common keyring cleanup; do
        # shellcheck source=/dev/null
        source "$LIB/$f.sh"
    done
    BIN="$BATS_TEST_TMPDIR/bin"
    mkdir -p "$BIN"
    ln -s "$BATS_TEST_DIRNAME/fakes/installer" "$BIN/gpg"
    for n in mount umount cryptsetup; do
        ln -s "$BATS_TEST_DIRNAME/fakes/record" "$BIN/$n"
    done
    PATH="$BIN:$PATH"
    export FAKE_SYS="$BATS_TEST_TMPDIR/sys" CALLS="$BATS_TEST_TMPDIR/calls"
    mkdir -p "$FAKE_SYS"
    : >"$CALLS"
    unset AIOS_INSTALL_DRYRUN FAILS
}

# key VALIDITY FPR: one primary key in gpg's --with-colons format, with a subkey.
key() {
    printf 'pub:%s:3072:1:%s:1628554460:::-:::scSC::::::23::0:\n' "$1" "${2: -16}"
    printf 'fpr:::::::::%s:\n' "$2"
    printf 'uid:%s::::1691645607::05DE::CachyOS <admin@cachyos.org>::::::::::0:\n' "$1"
    printf 'sub:e:3072:1:9B71BE9D397982C5:1628554460:1691626460:::::e::::::23:\n'
    printf 'fpr:::::::::9149495EB47A04A82FF0BA6F9B71BE9D397982C5:\n'
}

@test "only fully trusted primary keys count, never subkeys" {
    { key f "$FPR"; key r "$OTHER"; key e 1111111111111111111111111111111111111111; key - 2222222222222222222222222222222222222222; } >"$FAKE_SYS/gpg.out"

    run trusted_key_fprs admin@cachyos.org

    [ "$status" -eq 0 ]
    [ "$output" = "$FPR" ]
    [ "$(cat "$CALLS")" = "gpg --homedir /etc/pacman.d/gnupg --batch --no-permission-warning --with-colons --list-keys -- admin@cachyos.org" ]
}

@test "gen-keys.sh pins the trusted key into a sourceable keys.sh" {
    { key u "$FPR"; key f "$OTHER"; } >"$FAKE_SYS/gpg.out"

    run "$ROOT/installer/gen-keys.sh" "$BATS_TEST_TMPDIR/keys.sh"

    [ "$status" -eq 0 ]
    [ "$output" = "gen-keys.sh: pinned $OTHER $FPR in $BATS_TEST_TMPDIR/keys.sh" ]
    # shellcheck source=/dev/null
    source "$BATS_TEST_TMPDIR/keys.sh"
    [ "$AIOS_CACHYOS_KEYS" = "$OTHER $FPR" ]
    [ ! -e "$BATS_TEST_TMPDIR/keys.sh.tmp" ]
}

@test "gen-keys.sh fails without a trusted key and keeps no partial file" {
    key r "$FPR" >"$FAKE_SYS/gpg.out"

    run "$ROOT/installer/gen-keys.sh" "$BATS_TEST_TMPDIR/keys.sh"
    [ "$status" -eq 1 ]
    [[ "$output" == *"trusts no key for admin@cachyos.org"* ]]
    [ ! -e "$BATS_TEST_TMPDIR/keys.sh" ]

    rm "$FAKE_SYS/gpg.out"
    run "$ROOT/installer/gen-keys.sh" "$BATS_TEST_TMPDIR/keys.sh"
    [ "$status" -eq 1 ]
}

@test "gen-keys.sh reads the build host's real keyring (if it has CachyOS)" {
    rm "$BIN/gpg"
    command -v gpg >/dev/null || skip "gpg not installed"
    trusted_key_fprs admin@cachyos.org | grep -q . || skip "this host's pacman keyring has no CachyOS key"

    run "$ROOT/installer/gen-keys.sh" "$BATS_TEST_TMPDIR/keys.sh"

    [ "$status" -eq 0 ]
    grep -Eqx 'AIOS_CACHYOS_KEYS="[0-9A-F]{40}( [0-9A-F]{40})*"' "$BATS_TEST_TMPDIR/keys.sh"
}

@test "the live keyring must trust exactly the pinned keys" {
    key f "$FPR" >"$FAKE_SYS/gpg.out"
    check_cachyos_keys "$FPR"

    run check_cachyos_keys "$OTHER"
    [ "$status" -eq 1 ]
    [[ "$output" == *"trusts the CachyOS keys [$FPR], but this ISO pinned [$OTHER]"* ]]

    { key f "$FPR"; key f "$OTHER"; } >"$FAKE_SYS/gpg.out"
    run check_cachyos_keys "$FPR"
    [ "$status" -eq 1 ]

    run check_cachyos_keys ""
    [ "$status" -eq 1 ]
    [[ "$output" == *"no pinned CachyOS key"* ]]
}

@test "cleanup unmounts newest first, then closes LUKS, then has nothing left to do" {
    mount_tracked -t btrfs -o subvolid=5 /dev/mapper/aios /mnt/aios-top 2>/dev/null
    luks_opened
    mount_tracked -o umask=0077 /dev/vda1 /mnt/aios-esp 2>/dev/null
    mount_tracked --bind /mnt/aios-top/@persist/var/lib/sbctl /var/lib/sbctl 2>/dev/null
    : >"$CALLS"

    cleanup 2>/dev/null
    cleanup 2>/dev/null

    diff - "$CALLS" <<'EOF'
umount /var/lib/sbctl
umount /mnt/aios-esp
umount /mnt/aios-top
cryptsetup close aios
EOF
}

@test "a busy mount is lazily unmounted, and a failed close is only a warning" {
    export FAILS="$BATS_TEST_TMPDIR/fails"
    printf '%s\n' "umount /mnt/aios-top" "cryptsetup close aios" >"$FAILS"
    mount_tracked /dev/mapper/aios /mnt/aios-top 2>/dev/null
    luks_opened
    : >"$CALLS"

    run cleanup

    [ "$status" -eq 0 ]
    [ "$(paste -sd'|' "$CALLS")" = "umount /mnt/aios-top|umount -l /mnt/aios-top|cryptsetup close aios" ]
    [[ "$output" == *"warning: could not close the LUKS mapping aios"* ]]
}

@test "the exit trap names the failed step, cleans up and keeps the status" {
    run bash -c '
        for f in common cleanup; do . "$1/$f.sh"; done
        trap on_exit EXIT
        step 7 esp
        mount_tracked /dev/vda1 /mnt/aios-esp
        exit 3
    ' _ "$LIB"

    [ "$status" -eq 3 ]
    [[ "$output" == *"step 7 (esp) failed (exit 3)"* ]]
    [ "$(tail -n 1 "$CALLS")" = "umount /mnt/aios-esp" ]
}

@test "the exit trap does nothing after a success" {
    run bash -c '
        for f in common cleanup; do . "$1/$f.sh"; done
        trap on_exit EXIT
        step 13 finish
        mount_tracked /dev/vda1 /mnt/aios-esp
        cleanup
    ' _ "$LIB"

    [ "$status" -eq 0 ]
    [[ "$output" != *failed* ]]
    [ "$(grep -c '^umount ' "$CALLS")" -eq 1 ]
}
