#!/usr/bin/env bats
# installer/lib/keyring.sh, installer/gen-keys.sh and installer/lib/cleanup.sh: the pinned
# CachyOS key and the failure cleanup (spec §6.2 step 9, §7, §9).
# Literal $ in single quotes is test data; bats runs each test in a subshell.
# shellcheck disable=SC2016,SC2030,SC2031

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
    for n in gpg findmnt mountpoint; do
        ln -s "$BATS_TEST_DIRNAME/fakes/installer" "$BIN/$n"
    done
    for n in mount umount cryptsetup; do
        ln -s "$BATS_TEST_DIRNAME/fakes/record" "$BIN/$n"
    done
    PATH="$BIN:$PATH"
    export FAKE_SYS="$BATS_TEST_TMPDIR/sys" CALLS="$BATS_TEST_TMPDIR/calls"
    export AIOS_MAPPER_DIR="$BATS_TEST_TMPDIR/mapper"
    mkdir -p "$FAKE_SYS" "$AIOS_MAPPER_DIR"
    : >"$CALLS"
    unset AIOS_INSTALL_DRYRUN FAILS
}

# mounted PATH...: the fake mountpoint reports each PATH as a mount point.
mounted() {
    printf '%s\n' "$@" >>"$FAKE_SYS/mounted"
}

# mapping_open: /dev/mapper/aios exists (in $AIOS_MAPPER_DIR).
mapping_open() {
    : >"$AIOS_MAPPER_DIR/aios"
}

# on_mapping TARGET...: findmnt -S /dev/mapper/aios lists these (raw, \x-escaped) targets.
on_mapping() {
    mkdir -p "$FAKE_SYS/mnt/dev/mapper"
    printf '%s\n' "$@" >"$FAKE_SYS/mnt/dev/mapper/aios"
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

@test "cleanup unmounts newest first, then the mapping's other mounts deepest first, then closes LUKS" {
    luks_open_tracked secret /dev/vda2 2>/dev/null
    mount_tracked -t btrfs -o subvolid=5 /dev/mapper/aios /mnt/aios-top 2>/dev/null
    mount_tracked -o umask=0077 /dev/vda1 /efi 2>/dev/null
    mount_tracked --bind /mnt/aios-top/@persist/var/lib/sbctl /var/lib/sbctl 2>/dev/null
    mapping_open
    mounted /var/lib/sbctl /efi /mnt/aios-top /mnt/aios-top/@home /run/x '/mnt/a b' /mnt/aios-top/@home/u/v \
        '/mnt/back\slash'
    on_mapping /mnt/aios-top/@home /run/x '/mnt/a\x20b' /mnt/gone /mnt/aios-top/@home/u/v '/mnt/back\x5cslash'
    : >"$CALLS"

    cleanup 2>/dev/null
    cleanup 2>/dev/null

    diff - <(grep -v '^mountpoint ' "$CALLS") <<'EOF'
umount -R /var/lib/sbctl
umount -R /efi
umount -R /mnt/aios-top
findmnt -rno TARGET -S /dev/mapper/aios
umount -R /mnt/aios-top/@home/u/v
umount -R /mnt/aios-top/@home
umount -R /run/x
umount -R /mnt/a b
umount -R /mnt/back\slash
cryptsetup close aios
EOF
}

@test "cleanup checks each mount point and the mapping before it touches them" {
    luks_open_tracked secret /dev/vda2 2>/dev/null
    mount_tracked /dev/mapper/aios /mnt/aios-top 2>/dev/null
    mount_tracked /dev/vda1 /efi 2>/dev/null
    mapping_open
    mounted /mnt/aios-top
    : >"$CALLS"

    cleanup 2>/dev/null

    diff - "$CALLS" <<'EOF'
mountpoint -q -- /efi
mountpoint -q -- /mnt/aios-top
umount -R /mnt/aios-top
findmnt -rno TARGET -S /dev/mapper/aios
cryptsetup close aios
EOF
}

@test "a mount and the LUKS open are tracked before they run, and left alone if they failed" {
    export FAILS="$BATS_TEST_TMPDIR/fails"
    printf '%s\n' "cryptsetup open --key-file - /dev/vda2 aios" "mount /dev/vda1 /efi" >"$FAILS"

    luks_open_tracked secret /dev/vda2 2>/dev/null || true
    mount_tracked /dev/vda1 /efi 2>/dev/null || true

    [ "$AIOS_LUKS_OPEN" -eq 1 ]
    [ "${AIOS_MOUNTS[*]}" = /efi ]
    : >"$CALLS"
    cleanup 2>/dev/null
    [ "$(cat "$CALLS")" = "mountpoint -q -- /efi" ]
    [ "$AIOS_LUKS_OPEN" -eq 0 ]
    [ "${#AIOS_MOUNTS[@]}" -eq 0 ]
}

@test "a busy mount is lazily unmounted, and a failed close is only a warning" {
    export FAILS="$BATS_TEST_TMPDIR/fails"
    printf '%s\n' "umount -R /mnt/aios-top" "cryptsetup close aios" >"$FAILS"
    luks_open_tracked secret /dev/vda2 2>/dev/null
    mount_tracked /dev/mapper/aios /mnt/aios-top 2>/dev/null
    mapping_open
    mounted /mnt/aios-top
    : >"$CALLS"

    run cleanup

    [ "$status" -eq 0 ]
    [ "$(grep -v -e '^mountpoint ' -e '^findmnt ' "$CALLS" | paste -sd'|')" = "umount -R /mnt/aios-top|umount -R -l /mnt/aios-top|cryptsetup close aios" ]
    [[ "$output" == *"warning: could not close the LUKS mapping aios"* ]]
}

@test "the exit trap names the failed step, cleans up and keeps the status" {
    mounted /efi
    run bash -c '
        for f in common cleanup; do . "$1/$f.sh"; done
        trap on_exit EXIT
        step 7 esp
        mount_tracked /dev/vda1 /efi
        exit 3
    ' _ "$LIB"

    [ "$status" -eq 3 ]
    [[ "$output" == *"step 7 (esp) failed (exit 3)"* ]]
    [ "$(tail -n 1 "$CALLS")" = "umount -R /efi" ]
}

@test "the exit trap still cleans up when stderr is closed or read-only" {
    mounted /efi
    mapping_open
    for redirect in '2>&-' '2</dev/null'; do
        : >"$CALLS"
        run bash -c '
            for f in common cleanup; do . "$1/$f.sh"; done
            set -euo pipefail
            trap on_exit EXIT
            step 7 esp
            luks_open_tracked secret /dev/vda2
            mount_tracked /dev/vda1 /efi
            exec '"$redirect"'
            exit 3
        ' _ "$LIB"

        [ "$status" -eq 3 ] || { echo "$redirect: status $status"; return 1; }
        [ "$(grep -v '^mountpoint ' "$CALLS" | paste -sd'|')" = "cryptsetup open --key-file - /dev/vda2 aios|mount /dev/vda1 /efi|umount -R /efi|findmnt -rno TARGET -S /dev/mapper/aios|cryptsetup close aios" ] ||
            { echo "$redirect:"; cat "$CALLS"; return 1; }
    done
}

@test "the exit trap still cleans up when stderr is a pipe nobody reads any more" {
    mounted /efi
    mapping_open

    run bash -c '
        for f in common cleanup; do . "$1/$f.sh"; done
        set -euo pipefail
        trap on_exit EXIT
        luks_open_tracked secret /dev/vda2
        mount_tracked /dev/vda1 /efi
        exec 2> >(:)
        wait $!
        exit 3
    ' _ "$LIB"

    [ "$status" -eq 3 ]
    [ "$(grep -e '^umount ' -e '^cryptsetup close' "$CALLS" | paste -sd'|')" = "umount -R /efi|cryptsetup close aios" ]
}

@test "after a finished install, a failure says AIOS is installed" {
    run bash -c '
        for f in common cleanup; do . "$1/$f.sh"; done
        trap on_exit EXIT
        AIOS_DISK_CHANGED=1
        step 13 finish
        AIOS_INSTALLED=1
        exit 1
    ' _ "$LIB"

    [ "$status" -eq 1 ]
    [[ "$output" == *"AIOS is installed on the disk; only the end of step 13 failed: reboot by hand"* ]]
    [[ "$output" != *"undefined state"* ]]
}

@test "a second interrupt does not stop the cleanup" {
    # This umount interrupts the installer, like a second Ctrl-C during the cleanup.
    printf '#!/bin/sh\necho "umount $*" >>"$CALLS"\nkill -INT "$PPID"\n' >"$BIN/umount-int"
    chmod +x "$BIN/umount-int"
    ln -sf umount-int "$BIN/umount"
    mounted /efi /mnt/b
    mapping_open

    run bash -c '
        for f in common cleanup; do . "$1/$f.sh"; done
        set -euo pipefail
        trap on_exit EXIT
        trap "exit 130" INT TERM
        luks_open_tracked secret /dev/vda2
        mount_tracked /dev/vda1 /efi
        mount_tracked /dev/vda1 /mnt/b
        exit 3
    ' _ "$LIB"

    [ "$status" -eq 3 ]
    [ "$(grep -e '^umount ' -e '^cryptsetup close' "$CALLS" | paste -sd'|')" = "umount -R /mnt/b|umount -R /efi|cryptsetup close aios" ]
}

@test "a hangup during the cleanup does not stop it, and the installer turns SIGHUP into exit 129" {
    # This umount hangs the installer up, like an SSH drop during the cleanup.
    printf '#!/bin/sh\necho "umount $*" >>"$CALLS"\nkill -HUP "$PPID"\n' >"$BIN/umount-hup"
    chmod +x "$BIN/umount-hup"
    ln -sf umount-hup "$BIN/umount"
    mounted /efi /mnt/b
    mapping_open

    run bash -c '
        for f in common cleanup; do . "$1/$f.sh"; done
        set -euo pipefail
        trap on_exit EXIT
        trap "exit 129" HUP
        luks_open_tracked secret /dev/vda2
        mount_tracked /dev/vda1 /efi
        mount_tracked /dev/vda1 /mnt/b
        exit 3
    ' _ "$LIB"

    [ "$status" -eq 3 ]
    [ "$(grep -e '^umount ' -e '^cryptsetup close' "$CALLS" | paste -sd'|')" = "umount -R /mnt/b|umount -R /efi|cryptsetup close aios" ]
    grep -qF "trap 'exit 129' HUP" "$BATS_TEST_DIRNAME/../../installer/aios-install"
}

@test "the exit trap does nothing after a success" {
    mounted /efi
    run bash -c '
        for f in common cleanup; do . "$1/$f.sh"; done
        trap on_exit EXIT
        step 13 finish
        mount_tracked /dev/vda1 /efi
        cleanup
    ' _ "$LIB"

    [ "$status" -eq 0 ]
    [[ "$output" != *failed* ]]
    [ "$(grep -c '^umount ' "$CALLS")" -eq 1 ]
}
