#!/usr/bin/env bats
# iso/: the archiso profile and build-profile.sh, checked without building (spec §6.1, §9).
# This file is `make iso-check`.
# shellcheck disable=SC2016

FPR=882DCFE48E2051D48E2562ABF3B607488DB35A47

setup() {
    ROOT="$BATS_TEST_DIRNAME/../.."
    ISO="$ROOT/iso"
    AIR="$ISO/airootfs"
    ENTRIES="$ISO/efiboot/loader/entries"
    # A fake local repo and keys file for build-profile.sh.
    REPO="$BATS_TEST_TMPDIR/repo"
    mkdir -p "$REPO"
    : >"$REPO/aios-base-0.1.0-1-any.pkg.tar.zst"
    : >"$REPO/aios-local.db.tar.gz"
    ln -s aios-local.db.tar.gz "$REPO/aios-local.db"
    KEYS="$BATS_TEST_TMPDIR/keys.sh"
    printf 'AIOS_CACHYOS_KEYS="%s"\n' "$FPR" >"$KEYS"
    OUT="$BATS_TEST_TMPDIR/iso-build"
}

# packages: the package list without comments and blank lines.
packages() {
    sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "$ISO/packages.x86_64"
}

# option FILE KEY: the value of KEY in a systemd-boot entry or loader.conf.
option() {
    sed -n "s/^$2[[:space:]]\{1,\}//p" "$1"
}

# unit_key FILE SECTION KEY: the values of KEY in [SECTION] of a systemd unit, one per line.
unit_key() {
    sed -n "/^\[$2\]/,/^\[/s/^$3=//p" "$1"
}

@test "profiledef.sh: AIOS names, UEFI systemd-boot only" {
    run bash -c 'declare -A file_permissions=(); . "$1"; printf "%s\n" "$iso_name" "$install_dir" "${bootmodes[*]}" "$pacman_conf" "$iso_label"; printf "%s\n" "${!file_permissions[@]}" | sort' _ "$ISO/profiledef.sh"

    [ "$status" -eq 0 ]
    [ "${lines[0]}" = aios ]
    [ "${lines[1]}" = aios ]
    [ "${lines[2]}" = uefi.systemd-boot ]
    [ "${lines[3]}" = pacman.conf ]
    [[ "${lines[4]}" =~ ^AIOS_[0-9]{6}$ ]]
    [ "${lines[5]}" = /etc/shadow ]
    [ "${lines[6]}" = /root ]
    [ "${lines[7]}" = /usr/local/bin/aios-install ]
}

@test "the package list is releng plus the AIOS additions, without duplicates" {
    [ -z "$(packages | sort | uniq -d)" ]
    for p in base linux mkinitcpio mkinitcpio-archiso edk2-shell memtest86+-efi iwd zsh \
        arch-install-scripts sbctl btrfs-progs cryptsetup gptfdisk tpm2-tools git usbguard whois \
        aios-cli aios-base cachyos-keyring cachyos-mirrorlist cachyos-v3-mirrorlist; do
        packages | grep -qx -- "$p" || { echo "missing $p"; return 1; }
    done
}

@test "the boot entries: default, serial console, memtest" {
    [ "$(cd "$ENTRIES" && ls)" = "$(printf '%s\n' 01-aios-linux.conf 03-aios-serial.conf '04-aios-memtest86+x64.conf')" ]
    [ "$(option "$ISO/efiboot/loader/loader.conf" default)" = 01-aios-linux.conf ]
    for e in 01-aios-linux.conf 03-aios-serial.conf; do
        [[ "$(option "$ENTRIES/$e" options)" == "archisobasedir=%INSTALL_DIR% archisosearchuuid=%ARCHISO_UUID% %KERNEL_PARAMS%"* ]]
        [ "$(option "$ENTRIES/$e" linux)" = "/%INSTALL_DIR%/boot/%ARCH%/vmlinuz-linux" ]
        [ "$(option "$ENTRIES/$e" initrd)" = "/%INSTALL_DIR%/boot/%ARCH%/initramfs-linux.img" ]
    done
    [ "$(option "$ENTRIES/03-aios-serial.conf" options)" = "$(option "$ENTRIES/01-aios-linux.conf" options) console=ttyS0,115200" ]
    [ "$(cat "$ENTRIES"/*.conf | option /dev/stdin sort-key | paste -sd' ')" = "01 03 04" ]
}

@test "the live system: autologin on tty1 and ttyS0, the auto-install unit enabled" {
    for f in etc/hostname etc/motd etc/passwd etc/shadow root/.zlogin \
        etc/systemd/system/getty@tty1.service.d/autologin.conf \
        etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf \
        etc/systemd/system/aios-install-auto.service etc/systemd/system/pacman-init.service; do
        [ -f "$AIR/$f" ] || { echo "missing $f"; return 1; }
    done
    grep -qx 'ExecStart=-/usr/bin/agetty --noreset --noclear --autologin root --keep-baud 115200,57600,38400,9600 - ${TERM}' \
        "$AIR/etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf"
    grep -qx 'ExecStart=/usr/local/bin/aios-install --auto' "$AIR/etc/systemd/system/aios-install-auto.service"
    [ "$(readlink "$AIR/etc/systemd/system/multi-user.target.wants/aios-install-auto.service")" = ../aios-install-auto.service ]
    [ "$(readlink "$AIR/etc/systemd/system/multi-user.target.wants/pacman-init.service")" = ../pacman-init.service ]
    [ "$(cat "$AIR/etc/hostname")" = aios-live ]
}

@test "aios-install-auto.service: VMs only, after the live keyring, every line on the console" {
    unit=$AIR/etc/systemd/system/aios-install-auto.service

    [ "$(unit_key "$unit" Unit ConditionVirtualization)" = vm ]
    unit_key "$unit" Unit After | tr ' ' '\n' | grep -qx pacman-init.service
    [ "$(unit_key "$unit" Service LogRateLimitIntervalSec)" = 0 ]
    [ "$(unit_key "$unit" Service StandardOutput)" = journal+console ]
    [ "$(unit_key "$unit" Service StandardError)" = journal+console ]
}

@test "every airootfs symlink is absolute or stays inside /etc/systemd/system" {
    while IFS= read -r link; do
        target=$(readlink "$link")
        case $target in
            /*) ;;
            ../*.service) [[ $link == */etc/systemd/system/*.wants/* ]] && [ -f "$(dirname "$link")/$target" ] ;;
            *) echo "unexpected relative link $link -> $target"; return 1 ;;
        esac
    done < <(find "$AIR" -type l)
    [ "$(find "$AIR" -type l | wc -l)" -eq 15 ]
}

@test "pacman.conf.in: core, extra, cachyos, then the unsigned aios-local repo last" {
    [ "$(grep -c '@AIOS_REPO@' "$ISO/pacman.conf.in")" -eq 1 ]
    grep -qx 'Server = file://@AIOS_REPO@' "$ISO/pacman.conf.in"
    [ "$(grep '^\[' "$ISO/pacman.conf.in" | paste -sd' ')" = "[options] [core] [extra] [cachyos] [aios-local]" ]
    [ "$(sed -n '/^\[aios-local\]/,$p' "$ISO/pacman.conf.in" | grep -c '^SigLevel = Optional TrustAll$')" -eq 1 ]
    grep -qx 'Architecture = x86_64' "$ISO/pacman.conf.in"
}

@test "build-profile.sh assembles the complete profile" {
    run "$ISO/build-profile.sh" "$OUT" "$REPO" "$KEYS"

    [ "$status" -eq 0 ]
    [ -f "$OUT/.aios-iso-build" ]
    [ ! -e "$OUT/pacman.conf.in" ] && [ ! -e "$OUT/build-profile.sh" ]
    grep -qx "Server = file://$(readlink -f "$REPO")" "$OUT/pacman.conf"
    [ "$(grep -c '@AIOS_REPO@' "$OUT/pacman.conf")" -eq 0 ]
    [ "$(stat -c %a "$OUT/airootfs/usr/local/bin/aios-install")" = 755 ]
    cmp "$ROOT/installer/aios-install" "$OUT/airootfs/usr/local/bin/aios-install"
    for f in "$ROOT"/installer/lib/*.sh; do
        [ "$(basename "$f")" = keys.sh ] && continue
        cmp "$f" "$OUT/airootfs/usr/local/lib/aios-install/$(basename "$f")"
    done
    cmp "$KEYS" "$OUT/airootfs/usr/local/lib/aios-install/keys.sh"
    [ "$(readlink "$OUT/airootfs/opt/aios-repo/aios-local.db")" = aios-local.db.tar.gz ]
    [ -f "$OUT/airootfs/opt/aios-repo/aios-base-0.1.0-1-any.pkg.tar.zst" ]
    diff -r "$ISO/efiboot" "$OUT/efiboot"
    [ "$(readlink "$OUT/airootfs/etc/resolv.conf")" = /run/systemd/resolve/stub-resolv.conf ]
}

@test "build-profile.sh rebuilds its own output but never touches anything else" {
    "$ISO/build-profile.sh" "$OUT" "$REPO" "$KEYS"
    : >"$OUT/stale"
    "$ISO/build-profile.sh" "$OUT" "$REPO" "$KEYS"
    [ ! -e "$OUT/stale" ]

    mkdir "$BATS_TEST_TMPDIR/mine"
    : >"$BATS_TEST_TMPDIR/mine/precious"
    run "$ISO/build-profile.sh" "$BATS_TEST_TMPDIR/mine" "$REPO" "$KEYS"
    [ "$status" -eq 1 ]
    [[ "$output" == *"exists but was not made by build-profile.sh"* ]]
    [ -f "$BATS_TEST_TMPDIR/mine/precious" ]
}

@test "build-profile.sh marks its output first, so a run that failed midway can be rerun" {
    [ "$(id -u)" -ne 0 ] || skip "root can read a mode 000 file"
    chmod 000 "$REPO/aios-base-0.1.0-1-any.pkg.tar.zst"
    run "$ISO/build-profile.sh" "$OUT" "$REPO" "$KEYS"
    [ "$status" -eq 1 ]
    [ -d "$OUT" ]

    chmod 644 "$REPO/aios-base-0.1.0-1-any.pkg.tar.zst"
    run "$ISO/build-profile.sh" "$OUT" "$REPO" "$KEYS"

    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    [ -f "$OUT/.aios-iso-build" ]
    [ -f "$OUT/airootfs/opt/aios-repo/aios-base-0.1.0-1-any.pkg.tar.zst" ]
}

@test "build-profile.sh needs the local repo and a pinned key" {
    run "$ISO/build-profile.sh" "$OUT" "$BATS_TEST_TMPDIR/norepo" "$KEYS"
    [ "$status" -eq 1 ]
    [[ "$output" == *"run make repo first"* ]]

    : >"$KEYS"
    run "$ISO/build-profile.sh" "$OUT" "$REPO" "$KEYS"
    [ "$status" -eq 1 ]
    [[ "$output" == *"pins no CachyOS key: run make keys"* ]]
    [ ! -e "$OUT" ]
}

@test "build-profile.sh takes the keys file only as make keys writes it: comments, one assignment" {
    # The installer sources keys.sh as root, so nothing else may ride along.
    assignment="AIOS_CACHYOS_KEYS=\"$FPR F3B607488DB35A47882DCFE48E2051D48E2562AB\""
    {
        echo "# shellcheck shell=bash"
        echo "# Generated by installer/gen-keys.sh from the build host's pacman keyring. Do not edit."
        echo "# The CachyOS repository signing keys the live keyring must trust (lib/keyring.sh)."
        echo "# shellcheck disable=SC2034"
        echo "$assignment"
    } >"$BATS_TEST_TMPDIR/good.sh"
    cp "$BATS_TEST_TMPDIR/good.sh" "$KEYS"
    run "$ISO/build-profile.sh" "$OUT" "$REPO" "$KEYS"
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    cmp "$KEYS" "$OUT/airootfs/usr/local/lib/aios-install/keys.sh"

    refused=$BATS_TEST_TMPDIR/refused
    for extra in 'touch "$HOME/pwned"' "$assignment" '' ' # an indented comment'; do
        for where in after before; do
            if [ $where = after ]; then
                { cat "$BATS_TEST_TMPDIR/good.sh"; printf '%s\n' "$extra"; } >"$KEYS"
            else
                { printf '%s\n' "$extra"; cat "$BATS_TEST_TMPDIR/good.sh"; } >"$KEYS"
            fi
            run "$ISO/build-profile.sh" "$refused" "$REPO" "$KEYS"
            [ "$status" -eq 1 ] || { echo "took ${extra@Q} $where the assignment"; return 1; }
            [[ "$output" == *"holds more than comments and one AIOS_CACHYOS_KEYS line: run make keys"* ]]
            [ ! -e "$refused" ]
        done
    done
}

@test "every package resolves in the build host's sync databases (except aios-*)" {
    command -v pacman >/dev/null || skip "pacman not installed"
    db=$(pacman-conf DBPath)
    for r in core extra cachyos; do
        [ -f "$db/sync/$r.db" ] || skip "the host has no synced $r database"
    done
    sed '/^\[aios-local\]/,$d' "$ISO/pacman.conf.in" >"$BATS_TEST_TMPDIR/pacman.conf"
    mapfile -t pkgs < <(packages | grep -vx -e aios-base -e aios-cli)

    run pacman -Sp --config "$BATS_TEST_TMPDIR/pacman.conf" --print-format '%r %n' "${pkgs[@]}"

    [ "$status" -eq 0 ] || { echo "$output"; echo "(stale host databases give false misses)"; return 1; }
    [ "$(grep -c '^cachyos ' <<<"$output")" -eq 3 ]
}
