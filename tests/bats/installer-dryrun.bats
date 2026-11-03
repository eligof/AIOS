#!/usr/bin/env bats
# installer/aios-install end to end in dry-run mode (spec §6.2, §7, §9): the ordered list of
# commands that change the system, what actually runs (read-only queries only), the failure
# trap, and the unattended/interactive/--auto entry points.
# bats sets $stderr for `run --separate-stderr`; each test runs in a subshell.
# shellcheck disable=SC2030,SC2031,SC2154

bats_require_minimum_version 1.5.0

setup() {
    ROOT="$BATS_TEST_DIRNAME/../.."
    SCRIPT="$ROOT/installer/aios-install"
    T="$BATS_TEST_TMPDIR"
    FPR=882DCFE48E2051D48E2562ABF3B607488DB35A47

    # The libraries, plus a keys.sh like `make keys` writes.
    mkdir -p "$T/lib"
    cp "$ROOT"/installer/lib/*.sh "$T/lib/"
    printf 'AIOS_CACHYOS_KEYS="%s"\n' "$FPR" >"$T/lib/keys.sh"

    # The fake machine: a 20 GiB /dev/vda, the live medium on /dev/sr0, a CachyOS-trusting
    # keyring, firmware in Setup Mode, one USB controller, a v3 CPU.
    export FAKE_SYS="$T/sys" CALLS="$T/calls"
    : >"$CALLS"
    blk vda disk $((20 * 1024 * 1024 * 1024)) 0 ""
    blk sr0 rom 1073741824 1 /run/archiso/bootmnt
    mkdir -p "$FAKE_SYS/mnt/run/archiso"
    echo /dev/sr0 >"$FAKE_SYS/mnt/run/archiso/bootmnt"
    keyring "$FPR"
    echo 0b2a3c4d-1111-4222-8333-944455556666 >"$FAKE_SYS/luks-uuid"
    setup_mode true
    echo 'allow id 1d6b:0002 serial "0000:00:04.0" name "xHCI Host Controller" with-interface 09:00:00' \
        >"$FAKE_SYS/usbguard-policy"
    printf '#!/bin/sh\necho "  x86-64-v3 (supported, searched)"\n' >"$T/ld.so"
    chmod +x "$T/ld.so"

    mkdir -p "$T/efi" "$T/repo" "$T/zoneinfo"
    : >"$T/repo/aios-local.db.tar.gz"
    : >"$T/zoneinfo/UTC"
    export AIOS_INSTALL_LIB="$T/lib" AIOS_INSTALL_DRYRUN=1 AIOS_EFI_DIR="$T/efi"
    export AIOS_DEFAULTS="$ROOT/manifest" AIOS_LIVE_REPO="$T/repo" AIOS_ZONEINFO="$T/zoneinfo"
    export AIOS_PASSWD_FILE=/dev/null AIOS_LDSO="$T/ld.so" AIOS_FWCFG_DIR="$T/fw_cfg"
    unset AIOS_INSTALL_DRYRUN_FAILS
    DEFAULTS=$AIOS_DEFAULTS LIVE_REPO=$AIOS_LIVE_REPO

    cat >"$T/install.conf" <<'EOF'
DISK=/dev/vda
HOSTNAME=aios-e2e
USERNAME=tester
USER_PASSWORD=e2e-user-pass
LUKS_PASSPHRASE=e2e-luks-passphrase
TIMEZONE=UTC
WIPE=yes
EXTRA_CMDLINE=console=ttyS0,115200
EOF

    # Queries answer from $FAKE_SYS. Every other tool is `record`: dry-run must never call it.
    # (So the tests below write files with redirections, not with cp.)
    mkdir -p "$T/bin"
    for n in lsblk findmnt mountpoint gpg mkpasswd cryptsetup sbctl usbguard curl modprobe; do
        ln -s "$BATS_TEST_DIRNAME/fakes/installer" "$T/bin/$n"
    done
    for n in sgdisk udevadm mkfs.fat systemd-cryptenroll mkfs.btrfs btrfs mount umount git aios \
        bootctl install cp mv chown chmod; do
        ln -s "$BATS_TEST_DIRNAME/fakes/record" "$T/bin/$n"
    done
    PATH="$T/bin:$PATH"
}

blk() {
    local d="$FAKE_SYS/blk/$1"
    mkdir -p "$d"
    printf '%s\n' "$2" >"$d/TYPE"
    printf '%s\n' "$3" >"$d/SIZE"
    printf '%s\n' "$4" >"$d/RO"
    printf '%s\n' "$5" >"$d/MOUNTPOINTS"
    printf '\n' >"$d/PKNAME"
}

keyring() {
    printf 'pub:f:3072:1:%s:1628554460:::m:::scSC::::::23::0:\nfpr:::::::::%s:\nuid:f::::1691645607::05DE::CachyOS <admin@cachyos.org>::::::::::0:\n' \
        "${1: -16}" "$1" >"$FAKE_SYS/gpg.out"
}

setup_mode() {
    echo "{\"installed\":true,\"guid\":\"x\",\"setup_mode\":$1,\"secure_boot\":false,\"vendors\":[]}" \
        >"$FAKE_SYS/sbctl-status.json"
}

# install_dry ARGS...: run the installer (no stdin, so a stray prompt fails instead of
# hanging); DRY holds its DRYRUN lines, LOG its stderr.
install_dry() {
    run --separate-stderr "$SCRIPT" "$@" </dev/null
    DRY=$(grep '^DRYRUN ' <<<"$output" | sed 's/^DRYRUN //' || true)
    LOG=$stderr
}

# The commands of an unattended install on a v3 CPU in Setup Mode, in order.
golden() {
    cat <<EOF
sgdisk --zap-all /dev/vda
sgdisk -n1:0:+2G -t1:EF00 -n2:0:0 -t2:8309 /dev/vda
udevadm settle
mkfs.fat -F32 -n EFI /dev/vda1
cryptsetup luksFormat --type luks2 --pbkdf argon2id --batch-mode --key-file - /dev/vda2 <secret
cryptsetup open --key-file - /dev/vda2 aios <secret
systemd-cryptenroll --unlock-key-file=/dev/stdin --recovery-key /dev/vda2 <secret
mkfs.btrfs -L aios /dev/mapper/aios
mkdir -p /mnt/aios-top
mount -t btrfs -o subvolid=5,compress=zstd /dev/mapper/aios /mnt/aios-top
btrfs subvolume create /mnt/aios-top/@blank
install -d -m 0755 /mnt/aios-top/@blank/usr
install -d -m 0755 /mnt/aios-top/@blank/etc
install -d -m 0755 /mnt/aios-top/@blank/persist
install -d -m 0755 /mnt/aios-top/@blank/home
install -d -m 0755 /mnt/aios-top/@blank/efi
install -d -m 0555 /mnt/aios-top/@blank/proc
install -d -m 0555 /mnt/aios-top/@blank/sys
install -d -m 0755 /mnt/aios-top/@blank/dev
install -d -m 0755 /mnt/aios-top/@blank/run
install -d -m 1777 /mnt/aios-top/@blank/tmp
install -d -m 0755 /mnt/aios-top/@blank/var
install -d -m 0755 /mnt/aios-top/@blank/var/log
install -d -m 0755 /mnt/aios-top/@blank/var/lib
install -d -m 0755 /mnt/aios-top/@blank/var/cache
install -d -m 1777 /mnt/aios-top/@blank/var/tmp
install -d -m 0750 /mnt/aios-top/@blank/root
ln -s usr/bin /mnt/aios-top/@blank/bin
ln -s usr/bin /mnt/aios-top/@blank/sbin
ln -s usr/lib /mnt/aios-top/@blank/lib
ln -s usr/lib /mnt/aios-top/@blank/lib64
ln -s ../../usr/lib/pacman /mnt/aios-top/@blank/var/lib/pacman
btrfs property set -ts /mnt/aios-top/@blank ro true
btrfs subvolume create /mnt/aios-top/@persist
btrfs subvolume create /mnt/aios-top/@home
btrfs subvolume create /mnt/aios-top/@log
install -d -m 0755 /mnt/aios-top/@persist/aios
cp -a $DEFAULTS /mnt/aios-top/@persist/aios/config
chown -R 0:0 /mnt/aios-top/@persist/aios/config
chmod -R u=rwX,go=rX /mnt/aios-top/@persist/aios/config
mv /mnt/aios-top/@persist/aios/config/home/@USERNAME@ /mnt/aios-top/@persist/aios/config/home/tester
write /mnt/aios-top/@persist/aios/config/manifest.toml 0644
git -C /mnt/aios-top/@persist/aios/config init -q -b main
git -C /mnt/aios-top/@persist/aios/config add -A
git -C /mnt/aios-top/@persist/aios/config -c user.name=aios -c user.email=aios@localhost commit -q -m 'aios: initial manifest'
install -d -m 0700 /mnt/aios-top/@persist/aios/secrets /mnt/aios-top/@persist/aios/secrets/passwd
write /mnt/aios-top/@persist/aios/secrets/passwd/tester 0600
cp -a $LIVE_REPO /mnt/aios-top/@persist/aios/repo
mkdir -p /mnt/aios-esp
mount -o umask=0077 /dev/vda1 /mnt/aios-esp
install -d -m 0700 /mnt/aios-top/@persist/var/lib/sbctl
mkdir -p /var/lib/sbctl
mount --bind /mnt/aios-top/@persist/var/lib/sbctl /var/lib/sbctl
sbctl create-keys
aios bootstrap --target /mnt/aios-top --esp /mnt/aios-esp --manifest /mnt/aios-top/@persist/aios/config/manifest.toml --luks-uuid 0b2a3c4d-1111-4222-8333-944455556666
bootctl install --esp-path=/mnt/aios-esp
write /mnt/aios-esp/loader/loader.conf
sbctl sign -s /mnt/aios-esp/EFI/systemd/systemd-bootx64.efi
sbctl sign -s /mnt/aios-esp/EFI/BOOT/BOOTX64.EFI
sbctl enroll-keys --microsoft
install -d -m 0700 /mnt/aios-top/@persist/var/lib/usbguard
write /mnt/aios-top/@persist/var/lib/usbguard/rules.conf 0600
umount -R /var/lib/sbctl
umount -R /mnt/aios-esp
umount -R /mnt/aios-top
cryptsetup close aios
systemctl reboot
EOF
}

@test "an unattended install runs the 13 steps' commands in order" {
    install_dry --config "$T/install.conf"

    [ "$status" -eq 0 ]
    diff <(golden) - <<<"$DRY"
}

@test "dry-run mode only runs read-only queries" {
    install_dry --config "$T/install.conf"

    [ "$status" -eq 0 ]
    diff - "$CALLS" <<'EOF'
mountpoint -q -- /mnt/aios-top
mountpoint -q -- /mnt/aios-esp
mountpoint -q -- /var/lib/sbctl
lsblk -ndro TYPE /dev/vda
findmnt -nro SOURCE /run/archiso/bootmnt
lsblk -ndro PKNAME /dev/sr0
lsblk -ndro RO /dev/vda
lsblk -nro MOUNTPOINTS /dev/vda
lsblk -ndbro SIZE /dev/vda
curl -sI --max-time 20 --retry 3 --retry-connrefused https://geo.mirror.pkgbuild.com
gpg --homedir /etc/pacman.d/gnupg --batch --no-permission-warning --with-colons --list-keys -- admin@cachyos.org
cryptsetup luksUUID /dev/vda2
mkpasswd -m yescrypt -s
sbctl status --json
usbguard generate-policy
findmnt -rno TARGET -S /dev/mapper/aios
EOF
}

@test "the log names each step, ends with the summary and never shows a secret" {
    install_dry --config "$T/install.conf"

    for n in $(seq 1 13); do
        grep -q "^aios-install: step $n/13: " <<<"$LOG" || { echo "no step $n"; return 1; }
    done
    [[ "$LOG" == *"installation complete: /dev/vda holds AIOS generation 1 for tester@aios-e2e"* ]]
    [[ "$LOG" == *"Secure Boot keys are enrolled"* ]]
    [[ "$LOG$output" != *e2e-user-pass* ]]
    [[ "$LOG$output" != *e2e-luks-passphrase* ]]
}

@test "on a CPU without x86-64-v3 the stripped pacman.conf is written too" {
    printf '#!/bin/sh\necho "  x86-64-v3"\n' >"$T/ld.so"

    install_dry --config "$T/install.conf"

    [ "$status" -eq 0 ]
    [[ "$LOG" == *"the CPU lacks x86-64-v3"* ]]
    manifest=$(grep -n '^write .*/config/manifest.toml 0644$' <<<"$DRY" | cut -d: -f1)
    pacman=$(grep -n '^write .*/config/files/pacman.conf 0644$' <<<"$DRY" | cut -d: -f1)
    init=$(grep -n ' init -q -b main$' <<<"$DRY" | cut -d: -f1)
    [ "$((manifest + 1))" -eq "$pacman" ]
    [ "$((pacman + 1))" -eq "$init" ]
    [ "$(wc -l <<<"$DRY")" -eq "$(($(golden | wc -l) + 1))" ]
}

@test "outside Setup Mode no keys are enrolled and the summary says what to do" {
    setup_mode false

    install_dry --config "$T/install.conf"

    [ "$status" -eq 0 ]
    [[ "$DRY" != *"enroll-keys"* ]]
    [[ "$LOG" == *"Secure Boot keys are NOT enrolled"*"run0 aios secureboot enroll"* ]]
}

@test "a failing step is named, then everything is unmounted newest first and LUKS closed" {
    export AIOS_INSTALL_DRYRUN_FAILS="$T/fails"
    golden | grep '^aios bootstrap ' >"$AIOS_INSTALL_DRYRUN_FAILS"

    install_dry --config "$T/install.conf"

    [ "$status" -eq 1 ]
    [[ "$LOG" == *"step 9 (bootstrap) failed (exit 1)"* ]]
    [ "$(sed -n '/^aios bootstrap /,$p' <<<"$DRY" | tail -n +2)" = "$(printf '%s\n' \
        'umount -R /var/lib/sbctl' 'umount -R /mnt/aios-esp' 'umount -R /mnt/aios-top' 'cryptsetup close aios')" ]
}

@test "the cleanup also unmounts what else is mounted from the mapping, deepest first" {
    export AIOS_INSTALL_DRYRUN_FAILS="$T/fails"
    golden | grep '^aios bootstrap ' >"$AIOS_INSTALL_DRYRUN_FAILS"
    mkdir -p "$FAKE_SYS/mnt/dev/mapper"
    printf '%s\n' /mnt/aios-top /mnt/aios-top/@home /run/aios/top/@persist/x >"$FAKE_SYS/mnt/dev/mapper/aios"

    install_dry --config "$T/install.conf"

    [ "$status" -eq 1 ]
    [ "$(sed -n '/^aios bootstrap /,$p' <<<"$DRY" | tail -n +5)" = "$(printf '%s\n' \
        'umount -R /run/aios/top/@persist/x' 'umount -R /mnt/aios-top/@home' 'umount -R /mnt/aios-top' \
        'cryptsetup close aios')" ]
}

@test "a failure after LUKS opens but before any mount only closes LUKS" {
    export AIOS_INSTALL_DRYRUN_FAILS="$T/fails"
    echo "mkfs.btrfs -L aios /dev/mapper/aios" >"$AIOS_INSTALL_DRYRUN_FAILS"

    install_dry --config "$T/install.conf"

    [ "$status" -eq 1 ]
    [[ "$LOG" == *"step 5 (btrfs) failed"* ]]
    [ "$(tail -n 2 <<<"$DRY")" = "$(printf '%s\n' 'mkfs.btrfs -L aios /dev/mapper/aios' 'cryptsetup close aios')" ]
}

@test "a failure before LUKS opens leaves nothing to clean up" {
    export AIOS_INSTALL_DRYRUN_FAILS="$T/fails"
    echo "mkfs.fat -F32 -n EFI /dev/vda1" >"$AIOS_INSTALL_DRYRUN_FAILS"

    install_dry --config "$T/install.conf"

    [ "$status" -eq 1 ]
    [[ "$LOG" == *"step 3 (partition) failed"* ]]
    [[ "$LOG" == *"the disk is left in an undefined state"* ]]
    [ "$(tail -n 1 <<<"$DRY")" = "mkfs.fat -F32 -n EFI /dev/vda1" ]
}

@test "preflight problems stop the install before the disk is touched" {
    sed -i 's/^WIPE=yes$/WIPE=no/' "$T/install.conf"
    install_dry --config "$T/install.conf"
    [ "$status" -eq 1 ]
    [ -z "$DRY" ]
    [[ "$LOG" == *"erases DISK only with WIPE=yes"* ]]
    [[ "$LOG" == *"nothing on the disk was changed"* ]]
    [[ "$LOG" != *"undefined state"* ]]

    sed -i 's/^WIPE=no$/WIPE=yes/' "$T/install.conf"
    keyring 0123456789ABCDEF0123456789ABCDEF01234567
    install_dry --config "$T/install.conf"
    [ "$status" -eq 1 ]
    [ -z "$DRY" ]
    [[ "$LOG" == *"the live pacman keyring trusts the CachyOS keys [0123456789ABCDEF0123456789ABCDEF01234567]"* ]]

    keyring "$FPR"
    echo 6 >"$FAKE_SYS/curl.rc"
    install_dry --config "$T/install.conf"
    [ "$status" -eq 1 ]
    [ -z "$DRY" ]
    [[ "$LOG" == *"no network"* ]]
    [[ "$LOG" == *"step 1 (preflight) failed"* ]]
}

@test "a mount point the installer needs that is already in use stops the preflight" {
    echo /var/lib/sbctl >"$FAKE_SYS/mounted"

    install_dry --config "$T/install.conf"

    [ "$status" -eq 1 ]
    [ -z "$DRY" ]
    [[ "$LOG" == *"/var/lib/sbctl is already a mount point on the live system"* ]]
}

@test "--auto installs from the fw_cfg config, and exits 0 without one" {
    install_dry --auto
    [ "$status" -eq 0 ]
    [ -z "$DRY" ]
    [[ "$LOG" == *"no fw_cfg install config (opt/aios/install.conf)"* ]]
    grep -qx 'modprobe -q qemu_fw_cfg' "$CALLS"

    mkdir -p "$AIOS_FWCFG_DIR/by_name/opt/aios/install.conf"
    cat "$T/install.conf" >"$AIOS_FWCFG_DIR/by_name/opt/aios/install.conf/raw"
    install_dry --auto
    [ "$status" -eq 0 ]
    [[ "$LOG" == *"unattended install from $AIOS_FWCFG_DIR/by_name/opt/aios/install.conf/raw"* ]]
    diff <(golden) - <<<"$DRY"
}

@test "without arguments the fw_cfg config is used when present" {
    mkdir -p "$AIOS_FWCFG_DIR/by_name/opt/aios/install.conf"
    cat "$T/install.conf" >"$AIOS_FWCFG_DIR/by_name/opt/aios/install.conf/raw"

    install_dry

    [ "$status" -eq 0 ]
    diff <(golden) - <<<"$DRY"
}

@test "interactive mode asks for each value and needs the disk path typed back" {
    answers=$'/dev/vda\naios-e2e\ntester\ne2e-user-pass\ne2e-user-pass\ne2e-luks-passphrase\ne2e-luks-passphrase\nUTC\n'

    run --separate-stderr "$SCRIPT" <<<"${answers}/dev/vda"
    [ "$status" -eq 0 ]
    diff <(golden | sed '$d') <(grep '^DRYRUN ' <<<"$output" | sed 's/^DRYRUN //')

    run --separate-stderr "$SCRIPT" <<<"${answers}yes"
    [ "$status" -eq 1 ]
    [[ "$stderr" == *"not confirmed; nothing was changed"* ]]
    [[ "$output" != *DRYRUN* ]]
}
