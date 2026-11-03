#!/usr/bin/env bats
# installer/aios-install end to end in dry-run mode (spec §6.2, §7, §9): the ordered list of
# commands that change the system, what actually runs (read-only queries only), the failure
# trap, and the unattended/interactive/--auto entry points.
# bats sets $stderr for `run --separate-stderr`; each test runs in a subshell; literal $ in
# single quotes is test data (fake hooks).
# shellcheck disable=SC2016,SC2030,SC2031,SC2154

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
    export FAKE_SYS="$T/sys" CALLS="$T/calls" AIOS_SYS_BLOCK="$T/sysfs"
    : >"$CALLS"
    blk vda disk $((20 * 1024 * 1024 * 1024)) 0 ""
    blk sr0 rom 1073741824 1 /run/archiso/bootmnt
    mkdir -p "$FAKE_SYS/mnt/run/archiso"
    echo /dev/sr0 >"$FAKE_SYS/mnt/run/archiso/bootmnt"
    keyring "$FPR"
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
    export AIOS_CACHYOS_MIRRORLIST="$T/cachyos-mirrorlist"
    echo 'Server = https://cdn77.cachyos.org/repo/$arch/$repo' >"$AIOS_CACHYOS_MIRRORLIST"
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
    command -p chmod 0600 "$T/install.conf"

    # Queries answer from $FAKE_SYS. Every other tool is `record`: dry-run must never call it.
    # (So the tests below write files with redirections, not with cp.)
    mkdir -p "$T/bin"
    for n in lsblk findmnt mountpoint gpg mkpasswd sbctl usbguard curl modprobe; do
        ln -s "$BATS_TEST_DIRNAME/fakes/installer" "$T/bin/$n"
    done
    for n in wipefs sgdisk blockdev udevadm mkfs.fat cryptsetup systemd-cryptenroll mkfs.btrfs btrfs \
        mount umount git aios bootctl install cp mv chown chmod systemctl; do
        ln -s "$BATS_TEST_DIRNAME/fakes/record" "$T/bin/$n"
    done
    PATH="$T/bin:$PATH"
    # The golden quotes paths the way the installer prints them.
    # shellcheck source=/dev/null
    source "$ROOT/installer/lib/common.sh"
}

# blk NAME TYPE SIZE RO MOUNTPOINTS: a fake block device /dev/NAME with nothing on it, its
# lsblk answers, and its sysfs diskseq (7) and holders/.
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
    printf 'aios-e2e-disk\n' >"$d/SERIAL"
    printf 'NAME SIZE FSTYPE LABEL MODEL\n%s   20G              QEMU HARDDISK\n' "$1" \
        >"$d/NAME,SIZE,FSTYPE,LABEL,MODEL"
    echo 7 >"$AIOS_SYS_BLOCK/$1/diskseq"
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

# golden [DISK PART1 PART2]: the commands of an unattended install (/dev/vda by default) on
# a v3 CPU in Setup Mode, in order. golden_auto: the same for --auto, which reboots at the end.
golden() {
    local disk=${1:-/dev/vda} p1=${2:-/dev/vda1} p2=${3:-/dev/vda2}
    cat <<EOF
wipefs -a $disk
sgdisk --zap-all $disk
sgdisk -n1:0:+2G -t1:EF00 -n2:0:0 -t2:8309 $disk
udevadm settle
blockdev --rereadpt $disk
udevadm settle
wipefs -a $p1 $p2
mkfs.fat -F32 -n EFI $p1
cryptsetup luksFormat --type luks2 --pbkdf argon2id --batch-mode --key-file - $p2 <secret
cryptsetup open --key-file - $p2 aios <secret
systemd-cryptenroll --unlock-key-file=/dev/stdin --recovery-key $p2 <secret
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
cp -a $(quote_cmd "$DEFAULTS") /mnt/aios-top/@persist/aios/config
chown -R 0:0 /mnt/aios-top/@persist/aios/config
chmod -R u=rwX,go=rX /mnt/aios-top/@persist/aios/config
mv /mnt/aios-top/@persist/aios/config/home/@USERNAME@ /mnt/aios-top/@persist/aios/config/home/tester
write /mnt/aios-top/@persist/aios/config/manifest.toml 0644
git -C /mnt/aios-top/@persist/aios/config init -q -b main
git -C /mnt/aios-top/@persist/aios/config add -A
git -C /mnt/aios-top/@persist/aios/config -c user.name=aios -c user.email=aios@localhost commit -q -m 'aios: initial manifest'
install -d -m 0700 /mnt/aios-top/@persist/aios/secrets /mnt/aios-top/@persist/aios/secrets/passwd
write /mnt/aios-top/@persist/aios/secrets/passwd/tester 0600
cp -a $(quote_cmd "$LIVE_REPO") /mnt/aios-top/@persist/aios/repo
mkdir -p /efi
mount -o umask=0077 $p1 /efi
install -d -m 0700 /mnt/aios-top/@persist/var/lib/sbctl
mkdir -p /var/lib/sbctl
mount --bind /mnt/aios-top/@persist/var/lib/sbctl /var/lib/sbctl
sbctl create-keys
aios bootstrap --target /mnt/aios-top --esp /efi --manifest /mnt/aios-top/@persist/aios/config/manifest.toml --luks-uuid 00000000-0000-0000-0000-000000000000
bootctl install --esp-path=/efi
write /efi/loader/loader.conf
sbctl sign -s /efi/EFI/systemd/systemd-bootx64.efi
sbctl sign -s /efi/EFI/BOOT/BOOTX64.EFI
sbctl enroll-keys --microsoft
install -d -m 0700 /mnt/aios-top/@persist/var/lib/usbguard
write /mnt/aios-top/@persist/var/lib/usbguard/rules.conf 0600
umount -R /var/lib/sbctl
umount -R /efi
umount -R /mnt/aios-top
cryptsetup close aios
EOF
}

golden_auto() {
    golden
    echo systemctl reboot
}

@test "an unattended install runs the 13 steps' commands in order" {
    install_dry --config "$T/install.conf"

    [ "$status" -eq 0 ]
    diff <(golden) - <<<"$DRY"
    [[ "$LOG" != *"Press Enter"* ]]
    [[ "$LOG" == *"remove the install medium, then reboot into AIOS: systemctl reboot"* ]]
}

@test "an NVMe disk gets partitions p1 and p2" {
    blk nvme0n1 disk $((512 * 1024 * 1024 * 1024)) 0 ""
    sed -i 's|^DISK=.*|DISK=/dev/nvme0n1|' "$T/install.conf"

    install_dry --config "$T/install.conf"

    [ "$status" -eq 0 ]
    diff <(golden /dev/nvme0n1 /dev/nvme0n1p1 /dev/nvme0n1p2) - <<<"$DRY"
}

@test "paths with spaces are quoted in the commands" {
    export AIOS_DEFAULTS="$T/default manifest" AIOS_LIVE_REPO="$T/live repo"
    command -p cp -r "$ROOT/manifest" "$AIOS_DEFAULTS"
    command -p cp -r "$T/repo" "$AIOS_LIVE_REPO"
    DEFAULTS=$AIOS_DEFAULTS LIVE_REPO=$AIOS_LIVE_REPO

    install_dry --config "$T/install.conf"

    [ "$status" -eq 0 ]
    grep -qxF "cp -a '$T/default manifest' /mnt/aios-top/@persist/aios/config" <<<"$DRY"
    diff <(golden) - <<<"$DRY"
}

@test "the ESP is mounted at /efi, so sbctl saves the paths the installed system uses" {
    install_dry --config "$T/install.conf"

    [ "$status" -eq 0 ]
    grep -qx 'mount -o umask=0077 /dev/vda1 /efi' <<<"$DRY"
    grep -qx 'sbctl sign -s /efi/EFI/systemd/systemd-bootx64.efi' <<<"$DRY"
    grep -q '^aios bootstrap .* --esp /efi ' <<<"$DRY"
    grep -qx 'bootctl install --esp-path=/efi' <<<"$DRY"
    [ "$(grep -c aios-esp <<<"$DRY")" -eq 0 ]
}

@test "on a terminal the installer waits for Enter after the recovery key; only --auto reboots" {
    command -v script >/dev/null || skip "script (util-linux) is not installed"

    run script -qec "$(printf '%q ' "$SCRIPT" --config "$T/install.conf")" /dev/null <<<""
    out=$(tr -d '\r' <<<"$output")
    [ "$status" -eq 0 ]
    [[ "$out" == *"recovery key (shown only now"*"DRYRUN systemd-cryptenroll"*"Press Enter after writing down the recovery key: "*"DRYRUN mkfs.btrfs"* ]]
    [[ "$out" != *"DRYRUN systemctl reboot"* ]]

    mkdir -p "$AIOS_FWCFG_DIR/by_name/opt/aios/install.conf"
    cat "$T/install.conf" >"$AIOS_FWCFG_DIR/by_name/opt/aios/install.conf/raw"
    run script -qec "$(printf '%q ' "$SCRIPT" --auto)" /dev/null <<<""
    out=$(tr -d '\r' <<<"$output")
    [ "$status" -eq 0 ]
    [[ "$out" != *"Press Enter"* ]]
    [[ "$out" == *"rebooting into AIOS"*"DRYRUN systemctl reboot"* ]]
}

@test "dry-run mode only runs read-only queries" {
    install_dry --config "$T/install.conf"

    [ "$status" -eq 0 ]
    diff - "$CALLS" <<'EOF'
mountpoint -q -- /mnt/aios-top
mountpoint -q -- /efi
mountpoint -q -- /var/lib/sbctl
lsblk -ndro TYPE /dev/vda
findmnt -nro SOURCE /run/archiso/bootmnt
lsblk -nrso NAME,TYPE /dev/sr0
lsblk -ndro RO /dev/vda
lsblk -nro MOUNTPOINTS /dev/vda
lsblk -nro NAME,TYPE /dev/vda
lsblk -ndbro SIZE /dev/vda
lsblk -ndo MODEL /dev/vda
lsblk -ndo SERIAL /dev/vda
curl -fsI --max-time 20 --retry 3 --retry-connrefused https://geo.mirror.pkgbuild.com
curl -fsI --max-time 20 --retry 3 --retry-connrefused https://cdn77.cachyos.org/repo/x86_64/cachyos/cachyos.db
gpg --homedir /etc/pacman.d/gnupg --batch --no-permission-warning --with-colons --list-keys -- admin@cachyos.org
mkpasswd -m yescrypt -s
usbguard generate-policy
lsblk -o NAME,SIZE,FSTYPE,LABEL,MODEL /dev/vda
sbctl status --json
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
        'umount -R /var/lib/sbctl' 'umount -R /efi' 'umount -R /mnt/aios-top' 'cryptsetup close aios')" ]
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

@test "before the wipe the log shows which disk it is and what is on it" {
    install_dry --config "$T/install.conf"

    [ "$status" -eq 0 ]
    [[ "$LOG" == *"aios-install: /dev/vda: model QEMU HARDDISK, serial aios-e2e-disk, 20 GiB (21474836480 bytes), diskseq 7"* ]]
    [[ "$LOG" == *"NAME SIZE FSTYPE LABEL MODEL"$'\n'"vda   20G              QEMU HARDDISK"* ]]
}

@test "a disk that changes between validation and the wipe is left alone" {
    # Another disk takes the name while the confirmation is shown.
    printf '[ "$2" != NAME,SIZE,FSTYPE,LABEL,MODEL ] || echo 8 >"%s"\n' \
        "$AIOS_SYS_BLOCK/vda/diskseq" >"$FAKE_SYS/hook.lsblk"

    install_dry --config "$T/install.conf"

    [ "$status" -eq 1 ]
    [ -z "$DRY" ]
    [[ "$LOG" == *"/dev/vda: disk changed since validation (diskseq 7, now 8)"* ]]
    [[ "$LOG" == *"step 3 (partition) failed"* ]]
    [[ "$LOG" == *"nothing on the disk was changed"* ]]
}

@test "the kernel must re-read the new partition table" {
    export AIOS_INSTALL_DRYRUN_FAILS="$T/fails"
    echo "blockdev --rereadpt /dev/vda" >"$AIOS_INSTALL_DRYRUN_FAILS"

    install_dry --config "$T/install.conf"

    [ "$status" -eq 1 ]
    [ "$(tail -n 1 <<<"$DRY")" = "blockdev --rereadpt /dev/vda" ]
    [ "$(grep -c '^blockdev --rereadpt /dev/vda$' <<<"$DRY")" -eq 5 ]
    [[ "$LOG" == *"the kernel did not re-read the new partition table of /dev/vda"* ]]
}

@test "a disk in use by LVM is refused before anything is changed" {
    printf '%s\n' "vda1 part" "vg0-root lvm" >>"$FAKE_SYS/blk/vda/NAME,TYPE"

    install_dry --config "$T/install.conf"

    [ "$status" -eq 1 ]
    [ -z "$DRY" ]
    [[ "$LOG" == *"/dev/vda is in use by vg0-root (LVM/MD/dm); deactivate it first"* ]]
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

@test "the password hash, the USB policy and EXTRA_CMDLINE are checked before anything changes" {
    echo 'block id 1234:5678' >"$FAKE_SYS/usbguard-policy"
    install_dry --config "$T/install.conf"
    [ "$status" -eq 1 ]
    [ -z "$DRY" ]
    [[ "$LOG" == *"not an allow rule: block id 1234:5678"* ]]
    [[ "$LOG" == *"step 1 (preflight) failed"* ]]

    rm "$FAKE_SYS/usbguard-policy"
    install_dry --config "$T/install.conf"
    [ "$status" -eq 1 ]
    [ -z "$DRY" ]
    [[ "$LOG" == *"usbguard generate-policy failed"* ]]

    echo 'allow id 1d6b:0002' >"$FAKE_SYS/usbguard-policy"
    echo 1 >"$FAKE_SYS/mkpasswd.rc"
    install_dry --config "$T/install.conf"
    [ "$status" -eq 1 ]
    [ -z "$DRY" ]
    [[ "$LOG" == *"mkpasswd -m yescrypt -s failed"* ]]

    rm "$FAKE_SYS/mkpasswd.rc"
    sed -i 's/^EXTRA_CMDLINE=.*/EXTRA_CMDLINE=quiet x=@USERNAME@/' "$T/install.conf"
    install_dry --config "$T/install.conf"
    [ "$status" -eq 1 ]
    [ -z "$DRY" ]
    [[ "$LOG" == *"EXTRA_CMDLINE word 'x=@USERNAME@' may only hold"* ]]
}

@test "a manifest template or pacman.conf the installer cannot use is found in preflight" {
    export AIOS_DEFAULTS="$T/defaults"
    command -p cp -r "$ROOT/manifest" "$AIOS_DEFAULTS"
    echo '# @ROOTPW@' >>"$AIOS_DEFAULTS/manifest.toml"
    install_dry --config "$T/install.conf"
    [ "$status" -eq 1 ]
    [ -z "$DRY" ]
    [[ "$LOG" == *"unknown placeholder @ROOTPW@"* ]]

    command -p cp "$ROOT/manifest/manifest.toml" "$AIOS_DEFAULTS/manifest.toml"
    echo '# BEGIN v3' >>"$AIOS_DEFAULTS/files/pacman.conf"
    printf '#!/bin/sh\necho "  x86-64-v3"\n' >"$T/ld.so"
    install_dry --config "$T/install.conf"
    [ "$status" -eq 1 ]
    [ -z "$DRY" ]
    [[ "$LOG" == *"# BEGIN v3 is never closed"* ]]

    command -p cp "$ROOT/manifest/files/pacman.conf" "$AIOS_DEFAULTS/files/pacman.conf"
    command -p mv "$AIOS_DEFAULTS/home/@USERNAME@" "$AIOS_DEFAULTS/home/eli"
    install_dry --config "$T/install.conf"
    [ "$status" -eq 1 ]
    [ -z "$DRY" ]
    [[ "$LOG" == *"no home/@USERNAME@ template in $AIOS_DEFAULTS"* ]]
}

@test "a failure once AIOS is installed does not call the disk broken" {
    export AIOS_INSTALL_DRYRUN_FAILS="$T/fails"
    echo "systemctl reboot" >"$AIOS_INSTALL_DRYRUN_FAILS"
    mkdir -p "$AIOS_FWCFG_DIR/by_name/opt/aios/install.conf"
    cat "$T/install.conf" >"$AIOS_FWCFG_DIR/by_name/opt/aios/install.conf/raw"

    install_dry --auto

    [ "$status" -eq 1 ]
    [[ "$LOG" == *"AIOS is installed on the disk; only the end of step 13 failed: reboot by hand"* ]]
    [[ "$LOG" != *"undefined state"* ]]
}

@test "the passwords are forgotten as soon as they have been used" {
    # A probe: at the start of each step, save what the installer still holds.
    export PROBE="$T/probe"
    cat >>"$T/lib/keys.sh" <<'EOF'
eval "orig_$(declare -f step)"
step() {
    { declare -p CFG; declare -p PASSWD_HASH; } >"$PROBE.$1" 2>&1 || true
    orig_step "$@"
}
EOF

    install_dry --config "$T/install.conf"

    [ "$status" -eq 0 ]
    # The user password is hashed in preflight, then dropped.
    [ -s "$PROBE.2" ] && [ -s "$PROBE.5" ]
    run ! grep -q -e USER_PASSWORD -e e2e-user-pass "$PROBE.2"
    grep -qF 'PASSWD_HASH="\$y\$j9T\$fakesalt' "$PROBE.2"
    # The LUKS passphrase is gone once step 4 used it.
    grep -q '\[LUKS_PASSPHRASE\]="e2e-luks-passphrase"' "$PROBE.4"
    run ! grep -q -e LUKS_PASSPHRASE -e e2e-luks-passphrase "$PROBE.5"
}

@test "aios-install refuses to run under xtrace, which would print the passwords" {
    run --separate-stderr bash -x "$SCRIPT" --config "$T/install.conf" </dev/null

    [ "$status" -eq 1 ]
    [[ "$stderr" == *"aios-install: error: refusing to run with xtrace (bash -x): the trace would show the passwords"* ]]
    [[ "$output$stderr" != *DRYRUN* ]]
    [[ "$output$stderr" != *e2e-user-pass* ]]
}

@test "a --config file is warned about when others can read it, and the summary says to delete it" {
    install_dry --config "$T/install.conf"
    [ "$status" -eq 0 ]
    [[ "$LOG" != *"is readable by group or others"* ]]
    [[ "$LOG" == *"delete $T/install.conf now: it holds the passwords in clear text"* ]]

    command -p chmod 0644 "$T/install.conf"
    install_dry --config "$T/install.conf"
    [ "$status" -eq 0 ]
    [[ "$LOG" == *"warning: $T/install.conf is readable by group or others (mode 644)"* ]]

    # The fw_cfg file is the VM's, not the user's: no warning, nothing to delete.
    mkdir -p "$AIOS_FWCFG_DIR/by_name/opt/aios/install.conf"
    cat "$T/install.conf" >"$AIOS_FWCFG_DIR/by_name/opt/aios/install.conf/raw"
    command -p chmod 0644 "$AIOS_FWCFG_DIR/by_name/opt/aios/install.conf/raw"
    install_dry --auto
    [ "$status" -eq 0 ]
    [[ "$LOG" != *"is readable by group or others"* ]]
    [[ "$LOG" != *"delete "* ]]
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
    [[ "$LOG" == *"rebooting into AIOS"* ]]
    diff <(golden_auto) - <<<"$DRY"
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
    [[ "$stderr" == *"/dev/vda: model QEMU HARDDISK, serial aios-e2e-disk, 20 GiB"*"Everything on /dev/vda will be erased. Type /dev/vda to continue: "* ]]
    diff <(golden) <(grep '^DRYRUN ' <<<"$output" | sed 's/^DRYRUN //')

    run --separate-stderr "$SCRIPT" <<<"${answers}yes"
    [ "$status" -eq 1 ]
    [[ "$stderr" == *"not confirmed; nothing was changed"* ]]
    [[ "$output" != *DRYRUN* ]]
}
