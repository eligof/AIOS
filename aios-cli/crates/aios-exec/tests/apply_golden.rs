mod common;

use aios_exec::{Output, Step};
use common::{mkdir, write, Fixture, CLEANUP_MOUNTED, MANIFEST};
use std::fs;

const APPLY: &str = "
mount -t btrfs -o subvolid=5 /dev/mapper/aios {top}
git -C {config} status --porcelain
git -C {config} rev-parse --short HEAD
btrfs subvolume snapshot {top}/@usr-gen-0007 {top}/@usr-cand
btrfs subvolume snapshot {top}/@etc-gen-0007 {top}/@etc-cand
btrfs subvolume snapshot {top}/@blank {top}/@root-cand
mount --bind {top}/@root-cand {cand}
mount --bind {top}/@usr-cand {cand}/usr
mount --bind {top}/@etc-cand {cand}/etc
mount --bind {persist}/var/cache/pacman/pkg {cand}/var/cache/pacman/pkg
mount --bind {log} {cand}/var/log
mount --bind {persist}/aios/repo {cand}/persist/aios/repo
arch-chroot {cand} pacman -Syu --needed --noconfirm {set}
arch-chroot {cand} pacman -Qqe
arch-chroot {cand} pacman -Rns --noconfirm nano
arch-chroot {cand} pacman -D --asexplicit {set}
arch-chroot {cand} pacman -Qdtq
arch-chroot {cand} pacman -Rns --noconfirm libnano
arch-chroot {cand} pacman -Q linux-cachyos linux-cachyos-lts
arch-chroot {cand} pacman -Qq
arch-chroot {cand} locale-gen
arch-chroot {cand} chown -h root:wheel /etc/usbguard/usbguard-daemon.conf
systemctl --root={cand} enable NetworkManager.service aios-health.service fwupd-refresh.timer
systemctl --root={cand} disable bluetooth.service
systemctl --root={cand} mask sshd.socket
arch-chroot {cand} mkinitcpio -k 7.3.0-4-cachyos -g /var/tmp/aios/initramfs-cachyos.img
arch-chroot {cand} ukify build --linux=/usr/lib/modules/7.3.0-4-cachyos/vmlinuz --initrd=/var/tmp/aios/initramfs-cachyos.img --cmdline=@/etc/kernel/cmdline --os-release=@/usr/lib/os-release --output=/var/tmp/aios/aios-gen-0008-cachyos.efi
arch-chroot {cand} mkinitcpio -k 6.18.55-2-cachyos-lts -g /var/tmp/aios/initramfs-lts.img
arch-chroot {cand} ukify build --linux=/usr/lib/modules/6.18.55-2-cachyos-lts/vmlinuz --initrd=/var/tmp/aios/initramfs-lts.img --cmdline=@/etc/kernel/cmdline --os-release=@/usr/lib/os-release --output=/var/tmp/aios/aios-gen-0008-lts.efi
sbctl sign {cand}/var/tmp/aios/aios-gen-0008-cachyos.efi
sbctl sign {cand}/var/tmp/aios/aios-gen-0008-lts.efi
df --output=avail -B1 {esp}
umount -R {cand}
btrfs property set -ts {top}/@usr-cand ro true
btrfs property set -ts {top}/@etc-cand ro true
bootctl set-default ''
btrfs subvolume show {top}/@root-cand
btrfs subvolume delete --recursive {top}/@root-cand
umount {top}
";

const BOOTSTRAP: &str = "
git -C {config} status --porcelain
git -C {config} rev-parse --short HEAD
btrfs subvolume create {top}/@usr-cand
btrfs subvolume create {top}/@etc-cand
btrfs subvolume snapshot {top}/@blank {top}/@root-cand
mount --bind {top}/@root-cand {cand}
mount --bind {top}/@usr-cand {cand}/usr
mount --bind {top}/@etc-cand {cand}/etc
mount --bind {persist}/var/cache/pacman/pkg {cand}/var/cache/pacman/pkg
mount --bind {log} {cand}/var/log
mount --bind {persist}/aios/repo {cand}/persist/aios/repo
pacstrap -C {run}/aios-pacstrap.conf {cand} {set}
arch-chroot {cand} pacman-key --init
arch-chroot {cand} pacman-key --populate archlinux cachyos
arch-chroot {cand} pacman -Q linux-cachyos linux-cachyos-lts
arch-chroot {cand} pacman -Qq
arch-chroot {cand} locale-gen
arch-chroot {cand} chown -h root:wheel /etc/usbguard/usbguard-daemon.conf
chown 1000:1000 {home}/eli
systemctl --root={cand} enable NetworkManager.service aios-health.service fwupd-refresh.timer
systemctl --root={cand} disable bluetooth.service
systemctl --root={cand} mask sshd.socket
arch-chroot {cand} mkinitcpio -k 7.3.0-4-cachyos -g /var/tmp/aios/initramfs-cachyos.img
arch-chroot {cand} ukify build --linux=/usr/lib/modules/7.3.0-4-cachyos/vmlinuz --initrd=/var/tmp/aios/initramfs-cachyos.img --cmdline=@/etc/kernel/cmdline --os-release=@/usr/lib/os-release --output=/var/tmp/aios/aios-gen-0001-cachyos.efi
arch-chroot {cand} mkinitcpio -k 6.18.55-2-cachyos-lts -g /var/tmp/aios/initramfs-lts.img
arch-chroot {cand} ukify build --linux=/usr/lib/modules/6.18.55-2-cachyos-lts/vmlinuz --initrd=/var/tmp/aios/initramfs-lts.img --cmdline=@/etc/kernel/cmdline --os-release=@/usr/lib/os-release --output=/var/tmp/aios/aios-gen-0001-lts.efi
sbctl sign {cand}/var/tmp/aios/aios-gen-0001-cachyos.efi
sbctl sign {cand}/var/tmp/aios/aios-gen-0001-lts.efi
df --output=avail -B1 {esp}
umount -R {cand}
btrfs property set -ts {top}/@usr-cand ro true
btrfs property set -ts {top}/@etc-cand ro true
btrfs subvolume show {top}/@root-cand
btrfs subvolume delete --recursive {top}/@root-cand
";

fn esp(fx: &Fixture) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(fx.layout.uki_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn golden_apply() {
    let fx = Fixture::booted();
    let outcome = fx.run().unwrap();
    assert_eq!(fx.calls(), fx.expand(APPLY));
    assert_eq!(outcome.gen, aios_gen::GenId(8));
    assert_eq!(
        outcome.ukis,
        ["aios-gen-0008-cachyos+3.efi", "aios-gen-0008-lts+3.efi"]
    );
}

#[test]
fn golden_bootstrap() {
    let fx = Fixture::fresh();
    let outcome = fx.run().unwrap();
    assert_eq!(fx.calls(), fx.expand(BOOTSTRAP));
    assert_eq!(outcome.gen, aios_gen::GenId(1));
}

#[test]
fn the_new_generation_lands_on_disk_and_on_the_esp() {
    let fx = Fixture::booted();
    fx.run().unwrap();
    let l = &fx.layout;
    assert!(l.subvol("@usr-gen-0008").is_dir());
    assert!(l.subvol("@etc-gen-0008").is_dir());
    fx.assert_no_candidates();
    assert_eq!(
        esp(&fx),
        [
            "aios-gen-0006-cachyos.efi",
            "aios-gen-0007-cachyos.efi",
            "aios-gen-0008-cachyos+3.efi",
            "aios-gen-0008-lts+3.efi",
        ]
    );
    let uki = fs::read_to_string(l.uki_dir().join("aios-gen-0008-lts+3.efi")).unwrap();
    assert_eq!(uki, "UKI lts");
}

#[test]
fn bootstrap_on_a_target_with_generations_is_refused() {
    let fx = Fixture::fresh();
    mkdir(&fx.layout.subvol("@usr-gen-0001"));
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::MountTop);
    assert_eq!(
        err.detail,
        format!("{} already holds generations", fx.layout.top.display())
    );
    assert!(fx.calls().is_empty());
}

#[test]
fn without_a_fallback_kernel_one_uki_is_built() {
    let mut fx = Fixture::booted();
    fx.set_manifest(&MANIFEST.replace("fallback = \"linux-cachyos-lts\"\n", ""));
    let outcome = fx.run().unwrap();
    assert_eq!(outcome.ukis, ["aios-gen-0008-cachyos+3.efi"]);
    assert!(fx
        .calls()
        .contains(&"arch-chroot {cand} pacman -Q linux-cachyos".to_string()));
    let ukify = "arch-chroot {cand} ukify";
    assert_eq!(
        fx.calls().iter().filter(|c| c.starts_with(ukify)).count(),
        1
    );
}

#[test]
fn stale_esp_copies_are_removed() {
    let fx = Fixture::booted();
    write(
        &fx.layout.uki_dir().join("aios-gen-0005-cachyos+3.efi.tmp"),
        "x",
        0o644,
    );
    fx.run().unwrap();
    assert!(!esp(&fx).iter().any(|name| name.ends_with(".tmp")));
}

#[test]
fn a_kernel_without_modules_fails_the_uki_step() {
    let fx = Fixture::booted();
    fs::remove_file(
        fx.layout
            .cand
            .join("usr/lib/modules/6.18.55-2-cachyos-lts/pkgbase"),
    )
    .unwrap();
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::Uki);
    assert_eq!(
        err.detail,
        "no /usr/lib/modules/*/pkgbase names linux-cachyos-lts"
    );
}

#[test]
fn a_failed_initramfs_cleans_up() {
    let mut fx = Fixture::booted();
    let cand = fx.layout.cand.display().to_string();
    fx.runner.fail_on(&["arch-chroot", &cand, "mkinitcpio"]);
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::Uki);
    assert_eq!(
        fx.calls_after("arch-chroot {cand} mkinitcpio"),
        fx.expand(CLEANUP_MOUNTED)
    );
    fx.assert_no_candidates();
}

#[test]
fn a_failed_signature_cleans_up_and_leaves_the_esp_alone() {
    let mut fx = Fixture::booted();
    fx.runner.fail_on(&["sbctl"]);
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::Sign);
    assert_eq!(fx.calls_after("sbctl"), fx.expand(CLEANUP_MOUNTED));
    assert_eq!(
        esp(&fx),
        ["aios-gen-0006-cachyos.efi", "aios-gen-0007-cachyos.efi"]
    );
}

#[test]
fn a_full_esp_runs_gc_then_fails() {
    let mut fx = Fixture::booted();
    fx.runner.respond(&["df"], Output::ok("Avail\n10\n"));
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::EspSpace);
    assert_eq!(
        err.detail,
        format!(
            "{} has 10 bytes free, the new UKIs need 22",
            fx.layout.esp.display()
        )
    );
    let mut expected = fx.expand("df --output=avail -B1 {esp}");
    expected.extend(fx.expand(CLEANUP_MOUNTED));
    assert_eq!(
        fx.calls_after("df"),
        expected,
        "gc found nothing old enough to delete"
    );
}

#[test]
fn a_failed_finalize_deletes_the_candidates_and_esp_copies() {
    let mut fx = Fixture::booted();
    fx.runner.fail_on(&["btrfs", "property"]);
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::Finalize);
    let mut expected = fx.expand(CLEANUP_MOUNTED);
    expected.remove(0);
    assert_eq!(fx.calls_after("btrfs property"), expected);
    fx.assert_no_candidates();
    assert_eq!(
        esp(&fx),
        ["aios-gen-0006-cachyos.efi", "aios-gen-0007-cachyos.efi"]
    );
    assert!(!fx.layout.subvol("@usr-gen-0008").exists());
}
