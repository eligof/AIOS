mod common;

use aios_exec::{sha256_hex, Output, Step};
use aios_gen::GenerationMeta;
use aios_render::{cmdline, RenderCtx};
use common::{mkdir, Fixture, CLEANUP_MOUNTED, ESP_UUID, HARDENING, LUKS_UUID, MANIFEST};
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
}

/// The calls from the first one starting with `first`, up to and including the first one
/// starting with `last`.
fn span(fx: &Fixture, first: &str, last: &str) -> Vec<String> {
    let calls = fx.calls();
    let from = calls.iter().position(|c| c.starts_with(first)).unwrap();
    let to = from
        + calls[from..]
            .iter()
            .position(|c| c.starts_with(last))
            .unwrap();
    calls[from..=to].to_vec()
}

#[test]
fn apply_upgrades_removes_marks_and_drops_orphans() {
    let fx = Fixture::booted();
    fx.run().unwrap();
    assert_eq!(
        span(
            &fx,
            "arch-chroot {cand} pacman -Syu",
            "arch-chroot {cand} pacman -Rns --noconfirm libnano"
        ),
        fx.expand(
            "
            arch-chroot {cand} pacman -Syu --needed --noconfirm {set}
            arch-chroot {cand} pacman -Qqe
            arch-chroot {cand} pacman -Rns --noconfirm nano
            arch-chroot {cand} pacman -D --asexplicit {set}
            arch-chroot {cand} pacman -Qdtq
            arch-chroot {cand} pacman -Rns --noconfirm libnano
            "
        )
    );
}

#[test]
fn nothing_to_remove_means_no_removal_calls() {
    let mut fx = Fixture::booted();
    let cand = fx.layout.cand.display().to_string();
    let explicit = fx.manifest.package_set().join("\n");
    fx.runner
        .respond(
            &["arch-chroot", &cand, "pacman", "-Qqe"],
            Output::ok(explicit),
        )
        .respond(
            &["arch-chroot", &cand, "pacman", "-Qdtq"],
            Output::failed(1, ""),
        );
    fx.run().unwrap();
    assert!(!fx.calls().iter().any(|c| c.contains("-Rns")));
}

#[test]
fn renders_the_desired_etc_into_the_candidate() {
    let fx = Fixture::booted();
    fx.run().unwrap();
    let etc = fx.layout.cand.join("etc");
    assert_eq!(
        fs::read_to_string(etc.join("hostname")).unwrap(),
        "nightcity\n"
    );
    assert_eq!(
        fs::read_to_string(etc.join("nftables.conf")).unwrap(),
        "flush ruleset\n"
    );
    assert_eq!(mode(&etc.join("nftables.conf")), 0o600);
    assert_eq!(mode(&etc.join("shadow")), 0o600);
    assert_eq!(
        fs::read_link(etc.join("pacman.d/hooks/90-mkinitcpio-install.hook")).unwrap(),
        Path::new("/dev/null")
    );
    let ctx = RenderCtx::new(common::BOOTED, LUKS_UUID, ESP_UUID, HARDENING).unwrap();
    let gen8 = RenderCtx {
        gen: aios_gen::GenId(8),
        ..ctx
    };
    assert_eq!(
        fs::read_to_string(etc.join("kernel/cmdline")).unwrap(),
        cmdline(&fx.manifest, &gen8)
    );
    assert!(fs::read_to_string(etc.join("shadow"))
        .unwrap()
        .contains("\neli:$y$j9T$salt$hash:"));
    assert!(etc
        .join("aios/home/eli/.config/autostart/hello.desktop")
        .is_file());
}

#[test]
fn paths_the_old_generation_managed_are_removed() {
    let fx = Fixture::booted();
    fx.run().unwrap();
    let etc = fx.layout.cand.join("etc");
    assert!(!etc.join("old.conf").exists());
    let managed = fs::read_to_string(etc.join("aios/managed-files")).unwrap();
    assert!(managed.contains("/etc/hostname\n"));
    assert!(!managed.contains("old.conf"));
}

#[test]
fn generation_toml_records_ids_commit_kernels_and_package_hash() {
    let fx = Fixture::booted();
    fx.run().unwrap();
    let text = fs::read_to_string(fx.layout.cand.join("etc/aios/generation.toml")).unwrap();
    assert_eq!(
        GenerationMeta::from_toml(&text).unwrap(),
        GenerationMeta {
            id: 8,
            parent: 7,
            created: "2026-11-03T21:14:05Z".to_string(),
            manifest_commit: "3f9c2a1".to_string(),
            kernels: vec![
                "linux-cachyos 7.3.0-4".to_string(),
                "linux-cachyos-lts 6.18.55-2".to_string(),
            ],
            package_set_sha256: sha256_hex(b"base\nlinux-cachyos\nzsh\n"),
        }
    );
    assert_eq!(
        span(
            &fx,
            "arch-chroot {cand} pacman -Q ",
            "arch-chroot {cand} chown"
        ),
        fx.expand(
            "
            arch-chroot {cand} pacman -Q linux-cachyos linux-cachyos-lts
            arch-chroot {cand} pacman -Qq
            arch-chroot {cand} locale-gen
            arch-chroot {cand} chown -h root:wheel /etc/usbguard/usbguard-daemon.conf
            "
        )
    );
}

#[test]
fn c_utf8_needs_no_locale_gen() {
    let mut fx = Fixture::booted();
    fx.set_manifest(&MANIFEST.replace("en_US.UTF-8", "C.UTF-8"));
    fx.run().unwrap();
    assert!(!fx.calls().iter().any(|c| c.contains("locale-gen")));
    assert!(!fx.layout.cand.join("etc/locale.gen").exists());
}

#[test]
fn persist_directories_exist_for_the_binds() {
    let fx = Fixture::booted();
    fx.run().unwrap();
    for rel in ["var/lib/NetworkManager", "var/cache/pacman/pkg", "etc"] {
        assert!(fx.layout.persist.join(rel).is_dir(), "{rel}");
    }
}

#[test]
fn apply_never_touches_home() {
    let fx = Fixture::booted();
    fx.run().unwrap();
    assert_eq!(fs::read_dir(&fx.layout.home).unwrap().count(), 0);
    assert!(!fx.calls().iter().any(|c| c.starts_with("chown ")));
}

#[test]
fn bootstrap_creates_private_home_directories() {
    let fx = Fixture::fresh();
    fx.run().unwrap();
    let chowns: Vec<String> = fx
        .calls()
        .into_iter()
        .filter(|c| c.starts_with("chown "))
        .collect();
    assert_eq!(chowns, fx.expand("chown 1000:1000 {home}/eli"));
    let home = fx.layout.home.join("eli");
    assert_eq!(mode(&home), 0o700);
    assert_eq!(
        fs::read_dir(&home).unwrap().count(),
        0,
        "tmpfiles makes the rest"
    );
}

#[test]
fn bootstrap_keeps_an_existing_home_and_refuses_a_symlink() {
    let fx = Fixture::fresh();
    mkdir(&fx.layout.home.join("eli"));
    fx.run().unwrap();
    assert!(!fx.calls().iter().any(|c| c.starts_with("chown ")));

    let fx = Fixture::fresh();
    symlink("/etc", fx.layout.home.join("eli")).unwrap();
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::RenderEtc);
    assert_eq!(
        err.detail,
        format!(
            "{}: exists and is not a directory",
            fx.layout.home.join("eli").display()
        )
    );
}

#[test]
fn services_follow_the_manifest_plus_core_units() {
    let fx = Fixture::booted();
    fx.run().unwrap();
    assert_eq!(
        span(&fx, "systemctl", "systemctl --root={cand} mask"),
        fx.expand(
            "
            systemctl --root={cand} enable NetworkManager.service aios-health.service fwupd-refresh.timer
            systemctl --root={cand} disable bluetooth.service
            systemctl --root={cand} mask sshd.socket
            "
        )
    );
}

#[test]
fn masked_units_are_unmasked_and_missing_units_are_not_disabled() {
    let fx = Fixture::booted();
    let units = fx.layout.cand.join("etc/systemd/system");
    mkdir(&units);
    symlink("/dev/null", units.join("NetworkManager.service")).unwrap();
    fs::remove_file(
        fx.layout
            .cand
            .join("usr/lib/systemd/system/bluetooth.service"),
    )
    .unwrap();
    fx.run().unwrap();
    assert_eq!(
        span(&fx, "systemctl", "systemctl --root={cand} mask"),
        fx.expand(
            "
            systemctl --root={cand} unmask NetworkManager.service
            systemctl --root={cand} enable NetworkManager.service aios-health.service fwupd-refresh.timer
            systemctl --root={cand} mask sshd.socket
            "
        )
    );
}

#[test]
fn bootstrap_pacstraps_with_a_rewritten_conf_and_inits_the_keyring() {
    let fx = Fixture::fresh();
    fx.run().unwrap();
    assert_eq!(
        span(&fx, "pacstrap", "arch-chroot {cand} pacman-key --populate"),
        fx.expand(
            "
            pacstrap -C {run}/aios-pacstrap.conf {cand} {set}
            arch-chroot {cand} pacman-key --init
            arch-chroot {cand} pacman-key --populate archlinux cachyos
            "
        )
    );
    let conf = fs::read_to_string(fx.dir.path().join("aios-pacstrap.conf")).unwrap();
    assert!(
        !conf.contains("DBPath") && !conf.contains("LogFile"),
        "{conf}"
    );
    let repo = format!(
        "Server = file://{}/persist/aios/repo\n",
        fx.layout.cand.display()
    );
    assert!(conf.contains(&repo), "{conf}");
    assert!(conf.contains("CacheDir     = /var/cache/pacman/pkg/\n"));
    assert!(fx.layout.cand.join("usr/lib/pacman").is_dir());
    let meta = fs::read_to_string(fx.layout.cand.join("etc/aios/generation.toml")).unwrap();
    let meta = GenerationMeta::from_toml(&meta).unwrap();
    assert_eq!((meta.id, meta.parent), (1, 0));
}

#[test]
fn bootstrap_needs_a_pacman_conf_source() {
    let mut fx = Fixture::fresh();
    fx.set_manifest(&MANIFEST.replace(
        "\"/etc/pacman.conf\" = { source = \"files/pacman.conf\" }\n",
        "",
    ));
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::Packages);
    assert_eq!(
        err.detail,
        "bootstrap needs a [files] \"/etc/pacman.conf\" entry with a source"
    );
    assert_eq!(
        fx.calls().last().unwrap(),
        "btrfs subvolume delete --recursive {top}/@root-cand"
    );
}

#[test]
fn a_failed_upgrade_cleans_up() {
    let mut fx = Fixture::booted();
    let cand = fx.layout.cand.display().to_string();
    fx.runner.fail_on(&["arch-chroot", &cand, "pacman", "-Syu"]);
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::Packages);
    assert_eq!(
        fx.calls_after("arch-chroot {cand} pacman -Syu"),
        fx.expand(CLEANUP_MOUNTED)
    );
    fx.assert_no_candidates();
}

#[test]
fn a_failed_keyring_cleans_up_without_unmounting_the_target() {
    let mut fx = Fixture::fresh();
    let cand = fx.layout.cand.display().to_string();
    fx.runner
        .fail_on(&["arch-chroot", &cand, "pacman-key", "--init"]);
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::Keyring);
    let mut expected = fx.expand(CLEANUP_MOUNTED);
    expected.pop();
    assert_eq!(
        fx.calls_after("arch-chroot {cand} pacman-key --init"),
        expected
    );
    fx.assert_no_candidates();
}

#[test]
fn a_failed_render_cleans_up() {
    let mut fx = Fixture::booted();
    let cand = fx.layout.cand.display().to_string();
    fx.runner.fail_on(&["arch-chroot", &cand, "locale-gen"]);
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::RenderEtc);
    assert_eq!(
        fx.calls_after("arch-chroot {cand} locale-gen"),
        fx.expand(CLEANUP_MOUNTED)
    );
}

#[test]
fn a_failed_service_call_cleans_up() {
    let mut fx = Fixture::booted();
    fx.runner.fail_on(&["systemctl"]);
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::Services);
    assert_eq!(fx.calls_after("systemctl"), fx.expand(CLEANUP_MOUNTED));
}
