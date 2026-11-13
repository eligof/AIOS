mod common;

use aios_exec::{sha256_hex, Output, Step};
use aios_gen::GenerationMeta;
use aios_render::{cmdline, RenderCtx};
use common::{mkdir, Fixture, CLEANUP_MOUNTED, ESP_UUID, HARDENING, LUKS_UUID, MANIFEST};
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
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
            "arch-chroot {cand} pacman -Rns --noconfirm -- libnano"
        ),
        fx.expand(
            "
            arch-chroot {cand} pacman -Syu --needed --noconfirm -- {set}
            arch-chroot {cand} pacman -Qqe
            arch-chroot {cand} pacman -Rns --noconfirm -- nano
            arch-chroot {cand} pacman -D --asexplicit -- {set}
            arch-chroot {cand} pacman -Qdtq
            arch-chroot {cand} pacman -Rns --noconfirm -- libnano
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
            arch-chroot {cand} pacman -Q -- linux-cachyos linux-cachyos-lts
            arch-chroot {cand} pacman -Qq
            arch-chroot {cand} pacman -Qlq
            arch-chroot {cand} locale-gen
            arch-chroot {cand} chown -h -- root:wheel /etc/usbguard/usbguard-daemon.conf
            "
        )
    );
}

/// What `pacman -Qlq` lists for the pkgdirs test: paths in the generation, in persistent
/// or API trees, in `@blank`, below `@blank`'s links, missing on disk, and the ones the
/// next boot would lack.
const PACKAGE_FILES: &str = "/usr/
/usr/bin/zsh
/etc/
/etc/zshrc
/boot/
/boot/intel-ucode.img
/home/
/persist/
/var/
/var/log/
/var/log/old/
/tmp/
/run/
/bin
/lib/libfoo.so
/var/lib/pacman/
/var/empty/
/opt/
/opt/tool.conf
/srv/
/srv/http/
/srv/http/index.html
/var/spool/
/var/spool/mail/
/var/mail
/var/lib/foo/
/var/lib/foo/state
/opt/
";

fn package_tree(fx: &mut Fixture) {
    let (cand, blank) = (fx.layout.cand.clone(), fx.layout.subvol("@blank"));
    for (dir, mode) in [
        ("opt", 0o755),
        ("srv", 0o755),
        ("srv/http", 0o750),
        ("var/spool", 0o755),
        ("var/spool/mail", 0o1777),
        ("var/lib/pacman", 0o755),
        ("var/lib/foo", 0o755),
        ("var/log/old", 0o755),
        ("boot", 0o755),
        ("usr/lib", 0o755),
    ] {
        mkdir(&cand.join(dir));
        fs::set_permissions(cand.join(dir), fs::Permissions::from_mode(mode)).unwrap();
    }
    for file in ["opt/tool.conf", "srv/http/index.html", "var/lib/foo/state"] {
        common::write(&cand.join(file), "x\n", 0o644);
    }
    common::write(&cand.join("usr/lib/libfoo.so"), "x\n", 0o755);
    symlink("spool/mail", cand.join("var/mail")).unwrap();
    symlink("usr/bin", cand.join("bin")).unwrap();
    symlink("usr/lib", cand.join("lib")).unwrap();
    for dir in [
        "usr", "etc", "var/lib", "var/log", "tmp", "home", "run", "persist",
    ] {
        mkdir(&blank.join(dir));
    }
    symlink("usr/bin", blank.join("bin")).unwrap();
    symlink("usr/lib", blank.join("lib")).unwrap();
    symlink("../../usr/lib/pacman", blank.join("var/lib/pacman")).unwrap();
    fx.set_manifest(&MANIFEST.replace(
        "files = [\"/etc/machine-id\"]",
        "files = [\"/etc/machine-id\", \"/var/lib/foo/state\"]",
    ));
    let cand = cand.display().to_string();
    fx.runner.respond(
        &["arch-chroot", &cand, "pacman", "-Qlq"],
        Output::ok(PACKAGE_FILES),
    );
}

/// Spec §4.3 step 5: every boot starts from `@blank`, so what packages put outside `/usr`,
/// `/etc` and the persistent trees is recreated by tmpfiles, or reported when it can't be.
#[test]
fn package_paths_outside_the_generation_are_recreated_or_reported() {
    let mut fx = Fixture::booted();
    package_tree(&mut fx);
    let outcome = fx.run().unwrap();
    let cand = &fx.layout.cand;
    let owner = |dir: &str| {
        let meta = fs::metadata(cand.join(dir)).unwrap();
        format!("{} {}", meta.uid(), meta.gid())
    };
    let conf = cand.join("etc/tmpfiles.d/zz-aios-pkgdirs.conf");
    assert_eq!(
        fs::read_to_string(&conf).unwrap(),
        format!(
            "# Generated by aios. Do not edit: /etc is reset at every boot.\n\
             d /opt 0755 {} -\n\
             d /srv 0755 {} -\n\
             d /srv/http 0750 {} -\n\
             d /var/lib/foo 0755 {} -\n\
             L /var/mail - - - - spool/mail\n\
             d /var/spool 0755 {} -\n\
             d /var/spool/mail 1777 {} -\n",
            owner("opt"),
            owner("srv"),
            owner("srv/http"),
            owner("var/lib/foo"),
            owner("var/spool"),
            owner("var/spool/mail"),
        )
    );
    assert_eq!(mode(&conf), 0o644);
    // Pre-commit information, not a post-commit failure (spec §4.3 step 5, §7).
    assert_eq!(outcome.warnings, Vec::<String>::new());
    assert_eq!(
        outcome.notices,
        [
            "package file /opt/tool.conf lives outside /usr and /etc and is lost at every boot",
            "package file /srv/http/index.html lives outside /usr and /etc and is lost at every \
             boot",
        ]
    );
    let managed = fs::read_to_string(cand.join("etc/aios/managed-files")).unwrap();
    assert!(
        managed.contains("/etc/tmpfiles.d/zz-aios-pkgdirs.conf\n"),
        "{managed}"
    );
}

/// apply's root is a fresh snapshot of `@blank`, so a package the upgrade leaves alone has
/// nothing there: its lines come over from the booted generation, as long as a package
/// still owns the path. What the candidate holds wins.
#[test]
fn pkgdirs_of_packages_the_apply_leaves_alone_carry_over() {
    let mut fx = Fixture::booted();
    let cand = fx.layout.cand.clone();
    for dir in ["srv", "srv/new"] {
        mkdir(&cand.join(dir));
        fs::set_permissions(cand.join(dir), fs::Permissions::from_mode(0o755)).unwrap();
    }
    common::write(
        &fx.layout
            .subvol("@etc-gen-0007")
            .join("tmpfiles.d/zz-aios-pkgdirs.conf"),
        "# Generated by aios. Do not edit: /etc is reset at every boot.\n\
         d /opt 0755 0 0 -\n\
         d /srv 0700 5 6 -\n\
         d /srv/gone 0700 5 6 -\n\
         d /var/games 0775 0 50 -\n\
         L /var/mail - - - - spool/mail\n",
        0o644,
    );
    let listed = "/opt/\n/srv/\n/srv/new/\n/var/games/\n/var/mail\n/var/empty/\n";
    let cand_arg = cand.display().to_string();
    fx.runner.respond(
        &["arch-chroot", &cand_arg, "pacman", "-Qlq"],
        Output::ok(listed),
    );
    fx.run().unwrap();
    let meta = fs::metadata(cand.join("srv")).unwrap();
    let owner = format!("{} {}", meta.uid(), meta.gid());
    assert_eq!(
        fs::read_to_string(cand.join("etc/tmpfiles.d/zz-aios-pkgdirs.conf")).unwrap(),
        format!(
            "# Generated by aios. Do not edit: /etc is reset at every boot.\n\
             d /opt 0755 0 0 -\n\
             d /srv 0755 {owner} -\n\
             d /srv/new 0755 {owner} -\n\
             d /var/games 0775 0 50 -\n\
             L /var/mail - - - - spool/mail\n"
        )
    );
}

/// A path the candidate has below a symlink lives where the link points now: the booted
/// generation's line for it isn't carried over. A link to `-` (tmpfiles' "no argument")
/// and a name that isn't UTF-8 can't be written as tmpfiles lines: both are reported.
#[test]
fn pkgdirs_drops_paths_below_links_and_reports_what_tmpfiles_cannot_name() {
    let mut fx = Fixture::booted();
    let cand = fx.layout.cand.clone();
    mkdir(&cand.join("opt"));
    fs::set_permissions(cand.join("opt"), fs::Permissions::from_mode(0o755)).unwrap();
    symlink("var/srv", cand.join("srv")).unwrap();
    symlink("-", cand.join("opt/dash")).unwrap();
    common::write(
        &fx.layout
            .subvol("@etc-gen-0007")
            .join("tmpfiles.d/zz-aios-pkgdirs.conf"),
        "d /srv/x 0700 5 6 -\n",
        0o644,
    );
    let mut listed = b"/srv\n/srv/x/\n/opt/\n/opt/dash\n/usr/lib/\xff\n".to_vec();
    listed.extend_from_slice(b"/opt/\xfe/\n");
    let cand_arg = cand.display().to_string();
    fx.runner.respond(
        &["arch-chroot", &cand_arg, "pacman", "-Qlq"],
        Output::ok(listed),
    );
    let outcome = fx.run().unwrap();
    let meta = fs::metadata(cand.join("opt")).unwrap();
    assert_eq!(
        fs::read_to_string(cand.join("etc/tmpfiles.d/zz-aios-pkgdirs.conf")).unwrap(),
        format!(
            "# Generated by aios. Do not edit: /etc is reset at every boot.\n\
             d /opt 0755 {} {} -\n\
             L /srv - - - - var/srv\n",
            meta.uid(),
            meta.gid()
        )
    );
    assert_eq!(
        outcome.notices,
        [
            "package file /opt/\u{fffd} has a name that isn't UTF-8 and is lost at every boot",
            "package file /opt/dash lives outside /usr and /etc and is lost at every boot",
        ]
    );
}

#[test]
fn without_package_paths_outside_the_generation_pkgdirs_conf_is_only_a_header() {
    let fx = Fixture::booted();
    fx.run().unwrap();
    let conf = fx.layout.cand.join("etc/tmpfiles.d/zz-aios-pkgdirs.conf");
    assert_eq!(
        fs::read_to_string(conf).unwrap(),
        "# Generated by aios. Do not edit: /etc is reset at every boot.\n"
    );
}

#[test]
fn a_failed_package_listing_cleans_up() {
    let mut fx = Fixture::booted();
    let cand = fx.layout.cand.display().to_string();
    fx.runner.fail_on(&["arch-chroot", &cand, "pacman", "-Qlq"]);
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::RenderEtc);
    assert_eq!(
        fx.calls_after("arch-chroot {cand} pacman -Qlq"),
        fx.expand(CLEANUP_MOUNTED)
    );
}

/// `arch-chroot ROOT chown -h -- SPEC PATH`: the file has no setuid or setgid bit while
/// root still owns it, and (as the kernel does on chown) it has none afterwards either.
fn chown_drops_setuid(argv: &[&str]) {
    let path = Path::new(argv[1]).join(argv.last().unwrap().trim_start_matches('/'));
    let meta = fs::symlink_metadata(&path).unwrap();
    if meta.is_file() {
        let mode = meta.permissions().mode();
        assert_eq!(
            mode & 0o6000,
            0,
            "{} is setuid/setgid before chown",
            path.display()
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(mode & !0o6000)).unwrap();
    }
}

#[test]
fn setuid_and_setgid_are_set_after_the_owner() {
    let mut fx = Fixture::booted();
    let entry =
        "\"/etc/aios-helper\" = { source = \"files/helper\", mode = \"6750\", owner = \"eli\" }\n";
    fx.set_manifest(&MANIFEST.replace("\n[persist]", &format!("{entry}\n[persist]")));
    common::write(&fx.layout.config.join("files/helper"), "#!/bin/sh\n", 0o644);
    let cand = fx.layout.cand.display().to_string();
    fx.runner
        .on_success(&["arch-chroot", &cand, "chown"], chown_drops_setuid);
    fx.run().unwrap();
    let etc = fx.layout.cand.join("etc");
    assert_eq!(mode(&etc.join("aios-helper")), 0o6750);
    assert_eq!(mode(&etc.join("usbguard/usbguard-daemon.conf")), 0o600);
    assert!(fx
        .calls()
        .contains(&"arch-chroot {cand} chown -h -- eli:root /etc/aios-helper".to_string()));
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
    assert_eq!(chowns, fx.expand("chown -- 1000:1000 {home}/eli"));
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
            systemctl --root={cand} enable -- NetworkManager.service aios-health.service fwupd-refresh.timer
            systemctl --root={cand} disable -- bluetooth.service
            systemctl --root={cand} mask -- sshd.socket
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
            systemctl --root={cand} unmask -- NetworkManager.service
            systemctl --root={cand} enable -- NetworkManager.service aios-health.service fwupd-refresh.timer
            systemctl --root={cand} mask -- sshd.socket
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
            pacstrap -C {run}/aios-pacstrap.conf {cand} --dbpath={cand}/usr/lib/pacman/ {set}
            arch-chroot {cand} pacman-key --init
            arch-chroot {cand} pacman-key --populate archlinux cachyos
            "
        )
    );
    let conf = fs::read_to_string(fx.dir.path().join("aios-pacstrap.conf")).unwrap();
    let cand = fx.layout.cand.display();
    // The database goes straight into the candidate's /usr, and pacman reads the hooks
    // (and the masks) of the candidate's /etc, not the installer's.
    assert!(
        conf.starts_with(&format!(
            "[options]\nDBPath = {cand}/usr/lib/pacman/\nHookDir = {cand}/etc/pacman.d/hooks/\n"
        )),
        "{conf}"
    );
    assert_eq!(conf.matches("DBPath").count(), 1, "{conf}");
    assert!(!conf.contains("LogFile"), "{conf}");
    let repo = format!("Server = file://{cand}/persist/aios/repo\n");
    assert!(conf.contains(&repo), "{conf}");
    assert!(conf.contains("CacheDir     = /var/cache/pacman/pkg/\n"));
    assert!(fx.layout.cand.join("usr/lib/pacman").is_dir());
    let meta = fs::read_to_string(fx.layout.cand.join("etc/aios/generation.toml")).unwrap();
    let meta = GenerationMeta::from_toml(&meta).unwrap();
    assert_eq!((meta.id, meta.parent), (1, 0));
}

/// The hooks pacstrap must not run: mkinitcpio's (aios builds the initramfs itself) and
/// sbctl's (no keys in the candidate).
const PACSTRAP_MASKS: [&str; 3] = [
    "etc/pacman.d/hooks/90-mkinitcpio-install.hook",
    "etc/pacman.d/hooks/60-mkinitcpio-remove.hook",
    "etc/pacman.d/hooks/zz-sbctl.hook",
];

/// `pacstrap -C CONF ROOT PACKAGES...`: every mask is a symlink to /dev/null in ROOT.
fn hooks_are_masked(argv: &[&str]) {
    let root = Path::new(argv[3]);
    for mask in PACSTRAP_MASKS {
        assert_eq!(
            fs::read_link(root.join(mask)).ok().as_deref(),
            Some(Path::new("/dev/null")),
            "{mask} while pacstrap runs"
        );
    }
}

#[test]
fn bootstrap_masks_the_initramfs_and_sbctl_hooks_while_pacstrap_runs() {
    let mut fx = Fixture::fresh();
    fx.runner.on_success(&["pacstrap"], hooks_are_masked);
    fx.run().unwrap();
    let etc = fx.layout.cand.join("etc");
    // The manifest declares only the install hook's mask; the others were for pacstrap.
    assert_eq!(
        fs::read_link(etc.join("pacman.d/hooks/90-mkinitcpio-install.hook")).unwrap(),
        Path::new("/dev/null")
    );
    for gone in ["60-mkinitcpio-remove.hook", "zz-sbctl.hook"] {
        let path = etc.join("pacman.d/hooks").join(gone);
        assert!(fs::symlink_metadata(&path).is_err(), "{gone} is left");
    }
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
