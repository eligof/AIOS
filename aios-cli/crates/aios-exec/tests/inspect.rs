mod common;

use aios_exec::ops::{
    drift, gen_list, gen_rows, render_gen_list, status, Drift, GenRow, Modified, Status,
    DRIFT_READ_MAX,
};
use aios_gen::{GenId, GenerationMeta};
use common::{mkdir, write, Fixture};
use std::fs;
use std::os::unix::fs::symlink;

fn meta(id: u32, commit: &str) -> String {
    GenerationMeta {
        id,
        parent: id - 1,
        created: format!("2026-11-0{id}T10:00:00Z"),
        manifest_commit: commit.to_string(),
        kernels: vec!["linux-cachyos 7.3.0-4".to_string()],
        package_set_sha256: "ab".repeat(32),
    }
    .to_toml()
}

/// gen-6 (bad), gen-7 (booted) and gen-8 (newest, no generation.toml).
fn machine() -> Fixture {
    let fx = Fixture::booted();
    let l = &fx.layout;
    write(
        &l.subvol("@etc-gen-0006").join("aios/generation.toml"),
        &meta(6, "1111111"),
        0o644,
    );
    write(
        &l.subvol("@etc-gen-0007").join("aios/generation.toml"),
        &meta(7, "3f9c2a1"),
        0o644,
    );
    mkdir(&l.subvol("@usr-gen-0008"));
    mkdir(&l.subvol("@etc-gen-0008"));
    mkdir(&l.subvol("@usr-gen-0009"));
    fs::rename(
        l.uki_dir().join("aios-gen-0006-cachyos.efi"),
        l.uki_dir().join("aios-gen-0006-cachyos+0-3.efi"),
    )
    .unwrap();
    write(
        &l.uki_dir().join("aios-gen-0008-cachyos+3.efi"),
        "uki",
        0o644,
    );
    fx
}

#[test]
fn rows_carry_metadata_and_boot_states() {
    let fx = machine();
    let rows = gen_rows(&fx.layout).unwrap();
    assert_eq!(
        rows,
        [
            GenRow {
                gen: GenId(6),
                created: "2026-11-06T10:00:00Z".to_string(),
                commit: "1111111".to_string(),
                kernels: vec!["linux-cachyos 7.3.0-4".to_string()],
                states: vec!["bad"],
            },
            GenRow {
                gen: GenId(7),
                created: "2026-11-07T10:00:00Z".to_string(),
                commit: "3f9c2a1".to_string(),
                kernels: vec!["linux-cachyos 7.3.0-4".to_string()],
                states: vec!["booted"],
            },
            GenRow {
                gen: GenId(8),
                created: "?".to_string(),
                commit: "?".to_string(),
                kernels: vec![],
                states: vec!["default"],
            },
        ]
    );
}

#[test]
fn the_table_has_a_header_and_one_line_per_generation() {
    let fx = machine();
    let table = render_gen_list(&gen_rows(&fx.layout).unwrap());
    assert_eq!(
        table,
        "\
GEN   CREATED               COMMIT   STATE           KERNELS
0006  2026-11-06T10:00:00Z  1111111  bad             linux-cachyos 7.3.0-4
0007  2026-11-07T10:00:00Z  3f9c2a1  booted          linux-cachyos 7.3.0-4
0008  ?                     ?        default         \n"
    );
}

#[test]
fn gen_list_mounts_the_top_level_read_only() {
    let fx = machine();
    assert_eq!(gen_list(&fx.runner, &fx.layout).unwrap().len(), 3);
    assert_eq!(
        fx.calls(),
        fx.expand(
            "
            mount -t btrfs -o subvolid=5,ro /dev/mapper/aios {ro}
            umount {ro}
            "
        )
    );
}

#[test]
fn readers_mount_at_a_private_directory_and_remove_it() {
    let fx = machine();
    let ro = fx.layout.ro_top();
    assert_ne!(ro, fx.layout.top);
    gen_list(&fx.runner, &fx.layout).unwrap();
    status(&fx.runner, &fx.layout).unwrap();
    assert!(!ro.exists(), "{} left behind", ro.display());
    assert!(fx.layout.subvol("@etc-gen-0007").is_dir(), "top untouched");
}

#[test]
fn a_failed_read_only_mount_leaves_no_directory() {
    let mut fx = machine();
    fx.runner.fail_on(&["mount"]);
    let err = gen_list(&fx.runner, &fx.layout).unwrap_err();
    assert!(err.to_string().contains("injected failure"), "{err}");
    assert_eq!(fx.calls().len(), 1, "no umount after a failed mount");
    assert!(!fx.layout.ro_top().exists());
}

#[test]
fn a_failed_unmount_is_reported_and_keeps_the_mount_point() {
    let mut fx = machine();
    fx.runner.fail_on(&["umount"]);
    let err = gen_list(&fx.runner, &fx.layout).unwrap_err();
    assert!(err.to_string().starts_with("`umount "), "{err}");
    assert!(fx.layout.ro_top().is_dir(), "still mounted, so not removed");
}

/// The live /etc and the booted snapshot, identical except for a few runtime changes.
fn drifted() -> Fixture {
    let fx = machine();
    let (live, snap) = (&fx.layout.live_etc, fx.layout.subvol("@etc-gen-0007"));
    for etc in [live, &snap] {
        write(&etc.join("hostname"), "nightcity\n", 0o644);
        write(&etc.join("nftables.conf"), "flush ruleset\n", 0o600);
        write(&etc.join("aios/generation.toml"), "differs per tree", 0o644);
        symlink("/usr/share/zoneinfo/UTC", etc.join("localtime")).unwrap();
        mkdir(&etc.join("empty.d"));
    }
    write(&snap.join("issue"), "AIOS\n", 0o644);
    write(&live.join("ld.so.preload"), "/tmp/evil.so\n", 0o644);
    write(&live.join("hostname"), "evil\n", 0o644);
    write(&live.join("nftables.conf"), "flush ruleset\n", 0o644);
    fs::remove_file(live.join("localtime")).unwrap();
    symlink("/usr/share/zoneinfo/Europe/Berlin", live.join("localtime")).unwrap();
    fx
}

#[test]
fn drift_lists_added_modified_and_removed_paths() {
    let fx = drifted();
    let d = drift(&fx.layout.live_etc, &fx.layout.subvol("@etc-gen-0007")).unwrap();
    assert_eq!(
        d,
        Drift {
            added: vec!["/etc/ld.so.preload".to_string()],
            modified: vec![
                modified("/etc/hostname", &["size differs"]),
                modified("/etc/localtime", &["target differs"]),
                modified("/etc/nftables.conf", &["mode 0600 -> 0644"]),
            ],
            removed: vec!["/etc/issue".to_string()],
            skipped: vec![],
        }
    );
}

fn modified(path: &str, what: &[&str]) -> Modified {
    Modified {
        path: path.to_string(),
        what: what.iter().map(|w| w.to_string()).collect(),
    }
}

/// `drift` of the fixture's live `/etc` against the booted snapshot.
fn drift_of(fx: &Fixture) -> Drift {
    drift(&fx.layout.live_etc, &fx.layout.subvol("@etc-gen-0007")).unwrap()
}

#[test]
fn files_of_the_same_size_are_compared_byte_for_byte() {
    let fx = drifted();
    let (live, snap) = (&fx.layout.live_etc, fx.layout.subvol("@etc-gen-0007"));
    write(&live.join("motd"), "abc\n", 0o644);
    write(&snap.join("motd"), "abd\n", 0o644);
    assert!(drift_of(&fx)
        .modified
        .contains(&modified("/etc/motd", &["content differs"])));
}

/// Directories count too: their mode, and those only one tree has (shown with a `/`).
#[test]
fn directories_that_changed_mode_appeared_or_went_away_are_drift() {
    use std::os::unix::fs::PermissionsExt;
    let fx = drifted();
    let (live, snap) = (&fx.layout.live_etc, fx.layout.subvol("@etc-gen-0007"));
    fs::set_permissions(live.join("empty.d"), fs::Permissions::from_mode(0o777)).unwrap();
    fs::set_permissions(snap.join("empty.d"), fs::Permissions::from_mode(0o755)).unwrap();
    mkdir(&live.join("sudoers.d"));
    mkdir(&snap.join("old.d"));
    let d = drift_of(&fx);
    assert!(
        d.modified
            .contains(&modified("/etc/empty.d/", &["mode 0755 -> 0777"])),
        "{d:?}"
    );
    assert!(d.added.contains(&"/etc/sudoers.d/".to_string()), "{d:?}");
    assert!(d.removed.contains(&"/etc/old.d/".to_string()), "{d:?}");
}

#[test]
fn a_changed_type_is_drift() {
    let fx = drifted();
    let (live, snap) = (&fx.layout.live_etc, fx.layout.subvol("@etc-gen-0007"));
    write(&snap.join("resolv.conf"), "nameserver ::1\n", 0o644);
    symlink(
        "/run/systemd/resolve/stub-resolv.conf",
        live.join("resolv.conf"),
    )
    .unwrap();
    write(&snap.join("profile.d"), "a file\n", 0o644);
    mkdir(&live.join("profile.d"));
    let d = drift_of(&fx);
    assert!(
        d.modified
            .contains(&modified("/etc/resolv.conf", &["file -> symlink"])),
        "{d:?}"
    );
    assert!(
        d.modified
            .contains(&modified("/etc/profile.d/", &["file -> directory"])),
        "{d:?}"
    );
}

fn mkfifo(path: &std::path::Path) {
    use rustix::fs::{mknodat, FileType, Mode, CWD};
    mknodat(CWD, path, FileType::Fifo, Mode::from_raw_mode(0o644), 0).unwrap();
}

/// A FIFO is never opened, so drift can't hang waiting for a writer.
#[test]
fn special_files_are_compared_without_being_opened() {
    let fx = drifted();
    let (live, snap) = (&fx.layout.live_etc, fx.layout.subvol("@etc-gen-0007"));
    mkfifo(&live.join("initctl"));
    mkfifo(&snap.join("initctl"));
    write(&snap.join("pipe"), "", 0o644);
    mkfifo(&live.join("pipe"));
    let d = drift_of(&fx);
    assert!(!d
        .added
        .iter()
        .chain(&d.removed)
        .any(|p| p.contains("initctl")));
    assert!(
        !d.modified.iter().any(|m| m.path.contains("initctl")),
        "{d:?}"
    );
    assert!(
        d.modified
            .contains(&modified("/etc/pipe", &["file -> special file"])),
        "{d:?}"
    );
}

/// Files over the cap are not read: a size difference still shows, equal sizes get a note.
#[test]
fn files_over_the_read_cap_are_compared_by_size_only() {
    let fx = drifted();
    let (live, snap) = (&fx.layout.live_etc, fx.layout.subvol("@etc-gen-0007"));
    let sparse = |path: std::path::PathBuf, len: u64| {
        fs::File::create(path).unwrap().set_len(len).unwrap();
    };
    sparse(live.join("big"), DRIFT_READ_MAX + 1);
    sparse(snap.join("big"), DRIFT_READ_MAX + 1);
    sparse(live.join("bigger"), DRIFT_READ_MAX + 2);
    sparse(snap.join("bigger"), DRIFT_READ_MAX + 1);
    let d = drift_of(&fx);
    assert_eq!(
        d.skipped,
        ["/etc/big: larger than 16 MiB, contents not compared"]
    );
    assert!(!d.modified.iter().any(|m| m.path == "/etc/big"), "{d:?}");
    assert!(d
        .modified
        .contains(&modified("/etc/bigger", &["size differs"])));
}

/// What can be told from `lstat` is reported even when the contents can't be compared.
#[test]
fn a_file_whose_contents_are_not_compared_still_shows_its_mode_change() {
    use std::os::unix::fs::PermissionsExt;
    let fx = drifted();
    let (live, snap) = (&fx.layout.live_etc, fx.layout.subvol("@etc-gen-0007"));
    for etc in [live, &snap] {
        fs::File::create(etc.join("big"))
            .unwrap()
            .set_len(DRIFT_READ_MAX + 1)
            .unwrap();
    }
    fs::set_permissions(live.join("big"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(snap.join("big"), fs::Permissions::from_mode(0o644)).unwrap();
    let d = drift_of(&fx);
    assert!(
        d.modified
            .contains(&modified("/etc/big", &["mode 0644 -> 0600"])),
        "{d:?}"
    );
    assert_eq!(
        d.skipped,
        ["/etc/big: larger than 16 MiB, contents not compared"]
    );
}

/// Entries that couldn't be compared mean "none" isn't known: the report says so.
#[test]
fn no_drift_with_entries_not_compared_is_not_reported_as_none() {
    let st = Status {
        booted: Some(GenId(7)),
        default: Some(GenId(7)),
        bad: vec![],
        drift: Some(Drift {
            skipped: vec!["/etc/big: larger than 16 MiB, contents not compared".to_string()],
            ..Drift::default()
        }),
    };
    assert!(
        st.to_string().ends_with(
            "drift:   none found in what could be compared\n\
             note: skipped /etc/big: larger than 16 MiB, contents not compared\n"
        ),
        "{st}"
    );
}

/// A path can't forge another line of the report.
#[test]
fn control_characters_in_paths_are_escaped() {
    let fx = drifted();
    write(
        &fx.layout.live_etc.join("x\nnote: all clear\x1b[2J"),
        "",
        0o644,
    );
    let st = Status {
        booted: Some(GenId(7)),
        default: Some(GenId(7)),
        bad: vec![],
        drift: Some(drift_of(&fx)),
    };
    let text = st.to_string();
    assert!(
        text.contains("\n  + /etc/x\\nnote: all clear\\u{1b}[2J\n"),
        "{text}"
    );
    assert!(
        !text.lines().any(|l| l.starts_with("note: all clear")),
        "{text}"
    );
}

#[test]
fn identical_trees_have_no_drift() {
    let fx = machine();
    let (live, snap) = (&fx.layout.live_etc, fx.layout.subvol("@etc-gen-0007"));
    for etc in [live, &snap] {
        write(&etc.join("hostname"), "nightcity\n", 0o644);
    }
    // The snapshot's own generation.toml is ignored, but not the directory it is in.
    mkdir(&live.join("aios"));
    let d = drift(live, &snap).unwrap();
    assert!(d.is_empty(), "{d:?}");
}

#[test]
fn status_reports_boot_state_and_drift() {
    let fx = drifted();
    let st = status(&fx.runner, &fx.layout).unwrap();
    assert_eq!(st.booted, Some(GenId(7)));
    assert_eq!(st.default, Some(GenId(8)));
    assert_eq!(st.bad, [GenId(6)]);
    assert_eq!(
        st.to_string(),
        "\
booted:  gen-0007
default: gen-0008
bad:     gen-0006
drift (discarded at the next boot):
  + /etc/ld.so.preload
  ~ /etc/hostname (size differs)
  ~ /etc/localtime (target differs)
  ~ /etc/nftables.conf (mode 0600 -> 0644)
  - /etc/issue
"
    );
    assert_eq!(
        fx.calls()[0],
        "mount -t btrfs -o subvolid=5,ro /dev/mapper/aios {ro}"
    );
}

#[test]
fn status_without_a_booted_generation_skips_drift() {
    let fx = Fixture::fresh();
    let st = status(&fx.runner, &fx.layout).unwrap();
    assert_eq!(
        st,
        Status {
            booted: None,
            default: None,
            bad: vec![],
            drift: None,
        }
    );
    assert_eq!(
        st.to_string(),
        "booted:  unknown\ndefault: unknown\nbad:     none\n\
         drift:   unknown (no aios.gen= on the kernel cmdline)\n"
    );
    assert!(fx.calls().is_empty());
}

#[test]
fn unreadable_files_are_skipped_with_a_note() {
    use std::os::unix::fs::PermissionsExt;
    let fx = drifted();
    let (live, snap) = (&fx.layout.live_etc, fx.layout.subvol("@etc-gen-0007"));
    for etc in [live, &snap] {
        write(&etc.join("secret"), "x", 0o000);
    }
    if fs::read(live.join("secret")).is_ok() {
        return; // root reads anything; nothing to check
    }
    let d = drift(live, &snap).unwrap();
    assert_eq!(d.skipped, ["/etc/secret: Permission denied (os error 13)"]);
    assert!(!d.modified.iter().any(|m| m.path == "/etc/secret"));
    let st = Status {
        booted: Some(GenId(7)),
        default: Some(GenId(7)),
        bad: vec![],
        drift: Some(d),
    };
    assert!(st
        .to_string()
        .ends_with("note: skipped /etc/secret: Permission denied (os error 13)\n"));
    for etc in [live, &snap] {
        fs::set_permissions(etc.join("secret"), fs::Permissions::from_mode(0o600)).unwrap();
    }
}
