mod common;

use aios_exec::ops::{drift, gen_list, gen_rows, render_gen_list, status, Drift, GenRow, Status};
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
            mount -t btrfs -o subvolid=5,ro /dev/mapper/aios {top}
            umount {top}
            "
        )
    );
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
                "/etc/hostname".to_string(),
                "/etc/localtime".to_string(),
                "/etc/nftables.conf".to_string(),
            ],
            removed: vec!["/etc/issue".to_string()],
            skipped: vec![],
        }
    );
}

#[test]
fn identical_trees_have_no_drift() {
    let fx = machine();
    let (live, snap) = (&fx.layout.live_etc, fx.layout.subvol("@etc-gen-0007"));
    for etc in [live, &snap] {
        write(&etc.join("hostname"), "nightcity\n", 0o644);
    }
    assert!(drift(live, &snap).unwrap().is_empty());
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
  ~ /etc/hostname
  ~ /etc/localtime
  ~ /etc/nftables.conf
  - /etc/issue
"
    );
    assert_eq!(
        fx.calls()[0],
        "mount -t btrfs -o subvolid=5,ro /dev/mapper/aios {top}"
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
    assert!(!d.modified.contains(&"/etc/secret".to_string()));
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
