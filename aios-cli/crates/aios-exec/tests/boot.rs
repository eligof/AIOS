mod common;

use aios_exec::ops::{gc, gc_mounted, rollback, BootState, GcMode};
use aios_gen::GenId;
use common::{mkdir, write, Fixture};
use std::fs;
use std::path::Path;

/// `LoaderEntryDefault` as efivarfs stores it: attributes, then UTF-16LE with a NUL.
fn efivar(text: &str) -> Vec<u8> {
    let mut bytes = vec![0x07, 0, 0, 0];
    for unit in text.encode_utf16().chain([0]) {
        bytes.extend(unit.to_le_bytes());
    }
    bytes
}

/// Point `bootctl set-default` at `entry`.
fn set_default(fx: &Fixture, entry: &str) {
    mkdir(&fx.layout.efivars);
    fs::write(fx.layout.loader_entry_default(), efivar(entry)).unwrap();
}

/// A booted gen-7 machine with gens 1-9 (and their main UKIs), plus a bad gen-9.
fn many_gens() -> Fixture {
    let fx = Fixture::booted();
    let l = &fx.layout;
    for n in 1..=9 {
        mkdir(&l.subvol(&GenId(n).usr_subvol()));
        mkdir(&l.subvol(&GenId(n).etc_subvol()));
    }
    for n in [1, 2, 3, 4, 5, 8] {
        let name = format!("aios-gen-{}-cachyos+3.efi", GenId(n));
        write(&l.uki_dir().join(name), "uki", 0o644);
    }
    write(&l.uki_dir().join("aios-gen-0003-lts+3.efi"), "uki", 0o644);
    write(
        &l.uki_dir().join("aios-gen-0009-cachyos+0-3.efi"),
        "uki",
        0o644,
    );
    fx
}

/// gc deleting gen-`n`, whose UKIs are on the ESP: the UKIs (and an ESP fsync) first,
/// then the subvolumes.
fn delete_gen(n: u32) -> String {
    let gen = GenId(n);
    format!(
        "
        fsync {{esp}}/EFI/Linux
        btrfs subvolume show {{top}}/@usr-gen-{gen}
        btrfs subvolume delete --recursive {{top}}/@usr-gen-{gen}
        btrfs subvolume show {{top}}/@etc-gen-{gen}
        btrfs subvolume delete --recursive {{top}}/@etc-gen-{gen}
        "
    )
}

fn esp(fx: &Fixture) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(fx.layout.uki_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn boot_state_reads_cmdline_esp_and_override() {
    let fx = many_gens();
    let state = BootState::read(&fx.layout).unwrap();
    assert_eq!(state.booted, Some(GenId(7)));
    assert_eq!(state.default_override, None);
    assert_eq!(state.newest, Some(GenId(8)), "gen-9 is bad");
    assert_eq!(state.default_gen(), Some(GenId(8)));
    assert_eq!(state.bad(), [GenId(9)]);
    set_default(&fx, "aios-gen-0005-cachyos.efi");
    let state = BootState::read(&fx.layout).unwrap();
    assert_eq!(state.default_override, Some(GenId(5)));
    assert_eq!(state.default_gen(), Some(GenId(5)));
}

#[test]
fn missing_inputs_mean_unknown() {
    let fx = Fixture::fresh();
    fs::remove_file(&fx.layout.proc_cmdline).unwrap();
    let state = BootState::read(&fx.layout).unwrap();
    assert_eq!((state.booted, state.default_gen()), (None, None));
    assert!(state.ukis.is_empty());
}

/// A read-only look at the top level, then `bootctl set-default ENTRY`.
const ROLLBACK: &str = "
mount -t btrfs -o subvolid=5,ro /dev/mapper/aios {ro}
umount {ro}
bootctl set-default ";

#[test]
fn rollback_checks_the_generation_then_sets_the_default_entry_without_the_counter() {
    let fx = many_gens();
    assert_eq!(
        rollback(&fx.runner, &fx.layout, GenId(3), false).unwrap(),
        "aios-gen-0003-cachyos.efi"
    );
    assert_eq!(
        fx.calls(),
        fx.expand(&format!("{ROLLBACK}aios-gen-0003-cachyos.efi"))
    );
}

#[test]
fn rollback_needs_a_boot_entry() {
    let fx = many_gens();
    let err = rollback(&fx.runner, &fx.layout, GenId(42), false).unwrap_err();
    assert_eq!(err.to_string(), "no boot entry for gen-0042");
    assert!(fx.calls().is_empty());
}

#[test]
fn rollback_needs_both_subvolumes() {
    let fx = many_gens();
    for (gone, other) in [
        ("@usr-gen-0003", "@etc-gen-0003"),
        ("@etc-gen-0004", "@usr-gen-0004"),
    ] {
        fs::remove_dir(fx.layout.subvol(gone)).unwrap();
        let gen = if gone.ends_with('3') {
            GenId(3)
        } else {
            GenId(4)
        };
        let err = rollback(&fx.runner, &fx.layout, gen, true).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("gen-{gen} is not installed: {gone} is missing")
        );
        assert!(fx.layout.subvol(other).is_dir());
    }
    assert!(!fx.calls().iter().any(|c| c.starts_with("bootctl")));
    assert!(
        !fx.layout.ro_top().exists(),
        "the read-only mount point is removed"
    );
}

/// A symlink at a generation's name could point at another generation's subvolume, and a
/// plain directory is no subvolume at all: neither can boot.
#[test]
fn rollback_refuses_a_symlinked_or_plain_generation_directory() {
    let fx = many_gens();
    let l = &fx.layout;
    fs::remove_dir(l.subvol("@usr-gen-0003")).unwrap();
    std::os::unix::fs::symlink(l.subvol("@usr-gen-0004"), l.subvol("@usr-gen-0003")).unwrap();
    let err = rollback(&fx.runner, l, GenId(3), true).unwrap_err();
    assert_eq!(
        err.to_string(),
        "gen-0003 is not installed: @usr-gen-0003 is a symlink, not a subvolume"
    );
    fs::remove_dir(l.subvol("@etc-gen-0004")).unwrap();
    std::os::unix::fs::symlink("@etc-gen-0005", l.subvol("@etc-gen-0004")).unwrap();
    let err = rollback(&fx.runner, l, GenId(4), true).unwrap_err();
    assert_eq!(
        err.to_string(),
        "gen-0004 is not installed: @etc-gen-0004 is a symlink, not a subvolume"
    );
    // Without subvolume emulation a plain directory has the wrong inode.
    let mut plain = aios_exec::FakeRunner::new();
    plain.emulate_top_mounts(&l.top);
    let err = rollback(&plain, l, GenId(5), true).unwrap_err();
    assert_eq!(
        err.to_string(),
        "gen-0005 is not installed: @usr-gen-0005 is not a subvolume"
    );
    assert!(!fx.calls().iter().any(|c| c.starts_with("bootctl")));
    assert!(!plain.calls().iter().any(|c| c.starts_with("bootctl")));
}

#[test]
fn rollback_refuses_a_bad_generation_unless_forced() {
    let fx = many_gens();
    let err = rollback(&fx.runner, &fx.layout, GenId(9), false).unwrap_err();
    assert_eq!(
        err.to_string(),
        "gen-0009 is marked bad (its boot tries ran out); use --force to boot it anyway"
    );
    assert!(fx.calls().is_empty());
    assert_eq!(
        rollback(&fx.runner, &fx.layout, GenId(9), true).unwrap(),
        "aios-gen-0009-cachyos.efi"
    );
    assert_eq!(
        fx.calls(),
        fx.expand(&format!("{ROLLBACK}aios-gen-0009-cachyos.efi"))
    );
}

#[test]
fn gc_keeps_the_newest_protected_and_gen_one() {
    let fx = many_gens();
    set_default(&fx, "aios-gen-0003-cachyos.efi");
    let deleted = gc(&fx.runner, &fx.layout, 3).unwrap();
    assert_eq!(deleted, [GenId(2), GenId(4), GenId(5), GenId(6)]);
    let mut expected = fx.expand("mount -t btrfs -o subvolid=5 /dev/mapper/aios {top}");
    for n in [2, 4, 5, 6] {
        expected.extend(fx.expand(&delete_gen(n)));
    }
    expected.extend(fx.expand("btrfs filesystem sync {top}\numount {top}"));
    assert_eq!(fx.calls(), expected);
    for n in [2, 4, 5, 6] {
        assert!(!fx.layout.subvol(&GenId(n).usr_subvol()).exists());
        assert!(!fx.layout.subvol(&GenId(n).etc_subvol()).exists());
    }
    assert_eq!(
        esp(&fx),
        [
            "aios-gen-0001-cachyos+3.efi",
            "aios-gen-0003-cachyos+3.efi",
            "aios-gen-0003-lts+3.efi",
            "aios-gen-0007-cachyos.efi",
            "aios-gen-0008-cachyos+3.efi",
            "aios-gen-0009-cachyos+0-3.efi",
        ]
    );
}

#[test]
fn gc_with_keep_zero_still_keeps_booted_and_default() {
    let fx = many_gens();
    let deleted = gc_mounted(&fx.runner, &fx.layout, 0, GcMode::Running).unwrap();
    assert_eq!(
        deleted,
        [2, 3, 4, 5, 6, 9].map(GenId),
        "1 (baseline), 7 (booted) and 8 (newest good) stay"
    );
    assert!(!fx
        .calls()
        .iter()
        .any(|c| c.starts_with("mount") || c.starts_with("umount")));
}

#[test]
fn gc_deletes_incomplete_generations_and_ignores_their_ukis_for_the_default() {
    let fx = many_gens();
    let l = &fx.layout;
    mkdir(&l.subvol("@usr-gen-0010"));
    mkdir(&l.subvol("@etc-gen-0011"));
    write(&l.uki_dir().join("aios-gen-0011-lts+3.efi"), "uki", 0o644);
    // Newer than gen-8 and not bad, but it has no subvolumes, so it can't boot: gen-8 is
    // still what the next boot picks once it is gone, and must stay.
    write(
        &l.uki_dir().join("aios-gen-0012-cachyos+3.efi"),
        "uki",
        0o644,
    );
    let deleted = gc_mounted(&fx.runner, l, 0, GcMode::Running).unwrap();
    assert_eq!(deleted, [2, 3, 4, 5, 6, 9, 10, 11, 12].map(GenId));
    for name in ["@usr-gen-0010", "@etc-gen-0011"] {
        assert!(!l.subvol(name).exists(), "{name}");
    }
    assert!(l.subvol("@usr-gen-0008").is_dir() && l.subvol("@etc-gen-0008").is_dir());
    assert_eq!(
        esp(&fx),
        [
            "aios-gen-0001-cachyos+3.efi",
            "aios-gen-0007-cachyos.efi",
            "aios-gen-0008-cachyos+3.efi",
        ]
    );
    let calls = fx.calls();
    let from = calls
        .iter()
        .rposition(|c| c.ends_with("@etc-gen-0009"))
        .unwrap();
    assert_eq!(
        calls[from + 1..],
        fx.expand(
            "
            btrfs subvolume show {top}/@usr-gen-0010
            btrfs subvolume delete --recursive {top}/@usr-gen-0010
            fsync {esp}/EFI/Linux
            btrfs subvolume show {top}/@etc-gen-0011
            btrfs subvolume delete --recursive {top}/@etc-gen-0011
            fsync {esp}/EFI/Linux
            btrfs filesystem sync {top}
            "
        )
    );
}

#[test]
fn gc_never_touches_the_booted_generation_even_when_incomplete() {
    let fx = Fixture::booted();
    fs::remove_dir(fx.layout.subvol("@etc-gen-0007")).unwrap();
    assert!(gc(&fx.runner, &fx.layout, 0).unwrap().is_empty());
    assert!(fx.layout.subvol("@usr-gen-0007").is_dir());
    assert_eq!(
        esp(&fx),
        ["aios-gen-0006-cachyos.efi", "aios-gen-0007-cachyos.efi"]
    );
}

#[test]
fn gc_unmounts_even_when_a_delete_fails() {
    let mut fx = many_gens();
    fx.runner.fail_on(&["btrfs", "subvolume", "delete"]);
    let err = gc(&fx.runner, &fx.layout, 3).unwrap_err();
    assert!(err.to_string().contains("injected failure"), "got {err}");
    assert_eq!(fx.calls().last().unwrap(), "umount {top}");
}

#[test]
fn gc_with_nothing_to_delete() {
    let fx = Fixture::booted();
    assert!(gc(&fx.runner, &fx.layout, 5).unwrap().is_empty());
    assert_eq!(fx.calls().len(), 2);
    assert!(Path::new(&fx.layout.subvol("@usr-gen-0006")).exists());
}

const UNKNOWN_BOOTED: &str = "cannot determine the booted generation; refusing to garbage-collect";

/// Without `aios.gen=` gc can't tell which generation is running, so it deletes nothing.
#[test]
fn gc_refuses_when_the_booted_generation_is_unknown() {
    for cmdline in [Some("root=/dev/mapper/aios rw quiet\n"), None] {
        let fx = many_gens();
        let before = esp(&fx);
        match cmdline {
            Some(text) => write(&fx.layout.proc_cmdline, text, 0o644),
            None => fs::remove_file(&fx.layout.proc_cmdline).unwrap(),
        }
        let err = gc(&fx.runner, &fx.layout, 0).unwrap_err();
        assert_eq!(err.to_string(), UNKNOWN_BOOTED, "{cmdline:?}");
        let err = gc_mounted(&fx.runner, &fx.layout, 0, GcMode::Running).unwrap_err();
        assert_eq!(err.to_string(), UNKNOWN_BOOTED);
        assert!(
            !fx.calls()
                .iter()
                .any(|c| c.contains("delete") || c.starts_with("fsync")),
            "{:?}",
            fx.calls()
        );
        for n in 1..=9 {
            assert!(fx.layout.subvol(&GenId(n).usr_subvol()).is_dir(), "gen-{n}");
        }
        assert_eq!(esp(&fx), before);
    }
}

/// Bootstrap's ESP-space gc runs before anything on the target is booted.
#[test]
fn bootstrap_gc_needs_no_booted_generation() {
    let fx = many_gens();
    write(
        &fx.layout.proc_cmdline,
        "archisobasedir=arch quiet\n",
        0o644,
    );
    let deleted = gc_mounted(&fx.runner, &fx.layout, 0, GcMode::Bootstrap).unwrap();
    assert_eq!(
        deleted,
        [2, 3, 4, 5, 6, 7, 9].map(GenId),
        "1 and 8 (newest good) stay"
    );
}

/// Only a missing `LoaderEntryDefault` means "no override": one that can't be read is an
/// error, so gc never deletes a default it failed to see.
#[test]
fn an_unreadable_boot_default_is_an_error() {
    let fx = many_gens();
    let before = esp(&fx);
    mkdir(&fx.layout.loader_entry_default());
    let err = BootState::read(&fx.layout).unwrap_err();
    assert!(
        err.to_string()
            .starts_with(&format!("{}: ", fx.layout.loader_entry_default().display())),
        "{err}"
    );
    assert!(gc(&fx.runner, &fx.layout, 0).is_err());
    assert_eq!(esp(&fx), before);
    assert!(!fx.calls().iter().any(|c| c.contains("delete")));
}

/// A `LoaderEntryDefault` that can be read but not decoded fails too: gc must not guess
/// which entry the boot loader will pick. An empty name or one that isn't an aios UKI is
/// no aios override.
#[test]
fn an_undecodable_boot_default_is_an_error() {
    let fx = many_gens();
    mkdir(&fx.layout.efivars);
    let var = fx.layout.loader_entry_default();
    for bytes in [
        vec![7, 0, 0],
        vec![7, 0, 0, 0, b'a'],
        vec![7, 0, 0, 0, 0x00, 0xd8, 0, 0],
    ] {
        fs::write(&var, &bytes).unwrap();
        let err = BootState::read(&fx.layout).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("{}: not a UTF-16 boot entry name", var.display()),
            "{bytes:?}"
        );
        assert!(gc(&fx.runner, &fx.layout, 0).is_err());
    }
    for bytes in [
        vec![7, 0, 0, 0],
        vec![7, 0, 0, 0, 0, 0],
        efivar("arch.conf"),
    ] {
        fs::write(&var, &bytes).unwrap();
        let state = BootState::read(&fx.layout).unwrap();
        assert_eq!(state.default_override, None, "{bytes:?}");
    }
    assert!(!fx.calls().iter().any(|c| c.contains("delete")));
}
