mod common;

use aios_exec::ops::{gc, gc_mounted, rollback, BootState};
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

#[test]
fn rollback_sets_the_default_entry_without_the_counter() {
    let fx = many_gens();
    assert_eq!(
        rollback(&fx.runner, &fx.layout, GenId(3)).unwrap(),
        "aios-gen-0003-cachyos.efi"
    );
    assert_eq!(
        fx.calls(),
        ["bootctl set-default aios-gen-0003-cachyos.efi"]
    );
}

#[test]
fn rollback_needs_a_boot_entry() {
    let fx = many_gens();
    let err = rollback(&fx.runner, &fx.layout, GenId(42)).unwrap_err();
    assert_eq!(err.to_string(), "no boot entry for gen-0042");
    assert!(fx.calls().is_empty());
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
    let deleted = gc_mounted(&fx.runner, &fx.layout, 0).unwrap();
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
    let deleted = gc_mounted(&fx.runner, l, 0).unwrap();
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
