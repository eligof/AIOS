use aios_exec::btrfs;
use aios_exec::{FakeRunner, Output};
use std::fs;
use std::path::Path;

fn calls_with(fake: &FakeRunner, top: &Path) -> Vec<String> {
    let top = top.display().to_string();
    fake.calls()
        .iter()
        .map(|c| c.replace(&top, "$TOP"))
        .collect()
}

#[test]
fn subvolume_commands() {
    let fake = FakeRunner::new();
    let (a, b) = (Path::new("/top/@blank"), Path::new("/top/@root-cand"));
    btrfs::create(&fake, a).unwrap();
    btrfs::snapshot(&fake, a, b).unwrap();
    btrfs::set_readonly(&fake, b).unwrap();
    assert_eq!(
        fake.calls(),
        [
            "btrfs subvolume create /top/@blank",
            "btrfs subvolume snapshot /top/@blank /top/@root-cand",
            "btrfs property set -ts /top/@root-cand ro true",
        ]
    );
}

#[test]
fn mount_commands_and_top_mount_point() {
    let dir = tempfile::tempdir().unwrap();
    let top = dir.path().join("run/aios/top");
    let dev = Path::new("/dev/mapper/aios");
    let fake = FakeRunner::new();
    btrfs::mount_top(&fake, dev, &top, false).unwrap();
    btrfs::mount_top(&fake, dev, &top, true).unwrap();
    btrfs::bind(&fake, Path::new("/a"), Path::new("/b")).unwrap();
    btrfs::umount(&fake, &top).unwrap();
    btrfs::umount_recursive(&fake, Path::new("/run/aios/cand")).unwrap();
    assert!(top.is_dir(), "mount_top creates the mount point");
    assert_eq!(
        calls_with(&fake, &top),
        [
            "mount -t btrfs -o subvolid=5 /dev/mapper/aios $TOP",
            "mount -t btrfs -o subvolid=5,ro /dev/mapper/aios $TOP",
            "mount --bind /a /b",
            "umount $TOP",
            "umount -R /run/aios/cand",
        ]
    );
}

#[test]
fn delete_recursive_checks_then_lets_btrfs_walk_the_nesting() {
    let dir = tempfile::tempdir().unwrap();
    let top = dir.path();
    fs::create_dir_all(top.join("@root-cand/var/lib/machines")).unwrap();
    let mut fake = FakeRunner::new();
    fake.emulate_subvolumes();
    btrfs::delete_recursive(&fake, &top.join("@root-cand")).unwrap();
    assert_eq!(
        calls_with(&fake, top),
        [
            "btrfs subvolume show $TOP/@root-cand",
            "btrfs subvolume delete --recursive $TOP/@root-cand",
        ]
    );
    assert!(!top.join("@root-cand").exists());
}

#[test]
fn delete_recursive_skips_missing_paths() {
    let dir = tempfile::tempdir().unwrap();
    let fake = FakeRunner::new();
    btrfs::delete_recursive(&fake, &dir.path().join("@usr-cand")).unwrap();
    assert!(fake.calls().is_empty());
}

#[test]
fn a_non_subvolume_is_never_deleted() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("@etc-cand");
    fs::write(&path, "not a subvolume").unwrap();
    let mut fake = FakeRunner::new();
    fake.respond(
        &["btrfs", "subvolume", "show"],
        Output::failed(1, "ERROR: Not a Btrfs subvolume"),
    );
    let err = btrfs::delete_recursive(&fake, &path).unwrap_err();
    assert_eq!(
        err.to_string(),
        format!("{} exists but is not a subvolume", path.display())
    );
    assert_eq!(fake.calls().len(), 1);
}

#[test]
fn failures_propagate() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("@etc-cand")).unwrap();
    let mut fake = FakeRunner::new();
    fake.fail_on(&["btrfs", "subvolume", "delete"]);
    let err = btrfs::delete_recursive(&fake, &dir.path().join("@etc-cand")).unwrap_err();
    assert!(
        err.to_string()
            .ends_with("exited with status 1: injected failure"),
        "got {err}"
    );
}

#[test]
fn list_names_is_sorted() {
    let dir = tempfile::tempdir().unwrap();
    for name in ["@usr-gen-0002", "@blank", "@etc-gen-0002"] {
        fs::create_dir(dir.path().join(name)).unwrap();
    }
    assert_eq!(
        btrfs::list_names(dir.path()).unwrap(),
        ["@blank", "@etc-gen-0002", "@usr-gen-0002"]
    );
    assert!(btrfs::list_names(&dir.path().join("missing")).is_err());
}
