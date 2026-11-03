use aios_exec::etcfs;
use aios_plan::EtcEntry;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;

fn file(text: &str, mode: u32) -> EtcEntry {
    EtcEntry::File {
        content: text.as_bytes().to_vec(),
        mode,
    }
}

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
}

#[test]
fn writes_files_with_exact_modes_and_creates_parents() {
    let dir = tempfile::tempdir().unwrap();
    let etc = dir.path();
    etcfs::write(etc, "/etc/shadow", &file("root:!*:1::::::\n", 0o600)).unwrap();
    etcfs::write(etc, "/etc/kernel/helper", &file("#!/bin/sh\n", 0o4755)).unwrap();
    assert_eq!(
        fs::read_to_string(etc.join("shadow")).unwrap(),
        "root:!*:1::::::\n"
    );
    assert_eq!(mode(&etc.join("shadow")), 0o600);
    assert_eq!(mode(&etc.join("kernel/helper")), 0o4755);
    assert_eq!(mode(&etc.join("kernel")), 0o755);
}

#[test]
fn replaces_symlinks_instead_of_writing_through_them() {
    let dir = tempfile::tempdir().unwrap();
    let (etc, outside) = (dir.path().join("etc"), dir.path().join("outside"));
    fs::create_dir(&etc).unwrap();
    fs::write(&outside, "keep me\n").unwrap();
    symlink(&outside, etc.join("resolv.conf")).unwrap();
    etcfs::write(&etc, "/etc/resolv.conf", &file("nameserver ::1\n", 0o644)).unwrap();
    assert_eq!(fs::read_to_string(&outside).unwrap(), "keep me\n");
    assert!(fs::symlink_metadata(etc.join("resolv.conf"))
        .unwrap()
        .is_file());
}

#[test]
fn creates_symlinks_over_files() {
    let dir = tempfile::tempdir().unwrap();
    let etc = dir.path();
    fs::write(etc.join("localtime"), "UTC").unwrap();
    let link = EtcEntry::Symlink("/usr/share/zoneinfo/Asia/Jerusalem".to_string());
    etcfs::write(etc, "/etc/localtime", &link).unwrap();
    assert_eq!(
        fs::read_link(etc.join("localtime")).unwrap(),
        Path::new("/usr/share/zoneinfo/Asia/Jerusalem")
    );
}

#[test]
fn refuses_symlinked_parents_and_directories() {
    let dir = tempfile::tempdir().unwrap();
    let (etc, outside) = (dir.path().join("etc"), dir.path().join("outside"));
    fs::create_dir_all(etc.join("kernel")).unwrap();
    fs::create_dir(&outside).unwrap();
    symlink(&outside, etc.join("ssl")).unwrap();
    let err = etcfs::write(&etc, "/etc/ssl/cert.pem", &file("x", 0o644)).unwrap_err();
    assert_eq!(
        err.to_string(),
        format!(
            "{}: is a symlink; refusing to follow it",
            etc.join("ssl").display()
        )
    );
    assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
    let err = etcfs::write(&etc, "/etc/kernel", &file("x", 0o644)).unwrap_err();
    assert_eq!(
        err.to_string(),
        format!("{}: is a directory", etc.join("kernel").display())
    );
    assert!(etcfs::create_dirs(&etc, "/etc/ssl/private").is_err());
}

#[test]
fn remove_deletes_files_and_links_and_ignores_missing_paths() {
    let dir = tempfile::tempdir().unwrap();
    let etc = dir.path();
    fs::write(etc.join("old.conf"), "x").unwrap();
    symlink("/dev/null", etc.join("old.hook")).unwrap();
    for path in [
        "/etc/old.conf",
        "/etc/old.hook",
        "/etc/never.conf",
        "/etc/no/such/dir",
    ] {
        etcfs::remove(etc, path).unwrap();
    }
    assert_eq!(fs::read_dir(etc).unwrap().count(), 0);
}

#[test]
fn create_dirs_makes_the_whole_path() {
    let dir = tempfile::tempdir().unwrap();
    etcfs::create_dirs(dir.path(), "/etc/aios/home/eli/.config/autostart").unwrap();
    assert!(dir.path().join("aios/home/eli/.config/autostart").is_dir());
}

#[test]
fn set_mode_changes_a_file_and_never_follows_a_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let (etc, outside) = (dir.path().join("etc"), dir.path().join("outside"));
    fs::create_dir(&etc).unwrap();
    fs::write(&outside, "x").unwrap();
    fs::set_permissions(&outside, fs::Permissions::from_mode(0o644)).unwrap();
    etcfs::write(&etc, "/etc/helper", &file("#!/bin/sh\n", 0o755)).unwrap();
    etcfs::set_mode(&etc, "/etc/helper", 0o4755).unwrap();
    assert_eq!(mode(&etc.join("helper")), 0o4755);
    symlink(&outside, etc.join("link")).unwrap();
    assert!(etcfs::set_mode(&etc, "/etc/link", 0o4755).is_err());
    assert_eq!(mode(&outside), 0o644);
    let err = etcfs::set_mode(&etc, "/etc/missing/helper", 0o755).unwrap_err();
    assert!(err.to_string().contains("missing/helper"), "{err}");
}

#[test]
fn only_paths_below_etc() {
    let dir = tempfile::tempdir().unwrap();
    for bad in ["/usr/x", "/etc/../x", "/etc/", "/etc/a//b"] {
        let err = etcfs::write(dir.path(), bad, &file("x", 0o644)).unwrap_err();
        assert_eq!(err.to_string(), format!("{bad}: not a path below /etc"));
    }
}
