mod common;

use aios_plan::{desired_etc, EtcEntry, PlanError, MANAGED_FILES, PKGDIRS_CONF};
use aios_render::{cmdline, fstab, managed_list, UserDbError};
use common::{fixture, fixture_with, text_file, write, FakeProbe, ELI_HASH, MANIFEST};
use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use tempfile::TempDir;

#[test]
fn desired_has_every_managed_path() {
    let fx = fixture();
    let desired = desired_etc(&fx.inputs(), &FakeProbe::base()).unwrap();
    let paths: Vec<&str> = desired.keys().map(String::as_str).collect();
    assert_eq!(
        paths,
        [
            "/etc/aios/home/eli/.local/bin/hello",
            "/etc/aios/home/eli/.local/bin/lib/util.sh",
            "/etc/aios/home/eli/.zshrc",
            "/etc/aios/managed-files",
            "/etc/fstab",
            "/etc/group",
            "/etc/gshadow",
            "/etc/hostname",
            "/etc/kernel/cmdline",
            "/etc/locale.conf",
            "/etc/locale.gen",
            "/etc/localtime",
            "/etc/nftables.conf",
            "/etc/pacman.d/hooks/90-mkinitcpio-install.hook",
            "/etc/passwd",
            "/etc/shadow",
            "/etc/tmpfiles.d/aios-home.conf",
            "/etc/tmpfiles.d/aios-persist.conf",
            "/etc/vconsole.conf",
        ]
    );
}

#[test]
fn files_entries_carry_content_manifest_mode_and_symlinks() {
    let fx = fixture();
    let d = desired_etc(&fx.inputs(), &FakeProbe::base()).unwrap();
    assert_eq!(d["/etc/nftables.conf"], text_file("flush ruleset\n", 0o600));
    assert_eq!(
        d["/etc/pacman.d/hooks/90-mkinitcpio-install.hook"],
        EtcEntry::Symlink("/dev/null".to_string())
    );
}

#[test]
fn generated_files_come_from_the_renderers() {
    let fx = fixture();
    let d = desired_etc(&fx.inputs(), &FakeProbe::base()).unwrap();
    assert_eq!(
        d["/etc/fstab"],
        text_file(&fstab(&fx.manifest, &fx.ctx), 0o644)
    );
    assert_eq!(
        d["/etc/kernel/cmdline"],
        text_file(&cmdline(&fx.manifest, &fx.ctx), 0o644)
    );
    assert_eq!(d["/etc/hostname"], text_file("nightcity\n", 0o644));
    assert_eq!(
        d["/etc/locale.gen"],
        text_file("en_US.UTF-8 UTF-8\n", 0o644)
    );
    assert_eq!(
        d["/etc/localtime"],
        EtcEntry::Symlink("/usr/share/zoneinfo/Asia/Jerusalem".to_string())
    );
}

#[test]
fn locale_gen_is_omitted_for_c_utf8() {
    let fx = fixture_with(&MANIFEST.replace("en_US.UTF-8", "C.UTF-8"));
    let d = desired_etc(&fx.inputs(), &FakeProbe::base()).unwrap();
    assert!(!d.contains_key("/etc/locale.gen"));
    assert_eq!(d["/etc/locale.conf"], text_file("LANG=C.UTF-8\n", 0o644));
}

#[test]
fn account_files_merge_declared_users_into_the_probe_state() {
    let fx = fixture();
    let d = desired_etc(&fx.inputs(), &FakeProbe::base()).unwrap();
    assert_eq!(
        d["/etc/passwd"],
        text_file(
            "root:x:0:0::/root:/usr/bin/bash\n\
             nobody:x:65534:65534:Kernel Overflow User:/:/usr/bin/nologin\n\
             eli:x:1000:1000::/home/eli:/usr/bin/zsh\n",
            0o644
        )
    );
    assert_eq!(
        d["/etc/group"],
        text_file(
            "root:x:0:root\nwheel:x:998:eli\nnobody:x:65534:\neli:x:1000:\n",
            0o644
        )
    );
    let shadow =
        format!("root:!*:20000::::::\nnobody:!*:20000::::::\neli:{ELI_HASH}:20760:0:99999:7:::\n");
    assert_eq!(d["/etc/shadow"], text_file(&shadow, 0o600));
    assert_eq!(
        d["/etc/gshadow"],
        text_file("root:::root\nwheel:!*::eli\nnobody:!*::\neli:!*::\n", 0o600)
    );
}

#[test]
fn absent_account_files_mean_empty_databases() {
    let fx = fixture_with(&MANIFEST.replace("groups = [\"wheel\"]", "groups = []"));
    let d = desired_etc(&fx.inputs(), &FakeProbe::root_only()).unwrap();
    assert_eq!(
        d["/etc/passwd"],
        text_file(
            "root:x:0:0::/root:/usr/bin/bash\neli:x:1000:1000::/home/eli:/usr/bin/zsh\n",
            0o644
        )
    );
    assert_eq!(d["/etc/group"], text_file("eli:x:1000:\n", 0o644));
    let shadow = format!("root:!*:::::::\neli:{ELI_HASH}:20760:0:99999:7:::\n");
    assert_eq!(d["/etc/shadow"], text_file(&shadow, 0o600));
}

#[test]
fn probe_without_passwd_has_no_root_and_fails() {
    let fx = fixture_with(&MANIFEST.replace("groups = [\"wheel\"]", "groups = []"));
    assert_eq!(
        desired_etc(&fx.inputs(), &FakeProbe::default()).unwrap_err(),
        PlanError::Users(UserDbError::MissingRoot)
    );
}

#[test]
fn home_sources_copy_files_and_walk_directories() {
    let fx = fixture();
    let d = desired_etc(&fx.inputs(), &FakeProbe::base()).unwrap();
    assert_eq!(
        d["/etc/aios/home/eli/.zshrc"],
        text_file("# zshrc\n", 0o644)
    );
    assert_eq!(
        d["/etc/aios/home/eli/.local/bin/hello"],
        text_file("#!/bin/sh\necho hello\n", 0o755)
    );
    assert_eq!(
        d["/etc/aios/home/eli/.local/bin/lib/util.sh"],
        text_file("util() { :; }\n", 0o700)
    );
}

#[test]
fn managed_files_lists_every_path_including_itself_and_pkgdirs_conf() {
    let fx = fixture();
    let d = desired_etc(&fx.inputs(), &FakeProbe::base()).unwrap();
    let mut paths: Vec<String> = d.keys().cloned().collect();
    assert!(paths.iter().any(|p| p == MANAGED_FILES));
    paths.push(PKGDIRS_CONF.to_string());
    assert_eq!(d[MANAGED_FILES], text_file(&managed_list(&paths), 0o644));
}

/// The executor renders `aios-pkgdirs.conf` from the candidate's packages (spec §4.3
/// step 5), so it is managed but never part of the desired state, even when `[files]`
/// names it.
#[test]
fn pkgdirs_conf_is_managed_but_never_desired() {
    let fx = fixture_with(&MANIFEST.replace(
        "[files]\n",
        "[files]\n\"/etc/tmpfiles.d/aios-pkgdirs.conf\" = { source = \"files/nftables.conf\" }\n",
    ));
    let d = desired_etc(&fx.inputs(), &FakeProbe::base()).unwrap();
    assert!(!d.contains_key(PKGDIRS_CONF));
    let EtcEntry::File { content, .. } = &d[MANAGED_FILES] else {
        panic!("managed-files is a file")
    };
    let listed = String::from_utf8(content.clone()).unwrap();
    assert!(listed.lines().any(|l| l == PKGDIRS_CONF), "{listed}");
}

#[test]
fn bad_mode_is_an_error() {
    let fx = fixture_with(&MANIFEST.replace("mode = \"0600\"", "mode = \"0999\""));
    let err = desired_etc(&fx.inputs(), &FakeProbe::base()).unwrap_err();
    assert_eq!(
        err,
        PlanError::BadMode {
            path: "/etc/nftables.conf".to_string(),
            mode: "0999".to_string()
        }
    );
    assert_eq!(
        err.to_string(),
        "file \"/etc/nftables.conf\": invalid mode \"0999\""
    );
}

#[test]
fn missing_source_is_an_io_error() {
    let fx = fixture_with(&MANIFEST.replace("files/nftables.conf", "files/missing.conf"));
    match desired_etc(&fx.inputs(), &FakeProbe::base()).unwrap_err() {
        PlanError::Io { path, .. } => assert!(path.ends_with("files/missing.conf"), "got {path}"),
        other => panic!("expected PlanError::Io, got {other:?}"),
    }
}

#[test]
fn account_parse_errors_propagate() {
    let fx = fixture();
    let mut probe = FakeProbe::base();
    probe
        .etc
        .insert("/etc/passwd".to_string(), text_file("broken\n", 0o644));
    assert_eq!(
        desired_etc(&fx.inputs(), &probe).unwrap_err(),
        PlanError::Users(UserDbError::Malformed {
            file: "passwd",
            line: 1
        })
    );
}

fn expect_symlink_error(err: PlanError, suffix: &str) {
    match &err {
        PlanError::SymlinkInSource { path } => {
            assert!(path.ends_with(suffix), "got {path}");
            assert_eq!(
                err.to_string(),
                format!("{path}: symlinks are not allowed in a home source directory")
            );
        }
        other => panic!("expected PlanError::SymlinkInSource, got {other:?}"),
    }
}

#[test]
fn symlink_to_a_file_in_a_home_source_directory_is_an_error() {
    let fx = fixture();
    symlink("hello", fx.repo.path().join("home/eli/bin/alias")).unwrap();
    let err = desired_etc(&fx.inputs(), &FakeProbe::base()).unwrap_err();
    expect_symlink_error(err, "home/eli/bin/alias");
}

#[test]
fn symlink_deep_in_a_home_source_directory_is_an_error() {
    let fx = fixture();
    symlink(
        "/etc/shadow",
        fx.repo.path().join("home/eli/bin/lib/shadow"),
    )
    .unwrap();
    let err = desired_etc(&fx.inputs(), &FakeProbe::base()).unwrap_err();
    expect_symlink_error(err, "home/eli/bin/lib/shadow");
}

#[test]
fn symlinked_subdirectory_in_a_home_source_directory_is_an_error() {
    let fx = fixture();
    symlink("lib", fx.repo.path().join("home/eli/bin/more")).unwrap();
    let err = desired_etc(&fx.inputs(), &FakeProbe::base()).unwrap_err();
    expect_symlink_error(err, "home/eli/bin/more");
}

/// Replace `rel` in the fixture repo with a symlink to a fresh file or directory outside it.
fn point_outside(fx: &common::Fixture, rel: &str, dir: bool) -> TempDir {
    let outside = TempDir::new().unwrap();
    let target = outside.path().join("target");
    if dir {
        write(outside.path(), "target/secret", "secret\n", 0o644);
    } else {
        write(outside.path(), "target", "secret\n", 0o644);
    }
    let link = fx.repo.path().join(rel);
    if dir {
        fs::remove_dir_all(&link).unwrap();
    } else {
        fs::remove_file(&link).unwrap();
    }
    symlink(&target, &link).unwrap();
    outside
}

fn expect_outside_repo(err: PlanError, suffix: &str) {
    match &err {
        PlanError::OutsideRepo { path } => {
            assert!(path.ends_with(suffix), "got {path}");
            assert_eq!(
                err.to_string(),
                format!("{path}: resolves outside the manifest repo")
            );
        }
        other => panic!("expected PlanError::OutsideRepo, got {other:?}"),
    }
}

#[test]
fn files_source_resolving_outside_the_repo_is_an_error() {
    let fx = fixture();
    let _outside = point_outside(&fx, "files/nftables.conf", false);
    let err = desired_etc(&fx.inputs(), &FakeProbe::base()).unwrap_err();
    expect_outside_repo(err, "files/nftables.conf");
}

#[test]
fn home_file_source_resolving_outside_the_repo_is_an_error() {
    let fx = fixture();
    let _outside = point_outside(&fx, "home/eli/zshrc", false);
    let err = desired_etc(&fx.inputs(), &FakeProbe::base()).unwrap_err();
    expect_outside_repo(err, "home/eli/zshrc");
}

#[test]
fn home_directory_source_resolving_outside_the_repo_is_an_error() {
    let fx = fixture();
    let _outside = point_outside(&fx, "home/eli/bin", true);
    let err = desired_etc(&fx.inputs(), &FakeProbe::base()).unwrap_err();
    expect_outside_repo(err, "home/eli/bin");
}

#[test]
fn absolute_or_parent_sources_resolve_outside_the_repo() {
    let outside = TempDir::new().unwrap();
    write(outside.path(), "x.conf", "secret\n", 0o644);
    let abs = outside.path().join("x.conf").display().to_string();
    let fx = fixture_with(&MANIFEST.replace("files/nftables.conf", &abs));
    let err = desired_etc(&fx.inputs(), &FakeProbe::base()).unwrap_err();
    expect_outside_repo(err, "x.conf");

    let fx = fixture();
    let rel = format!(
        "../{}/x.conf",
        outside.path().file_name().unwrap().to_str().unwrap()
    );
    let fx = fixture_with_repo_rel(fx, &rel);
    let err = desired_etc(&fx.inputs(), &FakeProbe::base()).unwrap_err();
    expect_outside_repo(err, "x.conf");
}

/// The fixture with its `[files]` source replaced by `rel`, keeping the same repo tempdir.
fn fixture_with_repo_rel(mut fx: common::Fixture, rel: &str) -> common::Fixture {
    fx.manifest = aios_manifest::parse(&MANIFEST.replace("files/nftables.conf", rel)).unwrap();
    fx
}

#[test]
fn symlink_inside_the_repo_is_followed_for_file_sources() {
    let fx = fixture_with(&MANIFEST.replace("files/nftables.conf", "files/alias"));
    symlink("nftables.conf", fx.repo.path().join("files/alias")).unwrap();
    let d = desired_etc(&fx.inputs(), &FakeProbe::base()).unwrap();
    assert_eq!(d["/etc/nftables.conf"], text_file("flush ruleset\n", 0o600));
}

#[test]
fn non_utf8_file_name_in_a_home_source_directory_is_an_io_error() {
    let fx = fixture();
    let name = OsStr::from_bytes(b"bad\xffname");
    fs::write(fx.repo.path().join("home/eli/bin").join(name), "x").unwrap();
    match desired_etc(&fx.inputs(), &FakeProbe::base()).unwrap_err() {
        PlanError::Io { path, message } => {
            assert!(path.contains("home/eli/bin/bad"), "got {path}");
            assert!(message.contains("UTF-8"), "got {message}");
        }
        other => panic!("expected PlanError::Io, got {other:?}"),
    }
}

#[test]
fn control_character_in_a_home_source_file_name_is_an_io_error() {
    for name in ["bad\nname", "bad\rname", "bad\u{1}name", "bad\u{7f}name"] {
        let fx = fixture();
        let file = fx.repo.path().join("home/eli/bin").join(name);
        fs::write(&file, "x").unwrap();
        match desired_etc(&fx.inputs(), &FakeProbe::base()).unwrap_err() {
            PlanError::Io { path, message } => {
                assert!(path.contains("home/eli/bin/bad"), "got {path}");
                assert!(message.contains("control character"), "got {message}");
            }
            other => panic!("expected PlanError::Io for {name:?}, got {other:?}"),
        }
    }
}

#[test]
fn spaces_in_a_home_source_file_name_are_allowed() {
    let fx = fixture();
    fs::write(fx.repo.path().join("home/eli/bin/a b"), "x").unwrap();
    let d = desired_etc(&fx.inputs(), &FakeProbe::base()).unwrap();
    assert!(d.contains_key("/etc/aios/home/eli/.local/bin/a b"));
}
