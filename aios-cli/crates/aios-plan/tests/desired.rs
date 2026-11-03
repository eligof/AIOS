mod common;

use aios_plan::{desired_etc, EtcEntry, PlanError, MANAGED_FILES};
use aios_render::{cmdline, fstab, managed_list, UserDbError};
use common::{fixture, fixture_with, text_file, FakeProbe, ELI_HASH, MANIFEST};

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
fn managed_files_lists_every_path_including_itself() {
    let fx = fixture();
    let d = desired_etc(&fx.inputs(), &FakeProbe::base()).unwrap();
    let paths: Vec<String> = d.keys().cloned().collect();
    assert!(paths.iter().any(|p| p == MANAGED_FILES));
    assert_eq!(d[MANAGED_FILES], text_file(&managed_list(&paths), 0o644));
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
