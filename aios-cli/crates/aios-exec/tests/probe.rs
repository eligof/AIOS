use aios_exec::{parse_unit_state, read_etc_entry, DirProbe, FakeRunner, Output};
use aios_plan::{EtcEntry, ProbeError, SystemProbe, UnitState};
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};

fn etc_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let etc = dir.path();
    fs::write(etc.join("hostname"), "nightcity\n").unwrap();
    fs::write(etc.join("shadow"), "root:!*:20000::::::\n").unwrap();
    fs::set_permissions(etc.join("shadow"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::create_dir(etc.join("kernel")).unwrap();
    fs::write(etc.join("kernel/helper"), "#!/bin/sh\n").unwrap();
    fs::set_permissions(
        etc.join("kernel/helper"),
        fs::Permissions::from_mode(0o4755),
    )
    .unwrap();
    symlink("/usr/share/zoneinfo/Asia/Jerusalem", etc.join("localtime")).unwrap();
    dir
}

#[test]
fn reads_files_with_their_mode_and_symlinks_with_their_target() {
    let dir = etc_dir();
    let read = |path: &str| read_etc_entry(dir.path(), path).unwrap();
    assert_eq!(
        read("/etc/hostname"),
        Some(EtcEntry::File {
            content: b"nightcity\n".to_vec(),
            mode: 0o644,
        })
    );
    assert_eq!(
        read("/etc/shadow"),
        Some(EtcEntry::File {
            content: b"root:!*:20000::::::\n".to_vec(),
            mode: 0o600,
        })
    );
    assert!(matches!(
        read("/etc/kernel/helper"),
        Some(EtcEntry::File { mode: 0o4755, .. })
    ));
    assert_eq!(
        read("/etc/localtime"),
        Some(EtcEntry::Symlink(
            "/usr/share/zoneinfo/Asia/Jerusalem".to_string()
        ))
    );
}

#[test]
fn absent_paths_are_none() {
    let dir = etc_dir();
    assert_eq!(read_etc_entry(dir.path(), "/etc/fstab").unwrap(), None);
    assert_eq!(read_etc_entry(dir.path(), "/etc/hostname/x").unwrap(), None);
}

#[test]
fn only_paths_below_etc_are_read() {
    let dir = etc_dir();
    for bad in [
        "/usr/lib/os-release",
        "/etc/",
        "/etc/../shadow",
        "/etc/a//b",
        "etc/hostname",
    ] {
        assert_eq!(
            read_etc_entry(dir.path(), bad),
            Err(ProbeError(format!("{bad}: not a path below /etc"))),
        );
    }
}

#[test]
fn directories_are_errors() {
    let dir = etc_dir();
    let err = read_etc_entry(dir.path(), "/etc/kernel").unwrap_err();
    assert_eq!(
        err.0,
        format!(
            "{}: not a regular file or symlink",
            dir.path().join("kernel").display()
        )
    );
}

#[test]
fn packages_from_the_running_system_or_a_chroot() {
    let mut fake = FakeRunner::new();
    fake.respond(&["pacman", "-Qqe"], Output::ok("base\nzsh\n\n"))
        .respond(
            &["arch-chroot", "/cand", "pacman", "-Qqe"],
            Output::ok("git\n"),
        );
    let live = DirProbe::new("/etc", &fake, None);
    let cand = DirProbe::new("/cand/etc", &fake, Some(PathBuf::from("/cand")));
    let names = |set: std::collections::BTreeSet<String>| set.into_iter().collect::<Vec<_>>();
    assert_eq!(names(live.explicit_packages().unwrap()), ["base", "zsh"]);
    assert_eq!(names(cand.explicit_packages().unwrap()), ["git"]);
    assert_eq!(
        fake.calls(),
        ["pacman -Qqe", "arch-chroot /cand pacman -Qqe"]
    );
}

#[test]
fn unit_state_asks_systemctl() {
    let mut fake = FakeRunner::new();
    fake.respond(&["systemctl"], Output::ok("enabled\n"));
    let live = DirProbe::new("/etc", &fake, None);
    let cand = DirProbe::new("/cand/etc", &fake, Some(PathBuf::from("/cand")));
    assert_eq!(live.unit_state("sshd.socket").unwrap(), UnitState::Enabled);
    assert_eq!(cand.unit_state("sshd.socket").unwrap(), UnitState::Enabled);
    assert_eq!(
        fake.calls(),
        [
            "systemctl is-enabled -- sshd.socket",
            "systemctl --root=/cand is-enabled -- sshd.socket",
        ]
    );
}

#[test]
fn a_unit_name_is_never_an_option() {
    let mut fake = FakeRunner::new();
    fake.respond(&["systemctl"], Output::ok("enabled\n"));
    let live = DirProbe::new("/etc", &fake, None);
    live.unit_state("--root=/tmp/evil").unwrap();
    assert_eq!(fake.calls(), ["systemctl is-enabled -- --root=/tmp/evil"]);
}

#[test]
fn systemctl_answers_map_onto_unit_states() {
    let cases = [
        ("enabled\n", 0, "", UnitState::Enabled),
        ("enabled-runtime\n", 0, "", UnitState::Enabled),
        ("disabled\n", 1, "", UnitState::Disabled),
        ("linked\n", 1, "", UnitState::Disabled),
        ("masked\n", 1, "", UnitState::Masked),
        ("masked-runtime\n", 1, "", UnitState::Masked),
        ("static\n", 0, "", UnitState::Static),
        ("indirect\n", 0, "", UnitState::Static),
        ("generated\n", 0, "", UnitState::Static),
        ("alias\n", 0, "", UnitState::Static),
        ("not-found\n", 4, "", UnitState::NotFound),
        ("", 4, "", UnitState::NotFound),
        (
            "",
            1,
            "Failed to get unit file state for x.service: No such file or directory\n",
            UnitState::NotFound,
        ),
    ];
    for (stdout, status, stderr, want) in cases {
        let out = Output {
            status,
            stdout: stdout.into(),
            stderr: stderr.into(),
        };
        assert_eq!(parse_unit_state("x.service", &out), Ok(want), "{stdout:?}");
    }
}

#[test]
fn bad_or_unknown_answers_are_errors() {
    let out = Output {
        status: 1,
        stdout: b"bad\n".to_vec(),
        stderr: Vec::new(),
    };
    assert_eq!(
        parse_unit_state("x.service", &out),
        Err(ProbeError(
            "systemctl is-enabled x.service: unexpected answer \"bad\" (exit status 1)".to_string()
        ))
    );
}

#[test]
fn command_failures_are_probe_errors() {
    let mut fake = FakeRunner::new();
    fake.fail_on(&["pacman"]);
    let probe = DirProbe::new(Path::new("/etc"), &fake, None);
    assert_eq!(
        probe.explicit_packages(),
        Err(ProbeError(
            "`pacman -Qqe` exited with status 1: injected failure".to_string()
        ))
    );
}

#[test]
fn etc_entries_come_from_the_directory() {
    let dir = etc_dir();
    let fake = FakeRunner::new();
    let probe = DirProbe::new(dir.path(), &fake, None);
    assert!(probe.etc_entry("/etc/hostname").unwrap().is_some());
    assert!(fake.calls().is_empty());
}
