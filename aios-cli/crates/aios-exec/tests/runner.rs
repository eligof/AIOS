use aios_exec::{run_ok, Cmd, CommandRunner, FakeRunner, Output, RealRunner};
use std::fs;

#[test]
fn display_quotes_words_like_a_shell() {
    let commit = Cmd::new("git").args(["-C", "/persist/aios/config", "commit", "-m"]);
    assert_eq!(
        commit.arg("aios: manifest for gen-0008").to_string(),
        "git -C /persist/aios/config commit -m 'aios: manifest for gen-0008'"
    );
    assert_eq!(
        Cmd::new("bootctl").args(["set-default", ""]).to_string(),
        "bootctl set-default ''"
    );
    assert_eq!(Cmd::new("echo").arg("it's").to_string(), "echo 'it'\\''s'");
    assert_eq!(
        Cmd::new("systemctl")
            .arg("--root=/run/aios/cand")
            .arg_path("/a/b")
            .to_string(),
        "systemctl --root=/run/aios/cand /a/b"
    );
}

#[test]
fn display_never_shows_stdin() {
    let cmd = Cmd::new("mkpasswd")
        .args(["-m", "yescrypt", "-s"])
        .stdin("hunter2");
    assert_eq!(cmd.to_string(), "mkpasswd -m yescrypt -s");
    assert_eq!(cmd.stdin.as_deref(), Some(&b"hunter2"[..]));
}

#[test]
fn fake_records_calls_and_defaults_to_success() {
    let fake = FakeRunner::new();
    let out = fake.run(&Cmd::new("umount").arg("/run/aios/top")).unwrap();
    assert_eq!(out, Output::default());
    fake.run(&Cmd::new("sync")).unwrap();
    assert_eq!(fake.calls(), ["umount /run/aios/top", "sync"]);
    assert_eq!(fake.commands()[1], Cmd::new("sync"));
}

#[test]
fn longest_prefix_wins_and_later_entries_win_ties() {
    let mut fake = FakeRunner::new();
    fake.respond(&["pacman"], Output::ok("short\n"))
        .respond(&["pacman", "-Qqe"], Output::ok("long\n"))
        .respond(&["pacman"], Output::ok("later\n"));
    let qqe = fake.run(&Cmd::new("pacman").arg("-Qqe")).unwrap();
    assert_eq!(qqe.stdout_text(), "long\n");
    let q = fake.run(&Cmd::new("pacman").arg("-Q")).unwrap();
    assert_eq!(q.stdout_text(), "later\n");
    let other = fake.run(&Cmd::new("pacman-key")).unwrap();
    assert_eq!(other.stdout_text(), "", "prefixes match whole words");
}

#[test]
fn fail_on_injects_status_one_and_run_ok_reports_it() {
    let mut fake = FakeRunner::new();
    fake.respond(&["mount"], Output::ok(""))
        .fail_on(&["mount", "--bind"]);
    let bind = Cmd::new("mount").args(["--bind", "/a", "/b"]);
    assert_eq!(fake.run(&bind).unwrap().status, 1);
    assert_eq!(
        run_ok(&fake, &bind).unwrap_err().to_string(),
        "`mount --bind /a /b` exited with status 1: injected failure"
    );
    assert!(run_ok(&fake, &Cmd::new("mount").arg("-a")).is_ok());
}

#[test]
fn run_ok_keeps_the_last_three_stderr_lines() {
    let mut fake = FakeRunner::new();
    fake.respond(
        &["pacman"],
        Output::failed(4, "one\n\ntwo\nthree\n  four  \n"),
    )
    .respond(&["false"], Output::failed(2, ""));
    assert_eq!(
        run_ok(&fake, &Cmd::new("pacman").arg("-Syu"))
            .unwrap_err()
            .to_string(),
        "`pacman -Syu` exited with status 4: two; three; four"
    );
    assert_eq!(
        run_ok(&fake, &Cmd::new("false")).unwrap_err().to_string(),
        "`false` exited with status 2"
    );
}

#[cfg(feature = "test-hooks")]
#[test]
fn json_script_answers_and_logs_every_call() {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("fake.json");
    let top = dir.path().join("top");
    fs::create_dir_all(top.join("@usr-gen-0001")).unwrap();
    fs::create_dir_all(dir.path().join("ro")).unwrap();
    fs::write(
        &script,
        format!(
            r#"{{"respond": [{{"argv": ["findmnt", "-no", "UUID"], "stdout": "7A1B-2C3D\n"}}],
                "fail_on": [["bootctl"]], "emulate_top": "{}"}}"#,
            top.display()
        ),
    )
    .unwrap();
    let fake = FakeRunner::from_json_file(&script).unwrap();
    let ro = dir.path().join("ro");
    fake.run(
        &Cmd::new("mount")
            .args(["-t", "btrfs", "-o", "subvolid=5,ro", "x"])
            .arg_path(&ro),
    )
    .unwrap();
    assert!(ro.join("@usr-gen-0001").is_dir());
    let uuid = fake
        .run(&Cmd::new("findmnt").args(["-no", "UUID", "/efi"]))
        .unwrap();
    assert_eq!(uuid.stdout_text(), "7A1B-2C3D\n");
    let bootctl = fake
        .run(&Cmd::new("bootctl").args(["set-default", ""]))
        .unwrap();
    assert_eq!(bootctl.status, 1);
    assert_eq!(
        fs::read_to_string(dir.path().join("fake.json.calls")).unwrap(),
        format!(
            "mount -t btrfs -o subvolid=5,ro x {}\nfindmnt -no UUID /efi\nbootctl set-default ''\n",
            ro.display()
        )
    );
}

#[cfg(feature = "test-hooks")]
#[test]
fn json_script_rejects_unknown_keys() {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("fake.json");
    fs::write(&script, r#"{"responses": []}"#).unwrap();
    let err = FakeRunner::from_json_file(&script).unwrap_err();
    assert!(
        err.to_string().contains("unknown field `responses`"),
        "got {err}"
    );
}

#[cfg(feature = "test-hooks")]
#[test]
fn the_call_log_never_follows_a_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("fake.json");
    fs::write(&script, "{}").unwrap();
    let victim = dir.path().join("victim");
    fs::write(&victim, "precious\n").unwrap();
    std::os::unix::fs::symlink(&victim, dir.path().join("fake.json.calls")).unwrap();
    let fake = FakeRunner::from_json_file(&script).unwrap();
    let err = fake.run(&Cmd::new("sync")).unwrap_err();
    assert!(err.to_string().contains("fake.json.calls: "), "{err}");
    assert_eq!(fs::read_to_string(&victim).unwrap(), "precious\n");
}

#[test]
fn subvolume_emulation_uses_plain_directories() {
    let dir = tempfile::tempdir().unwrap();
    let top = dir.path();
    let path = |name: &str| top.join(name).display().to_string();
    let btrfs = |args: &[&str]| {
        Cmd::new("btrfs")
            .arg("subvolume")
            .args(args.iter().copied())
    };
    let mut fake = FakeRunner::new();
    fake.emulate_subvolumes();
    fake.run(&btrfs(&["create", &path("@usr-cand")])).unwrap();
    fake.run(&btrfs(&["snapshot", &path("@blank"), &path("@root-cand")]))
        .unwrap();
    assert!(top.join("@usr-cand").is_dir());
    assert!(top.join("@root-cand").is_dir());
    fake.run(&btrfs(&["delete", "--recursive", &path("@usr-cand")]))
        .unwrap();
    assert!(!top.join("@usr-cand").exists());
    fake.fail_on(&["btrfs", "subvolume", "snapshot"]);
    fake.run(&btrfs(&["snapshot", &path("@blank"), &path("@etc-cand")]))
        .unwrap();
    assert!(
        !top.join("@etc-cand").exists(),
        "a failed command has no effect"
    );
}

#[test]
fn subvolume_emulation_fails_like_btrfs_on_an_existing_destination() {
    let dir = tempfile::tempdir().unwrap();
    let dst = dir.path().join("@usr-cand");
    fs::create_dir(&dst).unwrap();
    let mut fake = FakeRunner::new();
    fake.emulate_subvolumes();
    for args in [vec!["create"], vec!["snapshot", "/top/@blank"]] {
        let cmd = Cmd::new("btrfs").arg("subvolume").args(args).arg_path(&dst);
        let err = fake.run(&cmd).unwrap_err();
        assert!(err.to_string().starts_with(&dst.display().to_string()));
    }
}

#[test]
fn subvolume_emulation_deletes_through_a_symlink_like_btrfs_progs() {
    // btrfs-progs resolves the path with realpath(3), so a symlink at PATH deletes its
    // target; the fake does the same, so a missing check in aios shows up as data loss.
    let dir = tempfile::tempdir().unwrap();
    let top = dir.path();
    fs::create_dir(top.join("@home")).unwrap();
    std::os::unix::fs::symlink("@home", top.join("@root-cand")).unwrap();
    let mut fake = FakeRunner::new();
    fake.emulate_subvolumes();
    let delete = Cmd::new("btrfs")
        .args(["subvolume", "delete", "--recursive"])
        .arg_path(top.join("@root-cand"));
    fake.run(&delete).unwrap();
    assert!(!top.join("@home").exists());
}

#[test]
fn subvolume_emulation_counts_directories_as_subvolume_roots() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("file"), "x").unwrap();
    let meta = |name: &str| fs::symlink_metadata(dir.path().join(name)).unwrap();
    let real = FakeRunner::new();
    assert!(!real.is_subvolume_root(&meta(".")), "real check: inode 256");
    assert!(!RealRunner.is_subvolume_root(&meta(".")));
    let mut fake = FakeRunner::new();
    fake.emulate_subvolumes();
    assert!(fake.is_subvolume_root(&meta(".")));
    assert!(!fake.is_subvolume_root(&meta("file")));
}

#[test]
fn the_fake_records_a_directory_sync_as_an_fsync_call() {
    let mut fake = FakeRunner::new();
    fake.sync_dir(std::path::Path::new("/efi/EFI/Linux"))
        .unwrap();
    assert_eq!(fake.calls(), ["fsync /efi/EFI/Linux"]);
    fake.fail_on(&["fsync"]);
    let err = fake
        .sync_dir(std::path::Path::new("/efi/EFI/Linux"))
        .unwrap_err();
    assert_eq!(err.to_string(), "/efi/EFI/Linux: fsync: injected failure");
}

#[test]
fn the_real_runner_fsyncs_a_directory() {
    let dir = tempfile::tempdir().unwrap();
    RealRunner.sync_dir(dir.path()).unwrap();
    let missing = dir.path().join("missing");
    let err = RealRunner.sync_dir(&missing).unwrap_err();
    assert_eq!(
        err.to_string(),
        format!(
            "{}: fsync: No such file or directory (os error 2)",
            missing.display()
        )
    );
}

fn touch_marker(argv: &[&str]) {
    fs::write(argv[1], "ran").unwrap();
}

#[test]
fn on_success_runs_an_effect_after_matching_successful_commands() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("marker");
    let mut fake = FakeRunner::new();
    fake.on_success(&["touch"], touch_marker);
    fake.fail_on(&["touch", "/never"]);
    fake.run(&Cmd::new("touch").arg("/never")).unwrap();
    fake.run(&Cmd::new("other").arg_path(&marker)).unwrap();
    assert!(
        !marker.exists(),
        "failed or unmatched commands have no effect"
    );
    fake.run(&Cmd::new("touch").arg_path(&marker)).unwrap();
    assert_eq!(fs::read_to_string(&marker).unwrap(), "ran");
}

/// The top level appears at the mount point: its entries are the real directories (no
/// symlinks), as a mount would show them.
#[test]
fn top_mount_emulation_shows_the_top_level_at_the_mount_point() {
    let dir = tempfile::tempdir().unwrap();
    let (top, ro) = (dir.path().join("top"), dir.path().join("ro.1"));
    fs::create_dir_all(top.join("@etc-gen-0007")).unwrap();
    fs::create_dir_all(&ro).unwrap();
    let mut fake = FakeRunner::new();
    fake.emulate_top_mounts(&top);
    let mount = |dst: &std::path::Path| {
        Cmd::new("mount")
            .args(["-t", "btrfs", "-o", "subvolid=5,ro", "/dev/mapper/aios"])
            .arg_path(dst)
    };
    fake.run(&mount(&ro)).unwrap();
    let entry = fs::symlink_metadata(ro.join("@etc-gen-0007")).unwrap();
    assert!(entry.is_dir(), "a directory, not a symlink: {entry:?}");
    fake.run(&Cmd::new("umount").arg_path(&ro)).unwrap();
    assert!(
        fs::symlink_metadata(&ro).unwrap().is_dir(),
        "the mount point is back"
    );
    assert_eq!(fs::read_dir(&ro).unwrap().count(), 0);
    assert!(
        top.join("@etc-gen-0007").is_dir(),
        "the top level is untouched"
    );
    fake.run(&mount(&top)).unwrap();
    fake.run(&Cmd::new("umount").arg_path(&top)).unwrap();
    assert!(
        top.join("@etc-gen-0007").is_dir(),
        "mounting at top itself is a no-op"
    );
}

#[test]
fn real_runner_reports_a_program_it_cannot_start() {
    let err = RealRunner
        .run(&Cmd::new("/nonexistent/aios-test-program"))
        .unwrap_err();
    assert!(
        err.to_string()
            .starts_with("cannot run `/nonexistent/aios-test-program`: "),
        "got {err}"
    );
}

#[test]
fn real_runner_passes_only_path_lc_all_and_term() {
    let out = run_ok(&RealRunner, &Cmd::new("env")).unwrap();
    let mut vars: Vec<String> = out.stdout_text().lines().map(str::to_string).collect();
    vars.sort();
    let mut expected = vec!["LC_ALL=C".to_string(), "PATH=/usr/bin".to_string()];
    if let Some(term) = std::env::var_os("TERM") {
        expected.push(format!("TERM={}", term.to_string_lossy()));
    }
    assert_eq!(vars, expected);
}

#[test]
fn real_runner_adds_the_command_env_after_clearing() {
    let cmd = Cmd::new("env")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("LC_ALL", "C.UTF-8");
    let out = run_ok(&RealRunner, &cmd).unwrap();
    let vars: Vec<&str> = out
        .stdout
        .split(|b| *b == b'\n')
        .map(|l| std::str::from_utf8(l).unwrap())
        .collect();
    assert!(vars.contains(&"GIT_CONFIG_GLOBAL=/dev/null"), "{vars:?}");
    assert!(
        vars.contains(&"LC_ALL=C.UTF-8"),
        "the command's value wins: {vars:?}"
    );
    assert!(!vars.contains(&"LC_ALL=C"), "{vars:?}");
    assert!(vars.contains(&"PATH=/usr/bin"), "{vars:?}");
}

#[test]
fn display_shows_env_assignments_as_a_prefix() {
    let cmd = Cmd::new("git")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("NAME", "a b")
        .env("X", "a\nb")
        .args(["status", "--porcelain"]);
    assert_eq!(
        cmd.to_string(),
        "GIT_CONFIG_NOSYSTEM=1 NAME='a b' X=\"a\\nb\" git status --porcelain"
    );
    assert_eq!(
        cmd.argv().collect::<Vec<_>>(),
        ["git", "status", "--porcelain"],
        "the env is not part of argv"
    );
}

#[test]
fn the_fake_matches_argv_and_logs_the_env_prefix() {
    let mut fake = FakeRunner::new();
    fake.respond(&["git", "status"], Output::ok("dirty\n"));
    let cmd = Cmd::new("git")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .arg("status");
    assert_eq!(fake.run(&cmd).unwrap().stdout_text(), "dirty\n");
    assert_eq!(fake.calls(), ["GIT_CONFIG_GLOBAL=/dev/null git status"]);
    assert_eq!(
        fake.commands()[0].env,
        [("GIT_CONFIG_GLOBAL".to_string(), "/dev/null".to_string())]
    );
}

#[test]
fn real_runner_children_read_dev_null_by_default() {
    let cmd = Cmd::new("sh").args(["-c", "readlink /proc/self/fd/0"]);
    assert_eq!(
        run_ok(&RealRunner, &cmd).unwrap().stdout_text(),
        "/dev/null\n"
    );
}

#[test]
fn interactive_commands_inherit_all_three_streams() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("fds");
    // Read each inherited fd and write the result through fd 3, so the log
    // redirection never touches fds 0/1/2 while we read them. `readlink` runs
    // in a command substitution, so its own stdout is a capture pipe, but
    // `/proc/$$/fd/N` still refers to this shell's inherited streams. (A plain
    // `readlink ... >> log` makes fd 1 read back as the log under dash, where
    // `sh` is not bash.)
    let script = format!(
        "exec 3>> '{}'; for fd in 0 1 2; do printf '%s\\n' \"$(readlink /proc/$$/fd/$fd)\" >&3; done",
        log.display()
    );
    let cmd = Cmd::new("sh").args(["-c", &script]).interactive();
    assert!(cmd.interactive);
    let out = RealRunner.run(&cmd).unwrap();
    assert_eq!(out, Output::default(), "nothing is captured");
    let ours: Vec<String> = (0..3)
        .map(|fd| {
            let link = fs::read_link(format!("/proc/self/fd/{fd}")).unwrap();
            format!("{}\n", link.display())
        })
        .collect();
    assert_eq!(fs::read_to_string(&log).unwrap(), ours.concat());
}

#[test]
fn large_stdin_does_not_deadlock() {
    let input: Vec<u8> = (0..4 << 20).map(|i: u32| b'a' + (i % 26) as u8).collect();
    let out = run_ok(&RealRunner, &Cmd::new("cat").stdin(input.clone())).unwrap();
    assert!(out.stdout == input, "cat echoed {} bytes", out.stdout.len());
}

#[test]
fn a_child_that_ignores_its_stdin_is_judged_by_its_status() {
    let cmd = Cmd::new("true").stdin(vec![b'x'; 1 << 20]);
    assert_eq!(RealRunner.run(&cmd).unwrap().status, 0);
}

#[test]
fn a_signal_death_is_reported_as_such() {
    let cmd = Cmd::new("sh").args(["-c", "kill -9 $$"]);
    let out = RealRunner.run(&cmd).unwrap();
    assert_eq!(out.signal, Some(9));
    assert_ne!(out.status, 0);
    assert_eq!(
        run_ok(&RealRunner, &cmd).unwrap_err().to_string(),
        "`sh -c 'kill -9 $$'` killed by signal 9"
    );
}

#[test]
fn status_error_names_the_signal() {
    let out = Output {
        status: -1,
        signal: Some(15),
        stderr: b"Terminated\n".to_vec(),
        ..Output::default()
    };
    assert_eq!(
        aios_exec::status_error(&Cmd::new("pacman"), &out).to_string(),
        "`pacman` killed by signal 15: Terminated"
    );
}

#[test]
fn stderr_tail_lines_are_capped_and_escaped() {
    let long = "x".repeat(1000);
    let stderr = format!("first\n\x1b[31mred\x1b[0m\rfake: ok\n{long}\n");
    let mut fake = FakeRunner::new();
    fake.respond(&["pacman"], Output::failed(1, stderr));
    let err = run_ok(&fake, &Cmd::new("pacman")).unwrap_err().to_string();
    let expected = format!(
        "`pacman` exited with status 1: first; \\u{{1b}}[31mred\\u{{1b}}[0m\\rfake: ok; {}…",
        "x".repeat(300)
    );
    assert_eq!(err, expected);
}

#[test]
fn the_stdout_tail_stands_in_for_an_empty_stderr() {
    let mut fake = FakeRunner::new();
    fake.respond(
        &["pacman"],
        Output {
            status: 1,
            stdout: b"resolving dependencies...\nerror: target not found: tree\n".to_vec(),
            ..Output::default()
        },
    );
    assert_eq!(
        run_ok(&fake, &Cmd::new("pacman")).unwrap_err().to_string(),
        "`pacman` exited with status 1: resolving dependencies...; error: target not found: tree"
    );
}

#[test]
fn debug_redacts_stdin() {
    let cmd = Cmd::new("mkpasswd").arg("-s").stdin("hunter2\n");
    let debug = format!("{cmd:?}");
    assert!(!debug.contains("hunter2"), "{debug}");
    assert_eq!(
        debug,
        "Cmd { program: \"mkpasswd\", args: [\"-s\"], env: [], stdin: Some(<8 bytes redacted>), \
         interactive: false }"
    );
}

#[test]
fn display_escapes_control_characters() {
    assert_eq!(Cmd::new("echo").arg("a\nb").to_string(), "echo \"a\\nb\"");
    assert_eq!(
        Cmd::new("git")
            .args(["commit", "-m", "x\r\x1b[2Jaios: ok"])
            .to_string(),
        "git commit -m \"x\\r\\u{1b}[2Jaios: ok\""
    );
    assert_eq!(
        Cmd::new("echo").arg("it's\t").to_string(),
        "echo \"it's\\t\""
    );
    assert!(!Cmd::new("x")
        .arg("\u{202e}gpj")
        .to_string()
        .contains('\u{202e}'));
}
