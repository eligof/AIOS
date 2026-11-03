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

#[test]
fn json_script_answers_and_logs_every_call() {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("fake.json");
    fs::write(
        &script,
        r#"{"respond": [{"argv": ["findmnt", "-no", "UUID"], "stdout": "7A1B-2C3D\n"}],
            "fail_on": [["bootctl"]]}"#,
    )
    .unwrap();
    let fake = FakeRunner::from_json_file(&script).unwrap();
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
        "findmnt -no UUID /efi\nbootctl set-default ''\n"
    );
}

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
    let script = format!(
        "for fd in 0 1 2; do readlink /proc/$$/fd/$fd >> '{}'; done",
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
        "Cmd { program: \"mkpasswd\", args: [\"-s\"], stdin: Some(<8 bytes redacted>), \
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
