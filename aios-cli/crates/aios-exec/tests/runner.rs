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
