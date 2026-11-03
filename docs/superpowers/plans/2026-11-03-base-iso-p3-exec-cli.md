# Base ISO — Phase 3: Executor + aios CLI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the two crates that touch the system. `aios-exec` runs every AIOS operation through a `CommandRunner` trait:
- `apply` and `bootstrap`, the step sequence of spec §4.3 with a cleanup guard;
- `rollback`, `gc`, `gen list`, `status` (boot state and `/etc` drift), `passwd`, `secureboot enroll`, `tpm enroll`;
- `plan`, the real `SystemProbe` for Phase 2's planner.

The `aios` binary crate is the clap CLI on top. It adds the root check, the flock, manifest loading, machine facts and exit codes.

**Architecture:**
- Both crates join the `aios-cli/` workspace under `crates/`.
- Every command goes through `CommandRunner`: `RealRunner` (`std::process::Command`) in production, `FakeRunner` in tests. `FakeRunner` records argv, answers from a script, injects failures, and can emulate btrfs subvolumes as plain directories.
- Every path comes from a `Layout` struct. Its production defaults come from the spec, and each path has an `AIOS_*` override, so tests point the whole machine at a tempdir.
- `apply` is a sequence of named steps over a small `Run` state. A failure after the top level is mounted unmounts the candidate tree, deletes every candidate subvolume and unmounts the top level. The CLI tests run the real binary with `AIOS_FAKE_RUNNER=<json>`.
- No test needs root, mounts anything or runs a system command.

**Tech Stack:** Rust 2021 (rustup nightly in `~/.cargo`), path dependencies on the four Phase 1/2 crates, plus new workspace dependencies:
- `serde_json` 1 (fake-runner scripts, `sbctl status --json`)
- `sha2` 0.10 (`package_set_sha256`)
- `walkdir` 2 (`/etc` drift)
- `clap` 4 with `derive`
- `rustix` 0.38 with `fs`, `process` (`flock`, `geteuid`)
- `rpassword` 7
- `tempfile` 3 (dev, already present)

**Spec:** `docs/superpowers/specs/2026-11-03-base-iso-design.md`:
- §2: layout, generation metadata
- §3: boot flow, cmdline, `bootctl set-default`
- §4.2: commands
- §4.3: apply algorithm
- §4.4: home binds
- §4.5: crate layout
- §5.1: Secure Boot and TPM
- §7: error handling

**Depends on:**
- **Phase 1** (`aios-manifest`, `aios-gen`) as merged:
  - `load`, `ValidationEnv`, `ManifestError`, `Manifest::package_set`, `FileEntry::{source, owner_or_default, group_or_default}`
  - `GenId` (`new`, `get`, `Display`, `usr_subvol`, `etc_subvol`), `parse_subvol`, `list_complete`, `next_id`, `gen_from_cmdline` (`None` on conflicting tokens), `gc_select`
  - `GenerationMeta` (`to_toml`, `from_toml`), `UkiName` (`fresh`, `parse`, `file_name`, `entry_id`, `is_bad`), `Flavor`
- **Phase 2** (`aios-render`, `aios-plan`) including the security pass (HEAD `7d3b204` or later):
  - `RenderCtx::new(gen, &luks, &esp, &hardening) -> Result<RenderCtx, String>`, `cmdline`, `home_binds`, `persist_dirs`
  - `parse_managed_list(&str) -> Result<Vec<String>, ManagedListError>`
  - `SystemProbe`, `EtcEntry`, `UnitState`, `ProbeError`, `Inputs`, `desired_etc`, `build_plan`, `Plan`, `MANAGED_FILES`, `GENERATION_TOML`

  The Phase 2 "Contracts for Phase 3" are honored. The coordinator's later updates supersede contract 6 (home targets) and add an ownership check; see "Contracts for Phase 4/5".

**Environment note for every task:** Rust is installed via rustup without PATH changes. Start every shell with:
```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/eli/Development/AIOS
```
- Task 1's and Task 11's first build download the new crates from crates.io (network needed once).
- No task needs root. The user has no passwordless sudo, so never run `sudo`.
- `make check` runs fmt, clippy, the Rust tests, shellcheck, bats and `systemd-analyze verify`. If `build/tools/` is missing, `make tools` fetches the pinned shell tools.

**GateGuard note:** a local hook blocks the *first* Write/Edit of each new file, and the first Bash call, until you state some facts:
- callers/importers
- that no existing file serves the purpose
- data schema if any
- the user's instruction

Answer briefly in text and retry the same call. A second gate fires on any Bash command containing `rm -rf` (or other destructive words, even inside a heredoc). For that one, list the files the command modifies or deletes, give a one-line rollback, and quote the instruction, then retry. The user's instruction is: "finish this project, use skills and subagents".

**Verified while writing this plan:** the whole plan was replayed from this document's text alone on top of HEAD `e0ec8fa` (Phase 2 with its security pass, Phase 4 merged):
- Each task's files were extracted in order.
- Each "fail" step was run and failed as stated.
- Each "pass" step was run and passed with the stated counts.
- Each task ran `make check`, including shellcheck, bats and `systemd-analyze verify`, and committed.

If an expected output differs, that is a real difference in your environment. Investigate it (superpowers:systematic-debugging) instead of editing a test until it passes.

**Conventions for this phase:**
- Tests are integration tests in each crate's `tests/` directory (public API only), one file per area. `aios-exec/tests/common/mod.rs` starts with `#![allow(dead_code)]` because each test binary uses a different subset.
- Golden argv sequences are inline strings. Paths are written as placeholders (`{top}`, `{cand}`, `{config}`, `{persist}`, `{log}`, `{home}`, `{esp}`, `{run}`) and `{set}` stands for the package set, so the goldens don't depend on the tempdir.
- Expected counts are per test binary. `cargo test -p <crate> --test <name>` prints exactly one `test result:` line for that binary.
- Every code block is rustfmt-clean as written. If `cargo fmt --all -- --check` still reports a diff, run `cargo fmt --all` and continue; formatting never changes behavior.
- Steps log `aios: <step>` lines to stderr. The test harness captures them, and they appear only for failing tests.
- Some files grow over several tasks (`lib.rs`, `apply/mod.rs`, `ops/mod.rs`, the workspace `Cargo.toml`). Each task shows the full new content.

---

## File Structure

```
aios-cli/Cargo.toml                                  workspace: + aios-exec, aios; new workspace deps
aios-cli/Cargo.lock                                  committed (new crates)
aios-cli/crates/aios-exec/Cargo.toml
aios-cli/crates/aios-exec/src/lib.rs                 module list + re-exports
aios-cli/crates/aios-exec/src/error.rs               ExecError
aios-cli/crates/aios-exec/src/runner.rs              Cmd, Output, CommandRunner, run_ok, status_error, RealRunner, FakeRunner
aios-cli/crates/aios-exec/src/layout.rs              Layout (paths + AIOS_* overrides)
aios-cli/crates/aios-exec/src/sys.rs                 cmdline/efivar/df parsing, dates, sha256, unit names
aios-cli/crates/aios-exec/src/btrfs.rs               subvolume and mount commands
aios-cli/crates/aios-exec/src/probe.rs               DirProbe (the real SystemProbe), unit-state mapping
aios-cli/crates/aios-exec/src/steps.rs               Step, StepError
aios-cli/crates/aios-exec/src/facts.rs               MachineFacts, read_hashes
aios-cli/crates/aios-exec/src/trust.rs               check_trusted_dirs (manifest repo + secrets ownership)
aios-cli/crates/aios-exec/src/etcfs.rs               symlink-safe writes into a candidate /etc
aios-cli/crates/aios-exec/src/apply/mod.rs           ApplyCtx, Mode, ApplyOutcome, apply(), step runner, cleanup guard
aios-cli/crates/aios-exec/src/apply/prepare.rs       mount-top, validate, commit-manifest, prepare-candidate, assemble
aios-cli/crates/aios-exec/src/apply/packages.rs      packages (pacman -Syu / pacstrap), keyring
aios-cli/crates/aios-exec/src/apply/etc.rs           render-etc: desired /etc, generation.toml, locale-gen, owners, persist and home dirs
aios-cli/crates/aios-exec/src/apply/services.rs      services
aios-cli/crates/aios-exec/src/apply/uki.rs           uki, sign, esp-space
aios-cli/crates/aios-exec/src/apply/finalize.rs      finalize
aios-cli/crates/aios-exec/src/ops/mod.rs             module list, with_top
aios-cli/crates/aios-exec/src/ops/boot.rs            BootState, EspUki, read_ukis
aios-cli/crates/aios-exec/src/ops/rollback.rs        rollback
aios-cli/crates/aios-exec/src/ops/gc.rs              gc, gc_mounted
aios-cli/crates/aios-exec/src/ops/gens.rs            gen_list, gen_rows, render_gen_list, GenRow
aios-cli/crates/aios-exec/src/ops/status.rs          status, drift, Status, Drift
aios-cli/crates/aios-exec/src/ops/keys.rs            secureboot_enroll, tpm_enroll
aios-cli/crates/aios-exec/src/ops/passwd.rs          passwd
aios-cli/crates/aios-exec/src/ops/plan.rs            plan
aios-cli/crates/aios-exec/tests/common/mod.rs        Fixture: a machine in a tempdir + scripted FakeRunner
aios-cli/crates/aios-exec/tests/runner.rs            10 tests
aios-cli/crates/aios-exec/tests/layout.rs            5
aios-cli/crates/aios-exec/tests/sys.rs               8
aios-cli/crates/aios-exec/tests/btrfs.rs             7
aios-cli/crates/aios-exec/tests/probe.rs             10
aios-cli/crates/aios-exec/tests/steps.rs             2
aios-cli/crates/aios-exec/tests/apply_prepare.rs     14
aios-cli/crates/aios-exec/tests/etcfs.rs             7
aios-cli/crates/aios-exec/tests/apply_build.rs       18
aios-cli/crates/aios-exec/tests/boot.rs              8
aios-cli/crates/aios-exec/tests/apply_golden.rs      11
aios-cli/crates/aios-exec/tests/inspect.rs           8
aios-cli/crates/aios-exec/tests/security.rs          6
aios-cli/crates/aios-exec/tests/passwd.rs            4
aios-cli/crates/aios-exec/tests/plan.rs              5
aios-cli/crates/aios/Cargo.toml                      bin "aios"
aios-cli/crates/aios/src/main.rs                     parse, dispatch, exit codes
aios-cli/crates/aios/src/cli.rs                      clap types
aios-cli/crates/aios/src/context.rs                  Context: layout, runner, root check, manifest, facts
aios-cli/crates/aios/src/failure.rs                  Failure (message + exit code)
aios-cli/crates/aios/src/lock.rs                     flock on /run/aios.lock
aios-cli/crates/aios/src/commands.rs                 one function per command
aios-cli/crates/aios/tests/cli.rs                    9 tests
```

---
### Task 1: Scaffold `aios-exec`, the command runner and the fake runner

**Files:**
- Modify: `aios-cli/Cargo.toml`
- Create: `aios-cli/crates/aios-exec/Cargo.toml`, `src/lib.rs`, `src/error.rs`, `src/runner.rs`
- Test: `aios-cli/crates/aios-exec/tests/runner.rs`

`FakeRunner` is the test double every later task relies on:
- It records every `Cmd`. `calls()` gives their `Display` forms and `commands()` the `Cmd`s themselves, including stdin.
- Scripted answers: `respond(prefix, Output)` matches whole argv words, and the longest prefix wins. Between equal prefixes the later entry wins, so `fail_on` can override a `respond`.
- Unscripted commands succeed with empty output.
- `emulate_subvolumes()` turns a successful `btrfs subvolume create|snapshot` into a `mkdir` of the destination, and `delete --recursive` into removing it. Tests can then check what exists afterwards.
- `from_json_file` is the CLI's `AIOS_FAKE_RUNNER` hook. It appends every call to `<json>.calls`.

`RealRunner` inherits stdin unless the command brings bytes, so `systemd-cryptenroll` can still prompt on the terminal. Its only test runs a program that doesn't exist; no test runs a real command.

- [ ] **Step 1: Check the baseline**

Run: `make check`
Expected: passes. Then run `grep -c "pub fn new" aios-cli/crates/aios-render/src/ctx.rs`, which must print `1`. If it prints `0`, Phase 2's security pass (`RenderCtx::new`) is missing: stop and report BLOCKED.

- [ ] **Step 2: Add the crate to the workspace**

`aios-cli/Cargo.toml`:
```toml
[workspace]
resolver = "2"
members = [
    "crates/aios-manifest",
    "crates/aios-gen",
    "crates/aios-render",
    "crates/aios-plan",
    "crates/aios-exec",
]

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "GPL-3.0-or-later"
publish = false

[workspace.dependencies]
serde = { version = "1", features = ["derive"] }
toml = "0.8"
tempfile = "3"
serde_json = "1"
sha2 = "0.10"
walkdir = "2"
```

`aios-cli/crates/aios-exec/Cargo.toml`:
```toml
[package]
name = "aios-exec"
description = "Run AIOS operations against the system: apply, bootstrap, rollback, gc, status"
version.workspace = true
edition.workspace = true
license.workspace = true
publish.workspace = true

[dependencies]
aios-gen = { path = "../aios-gen" }
aios-manifest = { path = "../aios-manifest" }
aios-plan = { path = "../aios-plan" }
aios-render = { path = "../aios-render" }
serde.workspace = true
serde_json.workspace = true
sha2.workspace = true
walkdir.workspace = true

[dev-dependencies]
tempfile.workspace = true
```

`aios-cli/crates/aios-exec/src/lib.rs`:
```rust
//! Everything `aios` does to the running system, behind `CommandRunner`.
```

- [ ] **Step 3: Write the failing tests**

`aios-cli/crates/aios-exec/tests/runner.rs`:
```rust
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
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `cd aios-cli && cargo test -p aios-exec --test runner`
Expected: compile error `error[E0432]: unresolved imports aios_exec::run_ok, aios_exec::Cmd, aios_exec::CommandRunner, aios_exec::FakeRunner, aios_exec::Output, aios_exec::RealRunner`.

- [ ] **Step 5: Implement `error.rs` and `runner.rs`**

`aios-cli/crates/aios-exec/src/error.rs`:
```rust
use std::fmt;
use std::path::Path;

/// A failed system operation: a command, a file access or a precondition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecError(pub String);

impl ExecError {
    pub fn new(message: impl Into<String>) -> ExecError {
        ExecError(message.into())
    }

    /// `<path>: <error>`, for file system failures.
    pub fn io(path: &Path, err: impl fmt::Display) -> ExecError {
        ExecError(format!("{}: {err}", path.display()))
    }
}

impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ExecError {}
```

`aios-cli/crates/aios-exec/src/runner.rs`:
```rust
use crate::ExecError;
use serde::Deserialize;
use std::cell::RefCell;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// One command line. `stdin`, when set, is written to the child's standard input. It is
/// never part of `Display`, because it may hold a password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cmd {
    pub program: String,
    pub args: Vec<String>,
    pub stdin: Option<Vec<u8>>,
}

impl Cmd {
    pub fn new(program: impl Into<String>) -> Cmd {
        Cmd {
            program: program.into(),
            args: Vec::new(),
            stdin: None,
        }
    }

    pub fn arg(mut self, arg: impl Into<String>) -> Cmd {
        self.args.push(arg.into());
        self
    }

    pub fn args<I, S>(mut self, args: I) -> Cmd
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// A path argument (AIOS paths are ASCII; others are converted lossily).
    pub fn arg_path(self, path: impl AsRef<Path>) -> Cmd {
        self.arg(path.as_ref().display().to_string())
    }

    pub fn stdin(mut self, bytes: impl Into<Vec<u8>>) -> Cmd {
        self.stdin = Some(bytes.into());
        self
    }

    /// The program followed by its arguments.
    pub fn argv(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.program.as_str()).chain(self.args.iter().map(String::as_str))
    }
}

impl fmt::Display for Cmd {
    /// Shell-like: words outside `[A-Za-z0-9@%+=:,./_-]` are single-quoted.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let words: Vec<String> = self.argv().map(quote).collect();
        f.write_str(&words.join(" "))
    }
}

fn quote(word: &str) -> String {
    let safe = !word.is_empty()
        && word
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"@%+=:,./_-".contains(&b));
    if safe {
        word.to_string()
    } else {
        format!("'{}'", word.replace('\'', "'\\''"))
    }
}

/// What a finished command produced.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Output {
    pub status: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl Output {
    /// Exit status 0 with this standard output.
    pub fn ok(stdout: impl Into<Vec<u8>>) -> Output {
        Output {
            status: 0,
            stdout: stdout.into(),
            stderr: Vec::new(),
        }
    }

    /// A non-zero exit status with this standard error.
    pub fn failed(status: i32, stderr: impl Into<Vec<u8>>) -> Output {
        Output {
            status,
            stdout: Vec::new(),
            stderr: stderr.into(),
        }
    }

    pub fn stdout_text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    pub fn stderr_text(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
}

/// Every system command aios runs goes through this trait.
pub trait CommandRunner {
    /// Run `cmd` to completion. `Err` only when it could not be started: a non-zero exit is
    /// an `Ok` carrying that status.
    fn run(&self, cmd: &Cmd) -> Result<Output, ExecError>;
}

/// Run `cmd` and turn a non-zero exit into an error naming the command and the last
/// lines of its standard error.
pub fn run_ok(runner: &dyn CommandRunner, cmd: &Cmd) -> Result<Output, ExecError> {
    let out = runner.run(cmd)?;
    if out.status == 0 {
        Ok(out)
    } else {
        Err(status_error(cmd, &out))
    }
}

/// The error `run_ok` reports for a command that exited with `out.status`.
pub fn status_error(cmd: &Cmd, out: &Output) -> ExecError {
    let text = out.stderr_text();
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let tail = lines[lines.len().saturating_sub(3)..].join("; ");
    if tail.is_empty() {
        ExecError(format!("`{cmd}` exited with status {}", out.status))
    } else {
        ExecError(format!("`{cmd}` exited with status {}: {tail}", out.status))
    }
}

/// Runs commands with `std::process::Command`, capturing stdout and stderr. Standard input
/// is inherited unless the command supplies bytes, so interactive tools such as
/// `systemd-cryptenroll` can still prompt on the terminal.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealRunner;

impl CommandRunner for RealRunner {
    fn run(&self, cmd: &Cmd) -> Result<Output, ExecError> {
        let fail = |e: std::io::Error| ExecError(format!("cannot run `{cmd}`: {e}"));
        let mut child = Command::new(&cmd.program)
            .args(&cmd.args)
            .stdin(if cmd.stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::inherit()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(fail)?;
        if let (Some(bytes), Some(mut pipe)) = (&cmd.stdin, child.stdin.take()) {
            // A child that exits without reading its input is reported by its status.
            if let Err(e) = pipe.write_all(bytes) {
                if e.kind() != ErrorKind::BrokenPipe {
                    return Err(fail(e));
                }
            }
        }
        let out = child.wait_with_output().map_err(fail)?;
        Ok(Output {
            status: out.status.code().unwrap_or(-1),
            stdout: out.stdout,
            stderr: out.stderr,
        })
    }
}

/// Test double: records every command and answers from a script. Unscripted commands
/// succeed with empty output.
#[derive(Debug, Default)]
pub struct FakeRunner {
    calls: RefCell<Vec<Cmd>>,
    script: Vec<(Vec<String>, Output)>,
    call_log: Option<PathBuf>,
    emulate_subvolumes: bool,
}

/// `AIOS_FAKE_RUNNER` file format.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Script {
    #[serde(default)]
    respond: Vec<Scripted>,
    #[serde(default)]
    fail_on: Vec<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Scripted {
    argv: Vec<String>,
    #[serde(default)]
    status: i32,
    #[serde(default)]
    stdout: String,
    #[serde(default)]
    stderr: String,
}

impl FakeRunner {
    pub fn new() -> FakeRunner {
        FakeRunner::default()
    }

    /// Answer every command whose argv starts with `prefix` (whole words). The longest
    /// matching prefix wins; between equal lengths, the later entry wins.
    pub fn respond(&mut self, prefix: &[&str], output: Output) -> &mut FakeRunner {
        let prefix = prefix.iter().map(|w| w.to_string()).collect();
        self.script.push((prefix, output));
        self
    }

    /// Commands starting with `prefix` exit 1 with `injected failure` on stderr.
    pub fn fail_on(&mut self, prefix: &[&str]) -> &mut FakeRunner {
        self.respond(prefix, Output::failed(1, "injected failure"))
    }

    /// Treat plain directories as subvolumes: a successful `btrfs subvolume create DST` or
    /// `snapshot SRC DST` creates the directory DST (empty), and `delete --recursive PATH`
    /// removes PATH.
    pub fn emulate_subvolumes(&mut self) -> &mut FakeRunner {
        self.emulate_subvolumes = true;
        self
    }

    /// Every command run so far, in `Display` form.
    pub fn calls(&self) -> Vec<String> {
        self.calls.borrow().iter().map(Cmd::to_string).collect()
    }

    /// Every command run so far, including any stdin.
    pub fn commands(&self) -> Vec<Cmd> {
        self.calls.borrow().clone()
    }

    /// Load a script (`{"respond": [{"argv": [..], "status": 0, "stdout": "", "stderr": ""}],
    /// "fail_on": [[..]]}`) and append each call to `<path>.calls`, one line per call.
    pub fn from_json_file(path: &Path) -> Result<FakeRunner, ExecError> {
        let text = fs::read_to_string(path).map_err(|e| ExecError::io(path, e))?;
        let script: Script = serde_json::from_str(&text).map_err(|e| ExecError::io(path, e))?;
        let mut fake = FakeRunner::new();
        for entry in script.respond {
            let argv: Vec<&str> = entry.argv.iter().map(String::as_str).collect();
            fake.respond(
                &argv,
                Output {
                    status: entry.status,
                    stdout: entry.stdout.into_bytes(),
                    stderr: entry.stderr.into_bytes(),
                },
            );
        }
        for prefix in &script.fail_on {
            let argv: Vec<&str> = prefix.iter().map(String::as_str).collect();
            fake.fail_on(&argv);
        }
        let mut log = path.as_os_str().to_owned();
        log.push(".calls");
        fake.call_log = Some(PathBuf::from(log));
        Ok(fake)
    }

    fn emulate(&self, argv: &[&str]) -> Result<(), ExecError> {
        match argv {
            ["btrfs", "subvolume", "create", dst] | ["btrfs", "subvolume", "snapshot", _, dst] => {
                fs::create_dir_all(dst).map_err(|e| ExecError::io(Path::new(dst), e))
            }
            ["btrfs", "subvolume", "delete", "--recursive", path] if Path::new(path).exists() => {
                fs::remove_dir_all(path).map_err(|e| ExecError::io(Path::new(path), e))
            }
            _ => Ok(()),
        }
    }
}

impl CommandRunner for FakeRunner {
    fn run(&self, cmd: &Cmd) -> Result<Output, ExecError> {
        self.calls.borrow_mut().push(cmd.clone());
        if let Some(log) = &self.call_log {
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(log)
                .map_err(|e| ExecError::io(log, e))?;
            writeln!(file, "{cmd}").map_err(|e| ExecError::io(log, e))?;
        }
        let argv: Vec<&str> = cmd.argv().collect();
        let output = self
            .script
            .iter()
            .filter(|(prefix, _)| {
                prefix.len() <= argv.len() && prefix.iter().zip(&argv).all(|(p, a)| p == a)
            })
            .max_by_key(|(prefix, _)| prefix.len())
            .map(|(_, out)| out.clone())
            .unwrap_or_default();
        if output.status == 0 && self.emulate_subvolumes {
            self.emulate(&argv)?;
        }
        Ok(output)
    }
}
```

- [ ] **Step 6: Replace `lib.rs`**

`aios-cli/crates/aios-exec/src/lib.rs`:
```rust
//! Everything `aios` does to the running system, behind [`CommandRunner`], so every test
//! runs without root against a [`FakeRunner`] and tempdirs.

mod error;
mod runner;

pub use error::ExecError;
pub use runner::{run_ok, status_error, Cmd, CommandRunner, FakeRunner, Output, RealRunner};
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cd aios-cli && cargo test -p aios-exec --test runner`
Expected: `test result: ok. 10 passed`.

- [ ] **Step 8: Lint**

Run: `make check`
Expected: fmt and clippy print no diagnostics, and every test binary, bats file and unit check passes. If fmt complains, run `cargo fmt --all` in `aios-cli/` and re-run.

- [ ] **Step 9: Commit**

```bash
cd /home/eli/Development/AIOS
git add aios-cli/
git commit -m "feat(exec): scaffold aios-exec with the command runner and a scripted fake"
```

---
### Task 2: `Layout` and the system-text helpers

**Files:**
- Create: `aios-cli/crates/aios-exec/src/layout.rs`, `aios-cli/crates/aios-exec/src/sys.rs`
- Modify: `aios-cli/crates/aios-exec/src/lib.rs` (full content below)
- Test: `aios-cli/crates/aios-exec/tests/layout.rs`, `aios-cli/crates/aios-exec/tests/sys.rs`

Every path comes from `Layout`:
- Its defaults follow the spec, and each field has an `AIOS_*` override. Besides the spec's list, it adds `AIOS_LOG` (the `@log` bind source), `AIOS_LIVE_ETC` (drift), `AIOS_EFIVARS` and `AIOS_DEVICE`.
- `Layout::under(dir)` puts every path below one tempdir for tests.
- `from_vars` takes the variable lookup as a closure, so the tests never mutate the process environment.

The helpers in `sys.rs` are pure text and time functions:
- `rfc3339_utc` uses Howard Hinnant's `civil_from_days`, so there's no date crate.
- `luks_uuid_from_cmdline` returns `None` on conflicting tokens, like `gen_from_cmdline`.

- [ ] **Step 1: Write the failing tests**

`aios-cli/crates/aios-exec/tests/layout.rs`:
```rust
use aios_exec::Layout;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

#[test]
fn defaults_follow_the_spec() {
    let l = Layout::from_vars(|_| None);
    let expected = [
        (&l.top, "/run/aios/top"),
        (&l.cand, "/run/aios/cand"),
        (&l.esp, "/efi"),
        (&l.config, "/persist/aios/config"),
        (&l.secrets, "/persist/aios/secrets"),
        (&l.persist, "/persist"),
        (&l.home, "/home"),
        (&l.log, "/var/log"),
        (&l.live_etc, "/etc"),
        (&l.proc_cmdline, "/proc/cmdline"),
        (&l.efivars, "/sys/firmware/efi/efivars"),
        (&l.lock, "/run/aios.lock"),
        (&l.device, "/dev/mapper/aios"),
    ];
    for (field, path) in expected {
        assert_eq!(field, Path::new(path));
    }
}

#[test]
fn every_path_has_an_env_override() {
    let names = [
        "AIOS_TOP",
        "AIOS_CAND",
        "AIOS_ESP",
        "AIOS_CONFIG",
        "AIOS_SECRETS",
        "AIOS_PERSIST",
        "AIOS_HOME",
        "AIOS_LOG",
        "AIOS_LIVE_ETC",
        "AIOS_CMDLINE",
        "AIOS_EFIVARS",
        "AIOS_LOCK",
        "AIOS_DEVICE",
    ];
    let vars: BTreeMap<&str, OsString> = names
        .iter()
        .map(|n| (*n, OsString::from(format!("/t/{n}"))))
        .collect();
    let l = Layout::from_vars(|name| vars.get(name).cloned());
    let fields = [
        &l.top,
        &l.cand,
        &l.esp,
        &l.config,
        &l.secrets,
        &l.persist,
        &l.home,
        &l.log,
        &l.live_etc,
        &l.proc_cmdline,
        &l.efivars,
        &l.lock,
        &l.device,
    ];
    for (name, field) in names.iter().zip(fields) {
        assert_eq!(field, &PathBuf::from(format!("/t/{name}")));
    }
}

#[test]
fn under_puts_everything_below_one_root() {
    let l = Layout::under(Path::new("/tmp/x"));
    assert_eq!(l.top, Path::new("/tmp/x/top"));
    assert_eq!(l.live_etc, Path::new("/tmp/x/live-etc"));
    assert_eq!(l.proc_cmdline, Path::new("/tmp/x/cmdline"));
    assert_eq!(l.lock, Path::new("/tmp/x/aios.lock"));
    assert_eq!(l.device, Path::new("/dev/mapper/aios"));
}

#[test]
fn derived_paths() {
    let l = Layout::from_vars(|_| None);
    assert_eq!(
        l.manifest_path(),
        Path::new("/persist/aios/config/manifest.toml")
    );
    assert_eq!(
        l.subvol("@usr-gen-0007"),
        Path::new("/run/aios/top/@usr-gen-0007")
    );
    assert_eq!(l.uki_dir(), Path::new("/efi/EFI/Linux"));
    assert_eq!(
        l.loader_entry_default(),
        Path::new(
            "/sys/firmware/efi/efivars/LoaderEntryDefault-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"
        )
    );
    assert_eq!(l.repo(), Path::new("/persist/aios/repo"));
    assert_eq!(l.pkg_cache(), Path::new("/persist/var/cache/pacman/pkg"));
    assert_eq!(
        l.passwd_secret("eli"),
        Path::new("/persist/aios/secrets/passwd/eli")
    );
}

#[test]
fn persist_path_maps_onto_the_persist_field() {
    let l = Layout::under(Path::new("/t"));
    assert_eq!(l.persist_path("/persist"), Path::new("/t/persist/"));
    assert_eq!(
        l.persist_path("/persist/var/lib/NetworkManager"),
        Path::new("/t/persist/var/lib/NetworkManager")
    );
}
```

`aios-cli/crates/aios-exec/tests/sys.rs`:
```rust
use aios_exec::{
    days_since_epoch, luks_uuid_from_cmdline, parse_df_avail, parse_efivar_utf16, rfc3339_utc,
    sha256_hex, unit_file_name,
};
use std::time::{Duration, UNIX_EPOCH};

const UUID: &str = "0b6c2e7f-5d0a-4c2e-9a71-3f1d2c4b5a69";

#[test]
fn luks_uuid_comes_from_rd_luks_name() {
    let cmdline = format!("rd.luks.name={UUID}=aios root=/dev/mapper/aios quiet");
    assert_eq!(luks_uuid_from_cmdline(&cmdline).as_deref(), Some(UUID));
    let other = format!("rd.luks.name=1111=swap rd.luks.name={UUID}=aios");
    assert_eq!(luks_uuid_from_cmdline(&other).as_deref(), Some(UUID));
    assert_eq!(luks_uuid_from_cmdline("root=/dev/sda2 quiet"), None);
    assert_eq!(luks_uuid_from_cmdline("rd.luks.name==aios"), None);
}

#[test]
fn conflicting_luks_tokens_are_none() {
    let same = format!("rd.luks.name={UUID}=aios rd.luks.name={UUID}=aios");
    assert_eq!(luks_uuid_from_cmdline(&same).as_deref(), Some(UUID));
    let conflict = format!("rd.luks.name={UUID}=aios rd.luks.name=2222=aios");
    assert_eq!(luks_uuid_from_cmdline(&conflict), None);
}

#[test]
fn days_and_timestamps_in_utc() {
    let t = UNIX_EPOCH + Duration::from_secs(1_793_740_445);
    assert_eq!(days_since_epoch(t), 20760);
    assert_eq!(rfc3339_utc(t), "2026-11-03T21:14:05Z");
    assert_eq!(rfc3339_utc(UNIX_EPOCH), "1970-01-01T00:00:00Z");
    assert_eq!(days_since_epoch(UNIX_EPOCH - Duration::from_secs(5)), 0);
}

#[test]
fn calendar_edges() {
    let at = |secs: u64| rfc3339_utc(UNIX_EPOCH + Duration::from_secs(secs));
    assert_eq!(at(951_782_400), "2000-02-29T00:00:00Z");
    assert_eq!(at(1_709_251_199), "2024-02-29T23:59:59Z");
    assert_eq!(at(946_684_799), "1999-12-31T23:59:59Z");
}

#[test]
fn sha256_is_lowercase_hex() {
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn efivar_strings_skip_attributes_and_the_nul() {
    let mut bytes = vec![0x07, 0, 0, 0];
    for unit in "aios-gen-0007-cachyos.efi\0".encode_utf16() {
        bytes.extend(unit.to_le_bytes());
    }
    assert_eq!(
        parse_efivar_utf16(&bytes).as_deref(),
        Some("aios-gen-0007-cachyos.efi")
    );
    assert_eq!(parse_efivar_utf16(&[7, 0, 0]), None);
    assert_eq!(parse_efivar_utf16(&[7, 0, 0, 0, 0, 0]), None);
    assert_eq!(parse_efivar_utf16(&[7, 0, 0, 0, b'a']), None);
}

#[test]
fn df_avail_is_the_last_number() {
    assert_eq!(
        parse_df_avail("     Avail\n2040123392\n"),
        Some(2_040_123_392)
    );
    assert_eq!(parse_df_avail("Avail\n"), None);
    assert_eq!(parse_df_avail(""), None);
}

#[test]
fn unit_names_get_a_service_suffix() {
    assert_eq!(unit_file_name("NetworkManager"), "NetworkManager.service");
    assert_eq!(unit_file_name("fwupd-refresh.timer"), "fwupd-refresh.timer");
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd aios-cli && cargo test -p aios-exec --test layout --test sys`
Expected: compile errors `unresolved import aios_exec::Layout` (`layout`) and `unresolved imports aios_exec::days_since_epoch, aios_exec::luks_uuid_from_cmdline, ...` (`sys`).

- [ ] **Step 3: Implement `layout.rs` and `sys.rs`**

`aios-cli/crates/aios-exec/src/layout.rs`:
```rust
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// GUID of the systemd-boot loader interface EFI variables.
const LOADER_GUID: &str = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f";

/// Every path aios reads or writes. `from_env` lets tests point all of them at a tempdir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    /// btrfs top level (`subvolid=5`) mount point. `AIOS_TOP`, default `/run/aios/top`.
    pub top: PathBuf,
    /// Candidate root during apply/bootstrap. `AIOS_CAND`, default `/run/aios/cand`.
    pub cand: PathBuf,
    /// ESP mount point. `AIOS_ESP`, default `/efi`.
    pub esp: PathBuf,
    /// Manifest git repo. `AIOS_CONFIG`, default `/persist/aios/config`.
    pub config: PathBuf,
    /// Secrets (`passwd/<user>`). `AIOS_SECRETS`, default `/persist/aios/secrets`.
    pub secrets: PathBuf,
    /// The `@persist` subvolume. `AIOS_PERSIST`, default `/persist`.
    pub persist: PathBuf,
    /// The `@home` subvolume. `AIOS_HOME`, default `/home`.
    pub home: PathBuf,
    /// The `@log` subvolume. `AIOS_LOG`, default `/var/log`.
    pub log: PathBuf,
    /// The running system's `/etc`, for drift. `AIOS_LIVE_ETC`, default `/etc`.
    pub live_etc: PathBuf,
    /// Kernel cmdline. `AIOS_CMDLINE`, default `/proc/cmdline`.
    pub proc_cmdline: PathBuf,
    /// efivarfs. `AIOS_EFIVARS`, default `/sys/firmware/efi/efivars`.
    pub efivars: PathBuf,
    /// flock file. `AIOS_LOCK`, default `/run/aios.lock`.
    pub lock: PathBuf,
    /// Unlocked LUKS device holding btrfs. `AIOS_DEVICE`, default `/dev/mapper/aios`.
    pub device: PathBuf,
}

impl Layout {
    /// The production layout, with any `AIOS_*` override from the environment.
    pub fn from_env() -> Layout {
        Layout::from_vars(|name| std::env::var_os(name))
    }

    /// Like `from_env`, reading variables through `var`.
    pub fn from_vars(var: impl Fn(&str) -> Option<OsString>) -> Layout {
        let path = |name: &str, default: &str| var(name).map_or_else(|| default.into(), Into::into);
        Layout {
            top: path("AIOS_TOP", "/run/aios/top"),
            cand: path("AIOS_CAND", "/run/aios/cand"),
            esp: path("AIOS_ESP", "/efi"),
            config: path("AIOS_CONFIG", "/persist/aios/config"),
            secrets: path("AIOS_SECRETS", "/persist/aios/secrets"),
            persist: path("AIOS_PERSIST", "/persist"),
            home: path("AIOS_HOME", "/home"),
            log: path("AIOS_LOG", "/var/log"),
            live_etc: path("AIOS_LIVE_ETC", "/etc"),
            proc_cmdline: path("AIOS_CMDLINE", "/proc/cmdline"),
            efivars: path("AIOS_EFIVARS", "/sys/firmware/efi/efivars"),
            lock: path("AIOS_LOCK", "/run/aios.lock"),
            device: path("AIOS_DEVICE", "/dev/mapper/aios"),
        }
    }

    /// Every path below `root` (named like its field), except `device`.
    pub fn under(root: &Path) -> Layout {
        Layout {
            top: root.join("top"),
            cand: root.join("cand"),
            esp: root.join("esp"),
            config: root.join("config"),
            secrets: root.join("secrets"),
            persist: root.join("persist"),
            home: root.join("home"),
            log: root.join("log"),
            live_etc: root.join("live-etc"),
            proc_cmdline: root.join("cmdline"),
            efivars: root.join("efivars"),
            lock: root.join("aios.lock"),
            device: PathBuf::from("/dev/mapper/aios"),
        }
    }

    pub fn manifest_path(&self) -> PathBuf {
        self.config.join("manifest.toml")
    }

    /// A subvolume in the top level, e.g. `@usr-gen-0007`.
    pub fn subvol(&self, name: &str) -> PathBuf {
        self.top.join(name)
    }

    /// Where UKIs live on the ESP.
    pub fn uki_dir(&self) -> PathBuf {
        self.esp.join("EFI/Linux")
    }

    /// The `LoaderEntryDefault` EFI variable (`bootctl set-default`).
    pub fn loader_entry_default(&self) -> PathBuf {
        self.efivars
            .join(format!("LoaderEntryDefault-{LOADER_GUID}"))
    }

    /// Local pacman repo, bound into the candidate at `/persist/aios/repo`.
    pub fn repo(&self) -> PathBuf {
        self.persist.join("aios/repo")
    }

    /// Persisted pacman cache, bound into the candidate.
    pub fn pkg_cache(&self) -> PathBuf {
        self.persist.join("var/cache/pacman/pkg")
    }

    /// `secrets/passwd/<user>`.
    pub fn passwd_secret(&self, user: &str) -> PathBuf {
        self.secrets.join("passwd").join(user)
    }

    /// Map an absolute `/persist/...` path onto `persist`.
    pub fn persist_path(&self, abs: &str) -> PathBuf {
        let rel = abs.strip_prefix("/persist").unwrap_or(abs);
        self.persist.join(rel.trim_start_matches('/'))
    }
}
```

`aios-cli/crates/aios-exec/src/sys.rs`:
```rust
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// The LUKS UUID from `rd.luks.name=<uuid>=aios`. `None` if absent, empty or conflicting.
pub fn luks_uuid_from_cmdline(cmdline: &str) -> Option<String> {
    let mut found: Option<&str> = None;
    for value in cmdline
        .split_whitespace()
        .filter_map(|t| t.strip_prefix("rd.luks.name="))
    {
        match value.split_once('=') {
            Some((uuid, "aios")) if !uuid.is_empty() => match found {
                Some(prev) if prev != uuid => return None,
                _ => found = Some(uuid),
            },
            _ => {}
        }
    }
    found.map(str::to_string)
}

fn epoch_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Whole days since 1970-01-01 (UTC). Times before the epoch count as 0.
pub fn days_since_epoch(t: SystemTime) -> u64 {
    epoch_secs(t) / 86_400
}

/// `YYYY-MM-DDTHH:MM:SSZ`.
pub fn rfc3339_utc(t: SystemTime) -> String {
    let secs = epoch_secs(t);
    let (y, m, d) = civil_from_days(secs / 86_400);
    let rem = secs % 86_400;
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Days since 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's `civil_from_days`).
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + u64::from(m <= 2);
    (y, m, d)
}

/// Lowercase hex sha256.
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// An efivarfs string variable: 4 attribute bytes, then NUL-terminated UTF-16LE.
/// `None` when malformed or empty.
pub fn parse_efivar_utf16(bytes: &[u8]) -> Option<String> {
    let data = bytes.get(4..)?;
    if data.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    let text = String::from_utf16(&units).ok()?;
    let text = text.trim_end_matches('\0');
    (!text.is_empty()).then(|| text.to_string())
}

/// Free bytes from `df --output=avail -B1 <dir>`: the last non-empty line.
pub fn parse_df_avail(stdout: &str) -> Option<u64> {
    stdout
        .lines()
        .map(str::trim)
        .rev()
        .find(|l| !l.is_empty())?
        .parse()
        .ok()
}

/// `NetworkManager` -> `NetworkManager.service`. Names with a type suffix are kept.
pub fn unit_file_name(name: &str) -> String {
    if name.contains('.') {
        name.to_string()
    } else {
        format!("{name}.service")
    }
}
```

- [ ] **Step 4: Replace `lib.rs`**

`aios-cli/crates/aios-exec/src/lib.rs`:
```rust
//! Everything `aios` does to the running system, behind [`CommandRunner`], so every test
//! runs without root against a [`FakeRunner`] and tempdirs.

mod error;
mod layout;
mod runner;
mod sys;

pub use error::ExecError;
pub use layout::Layout;
pub use runner::{run_ok, status_error, Cmd, CommandRunner, FakeRunner, Output, RealRunner};
pub use sys::{
    days_since_epoch, luks_uuid_from_cmdline, parse_df_avail, parse_efivar_utf16, rfc3339_utc,
    sha256_hex, unit_file_name,
};
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd aios-cli && cargo test -p aios-exec --test layout --test sys`
Expected: `layout`: `test result: ok. 5 passed`; `sys`: `test result: ok. 8 passed`.

- [ ] **Step 6: Lint**

Run: `make check`
Expected: as in Task 1.

- [ ] **Step 7: Commit**

```bash
cd /home/eli/Development/AIOS
git add aios-cli/
git commit -m "feat(exec): Layout with AIOS_* overrides, cmdline/efivar/date helpers"
```

---
### Task 3: btrfs subvolume and mount commands

**Files:**
- Create: `aios-cli/crates/aios-exec/src/btrfs.rs`
- Modify: `aios-cli/crates/aios-exec/src/lib.rs` (full content below)
- Test: `aios-cli/crates/aios-exec/tests/btrfs.rs`

`delete_recursive` works like `delete_subvol` in `initrd/aios-root.sh` after the security pass:
- Nothing at the path is a no-op.
- Otherwise `btrfs subvolume show` must succeed; anything that isn't a subvolume is an error.
- Then `btrfs subvolume delete --recursive` lets btrfs remove the nested subvolumes systemd creates (`/var/lib/machines`, `/var/lib/portables`).
- Subvolume names are never parsed, so a nested subvolume with a crafted name can't redirect the delete.

- [ ] **Step 1: Write the failing tests**

`aios-cli/crates/aios-exec/tests/btrfs.rs`:
```rust
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd aios-cli && cargo test -p aios-exec --test btrfs`
Expected: compile error `unresolved import aios_exec::btrfs`.

- [ ] **Step 3: Implement `btrfs.rs`**

`aios-cli/crates/aios-exec/src/btrfs.rs`:
```rust
//! btrfs subvolume and mount operations, as commands through the runner.
//!
//! Whether something exists at a subvolume path is checked on the file system, so tests
//! model subvolumes as plain directories (see `FakeRunner::emulate_subvolumes`).

use crate::{run_ok, Cmd, CommandRunner, ExecError};
use std::fs;
use std::io::ErrorKind;
use std::path::Path;

fn run(runner: &dyn CommandRunner, cmd: Cmd) -> Result<(), ExecError> {
    run_ok(runner, &cmd).map(drop)
}

/// `btrfs subvolume create PATH`
pub fn create(runner: &dyn CommandRunner, path: &Path) -> Result<(), ExecError> {
    run(
        runner,
        Cmd::new("btrfs")
            .args(["subvolume", "create"])
            .arg_path(path),
    )
}

/// `btrfs subvolume snapshot SRC DST` (writable, even from a read-only source).
pub fn snapshot(runner: &dyn CommandRunner, src: &Path, dst: &Path) -> Result<(), ExecError> {
    let cmd = Cmd::new("btrfs").args(["subvolume", "snapshot"]);
    run(runner, cmd.arg_path(src).arg_path(dst))
}

/// Delete the subvolume at `path` and every subvolume nested in it, if anything exists
/// there. btrfs walks the nesting itself (`delete --recursive`), so subvolume names are never
/// parsed, as in `aios-root.sh`. Anything at `path` that is not a subvolume is an error.
pub fn delete_recursive(runner: &dyn CommandRunner, path: &Path) -> Result<(), ExecError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(ExecError::io(path, e)),
    }
    let show = Cmd::new("btrfs").args(["subvolume", "show"]).arg_path(path);
    if runner.run(&show)?.status != 0 {
        return Err(ExecError(format!(
            "{} exists but is not a subvolume",
            path.display()
        )));
    }
    let cmd = Cmd::new("btrfs").args(["subvolume", "delete", "--recursive"]);
    run(runner, cmd.arg_path(path))
}

/// `btrfs property set -ts PATH ro true`
pub fn set_readonly(runner: &dyn CommandRunner, path: &Path) -> Result<(), ExecError> {
    let cmd = Cmd::new("btrfs")
        .args(["property", "set", "-ts"])
        .arg_path(path);
    run(runner, cmd.args(["ro", "true"]))
}

/// Create `top` and mount the btrfs top level there:
/// `mount -t btrfs -o subvolid=5[,ro] DEVICE TOP`.
pub fn mount_top(
    runner: &dyn CommandRunner,
    device: &Path,
    top: &Path,
    read_only: bool,
) -> Result<(), ExecError> {
    fs::create_dir_all(top).map_err(|e| ExecError::io(top, e))?;
    let options = if read_only {
        "subvolid=5,ro"
    } else {
        "subvolid=5"
    };
    let cmd = Cmd::new("mount").args(["-t", "btrfs", "-o", options]);
    run(runner, cmd.arg_path(device).arg_path(top))
}

/// `mount --bind SRC DST`
pub fn bind(runner: &dyn CommandRunner, src: &Path, dst: &Path) -> Result<(), ExecError> {
    run(
        runner,
        Cmd::new("mount").arg("--bind").arg_path(src).arg_path(dst),
    )
}

/// `umount PATH`
pub fn umount(runner: &dyn CommandRunner, path: &Path) -> Result<(), ExecError> {
    run(runner, Cmd::new("umount").arg_path(path))
}

/// `umount -R PATH`: `PATH` and everything mounted below it.
pub fn umount_recursive(runner: &dyn CommandRunner, path: &Path) -> Result<(), ExecError> {
    run(runner, Cmd::new("umount").arg("-R").arg_path(path))
}

/// Names in the top level (subvolumes and anything else), sorted.
pub fn list_names(top: &Path) -> Result<Vec<String>, ExecError> {
    let entries = fs::read_dir(top).map_err(|e| ExecError::io(top, e))?;
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| ExecError::io(top, e))?;
        names.push(entry.file_name().to_string_lossy().into_owned());
    }
    names.sort();
    Ok(names)
}
```

- [ ] **Step 4: Replace `lib.rs`**

`aios-cli/crates/aios-exec/src/lib.rs`:
```rust
//! Everything `aios` does to the running system, behind [`CommandRunner`], so every test
//! runs without root against a [`FakeRunner`] and tempdirs.

pub mod btrfs;
mod error;
mod layout;
mod runner;
mod sys;

pub use error::ExecError;
pub use layout::Layout;
pub use runner::{run_ok, status_error, Cmd, CommandRunner, FakeRunner, Output, RealRunner};
pub use sys::{
    days_since_epoch, luks_uuid_from_cmdline, parse_df_avail, parse_efivar_utf16, rfc3339_utc,
    sha256_hex, unit_file_name,
};
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd aios-cli && cargo test -p aios-exec --test btrfs`
Expected: `test result: ok. 7 passed`.

- [ ] **Step 6: Lint**

Run: `make check`
Expected: as in Task 1.

- [ ] **Step 7: Commit**

```bash
cd /home/eli/Development/AIOS
git add aios-cli/
git commit -m "feat(exec): btrfs subvolume and mount commands"
```

---
### Task 4: The real `SystemProbe`

**Files:**
- Create: `aios-cli/crates/aios-exec/src/probe.rs`
- Modify: `aios-cli/crates/aios-exec/src/lib.rs` (full content below)
- Test: `aios-cli/crates/aios-exec/tests/probe.rs`

One type, `DirProbe`, serves both the booted generation (`top/@etc-gen-N`, for `aios plan`) and the candidate (`cand/etc`, during apply):
- `etc_entry` reads `/etc/<rel>` from `etc_root/<rel>`.
  - A symlink gives its target. A file gives its bytes and `st_mode & 0o7777`.
  - A missing path is `None`. A directory or special file is an error, as is a path outside `/etc/`.
- `explicit_packages` runs `pacman -Qqe`, or `arch-chroot ROOT pacman -Qqe` with a root.
- `unit_state` runs `systemctl [--root=ROOT] is-enabled UNIT` and maps the answer (Phase 2 contract 4):
  - `enabled` and `enabled-runtime` are `Enabled`.
  - `disabled`, `linked` and `linked-runtime` are `Disabled`.
  - `masked` and `masked-runtime` are `Masked`.
  - `static`, `indirect`, `generated`, `transient` and `alias` are `Static`.
  - `not-found`, an empty answer with exit 4, or `Failed to get unit file state` on stderr are `NotFound`.
  - `bad` and anything else are errors.

- [ ] **Step 1: Write the failing tests**

`aios-cli/crates/aios-exec/tests/probe.rs`:
```rust
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
            "systemctl is-enabled sshd.socket",
            "systemctl --root=/cand is-enabled sshd.socket",
        ]
    );
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd aios-cli && cargo test -p aios-exec --test probe`
Expected: compile error `unresolved imports aios_exec::parse_unit_state, aios_exec::read_etc_entry, aios_exec::DirProbe`.

- [ ] **Step 3: Implement `probe.rs`**

`aios-cli/crates/aios-exec/src/probe.rs`:
```rust
use crate::{run_ok, Cmd, CommandRunner, Output};
use aios_plan::{EtcEntry, ProbeError, SystemProbe, UnitState};
use std::collections::BTreeSet;
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// The real [`SystemProbe`]: a generation's `/etc` read from a directory (the booted
/// `top/@etc-gen-N` snapshot, or the candidate's `cand/etc`), packages and units through
/// the runner.
pub struct DirProbe<'a> {
    /// The directory standing in for `/etc`.
    pub etc_root: PathBuf,
    pub runner: &'a dyn CommandRunner,
    /// `None`: ask the running system (`pacman -Qqe`, `systemctl is-enabled`).
    /// `Some(root)`: ask a candidate root (`arch-chroot ROOT pacman -Qqe`,
    /// `systemctl --root=ROOT is-enabled`).
    pub root: Option<PathBuf>,
}

impl<'a> DirProbe<'a> {
    pub fn new(
        etc_root: impl Into<PathBuf>,
        runner: &'a dyn CommandRunner,
        root: Option<PathBuf>,
    ) -> DirProbe<'a> {
        DirProbe {
            etc_root: etc_root.into(),
            runner,
            root,
        }
    }
}

impl SystemProbe for DirProbe<'_> {
    fn explicit_packages(&self) -> Result<BTreeSet<String>, ProbeError> {
        let cmd = match &self.root {
            None => Cmd::new("pacman").arg("-Qqe"),
            Some(root) => Cmd::new("arch-chroot")
                .arg_path(root)
                .args(["pacman", "-Qqe"]),
        };
        let out = run_ok(self.runner, &cmd).map_err(|e| ProbeError(e.to_string()))?;
        Ok(out
            .stdout_text()
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect())
    }

    fn etc_entry(&self, path: &str) -> Result<Option<EtcEntry>, ProbeError> {
        read_etc_entry(&self.etc_root, path)
    }

    fn unit_state(&self, unit: &str) -> Result<UnitState, ProbeError> {
        let mut cmd = Cmd::new("systemctl");
        if let Some(root) = &self.root {
            cmd = cmd.arg(format!("--root={}", root.display()));
        }
        let cmd = cmd.args(["is-enabled", unit]);
        let out = self
            .runner
            .run(&cmd)
            .map_err(|e| ProbeError(e.to_string()))?;
        parse_unit_state(unit, &out)
    }
}

/// `/etc/<rel>` read from `etc_root/<rel>`: a symlink's target, or a file's bytes and
/// `st_mode & 0o7777`. `None` when absent. Directories and special files are errors.
pub fn read_etc_entry(etc_root: &Path, path: &str) -> Result<Option<EtcEntry>, ProbeError> {
    let rel = path
        .strip_prefix("/etc/")
        .filter(|rel| rel.split('/').all(|c| !matches!(c, "" | "." | "..")))
        .ok_or_else(|| ProbeError(format!("{path}: not a path below /etc")))?;
    let full = etc_root.join(rel);
    let failed = |e: std::io::Error| ProbeError(format!("{}: {e}", full.display()));
    let meta = match fs::symlink_metadata(&full) {
        Ok(meta) => meta,
        Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => {
            return Ok(None)
        }
        Err(e) => return Err(failed(e)),
    };
    if meta.file_type().is_symlink() {
        let target = fs::read_link(&full).map_err(failed)?;
        Ok(Some(EtcEntry::Symlink(
            target.to_string_lossy().into_owned(),
        )))
    } else if meta.is_file() {
        Ok(Some(EtcEntry::File {
            content: fs::read(&full).map_err(failed)?,
            mode: meta.permissions().mode() & 0o7777,
        }))
    } else {
        Err(ProbeError(format!(
            "{}: not a regular file or symlink",
            full.display()
        )))
    }
}

/// Map `systemctl is-enabled UNIT` onto [`UnitState`]. `linked` units are not enabled, so
/// they count as `Disabled`; `bad` and unknown answers are errors.
pub fn parse_unit_state(unit: &str, out: &Output) -> Result<UnitState, ProbeError> {
    let stdout = out.stdout_text();
    let word = stdout.lines().next().unwrap_or("").trim();
    let state = match word {
        "enabled" | "enabled-runtime" => UnitState::Enabled,
        "disabled" | "linked" | "linked-runtime" => UnitState::Disabled,
        "masked" | "masked-runtime" => UnitState::Masked,
        "static" | "indirect" | "generated" | "transient" | "alias" => UnitState::Static,
        "not-found" => UnitState::NotFound,
        "" if out.status == 4 || out.stderr_text().contains("Failed to get unit file state") => {
            UnitState::NotFound
        }
        other => {
            return Err(ProbeError(format!(
                "systemctl is-enabled {unit}: unexpected answer {other:?} (exit status {})",
                out.status
            )))
        }
    };
    Ok(state)
}
```

- [ ] **Step 4: Replace `lib.rs`**

`aios-cli/crates/aios-exec/src/lib.rs`:
```rust
//! Everything `aios` does to the running system, behind [`CommandRunner`], so every test
//! runs without root against a [`FakeRunner`] and tempdirs.

pub mod btrfs;
mod error;
mod layout;
mod probe;
mod runner;
mod sys;

pub use error::ExecError;
pub use layout::Layout;
pub use probe::{parse_unit_state, read_etc_entry, DirProbe};
pub use runner::{run_ok, status_error, Cmd, CommandRunner, FakeRunner, Output, RealRunner};
pub use sys::{
    days_since_epoch, luks_uuid_from_cmdline, parse_df_avail, parse_efivar_utf16, rfc3339_utc,
    sha256_hex, unit_file_name,
};
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd aios-cli && cargo test -p aios-exec --test probe`
Expected: `test result: ok. 10 passed`.

- [ ] **Step 6: Lint**

Run: `make check`
Expected: as in Task 1.

- [ ] **Step 7: Commit**

```bash
cd /home/eli/Development/AIOS
git add aios-cli/
git commit -m "feat(exec): DirProbe, the real SystemProbe"
```

---
### Task 5: Apply part 1: steps, validation, manifest commit, candidates, assembly, cleanup guard

**Files:**
- Create: `aios-cli/crates/aios-exec/src/steps.rs`, `src/facts.rs`, `src/trust.rs`, `src/apply/mod.rs`, `src/apply/prepare.rs`
- Modify: `aios-cli/crates/aios-exec/src/lib.rs` (full content below)
- Test: `aios-cli/crates/aios-exec/tests/common/mod.rs`, `tests/steps.rs`, `tests/apply_prepare.rs`

The steps of `apply()` in order. Tasks 6 and 8 add the rest; `mount-top` comes first because the commit message needs the new id.
1. **mount-top:**
   - Apply mode: `mount -t btrfs -o subvolid=5 DEVICE TOP`.
   - Bootstrap mode: the installer has already mounted the target, so nothing is mounted.
   - Then the new id: the max over every `@usr-gen-*`/`@etc-gen-*` name + 1, or gen-1 for bootstrap. A bootstrap target that already holds generations is refused.
2. **validate:**
   - `check_trusted_dirs`: the manifest repo and the secrets directory must be owned by `ApplyCtx.trusted_uid` (0 in production) and not group/world-writable.
   - `RenderCtx::new` (via `MachineFacts::render_ctx`) must accept the LUKS UUID, the ESP id and the hardening cmdline.
3. **commit-manifest:** if `git status --porcelain` prints anything, `git add -A`, then `git -c user.name=aios -c user.email=aios@localhost commit -m "aios: manifest for gen-NNNN"`. `HEAD` (`rev-parse --short`) becomes `manifest_commit`.
   - `add -A` also commits new files under `files/` and `home/`.
   - The `-c` identity is needed because root has no git identity.
4. **prepare-candidate:**
   - `delete_recursive` stale `@usr-cand`, `@etc-cand`, `@root-cand`.
   - Check that `@blank` (and, for apply, the booted `@usr-gen-N`/`@etc-gen-N`) exists.
   - Apply: snapshot the booted pair into `@usr-cand`/`@etc-cand`. Bootstrap: `btrfs subvolume create` both.
   - Snapshot `@blank` → `@root-cand`.
5. **assemble:**
   - Bind `@root-cand` on `cand`.
   - Then bind `@usr-cand` on `usr`, `@etc-cand` on `etc`, `persist/var/cache/pacman/pkg`, the `@log` subvolume (`layout.log`) on `var/log`, and `persist/aios/repo` on `persist/aios/repo`.
   - Sources and mount points are created first.

The cleanup guard runs on any error, best effort, logging and never returning its own errors:
- `umount -R cand` if the root bind succeeded;
- `delete_recursive` each candidate that exists;
- `umount top` if this run mounted it.

The fixture in `tests/common/mod.rs` is used unchanged by every later task:
- **The machine:** a tempdir with the manifest repo, secrets, a top level with `@blank` and gen-6/gen-7 (apply) or `@blank` only (bootstrap), and an ESP.
- **The candidate tree:** pre-populated with what pacman would leave there, because the mounts are fake. That means account files, kernel module dirs with `pkgbase`, a unit file, and the UKIs `ukify` would build.
- **The runner:** emulates subvolumes and answers `git rev-parse`, the pacman queries and `df`.

Until Task 8, `apply()` stops after the last step that exists. The tests only check calls and files that stay the same once later steps run.

- [ ] **Step 1: Write the shared fixture**

`aios-cli/crates/aios-exec/tests/common/mod.rs`:
```rust
//! Shared fixtures: a whole machine in a tempdir plus a scripted `FakeRunner`. Each test
//! binary uses a different subset, hence the `allow`.
#![allow(dead_code)]

use aios_exec::StepError;
use aios_exec::{apply, ApplyCtx, ApplyOutcome, FakeRunner, Layout, MachineFacts, Mode, Output};
use aios_gen::GenId;
use aios_manifest::{parse, Manifest};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tempfile::TempDir;

pub const MANIFEST: &str = r#"[system]
hostname = "nightcity"
timezone = "Asia/Jerusalem"
locale = "en_US.UTF-8"
keymap = "us"

[kernel]
default = "linux-cachyos"
fallback = "linux-cachyos-lts"
lockdown = "integrity"
extra_cmdline = []

[packages]
install = ["base", "zsh", "git"]

[services]
enable = ["NetworkManager", "fwupd-refresh.timer"]
disable = ["bluetooth"]
mask = ["sshd.socket"]

[files]
"/etc/pacman.conf" = { source = "files/pacman.conf" }
"/etc/nftables.conf" = { source = "files/nftables.conf", mode = "0600" }
"/etc/usbguard/usbguard-daemon.conf" = { source = "files/usbguard-daemon.conf", mode = "0600", group = "wheel" }
"/etc/pacman.d/hooks/90-mkinitcpio-install.hook" = { symlink = "/dev/null" }

[persist]
directories = ["/var/lib/NetworkManager", "/var/cache/pacman/pkg"]
files = ["/etc/machine-id"]

[users.eli]
uid = 1000
groups = ["wheel"]
shell = "/usr/bin/zsh"

[users.eli.home]
".zshrc" = "home/eli/zshrc"
".config/autostart/" = "home/eli/autostart/"
".ssh/authorized_keys" = "home/eli/authorized_keys"
"#;

pub const PACMAN_CONF: &str = "[options]
DBPath       = /usr/lib/pacman/
CacheDir     = /var/cache/pacman/pkg/
LogFile      = /var/log/pacman.log
SigLevel     = Required DatabaseOptional

[aios-local]
SigLevel = Optional TrustAll
Server = file:///persist/aios/repo

[core]
Include = /etc/pacman.d/mirrorlist
";

pub const LUKS_UUID: &str = "0b6c2e7f-5d0a-4c2e-9a71-3f1d2c4b5a69";
pub const ESP_UUID: &str = "7A1B-2C3D";
pub const HARDENING: &str = "init_on_alloc=1 quiet\n";
pub const ELI_HASH: &str = "$y$j9T$salt$hash";
pub const BOOTED: GenId = GenId(7);
/// What `pacman -Q <kernels>` prints in the candidate.
pub const KERNELS: &str = "linux-cachyos 7.3.0-4\nlinux-cachyos-lts 6.18.55-2\n";
/// What `pacman -Qq` prints in the candidate (deliberately unsorted).
pub const ALL_PACKAGES: &str = "zsh\nbase\nlinux-cachyos\n";

/// 2026-11-03T21:14:05Z.
pub fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_793_740_445)
}

pub fn facts() -> MachineFacts {
    MachineFacts {
        hardening_cmdline: HARDENING.to_string(),
        luks_uuid: LUKS_UUID.to_string(),
        esp_uuid: ESP_UUID.to_string(),
    }
}

/// The cmdline gen-7 booted with.
pub fn booted_cmdline() -> String {
    format!("rd.luks.name={LUKS_UUID}=aios root=/dev/mapper/aios rw aios.gen=0007 quiet\n")
}

pub fn write(path: &Path, content: &str, mode: u32) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

pub fn mkdir(path: &Path) {
    fs::create_dir_all(path).unwrap();
}

/// A machine in a tempdir. `runner` emulates subvolumes as directories and answers the
/// queries apply makes. The candidate tree (`cand/`) is pre-populated with what the
/// package manager would have left there: account files, kernel modules, a unit file, and
/// the UKIs `ukify` would build.
pub struct Fixture {
    pub dir: TempDir,
    pub layout: Layout,
    pub manifest: Manifest,
    pub facts: MachineFacts,
    pub runner: FakeRunner,
    pub mode: Mode,
    /// Owner `check_trusted_dirs` requires: whoever runs the tests.
    pub trusted_uid: u32,
}

impl Fixture {
    /// An installed machine that booted gen-7; gen-6 and gen-7 exist. Apply builds gen-8.
    pub fn booted() -> Fixture {
        let fx = Fixture::machine(MANIFEST, Mode::Apply { booted: BOOTED }, GenId(8));
        let l = &fx.layout;
        for gen in ["0006", "0007"] {
            mkdir(&l.subvol(&format!("@usr-gen-{gen}")));
            mkdir(&l.subvol(&format!("@etc-gen-{gen}")));
            write(
                &l.uki_dir().join(format!("aios-gen-{gen}-cachyos.efi")),
                "old",
                0o644,
            );
        }
        write(&l.proc_cmdline, &booted_cmdline(), 0o644);
        // gen-7 managed a file this manifest no longer has.
        write(
            &l.cand.join("etc/aios/managed-files"),
            "/etc/old.conf\n",
            0o644,
        );
        write(&l.cand.join("etc/old.conf"), "old\n", 0o644);
        fx
    }

    /// An installer target: the top level holds only `@blank`. Bootstrap builds gen-1.
    pub fn fresh() -> Fixture {
        let fx = Fixture::machine(MANIFEST, Mode::Bootstrap, GenId(1));
        write(
            &fx.layout.proc_cmdline,
            "archisobasedir=arch quiet\n",
            0o644,
        );
        fx
    }

    fn machine(manifest: &str, mode: Mode, gen: GenId) -> Fixture {
        let dir = TempDir::new().unwrap();
        let layout = Layout::under(dir.path());
        let l = &layout;
        write(&l.manifest_path(), manifest, 0o644);
        write(&l.config.join("files/pacman.conf"), PACMAN_CONF, 0o644);
        write(
            &l.config.join("files/nftables.conf"),
            "flush ruleset\n",
            0o644,
        );
        write(
            &l.config.join("files/usbguard-daemon.conf"),
            "RuleFile=x\n",
            0o644,
        );
        write(&l.config.join("home/eli/zshrc"), "# zshrc\n", 0o644);
        write(&l.config.join("home/eli/authorized_keys"), "", 0o644);
        write(
            &l.config.join("home/eli/autostart/hello.desktop"),
            "[Desktop Entry]\n",
            0o644,
        );
        write(&l.passwd_secret("eli"), &format!("{ELI_HASH}\n"), 0o600);
        fs::set_permissions(&l.config, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&l.secrets, fs::Permissions::from_mode(0o700)).unwrap();
        mkdir(&l.subvol("@blank"));
        mkdir(&l.home);
        mkdir(&l.esp);
        let etc = l.cand.join("etc");
        write(
            &etc.join("passwd"),
            "root:x:0:0::/root:/usr/bin/bash\n",
            0o644,
        );
        write(&etc.join("group"), "root:x:0:root\nwheel:x:998:\n", 0o644);
        write(&etc.join("shadow"), "root:*:20000::::::\n", 0o600);
        write(&etc.join("gshadow"), "root:::root\nwheel:!*::\n", 0o600);
        let modules = l.cand.join("usr/lib/modules");
        write(
            &modules.join("7.3.0-4-cachyos/pkgbase"),
            "linux-cachyos\n",
            0o644,
        );
        write(
            &modules.join("6.18.55-2-cachyos-lts/pkgbase"),
            "linux-cachyos-lts\n",
            0o644,
        );
        mkdir(&modules.join("6.1.0-old/kernel"));
        write(
            &l.cand.join("usr/lib/systemd/system/bluetooth.service"),
            "[Unit]\n",
            0o644,
        );
        for flavor in ["cachyos", "lts"] {
            let uki = format!("var/tmp/aios/aios-gen-{gen}-{flavor}.efi");
            write(&l.cand.join(uki), &format!("UKI {flavor}"), 0o644);
        }
        let manifest = parse(manifest).expect("fixture manifest parses");
        let mut runner = FakeRunner::new();
        let cand = l.cand.display().to_string();
        let explicit = format!("{}\nnano\n", manifest.package_set().join("\n"));
        runner
            .emulate_subvolumes()
            .respond(
                &["git", "-C", &l.config.display().to_string(), "rev-parse"],
                Output::ok("3f9c2a1\n"),
            )
            .respond(
                &["arch-chroot", &cand, "pacman", "-Qqe"],
                Output::ok(explicit),
            )
            .respond(
                &["arch-chroot", &cand, "pacman", "-Qdtq"],
                Output::ok("libnano\n"),
            )
            .respond(&["arch-chroot", &cand, "pacman", "-Q"], Output::ok(KERNELS))
            .respond(
                &["arch-chroot", &cand, "pacman", "-Qq"],
                Output::ok(ALL_PACKAGES),
            )
            .respond(&["df"], Output::ok("     Avail\n2000000000\n"));
        Fixture {
            trusted_uid: fs::metadata(dir.path()).unwrap().uid(),
            facts: facts(),
            manifest,
            runner,
            mode,
            layout,
            dir,
        }
    }

    /// Replace the manifest (written to the repo too).
    pub fn set_manifest(&mut self, raw: &str) {
        write(&self.layout.manifest_path(), raw, 0o644);
        self.manifest = parse(raw).expect("test manifest parses");
    }

    pub fn ctx(&self) -> ApplyCtx<'_> {
        ApplyCtx {
            runner: &self.runner,
            layout: &self.layout,
            manifest: &self.manifest,
            facts: &self.facts,
            now: now(),
            mode: self.mode,
            trusted_uid: self.trusted_uid,
        }
    }

    pub fn run(&self) -> Result<ApplyOutcome, StepError> {
        apply(&self.ctx())
    }

    /// The calls so far, with paths written as `{top}`, `{cand}`, ... (see `expand`).
    pub fn calls(&self) -> Vec<String> {
        let mut calls = self.runner.calls();
        for (key, value) in self.placeholders() {
            for call in &mut calls {
                *call = call.replace(&value, key);
            }
        }
        calls
    }

    /// `{top}`, `{cand}`, `{config}`, `{persist}`, `{log}`, `{home}`, `{esp}` and `{run}`
    /// (the tempdir root) replaced by their paths; `{set}` by the package set. One entry
    /// per non-empty line.
    pub fn expand(&self, text: &str) -> Vec<String> {
        let set = self.manifest.package_set().join(" ");
        text.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(|l| l.replace("{set}", &set))
            .collect()
    }

    /// Longest paths first, so `{top}` never eats part of `{cand}`.
    fn placeholders(&self) -> Vec<(&'static str, String)> {
        let l = &self.layout;
        let mut pairs = vec![
            ("{top}", l.top.display().to_string()),
            ("{cand}", l.cand.display().to_string()),
            ("{config}", l.config.display().to_string()),
            ("{persist}", l.persist.display().to_string()),
            ("{log}", l.log.display().to_string()),
            ("{home}", l.home.display().to_string()),
            ("{esp}", l.esp.display().to_string()),
            ("{run}", self.dir.path().display().to_string()),
        ];
        pairs.sort_by_key(|(_, path)| std::cmp::Reverse(path.len()));
        pairs
    }

    /// Calls made after the first call starting with `failing` (placeholder form).
    pub fn calls_after(&self, failing: &str) -> Vec<String> {
        let calls = self.calls();
        let at = calls
            .iter()
            .position(|c| c.starts_with(failing))
            .unwrap_or_else(|| panic!("no call starts with {failing:?} in {calls:#?}"));
        calls[at + 1..].to_vec()
    }

    /// No candidate subvolume is left in the top level.
    pub fn assert_no_candidates(&self) {
        for name in ["@usr-cand", "@etc-cand", "@root-cand"] {
            assert!(!self.layout.subvol(name).exists(), "{name} left behind");
        }
    }
}

/// The cleanup after a failure once the candidate tree is mounted (apply mode).
pub const CLEANUP_MOUNTED: &str = "
umount -R {cand}
btrfs subvolume show {top}/@usr-cand
btrfs subvolume delete --recursive {top}/@usr-cand
btrfs subvolume show {top}/@etc-cand
btrfs subvolume delete --recursive {top}/@etc-cand
btrfs subvolume show {top}/@root-cand
btrfs subvolume delete --recursive {top}/@root-cand
umount {top}
";
```

- [ ] **Step 2: Write the failing tests**

`aios-cli/crates/aios-exec/tests/steps.rs`:
```rust
use aios_exec::{Step, StepError};

#[test]
fn step_names_are_kebab_case() {
    let names = [
        (Step::Lock, "lock"),
        (Step::Validate, "validate"),
        (Step::CommitManifest, "commit-manifest"),
        (Step::MountTop, "mount-top"),
        (Step::PrepareCandidate, "prepare-candidate"),
        (Step::Assemble, "assemble"),
        (Step::Packages, "packages"),
        (Step::Keyring, "keyring"),
        (Step::RenderEtc, "render-etc"),
        (Step::Services, "services"),
        (Step::Uki, "uki"),
        (Step::Sign, "sign"),
        (Step::EspSpace, "esp-space"),
        (Step::Finalize, "finalize"),
        (Step::Cleanup, "cleanup"),
    ];
    for (step, name) in names {
        assert_eq!(step.name(), name);
        assert_eq!(step.to_string(), name);
    }
}

#[test]
fn step_error_names_the_step() {
    let err = StepError {
        step: Step::Packages,
        detail: "`pacman -Syu` exited with status 1".to_string(),
    };
    assert_eq!(
        err.to_string(),
        "aios: step packages failed: `pacman -Syu` exited with status 1"
    );
}
```

`aios-cli/crates/aios-exec/tests/apply_prepare.rs`:
```rust
mod common;

use aios_exec::{check_trusted_dirs, Output, Step};
use common::{mkdir, Fixture, CLEANUP_MOUNTED};
use std::fs;
use std::os::unix::fs::PermissionsExt;

#[test]
fn mounts_the_top_level_and_records_head_of_a_clean_repo() {
    let fx = Fixture::booted();
    let outcome = fx.run().unwrap();
    assert_eq!(outcome.manifest_commit, "3f9c2a1");
    assert_eq!(
        fx.calls()[..3],
        fx.expand(
            "
            mount -t btrfs -o subvolid=5 /dev/mapper/aios {top}
            git -C {config} status --porcelain
            git -C {config} rev-parse --short HEAD
            "
        )
    );
    assert!(!fx.calls().iter().any(|c| c.contains(" commit ")));
}

#[test]
fn a_dirty_repo_is_committed_for_the_new_generation() {
    let mut fx = Fixture::booted();
    fx.runner.respond(
        &[
            "git",
            "-C",
            &fx.layout.config.display().to_string(),
            "status",
        ],
        Output::ok(" M manifest.toml\n?? files/new.conf\n"),
    );
    fx.run().unwrap();
    assert_eq!(
        fx.calls()[1..5],
        fx.expand(
            "
            git -C {config} status --porcelain
            git -C {config} add -A
            git -C {config} -c user.name=aios -c user.email=aios@localhost commit -m 'aios: manifest for gen-0008'
            git -C {config} rev-parse --short HEAD
            "
        )
    );
}

#[test]
fn the_new_id_follows_every_generation_subvolume() {
    let mut fx = Fixture::booted();
    mkdir(&fx.layout.subvol("@etc-gen-0011"));
    fx.runner.respond(
        &[
            "git",
            "-C",
            &fx.layout.config.display().to_string(),
            "status",
        ],
        Output::ok(" M manifest.toml\n"),
    );
    // The fixture's prebuilt UKIs are named for gen-0008, so this run fails later on;
    // only the commit message matters here.
    let _ = fx.run();
    assert!(fx
        .calls()
        .iter()
        .any(|c| c.ends_with("commit -m 'aios: manifest for gen-0012'")));
}

#[test]
fn snapshots_the_booted_generation_and_blank() {
    let fx = Fixture::booted();
    fx.run().unwrap();
    assert_eq!(
        fx.calls()[3..6],
        fx.expand(
            "
            btrfs subvolume snapshot {top}/@usr-gen-0007 {top}/@usr-cand
            btrfs subvolume snapshot {top}/@etc-gen-0007 {top}/@etc-cand
            btrfs subvolume snapshot {top}/@blank {top}/@root-cand
            "
        )
    );
}

#[test]
fn stale_candidates_are_deleted_first() {
    let fx = Fixture::booted();
    mkdir(&fx.layout.subvol("@usr-cand/var"));
    mkdir(&fx.layout.subvol("@root-cand"));
    fx.run().unwrap();
    assert_eq!(
        fx.calls()[3..8],
        fx.expand(
            "
            btrfs subvolume show {top}/@usr-cand
            btrfs subvolume delete --recursive {top}/@usr-cand
            btrfs subvolume show {top}/@root-cand
            btrfs subvolume delete --recursive {top}/@root-cand
            btrfs subvolume snapshot {top}/@usr-gen-0007 {top}/@usr-cand
            "
        )
    );
}

#[test]
fn assembles_the_candidate_root() {
    let fx = Fixture::booted();
    fx.run().unwrap();
    assert_eq!(
        fx.calls()[6..12],
        fx.expand(
            "
            mount --bind {top}/@root-cand {cand}
            mount --bind {top}/@usr-cand {cand}/usr
            mount --bind {top}/@etc-cand {cand}/etc
            mount --bind {persist}/var/cache/pacman/pkg {cand}/var/cache/pacman/pkg
            mount --bind {log} {cand}/var/log
            mount --bind {persist}/aios/repo {cand}/persist/aios/repo
            "
        )
    );
    let l = &fx.layout;
    for dir in [l.pkg_cache(), l.repo(), l.cand.join("persist/aios/repo")] {
        assert!(dir.is_dir(), "{} not created", dir.display());
    }
}

#[test]
fn a_failed_mount_needs_no_cleanup() {
    let mut fx = Fixture::booted();
    fx.runner.fail_on(&["mount", "-t", "btrfs"]);
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::MountTop);
    assert_eq!(
        err.to_string(),
        format!(
            "aios: step mount-top failed: `mount -t btrfs -o subvolid=5 /dev/mapper/aios {}` \
             exited with status 1: injected failure",
            fx.layout.top.display()
        )
    );
    assert_eq!(fx.calls().len(), 1);
}

#[test]
fn invalid_machine_facts_fail_validation() {
    let mut fx = Fixture::booted();
    fx.facts.luks_uuid = "not-a-uuid".to_string();
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::Validate);
    assert_eq!(err.detail, "invalid LUKS UUID \"not-a-uuid\"");
    assert_eq!(fx.calls()[1..], fx.expand("umount {top}"));
}

#[test]
fn a_group_writable_manifest_repo_fails_validation() {
    let fx = Fixture::booted();
    fs::set_permissions(&fx.layout.config, fs::Permissions::from_mode(0o775)).unwrap();
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::Validate);
    assert_eq!(
        err.to_string(),
        format!(
            "aios: step validate failed: manifest repo {} must be root-owned and not \
             group/world-writable",
            fx.layout.config.display()
        )
    );
    assert_eq!(fx.calls()[1..], fx.expand("umount {top}"));
}

#[test]
fn trusted_dirs_need_the_right_owner_and_private_secrets() {
    let fx = Fixture::booted();
    assert!(check_trusted_dirs(&fx.layout, fx.trusted_uid).is_ok());
    let err = check_trusted_dirs(&fx.layout, fx.trusted_uid + 1).unwrap_err();
    assert!(err.to_string().starts_with("manifest repo "), "{err}");
    fs::set_permissions(&fx.layout.secrets, fs::Permissions::from_mode(0o707)).unwrap();
    let err = check_trusted_dirs(&fx.layout, fx.trusted_uid).unwrap_err();
    assert_eq!(
        err.to_string(),
        format!(
            "secrets directory {} must be root-owned and not group/world-writable",
            fx.layout.secrets.display()
        )
    );
}

#[test]
fn a_failed_commit_unmounts_the_top_level() {
    let mut fx = Fixture::booted();
    fx.runner.fail_on(&["git"]);
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::CommitManifest);
    assert_eq!(fx.calls_after("git"), fx.expand("umount {top}"));
}

#[test]
fn a_missing_booted_generation_fails_before_any_snapshot() {
    let fx = Fixture::booted();
    std::fs::remove_dir(fx.layout.subvol("@etc-gen-0007")).unwrap();
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::PrepareCandidate);
    assert_eq!(
        err.detail,
        format!("{} is missing", fx.layout.subvol("@etc-gen-0007").display())
    );
    assert!(!fx.calls().iter().any(|c| c.contains("snapshot")));
}

#[test]
fn a_failed_snapshot_deletes_the_candidates_made_so_far() {
    let mut fx = Fixture::booted();
    let etc = fx.layout.subvol("@etc-gen-0007").display().to_string();
    fx.runner.fail_on(&["btrfs", "subvolume", "snapshot", &etc]);
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::PrepareCandidate);
    assert_eq!(
        fx.calls_after("btrfs subvolume snapshot {top}/@etc-gen-0007"),
        fx.expand(
            "
            btrfs subvolume show {top}/@usr-cand
            btrfs subvolume delete --recursive {top}/@usr-cand
            umount {top}
            "
        )
    );
    fx.assert_no_candidates();
}

#[test]
fn a_failed_bind_unmounts_and_deletes_everything() {
    let mut fx = Fixture::booted();
    let etc = fx.layout.cand.join("etc").display().to_string();
    let source = fx.layout.subvol("@etc-cand").display().to_string();
    fx.runner.fail_on(&["mount", "--bind", &source, &etc]);
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::Assemble);
    assert_eq!(
        fx.calls_after("mount --bind {top}/@etc-cand"),
        fx.expand(CLEANUP_MOUNTED)
    );
    fx.assert_no_candidates();
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cd aios-cli && cargo test -p aios-exec --test steps --test apply_prepare`
Expected: compile errors:
- `steps`: `unresolved imports aios_exec::Step, aios_exec::StepError`.
- `apply_prepare` (3 errors): from `common/mod.rs`, `unresolved imports aios_exec::apply, aios_exec::ApplyCtx, aios_exec::ApplyOutcome, aios_exec::MachineFacts, aios_exec::Mode` and `unresolved import aios_exec::StepError`; from the test, `unresolved imports aios_exec::check_trusted_dirs, aios_exec::Step`.

- [ ] **Step 4: Implement `steps.rs`, `facts.rs` and `trust.rs`**

`aios-cli/crates/aios-exec/src/steps.rs`:
```rust
use std::fmt;

/// The named steps of `aios apply` / `aios bootstrap` (spec §4.3), in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Lock,
    Validate,
    CommitManifest,
    MountTop,
    PrepareCandidate,
    Assemble,
    Packages,
    Keyring,
    RenderEtc,
    Services,
    Uki,
    Sign,
    EspSpace,
    Finalize,
    Cleanup,
}

impl Step {
    pub fn name(self) -> &'static str {
        match self {
            Step::Lock => "lock",
            Step::Validate => "validate",
            Step::CommitManifest => "commit-manifest",
            Step::MountTop => "mount-top",
            Step::PrepareCandidate => "prepare-candidate",
            Step::Assemble => "assemble",
            Step::Packages => "packages",
            Step::Keyring => "keyring",
            Step::RenderEtc => "render-etc",
            Step::Services => "services",
            Step::Uki => "uki",
            Step::Sign => "sign",
            Step::EspSpace => "esp-space",
            Step::Finalize => "finalize",
            Step::Cleanup => "cleanup",
        }
    }
}

impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The step that failed and why (spec §7: `aios: step <name> failed: <detail>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepError {
    pub step: Step,
    pub detail: String,
}

impl fmt::Display for StepError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "aios: step {} failed: {}", self.step, self.detail)
    }
}

impl std::error::Error for StepError {}
```

`aios-cli/crates/aios-exec/src/facts.rs`:
```rust
use crate::{ExecError, Layout};
use aios_gen::GenId;
use aios_manifest::Manifest;
use aios_render::RenderCtx;
use std::collections::BTreeMap;
use std::fs;

/// Machine facts the renderers need beyond the manifest. The CLI gathers them; apply and
/// plan only read them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineFacts {
    /// Content of `/usr/lib/aios/cmdline-hardening`.
    pub hardening_cmdline: String,
    /// UUID of the LUKS2 partition (`rd.luks.name=<uuid>=aios`).
    pub luks_uuid: String,
    /// Volume id of the ESP (`findmnt -no UUID <esp>`).
    pub esp_uuid: String,
}

impl MachineFacts {
    /// The validated render context for generation `gen` (`RenderCtx::new`).
    pub fn render_ctx(&self, gen: GenId) -> Result<RenderCtx, ExecError> {
        RenderCtx::new(
            gen,
            &self.luks_uuid,
            &self.esp_uuid,
            &self.hardening_cmdline,
        )
        .map_err(ExecError)
    }
}

/// `secrets/passwd/<user>` for every declared user, trailing newlines trimmed.
pub fn read_hashes(layout: &Layout, m: &Manifest) -> Result<BTreeMap<String, String>, ExecError> {
    let mut hashes = BTreeMap::new();
    for user in m.users.keys() {
        let path = layout.passwd_secret(user);
        let text = fs::read_to_string(&path).map_err(|e| ExecError::io(&path, e))?;
        hashes.insert(user.clone(), text.trim_end_matches('\n').to_string());
    }
    Ok(hashes)
}
```

`aios-cli/crates/aios-exec/src/trust.rs`:
```rust
use crate::{ExecError, Layout};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// The manifest repo and the secrets directory decide what runs as root, so they must be
/// owned by `uid` (0 in production) and not group- or world-writable. Checked before the
/// manifest is read, so nobody else can swap files between validation and use.
pub fn check_trusted_dirs(layout: &Layout, uid: u32) -> Result<(), ExecError> {
    check_dir(&layout.config, "manifest repo", uid)?;
    check_dir(&layout.secrets, "secrets directory", uid)
}

fn check_dir(path: &Path, what: &str, uid: u32) -> Result<(), ExecError> {
    let meta = fs::metadata(path).map_err(|e| ExecError::io(path, e))?;
    if meta.uid() != uid || meta.mode() & 0o022 != 0 {
        return Err(ExecError(format!(
            "{what} {} must be root-owned and not group/world-writable",
            path.display()
        )));
    }
    Ok(())
}
```

- [ ] **Step 5: Implement `apply/mod.rs` and `apply/prepare.rs`**

`aios-cli/crates/aios-exec/src/apply/mod.rs`:
```rust
//! `aios apply` and `aios bootstrap`: build the next generation in candidate subvolumes
//! (spec §4.3). The booted generation is never modified; any failure deletes the
//! candidates again.

mod prepare;

use crate::{btrfs, CommandRunner, ExecError, Layout, MachineFacts};
use crate::{Step, StepError};
use aios_gen::GenId;
use aios_manifest::Manifest;
use std::fs;
use std::path::Path;
use std::time::SystemTime;

const USR_CAND: &str = "@usr-cand";
const ETC_CAND: &str = "@etc-cand";
const ROOT_CAND: &str = "@root-cand";
const CANDIDATES: [&str; 3] = [USR_CAND, ETC_CAND, ROOT_CAND];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// `aios apply`: snapshot the booted generation, `pacman -Syu`, then clear the
    /// `bootctl set-default` override so the new generation boots next.
    Apply { booted: GenId },
    /// `aios bootstrap` (installer): the top level is already mounted at `layout.top`;
    /// empty candidates, `pacstrap`, a fresh keyring, gen-1. No `bootctl` call.
    Bootstrap,
}

/// Everything one apply needs.
pub struct ApplyCtx<'a> {
    pub runner: &'a dyn CommandRunner,
    pub layout: &'a Layout,
    pub manifest: &'a Manifest,
    pub facts: &'a MachineFacts,
    /// Clock for `generation.toml` (`created`) and shadow `lastchg`.
    pub now: SystemTime,
    /// Required owner of the manifest repo and secrets directory: 0 in production.
    pub trusted_uid: u32,
    pub mode: Mode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyOutcome {
    pub gen: GenId,
    pub manifest_commit: String,
}

/// Build the next generation. On error, the candidate tree is unmounted, every candidate
/// subvolume is deleted and the top level is unmounted (best effort, logged to stderr).
pub fn apply(ctx: &ApplyCtx) -> Result<ApplyOutcome, StepError> {
    let mut run = Run {
        ctx,
        gen: GenId(0),
        manifest_commit: String::new(),
        top_mounted: false,
        cand_mounted: false,
    };
    match run.steps() {
        Ok(()) => Ok(ApplyOutcome {
            gen: run.gen,
            manifest_commit: run.manifest_commit,
        }),
        Err(e) => {
            run.cleanup();
            Err(e)
        }
    }
}

/// State of one apply, shared by the step implementations in the submodules.
struct Run<'a> {
    ctx: &'a ApplyCtx<'a>,
    /// The generation being built. Set by `mount-top`.
    gen: GenId,
    manifest_commit: String,
    /// We mounted `layout.top` and must unmount it.
    top_mounted: bool,
    /// Something is mounted at `layout.cand`.
    cand_mounted: bool,
}

impl Run<'_> {
    fn steps(&mut self) -> Result<(), StepError> {
        self.step(Step::MountTop, Run::mount_top)?;
        self.step(Step::Validate, Run::validate)?;
        self.step(Step::CommitManifest, Run::commit_manifest)?;
        self.step(Step::PrepareCandidate, Run::prepare_candidate)?;
        self.step(Step::Assemble, Run::assemble)
    }

    fn step(
        &mut self,
        step: Step,
        f: impl FnOnce(&mut Self) -> Result<(), ExecError>,
    ) -> Result<(), StepError> {
        eprintln!("aios: {step}");
        f(self).map_err(|e| StepError { step, detail: e.0 })
    }

    /// Undo everything that is not finalized. Errors are logged, not returned.
    fn cleanup(&mut self) {
        eprintln!("aios: {}", Step::Cleanup);
        let (runner, l) = (self.ctx.runner, self.ctx.layout);
        let report = |what: &str, result: Result<(), ExecError>| {
            if let Err(e) = result {
                eprintln!("aios: cleanup: {what}: {e}");
            }
        };
        if self.cand_mounted {
            report(
                "unmount candidate",
                btrfs::umount_recursive(runner, &l.cand),
            );
        }
        for name in CANDIDATES {
            report(name, btrfs::delete_recursive(runner, &l.subvol(name)));
        }
        if self.top_mounted {
            report("unmount top level", btrfs::umount(runner, &l.top));
        }
    }
}

/// `mkdir -p`.
fn mkdir(path: &Path) -> Result<(), ExecError> {
    fs::create_dir_all(path).map_err(|e| ExecError::io(path, e))
}
```

`aios-cli/crates/aios-exec/src/apply/prepare.rs`:
```rust
use super::{mkdir, Mode, Run, CANDIDATES, ETC_CAND, ROOT_CAND, USR_CAND};
use crate::{btrfs, check_trusted_dirs, run_ok, Cmd, ExecError};
use aios_gen::{next_id, parse_subvol, GenId};

impl Run<'_> {
    /// Mount the top level (apply only; bootstrap gets it mounted) and pick the generation
    /// id: max of every `@usr-gen-*`/`@etc-gen-*` + 1, or gen-1 on an empty bootstrap target.
    pub(super) fn mount_top(&mut self) -> Result<(), ExecError> {
        let l = self.ctx.layout;
        if let Mode::Apply { .. } = self.ctx.mode {
            btrfs::mount_top(self.ctx.runner, &l.device, &l.top, false)?;
            self.top_mounted = true;
        }
        let ids: Vec<GenId> = btrfs::list_names(&l.top)?
            .iter()
            .filter_map(|name| parse_subvol(name))
            .map(|(_, id)| id)
            .collect();
        self.gen = match self.ctx.mode {
            Mode::Bootstrap if !ids.is_empty() => {
                return Err(ExecError(format!(
                    "{} already holds generations",
                    l.top.display()
                )))
            }
            Mode::Bootstrap => GenId(1),
            Mode::Apply { .. } => next_id(&ids)
                .ok_or_else(|| ExecError::new("no generation ids left (gen-9999 exists)"))?,
        };
        Ok(())
    }

    /// The manifest repo and secrets are trusted (`check_trusted_dirs`) and the machine
    /// facts render safely (`RenderCtx::new`).
    pub(super) fn validate(&mut self) -> Result<(), ExecError> {
        check_trusted_dirs(self.ctx.layout, self.ctx.trusted_uid)?;
        self.ctx.facts.render_ctx(self.gen).map(drop)
    }

    /// Commit a dirty manifest repo (new files included) and record `HEAD`.
    pub(super) fn commit_manifest(&mut self) -> Result<(), ExecError> {
        let runner = self.ctx.runner;
        let git = || Cmd::new("git").arg("-C").arg_path(&self.ctx.layout.config);
        let status = run_ok(runner, &git().args(["status", "--porcelain"]))?;
        if !status.stdout_text().trim().is_empty() {
            run_ok(runner, &git().args(["add", "-A"]))?;
            let identity = ["-c", "user.name=aios", "-c", "user.email=aios@localhost"];
            let commit = git().args(identity).args(["commit", "-m"]);
            run_ok(
                runner,
                &commit.arg(format!("aios: manifest for gen-{}", self.gen)),
            )?;
        }
        let head = run_ok(runner, &git().args(["rev-parse", "--short", "HEAD"]))?;
        self.manifest_commit = head.stdout_text().trim().to_string();
        if self.manifest_commit.is_empty() {
            return Err(ExecError::new("git rev-parse printed no commit"));
        }
        Ok(())
    }

    /// Delete stale candidates, then create fresh ones: snapshots of the booted generation
    /// (apply) or empty subvolumes (bootstrap), plus `@blank` -> `@root-cand`.
    pub(super) fn prepare_candidate(&mut self) -> Result<(), ExecError> {
        let (runner, l) = (self.ctx.runner, self.ctx.layout);
        for name in CANDIDATES {
            btrfs::delete_recursive(runner, &l.subvol(name))?;
        }
        let blank = l.subvol("@blank");
        let mut sources = vec![blank.clone()];
        if let Mode::Apply { booted } = self.ctx.mode {
            sources.push(l.subvol(&booted.usr_subvol()));
            sources.push(l.subvol(&booted.etc_subvol()));
        }
        if let Some(missing) = sources.iter().find(|s| !s.is_dir()) {
            return Err(ExecError(format!("{} is missing", missing.display())));
        }
        match self.ctx.mode {
            Mode::Apply { booted } => {
                let usr = l.subvol(&booted.usr_subvol());
                btrfs::snapshot(runner, &usr, &l.subvol(USR_CAND))?;
                let etc = l.subvol(&booted.etc_subvol());
                btrfs::snapshot(runner, &etc, &l.subvol(ETC_CAND))?;
            }
            Mode::Bootstrap => {
                btrfs::create(runner, &l.subvol(USR_CAND))?;
                btrfs::create(runner, &l.subvol(ETC_CAND))?;
            }
        }
        btrfs::snapshot(runner, &blank, &l.subvol(ROOT_CAND))
    }

    /// Mount the candidate tree at `layout.cand`: `@root-cand`, with `@usr-cand` on `usr`,
    /// `@etc-cand` on `etc`, and binds of the pacman cache, `/var/log` and the local repo.
    pub(super) fn assemble(&mut self) -> Result<(), ExecError> {
        let (runner, l) = (self.ctx.runner, self.ctx.layout);
        mkdir(&l.cand)?;
        btrfs::bind(runner, &l.subvol(ROOT_CAND), &l.cand)?;
        self.cand_mounted = true;
        let binds = [
            (l.subvol(USR_CAND), "usr"),
            (l.subvol(ETC_CAND), "etc"),
            (l.pkg_cache(), "var/cache/pacman/pkg"),
            (l.log.clone(), "var/log"),
            (l.repo(), "persist/aios/repo"),
        ];
        for (source, rel) in binds {
            let target = l.cand.join(rel);
            mkdir(&source)?;
            mkdir(&target)?;
            btrfs::bind(runner, &source, &target)?;
        }
        Ok(())
    }
}
```

- [ ] **Step 6: Replace `lib.rs`**

`aios-cli/crates/aios-exec/src/lib.rs`:
```rust
//! Everything `aios` does to the running system, behind [`CommandRunner`], so every test
//! runs without root against a [`FakeRunner`] and tempdirs.

mod apply;
pub mod btrfs;
mod error;
mod facts;
mod layout;
mod probe;
mod runner;
mod steps;
mod sys;
mod trust;

pub use apply::{apply, ApplyCtx, ApplyOutcome, Mode};
pub use error::ExecError;
pub use facts::{read_hashes, MachineFacts};
pub use layout::Layout;
pub use probe::{parse_unit_state, read_etc_entry, DirProbe};
pub use runner::{run_ok, status_error, Cmd, CommandRunner, FakeRunner, Output, RealRunner};
pub use steps::{Step, StepError};
pub use sys::{
    days_since_epoch, luks_uuid_from_cmdline, parse_df_avail, parse_efivar_utf16, rfc3339_utc,
    sha256_hex, unit_file_name,
};
pub use trust::check_trusted_dirs;
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cd aios-cli && cargo test -p aios-exec --test steps --test apply_prepare`
Expected: `apply_prepare`: `test result: ok. 14 passed`; `steps`: `test result: ok. 2 passed`.

- [ ] **Step 8: Lint**

Run: `make check`
Expected: as in Task 1.

- [ ] **Step 9: Commit**

```bash
cd /home/eli/Development/AIOS
git add aios-cli/
git commit -m "feat(exec): apply steps up to the assembled candidate, with cleanup guard"
```

---
### Task 6: Apply part 2: packages, keyring, render `/etc`, services

**Files:**
- Create: `aios-cli/crates/aios-exec/src/etcfs.rs`, `src/apply/packages.rs`, `src/apply/etc.rs`, `src/apply/services.rs`
- Modify: `aios-cli/crates/aios-exec/src/apply/mod.rs`, `aios-cli/crates/aios-exec/src/lib.rs` (full content below)
- Test: `aios-cli/crates/aios-exec/tests/etcfs.rs`, `aios-cli/crates/aios-exec/tests/apply_build.rs`

The new steps:
6. **packages:**
   - **Apply:**
     - `arch-chroot CAND pacman -Syu --needed --noconfirm <set>`.
     - `-Rns --noconfirm` of `pacman -Qqe` minus the set, skipped when empty.
     - `-D --asexplicit <set>`.
     - Orphans: `pacman -Qdtq` exits 1 when there are none; otherwise `-Rns --noconfirm` them.
   - **Bootstrap:** `pacstrap -C <conf> CAND <set>`. The conf is the manifest's `/etc/pacman.conf` source with two changes:
     - `DBPath` and `LogFile` are dropped, so both land inside the new root. Its `var/lib/pacman` links to `../../usr/lib/pacman`.
     - `file:///persist/` servers point at `file://CAND/persist/`, the bind of the local repo, because the installer host has no `/persist`.

     The conf is written next to `cand` (`/run/aios/aios-pacstrap.conf`) and left there. `cand/usr/lib/pacman` is created first, because pacstrap's `mkdir -p` fails on the dangling `var/lib/pacman` link.
7. **keyring** (bootstrap only): `arch-chroot CAND pacman-key --init`, then `--populate archlinux cachyos`.
8. **render-etc:**
   - `desired_etc` with a `DirProbe` over `cand/etc` and the context for the new generation.
   - Paths the candidate's previous `/etc/aios/managed-files` listed and the new state lacks are removed.
   - Every entry is written with `etcfs::write`. It never follows a symlink: an existing symlink or file is replaced, and a symlinked parent is an error.
   - Directory home bind sources are created, so an empty directory still has a bind source (Phase 2 contract 6).
   - `generation.toml`:
     - `id`; `parent` (the booted gen, or 0); `created` (RFC 3339); `manifest_commit`;
     - `kernels` from one `pacman -Q <kernels>`;
     - `package_set_sha256` over the sorted `pacman -Qq` lines, each followed by `\n`.
   - `locale-gen` runs when `/etc/locale.gen` is desired.
   - `chown -h owner:group` in the chroot for `[files]` entries that aren't root:root.
   - `mkdir -p` of each `persist_dirs()` entry below `layout.persist`.
   - Bootstrap only: `/home/<user>` (0700) on the new `@home`, chowned to `uid:uid` through the runner. Apply never touches `/home`: `aios-home.conf`'s `d` lines fix owners at boot, and systemd creates the bind mount points.
9. **services:** `systemctl --root=CAND` with one call per verb.
   - Units without a `.` get `.service`. Mask beats disable, which beats enable, as in the planner. `aios-health.service` is always enabled.
   - Units the candidate has masked (`etc/systemd/system/<unit>` → `/dev/null`) but that are now wanted enabled or disabled are unmasked first.
   - `disable` skips units with no unit file in the candidate. The planner counts them as already disabled, and `systemctl disable` would fail on them.

- [ ] **Step 1: Write the failing tests**

`aios-cli/crates/aios-exec/tests/etcfs.rs`:
```rust
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
fn only_paths_below_etc() {
    let dir = tempfile::tempdir().unwrap();
    for bad in ["/usr/x", "/etc/../x", "/etc/", "/etc/a//b"] {
        let err = etcfs::write(dir.path(), bad, &file("x", 0o644)).unwrap_err();
        assert_eq!(err.to_string(), format!("{bad}: not a path below /etc"));
    }
}
```

`aios-cli/crates/aios-exec/tests/apply_build.rs`:
```rust
mod common;

use aios_exec::{sha256_hex, Output, Step};
use aios_gen::GenerationMeta;
use aios_render::{cmdline, RenderCtx};
use common::{mkdir, Fixture, CLEANUP_MOUNTED, ESP_UUID, HARDENING, LUKS_UUID, MANIFEST};
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
}

/// The calls from the first one starting with `first`, up to and including the first one
/// starting with `last`.
fn span(fx: &Fixture, first: &str, last: &str) -> Vec<String> {
    let calls = fx.calls();
    let from = calls.iter().position(|c| c.starts_with(first)).unwrap();
    let to = from
        + calls[from..]
            .iter()
            .position(|c| c.starts_with(last))
            .unwrap();
    calls[from..=to].to_vec()
}

#[test]
fn apply_upgrades_removes_marks_and_drops_orphans() {
    let fx = Fixture::booted();
    fx.run().unwrap();
    assert_eq!(
        span(
            &fx,
            "arch-chroot {cand} pacman -Syu",
            "arch-chroot {cand} pacman -Rns --noconfirm libnano"
        ),
        fx.expand(
            "
            arch-chroot {cand} pacman -Syu --needed --noconfirm {set}
            arch-chroot {cand} pacman -Qqe
            arch-chroot {cand} pacman -Rns --noconfirm nano
            arch-chroot {cand} pacman -D --asexplicit {set}
            arch-chroot {cand} pacman -Qdtq
            arch-chroot {cand} pacman -Rns --noconfirm libnano
            "
        )
    );
}

#[test]
fn nothing_to_remove_means_no_removal_calls() {
    let mut fx = Fixture::booted();
    let cand = fx.layout.cand.display().to_string();
    let explicit = fx.manifest.package_set().join("\n");
    fx.runner
        .respond(
            &["arch-chroot", &cand, "pacman", "-Qqe"],
            Output::ok(explicit),
        )
        .respond(
            &["arch-chroot", &cand, "pacman", "-Qdtq"],
            Output::failed(1, ""),
        );
    fx.run().unwrap();
    assert!(!fx.calls().iter().any(|c| c.contains("-Rns")));
}

#[test]
fn renders_the_desired_etc_into_the_candidate() {
    let fx = Fixture::booted();
    fx.run().unwrap();
    let etc = fx.layout.cand.join("etc");
    assert_eq!(
        fs::read_to_string(etc.join("hostname")).unwrap(),
        "nightcity\n"
    );
    assert_eq!(
        fs::read_to_string(etc.join("nftables.conf")).unwrap(),
        "flush ruleset\n"
    );
    assert_eq!(mode(&etc.join("nftables.conf")), 0o600);
    assert_eq!(mode(&etc.join("shadow")), 0o600);
    assert_eq!(
        fs::read_link(etc.join("pacman.d/hooks/90-mkinitcpio-install.hook")).unwrap(),
        Path::new("/dev/null")
    );
    let ctx = RenderCtx::new(common::BOOTED, LUKS_UUID, ESP_UUID, HARDENING).unwrap();
    let gen8 = RenderCtx {
        gen: aios_gen::GenId(8),
        ..ctx
    };
    assert_eq!(
        fs::read_to_string(etc.join("kernel/cmdline")).unwrap(),
        cmdline(&fx.manifest, &gen8)
    );
    assert!(fs::read_to_string(etc.join("shadow"))
        .unwrap()
        .contains("\neli:$y$j9T$salt$hash:"));
    assert!(etc
        .join("aios/home/eli/.config/autostart/hello.desktop")
        .is_file());
}

#[test]
fn paths_the_old_generation_managed_are_removed() {
    let fx = Fixture::booted();
    fx.run().unwrap();
    let etc = fx.layout.cand.join("etc");
    assert!(!etc.join("old.conf").exists());
    let managed = fs::read_to_string(etc.join("aios/managed-files")).unwrap();
    assert!(managed.contains("/etc/hostname\n"));
    assert!(!managed.contains("old.conf"));
}

#[test]
fn generation_toml_records_ids_commit_kernels_and_package_hash() {
    let fx = Fixture::booted();
    fx.run().unwrap();
    let text = fs::read_to_string(fx.layout.cand.join("etc/aios/generation.toml")).unwrap();
    assert_eq!(
        GenerationMeta::from_toml(&text).unwrap(),
        GenerationMeta {
            id: 8,
            parent: 7,
            created: "2026-11-03T21:14:05Z".to_string(),
            manifest_commit: "3f9c2a1".to_string(),
            kernels: vec![
                "linux-cachyos 7.3.0-4".to_string(),
                "linux-cachyos-lts 6.18.55-2".to_string(),
            ],
            package_set_sha256: sha256_hex(b"base\nlinux-cachyos\nzsh\n"),
        }
    );
    assert_eq!(
        span(
            &fx,
            "arch-chroot {cand} pacman -Q ",
            "arch-chroot {cand} chown"
        ),
        fx.expand(
            "
            arch-chroot {cand} pacman -Q linux-cachyos linux-cachyos-lts
            arch-chroot {cand} pacman -Qq
            arch-chroot {cand} locale-gen
            arch-chroot {cand} chown -h root:wheel /etc/usbguard/usbguard-daemon.conf
            "
        )
    );
}

#[test]
fn c_utf8_needs_no_locale_gen() {
    let mut fx = Fixture::booted();
    fx.set_manifest(&MANIFEST.replace("en_US.UTF-8", "C.UTF-8"));
    fx.run().unwrap();
    assert!(!fx.calls().iter().any(|c| c.contains("locale-gen")));
    assert!(!fx.layout.cand.join("etc/locale.gen").exists());
}

#[test]
fn persist_directories_exist_for_the_binds() {
    let fx = Fixture::booted();
    fx.run().unwrap();
    for rel in ["var/lib/NetworkManager", "var/cache/pacman/pkg", "etc"] {
        assert!(fx.layout.persist.join(rel).is_dir(), "{rel}");
    }
}

#[test]
fn apply_never_touches_home() {
    let fx = Fixture::booted();
    fx.run().unwrap();
    assert_eq!(fs::read_dir(&fx.layout.home).unwrap().count(), 0);
    assert!(!fx.calls().iter().any(|c| c.starts_with("chown ")));
}

#[test]
fn bootstrap_creates_private_home_directories() {
    let fx = Fixture::fresh();
    fx.run().unwrap();
    let chowns: Vec<String> = fx
        .calls()
        .into_iter()
        .filter(|c| c.starts_with("chown "))
        .collect();
    assert_eq!(chowns, fx.expand("chown 1000:1000 {home}/eli"));
    let home = fx.layout.home.join("eli");
    assert_eq!(mode(&home), 0o700);
    assert_eq!(
        fs::read_dir(&home).unwrap().count(),
        0,
        "tmpfiles makes the rest"
    );
}

#[test]
fn bootstrap_keeps_an_existing_home_and_refuses_a_symlink() {
    let fx = Fixture::fresh();
    mkdir(&fx.layout.home.join("eli"));
    fx.run().unwrap();
    assert!(!fx.calls().iter().any(|c| c.starts_with("chown ")));

    let fx = Fixture::fresh();
    symlink("/etc", fx.layout.home.join("eli")).unwrap();
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::RenderEtc);
    assert_eq!(
        err.detail,
        format!(
            "{}: exists and is not a directory",
            fx.layout.home.join("eli").display()
        )
    );
}

#[test]
fn services_follow_the_manifest_plus_core_units() {
    let fx = Fixture::booted();
    fx.run().unwrap();
    assert_eq!(
        span(&fx, "systemctl", "systemctl --root={cand} mask"),
        fx.expand(
            "
            systemctl --root={cand} enable NetworkManager.service aios-health.service fwupd-refresh.timer
            systemctl --root={cand} disable bluetooth.service
            systemctl --root={cand} mask sshd.socket
            "
        )
    );
}

#[test]
fn masked_units_are_unmasked_and_missing_units_are_not_disabled() {
    let fx = Fixture::booted();
    let units = fx.layout.cand.join("etc/systemd/system");
    mkdir(&units);
    symlink("/dev/null", units.join("NetworkManager.service")).unwrap();
    fs::remove_file(
        fx.layout
            .cand
            .join("usr/lib/systemd/system/bluetooth.service"),
    )
    .unwrap();
    fx.run().unwrap();
    assert_eq!(
        span(&fx, "systemctl", "systemctl --root={cand} mask"),
        fx.expand(
            "
            systemctl --root={cand} unmask NetworkManager.service
            systemctl --root={cand} enable NetworkManager.service aios-health.service fwupd-refresh.timer
            systemctl --root={cand} mask sshd.socket
            "
        )
    );
}

#[test]
fn bootstrap_pacstraps_with_a_rewritten_conf_and_inits_the_keyring() {
    let fx = Fixture::fresh();
    fx.run().unwrap();
    assert_eq!(
        span(&fx, "pacstrap", "arch-chroot {cand} pacman-key --populate"),
        fx.expand(
            "
            pacstrap -C {run}/aios-pacstrap.conf {cand} {set}
            arch-chroot {cand} pacman-key --init
            arch-chroot {cand} pacman-key --populate archlinux cachyos
            "
        )
    );
    let conf = fs::read_to_string(fx.dir.path().join("aios-pacstrap.conf")).unwrap();
    assert!(
        !conf.contains("DBPath") && !conf.contains("LogFile"),
        "{conf}"
    );
    let repo = format!(
        "Server = file://{}/persist/aios/repo\n",
        fx.layout.cand.display()
    );
    assert!(conf.contains(&repo), "{conf}");
    assert!(conf.contains("CacheDir     = /var/cache/pacman/pkg/\n"));
    assert!(fx.layout.cand.join("usr/lib/pacman").is_dir());
    let meta = fs::read_to_string(fx.layout.cand.join("etc/aios/generation.toml")).unwrap();
    let meta = GenerationMeta::from_toml(&meta).unwrap();
    assert_eq!((meta.id, meta.parent), (1, 0));
}

#[test]
fn bootstrap_needs_a_pacman_conf_source() {
    let mut fx = Fixture::fresh();
    fx.set_manifest(&MANIFEST.replace(
        "\"/etc/pacman.conf\" = { source = \"files/pacman.conf\" }\n",
        "",
    ));
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::Packages);
    assert_eq!(
        err.detail,
        "bootstrap needs a [files] \"/etc/pacman.conf\" entry with a source"
    );
    assert_eq!(
        fx.calls().last().unwrap(),
        "btrfs subvolume delete --recursive {top}/@root-cand"
    );
}

#[test]
fn a_failed_upgrade_cleans_up() {
    let mut fx = Fixture::booted();
    let cand = fx.layout.cand.display().to_string();
    fx.runner.fail_on(&["arch-chroot", &cand, "pacman", "-Syu"]);
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::Packages);
    assert_eq!(
        fx.calls_after("arch-chroot {cand} pacman -Syu"),
        fx.expand(CLEANUP_MOUNTED)
    );
    fx.assert_no_candidates();
}

#[test]
fn a_failed_keyring_cleans_up_without_unmounting_the_target() {
    let mut fx = Fixture::fresh();
    let cand = fx.layout.cand.display().to_string();
    fx.runner
        .fail_on(&["arch-chroot", &cand, "pacman-key", "--init"]);
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::Keyring);
    let mut expected = fx.expand(CLEANUP_MOUNTED);
    expected.pop();
    assert_eq!(
        fx.calls_after("arch-chroot {cand} pacman-key --init"),
        expected
    );
    fx.assert_no_candidates();
}

#[test]
fn a_failed_render_cleans_up() {
    let mut fx = Fixture::booted();
    let cand = fx.layout.cand.display().to_string();
    fx.runner.fail_on(&["arch-chroot", &cand, "locale-gen"]);
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::RenderEtc);
    assert_eq!(
        fx.calls_after("arch-chroot {cand} locale-gen"),
        fx.expand(CLEANUP_MOUNTED)
    );
}

#[test]
fn a_failed_service_call_cleans_up() {
    let mut fx = Fixture::booted();
    fx.runner.fail_on(&["systemctl"]);
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::Services);
    assert_eq!(fx.calls_after("systemctl"), fx.expand(CLEANUP_MOUNTED));
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd aios-cli && cargo test -p aios-exec --test apply_build`
Expected: `test result: FAILED. 3 passed; 15 failed`.
- The file compiles against Task 5's API. `apply()` still stops after `assemble`, so every assertion about packages, `/etc`, services or bootstrap output fails.
- The three that pass only assert that something does *not* happen: `nothing_to_remove_means_no_removal_calls`, `c_utf8_needs_no_locale_gen` and `apply_never_touches_home`.

Run: `cd aios-cli && cargo test -p aios-exec --test etcfs`
Expected: compile error `unresolved import aios_exec::etcfs`.

- [ ] **Step 3: Implement `etcfs.rs`**

`aios-cli/crates/aios-exec/src/etcfs.rs`:
```rust
//! Writes into a candidate's `/etc` that never follow a symlink out of it. Paths are given
//! as `/etc/...` and resolved below `etc_root`.

use crate::ExecError;
use aios_plan::EtcEntry;
use std::fs::{self, OpenOptions, Permissions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Replace `path` with `entry`. Missing parent directories are created (0755). An existing
/// file or symlink at `path` is removed first, never written through.
pub fn write(etc_root: &Path, path: &str, entry: &EtcEntry) -> Result<(), ExecError> {
    let full = parents(etc_root, path, true)?.expect("parents are created");
    match fs::symlink_metadata(&full) {
        Ok(meta) if meta.is_dir() => {
            return Err(ExecError(format!("{}: is a directory", full.display())))
        }
        Ok(_) => fs::remove_file(&full).map_err(|e| ExecError::io(&full, e))?,
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(ExecError::io(&full, e)),
    }
    let io = |e: std::io::Error| ExecError::io(&full, e);
    match entry {
        EtcEntry::File { content, mode } => {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&full)
                .map_err(io)?;
            file.write_all(content).map_err(io)?;
            fs::set_permissions(&full, Permissions::from_mode(*mode)).map_err(io)?;
        }
        EtcEntry::Symlink(target) => symlink(target, &full).map_err(io)?,
    }
    Ok(())
}

/// Remove the file or symlink at `path`, if there is one.
pub fn remove(etc_root: &Path, path: &str) -> Result<(), ExecError> {
    let Some(full) = parents(etc_root, path, false)? else {
        return Ok(());
    };
    match fs::symlink_metadata(&full) {
        Ok(meta) if meta.is_dir() => Err(ExecError(format!("{}: is a directory", full.display()))),
        Ok(_) => fs::remove_file(&full).map_err(|e| ExecError::io(&full, e)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(ExecError::io(&full, e)),
    }
}

/// `mkdir -p` of `path` itself (0755 for new directories).
pub fn create_dirs(etc_root: &Path, path: &str) -> Result<(), ExecError> {
    let full = parents(etc_root, path, true)?.expect("parents are created");
    ensure_dir(&full, true).map(drop)
}

/// Check (and with `create`, make) every parent of `path` below `etc_root`. Returns the full
/// path, or `None` when a parent is missing and `create` is false.
fn parents(etc_root: &Path, path: &str, create: bool) -> Result<Option<PathBuf>, ExecError> {
    let rel = path
        .strip_prefix("/etc/")
        .filter(|rel| rel.split('/').all(|c| !matches!(c, "" | "." | "..")))
        .ok_or_else(|| ExecError(format!("{path}: not a path below /etc")))?;
    let mut full = etc_root.to_path_buf();
    let parts: Vec<&str> = rel.split('/').collect();
    for part in &parts[..parts.len() - 1] {
        full.push(part);
        if !ensure_dir(&full, create)? {
            return Ok(None);
        }
    }
    full.push(parts[parts.len() - 1]);
    Ok(Some(full))
}

/// `dir` is a real directory: `Ok(true)`. Missing: created when `create` (then `true`),
/// else `Ok(false)`. A symlink or any other file is an error.
fn ensure_dir(dir: &Path, create: bool) -> Result<bool, ExecError> {
    match fs::symlink_metadata(dir) {
        Ok(meta) if meta.file_type().is_symlink() => Err(ExecError(format!(
            "{}: is a symlink; refusing to follow it",
            dir.display()
        ))),
        Ok(meta) if meta.is_dir() => Ok(true),
        Ok(_) => Err(ExecError(format!("{}: is not a directory", dir.display()))),
        Err(e) if e.kind() == ErrorKind::NotFound && create => {
            let io = |e: std::io::Error| ExecError::io(dir, e);
            fs::create_dir(dir).map_err(io)?;
            fs::set_permissions(dir, Permissions::from_mode(0o755)).map_err(io)?;
            Ok(true)
        }
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(e) => Err(ExecError::io(dir, e)),
    }
}
```

- [ ] **Step 4: Implement the three steps**

`aios-cli/crates/aios-exec/src/apply/packages.rs`:
```rust
use super::{lines, mkdir, Mode, Run};
use crate::{run_ok, status_error, Cmd, ExecError, Layout};
use std::fs;
use std::path::{Path, PathBuf};

impl Run<'_> {
    /// Apply: full upgrade to the package set, remove what left it, mark the set explicit,
    /// remove orphans. Bootstrap: `pacstrap` the set into the empty candidate.
    pub(super) fn packages(&mut self) -> Result<(), ExecError> {
        let set = self.ctx.manifest.package_set();
        match self.ctx.mode {
            Mode::Apply { .. } => self.upgrade(&set),
            Mode::Bootstrap => self.pacstrap(&set),
        }
    }

    fn upgrade(&self, set: &[String]) -> Result<(), ExecError> {
        self.chroot(&["pacman", "-Syu", "--needed", "--noconfirm"], set)?;
        let explicit = lines(&self.chroot(&["pacman", "-Qqe"], &[])?.stdout_text());
        let removed: Vec<String> = explicit.into_iter().filter(|p| !set.contains(p)).collect();
        if !removed.is_empty() {
            self.chroot(&["pacman", "-Rns", "--noconfirm"], &removed)?;
        }
        self.chroot(&["pacman", "-D", "--asexplicit"], set)?;
        let orphans = self.orphans()?;
        if !orphans.is_empty() {
            self.chroot(&["pacman", "-Rns", "--noconfirm"], &orphans)?;
        }
        Ok(())
    }

    /// `pacman -Qdtq`, which exits 1 when there are none.
    fn orphans(&self) -> Result<Vec<String>, ExecError> {
        let cmd = self.chroot_cmd(&["pacman", "-Qdtq"]);
        let out = self.ctx.runner.run(&cmd)?;
        match out.status {
            0 => Ok(lines(&out.stdout_text())),
            1 if out.stdout.is_empty() => Ok(Vec::new()),
            _ => Err(status_error(&cmd, &out)),
        }
    }

    fn pacstrap(&self, set: &[String]) -> Result<(), ExecError> {
        let l = self.ctx.layout;
        let conf = pacstrap_conf_path(l);
        let text = pacstrap_conf(&self.manifest_pacman_conf()?, &l.cand);
        fs::write(&conf, text).map_err(|e| ExecError::io(&conf, e))?;
        // `var/lib/pacman` (from @blank) links to `../../usr/lib/pacman`; pacstrap's
        // `mkdir -p` fails on a dangling link.
        mkdir(&l.cand.join("usr/lib/pacman"))?;
        let cmd = Cmd::new("pacstrap")
            .arg("-C")
            .arg_path(&conf)
            .arg_path(&l.cand);
        run_ok(self.ctx.runner, &cmd.args(set.iter().cloned())).map(drop)
    }

    fn manifest_pacman_conf(&self) -> Result<String, ExecError> {
        let source = self
            .ctx
            .manifest
            .files
            .get("/etc/pacman.conf")
            .and_then(|entry| entry.source.as_ref())
            .ok_or_else(|| {
                ExecError::new("bootstrap needs a [files] \"/etc/pacman.conf\" entry with a source")
            })?;
        let path = self.ctx.layout.config.join(source);
        fs::read_to_string(&path).map_err(|e| ExecError::io(&path, e))
    }

    /// Bootstrap only: a fresh keyring in the new root, trusting Arch and CachyOS.
    pub(super) fn keyring(&mut self) -> Result<(), ExecError> {
        self.chroot(&["pacman-key", "--init"], &[])?;
        self.chroot(&["pacman-key", "--populate", "archlinux", "cachyos"], &[])?;
        Ok(())
    }
}

/// Next to the candidate mount point, e.g. `/run/aios/aios-pacstrap.conf`. It is left in
/// place (tmpfs) for inspection.
fn pacstrap_conf_path(l: &Layout) -> PathBuf {
    l.cand.with_file_name("aios-pacstrap.conf")
}

/// The manifest's `pacman.conf` for the host-side `pacstrap`:
/// - `DBPath` and `LogFile` are dropped, so both default to paths inside the new root
///   (`var/lib/pacman` there links into `/usr`, spec §2);
/// - `file:///persist/` servers point at the candidate's bind of the local repo, since the
///   installer host has no `/persist`.
fn pacstrap_conf(text: &str, cand: &Path) -> String {
    let repo = format!("file://{}/persist/", cand.display());
    text.lines()
        .filter(|line| {
            let key = line.split('=').next().unwrap_or("").trim();
            key != "DBPath" && key != "LogFile"
        })
        .map(|line| format!("{}\n", line.replace("file:///persist/", &repo)))
        .collect()
}
```

`aios-cli/crates/aios-exec/src/apply/etc.rs`:
```rust
use super::{lines, mkdir, Mode, Run};
use crate::{days_since_epoch, etcfs, read_etc_entry, read_hashes, rfc3339_utc, run_ok};
use crate::{sha256_hex, Cmd, DirProbe, ExecError};
use aios_gen::GenerationMeta;
use aios_plan::{desired_etc, EtcEntry, Inputs, GENERATION_TOML, MANAGED_FILES};
use aios_render::{home_binds, parse_managed_list, persist_dirs};
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

impl Run<'_> {
    /// Spec §4.3 steps 5–6: write the desired `/etc` (files, generated config, merged
    /// accounts, home bind sources) into `@etc-cand`, drop paths the previous generation
    /// managed and this one doesn't, write `generation.toml`, run `locale-gen`, apply
    /// `[files]` owners, and create the persist directories the binds need (plus, for
    /// bootstrap, the home directories).
    pub(super) fn render_etc(&mut self) -> Result<(), ExecError> {
        let (runner, l, m) = (self.ctx.runner, self.ctx.layout, self.ctx.manifest);
        let etc = l.cand.join("etc");
        let render = self.ctx.facts.render_ctx(self.gen)?;
        let hashes = read_hashes(l, m)?;
        let inputs = Inputs {
            manifest: m,
            repo_root: &l.config,
            ctx: &render,
            hashes: &hashes,
            today_days: days_since_epoch(self.ctx.now),
        };
        let probe = DirProbe::new(&etc, runner, Some(l.cand.clone()));
        let desired = desired_etc(&inputs, &probe).map_err(|e| ExecError(e.to_string()))?;

        let previous = read_etc_entry(&etc, MANAGED_FILES).map_err(|e| ExecError(e.0))?;
        if let Some(EtcEntry::File { content, .. }) = previous {
            let old = parse_managed_list(&String::from_utf8_lossy(&content))
                .map_err(|e| ExecError(format!("{MANAGED_FILES}: {e}")))?;
            for path in old {
                if !desired.contains_key(&path) {
                    etcfs::remove(&etc, &path)?;
                }
            }
        }
        for (path, entry) in &desired {
            etcfs::write(&etc, path, entry)?;
        }
        for bind in home_binds(m).iter().filter(|b| b.is_dir) {
            etcfs::create_dirs(&etc, &bind.bind_source)?;
        }
        self.write_generation_toml(&etc)?;

        if desired.contains_key("/etc/locale.gen") {
            self.chroot(&["locale-gen"], &[])?;
        }
        for (path, file) in &m.files {
            let (owner, group) = (file.owner_or_default(), file.group_or_default());
            if owner != "root" || group != "root" {
                let spec = format!("{owner}:{group}");
                self.chroot(&["chown", "-h", &spec, path], &[])?;
            }
        }
        for dir in persist_dirs(m) {
            mkdir(&l.persist_path(&dir))?;
        }
        if self.ctx.mode == Mode::Bootstrap {
            self.home_dirs()?;
        }
        Ok(())
    }

    fn write_generation_toml(&self, etc: &Path) -> Result<(), ExecError> {
        let m = self.ctx.manifest;
        let kernels: Vec<String> = std::iter::once(m.kernel.default.clone())
            .chain(m.kernel.fallback.clone())
            .collect();
        let versions = self.chroot(&["pacman", "-Q"], &kernels)?;
        let mut packages = lines(&self.chroot(&["pacman", "-Qq"], &[])?.stdout_text());
        packages.sort();
        let listing: String = packages.iter().map(|p| format!("{p}\n")).collect();
        let meta = GenerationMeta {
            id: self.gen.get(),
            parent: match self.ctx.mode {
                Mode::Apply { booted } => booted.get(),
                Mode::Bootstrap => 0,
            },
            created: rfc3339_utc(self.ctx.now),
            manifest_commit: self.manifest_commit.clone(),
            kernels: lines(&versions.stdout_text()),
            package_set_sha256: sha256_hex(listing.as_bytes()),
        };
        let entry = EtcEntry::File {
            content: meta.to_toml().into_bytes(),
            mode: 0o644,
        };
        etcfs::write(etc, GENERATION_TOML, &entry)
    }

    /// Bootstrap only: `/home/<user>` (0700, chowned to `uid:uid`) on the new `@home`.
    /// Apply never touches `/home`: the `aios-home.conf` `d` lines fix ownership at boot
    /// and systemd creates the bind mount points itself.
    fn home_dirs(&self) -> Result<(), ExecError> {
        for (name, user) in &self.ctx.manifest.users {
            let home = self.ctx.layout.home.join(name);
            match fs::symlink_metadata(&home) {
                Ok(meta) if meta.file_type().is_symlink() || !meta.is_dir() => {
                    return Err(ExecError(format!(
                        "{}: exists and is not a directory",
                        home.display()
                    )))
                }
                Ok(_) => continue,
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => return Err(ExecError::io(&home, e)),
            }
            let io = |e: std::io::Error| ExecError::io(&home, e);
            fs::create_dir(&home).map_err(io)?;
            fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).map_err(io)?;
            let owner = format!("{0}:{0}", user.uid);
            run_ok(
                self.ctx.runner,
                &Cmd::new("chown").arg(owner).arg_path(&home),
            )?;
        }
        Ok(())
    }
}
```

`aios-cli/crates/aios-exec/src/apply/services.rs`:
```rust
use super::Run;
use crate::{run_ok, unit_file_name, Cmd, ExecError};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// Units AIOS always enables (spec §4.3 step 7). `systemd-bless-boot.service` comes in
/// through `boot-complete.target`.
const CORE_UNITS: &[&str] = &["aios-health.service"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Want {
    Enable,
    Disable,
    Mask,
}

impl Run<'_> {
    /// `systemctl --root=<cand>` with one call per verb. A unit listed twice follows the
    /// planner: mask beats disable beats enable. Units that are masked but now wanted
    /// enabled or disabled are unmasked first, and `disable` skips units with no unit file
    /// (the planner treats them as already disabled).
    pub(super) fn services(&mut self) -> Result<(), ExecError> {
        let s = &self.ctx.manifest.services;
        let cand = &self.ctx.layout.cand;
        let mut wanted = BTreeMap::new();
        for (units, want) in [
            (&s.enable, Want::Enable),
            (&s.disable, Want::Disable),
            (&s.mask, Want::Mask),
        ] {
            for unit in units {
                wanted.insert(unit_file_name(unit), want);
            }
        }
        for unit in CORE_UNITS {
            wanted.insert(unit.to_string(), Want::Enable);
        }
        let select = |keep: &dyn Fn(&str, Want) -> bool| -> Vec<String> {
            wanted
                .iter()
                .filter(|(unit, want)| keep(unit, **want))
                .map(|(unit, _)| unit.clone())
                .collect()
        };
        let calls = [
            (
                "unmask",
                select(&|u, w| w != Want::Mask && is_masked(cand, u)),
            ),
            ("enable", select(&|_, w| w == Want::Enable)),
            (
                "disable",
                select(&|u, w| w == Want::Disable && has_unit_file(cand, u)),
            ),
            ("mask", select(&|_, w| w == Want::Mask)),
        ];
        for (verb, units) in calls {
            if !units.is_empty() {
                let cmd = Cmd::new("systemctl")
                    .arg(format!("--root={}", cand.display()))
                    .arg(verb)
                    .args(units);
                run_ok(self.ctx.runner, &cmd)?;
            }
        }
        Ok(())
    }
}

fn mask_link(path: &Path) -> bool {
    fs::read_link(path).is_ok_and(|target| target == Path::new("/dev/null"))
}

/// `etc/systemd/system/<unit>` is a symlink to `/dev/null`.
fn is_masked(cand: &Path, unit: &str) -> bool {
    mask_link(&cand.join("etc/systemd/system").join(unit))
}

/// The candidate has a unit file for `unit` (or, for `name@instance.type`, its template),
/// not counting mask links.
fn has_unit_file(cand: &Path, unit: &str) -> bool {
    let mut names = vec![unit.to_string()];
    if let Some((name, rest)) = unit.split_once('@') {
        if let Some((_, kind)) = rest.rsplit_once('.') {
            names.push(format!("{name}@.{kind}"));
        }
    }
    names.iter().any(|name| {
        ["etc/systemd/system", "usr/lib/systemd/system"]
            .iter()
            .map(|dir| cand.join(dir).join(name))
            .any(|path| fs::symlink_metadata(&path).is_ok() && !mask_link(&path))
    })
}
```

- [ ] **Step 5: Replace `apply/mod.rs` and `lib.rs`**

`aios-cli/crates/aios-exec/src/apply/mod.rs`:
```rust
//! `aios apply` and `aios bootstrap`: build the next generation in candidate subvolumes
//! (spec §4.3). The booted generation is never modified; any failure deletes the
//! candidates again.

mod etc;
mod packages;
mod prepare;
mod services;

use crate::{btrfs, run_ok, Cmd, CommandRunner, ExecError, Layout, MachineFacts, Output};
use crate::{Step, StepError};
use aios_gen::GenId;
use aios_manifest::Manifest;
use std::fs;
use std::path::Path;
use std::time::SystemTime;

const USR_CAND: &str = "@usr-cand";
const ETC_CAND: &str = "@etc-cand";
const ROOT_CAND: &str = "@root-cand";
const CANDIDATES: [&str; 3] = [USR_CAND, ETC_CAND, ROOT_CAND];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// `aios apply`: snapshot the booted generation, `pacman -Syu`, then clear the
    /// `bootctl set-default` override so the new generation boots next.
    Apply { booted: GenId },
    /// `aios bootstrap` (installer): the top level is already mounted at `layout.top`;
    /// empty candidates, `pacstrap`, a fresh keyring, gen-1. No `bootctl` call.
    Bootstrap,
}

/// Everything one apply needs.
pub struct ApplyCtx<'a> {
    pub runner: &'a dyn CommandRunner,
    pub layout: &'a Layout,
    pub manifest: &'a Manifest,
    pub facts: &'a MachineFacts,
    /// Clock for `generation.toml` (`created`) and shadow `lastchg`.
    pub now: SystemTime,
    /// Required owner of the manifest repo and secrets directory: 0 in production.
    pub trusted_uid: u32,
    pub mode: Mode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyOutcome {
    pub gen: GenId,
    pub manifest_commit: String,
}

/// Build the next generation. On error, the candidate tree is unmounted, every candidate
/// subvolume is deleted and the top level is unmounted (best effort, logged to stderr).
pub fn apply(ctx: &ApplyCtx) -> Result<ApplyOutcome, StepError> {
    let mut run = Run {
        ctx,
        gen: GenId(0),
        manifest_commit: String::new(),
        top_mounted: false,
        cand_mounted: false,
    };
    match run.steps() {
        Ok(()) => Ok(ApplyOutcome {
            gen: run.gen,
            manifest_commit: run.manifest_commit,
        }),
        Err(e) => {
            run.cleanup();
            Err(e)
        }
    }
}

/// State of one apply, shared by the step implementations in the submodules.
struct Run<'a> {
    ctx: &'a ApplyCtx<'a>,
    /// The generation being built. Set by `mount-top`.
    gen: GenId,
    manifest_commit: String,
    /// We mounted `layout.top` and must unmount it.
    top_mounted: bool,
    /// Something is mounted at `layout.cand`.
    cand_mounted: bool,
}

impl Run<'_> {
    fn steps(&mut self) -> Result<(), StepError> {
        self.step(Step::MountTop, Run::mount_top)?;
        self.step(Step::Validate, Run::validate)?;
        self.step(Step::CommitManifest, Run::commit_manifest)?;
        self.step(Step::PrepareCandidate, Run::prepare_candidate)?;
        self.step(Step::Assemble, Run::assemble)?;
        self.step(Step::Packages, Run::packages)?;
        if self.ctx.mode == Mode::Bootstrap {
            self.step(Step::Keyring, Run::keyring)?;
        }
        self.step(Step::RenderEtc, Run::render_etc)?;
        self.step(Step::Services, Run::services)
    }

    fn step(
        &mut self,
        step: Step,
        f: impl FnOnce(&mut Self) -> Result<(), ExecError>,
    ) -> Result<(), StepError> {
        eprintln!("aios: {step}");
        f(self).map_err(|e| StepError { step, detail: e.0 })
    }

    /// `arch-chroot <cand> ARGS...`
    fn chroot_cmd(&self, args: &[&str]) -> Cmd {
        Cmd::new("arch-chroot")
            .arg_path(&self.ctx.layout.cand)
            .args(args.iter().copied())
    }

    /// Run `arch-chroot <cand> ARGS... MORE...`; a non-zero exit is an error.
    fn chroot(&self, args: &[&str], more: &[String]) -> Result<Output, ExecError> {
        let cmd = self.chroot_cmd(args).args(more.iter().cloned());
        run_ok(self.ctx.runner, &cmd)
    }

    /// Undo everything that is not finalized. Errors are logged, not returned.
    fn cleanup(&mut self) {
        eprintln!("aios: {}", Step::Cleanup);
        let (runner, l) = (self.ctx.runner, self.ctx.layout);
        let report = |what: &str, result: Result<(), ExecError>| {
            if let Err(e) = result {
                eprintln!("aios: cleanup: {what}: {e}");
            }
        };
        if self.cand_mounted {
            report(
                "unmount candidate",
                btrfs::umount_recursive(runner, &l.cand),
            );
        }
        for name in CANDIDATES {
            report(name, btrfs::delete_recursive(runner, &l.subvol(name)));
        }
        if self.top_mounted {
            report("unmount top level", btrfs::umount(runner, &l.top));
        }
    }
}

/// `mkdir -p`.
fn mkdir(path: &Path) -> Result<(), ExecError> {
    fs::create_dir_all(path).map_err(|e| ExecError::io(path, e))
}

/// Non-empty, trimmed lines.
fn lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}
```

`aios-cli/crates/aios-exec/src/lib.rs`:
```rust
//! Everything `aios` does to the running system, behind [`CommandRunner`], so every test
//! runs without root against a [`FakeRunner`] and tempdirs.

mod apply;
pub mod btrfs;
mod error;
pub mod etcfs;
mod facts;
mod layout;
mod probe;
mod runner;
mod steps;
mod sys;
mod trust;

pub use apply::{apply, ApplyCtx, ApplyOutcome, Mode};
pub use error::ExecError;
pub use facts::{read_hashes, MachineFacts};
pub use layout::Layout;
pub use probe::{parse_unit_state, read_etc_entry, DirProbe};
pub use runner::{run_ok, status_error, Cmd, CommandRunner, FakeRunner, Output, RealRunner};
pub use steps::{Step, StepError};
pub use sys::{
    days_since_epoch, luks_uuid_from_cmdline, parse_df_avail, parse_efivar_utf16, rfc3339_utc,
    sha256_hex, unit_file_name,
};
pub use trust::check_trusted_dirs;
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cd aios-cli && cargo test -p aios-exec --test etcfs --test apply_build --test apply_prepare`
Expected: `apply_build`: `test result: ok. 18 passed`; `apply_prepare`: `test result: ok. 14 passed`; `etcfs`: `test result: ok. 7 passed`.

- [ ] **Step 7: Lint**

Run: `make check`
Expected: as in Task 1.

- [ ] **Step 8: Commit**

```bash
cd /home/eli/Development/AIOS
git add aios-cli/
git commit -m "feat(exec): apply packages, keyring, /etc rendering and services"
```

---
### Task 7: Boot state, `rollback` and `gc`

**Files:**
- Create: `aios-cli/crates/aios-exec/src/ops/mod.rs`, `src/ops/boot.rs`, `src/ops/rollback.rs`, `src/ops/gc.rs`
- Modify: `aios-cli/crates/aios-exec/src/lib.rs` (full content below)
- Test: `aios-cli/crates/aios-exec/tests/boot.rs`

This comes before apply part 3 because the `esp-space` step runs `gc`.
- `BootState` reads three things:
  - the booted gen from the cmdline (`gen_from_cmdline`);
  - the `bootctl set-default` override from the `LoaderEntryDefault` efivar, parsed with `UkiName::parse`;
  - the aios UKIs on the ESP.

  `newest` is the newest main-kernel UKI that isn't bad, the one `loader.conf`'s glob picks. `default_gen()` is the override, else `newest`. `bad()` lists generations with an exhausted counter.
- `rollback N` needs N's main-kernel UKI on the ESP (`no boot entry for gen-NNNN` otherwise). It then runs `bootctl set-default <entry id without counter>`.
- `gc` mounts the top level, runs `gc_mounted` and unmounts, even on error. `gc_mounted`:
  - takes the complete generations;
  - protects the booted gen, the override and `newest`. That covers the default even with `--keep 0`, and `gc_select` adds gen-1.
  - Each deleted generation loses its UKIs first, then its subvolumes, so no UKI ever outlives them.

- [ ] **Step 1: Write the failing tests**

`aios-cli/crates/aios-exec/tests/boot.rs`:
```rust
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
    let calls = fx.calls();
    assert_eq!(
        calls[0],
        "mount -t btrfs -o subvolid=5 /dev/mapper/aios {top}"
    );
    assert_eq!(calls.last().unwrap(), "umount {top}");
    assert_eq!(
        calls[1..5],
        fx.expand(
            "
            btrfs subvolume show {top}/@usr-gen-0002
            btrfs subvolume delete --recursive {top}/@usr-gen-0002
            btrfs subvolume show {top}/@etc-gen-0002
            btrfs subvolume delete --recursive {top}/@etc-gen-0002
            "
        )
    );
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd aios-cli && cargo test -p aios-exec --test boot`
Expected: compile error `unresolved import aios_exec::ops`.

- [ ] **Step 3: Implement the modules**

`aios-cli/crates/aios-exec/src/ops/mod.rs`:
```rust
//! The other `aios` commands: rollback and gc.

mod boot;
mod gc;
mod rollback;

pub use boot::{read_ukis, BootState, EspUki};
pub use gc::{gc, gc_mounted};
pub use rollback::rollback;

use crate::{btrfs, CommandRunner, ExecError, Layout};

/// Mount the top level, run `f`, and unmount again whether or not `f` succeeded.
fn with_top<T>(
    runner: &dyn CommandRunner,
    layout: &Layout,
    read_only: bool,
    f: impl FnOnce() -> Result<T, ExecError>,
) -> Result<T, ExecError> {
    btrfs::mount_top(runner, &layout.device, &layout.top, read_only)?;
    let result = f();
    let unmounted = btrfs::umount(runner, &layout.top);
    let value = result?;
    unmounted?;
    Ok(value)
}
```

`aios-cli/crates/aios-exec/src/ops/boot.rs`:
```rust
use crate::{parse_efivar_utf16, ExecError, Layout};
use aios_gen::{gen_from_cmdline, Flavor, GenId, UkiName};
use std::fs;
use std::io::ErrorKind;
use std::path::Path;

/// One UKI on the ESP: its file name and what it parses to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EspUki {
    pub file: String,
    pub name: UkiName,
}

/// What booted and what will boot next, from the cmdline, the ESP and the EFI variables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootState {
    /// `aios.gen=` of the running kernel.
    pub booted: Option<GenId>,
    /// The `bootctl set-default` override (`LoaderEntryDefault`), if it names an aios UKI.
    pub default_override: Option<GenId>,
    /// Newest generation with a main-kernel UKI that isn't bad: what `loader.conf` picks.
    pub newest: Option<GenId>,
    /// Every aios UKI on the ESP, by file name.
    pub ukis: Vec<EspUki>,
}

impl BootState {
    pub fn read(layout: &Layout) -> Result<BootState, ExecError> {
        let booted = fs::read_to_string(&layout.proc_cmdline)
            .ok()
            .and_then(|cmdline| gen_from_cmdline(&cmdline));
        let default_override = fs::read(layout.loader_entry_default())
            .ok()
            .and_then(|bytes| parse_efivar_utf16(&bytes))
            .and_then(|entry| UkiName::parse(&entry))
            .map(|uki| uki.gen);
        let ukis = read_ukis(&layout.uki_dir())?;
        let newest = ukis
            .iter()
            .filter(|u| u.name.flavor == Flavor::Main && !u.name.is_bad())
            .map(|u| u.name.gen)
            .max();
        Ok(BootState {
            booted,
            default_override,
            newest,
            ukis,
        })
    }

    /// The generation the next boot picks: the override, else the newest good one.
    pub fn default_gen(&self) -> Option<GenId> {
        self.default_override.or(self.newest)
    }

    /// Generations with a UKI whose boot counter ran out, ascending.
    pub fn bad(&self) -> Vec<GenId> {
        let mut bad: Vec<GenId> = self
            .ukis
            .iter()
            .filter(|u| u.name.is_bad())
            .map(|u| u.name.gen)
            .collect();
        bad.sort();
        bad.dedup();
        bad
    }
}

/// The aios UKIs in `dir`, sorted by file name. A missing directory has none.
pub fn read_ukis(dir: &Path) -> Result<Vec<EspUki>, ExecError> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(ExecError::io(dir, e)),
    };
    let mut ukis = Vec::new();
    for entry in entries {
        let file = entry
            .map_err(|e| ExecError::io(dir, e))?
            .file_name()
            .to_string_lossy()
            .into_owned();
        if let Some(name) = UkiName::parse(&file) {
            ukis.push(EspUki { file, name });
        }
    }
    ukis.sort_by(|a, b| a.file.cmp(&b.file));
    Ok(ukis)
}
```

`aios-cli/crates/aios-exec/src/ops/rollback.rs`:
```rust
use super::read_ukis;
use crate::{run_ok, Cmd, CommandRunner, ExecError, Layout};
use aios_gen::{Flavor, GenId};

/// Make generation `gen` the default boot entry (`bootctl set-default`, spec §4.2). Needs
/// its main-kernel UKI on the ESP. Returns the entry id. No subvolume is touched.
pub fn rollback(
    runner: &dyn CommandRunner,
    layout: &Layout,
    gen: GenId,
) -> Result<String, ExecError> {
    let entry = read_ukis(&layout.uki_dir())?
        .into_iter()
        .find(|u| u.name.gen == gen && u.name.flavor == Flavor::Main)
        .map(|u| u.name.entry_id())
        .ok_or_else(|| ExecError(format!("no boot entry for gen-{gen}")))?;
    run_ok(runner, &Cmd::new("bootctl").args(["set-default", &entry]))?;
    Ok(entry)
}
```

`aios-cli/crates/aios-exec/src/ops/gc.rs`:
```rust
use super::{with_top, BootState};
use crate::{btrfs, CommandRunner, ExecError, Layout};
use aios_gen::{gc_select, list_complete, GenId};
use std::fs;

/// `aios gc`: mount the top level, delete old generations, unmount.
pub fn gc(
    runner: &dyn CommandRunner,
    layout: &Layout,
    keep: usize,
) -> Result<Vec<GenId>, ExecError> {
    with_top(runner, layout, false, || gc_mounted(runner, layout, keep))
}

/// Delete generations beyond the newest `keep`, never the booted one, the default (the
/// `bootctl` override and the newest good one) or gen-1. A generation's UKIs go first, then
/// its subvolumes, so no UKI outlives them. Needs the top level mounted. Returns the
/// deleted ids, ascending.
pub fn gc_mounted(
    runner: &dyn CommandRunner,
    layout: &Layout,
    keep: usize,
) -> Result<Vec<GenId>, ExecError> {
    let state = BootState::read(layout)?;
    let gens = list_complete(&btrfs::list_names(&layout.top)?);
    let protected: Vec<GenId> = [state.booted, state.default_override, state.newest]
        .into_iter()
        .flatten()
        .collect();
    let doomed = gc_select(&gens, keep, &protected);
    for gen in &doomed {
        for uki in state.ukis.iter().filter(|u| u.name.gen == *gen) {
            let path = layout.uki_dir().join(&uki.file);
            fs::remove_file(&path).map_err(|e| ExecError::io(&path, e))?;
        }
        for subvol in [gen.usr_subvol(), gen.etc_subvol()] {
            btrfs::delete_recursive(runner, &layout.subvol(&subvol))?;
        }
    }
    Ok(doomed)
}
```

- [ ] **Step 4: Replace `lib.rs`**

This is its final content.

`aios-cli/crates/aios-exec/src/lib.rs`:
```rust
//! Everything `aios` does to the running system, behind [`CommandRunner`], so every test
//! runs without root against a [`FakeRunner`] and tempdirs.

mod apply;
pub mod btrfs;
mod error;
pub mod etcfs;
mod facts;
mod layout;
pub mod ops;
mod probe;
mod runner;
mod steps;
mod sys;
mod trust;

pub use apply::{apply, ApplyCtx, ApplyOutcome, Mode};
pub use error::ExecError;
pub use facts::{read_hashes, MachineFacts};
pub use layout::Layout;
pub use probe::{parse_unit_state, read_etc_entry, DirProbe};
pub use runner::{run_ok, status_error, Cmd, CommandRunner, FakeRunner, Output, RealRunner};
pub use steps::{Step, StepError};
pub use sys::{
    days_since_epoch, luks_uuid_from_cmdline, parse_df_avail, parse_efivar_utf16, rfc3339_utc,
    sha256_hex, unit_file_name,
};
pub use trust::check_trusted_dirs;
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd aios-cli && cargo test -p aios-exec --test boot`
Expected: `test result: ok. 8 passed`.

- [ ] **Step 6: Lint**

Run: `make check`
Expected: as in Task 1.

- [ ] **Step 7: Commit**

```bash
cd /home/eli/Development/AIOS
git add aios-cli/
git commit -m "feat(exec): boot state, rollback and gc"
```

---
### Task 8: Apply part 3: UKIs, signing, ESP space, finalize, and the golden sequences

**Files:**
- Create: `aios-cli/crates/aios-exec/src/apply/uki.rs`, `aios-cli/crates/aios-exec/src/apply/finalize.rs`
- Modify: `aios-cli/crates/aios-exec/src/apply/mod.rs` (final content below)
- Test: `aios-cli/crates/aios-exec/tests/apply_golden.rs`

The last steps:
10. **uki:** for the default kernel (`Flavor::Main`) and the optional fallback (`Flavor::Fallback`):
    - The version is the `cand/usr/lib/modules/*` directory whose `pkgbase` names the kernel. None or several is an error.
    - `arch-chroot CAND mkinitcpio -k VER -g /var/tmp/aios/initramfs-<token>.img`.
    - `arch-chroot CAND ukify build --linux=/usr/lib/modules/VER/vmlinuz --initrd=… --cmdline=@/etc/kernel/cmdline --os-release=@/usr/lib/os-release --output=/var/tmp/aios/<entry id>`.
    - Microcode is embedded by mkinitcpio's `microcode` hook, so there is no separate `--initrd`.
11. **sign:** `sbctl sign CAND/var/tmp/aios/<entry id>` for each UKI, on the host, with the persisted keys. There is no `sbctl verify` (documented deviation; e2e covers it).
12. **esp-space:**
    - Stale `aios-gen-*.efi.tmp` copies are removed first.
    - Then `df --output=avail -B1 ESP` must show at least ⌈1.2 × total UKI size⌉. If not, `gc_mounted` runs (keep 5, since the top level is already mounted) and the check repeats; still short is an error.
13. **finalize:**
    - Copy each UKI to `ESP/EFI/Linux/<file name>.tmp` (synced, no permission bits; the ESP is FAT). Systemd-boot ignores `.tmp`.
    - `umount -R cand`.
    - `btrfs property set -ts … ro true` on `@usr-cand` and `@etc-cand`.
    - Rename both to `@usr-gen-NNNN`/`@etc-gen-NNNN`.
    - Rename the ESP copies to their real names (`…+3.efi`).
    - Apply only: `bootctl set-default ''`.
    - `delete_recursive` `@root-cand`.
    - Apply only: `umount top`.

    The UKIs live in the candidate tree, which the unmount takes away, so they are copied first. They get their real names only after the subvolume renames, so a bootable UKI never exists without its subvolumes (spec §4.3 crash safety). The cleanup guard also removes any `.tmp` copy this run made.

- [ ] **Step 1: Write the failing tests**

`aios-cli/crates/aios-exec/tests/apply_golden.rs`:
```rust
mod common;

use aios_exec::{Output, Step};
use common::{mkdir, write, Fixture, CLEANUP_MOUNTED, MANIFEST};
use std::fs;

const APPLY: &str = "
mount -t btrfs -o subvolid=5 /dev/mapper/aios {top}
git -C {config} status --porcelain
git -C {config} rev-parse --short HEAD
btrfs subvolume snapshot {top}/@usr-gen-0007 {top}/@usr-cand
btrfs subvolume snapshot {top}/@etc-gen-0007 {top}/@etc-cand
btrfs subvolume snapshot {top}/@blank {top}/@root-cand
mount --bind {top}/@root-cand {cand}
mount --bind {top}/@usr-cand {cand}/usr
mount --bind {top}/@etc-cand {cand}/etc
mount --bind {persist}/var/cache/pacman/pkg {cand}/var/cache/pacman/pkg
mount --bind {log} {cand}/var/log
mount --bind {persist}/aios/repo {cand}/persist/aios/repo
arch-chroot {cand} pacman -Syu --needed --noconfirm {set}
arch-chroot {cand} pacman -Qqe
arch-chroot {cand} pacman -Rns --noconfirm nano
arch-chroot {cand} pacman -D --asexplicit {set}
arch-chroot {cand} pacman -Qdtq
arch-chroot {cand} pacman -Rns --noconfirm libnano
arch-chroot {cand} pacman -Q linux-cachyos linux-cachyos-lts
arch-chroot {cand} pacman -Qq
arch-chroot {cand} locale-gen
arch-chroot {cand} chown -h root:wheel /etc/usbguard/usbguard-daemon.conf
systemctl --root={cand} enable NetworkManager.service aios-health.service fwupd-refresh.timer
systemctl --root={cand} disable bluetooth.service
systemctl --root={cand} mask sshd.socket
arch-chroot {cand} mkinitcpio -k 7.3.0-4-cachyos -g /var/tmp/aios/initramfs-cachyos.img
arch-chroot {cand} ukify build --linux=/usr/lib/modules/7.3.0-4-cachyos/vmlinuz --initrd=/var/tmp/aios/initramfs-cachyos.img --cmdline=@/etc/kernel/cmdline --os-release=@/usr/lib/os-release --output=/var/tmp/aios/aios-gen-0008-cachyos.efi
arch-chroot {cand} mkinitcpio -k 6.18.55-2-cachyos-lts -g /var/tmp/aios/initramfs-lts.img
arch-chroot {cand} ukify build --linux=/usr/lib/modules/6.18.55-2-cachyos-lts/vmlinuz --initrd=/var/tmp/aios/initramfs-lts.img --cmdline=@/etc/kernel/cmdline --os-release=@/usr/lib/os-release --output=/var/tmp/aios/aios-gen-0008-lts.efi
sbctl sign {cand}/var/tmp/aios/aios-gen-0008-cachyos.efi
sbctl sign {cand}/var/tmp/aios/aios-gen-0008-lts.efi
df --output=avail -B1 {esp}
umount -R {cand}
btrfs property set -ts {top}/@usr-cand ro true
btrfs property set -ts {top}/@etc-cand ro true
bootctl set-default ''
btrfs subvolume show {top}/@root-cand
btrfs subvolume delete --recursive {top}/@root-cand
umount {top}
";

const BOOTSTRAP: &str = "
git -C {config} status --porcelain
git -C {config} rev-parse --short HEAD
btrfs subvolume create {top}/@usr-cand
btrfs subvolume create {top}/@etc-cand
btrfs subvolume snapshot {top}/@blank {top}/@root-cand
mount --bind {top}/@root-cand {cand}
mount --bind {top}/@usr-cand {cand}/usr
mount --bind {top}/@etc-cand {cand}/etc
mount --bind {persist}/var/cache/pacman/pkg {cand}/var/cache/pacman/pkg
mount --bind {log} {cand}/var/log
mount --bind {persist}/aios/repo {cand}/persist/aios/repo
pacstrap -C {run}/aios-pacstrap.conf {cand} {set}
arch-chroot {cand} pacman-key --init
arch-chroot {cand} pacman-key --populate archlinux cachyos
arch-chroot {cand} pacman -Q linux-cachyos linux-cachyos-lts
arch-chroot {cand} pacman -Qq
arch-chroot {cand} locale-gen
arch-chroot {cand} chown -h root:wheel /etc/usbguard/usbguard-daemon.conf
chown 1000:1000 {home}/eli
systemctl --root={cand} enable NetworkManager.service aios-health.service fwupd-refresh.timer
systemctl --root={cand} disable bluetooth.service
systemctl --root={cand} mask sshd.socket
arch-chroot {cand} mkinitcpio -k 7.3.0-4-cachyos -g /var/tmp/aios/initramfs-cachyos.img
arch-chroot {cand} ukify build --linux=/usr/lib/modules/7.3.0-4-cachyos/vmlinuz --initrd=/var/tmp/aios/initramfs-cachyos.img --cmdline=@/etc/kernel/cmdline --os-release=@/usr/lib/os-release --output=/var/tmp/aios/aios-gen-0001-cachyos.efi
arch-chroot {cand} mkinitcpio -k 6.18.55-2-cachyos-lts -g /var/tmp/aios/initramfs-lts.img
arch-chroot {cand} ukify build --linux=/usr/lib/modules/6.18.55-2-cachyos-lts/vmlinuz --initrd=/var/tmp/aios/initramfs-lts.img --cmdline=@/etc/kernel/cmdline --os-release=@/usr/lib/os-release --output=/var/tmp/aios/aios-gen-0001-lts.efi
sbctl sign {cand}/var/tmp/aios/aios-gen-0001-cachyos.efi
sbctl sign {cand}/var/tmp/aios/aios-gen-0001-lts.efi
df --output=avail -B1 {esp}
umount -R {cand}
btrfs property set -ts {top}/@usr-cand ro true
btrfs property set -ts {top}/@etc-cand ro true
btrfs subvolume show {top}/@root-cand
btrfs subvolume delete --recursive {top}/@root-cand
";

fn esp(fx: &Fixture) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(fx.layout.uki_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn golden_apply() {
    let fx = Fixture::booted();
    let outcome = fx.run().unwrap();
    assert_eq!(fx.calls(), fx.expand(APPLY));
    assert_eq!(outcome.gen, aios_gen::GenId(8));
    assert_eq!(
        outcome.ukis,
        ["aios-gen-0008-cachyos+3.efi", "aios-gen-0008-lts+3.efi"]
    );
}

#[test]
fn golden_bootstrap() {
    let fx = Fixture::fresh();
    let outcome = fx.run().unwrap();
    assert_eq!(fx.calls(), fx.expand(BOOTSTRAP));
    assert_eq!(outcome.gen, aios_gen::GenId(1));
}

#[test]
fn the_new_generation_lands_on_disk_and_on_the_esp() {
    let fx = Fixture::booted();
    fx.run().unwrap();
    let l = &fx.layout;
    assert!(l.subvol("@usr-gen-0008").is_dir());
    assert!(l.subvol("@etc-gen-0008").is_dir());
    fx.assert_no_candidates();
    assert_eq!(
        esp(&fx),
        [
            "aios-gen-0006-cachyos.efi",
            "aios-gen-0007-cachyos.efi",
            "aios-gen-0008-cachyos+3.efi",
            "aios-gen-0008-lts+3.efi",
        ]
    );
    let uki = fs::read_to_string(l.uki_dir().join("aios-gen-0008-lts+3.efi")).unwrap();
    assert_eq!(uki, "UKI lts");
}

#[test]
fn bootstrap_on_a_target_with_generations_is_refused() {
    let fx = Fixture::fresh();
    mkdir(&fx.layout.subvol("@usr-gen-0001"));
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::MountTop);
    assert_eq!(
        err.detail,
        format!("{} already holds generations", fx.layout.top.display())
    );
    assert!(fx.calls().is_empty());
}

#[test]
fn without_a_fallback_kernel_one_uki_is_built() {
    let mut fx = Fixture::booted();
    fx.set_manifest(&MANIFEST.replace("fallback = \"linux-cachyos-lts\"\n", ""));
    let outcome = fx.run().unwrap();
    assert_eq!(outcome.ukis, ["aios-gen-0008-cachyos+3.efi"]);
    assert!(fx
        .calls()
        .contains(&"arch-chroot {cand} pacman -Q linux-cachyos".to_string()));
    let ukify = "arch-chroot {cand} ukify";
    assert_eq!(
        fx.calls().iter().filter(|c| c.starts_with(ukify)).count(),
        1
    );
}

#[test]
fn stale_esp_copies_are_removed() {
    let fx = Fixture::booted();
    write(
        &fx.layout.uki_dir().join("aios-gen-0005-cachyos+3.efi.tmp"),
        "x",
        0o644,
    );
    fx.run().unwrap();
    assert!(!esp(&fx).iter().any(|name| name.ends_with(".tmp")));
}

#[test]
fn a_kernel_without_modules_fails_the_uki_step() {
    let fx = Fixture::booted();
    fs::remove_file(
        fx.layout
            .cand
            .join("usr/lib/modules/6.18.55-2-cachyos-lts/pkgbase"),
    )
    .unwrap();
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::Uki);
    assert_eq!(
        err.detail,
        "no /usr/lib/modules/*/pkgbase names linux-cachyos-lts"
    );
}

#[test]
fn a_failed_initramfs_cleans_up() {
    let mut fx = Fixture::booted();
    let cand = fx.layout.cand.display().to_string();
    fx.runner.fail_on(&["arch-chroot", &cand, "mkinitcpio"]);
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::Uki);
    assert_eq!(
        fx.calls_after("arch-chroot {cand} mkinitcpio"),
        fx.expand(CLEANUP_MOUNTED)
    );
    fx.assert_no_candidates();
}

#[test]
fn a_failed_signature_cleans_up_and_leaves_the_esp_alone() {
    let mut fx = Fixture::booted();
    fx.runner.fail_on(&["sbctl"]);
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::Sign);
    assert_eq!(fx.calls_after("sbctl"), fx.expand(CLEANUP_MOUNTED));
    assert_eq!(
        esp(&fx),
        ["aios-gen-0006-cachyos.efi", "aios-gen-0007-cachyos.efi"]
    );
}

#[test]
fn a_full_esp_runs_gc_then_fails() {
    let mut fx = Fixture::booted();
    fx.runner.respond(&["df"], Output::ok("Avail\n10\n"));
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::EspSpace);
    assert_eq!(
        err.detail,
        format!(
            "{} has 10 bytes free, the new UKIs need 22",
            fx.layout.esp.display()
        )
    );
    let mut expected = fx.expand("df --output=avail -B1 {esp}");
    expected.extend(fx.expand(CLEANUP_MOUNTED));
    assert_eq!(
        fx.calls_after("df"),
        expected,
        "gc found nothing old enough to delete"
    );
}

#[test]
fn a_failed_finalize_deletes_the_candidates_and_esp_copies() {
    let mut fx = Fixture::booted();
    fx.runner.fail_on(&["btrfs", "property"]);
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::Finalize);
    let mut expected = fx.expand(CLEANUP_MOUNTED);
    expected.remove(0);
    assert_eq!(fx.calls_after("btrfs property"), expected);
    fx.assert_no_candidates();
    assert_eq!(
        esp(&fx),
        ["aios-gen-0006-cachyos.efi", "aios-gen-0007-cachyos.efi"]
    );
    assert!(!fx.layout.subvol("@usr-gen-0008").exists());
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd aios-cli && cargo test -p aios-exec --test apply_golden`
Expected: compile errors E0609, "no field `ukis` on type `ApplyOutcome`", twice.

- [ ] **Step 3: Implement `uki.rs` and `finalize.rs`**

`aios-cli/crates/aios-exec/src/apply/uki.rs`:
```rust
use super::{mkdir, Run};
use crate::{ops, parse_df_avail, run_ok, Cmd, ExecError};
use aios_gen::{Flavor, UkiName};
use std::collections::BTreeMap;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

/// Where UKIs are built, as seen inside the candidate.
const BUILD_DIR: &str = "/var/tmp/aios";

impl Run<'_> {
    /// Spec §4.3 step 8, for the default kernel (`cachyos`) and the fallback (`lts`): an
    /// initramfs (microcode comes from mkinitcpio's `microcode` hook) and a UKI.
    pub(super) fn uki(&mut self) -> Result<(), ExecError> {
        let (l, m) = (self.ctx.layout, self.ctx.manifest);
        let versions = module_versions(&l.cand.join("usr/lib/modules"))?;
        mkdir(&self.build_dir())?;
        let kernels = std::iter::once((&m.kernel.default, Flavor::Main))
            .chain(m.kernel.fallback.iter().map(|k| (k, Flavor::Fallback)));
        for (kernel, flavor) in kernels {
            let version = match versions.get(kernel.as_str()).map(Vec::as_slice) {
                Some([only]) => only.clone(),
                Some(several) if several.len() > 1 => {
                    return Err(ExecError(format!(
                        "several module directories for {kernel}: {}",
                        several.join(", ")
                    )))
                }
                _ => {
                    return Err(ExecError(format!(
                        "no /usr/lib/modules/*/pkgbase names {kernel}"
                    )))
                }
            };
            let initrd = format!("{BUILD_DIR}/initramfs-{}.img", flavor.token());
            let name = UkiName::fresh(self.gen, flavor);
            self.chroot(&["mkinitcpio", "-k", &version, "-g", &initrd], &[])?;
            self.chroot(
                &[
                    "ukify",
                    "build",
                    &format!("--linux=/usr/lib/modules/{version}/vmlinuz"),
                    &format!("--initrd={initrd}"),
                    "--cmdline=@/etc/kernel/cmdline",
                    "--os-release=@/usr/lib/os-release",
                    &format!("--output={BUILD_DIR}/{}", name.entry_id()),
                ],
                &[],
            )?;
            self.ukis.push(name);
        }
        Ok(())
    }

    fn build_dir(&self) -> PathBuf {
        self.ctx.layout.cand.join(BUILD_DIR.trim_start_matches('/'))
    }

    /// Host path of a UKI built in the candidate.
    pub(super) fn built_uki(&self, name: &UkiName) -> PathBuf {
        self.build_dir().join(name.entry_id())
    }

    /// Sign each UKI on the host with the sbctl keys (spec §4.3 step 9).
    pub(super) fn sign(&mut self) -> Result<(), ExecError> {
        for name in &self.ukis {
            let cmd = Cmd::new("sbctl").arg("sign").arg_path(self.built_uki(name));
            run_ok(self.ctx.runner, &cmd)?;
        }
        Ok(())
    }

    /// The ESP needs 1.2 × the new UKIs' size free. If it doesn't have it, delete old
    /// generations (`gc`, keep 5) and check again (spec §4.3 step 10).
    pub(super) fn esp_space(&mut self) -> Result<(), ExecError> {
        let l = self.ctx.layout;
        remove_stale_copies(&l.uki_dir())?;
        let mut total = 0;
        for name in &self.ukis {
            let path = self.built_uki(name);
            total += fs::metadata(&path)
                .map_err(|e| ExecError::io(&path, e))?
                .len();
        }
        let need = (total * 6).div_ceil(5);
        let mut free = self.esp_free()?;
        if free < need {
            eprintln!("aios: the ESP has {free} bytes free and needs {need}: running gc");
            ops::gc_mounted(self.ctx.runner, l, 5)?;
            free = self.esp_free()?;
        }
        if free < need {
            return Err(ExecError(format!(
                "{} has {free} bytes free, the new UKIs need {need}",
                l.esp.display()
            )));
        }
        Ok(())
    }

    fn esp_free(&self) -> Result<u64, ExecError> {
        let cmd = Cmd::new("df")
            .args(["--output=avail", "-B1"])
            .arg_path(&self.ctx.layout.esp);
        let out = run_ok(self.ctx.runner, &cmd)?;
        parse_df_avail(&out.stdout_text())
            .ok_or_else(|| ExecError(format!("`{cmd}` printed no free space")))
    }
}

/// `pkgbase` -> module directory names, from `/usr/lib/modules/*/pkgbase`.
fn module_versions(dir: &Path) -> Result<BTreeMap<String, Vec<String>>, ExecError> {
    let mut versions: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let entries = fs::read_dir(dir).map_err(|e| ExecError::io(dir, e))?;
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    for name in names {
        let pkgbase = dir.join(&name).join("pkgbase");
        match fs::read_to_string(&pkgbase) {
            Ok(text) => versions
                .entry(text.trim().to_string())
                .or_default()
                .push(name),
            Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => {}
            Err(e) => return Err(ExecError::io(&pkgbase, e)),
        }
    }
    Ok(versions)
}

/// Delete `aios-gen-*.efi.tmp` copies an interrupted finalize left on the ESP.
fn remove_stale_copies(dir: &Path) -> Result<(), ExecError> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(ExecError::io(dir, e)),
    };
    for entry in entries.filter_map(Result::ok) {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("aios-gen-") && name.ends_with(".efi.tmp") {
            let path = entry.path();
            fs::remove_file(&path).map_err(|e| ExecError::io(&path, e))?;
        }
    }
    Ok(())
}
```

`aios-cli/crates/aios-exec/src/apply/finalize.rs`:
```rust
use super::{mkdir, Mode, Run, ETC_CAND, ROOT_CAND, USR_CAND};
use crate::{btrfs, run_ok, Cmd, ExecError};
use std::fs::{self, File};
use std::io;
use std::path::Path;

impl Run<'_> {
    /// Spec §4.3 steps 11–12. The UKIs are first copied to the ESP under a `.tmp` name,
    /// which systemd-boot ignores, because they live in the candidate tree that is unmounted
    /// next. They get their real names only after the subvolume renames, so a bootable UKI
    /// never exists without its subvolumes.
    pub(super) fn finalize(&mut self) -> Result<(), ExecError> {
        let (runner, l) = (self.ctx.runner, self.ctx.layout);
        let uki_dir = l.uki_dir();
        mkdir(&uki_dir)?;
        for name in &self.ukis {
            let tmp = uki_dir.join(format!("{}.tmp", name.file_name()));
            self.esp_tmp.push(tmp.clone());
            copy_synced(&self.built_uki(name), &tmp)?;
        }
        btrfs::umount_recursive(runner, &l.cand)?;
        self.cand_mounted = false;
        for name in [USR_CAND, ETC_CAND] {
            btrfs::set_readonly(runner, &l.subvol(name))?;
        }
        rename(&l.subvol(USR_CAND), &l.subvol(&self.gen.usr_subvol()))?;
        rename(&l.subvol(ETC_CAND), &l.subvol(&self.gen.etc_subvol()))?;
        for tmp in self.esp_tmp.clone() {
            rename(&tmp, &tmp.with_extension(""))?;
        }
        self.esp_tmp.clear();
        if let Mode::Apply { .. } = self.ctx.mode {
            run_ok(runner, &Cmd::new("bootctl").args(["set-default", ""]))?;
        }
        btrfs::delete_recursive(runner, &l.subvol(ROOT_CAND))?;
        if self.top_mounted {
            btrfs::umount(runner, &l.top)?;
            self.top_mounted = false;
        }
        Ok(())
    }
}

fn rename(from: &Path, to: &Path) -> Result<(), ExecError> {
    fs::rename(from, to).map_err(|e| {
        ExecError(format!(
            "rename {} to {}: {e}",
            from.display(),
            to.display()
        ))
    })
}

/// Copy without carrying permission bits (the ESP is FAT) and flush to disk.
fn copy_synced(from: &Path, to: &Path) -> Result<(), ExecError> {
    let mut src = File::open(from).map_err(|e| ExecError::io(from, e))?;
    let mut dst = File::create(to).map_err(|e| ExecError::io(to, e))?;
    io::copy(&mut src, &mut dst).map_err(|e| ExecError::io(to, e))?;
    dst.sync_all().map_err(|e| ExecError::io(to, e))
}
```

- [ ] **Step 4: Replace `apply/mod.rs`**

This is its final content.

`aios-cli/crates/aios-exec/src/apply/mod.rs`:
```rust
//! `aios apply` and `aios bootstrap`: build the next generation in candidate subvolumes
//! (spec §4.3). The booted generation is never modified; any failure deletes the
//! candidates again.

mod etc;
mod finalize;
mod packages;
mod prepare;
mod services;
mod uki;

use crate::{btrfs, run_ok, Cmd, CommandRunner, ExecError, Layout, MachineFacts, Output};
use crate::{Step, StepError};
use aios_gen::{GenId, UkiName};
use aios_manifest::Manifest;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

const USR_CAND: &str = "@usr-cand";
const ETC_CAND: &str = "@etc-cand";
const ROOT_CAND: &str = "@root-cand";
const CANDIDATES: [&str; 3] = [USR_CAND, ETC_CAND, ROOT_CAND];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// `aios apply`: snapshot the booted generation, `pacman -Syu`, then clear the
    /// `bootctl set-default` override so the new generation boots next.
    Apply { booted: GenId },
    /// `aios bootstrap` (installer): the top level is already mounted at `layout.top`;
    /// empty candidates, `pacstrap`, a fresh keyring, gen-1. No `bootctl` call.
    Bootstrap,
}

/// Everything one apply needs.
pub struct ApplyCtx<'a> {
    pub runner: &'a dyn CommandRunner,
    pub layout: &'a Layout,
    pub manifest: &'a Manifest,
    pub facts: &'a MachineFacts,
    /// Clock for `generation.toml` (`created`) and shadow `lastchg`.
    pub now: SystemTime,
    /// Required owner of the manifest repo and secrets directory: 0 in production.
    pub trusted_uid: u32,
    pub mode: Mode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyOutcome {
    pub gen: GenId,
    pub manifest_commit: String,
    /// The UKI file names now on the ESP.
    pub ukis: Vec<String>,
}

/// Build the next generation. On error, the candidate tree is unmounted, every candidate
/// subvolume is deleted and the top level is unmounted (best effort, logged to stderr).
pub fn apply(ctx: &ApplyCtx) -> Result<ApplyOutcome, StepError> {
    let mut run = Run {
        ctx,
        gen: GenId(0),
        manifest_commit: String::new(),
        top_mounted: false,
        cand_mounted: false,
        ukis: Vec::new(),
        esp_tmp: Vec::new(),
    };
    match run.steps() {
        Ok(()) => Ok(ApplyOutcome {
            gen: run.gen,
            manifest_commit: run.manifest_commit,
            ukis: run.ukis.iter().map(UkiName::file_name).collect(),
        }),
        Err(e) => {
            run.cleanup();
            Err(e)
        }
    }
}

/// State of one apply, shared by the step implementations in the submodules.
struct Run<'a> {
    ctx: &'a ApplyCtx<'a>,
    /// The generation being built. Set by `mount-top`.
    gen: GenId,
    manifest_commit: String,
    /// We mounted `layout.top` and must unmount it.
    top_mounted: bool,
    /// Something is mounted at `layout.cand`.
    cand_mounted: bool,
    /// UKIs built in the candidate.
    ukis: Vec<UkiName>,
    /// UKI copies on the ESP not yet renamed into place.
    esp_tmp: Vec<PathBuf>,
}

impl Run<'_> {
    fn steps(&mut self) -> Result<(), StepError> {
        self.step(Step::MountTop, Run::mount_top)?;
        self.step(Step::Validate, Run::validate)?;
        self.step(Step::CommitManifest, Run::commit_manifest)?;
        self.step(Step::PrepareCandidate, Run::prepare_candidate)?;
        self.step(Step::Assemble, Run::assemble)?;
        self.step(Step::Packages, Run::packages)?;
        if self.ctx.mode == Mode::Bootstrap {
            self.step(Step::Keyring, Run::keyring)?;
        }
        self.step(Step::RenderEtc, Run::render_etc)?;
        self.step(Step::Services, Run::services)?;
        self.step(Step::Uki, Run::uki)?;
        self.step(Step::Sign, Run::sign)?;
        self.step(Step::EspSpace, Run::esp_space)?;
        self.step(Step::Finalize, Run::finalize)
    }

    fn step(
        &mut self,
        step: Step,
        f: impl FnOnce(&mut Self) -> Result<(), ExecError>,
    ) -> Result<(), StepError> {
        eprintln!("aios: {step}");
        f(self).map_err(|e| StepError { step, detail: e.0 })
    }

    /// `arch-chroot <cand> ARGS...`
    fn chroot_cmd(&self, args: &[&str]) -> Cmd {
        Cmd::new("arch-chroot")
            .arg_path(&self.ctx.layout.cand)
            .args(args.iter().copied())
    }

    /// Run `arch-chroot <cand> ARGS... MORE...`; a non-zero exit is an error.
    fn chroot(&self, args: &[&str], more: &[String]) -> Result<Output, ExecError> {
        let cmd = self.chroot_cmd(args).args(more.iter().cloned());
        run_ok(self.ctx.runner, &cmd)
    }

    /// Undo everything that is not finalized. Errors are logged, not returned.
    fn cleanup(&mut self) {
        eprintln!("aios: {}", Step::Cleanup);
        let (runner, l) = (self.ctx.runner, self.ctx.layout);
        let report = |what: &str, result: Result<(), ExecError>| {
            if let Err(e) = result {
                eprintln!("aios: cleanup: {what}: {e}");
            }
        };
        if self.cand_mounted {
            report(
                "unmount candidate",
                btrfs::umount_recursive(runner, &l.cand),
            );
        }
        for name in CANDIDATES {
            report(name, btrfs::delete_recursive(runner, &l.subvol(name)));
        }
        for tmp in &self.esp_tmp {
            match fs::remove_file(tmp) {
                Err(e) if e.kind() != ErrorKind::NotFound => {
                    report("ESP", Err(ExecError::io(tmp, e)));
                }
                _ => {}
            }
        }
        if self.top_mounted {
            report("unmount top level", btrfs::umount(runner, &l.top));
        }
    }
}

/// `mkdir -p`.
fn mkdir(path: &Path) -> Result<(), ExecError> {
    fs::create_dir_all(path).map_err(|e| ExecError::io(path, e))
}

/// Non-empty, trimmed lines.
fn lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd aios-cli && cargo test -p aios-exec`
Expected, one line per binary: `apply_build` 18, `apply_golden` 11, `apply_prepare` 14, `boot` 8, `btrfs` 7, `etcfs` 7, `layout` 5, `probe` 10, `runner` 10, `steps` 2, `sys` 8. The lib unit tests and doc-tests report `0 passed`.

- [ ] **Step 6: Lint**

Run: `make check`
Expected: as in Task 1.

- [ ] **Step 7: Commit**

```bash
cd /home/eli/Development/AIOS
git add aios-cli/
git commit -m "feat(exec): UKIs, signing, ESP space check and finalize"
```

---
### Task 9: `gen list` and `status` with `/etc` drift

**Files:**
- Create: `aios-cli/crates/aios-exec/src/ops/gens.rs`, `aios-cli/crates/aios-exec/src/ops/status.rs`
- Modify: `aios-cli/crates/aios-exec/src/ops/mod.rs` (full content below)
- Test: `aios-cli/crates/aios-exec/tests/inspect.rs`

- `gen_list` mounts the top level read-only and returns one `GenRow` per complete generation:
  - `created`, `commit` and `kernels` come from `@etc-gen-N/aios/generation.toml`, or `?` when it can't be read;
  - `states` holds `booted`, `default` and `bad` from `BootState`.

  `render_gen_list` prints the table.
- `status` gives the booted, default and bad generations. When the booted generation is known, it also compares the live `/etc` (`layout.live_etc`) with `@etc-gen-<booted>` under a read-only mount.
- `drift` walks both trees without following links:
  - It reports added, modified (content, mode or link target) and removed regular files and symlinks.
  - It ignores `/etc/aios/generation.toml`, directories and special files.
  - Entries it can't read are listed as `note: skipped …` and not compared.

- [ ] **Step 1: Write the failing tests**

`aios-cli/crates/aios-exec/tests/inspect.rs`:
```rust
mod common;

use aios_exec::ops::{drift, gen_list, gen_rows, render_gen_list, status, Drift, GenRow, Status};
use aios_gen::{GenId, GenerationMeta};
use common::{mkdir, write, Fixture};
use std::fs;
use std::os::unix::fs::symlink;

fn meta(id: u32, commit: &str) -> String {
    GenerationMeta {
        id,
        parent: id - 1,
        created: format!("2026-11-0{id}T10:00:00Z"),
        manifest_commit: commit.to_string(),
        kernels: vec!["linux-cachyos 7.3.0-4".to_string()],
        package_set_sha256: "ab".repeat(32),
    }
    .to_toml()
}

/// gen-6 (bad), gen-7 (booted) and gen-8 (newest, no generation.toml).
fn machine() -> Fixture {
    let fx = Fixture::booted();
    let l = &fx.layout;
    write(
        &l.subvol("@etc-gen-0006").join("aios/generation.toml"),
        &meta(6, "1111111"),
        0o644,
    );
    write(
        &l.subvol("@etc-gen-0007").join("aios/generation.toml"),
        &meta(7, "3f9c2a1"),
        0o644,
    );
    mkdir(&l.subvol("@usr-gen-0008"));
    mkdir(&l.subvol("@etc-gen-0008"));
    mkdir(&l.subvol("@usr-gen-0009"));
    fs::rename(
        l.uki_dir().join("aios-gen-0006-cachyos.efi"),
        l.uki_dir().join("aios-gen-0006-cachyos+0-3.efi"),
    )
    .unwrap();
    write(
        &l.uki_dir().join("aios-gen-0008-cachyos+3.efi"),
        "uki",
        0o644,
    );
    fx
}

#[test]
fn rows_carry_metadata_and_boot_states() {
    let fx = machine();
    let rows = gen_rows(&fx.layout).unwrap();
    assert_eq!(
        rows,
        [
            GenRow {
                gen: GenId(6),
                created: "2026-11-06T10:00:00Z".to_string(),
                commit: "1111111".to_string(),
                kernels: vec!["linux-cachyos 7.3.0-4".to_string()],
                states: vec!["bad"],
            },
            GenRow {
                gen: GenId(7),
                created: "2026-11-07T10:00:00Z".to_string(),
                commit: "3f9c2a1".to_string(),
                kernels: vec!["linux-cachyos 7.3.0-4".to_string()],
                states: vec!["booted"],
            },
            GenRow {
                gen: GenId(8),
                created: "?".to_string(),
                commit: "?".to_string(),
                kernels: vec![],
                states: vec!["default"],
            },
        ]
    );
}

#[test]
fn the_table_has_a_header_and_one_line_per_generation() {
    let fx = machine();
    let table = render_gen_list(&gen_rows(&fx.layout).unwrap());
    assert_eq!(
        table,
        "\
GEN   CREATED               COMMIT   STATE           KERNELS
0006  2026-11-06T10:00:00Z  1111111  bad             linux-cachyos 7.3.0-4
0007  2026-11-07T10:00:00Z  3f9c2a1  booted          linux-cachyos 7.3.0-4
0008  ?                     ?        default         \n"
    );
}

#[test]
fn gen_list_mounts_the_top_level_read_only() {
    let fx = machine();
    assert_eq!(gen_list(&fx.runner, &fx.layout).unwrap().len(), 3);
    assert_eq!(
        fx.calls(),
        fx.expand(
            "
            mount -t btrfs -o subvolid=5,ro /dev/mapper/aios {top}
            umount {top}
            "
        )
    );
}

/// The live /etc and the booted snapshot, identical except for a few runtime changes.
fn drifted() -> Fixture {
    let fx = machine();
    let (live, snap) = (&fx.layout.live_etc, fx.layout.subvol("@etc-gen-0007"));
    for etc in [live, &snap] {
        write(&etc.join("hostname"), "nightcity\n", 0o644);
        write(&etc.join("nftables.conf"), "flush ruleset\n", 0o600);
        write(&etc.join("aios/generation.toml"), "differs per tree", 0o644);
        symlink("/usr/share/zoneinfo/UTC", etc.join("localtime")).unwrap();
        mkdir(&etc.join("empty.d"));
    }
    write(&snap.join("issue"), "AIOS\n", 0o644);
    write(&live.join("ld.so.preload"), "/tmp/evil.so\n", 0o644);
    write(&live.join("hostname"), "evil\n", 0o644);
    write(&live.join("nftables.conf"), "flush ruleset\n", 0o644);
    fs::remove_file(live.join("localtime")).unwrap();
    symlink("/usr/share/zoneinfo/Europe/Berlin", live.join("localtime")).unwrap();
    fx
}

#[test]
fn drift_lists_added_modified_and_removed_paths() {
    let fx = drifted();
    let d = drift(&fx.layout.live_etc, &fx.layout.subvol("@etc-gen-0007")).unwrap();
    assert_eq!(
        d,
        Drift {
            added: vec!["/etc/ld.so.preload".to_string()],
            modified: vec![
                "/etc/hostname".to_string(),
                "/etc/localtime".to_string(),
                "/etc/nftables.conf".to_string(),
            ],
            removed: vec!["/etc/issue".to_string()],
            skipped: vec![],
        }
    );
}

#[test]
fn identical_trees_have_no_drift() {
    let fx = machine();
    let (live, snap) = (&fx.layout.live_etc, fx.layout.subvol("@etc-gen-0007"));
    for etc in [live, &snap] {
        write(&etc.join("hostname"), "nightcity\n", 0o644);
    }
    assert!(drift(live, &snap).unwrap().is_empty());
}

#[test]
fn status_reports_boot_state_and_drift() {
    let fx = drifted();
    let st = status(&fx.runner, &fx.layout).unwrap();
    assert_eq!(st.booted, Some(GenId(7)));
    assert_eq!(st.default, Some(GenId(8)));
    assert_eq!(st.bad, [GenId(6)]);
    assert_eq!(
        st.to_string(),
        "\
booted:  gen-0007
default: gen-0008
bad:     gen-0006
drift (discarded at the next boot):
  + /etc/ld.so.preload
  ~ /etc/hostname
  ~ /etc/localtime
  ~ /etc/nftables.conf
  - /etc/issue
"
    );
    assert_eq!(
        fx.calls()[0],
        "mount -t btrfs -o subvolid=5,ro /dev/mapper/aios {top}"
    );
}

#[test]
fn status_without_a_booted_generation_skips_drift() {
    let fx = Fixture::fresh();
    let st = status(&fx.runner, &fx.layout).unwrap();
    assert_eq!(
        st,
        Status {
            booted: None,
            default: None,
            bad: vec![],
            drift: None,
        }
    );
    assert_eq!(
        st.to_string(),
        "booted:  unknown\ndefault: unknown\nbad:     none\n\
         drift:   unknown (no aios.gen= on the kernel cmdline)\n"
    );
    assert!(fx.calls().is_empty());
}

#[test]
fn unreadable_files_are_skipped_with_a_note() {
    use std::os::unix::fs::PermissionsExt;
    let fx = drifted();
    let (live, snap) = (&fx.layout.live_etc, fx.layout.subvol("@etc-gen-0007"));
    for etc in [live, &snap] {
        write(&etc.join("secret"), "x", 0o000);
    }
    if fs::read(live.join("secret")).is_ok() {
        return; // root reads anything; nothing to check
    }
    let d = drift(live, &snap).unwrap();
    assert_eq!(d.skipped, ["/etc/secret: Permission denied (os error 13)"]);
    assert!(!d.modified.contains(&"/etc/secret".to_string()));
    let st = Status {
        booted: Some(GenId(7)),
        default: Some(GenId(7)),
        bad: vec![],
        drift: Some(d),
    };
    assert!(st
        .to_string()
        .ends_with("note: skipped /etc/secret: Permission denied (os error 13)\n"));
    for etc in [live, &snap] {
        fs::set_permissions(etc.join("secret"), fs::Permissions::from_mode(0o600)).unwrap();
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd aios-cli && cargo test -p aios-exec --test inspect`
Expected: compile error `unresolved imports aios_exec::ops::drift, aios_exec::ops::gen_list, aios_exec::ops::gen_rows, ...`.

- [ ] **Step 3: Implement `gens.rs` and `status.rs`**

`aios-cli/crates/aios-exec/src/ops/gens.rs`:
```rust
use super::{with_top, BootState};
use crate::{btrfs, CommandRunner, ExecError, Layout};
use aios_gen::{list_complete, GenId, GenerationMeta};
use std::fs;

/// One line of `aios gen list`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenRow {
    pub gen: GenId,
    /// From `generation.toml`; `?` when it can't be read.
    pub created: String,
    pub commit: String,
    pub kernels: Vec<String>,
    /// Any of `booted`, `default`, `bad`.
    pub states: Vec<&'static str>,
}

/// `aios gen list`: mount the top level read-only, read every generation, unmount.
pub fn gen_list(runner: &dyn CommandRunner, layout: &Layout) -> Result<Vec<GenRow>, ExecError> {
    with_top(runner, layout, true, || gen_rows(layout))
}

/// Every complete generation in the (mounted) top level, ascending.
pub fn gen_rows(layout: &Layout) -> Result<Vec<GenRow>, ExecError> {
    let state = BootState::read(layout)?;
    let bad = state.bad();
    let gens = list_complete(&btrfs::list_names(&layout.top)?);
    Ok(gens
        .into_iter()
        .map(|gen| {
            let path = layout
                .subvol(&gen.etc_subvol())
                .join("aios/generation.toml");
            let meta = fs::read_to_string(path)
                .ok()
                .and_then(|text| GenerationMeta::from_toml(&text).ok());
            let mut states = Vec::new();
            if state.booted == Some(gen) {
                states.push("booted");
            }
            if state.default_gen() == Some(gen) {
                states.push("default");
            }
            if bad.contains(&gen) {
                states.push("bad");
            }
            let unknown = || "?".to_string();
            GenRow {
                gen,
                created: meta.as_ref().map_or_else(unknown, |m| m.created.clone()),
                commit: meta
                    .as_ref()
                    .map_or_else(unknown, |m| m.manifest_commit.clone()),
                kernels: meta.map(|m| m.kernels).unwrap_or_default(),
                states,
            }
        })
        .collect())
}

/// The `aios gen list` table.
pub fn render_gen_list(rows: &[GenRow]) -> String {
    let mut out = format!(
        "{:<4}  {:<20}  {:<7}  {:<14}  KERNELS\n",
        "GEN", "CREATED", "COMMIT", "STATE"
    );
    for row in rows {
        let states = if row.states.is_empty() {
            "-".to_string()
        } else {
            row.states.join(",")
        };
        out.push_str(&format!(
            "{:<4}  {:<20}  {:<7}  {:<14}  {}\n",
            row.gen.to_string(),
            row.created,
            row.commit,
            states,
            row.kernels.join(", ")
        ));
    }
    out
}
```

`aios-cli/crates/aios-exec/src/ops/status.rs`:
```rust
use super::{with_top, BootState};
use crate::{CommandRunner, ExecError, Layout};
use aios_gen::GenId;
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// `aios status` (spec §4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub booted: Option<GenId>,
    pub default: Option<GenId>,
    pub bad: Vec<GenId>,
    /// `None` when the booted generation is unknown.
    pub drift: Option<Drift>,
}

/// Regular files and symlinks in the live `/etc` that differ from `@etc-gen-<booted>`:
/// runtime edits a reboot will discard. Paths are absolute (`/etc/...`), sorted.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Drift {
    pub added: Vec<String>,
    pub modified: Vec<String>,
    pub removed: Vec<String>,
    /// Entries that could not be read, with the error. Not compared.
    pub skipped: Vec<String>,
}

impl Drift {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.modified.is_empty() && self.removed.is_empty()
    }
}

/// Boot state plus drift. Mounts the top level read-only while comparing.
pub fn status(runner: &dyn CommandRunner, layout: &Layout) -> Result<Status, ExecError> {
    let state = BootState::read(layout)?;
    let drift = match state.booted {
        Some(gen) => Some(with_top(runner, layout, true, || {
            drift(&layout.live_etc, &layout.subvol(&gen.etc_subvol()))
        })?),
        None => None,
    };
    Ok(Status {
        booted: state.booted,
        default: state.default_gen(),
        bad: state.bad(),
        drift,
    })
}

#[derive(Debug)]
enum Node {
    File(PathBuf, u32),
    Link(PathBuf),
}

/// Compare the live `/etc` with a generation's snapshot. `/etc/aios/generation.toml` is
/// ignored; directories and special files are not compared.
pub fn drift(live: &Path, snapshot: &Path) -> Result<Drift, ExecError> {
    if !snapshot.is_dir() {
        return Err(ExecError(format!("{} is missing", snapshot.display())));
    }
    let mut d = Drift::default();
    let live_nodes = scan(live, &mut d.skipped);
    let snap_nodes = scan(snapshot, &mut d.skipped);
    for (rel, node) in &live_nodes {
        let path = format!("/etc/{rel}");
        match snap_nodes.get(rel) {
            None => d.added.push(path),
            Some(old) => match differs(node, old) {
                Ok(true) => d.modified.push(path),
                Ok(false) => {}
                Err(e) => d.skipped.push(format!("{path}: {e}")),
            },
        }
    }
    for rel in snap_nodes.keys() {
        if !live_nodes.contains_key(rel) {
            d.removed.push(format!("/etc/{rel}"));
        }
    }
    Ok(d)
}

fn scan(root: &Path, skipped: &mut Vec<String>) -> BTreeMap<String, Node> {
    let mut nodes = BTreeMap::new();
    for entry in WalkDir::new(root).min_depth(1).follow_links(false) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                skipped.push(e.to_string());
                continue;
            }
        };
        let Ok(rel) = entry.path().strip_prefix(root) else {
            continue;
        };
        let rel = rel.to_string_lossy().into_owned();
        if rel == "aios/generation.toml" {
            continue;
        }
        let kind = entry.file_type();
        let node = if kind.is_symlink() {
            Node::Link(entry.path().to_path_buf())
        } else if kind.is_file() {
            match entry.metadata() {
                Ok(meta) => Node::File(entry.path().to_path_buf(), meta.permissions().mode()),
                Err(e) => {
                    skipped.push(e.to_string());
                    continue;
                }
            }
        } else {
            continue;
        };
        nodes.insert(rel, node);
    }
    nodes
}

fn differs(a: &Node, b: &Node) -> std::io::Result<bool> {
    Ok(match (a, b) {
        (Node::Link(a), Node::Link(b)) => fs::read_link(a)? != fs::read_link(b)?,
        (Node::File(a, mode_a), Node::File(b, mode_b)) => {
            mode_a != mode_b || fs::read(a)? != fs::read(b)?
        }
        _ => true,
    })
}

fn show(gen: Option<GenId>) -> String {
    gen.map_or_else(|| "unknown".to_string(), |g| format!("gen-{g}"))
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "booted:  {}", show(self.booted))?;
        writeln!(f, "default: {}", show(self.default))?;
        let bad: Vec<String> = self.bad.iter().map(|g| format!("gen-{g}")).collect();
        let bad = if bad.is_empty() {
            "none".to_string()
        } else {
            bad.join(", ")
        };
        writeln!(f, "bad:     {bad}")?;
        match &self.drift {
            None => writeln!(f, "drift:   unknown (no aios.gen= on the kernel cmdline)")?,
            Some(d) if d.is_empty() => writeln!(f, "drift:   none")?,
            Some(d) => {
                writeln!(f, "drift (discarded at the next boot):")?;
                for (marker, paths) in [('+', &d.added), ('~', &d.modified), ('-', &d.removed)] {
                    for path in paths {
                        writeln!(f, "  {marker} {path}")?;
                    }
                }
            }
        }
        for item in self.drift.iter().flat_map(|d| &d.skipped) {
            writeln!(f, "note: skipped {item}")?;
        }
        Ok(())
    }
}
```

- [ ] **Step 4: Replace `ops/mod.rs`**

`aios-cli/crates/aios-exec/src/ops/mod.rs`:
```rust
//! The other `aios` commands: rollback, gc, gen list and status.

mod boot;
mod gc;
mod gens;
mod rollback;
mod status;

pub use boot::{read_ukis, BootState, EspUki};
pub use gc::{gc, gc_mounted};
pub use gens::{gen_list, gen_rows, render_gen_list, GenRow};
pub use rollback::rollback;
pub use status::{drift, status, Drift, Status};

use crate::{btrfs, CommandRunner, ExecError, Layout};

/// Mount the top level, run `f`, and unmount again whether or not `f` succeeded.
fn with_top<T>(
    runner: &dyn CommandRunner,
    layout: &Layout,
    read_only: bool,
    f: impl FnOnce() -> Result<T, ExecError>,
) -> Result<T, ExecError> {
    btrfs::mount_top(runner, &layout.device, &layout.top, read_only)?;
    let result = f();
    let unmounted = btrfs::umount(runner, &layout.top);
    let value = result?;
    unmounted?;
    Ok(value)
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd aios-cli && cargo test -p aios-exec --test inspect`
Expected: `test result: ok. 8 passed`. When the tests run as root, `unreadable_files_are_skipped_with_a_note` returns early and passes, because root can read a mode-000 file.

- [ ] **Step 6: Lint**

Run: `make check`
Expected: as in Task 1.

- [ ] **Step 7: Commit**

```bash
cd /home/eli/Development/AIOS
git add aios-cli/
git commit -m "feat(exec): gen list and status with /etc drift"
```

---
### Task 10: Secure Boot and TPM enrollment, `passwd`, `plan`

**Files:**
- Create: `aios-cli/crates/aios-exec/src/ops/keys.rs`, `src/ops/passwd.rs`, `src/ops/plan.rs`
- Modify: `aios-cli/crates/aios-exec/src/ops/mod.rs` (final content below)
- Test: `aios-cli/crates/aios-exec/tests/security.rs`, `tests/passwd.rs`, `tests/plan.rs`

- **`secureboot_enroll`:**
  - `sbctl status --json`. In Setup Mode, `sbctl enroll-keys --microsoft`.
  - Otherwise an error explaining how to enter Setup Mode, so the CLI exits 1.
- **`tpm_enroll`:**
  - `sbctl status --json` must report `secure_boot: true`.
  - The LUKS UUID comes from the cmdline's `rd.luks.name=<uuid>=aios`.
  - Then `systemd-cryptenroll --tpm2-device=auto --tpm2-with-pin=yes --tpm2-pcrs=7 /dev/disk/by-uuid/<uuid>`. It prompts on the terminal, which `RealRunner` leaves attached.
- **`passwd`:**
  - The user name must match the manifest rule, so nothing can escape `secrets/passwd/`.
  - `mkpasswd -m yescrypt -s` gets the password on stdin.
  - The output must start with `$y$` and contain no `:` or newline.
  - It goes to `secrets/passwd/<user>`, mode 0600, via a temp file and `rename`. `secrets/` and `secrets/passwd/` are forced to 0700.
- **`plan`:**
  - The booted gen comes from the cmdline. The render context is built for the **booted** id (Phase 2 contract 1).
  - The top level is mounted read-only. `build_plan` runs with a `DirProbe` over `@etc-gen-<booted>` and no root: packages and units come from the running system, since a snapshot of `/etc` alone isn't a root `systemctl --root` could use.
  - The top level is unmounted afterwards, even on error.

The plan test builds `@etc-gen-0007` from this exact manifest with `desired_etc` + `etcfs::write`. The plan must then be `no changes`. This is spec §1 success criterion (c) end to end through the real probe and the real writer.

- [ ] **Step 1: Write the failing tests**

`aios-cli/crates/aios-exec/tests/security.rs`:
```rust
mod common;

use aios_exec::ops::{secureboot_enroll, tpm_enroll};
use aios_exec::Output;
use common::{write, Fixture, LUKS_UUID};

fn sbctl_says(fx: &mut Fixture, json: &str) {
    fx.runner
        .respond(&["sbctl", "status", "--json"], Output::ok(json));
}

const SETUP: &str =
    r#"{"installed":true,"guid":"x","setup_mode":true,"secure_boot":false,"vendors":[]}"#;
const ENFORCING: &str = r#"{"installed":true,"guid":"x","setup_mode":false,"secure_boot":true,"vendors":["microsoft"]}"#;
const USER_MODE_OFF: &str = r#"{"installed":true,"setup_mode":false,"secure_boot":false}"#;

#[test]
fn enrolls_keys_in_setup_mode() {
    let mut fx = Fixture::booted();
    sbctl_says(&mut fx, SETUP);
    let message = secureboot_enroll(&fx.runner).unwrap();
    assert!(
        message.starts_with("Secure Boot keys enrolled."),
        "{message}"
    );
    assert_eq!(
        fx.calls(),
        ["sbctl status --json", "sbctl enroll-keys --microsoft"]
    );
}

#[test]
fn outside_setup_mode_explains_how_to_get_there() {
    let mut fx = Fixture::booted();
    sbctl_says(&mut fx, ENFORCING);
    let err = secureboot_enroll(&fx.runner).unwrap_err();
    assert!(
        err.to_string().contains("not in Secure Boot Setup Mode"),
        "{err}"
    );
    assert_eq!(fx.calls(), ["sbctl status --json"]);
}

#[test]
fn unparsable_sbctl_output_is_an_error() {
    let mut fx = Fixture::booted();
    sbctl_says(&mut fx, "Installed: yes");
    let err = secureboot_enroll(&fx.runner).unwrap_err();
    assert!(
        err.to_string().starts_with("`sbctl status --json`: "),
        "{err}"
    );
}

#[test]
fn tpm_enroll_binds_pcr7_with_a_pin() {
    let mut fx = Fixture::booted();
    sbctl_says(&mut fx, ENFORCING);
    let message = tpm_enroll(&fx.runner, &fx.layout).unwrap();
    assert!(message.contains(LUKS_UUID), "{message}");
    assert_eq!(
        fx.calls()[1],
        format!(
            "systemd-cryptenroll --tpm2-device=auto --tpm2-with-pin=yes --tpm2-pcrs=7 \
             /dev/disk/by-uuid/{LUKS_UUID}"
        )
    );
}

#[test]
fn tpm_enroll_needs_secure_boot() {
    let mut fx = Fixture::booted();
    sbctl_says(&mut fx, USER_MODE_OFF);
    let err = tpm_enroll(&fx.runner, &fx.layout).unwrap_err();
    assert!(
        err.to_string().starts_with("Secure Boot is not enabled"),
        "{err}"
    );
    assert_eq!(fx.calls().len(), 1);
}

#[test]
fn tpm_enroll_needs_the_luks_uuid_on_the_cmdline() {
    let mut fx = Fixture::booted();
    sbctl_says(&mut fx, ENFORCING);
    write(
        &fx.layout.proc_cmdline,
        "root=/dev/sda2 aios.gen=0007\n",
        0o644,
    );
    let err = tpm_enroll(&fx.runner, &fx.layout).unwrap_err();
    assert_eq!(
        err.to_string(),
        "no rd.luks.name=<uuid>=aios on the kernel cmdline"
    );
}
```

`aios-cli/crates/aios-exec/tests/passwd.rs`:
```rust
mod common;

use aios_exec::ops::passwd;
use aios_exec::Output;
use common::Fixture;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

fn hashing(hash: &str) -> Fixture {
    let mut fx = Fixture::booted();
    fx.runner.respond(&["mkpasswd"], Output::ok(hash));
    fs::remove_dir_all(&fx.layout.secrets).unwrap();
    fx
}

#[test]
fn writes_the_yescrypt_hash_privately() {
    let fx = hashing("$y$j9T$new$hash\n");
    let path = passwd(&fx.runner, &fx.layout, "ada", "correct horse").unwrap();
    assert_eq!(path, fx.layout.passwd_secret("ada"));
    assert_eq!(fs::read_to_string(&path).unwrap(), "$y$j9T$new$hash\n");
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(&fx.layout.secrets), 0o700);
    assert_eq!(mode(&fx.layout.secrets.join("passwd")), 0o700);
    let cmds = fx.runner.commands();
    assert_eq!(fx.calls(), ["mkpasswd -m yescrypt -s"]);
    assert_eq!(cmds[0].stdin.as_deref(), Some(&b"correct horse\n"[..]));
    assert_eq!(
        fs::read_dir(fx.layout.secrets.join("passwd"))
            .unwrap()
            .count(),
        1
    );
}

#[test]
fn replaces_an_existing_hash() {
    let fx = hashing("$y$j9T$second$hash\n");
    passwd(&fx.runner, &fx.layout, "eli", "one").unwrap();
    passwd(&fx.runner, &fx.layout, "eli", "two").unwrap();
    let text = fs::read_to_string(fx.layout.passwd_secret("eli")).unwrap();
    assert_eq!(text, "$y$j9T$second$hash\n");
}

#[test]
fn rejects_unexpected_hashes() {
    for bad in ["$6$sha512$hash\n", "$y$a:b\n", "\n"] {
        let fx = hashing(bad);
        let err = passwd(&fx.runner, &fx.layout, "eli", "pw").unwrap_err();
        assert_eq!(
            err.to_string(),
            "`mkpasswd -m yescrypt -s` printed an unexpected hash"
        );
        assert!(!fx.layout.passwd_secret("eli").exists());
    }
}

#[test]
fn rejects_bad_user_names_and_passwords() {
    let fx = hashing("$y$j9T$x$y\n");
    for user in ["../etc", "Eli", "", "a/b"] {
        let err = passwd(&fx.runner, &fx.layout, user, "pw").unwrap_err();
        assert_eq!(err.to_string(), format!("invalid user name {user:?}"));
    }
    for password in ["", "two\nlines"] {
        let err = passwd(&fx.runner, &fx.layout, "eli", password).unwrap_err();
        assert_eq!(err.to_string(), "the password must be one non-empty line");
    }
    assert!(fx.calls().is_empty());
}
```

`aios-cli/crates/aios-exec/tests/plan.rs`:
```rust
mod common;

use aios_exec::ops::plan;
use aios_exec::{etcfs, read_hashes, DirProbe, FakeRunner, Output};
use aios_plan::{desired_etc, Inputs};
use common::{facts, now, write, Fixture, BOOTED, MANIFEST};

/// Make `@etc-gen-0007` exactly what this manifest renders for gen-7, and the running
/// system's packages and units match it.
fn synced() -> Fixture {
    let mut fx = Fixture::booted();
    let snapshot = fx.layout.subvol("@etc-gen-0007");
    write(
        &snapshot.join("passwd"),
        "root:x:0:0::/root:/usr/bin/bash\n",
        0o644,
    );
    write(
        &snapshot.join("group"),
        "root:x:0:root\nwheel:x:998:\n",
        0o644,
    );
    let ctx = facts().render_ctx(BOOTED).unwrap();
    let hashes = read_hashes(&fx.layout, &fx.manifest).unwrap();
    let inputs = Inputs {
        manifest: &fx.manifest,
        repo_root: &fx.layout.config,
        ctx: &ctx,
        hashes: &hashes,
        today_days: aios_exec::days_since_epoch(now()),
    };
    let quiet = FakeRunner::new();
    let probe = DirProbe::new(&snapshot, &quiet, None);
    for (path, entry) in desired_etc(&inputs, &probe).unwrap() {
        etcfs::write(&snapshot, &path, &entry).unwrap();
    }
    let packages = fx.manifest.package_set().join("\n");
    fx.runner
        .respond(&["pacman", "-Qqe"], Output::ok(packages))
        .respond(&["systemctl", "is-enabled"], Output::ok("enabled\n"))
        .respond(
            &["systemctl", "is-enabled", "bluetooth.service"],
            Output {
                status: 1,
                stdout: b"disabled\n".to_vec(),
                stderr: Vec::new(),
            },
        )
        .respond(
            &["systemctl", "is-enabled", "sshd.socket"],
            Output {
                status: 1,
                stdout: b"masked\n".to_vec(),
                stderr: Vec::new(),
            },
        );
    fx
}

fn run_plan(fx: &Fixture) -> Result<aios_plan::Plan, aios_exec::ExecError> {
    plan(&fx.runner, &fx.layout, &fx.manifest, &fx.facts, now())
}

#[test]
fn a_generation_built_from_this_manifest_has_no_changes() {
    let fx = synced();
    let p = run_plan(&fx).unwrap();
    assert!(p.is_empty(), "unexpected plan:\n{p}");
    assert_eq!(p.to_string(), "no changes\n");
}

#[test]
fn plan_mounts_read_only_and_asks_the_running_system() {
    let fx = synced();
    run_plan(&fx).unwrap();
    assert_eq!(
        fx.calls(),
        fx.expand(
            "
            mount -t btrfs -o subvolid=5,ro /dev/mapper/aios {top}
            pacman -Qqe
            systemctl is-enabled NetworkManager.service
            systemctl is-enabled bluetooth.service
            systemctl is-enabled fwupd-refresh.timer
            systemctl is-enabled sshd.socket
            umount {top}
            "
        )
    );
}

#[test]
fn a_new_package_shows_up() {
    let mut fx = synced();
    fx.set_manifest(&MANIFEST.replace("\"zsh\", \"git\"", "\"zsh\", \"git\", \"tree\""));
    let p = run_plan(&fx).unwrap();
    assert_eq!(p.packages_add, ["tree"]);
    assert!(p.etc_changes.is_empty());
    assert!(p.to_string().starts_with("packages:\n  + tree\n"));
}

#[test]
fn plan_needs_the_booted_generation() {
    let fx = synced();
    write(&fx.layout.proc_cmdline, "quiet\n", 0o644);
    let err = run_plan(&fx).unwrap_err();
    assert_eq!(
        err.to_string(),
        "cannot tell the booted generation: no single aios.gen= on the kernel cmdline"
    );
    assert!(fx.calls().is_empty());
}

#[test]
fn a_missing_snapshot_still_unmounts() {
    let fx = synced();
    std::fs::remove_dir_all(fx.layout.subvol("@etc-gen-0007")).unwrap();
    let err = run_plan(&fx).unwrap_err();
    assert!(
        err.to_string().ends_with("@etc-gen-0007 is missing"),
        "{err}"
    );
    assert_eq!(fx.calls().last().unwrap(), "umount {top}");
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd aios-cli && cargo test -p aios-exec --test security --test passwd --test plan`
Expected: compile errors, one per binary: `unresolved imports aios_exec::ops::secureboot_enroll, aios_exec::ops::tpm_enroll` (`security`), `unresolved import aios_exec::ops::passwd` (`passwd`) and `unresolved import aios_exec::ops::plan` (`plan`).

- [ ] **Step 3: Implement the three modules**

`aios-cli/crates/aios-exec/src/ops/keys.rs`:
```rust
use crate::{luks_uuid_from_cmdline, run_ok, Cmd, CommandRunner, ExecError, Layout};
use serde::Deserialize;
use std::fs;

/// The fields of `sbctl status --json` that aios reads.
#[derive(Deserialize)]
struct SbctlStatus {
    #[serde(default)]
    setup_mode: bool,
    #[serde(default)]
    secure_boot: bool,
}

fn sbctl_status(runner: &dyn CommandRunner) -> Result<SbctlStatus, ExecError> {
    let cmd = Cmd::new("sbctl").args(["status", "--json"]);
    let out = run_ok(runner, &cmd)?;
    serde_json::from_slice(&out.stdout).map_err(|e| ExecError(format!("`{cmd}`: {e}")))
}

/// Printed when the firmware is not in Setup Mode.
pub const SETUP_MODE_HELP: &str = "the firmware is not in Secure Boot Setup Mode, so keys \
cannot be enrolled. Reboot into the firmware setup, clear (reset) the Secure Boot keys to \
enter Setup Mode, boot AIOS again and re-run `aios secureboot enroll`";

/// `aios secureboot enroll`: in Setup Mode, enroll our keys plus Microsoft's (GPU option
/// ROMs need them). Otherwise an error explaining how to enter Setup Mode.
pub fn secureboot_enroll(runner: &dyn CommandRunner) -> Result<String, ExecError> {
    if !sbctl_status(runner)?.setup_mode {
        return Err(ExecError::new(SETUP_MODE_HELP));
    }
    run_ok(
        runner,
        &Cmd::new("sbctl").args(["enroll-keys", "--microsoft"]),
    )?;
    Ok(
        "Secure Boot keys enrolled. Enable Secure Boot in the firmware if it is off, \
reboot, then run `aios tpm enroll`."
            .to_string(),
    )
}

/// `aios tpm enroll`: with Secure Boot on, bind the LUKS volume to TPM2 PCR 7 plus a PIN.
/// The passphrase and recovery key slots stay.
pub fn tpm_enroll(runner: &dyn CommandRunner, layout: &Layout) -> Result<String, ExecError> {
    if !sbctl_status(runner)?.secure_boot {
        return Err(ExecError::new(
            "Secure Boot is not enabled: run `aios secureboot enroll`, enable Secure Boot \
in the firmware, reboot and retry",
        ));
    }
    let cmdline = fs::read_to_string(&layout.proc_cmdline)
        .map_err(|e| ExecError::io(&layout.proc_cmdline, e))?;
    let uuid = luks_uuid_from_cmdline(&cmdline)
        .ok_or_else(|| ExecError::new("no rd.luks.name=<uuid>=aios on the kernel cmdline"))?;
    let device = format!("/dev/disk/by-uuid/{uuid}");
    let cmd = Cmd::new("systemd-cryptenroll").args([
        "--tpm2-device=auto",
        "--tpm2-with-pin=yes",
        "--tpm2-pcrs=7",
        &device,
    ]);
    run_ok(runner, &cmd)?;
    Ok(format!(
        "TPM2 + PIN enrolled for {device}; the passphrase and recovery key still work"
    ))
}
```

`aios-cli/crates/aios-exec/src/ops/passwd.rs`:
```rust
use crate::{run_ok, Cmd, CommandRunner, ExecError, Layout};
use std::fs::{self, OpenOptions, Permissions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// `aios passwd <user>`: hash `password` with `mkpasswd -m yescrypt` (password on stdin)
/// and store it in `secrets/passwd/<user>` (0600, directories 0700). Takes effect at the
/// next apply. Returns the file written.
pub fn passwd(
    runner: &dyn CommandRunner,
    layout: &Layout,
    user: &str,
    password: &str,
) -> Result<PathBuf, ExecError> {
    if !valid_user_name(user) {
        return Err(ExecError(format!("invalid user name {user:?}")));
    }
    if password.is_empty() || password.contains('\n') {
        return Err(ExecError::new("the password must be one non-empty line"));
    }
    let cmd = Cmd::new("mkpasswd")
        .args(["-m", "yescrypt", "-s"])
        .stdin(format!("{password}\n"));
    let hash = run_ok(runner, &cmd)?.stdout_text();
    let hash = hash.trim_end_matches('\n');
    if !hash.starts_with("$y$") || hash.contains(':') || hash.contains('\n') {
        return Err(ExecError(format!("`{cmd}` printed an unexpected hash")));
    }
    let dir = layout.secrets.join("passwd");
    for d in [&layout.secrets, &dir] {
        private_dir(d)?;
    }
    let path = dir.join(user);
    let tmp = dir.join(format!(".{user}.tmp"));
    let io = |p: &Path, e: std::io::Error| ExecError::io(p, e);
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| io(&tmp, e))?;
    file.write_all(format!("{hash}\n").as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|e| io(&tmp, e))?;
    fs::set_permissions(&tmp, Permissions::from_mode(0o600)).map_err(|e| io(&tmp, e))?;
    fs::rename(&tmp, &path).map_err(|e| io(&path, e))?;
    Ok(path)
}

fn private_dir(dir: &Path) -> Result<(), ExecError> {
    fs::create_dir_all(dir).map_err(|e| ExecError::io(dir, e))?;
    fs::set_permissions(dir, Permissions::from_mode(0o700)).map_err(|e| ExecError::io(dir, e))
}

/// Same rule as manifest validation: `[a-z_][a-z0-9_-]*`, at most 32 characters.
fn valid_user_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_lowercase() || c == '_')
        && name.len() <= 32
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}
```

`aios-cli/crates/aios-exec/src/ops/plan.rs`:
```rust
use super::with_top;
use crate::MachineFacts;
use crate::{days_since_epoch, read_hashes, CommandRunner, DirProbe, ExecError, Layout};
use aios_gen::gen_from_cmdline;
use aios_manifest::Manifest;
use aios_plan::{build_plan, Inputs, Plan};
use std::fs;
use std::time::SystemTime;

/// `aios plan`: diff the manifest against the booted generation. Its `/etc` comes from the
/// `@etc-gen-<booted>` snapshot (top level mounted read-only meanwhile), packages and units
/// from the running system. Renders with the booted generation's id, so a generation built
/// from this exact manifest shows "no changes".
pub fn plan(
    runner: &dyn CommandRunner,
    layout: &Layout,
    manifest: &Manifest,
    facts: &MachineFacts,
    now: SystemTime,
) -> Result<Plan, ExecError> {
    let cmdline = fs::read_to_string(&layout.proc_cmdline)
        .map_err(|e| ExecError::io(&layout.proc_cmdline, e))?;
    let booted = gen_from_cmdline(&cmdline).ok_or_else(|| {
        ExecError::new(
            "cannot tell the booted generation: no single aios.gen= on the kernel cmdline",
        )
    })?;
    let ctx = facts.render_ctx(booted)?;
    let hashes = read_hashes(layout, manifest)?;
    with_top(runner, layout, true, || {
        let snapshot = layout.subvol(&booted.etc_subvol());
        if !snapshot.is_dir() {
            return Err(ExecError(format!("{} is missing", snapshot.display())));
        }
        let probe = DirProbe::new(snapshot, runner, None);
        let inputs = Inputs {
            manifest,
            repo_root: &layout.config,
            ctx: &ctx,
            hashes: &hashes,
            today_days: days_since_epoch(now),
        };
        build_plan(&inputs, &probe).map_err(|e| ExecError(e.to_string()))
    })
}
```

- [ ] **Step 4: Replace `ops/mod.rs`**

This is its final content.

`aios-cli/crates/aios-exec/src/ops/mod.rs`:
```rust
//! The other `aios` commands: rollback, gc, gen list, status, passwd, plan, Secure Boot
//! and TPM enrollment.

mod boot;
mod gc;
mod gens;
mod keys;
mod passwd;
mod plan;
mod rollback;
mod status;

pub use boot::{read_ukis, BootState, EspUki};
pub use gc::{gc, gc_mounted};
pub use gens::{gen_list, gen_rows, render_gen_list, GenRow};
pub use keys::{secureboot_enroll, tpm_enroll};
pub use passwd::passwd;
pub use plan::plan;
pub use rollback::rollback;
pub use status::{drift, status, Drift, Status};

use crate::{btrfs, CommandRunner, ExecError, Layout};

/// Mount the top level, run `f`, and unmount again whether or not `f` succeeded.
fn with_top<T>(
    runner: &dyn CommandRunner,
    layout: &Layout,
    read_only: bool,
    f: impl FnOnce() -> Result<T, ExecError>,
) -> Result<T, ExecError> {
    btrfs::mount_top(runner, &layout.device, &layout.top, read_only)?;
    let result = f();
    let unmounted = btrfs::umount(runner, &layout.top);
    let value = result?;
    unmounted?;
    Ok(value)
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd aios-cli && cargo test -p aios-exec --test security --test passwd --test plan`
Expected: `passwd`: `test result: ok. 4 passed`; `plan`: `test result: ok. 5 passed`; `security`: `test result: ok. 6 passed`.

- [ ] **Step 6: Lint**

Run: `make check`
Expected: as in Task 1.

- [ ] **Step 7: Commit**

```bash
cd /home/eli/Development/AIOS
git add aios-cli/
git commit -m "feat(exec): secureboot and tpm enrollment, passwd, plan"
```

---
### Task 11: The `aios` binary

**Files:**
- Modify: `aios-cli/Cargo.toml` (final content below)
- Create: `aios-cli/crates/aios/Cargo.toml`, `src/main.rs`, `src/cli.rs`, `src/failure.rs`, `src/lock.rs`, `src/context.rs`, `src/commands.rs`
- Test: `aios-cli/crates/aios/tests/cli.rs`

What the binary does:
- **Exit codes:**
  - 0: success.
  - 1: operational errors, including clap usage errors, a refused lock and a refused root check.
  - 2: an invalid manifest, printed as one `manifest.toml:line:col: reason` line per problem.
- **Root check:** `rustix::process::geteuid().is_root()`, skipped when `AIOS_FAKE_RUNNER` is set. The message is `aios: must run as root (try: run0 aios <cmd>)`.
- **Lock:** `flock` on `layout.lock`, non-blocking. On contention: `aios: another aios operation is running`, exit 1.
  - Exclusive for `apply`, `gc`, `rollback`, `bootstrap`, `passwd`, `secureboot`, `tpm`.
  - Shared for `plan`, `status`, `gen list`. They mount the top level too, and a read-only mount stacked on an apply's read-write one would break it.
- **Manifest:** `check_trusted_dirs(layout, uid)` runs first (failure: `aios: step validate failed: manifest repo … must be root-owned and not group/world-writable`, exit 1). Then `aios_manifest::load(config/manifest.toml, ValidationEnv { config, secrets, AIOS_ZONEINFO or /usr/share/zoneinfo })`.
  - `uid` is 0. Under `AIOS_FAKE_RUNNER` it is the caller's euid, so tests run unprivileged.
- **Facts:**
  - The hardening cmdline comes from `AIOS_HARDENING_CMDLINE_FILE` or `/usr/lib/aios/cmdline-hardening`.
  - The LUKS UUID comes from the cmdline (bootstrap: `--luks-uuid`).
  - The ESP id is the last non-empty line of `findmnt -no UUID <esp>`, after touching `<esp>` to trigger the `/efi` automount.
- **`apply`:** prints the plan.
  - `no changes` exits 0 without building.
  - Otherwise it asks `Proceed? [y/N]` unless `--yes`; anything but `y`/`yes` exits 1 with `aios: aborted`.
  - Then `apply(Mode::Apply { booted })` and `reboot to activate gen-NNNN`.
- **`bootstrap --target T --esp E --manifest M --luks-uuid U`:**
  - The layout becomes: top = T, ESP = E, config = M's directory, persist = `T/@persist`, secrets = `T/@persist/aios/secrets`, home = `T/@home`, log = `T/@log`.
  - Then `apply(Mode::Bootstrap)` and `gen-0001 built in T`.
- **`passwd <user>`:** prompts twice with `rpassword`. Under `AIOS_FAKE_RUNNER` it reads `AIOS_TEST_PASSWORD` instead (honored only then).

The CLI tests run the real binary (`env!("CARGO_BIN_EXE_aios")`) against a tempdir machine, with every `AIOS_*` path set and a JSON fake-runner script.

- [ ] **Step 1: Add the crate with an empty `main`**

`aios-cli/Cargo.toml`:
```toml
[workspace]
resolver = "2"
members = [
    "crates/aios-manifest",
    "crates/aios-gen",
    "crates/aios-render",
    "crates/aios-plan",
    "crates/aios-exec",
    "crates/aios",
]

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "GPL-3.0-or-later"
publish = false

[workspace.dependencies]
serde = { version = "1", features = ["derive"] }
toml = "0.8"
tempfile = "3"
clap = { version = "4", features = ["derive"] }
rpassword = "7"
rustix = { version = "0.38", features = ["fs", "process"] }
serde_json = "1"
sha2 = "0.10"
walkdir = "2"
```

`aios-cli/crates/aios/Cargo.toml`:
```toml
[package]
name = "aios"
description = "The AIOS command line: plan, apply, roll back and collect generations"
version.workspace = true
edition.workspace = true
license.workspace = true
publish.workspace = true

[[bin]]
name = "aios"
path = "src/main.rs"

[dependencies]
aios-exec = { path = "../aios-exec" }
aios-gen = { path = "../aios-gen" }
aios-manifest = { path = "../aios-manifest" }
clap.workspace = true
rpassword.workspace = true
rustix.workspace = true

[dev-dependencies]
rustix.workspace = true
tempfile.workspace = true
```

`aios-cli/crates/aios/src/main.rs`:
```rust
fn main() {}
```

- [ ] **Step 2: Write the failing tests**

`aios-cli/crates/aios/tests/cli.rs`:
```rust
//! The `aios` binary end to end, with `AIOS_FAKE_RUNNER` and every path in a tempdir.

use rustix::fs::{flock, FlockOperation};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};
use tempfile::TempDir;

const LUKS_UUID: &str = "0b6c2e7f-5d0a-4c2e-9a71-3f1d2c4b5a69";

const MANIFEST: &str = r#"[system]
hostname = "nightcity"
timezone = "Asia/Jerusalem"
locale = "en_US.UTF-8"
keymap = "us"

[kernel]
default = "linux-cachyos"
lockdown = "integrity"

[packages]
install = ["zsh"]

[services]
enable = ["NetworkManager"]

[files]
"/etc/nftables.conf" = { source = "files/nftables.conf", mode = "0600" }

[persist]
directories = ["/var/lib/NetworkManager"]

[users.eli]
uid = 1000
groups = ["wheel"]
shell = "/usr/bin/zsh"

[users.eli.home]
".zshrc" = "home/eli/zshrc"
"#;

/// Answers for the commands `aios plan` and `aios passwd` run.
const SCRIPT: &str = r#"{
  "respond": [
    {"argv": ["findmnt"], "stdout": "7A1B-2C3D\n"},
    {"argv": ["pacman", "-Qqe"], "stdout": "zsh\n"},
    {"argv": ["systemctl", "is-enabled"], "stdout": "enabled\n"},
    {"argv": ["mkpasswd"], "stdout": "$y$j9T$abc$def\n"}
  ]
}"#;

/// A booted gen-1 machine in a tempdir.
struct Machine {
    dir: TempDir,
}

impl Machine {
    fn new() -> Machine {
        let m = Machine {
            dir: TempDir::new().unwrap(),
        };
        m.write("config/manifest.toml", MANIFEST, 0o644);
        m.write("config/files/nftables.conf", "flush ruleset\n", 0o644);
        m.write("config/home/eli/zshrc", "# zshrc\n", 0o644);
        m.write("secrets/passwd/eli", "$y$j9T$salt$hash\n", 0o600);
        fs::set_permissions(m.path("config"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(m.path("secrets"), fs::Permissions::from_mode(0o700)).unwrap();
        m.write("zoneinfo/Asia/Jerusalem", "TZif", 0o644);
        m.write("cmdline-hardening", "quiet\n", 0o644);
        let cmdline =
            format!("rd.luks.name={LUKS_UUID}=aios root=/dev/mapper/aios aios.gen=0001\n");
        m.write("cmdline", &cmdline, 0o644);
        m.write(
            "top/@etc-gen-0001/passwd",
            "root:x:0:0::/root:/usr/bin/bash\n",
            0o644,
        );
        m.write(
            "top/@etc-gen-0001/group",
            "root:x:0:root\nwheel:x:998:\n",
            0o644,
        );
        fs::create_dir_all(m.path("top/@usr-gen-0001")).unwrap();
        fs::create_dir_all(m.path("esp/EFI/Linux")).unwrap();
        m.write("fake.json", SCRIPT, 0o644);
        m
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.dir.path().join(rel)
    }

    fn write(&self, rel: &str, content: &str, mode: u32) {
        let path = self.path(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, content).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn aios(&self, args: &[&str]) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_aios"));
        cmd.args(args)
            .env("AIOS_FAKE_RUNNER", self.path("fake.json"))
            .env("AIOS_ZONEINFO", self.path("zoneinfo"))
            .env(
                "AIOS_HARDENING_CMDLINE_FILE",
                self.path("cmdline-hardening"),
            )
            .env("AIOS_CMDLINE", self.path("cmdline"))
            .env("AIOS_DEVICE", "/dev/mapper/aios")
            .env_remove("AIOS_TEST_PASSWORD");
        for (var, rel) in [
            ("AIOS_TOP", "top"),
            ("AIOS_CAND", "cand"),
            ("AIOS_ESP", "esp"),
            ("AIOS_CONFIG", "config"),
            ("AIOS_SECRETS", "secrets"),
            ("AIOS_PERSIST", "persist"),
            ("AIOS_HOME", "home"),
            ("AIOS_LOG", "log"),
            ("AIOS_LIVE_ETC", "live-etc"),
            ("AIOS_EFIVARS", "efivars"),
            ("AIOS_LOCK", "aios.lock"),
        ] {
            cmd.env(var, self.path(rel));
        }
        cmd.output().unwrap()
    }

    fn calls(&self) -> String {
        fs::read_to_string(self.path("fake.json.calls")).unwrap_or_default()
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn help_lists_every_command() {
    let out = Command::new(env!("CARGO_BIN_EXE_aios"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(out.status.success());
    let help = text(&out.stdout);
    for command in [
        "plan",
        "apply",
        "status",
        "gen",
        "rollback",
        "gc",
        "passwd",
        "secureboot",
        "tpm",
        "bootstrap",
    ] {
        assert!(
            help.contains(&format!("  {command} ")),
            "{command} missing:\n{help}"
        );
    }
}

#[test]
fn usage_errors_exit_1() {
    let m = Machine::new();
    let out = m.aios(&["rollback", "0"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("invalid value '0'"));
}

#[test]
fn plan_prints_the_plan() {
    let m = Machine::new();
    let out = m.aios(&["plan"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(stdout.contains("/etc:\n"), "{stdout}");
    assert!(stdout.contains("  + /etc/hostname\n"), "{stdout}");
    assert!(stdout.contains("  ~ /etc/passwd\n"), "{stdout}");
    let calls = m.calls();
    assert!(calls.starts_with(&format!(
        "findmnt -no UUID {}\nmount -t btrfs -o subvolid=5,ro /dev/mapper/aios {}\n",
        m.path("esp").display(),
        m.path("top").display()
    )));
}

#[test]
fn an_invalid_manifest_exits_2_with_locations() {
    let m = Machine::new();
    m.write(
        "config/manifest.toml",
        &MANIFEST.replace("Asia/Jerusalem", "Mars/Olympus"),
        0o644,
    );
    let out = m.aios(&["plan"]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        text(&out.stderr),
        "manifest.toml:3:1: unknown timezone \"Mars/Olympus\"\n"
    );
    assert_eq!(m.calls(), "");
}

#[test]
fn a_writable_manifest_repo_is_refused() {
    let m = Machine::new();
    fs::set_permissions(m.path("config"), fs::Permissions::from_mode(0o777)).unwrap();
    let out = m.aios(&["plan"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        text(&out.stderr),
        format!(
            "aios: step validate failed: manifest repo {} must be root-owned and not \
             group/world-writable\n",
            m.path("config").display()
        )
    );
}

#[test]
fn rollback_needs_a_boot_entry() {
    let m = Machine::new();
    let out = m.aios(&["rollback", "7"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(text(&out.stderr), "aios: no boot entry for gen-0007\n");
}

#[test]
fn rollback_sets_the_boot_default() {
    let m = Machine::new();
    m.write("esp/EFI/Linux/aios-gen-0007-cachyos+3.efi", "uki", 0o644);
    let out = m.aios(&["rollback", "0007"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
    assert_eq!(m.calls(), "bootctl set-default aios-gen-0007-cachyos.efi\n");
}

#[test]
fn a_held_lock_stops_a_second_command() {
    let m = Machine::new();
    let held = fs::File::create(m.path("aios.lock")).unwrap();
    flock(&held, FlockOperation::NonBlockingLockExclusive).unwrap();
    for args in [&["rollback", "7"][..], &["status"][..]] {
        let out = m.aios(args);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        assert_eq!(
            text(&out.stderr),
            "aios: another aios operation is running\n"
        );
    }
}

#[test]
fn passwd_writes_the_secret() {
    let m = Machine::new();
    let out = Command::new(env!("CARGO_BIN_EXE_aios"))
        .args(["passwd", "ada"])
        .env("AIOS_FAKE_RUNNER", m.path("fake.json"))
        .env("AIOS_SECRETS", m.path("secrets"))
        .env("AIOS_LOCK", m.path("aios.lock"))
        .env("AIOS_TEST_PASSWORD", "hunter2")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
    let secret = m.path("secrets/passwd/ada");
    assert_eq!(fs::read_to_string(&secret).unwrap(), "$y$j9T$abc$def\n");
    assert_eq!(
        fs::metadata(&secret).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(m.calls(), "mkpasswd -m yescrypt -s\n");
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cd aios-cli && cargo test -p aios --test cli`
Expected: `test result: FAILED. 0 passed; 9 failed`: the empty `main` prints nothing and exits 0.

- [ ] **Step 4: Implement the binary**

`aios-cli/crates/aios/src/cli.rs`:
```rust
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "aios",
    version,
    about = "Change an AIOS system through its manifest: plan, apply, roll back"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Show what `aios apply` would change compared with the booted generation
    Plan,
    /// Build the next generation from the manifest (also a full system upgrade)
    Apply {
        /// Do not ask for confirmation
        #[arg(long)]
        yes: bool,
    },
    /// Show the booted, default and bad generations and runtime changes to /etc
    Status,
    /// Inspect generations
    Gen {
        #[command(subcommand)]
        command: GenCommand,
    },
    /// Boot generation N at the next reboot (no snapshot is touched)
    Rollback {
        /// Generation number, e.g. 7 or 0007
        #[arg(value_parser = clap::value_parser!(u32).range(1..=9999))]
        gen: u32,
    },
    /// Delete old generations
    Gc {
        /// Number of newest generations to keep
        #[arg(long, default_value_t = 5)]
        keep: usize,
    },
    /// Set a user's password hash (used from the next apply)
    Passwd {
        /// User declared in the manifest
        user: String,
    },
    /// Secure Boot key management
    Secureboot {
        #[command(subcommand)]
        command: EnrollCommand,
    },
    /// TPM2 unlock of the LUKS volume
    Tpm {
        #[command(subcommand)]
        command: EnrollCommand,
    },
    /// Installer only: build gen-1 in a mounted btrfs top level
    Bootstrap {
        /// Mount point of the new filesystem's top level (subvolid=5)
        #[arg(long)]
        target: PathBuf,
        /// Mount point of the new ESP
        #[arg(long)]
        esp: PathBuf,
        /// The manifest.toml inside <target>/@persist/aios/config
        #[arg(long)]
        manifest: PathBuf,
        /// UUID of the LUKS2 partition (`cryptsetup luksUUID <partition>`)
        #[arg(long)]
        luks_uuid: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum GenCommand {
    /// List generations: id, created, manifest commit, boot state, kernels
    List,
}

#[derive(Debug, Subcommand)]
pub enum EnrollCommand {
    /// Enroll (see `aios <command> enroll --help`)
    Enroll,
}
```

`aios-cli/crates/aios/src/failure.rs`:
```rust
use aios_exec::{ExecError, StepError};
use aios_manifest::ManifestError;
use std::fmt;

/// Why `aios` exits non-zero: the message for stderr and the exit code.
#[derive(Debug)]
pub struct Failure {
    pub code: u8,
    pub message: String,
}

impl Failure {
    /// Exit 1. `message` is printed as is.
    pub fn op(message: impl Into<String>) -> Failure {
        Failure {
            code: 1,
            message: message.into(),
        }
    }

    /// Exit 2: one `manifest.toml:line:col: reason` line per problem.
    pub fn manifest(errors: Vec<ManifestError>) -> Failure {
        let lines: Vec<String> = errors.iter().map(ToString::to_string).collect();
        Failure {
            code: 2,
            message: lines.join("\n"),
        }
    }
}

impl From<ExecError> for Failure {
    fn from(e: ExecError) -> Failure {
        Failure::op(format!("aios: {e}"))
    }
}

impl From<StepError> for Failure {
    fn from(e: StepError) -> Failure {
        Failure::op(e.to_string())
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}
```

`aios-cli/crates/aios/src/lock.rs`:
```rust
use crate::failure::Failure;
use aios_exec::{Step, StepError};
use rustix::fs::{flock, FlockOperation};
use rustix::io::Errno;
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// An flock on the lock file, held until dropped.
pub struct Lock(#[allow(dead_code)] File);

/// Take the lock without waiting: exclusive for commands that change anything, shared
/// for read-only ones (they mount the top level too, so they must not run during an apply).
pub fn acquire(path: &Path, exclusive: bool) -> Result<Lock, Failure> {
    let failed = |detail: String| {
        Failure::from(StepError {
            step: Step::Lock,
            detail,
        })
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| failed(format!("{}: {e}", parent.display())))?;
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .map_err(|e| failed(format!("{}: {e}", path.display())))?;
    let operation = if exclusive {
        FlockOperation::NonBlockingLockExclusive
    } else {
        FlockOperation::NonBlockingLockShared
    };
    match flock(&file, operation) {
        Ok(()) => Ok(Lock(file)),
        Err(e) if e == Errno::WOULDBLOCK => {
            Err(Failure::op("aios: another aios operation is running"))
        }
        Err(e) => Err(failed(format!("{}: {e}", path.display()))),
    }
}
```

`aios-cli/crates/aios/src/context.rs`:
```rust
use crate::failure::Failure;
use crate::lock::{self, Lock};
use aios_exec::{
    check_trusted_dirs, luks_uuid_from_cmdline, run_ok, Cmd, CommandRunner, FakeRunner, Layout,
    MachineFacts, RealRunner, Step, StepError,
};
use aios_gen::{gen_from_cmdline, GenId};
use aios_manifest::{load, Manifest, ValidationEnv};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// Paths, the command runner and environment overrides for one `aios` invocation.
pub struct Context {
    pub layout: Layout,
    runner: Box<dyn CommandRunner>,
    /// `AIOS_FAKE_RUNNER` is set (tests): no root check, commands are scripted, the
    /// manifest repo must belong to the caller instead of root, and `aios passwd` reads
    /// `AIOS_TEST_PASSWORD`.
    pub fake: bool,
    zoneinfo: PathBuf,
    hardening_file: PathBuf,
}

fn env_path(name: &str, default: &str) -> PathBuf {
    env::var_os(name).map_or_else(|| default.into(), PathBuf::from)
}

impl Context {
    pub fn from_env() -> Result<Context, Failure> {
        let script = env::var_os("AIOS_FAKE_RUNNER");
        let runner: Box<dyn CommandRunner> = match &script {
            Some(path) => Box::new(FakeRunner::from_json_file(Path::new(path))?),
            None => Box::new(RealRunner),
        };
        Ok(Context {
            layout: Layout::from_env(),
            runner,
            fake: script.is_some(),
            zoneinfo: env_path("AIOS_ZONEINFO", "/usr/share/zoneinfo"),
            hardening_file: env_path(
                "AIOS_HARDENING_CMDLINE_FILE",
                "/usr/lib/aios/cmdline-hardening",
            ),
        })
    }

    pub fn runner(&self) -> &dyn CommandRunner {
        self.runner.as_ref()
    }

    /// Every command mounts, writes secrets or changes boot state, so all need root.
    pub fn require_root(&self) -> Result<(), Failure> {
        if self.fake || rustix::process::geteuid().is_root() {
            Ok(())
        } else {
            Err(Failure::op("aios: must run as root (try: run0 aios <cmd>)"))
        }
    }

    pub fn lock(&self, exclusive: bool) -> Result<Lock, Failure> {
        lock::acquire(&self.layout.lock, exclusive)
    }

    /// Owner the manifest repo and secrets must have: root, or the caller under
    /// `AIOS_FAKE_RUNNER`.
    pub fn trusted_uid(&self) -> u32 {
        if self.fake {
            rustix::process::geteuid().as_raw()
        } else {
            0
        }
    }

    /// Check the manifest repo and secrets ownership, then load and validate
    /// `<config>/manifest.toml`. Problems with the manifest exit 2.
    pub fn load_manifest(&self) -> Result<Manifest, Failure> {
        check_trusted_dirs(&self.layout, self.trusted_uid()).map_err(|e| {
            Failure::from(StepError {
                step: Step::Validate,
                detail: e.0,
            })
        })?;
        let env = ValidationEnv {
            repo_root: self.layout.config.clone(),
            secrets_dir: self.layout.secrets.clone(),
            zoneinfo_dir: self.zoneinfo.clone(),
        };
        load(&self.layout.manifest_path(), &env).map_err(Failure::manifest)
    }

    /// The generation the running kernel booted (`aios.gen=`).
    pub fn booted(&self) -> Result<GenId, Failure> {
        let path = &self.layout.proc_cmdline;
        let cmdline = fs::read_to_string(path)
            .map_err(|e| Failure::op(format!("aios: {}: {e}", path.display())))?;
        gen_from_cmdline(&cmdline).ok_or_else(|| {
            Failure::op("aios: no single aios.gen= on the kernel cmdline; is this an AIOS boot?")
        })
    }

    /// Hardening cmdline, LUKS UUID (`luks_uuid`, else the running cmdline's
    /// `rd.luks.name=`) and the ESP's volume id (`findmnt`).
    pub fn facts(&self, luks_uuid: Option<String>) -> Result<MachineFacts, Failure> {
        let path = &self.hardening_file;
        let hardening_cmdline = fs::read_to_string(path)
            .map_err(|e| Failure::op(format!("aios: {}: {e}", path.display())))?;
        let luks_uuid = match luks_uuid {
            Some(uuid) => uuid,
            None => fs::read_to_string(&self.layout.proc_cmdline)
                .ok()
                .and_then(|cmdline| luks_uuid_from_cmdline(&cmdline))
                .ok_or_else(|| {
                    Failure::op("aios: no rd.luks.name=<uuid>=aios on the kernel cmdline")
                })?,
        };
        Ok(MachineFacts {
            hardening_cmdline,
            luks_uuid,
            esp_uuid: self.esp_uuid()?,
        })
    }

    fn esp_uuid(&self) -> Result<String, Failure> {
        let esp = &self.layout.esp;
        // Touch the mount point first: /efi is an automount, and findmnt alone would only
        // see the autofs entry.
        let _ = fs::read_dir(esp);
        let out = run_ok(
            self.runner(),
            &Cmd::new("findmnt").args(["-no", "UUID"]).arg_path(esp),
        )?;
        out.stdout_text()
            .lines()
            .map(str::trim)
            .rev()
            .find(|line| !line.is_empty())
            .map(str::to_string)
            .ok_or_else(|| {
                Failure::op(format!("aios: findmnt shows no UUID for {}", esp.display()))
            })
    }
}
```

`aios-cli/crates/aios/src/commands.rs`:
```rust
use crate::cli::{Command, EnrollCommand, GenCommand};
use crate::context::Context;
use crate::failure::Failure;
use aios_exec::{apply, ops, ApplyCtx, Mode};
use aios_gen::GenId;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

pub fn run(command: Command) -> Result<(), Failure> {
    let cx = Context::from_env()?;
    cx.require_root()?;
    match command {
        Command::Plan => plan(&cx),
        Command::Apply { yes } => apply_cmd(&cx, yes),
        Command::Status => status(&cx),
        Command::Gen {
            command: GenCommand::List,
        } => gen_list(&cx),
        Command::Rollback { gen } => rollback(&cx, gen),
        Command::Gc { keep } => gc(&cx, keep),
        Command::Passwd { user } => passwd(&cx, &user),
        Command::Secureboot {
            command: EnrollCommand::Enroll,
        } => {
            let _lock = cx.lock(true)?;
            println!("{}", ops::secureboot_enroll(cx.runner())?);
            Ok(())
        }
        Command::Tpm {
            command: EnrollCommand::Enroll,
        } => {
            let _lock = cx.lock(true)?;
            println!("{}", ops::tpm_enroll(cx.runner(), &cx.layout)?);
            Ok(())
        }
        Command::Bootstrap {
            target,
            esp,
            manifest,
            luks_uuid,
        } => bootstrap(cx, &target, esp, &manifest, luks_uuid),
    }
}

fn plan(cx: &Context) -> Result<(), Failure> {
    let _lock = cx.lock(false)?;
    let manifest = cx.load_manifest()?;
    let facts = cx.facts(None)?;
    let plan = ops::plan(
        cx.runner(),
        &cx.layout,
        &manifest,
        &facts,
        SystemTime::now(),
    )?;
    print!("{plan}");
    Ok(())
}

fn apply_cmd(cx: &Context, yes: bool) -> Result<(), Failure> {
    let _lock = cx.lock(true)?;
    let manifest = cx.load_manifest()?;
    let facts = cx.facts(None)?;
    let booted = cx.booted()?;
    let plan = ops::plan(
        cx.runner(),
        &cx.layout,
        &manifest,
        &facts,
        SystemTime::now(),
    )?;
    print!("{plan}");
    if plan.is_empty() {
        return Ok(());
    }
    if !yes && !confirm()? {
        return Err(Failure::op("aios: aborted"));
    }
    let outcome = apply(&ApplyCtx {
        runner: cx.runner(),
        layout: &cx.layout,
        manifest: &manifest,
        facts: &facts,
        now: SystemTime::now(),
        mode: Mode::Apply { booted },
        trusted_uid: cx.trusted_uid(),
    })?;
    println!("reboot to activate gen-{}", outcome.gen);
    Ok(())
}

/// `Proceed? [y/N]` on stdout; anything but y/yes declines.
fn confirm() -> Result<bool, Failure> {
    print!("Proceed? [y/N] ");
    io::stdout().flush().ok();
    let mut answer = String::new();
    io::stdin()
        .lock()
        .read_line(&mut answer)
        .map_err(|e| Failure::op(format!("aios: reading the answer: {e}")))?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn status(cx: &Context) -> Result<(), Failure> {
    let _lock = cx.lock(false)?;
    print!("{}", ops::status(cx.runner(), &cx.layout)?);
    Ok(())
}

fn gen_list(cx: &Context) -> Result<(), Failure> {
    let _lock = cx.lock(false)?;
    let rows = ops::gen_list(cx.runner(), &cx.layout)?;
    print!("{}", ops::render_gen_list(&rows));
    Ok(())
}

fn rollback(cx: &Context, gen: u32) -> Result<(), Failure> {
    let _lock = cx.lock(true)?;
    let gen = GenId::new(gen).ok_or_else(|| Failure::op("aios: generation out of range"))?;
    let entry = ops::rollback(cx.runner(), &cx.layout, gen)?;
    println!("gen-{gen} boots next ({entry}); reboot to activate it");
    Ok(())
}

fn gc(cx: &Context, keep: usize) -> Result<(), Failure> {
    let _lock = cx.lock(true)?;
    let deleted = ops::gc(cx.runner(), &cx.layout, keep)?;
    if deleted.is_empty() {
        println!("nothing to delete");
    } else {
        let names: Vec<String> = deleted.iter().map(|g| format!("gen-{g}")).collect();
        println!("deleted {}", names.join(" "));
    }
    Ok(())
}

fn passwd(cx: &Context, user: &str) -> Result<(), Failure> {
    let _lock = cx.lock(true)?;
    let password = read_password(cx, user)?;
    let path = ops::passwd(cx.runner(), &cx.layout, user, &password)?;
    println!("wrote {}; run `aios apply` to use it", path.display());
    Ok(())
}

/// Prompt twice on the terminal. Under `AIOS_FAKE_RUNNER`, `AIOS_TEST_PASSWORD` instead.
fn read_password(cx: &Context, user: &str) -> Result<String, Failure> {
    if cx.fake {
        return std::env::var("AIOS_TEST_PASSWORD")
            .map_err(|_| Failure::op("aios: AIOS_TEST_PASSWORD is not set"));
    }
    let prompt = |text: String| {
        rpassword::prompt_password(text)
            .map_err(|e| Failure::op(format!("aios: reading the password: {e}")))
    };
    let first = prompt(format!("New password for {user}: "))?;
    let second = prompt("Retype the password: ".to_string())?;
    if first != second {
        return Err(Failure::op("aios: the passwords do not match"));
    }
    Ok(first)
}

/// Installer only: everything lives below the target's subvolumes.
fn bootstrap(
    mut cx: Context,
    target: &Path,
    esp: PathBuf,
    manifest: &Path,
    luks_uuid: String,
) -> Result<(), Failure> {
    let config = manifest
        .parent()
        .ok_or_else(|| Failure::op("aios: --manifest must name a file inside the repo"))?;
    let l = &mut cx.layout;
    l.top = target.to_path_buf();
    l.esp = esp;
    l.config = config.to_path_buf();
    l.persist = target.join("@persist");
    l.secrets = l.persist.join("aios/secrets");
    l.home = target.join("@home");
    l.log = target.join("@log");
    let _lock = cx.lock(true)?;
    let manifest = cx.load_manifest()?;
    let facts = cx.facts(Some(luks_uuid))?;
    let outcome = apply(&ApplyCtx {
        runner: cx.runner(),
        layout: &cx.layout,
        manifest: &manifest,
        facts: &facts,
        now: SystemTime::now(),
        mode: Mode::Bootstrap,
        trusted_uid: cx.trusted_uid(),
    })?;
    println!("gen-{} built in {}", outcome.gen, target.display());
    Ok(())
}
```

`aios-cli/crates/aios/src/main.rs`:
```rust
//! `aios`: the one way to change an AIOS system (spec §4.2).
//!
//! Exit codes: 0 success, 1 operational error (including usage errors), 2 invalid manifest.

mod cli;
mod commands;
mod context;
mod failure;
mod lock;

use clap::Parser;
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = match cli::Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            // Help and version go to stdout and exit 0; usage errors exit 1, because 2
            // means "invalid manifest".
            let _ = e.print();
            return if e.use_stderr() {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            };
        }
    };
    match commands::run(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            eprintln!("{failure}");
            ExitCode::from(failure.code)
        }
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd aios-cli && cargo test -p aios --test cli`
Expected: `test result: ok. 9 passed`.

- [ ] **Step 6: Lint**

Run: `make check`
Expected: as in Task 1.

- [ ] **Step 7: Commit**

```bash
cd /home/eli/Development/AIOS
git add aios-cli/
git commit -m "feat(cli): aios binary with lock, root check, manifest loading and exit codes"
```

---
### Task 12: `make check` gate for Phase 3

**Files:** none expected. A fix is committed only if a step below finds a problem.

- [ ] **Step 1: Full check**

Run: `make check`
Expected: fmt, clippy, shellcheck and `systemd-analyze verify` print no diagnostics, and bats passes. `cargo test --workspace` reports `test result: ok` for every binary, with these counts for the Phase 3 binaries:

| Crate | Binary | Passed |
|---|---|---|
| aios-exec | `apply_build` | 18 |
| aios-exec | `apply_golden` | 11 |
| aios-exec | `apply_prepare` | 14 |
| aios-exec | `boot` | 8 |
| aios-exec | `btrfs` | 7 |
| aios-exec | `etcfs` | 7 |
| aios-exec | `inspect` | 8 |
| aios-exec | `layout` | 5 |
| aios-exec | `passwd` | 4 |
| aios-exec | `plan` | 5 |
| aios-exec | `probe` | 10 |
| aios-exec | `runner` | 10 |
| aios-exec | `security` | 6 |
| aios-exec | `steps` | 2 |
| aios-exec | `sys` | 8 |
| aios | `cli` | 9 |

That makes 123 for `aios-exec` and 9 for `aios`. The Phase 1, 2 and 4 crates keep their counts.

- [ ] **Step 2: Only the runner starts processes**

Run: `cd /home/eli/Development/AIOS && grep -rln "std::process" aios-cli/crates/aios-exec/src`
Expected: exactly `aios-cli/crates/aios-exec/src/runner.rs`.

Run: `grep -rln "RealRunner" aios-cli/crates/*/tests`
Expected: exactly `aios-cli/crates/aios-exec/tests/runner.rs`, whose only `RealRunner` test spawns a program that does not exist.

- [ ] **Step 3: Tests run unprivileged**

Run: `id -u`
Expected: a non-zero uid. Step 1 has already passed as this user.

- [ ] **Step 4: The release build Phase 4's PKGBUILD runs**

Run: `cd aios-cli && cargo build --release --locked -p aios && ./target/release/aios --version`
Expected: the build succeeds without touching `Cargo.lock`, and the binary prints `aios 0.1.0`.

- [ ] **Step 5: Commit (only if Steps 1–4 required a change)**

```bash
cd /home/eli/Development/AIOS
git status --short
```
Expected: no output after Task 11's commit. If a fix was needed, commit it:
```bash
git add aios-cli/
git commit -m "chore: phase 3 make check fixes"
```

---

## Contracts for Phase 4/5 (packaging, installer, ISO, e2e)

These follow from the Phase 3 code. Later phases must honor them.

1. **CLI surface.** Every command needs root, or `AIOS_FAKE_RUNNER` (tests).
   - **Read-only commands** take a shared lock:
     - `aios plan`
     - `aios status`
     - `aios gen list`
   - **Mutating commands** take an exclusive lock:
     - `aios apply [--yes]`
     - `aios rollback <N>`, where `N` is `1..=9999` and `7`/`0007` both work
     - `aios gc [--keep K]`, default 5
     - `aios passwd <user>`
     - `aios secureboot enroll`
     - `aios tpm enroll`
     - `aios bootstrap --target <top> --esp <esp> --manifest <path> --luks-uuid <uuid>`
2. **Exit codes:**
   - 0: success, including `apply` with "no changes".
   - 1: any operational error, including a clap usage error, the lock being held, a missing root check and a declined confirmation.
   - 2: an invalid manifest only.
3. **Output the e2e harness can match:**
   - The plan prints `no changes` (and warnings) when clean.
   - `apply` prints `reboot to activate gen-NNNN` on success.
   - Step failures print `aios: step <name> failed: <detail>`. Step names: `lock validate commit-manifest mount-top prepare-candidate assemble packages keyring render-etc services uki sign esp-space finalize cleanup`.
   - Lock contention prints `aios: another aios operation is running`.
   - Progress lines `aios: <step>` go to stderr.
4. **Paths:** `/run/aios/top` and `/run/aios/cand` are mount points, created on demand. Also:
   - `/run/aios.lock` (flock).
   - `/run/aios/aios-pacstrap.conf`, left behind by `bootstrap`.
   - `/persist/aios/config/manifest.toml` (git repo) and `/persist/aios/secrets/passwd/<user>` (one yescrypt line, 0600; `secrets/` and `passwd/` 0700).
   - `/usr/lib/aios/cmdline-hardening` (read verbatim) and `/usr/share/zoneinfo`.
   - The ESP's `/EFI/Linux/aios-gen-NNNN-{cachyos,lts}+3.efi`. Transient copies are `…+3.efi.tmp` and are never booted.
5. **Test hooks (env), in `test-hooks` builds only.** The `aios` binary reads these only when built with the `test-hooks` cargo feature (off by default; the CLI tests need `--all-features`). The shipped binary reads no `AIOS_*` variable at all, and `make check` fails if its release build contains any `AIOS_` string. Later phases can't use them to steer an installed or ISO `aios`.
   - Layout overrides: `AIOS_TOP AIOS_CAND AIOS_ESP AIOS_CONFIG AIOS_SECRETS AIOS_PERSIST AIOS_HOME AIOS_LOG AIOS_LIVE_ETC AIOS_CMDLINE AIOS_EFIVARS AIOS_LOCK AIOS_DEVICE`.
   - Other inputs: `AIOS_ZONEINFO` and `AIOS_HARDENING_CMDLINE_FILE`.
   - `AIOS_FAKE_RUNNER=<json>` with `{"respond": [{"argv": [...], "status": 0, "stdout": "", "stderr": ""}], "fail_on": [[...]], "emulate_top": "<top>", "emulate_subvolumes": false}`, every key optional. Calls are appended to `<json>.calls`. Under it, `AIOS_TEST_PASSWORD` feeds `aios passwd`, and the trusted owner is the caller's euid instead of root.
6. **Ownership (TOCTOU mitigation).** `plan`, `apply` and `bootstrap` refuse unless the manifest repo directory and the secrets directory are owned by root and not group/world-writable. The same goes for the repo's `.git` and `.git/config` where present, which may not be symlinks either (nor `.git` a `gitdir:` file), because git as root reads no other config. The installer must create `@persist/aios/config` (with `git init` as root and the default umask) and `@persist/aios/secrets` as root, 0755/0700 or stricter.
7. **What `bootstrap` expects from the installer:**
   - **Disk:** the btrfs top level mounted at `--target`, containing:
     - `@blank` (the §2 skeleton, read-only, including `var/lib/pacman → ../../usr/lib/pacman`);
     - `@persist`, `@home` and `@log`;
     - no `@usr-gen-*`/`@etc-gen-*` (refused otherwise).

     The ESP is mounted at `--esp`, and `--luks-uuid` comes from `cryptsetup luksUUID <partition>`.
   - **Manifest repo:** `@persist/aios/config` is a git repo with at least one commit (`rev-parse HEAD` must work). It is root-owned (item 6), and its manifest validates against `@persist/aios/secrets`.
   - **Local repo:** `@persist/aios/repo` holds the local repo (`[aios-local]`, bound into the candidate; `pacstrap` reads it through `file://<cand>/persist/aios/repo`).
   - **The live system:**
     - `/var/lib/sbctl` holds the keys (bind from `@persist/var/lib/sbctl`), because `sbctl sign` runs on the host.
     - Every `Include =` file named by the manifest's `pacman.conf` exists (the CachyOS mirrorlists).
     - Its pacman keyring trusts the CachyOS signing key. `pacstrap` verifies with, and copies, the host keyring.
   - **Packages:** the manifest's packages include `cachyos-keyring`, because the keyring step runs `pacman-key --populate archlinux cachyos`. The default manifest already lists it.
   - **Afterwards:** the installer runs `bootctl install`, writes `loader_conf()` to the ESP and signs systemd-boot. `bootstrap` doesn't call `bootctl`.
8. **Generation contents.** Every generation has:
   - `aios-health.service` enabled;
   - `/etc/aios/generation.toml` (`GenerationMeta`, `parent = 0` for gen-1);
   - `/etc/aios/managed-files`;
   - `/etc/kernel/cmdline`.

   Its UKIs are `aios-gen-NNNN-cachyos+3.efi`, plus `-lts+3.efi` when there is a fallback. `bootstrap` creates `@home/<user>` (0700, uid:uid); `apply` never touches `/home`.
9. **Render context.** `RenderCtx` is only ever built through `RenderCtx::new`, via `MachineFacts::render_ctx`. Invalid facts fail the `validate` step.
10. **Boot-time consistency (Phase 4, already merged).** `aios-root.sh` and `aios-health.sh` fail on conflicting `aios.gen=` values, as `gen_from_cmdline` does. `aios-root.sh` deletes the same candidate names (`@usr-cand @etc-cand @root-cand`) with the same `subvolume show` + `delete --recursive` sequence the executor uses.
11. **PKGBUILD (Phase 4 Task 7).** `cargo build --release --locked -p aios` builds `target/release/aios`. `Cargo.lock` is committed with every new dependency.

---

## Self-review

- **Spec coverage:**

  | Spec item | Task | Tests |
  |---|---|---|
  | §4.5 `CommandRunner` (real + fake, scripted, recorded argv) | 1 | `runner.rs` |
  | §4.5 env overrides for tests (`AIOS_TOP`, `AIOS_ESP`, `AIOS_CONFIG`, `AIOS_SECRETS`, `AIOS_FAKE_RUNNER`) | 2, 11 | `every_path_has_an_env_override`, `cli.rs` |
  | §4.3 step 1 lock, validate, commit dirty repo, record `HEAD`, mount top | 5, 11 | `a_dirty_repo_is_committed_for_the_new_generation`, `mounts_the_top_level_and_records_head_of_a_clean_repo`, `a_held_lock_stops_a_second_command` |
  | §4.3 step 2 stale candidates, snapshots | 5 | `stale_candidates_are_deleted_first`, `snapshots_the_booted_generation_and_blank` |
  | §4.3 step 3 assembly with binds | 5 | `assembles_the_candidate_root` |
  | §4.3 step 4 packages (`-Syu`, `-Rns`, `-D --asexplicit`, orphans) | 6 | `apply_upgrades_removes_marks_and_drops_orphans`, `nothing_to_remove_means_no_removal_calls` |
  | §4.2 bootstrap with `pacstrap`, empty candidates | 5, 6, 8 | `bootstrap_pacstraps_with_a_rewritten_conf_and_inits_the_keyring`, `golden_bootstrap` |
  | §4.3 steps 5–6 render `/etc`, users, generation.toml, locale-gen, owners | 6 | `renders_the_desired_etc_into_the_candidate`, `generation_toml_records_ids_commit_kernels_and_package_hash`, `paths_the_old_generation_managed_are_removed` |
  | §4.3 step 7 services + `aios-health.service` | 6 | `services_follow_the_manifest_plus_core_units`, `masked_units_are_unmasked_and_missing_units_are_not_disabled` |
  | §4.3 steps 8–9 UKIs (default + fallback), signing | 8 | `golden_apply`, `without_a_fallback_kernel_one_uki_is_built` |
  | §4.3 step 10 ESP space with gc | 8 | `a_full_esp_runs_gc_then_fails` |
  | §4.3 steps 11–12 finalize, crash-safe UKI copy, `bootctl set-default ""` | 8 | `golden_apply`, `the_new_generation_lands_on_disk_and_on_the_esp`, `a_failed_finalize_deletes_the_candidates_and_esp_copies` |
  | §4.3 abort deletes candidates, names the step (§7) | 5, 6, 8 | one failure test per step: mount-top, validate, commit-manifest, prepare-candidate, assemble, packages, keyring, render-etc, services, uki, sign, esp-space, finalize |
  | §4.2 `rollback` | 7, 11 | `rollback_sets_the_default_entry_without_the_counter`, `rollback_needs_a_boot_entry`, CLI rollback tests |
  | §4.2 `gc` (keep K, booted/default/gen-1 protected) | 7 | `gc_keeps_the_newest_protected_and_gen_one`, `gc_with_keep_zero_still_keeps_booted_and_default` |
  | §4.2 `gen list` | 9 | `rows_carry_metadata_and_boot_states`, `the_table_has_a_header_and_one_line_per_generation` |
  | §4.2 `status` (booted/default/bad, drift) | 9 | `drift_lists_added_modified_and_removed_paths`, `status_reports_boot_state_and_drift` |
  | §4.2 `passwd` (yescrypt via `mkpasswd`) | 10, 11 | `writes_the_yescrypt_hash_privately`, `passwd_writes_the_secret` |
  | §4.2/§5.1 `secureboot enroll`, `tpm enroll` | 10 | `security.rs` |
  | §4.2 `plan`, §1 (c) "no changes" on a fresh generation | 10, 11 | `a_generation_built_from_this_manifest_has_no_changes`, `plan_prints_the_plan` |
  | §7 invalid manifest → `manifest.toml:line:col`, exit 2 | 11 | `an_invalid_manifest_exits_2_with_locations` |
  | §7 concurrent commands → exit 1 with the message | 11 | `a_held_lock_stops_a_second_command` |

- **Decisions made beyond the design notes:**
  - **Task order:** Task 7 (`gc`) moved ahead of apply part 3, because `esp-space` calls `gc_mounted`. That makes 12 tasks.
  - **Step order:** `mount-top` runs before `commit-manifest`, because the commit message needs the new id, and the id needs the top level.
  - **Validate step:** `validate` checks the manifest repo/secrets ownership and `RenderCtx::new`. `ApplyCtx.trusted_uid` and `check_trusted_dirs(layout, uid)` keep it testable without root; the CLI passes 0, or its own euid under `AIOS_FAKE_RUNNER`.
  - **Manifest commit:** it runs `git add -A` first, so new files are committed, and passes `-c user.name=aios -c user.email=aios@localhost` because root has no git identity.
  - **Bootstrap:** it never mounts or unmounts the top level (the installer did), and it refuses a target that already holds generations.
  - **Subvolume deletion:** it is `btrfs subvolume show` + `btrfs subvolume delete --recursive`, matching `aios-root.sh` after the security pass, instead of parsing `subvolume list -o`.
  - **Crash-safe ESP copy:** UKIs go to the ESP as `.tmp` before the candidate is unmounted, and are renamed into place after the subvolume renames. `esp-space` removes stale `.tmp` copies.
  - **pacstrap:** the conf drops `LogFile` as well as `DBPath`, rewrites `file:///persist/` to the candidate's bind of the local repo, and is left in `/run/aios/`. `cand/usr/lib/pacman` is created before pacstrap.
  - **services:**
    - A masked unit that is now wanted is unmasked first.
    - `disable` skips units without a unit file.
    - There is one `systemctl` call per verb, and precedence follows the planner.
  - **chown:** `[files]` owners use `chown -h`, so a symlink is never followed.
  - **`/home`:** apply never touches it; bootstrap creates `@home/<user>` (coordinator update, superseding Phase 2 contract 6's home part).
  - **Locking:** read-only commands take a shared lock, so they cannot stack a read-only top-level mount over an apply.
  - **Usage errors** exit 1, keeping 2 for invalid manifests only.
  - **Bootstrap LUKS UUID:** it comes from `--luks-uuid`, not `cryptsetup` through the runner.
  - **`Layout`:**
    - `device` is a field.
    - `log` and `live_etc` were added, with `AIOS_LOG`, `AIOS_LIVE_ETC`, `AIOS_EFIVARS` and `AIOS_DEVICE`.
    - `under()` builds test layouts.
  - **Unit states:** `linked` maps to `Disabled`, `transient` to `Static`, and `bad` is an error.
  - **`RealRunner`** inherits stdin unless the command supplies bytes, and captures stdout and stderr.
  - **`plan`'s units** come from the running system's `systemctl is-enabled`, because a bare `/etc` snapshot isn't a root for `--root`.
  - **gc protection:** gc protects the booted generation, the `bootctl` override and the newest good main UKI, so `--keep 0` can't delete the default. UKIs are deleted before their subvolumes.
  - **Kernel versions** come from `usr/lib/modules/*/pkgbase`. Several directories for one kernel is an error.
  - **Drift** counts mode changes as modified, and lists unreadable entries as notes.
  - **ESP id:** the ESP directory is touched before `findmnt` (automount), and the last non-empty line is used.
  - **`generation.toml` kernels** come from one `pacman -Q <kernels>` call.
- **Known limits, left to later phases:**
  - **Upgrades:** `aios apply` with "no changes" builds nothing, so a pure package upgrade needs a manifest change (follow-up: `aios apply --upgrade`).
  - **`pacman.conf` timing:** packages run before `/etc` is rendered, so a repo added to the manifest's `pacman.conf` is used from the next apply on.
  - **`enable` is additive:** a unit dropped from `enable` stays enabled. To turn it off, list it under `disable`.
  - **Working tree, not commit:** apply reads manifest sources from the working tree, not from `manifest_commit` (spec follow-up #8). The ownership check narrows the race.
  - **Logging:** there is no journal logging (`SYSLOG_IDENTIFIER=aios`). Step lines go to stderr, and command output is captured and shown only on failure, so a long `pacman -Syu` shows no progress.
  - **Unit drift:** `plan` sees runtime unit enablement drift (live `/etc/systemd`) as the booted state.
- **Placeholder scan:** every step has complete code or an exact command. There is no "TBD" and no "similar to Task N".
- **Type consistency:**
  - `ExecError`, `Cmd`, `Output`, `Layout`, `MachineFacts`, `Step`, `StepError`, `ApplyCtx`, `Mode` and `ApplyOutcome` are each defined once in `aios-exec`.
  - The CLI uses them only through the public API.
  - Phase 1 and Phase 2 APIs are used exactly as listed under "Depends on".
