//! The `aios` binary end to end, with `AIOS_FAKE_RUNNER` and every path in a tempdir.
//! Needs the `test-hooks` feature (the binary reads no `AIOS_*` variable without it).

use aios_exec::{days_since_epoch, etcfs, read_hashes, DirProbe, FakeRunner, Layout, MachineFacts};
use aios_gen::{GenId, GenerationMeta};
use aios_plan::{desired_etc, Inputs};
use rustix::fs::{flock, FlockOperation};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::SystemTime;
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
const RESPOND: &str = r#"[
    {"argv": ["findmnt"], "stdout": "7A1B-2C3D\n"},
    {"argv": ["pacman", "-Qqe"], "stdout": "zsh\n"},
    {"argv": ["systemctl", "is-enabled"], "stdout": "enabled\n"},
    {"argv": ["mkpasswd"], "stdout": "$y$j9T$abc$def\n"}
]"#;

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
        m.script(RESPOND, "[]");
        m
    }

    /// Write the fake runner's script: these `respond` and `fail_on` lists, and the top
    /// level emulated wherever a reader mounts it.
    fn script(&self, respond: &str, fail_on: &str) {
        let top = self.path("top");
        let script = format!(
            r#"{{"respond": {respond}, "fail_on": {fail_on}, "emulate_top": "{}"}}"#,
            top.display()
        );
        self.write("fake.json", &script, 0o644);
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
        self.aios_with_stdin(args, "").0
    }

    /// Run `aios ARGS` with `stdin` as its standard input. Returns its pid too.
    fn aios_with_stdin(&self, args: &[&str], stdin: &str) -> (Output, u32) {
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
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let pid = child.id();
        let written = child.stdin.take().unwrap().write_all(stdin.as_bytes());
        // A command that never reads its input may exit first.
        if let Err(e) = written {
            assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe, "{e}");
        }
        (child.wait_with_output().unwrap(), pid)
    }

    fn calls(&self) -> String {
        fs::read_to_string(self.path("fake.json.calls")).unwrap_or_default()
    }

    /// Make `@etc-gen-0001` what the manifest renders for gen-1 and the running system's
    /// packages and units match it, so `aios plan` shows no changes. `fail_on` as in
    /// `script`.
    fn sync(&self, fail_on: &str) {
        let layout = Layout::under(self.dir.path());
        let manifest = aios_manifest::parse(MANIFEST).unwrap();
        let facts = MachineFacts {
            hardening_cmdline: "quiet\n".to_string(),
            luks_uuid: LUKS_UUID.to_string(),
            esp_uuid: "7A1B-2C3D".to_string(),
        };
        let ctx = facts.render_ctx(GenId(1)).unwrap();
        let hashes = read_hashes(&layout, &manifest).unwrap();
        let inputs = Inputs {
            manifest: &manifest,
            repo_root: &layout.config,
            ctx: &ctx,
            hashes: &hashes,
            today_days: days_since_epoch(SystemTime::now()),
        };
        let snapshot = layout.subvol("@etc-gen-0001");
        let quiet = FakeRunner::new();
        let probe = DirProbe::new(&snapshot, &quiet, None);
        for (path, entry) in desired_etc(&inputs, &probe).unwrap() {
            etcfs::write(&snapshot, &path, &entry).unwrap();
        }
        let respond = format!(
            r#"[
                {{"argv": ["findmnt"], "stdout": "7A1B-2C3D\n"}},
                {{"argv": ["pacman", "-Qqe"], "stdout": "{}\n"}},
                {{"argv": ["systemctl", "is-enabled"], "stdout": "enabled\n"}}
            ]"#,
            manifest.package_set().join("\\n")
        );
        self.script(&respond, fail_on);
    }

    /// Make a full build possible: `@blank`, the candidate tree the package manager would
    /// leave (accounts, kernel modules, the UKI ukify builds for gen-2), and a script that
    /// emulates subvolumes and answers the build's queries, with `fail_on` as in `script`.
    fn buildable(&self, fail_on: &str) {
        fs::create_dir_all(self.path("top/@blank")).unwrap();
        self.write(
            "cand/etc/passwd",
            "root:x:0:0::/root:/usr/bin/bash\n",
            0o644,
        );
        self.write("cand/etc/group", "root:x:0:root\nwheel:x:998:\n", 0o644);
        self.write("cand/etc/shadow", "root:*:20000::::::\n", 0o600);
        self.write("cand/etc/gshadow", "root:::root\nwheel:!*::\n", 0o600);
        self.write(
            "cand/usr/lib/modules/7.3.0-4-cachyos/pkgbase",
            "linux-cachyos\n",
            0o644,
        );
        self.write("cand/var/tmp/aios/aios-gen-0002-cachyos.efi", "UKI", 0o644);
        let config = self.path("config").display().to_string();
        let script = format!(
            r#"{{"respond": [
                    {{"argv": ["findmnt"], "stdout": "7A1B-2C3D\n"}},
                    {{"argv": ["pacman", "-Qqe"], "stdout": "zsh\n"}},
                    {{"argv": ["systemctl", "is-enabled"], "stdout": "enabled\n"}},
                    {{"argv": ["git", "-C", "{config}",
                               "--attr-source=4b825dc642cb6eb9a060e54bf8d69288fbee4904",
                               "-c", "core.attributesFile=/dev/null",
                               "-c", "core.hooksPath=/dev/null",
                               "-c", "core.fsmonitor=false", "-c", "commit.gpgsign=false",
                               "rev-parse"], "stdout": "3f9c2a1\n"}},
                    {{"argv": ["mountpoint"], "status": 32}},
                    {{"argv": ["df"], "stdout": "Avail\n2000000000\n"}}
                ],
                "fail_on": {fail_on},
                "emulate_top": "{}",
                "emulate_subvolumes": true}}"#,
            self.path("top").display()
        );
        self.write("fake.json", &script, 0o644);
    }

    /// Hold the lock the way another aios command would. Released on drop.
    fn hold_lock(&self, operation: FlockOperation) -> fs::File {
        let held = fs::File::create(self.path("aios.lock")).unwrap();
        flock(&held, operation).unwrap();
        held
    }

    /// The installer's view: a new top level at `target/` with the manifest repo (holding
    /// `manifest.toml` and `custom.toml`) and secrets in `@persist`.
    fn bootstrap_target(&self, custom: &str) -> PathBuf {
        let config = "target/@persist/aios/config";
        self.write(&format!("{config}/manifest.toml"), MANIFEST, 0o644);
        self.write(&format!("{config}/custom.toml"), custom, 0o644);
        self.write(
            &format!("{config}/files/nftables.conf"),
            "flush ruleset\n",
            0o644,
        );
        self.write(&format!("{config}/home/eli/zshrc"), "# zshrc\n", 0o644);
        let secrets = "target/@persist/aios/secrets";
        self.write(
            &format!("{secrets}/passwd/eli"),
            "$y$j9T$salt$hash\n",
            0o600,
        );
        fs::set_permissions(self.path(config), fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(self.path(secrets), fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir_all(self.path("target-esp")).unwrap();
        self.path(config)
    }
}

/// The read-write mount every build starts with. Scripted to fail in the apply tests,
/// which only check that the build starts: the build itself is aios-exec's.
const WRITER_MOUNT: &str = r#"[["mount", "-t", "btrfs", "-o", "subvolid=5"]]"#;

fn writer_mount(m: &Machine) -> String {
    format!(
        "mount -t btrfs -o subvolid=5 /dev/mapper/aios {}\n",
        m.path("top").display()
    )
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
    let (out, pid) = m.aios_with_stdin(&["plan"], "");
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(stdout.contains("/etc:\n"), "{stdout}");
    assert!(stdout.contains("  + /etc/hostname\n"), "{stdout}");
    assert!(stdout.contains("  ~ /etc/passwd\n"), "{stdout}");
    let ro = m.path(&format!("ro.{pid}"));
    let calls = m.calls();
    assert!(
        calls.starts_with(&format!(
            "findmnt -no UUID {}\nmount -t btrfs -o subvolid=5,ro /dev/mapper/aios {}\n",
            m.path("esp").display(),
            ro.display()
        )),
        "{calls}"
    );
    assert!(
        calls.ends_with(&format!("umount {}\n", ro.display())),
        "{calls}"
    );
    assert!(!ro.exists(), "the reader's mount point is removed");
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

/// gen-7: both subvolumes, and a main UKI named `uki`.
fn gen_7(m: &Machine, uki: &str) {
    fs::create_dir_all(m.path("top/@usr-gen-0007")).unwrap();
    fs::create_dir_all(m.path("top/@etc-gen-0007")).unwrap();
    m.write(&format!("esp/EFI/Linux/{uki}"), "uki", 0o644);
}

/// What `aios rollback 7` (process `pid`) runs: a read-only look at the top level, then
/// bootctl.
fn rollback_calls(m: &Machine, pid: u32) -> String {
    let ro = m.path(&format!("ro.{pid}"));
    format!(
        "mount -t btrfs -o subvolid=5,ro /dev/mapper/aios {}\numount {}\n\
         bootctl set-default aios-gen-0007-cachyos.efi\n",
        ro.display(),
        ro.display()
    )
}

#[test]
fn gc_refuses_without_a_booted_generation() {
    let m = Machine::new();
    gen_7(&m, "aios-gen-0007-cachyos+3.efi");
    m.write("cmdline", "root=/dev/mapper/aios rw quiet\n", 0o644);
    let out = m.aios(&["gc", "--keep", "0"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        text(&out.stderr),
        "aios: cannot determine the booted generation; refusing to garbage-collect\n"
    );
    assert!(!m.calls().contains("delete"), "{}", m.calls());
    assert!(m.path("top/@usr-gen-0007").is_dir());
}

#[test]
fn rollback_sets_the_boot_default() {
    let m = Machine::new();
    gen_7(&m, "aios-gen-0007-cachyos+3.efi");
    let (out, pid) = m.aios_with_stdin(&["rollback", "0007"], "");
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
    assert_eq!(m.calls(), rollback_calls(&m, pid));
}

#[test]
fn rollback_refuses_a_bad_generation_without_dash_dash_force() {
    let m = Machine::new();
    gen_7(&m, "aios-gen-0007-cachyos+0-3.efi");
    let out = m.aios(&["rollback", "7"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        text(&out.stderr),
        "aios: gen-0007 is marked bad (its boot tries ran out); use --force to boot it \
         anyway\n"
    );
    assert_eq!(m.calls(), "");
    let (out, pid) = m.aios_with_stdin(&["rollback", "--force", "7"], "");
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
    assert_eq!(m.calls(), rollback_calls(&m, pid));
}

#[test]
fn rollback_needs_the_generation_s_subvolumes() {
    let m = Machine::new();
    m.write("esp/EFI/Linux/aios-gen-0007-cachyos+3.efi", "uki", 0o644);
    let out = m.aios(&["rollback", "7"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        text(&out.stderr),
        "aios: gen-0007 is not installed: @usr-gen-0007 is missing\n"
    );
    assert!(!m.calls().contains("bootctl"));
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

#[test]
fn apply_asks_first_and_anything_but_yes_aborts() {
    let m = Machine::new();
    let (out, _) = m.aios_with_stdin(&["apply"], "n\n");
    assert_eq!(out.status.code(), Some(1));
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains("  + /etc/hostname\n"),
        "the plan comes first: {stdout}"
    );
    assert!(stdout.ends_with("Proceed? [y/N] "), "{stdout}");
    assert_eq!(text(&out.stderr), "aios: aborted\n");
    assert!(!m.calls().contains(&writer_mount(&m)), "nothing was built");
}

#[test]
fn apply_builds_after_yes_or_with_dash_dash_yes() {
    for (args, stdin) in [(&["apply"][..], "y\n"), (&["apply", "--yes"][..], "")] {
        let m = Machine::new();
        m.script(RESPOND, WRITER_MOUNT);
        let (out, _) = m.aios_with_stdin(args, stdin);
        let stdout = text(&out.stdout);
        assert_eq!(
            stdout.contains("Proceed?"),
            stdin == "y\n",
            "{args:?}: {stdout}"
        );
        assert!(
            m.calls().contains(&writer_mount(&m)),
            "{args:?}: {}",
            m.calls()
        );
        assert!(
            text(&out.stderr).contains("aios: step mount-top failed: "),
            "{}",
            text(&out.stderr)
        );
        assert_eq!(out.status.code(), Some(1));
    }
}

#[test]
fn apply_builds_gen_2_and_reports_post_commit_failures_as_warnings() {
    let m = Machine::new();
    m.buildable(r#"[["bootctl"]]"#);
    let out = m.aios(&["apply", "--yes"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr: {stderr}");
    let rev_parse = format!(
        "GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_ATTR_NOSYSTEM=1 git -C {} \
         --attr-source=4b825dc642cb6eb9a060e54bf8d69288fbee4904 \
         -c core.attributesFile=/dev/null -c core.hooksPath=/dev/null \
         -c core.fsmonitor=false -c commit.gpgsign=false rev-parse --short HEAD\n",
        m.path("config").display()
    );
    assert!(m.calls().contains(&rev_parse), "{}", m.calls());
    assert!(
        stderr.contains(
            "\naios: warning: `bootctl set-default ''` exited with status 1: injected \
             failure; `bootctl set-default ''` makes gen-0002 the default\n"
        ),
        "{stderr}"
    );
    assert!(
        text(&out.stdout).ends_with(
            "gen-0002 is installed; check the warnings above, then reboot to activate it\n"
        ),
        "{}",
        text(&out.stdout)
    );
    assert!(m.path("top/@usr-gen-0002").is_dir() && m.path("top/@etc-gen-0002").is_dir());
    assert!(m
        .path("esp/EFI/Linux/aios-gen-0002-cachyos+3.efi")
        .is_file());
    assert!(!m.path("top/@root-cand").exists());
}

#[test]
fn apply_without_changes_exits_0_and_builds_nothing() {
    let m = Machine::new();
    m.sync("[]");
    let (out, _) = m.aios_with_stdin(&["apply"], "");
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "no changes\n");
    assert!(!m.calls().contains(&writer_mount(&m)), "{}", m.calls());
}

#[test]
fn apply_upgrade_builds_even_without_changes() {
    let m = Machine::new();
    m.sync(WRITER_MOUNT);
    let (out, _) = m.aios_with_stdin(&["apply", "--upgrade", "--yes"], "");
    assert_eq!(
        text(&out.stdout),
        "no changes\nupgrading: no manifest changes\n"
    );
    assert!(m.calls().contains(&writer_mount(&m)), "{}", m.calls());
    assert!(text(&out.stderr).contains("aios: step mount-top failed: "));
}

#[test]
fn gen_list_prints_one_row_per_generation() {
    let m = Machine::new();
    let meta = GenerationMeta {
        id: 1,
        parent: 0,
        created: "2026-11-01T10:00:00Z".to_string(),
        manifest_commit: "3f9c2a1".to_string(),
        kernels: vec!["linux-cachyos 7.3.0-4".to_string()],
        package_set_sha256: "ab".repeat(32),
    };
    m.write(
        "top/@etc-gen-0001/aios/generation.toml",
        &meta.to_toml(),
        0o644,
    );
    m.write("esp/EFI/Linux/aios-gen-0001-cachyos.efi", "uki", 0o644);
    let out = m.aios(&["gen", "list"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout),
        "\
GEN   CREATED               COMMIT   STATE           KERNELS
0001  2026-11-01T10:00:00Z  3f9c2a1  booted,default  linux-cachyos 7.3.0-4
"
    );
}

#[test]
fn shared_readers_run_side_by_side() {
    let m = Machine::new();
    let _reader = m.hold_lock(FlockOperation::NonBlockingLockShared);
    for args in [&["gen", "list"][..], &["status"][..], &["plan"][..]] {
        let out = m.aios(args);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{args:?}: {}",
            text(&out.stderr)
        );
    }
}

#[test]
fn a_shared_holder_blocks_a_writer() {
    let m = Machine::new();
    let _reader = m.hold_lock(FlockOperation::NonBlockingLockShared);
    for args in [&["rollback", "7"][..], &["gc"][..], &["apply", "--yes"][..]] {
        let out = m.aios(args);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        assert_eq!(
            text(&out.stderr),
            "aios: another aios operation is running\n"
        );
    }
    assert_eq!(m.calls(), "");
}

#[test]
fn without_the_fake_runner_aios_needs_root() {
    if rustix::process::geteuid().is_root() {
        return; // the check passes as root, and a real command must not run here
    }
    let out = Command::new(env!("CARGO_BIN_EXE_aios"))
        .arg("status")
        .env_clear()
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        text(&out.stderr),
        "aios: must run as root (try: run0 aios <cmd>)\n"
    );
}

#[test]
fn bootstrap_loads_the_manifest_it_is_given() {
    let m = Machine::new();
    let invalid = MANIFEST.replace("Asia/Jerusalem", "Mars/Olympus");
    let config = m.bootstrap_target(&invalid);
    let custom = config.join("custom.toml");
    let (target, esp) = (m.path("target"), m.path("target-esp"));
    let out = m.aios(&[
        "bootstrap",
        "--target",
        &target.display().to_string(),
        "--esp",
        &esp.display().to_string(),
        "--manifest",
        &custom.display().to_string(),
        "--luks-uuid",
        LUKS_UUID,
    ]);
    assert_eq!(out.status.code(), Some(2), "stderr: {}", text(&out.stderr));
    assert_eq!(
        text(&out.stderr),
        "manifest.toml:3:1: unknown timezone \"Mars/Olympus\"\n"
    );
}

#[test]
fn bootstrap_needs_the_manifest_s_directory() {
    let m = Machine::new();
    m.bootstrap_target(MANIFEST);
    let (target, esp) = (m.path("target"), m.path("target-esp"));
    for manifest in ["manifest.toml", "/"] {
        let out = m.aios(&[
            "bootstrap",
            "--target",
            &target.display().to_string(),
            "--esp",
            &esp.display().to_string(),
            "--manifest",
            manifest,
            "--luks-uuid",
            LUKS_UUID,
        ]);
        assert_eq!(out.status.code(), Some(1), "{manifest}");
        assert_eq!(
            text(&out.stderr),
            "aios: --manifest must be a path to a file in the manifest repo, such as \
             <target>/@persist/aios/config/manifest.toml\n",
            "{manifest}"
        );
    }
    assert!(!Path::new("manifest.toml").exists());
}
