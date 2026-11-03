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
