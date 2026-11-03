//! The default manifest shipped in aios-base (`manifest/` at the repo root) must be
//! valid once the installer has substituted its placeholders (spec §4.6, §6.2 step 6).

use aios_manifest::{parse, validate, Manifest, ValidationEnv};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const PLACEHOLDERS: [&str; 4] = ["@HOSTNAME@", "@USERNAME@", "@TIMEZONE@", "@EXTRA_CMDLINE@"];

fn default_manifest_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../manifest")
}

fn template() -> String {
    let path = default_manifest_dir().join("manifest.toml");
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// The installer's substitution (spec §6.2 step 6). `extra_cmdline` is a TOML string list body.
fn substitute(template: &str, extra_cmdline: &str) -> String {
    template
        .replace("@HOSTNAME@", "testhost")
        .replace("@USERNAME@", "tester")
        .replace("@TIMEZONE@", "UTC")
        .replace("@EXTRA_CMDLINE@", extra_cmdline)
}

fn copy_tree(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap();
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &to);
        } else {
            fs::copy(entry.path(), &to).unwrap();
        }
    }
}

/// Tempdir laid out like a fresh install: repo/{files, home/tester}, secrets/passwd/tester,
/// zoneinfo/UTC.
fn installed_env() -> (TempDir, ValidationEnv) {
    let src = default_manifest_dir();
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let repo = root.join("repo");
    copy_tree(&src.join("files"), &repo.join("files"));
    copy_tree(&src.join("home/@USERNAME@"), &repo.join("home/tester"));
    fs::create_dir_all(root.join("secrets/passwd")).unwrap();
    fs::write(root.join("secrets/passwd/tester"), "$y$j9T$hash\n").unwrap();
    fs::create_dir_all(root.join("zoneinfo")).unwrap();
    fs::write(root.join("zoneinfo/UTC"), "TZif").unwrap();
    let env = ValidationEnv {
        repo_root: repo,
        secrets_dir: root.join("secrets"),
        zoneinfo_dir: root.join("zoneinfo"),
    };
    (tmp, env)
}

fn parse_ok(raw: &str) -> Manifest {
    parse(raw).unwrap_or_else(|e| panic!("default manifest does not parse: {e}"))
}

#[test]
fn template_contains_every_placeholder() {
    let raw = template();
    for p in PLACEHOLDERS {
        assert!(raw.contains(p), "manifest.toml lacks placeholder {p}");
    }
}

#[test]
fn default_manifest_is_valid_after_substitution() {
    let (_tmp, env) = installed_env();
    let raw = substitute(&template(), "\"console=ttyS0,115200\"");
    let m = parse_ok(&raw);
    let errors: Vec<String> = validate(&m, &raw, &env)
        .iter()
        .map(|e| e.to_string())
        .collect();
    assert_eq!(errors, Vec::<String>::new());
    assert_eq!(m.system.hostname, "testhost");
    assert_eq!(m.system.timezone, "UTC");
    assert_eq!(
        m.kernel.extra_cmdline,
        vec!["console=ttyS0,115200".to_string()]
    );
    assert_eq!(m.users["tester"].uid, 1000);
    assert_eq!(m.files["/etc/nftables.conf"].mode_or_default(), "0600");
    assert_eq!(
        m.files["/etc/usbguard/usbguard-daemon.conf"].mode_or_default(),
        "0600"
    );
    assert!(m.services.enable.contains(&"systemd-timesyncd".to_string()));
}

#[test]
fn empty_extra_cmdline_parses() {
    let m = parse_ok(&substitute(&template(), ""));
    assert!(m.kernel.extra_cmdline.is_empty());
}

#[test]
fn default_package_set_has_cachyos_keyring_and_aios_base() {
    let m = parse_ok(&substitute(&template(), ""));
    let set = m.package_set();
    for p in [
        "cachyos-keyring",
        "aios-base",
        "aios-cli",
        "linux-cachyos",
        "linux-cachyos-lts",
    ] {
        assert!(
            set.contains(&p.to_string()),
            "package set lacks {p}: {set:?}"
        );
    }
}

fn default_file(name: &str) -> String {
    let path = default_manifest_dir().join("files").join(name);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// `KEY=value` settings of a usbguard-daemon.conf, comments skipped.
fn conf_value<'a>(conf: &'a str, key: &str) -> Option<&'a str> {
    conf.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
}

/// Spec §4.4: the default home set covers the shell rc, SSH, systemd user-unit and D-Bus
/// activation autostart vectors, so a user-level RAT cannot add them.
#[test]
fn default_home_manages_autostart_vectors() {
    let m = parse_ok(&substitute(&template(), ""));
    let home = &m.users["tester"].home;
    for (target, source) in [
        (".zshrc", "home/tester/zshrc"),
        (".zshenv", "home/tester/zshenv"),
        (".zprofile", "home/tester/zprofile"),
        (".zlogin", "home/tester/zlogin"),
        (".zlogout", "home/tester/zlogout"),
        (".profile", "home/tester/profile"),
        (".bashrc", "home/tester/bashrc"),
        (".bash_profile", "home/tester/bash_profile"),
        (".bash_logout", "home/tester/bash_logout"),
        (".ssh/authorized_keys", "home/tester/authorized_keys"),
        (".ssh/authorized_keys2", "home/tester/authorized_keys2"),
        (".ssh/rc", "home/tester/ssh-rc"),
        (".config/autostart/", "home/tester/autostart/"),
        (".config/systemd/user/", "home/tester/systemd-user/"),
        (
            ".config/systemd/user.control/",
            "home/tester/systemd-user-control/",
        ),
        (
            ".local/share/systemd/user/",
            "home/tester/local-share-systemd-user/",
        ),
        (".config/environment.d/", "home/tester/environment.d/"),
        (".local/bin/", "home/tester/bin/"),
        (
            ".local/share/dbus-1/services/",
            "home/tester/local-share-dbus-services/",
        ),
    ] {
        assert_eq!(
            home.get(target).map(String::as_str),
            Some(source),
            "home entry {target}"
        );
    }
}

/// Spec §4.3 step 4: pacman in the candidate chroot never runs mkinitcpio's hooks (aios
/// builds the initramfs into the UKIs itself) or sbctl's (no keys in the candidate).
#[test]
fn default_files_mask_the_initramfs_and_sbctl_hooks() {
    let m = parse_ok(&substitute(&template(), ""));
    for hook in [
        "90-mkinitcpio-install.hook",
        "60-mkinitcpio-remove.hook",
        "zz-sbctl.hook",
    ] {
        let entry = &m.files[&format!("/etc/pacman.d/hooks/{hook}")];
        assert_eq!(entry.symlink.as_deref(), Some("/dev/null"), "{hook}");
    }
}

/// Spec §5.5: only root may talk to usbguard, so policy changes go through run0.
#[test]
fn usbguard_ipc_is_root_only() {
    let conf = default_file("usbguard-daemon.conf");
    assert_eq!(conf_value(&conf, "IPCAllowedUsers"), Some("root"));
    assert_eq!(conf_value(&conf, "IPCAllowedGroups"), Some(""));
}

/// The unsigned local repo comes last, so it can never shadow a signed package.
#[test]
fn aios_local_is_the_last_pacman_repo() {
    let conf = default_file("pacman.conf");
    let sections: Vec<&str> = conf
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with('[') && l.ends_with(']'))
        .collect();
    assert_eq!(sections.first(), Some(&"[options]"));
    assert_eq!(sections.last(), Some(&"[aios-local]"), "{sections:?}");
    assert_eq!(sections.iter().filter(|s| **s == "[aios-local]").count(), 1);
}

/// RFC 4890: MLD listener queries must reach the host, along with NDP.
#[test]
fn nftables_accepts_mld_listener_query() {
    let conf = default_file("nftables.conf");
    assert!(conf.contains("mld-listener-query"), "{conf}");
}
