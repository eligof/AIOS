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
