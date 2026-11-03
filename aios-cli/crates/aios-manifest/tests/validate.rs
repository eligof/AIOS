mod common;

use aios_manifest::{load, parse, validate, ValidationEnv};
use common::VALID;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

/// Temp layout: repo/{files/nftables.conf, home/eli/zshrc, home/eli/autostart/},
/// secrets/passwd/eli, zoneinfo/Asia/Jerusalem.
fn env() -> (TempDir, ValidationEnv) {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let repo = root.join("repo");
    fs::create_dir_all(repo.join("files")).unwrap();
    fs::write(repo.join("files/nftables.conf"), "flush ruleset\n").unwrap();
    fs::create_dir_all(repo.join("home/eli/autostart")).unwrap();
    fs::write(repo.join("home/eli/zshrc"), "# zshrc\n").unwrap();
    fs::create_dir_all(root.join("secrets/passwd")).unwrap();
    fs::write(root.join("secrets/passwd/eli"), "$y$j9T$hash\n").unwrap();
    fs::create_dir_all(root.join("zoneinfo/Asia")).unwrap();
    fs::write(root.join("zoneinfo/Asia/Jerusalem"), "TZif").unwrap();
    let env = ValidationEnv {
        repo_root: repo,
        secrets_dir: root.join("secrets"),
        zoneinfo_dir: root.join("zoneinfo"),
    };
    (tmp, env)
}

fn errors(raw: &str) -> Vec<String> {
    let (_tmp, env) = env();
    let m = parse(raw).expect("fixture must parse");
    validate(&m, raw, &env)
        .into_iter()
        .map(|e| e.to_string())
        .collect()
}

fn assert_error(raw: &str, needle: &str) {
    let errs = errors(raw);
    assert!(
        errs.iter().any(|e| e.contains(needle)),
        "expected an error containing {needle:?}, got {errs:#?}"
    );
}

#[test]
fn valid_manifest_has_no_errors() {
    assert_eq!(errors(VALID), Vec::<String>::new());
}

#[test]
fn load_reads_parses_and_validates() {
    let (tmp, env) = env();
    let path = tmp.path().join("manifest.toml");
    fs::write(&path, VALID).unwrap();
    assert!(load(&path, &env).is_ok());
    fs::write(&path, VALID.replace("uid = 1000", "uid = 5")).unwrap();
    let errs = load(&path, &env).unwrap_err();
    assert!(
        errs[0].message.contains("outside 1000-59999"),
        "got {errs:?}"
    );
}

#[test]
fn load_missing_file_is_error() {
    let (_tmp, env) = env();
    let errs = load(Path::new("/nonexistent/manifest.toml"), &env).unwrap_err();
    assert!(errs[0].message.contains("cannot read"));
}

#[test]
fn file_outside_etc_rejected() {
    let raw = VALID.replace("\"/etc/nftables.conf\" =", "\"/usr/lib/x\" =");
    assert_error(&raw, "only paths under /etc are allowed");
}

#[test]
fn file_with_parent_dir_rejected() {
    let raw = VALID.replace("\"/etc/nftables.conf\" =", "\"/etc/../usr/x\" =");
    assert_error(&raw, "only paths under /etc are allowed");
}

#[test]
fn file_with_both_source_and_symlink_rejected() {
    let raw = VALID.replace(
        "{ symlink = \"/dev/null\" }",
        "{ symlink = \"/dev/null\", source = \"files/nftables.conf\" }",
    );
    assert_error(&raw, "set exactly one of source or symlink");
}

#[test]
fn file_with_neither_source_nor_symlink_rejected() {
    let raw = VALID.replace("{ symlink = \"/dev/null\" }", "{ mode = \"0644\" }");
    assert_error(&raw, "set exactly one of source or symlink");
}

#[test]
fn missing_source_rejected() {
    let raw = VALID.replace("files/nftables.conf", "files/missing.conf");
    assert_error(&raw, "source \"files/missing.conf\" not found");
}

#[test]
fn bad_mode_rejected() {
    let raw = VALID.replace("mode = \"0600\"", "mode = \"0999\"");
    assert_error(&raw, "invalid mode \"0999\"");
}

#[test]
fn error_location_points_at_offending_key() {
    let raw = VALID.replace("mode = \"0600\"", "mode = \"rw\"");
    let errs = errors(&raw);
    let line = raw
        .lines()
        .position(|l| l.contains("/etc/nftables.conf"))
        .unwrap()
        + 1;
    assert!(
        errs[0].starts_with(&format!("manifest.toml:{line}:")),
        "got {errs:?}"
    );
}

#[test]
fn persist_relative_path_rejected() {
    let raw = VALID.replace("\"/var/lib/NetworkManager\"", "\"var/lib/nm\"");
    assert_error(&raw, "must be absolute without '..'");
}

#[test]
fn persist_under_usr_rejected() {
    let raw = VALID.replace("\"/var/lib/NetworkManager\"", "\"/usr/share/x\"");
    assert_error(&raw, "may not be under /usr");
}

#[test]
fn persist_under_home_rejected() {
    let raw = VALID.replace("\"/var/lib/NetworkManager\"", "\"/home/eli\"");
    assert_error(&raw, "may not be under /home");
}

#[test]
fn persist_overlap_rejected() {
    let raw = VALID.replace(
        "directories = [\"/var/lib/NetworkManager\", \"/var/cache/pacman/pkg\"]",
        "directories = [\"/var/lib\", \"/var/lib/NetworkManager\"]",
    );
    assert_error(&raw, "overlap");
}

#[test]
fn persist_prefix_without_component_boundary_is_not_overlap() {
    let raw = VALID.replace(
        "directories = [\"/var/lib/NetworkManager\", \"/var/cache/pacman/pkg\"]",
        "directories = [\"/var/lib/foo\", \"/var/lib/foobar\"]",
    );
    assert_eq!(errors(&raw), Vec::<String>::new());
}

#[test]
fn home_absolute_target_rejected() {
    let raw = VALID.replace("\".zshrc\" =", "\"/etc/zshrc\" =");
    assert_error(&raw, "must be relative inside the home directory");
}

#[test]
fn home_parent_target_rejected() {
    let raw = VALID.replace("\".zshrc\" =", "\"../other/.zshrc\" =");
    assert_error(&raw, "must be relative inside the home directory");
}

#[test]
fn home_kind_mismatch_rejected() {
    let raw = VALID.replace("\".zshrc\" =", "\".zshrc.d/\" =");
    assert_error(&raw, "needs a directory at \"home/eli/zshrc\"");
}

#[test]
fn home_missing_source_rejected() {
    let raw = VALID.replace("home/eli/zshrc", "home/eli/nope");
    assert_error(&raw, "needs a file at \"home/eli/nope\"");
}

#[test]
fn uid_out_of_range_rejected() {
    let raw = VALID.replace("uid = 1000", "uid = 60000");
    assert_error(&raw, "outside 1000-59999");
}

#[test]
fn duplicate_uid_rejected() {
    let raw = format!("{VALID}\n[users.bob]\nuid = 1000\nshell = \"/bin/sh\"\n");
    assert_error(&raw, "already used by");
}

#[test]
fn missing_password_hash_rejected() {
    let raw = format!("{VALID}\n[users.bob]\nuid = 1001\nshell = \"/bin/sh\"\n");
    assert_error(&raw, "missing password hash secrets/passwd/bob");
}

#[test]
fn invalid_username_rejected() {
    let raw = VALID
        .replace("[users.eli]", "[users.Eli]")
        .replace("[users.eli.home]", "[users.Eli.home]");
    assert_error(&raw, "invalid user name \"Eli\"");
}

#[test]
fn unknown_kernel_rejected() {
    let raw = VALID.replace("default = \"linux-cachyos\"", "default = \"linux-zen\"");
    assert_error(&raw, "unknown kernel \"linux-zen\"");
}

#[test]
fn fallback_equal_to_default_rejected() {
    let raw = VALID.replace(
        "fallback = \"linux-cachyos-lts\"",
        "fallback = \"linux-cachyos\"",
    );
    assert_error(&raw, "fallback kernel must differ from default");
}

#[test]
fn unknown_timezone_rejected() {
    let raw = VALID.replace("Asia/Jerusalem", "Mars/Olympus");
    assert_error(&raw, "unknown timezone \"Mars/Olympus\"");
}

#[test]
fn timezone_traversal_rejected() {
    let raw = VALID.replace("Asia/Jerusalem", "../../etc/passwd");
    assert_error(&raw, "unknown timezone");
}

#[test]
fn invalid_hostname_rejected() {
    let raw = VALID.replace("hostname = \"nightcity\"", "hostname = \"Night_City\"");
    assert_error(&raw, "invalid hostname \"Night_City\"");
}

#[test]
fn collects_multiple_errors() {
    let raw = VALID
        .replace("uid = 1000", "uid = 1")
        .replace("Asia/Jerusalem", "Nope/Nope");
    assert!(errors(&raw).len() >= 2);
}
