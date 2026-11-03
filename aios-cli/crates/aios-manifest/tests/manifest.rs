mod common;

use aios_manifest::{locate, offset_to_line_col, parse, Lockdown};
use common::VALID;

#[test]
fn parses_valid_manifest() {
    let m = parse(VALID).expect("valid manifest parses");
    assert_eq!(m.system.hostname, "nightcity");
    assert_eq!(m.kernel.default, "linux-cachyos");
    assert_eq!(m.kernel.fallback.as_deref(), Some("linux-cachyos-lts"));
    assert_eq!(m.kernel.lockdown, Lockdown::Integrity);
    assert_eq!(m.files["/etc/nftables.conf"].mode_or_default(), "0600");
    assert_eq!(
        m.files["/etc/pacman.d/hooks/90-mkinitcpio-install.hook"]
            .symlink
            .as_deref(),
        Some("/dev/null")
    );
    assert_eq!(m.users["eli"].uid, 1000);
    assert_eq!(m.users["eli"].home[".zshrc"], "home/eli/zshrc");
}

#[test]
fn defaults_apply_for_optional_fields() {
    let raw = r#"[system]
hostname = "h"
timezone = "UTC"
locale = "C.UTF-8"
keymap = "us"

[kernel]
default = "linux"
"#;
    let m = parse(raw).unwrap();
    assert_eq!(m.kernel.lockdown, Lockdown::Integrity);
    assert!(m.kernel.fallback.is_none());
    assert!(m.packages.install.is_empty());
    assert!(m.files.is_empty());
    assert!(m.users.is_empty());
}

#[test]
fn lockdown_none_parses() {
    let raw = VALID.replace("lockdown = \"integrity\"", "lockdown = \"none\"");
    assert_eq!(parse(&raw).unwrap().kernel.lockdown, Lockdown::None);
}

#[test]
fn file_entry_defaults() {
    let m = parse(VALID).unwrap();
    let hook = &m.files["/etc/pacman.d/hooks/90-mkinitcpio-install.hook"];
    assert_eq!(hook.mode_or_default(), "0644");
    assert_eq!(hook.owner_or_default(), "root");
    assert_eq!(hook.group_or_default(), "root");
}

#[test]
fn package_set_is_core_plus_kernels_plus_install_sorted_dedup() {
    let m = parse(VALID).unwrap();
    let set = m.package_set();
    for p in [
        "base",
        "aios-cli",
        "aios-base",
        "linux-cachyos",
        "linux-cachyos-lts",
        "zsh",
        "git",
    ] {
        assert!(set.contains(&p.to_string()), "missing {p}");
    }
    let mut sorted = set.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(set, sorted, "package_set must be sorted and deduplicated");
    assert_eq!(set.iter().filter(|p| *p == "base").count(), 1);
}

#[test]
fn unknown_key_is_parse_error_with_location() {
    let raw = VALID.replace("keymap = \"us\"", "keymap = \"us\"\nkeymapp = \"de\"");
    let err = parse(&raw).unwrap_err();
    assert_eq!(
        err.line, 6,
        "error should point at the unknown key line, got {err}"
    );
    assert!(
        err.message.contains("unknown field"),
        "got: {}",
        err.message
    );
    assert!(
        err.to_string().starts_with("manifest.toml:6:"),
        "got: {err}"
    );
}

#[test]
fn missing_required_field_is_error() {
    let err = parse("[system]\nhostname = \"h\"\n").unwrap_err();
    assert!(
        err.message.contains("missing field"),
        "got: {}",
        err.message
    );
}

#[test]
fn locate_finds_first_occurrence_one_based() {
    let raw = "a = 1\nb = \"/etc/x\"\n";
    assert_eq!(locate(raw, "\"/etc/x\""), (2, 5));
    assert_eq!(locate(raw, "a"), (1, 1));
    assert_eq!(locate(raw, "zzz"), (1, 1));
}

#[test]
fn offset_to_line_col_is_one_based() {
    let raw = "ab\ncd\n";
    assert_eq!(offset_to_line_col(raw, 0), (1, 1));
    assert_eq!(offset_to_line_col(raw, 1), (1, 2));
    assert_eq!(offset_to_line_col(raw, 3), (2, 1));
    assert_eq!(offset_to_line_col(raw, 4), (2, 2));
    assert_eq!(offset_to_line_col(raw, 999), (3, 1));
}
