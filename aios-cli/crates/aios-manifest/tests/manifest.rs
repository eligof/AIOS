mod common;

use aios_manifest::{
    locate, locate_key, locate_section, locate_value, offset_to_line_col, parse, Lockdown,
};
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

const SCOPED: &str = "# default settings\n[system]\nhostname = \"default\"\n\n[kernel]\n  default = \"x\"\nfallback = \"y\"\n\n[files]\n\"/etc/a\" = { symlink = \"/dev/null\" }\n\n[[extra]]\nkey = 1\n";

#[test]
fn locate_key_skips_comments_and_other_sections() {
    assert_eq!(locate_key(SCOPED, "kernel", "default"), (6, 3));
    assert_eq!(locate_key(SCOPED, "kernel", "fallback"), (7, 1));
    assert_eq!(locate_key(SCOPED, "system", "hostname"), (3, 1));
}

#[test]
fn locate_key_does_not_match_key_prefix_without_equals() {
    let raw = "[kernel]\ndefault_x = 1\ndefault = 2\n";
    assert_eq!(locate_key(raw, "kernel", "default"), (3, 1));
}

#[test]
fn locate_key_falls_back_to_header_when_key_missing() {
    assert_eq!(locate_key(SCOPED, "kernel", "nope"), (5, 1));
}

#[test]
fn locate_key_missing_section_is_one_one() {
    assert_eq!(locate_key(SCOPED, "nosuch", "default"), (1, 1));
}

#[test]
fn locate_key_stops_at_next_section() {
    // `fallback` lives in [kernel], so it is not found in [system]: header position.
    assert_eq!(locate_key(SCOPED, "system", "fallback"), (2, 1));
}

#[test]
fn locate_value_scoped_to_section() {
    let raw = "# \"/var/x\" note\n[other]\nk = \"/var/x\"\n[persist]\ndirectories = [\"/var/x\"]\n";
    assert_eq!(locate_value(raw, "persist", "\"/var/x\""), (5, 16));
    assert_eq!(locate_value(raw, "persist", "zzz"), (4, 1));
    assert_eq!(locate_value(raw, "nosuch", "zzz"), (1, 1));
}

#[test]
fn locate_section_picks_first_existing_header() {
    let raw = "[system]\n[users.bob.home]\n\"a\" = \"b\"\n";
    assert_eq!(
        locate_section(raw, &["users.bob", "users.bob.home"]),
        (2, 1)
    );
    assert_eq!(locate_section(raw, &["users.zed"]), (1, 1));
}

#[test]
fn offset_to_line_col_handles_non_char_boundary() {
    let raw = "a\u{e9}b\n\u{4e2d}x";
    // offset 2 is inside the two-byte `é` (bytes 1..3).
    assert_eq!(offset_to_line_col(raw, 2), (1, 2));
    // offset 6 is inside the three-byte `中` (bytes 5..8): clamps back to byte 5.
    assert_eq!(offset_to_line_col(raw, 6), (2, 1));
}

#[test]
fn locate_section_matches_header_with_trailing_comment_or_inner_spaces() {
    assert_eq!(locate_section("[kernel] # x\n", &["kernel"]), (1, 1));
    assert_eq!(locate_section("a = 1\n[ kernel ]\n", &["kernel"]), (2, 1));
    assert_eq!(locate_section("[kernel]#x\n", &["kernel"]), (1, 1));
    assert_eq!(locate_section("[kernelx]\n", &["kernel"]), (1, 1));
}

#[test]
fn locate_key_finds_key_under_commented_header() {
    let raw = "[kernel] # c\ndefault = 1\n";
    assert_eq!(locate_key(raw, "kernel", "default"), (2, 1));
}

#[test]
fn locate_value_skips_comment_lines() {
    let raw = "[kernel]\n# default = \"x\"\n  # more \"x\"\ndefault = \"x\"\n";
    assert_eq!(locate_value(raw, "kernel", "\"x\""), (4, 11));
}
