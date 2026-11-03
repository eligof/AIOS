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

#[test]
fn unknown_kernel_location_ignores_earlier_comment() {
    let raw = format!(
        "# default settings\n{}",
        VALID.replace("default = \"linux-cachyos\"", "default = \"linux-zen\"")
    );
    let line = raw
        .lines()
        .position(|l| l.starts_with("default ="))
        .unwrap()
        + 1;
    let errs = errors(&raw);
    assert!(
        errs.iter()
            .any(|e| e.starts_with(&format!("manifest.toml:{line}:1:"))
                && e.contains("unknown kernel")),
        "got {errs:?}"
    );
}

#[test]
fn user_declared_only_via_home_table_reports_at_that_header() {
    // bob has no `[users.bob]` header (dotted keys) and no password hash.
    let raw = VALID.replace(
        "[users.eli]\nuid = 1000\ngroups = [\"wheel\"]\nshell = \"/usr/bin/zsh\"\n\n[users.eli.home]",
        "[users]\nbob.uid = 1001\nbob.shell = \"/usr/bin/zsh\"\n\n[users.bob.home]",
    );
    let raw = raw.replace("\".zshrc\" = \"home/eli/zshrc\"\n", "");
    let raw = raw.replace("\".config/autostart/\" = \"home/eli/autostart/\"\n", "");
    let line = raw.lines().position(|l| l == "[users.bob.home]").unwrap() + 1;
    let errs = errors(&raw);
    assert!(
        errs.iter()
            .any(|e| e.starts_with(&format!("manifest.toml:{line}:1:"))
                && e.contains("missing password hash")),
        "got {errs:?}"
    );
}

#[test]
fn files_path_etc_slash_rejected() {
    let raw = VALID.replace("\"/etc/nftables.conf\"", "\"/etc/\"");
    assert_error(&raw, "only paths under /etc are allowed");
}

#[test]
fn files_path_trailing_slash_rejected() {
    let raw = VALID.replace("\"/etc/nftables.conf\"", "\"/etc/foo/\"");
    assert_error(&raw, "only paths under /etc are allowed");
}

#[test]
fn persist_root_rejected() {
    let raw = VALID.replace("\"/var/lib/NetworkManager\"", "\"/\"");
    assert_error(&raw, "persist path \"/\" may not be the root directory");
}

#[test]
fn file_source_symlink_escaping_repo_rejected() {
    let (_tmp, env) = env();
    let outside = _tmp.path().join("outside");
    fs::write(&outside, "secret").unwrap();
    std::os::unix::fs::symlink(&outside, env.repo_root.join("files/evil")).unwrap();
    let raw = VALID.replace("files/nftables.conf", "files/evil");
    let m = parse(&raw).unwrap();
    let errs: Vec<String> = validate(&m, &raw, &env)
        .into_iter()
        .map(|e| e.to_string())
        .collect();
    assert!(
        errs.iter().any(|e| e.contains(
            "file \"/etc/nftables.conf\": source \"files/evil\" resolves outside the manifest repo"
        )),
        "got {errs:#?}"
    );
}

#[test]
fn home_source_symlink_escaping_repo_rejected() {
    let (_tmp, env) = env();
    let outside = _tmp.path().join("outside");
    fs::write(&outside, "secret").unwrap();
    std::os::unix::fs::symlink(&outside, env.repo_root.join("home/eli/x")).unwrap();
    let raw = VALID.replace("home/eli/zshrc", "home/eli/x");
    let m = parse(&raw).unwrap();
    let errs: Vec<String> = validate(&m, &raw, &env)
        .into_iter()
        .map(|e| e.to_string())
        .collect();
    assert!(
        errs.iter().any(|e| e
            .contains("user \"eli\": home entry \".zshrc\" resolves outside the manifest repo")),
        "got {errs:#?}"
    );
}

#[test]
fn symlink_inside_repo_is_allowed() {
    let (_tmp, env) = env();
    std::os::unix::fs::symlink(
        env.repo_root.join("files/nftables.conf"),
        env.repo_root.join("files/alias"),
    )
    .unwrap();
    let raw = VALID.replace("files/nftables.conf", "files/alias");
    let m = parse(&raw).unwrap();
    assert!(validate(&m, &raw, &env).is_empty());
}

/// `VALID` with `directories` replaced by the TOML array body `dirs`.
fn with_persist_dirs(dirs: &str) -> String {
    VALID.replace(
        "directories = [\"/var/lib/NetworkManager\", \"/var/cache/pacman/pkg\"]",
        &format!("directories = [{dirs}]"),
    )
}

/// `(TOML basic-string body, decoded value)` pairs, one per forbidden path character.
const FORBIDDEN_PATH_CHARS: [(&str, &str); 9] = [
    (r"a b", "a b"),
    (r"a\tb", "a\tb"),
    (r"a\nb", "a\nb"),
    (r"a\u0001b", "a\u{1}b"),
    (r"a\u007fb", "a\u{7f}b"),
    (r"100%", "100%"),
    (r"a\\b", "a\\b"),
    (r#"a\"b"#, "a\"b"),
    (r"a'b", "a'b"),
];

#[test]
fn persist_directory_with_forbidden_character_rejected() {
    for (toml, decoded) in FORBIDDEN_PATH_CHARS {
        let raw = with_persist_dirs(&format!("\"/var/lib/{toml}\""));
        let p = format!("/var/lib/{decoded}");
        assert_error(
            &raw,
            &format!("persist path {p:?} contains a forbidden character"),
        );
    }
}

#[test]
fn persist_file_with_forbidden_character_rejected() {
    for (toml, decoded) in FORBIDDEN_PATH_CHARS {
        let raw = VALID.replace("files = []", &format!("files = [\"/var/lib/{toml}\"]"));
        let p = format!("/var/lib/{decoded}");
        assert_error(
            &raw,
            &format!("persist path {p:?} contains a forbidden character"),
        );
    }
}

#[test]
fn home_key_with_forbidden_character_rejected() {
    for (toml, decoded) in FORBIDDEN_PATH_CHARS {
        let raw = VALID.replace("\".zshrc\" =", &format!("\".zsh{toml}rc\" ="));
        let target = format!(".zsh{decoded}rc");
        assert_error(
            &raw,
            &format!("user \"eli\": home entry {target:?} contains a forbidden character"),
        );
    }
}

#[test]
fn invalid_shell_rejected() {
    let cases = [
        ("usr/bin/zsh", "usr/bin/zsh"),
        ("", ""),
        ("/usr/bin/zsh:x", "/usr/bin/zsh:x"),
        ("/usr/bin/z sh", "/usr/bin/z sh"),
        (r"/usr/bin/z\tsh", "/usr/bin/z\tsh"),
        (r"/usr/bin/zsh\n", "/usr/bin/zsh\n"),
        (r"/usr/bin/z\u0000sh", "/usr/bin/z\u{0}sh"),
    ];
    for (toml, shell) in cases {
        let raw = VALID.replace("shell = \"/usr/bin/zsh\"", &format!("shell = \"{toml}\""));
        assert_error(&raw, &format!("user \"eli\": invalid shell {shell:?}"));
    }
}

#[test]
fn invalid_locale_rejected() {
    let cases = [
        ("", ""),
        ("en US", "en US"),
        (r"en_US.UTF-8\n", "en_US.UTF-8\n"),
        ("en_US;reboot", "en_US;reboot"),
        ("../../etc/shadow", "../../etc/shadow"),
        ("en_US=x", "en_US=x"),
        ("é", "é"),
    ];
    for (toml, v) in cases {
        let raw = VALID.replace("locale = \"en_US.UTF-8\"", &format!("locale = \"{toml}\""));
        assert_error(&raw, &format!("invalid locale {v:?}"));
    }
}

#[test]
fn invalid_keymap_rejected() {
    let cases = [
        ("", ""),
        ("us x", "us x"),
        (r"us\n", "us\n"),
        ("us@euro", "us@euro"),
        ("../../x", "../../x"),
        ("us;reboot", "us;reboot"),
    ];
    for (toml, v) in cases {
        let raw = VALID.replace("keymap = \"us\"", &format!("keymap = \"{toml}\""));
        assert_error(&raw, &format!("invalid keymap {v:?}"));
    }
}

#[test]
fn common_locales_and_keymaps_accepted() {
    for (locale, keymap) in [
        ("C.UTF-8", "de-latin1"),
        ("sr_RS.UTF-8@latin", "de_CH-latin1"),
        ("en_US", "fr.map"),
    ] {
        let raw = VALID
            .replace(
                "locale = \"en_US.UTF-8\"",
                &format!("locale = \"{locale}\""),
            )
            .replace("keymap = \"us\"", &format!("keymap = \"{keymap}\""));
        assert_eq!(errors(&raw), Vec::<String>::new(), "{locale} / {keymap}");
    }
}

fn with_extra_cmdline(body: &str) -> String {
    VALID.replace("extra_cmdline = []", &format!("extra_cmdline = [{body}]"))
}

#[test]
fn extra_cmdline_token_must_be_a_single_word() {
    let cases = [
        ("", ""),
        ("a b", "a b"),
        (r"a\tb", "a\tb"),
        (r"quiet\nsplash", "quiet\nsplash"),
        (r#"a=\"b c\""#, "a=\"b c\""),
        (r#"x\""#, "x\""),
        (r"a\u0001", "a\u{1}"),
    ];
    for (toml, t) in cases {
        let raw = with_extra_cmdline(&format!("\"{toml}\""));
        assert_error(
            &raw,
            &format!("extra_cmdline token {t:?} must be a single word"),
        );
    }
}

#[test]
fn extra_cmdline_token_may_not_override_aios_parameters() {
    for t in [
        "root=/dev/sda2",
        "rootflags=subvol=@",
        "rw",
        "ro",
        "mount.usr=/dev/sda3",
        "mount.usrflags=rw",
        "rd.luks.name=0b6c2e7f-5d0a-4c2e-9a71-3f1d2c4b5a69=evil",
        "aios.gen=0001",
        "lockdown=none",
        "lsm=",
        "init=/bin/sh",
        "ro=1",
        "systemd.debug_shell",
        "systemd.debug_shell=1",
        "systemd.debug-shell=1",
        "rd.systemd.debug_shell",
        "rd.systemd.debug-shell=1",
        "rdinit=/bin/sh",
        "apparmor=0",
        "security=none",
    ] {
        let raw = with_extra_cmdline(&format!("\"{t}\""));
        assert_error(
            &raw,
            &format!("extra_cmdline token {t:?} overrides a parameter AIOS sets"),
        );
    }
}

#[test]
fn ordinary_extra_cmdline_tokens_accepted() {
    let raw = with_extra_cmdline(
        "\"console=ttyS0,115200\", \"aios.test.fail_health=1\", \"rootwait\", \"initrd_debug\", \"quiet\"",
    );
    assert_eq!(errors(&raw), Vec::<String>::new());
}

#[test]
fn persist_path_conflicting_with_aios_managed_paths_rejected() {
    let cases = [
        ("/etc", "/etc"),
        ("/etc/", "/etc"),
        ("/etc/passwd", "/etc/passwd"),
        ("/etc/shadow", "/etc/shadow"),
        ("/etc/gshadow", "/etc/gshadow"),
        ("/etc/group", "/etc/group"),
        ("/etc/fstab", "/etc/fstab"),
        ("/etc/hostname", "/etc/hostname"),
        ("/etc/locale.conf", "/etc/locale.conf"),
        ("/etc/locale.gen", "/etc/locale.gen"),
        ("/etc/vconsole.conf", "/etc/vconsole.conf"),
        ("/etc/localtime", "/etc/localtime"),
        ("/etc/kernel", "/etc/kernel/cmdline"),
        ("/etc/kernel/cmdline", "/etc/kernel/cmdline"),
        ("/etc/tmpfiles.d", "/etc/tmpfiles.d/aios-persist.conf"),
        (
            "/etc/tmpfiles.d/aios-home.conf",
            "/etc/tmpfiles.d/aios-home.conf",
        ),
        ("/etc/aios", "/etc/aios"),
        ("/etc/aios/home/eli", "/etc/aios"),
        ("/etc/nftables.conf", "/etc/nftables.conf"),
        (
            "/etc/pacman.d",
            "/etc/pacman.d/hooks/90-mkinitcpio-install.hook",
        ),
        ("/efi", "/efi"),
        ("/efi/EFI/Linux", "/efi"),
        ("/proc/sys", "/proc"),
        ("/sys", "/sys"),
        ("/dev/shm", "/dev"),
        ("/run/aios", "/run"),
        ("/tmp", "/tmp"),
        ("/var/log", "/var/log"),
        ("/var/log/journal", "/var/log"),
        ("/bin", "/bin"),
        ("/bin/x", "/bin"),
        ("/sbin", "/sbin"),
        ("/lib", "/lib"),
        ("/lib/modules", "/lib"),
        ("/lib64", "/lib64"),
        ("/lib64/x", "/lib64"),
        ("/var/lib/pacman", "/var/lib/pacman"),
        ("/var/lib/pacman/local", "/var/lib/pacman"),
        ("/etc/systemd", "/etc/systemd/system"),
        ("/etc/systemd/system", "/etc/systemd/system"),
        ("/etc/systemd/system/x.service", "/etc/systemd/system"),
    ];
    for (p, other) in cases {
        let raw = with_persist_dirs(&format!("\"{p}\""));
        assert_error(
            &raw,
            &format!("persist path {p:?} conflicts with {other:?}, which aios manages"),
        );
    }
}

#[test]
fn persist_file_conflicting_with_a_generated_file_rejected() {
    let raw = VALID.replace("files = []", "files = [\"/etc/hostname\"]");
    assert_error(
        &raw,
        "persist path \"/etc/hostname\" conflicts with \"/etc/hostname\", which aios manages",
    );
}

#[test]
fn persist_paths_near_managed_ones_accepted() {
    let raw = with_persist_dirs(
        "\"/etc/NetworkManager/system-connections\", \"/var/lib/systemd\", \"/var/logs\", \"/etc/aios-extra\", \"/etc/kernel.d\"",
    )
    .replace("files = []", "files = [\"/etc/machine-id\", \"/etc/passwd-\"]");
    assert_eq!(errors(&raw), Vec::<String>::new());
}

#[test]
fn home_key_with_empty_or_dot_component_rejected() {
    for key in ["./", ".", "a//b", "./.zshrc", "a/./b", ".config//"] {
        let raw = VALID.replace("\".config/autostart/\" =", &format!("\"{key}\" ="));
        assert_error(
            &raw,
            &format!("user \"eli\": home entry {key:?} must be relative inside the home directory"),
        );
    }
}

#[test]
fn home_keys_equal_up_to_trailing_slash_rejected() {
    let raw = VALID.replace(
        "\".zshrc\" = \"home/eli/zshrc\"",
        "\".config/autostart\" = \"home/eli/zshrc\"",
    );
    assert_error(
        &raw,
        "user \"eli\": duplicate home entry \".config/autostart/\"",
    );
}

#[test]
fn persist_prefix_of_system_tree_without_component_boundary_is_allowed() {
    let raw = with_persist_dirs("\"/binx\", \"/var/lib/pacman-cache\", \"/lib64x\"");
    assert_eq!(errors(&raw), Vec::<String>::new());
}

#[test]
fn files_key_with_forbidden_character_rejected() {
    for (toml, decoded) in FORBIDDEN_PATH_CHARS {
        let raw = VALID.replace("\"/etc/nftables.conf\" =", &format!("\"/etc/{toml}\" ="));
        let p = format!("/etc/{decoded}");
        assert_error(&raw, &format!("file {p:?}: contains a forbidden character"));
    }
}

#[test]
fn files_key_newline_cannot_forge_a_managed_files_line() {
    let raw = VALID.replace("\"/etc/nftables.conf\" =", "\"/etc/x\\n/etc/shadow\" =");
    assert_error(
        &raw,
        "file \"/etc/x\\n/etc/shadow\": contains a forbidden character",
    );
}

#[test]
fn home_key_inside_another_home_key_rejected() {
    let raw = VALID.replace(
        "\".zshrc\" = \"home/eli/zshrc\"",
        "\".zshrc\" = \"home/eli/zshrc\"\n\".config/\" = \"home/eli/autostart/\"",
    );
    assert_error(
        &raw,
        "user \"eli\": home entry \".config/autostart/\" is inside home entry \".config/\"",
    );
}

#[test]
fn home_key_inside_another_without_trailing_slash_rejected() {
    let raw = VALID.replace(
        "\".zshrc\" = \"home/eli/zshrc\"",
        "\".zshrc\" = \"home/eli/zshrc\"\n\".config/autostart/x\" = \"home/eli/zshrc\"",
    );
    assert_error(
        &raw,
        "user \"eli\": home entry \".config/autostart/x\" is inside home entry \".config/autostart/\"",
    );
}

#[test]
fn sibling_home_keys_sharing_a_prefix_are_not_nested() {
    let raw = VALID.replace(
        "\".zshrc\" = \"home/eli/zshrc\"",
        "\".zshrc\" = \"home/eli/zshrc\"\n\".config/autostart2/\" = \"home/eli/autostart/\"\n\".zshrc.d/\" = \"home/eli/autostart/\"",
    );
    assert_eq!(errors(&raw), Vec::<String>::new());
}
