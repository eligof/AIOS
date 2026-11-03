mod common;

use aios_manifest::Manifest;
use aios_render::{merge_users, UserDb, UserDbError, UserFiles};
use common::{manifest_from, MANIFEST};
use std::collections::BTreeMap;

/// The booted generation: Arch system accounts, plus eli and a stale user bob.
const PASSWD: &str = "root:x:0:0::/root:/usr/bin/bash
bin:x:1:1::/:/usr/bin/nologin
daemon:x:2:2::/:/usr/bin/nologin
dbus:x:81:81:System Message Bus:/:/usr/bin/nologin
systemd-network:x:982:982:systemd Network Management:/:/usr/bin/nologin
nobody:x:65534:65534:Kernel Overflow User:/:/usr/bin/nologin
eli:x:1000:1000::/home/eli:/usr/bin/bash
bob:x:1001:1001::/home/bob:/usr/bin/bash
";
const GROUP: &str = "root:x:0:root
bin:x:1:daemon
daemon:x:2:bin
wheel:x:998:bob,eli
video:x:985:eli,bob
audio:x:984:bob
dbus:x:81:
systemd-network:x:982:
nobody:x:65534:
eli:x:1000:
bob:x:1001:
";
const SHADOW: &str = "root:$6$oldroot$hash:20000::::::
bin:!*:20000::::::
daemon:!*:20000::::::
dbus:!*:20000::::::
systemd-network:!*:20000::::::
nobody:!*:20000::::::
eli:$y$j9T$eli$old:20100:0:99999:7:::
bob:$y$j9T$bob$hash:20200:0:99999:7:::
";
const GSHADOW: &str = "root:::root
bin:::daemon
daemon:::bin
wheel:!*::bob,eli
video:!*::eli,bob
audio:!*::bob
dbus:!*::
systemd-network:!*::
nobody:!*::
eli:!*::
bob:!*::
";

/// 2026-11-03 in days since the epoch.
const TODAY: u64 = 20760;

fn db() -> UserDb {
    UserDb::parse(PASSWD, GROUP, SHADOW, GSHADOW).expect("fixture parses")
}

/// The common manifest (eli: wheel, video) plus ada (uid 1001, video), who reuses bob's uid.
fn two_users() -> Manifest {
    manifest_from(&format!(
        "{MANIFEST}\n[users.ada]\nuid = 1001\ngroups = [\"video\"]\nshell = \"/usr/bin/bash\"\n"
    ))
}

fn hashes(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(user, hash)| (user.to_string(), hash.to_string()))
        .collect()
}

fn default_hashes() -> BTreeMap<String, String> {
    hashes(&[("ada", "$y$j9T$ada$new"), ("eli", "$y$j9T$eli$old")])
}

fn merged() -> UserFiles {
    merge_users(&two_users(), &db(), &default_hashes(), TODAY)
        .expect("merge succeeds")
        .render()
}

#[test]
fn golden_merge() {
    let files = merged();
    assert_eq!(
        files.passwd,
        "root:x:0:0::/root:/usr/bin/bash
bin:x:1:1::/:/usr/bin/nologin
daemon:x:2:2::/:/usr/bin/nologin
dbus:x:81:81:System Message Bus:/:/usr/bin/nologin
systemd-network:x:982:982:systemd Network Management:/:/usr/bin/nologin
nobody:x:65534:65534:Kernel Overflow User:/:/usr/bin/nologin
ada:x:1001:1001::/home/ada:/usr/bin/bash
eli:x:1000:1000::/home/eli:/usr/bin/zsh
"
    );
    assert_eq!(
        files.group,
        "root:x:0:root
bin:x:1:daemon
daemon:x:2:bin
wheel:x:998:eli
video:x:985:ada,eli
audio:x:984:
dbus:x:81:
systemd-network:x:982:
nobody:x:65534:
ada:x:1001:
eli:x:1000:
"
    );
    assert_eq!(
        files.shadow,
        "root:!*:20000::::::
bin:!*:20000::::::
daemon:!*:20000::::::
dbus:!*:20000::::::
systemd-network:!*:20000::::::
nobody:!*:20000::::::
ada:$y$j9T$ada$new:20760:0:99999:7:::
eli:$y$j9T$eli$old:20100:0:99999:7:::
"
    );
    assert_eq!(
        files.gshadow,
        "root:::root
bin:::daemon
daemon:::bin
wheel:!*::eli
video:!*::ada,eli
audio:!*::
dbus:!*::
systemd-network:!*::
nobody:!*::
ada:!*::
eli:!*::
"
    );
}

#[test]
fn stale_managed_user_is_removed_everywhere() {
    let files = merged();
    for text in [&files.passwd, &files.group, &files.shadow, &files.gshadow] {
        assert!(!text.contains("bob"), "bob left in:\n{text}");
    }
}

#[test]
fn root_is_locked_and_keeps_its_aging_fields() {
    let files = merged();
    assert!(files.shadow.starts_with("root:!*:20000::::::\n"));
}

#[test]
fn changed_hash_updates_lastchg() {
    let new = hashes(&[("ada", "$y$j9T$ada$new"), ("eli", "$y$j9T$eli$new")]);
    let files = merge_users(&two_users(), &db(), &new, TODAY)
        .unwrap()
        .render();
    assert!(files
        .shadow
        .contains("\neli:$y$j9T$eli$new:20760:0:99999:7:::\n"));
}

#[test]
fn unchanged_hash_is_stable_across_days() {
    let first = merge_users(&two_users(), &db(), &default_hashes(), TODAY).unwrap();
    let later = merge_users(&two_users(), &first, &default_hashes(), TODAY + 30).unwrap();
    assert_eq!(later, first);
}

#[test]
fn merge_is_idempotent() {
    let once = merge_users(&two_users(), &db(), &default_hashes(), TODAY).unwrap();
    let twice = merge_users(&two_users(), &once, &default_hashes(), TODAY).unwrap();
    assert_eq!(twice, once);
}

#[test]
fn empty_database_has_no_root_and_is_an_error() {
    let m = manifest_from(&MANIFEST.replace("groups = [\"wheel\", \"video\"]", "groups = []"));
    let err = merge_users(&m, &UserDb::default(), &hashes(&[("eli", "$y$h")]), TODAY).unwrap_err();
    assert_eq!(err, UserDbError::MissingRoot);
}

#[test]
fn root_only_database_gets_declared_users_and_a_locked_root_shadow() {
    let m = manifest_from(&MANIFEST.replace("groups = [\"wheel\", \"video\"]", "groups = []"));
    let db = UserDb::parse("root:x:0:0::/root:/usr/bin/bash\n", "", "", "").unwrap();
    let files = merge_users(&m, &db, &hashes(&[("eli", "$y$h")]), TODAY)
        .unwrap()
        .render();
    assert_eq!(
        files.passwd,
        "root:x:0:0::/root:/usr/bin/bash\neli:x:1000:1000::/home/eli:/usr/bin/zsh\n"
    );
    assert_eq!(files.group, "eli:x:1000:\n");
    assert_eq!(
        files.shadow,
        "root:!*:::::::\neli:$y$h:20760:0:99999:7:::\n"
    );
    assert_eq!(files.gshadow, "eli:!*::\n");
}

#[test]
fn root_with_a_managed_uid_is_dropped_and_missing() {
    let db = UserDb::parse(
        &PASSWD.replace("root:x:0:0:", "root:x:1003:0:"),
        GROUP,
        SHADOW,
        GSHADOW,
    )
    .unwrap();
    let err = merge_users(&two_users(), &db, &default_hashes(), TODAY).unwrap_err();
    assert_eq!(err, UserDbError::MissingRoot);
}

#[test]
fn root_shadow_entry_is_added_when_missing() {
    let db = UserDb::parse(
        PASSWD,
        GROUP,
        &SHADOW.replace("root:$6$oldroot$hash:20000::::::\n", ""),
        GSHADOW,
    )
    .unwrap();
    let files = merge_users(&two_users(), &db, &default_hashes(), TODAY)
        .unwrap()
        .render();
    assert!(
        files
            .shadow
            .starts_with("root:!*:::::::\nbin:!*:20000::::::\n"),
        "got:\n{}",
        files.shadow
    );
    assert_eq!(files.shadow.matches("root:").count(), 1);
}

#[test]
fn invalid_shell_is_an_error() {
    let cases = [
        "usr/bin/zsh",
        "",
        "/usr/bin/zsh:/x",
        "/usr/bin/z sh",
        r"/usr/bin/zsh\n",
        r"/usr/bin/z\tsh",
        r"/usr/bin/z\u0000sh",
        r"/usr/bin/z\u007fsh",
    ];
    for shell in cases {
        let m = manifest_from(&format!(
            "{MANIFEST}\n[users.ada]\nuid = 1001\ngroups = [\"video\"]\nshell = \"{shell}\"\n"
        ));
        let err = merge_users(&m, &db(), &default_hashes(), TODAY).unwrap_err();
        assert_eq!(
            err,
            UserDbError::InvalidShell("ada".to_string()),
            "shell {shell:?}"
        );
    }
}

#[test]
fn uid_outside_the_managed_range_is_an_error() {
    for uid in [0, 1, 999, 60000, 65534] {
        let m = manifest_from(&MANIFEST.replace("uid = 1000", &format!("uid = {uid}")));
        let err = merge_users(&m, &db(), &hashes(&[("eli", "$y$h")]), TODAY).unwrap_err();
        assert_eq!(
            err,
            UserDbError::InvalidUid {
                user: "eli".to_string(),
                uid
            },
            "uid {uid}"
        );
    }
}

#[test]
fn duplicate_uid_is_an_error() {
    let m = manifest_from(&format!(
        "{MANIFEST}\n[users.ada]\nuid = 1000\ngroups = [\"video\"]\nshell = \"/usr/bin/bash\"\n"
    ));
    let err = merge_users(&m, &db(), &default_hashes(), TODAY).unwrap_err();
    assert_eq!(err, UserDbError::DuplicateUid(1000));
}

#[test]
fn gshadow_admins_drop_removed_and_declared_users() {
    let db = UserDb::parse(
        PASSWD,
        GROUP,
        SHADOW,
        &GSHADOW.replace("wheel:!*::bob,eli\n", "wheel:!*:bob,daemon,eli:bob,eli\n"),
    )
    .unwrap();
    let files = merge_users(&two_users(), &db, &default_hashes(), TODAY)
        .unwrap()
        .render();
    assert!(
        files.gshadow.contains("\nwheel:!*:daemon:eli\n"),
        "got:\n{}",
        files.gshadow
    );
}

#[test]
fn missing_group_is_an_error() {
    let m = manifest_from(&MANIFEST.replace("[\"wheel\", \"video\"]", "[\"wheel\", \"docker\"]"));
    let err = merge_users(&m, &db(), &default_hashes(), TODAY).unwrap_err();
    assert_eq!(
        err,
        UserDbError::MissingGroup {
            user: "eli".to_string(),
            group: "docker".to_string()
        }
    );
}

#[test]
fn missing_hash_is_an_error() {
    let err = merge_users(
        &two_users(),
        &db(),
        &hashes(&[("eli", "$y$j9T$eli$old")]),
        TODAY,
    )
    .unwrap_err();
    assert_eq!(err, UserDbError::MissingHash("ada".to_string()));
}

#[test]
fn invalid_hashes_are_errors() {
    for bad in [
        "", "$y$a:b", "$y$ab\n", "$y$ab\r", "$y$a\0b", " $y$ab", "$y$ab ", "\t$y$ab",
    ] {
        let err = merge_users(
            &two_users(),
            &db(),
            &hashes(&[("ada", bad), ("eli", "$y$j9T$eli$old")]),
            TODAY,
        )
        .unwrap_err();
        assert_eq!(
            err,
            UserDbError::InvalidHash("ada".to_string()),
            "hash {bad:?}"
        );
    }
}

#[test]
fn declared_name_of_a_system_user_conflicts() {
    let m = manifest_from(&format!(
        "{MANIFEST}\n[users.dbus]\nuid = 1005\nshell = \"/usr/bin/bash\"\n"
    ));
    let hs = hashes(&[("dbus", "$y$d"), ("eli", "$y$j9T$eli$old")]);
    let err = merge_users(&m, &db(), &hs, TODAY).unwrap_err();
    assert_eq!(err, UserDbError::NameConflict("dbus".to_string()));
}

#[test]
fn declared_name_of_a_system_group_conflicts() {
    let m = manifest_from(&format!(
        "{MANIFEST}\n[users.audio]\nuid = 1005\nshell = \"/usr/bin/bash\"\n"
    ));
    let hs = hashes(&[("audio", "$y$a"), ("eli", "$y$j9T$eli$old")]);
    let err = merge_users(&m, &db(), &hs, TODAY).unwrap_err();
    assert_eq!(err, UserDbError::NameConflict("audio".to_string()));
}

#[test]
fn kept_root_must_have_uid_zero() {
    let db = UserDb::parse(
        &PASSWD.replace("root:x:0:0:", "root:x:5:0:"),
        GROUP,
        SHADOW,
        GSHADOW,
    )
    .unwrap();
    let err = merge_users(&two_users(), &db, &default_hashes(), TODAY).unwrap_err();
    assert_eq!(err, UserDbError::RootNotUidZero);
    assert_eq!(err.to_string(), "/etc/passwd: root must have uid 0");
}

#[test]
fn kept_non_root_account_with_uid_zero_is_an_error() {
    let db = UserDb::parse(
        &PASSWD.replace("bin:x:1:1:", "bin:x:0:1:"),
        GROUP,
        SHADOW,
        GSHADOW,
    )
    .unwrap();
    let err = merge_users(&two_users(), &db, &default_hashes(), TODAY).unwrap_err();
    assert_eq!(err, UserDbError::ExtraUidZero("bin".to_string()));
    assert_eq!(
        err.to_string(),
        "/etc/passwd: account \"bin\" has uid 0 but is not root"
    );
}
