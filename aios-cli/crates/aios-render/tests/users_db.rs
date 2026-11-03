use aios_render::{GroupEntry, GshadowEntry, PasswdEntry, ShadowEntry, UserDb, UserDbError};

const PASSWD: &str = "root:x:0:0::/root:/usr/bin/bash
bin:x:1:1::/:/usr/bin/nologin
nobody:x:65534:65534:Kernel Overflow User:/:/usr/bin/nologin
eli:x:1000:1000::/home/eli:/usr/bin/zsh
";
const GROUP: &str = "root:x:0:root
wheel:x:998:eli
video:x:985:eli
nobody:x:65534:
eli:x:1000:
";
const SHADOW: &str = "root:!*:20000::::::
bin:!*:20000::::::
nobody:!*:20000::::::
eli:$y$j9T$salt$hash:20100:0:99999:7:::
";
const GSHADOW: &str = "root:::root
wheel:!*::eli
video:!*::eli
nobody:!*::
eli:!*::
";

fn db() -> UserDb {
    UserDb::parse(PASSWD, GROUP, SHADOW, GSHADOW).expect("fixture parses")
}

#[test]
fn parses_arch_entries() {
    let db = db();
    assert_eq!(db.passwd.len(), 4);
    assert_eq!(
        db.passwd[2],
        PasswdEntry {
            name: "nobody".to_string(),
            uid: 65534,
            gid: 65534,
            gecos: "Kernel Overflow User".to_string(),
            home: "/".to_string(),
            shell: "/usr/bin/nologin".to_string(),
        }
    );
    assert_eq!(
        db.group[1],
        GroupEntry {
            name: "wheel".to_string(),
            gid: 998,
            members: vec!["eli".to_string()],
        }
    );
    assert!(db.group[3].members.is_empty());
    assert_eq!(
        db.shadow[3],
        ShadowEntry {
            name: "eli".to_string(),
            hash: "$y$j9T$salt$hash".to_string(),
            rest: "20100:0:99999:7:::".to_string(),
        }
    );
    assert_eq!(
        db.gshadow[0],
        GshadowEntry {
            name: "root".to_string(),
            password: String::new(),
            admins: vec![],
            members: vec!["root".to_string()],
        }
    );
}

#[test]
fn render_reproduces_canonical_text() {
    let files = db().render();
    assert_eq!(files.passwd, PASSWD);
    assert_eq!(files.group, GROUP);
    assert_eq!(files.shadow, SHADOW);
    assert_eq!(files.gshadow, GSHADOW);
}

#[test]
fn parse_of_render_is_identity() {
    let db = db();
    let files = db.render();
    let again = UserDb::parse(&files.passwd, &files.group, &files.shadow, &files.gshadow);
    assert_eq!(again, Ok(db));
}

#[test]
fn passwd_password_field_is_rendered_as_x() {
    let db = UserDb::parse("root:*:0:0::/root:/usr/bin/bash\n", "", "", "").unwrap();
    assert_eq!(db.render().passwd, "root:x:0:0::/root:/usr/bin/bash\n");
}

#[test]
fn member_lists_drop_empty_names() {
    let db = UserDb::parse("", "video:x:985:eli,,ada,\n", "", "video:!*:eli,:ada,,\n").unwrap();
    assert_eq!(db.group[0].members, ["eli", "ada"]);
    assert_eq!(db.gshadow[0].admins, ["eli"]);
    assert_eq!(db.gshadow[0].members, ["ada"]);
}

#[test]
fn blank_lines_are_skipped_but_still_counted() {
    let db = UserDb::parse("\nroot:x:0:0::/root:/usr/bin/bash\n\n", "", "", "").unwrap();
    assert_eq!(db.passwd.len(), 1);
    let err = UserDb::parse("root:x:0:0::/root:/usr/bin/bash\n\nbroken\n", "", "", "");
    assert_eq!(
        err,
        Err(UserDbError::Malformed {
            file: "passwd",
            line: 3
        })
    );
}

#[test]
fn malformed_entries_name_file_and_line() {
    let cases = [
        (UserDb::parse("root:x:0:0::/root\n", "", "", ""), "passwd"),
        (
            UserDb::parse("root:x:zero:0::/root:/bin/sh\n", "", "", ""),
            "passwd",
        ),
        (
            UserDb::parse(":x:0:0::/root:/bin/sh\n", "", "", ""),
            "passwd",
        ),
        (UserDb::parse("", "wheel:x:998\n", "", ""), "group"),
        (UserDb::parse("", "wheel:x:-1:\n", "", ""), "group"),
        (UserDb::parse("", "", "root\n", ""), "shadow"),
        (
            UserDb::parse("", "", "", "wheel:!*::eli:extra\n"),
            "gshadow",
        ),
    ];
    for (result, file) in cases {
        assert_eq!(result, Err(UserDbError::Malformed { file, line: 1 }));
    }
}

#[test]
fn error_messages() {
    let cases = [
        (
            UserDbError::Malformed {
                file: "group",
                line: 4,
            },
            "/etc/group:4: malformed entry",
        ),
        (
            UserDbError::MissingGroup {
                user: "eli".to_string(),
                group: "docker".to_string(),
            },
            "user \"eli\": group \"docker\" does not exist",
        ),
        (
            UserDbError::NameConflict("dbus".to_string()),
            "user \"dbus\": name is already used by a system account or group",
        ),
        (
            UserDbError::MissingHash("eli".to_string()),
            "user \"eli\": no password hash (run `aios passwd eli`)",
        ),
        (
            UserDbError::InvalidHash("eli".to_string()),
            "user \"eli\": password hash is empty or contains ':' or a newline",
        ),
    ];
    for (err, text) in cases {
        assert_eq!(err.to_string(), text);
    }
}
