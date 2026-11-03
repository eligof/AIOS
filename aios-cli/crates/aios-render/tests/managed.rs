use aios_render::{managed_list, parse_managed_list, ManagedListError};

#[test]
fn sorted_unique_one_path_per_line() {
    let paths = [
        "/etc/fstab".to_string(),
        "/etc/aios/managed-files".to_string(),
        "/etc/fstab".to_string(),
        "/etc/hostname".to_string(),
    ];
    assert_eq!(
        managed_list(&paths),
        "/etc/aios/managed-files\n/etc/fstab\n/etc/hostname\n"
    );
}

#[test]
fn empty_list_is_empty_text() {
    assert_eq!(managed_list(&[]), "");
}

#[test]
fn parse_round_trips_and_skips_blank_lines() {
    assert_eq!(
        parse_managed_list("/etc/b\n\n/etc/a\n/etc/b\n").unwrap(),
        ["/etc/a", "/etc/b"]
    );
    let paths = ["/etc/x".to_string(), "/etc/a b".to_string()];
    assert_eq!(
        parse_managed_list(&managed_list(&paths)).unwrap(),
        ["/etc/a b", "/etc/x"]
    );
}

#[test]
fn parse_rejects_any_line_that_is_not_an_absolute_etc_path() {
    for bad in [
        "/usr/bin/x",
        "etc/fstab",
        "/etc",
        "/etcetera",
        "/etc/../usr/x",
        "/etc/a\u{1}b",
        "/etc/a\rb",
        "/etc/a\u{0}b",
        " /etc/a",
        "/",
        "x",
    ] {
        let text = format!("/etc/ok\n{bad}\n");
        let err = parse_managed_list(&text).unwrap_err();
        assert_eq!(
            err,
            ManagedListError {
                line: 2,
                entry: bad.to_string()
            },
            "for {bad:?}"
        );
        assert!(err.to_string().contains("line 2"), "got {err}");
    }
}
