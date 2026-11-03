use aios_render::{managed_list, parse_managed_list};

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
        parse_managed_list("/etc/b\n\n/etc/a\n/etc/b\n"),
        ["/etc/a", "/etc/b"]
    );
    let paths = ["/etc/x".to_string(), "/etc/a b".to_string()];
    assert_eq!(
        parse_managed_list(&managed_list(&paths)),
        ["/etc/a b", "/etc/x"]
    );
}
