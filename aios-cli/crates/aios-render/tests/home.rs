mod common;

use aios_render::{home_binds, HomeBind};
use common::{manifest, manifest_from, MANIFEST};

#[test]
fn fixture_binds_in_key_order() {
    assert_eq!(
        home_binds(&manifest()),
        vec![
            HomeBind {
                user: "eli".to_string(),
                uid: 1000,
                target: "/home/eli/.config/autostart".to_string(),
                bind_source: "/etc/aios/home/eli/.config/autostart".to_string(),
                repo_source: "home/eli/autostart".to_string(),
                is_dir: true,
            },
            HomeBind {
                user: "eli".to_string(),
                uid: 1000,
                target: "/home/eli/.zshrc".to_string(),
                bind_source: "/etc/aios/home/eli/.zshrc".to_string(),
                repo_source: "home/eli/zshrc".to_string(),
                is_dir: false,
            },
        ]
    );
}

#[test]
fn users_in_name_order_then_keys() {
    let raw = format!(
        "{MANIFEST}\n[users.ada]\nuid = 1001\nshell = \"/usr/bin/bash\"\n\n[users.ada.home]\n\".profile\" = \"home/ada/profile\"\n\".local/bin/\" = \"home/ada/bin/\"\n"
    );
    let order: Vec<(String, String)> = home_binds(&manifest_from(&raw))
        .into_iter()
        .map(|b| (b.user, b.target))
        .collect();
    let expected = [
        ("ada", "/home/ada/.local/bin"),
        ("ada", "/home/ada/.profile"),
        ("eli", "/home/eli/.config/autostart"),
        ("eli", "/home/eli/.zshrc"),
    ]
    .map(|(u, t)| (u.to_string(), t.to_string()));
    assert_eq!(order, expected);
}

#[test]
fn no_users_no_binds() {
    let raw = MANIFEST.split("[users.eli]").next().unwrap();
    assert!(home_binds(&manifest_from(raw)).is_empty());
}
