mod common;

use aios_exec::ops::passwd;
use aios_exec::Output;
use common::Fixture;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

fn hashing(hash: &str) -> Fixture {
    let mut fx = Fixture::booted();
    fx.runner.respond(&["mkpasswd"], Output::ok(hash));
    fs::remove_dir_all(&fx.layout.secrets).unwrap();
    fx
}

#[test]
fn writes_the_yescrypt_hash_privately() {
    let fx = hashing("$y$j9T$new$hash\n");
    let path = passwd(&fx.runner, &fx.layout, "ada", "correct horse").unwrap();
    assert_eq!(path, fx.layout.passwd_secret("ada"));
    assert_eq!(fs::read_to_string(&path).unwrap(), "$y$j9T$new$hash\n");
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(&fx.layout.secrets), 0o700);
    assert_eq!(mode(&fx.layout.secrets.join("passwd")), 0o700);
    let cmds = fx.runner.commands();
    assert_eq!(fx.calls(), ["mkpasswd -m yescrypt -s"]);
    assert_eq!(cmds[0].stdin.as_deref(), Some(&b"correct horse\n"[..]));
    assert_eq!(
        fs::read_dir(fx.layout.secrets.join("passwd"))
            .unwrap()
            .count(),
        1
    );
}

#[test]
fn replaces_an_existing_hash() {
    let fx = hashing("$y$j9T$second$hash\n");
    passwd(&fx.runner, &fx.layout, "eli", "one").unwrap();
    passwd(&fx.runner, &fx.layout, "eli", "two").unwrap();
    let text = fs::read_to_string(fx.layout.passwd_secret("eli")).unwrap();
    assert_eq!(text, "$y$j9T$second$hash\n");
}

#[test]
fn rejects_unexpected_hashes() {
    for bad in ["$6$sha512$hash\n", "$y$a:b\n", "\n"] {
        let fx = hashing(bad);
        let err = passwd(&fx.runner, &fx.layout, "eli", "pw").unwrap_err();
        assert_eq!(
            err.to_string(),
            "`mkpasswd -m yescrypt -s` printed an unexpected hash"
        );
        assert!(!fx.layout.passwd_secret("eli").exists());
    }
}

#[test]
fn rejects_bad_user_names_and_passwords() {
    let fx = hashing("$y$j9T$x$y\n");
    for user in ["../etc", "Eli", "", "a/b"] {
        let err = passwd(&fx.runner, &fx.layout, user, "pw").unwrap_err();
        assert_eq!(err.to_string(), format!("invalid user name {user:?}"));
    }
    for password in ["", "two\nlines"] {
        let err = passwd(&fx.runner, &fx.layout, "eli", password).unwrap_err();
        assert_eq!(err.to_string(), "the password must be one non-empty line");
    }
    assert!(fx.calls().is_empty());
}
