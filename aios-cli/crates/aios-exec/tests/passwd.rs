mod common;

use aios_exec::ops::passwd;
use aios_exec::Output;
use common::Fixture;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
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
    let path = passwd(
        &fx.runner,
        &fx.layout,
        "ada",
        "correct horse",
        fx.trusted_uid,
    )
    .unwrap();
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
    passwd(&fx.runner, &fx.layout, "eli", "one", fx.trusted_uid).unwrap();
    passwd(&fx.runner, &fx.layout, "eli", "two", fx.trusted_uid).unwrap();
    let text = fs::read_to_string(fx.layout.passwd_secret("eli")).unwrap();
    assert_eq!(text, "$y$j9T$second$hash\n");
}

#[test]
fn rejects_unexpected_hashes() {
    for bad in ["$6$sha512$hash\n", "$y$a:b\n", "\n"] {
        let fx = hashing(bad);
        let err = passwd(&fx.runner, &fx.layout, "eli", "pw", fx.trusted_uid).unwrap_err();
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
        let err = passwd(&fx.runner, &fx.layout, user, "pw", fx.trusted_uid).unwrap_err();
        assert_eq!(err.to_string(), format!("invalid user name {user:?}"));
    }
    for password in ["", "two\nlines", "carriage\rreturn", "nul\0byte"] {
        let err = passwd(&fx.runner, &fx.layout, "eli", password, fx.trusted_uid).unwrap_err();
        assert_eq!(
            err.to_string(),
            "the password must be one non-empty line without NUL bytes",
            "{password:?}"
        );
    }
    assert!(fx.calls().is_empty());
}

fn tmp_file(fx: &Fixture, user: &str) -> std::path::PathBuf {
    fx.layout.secrets.join(format!("passwd/.{user}.tmp"))
}

#[test]
fn the_secrets_directories_must_not_be_symlinks() {
    for (dir, real) in [("secrets", "elsewhere"), ("secrets/passwd", "elsewhere")] {
        let fx = hashing("$y$j9T$x$y\n");
        let elsewhere = fx.dir.path().join(real);
        fs::create_dir_all(&elsewhere).unwrap();
        fs::set_permissions(&elsewhere, fs::Permissions::from_mode(0o700)).unwrap();
        let link = fx.dir.path().join(dir);
        fs::create_dir_all(link.parent().unwrap()).unwrap();
        symlink(&elsewhere, &link).unwrap();
        let err = passwd(&fx.runner, &fx.layout, "eli", "pw", fx.trusted_uid).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "secrets directory {} must be a real directory, not a symlink",
                link.display()
            )
        );
        assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0, "{dir}");
    }
}

#[test]
fn the_secrets_directories_must_belong_to_the_trusted_uid() {
    let fx = hashing("$y$j9T$x$y\n");
    let err = passwd(&fx.runner, &fx.layout, "eli", "pw", fx.trusted_uid + 1).unwrap_err();
    assert_eq!(
        err.to_string(),
        format!(
            "secrets directory {} must be root-owned and not group/world-writable",
            fx.layout.secrets.display()
        )
    );
    assert!(!fx.layout.passwd_secret("eli").exists());
}

#[test]
fn a_stale_temp_file_is_replaced() {
    let fx = hashing("$y$j9T$new$hash\n");
    passwd(&fx.runner, &fx.layout, "eli", "one", fx.trusted_uid).unwrap();
    fs::write(tmp_file(&fx, "eli"), "half-written junk").unwrap();
    passwd(&fx.runner, &fx.layout, "eli", "two", fx.trusted_uid).unwrap();
    assert_eq!(
        fs::read_to_string(fx.layout.passwd_secret("eli")).unwrap(),
        "$y$j9T$new$hash\n"
    );
    assert!(!tmp_file(&fx, "eli").exists());
}

#[test]
fn a_planted_temp_symlink_is_not_followed() {
    let fx = hashing("$y$j9T$new$hash\n");
    passwd(&fx.runner, &fx.layout, "eli", "one", fx.trusted_uid).unwrap();
    let victim = fx.dir.path().join("victim");
    fs::write(&victim, "precious\n").unwrap();
    symlink(&victim, tmp_file(&fx, "eli")).unwrap();
    passwd(&fx.runner, &fx.layout, "eli", "two", fx.trusted_uid).unwrap();
    assert_eq!(fs::read_to_string(&victim).unwrap(), "precious\n");
    let secret = fx.layout.passwd_secret("eli");
    assert!(fs::symlink_metadata(&secret).unwrap().is_file());
    assert_eq!(mode(&secret), 0o600);
}

#[test]
fn a_failed_write_removes_the_temp_file() {
    let fx = hashing("$y$j9T$new$hash\n");
    // A non-empty directory where the secret goes: the rename fails.
    fs::create_dir_all(fx.layout.passwd_secret("eli").join("x")).unwrap();
    let err = passwd(&fx.runner, &fx.layout, "eli", "pw", fx.trusted_uid).unwrap_err();
    assert!(
        err.to_string()
            .starts_with(&fx.layout.passwd_secret("eli").display().to_string()),
        "{err}"
    );
    assert!(!tmp_file(&fx, "eli").exists());
}
