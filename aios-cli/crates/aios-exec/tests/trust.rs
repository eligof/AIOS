mod common;

use aios_exec::check_trusted_dirs;
use common::Fixture;
use std::fs;
use std::os::unix::fs::symlink;

#[test]
fn a_symlinked_manifest_repo_or_secrets_directory_is_refused() {
    for (dir, what) in [
        ("config", "manifest repo"),
        ("secrets", "secrets directory"),
    ] {
        let fx = Fixture::booted();
        let path = fx.dir.path().join(dir);
        let real = fx.dir.path().join(format!("{dir}.real"));
        fs::rename(&path, &real).unwrap();
        symlink(&real, &path).unwrap();
        let err = check_trusted_dirs(&fx.layout, fx.trusted_uid).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "{what} {} must be a real directory, not a symlink",
                path.display()
            )
        );
    }
}
