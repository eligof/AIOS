mod common;

use aios_exec::check_trusted_dirs;
use common::Fixture;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;

fn chmod(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

/// `<config>/.git` (0755) with a `config` file (0644).
fn git_dir(fx: &Fixture) -> std::path::PathBuf {
    let git = fx.layout.config.join(".git");
    fs::create_dir(&git).unwrap();
    chmod(&git, 0o755);
    fs::write(git.join("config"), "[core]\n").unwrap();
    chmod(&git.join("config"), 0o644);
    git
}

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

#[test]
fn a_repo_with_a_trusted_git_directory_or_none_yet_passes() {
    let fx = Fixture::booted();
    assert!(!fx.layout.config.join(".git").exists());
    check_trusted_dirs(&fx.layout, fx.trusted_uid).unwrap();
    git_dir(&fx);
    check_trusted_dirs(&fx.layout, fx.trusted_uid).unwrap();
}

#[test]
fn a_group_or_world_writable_git_directory_or_config_is_refused() {
    for (rel, mode, what) in [
        (".git", 0o775, "manifest git directory"),
        (".git", 0o757, "manifest git directory"),
        (".git/config", 0o664, "manifest git config"),
        (".git/config", 0o646, "manifest git config"),
    ] {
        let fx = Fixture::booted();
        git_dir(&fx);
        let path = fx.layout.config.join(rel);
        chmod(&path, mode);
        let err = check_trusted_dirs(&fx.layout, fx.trusted_uid).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "{what} {} must be root-owned and not group/world-writable",
                path.display()
            ),
            "{rel} {mode:o}"
        );
    }
}

#[test]
fn a_symlinked_git_directory_or_config_is_refused() {
    for (rel, what, noun) in [
        (".git", "manifest git directory", "a real directory"),
        (".git/config", "manifest git config", "a regular file"),
    ] {
        let fx = Fixture::booted();
        git_dir(&fx);
        let path = fx.layout.config.join(rel);
        let real = fx.dir.path().join("elsewhere");
        fs::rename(&path, &real).unwrap();
        symlink(&real, &path).unwrap();
        let err = check_trusted_dirs(&fx.layout, fx.trusted_uid).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("{what} {} must be {noun}, not a symlink", path.display())
        );
    }
}

/// A `.git` file (`gitdir: <elsewhere>`) would move the repo's config out of reach of
/// this check.
#[test]
fn a_git_file_instead_of_a_directory_is_refused() {
    let fx = Fixture::booted();
    let git = fx.layout.config.join(".git");
    fs::write(&git, "gitdir: /home/eli/evil.git\n").unwrap();
    let err = check_trusted_dirs(&fx.layout, fx.trusted_uid).unwrap_err();
    assert_eq!(
        err.to_string(),
        format!(
            "manifest git directory {} must be a real directory",
            git.display()
        )
    );
}
