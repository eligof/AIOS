use crate::{ExecError, Layout};
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// The manifest repo and the secrets directory decide what runs as root, so they must be
/// owned by `uid` (0 in production) and not group- or world-writable. So must the repo's
/// `.git` directory and `.git/config`, if present: git, run as root, reads no other config
/// (spec §4.3 step 1), so nobody else can define a filter or diff driver there. Checked
/// before the manifest is read, so nobody else can swap files between validation and use.
pub fn check_trusted_dirs(layout: &Layout, uid: u32) -> Result<(), ExecError> {
    check_dir(&layout.config, "manifest repo", uid)?;
    check_git_dir(&layout.config, uid)?;
    check_dir(&layout.secrets, "secrets directory", uid)
}

/// `<repo>/.git` is a directory (not a symlink, nor a `gitdir:` file pointing elsewhere)
/// and `<repo>/.git/config` a regular file, both owned by `uid` and not group- or
/// world-writable. Either may be missing.
fn check_git_dir(repo: &Path, uid: u32) -> Result<(), ExecError> {
    let git = repo.join(".git");
    if check(&git, "manifest git directory", Kind::Dir, uid, true)? {
        check(
            &git.join("config"),
            "manifest git config",
            Kind::File,
            uid,
            true,
        )?;
    }
    Ok(())
}

/// `path` is a directory itself (not a symlink to one), owned by `uid` and not group- or
/// world-writable. `what` names it in the error.
pub(crate) fn check_dir(path: &Path, what: &str, uid: u32) -> Result<(), ExecError> {
    check(path, what, Kind::Dir, uid, false).map(drop)
}

#[derive(Debug, Clone, Copy)]
enum Kind {
    Dir,
    File,
}

/// `path` is a `kind` itself (never a symlink), owned by `uid` and not group- or
/// world-writable. `Ok(false)` when it is missing and `optional`.
fn check(path: &Path, what: &str, kind: Kind, uid: u32, optional: bool) -> Result<bool, ExecError> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if optional && e.kind() == ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(ExecError::io(path, e)),
    };
    let (is_kind, noun) = match kind {
        Kind::Dir => (meta.is_dir(), "a real directory"),
        Kind::File => (meta.is_file(), "a regular file"),
    };
    if meta.file_type().is_symlink() {
        return Err(ExecError(format!(
            "{what} {} must be {noun}, not a symlink",
            path.display()
        )));
    }
    if !is_kind {
        return Err(ExecError(format!(
            "{what} {} must be {noun}",
            path.display()
        )));
    }
    if meta.uid() != uid || meta.mode() & 0o022 != 0 {
        return Err(ExecError(format!(
            "{what} {} must be root-owned and not group/world-writable",
            path.display()
        )));
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::{check, check_git_dir, Kind};
    use std::fs;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    /// Tests can't chown, so the owner check is shown with a uid that isn't the owner.
    #[test]
    fn a_git_directory_owned_by_another_uid_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let git = dir.path().join(".git");
        fs::create_dir(&git).unwrap();
        fs::write(git.join("config"), "").unwrap();
        let owner = fs::metadata(&git).unwrap().uid();
        check_git_dir(dir.path(), owner).unwrap();
        let err = check_git_dir(dir.path(), owner.wrapping_add(1)).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "manifest git directory {} must be root-owned and not group/world-writable",
                git.display()
            )
        );
    }

    #[test]
    fn a_file_owned_by_another_uid_is_refused() {
        let passwd = Path::new("/etc/passwd");
        let owner = fs::metadata(passwd).unwrap().uid();
        assert!(check(passwd, "x", Kind::File, owner, false).unwrap());
        assert!(check(passwd, "x", Kind::File, owner.wrapping_add(1), false).is_err());
    }

    #[test]
    fn only_an_optional_entry_may_be_missing() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing");
        assert!(!check(&missing, "x", Kind::File, 0, true).unwrap());
        assert!(check(&missing, "x", Kind::File, 0, false).is_err());
    }
}
