use crate::{ExecError, Layout};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// The manifest repo and the secrets directory decide what runs as root, so they must be
/// owned by `uid` (0 in production) and not group- or world-writable. Checked before the
/// manifest is read, so nobody else can swap files between validation and use.
pub fn check_trusted_dirs(layout: &Layout, uid: u32) -> Result<(), ExecError> {
    check_dir(&layout.config, "manifest repo", uid)?;
    check_dir(&layout.secrets, "secrets directory", uid)
}

/// `path` is a directory itself (not a symlink to one), owned by `uid` and not group- or
/// world-writable. `what` names it in the error.
pub(crate) fn check_dir(path: &Path, what: &str, uid: u32) -> Result<(), ExecError> {
    let meta = fs::symlink_metadata(path).map_err(|e| ExecError::io(path, e))?;
    if !meta.is_dir() {
        return Err(ExecError(format!(
            "{what} {} must be a real directory, not a symlink",
            path.display()
        )));
    }
    if meta.uid() != uid || meta.mode() & 0o022 != 0 {
        return Err(ExecError(format!(
            "{what} {} must be root-owned and not group/world-writable",
            path.display()
        )));
    }
    Ok(())
}
