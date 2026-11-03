//! Writes into a candidate's `/etc` that never follow a symlink out of it. Paths are given
//! as `/etc/...` and resolved below `etc_root`.

use crate::sys::{O_NOFOLLOW, O_NONBLOCK};
use crate::ExecError;
use aios_plan::EtcEntry;
use std::fs::{self, OpenOptions, Permissions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Replace `path` with `entry`. Missing parent directories are created (0755). An existing
/// file or symlink at `path` is removed first, never written through.
pub fn write(etc_root: &Path, path: &str, entry: &EtcEntry) -> Result<(), ExecError> {
    let full = parents(etc_root, path, true)?.expect("parents are created");
    match fs::symlink_metadata(&full) {
        Ok(meta) if meta.is_dir() => {
            return Err(ExecError(format!("{}: is a directory", full.display())))
        }
        Ok(_) => fs::remove_file(&full).map_err(|e| ExecError::io(&full, e))?,
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(ExecError::io(&full, e)),
    }
    let io = |e: std::io::Error| ExecError::io(&full, e);
    match entry {
        EtcEntry::File { content, mode } => {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&full)
                .map_err(io)?;
            file.write_all(content).map_err(io)?;
            file.set_permissions(Permissions::from_mode(*mode))
                .map_err(io)?;
        }
        EtcEntry::Symlink(target) => symlink(target, &full).map_err(io)?,
    }
    Ok(())
}

/// Set the mode of the regular file at `path` through a descriptor opened without following
/// a symlink (any symlink, at `path` or in a parent, is an error). For after a `chown`,
/// which clears the setuid and setgid bits.
pub fn set_mode(etc_root: &Path, path: &str, mode: u32) -> Result<(), ExecError> {
    let full = parents(etc_root, path, false)?
        .ok_or_else(|| ExecError(format!("{path}: no such file")))?;
    let io = |e: std::io::Error| ExecError::io(&full, e);
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK)
        .open(&full)
        .map_err(io)?;
    if !file.metadata().map_err(io)?.is_file() {
        return Err(ExecError(format!("{}: not a regular file", full.display())));
    }
    file.set_permissions(Permissions::from_mode(mode))
        .map_err(io)
}

/// Remove the file or symlink at `path`, if there is one.
pub fn remove(etc_root: &Path, path: &str) -> Result<(), ExecError> {
    let Some(full) = parents(etc_root, path, false)? else {
        return Ok(());
    };
    match fs::symlink_metadata(&full) {
        Ok(meta) if meta.is_dir() => Err(ExecError(format!("{}: is a directory", full.display()))),
        Ok(_) => fs::remove_file(&full).map_err(|e| ExecError::io(&full, e)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(ExecError::io(&full, e)),
    }
}

/// `mkdir -p` of `path` itself (0755 for new directories).
pub fn create_dirs(etc_root: &Path, path: &str) -> Result<(), ExecError> {
    let full = parents(etc_root, path, true)?.expect("parents are created");
    ensure_dir(&full, true).map(drop)
}

/// Check (and with `create`, make) every parent of `path` below `etc_root`. Returns the full
/// path, or `None` when a parent is missing and `create` is false.
fn parents(etc_root: &Path, path: &str, create: bool) -> Result<Option<PathBuf>, ExecError> {
    let rel = path
        .strip_prefix("/etc/")
        .filter(|rel| rel.split('/').all(|c| !matches!(c, "" | "." | "..")))
        .ok_or_else(|| ExecError(format!("{path}: not a path below /etc")))?;
    let mut full = etc_root.to_path_buf();
    let parts: Vec<&str> = rel.split('/').collect();
    for part in &parts[..parts.len() - 1] {
        full.push(part);
        if !ensure_dir(&full, create)? {
            return Ok(None);
        }
    }
    full.push(parts[parts.len() - 1]);
    Ok(Some(full))
}

/// `dir` is a real directory: `Ok(true)`. Missing: created when `create` (then `true`),
/// else `Ok(false)`. A symlink or any other file is an error.
fn ensure_dir(dir: &Path, create: bool) -> Result<bool, ExecError> {
    match fs::symlink_metadata(dir) {
        Ok(meta) if meta.file_type().is_symlink() => Err(ExecError(format!(
            "{}: is a symlink; refusing to follow it",
            dir.display()
        ))),
        Ok(meta) if meta.is_dir() => Ok(true),
        Ok(_) => Err(ExecError(format!("{}: is not a directory", dir.display()))),
        Err(e) if e.kind() == ErrorKind::NotFound && create => {
            let io = |e: std::io::Error| ExecError::io(dir, e);
            fs::create_dir(dir).map_err(io)?;
            fs::set_permissions(dir, Permissions::from_mode(0o755)).map_err(io)?;
            Ok(true)
        }
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(e) => Err(ExecError::io(dir, e)),
    }
}
