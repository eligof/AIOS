//! btrfs subvolume and mount operations, as commands through the runner.
//!
//! Whether something exists at a subvolume path is checked on the file system, so tests
//! model subvolumes as plain directories (see `FakeRunner::emulate_subvolumes`).

use crate::{run_ok, Cmd, CommandRunner, ExecError};
use std::fs;
use std::io::ErrorKind;
use std::path::Path;

fn run(runner: &dyn CommandRunner, cmd: Cmd) -> Result<(), ExecError> {
    run_ok(runner, &cmd).map(drop)
}

/// `btrfs subvolume create PATH`. Refused if anything, even a dangling symlink, is at PATH.
pub fn create(runner: &dyn CommandRunner, path: &Path) -> Result<(), ExecError> {
    vacant(path)?;
    run(
        runner,
        Cmd::new("btrfs")
            .args(["subvolume", "create"])
            .arg_path(path),
    )
}

/// `btrfs subvolume snapshot SRC DST` (writable, even from a read-only source). Refused if
/// anything is at DST: btrfs would put the snapshot inside an existing directory.
pub fn snapshot(runner: &dyn CommandRunner, src: &Path, dst: &Path) -> Result<(), ExecError> {
    vacant(dst)?;
    let cmd = Cmd::new("btrfs").args(["subvolume", "snapshot"]);
    run(runner, cmd.arg_path(src).arg_path(dst))
}

/// Nothing is at `path`, not even a dangling symlink (`lstat`).
fn vacant(path: &Path) -> Result<(), ExecError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(ExecError(format!("{} already exists", path.display()))),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(ExecError::io(path, e)),
    }
}

/// Delete the subvolume at `path` and every subvolume nested in it, if anything exists
/// there. btrfs walks the nesting itself (`delete --recursive`), so subvolume names are never
/// parsed, as in `aios-root.sh`. Anything at `path` that is not a subvolume is an error:
/// - a symlink, which btrfs-progs would resolve and so delete its target;
/// - anything but a directory with the subvolume root inode
///   ([`CommandRunner::is_subvolume_root`]);
/// - anything `btrfs subvolume show` rejects.
pub fn delete_recursive(runner: &dyn CommandRunner, path: &Path) -> Result<(), ExecError> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(ExecError::io(path, e)),
    };
    let not_a_subvolume = || ExecError(format!("{} exists but is not a subvolume", path.display()));
    if meta.file_type().is_symlink() {
        return Err(ExecError(format!(
            "{} is a symlink, not a subvolume",
            path.display()
        )));
    }
    if !runner.is_subvolume_root(&meta) {
        return Err(not_a_subvolume());
    }
    let show = Cmd::new("btrfs").args(["subvolume", "show"]).arg_path(path);
    if runner.run(&show)?.status != 0 {
        return Err(not_a_subvolume());
    }
    let cmd = Cmd::new("btrfs").args(["subvolume", "delete", "--recursive"]);
    run(runner, cmd.arg_path(path))
}

/// `btrfs property set -ts PATH ro true`
pub fn set_readonly(runner: &dyn CommandRunner, path: &Path) -> Result<(), ExecError> {
    let cmd = Cmd::new("btrfs")
        .args(["property", "set", "-ts"])
        .arg_path(path);
    run(runner, cmd.args(["ro", "true"]))
}

/// Create `top` and mount the btrfs top level there:
/// `mount -t btrfs -o subvolid=5[,ro] DEVICE TOP`.
pub fn mount_top(
    runner: &dyn CommandRunner,
    device: &Path,
    top: &Path,
    read_only: bool,
) -> Result<(), ExecError> {
    fs::create_dir_all(top).map_err(|e| ExecError::io(top, e))?;
    let options = if read_only {
        "subvolid=5,ro"
    } else {
        "subvolid=5"
    };
    let cmd = Cmd::new("mount").args(["-t", "btrfs", "-o", options]);
    run(runner, cmd.arg_path(device).arg_path(top))
}

/// `btrfs filesystem sync PATH`: commit the file system holding PATH, so every subvolume
/// rename, property change and delete made so far is on disk.
pub fn filesystem_sync(runner: &dyn CommandRunner, path: &Path) -> Result<(), ExecError> {
    run(
        runner,
        Cmd::new("btrfs")
            .args(["filesystem", "sync"])
            .arg_path(path),
    )
}

/// `mount --bind SRC DST`
pub fn bind(runner: &dyn CommandRunner, src: &Path, dst: &Path) -> Result<(), ExecError> {
    run(
        runner,
        Cmd::new("mount").arg("--bind").arg_path(src).arg_path(dst),
    )
}

/// `umount PATH`
pub fn umount(runner: &dyn CommandRunner, path: &Path) -> Result<(), ExecError> {
    run(runner, Cmd::new("umount").arg_path(path))
}

/// `umount -R PATH`: `PATH` and everything mounted below it.
pub fn umount_recursive(runner: &dyn CommandRunner, path: &Path) -> Result<(), ExecError> {
    run(runner, Cmd::new("umount").arg("-R").arg_path(path))
}

/// Names in the top level (subvolumes and anything else), sorted.
pub fn list_names(top: &Path) -> Result<Vec<String>, ExecError> {
    let entries = fs::read_dir(top).map_err(|e| ExecError::io(top, e))?;
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| ExecError::io(top, e))?;
        names.push(entry.file_name().to_string_lossy().into_owned());
    }
    names.sort();
    Ok(names)
}
