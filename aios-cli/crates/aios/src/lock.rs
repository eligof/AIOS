use crate::failure::Failure;
use aios_exec::{Step, StepError};
use rustix::fs::{flock, FlockOperation};
use rustix::io::Errno;
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// An flock on the lock file, held until dropped.
pub struct Lock(#[allow(dead_code)] File);

/// Take the lock without waiting: exclusive for commands that change anything, shared
/// for read-only ones (they mount the top level too, so they must not run during an apply).
pub fn acquire(path: &Path, exclusive: bool) -> Result<Lock, Failure> {
    let failed = |detail: String| {
        Failure::from(StepError {
            step: Step::Lock,
            detail,
        })
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| failed(format!("{}: {e}", parent.display())))?;
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .map_err(|e| failed(format!("{}: {e}", path.display())))?;
    let operation = if exclusive {
        FlockOperation::NonBlockingLockExclusive
    } else {
        FlockOperation::NonBlockingLockShared
    };
    match flock(&file, operation) {
        Ok(()) => Ok(Lock(file)),
        Err(e) if e == Errno::WOULDBLOCK => {
            Err(Failure::op("aios: another aios operation is running"))
        }
        Err(e) => Err(failed(format!("{}: {e}", path.display()))),
    }
}
