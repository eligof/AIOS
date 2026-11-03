//! The other `aios` commands: rollback, gc, gen list, status, passwd, plan, Secure Boot
//! and TPM enrollment.

mod boot;
mod gc;
mod gens;
mod keys;
mod passwd;
mod plan;
mod rollback;
mod status;

pub use boot::{read_ukis, BootState, EspUki};
pub use gc::{gc, gc_mounted, GcMode};
pub use gens::{gen_list, gen_rows, render_gen_list, GenRow};
pub use keys::{secureboot_enroll, tpm_enroll};
pub use passwd::passwd;
pub use plan::plan;
pub use rollback::rollback;
pub use status::{drift, status, Drift, Modified, Status, DRIFT_READ_MAX};

use crate::{btrfs, CommandRunner, ExecError, Layout};
use std::fs;
use std::path::{Path, PathBuf};

/// Mount the top level, run `f` with the layout to use while it is mounted, and unmount
/// again whether `f` succeeds, fails or panics. A writer mounts read-write at `layout.top`
/// (it holds the exclusive lock). A reader mounts read-only at its own
/// [`Layout::ro_top`], created here and removed afterwards, and `f` gets a copy of the
/// layout with `top` pointing there: readers share the lock, so they must not share a
/// mount point.
fn with_top<T>(
    runner: &dyn CommandRunner,
    layout: &Layout,
    read_only: bool,
    f: impl FnOnce(&Layout) -> Result<T, ExecError>,
) -> Result<T, ExecError> {
    let mut view = layout.clone();
    if read_only {
        view.top = layout.ro_top();
    }
    let mount = TopMount::mount(runner, &layout.device, &view.top, read_only)?;
    let result = f(&view);
    match (result, mount.unmount()) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(e), Ok(())) | (Ok(_), Err(e)) => Err(e),
        (Err(e), Err(unmount)) => Err(ExecError(format!("{e}; also, {unmount}"))),
    }
}

/// The top level mounted at `path`. `unmount` reports a failure; if it never runs (an
/// early return or a panic), dropping the guard unmounts anyway and logs a failure to
/// stderr. A private (reader) mount point is removed once unmounted; if that fails, a
/// warning goes to stderr and the command's outcome stands.
struct TopMount<'a> {
    runner: &'a dyn CommandRunner,
    path: PathBuf,
    mounted: bool,
    private: bool,
}

impl<'a> TopMount<'a> {
    fn mount(
        runner: &'a dyn CommandRunner,
        device: &Path,
        path: &Path,
        read_only: bool,
    ) -> Result<TopMount<'a>, ExecError> {
        // Built before mounting (`mount_top` creates the directory), so a failed mount
        // still removes a private directory.
        let mut guard = TopMount {
            runner,
            path: path.to_path_buf(),
            mounted: false,
            private: read_only,
        };
        btrfs::mount_top(runner, device, path, read_only)?;
        guard.mounted = true;
        Ok(guard)
    }

    fn unmount(mut self) -> Result<(), ExecError> {
        self.release()
    }

    fn release(&mut self) -> Result<(), ExecError> {
        if std::mem::take(&mut self.mounted) {
            if let Err(e) = btrfs::umount(self.runner, &self.path) {
                // Still mounted: leave the directory alone.
                self.private = false;
                return Err(e);
            }
        }
        if std::mem::take(&mut self.private) {
            // Unmounted (or never mounted), so all that can be left is an empty directory:
            // the command's outcome stands.
            if let Some(warning) = remove_mount_point(&self.path) {
                eprintln!("aios: warning: {warning}");
            }
        }
        Ok(())
    }
}

/// Remove a reader's unmounted mount point. A failure (`EBUSY`, say) is returned as a
/// warning; a directory already gone is fine.
fn remove_mount_point(path: &Path) -> Option<String> {
    match fs::remove_dir(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            Some(format!("cannot remove {}: {e}", path.display()))
        }
        _ => None,
    }
}

impl Drop for TopMount<'_> {
    fn drop(&mut self) {
        if let Err(e) = self.release() {
            eprintln!("aios: cleanup: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{remove_mount_point, with_top};
    use crate::{ExecError, FakeRunner, Layout};
    use std::fs;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::path::Path;

    /// What `umount DIR` leaves when something else holds DIR: here a file in it, so
    /// removing DIR fails (ENOTEMPTY standing in for EBUSY).
    fn leave_a_file(argv: &[&str]) {
        fs::write(Path::new(argv[1]).join("busy"), "").unwrap();
    }

    #[test]
    fn a_mount_point_left_behind_after_a_successful_reader_is_only_a_warning() {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::under(dir.path());
        let mut runner = FakeRunner::new();
        runner.on_success(&["umount"], leave_a_file);
        let value = with_top(&runner, &layout, true, |_| Ok(42)).unwrap();
        assert_eq!(value, 42);
        assert!(layout.ro_top().join("busy").exists());
    }

    #[test]
    fn a_mount_point_left_behind_after_a_failed_reader_keeps_the_readers_error() {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::under(dir.path());
        let mut runner = FakeRunner::new();
        runner.on_success(&["umount"], leave_a_file);
        let err = with_top(&runner, &layout, true, |_| -> Result<(), ExecError> {
            Err(ExecError::new("reader failed"))
        })
        .unwrap_err();
        assert_eq!(err.to_string(), "reader failed");
    }

    #[test]
    fn removing_a_mount_point_reports_why_it_failed() {
        let dir = tempfile::tempdir().unwrap();
        let busy = dir.path().join("ro.1");
        fs::create_dir(&busy).unwrap();
        fs::write(busy.join("x"), "").unwrap();
        let warning = remove_mount_point(&busy).unwrap();
        assert!(
            warning.starts_with(&format!("cannot remove {}: ", busy.display())),
            "{warning}"
        );
        assert_eq!(remove_mount_point(&dir.path().join("gone")), None);
        fs::remove_file(busy.join("x")).unwrap();
        assert_eq!(remove_mount_point(&busy), None);
        assert!(!busy.exists());
    }

    #[test]
    fn a_panicking_reader_still_unmounts_and_removes_its_mount_point() {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::under(dir.path());
        let ro = layout.ro_top();
        let runner = FakeRunner::new();
        let caught = catch_unwind(AssertUnwindSafe(|| {
            with_top(&runner, &layout, true, |view| -> Result<(), ExecError> {
                assert_eq!(view.top, ro);
                assert!(view.top.is_dir());
                panic!("reader panicked");
            })
        }));
        assert!(caught.is_err());
        assert_eq!(
            runner.calls(),
            [
                format!(
                    "mount -t btrfs -o subvolid=5,ro /dev/mapper/aios {}",
                    ro.display()
                ),
                format!("umount {}", ro.display()),
            ]
        );
        assert!(!ro.exists(), "mount point left behind");
    }

    #[test]
    fn a_failed_unmount_is_reported_even_when_the_reader_failed() {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::under(dir.path());
        let mut runner = FakeRunner::new();
        runner.fail_on(&["umount"]);
        let err = with_top(&runner, &layout, true, |_| -> Result<(), ExecError> {
            Err(ExecError::new("reader failed"))
        })
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "reader failed; also, `umount {}` exited with status 1: injected failure",
                layout.ro_top().display()
            )
        );
    }

    #[test]
    fn a_panicking_writer_still_unmounts_the_shared_mount_point() {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::under(dir.path());
        let runner = FakeRunner::new();
        let caught = catch_unwind(AssertUnwindSafe(|| {
            with_top(&runner, &layout, false, |view| -> Result<(), ExecError> {
                assert_eq!(view, &layout);
                panic!("writer panicked");
            })
        }));
        assert!(caught.is_err());
        let top = layout.top.display();
        assert_eq!(
            runner.calls(),
            [
                format!("mount -t btrfs -o subvolid=5 /dev/mapper/aios {top}"),
                format!("umount {top}"),
            ]
        );
        assert!(layout.top.is_dir(), "the writer's mount point stays");
    }
}
