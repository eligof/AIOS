//! The other `aios` commands: rollback, gc, gen list and status.

mod boot;
mod gc;
mod gens;
mod rollback;
mod status;

pub use boot::{read_ukis, BootState, EspUki};
pub use gc::{gc, gc_mounted};
pub use gens::{gen_list, gen_rows, render_gen_list, GenRow};
pub use rollback::rollback;
pub use status::{drift, status, Drift, Status};

use crate::{btrfs, CommandRunner, ExecError, Layout};

/// Mount the top level, run `f`, and unmount again whether or not `f` succeeded.
fn with_top<T>(
    runner: &dyn CommandRunner,
    layout: &Layout,
    read_only: bool,
    f: impl FnOnce() -> Result<T, ExecError>,
) -> Result<T, ExecError> {
    btrfs::mount_top(runner, &layout.device, &layout.top, read_only)?;
    let result = f();
    let unmounted = btrfs::umount(runner, &layout.top);
    let value = result?;
    unmounted?;
    Ok(value)
}
