//! Pure renderers for the files AIOS writes into a generation's `/etc`.
//!
//! Nothing here touches the system: every function maps a manifest (plus a
//! [`RenderCtx`]) to text.

mod cmdline;
mod ctx;
mod fstab;
mod home;
mod managed;
mod merge;
mod simple;
mod tmpfiles;
mod users;

pub use cmdline::cmdline;
pub use ctx::RenderCtx;
pub use fstab::{fstab, fstab_escape};
pub use home::{home_binds, HomeBind};
pub use managed::{managed_list, parse_managed_list};
pub use merge::{merge_users, MANAGED_IDS};
pub use simple::{hostname, loader_conf, locale_conf, locale_gen, localtime_target, vconsole_conf};
pub use tmpfiles::{home_tmpfiles, persist_dirs, persist_tmpfiles};
pub use users::{
    GroupEntry, GshadowEntry, PasswdEntry, ShadowEntry, UserDb, UserDbError, UserFiles,
};
