//! Everything `aios` does to the running system, behind [`CommandRunner`], so every test
//! runs without root against a [`FakeRunner`] and tempdirs.

mod apply;
pub mod btrfs;
mod error;
mod facts;
mod layout;
mod probe;
mod runner;
mod steps;
mod sys;
mod trust;

pub use apply::{apply, ApplyCtx, ApplyOutcome, Mode};
pub use error::ExecError;
pub use facts::{read_hashes, MachineFacts};
pub use layout::Layout;
pub use probe::{parse_unit_state, read_etc_entry, DirProbe};
pub use runner::{run_ok, status_error, Cmd, CommandRunner, FakeRunner, Output, RealRunner};
pub use steps::{Step, StepError};
pub use sys::{
    days_since_epoch, luks_uuid_from_cmdline, parse_df_avail, parse_efivar_utf16, rfc3339_utc,
    sha256_hex, unit_file_name,
};
pub use trust::check_trusted_dirs;
