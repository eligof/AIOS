//! Everything `aios` does to the running system, behind [`CommandRunner`], so every test
//! runs without root against a [`FakeRunner`] and tempdirs.

mod apply;
pub mod btrfs;
mod error;
pub mod etcfs;
mod facts;
mod layout;
pub mod ops;
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
pub use runner::{
    run_ok, status_error, Cmd, CommandRunner, Effect, FakeRunner, Output, RealRunner,
    SUBVOLUME_ROOT_INO,
};
pub use steps::{Step, StepError};
pub use sys::{
    days_since_epoch, luks_uuid_from_cmdline, parse_df_avail, parse_efivar_utf16, rfc3339_utc,
    sha256_hex, unit_file_name,
};
pub use trust::check_trusted_dirs;
