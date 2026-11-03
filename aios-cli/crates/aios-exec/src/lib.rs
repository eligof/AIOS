//! Everything `aios` does to the running system, behind [`CommandRunner`], so every test
//! runs without root against a [`FakeRunner`] and tempdirs.

mod error;
mod runner;

pub use error::ExecError;
pub use runner::{run_ok, status_error, Cmd, CommandRunner, FakeRunner, Output, RealRunner};
