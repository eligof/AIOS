use aios_exec::{ExecError, StepError};
use aios_manifest::ManifestError;
use std::fmt;

/// Why `aios` exits non-zero: the message for stderr and the exit code.
#[derive(Debug)]
pub struct Failure {
    pub code: u8,
    pub message: String,
}

impl Failure {
    /// Exit 1. `message` is printed as is.
    pub fn op(message: impl Into<String>) -> Failure {
        Failure {
            code: 1,
            message: message.into(),
        }
    }

    /// Exit 2: one `manifest.toml:line:col: reason` line per problem.
    pub fn manifest(errors: Vec<ManifestError>) -> Failure {
        let lines: Vec<String> = errors.iter().map(ToString::to_string).collect();
        Failure {
            code: 2,
            message: lines.join("\n"),
        }
    }
}

impl From<ExecError> for Failure {
    fn from(e: ExecError) -> Failure {
        Failure::op(format!("aios: {e}"))
    }
}

impl From<StepError> for Failure {
    fn from(e: StepError) -> Failure {
        Failure::op(e.to_string())
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}
