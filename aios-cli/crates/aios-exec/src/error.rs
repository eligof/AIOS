use std::fmt;
use std::path::Path;

/// A failed system operation: a command, a file access or a precondition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecError(pub String);

impl ExecError {
    pub fn new(message: impl Into<String>) -> ExecError {
        ExecError(message.into())
    }

    /// `<path>: <error>`, for file system failures.
    pub fn io(path: &Path, err: impl fmt::Display) -> ExecError {
        ExecError(format!("{}: {err}", path.display()))
    }
}

impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ExecError {}
