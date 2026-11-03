use std::collections::BTreeSet;
use std::fmt;

/// One entry of a generation's `/etc`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EtcEntry {
    /// A regular file and its permission bits (`st_mode & 0o7777`).
    File { content: Vec<u8>, mode: u32 },
    /// A symlink and its target.
    Symlink(String),
}

/// `systemctl is-enabled` result, reduced to what the planner compares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitState {
    Enabled,
    Disabled,
    Masked,
    Static,
    NotFound,
}

impl UnitState {
    /// The `systemctl is-enabled` spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            UnitState::Enabled => "enabled",
            UnitState::Disabled => "disabled",
            UnitState::Masked => "masked",
            UnitState::Static => "static",
            UnitState::NotFound => "not-found",
        }
    }
}

impl fmt::Display for UnitState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A probe call failed (command error, unreadable snapshot, ...).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeError(pub String);

impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ProbeError {}

/// Read-only view of the booted generation. The real implementation lives in a later phase;
/// tests use an in-memory fake.
pub trait SystemProbe {
    /// `pacman -Qqe` of the booted generation.
    fn explicit_packages(&self) -> Result<BTreeSet<String>, ProbeError>;
    /// An entry of the booted `@etc-gen-N` snapshot (not the live `/etc`). `None` if absent.
    fn etc_entry(&self, path: &str) -> Result<Option<EtcEntry>, ProbeError>;
    /// Enablement state of a unit in the booted generation.
    fn unit_state(&self, unit: &str) -> Result<UnitState, ProbeError>;
}
