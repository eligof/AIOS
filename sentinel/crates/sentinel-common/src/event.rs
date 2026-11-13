//! Event kinds and the enums shared across the ringbuf and maps.

/// What a rule fires `on`, and the discriminant on every raw event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EventKind {
    Exec = 0,
    Fork = 1,
    Exit = 2,
    Connect = 3,
    Listen = 4,
    Open = 5,
    WriteRefused = 6,
    Memfd = 7,
    Ptrace = 8,
    Module = 9,
    Bpf = 10,
    Signal = 11,
    Dns = 12,
}

impl EventKind {
    /// Every variant, for exhaustive iteration in tests and validation.
    pub const ALL: [EventKind; 13] = [
        EventKind::Exec,
        EventKind::Fork,
        EventKind::Exit,
        EventKind::Connect,
        EventKind::Listen,
        EventKind::Open,
        EventKind::WriteRefused,
        EventKind::Memfd,
        EventKind::Ptrace,
        EventKind::Module,
        EventKind::Bpf,
        EventKind::Signal,
        EventKind::Dns,
    ];

    pub fn from_u8(v: u8) -> Option<EventKind> {
        EventKind::ALL.into_iter().find(|k| *k as u8 == v)
    }
}

/// What Sentinel does when a rule matches (§6). Values cross into kernel maps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Action {
    Alert = 0,
    Deny = 1,
    Freeze = 2,
    Kill = 3,
}

/// Enforce takes the action; audit only reports what would have happened (§5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    Enforce = 0,
    Audit = 1,
}

/// Alert severity (§9). Ordered: Info lowest, Critical highest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Severity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_kind_roundtrips_through_u8() {
        for k in EventKind::ALL {
            assert_eq!(EventKind::from_u8(k as u8), Some(k));
        }
        assert_eq!(EventKind::from_u8(255), None);
    }

    #[test]
    fn severity_orders_info_lowest_critical_highest() {
        assert!(Severity::Info < Severity::Critical);
        assert!(Severity::High < Severity::Critical);
        assert!(Severity::Medium > Severity::Low);
    }

    #[test]
    fn action_and_mode_have_stable_discriminants() {
        assert_eq!(Action::Alert as u8, 0);
        assert_eq!(Action::Deny as u8, 1);
        assert_eq!(Action::Freeze as u8, 2);
        assert_eq!(Action::Kill as u8, 3);
        assert_eq!(Mode::Enforce as u8, 0);
        assert_eq!(Mode::Audit as u8, 1);
    }
}
