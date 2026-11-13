//! Types shared by the Sentinel kernel programs and `sentineld`.
//!
//! `no_std` so the eBPF crate (S2) can depend on it. Pure data and the rule
//! evaluator; no allocation, no I/O, no clock.
#![no_std]

pub mod event;
pub mod facts;
pub mod rule;

pub use event::{Action, EventKind, Mode, Severity};
pub use facts::*;
pub use rule::{eval, KRule, MAX_CIDRS, MAX_MOUNTS, MAX_PORT_SETS, MAX_RULES, MAX_UID_LITERALS};
