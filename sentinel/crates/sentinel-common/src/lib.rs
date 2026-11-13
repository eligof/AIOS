//! Types shared by the Sentinel kernel programs and `sentineld`.
//!
//! `no_std` so the eBPF crate (S2) can depend on it. Pure data and the rule
//! evaluator; no allocation, no I/O, no clock.
#![no_std]

pub mod event;
pub mod facts;
pub mod rule;
