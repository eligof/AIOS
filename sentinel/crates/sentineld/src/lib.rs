//! The AIOS Sentinel daemon (spec §6–§10, §12–§13).
//!
//! Every effect on the kernel goes through the [`kernel::Kernel`] trait, so the
//! whole dispatch path is unit-testable on the host without root.

pub mod alert;
pub mod kernel;
pub mod proc;
pub mod table;
