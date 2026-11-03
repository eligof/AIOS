//! Compare the manifest with the booted generation: what would `aios apply` change?
//!
//! All system access goes through [`SystemProbe`], so every test runs without root.

mod desired;
mod probe;

pub use desired::{desired_etc, Inputs, PlanError, GENERATION_TOML, MANAGED_FILES};
pub use probe::{EtcEntry, ProbeError, SystemProbe, UnitState};
