//! Compare the manifest with the booted generation: what would `aios apply` change?
//!
//! All system access goes through [`SystemProbe`], so every test runs without root.

mod desired;
mod plan;
mod probe;

pub use desired::{desired_etc, Inputs, PlanError, GENERATION_TOML, MANAGED_FILES};
pub use plan::{build_plan, ChangeKind, EtcChange, Plan, UnitChange, LOCKDOWN_NONE_WARNING};
pub use probe::{EtcEntry, ProbeError, SystemProbe, UnitState};
