//! Sentinel rules: parse TOML, validate, classify kernel vs user space,
//! compile to kernel tables and user-space matchers, diff rule sets.
//!
//! Pure: no I/O except `load_dir`, no clock. Builds on stable so `aios-cli`
//! can path-depend on it (S4).

pub mod config;
