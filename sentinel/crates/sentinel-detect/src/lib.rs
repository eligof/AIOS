//! Built-in detectors. Pure: all time is passed in by the caller, so tests
//! drive synthetic timelines without a clock (spec §14).

pub mod beacon;
pub mod dns_tunnel;
