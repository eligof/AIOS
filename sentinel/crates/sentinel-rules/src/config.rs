//! The `[sentinel]` manifest section (§11.1) and the two detector configs
//! (§5.4). Shared by `aios-cli` and `sentineld`.

use globset::Glob;
use serde::Deserialize;

use crate::validate::{parse_duration_ms, parse_severity};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SentinelConfig {
    pub enable: bool,
    pub rules: String,
    pub lockdown_after: String,
    pub storm_brake: u32,
    pub never_act_on: Vec<String>,
    pub bpf_loaders: Vec<String>,
    pub beacon: Beacon,
    pub dns_tunnel: DnsTunnel,
}

impl Default for SentinelConfig {
    fn default() -> SentinelConfig {
        SentinelConfig {
            enable: true,
            rules: "sentinel/rules".to_string(),
            lockdown_after: "5s".to_string(),
            storm_brake: 5,
            never_act_on: vec![
                "systemd-*.service".to_string(),
                "dbus-broker.service".to_string(),
            ],
            bpf_loaders: Vec::new(),
            beacon: Beacon::default(),
            dns_tunnel: DnsTunnel::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Beacon {
    pub min_connects: u32,
    pub max_cov: f64,
    pub allow: Vec<String>,
    pub severity: String,
    pub action: String,
}

impl Default for Beacon {
    fn default() -> Beacon {
        Beacon {
            min_connects: 6,
            max_cov: 0.2,
            allow: vec![
                "9.9.9.9/32".to_string(),
                "149.112.112.112/32".to_string(),
                "1.1.1.1/32".to_string(),
            ],
            severity: "high".to_string(),
            action: "alert".to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DnsTunnel {
    pub label_len: u32,
    pub entropy: f64,
    pub unique_per_min: u32,
    pub severity: String,
    pub action: String,
}

impl Default for DnsTunnel {
    fn default() -> DnsTunnel {
        DnsTunnel {
            label_len: 20,
            entropy: 3.5,
            unique_per_min: 30,
            severity: "high".to_string(),
            action: "alert".to_string(),
        }
    }
}

/// Parse a standalone `[sentinel]`-section TOML (the rendered `sentinel.toml`,
/// whose keys are top-level).
pub fn parse(raw: &str) -> Result<SentinelConfig, String> {
    toml::from_str(raw).map_err(|e| e.message().to_string())
}

/// A detector action may only be alert, freeze or kill — never deny (§5.4).
fn detector_action_ok(a: &str) -> bool {
    matches!(a, "alert" | "freeze" | "kill")
}

/// Validate the documented ranges. Returns one message per problem.
pub fn validate(c: &SentinelConfig) -> Vec<String> {
    let mut e = Vec::new();

    match parse_duration_ms(&c.lockdown_after) {
        Ok(ms) if (2000..=30000).contains(&ms) => {}
        Ok(_) => e.push(format!("lockdown_after {:?} must be 2s..=30s", c.lockdown_after)),
        Err(m) => e.push(format!("lockdown_after: {m}")),
    }
    if c.storm_brake < 1 {
        e.push("storm_brake must be >= 1".to_string());
    }
    for u in &c.never_act_on {
        if Glob::new(u).is_err() {
            e.push(format!("never_act_on: glob {u:?} does not compile"));
        }
    }

    // beacon
    if !(0.0..=1.0).contains(&c.beacon.max_cov) {
        e.push(format!("beacon.max_cov {} must be 0.0..=1.0", c.beacon.max_cov));
    }
    if c.beacon.min_connects < 2 {
        e.push("beacon.min_connects must be >= 2".to_string());
    }
    for a in &c.beacon.allow {
        // a CIDR, or a `/`-prefixed executable glob
        let ok = a.parse::<ipnet::IpNet>().is_ok()
            || (a.starts_with('/') && Glob::new(a).is_ok());
        if !ok {
            e.push(format!("beacon.allow {a:?} must be a CIDR or a /-prefixed exe glob"));
        }
    }
    if parse_severity(&c.beacon.severity).is_none() {
        e.push(format!("beacon.severity {:?} is not a severity", c.beacon.severity));
    }
    if !detector_action_ok(&c.beacon.action) {
        e.push(format!("beacon.action {:?} must be alert|freeze|kill", c.beacon.action));
    }

    // dns_tunnel
    if c.dns_tunnel.label_len < 1 {
        e.push("dns_tunnel.label_len must be >= 1".to_string());
    }
    if !(0.0..=8.0).contains(&c.dns_tunnel.entropy) {
        e.push(format!("dns_tunnel.entropy {} must be 0.0..=8.0", c.dns_tunnel.entropy));
    }
    if c.dns_tunnel.unique_per_min < 1 {
        e.push("dns_tunnel.unique_per_min must be >= 1".to_string());
    }
    if parse_severity(&c.dns_tunnel.severity).is_none() {
        e.push(format!("dns_tunnel.severity {:?} is not a severity", c.dns_tunnel.severity));
    }
    if !detector_action_ok(&c.dns_tunnel.action) {
        e.push(format!("dns_tunnel.action {:?} must be alert|freeze|kill", c.dns_tunnel.action));
    }

    e
}
