//! The manifest's `[sentinel]` section (spec §11.1, amendment §17.9).

use serde::Deserialize;

/// The `[sentinel]` section. Absent from a manifest means
/// [`Sentinel::default`] — Sentinel enabled with the §11.1 defaults.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sentinel {
    #[serde(flatten)]
    pub config: sentinel_rules::config::SentinelConfig,
}

impl Sentinel {
    /// Problems with the section, in the shape `aios plan` prints. Empty is valid.
    pub fn problems(&self) -> Vec<String> {
        sentinel_rules::config::validate(&self.config)
            .into_iter()
            .map(|p| format!("[sentinel]: {p}"))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absent_section_means_the_documented_defaults() {
        let s = Sentinel::default();
        assert!(s.config.enable);
        assert_eq!(s.config.lockdown_after, "5s");
        assert_eq!(s.config.storm_brake, 5);
        assert_eq!(s.config.rules, "sentinel/rules");
        assert!(s.problems().is_empty());
    }

    #[test]
    fn the_section_parses_the_spec_example() {
        let raw = r#"
enable         = true
rules          = "sentinel/rules"
lockdown_after = "5s"
storm_brake    = 5
never_act_on   = ["systemd-*.service", "dbus-broker.service"]
bpf_loaders    = []

[beacon]
min_connects = 6
max_cov      = 0.2
allow        = ["9.9.9.9/32"]

[dns_tunnel]
label_len      = 20
entropy        = 3.5
unique_per_min = 30
"#;
        let s: Sentinel = toml::from_str(raw).expect("parses");
        assert_eq!(s.config.beacon.min_connects, 6);
        assert_eq!(s.config.dns_tunnel.label_len, 20);
        assert!(s.problems().is_empty());
    }

    #[test]
    fn an_unknown_key_is_rejected() {
        let e = toml::from_str::<Sentinel>("enabel = true\n").expect_err("typo rejected");
        assert!(
            e.to_string().contains("enabel") || e.to_string().contains("unknown"),
            "the error names the typo: {e}"
        );
    }

    #[test]
    fn a_bad_duration_is_a_problem_not_a_parse_error() {
        let s: Sentinel = toml::from_str("lockdown_after = \"5 fortnights\"\n").expect("parses");
        let p = s.problems();
        assert_eq!(p.len(), 1, "{p:?}");
        assert!(p[0].starts_with("[sentinel]: "), "{p:?}");
        assert!(p[0].contains("lockdown_after"), "{p:?}");
    }
}
