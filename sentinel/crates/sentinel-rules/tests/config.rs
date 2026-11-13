use sentinel_rules::config::{parse, validate, Beacon, SentinelConfig};

#[test]
fn empty_config_is_the_documented_defaults() {
    let c = SentinelConfig::default();
    assert!(c.enable);
    assert_eq!(c.rules, "sentinel/rules");
    assert_eq!(c.lockdown_after, "5s");
    assert_eq!(c.storm_brake, 5);
    assert_eq!(c.beacon.min_connects, 6);
    assert_eq!(c.beacon.max_cov, 0.2);
    assert_eq!(c.dns_tunnel.label_len, 20);
    assert_eq!(c.dns_tunnel.entropy, 3.5);
    assert!(validate(&c).is_empty());
}

#[test]
fn a_full_config_parses_and_validates() {
    let raw = r#"
enable = true
rules = "sentinel/rules"
lockdown_after = "8s"
storm_brake = 3
never_act_on = ["systemd-*.service"]
bpf_loaders = ["/usr/bin/bpftool"]

[beacon]
min_connects = 10
max_cov = 0.1
allow = ["9.9.9.9/32", "/usr/bin/chronyd"]
action = "freeze"

[dns_tunnel]
label_len = 24
entropy = 4.0
unique_per_min = 50
"#;
    let c = parse(raw).expect("parses");
    assert_eq!(c.lockdown_after, "8s");
    assert_eq!(c.beacon.action, "freeze");
    assert!(validate(&c).is_empty());
}

#[test]
fn out_of_range_values_are_rejected() {
    let c = SentinelConfig {
        lockdown_after: "60s".into(), // > 30s
        ..Default::default()
    };
    assert!(validate(&c).iter().any(|m| m.contains("lockdown_after")));

    let c = SentinelConfig {
        beacon: Beacon {
            max_cov: 2.0,
            ..Default::default()
        }, // > 1.0
        ..Default::default()
    };
    assert!(validate(&c).iter().any(|m| m.contains("max_cov")));

    let c = SentinelConfig {
        beacon: Beacon {
            allow: vec!["not a cidr or /glob".into()],
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(validate(&c).iter().any(|m| m.contains("allow")));

    let c = SentinelConfig {
        // detectors never deny (§5.4)
        beacon: Beacon {
            action: "deny".into(),
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(validate(&c).iter().any(|m| m.contains("action")));
}
