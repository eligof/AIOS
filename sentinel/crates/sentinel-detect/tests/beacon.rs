use sentinel_detect::beacon::{Beacon, BeaconConfig};

fn cfg() -> BeaconConfig {
    BeaconConfig {
        min_connects: 6,
        max_cov: 0.2,
        window_ms: 3_600_000,
        refire_ms: 3_600_000,
        max_keys: 1024,
    }
}

#[test]
fn perfectly_periodic_traffic_fires() {
    let mut b = Beacon::new(cfg());
    let mut hit = None;
    for i in 0..6u64 {
        hit = b.observe("/tmp/implant", "203.0.113.5", 443, i * 100_000);
    }
    let h = hit.expect("fires on the 6th periodic connect");
    assert_eq!(h.dest, "203.0.113.5");
    assert!(h.cov <= 0.2);
    assert_eq!(h.count, 6);
}

#[test]
fn low_jitter_still_fires() {
    let mut b = Beacon::new(cfg());
    let times = [0u64, 100_000, 205_000, 300_000, 402_000, 498_000];
    let mut hit = None;
    for t in times {
        hit = b.observe("/tmp/implant", "203.0.113.5", 443, t);
    }
    assert!(hit.is_some(), "about 5% jitter is still periodic");
}

#[test]
fn irregular_traffic_does_not_fire() {
    let mut b = Beacon::new(cfg());
    let times = [0u64, 5_000, 400_000, 410_000, 900_000, 905_000];
    let mut hit = None;
    for t in times {
        hit = b.observe("/usr/bin/curl", "203.0.113.9", 443, t);
    }
    assert!(hit.is_none());
}

#[test]
fn too_few_connects_does_not_fire() {
    let mut b = Beacon::new(cfg());
    for i in 0..5u64 {
        assert!(b
            .observe("/tmp/x", "203.0.113.5", 443, i * 100_000)
            .is_none());
    }
}

#[test]
fn a_key_does_not_refire_within_the_hour() {
    let mut b = Beacon::new(cfg());
    for i in 0..6u64 {
        b.observe("/tmp/x", "203.0.113.5", 443, i * 100_000);
    }
    // another periodic connect shortly after: no second alert
    assert!(b.observe("/tmp/x", "203.0.113.5", 443, 600_000).is_none());
}
