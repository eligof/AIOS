use sentinel_detect::dns_tunnel::{DnsReason, DnsTunnel, DnsTunnelConfig};

fn cfg() -> DnsTunnelConfig {
    DnsTunnelConfig {
        label_len: 20,
        entropy: 3.5,
        unique_per_min: 30,
        refire_ms: 3_600_000,
        max_keys: 1024,
    }
}

#[test]
fn a_long_high_entropy_label_fires() {
    let mut d = DnsTunnel::new(cfg());
    // 32 hex-ish chars, high entropy, under evil.example
    let q = "a9f3c7e1b5d82604f1a7c3e9b2d6085f.evil.example";
    let hit = d.observe(q, 0).expect("high-entropy label fires");
    assert_eq!(hit.domain, "evil.example");
    assert!(matches!(hit.reason, DnsReason::HighEntropy { .. }));
}

#[test]
fn an_ordinary_name_does_not_fire() {
    let mut d = DnsTunnel::new(cfg());
    assert!(d.observe("www.wikipedia.org", 0).is_none());
    assert!(d.observe("mail.google.com", 1000).is_none());
}

#[test]
fn many_unique_subdomains_a_minute_fires() {
    let mut d = DnsTunnel::new(cfg());
    let mut hit = None;
    for i in 0..31u64 {
        // short labels (no entropy trigger), but many of them, same registered domain
        hit = d.observe(&format!("s{i}.tun.example"), i * 1_000);
    }
    let h = hit.expect("rate trigger");
    assert!(matches!(h.reason, DnsReason::HighRate { .. }));
    assert_eq!(h.domain, "tun.example");
}

#[test]
fn a_domain_does_not_refire_within_the_hour() {
    let mut d = DnsTunnel::new(cfg());
    let q = "a9f3c7e1b5d82604f1a7c3e9b2d6085f.evil.example";
    assert!(d.observe(q, 0).is_some());
    assert!(d
        .observe("b8e2d6f0a4c71593e0b6d2f8a1c5074e.evil.example", 1_000)
        .is_none());
}
