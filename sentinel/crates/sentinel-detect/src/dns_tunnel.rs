//! DNS-tunnel detector: high-entropy labels or a high rate of unique
//! subdomains under one registered domain (§5.4). Pure; clock passed in.

use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug, Clone)]
pub struct DnsTunnelConfig {
    pub label_len: u32,
    pub entropy: f64,
    pub unique_per_min: u32,
    pub refire_ms: u64,
    pub max_keys: usize,
}

impl Default for DnsTunnelConfig {
    fn default() -> DnsTunnelConfig {
        DnsTunnelConfig {
            label_len: 20,
            entropy: 3.5,
            unique_per_min: 30,
            refire_ms: 3_600_000,
            max_keys: 4096,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum DnsReason {
    HighEntropy { label: String, bits: f64 },
    HighRate { unique: u32 },
}

#[derive(Debug, Clone, PartialEq)]
pub struct DnsHit {
    pub domain: String,
    pub reason: DnsReason,
}

#[derive(Default)]
struct DomainState {
    recent: VecDeque<(u64, String)>,
    last_seen: u64,
    last_fired: Option<u64>,
}

pub struct DnsTunnel {
    cfg: DnsTunnelConfig,
    domains: HashMap<String, DomainState>,
}

impl DnsTunnel {
    pub fn new(cfg: DnsTunnelConfig) -> DnsTunnel {
        DnsTunnel {
            cfg,
            domains: HashMap::new(),
        }
    }

    /// Record one resolved query name. Returns a hit when the domain just
    /// crossed a threshold.
    pub fn observe(&mut self, qname: &str, now_ms: u64) -> Option<DnsHit> {
        let qname = qname.trim_end_matches('.').to_ascii_lowercase();
        let registered = psl::domain_str(&qname)?.to_string();
        // the labels to the left of the registered domain
        let sub = qname
            .strip_suffix(&registered)
            .map(|s| s.trim_end_matches('.'))
            .unwrap_or("");

        self.evict_if_needed();
        let cfg = self.cfg.clone();
        let st = self.domains.entry(registered.clone()).or_default();
        st.last_seen = now_ms;

        // rate: distinct subdomains in the last minute
        if !sub.is_empty() {
            st.recent.push_back((now_ms, sub.to_string()));
        }
        while let Some(&(t, _)) = st.recent.front() {
            if now_ms.saturating_sub(t) > 60_000 {
                st.recent.pop_front();
            } else {
                break;
            }
        }

        if Self::refiring(st, now_ms, cfg.refire_ms) {
            return None;
        }

        // entropy trigger on any long label
        for label in sub.split('.').filter(|l| !l.is_empty()) {
            if label.len() as u32 >= cfg.label_len {
                let bits = shannon_entropy(label);
                if bits > cfg.entropy {
                    st.last_fired = Some(now_ms);
                    return Some(DnsHit {
                        domain: registered,
                        reason: DnsReason::HighEntropy {
                            label: label.to_string(),
                            bits,
                        },
                    });
                }
            }
        }

        // rate trigger
        let unique: HashSet<&str> = st.recent.iter().map(|(_, s)| s.as_str()).collect();
        if unique.len() as u32 > cfg.unique_per_min {
            st.last_fired = Some(now_ms);
            return Some(DnsHit {
                domain: registered,
                reason: DnsReason::HighRate {
                    unique: unique.len() as u32,
                },
            });
        }

        None
    }

    fn refiring(st: &DomainState, now_ms: u64, refire_ms: u64) -> bool {
        matches!(st.last_fired, Some(last) if now_ms.saturating_sub(last) < refire_ms)
    }

    fn evict_if_needed(&mut self) {
        if self.domains.len() < self.cfg.max_keys {
            return;
        }
        if let Some(k) = self
            .domains
            .iter()
            .min_by_key(|(_, s)| s.last_seen)
            .map(|(k, _)| k.clone())
        {
            self.domains.remove(&k);
        }
    }
}

/// Shannon entropy in bits per character.
fn shannon_entropy(s: &str) -> f64 {
    let mut counts: HashMap<char, usize> = HashMap::new();
    let mut n = 0usize;
    for c in s.chars() {
        *counts.entry(c).or_default() += 1;
        n += 1;
    }
    if n == 0 {
        return 0.0;
    }
    let n = n as f64;
    -counts
        .values()
        .map(|&c| {
            let p = c as f64 / n;
            p * p.log2()
        })
        .sum::<f64>()
}
