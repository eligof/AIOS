//! C2 beacon detector: periodic connects to the same destination (§5.4).
//! Pure — the caller supplies the clock and has already dropped allow-listed
//! destinations and executables.

use std::collections::{HashMap, VecDeque};

#[derive(Debug, Clone)]
pub struct BeaconConfig {
    pub min_connects: u32,
    pub max_cov: f64,
    /// Sliding window for the interval statistics (default 1h).
    pub window_ms: u64,
    /// Minimum gap between two alerts for the same key (default 1h).
    pub refire_ms: u64,
    /// Cap on tracked keys; the least-recently-seen is evicted past it.
    pub max_keys: usize,
}

impl Default for BeaconConfig {
    fn default() -> BeaconConfig {
        BeaconConfig {
            min_connects: 6,
            max_cov: 0.2,
            window_ms: 3_600_000,
            refire_ms: 3_600_000,
            max_keys: 4096,
        }
    }
}

/// A fired beacon detection.
#[derive(Debug, Clone, PartialEq)]
pub struct BeaconHit {
    pub exe: String,
    pub dest: String,
    pub port: u16,
    pub count: u32,
    pub cov: f64,
}

#[derive(Default)]
struct KeyState {
    times: VecDeque<u64>,
    last_seen: u64,
    last_fired: Option<u64>,
}

pub struct Beacon {
    cfg: BeaconConfig,
    keys: HashMap<(String, String, u16), KeyState>,
}

impl Beacon {
    pub fn new(cfg: BeaconConfig) -> Beacon {
        Beacon {
            cfg,
            keys: HashMap::new(),
        }
    }

    /// Record one connect. Returns a hit when the key just became a beacon.
    pub fn observe(&mut self, exe: &str, dest: &str, port: u16, now_ms: u64) -> Option<BeaconHit> {
        self.evict_if_needed(now_ms);
        let cfg = self.cfg.clone();
        let st = self
            .keys
            .entry((exe.to_string(), dest.to_string(), port))
            .or_default();
        st.last_seen = now_ms;
        st.times.push_back(now_ms);
        while let Some(&front) = st.times.front() {
            if now_ms.saturating_sub(front) > cfg.window_ms {
                st.times.pop_front();
            } else {
                break;
            }
        }

        if (st.times.len() as u32) < cfg.min_connects {
            return None;
        }
        let cov = coefficient_of_variation(st.times.make_contiguous());
        if cov > cfg.max_cov {
            return None;
        }
        if let Some(last) = st.last_fired {
            if now_ms.saturating_sub(last) < cfg.refire_ms {
                return None;
            }
        }
        st.last_fired = Some(now_ms);
        Some(BeaconHit {
            exe: exe.to_string(),
            dest: dest.to_string(),
            port,
            count: st.times.len() as u32,
            cov,
        })
    }

    fn evict_if_needed(&mut self, _now_ms: u64) {
        if self.keys.len() < self.cfg.max_keys {
            return;
        }
        if let Some(k) = self
            .keys
            .iter()
            .min_by_key(|(_, s)| s.last_seen)
            .map(|(k, _)| k.clone())
        {
            self.keys.remove(&k);
        }
    }
}

/// Coefficient of variation (stddev / mean) of the gaps between sorted times.
/// Fewer than two times, or a zero mean, counts as perfectly periodic (0.0).
fn coefficient_of_variation(times: &[u64]) -> f64 {
    if times.len() < 2 {
        return 0.0;
    }
    let intervals: Vec<f64> = times.windows(2).map(|w| (w[1] - w[0]) as f64).collect();
    let n = intervals.len() as f64;
    let mean = intervals.iter().sum::<f64>() / n;
    if mean == 0.0 {
        return 0.0;
    }
    let var = intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
    var.sqrt() / mean
}
