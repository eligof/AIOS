//! A pure sliding-window counter. The caller passes monotonic milliseconds.

use std::collections::{HashMap, VecDeque};

#[derive(Debug, Clone)]
pub struct WindowState {
    count: u32,
    within_ms: u64,
    keys: HashMap<String, VecDeque<u64>>,
}

impl WindowState {
    pub fn new(count: u32, within_ms: u64) -> WindowState {
        WindowState { count, within_ms, keys: HashMap::new() }
    }

    /// Record one matching event for `key` at `now_ms`. Returns true when at
    /// least `count` events for that key fall within the last `within_ms`.
    pub fn record(&mut self, key: &str, now_ms: u64) -> bool {
        let dq = self.keys.entry(key.to_string()).or_default();
        dq.push_back(now_ms);
        while let Some(&front) = dq.front() {
            if now_ms.saturating_sub(front) > self.within_ms {
                dq.pop_front();
            } else {
                break;
            }
        }
        dq.len() as u32 >= self.count
    }
}
