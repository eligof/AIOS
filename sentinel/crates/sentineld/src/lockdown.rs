//! Reading what the kernel did while no daemon was running (spec §8.3).

use crate::kernel::{Kernel, NHOOKS};

/// What each `LOCKDOWN_COUNTS` slot means, in slot order.
///
/// Read off the kernel side rather than assumed, because a wrong label here
/// would misreport which hook did the denying:
///
/// - 0 `socket_connect` — `count_lockdown(0)` in `observe.rs`'s connect hook,
///   which is also the slot `deny_quarantined` uses from there.
/// - 1 `exec` — `count_lockdown(1)` in the `bprm_check_security` hook, the
///   one lockdown's "exec only from the read-only /usr" rule denies.
/// - 2 `socket_sendmsg` — `deny_quarantined(2)` in `guard.rs`.
/// - 7 the probe slot the S2 heartbeat self-test writes from `main.rs`.
///
/// Slots 3 to 6 are allocated in the map but no program writes them yet, so
/// they are named for the slot rather than for a hook: a count appearing in
/// one is then visibly unattributed instead of silently blamed on the wrong
/// hook. A new enforcement hook must add its name here.
pub const HOOK_NAMES: [&str; NHOOKS] = [
    "connect", "exec", "sendmsg", "slot3", "slot4", "slot5", "slot6", "probe",
];

/// A gap during which the kernel side was locked down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gap {
    pub gap_ms: u64,
    pub counts: [u64; NHOOKS],
}

impl Gap {
    pub fn total(&self) -> u64 {
        self.counts.iter().sum()
    }

    /// The critical alert's message (spec §8.3).
    pub fn message(&self) -> String {
        let mut per_hook: Vec<String> = HOOK_NAMES
            .iter()
            .zip(self.counts.iter())
            .filter(|(_, c)| **c > 0)
            .map(|(n, c)| format!("{n} {c}"))
            .collect();
        if per_hook.is_empty() {
            per_hook.push("no denials".to_string());
        }
        format!(
            "lockdown was active for {:.1} s while no daemon was running ({})",
            self.gap_ms as f64 / 1000.0,
            per_hook.join(", ")
        )
    }

    pub fn event(&self) -> serde_json::Value {
        let counts: serde_json::Map<String, serde_json::Value> = HOOK_NAMES
            .iter()
            .zip(self.counts.iter())
            .map(|(n, c)| ((*n).to_string(), (*c).into()))
            .collect();
        serde_json::json!({
            "on": "lockdown",
            "gapMs": self.gap_ms,
            "total": self.total(),
            "counts": counts,
        })
    }
}

/// Read the heartbeat and the counters. Returns a gap only when a previous
/// instance left a stale heartbeat — a fresh boot has `HEARTBEAT[0] == 0` and
/// never locked anything down.
///
/// Call this **before** writing the first heartbeat of this instance.
pub fn report(k: &mut dyn Kernel, lockdown_after_ns: u64) -> Option<Gap> {
    let beat = k.heartbeat_value().ok()?;
    if beat == 0 {
        return None;
    }
    let now = k.monotonic_ns();
    let gap_ns = now.saturating_sub(beat);
    if gap_ns <= lockdown_after_ns {
        return None;
    }
    Some(Gap {
        gap_ms: gap_ns / 1_000_000,
        counts: k.lockdown_counts().ok()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::FakeKernel;

    #[test]
    fn a_fresh_boot_reports_nothing() {
        let mut k = FakeKernel::default();
        // HEARTBEAT[0] == 0 means nothing was ever loaded (spec §8.3).
        k.advance_ms(10_000);
        assert!(report(&mut k, 5_000_000_000).is_none());
    }

    #[test]
    fn a_restart_inside_the_threshold_reports_nothing() {
        let mut k = FakeKernel::default();
        k.advance_ms(10_000);
        k.heartbeat(9_000_000_000).unwrap();
        assert!(
            report(&mut k, 5_000_000_000).is_none(),
            "a 1 s gap is under the 5 s threshold"
        );
    }

    #[test]
    fn a_stale_heartbeat_reports_the_gap_and_the_counts() {
        let mut k = FakeKernel::default();
        k.advance_ms(30_000);
        k.heartbeat(10_000_000_000).unwrap();
        k.lockdown = [4, 0, 0, 0, 0, 0, 0, 1];

        let g = report(&mut k, 5_000_000_000).expect("a 20 s gap is reported");
        assert_eq!(g.gap_ms, 20_000);
        assert_eq!(g.counts[0], 4);
        assert_eq!(g.counts[7], 1);
        assert_eq!(g.total(), 5);
    }

    #[test]
    fn a_gap_with_no_denials_is_still_reported() {
        let mut k = FakeKernel::default();
        k.advance_ms(30_000);
        k.heartbeat(10_000_000_000).unwrap();
        let g = report(&mut k, 5_000_000_000).expect("the gap itself is the news");
        assert_eq!(g.total(), 0);
        assert!(g.message().contains("no denials"), "{}", g.message());
    }

    #[test]
    fn the_message_names_the_gap_and_the_busiest_hooks() {
        let g = Gap {
            gap_ms: 20_000,
            counts: [4, 0, 0, 0, 0, 0, 0, 1],
        };
        let m = g.message();
        assert!(m.contains("20.0 s"), "message was {m}");
        // Slot 0 is the connect hook and slot 7 the probe: the labels follow
        // what the kernel programs actually write.
        assert!(m.contains("connect 4"), "{m}");
        assert!(m.contains("probe 1"), "{m}");
        assert!(!m.contains("exec"), "slot 0 is not the exec hook: {m}");
    }

    #[test]
    fn the_event_names_every_slot() {
        let g = Gap {
            gap_ms: 1_000,
            counts: [1, 2, 0, 0, 0, 0, 0, 0],
        };
        let e = g.event();
        assert_eq!(e["counts"]["connect"], 1);
        assert_eq!(e["counts"]["exec"], 2);
        assert_eq!(e["total"], 3);
        assert_eq!(e["gapMs"], 1_000);
    }
}
