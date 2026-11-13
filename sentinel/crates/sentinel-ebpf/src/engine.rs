use crate::maps::{CONFIG, HEARTBEAT, LOCKDOWN_COUNTS};
use aya_ebpf::helpers::bpf_ktime_get_ns;

/// §8.3: lockdown is on when the heartbeat is stale by more than
/// `lockdown_after_ns`. Before the first heartbeat (0) there is no lockdown.
pub fn lockdown_active() -> bool {
    let hb = HEARTBEAT.get(0).copied().unwrap_or(0);
    if hb == 0 {
        return false;
    }
    let after = CONFIG
        .get(0)
        .map(|c| c.lockdown_after_ns)
        .unwrap_or(5_000_000_000);
    let now = unsafe { bpf_ktime_get_ns() };
    now.saturating_sub(hb) > after
}

#[allow(dead_code)]
pub fn count_lockdown(hook: u32) {
    if let Some(p) = LOCKDOWN_COUNTS.get_ptr_mut(hook) {
        unsafe {
            *p += 1;
        }
    }
}
