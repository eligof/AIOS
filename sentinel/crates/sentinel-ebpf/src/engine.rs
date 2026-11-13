use crate::maps::{CONFIG, HEARTBEAT, LOCKDOWN_COUNTS, RULES, RULE_COUNT};
use sentinel_common::event::{Action, Mode};
use sentinel_common::facts::Facts;
use sentinel_common::rule::{eval as rule_match, MAX_RULES};
use aya_ebpf::helpers::{bpf_ktime_get_ns, bpf_loop};

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

pub struct Verdict {
    pub matched: i32,
    pub deny: bool,
    pub would_deny: bool,
}

struct WalkCtx {
    kind: u8,
    facts: Facts,
    v: Verdict,
}

/// `bpf_loop` callback: one rule. Returns 0 to continue. The verifier checks
/// this body once (not once per unrolled iteration), which keeps the 64-rule
/// walk far inside the instruction budget.
unsafe extern "C" fn walk_one(i: u64, ctx: *mut core::ffi::c_void) -> i64 {
    let c = &mut *(ctx as *mut WalkCtx);
    if let Some(r) = RULES.get(i as u32) {
        if r.on == c.kind && rule_match(r, &c.facts) {
            if c.v.matched < 0 {
                c.v.matched = i as i32;
            }
            if r.action == Action::Deny as u8 {
                if r.mode == Mode::Enforce as u8 {
                    if !c.v.deny {
                        c.v.matched = i as i32;
                    }
                    c.v.deny = true;
                } else {
                    c.v.would_deny = true;
                }
            }
        }
    }
    0
}

/// Walk the compiled kernel rules whose `on` equals `kind`; the first
/// Deny+Enforce match wins the deny and names the rule, else the first match
/// names it. Bounded by MAX_RULES (and `bpf_loop`'s own cap).
pub fn evaluate(kind: u8, facts: &Facts) -> Verdict {
    let count = RULE_COUNT.get(0).copied().unwrap_or(0);
    let n = if count > MAX_RULES as u32 {
        MAX_RULES as u32
    } else {
        count
    };
    let mut c = WalkCtx {
        kind,
        facts: *facts,
        v: Verdict {
            matched: -1,
            deny: false,
            would_deny: false,
        },
    };
    unsafe {
        bpf_loop(
            n,
            walk_one as *mut core::ffi::c_void,
            &mut c as *mut WalkCtx as *mut core::ffi::c_void,
            0,
        );
    }
    c.v
}
