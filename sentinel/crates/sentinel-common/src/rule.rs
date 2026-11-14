//! The compiled kernel rule and the shared evaluator.

use crate::event::{Action, EventKind, Mode};
use crate::facts::{Facts, NGROUPS};

/// Kernel-synchronous evaluation bounds the tables (§5.3).
pub const MAX_RULES: usize = 64;
pub const MAX_UID_LITERALS: usize = 30;
pub const MAX_MOUNTS: usize = 32;
pub const MAX_CIDRS: usize = 32;
pub const MAX_PORT_SETS: usize = 32;

/// A compiled kernel rule. `#[repr(C)]` so it sits in a BPF array map unchanged.
///
/// Masks are over the `Facts` layout (`facts.rs`):
/// - `all`: every set bit must be present (AND).
/// - `any`: per group, if non-zero at least one bit must be present (OR).
/// - `ex_any`: if facts overlap any set bit the rule is suppressed — this is
///   `except`, which §5.1 defines as OR across predicates and OR within a list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct KRule {
    /// `EventKind` discriminant.
    pub on: u8,
    /// `Action` discriminant.
    pub action: u8,
    /// `Mode` discriminant.
    pub mode: u8,
    pub _pad: u8,
    /// Index of the source rule, so an alert can name which rule matched.
    pub index: u32,
    pub all: [u32; NGROUPS],
    pub any: [u32; NGROUPS],
    pub ex_any: [u32; NGROUPS],
}

impl KRule {
    pub fn empty(on: EventKind, action: Action, mode: Mode, index: u32) -> KRule {
        KRule {
            on: on as u8,
            action: action as u8,
            mode: mode as u8,
            _pad: 0,
            index,
            all: [0; NGROUPS],
            any: [0; NGROUPS],
            ex_any: [0; NGROUPS],
        }
    }
}

/// Match `facts` against one compiled rule. The caller has already selected
/// rules whose `on` equals the event kind.
#[inline]
pub fn eval(rule: &KRule, facts: &Facts) -> bool {
    let f = &facts.0;
    let mut g = 0;
    while g < NGROUPS {
        // every required bit present
        if rule.all[g] & f[g] != rule.all[g] {
            return false;
        }
        // group OR, when constrained
        if rule.any[g] != 0 && rule.any[g] & f[g] == 0 {
            return false;
        }
        g += 1;
    }
    // except: any overlap suppresses
    let mut g = 0;
    while g < NGROUPS {
        if rule.ex_any[g] & f[g] != 0 {
            return false;
        }
        g += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::*;

    fn exec_rule() -> KRule {
        KRule::empty(EventKind::Exec, Action::Deny, Mode::Enforce, 0)
    }

    #[test]
    fn empty_rule_matches_any_facts_of_its_kind() {
        // No constraints => matches (e.g. the `module-load` / `any = true` case).
        let r = exec_rule();
        assert!(eval(&r, &Facts::new()));
    }

    #[test]
    fn all_requires_every_bit() {
        let mut r = exec_rule();
        r.all[G_FLAGS] = F_MEMFD;
        let mut f = Facts::new();
        assert!(!eval(&r, &f)); // memfd not set
        f.set(G_FLAGS, F_MEMFD);
        assert!(eval(&r, &f));
    }

    #[test]
    fn any_requires_one_of_group() {
        // exe_on = [shm, tmp] => MOUNT group any = slot0|slot1.
        let mut r = exec_rule();
        r.any[G_MOUNT] = slot_bit(0) | slot_bit(1);
        let mut f = Facts::new();
        assert!(!eval(&r, &f)); // on neither mount
        f.set(G_MOUNT, slot_bit(1));
        assert!(eval(&r, &f)); // on tmp
    }

    #[test]
    fn all_and_any_combine_as_and() {
        // uid = "user" AND dest in {cidr0, cidr1}
        let mut r = KRule::empty(EventKind::Connect, Action::Alert, Mode::Enforce, 1);
        r.all[G_UID] = U_USER;
        r.any[G_DEST] = slot_bit(0) | slot_bit(1);
        let mut f = Facts::new();
        f.set(G_UID, U_USER);
        assert!(!eval(&r, &f)); // dest group empty
        f.set(G_DEST, slot_bit(0));
        assert!(eval(&r, &f));
        // drop the uid bit: the AND fails even with dest present
        f.0[G_UID] = 0;
        assert!(!eval(&r, &f));
    }

    #[test]
    fn except_suppresses_on_any_overlap() {
        // match uid=system, except uid literal slot 3 (e.g. uid 0)
        let mut r = exec_rule();
        r.all[G_UID] = U_SYSTEM;
        r.ex_any[G_UID] = uid_literal_bit(3);
        let mut f = Facts::new();
        f.set(G_UID, U_SYSTEM);
        assert!(eval(&r, &f)); // no except bit => fires
        f.set(G_UID, uid_literal_bit(3));
        assert!(!eval(&r, &f)); // except holds => suppressed
    }
}
