//! The per-event fact vector and its bit layout.
//!
//! A `Facts` is `[u32; NGROUPS]`: one group per `u32`, one predicate term per
//! bit. A compiled rule (`KRule`) holds masks over the same layout, and
//! `eval` (see `rule.rs`) is the only matcher. Kernel and user space must keep
//! these constants identical.

/// Number of fact groups.
pub const NGROUPS: usize = 7;

pub const G_FLAGS: usize = 0;
pub const G_UID: usize = 1;
pub const G_MOUNT: usize = 2;
pub const G_DEST: usize = 3;
pub const G_PORT: usize = 4;
pub const G_DEVICE: usize = 5;
pub const G_PTRACE: usize = 6;

// FLAGS (G_FLAGS) — exec and listen flags from §4.
pub const F_MEMFD: u32 = 1 << 0;
pub const F_DELETED: u32 = 1 << 1;
pub const F_OUTSIDE_USR: u32 = 1 << 2;
pub const F_STDIO_SOCKET: u32 = 1 << 3;
pub const F_ENV_LD: u32 = 1 << 4;
pub const F_LISTEN_NON_LOOPBACK: u32 = 1 << 5;

// UID (G_UID).
pub const U_USER: u32 = 1 << 0;
pub const U_SYSTEM: u32 = 1 << 1;
/// First bit available for a literal-uid table slot.
pub const U_LITERAL_SHIFT: u32 = 2;

// DEVICE (G_DEVICE) — device classes from §4/§5.2.
pub const D_CAMERA: u32 = 1 << 0;
pub const D_MIC: u32 = 1 << 1;
pub const D_INPUT: u32 = 1 << 2;
pub const D_UINPUT: u32 = 1 << 3;
pub const D_HIDRAW: u32 = 1 << 4;

// PTRACE (G_PTRACE) — ptrace_target from §5.2. `P_ANY` is set on every ptrace
// event so a rule with `ptrace_target = "any"` matches all of them.
pub const P_OTHER_UID: u32 = 1 << 0;
pub const P_NON_DESCENDANT: u32 = 1 << 1;
pub const P_ANY: u32 = 1 << 2;

/// The table-slot bit for literal-uid slot `i` (0-based). Slots 0..30 map to
/// bits 2..=31 of the UID group.
#[inline]
pub fn uid_literal_bit(i: usize) -> u32 {
    1u32 << (U_LITERAL_SHIFT + i as u32)
}

/// The table-slot bit for mount/CIDR/port-set slot `i` (0-based, 0..32).
#[inline]
pub fn slot_bit(i: usize) -> u32 {
    1u32 << i as u32
}

/// A per-event fact vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Facts(pub [u32; NGROUPS]);

impl Facts {
    #[inline]
    pub fn new() -> Facts {
        Facts([0; NGROUPS])
    }

    #[inline]
    pub fn set(&mut self, group: usize, bit: u32) {
        self.0[group] |= bit;
    }

    #[inline]
    pub fn has(&self, group: usize, bit: u32) -> bool {
        self.0[group] & bit == bit
    }
}

impl Default for Facts {
    fn default() -> Facts {
        Facts::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn facts_default_is_all_zero() {
        let f = Facts::new();
        assert_eq!(f.0, [0u32; NGROUPS]);
    }

    #[test]
    fn uid_literal_bit_is_in_range() {
        // bit 2 is the first literal slot; slot 29 is the last (30 slots).
        assert_eq!(uid_literal_bit(0), 1 << 2);
        assert_eq!(uid_literal_bit(29), 1 << 31);
    }

    #[test]
    fn set_and_test_a_flag() {
        let mut f = Facts::new();
        f.set(G_FLAGS, F_MEMFD);
        assert!(f.has(G_FLAGS, F_MEMFD));
        assert!(!f.has(G_FLAGS, F_DELETED));
    }

    #[test]
    fn uid_facts_set_summary_and_literal() {
        // uid 1000 is a "user" (>= 1000); its literal is table slot 3.
        let mut f = Facts::new();
        f.set(G_UID, U_USER);
        f.set(G_UID, uid_literal_bit(3));
        assert!(f.has(G_UID, U_USER));
        assert!(!f.has(G_UID, U_SYSTEM));
        assert!(f.has(G_UID, uid_literal_bit(3)));
    }
}
