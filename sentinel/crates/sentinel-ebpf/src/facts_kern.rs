use crate::shim::{self, TaskCore};
use aya_ebpf::helpers::bpf_ktime_get_ns;
use sentinel_common::facts::*;
use crate::maps::{CIDRS, PORTS, UID_LITERALS};
use sentinel_common::rule::{MAX_CIDRS, MAX_PORT_SETS, MAX_UID_LITERALS};
use sentinel_common::wire::{CidrEntry, RawEvent};

/// Fill the common header from the current task; returns the task core for reuse.
pub fn fill_header(ev: *mut RawEvent, kind: u8) -> Option<TaskCore> {
    let c = unsafe { shim::current_core()? };
    unsafe {
        (*ev).hdr.kind = kind;
        (*ev).hdr.kverdict = 0;
        (*ev).hdr._pad0 = [0; 2];
        (*ev).hdr.matched_rule = -1;
        (*ev).hdr.pid = c.pid;
        (*ev).hdr.tid = c.tid;
        (*ev).hdr.ppid = c.ppid;
        (*ev).hdr.uid = c.uid;
        (*ev).hdr.euid = c.euid;
        (*ev).hdr._pad1 = 0;
        (*ev).hdr.cgroup_id = c.cgroup_id;
        (*ev).hdr.ts_ns = bpf_ktime_get_ns();
        (*ev).hdr.facts = [0; NGROUPS];
        (*ev).hdr._pad2 = 0;
    }
    Some(c)
}

/// uid summary facts (§5.2): user (>=1000) / system (<1000). Also ORs literal-uid slots.
pub fn set_uid_facts(ev: *mut RawEvent, uid: u32) {
    unsafe {
        if uid >= 1000 {
            (*ev).hdr.facts[G_UID] |= U_USER;
        } else {
            (*ev).hdr.facts[G_UID] |= U_SYSTEM;
        }
    }
    set_uid_literal_facts(ev, uid);
}

/// Family-aware prefix match of `addr` against a CIDR entry.
fn cidr_match(addr: &[u8; 16], e: &CidrEntry) -> bool {
    let prefix = e.prefix as usize;
    if prefix > 128 {
        return false;
    }
    let full = prefix / 8;
    let rem = (prefix % 8) as u32;
    let mut i = 0usize;
    while i < 16 {
        if i < full {
            if addr[i] != e.addr[i] {
                return false;
            }
        } else if i == full && rem != 0 {
            let mask = 0xffu8 << (8 - rem);
            if (addr[i] ^ e.addr[i]) & mask != 0 {
                return false;
            }
        }
        i += 1;
    }
    true
}

/// Destination CIDR facts: OR `slot_bit` for every used CIDR containing the address.
pub fn set_dest_facts(ev: *mut RawEvent, a: &shim::SockAddr) {
    let mut i: u32 = 0;
    while i < MAX_CIDRS as u32 {
        if let Some(e) = CIDRS.get(i) {
            if e.used != 0 && e.family as u16 == a.family && cidr_match(&a.addr, e) {
                unsafe {
                    (*ev).hdr.facts[G_DEST] |= slot_bit((e.slot & 31) as usize);
                }
            }
        }
        i += 1;
    }
}

/// Destination port facts: OR `slot_bit` for every used range containing the port.
pub fn set_port_facts(ev: *mut RawEvent, port: u16) {
    let mut i: u32 = 0;
    while i < MAX_PORT_SETS as u32 {
        if let Some(r) = PORTS.get(i) {
            if r.used != 0 && port >= r.lo && port <= r.hi {
                unsafe {
                    (*ev).hdr.facts[G_PORT] |= slot_bit((r.slot & 31) as usize);
                }
            }
        }
        i += 1;
    }
}

/// Literal-uid facts: OR `uid_literal_bit(i)` for each table slot equal to `uid`.
/// An unused slot holds `u32::MAX` (loader fills the whole array).
pub fn set_uid_literal_facts(ev: *mut RawEvent, uid: u32) {
    let mut i: u32 = 0;
    while i < MAX_UID_LITERALS as u32 {
        if let Some(v) = UID_LITERALS.get(i) {
            if *v == uid && uid != u32::MAX {
                unsafe {
                    (*ev).hdr.facts[G_UID] |= uid_literal_bit(i as usize);
                }
            }
        }
        i += 1;
    }
}

fn name_ends_with(name: &[u8; 64], len: usize, c: u8) -> bool {
    len > 0 && len <= 64 && name[(len - 1) & 63] == c
}

fn starts_with(name: &[u8; 64], pre: &[u8]) -> bool {
    let mut i = 0;
    while i < pre.len() {
        if name[i] != pre[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Device class of a char device by major / dentry name: (OpenPayload.dev_class, D_* bit).
pub fn device_class(major: u32, name: &[u8; 64], len: usize) -> Option<(u8, u32)> {
    match major {
        81 => Some((1, D_CAMERA)),
        13 => Some((3, D_INPUT)),
        116 if name_ends_with(name, len, b'c') => Some((2, D_MIC)),
        _ if starts_with(name, b"uinput") => Some((4, D_UINPUT)),
        _ if starts_with(name, b"hidraw") => Some((5, D_HIDRAW)),
        _ => None,
    }
}
