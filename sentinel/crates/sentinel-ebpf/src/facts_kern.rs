use crate::shim::{self, TaskCore};
use aya_ebpf::helpers::bpf_ktime_get_ns;
use sentinel_common::facts::*;
use sentinel_common::wire::RawEvent;

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

/// uid summary facts (§5.2): user (>=1000) / system (<1000). Literal slots: Task 21.
pub fn set_uid_facts(ev: *mut RawEvent, uid: u32) {
    unsafe {
        if uid >= 1000 {
            (*ev).hdr.facts[G_UID] |= U_USER;
        } else {
            (*ev).hdr.facts[G_UID] |= U_SYSTEM;
        }
    }
}

/// Destination CIDR facts. Task 21: CIDRS/PORTS lookup
pub fn set_dest_facts(_ev: *mut RawEvent, _a: &shim::SockAddr) {
    // Task 21: CIDRS/PORTS lookup
}

/// Destination port facts. Task 21: CIDRS/PORTS lookup
pub fn set_port_facts(_ev: *mut RawEvent, _port: u16) {
    // Task 21: CIDRS/PORTS lookup
}
