//! Fixed-size events on the ring buffer (§4), shared by the kernel programs and
//! the userspace reader. `repr(C)`, POD, no padding surprises (asserted below).

use crate::facts::NGROUPS;

pub const EXE_LEN: usize = 256;
pub const ARGV_LEN: usize = 256;
pub const PATH_LEN: usize = 256;
pub const NAME_LEN: usize = 64;

/// Kernel verdict carried on the event. User space derives the full outcome.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KVerdict {
    None = 0,
    Denied = 1,
    WouldDeny = 2,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EventHeader {
    pub kind: u8,     // EventKind discriminant
    pub kverdict: u8, // KVerdict
    pub _pad0: [u8; 2],
    pub matched_rule: i32, // index of the matched kernel rule, -1 if none
    pub pid: u32,          // tgid (userspace pid)
    pub tid: u32,          // kernel pid (thread id)
    pub ppid: u32,
    pub uid: u32, // real uid
    pub euid: u32,
    pub _pad1: u32,
    pub cgroup_id: u64,
    pub ts_ns: u64, // bpf_ktime_get_ns
    pub facts: [u32; NGROUPS],
    pub _pad2: u32, // pad header to an 8-byte multiple (80 bytes)
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecPayload {
    pub exe: [u8; EXE_LEN],
    pub argv: [u8; ARGV_LEN],
    pub exe_len: u16,
    pub argv_len: u16,
    pub mnt_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetPayload {
    pub family: u16,
    pub proto: u16,
    pub addr: [u8; 16],
    pub port: u16,
    pub _pad: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OpenPayload {
    pub path: [u8; PATH_LEN],
    pub path_len: u16,
    pub dev_class: u8, // 0 none,1 camera,2 mic,3 input,4 uinput,5 hidraw
    pub _pad: u8,
    pub mode: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PtracePayload {
    pub target_pid: u32,
    pub target_uid: u32,
    pub mode: u32,
    pub _pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcPayload {
    // fork / exit
    pub child_pid: u32,
    pub exit_code: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ModulePayload {
    pub name: [u8; NAME_LEN],
    pub read_id: u32,
    pub _pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BpfPayload {
    pub cmd: u32,
    pub prog_type: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SignalPayload {
    pub target_pid: u32,
    pub sig: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MemfdPayload {
    pub name: [u8; NAME_LEN],
    pub flags: u32,
    pub _pad: u32,
}

/// Fixed-size payload union; the reader switches on `hdr.kind`.
#[repr(C)]
#[derive(Clone, Copy)]
pub union EventPayload {
    pub exec: ExecPayload,
    pub net: NetPayload,
    pub open: OpenPayload,
    pub ptrace: PtracePayload,
    pub proc_: ProcPayload,
    pub module: ModulePayload,
    pub bpf: BpfPayload,
    pub signal: SignalPayload,
    pub memfd: MemfdPayload,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawEvent {
    pub hdr: EventHeader,
    pub payload: EventPayload,
}

// ---- map value types (shared so the loader fills them identically) ----

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CidrEntry {
    pub addr: [u8; 16],
    pub prefix: u8,
    pub family: u8,
    pub slot: u8,
    pub used: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PortRange {
    pub lo: u16,
    pub hi: u16,
    pub slot: u8,
    pub used: u8,
    pub _pad: [u8; 2],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KConfig {
    pub lockdown_after_ns: u64,
    pub sentineld_tgid: u32,
    pub flags: u32,
    /// mnt_id of the read-only /usr mount (lockdown allows exec only from it).
    pub usr_mnt_id: u32,
    pub _pad: u32,
}

pub const CFG_ENFORCE: u32 = 1 << 0;
pub const CFG_SELFGUARD: u32 = 1 << 1;

// ---- compile-time ABI guards (kernel <-> user) ----
const fn assert_copy<T: Copy>() {}
const _: () = {
    assert_copy::<EventHeader>();
    assert_copy::<ExecPayload>();
    assert_copy::<NetPayload>();
    assert_copy::<OpenPayload>();
    assert_copy::<PtracePayload>();
    assert_copy::<ProcPayload>();
    assert_copy::<ModulePayload>();
    assert_copy::<BpfPayload>();
    assert_copy::<SignalPayload>();
    assert_copy::<MemfdPayload>();
    assert_copy::<EventPayload>();
    assert_copy::<RawEvent>();
    assert_copy::<CidrEntry>();
    assert_copy::<PortRange>();
    assert_copy::<KConfig>();

    use core::mem::size_of;
    assert!(size_of::<EventHeader>() == 80);
    assert!(size_of::<RawEvent>() % 8 == 0);
    assert!(size_of::<KConfig>() == 24);
    let m = size_of::<ExecPayload>();
    assert!(size_of::<NetPayload>() <= m);
    assert!(size_of::<OpenPayload>() <= m);
    assert!(size_of::<PtracePayload>() <= m);
    assert!(size_of::<ProcPayload>() <= m);
    assert!(size_of::<ModulePayload>() <= m);
    assert!(size_of::<BpfPayload>() <= m);
    assert!(size_of::<SignalPayload>() <= m);
    assert!(size_of::<MemfdPayload>() <= m);
    assert!(size_of::<EventPayload>() <= m);
};

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, size_of};

    #[test]
    fn header_is_80_bytes_8_aligned() {
        assert_eq!(size_of::<EventHeader>(), 80);
        assert_eq!(size_of::<RawEvent>() % 8, 0);
        assert!(align_of::<RawEvent>() <= 8);
    }
    #[test]
    fn exec_is_the_largest_payload() {
        let m = size_of::<ExecPayload>();
        assert!(size_of::<NetPayload>() <= m);
        assert!(size_of::<OpenPayload>() <= m);
        assert!(size_of::<EventPayload>() <= m);
    }
    #[test]
    fn kverdict_discriminants_are_stable() {
        assert_eq!(KVerdict::None as u8, 0);
        assert_eq!(KVerdict::Denied as u8, 1);
        assert_eq!(KVerdict::WouldDeny as u8, 2);
    }
    #[test]
    fn raw_event_is_pod_copy() {
        fn is_copy<T: Copy>() {}
        is_copy::<RawEvent>();
    }
}
