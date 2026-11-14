use aya_ebpf::{
    macros::map,
    maps::{Array, HashMap, PerCpuArray, RingBuf},
};
use sentinel_common::rule::{
    KRule, MAX_CIDRS, MAX_MOUNTS, MAX_PORT_SETS, MAX_RULES, MAX_UID_LITERALS,
};
use sentinel_common::wire::{CidrEntry, KConfig, PortRange};

pub const RING_BYTES: u32 = 8 * 1024 * 1024;
pub const NHOOKS: u32 = 8;

#[map]
pub static EVENTS: RingBuf = RingBuf::with_byte_size(RING_BYTES, 0);
#[map]
pub static DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map]
pub static HEARTBEAT: Array<u64> = Array::with_max_entries(1, 0);
#[map]
pub static LOCKDOWN_COUNTS: Array<u64> = Array::with_max_entries(NHOOKS, 0);
#[map]
pub static RULES: Array<KRule> = Array::with_max_entries(MAX_RULES as u32, 0);
#[map]
pub static RULE_COUNT: Array<u32> = Array::with_max_entries(1, 0);
#[map]
pub static MOUNTS: HashMap<u64, u32> = HashMap::with_max_entries(MAX_MOUNTS as u32, 0);
#[map]
pub static CIDRS: Array<CidrEntry> = Array::with_max_entries(MAX_CIDRS as u32, 0);
#[map]
pub static PORTS: Array<PortRange> = Array::with_max_entries(MAX_PORT_SETS as u32, 0);
#[map]
pub static UID_LITERALS: Array<u32> = Array::with_max_entries(MAX_UID_LITERALS as u32, 0);
#[map]
pub static QUARANTINE: HashMap<u64, u8> = HashMap::with_max_entries(1024, 0);
#[map]
pub static GUARDED_INODES: HashMap<u64, u8> = HashMap::with_max_entries(64, 0);
#[map]
pub static CONFIG: Array<KConfig> = Array::with_max_entries(1, 0);
