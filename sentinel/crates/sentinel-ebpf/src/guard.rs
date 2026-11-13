use crate::maps::CONFIG;
use sentinel_common::wire::CFG_SELFGUARD;

pub fn selfguard_on() -> bool {
    CONFIG
        .get(0)
        .map(|c| c.flags & CFG_SELFGUARD != 0)
        .unwrap_or(false)
}

pub fn daemon_tgid() -> u32 {
    CONFIG.get(0).map(|c| c.sentineld_tgid).unwrap_or(0)
}
