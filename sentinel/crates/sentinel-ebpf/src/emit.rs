use crate::maps::{DROPS, EVENTS};
use aya_ebpf::maps::ring_buf::RingBufEntry;
use sentinel_common::wire::RawEvent;

pub fn reserve() -> Option<RingBufEntry<RawEvent>> {
    match EVENTS.reserve::<RawEvent>(0) {
        Some(e) => Some(e),
        None => {
            if let Some(d) = DROPS.get_ptr_mut(0) {
                unsafe {
                    *d += 1;
                }
            }
            None
        }
    }
}
