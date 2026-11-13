#![no_std]
#![no_main]

use aya_ebpf::{macros::tracepoint, programs::TracePointContext};

mod emit;
mod engine;
mod facts_kern;
mod guard;
mod maps;
mod observe;
mod shim;

#[tracepoint]
pub fn probe(_ctx: TracePointContext) -> u32 {
    let v = engine::lockdown_active() as u64;
    // slot 7 = reserved, test output (kept: heartbeat-selftest reads it)
    if let Some(p) = maps::LOCKDOWN_COUNTS.get_ptr_mut(7) {
        unsafe {
            *p = v;
        }
    }
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }
