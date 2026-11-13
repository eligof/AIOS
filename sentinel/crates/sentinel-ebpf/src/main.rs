#![no_std]
#![no_main]

use aya_ebpf::{macros::tracepoint, programs::TracePointContext};

mod shim;

#[tracepoint]
pub fn probe(_ctx: TracePointContext) -> u32 {
    let _ = unsafe { shim::task_ids(core::ptr::null()) };
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }
