//! The AIOS Sentinel daemon (spec §6–§10, §12–§13).
//!
//! Every effect on the kernel goes through the [`kernel::Kernel`] trait, so the
//! whole dispatch path is unit-testable on the host without root.

pub mod action;
pub mod alert;
pub mod daemon;
pub mod dns;
pub mod engine;
pub mod kernel;
pub mod loader;
pub mod lockdown;
pub mod proc;
pub mod report;
pub mod resolve;
pub mod sockdestroy;
pub mod status;
pub mod table;
pub mod varlink;

/// Drain the `EVENTS` ring until `stop`. Blocks in `poll` on the ring fd, so
/// an idle daemon costs nothing (spec §13: under 1 % of one core).
pub fn drain(
    ring: &mut aya::maps::RingBuf<aya::maps::MapData>,
    daemon: std::sync::Arc<std::sync::Mutex<daemon::Daemon>>,
    kernel: std::sync::Arc<std::sync::Mutex<Box<dyn kernel::Kernel>>>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    use std::os::fd::AsRawFd;
    use std::sync::atomic::Ordering;

    let fd = ring.as_raw_fd();
    let mut quiet_rounds = 0u32;
    while !stop.load(Ordering::Relaxed) {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pfd is a valid single-element pollfd array; the 250 ms
        // timeout is what lets `stop` be noticed while the ring stays quiet.
        let rc = unsafe { libc::poll(&mut pfd, 1, 250) };
        if rc < 0 {
            continue;
        }
        while let Some(item) = ring.next() {
            if item.len() < core::mem::size_of::<sentinel_common::wire::RawEvent>() {
                continue;
            }
            // SAFETY: length checked above; RawEvent is repr(C) plain data and
            // a ring item is not necessarily aligned.
            let ev = unsafe {
                core::ptr::read_unaligned(item.as_ptr() as *const sentinel_common::wire::RawEvent)
            };
            drop(item);
            if let (Ok(mut d), Ok(mut k)) = (daemon.lock(), kernel.lock()) {
                d.on_event(&ev, k.as_mut());
            }
        }
        quiet_rounds += 1;
        // Roughly every 4 s of polling, or sooner under load.
        if quiet_rounds >= 16 {
            quiet_rounds = 0;
            if let (Ok(mut d), Ok(mut k)) = (daemon.lock(), kernel.lock()) {
                d.check_drops(k.as_mut());
            }
        }
    }
}
