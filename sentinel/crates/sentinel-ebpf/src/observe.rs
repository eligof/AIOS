use crate::{emit, facts_kern, shim};
use aya_ebpf::{cty::c_int, macros::lsm, programs::LsmContext};
use core::ffi::c_void;
use sentinel_common::event::EventKind;
use sentinel_common::facts::*;

#[lsm(hook = "bprm_check_security")]
pub fn exec(ctx: LsmContext) -> i32 {
    match unsafe { try_exec(&ctx) } {
        Ok(v) => v,
        Err(v) => v,
    }
}

unsafe fn try_exec(ctx: &LsmContext) -> Result<i32, i32> {
    // Read the full 64-bit slot: the verifier tracks the chained verdict as a
    // signed range, and a 32-bit read would zero-extend and lose the sign.
    let ret: i64 = ctx.arg(1);
    if ret != 0 {
        return Err(ret as c_int);
    }
    let bprm: *const c_void = ctx.arg(0);
    let Some(mut e) = emit::reserve() else {
        return Ok(0);
    };
    let p = e.as_mut_ptr();
    let Some(core) = facts_kern::fill_header(p, EventKind::Exec as u8) else {
        e.discard(0);
        return Ok(0);
    };
    facts_kern::set_uid_facts(p, core.uid);
    (*p).payload.exec.exe_len = 0; // S3 resolves exe/argv from /proc
    (*p).payload.exec.argv_len = 0;
    (*p).payload.exec.mnt_id = 0;
    if let Some(info) = shim::exec_info(bprm) {
        (*p).payload.exec.mnt_id = info.mnt_id;
        if info.is_memfd != 0 {
            (*p).hdr.facts[G_FLAGS] |= F_MEMFD;
        } else if info.nlink == 0 {
            (*p).hdr.facts[G_FLAGS] |= F_DELETED;
        }
        // exe_on: mnt_id -> slot bit (Task 21 fills MOUNTS)
        if let Some(bit) = crate::maps::MOUNTS.get(&(info.mnt_id as u64)) {
            (*p).hdr.facts[G_MOUNT] |= *bit;
        }
        // env_ld / stdio_socket: 0 here; S3: enrich from /proc
    }
    e.submit(0);
    Ok(0) // deny decided in Phase D
}
