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

use crate::{emit, facts_kern, shim};
use aya_ebpf::{macros::lsm, programs::LsmContext};
use core::ffi::c_void;
use sentinel_common::event::EventKind;

/// Emit an Open event with kverdict=Denied and return `Some(-EPERM)` unless the
/// caller is the daemon (or PID 1). Used by every guarded-file hook.
pub unsafe fn deny_guarded() -> Option<i32> {
    let mut e = emit::reserve()?;
    let p = e.as_mut_ptr();
    let Some(core) = facts_kern::fill_header(p, EventKind::Open as u8) else {
        e.discard(0);
        return None;
    };
    let d = daemon_tgid();
    if core.pid == d || core.pid == 1 {
        e.discard(0);
        return None;
    }
    facts_kern::set_uid_facts(p, core.uid);
    (*p).payload.open.dev_class = 0;
    (*p).payload.open._pad = 0;
    (*p).payload.open.mode = 0;
    (*p).payload.open.path_len = 0;
    (*p).hdr.kverdict = sentinel_common::wire::KVerdict::Denied as u8;
    e.submit(0);
    Some(-1) // -EPERM
}

unsafe fn guarded(ino: Option<u64>) -> bool {
    match ino {
        Some(i) => crate::maps::GUARDED_INODES.get(&i).is_some(),
        None => false,
    }
}

/// inode_unlink(struct inode *dir, struct dentry *dentry, ret@2).
#[lsm(hook = "inode_unlink")]
pub fn guard_unlink(ctx: LsmContext) -> i32 {
    unsafe {
        let ret: i64 = ctx.arg(2);
        if ret != 0 {
            return ret as i32;
        }
        if !selfguard_on() || !guarded(shim::dentry_ino(ctx.arg::<*const c_void>(1))) {
            return 0;
        }
        deny_guarded().unwrap_or(0)
    }
}

/// inode_rename(old_dir, old_dentry, new_dir, new_dentry, ret@4).
#[lsm(hook = "inode_rename")]
pub fn guard_rename(ctx: LsmContext) -> i32 {
    unsafe {
        let ret: i64 = ctx.arg(4);
        if ret != 0 {
            return ret as i32;
        }
        if !selfguard_on() || !guarded(shim::dentry_ino(ctx.arg::<*const c_void>(1))) {
            return 0;
        }
        deny_guarded().unwrap_or(0)
    }
}

/// path_truncate(const struct path *path, ret@1).
#[lsm(hook = "path_truncate")]
pub fn guard_truncate(ctx: LsmContext) -> i32 {
    unsafe {
        let ret: i64 = ctx.arg(1);
        if ret != 0 {
            return ret as i32;
        }
        if !selfguard_on() || !guarded(shim::path_ino(ctx.arg::<*const c_void>(0))) {
            return 0;
        }
        deny_guarded().unwrap_or(0)
    }
}

/// True when the current task's cgroup v2 id is in QUARANTINE.
pub fn quarantined() -> bool {
    let cg = unsafe { aya_ebpf::helpers::bpf_get_current_cgroup_id() };
    unsafe { crate::maps::QUARANTINE.get(&cg).is_some() }
}

/// Count the denial and emit a Connect event with kverdict=Denied (zeroed
/// destination). Always yields -EPERM; emission is best-effort.
pub unsafe fn deny_quarantined(hook: u32) -> i32 {
    crate::engine::count_lockdown(hook);
    if let Some(mut e) = emit::reserve() {
        let p = e.as_mut_ptr();
        if let Some(core) = facts_kern::fill_header(p, EventKind::Connect as u8) {
            facts_kern::set_uid_facts(p, core.uid);
            (*p).payload.net.family = 0;
            (*p).payload.net.proto = 0;
            (*p).payload.net.addr = [0; 16];
            (*p).payload.net.port = 0;
            (*p).payload.net._pad = 0;
            (*p).hdr.kverdict = sentinel_common::wire::KVerdict::Denied as u8;
            e.submit(0);
        } else {
            e.discard(0);
        }
    }
    -1 // -EPERM
}

/// socket_sendmsg(sock, msg, size, ret@3): quarantined cgroups cannot send
/// (closes connectionless UDP during the SOCK_DESTROY race).
#[lsm(hook = "socket_sendmsg")]
pub fn sendmsg(ctx: LsmContext) -> i32 {
    unsafe {
        let ret: i64 = ctx.arg(3);
        if ret != 0 {
            return ret as i32;
        }
        if quarantined() {
            return deny_quarantined(2);
        }
        0
    }
}
