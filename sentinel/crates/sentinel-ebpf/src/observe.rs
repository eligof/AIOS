use crate::{emit, facts_kern, shim};
use aya_ebpf::{
    cty::c_int,
    helpers::bpf_probe_read_user_str_bytes,
    macros::{btf_tracepoint, fexit, lsm, tracepoint},
    programs::{BtfTracePointContext, FExitContext, LsmContext, TracePointContext},
};
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
    let v = crate::engine::evaluate((*p).hdr.kind, &Facts((*p).hdr.facts));
    let deny = crate::engine::apply_verdict(p, &v);
    e.submit(0);
    match deny {
        Some(err) => Err(err),
        None => Ok(0),
    }
}

const AF_UNIX: u16 = 1;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

fn is_loopback(a: &shim::SockAddr) -> bool {
    if a.family == AF_INET {
        a.addr[0] == 127
    } else if a.family == AF_INET6 {
        a.addr[..15].iter().all(|b| *b == 0) && a.addr[15] == 1
    } else {
        false
    }
}

#[lsm(hook = "socket_connect")]
pub fn connect(ctx: LsmContext) -> i32 {
    match unsafe { try_connect(&ctx) } {
        Ok(v) => v,
        Err(v) => v,
    }
}

unsafe fn try_connect(ctx: &LsmContext) -> Result<i32, i32> {
    let ret: i64 = ctx.arg(3);
    if ret != 0 {
        return Err(ret as c_int);
    }
    let address: *const c_void = ctx.arg(1);
    let Some(a) = shim::sockaddr(address) else {
        return Ok(0);
    };
    if a.family == AF_UNIX || is_loopback(&a) {
        return Ok(0);
    }
    let Some(mut e) = emit::reserve() else {
        return Ok(0);
    };
    let p = e.as_mut_ptr();
    let Some(core) = facts_kern::fill_header(p, EventKind::Connect as u8) else {
        e.discard(0);
        return Ok(0);
    };
    facts_kern::set_uid_facts(p, core.uid);
    let port = u16::from_be(a.port_be);
    (*p).payload.net.family = a.family;
    (*p).payload.net.proto = 0;
    (*p).payload.net.addr = a.addr;
    (*p).payload.net.port = port;
    (*p).payload.net._pad = 0;
    facts_kern::set_dest_facts(p, &a);
    facts_kern::set_port_facts(p, port);
    let v = crate::engine::evaluate((*p).hdr.kind, &Facts((*p).hdr.facts));
    let deny = crate::engine::apply_verdict(p, &v);
    e.submit(0);
    match deny {
        Some(err) => Err(err),
        None => Ok(0),
    }
}

#[lsm(hook = "socket_listen")]
pub fn listen(ctx: LsmContext) -> i32 {
    match unsafe { try_listen(&ctx) } {
        Ok(v) => v,
        Err(v) => v,
    }
}

unsafe fn try_listen(ctx: &LsmContext) -> Result<i32, i32> {
    let ret: i64 = ctx.arg(2);
    if ret != 0 {
        return Err(ret as c_int);
    }
    let sock: *const c_void = ctx.arg(0);
    let Some(a) = shim::sock_laddr(sock) else {
        return Ok(0);
    };
    if a.family == AF_UNIX || is_loopback(&a) {
        return Ok(0);
    }
    let Some(mut e) = emit::reserve() else {
        return Ok(0);
    };
    let p = e.as_mut_ptr();
    let Some(core) = facts_kern::fill_header(p, EventKind::Listen as u8) else {
        e.discard(0);
        return Ok(0);
    };
    facts_kern::set_uid_facts(p, core.uid);
    let port = u16::from_be(a.port_be);
    (*p).payload.net.family = a.family;
    (*p).payload.net.proto = 0;
    (*p).payload.net.addr = a.addr;
    (*p).payload.net.port = port;
    (*p).payload.net._pad = 0;
    (*p).hdr.facts[G_FLAGS] |= F_LISTEN_NON_LOOPBACK;
    let v = crate::engine::evaluate((*p).hdr.kind, &Facts((*p).hdr.facts));
    let deny = crate::engine::apply_verdict(p, &v);
    e.submit(0);
    match deny {
        Some(err) => Err(err),
        None => Ok(0),
    }
}

#[btf_tracepoint(function = "sched_process_fork")]
pub fn fork(ctx: BtfTracePointContext) -> i32 {
    unsafe { proc_event(&ctx, EventKind::Fork) }
}

#[btf_tracepoint(function = "sched_process_exit")]
pub fn exit(ctx: BtfTracePointContext) -> i32 {
    unsafe { proc_event(&ctx, EventKind::Exit) }
}

/// fork: arg0 parent task, arg1 child task. exit: arg0 task. Observe only.
unsafe fn proc_event(ctx: &BtfTracePointContext, kind: EventKind) -> i32 {
    let Some(mut e) = emit::reserve() else {
        return 0;
    };
    let p = e.as_mut_ptr();
    if facts_kern::fill_header(p, kind as u8).is_none() {
        e.discard(0);
        return 0;
    }
    match kind {
        EventKind::Fork => {
            let child: *const c_void = ctx.arg(1);
            (*p).payload.proc_.child_pid = shim::task_tgid(child).unwrap_or(0);
            (*p).payload.proc_.exit_code = 0;
        }
        _ => {
            let task: *const c_void = ctx.arg(0);
            (*p).payload.proc_.child_pid = 0;
            (*p).payload.proc_.exit_code = shim::task_exit_code(task).unwrap_or(0);
        }
    }
    e.submit(0);
    0
}

#[lsm(hook = "file_open")]
pub fn open(ctx: LsmContext) -> i32 {
    match unsafe { try_open(&ctx) } {
        Ok(v) => v,
        Err(v) => v,
    }
}

unsafe fn try_open(ctx: &LsmContext) -> Result<i32, i32> {
    let ret: i64 = ctx.arg(1);
    if ret != 0 {
        return Err(ret as c_int);
    }
    let file: *const c_void = ctx.arg(0);
    // Self-guard: deny write-intent opens of Sentinel's own files (FMODE_WRITE = 2).
    if crate::guard::selfguard_on() {
        if let Some((ino, fmode)) = shim::file_ino(file) {
            if fmode & 2 != 0 && crate::maps::GUARDED_INODES.get(&ino).is_some() {
                if let Some(r) = crate::guard::deny_guarded() {
                    return Err(r);
                }
            }
        }
    }
    let Some(d) = shim::file_dev(file) else {
        return Ok(0);
    };
    if d.mode & 0o170000 != 0o020000 {
        return Ok(0); // not S_ISCHR
    }
    let major = d.rdev >> 20;
    let len = if d.name_len > 0 { (d.name_len - 1) as usize & 63 } else { 0 };
    let Some((class, bit)) = facts_kern::device_class(major, &d.name, len) else {
        return Ok(0);
    };
    let Some(mut e) = emit::reserve() else {
        return Ok(0);
    };
    let p = e.as_mut_ptr();
    let Some(core) = facts_kern::fill_header(p, EventKind::Open as u8) else {
        e.discard(0);
        return Ok(0);
    };
    facts_kern::set_uid_facts(p, core.uid);
    (*p).payload.open.dev_class = class;
    (*p).payload.open._pad = 0;
    (*p).payload.open.mode = d.mode;
    (*p).payload.open.path_len = len as u16;
    let mut i = 0;
    while i < 64 {
        (*p).payload.open.path[i] = d.name[i];
        i += 1;
    }
    (*p).hdr.facts[G_DEVICE] |= bit;
    let v = crate::engine::evaluate((*p).hdr.kind, &Facts((*p).hdr.facts));
    let deny = crate::engine::apply_verdict(p, &v);
    e.submit(0);
    match deny {
        Some(err) => Err(err),
        None => Ok(0),
    }
}

/// sys_enter_memfd_create: args[0] = name (user ptr) at offset 16, args[1] = flags at 24.
#[tracepoint(category = "syscalls", name = "sys_enter_memfd_create")]
pub fn memfd(ctx: TracePointContext) -> u32 {
    unsafe { try_memfd(&ctx) }
}

unsafe fn try_memfd(ctx: &TracePointContext) -> u32 {
    let name_ptr = ctx.read_at::<u64>(16).unwrap_or(0);
    let flags = ctx.read_at::<u64>(24).unwrap_or(0);
    let Some(mut e) = emit::reserve() else {
        return 0;
    };
    let p = e.as_mut_ptr();
    let Some(core) = facts_kern::fill_header(p, EventKind::Memfd as u8) else {
        e.discard(0);
        return 0;
    };
    facts_kern::set_uid_facts(p, core.uid);
    let mut i = 0;
    while i < 64 {
        (*p).payload.memfd.name[i] = 0;
        i += 1;
    }
    if name_ptr != 0 {
        let buf = core::slice::from_raw_parts_mut((*p).payload.memfd.name.as_mut_ptr(), 64);
        let _ = bpf_probe_read_user_str_bytes(name_ptr as *const u8, buf);
    }
    (*p).payload.memfd.flags = flags as u32;
    (*p).payload.memfd._pad = 0;
    (*p).hdr.matched_rule = crate::engine::evaluate((*p).hdr.kind, &Facts((*p).hdr.facts)).matched;
    e.submit(0);
    0
}

#[lsm(hook = "ptrace_access_check")]
pub fn ptrace(ctx: LsmContext) -> i32 {
    match unsafe { try_ptrace(&ctx) } {
        Ok(v) => v,
        Err(v) => v,
    }
}

unsafe fn try_ptrace(ctx: &LsmContext) -> Result<i32, i32> {
    let ret: i64 = ctx.arg(2);
    if ret != 0 {
        return Err(ret as c_int);
    }
    let child: *const c_void = ctx.arg(0);
    let mode: u32 = ctx.arg(1);
    let Some((tgid, uid)) = shim::ptrace_target(child) else {
        return Ok(0);
    };
    let Some(mut e) = emit::reserve() else {
        return Ok(0);
    };
    let p = e.as_mut_ptr();
    let Some(core) = facts_kern::fill_header(p, EventKind::Ptrace as u8) else {
        e.discard(0);
        return Ok(0);
    };
    if tgid == core.pid {
        e.discard(0); // self-ptrace
        return Ok(0);
    }
    facts_kern::set_uid_facts(p, core.uid);
    let mut bits = P_ANY;
    if uid != core.uid {
        bits |= P_OTHER_UID;
    }
    if !shim::is_descendant(child, core.pid) {
        bits |= P_NON_DESCENDANT;
    }
    (*p).hdr.facts[G_PTRACE] |= bits;
    (*p).payload.ptrace.target_pid = tgid;
    (*p).payload.ptrace.target_uid = uid;
    (*p).payload.ptrace.mode = mode;
    (*p).payload.ptrace._pad = 0;
    let v = crate::engine::evaluate((*p).hdr.kind, &Facts((*p).hdr.facts));
    let deny = crate::engine::apply_verdict(p, &v);
    if crate::guard::selfguard_on() {
        let d = crate::guard::daemon_tgid();
        if tgid == d && d != 0 {
            let is_attach = (mode & PTRACE_MODE_ATTACH) != 0;
            if is_attach || core.pid != 1 {
                (*p).hdr.kverdict = sentinel_common::wire::KVerdict::Denied as u8;
                e.submit(0);
                return Err(-1); // -EPERM
            }
        }
    }
    e.submit(0);
    match deny {
        Some(err) => Err(err),
        None => Ok(0),
    }
}

/// `PTRACE_MODE_ATTACH` bit of the `mode` argument.
const PTRACE_MODE_ATTACH: u32 = 0x02;

/// `enum kernel_read_file_id`: READING_MODULE.
const READING_MODULE: u32 = 2;
/// READING_MODULE_COMPRESSED: `finit_module(MODULE_INIT_COMPRESSED_FILE)` (e.g. `.ko.zst`).
const READING_MODULE_COMPRESSED: u32 = 7;

#[lsm(hook = "kernel_read_file")]
pub fn module_read(ctx: LsmContext) -> i32 {
    match unsafe { try_module(&ctx, true) } {
        Ok(v) => v,
        Err(v) => v,
    }
}

#[lsm(hook = "kernel_load_data")]
pub fn module_data(ctx: LsmContext) -> i32 {
    match unsafe { try_module(&ctx, false) } {
        Ok(v) => v,
        Err(v) => v,
    }
}

/// kernel_read_file(file, id, contents, ret@3); kernel_load_data(id, contents, ret@2).
unsafe fn try_module(ctx: &LsmContext, has_file: bool) -> Result<i32, i32> {
    let ret: i64 = if has_file { ctx.arg(3) } else { ctx.arg(2) };
    if ret != 0 {
        return Err(ret as c_int);
    }
    let id: u32 = if has_file { ctx.arg(1) } else { ctx.arg(0) };
    if id != READING_MODULE && id != READING_MODULE_COMPRESSED {
        return Ok(0);
    }
    let Some(mut e) = emit::reserve() else {
        return Ok(0);
    };
    let p = e.as_mut_ptr();
    let Some(core) = facts_kern::fill_header(p, EventKind::Module as u8) else {
        e.discard(0);
        return Ok(0);
    };
    facts_kern::set_uid_facts(p, core.uid);
    let mut i = 0;
    while i < 64 {
        (*p).payload.module.name[i] = 0;
        i += 1;
    }
    if has_file {
        let file: *const c_void = ctx.arg(0);
        let _ = shim::file_name(file, (*p).payload.module.name.as_mut_ptr(), 64);
    }
    (*p).payload.module.read_id = id;
    (*p).payload.module._pad = 0;
    (*p).hdr.matched_rule = crate::engine::evaluate((*p).hdr.kind, &Facts((*p).hdr.facts)).matched;
    e.submit(0);
    Ok(0)
}

/// `enum bpf_cmd`: BPF_PROG_LOAD.
const BPF_PROG_LOAD: u32 = 5;

#[lsm(hook = "bpf")]
pub fn bpf(ctx: LsmContext) -> i32 {
    match unsafe { try_bpf(&ctx) } {
        Ok(v) => v,
        Err(v) => v,
    }
}

/// bpf(int cmd, union bpf_attr *attr, unsigned int size, bool kernel, ret@4).
unsafe fn try_bpf(ctx: &LsmContext) -> Result<i32, i32> {
    let ret: i64 = ctx.arg(4);
    if ret != 0 {
        return Err(ret as c_int);
    }
    let cmd: u32 = ctx.arg(0);
    let attr: *const c_void = ctx.arg(1);
    let Some(mut e) = emit::reserve() else {
        return Ok(0);
    };
    let p = e.as_mut_ptr();
    let Some(core) = facts_kern::fill_header(p, EventKind::Bpf as u8) else {
        e.discard(0);
        return Ok(0);
    };
    facts_kern::set_uid_facts(p, core.uid);
    (*p).payload.bpf.cmd = cmd;
    (*p).payload.bpf.prog_type = if cmd == BPF_PROG_LOAD {
        shim::bpf_prog_type(attr).unwrap_or(0)
    } else {
        0
    };
    let v = crate::engine::evaluate((*p).hdr.kind, &Facts((*p).hdr.facts));
    let deny = crate::engine::apply_verdict(p, &v);
    // Self-guard: refuse blinding-capable program loads from anyone but the daemon / PID 1.
    // S3: map detach / *_GET_FD_BY_ID / map-update against Sentinel's objects needs object-id tracking.
    if crate::guard::selfguard_on()
        && cmd == BPF_PROG_LOAD
        && is_hostile_prog_type((*p).payload.bpf.prog_type)
        && core.pid != 1
        && core.pid != crate::guard::daemon_tgid()
    {
        (*p).hdr.kverdict = sentinel_common::wire::KVerdict::Denied as u8;
        e.submit(0);
        return Err(-1); // -EPERM
    }
    e.submit(0);
    match deny {
        Some(err) => Err(err),
        None => Ok(0),
    }
}

/// Program types able to observe or blind the system: kprobe, tracepoint, perf event,
/// raw tracepoint (+writable), tracing (fentry/fexit/iter), extension, LSM.
fn is_hostile_prog_type(t: u32) -> bool {
    matches!(t, 2 | 5 | 7 | 17 | 24 | 26 | 28 | 29)
}

#[lsm(hook = "task_kill")]
pub fn signal(ctx: LsmContext) -> i32 {
    match unsafe { try_signal(&ctx) } {
        Ok(v) => v,
        Err(v) => v,
    }
}

/// task_kill(struct task_struct *p, struct kernel_siginfo *info, int sig, const struct cred *cred, ret@4).
/// Only signals aimed at sentineld are reported (keeps the ring quiet).
unsafe fn try_signal(ctx: &LsmContext) -> Result<i32, i32> {
    let ret: i64 = ctx.arg(4);
    if ret != 0 {
        return Err(ret as c_int);
    }
    let target: *const c_void = ctx.arg(0);
    let sig: u32 = ctx.arg(2);
    let Some(target_tgid) = shim::task_tgid(target) else {
        return Ok(0);
    };
    let Some(cfg) = crate::maps::CONFIG.get(0) else {
        return Ok(0);
    };
    let sentineld = cfg.sentineld_tgid;
    if sentineld == 0 || target_tgid != sentineld {
        return Ok(0);
    }
    let Some(mut e) = emit::reserve() else {
        return Ok(0);
    };
    let p = e.as_mut_ptr();
    let Some(core) = facts_kern::fill_header(p, EventKind::Signal as u8) else {
        e.discard(0);
        return Ok(0);
    };
    facts_kern::set_uid_facts(p, core.uid);
    (*p).payload.signal.target_pid = target_tgid;
    (*p).payload.signal.sig = sig;
    let v = crate::engine::evaluate((*p).hdr.kind, &Facts((*p).hdr.facts));
    let deny = crate::engine::apply_verdict(p, &v);
    if crate::guard::selfguard_on() {
        let d = crate::guard::daemon_tgid();
        let sender = core.pid;
        if target_tgid == d && d != 0 && sender != d && sender != 1 {
            (*p).hdr.kverdict = sentinel_common::wire::KVerdict::Denied as u8;
            e.submit(0);
            return Err(-1); // -EPERM
        }
    }
    e.submit(0);
    match deny {
        Some(err) => Err(err),
        None => Ok(0),
    }
}

/// -EROFS as an ERR_PTR-encoded `struct file *`.
const EROFS_RET: i64 = -30;
const O_ACCMODE: i32 = 3;
const O_CREAT: i32 = 0o100;
const O_TRUNC: i32 = 0o1000;

/// Hook choice: `do_filp_open` is not BTF-attachable (absent from vmlinux
/// BTF, inlined), so this is the documented fallback `path_openat`. fexit sees
/// the final -EROFS; a write to a read-only mount fails in the VFS before
/// `file_open`, so the LSM hook cannot see it.
#[fexit(function = "path_openat")]
pub fn write_refused(ctx: FExitContext) -> i32 {
    unsafe {
        let _ = try_write_refused(&ctx);
    }
    0
}

/// path_openat(struct nameidata *nd, const struct open_flags *op, unsigned flags) -> struct file *@3.
unsafe fn try_write_refused(ctx: &FExitContext) -> Result<(), ()> {
    let ret: i64 = ctx.arg(3);
    if ret != EROFS_RET {
        return Err(());
    }
    let op: *const c_void = ctx.arg(1);
    let flags = shim::open_flag(op).ok_or(())?;
    if (flags & O_ACCMODE) == 0 && (flags & (O_CREAT | O_TRUNC)) == 0 {
        return Err(());
    }
    let nd: *const c_void = ctx.arg(0);
    let mut e = emit::reserve().ok_or(())?;
    let p = e.as_mut_ptr();
    let Some(core) = facts_kern::fill_header(p, EventKind::WriteRefused as u8) else {
        e.discard(0);
        return Err(());
    };
    facts_kern::set_uid_facts(p, core.uid);
    let path = &mut (*p).payload.open;
    let mut i = 0;
    while i < path.path.len() {
        path.path[i] = 0;
        i += 1;
    }
    path.path_len = 0;
    path.dev_class = 0;
    path._pad = 0;
    path.mode = 0;
    if shim::nd_filename(nd, path.path.as_mut_ptr(), path.path.len() as i32) {
        let mut n = 0;
        while n < path.path.len() && path.path[n] != 0 {
            n += 1;
        }
        path.path_len = n as u16;
    }
    (*p).hdr.matched_rule = crate::engine::evaluate((*p).hdr.kind, &Facts((*p).hdr.facts)).matched;
    e.submit(0);
    Ok(())
}
