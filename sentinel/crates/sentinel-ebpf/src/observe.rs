use crate::{emit, facts_kern, shim};
use aya_ebpf::{
    cty::c_int,
    helpers::bpf_probe_read_user_str_bytes,
    macros::{btf_tracepoint, lsm, tracepoint},
    programs::{BtfTracePointContext, LsmContext, TracePointContext},
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
    e.submit(0);
    Ok(0) // deny decided in Phase D
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
    e.submit(0);
    Ok(0)
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
    e.submit(0);
    Ok(0)
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
    e.submit(0);
    Ok(0)
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
    e.submit(0);
    Ok(0)
}

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
    e.submit(0);
    Ok(0)
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
    e.submit(0);
    Ok(0)
}
