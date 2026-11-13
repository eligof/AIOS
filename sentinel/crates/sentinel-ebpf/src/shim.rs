use aya_ebpf::helpers::{bpf_get_current_cgroup_id, bpf_get_current_task};
use core::ffi::c_void;

#[repr(C)]
pub struct TaskCore {
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub euid: u32,
    pub cgroup_id: u64,
}

#[repr(C)]
pub struct ExecInfo {
    pub mnt_id: u32,
    pub nlink: i32,
    pub is_memfd: i32,
    pub name: [u8; 64],
    pub name_len: i32,
}

#[repr(C)]
pub struct FileDev {
    pub mode: u32,
    pub rdev: u32,
    pub name_len: i32,
    pub name: [u8; 64],
}

#[repr(C)]
pub struct SockAddr {
    pub family: u16,
    pub port_be: u16,
    pub addr: [u8; 16],
}

unsafe extern "C" {
    fn shim_sockaddr(address: *const c_void, out: *mut SockAddr) -> i32;
    fn shim_sock_laddr(sock: *const c_void, out: *mut SockAddr) -> i32;
    fn shim_current_core(task: *const c_void, out: *mut TaskCore) -> i32;
    fn shim_exec_info(bprm: *const c_void, out: *mut ExecInfo) -> i32;
    fn shim_file_dev(file: *const c_void, out: *mut FileDev) -> i32;
    fn shim_ptrace(child: *const c_void, tgid: *mut u32, uid: *mut u32) -> i32;
    fn shim_is_descendant(child: *const c_void, ancestor_tgid: u32) -> i32;
    fn shim_task_tgid(task: *const c_void, out: *mut u32) -> i32;
    fn shim_task_exit_code(task: *const c_void, out: *mut i32) -> i32;
}

/// Core ids of the current task (pid/tid/ppid/uid/euid + cgroup id).
pub unsafe fn current_core() -> Option<TaskCore> {
    let task = bpf_get_current_task() as *const c_void;
    let mut o: TaskCore = core::mem::zeroed();
    if shim_current_core(task, &mut o) == 0 {
        o.cgroup_id = bpf_get_current_cgroup_id();
        Some(o)
    } else {
        None
    }
}

/// Exec-file facts of a `linux_binprm*`.
pub unsafe fn exec_info(bprm: *const c_void) -> Option<ExecInfo> {
    let mut o: ExecInfo = core::mem::zeroed();
    if shim_exec_info(bprm, &mut o) == 0 {
        Some(o)
    } else {
        None
    }
}

/// Thread-group id of an arbitrary `task_struct*`.
pub unsafe fn task_tgid(task: *const c_void) -> Option<u32> {
    let mut v: u32 = 0;
    if shim_task_tgid(task, &mut v) == 0 {
        Some(v)
    } else {
        None
    }
}

/// `task->exit_code` of an arbitrary `task_struct*`.
pub unsafe fn task_exit_code(task: *const c_void) -> Option<i32> {
    let mut v: i32 = 0;
    if shim_task_exit_code(task, &mut v) == 0 {
        Some(v)
    } else {
        None
    }
}

/// Family, raw address and big-endian port of a kernel `sockaddr*`.
pub unsafe fn sockaddr(address: *const c_void) -> Option<SockAddr> {
    let mut o: SockAddr = core::mem::zeroed();
    if shim_sockaddr(address, &mut o) == 0 {
        Some(o)
    } else {
        None
    }
}

/// Bound local family/address/big-endian port of a `struct socket*`.
pub unsafe fn sock_laddr(sock: *const c_void) -> Option<SockAddr> {
    let mut o: SockAddr = core::mem::zeroed();
    if shim_sock_laddr(sock, &mut o) == 0 {
        Some(o)
    } else {
        None
    }
}

/// Mode, raw `i_rdev` and dentry name (first 64 bytes) of a `struct file*`.
pub unsafe fn file_dev(file: *const c_void) -> Option<FileDev> {
    let mut o: FileDev = core::mem::zeroed();
    if shim_file_dev(file, &mut o) == 0 {
        Some(o)
    } else {
        None
    }
}

/// Target `(tgid, uid)` of a ptrace `child` task.
pub unsafe fn ptrace_target(child: *const c_void) -> Option<(u32, u32)> {
    let (mut tgid, mut uid) = (0u32, 0u32);
    if shim_ptrace(child, &mut tgid, &mut uid) == 0 {
        Some((tgid, uid))
    } else {
        None
    }
}

/// True if `ancestor_tgid` is on `child`'s real_parent chain (bounded walk).
pub unsafe fn is_descendant(child: *const c_void, ancestor_tgid: u32) -> bool {
    shim_is_descendant(child, ancestor_tgid) == 1
}
