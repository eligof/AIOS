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

unsafe extern "C" {
    fn shim_current_core(task: *const c_void, out: *mut TaskCore) -> i32;
    fn shim_exec_info(bprm: *const c_void, out: *mut ExecInfo) -> i32;
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
