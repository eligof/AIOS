use core::ffi::c_void;
#[repr(C)] pub struct TaskIds { pub pid: u32, pub tid: u32, pub ppid: u32 }
unsafe extern "C" { fn shim_task_ids(task: *const c_void, out: *mut TaskIds) -> i32; }
pub unsafe fn task_ids(task: *const c_void) -> Option<TaskIds> {
    let mut o = core::mem::zeroed();
    if shim_task_ids(task, &mut o) == 0 { Some(o) } else { None }
}
