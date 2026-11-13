#include "vmlinux_min.h"
#include "shim_types.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

int shim_task_ids(const void *task, struct sentinel_task_ids *out) {
    const struct task_struct *t = task;
    int err = 0;
    err |= BPF_CORE_READ_INTO(&out->pid,  t, tgid);
    err |= BPF_CORE_READ_INTO(&out->tid,  t, pid);
    err |= BPF_CORE_READ_INTO(&out->ppid, t, real_parent, tgid);
    return err;
}
