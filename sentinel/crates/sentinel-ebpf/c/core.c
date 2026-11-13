#include "vmlinux_min.h"
#include "shim_types.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

int shim_current_core(const void *task, struct sentinel_task_core *o) {
    const struct task_struct *t = task;
    int e = 0;
    e |= BPF_CORE_READ_INTO(&o->pid,  t, tgid);
    e |= BPF_CORE_READ_INTO(&o->tid,  t, pid);
    e |= BPF_CORE_READ_INTO(&o->ppid, t, real_parent, tgid);
    e |= BPF_CORE_READ_INTO(&o->uid,  t, cred, uid.val);
    e |= BPF_CORE_READ_INTO(&o->euid, t, cred, euid.val);
    return e;  /* cgroup_id is filled by the Rust side via the helper */
}

/* container_of(vfsmnt, struct mount, mnt)->mnt_id, with a CO-RE field offset. */
static __always_inline int mount_id_of(const struct vfsmount *vfsmnt, unsigned int *out) {
    unsigned long off = bpf_core_field_offset(((struct mount *)0)->mnt);
    const struct mount *m = (const struct mount *)((const char *)vfsmnt - off);
    int id = 0;
    int e = BPF_CORE_READ_INTO(&id, m, mnt_id);
    *out = (unsigned int)id;
    return e;
}

int shim_mount_id(const void *vfsmnt, unsigned int *mnt_id) {
    return mount_id_of(vfsmnt, mnt_id);
}

/* bprm->file: nlink (deleted), dentry name (memfd:), f_path.mnt mount id */
int shim_exec_info(const void *bprm, struct sentinel_exec_info *o) {
    const struct linux_binprm *b = bprm;
    const struct file *f = 0;
    const struct dentry *d = 0;
    const struct vfsmount *mnt = 0;
    const unsigned char *name = 0;
    int e = 0;
    e |= BPF_CORE_READ_INTO(&f, b, file);
    if (!f) return -1;
    e |= BPF_CORE_READ_INTO(&o->nlink, f, f_inode, i_nlink);
    e |= BPF_CORE_READ_INTO(&d, f, f_path.dentry);
    e |= BPF_CORE_READ_INTO(&name, d, d_name.name);
    o->name_len = bpf_core_read_str(o->name, sizeof(o->name), name);
    e |= BPF_CORE_READ_INTO(&mnt, f, f_path.mnt);
    o->mnt_id = 0;
    if (mnt) e |= mount_id_of(mnt, &o->mnt_id);
    o->is_memfd = (o->name[0]=='m'&&o->name[1]=='e'&&o->name[2]=='m'&&o->name[3]=='f'&&o->name[4]=='d'&&o->name[5]==':');
    return e;
}

int shim_task_tgid(const void *task, unsigned int *out) {
    const struct task_struct *t = task;
    int v = 0;
    int e = BPF_CORE_READ_INTO(&v, t, tgid);
    *out = (unsigned int)v;
    return e;
}

int shim_task_exit_code(const void *task, int *out) {
    const struct task_struct *t = task;
    return BPF_CORE_READ_INTO(out, t, exit_code);
}

/* sockaddr: family, address (v4 in addr[0..4]), port (network byte order). */
int shim_sockaddr(const void *address, struct sentinel_addr *o) {
    const struct sockaddr *sa = address;
    unsigned short fam = 0;
    int e = BPF_CORE_READ_INTO(&fam, sa, sa_family);
    o->family = fam;
    o->port_be = 0;
    if (fam == 2) {
        const struct sockaddr_in *s4 = address;
        unsigned int a4 = 0;
        e |= BPF_CORE_READ_INTO(&a4, s4, sin_addr.s_addr);
        e |= BPF_CORE_READ_INTO(&o->port_be, s4, sin_port);
        __builtin_memcpy(o->addr, &a4, 4);
    } else if (fam == 10) {
        const struct sockaddr_in6 *s6 = address;
        e |= bpf_core_read(o->addr, 16, &s6->sin6_addr);
        e |= BPF_CORE_READ_INTO(&o->port_be, s6, sin6_port);
    }
    return e;
}
