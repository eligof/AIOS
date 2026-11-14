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

/* bprm->filename: the path execve was given, as a string.
 *
 * The exec hook runs before the new image is installed, so /proc/<pid>/exe
 * still names the caller's old image. Reading the path here is the only way
 * an `exe` rule can match the program actually being executed.
 *
 * Returns the string length including the NUL, or negative on failure. */
int shim_exec_path(const void *bprm, unsigned char *out, int cap) {
    const struct linux_binprm *b = bprm;
    const char *p = 0;
    if (cap <= 0) return -1;
    out[0] = 0;
    if (BPF_CORE_READ_INTO(&p, b, filename)) return -1;
    if (!p) return -1;
    return bpf_core_read_str(out, cap, p);
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

/* Bound local address of a struct socket*. Port is returned big-endian
 * (skc_num is host order) so it shares the SockAddr convention. */
int shim_sock_laddr(const void *sock, struct sentinel_addr *o) {
    const struct socket *so = sock;
    const struct sock *sk = 0;
    unsigned short fam = 0, num = 0;
    int e = BPF_CORE_READ_INTO(&sk, so, sk);
    if (!sk) return -1;
    e |= BPF_CORE_READ_INTO(&fam, sk, __sk_common.skc_family);
    e |= BPF_CORE_READ_INTO(&num, sk, __sk_common.skc_num);
    o->family = fam;
    o->port_be = __builtin_bswap16(num);
    if (fam == 2) {
        unsigned int a4 = 0;
        e |= BPF_CORE_READ_INTO(&a4, sk, __sk_common.skc_rcv_saddr);
        __builtin_memcpy(o->addr, &a4, 4);
    } else if (fam == 10) {
        e |= bpf_core_read(o->addr, 16, &sk->__sk_common.skc_v6_rcv_saddr);
    }
    return e;
}

/* file->f_inode i_mode / i_rdev and dentry name (first 64 bytes). */
int shim_file_dev(const void *file, struct sentinel_file_dev *o) {
    const struct file *f = file;
    const struct dentry *d = 0;
    const unsigned char *name = 0;
    unsigned short mode = 0;
    int e = 0;
    e |= BPF_CORE_READ_INTO(&mode, f, f_inode, i_mode);
    e |= BPF_CORE_READ_INTO(&o->rdev, f, f_inode, i_rdev);
    o->mode = mode;
    e |= BPF_CORE_READ_INTO(&d, f, f_path.dentry);
    e |= BPF_CORE_READ_INTO(&name, d, d_name.name);
    o->name_len = bpf_core_read_str(o->name, sizeof(o->name), name);
    return e;
}

/* i_ino and f_mode of a struct file*. */
int shim_file_ino(const void *file, unsigned long long *ino, unsigned int *fmode) {
    const struct file *f = file;
    int e = 0;
    *ino = 0;
    e |= BPF_CORE_READ_INTO(ino, f, f_inode, i_ino);
    e |= BPF_CORE_READ_INTO(fmode, f, f_mode);
    return e;
}

/* i_ino of dentry->d_inode. */
int shim_dentry_ino(const void *dentry, unsigned long long *ino) {
    const struct dentry *d = dentry;
    *ino = 0;
    return BPF_CORE_READ_INTO(ino, d, d_inode, i_ino);
}

/* i_ino of path->dentry->d_inode. */
int shim_path_ino(const void *path, unsigned long long *ino) {
    const struct path *p = path;
    *ino = 0;
    return BPF_CORE_READ_INTO(ino, p, dentry, d_inode, i_ino);
}

/* dentry name of a struct file*, NUL-terminated into out (cap <= 64). */
int shim_file_name(const void *file, unsigned char *out, int cap) {
    const struct file *f = file;
    const struct dentry *d = 0;
    const unsigned char *name = 0;
    int e = 0;
    if (cap <= 0 || cap > 64) return -1;
    e |= BPF_CORE_READ_INTO(&d, f, f_path.dentry);
    e |= BPF_CORE_READ_INTO(&name, d, d_name.name);
    if (e || !name) return -1;
    bpf_core_read_str(out, cap, name);
    return 0;
}

/* target task tgid and cred->uid */
int shim_ptrace(const void *child, unsigned int *tgid, unsigned int *uid) {
    const struct task_struct *t = child;
    int v = 0, e = 0;
    e |= BPF_CORE_READ_INTO(&v, t, tgid);
    *tgid = (unsigned int)v;
    e |= BPF_CORE_READ_INTO(uid, t, cred, uid.val);
    return e;
}

/* 1 if any ancestor (real_parent chain, bounded) of child has tgid == ancestor_tgid. */
int shim_is_descendant(const void *child, unsigned int ancestor_tgid) {
    const struct task_struct *t = child;
    for (int i = 0; i < 32; i++) {
        const struct task_struct *p = 0;
        int tg = 0;
        if (BPF_CORE_READ_INTO(&p, t, real_parent)) return 0;
        if (!p || p == t) return 0;
        if (BPF_CORE_READ_INTO(&tg, p, tgid)) return 0;
        if ((unsigned int)tg == ancestor_tgid) return 1;
        if (tg <= 1) return 0;
        t = p;
    }
    return 0;
}

/* BPF_PROG_LOAD attr->prog_type (kernel copy of bpf_attr) */
int shim_bpf_prog_type(const void *attr, unsigned int *out) {
    const union bpf_attr *a = attr;
    return BPF_CORE_READ_INTO(out, a, prog_type);
}

/* struct filename->name (kernel string) into out, NUL-terminated (cap <= 256). */
int shim_filename(const void *filename, unsigned char *out, int cap) {
    const struct filename *f = filename;
    const unsigned char *name = 0;
    if (cap <= 0 || cap > 256) return -1;
    if (BPF_CORE_READ_INTO(&name, f, name) || !name) return -1;
    return bpf_core_read_str(out, cap, name) < 0 ? -1 : 0;
}

/* nameidata->name->name (path_openat's requested path). */
int shim_nd_filename(const void *nd, unsigned char *out, int cap) {
    const struct nameidata *n = nd;
    const struct filename *f = 0;
    if (BPF_CORE_READ_INTO(&f, n, name) || !f) return -1;
    return shim_filename(f, out, cap);
}

/* struct open_flags->open_flag */
int shim_open_flag(const void *op, int *out) {
    const struct open_flags *o = op;
    return BPF_CORE_READ_INTO(out, o, open_flag);
}
