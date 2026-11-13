#ifndef SENTINEL_VMLINUX_MIN_H
#define SENTINEL_VMLINUX_MIN_H
/* Confirmed against host BTF (bpftool btf dump /sys/kernel/btf/vmlinux):
 * task_struct has pid_t pid, pid_t tgid, struct task_struct *real_parent,
 * const struct cred *cred. */
typedef unsigned char __u8;  typedef unsigned short __u16;
typedef unsigned int  __u32; typedef unsigned long long __u64;
typedef signed char __s8;  typedef short __s16;
typedef int __s32; typedef long long __s64;
typedef __u16 __be16; typedef __u32 __be32; typedef __u64 __be64;
typedef __u16 __le16; typedef __u32 __le32; typedef __u64 __le64;
typedef __u16 __sum16; typedef __u32 __wsum;
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
struct task_struct {
    int pid; int tgid;
    int exit_code;
    struct task_struct *real_parent;
    const struct cred *cred;
};
/* kuid_t/kgid_t are struct { uid_t val; } in-kernel; the shim reads ->val */
typedef struct { __u32 val; } kuid_t;
struct cred { kuid_t uid; kuid_t euid; };
/* exec-file info. mount.mnt_id confirmed in host BTF. */
struct qstr { const unsigned char *name; };
struct dentry { struct qstr d_name; };
struct inode { unsigned int i_nlink; };
struct vfsmount {};
struct path { struct vfsmount *mnt; struct dentry *dentry; };
struct file { struct inode *f_inode; struct path f_path; };
struct mount { struct vfsmount mnt; int mnt_id; };
struct linux_binprm { struct file *file; };
typedef unsigned short sa_family_t;
struct in_addr { __be32 s_addr; };
struct in6_addr { __u8 s6_addr[16]; };
struct sockaddr { sa_family_t sa_family; };
struct sockaddr_in { sa_family_t sin_family; __be16 sin_port; struct in_addr sin_addr; };
struct sockaddr_in6 { sa_family_t sin6_family; __be16 sin6_port; struct in6_addr sin6_addr; };
#pragma clang attribute pop
#endif
