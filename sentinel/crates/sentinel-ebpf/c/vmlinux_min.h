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
    struct task_struct *real_parent;
    const struct cred *cred;
};
/* kuid_t/kgid_t are struct { uid_t val; } in-kernel; the shim reads ->val */
typedef struct { __u32 val; } kuid_t;
struct cred { kuid_t uid; kuid_t euid; };
/* socket, file, path, dentry, vfsmount, linux_binprm, sockaddr_in* added per task */
#pragma clang attribute pop
#endif
