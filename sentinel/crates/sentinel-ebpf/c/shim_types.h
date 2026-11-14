#ifndef SENTINEL_SHIM_TYPES_H
#define SENTINEL_SHIM_TYPES_H
struct sentinel_task_core { unsigned int pid, tid, ppid, uid, euid; unsigned long long cgroup_id; };
struct sentinel_exec_info { unsigned int mnt_id; int nlink; int is_memfd; unsigned char name[64]; int name_len; };
struct sentinel_addr { unsigned short family; unsigned short port_be; unsigned char addr[16]; };
struct sentinel_file_dev { unsigned int mode; unsigned int rdev; int name_len; unsigned char name[64]; };
#endif
