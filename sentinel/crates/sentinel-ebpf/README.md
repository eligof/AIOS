# sentinel-ebpf: kernel ABI handed to S3 (`sentineld`)

This crate is the eBPF object (Aya, `no_std`, target `bpfel-unknown-none`) plus C CO-RE shims. `sentineld` embeds the built object and loads it. The reference loader is `sentinel/crates/ebpf-loadtest/src/main.rs` (`load` subcommand); copy its sequence.

## Maps

| Name | Type | Size | Purpose |
|---|---|---|---|
| `EVENTS` | RingBuf | 8 MiB | `RawEvent` stream to user space |
| `DROPS` | PerCpuArray<u64> | 1 | per-CPU count of events dropped (ring full) |
| `HEARTBEAT` | Array<u64> | 1 | `CLOCK_MONOTONIC` ns written by the daemon |
| `LOCKDOWN_COUNTS` | Array<u64> | 8 (`NHOOKS`) | per-hook count of lockdown denials |
| `RULES` | Array<KRule> | 64 (`MAX_RULES`) | compiled kernel rules |
| `RULE_COUNT` | Array<u32> | 1 | number of valid entries in `RULES` |
| `MOUNTS` | HashMap<u64, u32> | 32 (`MAX_MOUNTS`) | mnt_id -> bitmask of `exe_on` slots |
| `CIDRS` | Array<CidrEntry> | 32 | CIDR lookup table (`used`, `slot`, `family` 2/10) |
| `PORTS` | Array<PortRange> | 32 | port ranges grouped by set `slot` |
| `UID_LITERALS` | Array<u32> | 30 | uid literals; unused slots = `u32::MAX` (0 would match root) |
| `QUARANTINE` | HashMap<u64, u8> | 1024 | cgroup ids whose connect/sendmsg are denied |
| `GUARDED_INODES` | HashMap<u64, u8> | 64 | inodes protected from unlink/rename/truncate |
| `CONFIG` | Array<KConfig> | 1 | daemon configuration (below) |

Map value types live in `sentinel-common` (`wire.rs`, `rule.rs`); both sides share them. Loader newtypes implement `aya::Pod` (orphan rule).

## `RawEvent` wire layout (`sentinel-common/src/wire.rs`)

`RawEvent { hdr: EventHeader (80 bytes), payload: EventPayload (union) }`, `repr(C)`, size a multiple of 8; the payload is sized to the largest variant (`ExecPayload`). Read ring items with `read_unaligned` after checking `len >= size_of::<RawEvent>()`.

`EventHeader` (80 bytes): `kind u8`, `kverdict u8`, `_pad0 [u8;2]`, `matched_rule i32` (-1 none), `pid u32` (tgid), `tid u32`, `ppid u32`, `uid u32`, `euid u32`, `_pad1 u32`, `cgroup_id u64`, `ts_ns u64` (`bpf_ktime_get_ns`), `facts [u32; NGROUPS]`, `_pad2 u32`.

`EventKind` (`hdr.kind`): Exec 0, Fork 1, Exit 2, Connect 3, Listen 4, Open 5, WriteRefused 6, Memfd 7, Ptrace 8, Module 9, Bpf 10, Signal 11.

`KVerdict` (`hdr.kverdict`): None 0, Denied 1, WouldDeny 2.

Payload variant per kind: Exec -> `ExecPayload{exe[256],argv[256],exe_len,argv_len,mnt_id}`; Fork/Exit -> `ProcPayload{child_pid,exit_code}`; Connect/Listen -> `NetPayload{family(2/10),proto,addr[16],port}`; Open/WriteRefused -> `OpenPayload{path[256],path_len,dev_class(0 none,1 camera,2 mic,3 input,4 uinput,5 hidraw),mode}`; Memfd -> `MemfdPayload{name[64],flags}`; Ptrace -> `PtracePayload{target_pid,target_uid,mode}`; Module -> `ModulePayload{name[64],read_id}`; Bpf -> `BpfPayload{cmd,prog_type}`; Signal -> `SignalPayload{target_pid,sig}`.

Note: Exec `exe`/`argv` are NOT filled by the kernel (only `mnt_id` and the facts); resolve from `/proc/<pid>`.

## Load sequence

1. `aya::Ebpf::load(include_bytes_aligned!(...))` the embedded object.
2. `let btf = Btf::from_sys_fs()?;`
3. Write `CONFIG`, seed `HEARTBEAT[0]` with the current monotonic ns, populate `RULES`/`RULE_COUNT`/`MOUNTS`/`CIDRS`/`PORTS`/`UID_LITERALS`, and `GUARDED_INODES`. Do this before attaching.
4. LSM programs: `Lsm::load("<KERNEL HOOK NAME>", &btf)` then `attach()`. Pass the **hook name**, not the program name. Program -> hook: `exec`->`bprm_check_security`, `connect`->`socket_connect`, `sendmsg`->`socket_sendmsg`, `listen`->`socket_listen`, `open`->`file_open`, `ptrace`->`ptrace_access_check`, `module_read`->`kernel_read_file`, `module_data`->`kernel_load_data`, `signal`->`task_kill`, `guard_unlink`->`inode_unlink`, `guard_rename`->`inode_rename`, `guard_truncate`->`path_truncate`, `bpf`->`bpf`.
5. BTF tracepoints: `BtfTracePoint::load(tp, &btf)` + `attach()`: `fork`->`sched_process_fork`, `exit`->`sched_process_exit`.
6. fexit: `FExit::load("path_openat", &btf)` + `attach()` for `write_refused`.
7. Plain tracepoint: `TracePoint` program `memfd` -> `attach("syscalls", "sys_enter_memfd_create")`.
8. Take the `EVENTS` ring buffer and start the heartbeat thread, then attach the `bpf` LSM last so the loader's own setup `bpf()` calls are not observed.
9. Pin maps and programs under `/sys/fs/bpf/aios-sentinel/` so the kernel side outlives the daemon (lockdown then engages when the heartbeat goes stale). `ebpf-loadtest` does not pin; S3 must.

## `CONFIG` fields the daemon must write (`KConfig`, 24 bytes)

- `sentineld_tgid`: the daemon's own tgid (`std::process::id()`); exempts it from self-guard and quarantine.
- `usr_mnt_id`: mount id of `/usr`, from `/proc/self/mountinfo` (field 1 of the mount holding `/usr/bin`). Lockdown allows exec only from this mount.
- `lockdown_after_ns`: heartbeat staleness threshold (loadtest uses 1.5 s).
- `flags`: `CFG_ENFORCE = 1<<0` (Deny+Enforce rules actually block; otherwise they report `WouldDeny`), `CFG_SELFGUARD = 1<<1` (refuse signals aimed at the daemon, etc.).

## Heartbeat

Write `HEARTBEAT[0] = clock_gettime(CLOCK_MONOTONIC)` in ns at least every ~500 ms to 1 s (loadtest: 500 ms). If `now - HEARTBEAT[0] > lockdown_after_ns` the kernel side enters lockdown (counted in `LOCKDOWN_COUNTS`). `HEARTBEAT[0] == 0` means "not started", lockdown inactive.

## What S3 must still build

- Resolve exec `exe`/`argv` from `/proc/<pid>/exe` and `cmdline`.
- Compute `env_ld` / `stdio_socket` facts in user space for the alert/freeze rules using them.
- Self-guard's BPF map-detach / `*_GET_FD_BY_ID` clause, and `SOCK_DESTROY` for freeze (sock_diag).
- Pinning under `/sys/fs/bpf/aios-sentinel/`, drain of `EVENTS`, `DROPS` monitoring, rule-pack reload.
- Cleanup: an unused `shim_filename` dead-code warning remains in the eBPF build. The `socket_sendmsg` quarantine deny and the daemon-can-still-write-guarded-files path were not VM-exercised.

## Implementation gotchas

- Chained LSM verdicts are read as `i64` (sign of `-EPERM`); `security_bpf`/`task_kill` are 4-arg hooks (chained verdict at `arg(4)`).
- The rule walk uses `bpf_loop` (inlined matcher over `MAX_RULES` blew the instruction limit).
- `.ko.zst` module loads report `READING_MODULE_COMPRESSED = 7`.
- `exe_on` needs an EXACT mount-point match (see `mount_id_for` in the loadtest); longest-prefix would map `/`.
- `write_refused` is `fexit/path_openat` on `-EROFS` (`do_filp_open` is not in this kernel's BTF).

See design §17.7 for the full S2 outcomes.
