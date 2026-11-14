# Sentinel S2 — eBPF Kernel Layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `sentinel-ebpf` — the Aya kernel programs (observers + LSM deny + self-guard + heartbeat lockdown + quarantine enforcement) with C CO-RE shims, the `cargo build`-time object embedding (`aya-build`), and a virtme-ng VM harness that loads, attaches, and behaviourally verifies them — so the kernel object builds in `make check` and its behaviour is proven in a KVM VM.

**Architecture:** One eBPF ELF object (`sentinel-ebpf`, built for `bpfel-unknown-none` on the pinned nightly, linked by `bpf-linker --btf`) carries every Sentinel kernel program. Kernel-struct field reads that must survive a kernel-version change live in a small C shim (`c/core.c`, CO-RE via `BPF_CORE_READ_INTO`) linked into the same object; all policy logic, maps and event emission stay in Rust. The object shares the `sentinel-common` data contract (`Facts`, `KRule`, `eval`, and the new fixed-size wire events) with user space, so the kernel and the future `sentineld` (S3) evaluate rules with identical code. The BPF verifier runs only in the VM, so each kernel program's real acceptance test is a virtme-ng assertion, not `make check` (which proves only that the object builds).

**Tech Stack:** Rust (Aya `aya-ebpf` 0.3 / `aya` 0.16, nightly-2026-11-03, target `bpfel-unknown-none`, `-Z build-std=core`), C CO-RE shim (clang 23, libbpf headers, `bpf-linker --btf`), `aya-build` 0.2.1 (build-script object build), virtme-ng 1.42 (`uvx --from virtme-ng vng`, host kernel, `--user root`) for the VM harness, `xtask` for VM orchestration.

**Scope boundary.** S2 produces the kernel object + its build + the VM harness + a minimal load-test binary (`ebpf-loadtest`) that stands in for the daemon so the programs can be proven in isolation. The real daemon (`sentineld`: ring-buffer reader, process table, actions, alert store, varlink) is **S3** and is out of scope here. Where a program needs a userspace decision at runtime (e.g. populating rule tables, writing the heartbeat, resolving `exe_on` mounts), `ebpf-loadtest` does the minimum to exercise the kernel path; S3 replaces it.

---

## Spec amendments that shape S2 (from §17 of the design)

1. **CO-RE via C shims (§17.1).** Rust eBPF can't emit CO-RE relocations. Every kernel-struct field read goes through `c/core.c` (`BPF_CORE_READ_INTO`), compiled `clang -target bpfel -O2 -g -emit-llvm -c` and linked by `bpf-linker --btf`. Rust never hard-codes a kernel struct offset.
2. **Socket destruction from user space (§17.2).** No socket-iterator program in Aya. S2 implements only the **in-kernel** half of `freeze`: the `QUARANTINE` map + `socket_connect`/`socket_sendmsg` deny for a quarantined cgroup. The `SOCK_DESTROY` enumeration is `sentineld` (S3).
3. **`aya-build` build-script, not `cargo xtask build`, for the object (§17.3).** A plain `cargo build` of the host crate that embeds the object (here `ebpf-loadtest`; in S3, `sentineld`) builds everything via an `aya-build` build-script. `xtask` is kept only for the S2 VM tests.
4. **`any = true` predicate (§17.4)** — kernel-evaluable, already compiled by `sentinel-rules` (S1) into an all-zero `KRule`; the kernel's `eval` already matches it.
5. **`managed_home = true` (§17.5)** — a *user-space* predicate; the kernel does not evaluate it. `write_refused` events carry the raw path; S3 classifies.
6. **`exe_on` by mount id (§17.6).** The kernel reads the exec file's VFS `mnt_id` (C shim) and looks it up in the `MOUNTS` map (mnt_id → slot bit). The loader populates `MOUNTS` from resolved rule paths.

---

## File structure

**New crate `sentinel/crates/sentinel-ebpf/`** (the kernel object; one bin target, many programs):

| File | Responsibility |
|---|---|
| `Cargo.toml` | ebpf bin crate; deps `aya-ebpf` 0.3, `aya-log-ebpf`, `sentinel-common` (path, `default-features=false`). `[[bin]] name="sentinel-ebpf", path="src/main.rs"`. `[profile.*] panic="abort"`. |
| `.cargo/config.toml` | default `target = "bpfel-unknown-none"`, `build-std = ["core"]`, and the `rustflags` note for the C-shim link args (emitted by `build.rs`, not hard-coded here). |
| `build.rs` | Compile `c/core.c` → `$OUT_DIR/core.bc` with `clang`; emit `cargo:rustc-link-arg=--btf` and `cargo:rustc-link-arg=<OUT_DIR>/core.bc`; `rerun-if-changed` on `c/`. |
| `c/core.c` | **All** CO-RE kernel-struct field reads (`BPF_CORE_READ_INTO`): task pid/ppid/uid/euid, cgroup id, `mnt_id` of a file, `linux_binprm` flags source, socket family/addr/port, `file`→path dentry, ptrace task identities, module/bpf args. |
| `c/vmlinux_min.h` | Minimal, committed, CO-RE kernel type header (only the structs/fields the shim reads), wrapped in `#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to=record)`. Hermetic: no `bpftool`/`/sys` at build time. |
| `c/shim_types.h` | POD output structs the shim fills, mirrored `#[repr(C)]` in `src/shim.rs`. |
| `src/main.rs` | `#![no_std] #![no_main]`, module decls, panic handler. |
| `src/shim.rs` | The C-shim `extern "C"` block + safe wrappers. |
| `src/maps.rs` | Every `#[map]` definition (names fixed below). |
| `src/emit.rs` | `reserve()` ring-buffer helper + `DROPS` bump. |
| `src/facts_kern.rs` | Build a `Facts` from an event's raw fields + the lookup maps (mirrors `sentinel-rules` fact construction, kernel-side). |
| `src/engine.rs` | Kernel rule evaluation + `lockdown_active()` + self-guard predicate helpers. |
| `src/observe.rs` | The observer programs (exec, fork, exit, connect, listen, open, memfd, ptrace, module, bpf, signal, write_refused). |
| `src/guard.rs` | Self-guard programs + heartbeat-lockdown enforcement + quarantine enforcement. |

**New crate `sentinel/crates/ebpf-loadtest/`** (userspace stand-in for the daemon, used only by the VM harness and `make check`'s object-build):

| File | Responsibility |
|---|---|
| `Cargo.toml` | `aya` 0.16, `sentinel-common`, `sentinel-rules` (path), `anyhow`, `clap`, `libc`. |
| `build.rs` | `aya_build::build_ebpf` builds `sentinel-ebpf` into `$OUT_DIR/sentinel-ebpf` (the §17.3 mechanism). |
| `src/main.rs` | Subcommands the harness drives: `selftest`, `maps`, `load` (load, pin, populate maps from the default pack, write heartbeat, stream ringbuf as JSON), `heartbeat --stop`, `quarantine-add <cgid>`, helpers. |

**New `sentinel/xtask/`** (`Cargo.toml`, `src/main.rs`): `xtask build-ebpf` (object only), `xtask vmtest [scenario]` (boot virtme-ng, run a harness scenario).

**New `sentinel/tests/vm/`**: `harness.sh` (boot virtme-ng + run a scenario in-VM, collect results), `scenarios/*.sh` (one per behaviour), `lib.sh` (assert helpers). Local-only (needs KVM); not in `make check`.

**Modify `sentinel/crates/sentinel-common/`**: add `src/wire.rs` (fixed-size events + map value types), export from `lib.rs`.

**Modify `sentinel/Cargo.toml`**: add `crates/ebpf-loadtest` and `xtask` to `members`; `exclude` `crates/sentinel-ebpf` (built for a different target). Add workspace deps `aya`, `anyhow`, `clap`, `libc`.

**Modify root `Makefile`**: `sentinel-check` also builds the object (`cargo build -p ebpf-loadtest`); new `sentinel-vmtest` target (local, KVM); `make tools` installs `bpf-linker` (pinned) and asserts `clang`.

---

## Shared contract reference (every task uses these exact names)

### Wire events — `sentinel-common/src/wire.rs`

`no_std`, `repr(C)`, POD. The kernel writes a `RawEvent` into the ring buffer; `ebpf-loadtest` (and S3's `sentineld`) read it back by `core::ptr::read`. Field names below are canonical — do not rename.

```rust
//! Fixed-size events on the ring buffer (§4), shared by the kernel programs and
//! the userspace reader. `repr(C)`, POD, no padding surprises (asserted below).

use crate::event::EventKind;
use crate::facts::NGROUPS;

pub const EXE_LEN: usize = 256;
pub const ARGV_LEN: usize = 256;
pub const PATH_LEN: usize = 256;
pub const NAME_LEN: usize = 64;

/// Kernel verdict carried on the event. User space derives the full outcome.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KVerdict {
    None = 0,
    Denied = 1,
    WouldDeny = 2,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EventHeader {
    pub kind: u8,            // EventKind discriminant
    pub kverdict: u8,        // KVerdict
    pub _pad0: [u8; 2],
    pub matched_rule: i32,   // index of the matched kernel rule, -1 if none
    pub pid: u32,            // tgid (userspace pid)
    pub tid: u32,            // kernel pid (thread id)
    pub ppid: u32,
    pub uid: u32,            // real uid
    pub euid: u32,
    pub _pad1: u32,
    pub cgroup_id: u64,
    pub ts_ns: u64,          // bpf_ktime_get_ns
    pub facts: [u32; NGROUPS],
    pub _pad2: u32,          // pad header to an 8-byte multiple (80 bytes)
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecPayload {
    pub exe: [u8; EXE_LEN],
    pub argv: [u8; ARGV_LEN],
    pub exe_len: u16,
    pub argv_len: u16,
    pub mnt_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetPayload {
    pub family: u16,
    pub proto: u16,
    pub addr: [u8; 16],
    pub port: u16,
    pub _pad: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OpenPayload {
    pub path: [u8; PATH_LEN],
    pub path_len: u16,
    pub dev_class: u8,   // 0 none,1 camera,2 mic,3 input,4 uinput,5 hidraw
    pub _pad: u8,
    pub mode: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PtracePayload {
    pub target_pid: u32,
    pub target_uid: u32,
    pub mode: u32,
    pub _pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcPayload { // fork / exit
    pub child_pid: u32,
    pub exit_code: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ModulePayload {
    pub name: [u8; NAME_LEN],
    pub read_id: u32,
    pub _pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BpfPayload {
    pub cmd: u32,
    pub prog_type: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SignalPayload {
    pub target_pid: u32,
    pub sig: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MemfdPayload {
    pub name: [u8; NAME_LEN],
    pub flags: u32,
    pub _pad: u32,
}

/// Fixed-size payload union; the reader switches on `hdr.kind`.
#[repr(C)]
#[derive(Clone, Copy)]
pub union EventPayload {
    pub exec: ExecPayload,
    pub net: NetPayload,
    pub open: OpenPayload,
    pub ptrace: PtracePayload,
    pub proc_: ProcPayload,
    pub module: ModulePayload,
    pub bpf: BpfPayload,
    pub signal: SignalPayload,
    pub memfd: MemfdPayload,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawEvent {
    pub hdr: EventHeader,
    pub payload: EventPayload,
}

// ---- map value types (shared so the loader fills them identically) ----

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CidrEntry {
    pub addr: [u8; 16],
    pub prefix: u8,
    pub family: u8,
    pub slot: u8,
    pub used: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PortRange {
    pub lo: u16,
    pub hi: u16,
    pub slot: u8,
    pub used: u8,
    pub _pad: [u8; 2],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KConfig {
    pub lockdown_after_ns: u64,
    pub sentineld_tgid: u32,
    pub flags: u32,
}

pub const CFG_ENFORCE: u32 = 1 << 0;
pub const CFG_SELFGUARD: u32 = 1 << 1;
```

**Compile-time asserts (in `wire.rs`, Task 1):** every struct is `Copy`, `RawEvent` size a multiple of 8, `size_of::<EventHeader>() == 80`, each payload `<= size_of::<ExecPayload>()`. These guard the kernel↔user ABI.

### Maps — `sentinel-ebpf/src/maps.rs` (names are the ABI the loader binds by)

| Name | Type | Entries | Purpose |
|---|---|---|---|
| `EVENTS` | `RingBuf` | 8 MiB | all events |
| `DROPS` | `PerCpuArray<u64>` | 1 | ring reservation failures (`sensor-overflow`, §4) |
| `HEARTBEAT` | `Array<u64>` | 1 | `sentineld`'s last monotonic ns (§8.3) |
| `LOCKDOWN_COUNTS` | `Array<u64>` | `NHOOKS` (8) | per-hook lockdown denials |
| `RULES` | `Array<KRule>` | `MAX_RULES` (64) | compiled kernel rules |
| `RULE_COUNT` | `Array<u32>` | 1 | live entries in `RULES` |
| `MOUNTS` | `HashMap<u64,u32>` | `MAX_MOUNTS` (32) | `mnt_id` → `slot_bit` (`exe_on`) |
| `CIDRS` | `Array<CidrEntry>` | `MAX_CIDRS` (32) | `dest` prefixes |
| `PORTS` | `Array<PortRange>` | `MAX_PORT_SETS` (32) | `port` ranges |
| `UID_LITERALS` | `Array<u32>` | `MAX_UID_LITERALS` (30) | literal uids per slot |
| `QUARANTINE` | `HashMap<u64,u8>` | 1024 | quarantined cgroup ids (§6) |
| `GUARDED_INODES` | `HashMap<u64,u8>` | 64 | Sentinel's bpffs + log inode numbers (§8.2) |
| `CONFIG` | `Array<KConfig>` | 1 | runtime config |

`LOCKDOWN_COUNTS` hook indices (fixed): `0 connect, 1 exec, 2 sendmsg, 3 listen, 4 open, 5 ptrace, 6 bpf, 7 reserved`.

### Grounded API patterns (verified against Aya 0.16 / aya-ebpf 0.3, 2026-11-13)

**LSM program + deny** (`ret` is the chained prior verdict — never weaken a non-zero `ret`):
```rust
use aya_ebpf::{cty::c_int, macros::lsm, programs::LsmContext};

#[lsm(hook = "socket_connect")]
pub fn socket_connect(ctx: LsmContext) -> i32 {
    match unsafe { try_connect(&ctx) } { Ok(v) => v, Err(v) => v }
}

unsafe fn try_connect(ctx: &LsmContext) -> Result<i32, i32> {
    let ret: c_int = ctx.arg(3);   // prior LSM verdict (index = hook args + 1)
    if ret != 0 { return Err(ret); }
    // build facts, evaluate; on deny: Err(-libc::EPERM as i32)
    Ok(0)
}
```
Hook arg indices follow `lsm_hook_defs.h`: `socket_connect(sock, address, addrlen)` → `arg(0..=2)`, chained `ret` at `arg(3)`. Pass opaque pointers (`ctx.arg::<*const c_void>(n)`) straight into the C shim; never deref in Rust. **`-EPERM` = `-1`.**

**RingBuf emit** (reserve writes into ring memory — dodges the 512-byte stack limit):
```rust
if let Some(mut e) = crate::emit::reserve() {
    let p = e.as_mut_ptr();              // *mut RawEvent into the ring
    unsafe { (*p).hdr.kind = EventKind::Connect as u8; /* fill via shim copies */ }
    e.submit(0);
}
```

**C shim** (`c/core.c`) and its Rust binding:
```c
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
```
```rust
// src/shim.rs
use core::ffi::c_void;
#[repr(C)] pub struct TaskIds { pub pid: u32, pub tid: u32, pub ppid: u32 }
unsafe extern "C" { fn shim_task_ids(task: *const c_void, out: *mut TaskIds) -> i32; }
pub unsafe fn task_ids(task: *const c_void) -> Option<TaskIds> {
    let mut o = core::mem::zeroed();
    if shim_task_ids(task, &mut o) == 0 { Some(o) } else { None }
}
```
Each shim-output struct lives in `c/shim_types.h` and is mirrored `#[repr(C)]` in `src/shim.rs`. Keep the two in lockstep.

**`build.rs` — `sentinel-ebpf`** (compiles the shim, wires link args):
```rust
use std::{env, path::PathBuf, process::Command};
fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let bc = out.join("core.bc");
    let status = Command::new("clang")
        .args(["-target","bpfel","-O2","-g","-emit-llvm","-Wno-unknown-attributes","-c","c/core.c","-o"])
        .arg(&bc).status().expect("clang for the C shim");
    assert!(status.success(), "C shim failed to compile");
    println!("cargo:rustc-link-arg=--btf");
    println!("cargo:rustc-link-arg={}", bc.display());
    println!("cargo:rerun-if-changed=c/core.c");
    println!("cargo:rerun-if-changed=c/vmlinux_min.h");
    println!("cargo:rerun-if-changed=c/shim_types.h");
}
```

**`build.rs` — `ebpf-loadtest`** (embeds the object, §17.3):
```rust
use aya_build::{build_ebpf, Package, Toolchain};
use cargo_metadata::MetadataCommand;
fn main() -> anyhow::Result<()> {
    let md = MetadataCommand::new().no_deps().exec()?;
    let p = md.packages.into_iter().find(|p| p.name == "sentinel-ebpf").expect("sentinel-ebpf");
    let root = p.manifest_path.parent().unwrap().to_string();
    build_ebpf([Package { name: "sentinel-ebpf".into(), root_dir: root, ..Default::default() }],
               Toolchain::default())?;
    Ok(())
}
```
Loader embeds it: `aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/sentinel-ebpf"))`.

**virtme-ng** (host kernel, root, repo mounted — no image build):
```bash
uvx --from virtme-ng vng --run "$(uname -r)" --user root --rwdir "$PWD/sentinel" \
    --script-sh "sentinel/tests/vm/scenarios/$SCENARIO.sh"
```
Needs `busybox` on `PATH` (`build/hosttools/root/usr/bin/busybox`, gitignored, sig-verified — S1 note) and `PATH=$HOME/.cargo/bin:$PATH` for the host build that precedes the boot.

### Committed minimal `vmlinux_min.h` (hermetic CO-RE)

Rather than generate a multi-MB `vmlinux.h` with `bpftool` at build time (which would make `make check` depend on `/sys/kernel/btf` and `bpftool`), commit a minimal header with only the shim's types, each field CO-RE-relocatable:

```c
#ifndef SENTINEL_VMLINUX_MIN_H
#define SENTINEL_VMLINUX_MIN_H
typedef unsigned char __u8;  typedef unsigned short __u16;
typedef unsigned int  __u32; typedef unsigned long long __u64;
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
```
CO-RE relocates by field **name**, so a partial struct is valid as long as names match the target BTF; Task 3 establishes the header and later tasks extend it. Task 3 confirms the exact `cred`/`task_struct` field forms against the host BTF with one `bpftool btf dump file /sys/kernel/btf/vmlinux format c | grep -A3 'struct cred'` and records it in a comment.

---

## Task list

Phase A — contract + scaffolding (1–5) · Phase B — maps + heartbeat (6–7) · Phase C — observers (8–18) · Phase D — rule eval + deny (19–21) · Phase E — self-guard + lockdown + quarantine (22–27) · Phase F — build + VM harness + handoff (28–31).

Each task touching only pure Rust (`sentinel-common`, loader logic) is TDD with `cargo test` in `make check`. Each task that adds or changes a **kernel program** is verified in the VM: its acceptance step runs `cargo run -p xtask -- vmtest <scenario>` and asserts the behaviour; a verifier rejection is debugged with **superpowers:systematic-debugging** inside the VM (read the verifier log, trace the offending instruction, fix, reload) before the task is done. Commit at the end of every task.

**Commit trailer (every task's commit):**
```
Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_017tTdALyhuFv5WMqfWC2UMV
```

---

### Task 1: Wire events + map value types in `sentinel-common`

**Files:**
- Create: `sentinel/crates/sentinel-common/src/wire.rs`
- Modify: `sentinel/crates/sentinel-common/src/lib.rs`
- Test: in `wire.rs` (`#[cfg(test)]`)

- [ ] **Step 1: Write failing tests** — create `wire.rs` with the contract module above plus:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, size_of};

    #[test]
    fn header_is_80_bytes_8_aligned() {
        assert_eq!(size_of::<EventHeader>(), 80);
        assert_eq!(size_of::<RawEvent>() % 8, 0);
        assert!(align_of::<RawEvent>() <= 8);
    }
    #[test]
    fn exec_is_the_largest_payload() {
        let m = size_of::<ExecPayload>();
        assert!(size_of::<NetPayload>() <= m);
        assert!(size_of::<OpenPayload>() <= m);
        assert!(size_of::<EventPayload>() <= m);
    }
    #[test]
    fn kverdict_discriminants_are_stable() {
        assert_eq!(KVerdict::None as u8, 0);
        assert_eq!(KVerdict::Denied as u8, 1);
        assert_eq!(KVerdict::WouldDeny as u8, 2);
    }
    #[test]
    fn raw_event_is_pod_copy() { fn is_copy<T: Copy>() {} is_copy::<RawEvent>(); }
}
```
- [ ] **Step 2: Verify it fails** — `cd sentinel && cargo test -p sentinel-common wire` → FAIL (module not declared / sizes off).
- [ ] **Step 3: Implement** — paste the full `wire.rs` contract. If `header_is_80_bytes` fails, adjust only `_pad*` to reach 80 (comment the arithmetic); do not reorder named fields.
- [ ] **Step 4: Export** — `lib.rs`: `pub mod wire;` and `pub use wire::{RawEvent, EventHeader, EventPayload, KVerdict, CidrEntry, PortRange, KConfig, CFG_ENFORCE, CFG_SELFGUARD, EXE_LEN, ARGV_LEN, PATH_LEN, NAME_LEN};`
- [ ] **Step 5: Verify** — `cargo test -p sentinel-common` PASS; `cargo fmt --all`; `cargo clippy -p sentinel-common -- -D warnings` clean.
- [ ] **Step 6: Commit** — `git add sentinel/crates/sentinel-common && git commit` (`feat(sentinel-common): fixed-size wire events and map value types`).

---

### Task 2: `sentinel-ebpf` crate skeleton building for `bpfel-unknown-none`

**Files:**
- Create: `sentinel/crates/sentinel-ebpf/{Cargo.toml,.cargo/config.toml,src/main.rs,rust-toolchain.toml}`
- Modify: `sentinel/Cargo.toml` (`exclude = ["crates/sentinel-ebpf"]`)

- [ ] **Step 1: `Cargo.toml`**
```toml
[package]
name = "sentinel-ebpf"
version = "0.1.0"
edition = "2021"
publish = false

[dependencies]
aya-ebpf = "0.3"
aya-log-ebpf = "0.1"
sentinel-common = { path = "../sentinel-common", default-features = false }

[[bin]]
name = "sentinel-ebpf"
path = "src/main.rs"

[profile.dev]
panic = "abort"
[profile.release]
panic = "abort"
```
- [ ] **Step 2: `.cargo/config.toml`**
```toml
[build]
target = "bpfel-unknown-none"

[unstable]
build-std = ["core"]
```
- [ ] **Step 3: `rust-toolchain.toml`** — copy the workspace one (channel `nightly-2026-11-03`, components incl. `rust-src`).
- [ ] **Step 4: Minimal program** — `src/main.rs`:
```rust
#![no_std]
#![no_main]

use aya_ebpf::{macros::tracepoint, programs::TracePointContext};

#[tracepoint]
pub fn probe(_ctx: TracePointContext) -> u32 { 0 }

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }
```
- [ ] **Step 5: Exclude from the host workspace build** — `sentinel/Cargo.toml`: add `exclude = ["crates/sentinel-ebpf"]`.
- [ ] **Step 6: Verify** — `cd sentinel/crates/sentinel-ebpf && PATH="$HOME/.cargo/bin:$PATH" cargo build --release` builds; `ls target/bpfel-unknown-none/release/sentinel-ebpf` exists.
- [ ] **Step 7: Commit** (`feat(sentinel-ebpf): crate skeleton building for bpfel-unknown-none`).

---

### Task 3: C CO-RE shim scaffolding + `build.rs` link wiring

**Files:**
- Create: `sentinel/crates/sentinel-ebpf/{c/core.c,c/vmlinux_min.h,c/shim_types.h,build.rs,src/shim.rs}`
- Modify: `sentinel/crates/sentinel-ebpf/src/main.rs` (`mod shim;`, keep one shim symbol live)

- [ ] **Step 1: `c/shim_types.h`**
```c
#ifndef SENTINEL_SHIM_TYPES_H
#define SENTINEL_SHIM_TYPES_H
struct sentinel_task_ids { unsigned int pid; unsigned int tid; unsigned int ppid; };
#endif
```
- [ ] **Step 2: `c/vmlinux_min.h`** — the reference minimal header. Confirm the field path first:
```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c | grep -m1 -A6 'struct task_struct {'
```
- [ ] **Step 3: `c/core.c`** — include the headers; define `shim_task_ids` (reference).
- [ ] **Step 4: `build.rs`** — the `sentinel-ebpf` build.rs (reference).
- [ ] **Step 5: `src/shim.rs`** — `TaskIds` + `task_ids` wrapper (reference).
- [ ] **Step 6: Keep the symbol live** — `src/main.rs`: `mod shim;` and inside `probe` add `let _ = unsafe { shim::task_ids(core::ptr::null()) };`
- [ ] **Step 7: Verify the shim links + a CO-RE record emits**
```bash
cd sentinel/crates/sentinel-ebpf
PATH="$HOME/.cargo/bin:$PATH" cargo build --release
llvm-objdump -dr target/bpfel-unknown-none/release/sentinel-ebpf | grep -i 'CO-RE' | head
```
Expected: builds; at least one `CO-RE ... task_struct` line prints. None → shim not linked (`link-arg` path) or `--btf` missing; debug before continuing.
- [ ] **Step 8: Commit** (`feat(sentinel-ebpf): C CO-RE shim scaffolding and build-script link wiring`).

---

### Task 4: `ebpf-loadtest` crate — embeds + loads the object

**Files:**
- Create: `sentinel/crates/ebpf-loadtest/{Cargo.toml,build.rs,src/main.rs}`
- Modify: `sentinel/Cargo.toml` (members + workspace deps `aya="0.16"`, `anyhow="1"`, `clap={version="4",features=["derive"]}`, `libc="0.2"`, `aya-build="0.2.1"`, `cargo_metadata="0.18"`)

- [ ] **Step 1: `Cargo.toml`** — bin crate: deps `aya`, `sentinel-common`, `sentinel-rules`, `anyhow`, `clap`, `libc`; `[build-dependencies] aya-build, cargo_metadata, anyhow`.
- [ ] **Step 2: `build.rs`** — the `aya_build::build_ebpf` script (reference).
- [ ] **Step 3: `src/main.rs` — `selftest`**
```rust
use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)] struct Cli { #[command(subcommand)] cmd: Cmd }
#[derive(Subcommand)] enum Cmd { Selftest }

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Selftest => {
            let data = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/sentinel-ebpf"));
            let bpf = aya::Ebpf::load(data)?;
            let names: Vec<_> = bpf.programs().map(|(n, _)| n.to_string()).collect();
            println!("loaded object with {} programs: {:?}", names.len(), names);
            Ok(())
        }
    }
}
```
- [ ] **Step 4: Verify the host build drives the object build**
```bash
cd sentinel && PATH="$HOME/.cargo/bin:$PATH" cargo build -p ebpf-loadtest
ls target/debug/build/ebpf-loadtest-*/out/sentinel-ebpf
```
Expected: builds; embedded object present. (This becomes the `make check` object-build gate, Task 28.)
- [ ] **Step 5: fmt/clippy** — `cargo fmt --all`; `cargo clippy -p ebpf-loadtest -- -D warnings`.
- [ ] **Step 6: Commit** (`feat(ebpf-loadtest): embed and load the kernel object via aya-build`).

---

### Task 5: virtme-ng VM harness skeleton + `selftest` scenario

**Files:**
- Create: `sentinel/xtask/{Cargo.toml,src/main.rs}`, `sentinel/tests/vm/{harness.sh,lib.sh,scenarios/selftest.sh}`
- Modify: `sentinel/Cargo.toml` (add `xtask` to members)

- [ ] **Step 1: `tests/vm/lib.sh`**
```bash
assert_contains() { grep -qF -- "$2" "$1" || { echo "ASSERT FAIL: '$2' not in $1"; cat "$1"; exit 1; }; }
```
- [ ] **Step 2: `tests/vm/scenarios/selftest.sh`** (runs in-VM as root)
```bash
#!/bin/sh
set -eu
cd /sentinel
./target/debug/ebpf-loadtest selftest | tee /tmp/out.txt
grep -q 'loaded object with' /tmp/out.txt
```
- [ ] **Step 3: `tests/vm/harness.sh`**
```bash
#!/usr/bin/env bash
set -euo pipefail
SCEN="${1:?scenario}"
export PATH="$HOME/.cargo/bin:$PATH:$PWD/build/hosttools/root/usr/bin"
( cd sentinel && cargo build -p ebpf-loadtest )
uvx --from virtme-ng vng --run "$(uname -r)" --user root \
    --rwdir "$PWD/sentinel" --script-sh "sentinel/tests/vm/scenarios/${SCEN}.sh"
```
(Confirm the vng mount path on first run and align the scenario `cd` to it.)
- [ ] **Step 4: `xtask`** — `vmtest` shells to the harness:
```rust
use std::process::Command;
fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("vmtest") => {
            let scen = a.get(2).expect("scenario");
            let st = Command::new("bash").arg("tests/vm/harness.sh").arg(scen).status().expect("harness");
            std::process::exit(st.code().unwrap_or(1));
        }
        _ => { eprintln!("usage: xtask vmtest <scenario>"); std::process::exit(2); }
    }
}
```
- [ ] **Step 5: Verify in the VM** — `cd sentinel && cargo run -p xtask -- vmtest selftest`. Expected: boots, prints `loaded object with 1 programs: ["probe"]`, exit 0. Kernel not found → pass `--run <vmlinuz>`; busybox missing → ensure `build/hosttools/root/usr/bin` on PATH.
- [ ] **Step 6: Commit** (`test(sentinel): virtme-ng harness and selftest scenario`).

---

### Task 6: Map definitions + ring-buffer emit helper

**Files:**
- Create: `sentinel/crates/sentinel-ebpf/src/{maps.rs,emit.rs}`
- Modify: `sentinel-ebpf/src/main.rs` (`mod maps; mod emit;`), `ebpf-loadtest/src/main.rs` (`maps` subcommand), `tests/vm/scenarios/maps.sh`

- [ ] **Step 1: `maps.rs`** — every map from the contract table:
```rust
use aya_ebpf::{macros::map, maps::{Array, HashMap, PerCpuArray, RingBuf}};
use sentinel_common::rule::{KRule, MAX_CIDRS, MAX_MOUNTS, MAX_PORT_SETS, MAX_RULES, MAX_UID_LITERALS};
use sentinel_common::wire::{CidrEntry, KConfig, PortRange};

pub const RING_BYTES: u32 = 8 * 1024 * 1024;
pub const NHOOKS: u32 = 8;

#[map] pub static EVENTS: RingBuf = RingBuf::with_byte_size(RING_BYTES, 0);
#[map] pub static DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map] pub static HEARTBEAT: Array<u64> = Array::with_max_entries(1, 0);
#[map] pub static LOCKDOWN_COUNTS: Array<u64> = Array::with_max_entries(NHOOKS, 0);
#[map] pub static RULES: Array<KRule> = Array::with_max_entries(MAX_RULES as u32, 0);
#[map] pub static RULE_COUNT: Array<u32> = Array::with_max_entries(1, 0);
#[map] pub static MOUNTS: HashMap<u64, u32> = HashMap::with_max_entries(MAX_MOUNTS as u32, 0);
#[map] pub static CIDRS: Array<CidrEntry> = Array::with_max_entries(MAX_CIDRS as u32, 0);
#[map] pub static PORTS: Array<PortRange> = Array::with_max_entries(MAX_PORT_SETS as u32, 0);
#[map] pub static UID_LITERALS: Array<u32> = Array::with_max_entries(MAX_UID_LITERALS as u32, 0);
#[map] pub static QUARANTINE: HashMap<u64, u8> = HashMap::with_max_entries(1024, 0);
#[map] pub static GUARDED_INODES: HashMap<u64, u8> = HashMap::with_max_entries(64, 0);
#[map] pub static CONFIG: Array<KConfig> = Array::with_max_entries(1, 0);
```
- [ ] **Step 2: `emit.rs`**
```rust
use aya_ebpf::maps::ring_buf::RingBufEntry;
use crate::maps::{DROPS, EVENTS};
use sentinel_common::wire::RawEvent;

pub fn reserve() -> Option<RingBufEntry<RawEvent>> {
    match EVENTS.reserve::<RawEvent>(0) {
        Some(e) => Some(e),
        None => { if let Some(d) = DROPS.get_ptr_mut(0) { unsafe { *d += 1; } } None }
    }
}
```
- [ ] **Step 3: loader `maps` subcommand** — after load, assert `bpf.map("EVENTS")` … each name is `Some`; print found/missing; non-zero exit if any missing.
- [ ] **Step 4: Verify** — `cargo build -p ebpf-loadtest`; add `scenarios/maps.sh` (`ebpf-loadtest maps`); `cargo run -p xtask -- vmtest maps` — every map found.
- [ ] **Step 5: Commit** (`feat(sentinel-ebpf): map set and ring-buffer emit helper`).

---

### Task 7: Heartbeat write + lockdown staleness helper

**Files:**
- Create: `sentinel/crates/sentinel-ebpf/src/engine.rs` (lockdown only for now)
- Modify: `ebpf-loadtest/src/main.rs` (`load` writes `HEARTBEAT[0]` + a 1 s thread; `heartbeat --stop`), `sentinel-ebpf/src/main.rs` (`mod engine;`), `tests/vm/scenarios/heartbeat.sh`

- [ ] **Step 1: `engine.rs` lockdown helper**
```rust
use aya_ebpf::helpers::bpf_ktime_get_ns;
use crate::maps::{CONFIG, HEARTBEAT, LOCKDOWN_COUNTS};

/// §8.3: lockdown is on when the heartbeat is stale by more than
/// `lockdown_after_ns`. Before the first heartbeat (0) there is no lockdown.
pub fn lockdown_active() -> bool {
    let hb = HEARTBEAT.get(0).copied().unwrap_or(0);
    if hb == 0 { return false; }
    let after = CONFIG.get(0).map(|c| c.lockdown_after_ns).unwrap_or(5_000_000_000);
    let now = unsafe { bpf_ktime_get_ns() };
    now.saturating_sub(hb) > after
}

pub fn count_lockdown(hook: u32) {
    if let Some(p) = LOCKDOWN_COUNTS.get_ptr_mut(hook) { unsafe { *p += 1; } }
}
```
- [ ] **Step 2: loader heartbeat** — `load` writes `HEARTBEAT[0] = CLOCK_MONOTONIC ns` (`clock_gettime`, matching `bpf_ktime_get_ns`) on start and each second; `heartbeat --stop` stops the thread.
- [ ] **Step 3: VM scenario `heartbeat.sh`** — load, confirm lockdown false, stop heartbeat, wait > `lockdown_after`, confirm it flips true. Expose the flag via a test tracepoint that reads `lockdown_active()` and emits it (or an `aya-log` line).
- [ ] **Step 4: Verify** — `cargo run -p xtask -- vmtest heartbeat` passes.
- [ ] **Step 5: Commit** (`feat(sentinel-ebpf): heartbeat read and lockdown staleness check`).

---

### Task 8: exec observer (`bprm_check_security`) + common header fill

Single LSM program for exec: it is synchronous (enables `deny` in Phase D), sees `linux_binprm`, and fires before exec completes. The default-pack **deny** rules that touch exec are `exec-memfd` (F_MEMFD), `exec-deleted` (F_DELETED), `exec-shm`/`exec-tmp` (`exe_on` mnt_id) — so those three facts must be kernel-computed. `env_ld` and `stdio_socket` back only *alert*/*freeze* rules that are user-space anyway (`ld-preload`, `reverse-shell` use the user-space `exe` glob); the kernel emits the exec event and S3 computes those from `/proc/<pid>`. The plan computes the deny-critical flags in-kernel and leaves `env_ld`/`stdio_socket` as `0` with a `// S3: enrich from /proc` note.

**Files:**
- Create: `sentinel/crates/sentinel-ebpf/src/{facts_kern.rs,observe.rs}`
- Modify: `c/shim_types.h`, `c/core.c`, `src/shim.rs` (add the exec-file + current-task shims), `src/main.rs` (`mod facts_kern; mod observe;`), `tests/vm/scenarios/exec.sh`, `ebpf-loadtest` (the `load` subcommand must stream the ring buffer as JSON lines — add it here)

- [ ] **Step 1: Extend the shim** — first delete the scaffolding `probe` tracepoint (and its `shim::task_ids` call) from `src/main.rs`/`observe.rs`; it was only there to prove the toolchain in Tasks 2–7 and is replaced by the real programs now. Then `c/shim_types.h`: replace `sentinel_task_ids` with
```c
struct sentinel_task_core { unsigned int pid,tid,ppid,uid,euid; unsigned long long cgroup_id; };
struct sentinel_exec_info { unsigned int mnt_id; int nlink; int is_memfd; unsigned char name[64]; int name_len; };
```
`c/core.c`:
```c
int shim_current_core(const void *task, struct sentinel_task_core *o) {
    const struct task_struct *t = task;
    int e = 0;
    e |= BPF_CORE_READ_INTO(&o->pid,  t, tgid);
    e |= BPF_CORE_READ_INTO(&o->tid,  t, pid);
    e |= BPF_CORE_READ_INTO(&o->ppid, t, real_parent, tgid);
    e |= BPF_CORE_READ_INTO(&o->uid,  t, cred, uid.val);
    e |= BPF_CORE_READ_INTO(&o->euid, t, cred, euid.val);
    return e;  /* cgroup_id filled by the helper, not here */
}
// bprm->file: nlink (deleted), dentry name (memfd:), f_path.mnt mount id
int shim_exec_info(const void *bprm, struct sentinel_exec_info *o) {
    const struct linux_binprm *b = bprm;
    const struct file *f; const struct dentry *d; struct vfsmount *mnt;
    BPF_CORE_READ_INTO(&f, b, file);
    BPF_CORE_READ_INTO(&o->nlink, f, f_inode, i_nlink);
    BPF_CORE_READ_INTO(&d, f, f_path.dentry);
    const unsigned char *name; BPF_CORE_READ_INTO(&name, d, d_name.name);
    o->name_len = bpf_core_read_str(o->name, sizeof(o->name), name);
    BPF_CORE_READ_INTO(&mnt, f, f_path.mnt);
    /* real_mount(mnt)->mnt_id : mount wraps vfsmount; read via container_of offset.
       vmlinux_min.h declares `struct mount { ... struct vfsmount mnt; int mnt_id; }`;
       the shim recovers it (Task extends the header with the real offsets — confirm
       against host BTF). */
    o->mnt_id = 0; // set by shim_mount_id below
    o->is_memfd = (o->name[0]=='m'&&o->name[1]=='e'&&o->name[2]=='m'&&o->name[3]=='f'&&o->name[4]=='d'&&o->name[5]==':');
    return 0;
}
int shim_mount_id(const void *vfsmnt, int *mnt_id) {
    /* struct mount *m = container_of(vfsmnt, struct mount, mnt); return m->mnt_id */
    const struct mount *m = (const struct mount *)((const char *)vfsmnt - __builtin_offsetof(struct mount, mnt));
    return BPF_CORE_READ_INTO(mnt_id, m, mnt_id);
}
```
Extend `c/vmlinux_min.h` with `struct file { struct inode *f_inode; struct path f_path; }`, `struct path { struct vfsmount *mnt; struct dentry *dentry; }`, `struct inode { unsigned int i_nlink; }`, `struct dentry { struct qstr d_name; }`, `struct qstr { const unsigned char *name; }`, `struct vfsmount {}`, `struct mount { struct vfsmount mnt; int mnt_id; }`, `struct linux_binprm { struct file *file; }`. Confirm `mount.mnt_id` exists in host BTF (`bpftool btf dump file /sys/kernel/btf/vmlinux format c | grep -A20 'struct mount {'`); if the field is `mnt_id` vs `mnt_id` plus a `mnt_group_id`, keep only what you read.

`src/shim.rs`: mirror both structs (`TaskCore{pid,tid,ppid,uid,euid,cgroup_id:u64}`, `ExecInfo{mnt_id:u32,nlink:i32,is_memfd:i32,name:[u8;64],name_len:i32}`) and add `current_core()` (uses `bpf_get_current_task()` for the pointer and `bpf_get_current_cgroup_id()` for `cgroup_id`) and `exec_info(bprm)`.

- [ ] **Step 2: `facts_kern.rs` — header + exec facts**
```rust
use aya_ebpf::helpers::{bpf_get_current_cgroup_id, bpf_ktime_get_ns};
use sentinel_common::facts::*;
use sentinel_common::wire::RawEvent;
use crate::shim::{self, TaskCore};

/// Fill the common header from the current task; returns the task core for reuse.
pub fn fill_header(ev: *mut RawEvent, kind: u8) -> Option<TaskCore> {
    let c = unsafe { shim::current_core()? };
    unsafe {
        (*ev).hdr.kind = kind;
        (*ev).hdr.kverdict = 0;
        (*ev).hdr._pad0 = [0; 2];
        (*ev).hdr.matched_rule = -1;
        (*ev).hdr.pid = c.pid; (*ev).hdr.tid = c.tid; (*ev).hdr.ppid = c.ppid;
        (*ev).hdr.uid = c.uid; (*ev).hdr.euid = c.euid; (*ev).hdr._pad1 = 0;
        (*ev).hdr.cgroup_id = bpf_get_current_cgroup_id();
        (*ev).hdr.ts_ns = bpf_ktime_get_ns();
        (*ev).hdr.facts = [0; NGROUPS];
        (*ev).hdr._pad2 = 0;
    }
    Some(c)
}

/// uid summary facts (§5.2): user (>=1000) / system (<1000) + literal slots (Task 21).
pub fn set_uid_facts(ev: *mut RawEvent, uid: u32) {
    unsafe {
        if uid >= 1000 { (*ev).hdr.facts[G_UID] |= U_USER; }
        else { (*ev).hdr.facts[G_UID] |= U_SYSTEM; }
    }
}
```
- [ ] **Step 3: `observe.rs` — exec program**
```rust
use aya_ebpf::{cty::c_int, macros::lsm, programs::LsmContext};
use core::ffi::c_void;
use sentinel_common::event::EventKind;
use sentinel_common::facts::*;
use crate::{emit, facts_kern, shim};

#[lsm(hook = "bprm_check_security")]
pub fn exec(ctx: LsmContext) -> i32 {
    match unsafe { try_exec(&ctx) } { Ok(v) => v, Err(v) => v }
}

unsafe fn try_exec(ctx: &LsmContext) -> Result<i32, i32> {
    let ret: c_int = ctx.arg(1);
    if ret != 0 { return Err(ret); }
    let bprm: *const c_void = ctx.arg(0);
    let Some(mut e) = emit::reserve() else { return Ok(0); };
    let p = e.as_mut_ptr();
    let Some(core) = facts_kern::fill_header(p, EventKind::Exec as u8) else { e.discard(0); return Ok(0); };
    facts_kern::set_uid_facts(p, core.uid);
    if let Some(info) = shim::exec_info(bprm) {
        (*p).payload.exec.mnt_id = info.mnt_id;
        (*p).payload.exec.exe = [0; sentinel_common::wire::EXE_LEN];
        (*p).payload.exec.argv = [0; sentinel_common::wire::ARGV_LEN];
        (*p).payload.exec.exe_len = 0;  // S3 resolves the full path from /proc; dentry name is in info.name
        (*p).payload.exec.argv_len = 0;
        if info.is_memfd != 0 { (*p).hdr.facts[G_FLAGS] |= F_MEMFD; }
        else if info.nlink == 0 { (*p).hdr.facts[G_FLAGS] |= F_DELETED; }
        // exe_on: mnt_id -> slot bit (Task 21 fills MOUNTS; here consult it)
        if let Some(bit) = crate::maps::MOUNTS.get(&(info.mnt_id as u64)) {
            (*p).hdr.facts[G_MOUNT] |= *bit;
        }
        // env_ld / stdio_socket: 0 here; S3 enriches from /proc for the alert rules.
    }
    e.submit(0);
    Ok(0)   // deny decided in Phase D once the rule engine is wired
}
```
(The `exe`/`argv` strings stay empty in S2 — resolving the full path in-kernel is a bounded-loop headache and only the alert path needs it; S3 fills them from `/proc/<pid>/exe` and `cmdline`. The kernel-critical facts — memfd/deleted/exe_on — are complete.)
- [ ] **Step 4: loader `load` streams the ring buffer** — add `load` to `ebpf-loadtest`: load the object, attach `exec` (as an `Lsm` program, `Btf::from_sys_fs()`, `load("exec",&btf)`, `attach()`), then poll a `RingBuf` userspace reader over `EVENTS`, decoding each `RawEvent` to a JSON line (`{"kind":0,"pid":...,"facts":[...],"flags_memfd":...}`). Keep running until SIGINT.
- [ ] **Step 5: VM scenario `exec.sh`** — start `ebpf-loadtest load &` (background, stdout → `/tmp/ev.jsonl`), give it 1 s, then: build a tiny memfd-exec payload (`memfd_create`+`write`+`fexecve` — ship a 20-line C helper `tests/vm/payloads/memfd_run.c`, compiled in the scenario with the in-VM `clang`/`cc`), run it, run a normal `/bin/true`, stop the loader, then assert `/tmp/ev.jsonl` has an exec event with `flags_memfd` set for the memfd run and a plain exec for `/bin/true`.
```sh
grep -q '"kind":0' /tmp/ev.jsonl && grep -q '"flags_memfd":true' /tmp/ev.jsonl
```
- [ ] **Step 6: Verify** — `cargo run -p xtask -- vmtest exec`. Verifier rejection (likely on the bounded string copy or pointer walks) → systematic-debugging in the VM: `dmesg`/the loader's verifier log names the instruction; shrink the loop bound or move the read into the shim; reload.
- [ ] **Step 7: Commit** (`feat(sentinel-ebpf): exec observer with memfd/deleted/exe_on facts`).

---

### Task 9: fork + exit observers (process-table feed)

**Files:** `src/observe.rs` (+2 programs), `tests/vm/scenarios/proctree.sh`

- [ ] **Step 1: programs** (btf tracepoints; no deny, observe only):
```rust
use aya_ebpf::{macros::btf_tracepoint, programs::BtfTracePointContext};
use sentinel_common::event::EventKind;

#[btf_tracepoint(function = "sched_process_fork")]
pub fn fork(ctx: BtfTracePointContext) -> i32 { unsafe { proc_event(&ctx, EventKind::Fork) } }

#[btf_tracepoint(function = "sched_process_exit")]
pub fn exit(ctx: BtfTracePointContext) -> i32 { unsafe { proc_event(&ctx, EventKind::Exit) } }

unsafe fn proc_event(ctx: &BtfTracePointContext, kind: EventKind) -> i32 {
    // fork: arg0 parent task, arg1 child task. exit: arg0 task.
    let Some(mut e) = emit::reserve() else { return 0; };
    let p = e.as_mut_ptr();
    if facts_kern::fill_header(p, kind as u8).is_none() { e.discard(0); return 0; }
    match kind {
        EventKind::Fork => {
            let child: *const core::ffi::c_void = ctx.arg(1);
            (*p).payload.proc_.child_pid = shim::task_tgid(child).unwrap_or(0);
            (*p).payload.proc_.exit_code = 0;
        }
        _ => {
            (*p).payload.proc_.child_pid = 0;
            (*p).payload.proc_.exit_code = shim::task_exit_code(ctx.arg(0)).unwrap_or(0);
        }
    }
    e.submit(0);
    0
}
```
Add `shim_task_tgid` and `shim_task_exit_code` (reads `task->exit_code`) to the C shim + `shim.rs`.
- [ ] **Step 2: VM scenario `proctree.sh`** — `load &`, run `sh -c 'sleep 0; true'` (forks + exits), assert a fork event whose `child_pid` matches and a matching exit.
- [ ] **Step 3: Verify** — `vmtest proctree`.
- [ ] **Step 4: Commit** (`feat(sentinel-ebpf): fork and exit observers`).

---

### Task 10: connect observer (`socket_connect`)

**Files:** `src/observe.rs` (+program), `c/core.c`+`shim.rs` (`shim_sockaddr`: family, addr, port), `tests/vm/scenarios/connect.sh`

- [ ] **Step 1: shim** — `shim_sockaddr(const void *address, struct sentinel_addr *o)` reading `sa_family`, and for AF_INET `sin_addr.s_addr`+`sin_port`, AF_INET6 `sin6_addr`+`sin6_port` (CO-RE reads on `struct sockaddr_in`/`in6`). Ports are big-endian on the wire — convert to host order in Rust.
- [ ] **Step 2: program**
```rust
#[lsm(hook = "socket_connect")]
pub fn connect(ctx: LsmContext) -> i32 { match unsafe { try_connect(&ctx) } { Ok(v)=>v, Err(v)=>v } }

unsafe fn try_connect(ctx: &LsmContext) -> Result<i32, i32> {
    let ret: c_int = ctx.arg(3);
    if ret != 0 { return Err(ret); }
    let address: *const c_void = ctx.arg(1);
    let Some(a) = shim::sockaddr(address) else { return Ok(0); };
    if a.family == AF_UNIX { return Ok(0); }                 // §4 skip AF_UNIX
    if is_loopback(&a) { return Ok(0); }                      // §4 skip loopback
    let Some(mut e) = emit::reserve() else { return Ok(0); };
    let p = e.as_mut_ptr();
    let Some(core) = facts_kern::fill_header(p, EventKind::Connect as u8) else { e.discard(0); return Ok(0); };
    facts_kern::set_uid_facts(p, core.uid);
    (*p).payload.net.family = a.family;
    (*p).payload.net.addr = a.addr;
    (*p).payload.net.port = u16::from_be(a.port_be);
    facts_kern::set_dest_facts(p, &a);   // CIDRS lookup (Task 21)
    facts_kern::set_port_facts(p, u16::from_be(a.port_be)); // PORTS lookup (Task 21)
    e.submit(0);
    Ok(0)
}
```
`AF_UNIX=1`, `AF_INET=2`, `AF_INET6=10`; `is_loopback` checks 127.0.0.0/8 or `::1`.
- [ ] **Step 3: VM scenario `connect.sh`** — `load &`, `busybox nc -w1 10.0.2.2 9` (QEMU user-net host) or a tiny connect helper, assert a connect event with the right addr/port and no event for a loopback connect.
- [ ] **Step 4: Verify** — `vmtest connect`.
- [ ] **Step 5: Commit** (`feat(sentinel-ebpf): connect observer with dest/port facts`).

---

### Task 11: listen observer (`socket_listen`)

**Files:** `src/observe.rs` (+program using the `socket` arg → `inet_sk` local addr/port via shim), `tests/vm/scenarios/listen.sh`

- [ ] **Step 1: shim** — `shim_sock_laddr(const void *sock, struct sentinel_addr *o)` reading the bound local address/port from `struct socket`→`sk`→`__sk_common` (`skc_rcv_saddr`, `skc_num`).
- [ ] **Step 2: program** — `socket_listen(sock, backlog)`; build `NetPayload`; set `F_LISTEN_NON_LOOPBACK` when the bound address is not loopback and not a specific loopback bind (`0.0.0.0` or a routable addr). Skip AF_UNIX.
```rust
#[lsm(hook = "socket_listen")]
pub fn listen(ctx: LsmContext) -> i32 { /* fill header, laddr; if !loopback set F_LISTEN_NON_LOOPBACK; set_port_facts */ }
```
- [ ] **Step 3: VM scenario `listen.sh`** — `load &`, `busybox nc -l -p 8888 &` on `0.0.0.0`, assert a listen event with `F_LISTEN_NON_LOOPBACK`; a loopback-only listener raises none.
- [ ] **Step 4: Verify** — `vmtest listen`.
- [ ] **Step 5: Commit** (`feat(sentinel-ebpf): listen observer with non-loopback flag`).

---

### Task 12: open observer (`file_open`) with device-class detection

**Files:** `src/observe.rs` (+program), `c/core.c`+`shim.rs` (`shim_file_dev`: i_mode, i_rdev major/minor, path), `facts_kern.rs` (device-class facts), `tests/vm/scenarios/open.sh`

The kernel-filtered device classes (§4/§5.2): camera V4L2 major 81; mic ALSA capture (char major 116, PCM capture nodes); input evdev major 13; `uinput` (misc); `hidraw` (major 245 typically, but it is dynamic — match by the `hidraw` device name prefix instead). Only emit for a recognised device class or for Sentinel's own guarded files (self-guard uses a different hook; here, filter to device classes to keep the ring quiet).

- [ ] **Step 1: shim** — read `file->f_inode->i_mode` (S_ISCHR), `i_rdev` (MAJOR/MINOR via `MKDEV` inverse), and the dentry name (first 64 bytes) for the `hidraw`/`uinput`/pcm `*c` suffix checks.
- [ ] **Step 2: facts** — `facts_kern::device_class(major, minor, name) -> Option<u32>` returning the `D_*` bit; set it in `G_DEVICE` and `OpenPayload.dev_class`. Return early (discard) when no class matches.
```rust
pub fn device_class(major: u32, name: &[u8]) -> Option<(u8,u32)> {
    match major {
        81 => Some((1, D_CAMERA)),
        13 => Some((3, D_INPUT)),
        116 if name_ends_with(name, b"c") => Some((2, D_MIC)), // pcmC*D*c = capture
        _ if starts_with(name, b"uinput") => Some((4, D_UINPUT)),
        _ if starts_with(name, b"hidraw") => Some((5, D_HIDRAW)),
        _ => None,
    }
}
```
- [ ] **Step 3: program** — `file_open(file)`; build header; compute class; discard if none; else fill `OpenPayload` + `G_DEVICE` fact and submit.
- [ ] **Step 4: VM scenario `open.sh`** — QEMU adds a virtio keyboard (`/dev/input/event0`); `load &`, `cat /dev/input/event0 &` (brief) and `: < /dev/uinput`, assert `D_INPUT` and `D_UINPUT` events; opening `/etc/hostname` raises none.
- [ ] **Step 5: Verify** — `vmtest open`.
- [ ] **Step 6: Commit** (`feat(sentinel-ebpf): open observer with device-class detection`).

---

### Task 13: memfd observer (`sys_enter_memfd_create` tracepoint)

**Files:** `src/observe.rs` (+program), `tests/vm/scenarios/memfd.sh`

- [ ] **Step 1: program** — raw syscall tracepoint; read the `name` (arg0) and `flags` (arg1) from the tracepoint context (`ctx.read_at`), fill `MemfdPayload`. Observe only.
```rust
#[tracepoint(category = "syscalls", name = "sys_enter_memfd_create")]
pub fn memfd(ctx: TracePointContext) -> u32 { /* header + name/flags from args offset; submit */ 0 }
```
(The arg offsets in the `sys_enter_memfd_create` format: `name` and `flags` after the 16-byte common+`__syscall_nr` prefix; read `args[0]`,`args[1]` at offset 16 and 24.)
- [ ] **Step 2: VM scenario `memfd.sh`** — run the memfd payload from Task 8; assert a memfd event with the name.
- [ ] **Step 3: Verify** — `vmtest memfd`.
- [ ] **Step 4: Commit** (`feat(sentinel-ebpf): memfd_create observer`).

---

### Task 14: ptrace observer (`ptrace_access_check`)

**Files:** `src/observe.rs` (+program), `c/core.c`+`shim.rs` (target task ids/uid; descendant check), `facts_kern.rs` (P_* facts), `tests/vm/scenarios/ptrace.sh`

- [ ] **Step 1: shim** — `shim_ptrace(const void *child, u32 *tgid, u32 *uid)` and `shim_is_descendant(const void *child, u32 ancestor_tgid) -> int` walking `real_parent` up to a bounded depth (e.g. 32) comparing tgid.
- [ ] **Step 2: facts** — `ptrace_access_check(child, mode)`; skip when `child` is current (self). Set `P_ANY` always; `P_OTHER_UID` when target uid != current uid; `P_NON_DESCENDANT` when current is not an ancestor of the target.
- [ ] **Step 3: VM scenario `ptrace.sh`** — as root, `strace -p <pid-of-unrelated>` (or a small `PTRACE_ATTACH` helper) against a process in another tree; assert a ptrace event with `P_NON_DESCENDANT` set; tracing a child raises `P_ANY` only (descendant).
- [ ] **Step 4: Verify** — `vmtest ptrace`.
- [ ] **Step 5: Commit** (`feat(sentinel-ebpf): ptrace observer with target facts`).

---

### Task 15: module-load observer (`kernel_read_file` / `kernel_load_data`)

**Files:** `src/observe.rs` (+program), `tests/vm/scenarios/module.sh`

- [ ] **Step 1: program** — `kernel_read_file(file, id, contents)`: filter to module ids (`READING_MODULE`); also `kernel_load_data(id, ...)` for the syscall path. Emit a `Module` event with `read_id` and the file name (shim dentry read). Observe only (the `module-load` default rule is `alert`).
- [ ] **Step 2: VM scenario `module.sh`** — `load &`, `modprobe dummy` or `insmod` a tiny built module (or `finit_module` helper); assert a module event.
- [ ] **Step 3: Verify** — `vmtest module`.
- [ ] **Step 4: Commit** (`feat(sentinel-ebpf): module-load observer`).

---

### Task 16: bpf observer (`bpf` / `bpf_prog_load`)

**Files:** `src/observe.rs` (+program), `tests/vm/scenarios/bpf.sh`

- [ ] **Step 1: program** — LSM `bpf(cmd, attr, size)`: emit a `Bpf` event with `cmd`; for `BPF_PROG_LOAD` also record `prog_type` from `attr` (shim read). Observe only here; the self-guard **deny** on tracing/LSM loads is Task 24.
- [ ] **Step 2: VM scenario `bpf.sh`** — `load &`, run `bpftool prog show` or a tiny `BPF_PROG_LOAD` of a trivial socket-filter; assert a bpf event with the cmd.
- [ ] **Step 3: Verify** — `vmtest bpf`.
- [ ] **Step 4: Commit** (`feat(sentinel-ebpf): bpf observer`).

---

### Task 17: signal observer (`task_kill`, only to the daemon)

**Files:** `src/observe.rs` (+program), `tests/vm/scenarios/signal.sh`

- [ ] **Step 1: program** — LSM `task_kill(target, info, sig, cred)`: read the target tgid (shim); emit a `Signal` event **only** when the target tgid equals `CONFIG[0].sentineld_tgid` (keeps the ring quiet; §4 "only signals to sentineld"). Observe only here; the self-guard **deny** is Task 22.
- [ ] **Step 2: VM scenario `signal.sh`** — `load &` (it writes its own pid into `CONFIG.sentineld_tgid`), then `kill -0 <loader-pid>` from another shell; assert a signal event targeting that pid; a signal to an unrelated pid raises none.
- [ ] **Step 3: Verify** — `vmtest signal`.
- [ ] **Step 4: Commit** (`feat(sentinel-ebpf): signal observer scoped to the daemon`).

---

### Task 18: write_refused observer (`fexit/do_filp_open` → -EROFS)

The hardest sensor (§4): a read-only-/usr write attempt fails in `do_filp_open` with `-EROFS`. An `fexit` program sees the return value.

**Files:** `src/observe.rs` (+program), `c/core.c`+`shim.rs` (`do_filp_open` args: the `struct open_flags` for intent, the `struct filename` for the path), `tests/vm/scenarios/write_refused.sh`

- [ ] **Step 1: shim** — read the `fexit` return value (`ctx.arg(N)` is the returned `struct file *`/errno-encoded pointer; use `IS_ERR` test → `-EROFS == -30`), the requested path from the `struct filename` arg, and the `acc_mode`/`open_flag` from `struct open_flags` to confirm write intent (`O_WRONLY|O_RDWR|O_CREAT|O_TRUNC`).
- [ ] **Step 2: program**
```rust
#[fexit(function = "do_filp_open")]
pub fn write_refused(ctx: FExitContext) -> i32 { /* if ret == -EROFS and write intent: emit WriteRefused with path */ 0 }
```
Emit `WriteRefused` with the raw path; the `persistence-write`/`managed_home` classification is user-space (§17.5), so the kernel only reports the refusal. Note the §4 caveat: a write to a read-only *bind* fails in the VFS before `file_open`, so this `fexit` on `do_filp_open` is the correct hook for the `-EROFS` case.
- [ ] **Step 3: VM scenario `write_refused.sh`** — mount a tiny `tmpfs` read-only at `/mnt/ro`, `: > /mnt/ro/x` (fails `-EROFS`), assert a `write_refused` event with path `/mnt/ro/x`. (A real `/usr` RO bind is set up by the ISO; the tmpfs RO mount reproduces the `-EROFS` path in the bare VM.)
- [ ] **Step 4: Verify** — `vmtest write_refused`. If `do_filp_open`'s signature/return handling fights the verifier, fall back to `fexit/path_openat` and record the choice in a comment.
- [ ] **Step 5: Commit** (`feat(sentinel-ebpf): write_refused observer on -EROFS`).

---

### Task 19: kernel rule engine (`evaluate`) + loader populates `RULES`

The kernel reuses the S1 shared matcher `sentinel_common::rule::eval` (imported below under the alias `rule_match` so the per-rule call reads clearly). No matching logic is re-implemented.

**Files:** `src/engine.rs` (+`evaluate`), `ebpf-loadtest/src/main.rs` (`load` compiles the default pack with `sentinel-rules` and writes `RULES`/`RULE_COUNT`), `tests/vm/scenarios/rules.sh`

- [ ] **Step 1: `engine.rs` — `evaluate`**
```rust
use sentinel_common::event::{Action, Mode};
use sentinel_common::facts::Facts;
use sentinel_common::rule::{eval as rule_match, MAX_RULES};
use crate::maps::{RULES, RULE_COUNT};

pub struct Verdict { pub matched: i32, pub deny: bool, pub would_deny: bool }

/// Walk the compiled kernel rules whose `on` equals `kind`; first Deny+Enforce
/// wins the deny, first match names the rule. Bounded by MAX_RULES (verifier).
pub fn evaluate(kind: u8, facts: &Facts) -> Verdict {
    let count = RULE_COUNT.get(0).copied().unwrap_or(0);
    let mut v = Verdict { matched: -1, deny: false, would_deny: false };
    let mut i: u32 = 0;
    while i < MAX_RULES as u32 {
        if i >= count { break; }
        if let Some(r) = RULES.get(i) {
            if r.on == kind && rule_match(r, facts) {
                if v.matched < 0 { v.matched = i as i32; }
                if r.action == Action::Deny as u8 {
                    if r.mode == Mode::Enforce as u8 { v.deny = true; v.matched = i as i32; }
                    else { v.would_deny = true; }
                }
            }
        }
        i += 1;
    }
    v
}
```
- [ ] **Step 2: loader populates rules** — in `ebpf-loadtest` `load`: read `manifest/sentinel/rules/default.toml` (path arg, default to the repo copy), call `sentinel_rules` to parse + `compile_all` into the `KRule` vector + lookup tables (the S1 compile API), then write each `KRule` into `RULES[i]` and `RULE_COUNT[0]=n`. (Reuse the exact S1 `sentinel-rules` entry points; do not reimplement compilation.)
- [ ] **Step 3: engine wired into observers (read-only)** — in each LSM observer, after facts are built and before `submit`, call `evaluate` and record on the event:
```rust
let facts = Facts((*p).hdr.facts);
let v = engine::evaluate((*p).hdr.kind, &facts);
(*p).hdr.matched_rule = v.matched;
// kverdict set in Task 20
```
- [ ] **Step 4: VM scenario `rules.sh`** — `load` with the default pack; run the memfd payload; assert the exec event's `matched_rule` names `exec-memfd` (map the index back via the loader's printed rule list).
- [ ] **Step 5: Verify** — `vmtest rules`.
- [ ] **Step 6: Commit** (`feat(sentinel-ebpf): kernel rule engine and loader rule population`).

---

### Task 20: `deny` enforcement in the LSM hooks

**Files:** `src/engine.rs` (helper `apply_verdict`), `src/observe.rs` (deny in each LSM observer), `tests/vm/scenarios/deny.sh`

- [ ] **Step 1: enforcement helper**
```rust
use sentinel_common::wire::{KVerdict, CFG_ENFORCE};
use crate::maps::CONFIG;

/// Record the verdict on the event; return Some(-EPERM) when the kernel must deny.
pub fn apply_verdict(p: *mut sentinel_common::wire::RawEvent, v: &Verdict) -> Option<i32> {
    let enforce = CONFIG.get(0).map(|c| c.flags & CFG_ENFORCE != 0).unwrap_or(false);
    unsafe {
        (*p).hdr.matched_rule = v.matched;
        if v.deny && enforce {
            (*p).hdr.kverdict = KVerdict::Denied as u8;
            Some(-1) // -EPERM
        } else {
            if v.would_deny { (*p).hdr.kverdict = KVerdict::WouldDeny as u8; }
            None
        }
    }
}
```
- [ ] **Step 2: deny in observers** — in `exec` (and every other LSM observer), replace the tail with:
```rust
let facts = Facts((*p).hdr.facts);
let v = engine::evaluate((*p).hdr.kind, &facts);
let deny = engine::apply_verdict(p, &v);
e.submit(0);
match deny { Some(err) => Err(err), None => Ok(0) }
```
(The event is submitted with the verdict *before* returning the deny, so S3 records the denied attempt.)
- [ ] **Step 3: loader sets enforce** — `load --enforce` sets `CONFIG[0].flags |= CFG_ENFORCE`; default off (observe-only) so scenarios opt in.
- [ ] **Step 4: VM scenario `deny.sh`** — `load --enforce` with the default pack; run the memfd payload → `fexecve` returns `EPERM` and the event shows `kverdict=Denied`; run a `/tmp` binary → `exec-tmp` is audit → runs, event shows `WouldDeny`.
```sh
./payloads/memfd_run; test $? -ne 0    # denied
grep -q '"kverdict":1' /tmp/ev.jsonl   # Denied
cp /bin/true /tmp/t && /tmp/t; test $? -eq 0   # audit: still runs
grep -q '"kverdict":2' /tmp/ev.jsonl   # WouldDeny
```
- [ ] **Step 5: Verify** — `vmtest deny`.
- [ ] **Step 6: Commit** (`feat(sentinel-ebpf): LSM deny enforcement for kernel rules`).

---

### Task 21: lookup-table facts (mounts, CIDRs, ports, uid literals)

**Files:** `src/facts_kern.rs` (+`set_dest_facts`, `set_port_facts`, `set_uid_literal_facts`), `ebpf-loadtest/src/main.rs` (resolve + populate `MOUNTS`/`CIDRS`/`PORTS`/`UID_LITERALS`), `tests/vm/scenarios/exe_on.sh`

- [ ] **Step 1: fact builders**
```rust
use crate::maps::{CIDRS, PORTS, UID_LITERALS};
use sentinel_common::rule::{MAX_CIDRS, MAX_PORT_SETS, MAX_UID_LITERALS};
use sentinel_common::facts::{slot_bit, uid_literal_bit, G_DEST, G_PORT, G_UID};

pub fn set_port_facts(p: *mut RawEvent, port: u16) {
    let mut i: u32 = 0;
    while i < MAX_PORT_SETS as u32 {
        if let Some(r) = PORTS.get(i) {
            if r.used != 0 && port >= r.lo && port <= r.hi {
                unsafe { (*p).hdr.facts[G_PORT] |= slot_bit(r.slot as usize); }
            }
        }
        i += 1;
    }
}
// set_dest_facts: for each used CidrEntry, if addr matches prefix (family-aware), OR slot_bit into G_DEST.
// set_uid_literal_facts: for each used UID_LITERALS slot == uid, OR uid_literal_bit(i) into G_UID.
```
- [ ] **Step 2: loader resolves + populates** — `load` resolves each `exe_on` path to its `mnt_id` (parse `/proc/self/mountinfo`: the mount id is the first field; match the mount point that contains the path), writing `MOUNTS[mnt_id] = slot_bit(slot)`; writes `CIDRS`/`PORTS`/`UID_LITERALS` from the S1 compile output. It also resolves `/usr`, `/dev/shm`, `/tmp`, `/var/tmp` as needed by the default pack. Warn on a path that is not a mount point (the rule would never match, §17.6).
- [ ] **Step 3: VM scenario `exe_on.sh`** — `load --enforce`; copy `/bin/true` to `/dev/shm/t` and run it → `exec-shm` denies (EPERM), event `matched_rule=exec-shm`, `kverdict=Denied`; from `/tmp` → `exec-tmp` would-deny.
- [ ] **Step 4: Verify** — `vmtest exe_on`.
- [ ] **Step 5: Commit** (`feat(sentinel-ebpf): mount/cidr/port/uid lookup-table facts`).

---

### Task 22: self-guard — refuse signals to the daemon (`task_kill` deny)

**Files:** `src/guard.rs` (new; self-guard predicate helpers), `src/observe.rs` (extend the Task 17 `task_kill` program with deny), `tests/vm/scenarios/guard_kill.sh`

- [ ] **Step 1: `guard.rs` helpers**
```rust
use sentinel_common::wire::CFG_SELFGUARD;
use crate::maps::CONFIG;

pub fn selfguard_on() -> bool { CONFIG.get(0).map(|c| c.flags & CFG_SELFGUARD != 0).unwrap_or(false) }
pub fn daemon_tgid() -> u32 { CONFIG.get(0).map(|c| c.sentineld_tgid).unwrap_or(0) }
```
- [ ] **Step 2: deny in `task_kill`** — §8.2: refuse any user-sent signal whose target tgid is the daemon, except from PID 1 and from the daemon itself (kernel-generated signals don't pass this hook). After emitting the event:
```rust
if selfguard_on() {
    let d = daemon_tgid();
    let cur = core.pid; // sender tgid
    if target_tgid == d && d != 0 && cur != d && cur != 1 {
        (*p).hdr.kverdict = KVerdict::Denied as u8;
        e.submit(0);
        return -1; // -EPERM, critical self-guard alert in S3
    }
}
```
- [ ] **Step 3: VM scenario `guard_kill.sh`** — `load --enforce --selfguard` (writes its own tgid as the daemon); from another shell `kill -TERM <loader-pid>` → fails `EPERM`, the loader keeps running; event shows `Denied`.
- [ ] **Step 4: Verify** — `vmtest guard_kill`.
- [ ] **Step 5: Commit** (`feat(sentinel-ebpf): self-guard deny on signals to the daemon`).

---

### Task 23: self-guard — refuse ptrace of the daemon (`ptrace_access_check` deny)

**Files:** `src/observe.rs` (extend the Task 14 ptrace program), `tests/vm/scenarios/guard_ptrace.sh`

- [ ] **Step 1: deny** — §8.2: refuse `PTRACE_MODE_ATTACH` on the daemon from anyone; refuse `PTRACE_MODE_READ` except from PID 1 and `systemd-journald`. In S2 (no journald identity yet) refuse ATTACH on the daemon from anyone and READ from anyone but PID 1; record the daemon tgid as target.
```rust
if selfguard_on() && target_tgid == daemon_tgid() && daemon_tgid() != 0 {
    let is_attach = mode & PTRACE_MODE_ATTACH != 0;
    if is_attach || core.pid != 1 { /* set Denied, submit, return -EPERM */ }
}
```
- [ ] **Step 2: VM scenario `guard_ptrace.sh`** — `load --enforce --selfguard`; `strace -p <loader-pid>` (or a `PTRACE_ATTACH` helper) → fails `EPERM`; event `Denied`.
- [ ] **Step 3: Verify** — `vmtest guard_ptrace`.
- [ ] **Step 4: Commit** (`feat(sentinel-ebpf): self-guard deny on ptrace of the daemon`).

---

### Task 24: self-guard — refuse hostile BPF loads (`bpf` deny)

**Files:** `src/observe.rs` (extend the Task 16 bpf program), `tests/vm/scenarios/guard_bpf.sh`

- [ ] **Step 1: deny** — §8.2: refuse `BPF_PROG_LOAD` of program types kprobe, tracepoint, raw tracepoint, tracing (fentry/fexit/iter), LSM, perf event or extension, except from the daemon and PID 1. Cgroup and socket-filter types stay allowed for everyone. (The `bpf_loaders` allowlist is S3 config; in S2 allow only daemon + PID 1.)
```rust
const HOSTILE: &[u32] = &[ /* BPF_PROG_TYPE_KPROBE, TRACEPOINT, RAW_TRACEPOINT, TRACING, LSM, PERF_EVENT, EXT */ ];
if selfguard_on() && cmd == BPF_PROG_LOAD && is_hostile(prog_type) && core.pid != 1 && core.pid != daemon_tgid() {
    /* Denied, submit, -EPERM */
}
```
(Map detach / `*_GET_FD_BY_ID` / map-update aimed at Sentinel's objects — §8.2's last clause — needs object-id tracking and is deferred to S3 with a `// S3` note; S2 covers the program-load class, which is the blinding vector the gauntlet tests.)
- [ ] **Step 2: VM scenario `guard_bpf.sh`** — `load --enforce --selfguard`; run a static kprobe loader (ship `tests/vm/payloads/kprobe_load` — a tiny `BPF_PROG_LOAD` of a kprobe) → `EPERM`; a socket-filter load succeeds.
- [ ] **Step 3: Verify** — `vmtest guard_bpf`.
- [ ] **Step 4: Commit** (`feat(sentinel-ebpf): self-guard deny on tracing/LSM BPF loads`).

---

### Task 25: self-guard — protect Sentinel's files (`file_open`/`inode_unlink`/`inode_rename`/`path_truncate`)

**Files:** `src/guard.rs` (+4 programs), `src/main.rs` (`mod guard;`), `ebpf-loadtest` (`load` populates `GUARDED_INODES` with the bpffs dir + log dir inodes), `tests/vm/scenarios/guard_files.sh`

- [ ] **Step 1: programs** — each hook reads the target inode number (shim: `inode->i_ino`) and denies the write/rename/unlink/truncate when the inode is in `GUARDED_INODES`, except for the daemon:
```rust
#[lsm(hook = "inode_unlink")]
pub fn guard_unlink(ctx: LsmContext) -> i32 { unsafe { guard_inode_op(&ctx, /*dir*/0, /*child*/1) } }
// file_open: deny write-intent opens of a guarded file; inode_rename: deny if old/new under guarded; path_truncate: deny guarded.
```
Use the inode number as the `GUARDED_INODES` key (`u64`); the loader seeds it from `stat()` on the pinned dir and `/var/log/aios/sentinel/`.
- [ ] **Step 2: loader seeds inodes** — `load` stats a stand-in guarded dir (in the VM, a dir passed as `--guard-dir`) and writes its inode (and the files it contains) into `GUARDED_INODES`.
- [ ] **Step 3: VM scenario `guard_files.sh`** — `load --enforce --selfguard --guard-dir /tmp/g`; `echo x > /tmp/g/alerts.jsonl` → `EPERM`; `rm /tmp/g/alerts.jsonl` → `EPERM`; the daemon process itself can still write it.
- [ ] **Step 4: Verify** — `vmtest guard_files`.
- [ ] **Step 5: Commit** (`feat(sentinel-ebpf): self-guard on Sentinel's own files`).

---

### Task 26: heartbeat lockdown enforcement

**Files:** `src/observe.rs` (lockdown branch in `socket_connect` + `exec`), `sentinel-common/src/wire.rs` (+`usr_mnt_id` in `KConfig`), `tests/vm/scenarios/lockdown.sh`

- [ ] **Step 1: add `usr_mnt_id`** — add `pub usr_mnt_id: u32` to `KConfig` (and a matching pad to keep 8-byte alignment); update the Task 1 size assert and every `KConfig` writer in the loader.
- [ ] **Step 2: enforcement** — §8.3: while `lockdown_active()`, `socket_connect` denies everything but AF_UNIX and loopback (`LOCKDOWN_COUNTS[0]++`), and `exec` denies executables not on the read-only `/usr` (`LOCKDOWN_COUNTS[1]++`):
```rust
// in try_connect, after the AF_UNIX/loopback skips:
if engine::lockdown_active() { engine::count_lockdown(0); return Err(-1); }
// in try_exec, once mnt_id is known:
if engine::lockdown_active() && info.mnt_id != usr_mnt_id() { engine::count_lockdown(1); e.submit(0); return Err(-1); }
```
`usr_mnt_id()` reads `CONFIG[0].usr_mnt_id`. `/usr` programs still run so a TTY login works.
- [ ] **Step 3: VM scenario `lockdown.sh`** — `load --enforce` heartbeat on; confirm a host connect succeeds and a `/home`-copied binary runs; `heartbeat --stop`; wait > `lockdown_after`; the same connect now fails and the `/home` binary fails, while `/bin/true` still runs; `LOCKDOWN_COUNTS` incremented.
- [ ] **Step 4: Verify** — `vmtest lockdown`.
- [ ] **Step 5: Commit** (`feat(sentinel-ebpf): heartbeat lockdown enforcement`).

---

### Task 27: quarantine enforcement (`socket_connect`/`socket_sendmsg` deny)

**Files:** `src/guard.rs` (quarantine check in `socket_connect` + a new `socket_sendmsg` program), `ebpf-loadtest` (`quarantine-add <cgid>`), `tests/vm/scenarios/quarantine.sh`

- [ ] **Step 1: quarantine check** — §6: a process whose cgroup id is in `QUARANTINE` is denied `socket_connect` and `socket_sendmsg` (new connections impossible during the S3 `SOCK_DESTROY` race):
```rust
pub fn quarantined() -> bool {
    let cg = unsafe { aya_ebpf::helpers::bpf_get_current_cgroup_id() };
    unsafe { crate::maps::QUARANTINE.get(&cg).is_some() }
}
// in try_connect (early) and in a new socket_sendmsg LSM program:
if guard::quarantined() { engine::count_lockdown(if is_sendmsg {2} else {0}); return Err(-1); }
```
- [ ] **Step 2: loader `quarantine-add`** — writes a cgroup id into `QUARANTINE`; the scenario creates a cgroup, puts a shell in it, reads its id.
- [ ] **Step 3: VM scenario `quarantine.sh`** — `load --enforce`; create a cgroup, run `sh` inside it, `quarantine-add <cgid>`; the quarantined shell's connect fails `EPERM`; a shell outside the cgroup connects fine.
- [ ] **Step 4: Verify** — `vmtest quarantine`.
- [ ] **Step 5: Commit** (`feat(sentinel-ebpf): quarantine cgroup connect/sendmsg deny`).

---

### Task 28: build wiring — `make tools`, `make check` builds the object, CI

The object must build in `make check` (spec §14), which needs `bpf-linker` (pinned) and `clang` on top of the S1 nightly toolchain. The object build runs through `ebpf-loadtest`'s build-script (§17.3).

**Files:** `Makefile` (`tools`, `sentinel-check`, a `BPF_LINKER_VERSION`), `.github/workflows/ci.yml` (clang + bpf-linker in the `check` job)

- [ ] **Step 1: `make tools` installs bpf-linker + asserts clang** — add to the `Makefile`:
```make
BPF_LINKER_VERSION ?= 0.9.13
tools: ... build/tools/.bpf-linker-$(BPF_LINKER_VERSION)
build/tools/.bpf-linker-$(BPF_LINKER_VERSION):
	command -v clang >/dev/null || { echo "clang required for the C CO-RE shim" >&2; exit 1; }
	cargo install bpf-linker --version $(BPF_LINKER_VERSION) --locked
	mkdir -p build/tools && touch $@
```
(`cargo install` lands in `~/.cargo/bin`; the `sentinel-check` recipe must have it on `PATH`.)
- [ ] **Step 2: `sentinel-check` builds the object** — append one line to the `sentinel-check` recipe:
```make
	cd sentinel && PATH="$$HOME/.cargo/bin:$$PATH" $(CARGO) build -p ebpf-loadtest
```
This compiles the C shim, builds `sentinel-ebpf` for `bpfel-unknown-none`, and embeds it — proving the whole object builds without root.
- [ ] **Step 3: CI** — in `.github/workflows/ci.yml` `check` job, before `make check`:
```yaml
      - name: Install clang + bpf prerequisites
        run: |
          sudo apt-get update && sudo apt-get install -y clang llvm libelf-dev
          rustup component add rust-src --toolchain nightly-2026-11-03 || true
```
(`make tools` installs `bpf-linker`; the nightly auto-installs from `sentinel/rust-toolchain.toml`.) Note in the workflow comment that this adds a few minutes to CI for the first, uncached `bpf-linker` build.
- [ ] **Step 4: Verify** — `make tools && make sentinel-check` → builds all pure crates **and** the object, EXIT 0. Then full `make check` EXIT 0.
- [ ] **Step 5: Commit** (`build(sentinel): build the eBPF object in make check; bpf-linker + clang in tools and CI`).

---

### Task 29: `make sentinel-vmtest` + `xtask vmtest all` + docs

**Files:** `Makefile` (`sentinel-vmtest` target, local-only), `sentinel/xtask/src/main.rs` (`vmtest all`), `sentinel/tests/vm/README.md`

- [ ] **Step 1: `xtask vmtest all`** — iterate every scenario in `tests/vm/scenarios/` and run the harness for each; fail on the first non-zero; print a per-scenario pass/fail summary.
- [ ] **Step 2: `make sentinel-vmtest`** (local, needs KVM — **not** in `make check`, like `make e2e`):
```make
.PHONY: sentinel-vmtest
sentinel-vmtest:
	cd sentinel && PATH="$$HOME/.cargo/bin:$$PATH:$$PWD/../build/hosttools/root/usr/bin" \
		$(CARGO) run -p xtask -- vmtest all
```
- [ ] **Step 3: `tests/vm/README.md`** — document: requires KVM + virtme-ng (`uvx --from virtme-ng`) + `busybox` on PATH; runs the host kernel with `--user root`; each scenario boots once; the object is built on the host before boot; list the scenarios and what each asserts.
- [ ] **Step 4: Verify** — `make sentinel-vmtest` runs every scenario green (local; skip in CI).
- [ ] **Step 5: Commit** (`test(sentinel): sentinel-vmtest target running the full VM scenario suite`).

---

### Task 30: S3 handoff + design §17 update

**Files:** `docs/superpowers/specs/2026-11-12-sentinel-core-design.md` (append S2 outcomes to §17), `sentinel/crates/sentinel-ebpf/README.md`

- [ ] **Step 1: `sentinel-ebpf/README.md`** — the ABI S3 inherits: the map name/type table, the `RawEvent` layout, the load→`Btf::from_sys_fs`→`load(name,&btf)`→`attach`→pin-under-`/sys/fs/bpf/aios-sentinel/` sequence, and the `CONFIG` fields the daemon must write (`sentineld_tgid`, `usr_mnt_id`, `lockdown_after_ns`, `flags`) and the heartbeat cadence.
- [ ] **Step 2: append to design §17** — record what S2 settled or deferred:
  - exec `exe`/`argv` strings are **not** filled in-kernel; S3 resolves them from `/proc/<pid>` (kernel-critical facts memfd/deleted/exe_on are complete).
  - `env_ld`/`stdio_socket` facts are computed in user space (S3) for the alert/freeze rules that use them.
  - self-guard's BPF map-detach / `*_GET_FD_BY_ID` clause and the `SOCK_DESTROY` half of freeze are S3 (§17.2 already notes the latter).
  - `write_refused` uses `fexit/do_filp_open` on `-EROFS` (or `path_openat` if the verifier preferred it — record the actual choice).
- [ ] **Step 3: Verify** — `make check` still green (design/README are docs).
- [ ] **Step 4: Commit** (`docs(sentinel): S2 eBPF ABI handoff for S3 and §17 outcomes`).

---

## Spec coverage map

| Spec requirement | Task(s) |
|---|---|
| §3.1 `sentinel-ebpf` crate (Aya, nightly, bpfel, CO-RE) | 2, 3 |
| §4 ring buffer (8 MiB) + fixed events + drop counter | 1, 6 |
| §4 exec sensor + flags (memfd/deleted/outside_usr; env_ld/stdio → S3) | 8 |
| §4 fork/exit | 9 |
| §4 connect / listen | 10, 11 |
| §4 open + device classes | 12 |
| §4 memfd | 13 |
| §4 ptrace | 14 |
| §4 module | 15 |
| §4 bpf | 16 |
| §4 signal (to daemon) | 17 |
| §4 write_refused (-EROFS) | 18 |
| §5.2 predicates → facts (flags, uid, exe_on, dest, port, device, ptrace_target) | 8, 10, 11, 12, 14, 21 |
| §5.3 kernel-rule evaluation (shared `eval`) | 19 |
| §6 deny (LSM -EPERM) | 20 |
| §6 freeze — in-kernel quarantine half (§17.2) | 27 |
| §8.2 self-guard: task_kill / ptrace / bpf / own-files | 22, 23, 24, 25 |
| §8.3 heartbeat lockdown | 7, 26 |
| §11.4 `aya-build` object build (§17.3); `make tools` bpf-linker+clang | 4, 28 |
| §14 object builds in `make check` | 28 |
| §14 VM verification of each program (verifier only in VM) | 5, 8–27 (each `vmtest` scenario), 29 |
| §17.1 CO-RE via C shims | 3, 8, and every shim-using task |
| §17.6 `exe_on` by mnt_id | 8, 21 |

**Deferred to S3 (noted in-plan, not gaps):** the ring-buffer *reader* + process table + actions (freeze/kill/release, `SOCK_DESTROY`) + alert store + varlink (all of `sentineld`); `env_ld`/`stdio_socket`/`exe`/`argv` user-space enrichment; the BPF map-detach / fd-by-id self-guard clause; `managed_home` classification (§17.5). S4 integrates the package/unit/health into the Base ISO; S5 is the full e2e gauntlet.

---

## Execution

Per the project's established mode, execute with **superpowers:subagent-driven-development**: a fresh subagent per task, spec-compliance review then code-quality review at each crate/phase boundary, VM scenarios as the acceptance gate for every kernel-program task. Pure-Rust tasks (1, 6–7 loader bits, 19, 21 fact builders) are TDD under `make check`; kernel-program tasks are proven by `cargo run -p xtask -- vmtest <scenario>` and, on a verifier rejection, **superpowers:systematic-debugging** inside the VM. Commit at the end of each task with the trailer above. After all tasks, a whole-implementation review, then **superpowers:finishing-a-development-branch** (the branch stays `feat/sentinel`; S2 is sub-project 2 plan 2 of 5 — do not merge to `main` until S5, like Base ISO).

