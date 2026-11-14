# Sentinel — S1: Workspace + Core Crates Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create the `sentinel/` Cargo workspace and its three pure-logic crates — `sentinel-common` (shared `no_std` types, the kernel rule format and its evaluator), `sentinel-rules` (TOML schema, validation, kernel/user classification, compilation into kernel tables and user-space matchers, rule-set diff, the `[sentinel]` config), and `sentinel-detect` (the beacon and DNS-tunnel detectors) — plus the default rule pack, all wired into `make check` and running without root.

**Architecture:** A workspace separate from `aios-cli` (spec §3.1), because the kernel crate added in S2 needs a nightly toolchain and the `bpfel-unknown-none` target. S1 contains only the pure crates, so every test runs on the host with `cargo test`, no VM, no root. `sentinel-common` holds the data contract both kernel and user space agree on: a rule compiles to a fixed-size `KRule` whose `eval()` runs identically in the LSM hook (S2) and in `sentineld` (S3). `sentinel-rules` turns TOML into `KRule`s plus side tables (mounts, CIDRs, ports, uid literals) and residual user-space matchers; the same code backs `aios plan`, `sentinel rules check` and the daemon. Nothing here does I/O or reads a clock.

**Tech Stack:** Rust (toolchain pinned to `nightly-2026-11-03` by `sentinel/rust-toolchain.toml`, so S2's kernel crate shares it; the pure crates also build on stable, which S4 relies on when `aios-cli` path-depends on `sentinel-rules`). `serde` 1, `toml` 0.8, `globset` 0.4.21, `ipnet` 2.12, `psl` 2.1.252, `ulid` 3 (`sentineld` only, not S1). Dev: `tempfile` 3.

**Spec:** `docs/superpowers/specs/2026-11-12-sentinel-core-design.md` — §3.1 (crate layout), §4 (event flags), §5 (rules: format, predicates, kernel/user split, detectors, default pack), §11.1 (`[sentinel]` config), §11.2 (plan diff), §14 (Rust unit test bar).

---

## Environment note for every task

Rust is installed via rustup. The `sentinel/` directory pins `nightly-2026-11-03` through `rust-toolchain.toml`, so `cargo` inside it uses that automatically. Start every shell with:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/eli/Development/AIOS
```

The nightly toolchain, `bpf-linker`, clang 23 and the libbpf headers are already installed (verified building the S2 spike). The VM harness used from S2 onward needs `busybox` on PATH; it lives at `build/hosttools/root/usr/bin/busybox` (gitignored, signature-verified). S1 needs none of that — it is pure host Rust.

**GateGuard note:** a local hook blocks the *first* Write/Edit of each new file, and the first Bash call, until you state the facts: the user's instruction, what the command/file produces, that no existing file serves the purpose, and the data schema if any. State them briefly in text and retry the same call. The user's standing instruction is: "finish this project, use skills and subagents". The hook also blocks `rm -rf`; use `mktemp -d` scratch dirs.

---

## Where S1 sits in the Sentinel build

Sentinel (sub-project 2a) is built in five plans, mirroring the Base ISO's five. Each produces working, tested software on its own.

| Plan | Scope | Spec sections | Needs root / VM |
|---|---|---|---|
| **S1 (this plan)** | `sentinel/` workspace; `sentinel-common`, `sentinel-rules`, `sentinel-detect`; default rule pack; `make check` wiring; spec amendments | §3.1, §4 (flags), §5, §11.1–11.2, §14 (unit) | no |
| S2 | `sentinel-ebpf` (Aya kernel programs + C CO-RE shims), `xtask` build, VM test harness per sensor | §4, §8 | VM (virtme-ng, no sudo) |
| S3 | `sentineld` (loader, process table, rule/detector dispatch, actions, alert chain, varlink) and the `sentinel` CLI | §6–§10, §12–§13 | VM |
| S4 | Base ISO integration: `[sentinel]` manifest section, plan/apply rendering, `LoadGeneration`, PKGBUILD, unit, health check | §11 | host + VM |
| S5 | E2E gauntlet in the Base ISO VM, including the Sliver implant | §14 (e2e) | VM |

S1 locks the data contract (`sentinel-common`) and the whole rules/detector engine. S2–S5 build on these types without changing them. Write S2's plan only after S1 executes and its types are proven by tests.

### Why a C shim appears in S2 (recorded here so S1's `sentinel-common` anticipates it)

The S2 spike proved that Rust eBPF has no CO-RE relocations today (rustc can't emit `.BTF.ext` for `preserve_access_index`; rust#158412, aya#349). Kernel-struct field reads that must survive a kernel version change (e.g. `task->real_parent->tgid`, `binprm->file->f_inode->i_nlink`) are therefore done in a tiny C file compiled with `clang -target bpfel -O2 -g -emit-llvm` and linked via bpf-linker `--btf`; the Aya loader relocates it. The spec already permits this (§3.1: "If one program can't be expressed in Aya, that program alone may be written in C … the plan must name it and say why"). S1's `sentinel-common` stays plain `no_std` Rust and is shared unchanged by both the Rust and C sides — the C shim only *reads* kernel structs and writes into the same `#[repr(C)]` event structs `sentinel-common` defines. Task 12 amends the spec to record this and three other deviations.

---

## File Structure

```
sentinel/Cargo.toml                                   workspace (S1 members: the 3 pure crates)
sentinel/Cargo.lock                                   committed
sentinel/rust-toolchain.toml                          nightly-2026-11-03 + rust-src, clippy, rustfmt
sentinel/crates/sentinel-common/Cargo.toml
sentinel/crates/sentinel-common/src/lib.rs            re-exports, no_std gate
sentinel/crates/sentinel-common/src/event.rs          EventKind, Action, Mode, Severity; raw event structs
sentinel/crates/sentinel-common/src/facts.rs          group indices, bit constants, Facts, helpers
sentinel/crates/sentinel-common/src/rule.rs           KRule, limits, eval()
sentinel/crates/sentinel-rules/Cargo.toml
sentinel/crates/sentinel-rules/src/lib.rs             re-exports, RuleError, load_dir()
sentinel/crates/sentinel-rules/src/model.rs           RuleFile, Rule, Match, predicate value types
sentinel/crates/sentinel-rules/src/validate.rs        validate(): all §5.1 error cases
sentinel/crates/sentinel-rules/src/classify.rs        Kind (Kernel|User), predicate→group/kind map
sentinel/crates/sentinel-rules/src/compile.rs         Tables, compile(): rules → KRule[] + side tables + UserRule[]
sentinel/crates/sentinel-rules/src/matcher.rs         ResolvedEvent, UserRule, user-space eval incl. globs
sentinel/crates/sentinel-rules/src/window.rs          Window, WindowState sliding counter
sentinel/crates/sentinel-rules/src/diff.rs            RuleSetDiff for `aios plan`
sentinel/crates/sentinel-rules/src/config.rs          SentinelConfig, Beacon, DnsTunnel ([sentinel] section)
sentinel/crates/sentinel-rules/tests/common/mod.rs    shared fixtures
sentinel/crates/sentinel-rules/tests/validate.rs
sentinel/crates/sentinel-rules/tests/compile.rs
sentinel/crates/sentinel-rules/tests/matcher.rs
sentinel/crates/sentinel-rules/tests/diff.rs
sentinel/crates/sentinel-rules/tests/config.rs
sentinel/crates/sentinel-rules/tests/default_pack.rs  loads manifest/sentinel/rules/default.toml
sentinel/crates/sentinel-detect/Cargo.toml
sentinel/crates/sentinel-detect/src/lib.rs            re-exports
sentinel/crates/sentinel-detect/src/beacon.rs         Beacon detector
sentinel/crates/sentinel-detect/src/dns_tunnel.rs     DnsTunnel detector
sentinel/crates/sentinel-detect/tests/beacon.rs
sentinel/crates/sentinel-detect/tests/dns_tunnel.rs
manifest/sentinel/rules/default.toml                  the default rule pack (§5.5)
Makefile                                              + sentinel-check target, added to `check`
```

---

## Data contract locked in S1 (reference for S2–S5)

The kernel and user space agree on `[u32; NGROUPS]` **facts**: one `u32` per group, each bit a predicate term. A rule compiles to a `KRule` holding `all` / `any` / `ex_any` masks over those groups; `eval(&KRule, &Facts) -> bool` is the single source of truth, compiled into both the LSM hook (S2) and `sentineld` (S3).

| Group | Index | Bits |
|---|---|---|
| FLAGS | 0 | memfd 0, deleted 1, outside_usr 2, stdio_socket 3, env_ld 4, listen_non_loopback 5 |
| UID | 1 | user 0, system 1, uid literals 2..=31 (≤ 30 literals) |
| MOUNT | 2 | one bit per compiled mount point (≤ 32) |
| DEST | 3 | one bit per compiled CIDR (≤ 32) |
| PORT | 4 | one bit per compiled port set (≤ 32) |
| DEVICE | 5 | camera 0, mic 1, input 2, uinput 3, hidraw 4 |
| PTRACE | 6 | other_uid 0, non_descendant 1, any 2 (always set on a ptrace event) |

`eval` per group: every `all` bit must be present; if `any` is non-zero at least one of its bits must be present; any `ex_any` overlap suppresses the rule (§5.1 `except` is OR across predicates and OR within a list, which this mask expresses exactly). Kernel-rule limits: 64 rules, 30 uid literals, 32 mounts, 32 CIDRs, 32 port sets (§5.3 is kernel-synchronous, so the tables are bounded).

---

### Task 1: Workspace scaffold and `make check` wiring

**Files:**
- Create: `sentinel/Cargo.toml`, `sentinel/rust-toolchain.toml`
- Create: `sentinel/crates/sentinel-common/Cargo.toml`, `sentinel/crates/sentinel-common/src/lib.rs`
- Create: `sentinel/crates/sentinel-rules/Cargo.toml`, `sentinel/crates/sentinel-rules/src/lib.rs`
- Create: `sentinel/crates/sentinel-detect/Cargo.toml`, `sentinel/crates/sentinel-detect/src/lib.rs`
- Modify: `Makefile` (add `sentinel-check`, add it to `check` and `.PHONY`)

- [ ] **Step 1: Check the toolchain**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cd sentinel 2>/dev/null; rustup show active-toolchain 2>&1; cd /home/eli/Development/AIOS`
Expected: once the files exist, inside `sentinel/` the active toolchain is `nightly-2026-11-03-...`. For now just confirm `cargo --version` prints.

- [ ] **Step 2: Create `sentinel/rust-toolchain.toml`**

```toml
[toolchain]
channel = "nightly-2026-11-03"
components = ["rust-src", "clippy", "rustfmt"]
```

- [ ] **Step 3: Create the workspace `sentinel/Cargo.toml`**

S2 adds `sentinel-ebpf`, `sentineld`, `sentinel` (CLI) and `xtask` to `members`. S1 ships the three pure crates only.

```toml
[workspace]
resolver = "2"
members = [
    "crates/sentinel-common",
    "crates/sentinel-rules",
    "crates/sentinel-detect",
]

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "GPL-3.0-or-later"
publish = false

[workspace.dependencies]
serde = { version = "1", features = ["derive"] }
toml = "0.8"
globset = "0.4.21"
ipnet = "2.12"
psl = "2.1.252"
tempfile = "3"
sentinel-common = { path = "crates/sentinel-common" }
```

- [ ] **Step 4: Create `sentinel-common` crate manifest and lib**

`sentinel/crates/sentinel-common/Cargo.toml`:
```toml
[package]
name = "sentinel-common"
description = "Shared no_std types and the kernel rule format for AIOS Sentinel"
version.workspace = true
edition.workspace = true
license.workspace = true
publish.workspace = true

[dependencies]
```

`sentinel/crates/sentinel-common/src/lib.rs`:
```rust
//! Types shared by the Sentinel kernel programs and `sentineld`.
//!
//! `no_std` so the eBPF crate (S2) can depend on it. Pure data and the rule
//! evaluator; no allocation, no I/O, no clock.
#![no_std]

pub mod event;
pub mod facts;
pub mod rule;

pub use event::{Action, EventKind, Mode, Severity};
pub use facts::*;
pub use rule::{eval, KRule, MAX_CIDRS, MAX_MOUNTS, MAX_PORT_SETS, MAX_RULES, MAX_UID_LITERALS};
```

- [ ] **Step 5: Create `sentinel-rules` crate manifest and lib stub**

`sentinel/crates/sentinel-rules/Cargo.toml`:
```toml
[package]
name = "sentinel-rules"
description = "Sentinel rule schema, validation, compilation and diff"
version.workspace = true
edition.workspace = true
license.workspace = true
publish.workspace = true

[dependencies]
sentinel-common.workspace = true
serde.workspace = true
toml.workspace = true
globset.workspace = true
ipnet.workspace = true
psl.workspace = true

[dev-dependencies]
tempfile.workspace = true
```

`sentinel/crates/sentinel-rules/src/lib.rs` (stub, filled in later tasks):
```rust
//! Sentinel rules: parse TOML, validate, classify kernel vs user space,
//! compile to kernel tables and user-space matchers, diff rule sets.
//!
//! Pure: no I/O except `load_dir`, no clock. Builds on stable so `aios-cli`
//! can path-depend on it (S4).

pub mod config;
```

For Step 5 the stub only needs to compile; create `config.rs` with a placeholder that Task 9 replaces:
```rust
//! The `[sentinel]` manifest section. Filled in Task 9.
```

- [ ] **Step 6: Create `sentinel-detect` crate manifest and lib stub**

`sentinel/crates/sentinel-detect/Cargo.toml`:
```toml
[package]
name = "sentinel-detect"
description = "Sentinel built-in detectors: C2 beacon and DNS tunnel"
version.workspace = true
edition.workspace = true
license.workspace = true
publish.workspace = true

[dependencies]
psl.workspace = true

[dev-dependencies]
```

`sentinel/crates/sentinel-detect/src/lib.rs`:
```rust
//! Built-in detectors. Pure: all time is passed in by the caller, so tests
//! drive synthetic timelines without a clock (spec §14).
```

- [ ] **Step 7: Add the `sentinel-check` Makefile target**

In `Makefile`, extend the `.PHONY` line and the `check` target, and add the new target after `rust-check`. The `cd sentinel` picks up the pinned nightly via `rust-toolchain.toml`.

Change the `.PHONY` line to include `sentinel-check`:
```make
.PHONY: check rust-check sentinel-check release-check shell-check bats-check unit-check e2e-unit tools repo \
	keys iso-build iso iso-check clean-iso e2e FORCE
```

Change the `check` target to:
```make
check: rust-check sentinel-check shell-check bats-check unit-check e2e-unit
```

Add the target (place it right after the `rust-check` block):
```make
# Sentinel's own workspace (sentinel/) pins a nightly toolchain via rust-toolchain.toml.
# S1 covers the three pure crates; S2 extends this to build the eBPF object too.
sentinel-check:
	cd sentinel && $(CARGO) fmt --all -- --check
	cd sentinel && $(CARGO) clippy --workspace --all-targets -- -D warnings
	cd sentinel && $(CARGO) test --workspace
```

- [ ] **Step 8: Verify the empty workspace builds and `make check` sees it**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cd sentinel && cargo build --workspace && cargo fmt --all -- --check && cd ..`
Expected: three crates compile; fmt clean. (`sentinel-common/src/event.rs`, `facts.rs`, `rule.rs` don't exist yet, so `lib.rs`'s `pub mod` lines will fail — create the three files as empty `//!` stubs in this step so the scaffold compiles, then Tasks 2–4 fill them.)

Create empty stubs so Step 8 passes:
- `sentinel/crates/sentinel-common/src/event.rs`: `//! Event kinds and enums. Filled in Task 2.`
- `sentinel/crates/sentinel-common/src/facts.rs`: `//! Facts groups and bits. Filled in Task 3.`
- `sentinel/crates/sentinel-common/src/rule.rs`: `//! KRule and eval. Filled in Task 4.`

With empty `facts.rs`, `pub use facts::*;` re-exports nothing — fine. `rule.rs` is empty but `lib.rs` re-exports `rule::{eval, KRule, ...}`; those don't exist yet, so for Step 8 temporarily reduce the `sentinel-common/src/lib.rs` re-exports to only the module declarations:
```rust
#![no_std]

pub mod event;
pub mod facts;
pub mod rule;
```
(Drop the `pub use` lines until Task 4; add them back in Task 4 Step 4.)

- [ ] **Step 9: Commit**

```bash
git add sentinel/Cargo.toml sentinel/Cargo.lock sentinel/rust-toolchain.toml sentinel/crates Makefile
git commit -m "feat(sentinel): workspace scaffold and make check wiring

sentinel/ is a separate Cargo workspace pinned to nightly-2026-11-03 so the
S2 eBPF crate can share the toolchain. S1 holds three pure crates:
sentinel-common, sentinel-rules, sentinel-detect. make check now runs
sentinel-check (fmt, clippy -D warnings, tests), all without root.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_017tTdALyhuFv5WMqfWC2UMV"
```

---

### Task 2: `sentinel-common` event enums

**Files:**
- Modify: `sentinel/crates/sentinel-common/src/event.rs`
- Test: inline `#[cfg(test)]` in `event.rs` (no_std crate; tests run on host with std available to the test harness)

`EventKind` is the `on` of a rule and the discriminant stamped on every raw event. `Action`, `Mode`, `Severity` are shared so the kernel object and `sentineld` agree on numeric values (they cross the ringbuf and the maps).

- [ ] **Step 1: Write the failing test**

Append to `sentinel/crates/sentinel-common/src/event.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_kind_roundtrips_through_u8() {
        for k in EventKind::ALL {
            assert_eq!(EventKind::from_u8(k as u8), Some(k));
        }
        assert_eq!(EventKind::from_u8(255), None);
    }

    #[test]
    fn severity_orders_info_lowest_critical_highest() {
        assert!(Severity::Info < Severity::Critical);
        assert!(Severity::High < Severity::Critical);
        assert!(Severity::Medium > Severity::Low);
    }

    #[test]
    fn action_and_mode_have_stable_discriminants() {
        assert_eq!(Action::Alert as u8, 0);
        assert_eq!(Action::Deny as u8, 1);
        assert_eq!(Action::Freeze as u8, 2);
        assert_eq!(Action::Kill as u8, 3);
        assert_eq!(Mode::Enforce as u8, 0);
        assert_eq!(Mode::Audit as u8, 1);
    }
}
```

- [ ] **Step 2: Run the test, watch it fail**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cd sentinel && cargo test -p sentinel-common event::tests 2>&1 | tail -20; cd ..`
Expected: FAIL — `EventKind`, `Severity`, `Action`, `Mode` are not defined.

- [ ] **Step 3: Write the implementation**

Replace the contents of `sentinel/crates/sentinel-common/src/event.rs` (keep the test module at the bottom):
```rust
//! Event kinds and the enums shared across the ringbuf and maps.

/// What a rule fires `on`, and the discriminant on every raw event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EventKind {
    Exec = 0,
    Fork = 1,
    Exit = 2,
    Connect = 3,
    Listen = 4,
    Open = 5,
    WriteRefused = 6,
    Memfd = 7,
    Ptrace = 8,
    Module = 9,
    Bpf = 10,
    Signal = 11,
    Dns = 12,
}

impl EventKind {
    /// Every variant, for exhaustive iteration in tests and validation.
    pub const ALL: [EventKind; 13] = [
        EventKind::Exec,
        EventKind::Fork,
        EventKind::Exit,
        EventKind::Connect,
        EventKind::Listen,
        EventKind::Open,
        EventKind::WriteRefused,
        EventKind::Memfd,
        EventKind::Ptrace,
        EventKind::Module,
        EventKind::Bpf,
        EventKind::Signal,
        EventKind::Dns,
    ];

    pub fn from_u8(v: u8) -> Option<EventKind> {
        EventKind::ALL.into_iter().find(|k| *k as u8 == v)
    }
}

/// What Sentinel does when a rule matches (§6). Values cross into kernel maps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Action {
    Alert = 0,
    Deny = 1,
    Freeze = 2,
    Kill = 3,
}

/// Enforce takes the action; audit only reports what would have happened (§5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    Enforce = 0,
    Audit = 1,
}

/// Alert severity (§9). Ordered: Info lowest, Critical highest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Severity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}
```

- [ ] **Step 4: Run the test, watch it pass**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cd sentinel && cargo test -p sentinel-common event::tests 2>&1 | tail -20; cd ..`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add sentinel/crates/sentinel-common/src/event.rs
git commit -m "feat(sentinel-common): event kinds, action, mode, severity enums

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_017tTdALyhuFv5WMqfWC2UMV"
```

---

### Task 3: `sentinel-common` facts groups, bits and helpers

**Files:**
- Modify: `sentinel/crates/sentinel-common/src/facts.rs`

The `Facts` value is the compiled, per-event fact vector both sides evaluate rules against. This task defines the group layout, the bit constants, and the small helpers that set bits (used by `sentineld`'s user-space fact assembly in S3 and mirrored by the kernel in S2).

- [ ] **Step 1: Write the failing test**

Append to `sentinel/crates/sentinel-common/src/facts.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn facts_default_is_all_zero() {
        let f = Facts::new();
        assert_eq!(f.0, [0u32; NGROUPS]);
    }

    #[test]
    fn uid_literal_bit_is_in_range() {
        // bit 2 is the first literal slot; slot 29 is the last (30 slots).
        assert_eq!(uid_literal_bit(0), 1 << 2);
        assert_eq!(uid_literal_bit(29), 1 << 31);
    }

    #[test]
    fn set_and_test_a_flag() {
        let mut f = Facts::new();
        f.set(G_FLAGS, F_MEMFD);
        assert!(f.has(G_FLAGS, F_MEMFD));
        assert!(!f.has(G_FLAGS, F_DELETED));
    }

    #[test]
    fn uid_facts_set_summary_and_literal() {
        // uid 1000 is a "user" (>= 1000); its literal is table slot 3.
        let mut f = Facts::new();
        f.set(G_UID, U_USER);
        f.set(G_UID, uid_literal_bit(3));
        assert!(f.has(G_UID, U_USER));
        assert!(!f.has(G_UID, U_SYSTEM));
        assert!(f.has(G_UID, uid_literal_bit(3)));
    }
}
```

- [ ] **Step 2: Run the test, watch it fail**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cd sentinel && cargo test -p sentinel-common facts::tests 2>&1 | tail -20; cd ..`
Expected: FAIL — `Facts`, group and bit constants undefined.

- [ ] **Step 3: Write the implementation**

Replace the contents of `sentinel/crates/sentinel-common/src/facts.rs` (keep the test module):
```rust
//! The per-event fact vector and its bit layout.
//!
//! A `Facts` is `[u32; NGROUPS]`: one group per `u32`, one predicate term per
//! bit. A compiled rule (`KRule`) holds masks over the same layout, and
//! `eval` (see `rule.rs`) is the only matcher. Kernel and user space must keep
//! these constants identical.

/// Number of fact groups.
pub const NGROUPS: usize = 7;

pub const G_FLAGS: usize = 0;
pub const G_UID: usize = 1;
pub const G_MOUNT: usize = 2;
pub const G_DEST: usize = 3;
pub const G_PORT: usize = 4;
pub const G_DEVICE: usize = 5;
pub const G_PTRACE: usize = 6;

// FLAGS (G_FLAGS) — exec and listen flags from §4.
pub const F_MEMFD: u32 = 1 << 0;
pub const F_DELETED: u32 = 1 << 1;
pub const F_OUTSIDE_USR: u32 = 1 << 2;
pub const F_STDIO_SOCKET: u32 = 1 << 3;
pub const F_ENV_LD: u32 = 1 << 4;
pub const F_LISTEN_NON_LOOPBACK: u32 = 1 << 5;

// UID (G_UID).
pub const U_USER: u32 = 1 << 0;
pub const U_SYSTEM: u32 = 1 << 1;
/// First bit available for a literal-uid table slot.
pub const U_LITERAL_SHIFT: u32 = 2;

// DEVICE (G_DEVICE) — device classes from §4/§5.2.
pub const D_CAMERA: u32 = 1 << 0;
pub const D_MIC: u32 = 1 << 1;
pub const D_INPUT: u32 = 1 << 2;
pub const D_UINPUT: u32 = 1 << 3;
pub const D_HIDRAW: u32 = 1 << 4;

// PTRACE (G_PTRACE) — ptrace_target from §5.2. `P_ANY` is set on every ptrace
// event so a rule with `ptrace_target = "any"` matches all of them.
pub const P_OTHER_UID: u32 = 1 << 0;
pub const P_NON_DESCENDANT: u32 = 1 << 1;
pub const P_ANY: u32 = 1 << 2;

/// The table-slot bit for literal-uid slot `i` (0-based). Slots 0..30 map to
/// bits 2..=31 of the UID group.
#[inline]
pub fn uid_literal_bit(i: usize) -> u32 {
    1u32 << (U_LITERAL_SHIFT + i as u32)
}

/// The table-slot bit for mount/CIDR/port-set slot `i` (0-based, 0..32).
#[inline]
pub fn slot_bit(i: usize) -> u32 {
    1u32 << i as u32
}

/// A per-event fact vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Facts(pub [u32; NGROUPS]);

impl Facts {
    #[inline]
    pub fn new() -> Facts {
        Facts([0; NGROUPS])
    }

    #[inline]
    pub fn set(&mut self, group: usize, bit: u32) {
        self.0[group] |= bit;
    }

    #[inline]
    pub fn has(&self, group: usize, bit: u32) -> bool {
        self.0[group] & bit == bit
    }
}

impl Default for Facts {
    fn default() -> Facts {
        Facts::new()
    }
}
```

- [ ] **Step 4: Run the test, watch it pass**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cd sentinel && cargo test -p sentinel-common facts::tests 2>&1 | tail -20; cd ..`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add sentinel/crates/sentinel-common/src/facts.rs
git commit -m "feat(sentinel-common): facts groups, bit layout and helpers

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_017tTdALyhuFv5WMqfWC2UMV"
```

---

### Task 4: `sentinel-common` KRule and eval

**Files:**
- Modify: `sentinel/crates/sentinel-common/src/rule.rs`
- Modify: `sentinel/crates/sentinel-common/src/lib.rs` (restore the full re-exports dropped in Task 1 Step 8)

`KRule` is the compiled kernel rule, `#[repr(C)]` so it lives in a BPF array map unchanged (S2). `eval` is the matcher shared by the hook and the daemon. This is the heart of the data contract.

- [ ] **Step 1: Write the failing test**

Append to `sentinel/crates/sentinel-common/src/rule.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::*;

    fn exec_rule() -> KRule {
        KRule::empty(EventKind::Exec, Action::Deny, Mode::Enforce, 0)
    }

    #[test]
    fn empty_rule_matches_any_facts_of_its_kind() {
        // No constraints => matches (e.g. the `module-load` / `any = true` case).
        let r = exec_rule();
        assert!(eval(&r, &Facts::new()));
    }

    #[test]
    fn all_requires_every_bit() {
        let mut r = exec_rule();
        r.all[G_FLAGS] = F_MEMFD;
        let mut f = Facts::new();
        assert!(!eval(&r, &f)); // memfd not set
        f.set(G_FLAGS, F_MEMFD);
        assert!(eval(&r, &f));
    }

    #[test]
    fn any_requires_one_of_group() {
        // exe_on = [shm, tmp] => MOUNT group any = slot0|slot1.
        let mut r = exec_rule();
        r.any[G_MOUNT] = slot_bit(0) | slot_bit(1);
        let mut f = Facts::new();
        assert!(!eval(&r, &f)); // on neither mount
        f.set(G_MOUNT, slot_bit(1));
        assert!(eval(&r, &f)); // on tmp
    }

    #[test]
    fn all_and_any_combine_as_and() {
        // uid = "user" AND dest in {cidr0, cidr1}
        let mut r = KRule::empty(EventKind::Connect, Action::Alert, Mode::Enforce, 1);
        r.all[G_UID] = U_USER;
        r.any[G_DEST] = slot_bit(0) | slot_bit(1);
        let mut f = Facts::new();
        f.set(G_UID, U_USER);
        assert!(!eval(&r, &f)); // dest group empty
        f.set(G_DEST, slot_bit(0));
        assert!(eval(&r, &f));
        // drop the uid bit: the AND fails even with dest present
        f.0[G_UID] = 0;
        assert!(!eval(&r, &f));
    }

    #[test]
    fn except_suppresses_on_any_overlap() {
        // match uid=system, except uid literal slot 3 (e.g. uid 0)
        let mut r = exec_rule();
        r.all[G_UID] = U_SYSTEM;
        r.ex_any[G_UID] = uid_literal_bit(3);
        let mut f = Facts::new();
        f.set(G_UID, U_SYSTEM);
        assert!(eval(&r, &f)); // no except bit => fires
        f.set(G_UID, uid_literal_bit(3));
        assert!(!eval(&r, &f)); // except holds => suppressed
    }
}
```

- [ ] **Step 2: Run the test, watch it fail**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cd sentinel && cargo test -p sentinel-common rule::tests 2>&1 | tail -20; cd ..`
Expected: FAIL — `KRule`, `eval`, the `MAX_*` constants undefined.

- [ ] **Step 3: Write the implementation**

Replace the contents of `sentinel/crates/sentinel-common/src/rule.rs` (keep the test module):
```rust
//! The compiled kernel rule and the shared evaluator.

use crate::event::{Action, EventKind, Mode};
use crate::facts::{Facts, NGROUPS};

/// Kernel-synchronous evaluation bounds the tables (§5.3).
pub const MAX_RULES: usize = 64;
pub const MAX_UID_LITERALS: usize = 30;
pub const MAX_MOUNTS: usize = 32;
pub const MAX_CIDRS: usize = 32;
pub const MAX_PORT_SETS: usize = 32;

/// A compiled kernel rule. `#[repr(C)]` so it sits in a BPF array map unchanged.
///
/// Masks are over the `Facts` layout (`facts.rs`):
/// - `all`: every set bit must be present (AND).
/// - `any`: per group, if non-zero at least one bit must be present (OR).
/// - `ex_any`: if facts overlap any set bit the rule is suppressed — this is
///   `except`, which §5.1 defines as OR across predicates and OR within a list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct KRule {
    /// `EventKind` discriminant.
    pub on: u8,
    /// `Action` discriminant.
    pub action: u8,
    /// `Mode` discriminant.
    pub mode: u8,
    pub _pad: u8,
    /// Index of the source rule, so an alert can name which rule matched.
    pub index: u32,
    pub all: [u32; NGROUPS],
    pub any: [u32; NGROUPS],
    pub ex_any: [u32; NGROUPS],
}

impl KRule {
    pub fn empty(on: EventKind, action: Action, mode: Mode, index: u32) -> KRule {
        KRule {
            on: on as u8,
            action: action as u8,
            mode: mode as u8,
            _pad: 0,
            index,
            all: [0; NGROUPS],
            any: [0; NGROUPS],
            ex_any: [0; NGROUPS],
        }
    }
}

/// Match `facts` against one compiled rule. The caller has already selected
/// rules whose `on` equals the event kind.
#[inline]
pub fn eval(rule: &KRule, facts: &Facts) -> bool {
    let f = &facts.0;
    let mut g = 0;
    while g < NGROUPS {
        // every required bit present
        if rule.all[g] & f[g] != rule.all[g] {
            return false;
        }
        // group OR, when constrained
        if rule.any[g] != 0 && rule.any[g] & f[g] == 0 {
            return false;
        }
        g += 1;
    }
    // except: any overlap suppresses
    let mut g = 0;
    while g < NGROUPS {
        if rule.ex_any[g] & f[g] != 0 {
            return false;
        }
        g += 1;
    }
    true
}
```

- [ ] **Step 4: Restore the full re-exports in `lib.rs`**

Set `sentinel/crates/sentinel-common/src/lib.rs` back to the full version from Task 1 Step 4 (the one with the `pub use` block). Verify it compiles.

- [ ] **Step 5: Run the test, watch it pass**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cd sentinel && cargo test -p sentinel-common 2>&1 | tail -20; cd ..`
Expected: PASS (all of event + facts + rule tests).

- [ ] **Step 6: Commit**

```bash
git add sentinel/crates/sentinel-common/src/rule.rs sentinel/crates/sentinel-common/src/lib.rs
git commit -m "feat(sentinel-common): KRule format and the shared eval()

The one matcher both the LSM hook (S2) and sentineld (S3) run: all/any/ex_any
masks over the facts layout. #[repr(C)] for a BPF array map; limits bound the
kernel tables (64 rules, 30 uid literals, 32 mounts/CIDRs/port sets).

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_017tTdALyhuFv5WMqfWC2UMV"
```

---

### Task 5: `sentinel-rules` model, parse and `load_dir`

**Files:**
- Create: `sentinel/crates/sentinel-rules/src/model.rs`
- Modify: `sentinel/crates/sentinel-rules/src/lib.rs`
- Test: `sentinel/crates/sentinel-rules/tests/common/mod.rs`, `sentinel/crates/sentinel-rules/tests/validate.rs` (parse half)

The raw TOML model keeps the enum-ish fields (`on`, `severity`, `action`, `mode`) as strings so `sentinel-common` stays dependency-free (no serde): Task 6's `validate` resolves them to the typed enums with good messages. `OneOrMany<T>` lets a predicate be a scalar or a list (§5.1: "A list value matches if any element does").

- [ ] **Step 1: Write the failing test**

`sentinel/crates/sentinel-rules/tests/common/mod.rs`:
```rust
//! Shared fixtures for sentinel-rules tests.
#![allow(dead_code)]

/// A valid two-rule file covering a kernel rule and a user-space rule.
pub const SAMPLE: &str = r#"
[[rule]]
id       = "exec-memfd"
desc     = "Fileless execution from a memfd"
on       = "exec"
severity = "critical"
action   = "deny"
match    = { exe_memfd = true }

[[rule]]
id       = "reverse-shell"
on       = "exec"
severity = "high"
action   = "freeze"
match    = { exe = ["/usr/bin/bash", "/usr/bin/sh"], stdio_socket = true }
except   = { ancestors = ["/usr/bin/sshd"] }
"#;
```

`sentinel/crates/sentinel-rules/tests/validate.rs` (parse portion; validation cases added in Task 6):
```rust
mod common;
use sentinel_rules::model::{parse, OneOrMany};

#[test]
fn parses_the_sample_file() {
    let rf = parse(common::SAMPLE).expect("sample parses");
    assert_eq!(rf.rules.len(), 2);
    assert_eq!(rf.rules[0].id, "exec-memfd");
    assert_eq!(rf.rules[0].on, "exec");
    assert_eq!(rf.rules[0].match_.exe_memfd, Some(true));
    // list and scalar both land in OneOrMany
    let exe = rf.rules[1].match_.exe.as_ref().unwrap().to_vec();
    assert_eq!(exe, vec!["/usr/bin/bash".to_string(), "/usr/bin/sh".to_string()]);
}

#[test]
fn unknown_predicate_key_is_a_parse_error() {
    let bad = r#"
[[rule]]
id = "x"
on = "exec"
severity = "low"
match = { exe_memfdx = true }
"#;
    assert!(parse(bad).is_err());
}

#[test]
fn scalar_predicate_value_is_accepted() {
    let one = r#"
[[rule]]
id = "cam"
on = "open"
severity = "low"
match = { device = "camera" }
"#;
    let rf = parse(one).unwrap();
    assert_eq!(rf.rules[0].match_.device.as_ref().unwrap().to_vec(), vec!["camera".to_string()]);
}
```

- [ ] **Step 2: Run the test, watch it fail**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cd sentinel && cargo test -p sentinel-rules --test validate 2>&1 | tail -20; cd ..`
Expected: FAIL — `sentinel_rules::model` does not exist.

- [ ] **Step 3: Write `model.rs`**

`sentinel/crates/sentinel-rules/src/model.rs`:
```rust
//! The raw TOML model. Enum-ish fields stay strings; `validate` (Task 6)
//! resolves and checks them.

use serde::Deserialize;

/// The whole rule file: a list of `[[rule]]` tables.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleFile {
    #[serde(default, rename = "rule")]
    pub rules: Vec<Rule>,
}

/// One rule as written in TOML.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    #[serde(default)]
    pub desc: String,
    pub on: String,
    pub severity: String,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default, rename = "match")]
    pub match_: Match,
    #[serde(default)]
    pub except: Match,
    #[serde(default)]
    pub window: Option<Window>,
    /// Source file name, filled by `load_dir`; not from TOML.
    #[serde(skip)]
    pub source: String,
}

/// Every predicate, all optional. `deny_unknown_fields` rejects typos.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Match {
    // kernel-evaluable flags (§5.2)
    pub exe_memfd: Option<bool>,
    pub exe_deleted: Option<bool>,
    pub exe_outside_usr: Option<bool>,
    pub stdio_socket: Option<bool>,
    pub env_ld: Option<bool>,
    pub exe_on: Option<OneOrMany<String>>,
    pub uid: Option<OneOrMany<UidItem>>,
    pub dest: Option<OneOrMany<String>>,
    pub port: Option<OneOrMany<PortSpec>>,
    pub listen_scope: Option<String>,
    pub device: Option<OneOrMany<String>>,
    pub ptrace_target: Option<String>,
    pub any: Option<bool>,
    // user-space only (§5.2) and the managed-home amendment (Task 14)
    pub managed_home: Option<bool>,
    pub exe: Option<OneOrMany<String>>,
    pub argv: Option<OneOrMany<String>>,
    pub parent: Option<OneOrMany<String>>,
    pub ancestors: Option<OneOrMany<String>>,
    pub unit: Option<OneOrMany<String>>,
    pub path: Option<OneOrMany<String>>,
}

/// Optional sliding-window qualifier (§5.1). Having one makes a rule user-space.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Window {
    pub count: u32,
    pub within: String,
    pub by: String,
}

/// A scalar or a list of `T`.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

impl<T: Clone> OneOrMany<T> {
    pub fn to_vec(&self) -> Vec<T> {
        match self {
            OneOrMany::One(x) => vec![x.clone()],
            OneOrMany::Many(v) => v.clone(),
        }
    }
}

/// A `uid` list item: a keyword (`"user"`/`"system"`) or a numeric uid.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum UidItem {
    Num(i64),
    Kw(String),
}

/// A `port` list item: a number or a `"start-end"` range.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum PortSpec {
    Num(i64),
    Range(String),
}

/// Parse rule-file text. Unknown keys and type errors fail here.
pub fn parse(raw: &str) -> Result<RuleFile, String> {
    toml::from_str(raw).map_err(|e| e.message().to_string())
}
```

- [ ] **Step 4: Wire `model` and `load_dir` into `lib.rs`**

Replace `sentinel/crates/sentinel-rules/src/lib.rs`:
```rust
//! Sentinel rules: parse TOML, validate, classify kernel vs user space,
//! compile to kernel tables and user-space matchers, diff rule sets.
//!
//! Pure except `load_dir`, no clock. Builds on stable so `aios-cli` can
//! path-depend on it (S4).

pub mod config;
pub mod model;

use std::fmt;
use std::path::Path;

use model::Rule;

/// A rule problem, located to a file and (usually) a rule id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleError {
    pub file: String,
    pub rule: Option<String>,
    pub message: String,
}

impl fmt::Display for RuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.rule {
            Some(id) => write!(f, "{}: rule {}: {}", self.file, id, self.message),
            None => write!(f, "{}: {}", self.file, self.message),
        }
    }
}

impl std::error::Error for RuleError {}

/// Read every `*.toml` under `dir` (sorted), parse and validate them together.
/// Returns the rules in load order, or every problem found.
pub fn load_dir(dir: &Path) -> Result<Vec<Rule>, Vec<RuleError>> {
    let mut paths: Vec<_> = match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "toml"))
            .collect(),
        Err(e) => {
            return Err(vec![RuleError {
                file: dir.display().to_string(),
                rule: None,
                message: format!("cannot read rules directory: {e}"),
            }])
        }
    };
    paths.sort();

    let mut rules = Vec::new();
    let mut errors = Vec::new();
    for p in &paths {
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        let raw = match std::fs::read_to_string(p) {
            Ok(s) => s,
            Err(e) => {
                errors.push(RuleError { file: name, rule: None, message: format!("cannot read: {e}") });
                continue;
            }
        };
        match model::parse(&raw) {
            Ok(rf) => {
                for mut r in rf.rules {
                    r.source = name.clone();
                    rules.push(r);
                }
            }
            Err(msg) => errors.push(RuleError { file: name, rule: None, message: msg }),
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    let verrs = validate::validate(&rules);
    if verrs.is_empty() {
        Ok(rules)
    } else {
        Err(verrs)
    }
}

pub mod validate;
```

(Leave `validate.rs` to Task 6; create it now as `//! Filled in Task 6.` plus a `pub fn validate(_: &[model::Rule]) -> Vec<crate::RuleError> { Vec::new() }` stub so Step 5 compiles, then Task 6 replaces it.)

- [ ] **Step 5: Run the test, watch it pass**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cd sentinel && cargo test -p sentinel-rules --test validate 2>&1 | tail -20; cd ..`
Expected: PASS (3 parse tests).

- [ ] **Step 6: Commit**

```bash
git add sentinel/crates/sentinel-rules/src/model.rs sentinel/crates/sentinel-rules/src/lib.rs \
  sentinel/crates/sentinel-rules/src/validate.rs sentinel/crates/sentinel-rules/tests
git commit -m "feat(sentinel-rules): TOML model, parse and load_dir

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_017tTdALyhuFv5WMqfWC2UMV"
```

---

### Task 6: `sentinel-rules` validation

**Files:**
- Create (replace stub): `sentinel/crates/sentinel-rules/src/validate.rs`
- Create: `sentinel/crates/sentinel-rules/src/classify.rs`
- Modify: `sentinel/crates/sentinel-rules/src/lib.rs` (add `pub mod classify;` and helper `parse_duration`)
- Test: add to `sentinel/crates/sentinel-rules/tests/validate.rs`

Validation covers every §5.1 error class: id format, duplicate ids, unknown `on`/`severity`/`action`/`mode`, predicate applicability to the rule's `on`, empty match, bad globs/CIDRs/ports/uids, and `action = "deny"` on a user-space rule naming the offending predicate (§5.3). `classify` is written here because `validate` needs it for that last check; `compile` (Task 7) reuses it.

- [ ] **Step 1: Write the failing tests**

Append to `sentinel/crates/sentinel-rules/tests/validate.rs`:
```rust
use sentinel_rules::validate::validate;
use sentinel_rules::model::parse;

fn load(raw: &str) -> Vec<sentinel_rules::RuleError> {
    let mut rules = parse(raw).unwrap().rules;
    for r in &mut rules { r.source = "t.toml".into(); }
    validate(&rules)
}

fn msgs(raw: &str) -> String {
    load(raw).iter().map(|e| e.message.clone()).collect::<Vec<_>>().join(" | ")
}

#[test]
fn the_sample_is_valid() {
    assert!(load(common::SAMPLE).is_empty());
}

#[test]
fn bad_id_rejected() {
    let e = msgs(r#"[[rule]]
id="Bad_ID"
on="exec"
severity="low"
match={any=true}"#);
    assert!(e.contains("[a-z0-9-]"), "{e}");
}

#[test]
fn duplicate_ids_rejected() {
    let e = msgs(r#"[[rule]]
id="dup"
on="exec"
severity="low"
match={any=true}
[[rule]]
id="dup"
on="exec"
severity="low"
match={any=true}"#);
    assert!(e.contains("duplicate"), "{e}");
}

#[test]
fn unknown_on_rejected() {
    assert!(msgs(r#"[[rule]]
id="x"
on="nope"
severity="low"
match={any=true}"#).contains("event"));
}

#[test]
fn predicate_wrong_event_rejected() {
    // `device` only applies to `open`.
    let e = msgs(r#"[[rule]]
id="x"
on="exec"
severity="low"
match={device="camera"}"#);
    assert!(e.contains("device") && e.contains("exec"), "{e}");
}

#[test]
fn empty_match_rejected() {
    let e = msgs(r#"[[rule]]
id="x"
on="exec"
severity="low"
match={}"#);
    assert!(e.contains("no predicates"), "{e}");
}

#[test]
fn deny_on_userspace_rule_names_predicate() {
    let e = msgs(r#"[[rule]]
id="x"
on="exec"
severity="high"
action="deny"
match={exe=["/usr/bin/bash"]}"#);
    assert!(e.contains("deny") && e.contains("exe"), "{e}");
}

#[test]
fn bad_cidr_and_port_rejected() {
    assert!(msgs(r#"[[rule]]
id="x"
on="connect"
severity="low"
match={dest=["999.0.0.0/8"]}"#).contains("dest"));
    assert!(msgs(r#"[[rule]]
id="y"
on="connect"
severity="low"
match={port=[70000]}"#).contains("port"));
}

#[test]
fn bad_glob_rejected() {
    assert!(msgs(r#"[[rule]]
id="x"
on="exec"
severity="low"
match={exe=["/usr/bin/[["]}"#).contains("glob"));
}
```

- [ ] **Step 2: Run the tests, watch them fail**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cd sentinel && cargo test -p sentinel-rules --test validate 2>&1 | tail -25; cd ..`
Expected: FAIL — the stub `validate` returns no errors.

- [ ] **Step 3: Write `classify.rs`**

`sentinel/crates/sentinel-rules/src/classify.rs`:
```rust
//! Split a rule into kernel-evaluable vs user-space (§5.3).

use crate::model::Match;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Kernel,
    User,
}

/// The user-space-only predicates, in the order we report them.
const USER_PREDS: &[&str] = &["exe", "argv", "parent", "ancestors", "unit", "path", "managed_home"];

/// First user-space-only predicate set in `m`, if any.
pub fn first_user_pred(m: &Match) -> Option<&'static str> {
    for name in USER_PREDS {
        let set = match *name {
            "exe" => m.exe.is_some(),
            "argv" => m.argv.is_some(),
            "parent" => m.parent.is_some(),
            "ancestors" => m.ancestors.is_some(),
            "unit" => m.unit.is_some(),
            "path" => m.path.is_some(),
            "managed_home" => m.managed_home.is_some(),
            _ => false,
        };
        if set {
            return Some(name);
        }
    }
    None
}

/// Classify a rule. A window, or any user-space predicate in `match` or
/// `except`, forces user space. Returns the first offending predicate too.
pub fn classify(match_: &Match, except: &Match, has_window: bool) -> (Kind, Option<&'static str>) {
    if has_window {
        return (Kind::User, Some("window"));
    }
    if let Some(p) = first_user_pred(match_).or_else(|| first_user_pred(except)) {
        return (Kind::User, Some(p));
    }
    (Kind::Kernel, None)
}
```

- [ ] **Step 4: Write `validate.rs`**

`sentinel/crates/sentinel-rules/src/validate.rs`:
```rust
//! Validate parsed rules. Every §5.1 error class, with file+id locations.

use globset::Glob;
use sentinel_common::EventKind;

use crate::classify::{classify, Kind};
use crate::model::{Match, PortSpec, Rule, UidItem};
use crate::RuleError;

/// Map the 8 valid `on` strings to an `EventKind` (the subset rules may fire on).
pub fn parse_on(s: &str) -> Option<EventKind> {
    Some(match s {
        "exec" => EventKind::Exec,
        "connect" => EventKind::Connect,
        "listen" => EventKind::Listen,
        "open" => EventKind::Open,
        "write_refused" => EventKind::WriteRefused,
        "memfd" => EventKind::Memfd,
        "ptrace" => EventKind::Ptrace,
        "module" => EventKind::Module,
        _ => return None,
    })
}

pub fn parse_severity(s: &str) -> Option<sentinel_common::Severity> {
    use sentinel_common::Severity::*;
    Some(match s {
        "info" => Info,
        "low" => Low,
        "medium" => Medium,
        "high" => High,
        "critical" => Critical,
        _ => return None,
    })
}

pub fn parse_action(s: &str) -> Option<sentinel_common::Action> {
    use sentinel_common::Action::*;
    Some(match s {
        "alert" => Alert,
        "deny" => Deny,
        "freeze" => Freeze,
        "kill" => Kill,
        _ => return None,
    })
}

pub fn parse_mode(s: &str) -> Option<sentinel_common::Mode> {
    use sentinel_common::Mode::*;
    Some(match s {
        "enforce" => Enforce,
        "audit" => Audit,
        _ => return None,
    })
}

/// Parse a duration like `"60s"`, `"5s"`, `"2m"` into milliseconds.
pub fn parse_duration_ms(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (num, unit) = s.split_at(
        s.find(|c: char| c.is_ascii_alphabetic())
            .ok_or_else(|| format!("{s:?} has no unit"))?,
    );
    let n: u64 = num.trim().parse().map_err(|_| format!("{s:?} has a bad number"))?;
    let mult = match unit {
        "ms" => 1,
        "s" => 1000,
        "m" => 60_000,
        "h" => 3_600_000,
        _ => return Err(format!("{s:?} has an unknown unit")),
    };
    Ok(n * mult)
}

fn id_ok(id: &str) -> bool {
    !id.is_empty()
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

pub fn validate(rules: &[Rule]) -> Vec<RuleError> {
    let mut errors = Vec::new();
    let mut seen: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();

    for r in rules {
        let err = |message: String| RuleError {
            file: r.source.clone(),
            rule: Some(r.id.clone()),
            message,
        };

        if !id_ok(&r.id) {
            errors.push(err(format!("id {:?} must match [a-z0-9-]+ and be non-empty", r.id)));
        }
        if let Some(_prev) = seen.insert(r.id.as_str(), 0) {
            errors.push(err(format!("duplicate rule id {:?}", r.id)));
        }

        let on = match parse_on(&r.on) {
            Some(k) => k,
            None => {
                errors.push(err(format!(
                    "unknown event {:?} (exec|connect|listen|open|write_refused|memfd|ptrace|module)",
                    r.on
                )));
                continue;
            }
        };
        if parse_severity(&r.severity).is_none() {
            errors.push(err(format!("unknown severity {:?}", r.severity)));
        }
        let action = match &r.action {
            Some(a) => match parse_action(a) {
                Some(x) => x,
                None => {
                    errors.push(err(format!("unknown action {:?}", a)));
                    sentinel_common::Action::Alert
                }
            },
            None => sentinel_common::Action::Alert,
        };
        if let Some(m) = &r.mode {
            if parse_mode(m).is_none() {
                errors.push(err(format!("unknown mode {:?}", m)));
            }
        }

        validate_match(&r.match_, on, false, &err, &mut errors);
        validate_match(&r.except, on, true, &err, &mut errors);

        if is_empty(&r.match_) {
            errors.push(err("match has no predicates (use any = true to match every event)".into()));
        }

        let (kind, offending) = classify(&r.match_, &r.except, r.window.is_some());
        if action == sentinel_common::Action::Deny && kind == Kind::User {
            errors.push(err(format!(
                "action \"deny\" must be decided in the kernel, but predicate {:?} needs user space",
                offending.unwrap_or("window")
            )));
        }

        if let Some(w) = &r.window {
            if w.count == 0 {
                errors.push(err("window.count must be >= 1".into()));
            }
            if let Err(m) = parse_duration_ms(&w.within) {
                errors.push(err(format!("window.within: {m}")));
            }
            if !matches!(w.by.as_str(), "exe" | "uid" | "unit" | "dest") {
                errors.push(err(format!("window.by {:?} must be exe|uid|unit|dest", w.by)));
            }
        }
    }
    errors
}

/// Is this match empty (no predicate at all)?
pub fn is_empty(m: &Match) -> bool {
    let Match {
        exe_memfd, exe_deleted, exe_outside_usr, stdio_socket, env_ld, exe_on, uid, dest, port,
        listen_scope, device, ptrace_target, any, managed_home, exe, argv, parent, ancestors, unit,
        path,
    } = m;
    exe_memfd.is_none() && exe_deleted.is_none() && exe_outside_usr.is_none() && stdio_socket.is_none()
        && env_ld.is_none() && exe_on.is_none() && uid.is_none() && dest.is_none() && port.is_none()
        && listen_scope.is_none() && device.is_none() && ptrace_target.is_none() && any.is_none()
        && managed_home.is_none() && exe.is_none() && argv.is_none() && parent.is_none()
        && ancestors.is_none() && unit.is_none() && path.is_none()
}

/// Which event kinds a predicate applies to; `None` = all 8.
fn applies_to(pred: &str) -> Option<&'static [EventKind]> {
    use EventKind::*;
    Some(match pred {
        "exe_memfd" | "exe_deleted" | "exe_outside_usr" | "stdio_socket" | "env_ld" | "exe_on"
        | "argv" => &[Exec],
        "dest" => &[Connect],
        "port" => &[Connect, Listen],
        "listen_scope" => &[Listen],
        "device" => &[Open],
        "ptrace_target" => &[Ptrace],
        "path" => &[Open, WriteRefused],
        "managed_home" => &[WriteRefused],
        // uid, exe, parent, ancestors, unit, any apply to all
        _ => return None,
    })
}

/// The lowercase `on` name for a kind, matching the TOML spelling.
fn on_name(k: EventKind) -> &'static str {
    use EventKind::*;
    match k {
        Exec => "exec",
        Connect => "connect",
        Listen => "listen",
        Open => "open",
        WriteRefused => "write_refused",
        Memfd => "memfd",
        Ptrace => "ptrace",
        Module => "module",
        _ => "?",
    }
}

fn check_applies(pred: &str, on: EventKind, except: bool, err: &dyn Fn(String) -> RuleError, out: &mut Vec<RuleError>) {
    if let Some(kinds) = applies_to(pred) {
        if !kinds.contains(&on) {
            let where_ = if except { "except" } else { "match" };
            out.push(err(format!(
                "{where_} predicate {pred:?} does not apply to on = {}",
                on_name(on)
            )));
        }
    }
}

fn check_globs(pred: &str, v: &crate::model::OneOrMany<String>, err: &dyn Fn(String) -> RuleError, out: &mut Vec<RuleError>) {
    for g in v.to_vec() {
        if Glob::new(&g).is_err() {
            out.push(err(format!("{pred}: glob {g:?} does not compile")));
        }
    }
}

fn validate_match(m: &Match, on: EventKind, except: bool, err: &dyn Fn(String) -> RuleError, out: &mut Vec<RuleError>) {
    // applicability for every set predicate
    macro_rules! appl {
        ($field:ident, $name:literal) => {
            if m.$field.is_some() {
                check_applies($name, on, except, err, out);
            }
        };
    }
    appl!(exe_memfd, "exe_memfd");
    appl!(exe_deleted, "exe_deleted");
    appl!(exe_outside_usr, "exe_outside_usr");
    appl!(stdio_socket, "stdio_socket");
    appl!(env_ld, "env_ld");
    appl!(exe_on, "exe_on");
    appl!(dest, "dest");
    appl!(port, "port");
    appl!(listen_scope, "listen_scope");
    appl!(device, "device");
    appl!(ptrace_target, "ptrace_target");
    appl!(managed_home, "managed_home");
    appl!(argv, "argv");
    appl!(path, "path");

    // value checks
    if let Some(v) = &m.exe {
        check_globs("exe", v, err, out);
    }
    for (name, opt) in [
        ("argv", &m.argv),
        ("parent", &m.parent),
        ("ancestors", &m.ancestors),
        ("unit", &m.unit),
        ("path", &m.path),
    ] {
        if let Some(v) = opt {
            check_globs(name, v, err, out);
        }
    }
    if let Some(v) = &m.dest {
        for c in v.to_vec() {
            if c.parse::<ipnet::IpNet>().is_err() {
                out.push(err(format!("dest: {c:?} is not a CIDR")));
            }
        }
    }
    if let Some(v) = &m.port {
        for p in v.to_vec() {
            match p {
                PortSpec::Num(n) => {
                    if !(1..=65535).contains(&n) {
                        out.push(err(format!("port: {n} out of range 1..=65535")));
                    }
                }
                PortSpec::Range(s) => {
                    if parse_port_range(&s).is_none() {
                        out.push(err(format!("port: range {s:?} is not start-end in 1..=65535")));
                    }
                }
            }
        }
    }
    if let Some(v) = &m.uid {
        let mut n = 0;
        for it in v.to_vec() {
            match it {
                UidItem::Num(x) => {
                    if !(0..=u32::MAX as i64).contains(&x) {
                        out.push(err(format!("uid: {x} out of range")));
                    }
                    n += 1;
                }
                UidItem::Kw(k) if k == "user" || k == "system" => {}
                UidItem::Kw(k) => out.push(err(format!("uid: {k:?} must be a number, \"user\" or \"system\""))),
            }
        }
        if n > sentinel_common::MAX_UID_LITERALS {
            out.push(err(format!("uid: at most {} literal uids", sentinel_common::MAX_UID_LITERALS)));
        }
    }
    if let Some(v) = &m.device {
        for d in v.to_vec() {
            if !matches!(d.as_str(), "camera" | "mic" | "input" | "uinput" | "hidraw") {
                out.push(err(format!("device: {d:?} is not camera|mic|input|uinput|hidraw")));
            }
        }
    }
    if let Some(s) = &m.listen_scope {
        if s != "non-loopback" {
            out.push(err(format!("listen_scope: {s:?} must be \"non-loopback\"")));
        }
    }
    if let Some(s) = &m.ptrace_target {
        if !matches!(s.as_str(), "other-uid" | "non-descendant" | "any") {
            out.push(err(format!("ptrace_target: {s:?} must be other-uid|non-descendant|any")));
        }
    }
}

/// Parse `"start-end"` into an inclusive port range.
pub fn parse_port_range(s: &str) -> Option<(u16, u16)> {
    let (a, b) = s.split_once('-')?;
    let a: u32 = a.trim().parse().ok()?;
    let b: u32 = b.trim().parse().ok()?;
    if (1..=65535).contains(&a) && (1..=65535).contains(&b) && a <= b {
        Some((a as u16, b as u16))
    } else {
        None
    }
}
```

- [ ] **Step 5: Add `pub mod classify;` to `lib.rs`**

In `sentinel/crates/sentinel-rules/src/lib.rs`, add `pub mod classify;` next to the other `pub mod` lines, and re-export the duration helper for Task 9: `pub use validate::parse_duration_ms;`.

- [ ] **Step 6: Run the tests, watch them pass**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cd sentinel && cargo test -p sentinel-rules --test validate 2>&1 | tail -25; cd ..`
Expected: PASS (all parse + validation tests).

- [ ] **Step 7: Commit**

```bash
git add sentinel/crates/sentinel-rules/src/validate.rs sentinel/crates/sentinel-rules/src/classify.rs \
  sentinel/crates/sentinel-rules/src/lib.rs sentinel/crates/sentinel-rules/tests/validate.rs
git commit -m "feat(sentinel-rules): validation and kernel/user classification

Every §5.1 error class with file+id locations: id format, duplicate ids,
unknown on/severity/action/mode, predicate applicability, empty match, bad
glob/CIDR/port/uid, and deny on a user-space rule naming the predicate.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_017tTdALyhuFv5WMqfWC2UMV"
```

---

### Task 7: `sentinel-rules` kernel tables and compilation

**Files:**
- Create: `sentinel/crates/sentinel-rules/src/compile.rs`
- Modify: `sentinel/crates/sentinel-rules/src/lib.rs` (`pub mod compile;`)
- Test: `sentinel/crates/sentinel-rules/tests/compile.rs`

`compile_kernel` turns kernel rules into `KRule`s plus the side tables (`uid_lits`, `mounts`, `cidrs`, `port_sets`) that S2's maps are built from. `build_masks` is the shared translation from predicates to the `all`/`any`/`ex_any` masks over the `Facts` layout; Task 8 reuses it for the kernel portion of user-space rules, so both evaluate the same way. Slots are interned and deduplicated; exceeding a `MAX_*` limit is an error.

**Mapping (why each predicate lands where):**
- FLAGS group, `all`: `exe_memfd`/`exe_deleted`/`exe_outside_usr`/`stdio_socket`/`env_ld` and `listen_scope = "non-loopback"` — flags AND together.
- `exe_on` → `any[MOUNT]` (OR of mount slots), `uid` → `any[UID]` (OR of `user`/`system`/literal bits), `dest` → `any[DEST]` (OR of per-CIDR slots — the kernel LPM map sets a bit per matching prefix), `device` → `any[DEVICE]`.
- `port` → `all[PORT]` as **one** slot for the whole set (membership is a single test, so one bit).
- `ptrace_target` → `all[PTRACE]` one bit (`"any"` → `P_ANY`, always present on ptrace events).
- `any = true` adds no bits (matches every event of its kind).
- `except` ORs every element bit into `ex_any` (§5.1: except is OR across predicates and within a list).

- [ ] **Step 1: Write the failing test**

`sentinel/crates/sentinel-rules/tests/compile.rs`:
```rust
mod common;
use sentinel_common::{eval, Facts, EventKind};
use sentinel_common::{G_FLAGS, G_MOUNT, G_UID, G_DEST, F_MEMFD, F_STDIO_SOCKET, U_USER, slot_bit};
use sentinel_rules::compile::compile_kernel;
use sentinel_rules::model::parse;

fn rules(raw: &str) -> Vec<sentinel_rules::model::Rule> {
    let mut rs = parse(raw).unwrap().rules;
    for r in &mut rs { r.source = "t.toml".into(); }
    rs
}

#[test]
fn memfd_rule_compiles_to_a_flags_bit() {
    let t = compile_kernel(&rules(common::SAMPLE)).unwrap();
    // SAMPLE has one kernel rule (exec-memfd); reverse-shell is user-space.
    assert_eq!(t.rules.len(), 1);
    let kr = &t.rules[0];
    assert_eq!(kr.on, EventKind::Exec as u8);
    assert_eq!(kr.all[G_FLAGS], F_MEMFD);
    // a memfd exec matches; a plain exec does not
    let mut f = Facts::new();
    assert!(!eval(kr, &f));
    f.set(G_FLAGS, F_MEMFD);
    assert!(eval(kr, &f));
}

#[test]
fn exe_on_list_and_uid_and_dest_use_any() {
    let raw = r#"
[[rule]]
id="exec-shm"
on="exec"
severity="high"
action="deny"
match={ exe_on=["/dev/shm","/tmp"] }

[[rule]]
id="user-beacon"
on="connect"
severity="medium"
match={ uid="user", dest=["10.0.0.0/8","192.168.0.0/16"] }
"#;
    let t = compile_kernel(&rules(raw)).unwrap();
    assert_eq!(t.mounts.len(), 2);
    assert_eq!(t.cidrs.len(), 2);
    // exec-shm: any over the two mount slots
    let shm = &t.rules[0];
    assert_eq!(shm.any[G_MOUNT], slot_bit(0) | slot_bit(1));
    // user-beacon: uid user in all, dest any over two cidr slots
    let bc = &t.rules[1];
    assert_eq!(bc.all[G_UID], U_USER);
    assert_eq!(bc.any[G_DEST], slot_bit(0) | slot_bit(1));
}

#[test]
fn slots_are_deduplicated_across_rules() {
    let raw = r#"
[[rule]]
id="a"
on="connect"
severity="low"
match={ dest=["10.0.0.0/8"] }
[[rule]]
id="b"
on="connect"
severity="low"
match={ dest=["10.0.0.0/8"] }
"#;
    let t = compile_kernel(&rules(raw)).unwrap();
    assert_eq!(t.cidrs.len(), 1, "same CIDR shares one slot");
    assert_eq!(t.rules[0].any[G_DEST], t.rules[1].any[G_DEST]);
}

#[test]
fn too_many_rules_is_an_error() {
    let mut raw = String::new();
    for i in 0..65 {
        raw.push_str(&format!("[[rule]]\nid=\"r{i}\"\non=\"exec\"\nseverity=\"low\"\nmatch={{any=true}}\n"));
    }
    assert!(compile_kernel(&rules(&raw)).is_err());
}
```

- [ ] **Step 2: Run the test, watch it fail**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cd sentinel && cargo test -p sentinel-rules --test compile 2>&1 | tail -20; cd ..`
Expected: FAIL — `sentinel_rules::compile` does not exist.

- [ ] **Step 3: Write `compile.rs`**

`sentinel/crates/sentinel-rules/src/compile.rs`:
```rust
//! Compile kernel-evaluable rules into `KRule`s and the side tables S2's maps
//! are built from. `build_masks` is shared with the user-rule matcher (Task 8).

use ipnet::IpNet;
use sentinel_common::{
    slot_bit, uid_literal_bit, Action, KRule, Mode, D_CAMERA, D_HIDRAW, D_INPUT, D_MIC, D_UINPUT,
    F_ENV_LD, F_DELETED, F_LISTEN_NON_LOOPBACK, F_MEMFD, F_OUTSIDE_USR, F_STDIO_SOCKET, G_DEST,
    G_DEVICE, G_FLAGS, G_MOUNT, G_PORT, G_PTRACE, G_UID, NGROUPS, P_ANY, P_NON_DESCENDANT,
    P_OTHER_UID, U_SYSTEM, U_USER, MAX_CIDRS, MAX_MOUNTS, MAX_PORT_SETS, MAX_RULES,
    MAX_UID_LITERALS,
};

use crate::classify::{classify, Kind};
use crate::model::{Match, OneOrMany, PortSpec, Rule, UidItem};
use crate::validate::{parse_on, parse_port_range};
use crate::RuleError;

/// The kernel-side tables. Indices are the bit positions in each group.
#[derive(Debug, Default, Clone)]
pub struct Tables {
    pub uid_lits: Vec<u32>,
    pub mounts: Vec<String>,
    pub cidrs: Vec<IpNet>,
    pub port_sets: Vec<Vec<(u16, u16)>>,
    /// Compiled kernel rules, in source order.
    pub rules: Vec<KRule>,
}

impl Tables {
    fn intern_uid(&mut self, uid: u32) -> Option<u32> {
        if let Some(i) = self.uid_lits.iter().position(|&x| x == uid) {
            return Some(uid_literal_bit(i));
        }
        if self.uid_lits.len() >= MAX_UID_LITERALS {
            return None;
        }
        self.uid_lits.push(uid);
        Some(uid_literal_bit(self.uid_lits.len() - 1))
    }
    fn intern_mount(&mut self, path: &str) -> Option<u32> {
        if let Some(i) = self.mounts.iter().position(|x| x == path) {
            return Some(slot_bit(i));
        }
        if self.mounts.len() >= MAX_MOUNTS {
            return None;
        }
        self.mounts.push(path.to_string());
        Some(slot_bit(self.mounts.len() - 1))
    }
    fn intern_cidr(&mut self, net: IpNet) -> Option<u32> {
        if let Some(i) = self.cidrs.iter().position(|x| *x == net) {
            return Some(slot_bit(i));
        }
        if self.cidrs.len() >= MAX_CIDRS {
            return None;
        }
        self.cidrs.push(net);
        Some(slot_bit(self.cidrs.len() - 1))
    }
    fn intern_portset(&mut self, set: Vec<(u16, u16)>) -> Option<u32> {
        if let Some(i) = self.port_sets.iter().position(|x| *x == set) {
            return Some(slot_bit(i));
        }
        if self.port_sets.len() >= MAX_PORT_SETS {
            return None;
        }
        self.port_sets.push(set);
        Some(slot_bit(self.port_sets.len() - 1))
    }
}

fn normalize_ports(v: &OneOrMany<PortSpec>) -> Vec<(u16, u16)> {
    let mut out: Vec<(u16, u16)> = Vec::new();
    for p in v.to_vec() {
        match p {
            PortSpec::Num(n) => out.push((n as u16, n as u16)),
            PortSpec::Range(s) => {
                if let Some(r) = parse_port_range(&s) {
                    out.push(r);
                }
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn device_bit(d: &str) -> u32 {
    match d {
        "camera" => D_CAMERA,
        "mic" => D_MIC,
        "input" => D_INPUT,
        "uinput" => D_UINPUT,
        "hidraw" => D_HIDRAW,
        _ => 0,
    }
}

/// Translate a rule's kernel-evaluable predicates into masks. `except` bits go
/// entirely into `ex_any`. Returns `Err` when a table limit is hit.
pub fn build_masks(
    m: &Match,
    except: &Match,
    t: &mut Tables,
) -> Result<([u32; NGROUPS], [u32; NGROUPS], [u32; NGROUPS]), String> {
    let mut all = [0u32; NGROUPS];
    let mut any = [0u32; NGROUPS];
    let mut ex = [0u32; NGROUPS];

    // match: positive constraints
    add_flags(m, &mut all);
    if let Some(v) = &m.exe_on {
        for p in v.to_vec() {
            any[G_MOUNT] |= t.intern_mount(&p).ok_or("too many exe_on mount points")?;
        }
    }
    if let Some(v) = &m.uid {
        any[G_UID] |= uid_bits(v, t)?;
    }
    if let Some(v) = &m.dest {
        for c in v.to_vec() {
            let net: IpNet = c.parse().map_err(|_| format!("bad CIDR {c:?}"))?;
            any[G_DEST] |= t.intern_cidr(net).ok_or("too many dest CIDRs")?;
        }
    }
    if let Some(v) = &m.port {
        all[G_PORT] |= t.intern_portset(normalize_ports(v)).ok_or("too many port sets")?;
    }
    if let Some(v) = &m.device {
        for d in v.to_vec() {
            any[G_DEVICE] |= device_bit(&d);
        }
    }
    if let Some(s) = &m.ptrace_target {
        all[G_PTRACE] |= ptrace_bit(s);
    }
    // `any = true` adds nothing.

    // except: OR everything into ex_any (reuses the same interned slots)
    add_flags(except, &mut ex);
    if let Some(v) = &except.exe_on {
        for p in v.to_vec() {
            ex[G_MOUNT] |= t.intern_mount(&p).ok_or("too many exe_on mount points")?;
        }
    }
    if let Some(v) = &except.uid {
        ex[G_UID] |= uid_bits(v, t)?;
    }
    if let Some(v) = &except.dest {
        for c in v.to_vec() {
            let net: IpNet = c.parse().map_err(|_| format!("bad CIDR {c:?}"))?;
            ex[G_DEST] |= t.intern_cidr(net).ok_or("too many dest CIDRs")?;
        }
    }
    if let Some(v) = &except.port {
        ex[G_PORT] |= t.intern_portset(normalize_ports(v)).ok_or("too many port sets")?;
    }
    if let Some(v) = &except.device {
        for d in v.to_vec() {
            ex[G_DEVICE] |= device_bit(&d);
        }
    }
    if let Some(s) = &except.ptrace_target {
        ex[G_PTRACE] |= ptrace_bit(s);
    }

    Ok((all, any, ex))
}

fn add_flags(m: &Match, out: &mut [u32; NGROUPS]) {
    if m.exe_memfd == Some(true) {
        out[G_FLAGS] |= F_MEMFD;
    }
    if m.exe_deleted == Some(true) {
        out[G_FLAGS] |= F_DELETED;
    }
    if m.exe_outside_usr == Some(true) {
        out[G_FLAGS] |= F_OUTSIDE_USR;
    }
    if m.stdio_socket == Some(true) {
        out[G_FLAGS] |= F_STDIO_SOCKET;
    }
    if m.env_ld == Some(true) {
        out[G_FLAGS] |= F_ENV_LD;
    }
    if m.listen_scope.as_deref() == Some("non-loopback") {
        out[G_FLAGS] |= F_LISTEN_NON_LOOPBACK;
    }
}

fn uid_bits(v: &OneOrMany<UidItem>, t: &mut Tables) -> Result<u32, String> {
    let mut bits = 0u32;
    for it in v.to_vec() {
        bits |= match it {
            UidItem::Kw(k) if k == "user" => U_USER,
            UidItem::Kw(k) if k == "system" => U_SYSTEM,
            UidItem::Kw(k) => return Err(format!("bad uid keyword {k:?}")),
            UidItem::Num(n) => t.intern_uid(n as u32).ok_or("too many literal uids")?,
        };
    }
    Ok(bits)
}

fn ptrace_bit(s: &str) -> u32 {
    match s {
        "other-uid" => P_OTHER_UID,
        "non-descendant" => P_NON_DESCENDANT,
        "any" => P_ANY,
        _ => 0,
    }
}

/// Compile only the kernel rules, returning the populated tables.
pub fn compile_kernel(rules: &[Rule]) -> Result<Tables, Vec<RuleError>> {
    let mut t = Tables::default();
    let mut errors = Vec::new();

    for (i, r) in rules.iter().enumerate() {
        let (kind, _) = classify(&r.match_, &r.except, r.window.is_some());
        if kind != Kind::Kernel {
            continue;
        }
        let on = parse_on(&r.on).expect("validated");
        let action = r
            .action
            .as_deref()
            .and_then(crate::validate::parse_action)
            .unwrap_or(Action::Alert);
        let mode = r
            .mode
            .as_deref()
            .and_then(crate::validate::parse_mode)
            .unwrap_or(Mode::Enforce);

        match build_masks(&r.match_, &r.except, &mut t) {
            Ok((all, any, ex)) => {
                let mut kr = KRule::empty(on, action, mode, i as u32);
                kr.all = all;
                kr.any = any;
                kr.ex_any = ex;
                t.rules.push(kr);
            }
            Err(msg) => errors.push(RuleError {
                file: r.source.clone(),
                rule: Some(r.id.clone()),
                message: msg,
            }),
        }
    }

    if t.rules.len() > MAX_RULES {
        errors.push(RuleError {
            file: String::new(),
            rule: None,
            message: format!("{} kernel rules exceed the limit of {MAX_RULES}", t.rules.len()),
        });
    }
    if errors.is_empty() {
        Ok(t)
    } else {
        Err(errors)
    }
}
```

- [ ] **Step 4: Add `pub mod compile;` to `lib.rs`** and re-export `parse_action`/`parse_mode` from `validate` (used by `compile`): add `pub use validate::{parse_action, parse_mode, parse_on};`.

- [ ] **Step 5: Run the test, watch it pass**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cd sentinel && cargo test -p sentinel-rules --test compile 2>&1 | tail -20; cd ..`
Expected: PASS (4 tests).

- [ ] **Step 6: Commit**

```bash
git add sentinel/crates/sentinel-rules/src/compile.rs sentinel/crates/sentinel-rules/src/lib.rs \
  sentinel/crates/sentinel-rules/tests/compile.rs
git commit -m "feat(sentinel-rules): compile kernel rules into KRules and side tables

build_masks translates predicates into all/any/ex_any over the facts layout;
slots for uid literals, mounts, CIDRs and port sets are interned and
deduplicated, with the §5.3 limits enforced.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_017tTdALyhuFv5WMqfWC2UMV"
```

---

### Task 8: `sentinel-rules` user-space matcher and sliding windows

**Files:**
- Create: `sentinel/crates/sentinel-rules/src/matcher.rs`
- Create: `sentinel/crates/sentinel-rules/src/window.rs`
- Modify: `sentinel/crates/sentinel-rules/src/lib.rs` (`pub mod matcher; pub mod window;`)
- Test: `sentinel/crates/sentinel-rules/tests/matcher.rs`

A user-space rule still has a kernel-evaluable portion (its `Facts` terms) plus residual globs (`exe`, `argv`, `parent`, `ancestors`, `unit`, `path`) and the `managed_home` flag. `UserRule` holds the compiled `KRule` for the kernel portion (run through the same `eval`) and `GlobSet`s for the rest. `compile_all` returns both the kernel `Tables` and the `UserRule`s, indexed by source position so `sentineld` can recover the original rule for alert metadata. `WindowState` is a pure sliding counter; the caller supplies the clock (§14).

- [ ] **Step 1: Write the failing test**

`sentinel/crates/sentinel-rules/tests/matcher.rs`:
```rust
mod common;
use sentinel_common::{Facts, EventKind, G_FLAGS, F_STDIO_SOCKET};
use sentinel_rules::matcher::{compile_all, ResolvedEvent};
use sentinel_rules::window::WindowState;
use sentinel_rules::model::parse;

fn rules(raw: &str) -> Vec<sentinel_rules::model::Rule> {
    let mut rs = parse(raw).unwrap().rules;
    for r in &mut rs { r.source = "t.toml".into(); }
    rs
}

fn ev<'a>(kind: EventKind, facts: Facts, exe: &'a str, ancestors: &'a [String]) -> ResolvedEvent<'a> {
    ResolvedEvent { kind, facts, exe, argv: "", parent_exe: "", ancestors, unit: "", path: "", managed_home: false }
}

#[test]
fn reverse_shell_matches_exe_and_facts_but_except_suppresses() {
    let (_tables, user) = compile_all(&rules(common::SAMPLE)).unwrap();
    // one user rule: reverse-shell
    let r = user.iter().find(|u| u.index == 1).unwrap();

    let mut f = Facts::new();
    f.set(G_FLAGS, F_STDIO_SOCKET);
    let anc = vec!["/usr/bin/login".to_string()];
    // bash with a socket stdio, not under sshd => matches
    assert!(r.matches(&ev(EventKind::Exec, f, "/usr/bin/bash", &anc)));

    // same, but an sshd ancestor => except suppresses
    let anc2 = vec!["/usr/bin/sshd".to_string()];
    assert!(!r.matches(&ev(EventKind::Exec, f, "/usr/bin/bash", &anc2)));

    // wrong exe => no match even with the socket
    assert!(!r.matches(&ev(EventKind::Exec, f, "/usr/bin/cat", &anc)));

    // right exe, no socket => kernel portion fails
    assert!(!r.matches(&ev(EventKind::Exec, Facts::new(), "/usr/bin/bash", &anc)));
}

#[test]
fn window_fires_on_the_nth_event_within_the_span() {
    // 3 within 60s, keyed by exe
    let mut w = WindowState::new(3, 60_000);
    assert!(!w.record("a", 0));
    assert!(!w.record("a", 10_000));
    assert!(w.record("a", 20_000)); // 3rd within 60s
    // a different key is independent
    assert!(!w.record("b", 20_000));
}

#[test]
fn window_forgets_events_older_than_the_span() {
    let mut w = WindowState::new(2, 10_000);
    assert!(!w.record("a", 0));
    assert!(!w.record("a", 100_000)); // first is now stale; only 1 in window
    assert!(w.record("a", 105_000));  // 2 within 10s
}
```

- [ ] **Step 2: Run the test, watch it fail**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cd sentinel && cargo test -p sentinel-rules --test matcher 2>&1 | tail -20; cd ..`
Expected: FAIL — `matcher` and `window` modules do not exist.

- [ ] **Step 3: Write `window.rs`**

`sentinel/crates/sentinel-rules/src/window.rs`:
```rust
//! A pure sliding-window counter. The caller passes monotonic milliseconds.

use std::collections::{HashMap, VecDeque};

#[derive(Debug, Clone)]
pub struct WindowState {
    count: u32,
    within_ms: u64,
    keys: HashMap<String, VecDeque<u64>>,
}

impl WindowState {
    pub fn new(count: u32, within_ms: u64) -> WindowState {
        WindowState { count, within_ms, keys: HashMap::new() }
    }

    /// Record one matching event for `key` at `now_ms`. Returns true when at
    /// least `count` events for that key fall within the last `within_ms`.
    pub fn record(&mut self, key: &str, now_ms: u64) -> bool {
        let dq = self.keys.entry(key.to_string()).or_default();
        dq.push_back(now_ms);
        while let Some(&front) = dq.front() {
            if now_ms.saturating_sub(front) > self.within_ms {
                dq.pop_front();
            } else {
                break;
            }
        }
        dq.len() as u32 >= self.count
    }
}
```

- [ ] **Step 4: Write `matcher.rs`**

`sentinel/crates/sentinel-rules/src/matcher.rs`:
```rust
//! User-space rules: the kernel portion via `eval`, plus residual globs and
//! `managed_home`. `compile_all` returns the kernel tables and the user rules.

use globset::{Glob, GlobSet, GlobSetBuilder};
use sentinel_common::{eval, EventKind, Facts, KRule};

use crate::classify::{classify, Kind};
use crate::compile::{build_masks, Tables};
use crate::model::{Match, OneOrMany, Rule, Window};
use crate::validate::{parse_action, parse_mode, parse_on};
use crate::RuleError;

/// An event after `sentineld` has resolved paths, uid, unit and ancestors (§7).
pub struct ResolvedEvent<'a> {
    pub kind: EventKind,
    pub facts: Facts,
    pub exe: &'a str,
    pub argv: &'a str,
    pub parent_exe: &'a str,
    pub ancestors: &'a [String],
    pub unit: &'a str,
    pub path: &'a str,
    pub managed_home: bool,
}

/// The compiled residual (non-kernel) predicates of one `match`/`except`.
#[derive(Default)]
struct GlobPart {
    exe: Option<GlobSet>,
    argv: Option<GlobSet>,
    parent: Option<GlobSet>,
    ancestors: Option<GlobSet>,
    unit: Option<GlobSet>,
    path: Option<GlobSet>,
    managed_home: Option<bool>,
}

fn build_set(v: &OneOrMany<String>) -> GlobSet {
    let mut b = GlobSetBuilder::new();
    for g in v.to_vec() {
        // validated already; unwrap is safe
        b.add(Glob::new(&g).unwrap());
    }
    b.build().unwrap()
}

impl GlobPart {
    fn from(m: &Match) -> GlobPart {
        GlobPart {
            exe: m.exe.as_ref().map(build_set),
            argv: m.argv.as_ref().map(build_set),
            parent: m.parent.as_ref().map(build_set),
            ancestors: m.ancestors.as_ref().map(build_set),
            unit: m.unit.as_ref().map(build_set),
            path: m.path.as_ref().map(build_set),
            managed_home: m.managed_home,
        }
    }

    /// For `match`: every present predicate must hold (AND).
    fn all_hold(&self, ev: &ResolvedEvent) -> bool {
        if let Some(s) = &self.exe {
            if !s.is_match(ev.exe) {
                return false;
            }
        }
        if let Some(s) = &self.argv {
            if !s.is_match(ev.argv) {
                return false;
            }
        }
        if let Some(s) = &self.parent {
            if !s.is_match(ev.parent_exe) {
                return false;
            }
        }
        if let Some(s) = &self.ancestors {
            if !ev.ancestors.iter().any(|a| s.is_match(a)) {
                return false;
            }
        }
        if let Some(s) = &self.unit {
            if !s.is_match(ev.unit) {
                return false;
            }
        }
        if let Some(s) = &self.path {
            if !s.is_match(ev.path) {
                return false;
            }
        }
        if self.managed_home == Some(true) && !ev.managed_home {
            return false;
        }
        true
    }

    /// For `except`: any present predicate holding suppresses (OR).
    fn any_holds(&self, ev: &ResolvedEvent) -> bool {
        if self.exe.as_ref().is_some_and(|s| s.is_match(ev.exe)) {
            return true;
        }
        if self.argv.as_ref().is_some_and(|s| s.is_match(ev.argv)) {
            return true;
        }
        if self.parent.as_ref().is_some_and(|s| s.is_match(ev.parent_exe)) {
            return true;
        }
        if self
            .ancestors
            .as_ref()
            .is_some_and(|s| ev.ancestors.iter().any(|a| s.is_match(a)))
        {
            return true;
        }
        if self.unit.as_ref().is_some_and(|s| s.is_match(ev.unit)) {
            return true;
        }
        if self.path.as_ref().is_some_and(|s| s.is_match(ev.path)) {
            return true;
        }
        if self.managed_home == Some(true) && ev.managed_home {
            return true;
        }
        false
    }

    fn is_empty(&self) -> bool {
        self.exe.is_none()
            && self.argv.is_none()
            && self.parent.is_none()
            && self.ancestors.is_none()
            && self.unit.is_none()
            && self.path.is_none()
            && self.managed_home.is_none()
    }
}

/// A compiled user-space rule.
pub struct UserRule {
    pub index: u32,
    pub on: EventKind,
    pub action: sentinel_common::Action,
    pub mode: sentinel_common::Mode,
    /// Kernel-evaluable portion (facts terms), run through the shared `eval`.
    pub kernel: KRule,
    match_glob: GlobPart,
    except_glob: GlobPart,
    pub window: Option<Window>,
}

impl UserRule {
    /// Does this rule match the resolved event (ignoring any `window`, which the
    /// caller applies with a `WindowState`)?
    pub fn matches(&self, ev: &ResolvedEvent) -> bool {
        if ev.kind != self.on {
            return false;
        }
        // kernel portion (facts, incl. kernel-side except via ex_any)
        if !eval(&self.kernel, &ev.facts) {
            return false;
        }
        // residual match globs: all must hold
        if !self.match_glob.all_hold(ev) {
            return false;
        }
        // residual except globs: any holding suppresses
        if !self.except_glob.is_empty() && self.except_glob.any_holds(ev) {
            return false;
        }
        true
    }
}

/// Compile the whole rule set: kernel `Tables` plus the user-space rules.
pub fn compile_all(rules: &[Rule]) -> Result<(Tables, Vec<UserRule>), Vec<RuleError>> {
    let mut t = Tables::default();
    let mut user = Vec::new();
    let mut errors = Vec::new();

    for (i, r) in rules.iter().enumerate() {
        let on = parse_on(&r.on).expect("validated");
        let action = r.action.as_deref().and_then(parse_action).unwrap_or(sentinel_common::Action::Alert);
        let mode = r.mode.as_deref().and_then(parse_mode).unwrap_or(sentinel_common::Mode::Enforce);

        let (all, any, ex) = match build_masks(&r.match_, &r.except, &mut t) {
            Ok(v) => v,
            Err(msg) => {
                errors.push(RuleError { file: r.source.clone(), rule: Some(r.id.clone()), message: msg });
                continue;
            }
        };
        let mut kr = KRule::empty(on, action, mode, i as u32);
        kr.all = all;
        kr.any = any;
        kr.ex_any = ex;

        match classify(&r.match_, &r.except, r.window.is_some()).0 {
            Kind::Kernel => t.rules.push(kr),
            Kind::User => user.push(UserRule {
                index: i as u32,
                on,
                action,
                mode,
                kernel: kr,
                match_glob: GlobPart::from(&r.match_),
                except_glob: GlobPart::from(&r.except),
                window: r.window.clone(),
            }),
        }
    }

    if errors.is_empty() {
        Ok((t, user))
    } else {
        Err(errors)
    }
}
```

- [ ] **Step 5: Add the modules to `lib.rs`** — `pub mod matcher;` and `pub mod window;`.

- [ ] **Step 6: Run the test, watch it pass**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cd sentinel && cargo test -p sentinel-rules --test matcher 2>&1 | tail -20; cd ..`
Expected: PASS (3 tests).

- [ ] **Step 7: Commit**

```bash
git add sentinel/crates/sentinel-rules/src/matcher.rs sentinel/crates/sentinel-rules/src/window.rs \
  sentinel/crates/sentinel-rules/src/lib.rs sentinel/crates/sentinel-rules/tests/matcher.rs
git commit -m "feat(sentinel-rules): user-space matcher and sliding windows

A user rule runs its kernel portion through the shared eval() and its residual
exe/argv/parent/ancestors/unit/path globs and managed_home flag on the resolved
event; except globs suppress. WindowState is a pure per-key sliding counter.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_017tTdALyhuFv5WMqfWC2UMV"
```

---

### Task 9: `sentinel-rules` the `[sentinel]` config

**Files:**
- Create (replace stub): `sentinel/crates/sentinel-rules/src/config.rs`
- Test: `sentinel/crates/sentinel-rules/tests/config.rs`

`SentinelConfig` is the `[sentinel]` section (§11.1) including the two detector sub-tables (§5.4). It is shared by `aios-cli` (which validates the manifest section, S4) and `sentineld` (which reads the rendered `/etc/aios/sentinel/sentinel.toml`, S3). Defaults match §11.1 exactly, so an absent section yields an enabled Sentinel with those values. `validate` enforces the documented ranges.

- [ ] **Step 1: Write the failing test**

`sentinel/crates/sentinel-rules/tests/config.rs`:
```rust
use sentinel_rules::config::{parse, validate, SentinelConfig};

#[test]
fn empty_config_is_the_documented_defaults() {
    let c = SentinelConfig::default();
    assert!(c.enable);
    assert_eq!(c.rules, "sentinel/rules");
    assert_eq!(c.lockdown_after, "5s");
    assert_eq!(c.storm_brake, 5);
    assert_eq!(c.beacon.min_connects, 6);
    assert_eq!(c.beacon.max_cov, 0.2);
    assert_eq!(c.dns_tunnel.label_len, 20);
    assert_eq!(c.dns_tunnel.entropy, 3.5);
    assert!(validate(&c).is_empty());
}

#[test]
fn a_full_config_parses_and_validates() {
    let raw = r#"
enable = true
rules = "sentinel/rules"
lockdown_after = "8s"
storm_brake = 3
never_act_on = ["systemd-*.service"]
bpf_loaders = ["/usr/bin/bpftool"]

[beacon]
min_connects = 10
max_cov = 0.1
allow = ["9.9.9.9/32", "/usr/bin/chronyd"]
action = "freeze"

[dns_tunnel]
label_len = 24
entropy = 4.0
unique_per_min = 50
"#;
    let c = parse(raw).expect("parses");
    assert_eq!(c.lockdown_after, "8s");
    assert_eq!(c.beacon.action, "freeze");
    assert!(validate(&c).is_empty());
}

#[test]
fn out_of_range_values_are_rejected() {
    let mut c = SentinelConfig::default();
    c.lockdown_after = "60s".into(); // > 30s
    assert!(validate(&c).iter().any(|m| m.contains("lockdown_after")));

    let mut c = SentinelConfig::default();
    c.beacon.max_cov = 2.0; // > 1.0
    assert!(validate(&c).iter().any(|m| m.contains("max_cov")));

    let mut c = SentinelConfig::default();
    c.beacon.allow = vec!["not a cidr or /glob".into()];
    assert!(validate(&c).iter().any(|m| m.contains("allow")));

    let mut c = SentinelConfig::default();
    c.beacon.action = "deny".into(); // detectors never deny (§5.4)
    assert!(validate(&c).iter().any(|m| m.contains("action")));
}
```

- [ ] **Step 2: Run the test, watch it fail**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cd sentinel && cargo test -p sentinel-rules --test config 2>&1 | tail -20; cd ..`
Expected: FAIL — `config` has no `SentinelConfig`.

- [ ] **Step 3: Write `config.rs`**

`sentinel/crates/sentinel-rules/src/config.rs`:
```rust
//! The `[sentinel]` manifest section (§11.1) and the two detector configs
//! (§5.4). Shared by `aios-cli` and `sentineld`.

use globset::Glob;
use serde::Deserialize;

use crate::validate::{parse_duration_ms, parse_severity};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SentinelConfig {
    pub enable: bool,
    pub rules: String,
    pub lockdown_after: String,
    pub storm_brake: u32,
    pub never_act_on: Vec<String>,
    pub bpf_loaders: Vec<String>,
    pub beacon: Beacon,
    pub dns_tunnel: DnsTunnel,
}

impl Default for SentinelConfig {
    fn default() -> SentinelConfig {
        SentinelConfig {
            enable: true,
            rules: "sentinel/rules".to_string(),
            lockdown_after: "5s".to_string(),
            storm_brake: 5,
            never_act_on: vec![
                "systemd-*.service".to_string(),
                "dbus-broker.service".to_string(),
            ],
            bpf_loaders: Vec::new(),
            beacon: Beacon::default(),
            dns_tunnel: DnsTunnel::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Beacon {
    pub min_connects: u32,
    pub max_cov: f64,
    pub allow: Vec<String>,
    pub severity: String,
    pub action: String,
}

impl Default for Beacon {
    fn default() -> Beacon {
        Beacon {
            min_connects: 6,
            max_cov: 0.2,
            allow: vec![
                "9.9.9.9/32".to_string(),
                "149.112.112.112/32".to_string(),
                "1.1.1.1/32".to_string(),
            ],
            severity: "high".to_string(),
            action: "alert".to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DnsTunnel {
    pub label_len: u32,
    pub entropy: f64,
    pub unique_per_min: u32,
    pub severity: String,
    pub action: String,
}

impl Default for DnsTunnel {
    fn default() -> DnsTunnel {
        DnsTunnel {
            label_len: 20,
            entropy: 3.5,
            unique_per_min: 30,
            severity: "high".to_string(),
            action: "alert".to_string(),
        }
    }
}

/// Parse a standalone `[sentinel]`-section TOML (the rendered `sentinel.toml`,
/// whose keys are top-level).
pub fn parse(raw: &str) -> Result<SentinelConfig, String> {
    toml::from_str(raw).map_err(|e| e.message().to_string())
}

/// A detector action may only be alert, freeze or kill — never deny (§5.4).
fn detector_action_ok(a: &str) -> bool {
    matches!(a, "alert" | "freeze" | "kill")
}

/// Validate the documented ranges. Returns one message per problem.
pub fn validate(c: &SentinelConfig) -> Vec<String> {
    let mut e = Vec::new();

    match parse_duration_ms(&c.lockdown_after) {
        Ok(ms) if (2000..=30000).contains(&ms) => {}
        Ok(_) => e.push(format!("lockdown_after {:?} must be 2s..=30s", c.lockdown_after)),
        Err(m) => e.push(format!("lockdown_after: {m}")),
    }
    if c.storm_brake < 1 {
        e.push("storm_brake must be >= 1".to_string());
    }
    for u in &c.never_act_on {
        if Glob::new(u).is_err() {
            e.push(format!("never_act_on: glob {u:?} does not compile"));
        }
    }

    // beacon
    if !(0.0..=1.0).contains(&c.beacon.max_cov) {
        e.push(format!("beacon.max_cov {} must be 0.0..=1.0", c.beacon.max_cov));
    }
    if c.beacon.min_connects < 2 {
        e.push("beacon.min_connects must be >= 2".to_string());
    }
    for a in &c.beacon.allow {
        // a CIDR, or a `/`-prefixed executable glob
        let ok = a.parse::<ipnet::IpNet>().is_ok()
            || (a.starts_with('/') && Glob::new(a).is_ok());
        if !ok {
            e.push(format!("beacon.allow {a:?} must be a CIDR or a /-prefixed exe glob"));
        }
    }
    if parse_severity(&c.beacon.severity).is_none() {
        e.push(format!("beacon.severity {:?} is not a severity", c.beacon.severity));
    }
    if !detector_action_ok(&c.beacon.action) {
        e.push(format!("beacon.action {:?} must be alert|freeze|kill", c.beacon.action));
    }

    // dns_tunnel
    if c.dns_tunnel.label_len < 1 {
        e.push("dns_tunnel.label_len must be >= 1".to_string());
    }
    if !(0.0..=8.0).contains(&c.dns_tunnel.entropy) {
        e.push(format!("dns_tunnel.entropy {} must be 0.0..=8.0", c.dns_tunnel.entropy));
    }
    if c.dns_tunnel.unique_per_min < 1 {
        e.push("dns_tunnel.unique_per_min must be >= 1".to_string());
    }
    if parse_severity(&c.dns_tunnel.severity).is_none() {
        e.push(format!("dns_tunnel.severity {:?} is not a severity", c.dns_tunnel.severity));
    }
    if !detector_action_ok(&c.dns_tunnel.action) {
        e.push(format!("dns_tunnel.action {:?} must be alert|freeze|kill", c.dns_tunnel.action));
    }

    e
}
```

- [ ] **Step 4: Run the test, watch it pass**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cd sentinel && cargo test -p sentinel-rules --test config 2>&1 | tail -20; cd ..`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add sentinel/crates/sentinel-rules/src/config.rs sentinel/crates/sentinel-rules/tests/config.rs
git commit -m "feat(sentinel-rules): the [sentinel] config with detector sub-tables

SentinelConfig mirrors §11.1 with §11.1 defaults; validate enforces the
documented ranges (lockdown_after 2-30s, max_cov 0-1, detector actions never
deny). Shared by aios-cli and sentineld.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_017tTdALyhuFv5WMqfWC2UMV"
```

---

### Task 10: `sentinel-rules` rule-set and config diff

**Files:**
- Create: `sentinel/crates/sentinel-rules/src/diff.rs`
- Modify: `sentinel/crates/sentinel-rules/src/model.rs` (add `PartialEq` to `Match`, `Window`, `OneOrMany`, `UidItem`, `PortSpec`)
- Modify: `sentinel/crates/sentinel-rules/src/config.rs` (add `PartialEq` to `SentinelConfig`, `Beacon`, `DnsTunnel`)
- Modify: `sentinel/crates/sentinel-rules/src/lib.rs` (`pub mod diff;`)
- Test: `sentinel/crates/sentinel-rules/tests/diff.rs`

`aios plan` prints a Sentinel summary: rules added, removed and changed (naming changed fields, e.g. `reverse-shell: action freeze → kill`), and any change to the `[sentinel]` section (§11.2). This task produces that diff; S4 wires it into the plan output.

- [ ] **Step 1: Write the failing test**

`sentinel/crates/sentinel-rules/tests/diff.rs`:
```rust
use sentinel_rules::config::SentinelConfig;
use sentinel_rules::diff::{diff_config, diff_rules};
use sentinel_rules::model::parse;

fn rules(raw: &str) -> Vec<sentinel_rules::model::Rule> {
    parse(raw).unwrap().rules
}

#[test]
fn added_removed_and_changed_rules() {
    let old = rules(r#"
[[rule]]
id="keep"
on="exec"
severity="low"
action="freeze"
match={any=true}
[[rule]]
id="gone"
on="exec"
severity="low"
match={any=true}
"#);
    let new = rules(r#"
[[rule]]
id="keep"
on="exec"
severity="low"
action="kill"
match={any=true}
[[rule]]
id="added"
on="exec"
severity="low"
match={any=true}
"#);
    let d = diff_rules(&old, &new);
    assert_eq!(d.added, vec!["added".to_string()]);
    assert_eq!(d.removed, vec!["gone".to_string()]);
    assert_eq!(d.changed.len(), 1);
    assert_eq!(d.changed[0].0, "keep");
    let line = d.summary().join("\n");
    assert!(line.contains("keep: action freeze → kill"), "{line}");
    assert!(line.contains("+ added"));
    assert!(line.contains("- gone"));
}

#[test]
fn config_change_is_reported() {
    let old = SentinelConfig::default();
    let mut new = SentinelConfig::default();
    new.lockdown_after = "10s".into();
    let lines = diff_config(&old, &new);
    assert!(lines.iter().any(|l| l.contains("lockdown_after") && l.contains("5s") && l.contains("10s")));
    assert!(diff_config(&old, &old).is_empty());
}
```

- [ ] **Step 2: Run the test, watch it fail**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cd sentinel && cargo test -p sentinel-rules --test diff 2>&1 | tail -20; cd ..`
Expected: FAIL — `diff` module absent.

- [ ] **Step 3: Add `PartialEq` derives**

In `model.rs`, change the derives on `Match`, `Window`, `OneOrMany<T>`, `UidItem`, `PortSpec` to include `PartialEq` (e.g. `#[derive(Debug, Clone, PartialEq, Deserialize)]`; `Match` keeps `Default`). In `config.rs`, add `PartialEq` to `SentinelConfig`, `Beacon`, `DnsTunnel`.

- [ ] **Step 4: Write `diff.rs`**

`sentinel/crates/sentinel-rules/src/diff.rs`:
```rust
//! Diff two rule sets and two configs for `aios plan` (§11.2).

use std::collections::BTreeMap;

use crate::config::SentinelConfig;
use crate::model::Rule;

#[derive(Debug, Default, PartialEq)]
pub struct RuleSetDiff {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    /// (id, per-field change lines)
    pub changed: Vec<(String, Vec<String>)>,
}

impl RuleSetDiff {
    /// Human lines for the plan output.
    pub fn summary(&self) -> Vec<String> {
        let mut out = Vec::new();
        for id in &self.added {
            out.push(format!("+ {id}"));
        }
        for id in &self.removed {
            out.push(format!("- {id}"));
        }
        for (id, fields) in &self.changed {
            for f in fields {
                out.push(format!("{id}: {f}"));
            }
        }
        out
    }

    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }
}

fn by_id(rules: &[Rule]) -> BTreeMap<&str, &Rule> {
    rules.iter().map(|r| (r.id.as_str(), r)).collect()
}

fn action_of(r: &Rule) -> &str {
    r.action.as_deref().unwrap_or("alert")
}
fn mode_of(r: &Rule) -> &str {
    r.mode.as_deref().unwrap_or("enforce")
}

/// The field-level changes between two rules of the same id.
pub fn rule_field_changes(old: &Rule, new: &Rule) -> Vec<String> {
    let mut c = Vec::new();
    if old.on != new.on {
        c.push(format!("on {} → {}", old.on, new.on));
    }
    if old.severity != new.severity {
        c.push(format!("severity {} → {}", old.severity, new.severity));
    }
    if action_of(old) != action_of(new) {
        c.push(format!("action {} → {}", action_of(old), action_of(new)));
    }
    if mode_of(old) != mode_of(new) {
        c.push(format!("mode {} → {}", mode_of(old), mode_of(new)));
    }
    if old.match_ != new.match_ {
        c.push("match changed".to_string());
    }
    if old.except != new.except {
        c.push("except changed".to_string());
    }
    if old.window != new.window {
        c.push("window changed".to_string());
    }
    c
}

pub fn diff_rules(old: &[Rule], new: &[Rule]) -> RuleSetDiff {
    let om = by_id(old);
    let nm = by_id(new);
    let mut d = RuleSetDiff::default();

    for id in nm.keys() {
        if !om.contains_key(id) {
            d.added.push(id.to_string());
        }
    }
    for id in om.keys() {
        if !nm.contains_key(id) {
            d.removed.push(id.to_string());
        }
    }
    for (id, nr) in &nm {
        if let Some(or) = om.get(id) {
            let fields = rule_field_changes(or, nr);
            if !fields.is_empty() {
                d.changed.push((id.to_string(), fields));
            }
        }
    }
    d.added.sort();
    d.removed.sort();
    d.changed.sort_by(|a, b| a.0.cmp(&b.0));
    d
}

/// Changed `[sentinel]` fields as `name old → new` lines.
pub fn diff_config(old: &SentinelConfig, new: &SentinelConfig) -> Vec<String> {
    let mut c = Vec::new();
    if old.enable != new.enable {
        c.push(format!("enable {} → {}", old.enable, new.enable));
    }
    if old.rules != new.rules {
        c.push(format!("rules {} → {}", old.rules, new.rules));
    }
    if old.lockdown_after != new.lockdown_after {
        c.push(format!("lockdown_after {} → {}", old.lockdown_after, new.lockdown_after));
    }
    if old.storm_brake != new.storm_brake {
        c.push(format!("storm_brake {} → {}", old.storm_brake, new.storm_brake));
    }
    if old.never_act_on != new.never_act_on {
        c.push("never_act_on changed".to_string());
    }
    if old.bpf_loaders != new.bpf_loaders {
        c.push("bpf_loaders changed".to_string());
    }
    if old.beacon != new.beacon {
        c.push("beacon changed".to_string());
    }
    if old.dns_tunnel != new.dns_tunnel {
        c.push("dns_tunnel changed".to_string());
    }
    c
}
```

- [ ] **Step 5: Add `pub mod diff;` to `lib.rs`.**

- [ ] **Step 6: Run the test, watch it pass**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cd sentinel && cargo test -p sentinel-rules --test diff 2>&1 | tail -20; cd ..`
Expected: PASS (2 tests).

- [ ] **Step 7: Commit**

```bash
git add sentinel/crates/sentinel-rules/src/diff.rs sentinel/crates/sentinel-rules/src/model.rs \
  sentinel/crates/sentinel-rules/src/config.rs sentinel/crates/sentinel-rules/src/lib.rs \
  sentinel/crates/sentinel-rules/tests/diff.rs
git commit -m "feat(sentinel-rules): rule-set and config diff for aios plan

diff_rules reports added/removed/changed rules naming changed fields
(action freeze → kill); diff_config reports [sentinel] section changes.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_017tTdALyhuFv5WMqfWC2UMV"
```

---

### Task 11: `sentinel-detect` the C2 beacon detector

**Files:**
- Create: `sentinel/crates/sentinel-detect/src/beacon.rs`
- Modify: `sentinel/crates/sentinel-detect/src/lib.rs` (`pub mod beacon;`)
- Test: `sentinel/crates/sentinel-detect/tests/beacon.rs`

Per `(executable, destination address, port)`, the detector keeps the connect timestamps over a sliding hour and fires when there are at least `min_connects` and the coefficient of variation of the intervals is at most `max_cov` (§5.4 — periodic, low-jitter traffic). It is pure: the caller passes monotonic milliseconds and has already dropped allow-listed destinations and executables (the `allow` list lives in `[sentinel.beacon]`, applied by `sentineld` before `observe`). A key re-fires at most once per hour, and the key count is bounded.

- [ ] **Step 1: Write the failing test**

`sentinel/crates/sentinel-detect/tests/beacon.rs`:
```rust
use sentinel_detect::beacon::{Beacon, BeaconConfig};

fn cfg() -> BeaconConfig {
    BeaconConfig { min_connects: 6, max_cov: 0.2, window_ms: 3_600_000, refire_ms: 3_600_000, max_keys: 1024 }
}

#[test]
fn perfectly_periodic_traffic_fires() {
    let mut b = Beacon::new(cfg());
    let mut hit = None;
    for i in 0..6u64 {
        hit = b.observe("/tmp/implant", "203.0.113.5", 443, i * 100_000);
    }
    let h = hit.expect("fires on the 6th periodic connect");
    assert_eq!(h.dest, "203.0.113.5");
    assert!(h.cov <= 0.2);
    assert_eq!(h.count, 6);
}

#[test]
fn low_jitter_still_fires() {
    let mut b = Beacon::new(cfg());
    let times = [0u64, 100_000, 205_000, 300_000, 402_000, 498_000];
    let mut hit = None;
    for t in times {
        hit = b.observe("/tmp/implant", "203.0.113.5", 443, t);
    }
    assert!(hit.is_some(), "about 5% jitter is still periodic");
}

#[test]
fn irregular_traffic_does_not_fire() {
    let mut b = Beacon::new(cfg());
    let times = [0u64, 5_000, 400_000, 410_000, 900_000, 905_000];
    let mut hit = None;
    for t in times {
        hit = b.observe("/usr/bin/curl", "203.0.113.9", 443, t);
    }
    assert!(hit.is_none());
}

#[test]
fn too_few_connects_does_not_fire() {
    let mut b = Beacon::new(cfg());
    for i in 0..5u64 {
        assert!(b.observe("/tmp/x", "203.0.113.5", 443, i * 100_000).is_none());
    }
}

#[test]
fn a_key_does_not_refire_within_the_hour() {
    let mut b = Beacon::new(cfg());
    for i in 0..6u64 {
        b.observe("/tmp/x", "203.0.113.5", 443, i * 100_000);
    }
    // another periodic connect shortly after: no second alert
    assert!(b.observe("/tmp/x", "203.0.113.5", 443, 600_000).is_none());
}
```

- [ ] **Step 2: Run the test, watch it fail**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cd sentinel && cargo test -p sentinel-detect --test beacon 2>&1 | tail -20; cd ..`
Expected: FAIL — `beacon` module absent.

- [ ] **Step 3: Write `beacon.rs`**

`sentinel/crates/sentinel-detect/src/beacon.rs`:
```rust
//! C2 beacon detector: periodic connects to the same destination (§5.4).
//! Pure — the caller supplies the clock and has already dropped allow-listed
//! destinations and executables.

use std::collections::{HashMap, VecDeque};

#[derive(Debug, Clone)]
pub struct BeaconConfig {
    pub min_connects: u32,
    pub max_cov: f64,
    /// Sliding window for the interval statistics (default 1h).
    pub window_ms: u64,
    /// Minimum gap between two alerts for the same key (default 1h).
    pub refire_ms: u64,
    /// Cap on tracked keys; the least-recently-seen is evicted past it.
    pub max_keys: usize,
}

impl Default for BeaconConfig {
    fn default() -> BeaconConfig {
        BeaconConfig {
            min_connects: 6,
            max_cov: 0.2,
            window_ms: 3_600_000,
            refire_ms: 3_600_000,
            max_keys: 4096,
        }
    }
}

/// A fired beacon detection.
#[derive(Debug, Clone, PartialEq)]
pub struct BeaconHit {
    pub exe: String,
    pub dest: String,
    pub port: u16,
    pub count: u32,
    pub cov: f64,
}

#[derive(Default)]
struct KeyState {
    times: VecDeque<u64>,
    last_seen: u64,
    last_fired: Option<u64>,
}

pub struct Beacon {
    cfg: BeaconConfig,
    keys: HashMap<(String, String, u16), KeyState>,
}

impl Beacon {
    pub fn new(cfg: BeaconConfig) -> Beacon {
        Beacon { cfg, keys: HashMap::new() }
    }

    /// Record one connect. Returns a hit when the key just became a beacon.
    pub fn observe(&mut self, exe: &str, dest: &str, port: u16, now_ms: u64) -> Option<BeaconHit> {
        self.evict_if_needed(now_ms);
        let cfg = self.cfg.clone();
        let st = self
            .keys
            .entry((exe.to_string(), dest.to_string(), port))
            .or_default();
        st.last_seen = now_ms;
        st.times.push_back(now_ms);
        while let Some(&front) = st.times.front() {
            if now_ms.saturating_sub(front) > cfg.window_ms {
                st.times.pop_front();
            } else {
                break;
            }
        }

        if (st.times.len() as u32) < cfg.min_connects {
            return None;
        }
        let cov = coefficient_of_variation(st.times.make_contiguous());
        if cov > cfg.max_cov {
            return None;
        }
        if let Some(last) = st.last_fired {
            if now_ms.saturating_sub(last) < cfg.refire_ms {
                return None;
            }
        }
        st.last_fired = Some(now_ms);
        Some(BeaconHit {
            exe: exe.to_string(),
            dest: dest.to_string(),
            port,
            count: st.times.len() as u32,
            cov,
        })
    }

    fn evict_if_needed(&mut self, _now_ms: u64) {
        if self.keys.len() < self.cfg.max_keys {
            return;
        }
        if let Some(k) = self
            .keys
            .iter()
            .min_by_key(|(_, s)| s.last_seen)
            .map(|(k, _)| k.clone())
        {
            self.keys.remove(&k);
        }
    }
}

/// Coefficient of variation (stddev / mean) of the gaps between sorted times.
/// Fewer than two times, or a zero mean, counts as perfectly periodic (0.0).
fn coefficient_of_variation(times: &[u64]) -> f64 {
    if times.len() < 2 {
        return 0.0;
    }
    let intervals: Vec<f64> = times.windows(2).map(|w| (w[1] - w[0]) as f64).collect();
    let n = intervals.len() as f64;
    let mean = intervals.iter().sum::<f64>() / n;
    if mean == 0.0 {
        return 0.0;
    }
    let var = intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
    var.sqrt() / mean
}
```

- [ ] **Step 4: Add `pub mod beacon;` to `lib.rs`.**

- [ ] **Step 5: Run the test, watch it pass**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cd sentinel && cargo test -p sentinel-detect --test beacon 2>&1 | tail -20; cd ..`
Expected: PASS (5 tests).

- [ ] **Step 6: Commit**

```bash
git add sentinel/crates/sentinel-detect/src/beacon.rs sentinel/crates/sentinel-detect/src/lib.rs \
  sentinel/crates/sentinel-detect/tests/beacon.rs
git commit -m "feat(sentinel-detect): C2 beacon detector

Per (exe, dest, port), fires when >= min_connects periodic connects with
coefficient of variation <= max_cov over a sliding hour. Pure; clock passed in;
re-fires at most hourly; key count bounded.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_017tTdALyhuFv5WMqfWC2UMV"
```

---

### Task 12: `sentinel-detect` the DNS-tunnel detector

**Files:**
- Create: `sentinel/crates/sentinel-detect/src/dns_tunnel.rs`
- Modify: `sentinel/crates/sentinel-detect/src/lib.rs` (`pub mod dns_tunnel;`)
- Test: `sentinel/crates/sentinel-detect/tests/dns_tunnel.rs`

Per registered domain (public-suffix aware via `psl`), the detector fires on either a label at least `label_len` long whose Shannon entropy exceeds `entropy` bits per character, or more than `unique_per_min` distinct subdomains in a minute (§5.4). Host-level: the hit names the domain, not a process.

- [ ] **Step 1: Write the failing test**

`sentinel/crates/sentinel-detect/tests/dns_tunnel.rs`:
```rust
use sentinel_detect::dns_tunnel::{DnsTunnel, DnsTunnelConfig, DnsReason};

fn cfg() -> DnsTunnelConfig {
    DnsTunnelConfig { label_len: 20, entropy: 3.5, unique_per_min: 30, refire_ms: 3_600_000, max_keys: 1024 }
}

#[test]
fn a_long_high_entropy_label_fires() {
    let mut d = DnsTunnel::new(cfg());
    // 32 hex-ish chars, high entropy, under evil.example
    let q = "a9f3c7e1b5d82604f1a7c3e9b2d6085f.evil.example";
    let hit = d.observe(q, 0).expect("high-entropy label fires");
    assert_eq!(hit.domain, "evil.example");
    assert!(matches!(hit.reason, DnsReason::HighEntropy { .. }));
}

#[test]
fn an_ordinary_name_does_not_fire() {
    let mut d = DnsTunnel::new(cfg());
    assert!(d.observe("www.wikipedia.org", 0).is_none());
    assert!(d.observe("mail.google.com", 1000).is_none());
}

#[test]
fn many_unique_subdomains_a_minute_fires() {
    let mut d = DnsTunnel::new(cfg());
    let mut hit = None;
    for i in 0..31u64 {
        // short labels (no entropy trigger), but many of them, same registered domain
        hit = d.observe(&format!("s{i}.tun.example"), i * 1_000);
    }
    let h = hit.expect("rate trigger");
    assert!(matches!(h.reason, DnsReason::HighRate { .. }));
    assert_eq!(h.domain, "tun.example");
}

#[test]
fn a_domain_does_not_refire_within_the_hour() {
    let mut d = DnsTunnel::new(cfg());
    let q = "a9f3c7e1b5d82604f1a7c3e9b2d6085f.evil.example";
    assert!(d.observe(q, 0).is_some());
    assert!(d.observe("b8e2d6f0a4c71593e0b6d2f8a1c5074e.evil.example", 1_000).is_none());
}
```

- [ ] **Step 2: Run the test, watch it fail**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cd sentinel && cargo test -p sentinel-detect --test dns_tunnel 2>&1 | tail -20; cd ..`
Expected: FAIL — `dns_tunnel` module absent.

- [ ] **Step 3: Write `dns_tunnel.rs`**

`sentinel/crates/sentinel-detect/src/dns_tunnel.rs`:
```rust
//! DNS-tunnel detector: high-entropy labels or a high rate of unique
//! subdomains under one registered domain (§5.4). Pure; clock passed in.

use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug, Clone)]
pub struct DnsTunnelConfig {
    pub label_len: u32,
    pub entropy: f64,
    pub unique_per_min: u32,
    pub refire_ms: u64,
    pub max_keys: usize,
}

impl Default for DnsTunnelConfig {
    fn default() -> DnsTunnelConfig {
        DnsTunnelConfig {
            label_len: 20,
            entropy: 3.5,
            unique_per_min: 30,
            refire_ms: 3_600_000,
            max_keys: 4096,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum DnsReason {
    HighEntropy { label: String, bits: f64 },
    HighRate { unique: u32 },
}

#[derive(Debug, Clone, PartialEq)]
pub struct DnsHit {
    pub domain: String,
    pub reason: DnsReason,
}

#[derive(Default)]
struct DomainState {
    recent: VecDeque<(u64, String)>,
    last_seen: u64,
    last_fired: Option<u64>,
}

pub struct DnsTunnel {
    cfg: DnsTunnelConfig,
    domains: HashMap<String, DomainState>,
}

impl DnsTunnel {
    pub fn new(cfg: DnsTunnelConfig) -> DnsTunnel {
        DnsTunnel { cfg, domains: HashMap::new() }
    }

    /// Record one resolved query name. Returns a hit when the domain just
    /// crossed a threshold.
    pub fn observe(&mut self, qname: &str, now_ms: u64) -> Option<DnsHit> {
        let qname = qname.trim_end_matches('.').to_ascii_lowercase();
        let registered = psl::domain_str(&qname)?.to_string();
        // the labels to the left of the registered domain
        let sub = qname
            .strip_suffix(&registered)
            .map(|s| s.trim_end_matches('.'))
            .unwrap_or("");

        self.evict_if_needed();
        let cfg = self.cfg.clone();
        let st = self.domains.entry(registered.clone()).or_default();
        st.last_seen = now_ms;

        // rate: distinct subdomains in the last minute
        if !sub.is_empty() {
            st.recent.push_back((now_ms, sub.to_string()));
        }
        while let Some(&(t, _)) = st.recent.front() {
            if now_ms.saturating_sub(t) > 60_000 {
                st.recent.pop_front();
            } else {
                break;
            }
        }

        if Self::refiring(st, now_ms, cfg.refire_ms) {
            return None;
        }

        // entropy trigger on any long label
        for label in sub.split('.').filter(|l| !l.is_empty()) {
            if label.len() as u32 >= cfg.label_len {
                let bits = shannon_entropy(label);
                if bits > cfg.entropy {
                    st.last_fired = Some(now_ms);
                    return Some(DnsHit {
                        domain: registered,
                        reason: DnsReason::HighEntropy { label: label.to_string(), bits },
                    });
                }
            }
        }

        // rate trigger
        let unique: HashSet<&str> = st.recent.iter().map(|(_, s)| s.as_str()).collect();
        if unique.len() as u32 > cfg.unique_per_min {
            st.last_fired = Some(now_ms);
            return Some(DnsHit {
                domain: registered,
                reason: DnsReason::HighRate { unique: unique.len() as u32 },
            });
        }

        None
    }

    fn refiring(st: &DomainState, now_ms: u64, refire_ms: u64) -> bool {
        matches!(st.last_fired, Some(last) if now_ms.saturating_sub(last) < refire_ms)
    }

    fn evict_if_needed(&mut self) {
        if self.domains.len() < self.cfg.max_keys {
            return;
        }
        if let Some(k) = self
            .domains
            .iter()
            .min_by_key(|(_, s)| s.last_seen)
            .map(|(k, _)| k.clone())
        {
            self.domains.remove(&k);
        }
    }
}

/// Shannon entropy in bits per character.
fn shannon_entropy(s: &str) -> f64 {
    let mut counts: HashMap<char, usize> = HashMap::new();
    let mut n = 0usize;
    for c in s.chars() {
        *counts.entry(c).or_default() += 1;
        n += 1;
    }
    if n == 0 {
        return 0.0;
    }
    let n = n as f64;
    -counts
        .values()
        .map(|&c| {
            let p = c as f64 / n;
            p * p.log2()
        })
        .sum::<f64>()
}
```

- [ ] **Step 4: Add `pub mod dns_tunnel;` to `lib.rs`.**

- [ ] **Step 5: Run the test, watch it pass**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cd sentinel && cargo test -p sentinel-detect 2>&1 | tail -20; cd ..`
Expected: PASS (beacon + dns_tunnel).

- [ ] **Step 6: Commit**

```bash
git add sentinel/crates/sentinel-detect/src/dns_tunnel.rs sentinel/crates/sentinel-detect/src/lib.rs \
  sentinel/crates/sentinel-detect/tests/dns_tunnel.rs
git commit -m "feat(sentinel-detect): DNS-tunnel detector

Per registered domain (psl public-suffix aware): fires on a long high-entropy
label or more than unique_per_min distinct subdomains a minute. Pure; clock in.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_017tTdALyhuFv5WMqfWC2UMV"
```

---

### Task 13: default rule pack and its test

**Files:**
- Create: `manifest/sentinel/rules/default.toml`
- Test: `sentinel/crates/sentinel-rules/tests/default_pack.rs`

The shipped default pack (§5.5). The test loads it through `load_dir` (the same path `aios plan` and `sentinel rules check` use), asserts it validates, and compiles it, checking the kernel/user split and that the kernel tables stay within limits. This catches a broken default before it ever reaches a generation.

- [ ] **Step 1: Write the failing test**

`sentinel/crates/sentinel-rules/tests/default_pack.rs`:
```rust
use std::path::Path;
use sentinel_rules::{load_dir, matcher::compile_all};

fn pack_dir() -> std::path::PathBuf {
    // tests run with CWD = crate dir; the repo root is three levels up.
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../manifest/sentinel/rules")
}

#[test]
fn default_pack_loads_validates_and_compiles() {
    let rules = load_dir(&pack_dir()).expect("default pack validates");
    assert_eq!(rules.len(), 14, "the §5.5 table has 14 rules");

    let (tables, user) = compile_all(&rules).expect("default pack compiles");
    // 9 kernel rules, 5 user-space rules (the ones with exe/ancestors/managed_home)
    assert_eq!(tables.rules.len(), 9, "kernel rules");
    assert_eq!(user.len(), 5, "user-space rules");
    assert!(tables.rules.len() <= sentinel_common::MAX_RULES);
    assert!(tables.cidrs.len() <= sentinel_common::MAX_CIDRS);

    // spot checks: the amendment predicates are present and classified right
    assert!(rules.iter().any(|r| r.id == "module-load" && r.match_.any == Some(true)));
    assert!(user.iter().any(|u| rules[u.index as usize].id == "persistence-write"));
    assert!(user.iter().any(|u| rules[u.index as usize].id == "reverse-shell"));
}
```

- [ ] **Step 2: Run the test, watch it fail**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cd sentinel && cargo test -p sentinel-rules --test default_pack 2>&1 | tail -20; cd ..`
Expected: FAIL — `manifest/sentinel/rules/default.toml` does not exist, so `load_dir` errors.

- [ ] **Step 3: Write `manifest/sentinel/rules/default.toml`**

```toml
# AIOS Sentinel default rule pack (spec §5.5).
# Copied to /etc/aios/sentinel/rules.d/ by the installer, like the other defaults.

[[rule]]
id       = "exec-memfd"
desc     = "Fileless execution from a memfd"
on       = "exec"
severity = "critical"
action   = "deny"
match    = { exe_memfd = true }

[[rule]]
id       = "exec-deleted"
desc     = "Execution of a deleted (unlinked) file"
on       = "exec"
severity = "high"
action   = "deny"
match    = { exe_deleted = true }

[[rule]]
id       = "exec-shm"
desc     = "Execution from /dev/shm"
on       = "exec"
severity = "high"
action   = "deny"
match    = { exe_on = ["/dev/shm"] }

[[rule]]
id       = "exec-tmp"
desc     = "Execution from /tmp or /var/tmp"
on       = "exec"
severity = "medium"
action   = "deny"
mode     = "audit"
match    = { exe_on = ["/tmp", "/var/tmp"] }

[[rule]]
id       = "reverse-shell"
desc     = "Shell or interpreter with stdio on a socket"
on       = "exec"
severity = "high"
action   = "freeze"
match    = { exe = ["/usr/bin/{bash,sh,zsh,dash}", "/usr/bin/python3*"], stdio_socket = true }
except   = { ancestors = ["/usr/bin/sshd"] }

[[rule]]
id       = "ld-preload"
desc     = "LD_PRELOAD or LD_LIBRARY_PATH in a new process environment"
on       = "exec"
severity = "medium"
action   = "alert"
match    = { env_ld = true }

[[rule]]
id       = "ptrace-other"
desc     = "ptrace of a non-descendant process"
on       = "ptrace"
severity = "high"
action   = "alert"
match    = { ptrace_target = "non-descendant" }
except   = { exe = ["/usr/bin/{gdb,lldb,strace}"] }

[[rule]]
id       = "camera-open"
desc     = "A process opened the camera"
on       = "open"
severity = "low"
action   = "alert"
match    = { device = "camera" }

[[rule]]
id       = "mic-open"
desc     = "A process opened the microphone"
on       = "open"
severity = "low"
action   = "alert"
match    = { device = "mic" }
except   = { exe = ["/usr/bin/pipewire", "/usr/bin/wireplumber"] }

[[rule]]
id       = "input-read"
desc     = "A process read input devices (possible keylogger)"
on       = "open"
severity = "high"
action   = "alert"
match    = { device = "input" }
except   = { exe = ["/usr/lib/systemd/systemd-logind"] }

[[rule]]
id       = "uinput-open"
desc     = "A process opened uinput (possible input injection)"
on       = "open"
severity = "high"
action   = "alert"
match    = { device = "uinput" }

[[rule]]
id       = "module-load"
desc     = "A kernel module was loaded"
on       = "module"
severity = "medium"
action   = "alert"
match    = { any = true }

[[rule]]
id       = "user-listener"
desc     = "A user process opened a non-loopback listener"
on       = "listen"
severity = "medium"
action   = "alert"
match    = { uid = "user", listen_scope = "non-loopback" }

[[rule]]
id       = "persistence-write"
desc     = "Write attempt on a manifest-managed home file"
on       = "write_refused"
severity = "medium"
action   = "alert"
match    = { managed_home = true }
```

- [ ] **Step 4: Run the test, watch it pass**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cd sentinel && cargo test -p sentinel-rules --test default_pack 2>&1 | tail -20; cd ..`
Expected: PASS (1 test).

- [ ] **Step 5: Commit**

```bash
git add manifest/sentinel/rules/default.toml sentinel/crates/sentinel-rules/tests/default_pack.rs
git commit -m "feat(sentinel): default rule pack and its load/compile test

The §5.5 pack: 14 rules (9 kernel, 5 user-space). The test loads it through
the same load_dir aios plan uses and asserts it validates and compiles within
the kernel limits.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_017tTdALyhuFv5WMqfWC2UMV"
```

---

### Task 14: spec amendments

**Files:**
- Modify: `docs/superpowers/specs/2026-11-12-sentinel-core-design.md` (append a new section 17)

The S1 implementation differs from the original spec in a few places the spec itself told us to record (§3.1: name any C program and why). Append the amendments so the spec stays the source of truth for S2–S5.

- [ ] **Step 1: Append section 17 to the spec**

Add at the end of `docs/superpowers/specs/2026-11-12-sentinel-core-design.md`:
```markdown

## 17. Implementation amendments

Recorded during S1 (plan `docs/superpowers/plans/2026-11-13-sentinel-s1-core-crates.md`). These refine the design where the toolchain or the chosen crates differ from the original text; the guarantees of §1–§2 are unchanged.

1. **CO-RE via C shims (§3.1, §4).** Rust eBPF cannot emit CO-RE relocations today (rustc has no `.BTF.ext` for `preserve_access_index`; rust#158412, aya#349). Kernel-struct field reads that must survive a kernel version change are done in a small C file (`sentinel-ebpf/c/`), compiled with `clang -target bpfel -O2 -g -emit-llvm` and linked by bpf-linker `--btf`; the Aya loader relocates it. Everything else stays Rust (Aya). This is the §3.1 "written in C … name it and say why" allowance. Verified working in a virtme-ng VM during S1 pre-work.

2. **Socket destruction from user space (§6 freeze).** Aya exposes no socket-iterator program type, so the "`bpf_sock_destroy` from a socket iterator" step runs in `sentineld` instead: for each quarantined pid it enumerates sockets via `sock_diag` and destroys them with `SOCK_DESTROY` (`INET_DIAG_DESTROY`, present on the host kernel). The `socket_connect`/`socket_sendmsg` LSM deny for the quarantine cgroup still runs in the kernel, so no new connection is possible during the race.

3. **`aya-build` instead of `cargo xtask build` for the package (§11.4).** The kernel object is built by an `aya-build` build-script step, so a plain `cargo build --release --locked` (what the PKGBUILD runs) produces everything. `xtask` is kept for the S2 VM tests, not the package build.

4. **New predicate `any = true` (§5.2).** A rule that should match every event of its `on` (e.g. `module-load`) sets `any = true`. It is kernel-evaluable and satisfies the "empty match is an error" rule. Applies to all event kinds.

5. **New predicate `managed_home = true` (§5.2, §5.5 `persistence-write`).** The protected home files are known only to `sentineld` (it fills the list from the rendered home binds). `managed_home = true` is a user-space predicate on `write_refused` that holds when the resolved path is one of them.

6. **`exe_on` matches by mount id (§5.2).** Btrfs subvolumes share one `s_dev`, so `exe_on` is matched on the VFS mount's `mnt_id`, not on `s_dev` or path text. `sentineld` resolves each `exe_on` path to its mount at load time and warns when a path is not a mount point (the rule would then never match).
```

- [ ] **Step 2: Verify the spec still reads cleanly**

Run: `tail -40 docs/superpowers/specs/2026-11-12-sentinel-core-design.md`
Expected: section 17 present, well-formed.

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/specs/2026-11-12-sentinel-core-design.md
git commit -m "docs(spec): record S1 implementation amendments (section 17)

C shims for CO-RE, user-space SOCK_DESTROY, aya-build for packaging, and the
any/managed_home predicates and exe_on mount-id matching.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_017tTdALyhuFv5WMqfWC2UMV"
```

---

### Task 15: full `sentinel-check` and `make check`

**Files:** none (verification only)

- [ ] **Step 1: Run the Sentinel workspace gate exactly as `make` will**

Run:
```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd sentinel
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cd ..
```
Expected: fmt clean, clippy clean (no warnings), all tests pass across `sentinel-common`, `sentinel-rules`, `sentinel-detect`.

- [ ] **Step 2: Run the whole `make check`**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; make check 2>&1 | tail -30`
Expected: every stage green, including the new `sentinel-check`. (This also re-runs the existing Base ISO Rust, shell, bats and unit checks.)

- [ ] **Step 3: Confirm the branch state**

Run: `git log --oneline -14 && git status`
Expected: the S1 commits on `feat/sentinel`, working tree clean. S1 is complete; S2's plan is written next (it needs these types to be final).

---

## Spec coverage map (self-review)

Every S1-relevant spec requirement maps to a task:

| Spec | Requirement | Task |
|---|---|---|
| §3.1 | `sentinel/` workspace, crate layout, nightly pin | 1 |
| §3.1 | C-in-Rust allowance named | 14 (amendment 1) |
| §4 | event flags (`memfd`, `deleted`, `outside_usr`, `stdio_socket`, `env_ld`) | 3 (bits), 7 (mapping) |
| §4 | `EventKind`, severity/action/mode shared values | 2 |
| §5.1 | rule format, `match`/`except`/`window`/`mode`, all error classes | 5, 6, 8 |
| §5.2 | every predicate, applicability | 6 (validate), 7/8 (compile) |
| §5.2 | `any`, `managed_home` predicates | 5 (model), 6 (validate), 7/8, 14 |
| §5.3 | kernel vs user-space split, `deny` on user rule is an error | 6 (classify) |
| §5.4 | beacon and dns_tunnel detectors | 11, 12 |
| §5.5 | default rule pack | 13 |
| §9 | `KRule` masks / `eval` (the kernel matcher) | 4 |
| §11.1 | `[sentinel]` config + defaults + ranges | 9 |
| §11.2 | plan diff summary (rules + config) | 10 |
| §14 (unit) | all validation errors, classification, compile, match/except/window, detectors, default pack | 2–13 |

**Deferred to later plans (correctly out of S1 scope):** the kernel programs and CO-RE object (S2); `sentineld`, the process table, actions, alert chain, varlink and the CLI (S3); manifest wiring, rendering, `LoadGeneration`, PKGBUILD, unit, health check (S4); the e2e gauntlet and Sliver (S5).

**Placeholder scan:** none — every code step carries complete code; every run step names the command and expected result.

**Type consistency:** `Facts`/`KRule`/`eval` (Task 4) are used unchanged by `compile` (7), `matcher` (8) and the default-pack test (13); `build_masks` (7) is the single predicate→mask translator reused by `compile_all` (8); `parse_duration_ms`/`parse_severity`/`parse_action`/`parse_mode` (6) are reused by `config` (9); `Rule`/`Match` field names (5) match every later reference.
