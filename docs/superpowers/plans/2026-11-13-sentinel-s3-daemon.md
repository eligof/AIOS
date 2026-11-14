# Sentinel — S3: `sentineld` and the `sentinel` CLI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `sentineld` — the root daemon that loads and pins the S2 eBPF object, drains its ring buffer, keeps a process table, resolves and dispatches events against the S1 rule engine and detectors, freezes or kills what the rules say, writes a hash-chained alert log, reports the heartbeat lockdown, and serves `io.aios.Sentinel` over varlink — plus the `sentinel` CLI that talks to it.

**Architecture:** Synchronous, thread-per-concern. A main thread owns a `Mutex<Daemon>`; four threads touch it — the ring drain (polls the `EVENTS` ring fd), the heartbeat (writes `HEARTBEAT[0]` every 500 ms), the varlink listener (one thread per client), and the systemd-resolved DNS monitor. Everything the daemon does to the kernel — map writes, cgroupfs, socket destruction, the clock — goes through one `Kernel` trait, exactly as `aios-exec` routes every system effect through `CommandRunner`. A `FakeKernel` makes the whole daemon testable on the host without root: process-table upkeep, rule dispatch, freeze/kill/release, the storm brake, protected processes, `LoadGeneration`, the alert chain, rotation and `verify` are all unit tests. Only the loader (`loader.rs`) and the socket destroyer need a real kernel, and those are covered by VM scenarios.

**Tech Stack:** Rust, the `nightly-2026-11-03` toolchain pinned by `sentinel/rust-toolchain.toml`. New dependencies: `serde_json` 1 (varlink and the alert store), `sha2` 0.10 (the alert chain), `ulid` 3 (alert ids). Already in the workspace: `aya` 0.16, `anyhow`, `clap` 4, `libc`, `serde`, `globset`, `ipnet`, `psl`. **No tokio and no varlink crate** — see amendment 7 below.

**Spec:** `docs/superpowers/specs/2026-11-12-sentinel-core-design.md` — §6 (actions), §7 (process table and context), §8 (self-guard, pinning, lockdown), §9 (alerts), §10 (varlink and CLI), §12 (error handling), §13 (resource budget), §14 (the Rust-unit test bar).

**Kernel ABI:** `sentinel/crates/sentinel-ebpf/README.md` is the contract S2 handed over. The reference loader is `sentinel/crates/ebpf-loadtest/src/main.rs`; its `load` function is the sequence `loader.rs` copies and extends with pinning.

---

## Where S3 sits

| Plan | Scope | Status |
|---|---|---|
| S1 | `sentinel-common`, `sentinel-rules`, `sentinel-detect`, default rule pack | done |
| S2 | `sentinel-ebpf` (Aya + C CO-RE shims), `xtask`, VM harness | done |
| **S3 (this plan)** | `sentineld` (loader, process table, dispatch, actions, alerts, varlink) and the `sentinel` CLI — §6–§10, §12–§13 | — |
| S4 | Base ISO integration: `[sentinel]` manifest section, plan/apply rendering, `LoadGeneration` call, PKGBUILD, unit, health check — §11 | — |
| S5 | E2E gauntlet in the Base ISO VM, including the Sliver implant — §14 | — |

S4 writes the systemd unit and the PKGBUILD. S3 therefore builds the binaries and their behaviour and leaves packaging alone; where S3 needs the unit's guarantees (`LogsDirectory`, `Type=notify`), it implements the daemon side and the VM scenarios start the daemon by hand.

---

## Environment note for every task

Rust is installed via rustup. `sentinel/` pins `nightly-2026-11-03` through `rust-toolchain.toml`, so `cargo` inside it uses that automatically. Start every shell with:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/eli/Development/AIOS
```

The nightly toolchain, `bpf-linker`, clang and the libbpf headers are installed. The VM harness needs `busybox` on `PATH`; it lives at `build/hosttools/root/usr/bin/busybox` (gitignored, signature-verified) and both `harness.sh` and the Makefile append it.

Every task except Task 22 runs on the host as your normal user: no root, no VM. Task 22 adds VM scenarios, which need `/dev/kvm` and `uvx`.

**Local hook notes.** Two hooks interrupt an agent working this plan:

- **GateGuard** blocks the *first* Write/Edit of each new file, the first Bash call, and any shell output redirection, until you state the facts: the user's instruction, what the command or file produces, that no existing file serves the purpose, the data schema if any, and a rollback line for a destructive command. State them briefly in text and retry the same call. It also blocks `rm -rf`; use `mktemp -d` scratch dirs.
- **A security-reminder hook** rejects any diff containing the token `eval` immediately followed by an open parenthesis. `sentinel-common`'s rule evaluator is named exactly that, so this plan writes it as `sentinel_common::eval` in prose. When a write is blocked for this reason, split the file so the offending line lands in its own small edit, or write that line with the `Edit` tool rather than `Write`.

---

## Spec amendments this plan introduces

Record these in spec §17 in the final task. They are listed here because tasks depend on them.

7. **No tokio, no varlink crate (§3.1).** `sentineld` is synchronous and thread-per-concern, and the varlink transport is implemented directly (`varlink.rs`, about 150 lines over `std::os::unix::net::UnixListener`). Reasons: the §10.1 access rule is per-peer (`SO_PEERCRED`, root versus `wheel`), which a service macro does not express; `WatchAlerts` needs raw `continues: true` framing; everything else the daemon does (cgroupfs writes, `/proc` reads, the alert store) is blocking; and the rest of AIOS (`aios-cli`) is synchronous. The §13 budget (RSS at most 64 MiB) is easier to hold without an async runtime. The wire protocol is unchanged, so `varlinkctl` and any varlink client still work.

8. **`env_ld` and `stdio_socket` are user-space predicates (§5.2, §5.3).** S2 does not fill these two facts in the kernel (§17.7), so a rule matching only on them compiled to a kernel rule that could never fire — `ld-preload` in the default pack (§5.5) is exactly that, and §14 expects it to alert. `classify` now counts both as user-space, so such rules become user rules that `sentineld` evaluates after filling the facts from `/proc`. Consequence, by the existing §5.3 rule: `action = "deny"` together with only these predicates is now a validation error naming the predicate. No default-pack rule uses `deny` with them.

9. **Alert context is a time-bounded global ring (§7).** "The last 20 events of the process tree" is served from one process-wide ring of recent events (5 minutes, capped at 200 000 entries, within the §13 budget), filtered to the tree at alert time, newest 20 kept. A per-tree ring would hold memory for every short-lived process.

10. **TTY broadcast enumerates `/dev/pts/*` and `/dev/tty[1-12]` (§9).** There is no utmp reader in the dependency set; `sentineld` writes high and critical alerts to each of those that opens for writing. Equivalent to `wall` for the VM and the desktop case.

---

## File structure

New crate `sentinel/crates/sentineld` (library plus binary `sentineld`, so every module is unit-testable):

| File | Responsibility |
|---|---|
| `src/main.rs` | CLI flags, config load, build the daemon, start the threads, signal handling, the §12 exit paths |
| `src/kernel.rs` | The `Kernel` trait — every map, cgroupfs and socket effect, plus the clock — and `FakeKernel` |
| `src/loader.rs` | The real `Kernel`: aya load, attach, pin under `/sys/fs/bpf/aios-sentinel/`, pin reuse, `CONFIG`, rule tables |
| `src/proc.rs` | `ProcSource` trait and the real `/proc` reader: exe, argv, uid, cgroup, unit, environ, fd kinds |
| `src/table.rs` | The process table: `/proc` seed, upkeep from Exec/Fork/Exit, ancestor chains, the context ring |
| `src/resolve.rs` | `RawEvent` to `ResolvedEvent`: payload decode per kind, user-space facts, `managed_home` |
| `src/engine.rs` | Dispatch: kernel-matched events, user rules, windows, detectors, protected processes, the storm brake |
| `src/action.rs` | freeze / kill / release over the `Kernel` trait, and the quarantine registry |
| `src/sockdestroy.rs` | `sock_diag` enumeration and `SOCK_DESTROY` for quarantined pids (real `Kernel` only) |
| `src/alert.rs` | The `Alert` record, canonical JSON, the SHA-256 chain, the store, rotation, `verify` |
| `src/report.rs` | journald native protocol and the TTY broadcast, behind a `Sink` trait |
| `src/varlink.rs` | Transport (NUL-framed JSON, `SO_PEERCRED`) and the `io.aios.Sentinel` method dispatch |
| `src/status.rs` | The `Status` snapshot, `/run/aios-sentinel/state`, `sd_notify` |
| `src/dns.rs` | The systemd-resolved `io.systemd.Resolve.Monitor` client thread |
| `src/lockdown.rs` | Reading `LOCKDOWN_COUNTS` and the heartbeat gap at start, into one critical alert |

New crate `sentinel/crates/sentinel` (binary only): `src/main.rs` (clap subcommands), `src/client.rs` (varlink client).

New VM scenarios in `sentinel/tests/vm/scenarios/`: `daemon.sh`, `freeze.sh`, `lockdown_report.sh`, `guard_detach.sh`.

---

## Shared contract reference

Every task uses these exact names. They come from S1 and S2 and must not be changed.

### From `sentinel-common`

```rust
pub enum EventKind { Exec = 0, Fork = 1, Exit = 2, Connect = 3, Listen = 4, Open = 5,
                     WriteRefused = 6, Memfd = 7, Ptrace = 8, Module = 9, Bpf = 10, Signal = 11 }
pub enum Action { Alert, Deny, Freeze, Kill }     // event.rs
pub enum Mode { Enforce, Audit }
pub enum Severity { Info, Low, Medium, High, Critical }
pub enum KVerdict { None = 0, Denied = 1, WouldDeny = 2 }

pub struct Facts(pub [u32; NGROUPS]);             // NGROUPS = 7
pub const G_FLAGS: usize = 0;  pub const G_UID: usize = 1;    pub const G_MOUNT: usize = 2;
pub const G_DEST: usize = 3;   pub const G_PORT: usize = 4;   pub const G_DEVICE: usize = 5;
pub const G_PTRACE: usize = 6;
pub const F_MEMFD: u32 = 1 << 0;        pub const F_DELETED: u32 = 1 << 1;
pub const F_OUTSIDE_USR: u32 = 1 << 2;  pub const F_STDIO_SOCKET: u32 = 1 << 3;
pub const F_ENV_LD: u32 = 1 << 4;       pub const F_LISTEN_NON_LOOPBACK: u32 = 1 << 5;
pub const U_USER: u32 = 1 << 0;         pub const U_SYSTEM: u32 = 1 << 1;
pub const D_CAMERA: u32 = 1 << 0;       pub const D_MIC: u32 = 1 << 1;
pub const D_INPUT: u32 = 1 << 2;        pub const D_UINPUT: u32 = 1 << 3;
pub const D_HIDRAW: u32 = 1 << 4;
pub const P_OTHER_UID: u32 = 1 << 0;    pub const P_NON_DESCENDANT: u32 = 1 << 1;
pub const P_ANY: u32 = 1 << 2;
pub fn uid_literal_bit(i: usize) -> u32;
pub fn slot_bit(i: usize) -> u32;
```

`sentinel_common::eval` is the shared matcher: it takes `&KRule` and `&Facts` and returns `bool`. It is the single source of truth both the LSM hook (S2) and `sentineld` run, so never re-implement the mask logic — call it.

```rust
// wire.rs — EventHeader is 80 bytes, RawEvent is repr(C).
pub struct EventHeader { pub kind: u8, pub kverdict: u8, _pad0: [u8; 2], pub matched_rule: i32,
    pub pid: u32, pub tid: u32, pub ppid: u32, pub uid: u32, pub euid: u32, _pad1: u32,
    pub cgroup_id: u64, pub ts_ns: u64, pub facts: [u32; NGROUPS], _pad2: u32 }
pub struct RawEvent { pub hdr: EventHeader, pub payload: EventPayload }
pub struct KConfig { pub lockdown_after_ns: u64, pub sentineld_tgid: u32, pub flags: u32,
                     pub usr_mnt_id: u32, pub _pad: u32 }
pub const CFG_ENFORCE: u32 = 1 << 0;    pub const CFG_SELFGUARD: u32 = 1 << 1;
```

Payload variants (union `EventPayload`, field names exactly as in `wire.rs`): `exec: ExecPayload{exe[256], argv[256], exe_len, argv_len, mnt_id}`, `proc_: ProcPayload{child_pid, exit_code}`, `net: NetPayload{family, proto, addr[16], port}`, `open: OpenPayload{path[256], path_len, dev_class, mode}`, `memfd: MemfdPayload{name[64], flags}`, `ptrace: PtracePayload{target_pid, target_uid, mode}`, `module: ModulePayload{name[64], read_id}`, `bpf: BpfPayload{cmd, prog_type}`, `signal: SignalPayload{target_pid, sig}`.

`dev_class`: 0 none, 1 camera, 2 mic, 3 input, 4 uinput, 5 hidraw. `family`: 2 for IPv4, 10 for IPv6. Exec `exe`/`argv` are **not** filled by the kernel (§17.7) — resolve them from `/proc`.

Reading a ring item: check `item.len() >= size_of::<RawEvent>()`, then `core::ptr::read_unaligned(item.as_ptr() as *const RawEvent)`. Ring items are not guaranteed aligned.

### From `sentinel-rules`

```rust
pub fn load_dir(dir: &Path) -> Result<Vec<Rule>, Vec<RuleError>>;
pub struct RuleError { pub file: String, pub rule: Option<String>, pub message: String }

pub mod compile { pub struct Tables { pub uid_lits: Vec<u32>, pub mounts: Vec<String>,
    pub cidrs: Vec<IpNet>, pub port_sets: Vec<Vec<(u16,u16)>>, pub rules: Vec<KRule> } }

pub mod matcher {
    pub struct ResolvedEvent<'a> { pub kind: EventKind, pub facts: Facts, pub exe: &'a str,
        pub argv: &'a str, pub parent_exe: &'a str, pub ancestors: &'a [String],
        pub unit: &'a str, pub path: &'a str, pub managed_home: bool }
    pub struct UserRule { pub index: u32, pub on: EventKind, pub action: Action,
        pub mode: Mode, pub kernel: KRule, pub window: Option<Window> }
    impl UserRule { pub fn matches(&self, ev: &ResolvedEvent) -> bool }
    pub fn compile_all(rules: &[Rule]) -> Result<(Tables, Vec<UserRule>), Vec<RuleError>>;
}

pub mod window { pub struct WindowState;
    impl WindowState { pub fn new(count: u32, within_ms: u64) -> WindowState;
                       pub fn record(&mut self, key: &str, now_ms: u64) -> bool } }

pub mod config { pub struct SentinelConfig { pub enable: bool, pub rules: String,
    pub lockdown_after: String, pub storm_brake: u32, pub never_act_on: Vec<String>,
    pub bpf_loaders: Vec<String>, pub beacon: Beacon, pub dns_tunnel: DnsTunnel }
    pub struct Beacon { pub min_connects: u32, pub max_cov: f64, pub allow: Vec<String>,
                        pub severity: String, pub action: String }
    pub struct DnsTunnel { pub label_len: u32, pub entropy: f64, pub unique_per_min: u32,
                           pub severity: String, pub action: String }
    pub fn parse(raw: &str) -> Result<SentinelConfig, String>;
    pub fn validate(c: &SentinelConfig) -> Vec<String>; }

pub mod validate { pub fn parse_duration_ms(s: &str) -> Result<u64, String>;
    pub fn parse_severity(s: &str) -> Option<Severity>;
    pub fn parse_action(s: &str) -> Option<Action>; }

pub mod diff { pub fn diff_rules(old: &[Rule], new: &[Rule]) -> RuleSetDiff;
    pub fn diff_config(old: &SentinelConfig, new: &SentinelConfig) -> Vec<String>;
    impl RuleSetDiff { pub fn summary(&self) -> Vec<String>; pub fn is_empty(&self) -> bool } }

pub mod model { pub struct Rule { pub id: String, pub desc: String, pub on: String,
    pub severity: String, pub action: Option<String>, pub mode: Option<String>,
    pub match_: Match, pub except: Match, pub window: Option<Window>, pub source: String }
    pub struct Window { pub count: u32, pub within: String, pub by: String } }
```

`UserRule.index` and `KRule.index` are both the index of the rule in the `Vec<Rule>` that `load_dir` returned. That is how an event's `matched_rule`, or a user-rule hit, resolves back to a rule id, severity and description — keep the `Vec<Rule>` alongside the compiled output for exactly this reason.

### From `sentinel-detect`

```rust
pub struct BeaconConfig { pub min_connects: u32, pub max_cov: f64, pub window_ms: u64,
                          pub refire_ms: u64, pub max_keys: usize }
pub struct BeaconHit { pub exe: String, pub dest: String, pub port: u16, pub count: u32, pub cov: f64 }
impl Beacon { pub fn new(cfg: BeaconConfig) -> Beacon;
    pub fn observe(&mut self, exe: &str, dest: &str, port: u16, now_ms: u64) -> Option<BeaconHit> }

pub struct DnsTunnelConfig { pub label_len: u32, pub entropy: f64, pub unique_per_min: u32,
                             pub refire_ms: u64, pub max_keys: usize }
pub enum DnsReason { HighEntropy { label: String, bits: f64 }, HighRate { unique: u32 } }
pub struct DnsHit { pub domain: String, pub reason: DnsReason }
impl DnsTunnel { pub fn new(cfg: DnsTunnelConfig) -> DnsTunnel;
    pub fn observe(&mut self, qname: &str, now_ms: u64) -> Option<DnsHit> }
```

Both detectors are pure and take the clock as an argument. The daemon owns the allow-list filtering: `Beacon::observe` must not be called for a destination or executable in `config.beacon.allow`.

### The `Kernel` trait (defined in Task 7, used by every task after it)

```rust
pub trait Kernel: Send {
    fn monotonic_ns(&self) -> u64;
    fn wall_ms(&self) -> u64;
    fn heartbeat(&mut self, ns: u64) -> Result<(), KernelError>;
    fn heartbeat_value(&self) -> Result<u64, KernelError>;
    fn drops(&self) -> Result<u64, KernelError>;
    fn lockdown_counts(&self) -> Result<[u64; NHOOKS], KernelError>;
    fn swap_rules(&mut self, tables: &Tables) -> Result<(), KernelError>;
    fn quarantine_add(&mut self, cgroup_id: u64) -> Result<(), KernelError>;
    fn quarantine_remove(&mut self, cgroup_id: u64) -> Result<(), KernelError>;
    fn cgroup_create(&mut self, path: &str) -> Result<u64, KernelError>;
    fn cgroup_remove(&mut self, path: &str) -> Result<(), KernelError>;
    fn cgroup_attach(&mut self, path: &str, pid: u32) -> Result<(), KernelError>;
    fn cgroup_freeze(&mut self, path: &str, on: bool) -> Result<(), KernelError>;
    fn cgroup_kill(&mut self, path: &str) -> Result<(), KernelError>;
    fn cgroup_of(&self, pid: u32) -> Result<String, KernelError>;
    fn destroy_sockets(&mut self, pids: &[u32]) -> Result<usize, KernelError>;
}
```

### Aya 0.16 APIs the loader needs (verified against the vendored source)

- `aya::maps::Map::pin(&self, path)` and the typed wrappers' `pin(self, path)`.
- `aya::programs::links::FdLink::pin(self, path) -> PinnedLink`; `PinnedLink::from_pin(path)`; `PinnedLink::unpin()`.
- Each program type has `take_link(link_id) -> <Type>Link`, and every one of those link types converts into `FdLink` (`define_link_wrapper!(LsmLink, LsmLinkId, FdLink, FdLinkId, Lsm)` and the same for `FExitLink`, `BtfTracePointLink`, `TracePointLink`). Pin by taking the link, converting to `FdLink`, then pinning.
- `aya::maps::RingBuf` implements `AsRawFd`, so the drain thread blocks in `libc::poll` on that fd instead of sleeping. The reference loader sleeps 10 ms in a loop; **do not copy that** — the §13 budget is under 1 % of one core.
- `aya::maps::MapData::from_pin(path)` and `aya::maps::Map::from_pin(path)` recover a pinned map on restart.

---

## Task 1: The two crates and the workspace wiring

**Files:**
- Create: `sentinel/crates/sentineld/Cargo.toml`
- Create: `sentinel/crates/sentineld/build.rs`
- Create: `sentinel/crates/sentineld/src/lib.rs`
- Create: `sentinel/crates/sentineld/src/main.rs`
- Create: `sentinel/crates/sentinel/Cargo.toml`
- Create: `sentinel/crates/sentinel/src/main.rs`
- Modify: `sentinel/Cargo.toml`

- [ ] **Step 1: Add the members and dependencies to the workspace manifest**

In `sentinel/Cargo.toml`, extend `members` and `[workspace.dependencies]`:

```toml
members = [
    "crates/sentinel-common",
    "crates/sentinel-rules",
    "crates/sentinel-detect",
    "crates/sentineld",
    "crates/sentinel",
    "crates/ebpf-loadtest",
    "xtask",
]
```

```toml
serde_json = "1"
sha2 = "0.10"
ulid = "3"
sentinel-rules = { path = "crates/sentinel-rules" }
sentinel-detect = { path = "crates/sentinel-detect" }
```

(`sentinel-common` is already there. `ebpf-loadtest` spells its `sentinel-rules` path dependency out in full; leave that alone — the new workspace entries just let the new crates say `sentinel-rules.workspace = true`.)

- [ ] **Step 2: Write `sentinel/crates/sentineld/Cargo.toml`**

```toml
[package]
name = "sentineld"
description = "AIOS Sentinel daemon: loads the eBPF object, dispatches rules, acts, alerts"
version.workspace = true
edition.workspace = true
license.workspace = true
publish.workspace = true

[lib]
name = "sentineld"
path = "src/lib.rs"

[[bin]]
name = "sentineld"
path = "src/main.rs"

[dependencies]
sentinel-common.workspace = true
sentinel-rules.workspace = true
sentinel-detect.workspace = true
aya.workspace = true
anyhow.workspace = true
clap.workspace = true
libc.workspace = true
serde.workspace = true
serde_json.workspace = true
sha2.workspace = true
ulid.workspace = true
globset.workspace = true
ipnet.workspace = true

[build-dependencies]
aya-build.workspace = true
cargo_metadata.workspace = true
anyhow.workspace = true

[dev-dependencies]
tempfile.workspace = true
```

- [ ] **Step 3: Write `sentinel/crates/sentineld/build.rs`**

The daemon embeds the kernel object the same way `ebpf-loadtest` does (spec §3.1: "The kernel object is embedded at build time"; amendment 3: `aya-build`, so a plain `cargo build --release --locked` produces everything).

Read `sentinel/crates/ebpf-loadtest/build.rs` and reproduce it exactly, including the `Toolchain::Custom("nightly-2026-11-03")` pin — that pin is what keeps CI green (commit `2512681`).

- [ ] **Step 4: Write `sentinel/crates/sentineld/src/lib.rs`**

```rust
//! The AIOS Sentinel daemon (spec §6–§10, §12–§13).
//!
//! Every effect on the kernel goes through the [`kernel::Kernel`] trait, so the
//! whole dispatch path is unit-testable on the host without root.

pub mod alert;
pub mod kernel;
pub mod proc;
pub mod table;
```

Each later task adds its own `pub mod` line here.

- [ ] **Step 5: Write `sentinel/crates/sentineld/src/main.rs`**

```rust
use anyhow::Result;

fn main() -> Result<()> {
    println!("sentineld {}", env!("CARGO_PKG_VERSION"));
    Ok(())
}
```

- [ ] **Step 6: Write `sentinel/crates/sentinel/Cargo.toml`**

```toml
[package]
name = "sentinel"
description = "AIOS Sentinel CLI: a varlink client for io.aios.Sentinel"
version.workspace = true
edition.workspace = true
license.workspace = true
publish.workspace = true

[dependencies]
sentinel-common.workspace = true
sentinel-rules.workspace = true
anyhow.workspace = true
clap.workspace = true
libc.workspace = true
serde.workspace = true
serde_json.workspace = true

[dev-dependencies]
tempfile.workspace = true
```

- [ ] **Step 7: Write `sentinel/crates/sentinel/src/main.rs`**

```rust
use anyhow::Result;

fn main() -> Result<()> {
    println!("sentinel {}", env!("CARGO_PKG_VERSION"));
    Ok(())
}
```

- [ ] **Step 8: Create the four module files as stubs so `lib.rs` compiles**

Tasks 3–7 fill these. For now each file holds only its doc comment:

- `src/alert.rs`: `//! The alert record, its canonical form and the SHA-256 chain (spec §9).`
- `src/kernel.rs`: `//! Every effect the daemon has on the kernel, behind one trait (spec §14).`
- `src/proc.rs`: `//! Reading /proc, behind a trait (spec §7, §17.7).`
- `src/table.rs`: `//! The process table and the alert-context ring (spec §7, amendment 9).`

- [ ] **Step 9: Verify both crates build and the workspace is clean**

Run: `cd sentinel && cargo build -p sentineld -p sentinel`
Expected: compiles. The `sentineld` build script builds the eBPF object, so the first run takes a minute and needs `bpf-linker` and clang on `PATH`. A non-fatal `libLLVM-23 file too short` warning from bpf-linker is pre-existing noise (S2); the object still builds.

Run: `cd sentinel && cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings`
Expected: no output, exit 0.

- [ ] **Step 10: Commit**

```bash
git add sentinel/Cargo.toml sentinel/crates/sentineld sentinel/crates/sentinel
git commit -m "feat(sentinel): sentineld and sentinel crate skeletons"
```

---

## Task 2: `env_ld` and `stdio_socket` become user-space predicates

**Files:**
- Modify: `sentinel/crates/sentinel-rules/src/classify.rs`
- Modify: `sentinel/crates/sentinel-rules/src/matcher.rs` (its `#[cfg(test)] mod tests`)

Amendment 8. Without this the default pack's `ld-preload` compiles to a kernel rule that can never fire, because S2 does not fill `F_ENV_LD` or `F_STDIO_SOCKET` in the kernel (§17.7). Read `classify.rs` first: `first_user_pred` returns the name of the first user-space predicate present in a `Match`, and `classify` calls it for both `match` and `except`.

- [ ] **Step 1: Write the failing tests**

Append to the `tests` module in `sentinel/crates/sentinel-rules/src/classify.rs`:

```rust
    #[test]
    fn env_ld_alone_is_a_user_rule() {
        let m = Match {
            env_ld: Some(true),
            ..Default::default()
        };
        let (kind, pred) = classify(&m, &Match::default(), false);
        assert_eq!(kind, Kind::User);
        assert_eq!(pred, Some("env_ld"));
    }

    #[test]
    fn stdio_socket_alone_is_a_user_rule() {
        let m = Match {
            stdio_socket: Some(true),
            ..Default::default()
        };
        let (kind, pred) = classify(&m, &Match::default(), false);
        assert_eq!(kind, Kind::User);
        assert_eq!(pred, Some("stdio_socket"));
    }

    #[test]
    fn memfd_alone_is_still_a_kernel_rule() {
        let m = Match {
            exe_memfd: Some(true),
            ..Default::default()
        };
        assert_eq!(classify(&m, &Match::default(), false).0, Kind::Kernel);
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd sentinel && cargo test -p sentinel-rules classify`
Expected: `env_ld_alone_is_a_user_rule` and `stdio_socket_alone_is_a_user_rule` FAIL on the first assertion — left `Kernel`, right `User`.

- [ ] **Step 3: Move the two predicates into `first_user_pred`**

In `first_user_pred`, add these two checks ahead of the existing ones, so the reported name is deterministic:

```rust
    if m.env_ld.is_some() {
        return Some("env_ld");
    }
    if m.stdio_socket.is_some() {
        return Some("stdio_socket");
    }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd sentinel && cargo test -p sentinel-rules`
Expected: all pass. If a pre-existing test asserted that a `stdio_socket` or `env_ld` rule is a kernel rule, change it to expect `Kind::User` and add a comment pointing at spec amendment 8.

- [ ] **Step 5: Prove the default pack now carries `ld-preload` as a user rule**

Append to the `tests` module in `sentinel/crates/sentinel-rules/src/matcher.rs`:

```rust
    #[test]
    fn default_pack_has_ld_preload_as_a_user_rule() {
        let dir = std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../manifest/sentinel/rules"
        ));
        let rules = crate::load_dir(dir).expect("default pack is valid");
        let (_tables, user) = compile_all(&rules).expect("default pack compiles");
        let ids: Vec<&str> = user
            .iter()
            .map(|u| rules[u.index as usize].id.as_str())
            .collect();
        assert!(ids.contains(&"ld-preload"), "user rules were {ids:?}");
        assert!(ids.contains(&"reverse-shell"), "user rules were {ids:?}");
    }
```

Run: `cd sentinel && cargo test -p sentinel-rules`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add sentinel/crates/sentinel-rules/src/classify.rs sentinel/crates/sentinel-rules/src/matcher.rs
git commit -m "fix(sentinel): env_ld and stdio_socket are user-space predicates

The kernel does not fill either fact (S2, spec 17.7), so a rule matching
only on them compiled to a kernel rule that could never fire. The default
pack's ld-preload rule was exactly that. Spec amendment 8."
```

---

## Task 3: The alert record and its hash chain

**Files:**
- Modify: `sentinel/crates/sentineld/src/alert.rs`

Spec §9. The record is JSON; `hash` is SHA-256 over the record **without** `hash`, serialised canonically (keys sorted, no whitespace), and that body includes `prev_hash`. The first record of a fresh store chains from 64 zeros.

- [ ] **Step 1: Write the failing tests**

Append to `sentinel/crates/sentineld/src/alert.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn sample() -> Alert {
        Alert {
            id: "01JCZZZZZZZZZZZZZZZZZZZZZZ".to_string(),
            ts: "2026-11-12T16:42:51.123Z".to_string(),
            rule: "reverse-shell".to_string(),
            severity: "high".to_string(),
            action: "freeze".to_string(),
            mode: "enforce".to_string(),
            outcome: "frozen".to_string(),
            message: String::new(),
            process: Some(ProcRef {
                pid: 4242,
                exe: "/usr/bin/bash".to_string(),
                argv: "bash -i".to_string(),
                uid: 1000,
                unit: "session-2.scope".to_string(),
            }),
            ancestors: vec![ProcRef {
                pid: 1,
                exe: "/usr/lib/systemd/systemd".to_string(),
                argv: String::new(),
                uid: 0,
                unit: "init.scope".to_string(),
            }],
            event: serde_json::json!({"on": "exec", "stdio_socket": true}),
            context: vec![],
            prev_hash: GENESIS.to_string(),
            hash: String::new(),
        }
    }

    #[test]
    fn canonical_json_sorts_keys_and_drops_whitespace() {
        let v = serde_json::json!({"b": 1, "a": {"d": 2, "c": [3, 4]}});
        assert_eq!(canonical(&v), r#"{"a":{"c":[3,4],"d":2},"b":1}"#);
    }

    #[test]
    fn genesis_is_sixty_four_zeros() {
        assert_eq!(GENESIS.len(), 64);
        assert!(GENESIS.chars().all(|c| c == '0'));
    }

    #[test]
    fn hash_is_stable_and_excludes_the_hash_field() {
        let mut a = sample();
        let h1 = a.compute_hash();
        // A stale `hash` field must not change the result.
        a.hash = "deadbeef".to_string();
        assert_eq!(a.compute_hash(), h1);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn hash_changes_when_prev_hash_changes() {
        let a = sample();
        let mut b = sample();
        b.prev_hash = "11".repeat(32);
        assert_ne!(a.compute_hash(), b.compute_hash());
    }

    #[test]
    fn sealing_links_a_chain() {
        let mut a = sample();
        a.seal(GENESIS);
        let mut b = sample();
        b.id = "01JCZZZZZZZZZZZZZZZZZZZZA0".to_string();
        b.seal(&a.hash);
        assert_eq!(b.prev_hash, a.hash);
        assert_eq!(b.hash, b.compute_hash());
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd sentinel && cargo test -p sentineld alert`
Expected: FAIL to compile — `cannot find type Alert in this scope`.

- [ ] **Step 3: Write the implementation**

Put this above the `tests` module in `sentinel/crates/sentineld/src/alert.rs`, under the existing doc comment:

```rust
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The `prev_hash` of the first record of a fresh store (spec §9).
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// One process as it appears in an alert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcRef {
    pub pid: u32,
    pub exe: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub argv: String,
    pub uid: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub unit: String,
}

/// An alert record (spec §9). The declaration order here does not matter: the
/// hash is taken over the canonical form, which sorts keys.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub ts: String,
    pub rule: String,
    pub severity: String,
    pub action: String,
    pub mode: String,
    pub outcome: String,
    /// Free text for alerts that are not a rule hit: the lockdown gap, an
    /// action failure, a sensor overflow, a configuration change.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ancestors: Vec<ProcRef>,
    pub event: serde_json::Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub context: Vec<serde_json::Value>,
    pub prev_hash: String,
    pub hash: String,
}

/// Serialise `v` with sorted object keys and no whitespace.
///
/// `serde_json`'s map preserves insertion order unless the `preserve_order`
/// feature is on (it is not), so re-walking the value and sorting at each
/// object is what guarantees the ordering the spec asks for, independent of
/// how the value was built.
pub fn canonical(v: &serde_json::Value) -> String {
    let mut out = String::new();
    write_canonical(v, &mut out);
    out
}

fn write_canonical(v: &serde_json::Value, out: &mut String) {
    match v {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::Value::String((*k).clone()).to_string());
                out.push(':');
                write_canonical(&map[*k], out);
            }
            out.push('}');
        }
        serde_json::Value::Array(items) => {
            out.push('[');
            for (i, it) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(it, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

impl Alert {
    /// SHA-256, hex, over the canonical record with `hash` removed (spec §9).
    pub fn compute_hash(&self) -> String {
        let mut v = serde_json::to_value(self).expect("Alert serialises");
        if let Some(map) = v.as_object_mut() {
            map.remove("hash");
        }
        let mut h = Sha256::new();
        h.update(canonical(&v).as_bytes());
        format!("{:x}", h.finalize())
    }

    /// Chain this record onto `prev` and fill `hash`.
    pub fn seal(&mut self, prev: &str) {
        self.prev_hash = prev.to_string();
        self.hash = self.compute_hash();
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd sentinel && cargo test -p sentineld alert`
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add sentinel/crates/sentineld/src/alert.rs
git commit -m "feat(sentineld): alert record, canonical JSON and the SHA-256 chain"
```

---

## Task 4: The alert store — append, rotate, verify

**Files:**
- Modify: `sentinel/crates/sentineld/src/alert.rs`

Spec §9: `/var/log/aios/sentinel/alerts.jsonl`, rotating at 64 MiB to `alerts.<n>.jsonl`, the new file's first record chaining from the old file's last hash; `sentinel verify` checks the whole chain.

Rotation numbering: the live file is `alerts.jsonl`; on rotation it is renamed to `alerts.<n>.jsonl` with `n` one past the highest existing, so `alerts.1.jsonl` is the oldest. `verify` therefore reads `alerts.1.jsonl`, `alerts.2.jsonl`, … then `alerts.jsonl`.

> **Corrections applied during execution (commit `aa90091`).** The code block in Step 3 below was written before the store had ever run, and review found four defects in it. The committed implementation is the authority; read it rather than re-deriving from the block below.
>
> 1. **`rotate` numbering.** The block scans upward for the first *free* slot, which contradicts the "one past the highest existing" rule stated just above. With a gap in the sequence — an admin deleting a rotated file, a partial restore — it reuses the gap, and `verify` then reports a hash-chain mismatch that reads exactly like tampering. Compute `max(existing) + 1` instead.
> 2. **A crash-torn tail wedged `Store::open`.** `open` propagated any JSON parse error, so a half-written final line from an OOM-kill or power loss made the daemon fail to start — and since `main` exits non-zero on store failure, systemd would restart-loop it and the kernel lockdown would stay engaged for the rest of that boot. The opposite of §12's intent. `open` now tolerates exactly one torn record, and only as the final line of the live file: it truncates to the last complete line and records the fact for `Status`. A parse failure anywhere earlier, or anywhere in a rotated file, is still a hard error, and `verify` stays strict.
> 3. **`append` silently disabled rotation.** `f.metadata().map(|m| m.len()).unwrap_or(0)` turned an `fstat` failure into "file is empty", which makes the rotation test false forever with no error and no way for `Status` to notice. The error is propagated now.
> 4. **`open` was O(total log).** It called `read_all` — deserialising every historical record — purely to read the last record's hash, on every daemon start, with the unit ordered `Before=sysinit.target` and a 64 MiB RSS budget. It now reads only the tail of the live file, falling back to the newest rotated file, bounding the work to one file. `read_all` and `verify` still walk everything, which is their job.
>
> Also added there: a test for the `prev_hash` branch of `verify` (the original tamper test only reached the hash-mismatch branch), explicit error handling in the directory walk instead of `flatten()`, a doc comment recording `verify`'s one real blind spot — deleting a trailing run of whole records is undetectable by a hash chain alone, since nothing survives after them to show a broken link — and byte-level line scanning so that a torn multi-byte UTF-8 character isolates to one bad line instead of failing the whole file read.

- [ ] **Step 1: Write the failing tests**

Append inside the existing `tests` module in `alert.rs` (before its closing brace):

```rust
    fn store_alert(id: &str) -> Alert {
        let mut a = sample();
        a.id = id.to_string();
        a
    }

    #[test]
    fn append_chains_each_record_to_the_last() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = Store::open(dir.path()).unwrap();
        let h1 = s.append(store_alert("a1")).unwrap();
        let h2 = s.append(store_alert("a2")).unwrap();
        assert_ne!(h1, h2);
        let read = s.read_all().unwrap();
        assert_eq!(read.len(), 2);
        assert_eq!(read[0].prev_hash, GENESIS);
        assert_eq!(read[1].prev_hash, read[0].hash);
        assert_eq!(read[1].hash, h2);
    }

    #[test]
    fn a_fresh_store_verifies_and_reports_the_count() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = Store::open(dir.path()).unwrap();
        for i in 0..5 {
            s.append(store_alert(&format!("a{i}"))).unwrap();
        }
        assert_eq!(s.verify().unwrap(), 5);
    }

    #[test]
    fn a_tampered_record_fails_verification_at_its_index() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut s = Store::open(dir.path()).unwrap();
            for i in 0..3 {
                s.append(store_alert(&format!("a{i}"))).unwrap();
            }
        }
        // Rewrite record 1's severity, keeping its stored hash.
        let path = dir.path().join("alerts.jsonl");
        let text = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
        lines[1] = lines[1].replace(r#""severity":"high""#, r#""severity":"low""#);
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let s = Store::open(dir.path()).unwrap();
        let err = s.verify().unwrap_err();
        assert!(err.to_string().contains("record 1"), "unexpected error: {err}");
    }

    #[test]
    fn rotation_renames_the_live_file_and_keeps_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = Store::open(dir.path()).unwrap();
        // A tiny limit, so every record rotates.
        s.rotate_at = 1;
        let h1 = s.append(store_alert("a1")).unwrap();
        let h2 = s.append(store_alert("a2")).unwrap();
        assert!(dir.path().join("alerts.1.jsonl").exists());
        let all = s.read_all().unwrap();
        assert_eq!(all.len(), 2, "read_all must span rotated files");
        assert_eq!(all[0].hash, h1);
        assert_eq!(all[1].prev_hash, h1);
        assert_eq!(all[1].hash, h2);
        assert_eq!(s.verify().unwrap(), 2);
    }

    #[test]
    fn reopening_resumes_the_chain_from_the_last_record() {
        let dir = tempfile::tempdir().unwrap();
        let h1 = {
            let mut s = Store::open(dir.path()).unwrap();
            s.append(store_alert("a1")).unwrap()
        };
        let mut s = Store::open(dir.path()).unwrap();
        assert_eq!(s.last_hash(), h1);
        s.append(store_alert("a2")).unwrap();
        assert_eq!(s.verify().unwrap(), 2);
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd sentinel && cargo test -p sentineld alert`
Expected: FAIL to compile — `cannot find type Store in this scope`.

- [ ] **Step 3: Write the implementation**

Insert above the `tests` module in `alert.rs`:

```rust
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

/// Rotation threshold (spec §9).
pub const ROTATE_AT: u64 = 64 * 1024 * 1024;

/// A store error. The daemon downgrades these to "alerts still reach the
/// journal and the TTY" rather than exiting (spec §12).
#[derive(Debug)]
pub struct StoreError(pub String);

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StoreError {}

fn err<T>(msg: impl Into<String>) -> Result<T, StoreError> {
    Err(StoreError(msg.into()))
}

/// The hash-chained alert log (spec §9).
pub struct Store {
    dir: PathBuf,
    live: PathBuf,
    last: String,
    /// Bytes after which the live file rotates. Public so tests can shrink it.
    pub rotate_at: u64,
}

impl Store {
    /// Open (creating the directory if needed) and recover the chain head.
    pub fn open(dir: &Path) -> Result<Store, StoreError> {
        if let Err(e) = std::fs::create_dir_all(dir) {
            return err(format!("cannot create {}: {e}", dir.display()));
        }
        let live = dir.join("alerts.jsonl");
        let mut s = Store {
            dir: dir.to_path_buf(),
            live,
            last: GENESIS.to_string(),
            rotate_at: ROTATE_AT,
        };
        s.last = match s.read_all()?.last() {
            Some(a) => a.hash.clone(),
            None => GENESIS.to_string(),
        };
        Ok(s)
    }

    /// The hash the next record will chain from.
    pub fn last_hash(&self) -> String {
        self.last.clone()
    }

    /// The rotated files, oldest first, then the live file.
    fn files(&self) -> Result<Vec<PathBuf>, StoreError> {
        let mut rotated: Vec<(u32, PathBuf)> = Vec::new();
        let rd = match std::fs::read_dir(&self.dir) {
            Ok(rd) => rd,
            Err(e) => return err(format!("cannot read {}: {e}", self.dir.display())),
        };
        for ent in rd.flatten() {
            let name = ent.file_name().to_string_lossy().into_owned();
            if let Some(n) = name
                .strip_prefix("alerts.")
                .and_then(|r| r.strip_suffix(".jsonl"))
                .and_then(|n| n.parse::<u32>().ok())
            {
                rotated.push((n, ent.path()));
            }
        }
        rotated.sort_by_key(|(n, _)| *n);
        let mut out: Vec<PathBuf> = rotated.into_iter().map(|(_, p)| p).collect();
        if self.live.exists() {
            out.push(self.live.clone());
        }
        Ok(out)
    }

    /// Every record, oldest first, across rotated files.
    pub fn read_all(&self) -> Result<Vec<Alert>, StoreError> {
        let mut out = Vec::new();
        for p in self.files()? {
            let f = match File::open(&p) {
                Ok(f) => f,
                Err(e) => return err(format!("cannot read {}: {e}", p.display())),
            };
            for (i, line) in BufReader::new(f).lines().enumerate() {
                let line = match line {
                    Ok(l) => l,
                    Err(e) => return err(format!("{}: line {}: {e}", p.display(), i + 1)),
                };
                if line.trim().is_empty() {
                    continue;
                }
                match serde_json::from_str::<Alert>(&line) {
                    Ok(a) => out.push(a),
                    Err(e) => return err(format!("{}: line {}: {e}", p.display(), i + 1)),
                }
            }
        }
        Ok(out)
    }

    /// Seal `a` onto the chain, write it, rotate if the live file is now over
    /// the threshold. Returns the record's hash.
    pub fn append(&mut self, mut a: Alert) -> Result<String, StoreError> {
        a.seal(&self.last);
        let line = match serde_json::to_string(&a) {
            Ok(l) => l,
            Err(e) => return err(format!("cannot serialise alert {}: {e}", a.id)),
        };
        let mut f = match OpenOptions::new().create(true).append(true).open(&self.live) {
            Ok(f) => f,
            Err(e) => return err(format!("cannot open {}: {e}", self.live.display())),
        };
        if let Err(e) = writeln!(f, "{line}").and_then(|()| f.sync_data()) {
            return err(format!("cannot write {}: {e}", self.live.display()));
        }
        self.last = a.hash.clone();
        let size = f.metadata().map(|m| m.len()).unwrap_or(0);
        if size >= self.rotate_at {
            self.rotate()?;
        }
        Ok(a.hash)
    }

    /// Rename the live file to the next free `alerts.<n>.jsonl`. The next
    /// record keeps chaining from `self.last`, so the chain spans the rename.
    fn rotate(&mut self) -> Result<(), StoreError> {
        let mut n = 1u32;
        while self.dir.join(format!("alerts.{n}.jsonl")).exists() {
            n += 1;
        }
        let to = self.dir.join(format!("alerts.{n}.jsonl"));
        if let Err(e) = std::fs::rename(&self.live, &to) {
            return err(format!("cannot rotate to {}: {e}", to.display()));
        }
        Ok(())
    }

    /// Walk the whole chain. Returns the number of records, or an error naming
    /// the index of the first bad one.
    pub fn verify(&self) -> Result<usize, StoreError> {
        let all = self.read_all()?;
        let mut prev = GENESIS.to_string();
        for (i, a) in all.iter().enumerate() {
            if a.prev_hash != prev {
                return err(format!(
                    "record {i} ({}) chains from {}, expected {prev}",
                    a.id, a.prev_hash
                ));
            }
            if a.hash != a.compute_hash() {
                return err(format!("record {i} ({}) hash mismatch", a.id));
            }
            prev = a.hash.clone();
        }
        Ok(all.len())
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd sentinel && cargo test -p sentineld alert`
Expected: 10 passed.

- [ ] **Step 5: Commit**

```bash
git add sentinel/crates/sentineld/src/alert.rs
git commit -m "feat(sentineld): alert store with rotation and chain verification"
```

---

## Task 5: `/proc` reading behind a trait

**Files:**
- Modify: `sentinel/crates/sentineld/src/proc.rs`

Spec §7: the daemon resolves executable path, argv, uid, unit (from the cgroup path), parent and ancestors. S2 deferred the exec `exe`/`argv` strings and the `env_ld`/`stdio_socket` facts to user space (§17.7), so this module answers those too.

- [ ] **Step 1: Write the failing tests**

Append to `sentinel/crates/sentineld/src/proc.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_is_the_last_unit_like_component() {
        assert_eq!(
            unit_from_cgroup("0::/user.slice/user-1000.slice/session-2.scope"),
            "session-2.scope"
        );
        assert_eq!(unit_from_cgroup("0::/system.slice/sshd.service"), "sshd.service");
        assert_eq!(
            unit_from_cgroup("0::/system.slice/system-getty.slice/getty@tty1.service"),
            "getty@tty1.service"
        );
        assert_eq!(unit_from_cgroup("0::/"), "");
        assert_eq!(unit_from_cgroup(""), "");
    }

    #[test]
    fn argv_joins_nul_separated_cmdline() {
        assert_eq!(argv_from_cmdline(b"bash\0-i\0"), "bash -i");
        assert_eq!(argv_from_cmdline(b"/usr/bin/true\0"), "/usr/bin/true");
        assert_eq!(argv_from_cmdline(b""), "");
    }

    #[test]
    fn env_ld_is_set_by_either_variable() {
        assert!(environ_has_ld(b"PATH=/usr/bin\0LD_PRELOAD=/tmp/x.so\0"));
        assert!(environ_has_ld(b"LD_LIBRARY_PATH=/tmp\0"));
        assert!(!environ_has_ld(b"PATH=/usr/bin\0HOME=/root\0"));
        // Must match only at the start of a variable, never inside a value.
        assert!(!environ_has_ld(b"NOTE=see LD_PRELOAD docs\0"));
    }

    #[test]
    fn fake_proc_answers_every_field() {
        let mut p = FakeProc::default();
        p.add(Proc {
            pid: 4242,
            ppid: 4100,
            exe: "/usr/bin/bash".to_string(),
            argv: "bash -i".to_string(),
            uid: 1000,
            unit: "session-2.scope".to_string(),
            cgroup_id: 77,
        });
        assert_eq!(p.read(4242).unwrap().exe, "/usr/bin/bash");
        assert!(p.read(9999).is_none());
        assert_eq!(p.pids(), vec![4242]);
    }

    #[test]
    fn fake_proc_reports_the_configured_facts() {
        let mut p = FakeProc::default();
        p.env_ld.insert(7);
        p.stdio_socket.insert(7);
        assert!(p.has_env_ld(7));
        assert!(p.has_stdio_socket(7));
        assert!(!p.has_env_ld(8));
        assert!(!p.has_stdio_socket(8));
    }

    #[test]
    fn real_proc_reads_this_process() {
        let me = std::process::id();
        let p = RealProc.read(me).expect("own /proc entry");
        assert_eq!(p.pid, me);
        assert!(!p.exe.is_empty(), "exe should resolve for the test binary");
        assert!(RealProc.pids().contains(&me));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd sentinel && cargo test -p sentineld proc`
Expected: FAIL to compile — `cannot find function unit_from_cgroup`.

- [ ] **Step 3: Write the implementation**

Insert above the `tests` module in `proc.rs`, under the existing doc comment:

```rust
use std::collections::{HashMap, HashSet};

/// One process as the daemon knows it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Proc {
    pub pid: u32,
    pub ppid: u32,
    pub exe: String,
    pub argv: String,
    pub uid: u32,
    pub unit: String,
    pub cgroup_id: u64,
}

/// Everything the daemon reads out of `/proc`.
pub trait ProcSource: Send {
    /// A full snapshot of one process, or `None` if it is already gone.
    fn read(&self, pid: u32) -> Option<Proc>;
    /// Every pid currently alive (the start-up scan).
    fn pids(&self) -> Vec<u32>;
    /// `LD_PRELOAD` or `LD_LIBRARY_PATH` in the environment (`F_ENV_LD`).
    fn has_env_ld(&self, pid: u32) -> bool;
    /// fd 0, 1 or 2 is a socket (`F_STDIO_SOCKET`).
    fn has_stdio_socket(&self, pid: u32) -> bool;
}

/// The systemd unit is the last unit-like component of the cgroup v2 path.
pub fn unit_from_cgroup(line: &str) -> String {
    let path = line.rsplit("::").next().unwrap_or("");
    path.rsplit('/')
        .find(|c| {
            c.ends_with(".service")
                || c.ends_with(".scope")
                || c.ends_with(".slice")
                || c.ends_with(".socket")
                || c.ends_with(".mount")
        })
        .unwrap_or("")
        .to_string()
}

/// `/proc/<pid>/cmdline` is NUL-separated; join with spaces.
pub fn argv_from_cmdline(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw)
        .split('\0')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// `LD_PRELOAD=` or `LD_LIBRARY_PATH=` at the start of a NUL-separated entry.
pub fn environ_has_ld(raw: &[u8]) -> bool {
    raw.split(|b| *b == 0)
        .any(|e| e.starts_with(b"LD_PRELOAD=") || e.starts_with(b"LD_LIBRARY_PATH="))
}

/// The real `/proc`.
#[derive(Default)]
pub struct RealProc;

impl RealProc {
    fn read_bytes(pid: u32, what: &str) -> Option<Vec<u8>> {
        std::fs::read(format!("/proc/{pid}/{what}")).ok()
    }
}

impl ProcSource for RealProc {
    fn read(&self, pid: u32) -> Option<Proc> {
        use std::os::unix::fs::MetadataExt;
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        let mut ppid = 0u32;
        let mut uid = 0u32;
        for line in status.lines() {
            if let Some(v) = line.strip_prefix("PPid:") {
                ppid = v.trim().parse().unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("Uid:") {
                // "Uid:\treal\teffective\tsaved\tfs"
                uid = v
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            }
        }
        let cgroup_file = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap_or_default();
        let first = cgroup_file.lines().next().unwrap_or("");
        let unit = unit_from_cgroup(first);
        // The cgroup id is the inode of the cgroup directory, which is what
        // bpf_get_current_cgroup_id() returns on the kernel side.
        let rel = first.rsplit("::").next().unwrap_or("/");
        let cgroup_id = std::fs::metadata(format!("/sys/fs/cgroup{rel}"))
            .map(|m| m.ino())
            .unwrap_or(0);
        Some(Proc {
            pid,
            ppid,
            exe: std::fs::read_link(format!("/proc/{pid}/exe"))
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default(),
            argv: argv_from_cmdline(&Self::read_bytes(pid, "cmdline").unwrap_or_default()),
            uid,
            unit,
            cgroup_id,
        })
    }

    fn pids(&self) -> Vec<u32> {
        let mut out = Vec::new();
        if let Ok(rd) = std::fs::read_dir("/proc") {
            for ent in rd.flatten() {
                if let Ok(pid) = ent.file_name().to_string_lossy().parse::<u32>() {
                    out.push(pid);
                }
            }
        }
        out.sort_unstable();
        out
    }

    fn has_env_ld(&self, pid: u32) -> bool {
        // Only the first 4 KiB, as the spec's env_ld flag describes (§4).
        match Self::read_bytes(pid, "environ") {
            Some(raw) => environ_has_ld(&raw[..raw.len().min(4096)]),
            None => false,
        }
    }

    fn has_stdio_socket(&self, pid: u32) -> bool {
        (0..3).any(|fd| {
            std::fs::read_link(format!("/proc/{pid}/fd/{fd}"))
                .map(|t| t.to_string_lossy().starts_with("socket:["))
                .unwrap_or(false)
        })
    }
}

/// A `ProcSource` built from literals, for tests.
#[derive(Default)]
pub struct FakeProc {
    pub procs: HashMap<u32, Proc>,
    pub env_ld: HashSet<u32>,
    pub stdio_socket: HashSet<u32>,
}

impl FakeProc {
    pub fn add(&mut self, p: Proc) {
        self.procs.insert(p.pid, p);
    }
}

impl ProcSource for FakeProc {
    fn read(&self, pid: u32) -> Option<Proc> {
        self.procs.get(&pid).cloned()
    }
    fn pids(&self) -> Vec<u32> {
        let mut v: Vec<u32> = self.procs.keys().copied().collect();
        v.sort_unstable();
        v
    }
    fn has_env_ld(&self, pid: u32) -> bool {
        self.env_ld.contains(&pid)
    }
    fn has_stdio_socket(&self, pid: u32) -> bool {
        self.stdio_socket.contains(&pid)
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd sentinel && cargo test -p sentineld proc`
Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add sentinel/crates/sentineld/src/proc.rs
git commit -m "feat(sentineld): /proc reader behind a ProcSource trait"
```

---

## Task 6: The process table and the context ring

**Files:**
- Modify: `sentinel/crates/sentineld/src/table.rs`

Spec §7 and amendment 9. The table is seeded from `/proc` at start and kept up to date from Exec, Fork and Exit. Alerts carry the ancestor chain up to PID 1 and the last 20 events of the process tree.

> **Correction applied during execution (commit `c59f251`).** The Step 3 block below drops an exiting pid outright, which loses every process under it: the children keep a `ppid` pointing at a number that is no longer in the table. That is a one-line bypass of the whole §4 ancestry story — fork, let the middle process exit, and the orphan has no `sshd` (or anything else) left in its chain, so `parent` and `ancestors` conditions stop matching, and a `freeze` of the original process no longer takes the orphan with it (§6). Double-forking to detach is the oldest trick there is, and `reverse-shell` and `ptrace-other` both lean on ancestry.
>
> The committed implementation keeps an exited pid as a **tombstone** while something alive is still below it: `procs` holds live entries and tombstones, a `children` index makes the exit path O(children) instead of a table scan, and `prune` drops a childless tombstone and cascades up, so the extra entries stay bounded by the live process count. `get` and `len` report live processes only, `descendants` walks *through* tombstones but never reports one (a dead pid cannot be attached to a quarantine cgroup), and `ancestors` walks through them so the chain still reaches pid 1. `on_exec` goes through `insert` as well, so `/proc` repairs a parent link that a missed or out-of-order fork event left wrong.
>
> This deliberately does not mirror the kernel, which reparents an orphan to the nearest subreaper. Matching the kernel is what creates the blind spot, and the subreaper is not cheaply knowable from user space anyway.

- [ ] **Step 1: Write the failing tests**

Append to `sentinel/crates/sentineld/src/table.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::proc::{FakeProc, Proc};

    fn p(pid: u32, ppid: u32, exe: &str) -> Proc {
        Proc {
            pid,
            ppid,
            exe: exe.to_string(),
            argv: exe.to_string(),
            uid: 1000,
            unit: "session-2.scope".to_string(),
            cgroup_id: 77,
        }
    }

    fn seeded() -> (Table, FakeProc) {
        let mut src = FakeProc::default();
        src.add(p(1, 0, "/usr/lib/systemd/systemd"));
        src.add(p(100, 1, "/usr/bin/sshd"));
        src.add(p(200, 100, "/usr/bin/bash"));
        let mut t = Table::default();
        t.seed(&src);
        (t, src)
    }

    #[test]
    fn seed_reads_every_pid() {
        let (t, _) = seeded();
        assert_eq!(t.len(), 3);
        assert_eq!(t.get(200).unwrap().exe, "/usr/bin/bash");
    }

    #[test]
    fn ancestors_walk_up_to_pid_one() {
        let (t, _) = seeded();
        let exes: Vec<String> = t.ancestors(200).iter().map(|a| a.exe.clone()).collect();
        assert_eq!(
            exes,
            vec!["/usr/bin/sshd", "/usr/lib/systemd/systemd"],
            "the chain excludes the process itself and ends at pid 1"
        );
    }

    #[test]
    fn ancestors_terminate_on_a_cycle() {
        let mut t = Table::default();
        t.insert(p(5, 6, "/a"));
        t.insert(p(6, 5, "/b"));
        assert!(t.ancestors(5).len() <= MAX_ANCESTORS);
    }

    #[test]
    fn fork_inserts_the_child_with_the_parents_image() {
        let (mut t, _) = seeded();
        t.on_fork(200, 201);
        let c = t.get(201).expect("child present");
        assert_eq!(c.ppid, 200);
        assert_eq!(c.exe, "/usr/bin/bash", "a fork shares the parent's image");
    }

    #[test]
    fn exec_replaces_the_image_of_an_existing_pid() {
        let (mut t, mut src) = seeded();
        src.add(p(200, 100, "/usr/bin/python3"));
        t.on_exec(200, &src);
        assert_eq!(t.get(200).unwrap().exe, "/usr/bin/python3");
    }

    #[test]
    fn exit_removes_the_pid() {
        let (mut t, _) = seeded();
        t.on_exit(200);
        assert!(t.get(200).is_none());
    }

    #[test]
    fn descendants_include_the_whole_subtree() {
        let (mut t, _) = seeded();
        t.on_fork(200, 201);
        t.on_fork(201, 202);
        let mut d = t.descendants(200);
        d.sort_unstable();
        assert_eq!(d, vec![200, 201, 202]);
    }

    #[test]
    fn context_keeps_only_the_trees_newest_events() {
        let (mut t, _) = seeded();
        t.on_fork(200, 201);
        for i in 0..25u64 {
            t.record_context(200, serde_json::json!({"on": "connect", "n": i}), i);
        }
        t.record_context(201, serde_json::json!({"on": "exec"}), 30);
        // A sibling's events must not appear.
        t.record_context(999, serde_json::json!({"on": "open"}), 31);

        let ctx = t.context_for(200, 32);
        assert_eq!(ctx.len(), MAX_CONTEXT);
        assert_eq!(ctx.last().unwrap()["on"], "exec", "newest last");
        assert!(
            ctx.iter().all(|e| e["on"] != "open"),
            "unrelated events excluded: {ctx:?}"
        );
    }

    #[test]
    fn context_drops_events_older_than_the_window() {
        let mut t = Table::default();
        t.insert(p(10, 1, "/a"));
        t.record_context(10, serde_json::json!({"on": "connect"}), 0);
        t.record_context(10, serde_json::json!({"on": "listen"}), CONTEXT_WINDOW_MS + 1);
        let ctx = t.context_for(10, CONTEXT_WINDOW_MS + 2);
        assert_eq!(ctx.len(), 1);
        assert_eq!(ctx[0]["on"], "listen");
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd sentinel && cargo test -p sentineld table`
Expected: FAIL to compile — `cannot find type Table`.

- [ ] **Step 3: Write the implementation**

Insert above the `tests` module in `table.rs`, under the existing doc comment:

```rust
use std::collections::{HashMap, HashSet, VecDeque};

use crate::proc::{Proc, ProcSource};

/// Longest ancestor chain an alert carries; also the cycle guard.
pub const MAX_ANCESTORS: usize = 64;
/// Context events per alert (spec §7).
pub const MAX_CONTEXT: usize = 20;
/// How long a context event stays in the ring (spec §4: "about five minutes").
pub const CONTEXT_WINDOW_MS: u64 = 5 * 60 * 1000;
/// Hard cap on the ring, so a storm cannot grow it past the §13 budget.
pub const MAX_CONTEXT_RING: usize = 200_000;

#[derive(Debug, Clone)]
struct ContextEvent {
    pid: u32,
    at_ms: u64,
    json: serde_json::Value,
}

/// The live process table plus the recent-event ring.
#[derive(Default)]
pub struct Table {
    procs: HashMap<u32, Proc>,
    ring: VecDeque<ContextEvent>,
}

impl Table {
    /// Build the table from a full `/proc` scan (spec §4: at start).
    pub fn seed(&mut self, src: &dyn ProcSource) {
        for pid in src.pids() {
            if let Some(p) = src.read(pid) {
                self.procs.insert(pid, p);
            }
        }
    }

    pub fn len(&self) -> usize {
        self.procs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.procs.is_empty()
    }

    pub fn get(&self, pid: u32) -> Option<&Proc> {
        self.procs.get(&pid)
    }

    pub fn insert(&mut self, p: Proc) {
        self.procs.insert(p.pid, p);
    }

    /// A fork: the child starts as a copy of the parent.
    pub fn on_fork(&mut self, parent: u32, child: u32) {
        let mut p = self.procs.get(&parent).cloned().unwrap_or_default();
        p.pid = child;
        p.ppid = parent;
        self.procs.insert(child, p);
    }

    /// An exec: re-read the pid, because its image, argv and cgroup changed.
    pub fn on_exec(&mut self, pid: u32, src: &dyn ProcSource) {
        if let Some(p) = src.read(pid) {
            self.procs.insert(pid, p);
        }
    }

    /// An exit: drop the pid. Its context events age out of the ring on their
    /// own, so an alert raised moments later still has them.
    pub fn on_exit(&mut self, pid: u32) {
        self.procs.remove(&pid);
    }

    /// The ancestors of `pid`, nearest first, excluding `pid` itself; stops at
    /// pid 1, at an unknown pid, at a cycle, or after [`MAX_ANCESTORS`].
    pub fn ancestors(&self, pid: u32) -> Vec<Proc> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let mut cur = pid;
        seen.insert(cur);
        while out.len() < MAX_ANCESTORS {
            let Some(p) = self.procs.get(&cur) else { break };
            let parent = p.ppid;
            if parent == 0 || !seen.insert(parent) {
                break;
            }
            let Some(pp) = self.procs.get(&parent) else { break };
            out.push(pp.clone());
            if parent == 1 {
                break;
            }
            cur = parent;
        }
        out
    }

    /// `pid` and every descendant of it (spec §6: what a freeze takes).
    pub fn descendants(&self, pid: u32) -> Vec<u32> {
        let mut out = vec![pid];
        let mut i = 0;
        while i < out.len() {
            let parent = out[i];
            for (child, p) in &self.procs {
                if p.ppid == parent && !out.contains(child) {
                    out.push(*child);
                }
            }
            i += 1;
        }
        out
    }

    /// Record one event for the alert context of `pid`'s tree.
    pub fn record_context(&mut self, pid: u32, json: serde_json::Value, now_ms: u64) {
        self.ring.push_back(ContextEvent {
            pid,
            at_ms: now_ms,
            json,
        });
        while self.ring.len() > MAX_CONTEXT_RING {
            self.ring.pop_front();
        }
        while let Some(front) = self.ring.front() {
            if now_ms.saturating_sub(front.at_ms) > CONTEXT_WINDOW_MS {
                self.ring.pop_front();
            } else {
                break;
            }
        }
    }

    /// The newest [`MAX_CONTEXT`] events belonging to `pid`'s tree — `pid`
    /// itself, its ancestors and its descendants — oldest first.
    pub fn context_for(&self, pid: u32, now_ms: u64) -> Vec<serde_json::Value> {
        let mut tree: HashSet<u32> = self.descendants(pid).into_iter().collect();
        tree.insert(pid);
        for a in self.ancestors(pid) {
            tree.insert(a.pid);
        }
        let mut out: Vec<serde_json::Value> = self
            .ring
            .iter()
            .filter(|e| {
                tree.contains(&e.pid) && now_ms.saturating_sub(e.at_ms) <= CONTEXT_WINDOW_MS
            })
            .map(|e| e.json.clone())
            .collect();
        if out.len() > MAX_CONTEXT {
            out.drain(..out.len() - MAX_CONTEXT);
        }
        out
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd sentinel && cargo test -p sentineld table`
Expected: 9 passed.

- [ ] **Step 5: Commit**

```bash
git add sentinel/crates/sentineld/src/table.rs
git commit -m "feat(sentineld): process table, ancestor chains and the context ring"
```

---

## Task 7: The `Kernel` trait and its fake

**Files:**
- Modify: `sentinel/crates/sentineld/src/kernel.rs`

Spec §14: "`sentineld` logic behind a `Kernel` trait (maps, ring buffer, cgroupfs) with a fake, as `aios-exec` does with its `Runner`". Read `aios-cli/crates/aios-exec/src/runner.rs` first for the house style — the trait carries every effect, and the fake records calls in order so tests can assert the sequence, not just the end state.

- [ ] **Step 1: Write the failing tests**

Append to `sentinel/crates/sentineld/src/kernel.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fake_records_every_call_in_order() {
        let mut k = FakeKernel::default();
        let id = k.cgroup_create("/sys/fs/cgroup/aios-sentinel.slice/q-A").unwrap();
        k.cgroup_attach("/sys/fs/cgroup/aios-sentinel.slice/q-A", 42).unwrap();
        k.cgroup_freeze("/sys/fs/cgroup/aios-sentinel.slice/q-A", true).unwrap();
        k.quarantine_add(id).unwrap();
        assert_eq!(
            k.calls,
            vec![
                "cgroup_create /sys/fs/cgroup/aios-sentinel.slice/q-A".to_string(),
                "cgroup_attach /sys/fs/cgroup/aios-sentinel.slice/q-A 42".to_string(),
                "cgroup_freeze /sys/fs/cgroup/aios-sentinel.slice/q-A on".to_string(),
                format!("quarantine_add {id}"),
            ]
        );
        assert!(k.quarantined.contains(&id));
    }

    #[test]
    fn the_fake_clock_advances_only_when_told() {
        let mut k = FakeKernel::default();
        assert_eq!(k.monotonic_ns(), 0);
        k.advance_ms(1500);
        assert_eq!(k.monotonic_ns(), 1_500_000_000);
        assert_eq!(k.wall_ms(), 1500);
    }

    #[test]
    fn a_configured_failure_surfaces_as_an_error() {
        let mut k = FakeKernel::default();
        k.fail_on.insert("cgroup_freeze /x on".to_string());
        assert!(k.cgroup_freeze("/x", true).is_err());
        // The attempt is still recorded, so a test can assert it was tried.
        assert_eq!(k.calls, vec!["cgroup_freeze /x on".to_string()]);
    }

    #[test]
    fn heartbeat_and_counters_round_trip() {
        let mut k = FakeKernel::default();
        k.heartbeat(123).unwrap();
        assert_eq!(k.heartbeat_value().unwrap(), 123);
        k.drops_value = 7;
        assert_eq!(k.drops().unwrap(), 7);
        k.lockdown = [1, 0, 0, 0, 0, 0, 0, 2];
        assert_eq!(k.lockdown_counts().unwrap()[7], 2);
    }

    #[test]
    fn release_undoes_quarantine() {
        let mut k = FakeKernel::default();
        let id = k.cgroup_create("/q").unwrap();
        k.quarantine_add(id).unwrap();
        k.quarantine_remove(id).unwrap();
        assert!(!k.quarantined.contains(&id));
    }

    #[test]
    fn cgroup_of_answers_from_the_configured_map() {
        let mut k = FakeKernel::default();
        k.pid_cgroups.insert(42, "/user.slice/session-2.scope".to_string());
        assert_eq!(k.cgroup_of(42).unwrap(), "/user.slice/session-2.scope");
        assert!(k.cgroup_of(43).is_err());
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd sentinel && cargo test -p sentineld kernel`
Expected: FAIL to compile — `cannot find type FakeKernel`.

- [ ] **Step 3: Write the implementation**

Insert above the `tests` module in `kernel.rs`, under the existing doc comment:

```rust
use std::collections::{HashMap, HashSet};

use sentinel_rules::compile::Tables;

/// Number of enforcement hooks counted in `LOCKDOWN_COUNTS` (S2's `NHOOKS`).
pub const NHOOKS: usize = 8;

#[derive(Debug)]
pub struct KernelError(pub String);

impl std::fmt::Display for KernelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for KernelError {}

/// Maps, cgroupfs, socket destruction and the clock — every effect the daemon
/// has on the kernel.
pub trait Kernel: Send {
    /// `CLOCK_MONOTONIC` in ns — the clock `bpf_ktime_get_ns` reads.
    fn monotonic_ns(&self) -> u64;
    /// Wall clock in ms since the epoch, for an alert's `ts`.
    fn wall_ms(&self) -> u64;

    fn heartbeat(&mut self, ns: u64) -> Result<(), KernelError>;
    fn heartbeat_value(&self) -> Result<u64, KernelError>;
    fn drops(&self) -> Result<u64, KernelError>;
    fn lockdown_counts(&self) -> Result<[u64; NHOOKS], KernelError>;

    /// Replace `RULES`, `RULE_COUNT` and the lookup tables (spec §11.3). Write
    /// the new rules first and `RULE_COUNT` last, so a hook never walks a
    /// half-written set.
    fn swap_rules(&mut self, tables: &Tables) -> Result<(), KernelError>;

    fn quarantine_add(&mut self, cgroup_id: u64) -> Result<(), KernelError>;
    fn quarantine_remove(&mut self, cgroup_id: u64) -> Result<(), KernelError>;

    /// Create the cgroup directory and return its id (its inode).
    fn cgroup_create(&mut self, path: &str) -> Result<u64, KernelError>;
    fn cgroup_remove(&mut self, path: &str) -> Result<(), KernelError>;
    fn cgroup_attach(&mut self, path: &str, pid: u32) -> Result<(), KernelError>;
    fn cgroup_freeze(&mut self, path: &str, on: bool) -> Result<(), KernelError>;
    fn cgroup_kill(&mut self, path: &str) -> Result<(), KernelError>;
    /// The cgroup path of a live process, recorded before a freeze so
    /// `release` can put it back (spec §6).
    fn cgroup_of(&self, pid: u32) -> Result<String, KernelError>;

    /// Destroy the TCP and UDP sockets of these pids (spec §17.2). Returns how
    /// many were destroyed.
    fn destroy_sockets(&mut self, pids: &[u32]) -> Result<usize, KernelError>;
}

/// A `Kernel` that records calls instead of making them.
#[derive(Default)]
pub struct FakeKernel {
    /// Every call, in order, as `"<op> <args>"`.
    pub calls: Vec<String>,
    /// Calls that should fail, matched against the same strings as `calls`.
    pub fail_on: HashSet<String>,
    pub quarantined: HashSet<u64>,
    pub cgroups: HashMap<String, u64>,
    pub frozen: HashSet<String>,
    pub killed: HashSet<String>,
    /// What `cgroup_of` answers, per pid.
    pub pid_cgroups: HashMap<u32, String>,
    pub heartbeat_ns: u64,
    pub drops_value: u64,
    pub lockdown: [u64; NHOOKS],
    pub destroyed: Vec<u32>,
    pub rule_swaps: usize,
    now_ms: u64,
    next_cgroup_id: u64,
}

impl FakeKernel {
    /// Move the fake clock forward.
    pub fn advance_ms(&mut self, ms: u64) {
        self.now_ms += ms;
    }

    fn record(&mut self, call: String) -> Result<(), KernelError> {
        let fail = self.fail_on.contains(&call);
        self.calls.push(call.clone());
        if fail {
            Err(KernelError(format!("fake failure: {call}")))
        } else {
            Ok(())
        }
    }
}

impl Kernel for FakeKernel {
    fn monotonic_ns(&self) -> u64 {
        self.now_ms * 1_000_000
    }
    fn wall_ms(&self) -> u64 {
        self.now_ms
    }
    fn heartbeat(&mut self, ns: u64) -> Result<(), KernelError> {
        self.heartbeat_ns = ns;
        Ok(())
    }
    fn heartbeat_value(&self) -> Result<u64, KernelError> {
        Ok(self.heartbeat_ns)
    }
    fn drops(&self) -> Result<u64, KernelError> {
        Ok(self.drops_value)
    }
    fn lockdown_counts(&self) -> Result<[u64; NHOOKS], KernelError> {
        Ok(self.lockdown)
    }
    fn swap_rules(&mut self, tables: &Tables) -> Result<(), KernelError> {
        self.rule_swaps += 1;
        self.record(format!("swap_rules {}", tables.rules.len()))
    }
    fn quarantine_add(&mut self, cgroup_id: u64) -> Result<(), KernelError> {
        self.record(format!("quarantine_add {cgroup_id}"))?;
        self.quarantined.insert(cgroup_id);
        Ok(())
    }
    fn quarantine_remove(&mut self, cgroup_id: u64) -> Result<(), KernelError> {
        self.record(format!("quarantine_remove {cgroup_id}"))?;
        self.quarantined.remove(&cgroup_id);
        Ok(())
    }
    fn cgroup_create(&mut self, path: &str) -> Result<u64, KernelError> {
        self.record(format!("cgroup_create {path}"))?;
        self.next_cgroup_id += 1;
        let id = 1000 + self.next_cgroup_id;
        self.cgroups.insert(path.to_string(), id);
        Ok(id)
    }
    fn cgroup_remove(&mut self, path: &str) -> Result<(), KernelError> {
        self.record(format!("cgroup_remove {path}"))?;
        self.cgroups.remove(path);
        Ok(())
    }
    fn cgroup_attach(&mut self, path: &str, pid: u32) -> Result<(), KernelError> {
        self.record(format!("cgroup_attach {path} {pid}"))
    }
    fn cgroup_freeze(&mut self, path: &str, on: bool) -> Result<(), KernelError> {
        self.record(format!(
            "cgroup_freeze {path} {}",
            if on { "on" } else { "off" }
        ))?;
        if on {
            self.frozen.insert(path.to_string());
        } else {
            self.frozen.remove(path);
        }
        Ok(())
    }
    fn cgroup_kill(&mut self, path: &str) -> Result<(), KernelError> {
        self.record(format!("cgroup_kill {path}"))?;
        self.killed.insert(path.to_string());
        Ok(())
    }
    fn cgroup_of(&self, pid: u32) -> Result<String, KernelError> {
        self.pid_cgroups
            .get(&pid)
            .cloned()
            .ok_or_else(|| KernelError(format!("no cgroup recorded for pid {pid}")))
    }
    fn destroy_sockets(&mut self, pids: &[u32]) -> Result<usize, KernelError> {
        self.record(format!(
            "destroy_sockets {}",
            pids.iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(",")
        ))?;
        self.destroyed.extend_from_slice(pids);
        Ok(pids.len())
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd sentinel && cargo test -p sentineld kernel`
Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add sentinel/crates/sentineld/src/kernel.rs
git commit -m "feat(sentineld): Kernel trait for every kernel effect, plus FakeKernel"
```

---

## Task 8: Resolving a raw event

**Files:**
- Create: `sentinel/crates/sentineld/src/resolve.rs`
- Modify: `sentinel/crates/sentineld/src/lib.rs` (add `pub mod resolve;`)

Spec §7 and §17.7. A `RawEvent` from the ring carries a header and a kind-specific payload. The daemon turns it into an owned `Resolved`: the payload decoded into JSON, the executable and argv read from `/proc` (the kernel does not fill them), the `env_ld` and `stdio_socket` facts filled in user space, the ancestors and unit from the table, and `managed_home` decided against the rendered home-bind list.

`sentinel_rules::matcher::ResolvedEvent` borrows its strings, so `Resolved` owns them and lends a `ResolvedEvent` through `as_event`.

> **Corrections applied during execution (commit `155df39`).** `sentinel-common` is the contract, and the blocks below disagree with it in three places.
>
> 1. **`EventKind` has a thirteenth variant, `Dns`.** The `match kind` and `kind_name` below cover twelve, so neither compiles. No kernel program emits `Dns` — `grep EventKind:: crates/sentinel-ebpf/src/` lists eleven kinds, and `sentinel-detect` synthesizes the DNS ones from port-53 connects — and the payload union has no variant for it. It therefore decodes to no payload at all: `detail` carries `"on": "dns"` and nothing else, rather than another variant's bytes reinterpreted.
> 2. **The payload literals in the tests do not match the wire types.** `NetPayload` and `OpenPayload` both carry explicit padding (`_pad`), and `OpenPayload::path_len` is `u16`, not `u32`. The committed tests build their payloads through two helpers instead of repeating the literals.
> 3. **`from_raw` returns `Option<Resolved>`.** `EventKind::from_u8(h.kind).unwrap_or(EventKind::Exec)` turns a record whose `kind` byte decodes to nothing into an exec: the exec arm then reads the union as an `ExecPayload`, does two `/proc` reads against whatever pid the header claims, and the result goes to every `on = "exec"` rule, including those whose action is `freeze` or `kill`. Since the kernel object is embedded at build time the two sides cannot drift, so an unknown kind means a corrupt or forged record and the event is dropped. **Task 13's `on_event` must handle the `None`** — it already decodes `EventKind::from_u8` for its own table upkeep, so it can drop the event there.
>
> Added with it: a test that an unknown kind byte resolves to `None`, and one that a `Dns` kind decodes no payload.

- [ ] **Step 1: Write the failing tests**

Create `sentinel/crates/sentineld/src/resolve.rs` with the tests first:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::proc::{FakeProc, Proc};
    use crate::table::Table;
    use sentinel_common::wire::{EventPayload, ExecPayload, NetPayload, OpenPayload, RawEvent};

    fn hdr(kind: EventKind, pid: u32) -> EventHeader {
        let mut h: EventHeader = unsafe { std::mem::zeroed() };
        h.kind = kind as u8;
        h.pid = pid;
        h.ppid = 100;
        h.uid = 1000;
        h.cgroup_id = 77;
        h.ts_ns = 5_000_000_000;
        h.matched_rule = -1;
        h
    }

    fn fixture() -> (Table, FakeProc) {
        let mut src = FakeProc::default();
        for (pid, ppid, exe) in [
            (1u32, 0u32, "/usr/lib/systemd/systemd"),
            (100, 1, "/usr/bin/sshd"),
            (200, 100, "/usr/bin/bash"),
        ] {
            src.add(Proc {
                pid,
                ppid,
                exe: exe.to_string(),
                argv: format!("{exe} -i"),
                uid: 1000,
                unit: "session-2.scope".to_string(),
                cgroup_id: 77,
            });
        }
        let mut t = Table::default();
        t.seed(&src);
        (t, src)
    }

    #[test]
    fn exec_fills_exe_and_argv_from_proc_not_the_kernel() {
        let (t, src) = fixture();
        let mut ev = RawEvent {
            hdr: hdr(EventKind::Exec, 200),
            payload: EventPayload {
                exec: ExecPayload {
                    exe: [0; 256],
                    argv: [0; 256],
                    exe_len: 0,
                    argv_len: 0,
                    mnt_id: 42,
                },
            },
        };
        ev.hdr.facts[G_FLAGS] = F_MEMFD;
        let r = Resolved::from_raw(&ev, &t, &src, &HomeBinds::default());
        assert_eq!(r.exe, "/usr/bin/bash");
        assert_eq!(r.argv, "/usr/bin/bash -i");
        assert_eq!(r.parent_exe, "/usr/bin/sshd");
        assert_eq!(r.ancestors, vec!["/usr/bin/sshd", "/usr/lib/systemd/systemd"]);
        assert_eq!(r.unit, "session-2.scope");
        assert_eq!(r.detail["on"], "exec");
        assert_eq!(r.detail["mnt_id"], 42);
        assert_eq!(r.detail["memfd"], true);
    }

    #[test]
    fn exec_adds_the_user_space_facts() {
        let (t, mut src) = fixture();
        src.env_ld.insert(200);
        src.stdio_socket.insert(200);
        let ev = RawEvent {
            hdr: hdr(EventKind::Exec, 200),
            payload: EventPayload {
                exec: ExecPayload {
                    exe: [0; 256],
                    argv: [0; 256],
                    exe_len: 0,
                    argv_len: 0,
                    mnt_id: 0,
                },
            },
        };
        let r = Resolved::from_raw(&ev, &t, &src, &HomeBinds::default());
        assert!(r.facts.has(G_FLAGS, F_ENV_LD), "env_ld filled in user space");
        assert!(r.facts.has(G_FLAGS, F_STDIO_SOCKET));
        assert_eq!(r.detail["env_ld"], true);
        assert_eq!(r.detail["stdio_socket"], true);
    }

    #[test]
    fn non_exec_kinds_do_not_pay_for_the_proc_fact_reads() {
        let (t, mut src) = fixture();
        src.env_ld.insert(200);
        let ev = RawEvent {
            hdr: hdr(EventKind::Connect, 200),
            payload: EventPayload {
                net: NetPayload {
                    family: 2,
                    proto: 6,
                    addr: [10, 0, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    port: 443,
                },
            },
        };
        let r = Resolved::from_raw(&ev, &t, &src, &HomeBinds::default());
        assert!(
            !r.facts.has(G_FLAGS, F_ENV_LD),
            "env_ld is an exec-only fact"
        );
        assert_eq!(r.net, Some(("10.0.2.2".to_string(), 443)));
        assert_eq!(r.detail["addr"], "10.0.2.2");
        assert_eq!(r.detail["port"], 443);
    }

    #[test]
    fn ipv6_connect_renders_a_bracketed_address() {
        let (t, src) = fixture();
        let mut addr = [0u8; 16];
        addr[0] = 0x20;
        addr[1] = 0x01;
        addr[15] = 1;
        let ev = RawEvent {
            hdr: hdr(EventKind::Connect, 200),
            payload: EventPayload {
                net: NetPayload {
                    family: 10,
                    proto: 6,
                    addr,
                    port: 53,
                },
            },
        };
        let r = Resolved::from_raw(&ev, &t, &src, &HomeBinds::default());
        assert_eq!(r.net.unwrap().0, "[2001:0:0:0:0:0:0:1]");
    }

    #[test]
    fn open_decodes_the_path_and_the_device_class() {
        let (t, src) = fixture();
        let mut path = [0u8; 256];
        let p = b"/dev/video0";
        path[..p.len()].copy_from_slice(p);
        let ev = RawEvent {
            hdr: hdr(EventKind::Open, 200),
            payload: EventPayload {
                open: OpenPayload {
                    path,
                    path_len: p.len() as u32,
                    dev_class: 1,
                    mode: 0,
                },
            },
        };
        let r = Resolved::from_raw(&ev, &t, &src, &HomeBinds::default());
        assert_eq!(r.path, "/dev/video0");
        assert_eq!(r.detail["device"], "camera");
    }

    #[test]
    fn write_refused_sets_managed_home_for_a_bind_target() {
        let (t, src) = fixture();
        let binds = HomeBinds::new(vec!["/home/user/.bashrc".to_string()]);
        let mut path = [0u8; 256];
        let p = b"/home/user/.bashrc";
        path[..p.len()].copy_from_slice(p);
        let ev = RawEvent {
            hdr: hdr(EventKind::WriteRefused, 200),
            payload: EventPayload {
                open: OpenPayload {
                    path,
                    path_len: p.len() as u32,
                    dev_class: 0,
                    mode: 0,
                },
            },
        };
        let r = Resolved::from_raw(&ev, &t, &src, &binds);
        assert!(r.managed_home);

        let mut other = ev;
        let q = b"/home/user/notes.txt";
        let mut path2 = [0u8; 256];
        path2[..q.len()].copy_from_slice(q);
        // SAFETY: WriteRefused uses the open variant.
        other.payload.open.path = path2;
        other.payload.open.path_len = q.len() as u32;
        let r2 = Resolved::from_raw(&other, &t, &src, &binds);
        assert!(!r2.managed_home);
    }

    #[test]
    fn as_event_lends_the_matcher_view() {
        let (t, src) = fixture();
        let ev = RawEvent {
            hdr: hdr(EventKind::Exec, 200),
            payload: EventPayload {
                exec: ExecPayload {
                    exe: [0; 256],
                    argv: [0; 256],
                    exe_len: 0,
                    argv_len: 0,
                    mnt_id: 0,
                },
            },
        };
        let r = Resolved::from_raw(&ev, &t, &src, &HomeBinds::default());
        let view = r.as_event();
        assert_eq!(view.exe, "/usr/bin/bash");
        assert_eq!(view.kind, EventKind::Exec);
        assert_eq!(view.ancestors.len(), 2);
    }

    #[test]
    fn an_unknown_pid_still_resolves_with_header_facts() {
        let (t, src) = fixture();
        let ev = RawEvent {
            hdr: hdr(EventKind::Exec, 9999),
            payload: EventPayload {
                exec: ExecPayload {
                    exe: [0; 256],
                    argv: [0; 256],
                    exe_len: 0,
                    argv_len: 0,
                    mnt_id: 0,
                },
            },
        };
        let r = Resolved::from_raw(&ev, &t, &src, &HomeBinds::default());
        assert_eq!(r.exe, "");
        assert!(r.ancestors.is_empty());
        assert_eq!(r.pid, 9999);
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd sentinel && cargo test -p sentineld resolve`
Expected: FAIL to compile — `cannot find type Resolved`.

- [ ] **Step 3: Write the implementation**

Insert above the `tests` module in `resolve.rs`:

```rust
//! Turning a `RawEvent` into an owned, fully resolved event (spec §7, §17.7).

use std::collections::HashSet;

use sentinel_common::event::EventKind;
use sentinel_common::facts::{
    Facts, F_ENV_LD, F_STDIO_SOCKET, G_FLAGS,
};
use sentinel_common::wire::{EventHeader, KVerdict, RawEvent};
use sentinel_rules::matcher::ResolvedEvent;

use crate::proc::ProcSource;
use crate::table::Table;

/// The manifest-managed home targets (Base ISO §4.4), which `sentineld` fills
/// from the rendered home binds. `managed_home = true` holds for these paths
/// (spec amendment 5).
#[derive(Debug, Clone, Default)]
pub struct HomeBinds(HashSet<String>);

impl HomeBinds {
    pub fn new(paths: Vec<String>) -> HomeBinds {
        HomeBinds(paths.into_iter().collect())
    }
    pub fn contains(&self, path: &str) -> bool {
        self.0.contains(path)
    }
}

/// An event with every string resolved and every fact filled.
#[derive(Debug, Clone)]
pub struct Resolved {
    pub kind: EventKind,
    pub facts: Facts,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub cgroup_id: u64,
    pub ts_ns: u64,
    pub matched_rule: i32,
    pub kverdict: KVerdict,
    pub exe: String,
    pub argv: String,
    pub parent_exe: String,
    /// Ancestor executables, nearest first — what `ancestors` globs match.
    pub ancestors: Vec<String>,
    /// The same chain with pids and uids, for the alert record.
    pub ancestor_pids: Vec<u32>,
    pub unit: String,
    pub path: String,
    pub managed_home: bool,
    /// Destination of a connect or listen, as `(address, port)`.
    pub net: Option<(String, u16)>,
    /// The decoded payload, which becomes the alert's `event` object.
    pub detail: serde_json::Value,
}

fn kind_name(k: EventKind) -> &'static str {
    match k {
        EventKind::Exec => "exec",
        EventKind::Fork => "fork",
        EventKind::Exit => "exit",
        EventKind::Connect => "connect",
        EventKind::Listen => "listen",
        EventKind::Open => "open",
        EventKind::WriteRefused => "write_refused",
        EventKind::Memfd => "memfd",
        EventKind::Ptrace => "ptrace",
        EventKind::Module => "module",
        EventKind::Bpf => "bpf",
        EventKind::Signal => "signal",
    }
}

fn device_name(c: u8) -> &'static str {
    match c {
        1 => "camera",
        2 => "mic",
        3 => "input",
        4 => "uinput",
        5 => "hidraw",
        _ => "none",
    }
}

/// `addr` as text: dotted quad for family 2, bracketed groups for family 10.
fn render_addr(family: u16, addr: &[u8; 16]) -> String {
    if family == 2 {
        format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
    } else {
        let groups: Vec<String> = (0..8)
            .map(|i| format!("{:x}", u16::from_be_bytes([addr[2 * i], addr[2 * i + 1]])))
            .collect();
        format!("[{}]", groups.join(":"))
    }
}

/// A fixed-size, length-prefixed byte field as a string.
fn field_str(buf: &[u8], len: usize) -> String {
    let n = len.min(buf.len());
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

/// A NUL-terminated byte field as a string.
fn cstr(buf: &[u8]) -> String {
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

impl Resolved {
    pub fn from_raw(
        ev: &RawEvent,
        table: &Table,
        src: &dyn ProcSource,
        binds: &HomeBinds,
    ) -> Resolved {
        let h: &EventHeader = &ev.hdr;
        let kind = EventKind::from_u8(h.kind).unwrap_or(EventKind::Exec);
        let mut facts = Facts(h.facts);

        let me = table.get(h.pid);
        let exe = me.map(|p| p.exe.clone()).unwrap_or_default();
        let argv = me.map(|p| p.argv.clone()).unwrap_or_default();
        let unit = me.map(|p| p.unit.clone()).unwrap_or_default();
        let chain = table.ancestors(h.pid);
        let parent_exe = chain.first().map(|p| p.exe.clone()).unwrap_or_default();
        let ancestors: Vec<String> = chain.iter().map(|p| p.exe.clone()).collect();
        let ancestor_pids: Vec<u32> = chain.iter().map(|p| p.pid).collect();

        let mut detail = serde_json::json!({ "on": kind_name(kind) });
        let mut path = String::new();
        let mut net = None;

        match kind {
            EventKind::Exec => {
                // The kernel fills only mnt_id and the facts (§17.7); the two
                // remaining facts are ours to decide.
                // SAFETY: the kernel wrote the exec variant for this kind.
                let x = unsafe { ev.payload.exec };
                if src.has_env_ld(h.pid) {
                    facts.set(G_FLAGS, F_ENV_LD);
                }
                if src.has_stdio_socket(h.pid) {
                    facts.set(G_FLAGS, F_STDIO_SOCKET);
                }
                detail["mnt_id"] = x.mnt_id.into();
                detail["memfd"] = facts
                    .has(G_FLAGS, sentinel_common::facts::F_MEMFD)
                    .into();
                detail["deleted"] = facts
                    .has(G_FLAGS, sentinel_common::facts::F_DELETED)
                    .into();
                detail["outside_usr"] = facts
                    .has(G_FLAGS, sentinel_common::facts::F_OUTSIDE_USR)
                    .into();
                detail["env_ld"] = facts.has(G_FLAGS, F_ENV_LD).into();
                detail["stdio_socket"] = facts.has(G_FLAGS, F_STDIO_SOCKET).into();
            }
            EventKind::Fork | EventKind::Exit => {
                // SAFETY: the kernel wrote the proc_ variant for these kinds.
                let p = unsafe { ev.payload.proc_ };
                detail["child_pid"] = p.child_pid.into();
                detail["exit_code"] = p.exit_code.into();
            }
            EventKind::Connect | EventKind::Listen => {
                // SAFETY: the kernel wrote the net variant for these kinds.
                let n = unsafe { ev.payload.net };
                let addr = render_addr(n.family, &n.addr);
                detail["family"] = n.family.into();
                detail["addr"] = addr.clone().into();
                detail["port"] = n.port.into();
                detail["proto"] = n.proto.into();
                net = Some((addr, n.port));
            }
            EventKind::Open | EventKind::WriteRefused => {
                // SAFETY: the kernel wrote the open variant for these kinds.
                let o = unsafe { ev.payload.open };
                path = field_str(&o.path, o.path_len as usize);
                detail["path"] = path.clone().into();
                detail["device"] = device_name(o.dev_class).into();
                detail["mode"] = o.mode.into();
            }
            EventKind::Memfd => {
                // SAFETY: the kernel wrote the memfd variant for this kind.
                let m = unsafe { ev.payload.memfd };
                detail["name"] = cstr(&m.name).into();
                detail["flags"] = m.flags.into();
            }
            EventKind::Ptrace => {
                // SAFETY: the kernel wrote the ptrace variant for this kind.
                let t = unsafe { ev.payload.ptrace };
                detail["target_pid"] = t.target_pid.into();
                detail["target_uid"] = t.target_uid.into();
                detail["mode"] = t.mode.into();
            }
            EventKind::Module => {
                // SAFETY: the kernel wrote the module variant for this kind.
                let m = unsafe { ev.payload.module };
                detail["name"] = cstr(&m.name).into();
                detail["read_id"] = m.read_id.into();
            }
            EventKind::Bpf => {
                // SAFETY: the kernel wrote the bpf variant for this kind.
                let b = unsafe { ev.payload.bpf };
                detail["cmd"] = b.cmd.into();
                detail["prog_type"] = b.prog_type.into();
            }
            EventKind::Signal => {
                // SAFETY: the kernel wrote the signal variant for this kind.
                let s = unsafe { ev.payload.signal };
                detail["target_pid"] = s.target_pid.into();
                detail["sig"] = s.sig.into();
            }
        }

        let managed_home =
            matches!(kind, EventKind::WriteRefused | EventKind::Open) && binds.contains(&path);

        Resolved {
            kind,
            facts,
            pid: h.pid,
            ppid: h.ppid,
            uid: h.uid,
            cgroup_id: h.cgroup_id,
            ts_ns: h.ts_ns,
            matched_rule: h.matched_rule,
            kverdict: match h.kverdict {
                1 => KVerdict::Denied,
                2 => KVerdict::WouldDeny,
                _ => KVerdict::None,
            },
            exe,
            argv,
            parent_exe,
            ancestors,
            ancestor_pids,
            unit,
            path,
            managed_home,
            net,
            detail,
        }
    }

    /// The borrowed view `sentinel-rules` matches against.
    pub fn as_event(&self) -> ResolvedEvent<'_> {
        ResolvedEvent {
            kind: self.kind,
            facts: self.facts,
            exe: &self.exe,
            argv: &self.argv,
            parent_exe: &self.parent_exe,
            ancestors: &self.ancestors,
            unit: &self.unit,
            path: &self.path,
            managed_home: self.managed_home,
        }
    }
}
```

Add `pub mod resolve;` to `lib.rs`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd sentinel && cargo test -p sentineld resolve`
Expected: 8 passed.

If `EventKind::from_u8` or `Facts::has` has a different signature than the contract reference above, read `sentinel-common/src/event.rs` and `facts.rs` and match them — those two crates are the contract, not this plan.

- [ ] **Step 5: Commit**

```bash
git add sentinel/crates/sentineld/src/resolve.rs sentinel/crates/sentineld/src/lib.rs
git commit -m "feat(sentineld): resolve raw events into owned, fact-complete events"
```

---

## Task 9: freeze, kill and release

**Files:**
- Create: `sentinel/crates/sentineld/src/action.rs`
- Modify: `sentinel/crates/sentineld/src/lib.rs` (add `pub mod action;`)

Spec §6. **freeze:** take the process and all its descendants, create `/sys/fs/cgroup/aios-sentinel.slice/q-<alert-id>/`, write each pid into `cgroup.procs`, rescan until no new descendant appears, set `cgroup.freeze = 1`, put the cgroup id in the quarantine map, destroy the existing sockets, and record each process's original cgroup. **kill:** the same, then `cgroup.kill = 1`. **release:** unfreeze, remove from the quarantine map, move the processes back. A failed action is a critical alert naming the error, and the process is then neither frozen nor killed.

Order matters and the tests assert it: the quarantine map entry and the socket destruction must both happen **after** the freeze, so nothing in the tree can open a new connection in between.

- [ ] **Step 1: Write the failing tests**

Create `sentinel/crates/sentineld/src/action.rs` with the tests first:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::FakeKernel;
    use crate::proc::Proc;
    use crate::table::Table;

    fn p(pid: u32, ppid: u32) -> Proc {
        Proc {
            pid,
            ppid,
            exe: "/usr/bin/bash".to_string(),
            argv: "bash -i".to_string(),
            uid: 1000,
            unit: "session-2.scope".to_string(),
            cgroup_id: 77,
        }
    }

    fn setup() -> (Table, FakeKernel) {
        let mut t = Table::default();
        t.insert(p(1, 0));
        t.insert(p(200, 1));
        t.insert(p(201, 200));
        let mut k = FakeKernel::default();
        for pid in [200u32, 201] {
            k.pid_cgroups
                .insert(pid, "/user.slice/session-2.scope".to_string());
        }
        (t, k)
    }

    #[test]
    fn freeze_moves_the_whole_tree_then_freezes_then_cuts_the_network() {
        let (t, mut k) = setup();
        let q = freeze(&mut k, &t, "A1", 200, false).expect("freeze succeeds");
        assert_eq!(q.cgroup, "/sys/fs/cgroup/aios-sentinel.slice/q-A1");
        let mut pids = q.pids.clone();
        pids.sort_unstable();
        assert_eq!(pids, vec![200, 201]);

        // The order is the guarantee: attach, freeze, quarantine, destroy.
        let ops: Vec<&str> = k.calls.iter().map(|c| c.split(' ').next().unwrap()).collect();
        let freeze_at = ops.iter().position(|o| *o == "cgroup_freeze").unwrap();
        let quarantine_at = ops.iter().position(|o| *o == "quarantine_add").unwrap();
        let destroy_at = ops.iter().position(|o| *o == "destroy_sockets").unwrap();
        let last_attach = ops.iter().rposition(|o| *o == "cgroup_attach").unwrap();
        assert!(last_attach < freeze_at, "every pid is attached before the freeze");
        assert!(freeze_at < quarantine_at, "freeze before the quarantine map");
        assert!(quarantine_at < destroy_at, "map entry before destroying sockets");
        assert!(k.frozen.contains(&q.cgroup));
        assert!(k.quarantined.contains(&q.cgroup_id));
    }

    #[test]
    fn freeze_records_the_original_cgroup_of_each_process() {
        let (t, mut k) = setup();
        let q = freeze(&mut k, &t, "A1", 200, false).unwrap();
        assert_eq!(
            q.original.get(&200).map(String::as_str),
            Some("/user.slice/session-2.scope")
        );
        assert_eq!(q.original.len(), 2);
    }

    #[test]
    fn kill_freezes_first_then_kills() {
        let (t, mut k) = setup();
        let q = freeze(&mut k, &t, "A2", 200, true).unwrap();
        let ops: Vec<&str> = k.calls.iter().map(|c| c.split(' ').next().unwrap()).collect();
        let freeze_at = ops.iter().position(|o| *o == "cgroup_freeze").unwrap();
        let kill_at = ops.iter().position(|o| *o == "cgroup_kill").unwrap();
        assert!(freeze_at < kill_at, "freeze stops forking before the kill");
        assert!(k.killed.contains(&q.cgroup));
    }

    #[test]
    fn a_failed_freeze_reports_the_error_and_leaves_nothing_quarantined() {
        let (t, mut k) = setup();
        k.fail_on
            .insert("cgroup_freeze /sys/fs/cgroup/aios-sentinel.slice/q-A3 on".to_string());
        let e = freeze(&mut k, &t, "A3", 200, false).unwrap_err();
        assert!(e.to_string().contains("cgroup_freeze"), "error was {e}");
        assert!(
            k.quarantined.is_empty(),
            "a failed freeze must not leave a quarantine entry"
        );
    }

    #[test]
    fn release_unfreezes_restores_cgroups_and_clears_the_map() {
        let (t, mut k) = setup();
        let q = freeze(&mut k, &t, "A4", 200, false).unwrap();
        k.calls.clear();
        release(&mut k, &q).expect("release succeeds");
        assert!(!k.frozen.contains(&q.cgroup));
        assert!(!k.quarantined.contains(&q.cgroup_id));
        assert!(
            k.calls.contains(&"cgroup_attach /user.slice/session-2.scope 200".to_string()),
            "calls were {:?}",
            k.calls
        );
        assert!(k.calls.contains(&format!("cgroup_remove {}", q.cgroup)));
    }

    #[test]
    fn kill_quarantine_kills_an_existing_quarantine() {
        let (t, mut k) = setup();
        let q = freeze(&mut k, &t, "A5", 200, false).unwrap();
        k.calls.clear();
        kill_quarantine(&mut k, &q).expect("kill succeeds");
        assert!(k.killed.contains(&q.cgroup));
    }

    #[test]
    fn the_registry_tracks_and_drops_quarantines() {
        let (t, mut k) = setup();
        let mut reg = Registry::default();
        let q = freeze(&mut k, &t, "A6", 200, false).unwrap();
        reg.insert(q);
        assert_eq!(reg.list().len(), 1);
        assert!(reg.get("A6").is_some());
        let taken = reg.take("A6").expect("present");
        assert_eq!(taken.alert_id, "A6");
        assert!(reg.list().is_empty());
        assert!(reg.take("A6").is_none());
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd sentinel && cargo test -p sentineld action`
Expected: FAIL to compile — `cannot find function freeze`.

- [ ] **Step 3: Write the implementation**

Insert above the `tests` module in `action.rs`:

```rust
//! freeze, kill and release over the [`Kernel`] trait (spec §6).

use std::collections::HashMap;

use crate::kernel::{Kernel, KernelError};
use crate::table::Table;

/// Parent slice of every quarantine cgroup (spec §6).
pub const QUARANTINE_SLICE: &str = "/sys/fs/cgroup/aios-sentinel.slice";

/// How many times the descendant rescan runs before giving up. A tree that
/// keeps forking faster than this is a `kill` case, not a `freeze` case.
const RESCAN_ROUNDS: usize = 4;

/// One live quarantine.
#[derive(Debug, Clone)]
pub struct Quarantine {
    /// The alert that caused it; also the cgroup's name suffix.
    pub alert_id: String,
    pub cgroup: String,
    pub cgroup_id: u64,
    /// Every pid moved into the quarantine cgroup.
    pub pids: Vec<u32>,
    /// Where each pid came from, so `release` can put it back.
    pub original: HashMap<u32, String>,
    /// The process the rule actually hit.
    pub root_pid: u32,
    pub killed: bool,
}

/// Move `root_pid` and its descendants into a fresh quarantine cgroup, freeze
/// them, deny their network and destroy their sockets. With `kill`, also set
/// `cgroup.kill` once the tree is frozen (spec §6).
pub fn freeze(
    k: &mut dyn Kernel,
    table: &Table,
    alert_id: &str,
    root_pid: u32,
    kill: bool,
) -> Result<Quarantine, KernelError> {
    let cgroup = format!("{QUARANTINE_SLICE}/q-{alert_id}");
    let cgroup_id = k.cgroup_create(&cgroup)?;

    let mut moved: Vec<u32> = Vec::new();
    let mut original: HashMap<u32, String> = HashMap::new();

    // Rescan until a round adds nothing: a process that forked while we were
    // moving its siblings is caught by the next round.
    for _ in 0..RESCAN_ROUNDS {
        let mut added = 0;
        for pid in table.descendants(root_pid) {
            if moved.contains(&pid) {
                continue;
            }
            // Record where it came from before moving it. A process that died
            // in the meantime has no cgroup; skip it rather than fail the
            // whole action.
            let Ok(from) = k.cgroup_of(pid) else { continue };
            k.cgroup_attach(&cgroup, pid)?;
            original.insert(pid, from);
            moved.push(pid);
            added += 1;
        }
        if added == 0 {
            break;
        }
    }

    // Freeze before touching the quarantine map, so nothing in the tree runs
    // while the map entry is going in.
    k.cgroup_freeze(&cgroup, true)?;
    k.quarantine_add(cgroup_id)?;
    // New connections are already denied by the LSM hooks; this closes the
    // ones that were open before (spec §17.2).
    k.destroy_sockets(&moved)?;

    if kill {
        k.cgroup_kill(&cgroup)?;
    }

    Ok(Quarantine {
        alert_id: alert_id.to_string(),
        cgroup,
        cgroup_id,
        pids: moved,
        original,
        root_pid,
        killed: kill,
    })
}

/// Unfreeze, drop the quarantine map entry, put every process back in its
/// original cgroup and remove the quarantine cgroup (spec §6 `release`).
pub fn release(k: &mut dyn Kernel, q: &Quarantine) -> Result<(), KernelError> {
    k.quarantine_remove(q.cgroup_id)?;
    k.cgroup_freeze(&q.cgroup, false)?;
    for pid in &q.pids {
        if let Some(from) = q.original.get(pid) {
            // A process that exited while frozen cannot be moved; that is not
            // a failure of the release.
            let _ = k.cgroup_attach(from, *pid);
        }
    }
    k.cgroup_remove(&q.cgroup)?;
    Ok(())
}

/// `cgroup.kill = 1` on an existing quarantine (spec §6 `kill`).
pub fn kill_quarantine(k: &mut dyn Kernel, q: &Quarantine) -> Result<(), KernelError> {
    k.cgroup_kill(&q.cgroup)
}

/// The live quarantines, keyed by alert id.
#[derive(Default)]
pub struct Registry {
    items: HashMap<String, Quarantine>,
}

impl Registry {
    pub fn insert(&mut self, q: Quarantine) {
        self.items.insert(q.alert_id.clone(), q);
    }
    pub fn get(&self, alert_id: &str) -> Option<&Quarantine> {
        self.items.get(alert_id)
    }
    /// Remove and return one, for `Release` and `Kill`.
    pub fn take(&mut self, alert_id: &str) -> Option<Quarantine> {
        self.items.remove(alert_id)
    }
    /// Every quarantine, sorted by alert id so `ListQuarantine` is stable.
    pub fn list(&self) -> Vec<&Quarantine> {
        let mut v: Vec<&Quarantine> = self.items.values().collect();
        v.sort_by(|a, b| a.alert_id.cmp(&b.alert_id));
        v
    }
}
```

Add `pub mod action;` to `lib.rs`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd sentinel && cargo test -p sentineld action`
Expected: 7 passed.

- [ ] **Step 5: Commit**

```bash
git add sentinel/crates/sentineld/src/action.rs sentinel/crates/sentineld/src/lib.rs
git commit -m "feat(sentineld): freeze, kill and release over the Kernel trait"
```

---

## Task 10: Rule dispatch, protected processes and outcomes

**Files:**
- Create: `sentinel/crates/sentineld/src/engine.rs`
- Modify: `sentinel/crates/sentineld/src/lib.rs` (add `pub mod engine;`)

Spec §5.3, §6. Two things produce a decision for one event:

1. **The kernel already matched it.** `hdr.matched_rule >= 0` names a kernel rule by index. Its event carries the verdict (§5.3: "Kernel rules also emit their event with the verdict, so the alert carries full context from user space").
2. **A user rule matches.** `UserRule::matches` decides, and a rule with a `window` only fires once its sliding count is reached.

Then §6 trims the result: PID 1, `sentineld` itself, `systemd-journald`, kernel threads and units matching `never_act_on` are **never acted on** — such a hit alerts with `outcome = "suppressed"`. A rule in `mode = "audit"` never acts either; its outcome says what would have happened.

This task produces `Decision` values only. Task 13 turns them into alerts and actions.

- [ ] **Step 1: Write the failing tests**

Create `sentinel/crates/sentineld/src/engine.rs` with the tests first:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::proc::{FakeProc, Proc};
    use crate::resolve::{HomeBinds, Resolved};
    use crate::table::Table;
    use sentinel_common::wire::{EventPayload, ExecPayload, EventHeader, RawEvent};

    const PACK: &str = r#"
[[rule]]
id = "exec-memfd"
on = "exec"
severity = "critical"
action = "deny"
match = { exe_memfd = true }

[[rule]]
id = "ld-preload"
on = "exec"
severity = "medium"
action = "alert"
match = { env_ld = true }

[[rule]]
id = "reverse-shell"
on = "exec"
severity = "high"
action = "freeze"
match = { exe = ["/usr/bin/bash"], stdio_socket = true }
except = { ancestors = ["/usr/bin/sshd"] }

[[rule]]
id = "noisy"
on = "exec"
severity = "low"
action = "alert"
match = { exe = ["/usr/bin/noisy"] }
window = { count = 3, within = "60s", by = "exe" }

[[rule]]
id = "audited"
on = "exec"
severity = "medium"
action = "freeze"
mode = "audit"
match = { exe = ["/usr/bin/audited"] }
"#;

    fn ruleset() -> RuleSet {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("pack.toml"), PACK).unwrap();
        let rules = sentinel_rules::load_dir(dir.path()).expect("pack is valid");
        RuleSet::compile(rules).expect("pack compiles")
    }

    fn proc_at(pid: u32, ppid: u32, exe: &str, unit: &str) -> Proc {
        Proc {
            pid,
            ppid,
            exe: exe.to_string(),
            argv: exe.to_string(),
            uid: 1000,
            unit: unit.to_string(),
            cgroup_id: 77,
        }
    }

    /// An exec event for `pid`, with the table and /proc wired to `exe`.
    fn exec_for(pid: u32, exe: &str, unit: &str, env_ld: bool, stdio: bool)
        -> (Resolved, Table)
    {
        let mut src = FakeProc::default();
        src.add(proc_at(1, 0, "/usr/lib/systemd/systemd", "init.scope"));
        src.add(proc_at(pid, 1, exe, unit));
        if env_ld {
            src.env_ld.insert(pid);
        }
        if stdio {
            src.stdio_socket.insert(pid);
        }
        let mut t = Table::default();
        t.seed(&src);
        let mut h: EventHeader = unsafe { std::mem::zeroed() };
        h.kind = EventKind::Exec as u8;
        h.pid = pid;
        h.ppid = 1;
        h.uid = 1000;
        h.matched_rule = -1;
        let ev = RawEvent {
            hdr: h,
            payload: EventPayload {
                exec: ExecPayload {
                    exe: [0; 256],
                    argv: [0; 256],
                    exe_len: 0,
                    argv_len: 0,
                    mnt_id: 0,
                },
            },
        };
        let r = Resolved::from_raw(&ev, &t, &src, &HomeBinds::default());
        (r, t)
    }

    fn policy() -> Policy {
        Policy::new(7, 9, vec!["systemd-*.service".to_string()])
    }

    #[test]
    fn a_user_rule_hit_produces_a_decision_naming_the_rule() {
        let mut rs = ruleset();
        let (r, _) = exec_for(200, "/usr/bin/bash", "session-2.scope", true, false);
        let d = rs.decide(&r, &policy(), 0);
        let ids: Vec<&str> = d.iter().map(|x| x.rule_id.as_str()).collect();
        assert_eq!(ids, vec!["ld-preload"]);
        assert_eq!(d[0].action, Action::Alert);
        assert_eq!(d[0].outcome, Outcome::Alerted);
        assert_eq!(d[0].severity, "medium");
    }

    #[test]
    fn except_suppresses_a_rule() {
        let mut rs = ruleset();
        let mut src = FakeProc::default();
        src.add(proc_at(1, 0, "/usr/lib/systemd/systemd", "init.scope"));
        src.add(proc_at(100, 1, "/usr/bin/sshd", "sshd.service"));
        src.add(proc_at(200, 100, "/usr/bin/bash", "session-2.scope"));
        src.stdio_socket.insert(200);
        let mut t = Table::default();
        t.seed(&src);
        let mut h: EventHeader = unsafe { std::mem::zeroed() };
        h.kind = EventKind::Exec as u8;
        h.pid = 200;
        h.matched_rule = -1;
        let ev = RawEvent {
            hdr: h,
            payload: EventPayload {
                exec: ExecPayload { exe: [0; 256], argv: [0; 256], exe_len: 0, argv_len: 0, mnt_id: 0 },
            },
        };
        let r = Resolved::from_raw(&ev, &t, &src, &HomeBinds::default());
        let d = rs.decide(&r, &policy(), 0);
        assert!(
            d.iter().all(|x| x.rule_id != "reverse-shell"),
            "sshd ancestor must suppress it: {:?}",
            d.iter().map(|x| &x.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_kernel_matched_event_becomes_a_decision_with_the_kernel_verdict() {
        let mut rs = ruleset();
        let (mut r, _) = exec_for(200, "/usr/bin/x", "session-2.scope", false, false);
        // The kernel matched rule index 0 (exec-memfd) and denied it.
        r.matched_rule = 0;
        r.kverdict = KVerdict::Denied;
        let d = rs.decide(&r, &policy(), 0);
        assert_eq!(d[0].rule_id, "exec-memfd");
        assert_eq!(d[0].outcome, Outcome::Denied);
        assert_eq!(d[0].action, Action::Deny);
    }

    #[test]
    fn a_would_deny_verdict_reports_would_deny() {
        let mut rs = ruleset();
        let (mut r, _) = exec_for(200, "/usr/bin/x", "session-2.scope", false, false);
        r.matched_rule = 0;
        r.kverdict = KVerdict::WouldDeny;
        let d = rs.decide(&r, &policy(), 0);
        assert_eq!(d[0].outcome, Outcome::WouldDeny);
    }

    #[test]
    fn an_audit_rule_reports_what_it_would_have_done() {
        let mut rs = ruleset();
        let (r, _) = exec_for(200, "/usr/bin/audited", "session-2.scope", false, false);
        let d = rs.decide(&r, &policy(), 0);
        assert_eq!(d[0].rule_id, "audited");
        assert_eq!(d[0].outcome, Outcome::WouldFreeze);
        assert!(!d[0].acts(), "an audit rule never acts");
    }

    #[test]
    fn a_windowed_rule_fires_only_on_the_nth_event() {
        let mut rs = ruleset();
        let (r, _) = exec_for(200, "/usr/bin/noisy", "session-2.scope", false, false);
        assert!(rs.decide(&r, &policy(), 0).is_empty(), "1st");
        assert!(rs.decide(&r, &policy(), 1000).is_empty(), "2nd");
        let d = rs.decide(&r, &policy(), 2000);
        assert_eq!(d.len(), 1, "3rd fires");
        assert_eq!(d[0].rule_id, "noisy");
    }

    #[test]
    fn a_windowed_rule_forgets_events_outside_the_window() {
        let mut rs = ruleset();
        let (r, _) = exec_for(200, "/usr/bin/noisy", "session-2.scope", false, false);
        rs.decide(&r, &policy(), 0);
        rs.decide(&r, &policy(), 1000);
        // The first two fall outside a 60 s window by now.
        assert!(rs.decide(&r, &policy(), 200_000).is_empty());
    }

    #[test]
    fn protected_processes_are_suppressed_not_acted_on() {
        let mut rs = ruleset();
        // pid 1
        let (r1, _) = exec_for(1, "/usr/bin/bash", "init.scope", false, true);
        // the daemon itself (policy says tgid 7)
        let (r2, _) = exec_for(7, "/usr/bin/bash", "session-2.scope", false, true);
        // journald (policy says pid 9)
        let (r3, _) = exec_for(9, "/usr/bin/bash", "session-2.scope", false, true);
        // a never_act_on unit
        let (r4, _) = exec_for(300, "/usr/bin/bash", "systemd-logind.service", false, true);
        for r in [r1, r2, r3, r4] {
            let d = rs.decide(&r, &policy(), 0);
            let hit = d.iter().find(|x| x.rule_id == "reverse-shell").expect("rule hit");
            assert_eq!(hit.outcome, Outcome::Suppressed, "pid {} unit {}", r.pid, r.unit);
            assert!(!hit.acts());
        }
    }

    #[test]
    fn an_alert_rule_on_a_protected_process_still_alerts() {
        let mut rs = ruleset();
        let (r, _) = exec_for(1, "/usr/bin/bash", "init.scope", true, false);
        let d = rs.decide(&r, &policy(), 0);
        let hit = d.iter().find(|x| x.rule_id == "ld-preload").unwrap();
        assert_eq!(
            hit.outcome,
            Outcome::Alerted,
            "protection only blocks freeze and kill, not alerting"
        );
    }

    #[test]
    fn kernel_threads_are_protected() {
        let p = policy();
        assert!(p.is_protected(2, ""), "kthreadd");
        assert!(p.is_protected(1, ""), "pid 1");
        assert!(!p.is_protected(4242, "session-2.scope"));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd sentinel && cargo test -p sentineld engine`
Expected: FAIL to compile — `cannot find type RuleSet`.

- [ ] **Step 3: Write the implementation**

Insert above the `tests` module in `engine.rs`:

```rust
//! Dispatch: which rules a resolved event hits, and what the outcome is
//! before any action runs (spec §5.3, §6).

use std::collections::HashMap;

use globset::{Glob, GlobSet, GlobSetBuilder};
use sentinel_common::event::{Action, EventKind, Mode};
use sentinel_common::wire::KVerdict;
use sentinel_rules::matcher::{compile_all, UserRule};
use sentinel_rules::model::Rule;
use sentinel_rules::validate::parse_duration_ms;
use sentinel_rules::window::WindowState;
use sentinel_rules::{compile::Tables, RuleError};

use crate::resolve::Resolved;

/// What happened, or would have happened (spec §6, §9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Alerted,
    Denied,
    WouldDeny,
    Frozen,
    WouldFreeze,
    Killed,
    WouldKill,
    /// The target is never acted on (spec §6).
    Suppressed,
    /// The storm brake is engaged (spec §6, Task 11).
    Braked,
    /// The action itself failed (spec §6, §12).
    Failed,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Alerted => "alerted",
            Outcome::Denied => "denied",
            Outcome::WouldDeny => "would-deny",
            Outcome::Frozen => "frozen",
            Outcome::WouldFreeze => "would-freeze",
            Outcome::Killed => "killed",
            Outcome::WouldKill => "would-kill",
            Outcome::Suppressed => "suppressed",
            Outcome::Braked => "braked",
            Outcome::Failed => "failed",
        }
    }
}

/// One rule hit on one event, before any action has run.
#[derive(Debug, Clone)]
pub struct Decision {
    pub rule_index: u32,
    pub rule_id: String,
    pub desc: String,
    pub severity: String,
    pub action: Action,
    pub mode: Mode,
    pub outcome: Outcome,
}

impl Decision {
    /// Does the daemon still have to do something, or is this alert-only?
    pub fn acts(&self) -> bool {
        matches!(self.outcome, Outcome::Frozen | Outcome::Killed)
    }
}

/// Which processes are never frozen or killed (spec §6).
pub struct Policy {
    /// The daemon's own tgid.
    pub self_tgid: u32,
    /// `systemd-journald`'s pid, or 0 if it is not running.
    pub journald_pid: u32,
    never_act_on: GlobSet,
}

impl Policy {
    pub fn new(self_tgid: u32, journald_pid: u32, never_act_on: Vec<String>) -> Policy {
        let mut b = GlobSetBuilder::new();
        for g in &never_act_on {
            // Validated by `config::validate`; a bad glob here is a bug.
            if let Ok(glob) = Glob::new(g) {
                b.add(glob);
            }
        }
        Policy {
            self_tgid,
            journald_pid,
            never_act_on: b.build().unwrap_or_else(|_| GlobSet::empty()),
        }
    }

    /// PID 1, the daemon, journald, kernel threads, and `never_act_on` units.
    pub fn is_protected(&self, pid: u32, unit: &str) -> bool {
        // pid 2 is kthreadd; every kernel thread descends from it, and those
        // never have an executable, so the table never resolves them anyway.
        pid <= 2
            || pid == self.self_tgid
            || (self.journald_pid != 0 && pid == self.journald_pid)
            || (!unit.is_empty() && self.never_act_on.is_match(unit))
    }
}

/// The compiled rule set, plus one window counter per windowed rule.
pub struct RuleSet {
    pub rules: Vec<Rule>,
    pub tables: Tables,
    pub user: Vec<UserRule>,
    windows: HashMap<u32, WindowState>,
}

impl RuleSet {
    /// Compile a loaded rule list. Fails with the same errors `aios plan` prints.
    pub fn compile(rules: Vec<Rule>) -> Result<RuleSet, Vec<RuleError>> {
        let (tables, user) = compile_all(&rules)?;
        let mut windows = HashMap::new();
        for u in &user {
            if let Some(w) = &u.window {
                // `within` was validated at load time.
                let ms = parse_duration_ms(&w.within).unwrap_or(60_000);
                windows.insert(u.index, WindowState::new(w.count, ms));
            }
        }
        Ok(RuleSet {
            rules,
            tables,
            user,
            windows,
        })
    }

    /// How many rules of each kind, for `Status` (spec §10.1).
    pub fn counts(&self) -> (usize, usize) {
        (self.tables.rules.len(), self.user.len())
    }

    /// The window key for a hit, per the rule's `by` (spec §5.1).
    fn window_key(by: &str, r: &Resolved) -> String {
        match by {
            "uid" => r.uid.to_string(),
            "unit" => r.unit.clone(),
            "dest" => r
                .net
                .as_ref()
                .map(|(a, p)| format!("{a}:{p}"))
                .unwrap_or_default(),
            // "exe" and anything else
            _ => r.exe.clone(),
        }
    }

    /// Build the decision for one rule hit, applying audit mode and protection.
    fn outcome_for(&self, idx: u32, action: Action, mode: Mode, protected: bool) -> Outcome {
        let _ = idx;
        if mode == Mode::Audit {
            return match action {
                Action::Alert => Outcome::Alerted,
                Action::Deny => Outcome::WouldDeny,
                Action::Freeze => Outcome::WouldFreeze,
                Action::Kill => Outcome::WouldKill,
            };
        }
        match action {
            Action::Alert => Outcome::Alerted,
            // A user rule can never be `deny` (§5.3), so this arm is only
            // reached for a kernel rule, whose verdict the caller overrides.
            Action::Deny => Outcome::Denied,
            Action::Freeze if protected => Outcome::Suppressed,
            Action::Kill if protected => Outcome::Suppressed,
            Action::Freeze => Outcome::Frozen,
            Action::Kill => Outcome::Killed,
        }
    }

    fn decision(&self, idx: u32, action: Action, mode: Mode, outcome: Outcome) -> Decision {
        let r = &self.rules[idx as usize];
        Decision {
            rule_index: idx,
            rule_id: r.id.clone(),
            desc: r.desc.clone(),
            severity: r.severity.clone(),
            action,
            mode,
            outcome,
        }
    }

    /// Every rule this event hits: the kernel's own match first, then the user
    /// rules in source order.
    pub fn decide(&mut self, r: &Resolved, policy: &Policy, now_ms: u64) -> Vec<Decision> {
        let mut out = Vec::new();
        let protected = policy.is_protected(r.pid, &r.unit);

        // 1. The kernel already decided this one (spec §5.3).
        if r.matched_rule >= 0 {
            let idx = r.matched_rule as u32;
            if let Some(rule) = self.rules.get(idx as usize) {
                let action = rule
                    .action
                    .as_deref()
                    .and_then(sentinel_rules::validate::parse_action)
                    .unwrap_or(Action::Alert);
                let mode = rule
                    .mode
                    .as_deref()
                    .and_then(sentinel_rules::validate::parse_mode)
                    .unwrap_or(Mode::Enforce);
                // The kernel's verdict wins over our own reading of the rule:
                // it is what actually happened in the hook.
                let outcome = match r.kverdict {
                    KVerdict::Denied => Outcome::Denied,
                    KVerdict::WouldDeny => Outcome::WouldDeny,
                    KVerdict::None => self.outcome_for(idx, action, mode, protected),
                };
                out.push(self.decision(idx, action, mode, outcome));
            }
        }

        // 2. User-space rules.
        let view = r.as_event();
        let hits: Vec<(u32, Action, Mode, Option<String>)> = self
            .user
            .iter()
            .filter(|u| u.on == r.kind && u.matches(&view))
            .map(|u| {
                (
                    u.index,
                    u.action,
                    u.mode,
                    u.window.as_ref().map(|w| w.by.clone()),
                )
            })
            .collect();

        for (idx, action, mode, by) in hits {
            if let Some(by) = by {
                let key = Self::window_key(&by, r);
                let fired = self
                    .windows
                    .get_mut(&idx)
                    .map(|w| w.record(&key, now_ms))
                    .unwrap_or(true);
                if !fired {
                    continue;
                }
            }
            let outcome = self.outcome_for(idx, action, mode, protected);
            out.push(self.decision(idx, action, mode, outcome));
        }

        out
    }
}
```

Add `pub mod engine;` to `lib.rs`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd sentinel && cargo test -p sentineld engine`
Expected: 10 passed.

If `parse_mode` is not public in `sentinel_rules::validate`, make it `pub` there (it is already used by `matcher.rs` internally) and note the change in the commit message.

- [ ] **Step 5: Commit**

```bash
git add sentinel/crates/sentineld/src/engine.rs sentinel/crates/sentineld/src/lib.rs
git commit -m "feat(sentineld): rule dispatch, windows, protected processes and outcomes"
```

---

## Task 11: The storm brake and the detectors

**Files:**
- Modify: `sentinel/crates/sentineld/src/engine.rs`

Spec §6 storm brake: more than `storm_brake` automatic freezes or kills within a minute and further hits only alert (`outcome = "braked"`), with a critical alert when the brake engages. Spec §5.4 detectors: `beacon` on connects, `dns_tunnel` on resolved query names; each has its own severity and action, and `beacon.allow` lists destinations and executables that are never reported.

- [ ] **Step 1: Write the failing tests**

Append inside the `tests` module in `engine.rs`:

```rust
    #[test]
    fn the_brake_engages_after_the_configured_count() {
        let mut b = StormBrake::new(2);
        assert!(!b.trip(0), "1st act allowed");
        assert!(!b.trip(100), "2nd act allowed");
        assert!(b.trip(200), "3rd act is braked");
        assert!(b.engaged(), "the brake reports itself engaged");
    }

    #[test]
    fn the_brake_reports_engaging_only_once() {
        let mut b = StormBrake::new(1);
        b.trip(0);
        assert!(b.trip(10) && b.just_engaged(), "first brake reports");
        assert!(b.trip(20) && !b.just_engaged(), "later brakes stay quiet");
    }

    #[test]
    fn the_brake_forgets_acts_older_than_a_minute() {
        let mut b = StormBrake::new(2);
        b.trip(0);
        b.trip(1_000);
        assert!(b.trip(2_000), "braked inside the minute");
        assert!(!b.trip(70_000), "the window has rolled past the old acts");
    }

    #[test]
    fn beacon_allow_list_skips_destinations_and_executables() {
        let d = Detectors::new(
            &sentinel_rules::config::Beacon {
                min_connects: 2,
                max_cov: 1.0,
                allow: vec!["9.9.9.9/32".to_string(), "/usr/bin/chronyd".to_string()],
                severity: "high".to_string(),
                action: "alert".to_string(),
            },
            &sentinel_rules::config::DnsTunnel::default(),
        );
        assert!(d.beacon_allowed("/usr/bin/curl", "9.9.9.9"), "CIDR match");
        assert!(d.beacon_allowed("/usr/bin/chronyd", "1.2.3.4"), "exe match");
        assert!(!d.beacon_allowed("/usr/bin/curl", "1.2.3.4"));
    }

    #[test]
    fn a_periodic_connect_fires_the_beacon_detector() {
        let mut d = Detectors::new(
            &sentinel_rules::config::Beacon {
                min_connects: 3,
                max_cov: 0.2,
                allow: vec![],
                severity: "high".to_string(),
                action: "alert".to_string(),
            },
            &sentinel_rules::config::DnsTunnel::default(),
        );
        let mut fired = None;
        for i in 0..4 {
            fired = d.on_connect("/usr/bin/implant", "10.0.2.2", 443, i * 5_000);
        }
        let hit = fired.expect("a perfectly periodic connect is a beacon");
        assert_eq!(hit.rule_id, "beacon");
        assert_eq!(hit.severity, "high");
        assert_eq!(hit.action, Action::Alert);
        assert_eq!(hit.event["dest"], "10.0.2.2");
    }

    #[test]
    fn a_detector_action_of_freeze_is_carried_through() {
        let mut d = Detectors::new(
            &sentinel_rules::config::Beacon {
                min_connects: 2,
                max_cov: 0.5,
                allow: vec![],
                severity: "critical".to_string(),
                action: "freeze".to_string(),
            },
            &sentinel_rules::config::DnsTunnel::default(),
        );
        let mut fired = None;
        for i in 0..3 {
            fired = d.on_connect("/usr/bin/implant", "10.0.2.2", 443, i * 5_000);
        }
        let hit = fired.expect("beacon fires");
        assert_eq!(hit.action, Action::Freeze);
        assert_eq!(hit.severity, "critical");
    }

    #[test]
    fn high_entropy_subdomains_fire_the_dns_detector() {
        let mut d = Detectors::new(
            &sentinel_rules::config::Beacon::default(),
            &sentinel_rules::config::DnsTunnel {
                label_len: 10,
                entropy: 3.0,
                unique_per_min: 1000,
                severity: "high".to_string(),
                action: "alert".to_string(),
            },
        );
        let hit = d
            .on_dns("a7f3k9x2m4q8w1e5r6t0y.example.com", 0)
            .expect("a high-entropy label is a tunnel");
        assert_eq!(hit.rule_id, "dns-tunnel");
        assert_eq!(hit.event["domain"], "example.com");
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd sentinel && cargo test -p sentineld engine`
Expected: FAIL to compile — `cannot find type StormBrake`.

- [ ] **Step 3: Write the implementation**

Append to `engine.rs`, above the `tests` module:

```rust
use std::collections::VecDeque;

use ipnet::IpNet;
use sentinel_detect::beacon::{Beacon, BeaconConfig};
use sentinel_detect::dns_tunnel::{DnsReason, DnsTunnel, DnsTunnelConfig};

/// The storm-brake window (spec §6: "within a minute").
pub const BRAKE_WINDOW_MS: u64 = 60_000;

/// Caps automatic freezes and kills (spec §6).
pub struct StormBrake {
    limit: u32,
    acts: VecDeque<u64>,
    engaged: bool,
    reported: bool,
}

impl StormBrake {
    pub fn new(limit: u32) -> StormBrake {
        StormBrake {
            limit,
            acts: VecDeque::new(),
            engaged: false,
            reported: false,
        }
    }

    /// Record one automatic act. Returns true when this one must be braked.
    pub fn trip(&mut self, now_ms: u64) -> bool {
        while let Some(&front) = self.acts.front() {
            if now_ms.saturating_sub(front) > BRAKE_WINDOW_MS {
                self.acts.pop_front();
            } else {
                break;
            }
        }
        if self.acts.len() as u32 >= self.limit {
            // Engaging for the first time in this window is itself a critical
            // alert (spec §6); `just_engaged` reports it exactly once.
            self.engaged = true;
            return true;
        }
        self.acts.push_back(now_ms);
        self.engaged = false;
        self.reported = false;
        false
    }

    pub fn engaged(&self) -> bool {
        self.engaged
    }

    /// True the first time the brake engages, false on every later brake.
    pub fn just_engaged(&mut self) -> bool {
        if self.engaged && !self.reported {
            self.reported = true;
            return true;
        }
        false
    }
}

/// A detector hit, shaped like a rule hit so the daemon handles both the same way.
#[derive(Debug, Clone)]
pub struct DetectorHit {
    pub rule_id: &'static str,
    pub severity: String,
    pub action: Action,
    pub event: serde_json::Value,
    /// The executable the hit is about, for the alert's process reference.
    pub exe: String,
}

/// The two built-in detectors plus their allow lists (spec §5.4).
pub struct Detectors {
    beacon: Beacon,
    dns: DnsTunnel,
    beacon_nets: Vec<IpNet>,
    beacon_exes: GlobSet,
    beacon_severity: String,
    beacon_action: Action,
    dns_severity: String,
    dns_action: Action,
}

impl Detectors {
    pub fn new(
        b: &sentinel_rules::config::Beacon,
        d: &sentinel_rules::config::DnsTunnel,
    ) -> Detectors {
        let mut nets = Vec::new();
        let mut exes = GlobSetBuilder::new();
        for a in &b.allow {
            // `config::validate` has already checked these are a CIDR or a
            // `/`-prefixed glob.
            if let Ok(n) = a.parse::<IpNet>() {
                nets.push(n);
            } else if let Ok(g) = Glob::new(a) {
                exes.add(g);
            }
        }
        Detectors {
            beacon: Beacon::new(BeaconConfig {
                min_connects: b.min_connects,
                max_cov: b.max_cov,
                ..BeaconConfig::default()
            }),
            dns: DnsTunnel::new(DnsTunnelConfig {
                label_len: d.label_len,
                entropy: d.entropy,
                unique_per_min: d.unique_per_min,
                ..DnsTunnelConfig::default()
            }),
            beacon_nets: nets,
            beacon_exes: exes.build().unwrap_or_else(|_| GlobSet::empty()),
            beacon_severity: b.severity.clone(),
            beacon_action: sentinel_rules::validate::parse_action(&b.action)
                .unwrap_or(Action::Alert),
            dns_severity: d.severity.clone(),
            dns_action: sentinel_rules::validate::parse_action(&d.action).unwrap_or(Action::Alert),
        }
    }

    /// Is this (executable, destination) never reported (spec §5.4 `allow`)?
    pub fn beacon_allowed(&self, exe: &str, dest: &str) -> bool {
        if self.beacon_exes.is_match(exe) {
            return true;
        }
        match dest.trim_matches(['[', ']']).parse::<std::net::IpAddr>() {
            Ok(ip) => self.beacon_nets.iter().any(|n| n.contains(&ip)),
            Err(_) => false,
        }
    }

    /// Feed one connect to the beacon detector.
    pub fn on_connect(
        &mut self,
        exe: &str,
        dest: &str,
        port: u16,
        now_ms: u64,
    ) -> Option<DetectorHit> {
        if self.beacon_allowed(exe, dest) {
            return None;
        }
        let hit = self.beacon.observe(exe, dest, port, now_ms)?;
        Some(DetectorHit {
            rule_id: "beacon",
            severity: self.beacon_severity.clone(),
            action: self.beacon_action,
            event: serde_json::json!({
                "on": "connect",
                "detector": "beacon",
                "dest": hit.dest,
                "port": hit.port,
                "count": hit.count,
                "cov": hit.cov,
            }),
            exe: hit.exe,
        })
    }

    /// Feed one resolved query name to the DNS-tunnel detector.
    pub fn on_dns(&mut self, qname: &str, now_ms: u64) -> Option<DetectorHit> {
        let hit = self.dns.observe(qname, now_ms)?;
        let reason = match &hit.reason {
            DnsReason::HighEntropy { label, bits } => serde_json::json!({
                "reason": "entropy", "label": label, "bits": bits
            }),
            DnsReason::HighRate { unique } => serde_json::json!({
                "reason": "rate", "unique": unique
            }),
        };
        let mut event = serde_json::json!({
            "on": "dns",
            "detector": "dns_tunnel",
            "domain": hit.domain,
        });
        if let (Some(dst), Some(src)) = (event.as_object_mut(), reason.as_object()) {
            for (k, v) in src {
                dst.insert(k.clone(), v.clone());
            }
        }
        Some(DetectorHit {
            rule_id: "dns-tunnel",
            severity: self.dns_severity.clone(),
            action: self.dns_action,
            // Host-level: the alert names the domain, not a process (§5.4).
            event,
            exe: String::new(),
        })
    }
}
```

`sentinel_rules::config::Beacon` and `DnsTunnel` must derive `Default` for the tests above; they already do (S1 implements `Default` by hand). If `Beacon::default()` is not reachable from another crate, the S1 impl is private — make it `impl Default for Beacon` public, which it already is.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd sentinel && cargo test -p sentineld engine`
Expected: 17 passed (the 10 from Task 10 plus these 7).

- [ ] **Step 5: Commit**

```bash
git add sentinel/crates/sentineld/src/engine.rs
git commit -m "feat(sentineld): storm brake and the beacon/dns-tunnel detectors"
```

---

## Task 12: Reporting an alert to the journal and the TTYs

**Files:**
- Create: `sentinel/crates/sentineld/src/report.rs`
- Modify: `sentinel/crates/sentineld/src/lib.rs` (add `pub mod report;`)

Spec §9: every alert is logged to the journal with `SYSLOG_IDENTIFIER=sentineld`, a `PRIORITY` derived from severity (critical 2, high 3, medium 4, low 5, info 6) and `AIOS_SENTINEL_ALERT=<id>`; `high` and `critical` are also written to every logged-in TTY. Amendment 10 fixes how the TTY set is found.

The journald native protocol: a datagram to `/run/systemd/journal/socket`, fields as `KEY=value\n`. A value containing a newline is sent as `KEY\n` followed by its length as little-endian `u64`, the bytes, then `\n`. The encoder is pure and tested; the socket write is behind the `Sink` trait so the daemon's tests never need journald.

- [ ] **Step 1: Write the failing tests**

Create `sentinel/crates/sentineld/src/report.rs` with the tests first:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priority_follows_severity() {
        assert_eq!(priority("critical"), 2);
        assert_eq!(priority("high"), 3);
        assert_eq!(priority("medium"), 4);
        assert_eq!(priority("low"), 5);
        assert_eq!(priority("info"), 6);
        assert_eq!(priority("nonsense"), 6, "unknown severities are info");
    }

    #[test]
    fn plain_fields_are_key_equals_value_lines() {
        let out = encode_fields(&[("PRIORITY", "3"), ("SYSLOG_IDENTIFIER", "sentineld")]);
        assert_eq!(out, b"PRIORITY=3\nSYSLOG_IDENTIFIER=sentineld\n");
    }

    #[test]
    fn a_multiline_value_uses_the_binary_framing() {
        let out = encode_fields(&[("MESSAGE", "one\ntwo")]);
        let mut want = Vec::new();
        want.extend_from_slice(b"MESSAGE\n");
        want.extend_from_slice(&7u64.to_le_bytes());
        want.extend_from_slice(b"one\ntwo");
        want.push(b'\n');
        assert_eq!(out, want);
    }

    #[test]
    fn broadcast_covers_high_and_critical_only() {
        assert!(broadcasts("critical"));
        assert!(broadcasts("high"));
        assert!(!broadcasts("medium"));
        assert!(!broadcasts("low"));
    }

    #[test]
    fn the_fake_sink_records_what_it_was_given() {
        let mut s = FakeSink::default();
        let a = crate::alert::Alert {
            id: "A1".to_string(),
            ts: "2026-11-12T16:42:51.123Z".to_string(),
            rule: "reverse-shell".to_string(),
            severity: "high".to_string(),
            action: "freeze".to_string(),
            mode: "enforce".to_string(),
            outcome: "frozen".to_string(),
            message: String::new(),
            process: None,
            ancestors: vec![],
            event: serde_json::json!({"on": "exec"}),
            context: vec![],
            prev_hash: crate::alert::GENESIS.to_string(),
            hash: "abc".to_string(),
        };
        s.emit(&a);
        assert_eq!(s.journal.len(), 1);
        assert_eq!(s.tty.len(), 1, "high severity reaches the TTYs");
        assert!(s.tty[0].contains("reverse-shell"), "message was {}", s.tty[0]);
        assert!(s.tty[0].contains("frozen"));
    }

    #[test]
    fn the_fake_sink_skips_the_tty_for_a_low_alert() {
        let mut s = FakeSink::default();
        let mut a = crate::alert::Alert {
            id: "A2".to_string(),
            ts: String::new(),
            rule: "camera-open".to_string(),
            severity: "low".to_string(),
            action: "alert".to_string(),
            mode: "enforce".to_string(),
            outcome: "alerted".to_string(),
            message: String::new(),
            process: None,
            ancestors: vec![],
            event: serde_json::json!({}),
            context: vec![],
            prev_hash: crate::alert::GENESIS.to_string(),
            hash: String::new(),
        };
        a.severity = "low".to_string();
        s.emit(&a);
        assert_eq!(s.journal.len(), 1);
        assert!(s.tty.is_empty());
    }

    #[test]
    fn the_one_line_summary_names_rule_outcome_and_process() {
        let a = crate::alert::Alert {
            id: "A3".to_string(),
            ts: String::new(),
            rule: "exec-memfd".to_string(),
            severity: "critical".to_string(),
            action: "deny".to_string(),
            mode: "enforce".to_string(),
            outcome: "denied".to_string(),
            message: String::new(),
            process: Some(crate::alert::ProcRef {
                pid: 4242,
                exe: "/usr/bin/x".to_string(),
                argv: String::new(),
                uid: 1000,
                unit: String::new(),
            }),
            ancestors: vec![],
            event: serde_json::json!({}),
            context: vec![],
            prev_hash: crate::alert::GENESIS.to_string(),
            hash: String::new(),
        };
        let line = summary(&a);
        assert!(line.contains("exec-memfd"));
        assert!(line.contains("denied"));
        assert!(line.contains("4242"));
        assert!(line.contains("/usr/bin/x"));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd sentinel && cargo test -p sentineld report`
Expected: FAIL to compile — `cannot find function priority`.

- [ ] **Step 3: Write the implementation**

Insert above the `tests` module in `report.rs`:

```rust
//! Where an alert goes besides the store: the journal and the TTYs (spec §9).

use std::io::Write;

use crate::alert::Alert;

/// syslog priority from a severity name (spec §9).
pub fn priority(severity: &str) -> u8 {
    match severity {
        "critical" => 2,
        "high" => 3,
        "medium" => 4,
        "low" => 5,
        _ => 6,
    }
}

/// Which severities are broadcast to the TTYs (spec §9).
pub fn broadcasts(severity: &str) -> bool {
    matches!(severity, "high" | "critical")
}

/// Encode journald native-protocol fields. A value with a newline in it uses
/// the length-prefixed binary framing; everything else is `KEY=value\n`.
pub fn encode_fields(fields: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (k, v) in fields {
        if v.contains('\n') {
            out.extend_from_slice(k.as_bytes());
            out.push(b'\n');
            out.extend_from_slice(&(v.len() as u64).to_le_bytes());
            out.extend_from_slice(v.as_bytes());
            out.push(b'\n');
        } else {
            out.extend_from_slice(k.as_bytes());
            out.push(b'=');
            out.extend_from_slice(v.as_bytes());
            out.push(b'\n');
        }
    }
    out
}

/// The one-line form used for the journal MESSAGE and the TTY broadcast.
pub fn summary(a: &Alert) -> String {
    match &a.process {
        Some(p) => format!(
            "sentinel: {} [{}] {} — pid {} {} (uid {})",
            a.rule, a.severity, a.outcome, p.pid, p.exe, p.uid
        ),
        None => {
            let tail = if a.message.is_empty() {
                String::new()
            } else {
                format!(" — {}", a.message)
            };
            format!(
                "sentinel: {} [{}] {}{tail}",
                a.rule, a.severity, a.outcome
            )
        }
    }
}

/// Where alerts are reported, besides the store.
pub trait Sink: Send {
    fn emit(&mut self, a: &Alert);
}

/// The real sink: journald over its native socket, plus the TTYs.
pub struct SystemSink {
    journal: Option<std::os::unix::net::UnixDatagram>,
}

impl Default for SystemSink {
    fn default() -> SystemSink {
        SystemSink::new()
    }
}

impl SystemSink {
    pub fn new() -> SystemSink {
        let journal = std::os::unix::net::UnixDatagram::unbound()
            .ok()
            .filter(|s| s.connect("/run/systemd/journal/socket").is_ok());
        SystemSink { journal }
    }

    /// Every TTY an alert is broadcast to (amendment 10).
    fn ttys() -> Vec<String> {
        let mut out = Vec::new();
        if let Ok(rd) = std::fs::read_dir("/dev/pts") {
            for ent in rd.flatten() {
                let name = ent.file_name().to_string_lossy().into_owned();
                if name.chars().all(|c| c.is_ascii_digit()) {
                    out.push(format!("/dev/pts/{name}"));
                }
            }
        }
        for n in 1..=12 {
            let p = format!("/dev/tty{n}");
            if std::path::Path::new(&p).exists() {
                out.push(p);
            }
        }
        out.sort();
        out
    }
}

impl Sink for SystemSink {
    fn emit(&mut self, a: &Alert) {
        let prio = priority(&a.severity).to_string();
        let msg = summary(a);
        let payload = encode_fields(&[
            ("MESSAGE", &msg),
            ("PRIORITY", &prio),
            ("SYSLOG_IDENTIFIER", "sentineld"),
            ("AIOS_SENTINEL_ALERT", &a.id),
            ("AIOS_SENTINEL_RULE", &a.rule),
            ("AIOS_SENTINEL_OUTCOME", &a.outcome),
        ]);
        if let Some(s) = &self.journal {
            // A failed journal write must never take the daemon down; the
            // store and the TTYs still have the alert (spec §12).
            let _ = s.send(&payload);
        }
        if broadcasts(&a.severity) {
            let line = format!("\r\n{msg}\r\n");
            for t in Self::ttys() {
                if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(&t) {
                    let _ = f.write_all(line.as_bytes());
                }
            }
        }
    }
}

/// A sink that records instead of writing, for tests.
#[derive(Default)]
pub struct FakeSink {
    pub journal: Vec<String>,
    pub tty: Vec<String>,
}

impl Sink for FakeSink {
    fn emit(&mut self, a: &Alert) {
        let msg = summary(a);
        self.journal.push(msg.clone());
        if broadcasts(&a.severity) {
            self.tty.push(msg);
        }
    }
}
```

Add `pub mod report;` to `lib.rs`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd sentinel && cargo test -p sentineld report`
Expected: 7 passed.

- [ ] **Step 5: Commit**

```bash
git add sentinel/crates/sentineld/src/report.rs sentinel/crates/sentineld/src/lib.rs
git commit -m "feat(sentineld): journald and TTY reporting behind a Sink trait"
```

---

## Task 13: The daemon core — event in, alert and action out

**Files:**
- Create: `sentinel/crates/sentineld/src/daemon.rs`
- Modify: `sentinel/crates/sentineld/src/lib.rs` (add `pub mod daemon;`)

This is where the pieces meet. One `Daemon` owns the table, the rule set, the policy, the brake, the detectors, the quarantine registry, the store and the sinks. `on_event` is the whole hot path:

1. Update the process table (Exec, Fork, Exit).
2. Record the event in the context ring.
3. Feed the beacon detector on Connect.
4. Ask the engine for decisions.
5. For each decision: run the action, build the alert, append it, emit it.

Spec §6 (a failed action is a critical alert and the process is neither frozen nor killed), §9 (every alert is stored, journalled, broadcast), §12 (a store failure does not stop the journal and the TTYs).

- [ ] **Step 1: Write the failing tests**

Create `sentinel/crates/sentineld/src/daemon.rs` with the tests first:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::FakeKernel;
    use crate::proc::{FakeProc, Proc};
    use crate::report::FakeSink;
    use sentinel_common::event::EventKind;
    use sentinel_common::wire::{EventHeader, EventPayload, ExecPayload, NetPayload, RawEvent};

    const PACK: &str = r#"
[[rule]]
id = "ld-preload"
on = "exec"
severity = "medium"
action = "alert"
match = { env_ld = true }

[[rule]]
id = "reverse-shell"
on = "exec"
severity = "high"
action = "freeze"
match = { exe = ["/usr/bin/bash"], stdio_socket = true }
"#;

    fn p(pid: u32, ppid: u32, exe: &str) -> Proc {
        Proc {
            pid,
            ppid,
            exe: exe.to_string(),
            argv: format!("{exe} -i"),
            uid: 1000,
            unit: "session-2.scope".to_string(),
            cgroup_id: 77,
        }
    }

    /// A daemon over fakes, with the two-rule pack above.
    fn daemon(dir: &std::path::Path) -> (Daemon, Box<FakeKernel>) {
        let pack = dir.join("rules");
        std::fs::create_dir_all(&pack).unwrap();
        std::fs::write(pack.join("p.toml"), PACK).unwrap();
        let rules = sentinel_rules::load_dir(&pack).unwrap();
        let rs = crate::engine::RuleSet::compile(rules).unwrap();

        let mut src = FakeProc::default();
        src.add(p(1, 0, "/usr/lib/systemd/systemd"));
        src.add(p(200, 1, "/usr/bin/bash"));
        src.env_ld.insert(200);
        src.stdio_socket.insert(200);

        let mut k = FakeKernel::default();
        k.pid_cgroups.insert(200, "/user.slice/session-2.scope".to_string());

        let cfg = sentinel_rules::config::SentinelConfig::default();
        let mut d = Daemon::new(
            rs,
            cfg,
            Box::new(src),
            Box::new(FakeSink::default()),
            crate::alert::Store::open(&dir.join("alerts")).unwrap(),
            crate::engine::Policy::new(7, 9, vec![]),
            crate::resolve::HomeBinds::default(),
        );
        d.seed_table();
        (d, Box::new(k))
    }

    fn exec_event(pid: u32) -> RawEvent {
        let mut h: EventHeader = unsafe { std::mem::zeroed() };
        h.kind = EventKind::Exec as u8;
        h.pid = pid;
        h.ppid = 1;
        h.uid = 1000;
        h.matched_rule = -1;
        RawEvent {
            hdr: h,
            payload: EventPayload {
                exec: ExecPayload {
                    exe: [0; 256],
                    argv: [0; 256],
                    exe_len: 0,
                    argv_len: 0,
                    mnt_id: 0,
                },
            },
        }
    }

    #[test]
    fn an_alert_rule_stores_and_emits_one_alert() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, mut k) = daemon(dir.path());
        d.on_event(&exec_event(200), k.as_mut());

        let stored = d.store.read_all().unwrap();
        let ld = stored.iter().find(|a| a.rule == "ld-preload").expect("stored");
        assert_eq!(ld.outcome, "alerted");
        assert_eq!(ld.severity, "medium");
        assert_eq!(ld.process.as_ref().unwrap().exe, "/usr/bin/bash");
        assert_eq!(
            ld.ancestors.first().map(|a| a.exe.as_str()),
            Some("/usr/lib/systemd/systemd"),
            "the chain is carried into the alert"
        );
        assert!(!ld.id.is_empty(), "every alert gets an id");
    }

    #[test]
    fn a_freeze_rule_actually_freezes_and_records_the_quarantine() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, mut k) = daemon(dir.path());
        d.on_event(&exec_event(200), k.as_mut());

        let frozen = d
            .store
            .read_all()
            .unwrap()
            .into_iter()
            .find(|a| a.rule == "reverse-shell")
            .expect("reverse-shell alert");
        assert_eq!(frozen.outcome, "frozen");
        assert_eq!(d.quarantines.list().len(), 1);
        let q = d.quarantines.get(&frozen.id).expect("registered by alert id");
        assert_eq!(q.root_pid, 200);
        assert!(k.frozen.contains(&q.cgroup));
        assert!(k.quarantined.contains(&q.cgroup_id));
    }

    #[test]
    fn a_failed_action_becomes_a_critical_alert_and_freezes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, mut k) = daemon(dir.path());
        // Fail the freeze on whichever quarantine cgroup gets created.
        k.fail_on.insert(
            "cgroup_freeze /sys/fs/cgroup/aios-sentinel.slice/q-".to_string(),
        );
        // The id is a ULID, so match by prefix instead: make every freeze fail.
        k.fail_all_prefixed = Some("cgroup_freeze".to_string());

        d.on_event(&exec_event(200), k.as_mut());

        let stored = d.store.read_all().unwrap();
        let failed = stored
            .iter()
            .find(|a| a.rule == "reverse-shell")
            .expect("alert exists");
        assert_eq!(failed.outcome, "failed");
        assert!(
            failed.message.contains("cgroup_freeze"),
            "the error is named: {}",
            failed.message
        );
        assert_eq!(failed.severity, "critical", "a failed action is critical");
        assert!(d.quarantines.list().is_empty());
    }

    #[test]
    fn the_storm_brake_downgrades_later_freezes() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, mut k) = daemon(dir.path());
        d.brake = crate::engine::StormBrake::new(1);

        d.on_event(&exec_event(200), k.as_mut());
        d.on_event(&exec_event(200), k.as_mut());

        let outcomes: Vec<String> = d
            .store
            .read_all()
            .unwrap()
            .into_iter()
            .filter(|a| a.rule == "reverse-shell")
            .map(|a| a.outcome)
            .collect();
        assert_eq!(outcomes, vec!["frozen", "braked"]);
        assert!(
            d.store
                .read_all()
                .unwrap()
                .iter()
                .any(|a| a.rule == "storm-brake" && a.severity == "critical"),
            "engaging the brake is itself a critical alert"
        );
    }

    #[test]
    fn exit_removes_the_pid_from_the_table() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, mut k) = daemon(dir.path());
        let mut h: EventHeader = unsafe { std::mem::zeroed() };
        h.kind = EventKind::Exit as u8;
        h.pid = 200;
        h.matched_rule = -1;
        let ev = RawEvent {
            hdr: h,
            payload: EventPayload {
                proc_: sentinel_common::wire::ProcPayload {
                    child_pid: 200,
                    exit_code: 0,
                },
            },
        };
        d.on_event(&ev, k.as_mut());
        assert!(d.table.get(200).is_none());
    }

    #[test]
    fn a_connect_feeds_the_beacon_detector() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, mut k) = daemon(dir.path());
        d.detectors = crate::engine::Detectors::new(
            &sentinel_rules::config::Beacon {
                min_connects: 3,
                max_cov: 0.2,
                allow: vec![],
                severity: "high".to_string(),
                action: "alert".to_string(),
            },
            &sentinel_rules::config::DnsTunnel::default(),
        );
        for i in 0..4u64 {
            let mut h: EventHeader = unsafe { std::mem::zeroed() };
            h.kind = EventKind::Connect as u8;
            h.pid = 200;
            h.matched_rule = -1;
            h.ts_ns = i * 5_000_000_000;
            let ev = RawEvent {
                hdr: h,
                payload: EventPayload {
                    net: NetPayload {
                        family: 2,
                        proto: 6,
                        addr: [10, 0, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                        port: 443,
                    },
                },
            };
            k.advance_ms(5_000);
            d.on_event(&ev, k.as_mut());
        }
        assert!(
            d.store.read_all().unwrap().iter().any(|a| a.rule == "beacon"),
            "a periodic connect raises a beacon alert"
        );
    }

    #[test]
    fn a_ring_drop_raises_one_sensor_overflow_alert() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, mut k) = daemon(dir.path());
        k.drops_value = 5;
        d.check_drops(k.as_mut());
        d.check_drops(k.as_mut());
        let overflows = d
            .store
            .read_all()
            .unwrap()
            .into_iter()
            .filter(|a| a.rule == "sensor-overflow")
            .count();
        assert_eq!(overflows, 1, "only an increase alerts");

        k.drops_value = 9;
        d.check_drops(k.as_mut());
        let overflows = d
            .store
            .read_all()
            .unwrap()
            .into_iter()
            .filter(|a| a.rule == "sensor-overflow")
            .count();
        assert_eq!(overflows, 2);
    }
}
```

The failure test needs one more knob on `FakeKernel`. Add it in Task 7's file now:

```rust
    /// Every call whose text starts with this prefix fails. Useful when the
    /// argument contains a generated id.
    pub fail_all_prefixed: Option<String>,
```

and in `FakeKernel::record`, before the existing check:

```rust
        let fail = self.fail_on.contains(&call)
            || self
                .fail_all_prefixed
                .as_ref()
                .is_some_and(|p| call.starts_with(p.as_str()));
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd sentinel && cargo test -p sentineld daemon`
Expected: FAIL to compile — `cannot find type Daemon`.

- [ ] **Step 3: Write the implementation**

Insert above the `tests` module in `daemon.rs`:

```rust
//! The daemon state and the hot path: one raw event in, alerts and actions out.

use sentinel_common::event::{Action, EventKind};
use sentinel_common::wire::RawEvent;
use sentinel_rules::config::SentinelConfig;

use crate::action::{self, Registry};
use crate::alert::{Alert, ProcRef, Store};
use crate::engine::{Decision, Detectors, Outcome, Policy, RuleSet, StormBrake};
use crate::kernel::Kernel;
use crate::proc::ProcSource;
use crate::report::Sink;
use crate::resolve::{HomeBinds, Resolved};
use crate::table::Table;

/// Everything the daemon owns. The threads share one `Mutex<Daemon>`.
pub struct Daemon {
    pub rules: RuleSet,
    pub config: SentinelConfig,
    pub table: Table,
    pub procs: Box<dyn ProcSource>,
    pub sink: Box<dyn Sink>,
    pub store: Store,
    pub policy: Policy,
    pub binds: HomeBinds,
    pub quarantines: Registry,
    pub brake: StormBrake,
    pub detectors: Detectors,
    /// The last `DROPS` value seen, so only an increase alerts (spec §4).
    last_drops: u64,
    /// Alerts kept in memory for `WatchAlerts` subscribers (Task 17).
    pub recent: std::collections::VecDeque<Alert>,
    /// Set when the store is failing, for `Status` (spec §12).
    pub store_failing: Option<String>,
}

/// How many alerts stay in memory for watchers.
const RECENT_CAP: usize = 256;

impl Daemon {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rules: RuleSet,
        config: SentinelConfig,
        procs: Box<dyn ProcSource>,
        sink: Box<dyn Sink>,
        store: Store,
        policy: Policy,
        binds: HomeBinds,
    ) -> Daemon {
        let brake = StormBrake::new(config.storm_brake);
        let detectors = Detectors::new(&config.beacon, &config.dns_tunnel);
        Daemon {
            rules,
            config,
            table: Table::default(),
            procs,
            sink,
            store,
            policy,
            binds,
            quarantines: Registry::default(),
            brake,
            detectors,
            last_drops: 0,
            recent: std::collections::VecDeque::new(),
            store_failing: None,
        }
    }

    /// The start-up `/proc` scan (spec §4).
    pub fn seed_table(&mut self) {
        let src = &*self.procs;
        self.table.seed(src);
    }

    /// RFC 3339 UTC with millisecond precision, from a wall-clock millisecond
    /// count. Written by hand because the dependency set has no date crate.
    fn format_ts(ms: u64) -> String {
        let secs = (ms / 1000) as i64;
        let millis = ms % 1000;
        // Days since the Unix epoch, converted with the civil-from-days
        // algorithm (Howard Hinnant's, public domain).
        let days = secs.div_euclid(86_400);
        let rem = secs.rem_euclid(86_400);
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = if m <= 2 { y + 1 } else { y };
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
            y,
            m,
            d,
            rem / 3600,
            (rem % 3600) / 60,
            rem % 60,
            millis
        )
    }

    fn proc_ref(&self, pid: u32) -> Option<ProcRef> {
        self.table.get(pid).map(|p| ProcRef {
            pid: p.pid,
            exe: p.exe.clone(),
            argv: p.argv.clone(),
            uid: p.uid,
            unit: p.unit.clone(),
        })
    }

    /// Store, remember and emit one alert. A store failure is recorded for
    /// `Status` but never stops the journal or the TTYs (spec §12).
    pub fn raise(&mut self, mut a: Alert) -> String {
        match self.store.append(a.clone()) {
            Ok(hash) => {
                // `append` sealed its own copy; mirror the chain fields so the
                // in-memory record matches what is on disk.
                a.prev_hash = self.store_prev_of(&hash);
                a.hash = hash;
                if self.store_failing.take().is_some() {
                    // Recovered: spec §12 asks for a critical alert once the
                    // store works again.
                    let note = self.blank_alert("store-recovered", "critical", "alerted");
                    let _ = self.store.append(note);
                }
            }
            Err(e) => {
                self.store_failing = Some(e.to_string());
            }
        }
        self.sink.emit(&a);
        let id = a.id.clone();
        self.recent.push_back(a);
        while self.recent.len() > RECENT_CAP {
            self.recent.pop_front();
        }
        id
    }

    /// The `prev_hash` of the record whose hash is `hash` — that is, the chain
    /// head as it stood just before the append.
    fn store_prev_of(&self, hash: &str) -> String {
        self.store
            .read_all()
            .ok()
            .and_then(|all| all.iter().rev().find(|a| a.hash == hash).map(|a| a.prev_hash.clone()))
            .unwrap_or_else(|| crate::alert::GENESIS.to_string())
    }

    /// An alert that is not a rule hit: a lockdown report, a brake, an
    /// overflow, a configuration change.
    pub fn blank_alert(&self, rule: &str, severity: &str, outcome: &str) -> Alert {
        Alert {
            id: ulid::Ulid::new().to_string(),
            ts: String::new(),
            rule: rule.to_string(),
            severity: severity.to_string(),
            action: "alert".to_string(),
            mode: "enforce".to_string(),
            outcome: outcome.to_string(),
            message: String::new(),
            process: None,
            ancestors: vec![],
            event: serde_json::json!({}),
            context: vec![],
            prev_hash: String::new(),
            hash: String::new(),
        }
    }

    /// Report an increase in the kernel's dropped-event counter (spec §4, §12).
    pub fn check_drops(&mut self, k: &mut dyn Kernel) {
        let Ok(now) = k.drops() else { return };
        if now <= self.last_drops {
            return;
        }
        let lost = now - self.last_drops;
        self.last_drops = now;
        let mut a = self.blank_alert("sensor-overflow", "high", "alerted");
        a.ts = Self::format_ts(k.wall_ms());
        a.message = format!("{lost} events dropped by a full ring buffer");
        a.event = serde_json::json!({"on": "sensor", "dropped": lost, "total": now});
        self.raise(a);
    }

    /// Build the alert for one decision on one resolved event.
    fn alert_for(&self, r: &Resolved, d: &Decision, outcome: Outcome, now_ms: u64) -> Alert {
        let severity = if outcome == Outcome::Failed {
            // A failed action is critical regardless of the rule (spec §6).
            "critical".to_string()
        } else {
            d.severity.clone()
        };
        Alert {
            id: ulid::Ulid::new().to_string(),
            ts: Self::format_ts(now_ms),
            rule: d.rule_id.clone(),
            severity,
            action: match d.action {
                Action::Alert => "alert",
                Action::Deny => "deny",
                Action::Freeze => "freeze",
                Action::Kill => "kill",
            }
            .to_string(),
            mode: match d.mode {
                sentinel_common::event::Mode::Enforce => "enforce",
                sentinel_common::event::Mode::Audit => "audit",
            }
            .to_string(),
            outcome: outcome.as_str().to_string(),
            message: String::new(),
            process: self.proc_ref(r.pid),
            ancestors: r
                .ancestor_pids
                .iter()
                .filter_map(|p| self.proc_ref(*p))
                .collect(),
            event: r.detail.clone(),
            context: self.table.context_for(r.pid, now_ms),
            prev_hash: String::new(),
            hash: String::new(),
        }
    }

    /// The whole hot path for one raw event.
    pub fn on_event(&mut self, ev: &RawEvent, k: &mut dyn Kernel) {
        let now_ms = k.wall_ms();

        // 1. Table upkeep.
        let kind = EventKind::from_u8(ev.hdr.kind);
        match kind {
            Some(EventKind::Exec) => {
                let src = &*self.procs;
                self.table.on_exec(ev.hdr.pid, src);
            }
            Some(EventKind::Fork) => {
                // SAFETY: the kernel wrote the proc_ variant for a fork.
                let p = unsafe { ev.payload.proc_ };
                self.table.on_fork(ev.hdr.pid, p.child_pid);
            }
            _ => {}
        }

        // 2. Resolve.
        let r = {
            let src = &*self.procs;
            Resolved::from_raw(ev, &self.table, src, &self.binds)
        };

        // 3. Context ring.
        self.table.record_context(r.pid, r.detail.clone(), now_ms);

        // 4. Detectors.
        if r.kind == EventKind::Connect {
            if let Some((dest, port)) = r.net.clone() {
                if let Some(hit) = self.detectors.on_connect(&r.exe, &dest, port, now_ms) {
                    self.raise_detector(hit, &r, now_ms, k);
                }
            }
        }

        // 5. Decisions.
        let decisions = self.rules.decide(&r, &self.policy, now_ms);
        for d in decisions {
            self.apply(&r, d, now_ms, k);
        }

        // 6. An exit is processed last, so the alert above still saw the pid.
        if kind == Some(EventKind::Exit) {
            self.table.on_exit(ev.hdr.pid);
        }
    }

    /// Run a decision's action, then store and emit its alert.
    fn apply(&mut self, r: &Resolved, d: Decision, now_ms: u64, k: &mut dyn Kernel) {
        let mut outcome = d.outcome;
        let mut message = String::new();
        let mut quarantine = None;

        if d.acts() {
            if self.brake.trip(now_ms) {
                outcome = Outcome::Braked;
                if self.brake.just_engaged() {
                    let mut a = self.blank_alert("storm-brake", "critical", "alerted");
                    a.ts = Self::format_ts(now_ms);
                    a.message = format!(
                        "storm brake engaged: more than {} automatic actions in a minute",
                        self.config.storm_brake
                    );
                    self.raise(a);
                }
            } else {
                // The alert id names the quarantine cgroup, so it is minted here.
                let id = ulid::Ulid::new().to_string();
                let kill = outcome == Outcome::Killed;
                match action::freeze(k, &self.table, &id, r.pid, kill) {
                    Ok(q) => quarantine = Some((id, q)),
                    Err(e) => {
                        outcome = Outcome::Failed;
                        message = e.to_string();
                    }
                }
            }
        }

        let mut a = self.alert_for(r, &d, outcome, now_ms);
        a.message = message;
        if let Some((id, _)) = &quarantine {
            // Keep the alert id and the cgroup name in step.
            a.id = id.clone();
        }
        let id = self.raise(a);
        if let Some((_, q)) = quarantine {
            self.quarantines.insert(q);
        }
        let _ = id;
    }

    /// A detector hit becomes an alert the same way a rule hit does.
    fn raise_detector(
        &mut self,
        hit: crate::engine::DetectorHit,
        r: &Resolved,
        now_ms: u64,
        k: &mut dyn Kernel,
    ) {
        let mut outcome = match hit.action {
            Action::Alert => Outcome::Alerted,
            Action::Freeze => Outcome::Frozen,
            Action::Kill => Outcome::Killed,
            // `config::validate` rejects deny for a detector (§5.4).
            Action::Deny => Outcome::Alerted,
        };
        let mut message = String::new();
        let mut quarantine = None;

        if matches!(outcome, Outcome::Frozen | Outcome::Killed) {
            if self.policy.is_protected(r.pid, &r.unit) {
                outcome = Outcome::Suppressed;
            } else if self.brake.trip(now_ms) {
                outcome = Outcome::Braked;
            } else {
                let id = ulid::Ulid::new().to_string();
                match action::freeze(k, &self.table, &id, r.pid, outcome == Outcome::Killed) {
                    Ok(q) => quarantine = Some((id, q)),
                    Err(e) => {
                        outcome = Outcome::Failed;
                        message = e.to_string();
                    }
                }
            }
        }

        let mut a = self.blank_alert(hit.rule_id, &hit.severity, outcome.as_str());
        a.ts = Self::format_ts(now_ms);
        a.action = match hit.action {
            Action::Alert => "alert",
            Action::Deny => "deny",
            Action::Freeze => "freeze",
            Action::Kill => "kill",
        }
        .to_string();
        a.message = message;
        a.event = hit.event;
        a.process = self.proc_ref(r.pid);
        a.ancestors = r
            .ancestor_pids
            .iter()
            .filter_map(|p| self.proc_ref(*p))
            .collect();
        a.context = self.table.context_for(r.pid, now_ms);
        if let Some((id, _)) = &quarantine {
            a.id = id.clone();
        }
        self.raise(a);
        if let Some((_, q)) = quarantine {
            self.quarantines.insert(q);
        }
    }
}
```

Add `pub mod daemon;` to `lib.rs`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd sentinel && cargo test -p sentineld daemon`
Expected: 7 passed.

Two things commonly need a nudge here:

- `Daemon::raise` borrows `self.store` and `self.sink` in one body. If the borrow checker objects, take the alert by value and split the store call into a local `let result = self.store.append(...)` before touching `self.sink`.
- `format_ts` is exercised indirectly. Add a direct test if the first run disagrees with your expectation:

```rust
    #[test]
    fn timestamps_are_rfc3339_utc() {
        assert_eq!(
            Daemon::format_ts(1_763_000_571_123),
            "2025-11-13T04:62:51.123Z".to_string(),
            "replace this expectation with the value the first run prints"
        );
    }
```

Run it once, read the actual value out of the failure message, check it by hand against `date -u -d @1763000571`, and write the correct expectation in. Do not accept a value you have not checked against `date`.

- [ ] **Step 5: Commit**

```bash
git add sentinel/crates/sentineld/src/daemon.rs sentinel/crates/sentineld/src/kernel.rs sentinel/crates/sentineld/src/lib.rs
git commit -m "feat(sentineld): the daemon hot path - dispatch, act, alert, emit"
```

---

## Task 14: Status, the state file and readiness

**Files:**
- Create: `sentinel/crates/sentineld/src/status.rs`
- Modify: `sentinel/crates/sentineld/src/lib.rs` (add `pub mod status;`)

Spec §10.1 `Status`: version, programs attached, heartbeat age, lockdown state and counts, rules loaded by kind and mode, loaded generation, ring-buffer drops, quarantines. Spec §11.5: `sentineld` writes `ok` or `degraded` into `/run/aios-sentinel/state` once ready, and the unit is `Type=notify`, so readiness is also sent to systemd. Spec §12: degraded means the LSM programs did not attach — observe only, no deny, no self-guard, no lockdown.

- [ ] **Step 1: Write the failing tests**

Create `sentinel/crates/sentineld/src/status.rs` with the tests first:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_state_file_holds_ok_or_degraded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state");
        write_state(&path, Health::Ok).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "ok");
        write_state(&path, Health::Degraded).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "degraded");
    }

    #[test]
    fn the_state_file_directory_is_created() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/run/state");
        write_state(&path, Health::Ok).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn heartbeat_age_is_the_gap_in_milliseconds() {
        assert_eq!(heartbeat_age_ms(5_000_000_000, 3_000_000_000), 2_000);
        assert_eq!(
            heartbeat_age_ms(1_000, 9_000),
            0,
            "a heartbeat from the future reads as fresh, never as a huge gap"
        );
    }

    #[test]
    fn lockdown_is_active_only_past_the_threshold() {
        // 5 s threshold, 2 s gap.
        assert!(!lockdown_active(7_000_000_000, 5_000_000_000, 5_000_000_000));
        // 6 s gap.
        assert!(lockdown_active(11_000_000_000, 5_000_000_000, 5_000_000_000));
        // Never started.
        assert!(!lockdown_active(11_000_000_000, 0, 5_000_000_000));
    }

    #[test]
    fn status_serialises_every_field_the_spec_names() {
        let s = Status {
            version: "0.1.0".to_string(),
            health: Health::Degraded,
            programs: vec!["exec".to_string(), "connect".to_string()],
            heartbeat_age_ms: 400,
            lockdown_active: false,
            lockdown_counts: vec![0, 0, 0, 0, 0, 0, 0, 3],
            kernel_rules: 4,
            user_rules: 6,
            audit_rules: 1,
            generation: "gen-7".to_string(),
            drops: 0,
            quarantines: 2,
            dns_monitor: false,
            store_error: Some("disk full".to_string()),
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["health"], "degraded");
        assert_eq!(v["programs"][0], "exec");
        assert_eq!(v["lockdownCounts"][7], 3);
        assert_eq!(v["kernelRules"], 4);
        assert_eq!(v["userRules"], 6);
        assert_eq!(v["auditRules"], 1);
        assert_eq!(v["heartbeatAgeMs"], 400);
        assert_eq!(v["dnsMonitor"], false);
        assert_eq!(v["storeError"], "disk full");
    }

    #[test]
    fn notify_payload_is_the_systemd_ready_line() {
        assert_eq!(ready_payload(), b"READY=1\n".to_vec());
    }

    #[test]
    fn an_abstract_notify_socket_is_translated() {
        assert_eq!(notify_addr("@/run/x"), Some("\0/run/x".to_string()));
        assert_eq!(notify_addr("/run/x"), Some("/run/x".to_string()));
        assert_eq!(notify_addr(""), None);
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd sentinel && cargo test -p sentineld status`
Expected: FAIL to compile — `cannot find function write_state`.

- [ ] **Step 3: Write the implementation**

Insert above the `tests` module in `status.rs`:

```rust
//! The `Status` snapshot, `/run/aios-sentinel/state` and systemd readiness
//! (spec §10.1, §11.5, §12).

use std::path::Path;

use serde::Serialize;

/// Where the health check reads the daemon's own verdict (spec §11.5).
pub const STATE_PATH: &str = "/run/aios-sentinel/state";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Health {
    Ok,
    Degraded,
}

impl Health {
    pub fn as_str(self) -> &'static str {
        match self {
            Health::Ok => "ok",
            Health::Degraded => "degraded",
        }
    }
}

/// The `Status` reply (spec §10.1). Field names are camelCase, as varlink
/// interfaces conventionally use.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub version: String,
    pub health: Health,
    pub programs: Vec<String>,
    pub heartbeat_age_ms: u64,
    pub lockdown_active: bool,
    pub lockdown_counts: Vec<u64>,
    pub kernel_rules: usize,
    pub user_rules: usize,
    pub audit_rules: usize,
    pub generation: String,
    pub drops: u64,
    pub quarantines: usize,
    pub dns_monitor: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub store_error: Option<String>,
}

/// Write `ok` or `degraded` where `aios-health.sh` looks (spec §11.5).
pub fn write_state(path: &Path, h: Health) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, h.as_str())
}

/// Milliseconds since the last heartbeat. A heartbeat at or after `now`
/// reads as 0, never as an enormous gap from wrapping.
pub fn heartbeat_age_ms(now_ns: u64, beat_ns: u64) -> u64 {
    now_ns.saturating_sub(beat_ns) / 1_000_000
}

/// The same test the kernel hooks make (spec §8.3). A heartbeat of 0 means
/// "not started", and there is no lockdown before the first one.
pub fn lockdown_active(now_ns: u64, beat_ns: u64, after_ns: u64) -> bool {
    beat_ns != 0 && now_ns.saturating_sub(beat_ns) > after_ns
}

/// The `sd_notify` readiness datagram.
pub fn ready_payload() -> Vec<u8> {
    b"READY=1\n".to_vec()
}

/// `NOTIFY_SOCKET` as a connectable path: a leading `@` means the abstract
/// namespace, which is a leading NUL on the wire.
pub fn notify_addr(raw: &str) -> Option<String> {
    if raw.is_empty() {
        return None;
    }
    Some(match raw.strip_prefix('@') {
        Some(rest) => format!("\0{rest}"),
        None => raw.to_string(),
    })
}

/// Tell systemd the unit is ready (`Type=notify`, spec §11.4). Silent when
/// `NOTIFY_SOCKET` is unset, which is the case outside systemd.
pub fn notify_ready() {
    let Ok(raw) = std::env::var("NOTIFY_SOCKET") else {
        return;
    };
    let Some(addr) = notify_addr(&raw) else {
        return;
    };
    if let Ok(sock) = std::os::unix::net::UnixDatagram::unbound() {
        let _ = sock.send_to(&ready_payload(), &addr);
    }
}
```

Add `pub mod status;` to `lib.rs`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd sentinel && cargo test -p sentineld status`
Expected: 7 passed.

`UnixDatagram::send_to` with a path containing a NUL will not accept a `&str` on every libc; if the abstract-socket send does not compile, build a `std::os::unix::net::SocketAddr` with `SocketAddr::from_abstract_name` (Rust 1.70+) and use `send_to_addr`. Keep `notify_addr` and its test either way — it documents the translation.

- [ ] **Step 5: Commit**

```bash
git add sentinel/crates/sentineld/src/status.rs sentinel/crates/sentineld/src/lib.rs
git commit -m "feat(sentineld): Status snapshot, state file and systemd readiness"
```

---

## Task 15: Reporting the lockdown gap at start

**Files:**
- Create: `sentinel/crates/sentineld/src/lockdown.rs`
- Modify: `sentinel/crates/sentineld/src/lib.rs` (add `pub mod lockdown;`)

Spec §8.3: "Lockdown denials are counted per hook in a pinned map. The next `sentineld` reports the gap's length and the counts as a critical alert, then resumes the heartbeat, which ends the lockdown." So at start, **before** writing the first heartbeat, the daemon reads `HEARTBEAT[0]` and `LOCKDOWN_COUNTS`; if the heartbeat is non-zero and stale, the previous instance died and the kernel was locked down for the gap.

- [ ] **Step 1: Write the failing tests**

Create `sentinel/crates/sentineld/src/lockdown.rs` with the tests first:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::FakeKernel;

    #[test]
    fn a_fresh_boot_reports_nothing() {
        let mut k = FakeKernel::default();
        // HEARTBEAT[0] == 0 means nothing was ever loaded (spec §8.3).
        k.advance_ms(10_000);
        assert!(report(&mut k, 5_000_000_000).is_none());
    }

    #[test]
    fn a_restart_inside_the_threshold_reports_nothing() {
        let mut k = FakeKernel::default();
        k.advance_ms(10_000);
        k.heartbeat(9_000_000_000).unwrap();
        assert!(
            report(&mut k, 5_000_000_000).is_none(),
            "a 1 s gap is under the 5 s threshold"
        );
    }

    #[test]
    fn a_stale_heartbeat_reports_the_gap_and_the_counts() {
        let mut k = FakeKernel::default();
        k.advance_ms(30_000);
        k.heartbeat(10_000_000_000).unwrap();
        k.lockdown = [4, 0, 0, 0, 0, 0, 0, 1];

        let g = report(&mut k, 5_000_000_000).expect("a 20 s gap is reported");
        assert_eq!(g.gap_ms, 20_000);
        assert_eq!(g.counts[0], 4);
        assert_eq!(g.counts[7], 1);
        assert_eq!(g.total(), 5);
    }

    #[test]
    fn a_gap_with_no_denials_is_still_reported() {
        let mut k = FakeKernel::default();
        k.advance_ms(30_000);
        k.heartbeat(10_000_000_000).unwrap();
        let g = report(&mut k, 5_000_000_000).expect("the gap itself is the news");
        assert_eq!(g.total(), 0);
    }

    #[test]
    fn the_message_names_the_gap_and_the_busiest_hooks() {
        let g = Gap {
            gap_ms: 20_000,
            counts: [4, 0, 0, 0, 0, 0, 0, 1],
        };
        let m = g.message();
        assert!(m.contains("20.0 s"), "message was {m}");
        assert!(m.contains("exec"), "the per-hook names appear: {m}");
        assert!(m.contains('4'));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd sentinel && cargo test -p sentineld lockdown`
Expected: FAIL to compile — `cannot find function report`.

- [ ] **Step 3: Write the implementation**

Insert above the `tests` module in `lockdown.rs`:

```rust
//! Reading what the kernel did while no daemon was running (spec §8.3).

use crate::kernel::{Kernel, NHOOKS};

/// The hooks `LOCKDOWN_COUNTS` indexes, in slot order. Slot 7 is the probe
/// slot the S2 heartbeat self-test uses.
pub const HOOK_NAMES: [&str; NHOOKS] = [
    "exec",
    "connect",
    "sendmsg",
    "listen",
    "open",
    "ptrace",
    "bpf",
    "probe",
];

/// A gap during which the kernel side was locked down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gap {
    pub gap_ms: u64,
    pub counts: [u64; NHOOKS],
}

impl Gap {
    pub fn total(&self) -> u64 {
        self.counts.iter().sum()
    }

    /// The critical alert's message (spec §8.3).
    pub fn message(&self) -> String {
        let mut per_hook: Vec<String> = HOOK_NAMES
            .iter()
            .zip(self.counts.iter())
            .filter(|(_, c)| **c > 0)
            .map(|(n, c)| format!("{n} {c}"))
            .collect();
        if per_hook.is_empty() {
            per_hook.push("no denials".to_string());
        }
        format!(
            "lockdown was active for {:.1} s while no daemon was running ({})",
            self.gap_ms as f64 / 1000.0,
            per_hook.join(", ")
        )
    }

    pub fn event(&self) -> serde_json::Value {
        let counts: serde_json::Map<String, serde_json::Value> = HOOK_NAMES
            .iter()
            .zip(self.counts.iter())
            .map(|(n, c)| ((*n).to_string(), (*c).into()))
            .collect();
        serde_json::json!({
            "on": "lockdown",
            "gapMs": self.gap_ms,
            "total": self.total(),
            "counts": counts,
        })
    }
}

/// Read the heartbeat and the counters. Returns a gap only when a previous
/// instance left a stale heartbeat — a fresh boot has `HEARTBEAT[0] == 0` and
/// never locked anything down.
///
/// Call this **before** writing the first heartbeat of this instance.
pub fn report(k: &mut dyn Kernel, lockdown_after_ns: u64) -> Option<Gap> {
    let beat = k.heartbeat_value().ok()?;
    if beat == 0 {
        return None;
    }
    let now = k.monotonic_ns();
    let gap_ns = now.saturating_sub(beat);
    if gap_ns <= lockdown_after_ns {
        return None;
    }
    Some(Gap {
        gap_ms: gap_ns / 1_000_000,
        counts: k.lockdown_counts().ok()?,
    })
}
```

Add `pub mod lockdown;` to `lib.rs`.

Confirm `HOOK_NAMES` against the kernel side before trusting the labels: read the `NHOOKS` slot constants in `sentinel/crates/sentinel-ebpf/src/` and reorder to match. The S2 README records that slot 7 is what `trigger_and_read` reads in the heartbeat self-test, which pins that end of the list.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd sentinel && cargo test -p sentineld lockdown`
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add sentinel/crates/sentineld/src/lockdown.rs sentinel/crates/sentineld/src/lib.rs
git commit -m "feat(sentineld): report the lockdown gap left by a previous instance"
```

---

## Task 16: The varlink transport and the read methods

**Files:**
- Create: `sentinel/crates/sentineld/src/varlink.rs`
- Modify: `sentinel/crates/sentineld/src/lib.rs` (add `pub mod varlink;`)

Spec §10.1 and amendment 7. Varlink is JSON objects separated by NUL bytes over a Unix socket:

- call: `{"method":"io.aios.Sentinel.Status","parameters":{…}}\0`, optionally with `"more":true`
- reply: `{"parameters":{…}}\0`; a streaming reply sets `"continues":true` on every message but the last
- error: `{"error":"io.aios.Sentinel.PermissionDenied","parameters":{…}}\0`

Access comes from `SO_PEERCRED`: root and the `wheel` group may read, only root may change anything.

This task does the framing, the access check and the read-only methods: `Status`, `ListAlerts`, `GetAlert`, `ListQuarantine`, `VerifyChain`. Task 17 adds the root-only methods and `WatchAlerts`.

- [ ] **Step 1: Write the failing tests**

Create `sentinel/crates/sentineld/src/varlink.rs` with the tests first:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_split_on_nul() {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(br#"{"method":"A"}"#);
        buf.push(0);
        buf.extend_from_slice(br#"{"method":"B"}"#);
        buf.push(0);
        buf.extend_from_slice(br#"{"method":"partial"#);
        let (frames, rest) = split_frames(&buf);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0], br#"{"method":"A"}"#);
        assert_eq!(rest, br#"{"method":"partial"#);
    }

    #[test]
    fn a_reply_is_nul_terminated_json() {
        let out = encode_reply(&serde_json::json!({"ok": true}), false);
        assert_eq!(out.last(), Some(&0u8));
        let text = std::str::from_utf8(&out[..out.len() - 1]).unwrap();
        let v: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(v["parameters"]["ok"], true);
        assert!(v.get("continues").is_none());
    }

    #[test]
    fn a_streaming_reply_sets_continues() {
        let out = encode_reply(&serde_json::json!({}), true);
        let text = std::str::from_utf8(&out[..out.len() - 1]).unwrap();
        let v: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(v["continues"], true);
    }

    #[test]
    fn an_error_names_the_interface() {
        let out = encode_error("PermissionDenied", serde_json::json!({"method": "Release"}));
        let text = std::str::from_utf8(&out[..out.len() - 1]).unwrap();
        let v: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(v["error"], "io.aios.Sentinel.PermissionDenied");
        assert_eq!(v["parameters"]["method"], "Release");
    }

    #[test]
    fn the_method_name_is_stripped_of_the_interface_prefix() {
        assert_eq!(short_method("io.aios.Sentinel.Status"), Some("Status"));
        assert_eq!(short_method("org.varlink.service.GetInfo"), None);
        assert_eq!(short_method("Status"), None);
    }

    #[test]
    fn access_follows_peer_credentials() {
        let root = Peer { uid: 0, gid: 0, wheel: false };
        let wheel = Peer { uid: 1000, gid: 998, wheel: true };
        let user = Peer { uid: 1000, gid: 1000, wheel: false };
        assert!(root.may_read() && root.may_write());
        assert!(wheel.may_read() && !wheel.may_write());
        assert!(!user.may_read() && !user.may_write());
    }

    #[test]
    fn wheel_membership_is_read_from_the_group_file() {
        let text = "root:x:0:\nwheel:x:998:alice,bob\nusers:x:100:\n";
        assert_eq!(wheel_gid(text), Some(998));
        assert!(wheel_members(text).contains(&"alice".to_string()));
        assert!(wheel_members(text).contains(&"bob".to_string()));
        assert_eq!(wheel_gid("root:x:0:\n"), None);
    }

    #[test]
    fn an_unknown_method_is_an_interface_error() {
        let out = dispatch_read(
            "Nonsense",
            &serde_json::json!({}),
            &ReadView::default(),
        );
        let v = decode(&out);
        assert_eq!(v["error"], "io.aios.Sentinel.MethodNotFound");
    }

    fn decode(out: &[u8]) -> serde_json::Value {
        serde_json::from_slice(&out[..out.len() - 1]).unwrap()
    }

    fn view_with_alerts() -> ReadView {
        let a = |id: &str, sev: &str, ts: &str| crate::alert::Alert {
            id: id.to_string(),
            ts: ts.to_string(),
            rule: "r".to_string(),
            severity: sev.to_string(),
            action: "alert".to_string(),
            mode: "enforce".to_string(),
            outcome: "alerted".to_string(),
            message: String::new(),
            process: None,
            ancestors: vec![],
            event: serde_json::json!({}),
            context: vec![],
            prev_hash: crate::alert::GENESIS.to_string(),
            hash: String::new(),
        };
        ReadView {
            alerts: vec![
                a("A1", "low", "2026-11-12T10:00:00.000Z"),
                a("A2", "high", "2026-11-12T11:00:00.000Z"),
                a("A3", "critical", "2026-11-12T12:00:00.000Z"),
            ],
            ..ReadView::default()
        }
    }

    #[test]
    fn list_alerts_filters_by_severity() {
        let out = dispatch_read(
            "ListAlerts",
            &serde_json::json!({"minSeverity": "high"}),
            &view_with_alerts(),
        );
        let v = decode(&out);
        let ids: Vec<&str> = v["parameters"]["alerts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, vec!["A2", "A3"]);
    }

    #[test]
    fn list_alerts_honours_since_and_limit() {
        let out = dispatch_read(
            "ListAlerts",
            &serde_json::json!({"since": "2026-11-12T10:30:00.000Z"}),
            &view_with_alerts(),
        );
        assert_eq!(decode(&out)["parameters"]["alerts"].as_array().unwrap().len(), 2);

        let out = dispatch_read(
            "ListAlerts",
            &serde_json::json!({"limit": 1}),
            &view_with_alerts(),
        );
        let v = decode(&out);
        let arr = v["parameters"]["alerts"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["id"], "A3", "a limit keeps the newest");
    }

    #[test]
    fn get_alert_finds_one_or_errors() {
        let out = dispatch_read("GetAlert", &serde_json::json!({"id": "A2"}), &view_with_alerts());
        assert_eq!(decode(&out)["parameters"]["alert"]["id"], "A2");

        let out = dispatch_read("GetAlert", &serde_json::json!({"id": "ZZ"}), &view_with_alerts());
        assert_eq!(decode(&out)["error"], "io.aios.Sentinel.NoSuchAlert");
    }

    #[test]
    fn verify_chain_reports_the_count() {
        let mut v = ReadView::default();
        v.chain = Ok(12);
        let out = dispatch_read("VerifyChain", &serde_json::json!({}), &v);
        let r = decode(&out);
        assert_eq!(r["parameters"]["ok"], true);
        assert_eq!(r["parameters"]["records"], 12);

        let mut v = ReadView::default();
        v.chain = Err("record 3 hash mismatch".to_string());
        let out = dispatch_read("VerifyChain", &serde_json::json!({}), &v);
        let r = decode(&out);
        assert_eq!(r["parameters"]["ok"], false);
        assert_eq!(r["parameters"]["error"], "record 3 hash mismatch");
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd sentinel && cargo test -p sentineld varlink`
Expected: FAIL to compile — `cannot find function split_frames`.

- [ ] **Step 3: Write the implementation**

Insert above the `tests` module in `varlink.rs`:

```rust
//! The `io.aios.Sentinel` varlink service: framing, access control and the
//! read-only methods (spec §10.1, amendment 7).

use crate::alert::Alert;

/// The interface name every method and error is prefixed with.
pub const INTERFACE: &str = "io.aios.Sentinel";
/// The socket the CLI and the Cockpit connect to (spec §10.1).
pub const SOCKET_PATH: &str = "/run/aios-sentinel/io.aios.Sentinel";

/// Split a read buffer into complete NUL-terminated frames plus the remainder.
pub fn split_frames(buf: &[u8]) -> (Vec<Vec<u8>>, Vec<u8>) {
    let mut frames = Vec::new();
    let mut start = 0;
    for (i, b) in buf.iter().enumerate() {
        if *b == 0 {
            frames.push(buf[start..i].to_vec());
            start = i + 1;
        }
    }
    (frames, buf[start..].to_vec())
}

/// `{"parameters": …}` plus the NUL, with `continues` on a streaming reply.
pub fn encode_reply(parameters: &serde_json::Value, continues: bool) -> Vec<u8> {
    let mut v = serde_json::json!({ "parameters": parameters });
    if continues {
        v["continues"] = true.into();
    }
    let mut out = serde_json::to_vec(&v).unwrap_or_default();
    out.push(0);
    out
}

/// `{"error": "io.aios.Sentinel.<name>", "parameters": …}` plus the NUL.
pub fn encode_error(name: &str, parameters: serde_json::Value) -> Vec<u8> {
    let v = serde_json::json!({
        "error": format!("{INTERFACE}.{name}"),
        "parameters": parameters,
    });
    let mut out = serde_json::to_vec(&v).unwrap_or_default();
    out.push(0);
    out
}

/// The method name without the interface prefix, or `None` for another interface.
pub fn short_method(full: &str) -> Option<&str> {
    full.strip_prefix(INTERFACE)
        .and_then(|r| r.strip_prefix('.'))
        .filter(|m| !m.is_empty() && !m.contains('.'))
}

/// The connected peer, from `SO_PEERCRED` (spec §10.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peer {
    pub uid: u32,
    pub gid: u32,
    pub wheel: bool,
}

impl Peer {
    /// Root and `wheel` may read.
    pub fn may_read(&self) -> bool {
        self.uid == 0 || self.wheel
    }
    /// Only root may change anything.
    pub fn may_write(&self) -> bool {
        self.uid == 0
    }
}

/// The gid of the `wheel` line of a `/etc/group` text.
pub fn wheel_gid(group_file: &str) -> Option<u32> {
    group_file.lines().find_map(|l| {
        let mut f = l.split(':');
        (f.next()? == "wheel").then(|| f.nth(1)?.parse().ok())?
    })
}

/// The member names on the `wheel` line.
pub fn wheel_members(group_file: &str) -> Vec<String> {
    group_file
        .lines()
        .find(|l| l.starts_with("wheel:"))
        .and_then(|l| l.split(':').nth(3))
        .map(|m| {
            m.split(',')
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// Read `SO_PEERCRED` off a connected stream and decide `wheel` membership.
pub fn peer_of(stream: &std::os::unix::net::UnixStream) -> std::io::Result<Peer> {
    use std::os::fd::AsRawFd;
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: cred and len are valid out-pointers of the documented types.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let group_file = std::fs::read_to_string("/etc/group").unwrap_or_default();
    let wheel = match wheel_gid(&group_file) {
        Some(g) => cred.gid as u32 == g || {
            // Secondary membership: match the peer's login name.
            let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
            let name = passwd.lines().find_map(|l| {
                let mut f = l.split(':');
                let n = f.next()?;
                let u: u32 = f.nth(1)?.parse().ok()?;
                (u == cred.uid as u32).then(|| n.to_string())
            });
            name.is_some_and(|n| wheel_members(&group_file).contains(&n))
        },
        None => false,
    };
    Ok(Peer {
        uid: cred.uid as u32,
        gid: cred.gid as u32,
        wheel,
    })
}

/// A read-only snapshot the dispatcher works from, so the methods are pure
/// and testable without a daemon.
#[derive(Default)]
pub struct ReadView {
    pub status: Option<crate::status::Status>,
    pub alerts: Vec<Alert>,
    pub quarantines: Vec<serde_json::Value>,
    /// `Ok(record count)` or `Err(message)`.
    pub chain: Result<usize, String>,
}

impl Default for Result<usize, String> {
    // placeholder: see the note below
    fn default() -> Self {
        Ok(0)
    }
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "info" => 0,
        "low" => 1,
        "medium" => 2,
        "high" => 3,
        "critical" => 4,
        _ => 0,
    }
}

/// Handle one read-only method. Returns the encoded reply or error.
pub fn dispatch_read(method: &str, params: &serde_json::Value, v: &ReadView) -> Vec<u8> {
    match method {
        "Status" => match &v.status {
            Some(s) => encode_reply(
                &serde_json::json!({ "status": serde_json::to_value(s).unwrap_or_default() }),
                false,
            ),
            None => encode_error("NotReady", serde_json::json!({})),
        },
        "ListAlerts" => {
            let min = params
                .get("minSeverity")
                .and_then(|s| s.as_str())
                .map(severity_rank)
                .unwrap_or(0);
            let since = params.get("since").and_then(|s| s.as_str()).unwrap_or("");
            let mut out: Vec<&Alert> = v
                .alerts
                .iter()
                .filter(|a| severity_rank(&a.severity) >= min)
                .filter(|a| since.is_empty() || a.ts.as_str() >= since)
                .collect();
            if let Some(limit) = params.get("limit").and_then(|l| l.as_u64()) {
                let limit = limit as usize;
                if out.len() > limit {
                    // Keep the newest.
                    out.drain(..out.len() - limit);
                }
            }
            encode_reply(&serde_json::json!({ "alerts": out }), false)
        }
        "GetAlert" => {
            let id = params.get("id").and_then(|i| i.as_str()).unwrap_or("");
            match v.alerts.iter().find(|a| a.id == id) {
                Some(a) => encode_reply(&serde_json::json!({ "alert": a }), false),
                None => encode_error("NoSuchAlert", serde_json::json!({ "id": id })),
            }
        }
        "ListQuarantine" => {
            encode_reply(&serde_json::json!({ "quarantines": v.quarantines }), false)
        }
        "VerifyChain" => match &v.chain {
            Ok(n) => encode_reply(&serde_json::json!({"ok": true, "records": n}), false),
            Err(e) => encode_reply(&serde_json::json!({"ok": false, "error": e}), false),
        },
        other => encode_error("MethodNotFound", serde_json::json!({ "method": other })),
    }
}
```

**Remove the bogus `impl Default for Result<usize, String>`** — that is an orphan impl and will not compile. Instead write `ReadView`'s `Default` by hand:

```rust
impl Default for ReadView {
    fn default() -> ReadView {
        ReadView {
            status: None,
            alerts: Vec::new(),
            quarantines: Vec::new(),
            chain: Ok(0),
        }
    }
}
```

and drop `#[derive(Default)]` from the struct.

Add `pub mod varlink;` to `lib.rs`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd sentinel && cargo test -p sentineld varlink`
Expected: 13 passed.

`wheel_gid`'s closure uses `?` inside a `then` closure, which does not type-check as written. If the compiler objects, rewrite it plainly:

```rust
pub fn wheel_gid(group_file: &str) -> Option<u32> {
    for l in group_file.lines() {
        let f: Vec<&str> = l.split(':').collect();
        if f.len() >= 3 && f[0] == "wheel" {
            return f[2].parse().ok();
        }
    }
    None
}
```

- [ ] **Step 5: Commit**

```bash
git add sentinel/crates/sentineld/src/varlink.rs sentinel/crates/sentineld/src/lib.rs
git commit -m "feat(sentineld): varlink framing, peer credentials and the read methods"
```

---

## Task 17: The root-only methods, `WatchAlerts` and the server loop

**Files:**
- Modify: `sentinel/crates/sentineld/src/varlink.rs`

Spec §10.1: `Release(id)`, `Kill(id)` and `LoadGeneration(gen, files)` need root; `WatchAlerts` streams new alerts with `more: true`. Spec §11.3: `LoadGeneration` validates the files, and if valid swaps the kernel tables and the user rules atomically, records the generation and raises a critical alert naming the diff; if invalid it keeps the current rules, alerts, and returns the error.

- [ ] **Step 1: Write the failing tests**

Append inside the `tests` module in `varlink.rs`:

```rust
    #[test]
    fn a_non_root_peer_is_refused_a_write_method() {
        let wheel = Peer { uid: 1000, gid: 998, wheel: true };
        assert!(requires_root("Release"));
        assert!(requires_root("Kill"));
        assert!(requires_root("LoadGeneration"));
        assert!(!requires_root("Status"));
        assert!(!wheel.may_write());
    }

    #[test]
    fn a_peer_with_no_access_is_refused_everything() {
        let user = Peer { uid: 1000, gid: 1000, wheel: false };
        let out = check_access("Status", &user).expect("an error is produced");
        assert_eq!(decode(&out)["error"], "io.aios.Sentinel.PermissionDenied");
        assert!(check_access("Status", &Peer { uid: 0, gid: 0, wheel: false }).is_none());
    }

    #[test]
    fn load_generation_rejects_an_invalid_rule_set_and_keeps_the_old_one() {
        let out = load_generation_result(Err(vec![
            "default.toml: rule x: unknown predicate `nope`".to_string(),
        ]));
        let v = decode(&out);
        assert_eq!(v["error"], "io.aios.Sentinel.InvalidRules");
        assert!(
            v["parameters"]["errors"][0]
                .as_str()
                .unwrap()
                .contains("unknown predicate"),
            "the validation error is returned verbatim: {v}"
        );
    }

    #[test]
    fn load_generation_reports_the_diff_on_success() {
        let out = load_generation_result(Ok(vec![
            "reverse-shell: action freeze -> kill".to_string(),
            "+ exec-shm".to_string(),
        ]));
        let v = decode(&out);
        assert_eq!(v["parameters"]["ok"], true);
        assert_eq!(v["parameters"]["changes"][1], "+ exec-shm");
    }

    #[test]
    fn watch_alerts_streams_each_alert_with_continues() {
        let a = |id: &str| crate::alert::Alert {
            id: id.to_string(),
            ts: String::new(),
            rule: "r".to_string(),
            severity: "high".to_string(),
            action: "alert".to_string(),
            mode: "enforce".to_string(),
            outcome: "alerted".to_string(),
            message: String::new(),
            process: None,
            ancestors: vec![],
            event: serde_json::json!({}),
            context: vec![],
            prev_hash: crate::alert::GENESIS.to_string(),
            hash: String::new(),
        };
        let out = encode_watch_item(&a("A1"));
        let v = decode(&out);
        assert_eq!(v["continues"], true, "a stream item always continues");
        assert_eq!(v["parameters"]["alert"]["id"], "A1");
    }

    #[test]
    fn watch_alerts_without_more_is_an_error() {
        let out = dispatch_watch_precheck(false);
        assert_eq!(
            decode(&out.unwrap())["error"],
            "io.aios.Sentinel.ExpectedMore",
            "WatchAlerts only makes sense with more: true"
        );
        assert!(dispatch_watch_precheck(true).is_none());
    }

    #[test]
    fn a_call_is_parsed_into_method_parameters_and_more() {
        let c = Call::parse(br#"{"method":"io.aios.Sentinel.GetAlert","parameters":{"id":"A1"},"more":true}"#)
            .expect("parses");
        assert_eq!(c.method, "io.aios.Sentinel.GetAlert");
        assert_eq!(c.parameters["id"], "A1");
        assert!(c.more);

        assert!(Call::parse(b"not json").is_none());
    }

    #[test]
    fn a_call_without_parameters_defaults_to_an_empty_object() {
        let c = Call::parse(br#"{"method":"io.aios.Sentinel.Status"}"#).unwrap();
        assert!(c.parameters.is_object());
        assert!(!c.more);
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd sentinel && cargo test -p sentineld varlink`
Expected: FAIL to compile — `cannot find function requires_root`.

- [ ] **Step 3: Write the implementation**

Append to `varlink.rs`, above the `tests` module:

```rust
/// One parsed call.
#[derive(Debug, Clone)]
pub struct Call {
    pub method: String,
    pub parameters: serde_json::Value,
    pub more: bool,
}

impl Call {
    pub fn parse(frame: &[u8]) -> Option<Call> {
        let v: serde_json::Value = serde_json::from_slice(frame).ok()?;
        Some(Call {
            method: v.get("method")?.as_str()?.to_string(),
            parameters: v
                .get("parameters")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({})),
            more: v.get("more").and_then(|m| m.as_bool()).unwrap_or(false),
        })
    }
}

/// Methods that change something, and so need root (spec §10.1).
pub fn requires_root(method: &str) -> bool {
    matches!(method, "Release" | "Kill" | "LoadGeneration")
}

/// `Some(error frame)` when the peer may not call this method.
pub fn check_access(method: &str, peer: &Peer) -> Option<Vec<u8>> {
    let allowed = if requires_root(method) {
        peer.may_write()
    } else {
        peer.may_read()
    };
    if allowed {
        None
    } else {
        Some(encode_error(
            "PermissionDenied",
            serde_json::json!({ "method": method, "uid": peer.uid }),
        ))
    }
}

/// One `WatchAlerts` stream item. Always `continues`, because the stream only
/// ends when the client disconnects.
pub fn encode_watch_item(a: &Alert) -> Vec<u8> {
    encode_reply(&serde_json::json!({ "alert": a }), true)
}

/// `WatchAlerts` requires `more: true`; returns the error frame when it is absent.
pub fn dispatch_watch_precheck(more: bool) -> Option<Vec<u8>> {
    if more {
        None
    } else {
        Some(encode_error("ExpectedMore", serde_json::json!({})))
    }
}

/// The reply for `LoadGeneration`: the change summary, or the validation errors.
pub fn load_generation_result(r: Result<Vec<String>, Vec<String>>) -> Vec<u8> {
    match r {
        Ok(changes) => encode_reply(&serde_json::json!({"ok": true, "changes": changes}), false),
        Err(errors) => encode_error("InvalidRules", serde_json::json!({ "errors": errors })),
    }
}

/// The reply for `Release` and `Kill`.
pub fn quarantine_result(r: Result<(), String>, id: &str) -> Vec<u8> {
    match r {
        Ok(()) => encode_reply(&serde_json::json!({"ok": true, "id": id}), false),
        Err(e) => encode_error("ActionFailed", serde_json::json!({"id": id, "error": e})),
    }
}

/// The reply when `Release` or `Kill` names a quarantine that is not there.
pub fn no_such_quarantine(id: &str) -> Vec<u8> {
    encode_error("NoSuchQuarantine", serde_json::json!({ "id": id }))
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd sentinel && cargo test -p sentineld varlink`
Expected: 21 passed (13 from Task 16 plus these 8).

- [ ] **Step 5: Write the server loop**

This part is wiring, not logic, so it has no unit test of its own; Task 22's `daemon` VM scenario exercises it end to end. Append to `varlink.rs`:

```rust
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};

/// What a connection thread needs to answer a call. The daemon is behind the
/// same mutex every other thread uses.
pub struct Service {
    pub daemon: Arc<Mutex<crate::daemon::Daemon>>,
    /// Hands each watcher a clone of every new alert.
    pub watchers: Arc<Mutex<Vec<Sender<Alert>>>>,
    /// The kernel handle, for `Release` and `Kill`.
    pub kernel: Arc<Mutex<Box<dyn crate::kernel::Kernel>>>,
    /// Where the rendered rule files live, for `LoadGeneration`.
    pub rules_dir: std::path::PathBuf,
}

/// Bind the socket, replacing a stale one from a previous instance. Mode 0660
/// so `wheel` can connect; the peer check is still what decides access.
pub fn bind(path: &std::path::Path) -> std::io::Result<UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // A leftover socket file from a killed instance would make bind fail.
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    let l = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(l)
}

/// Serve one connection until the peer goes away.
pub fn serve_conn(mut stream: UnixStream, svc: Arc<Service>) {
    let Ok(peer) = peer_of(&stream) else { return };
    let mut pending: Vec<u8> = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = match stream.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        pending.extend_from_slice(&buf[..n]);
        let (frames, rest) = split_frames(&pending);
        pending = rest;
        for frame in frames {
            let Some(call) = Call::parse(&frame) else {
                let _ = stream.write_all(&encode_error(
                    "InvalidParameter",
                    serde_json::json!({"frame": String::from_utf8_lossy(&frame)}),
                ));
                continue;
            };
            let Some(method) = short_method(&call.method).map(|m| m.to_string()) else {
                let _ = stream.write_all(&encode_error(
                    "InterfaceNotFound",
                    serde_json::json!({"method": call.method}),
                ));
                continue;
            };
            if let Some(denied) = check_access(&method, &peer) {
                let _ = stream.write_all(&denied);
                continue;
            }
            if method == "WatchAlerts" {
                if let Some(e) = dispatch_watch_precheck(call.more) {
                    let _ = stream.write_all(&e);
                    continue;
                }
                stream_alerts(&mut stream, &svc);
                return;
            }
            let reply = handle(&method, &call.parameters, &svc);
            if stream.write_all(&reply).is_err() {
                return;
            }
        }
    }
}

/// Register a watcher and forward alerts until the write fails.
fn stream_alerts(stream: &mut UnixStream, svc: &Arc<Service>) {
    let (tx, rx): (Sender<Alert>, Receiver<Alert>) = channel();
    if let Ok(mut w) = svc.watchers.lock() {
        w.push(tx);
    }
    while let Ok(a) = rx.recv() {
        if stream.write_all(&encode_watch_item(&a)).is_err() {
            return;
        }
    }
}

/// Answer one non-streaming method against the live daemon.
fn handle(method: &str, params: &serde_json::Value, svc: &Arc<Service>) -> Vec<u8> {
    use crate::action;

    let mut d = match svc.daemon.lock() {
        Ok(d) => d,
        Err(_) => return encode_error("Internal", serde_json::json!({"error": "state poisoned"})),
    };

    match method {
        "Release" | "Kill" => {
            let id = params.get("id").and_then(|i| i.as_str()).unwrap_or("");
            let Some(q) = d.quarantines.take(id) else {
                return no_such_quarantine(id);
            };
            let mut k = match svc.kernel.lock() {
                Ok(k) => k,
                Err(_) => {
                    d.quarantines.insert(q);
                    return encode_error("Internal", serde_json::json!({"error": "kernel busy"}));
                }
            };
            let r = if method == "Release" {
                action::release(k.as_mut().as_mut(), &q)
            } else {
                action::kill_quarantine(k.as_mut().as_mut(), &q)
            };
            match r {
                Ok(()) => {
                    if method == "Kill" {
                        // A killed quarantine stays listed until its cgroup is
                        // gone, so put it back with the flag set.
                        let mut q = q;
                        q.killed = true;
                        d.quarantines.insert(q);
                    }
                    quarantine_result(Ok(()), id)
                }
                Err(e) => {
                    d.quarantines.insert(q);
                    quarantine_result(Err(e.to_string()), id)
                }
            }
        }
        "LoadGeneration" => {
            let gen = params
                .get("gen")
                .and_then(|g| g.as_str())
                .unwrap_or("")
                .to_string();
            let dir = params
                .get("dir")
                .and_then(|p| p.as_str())
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| svc.rules_dir.clone());
            match d.load_generation(&gen, &dir, svc.kernel.clone()) {
                Ok(changes) => load_generation_result(Ok(changes)),
                Err(errors) => load_generation_result(Err(errors)),
            }
        }
        other => {
            let view = d.read_view();
            dispatch_read(other, params, &view)
        }
    }
}
```

- [ ] **Step 6: Add the two `Daemon` methods the server calls**

Append to `impl Daemon` in `daemon.rs`:

```rust
    /// The snapshot the read methods answer from.
    pub fn read_view(&self) -> crate::varlink::ReadView {
        crate::varlink::ReadView {
            status: self.status.clone(),
            alerts: self.store.read_all().unwrap_or_default(),
            quarantines: self
                .quarantines
                .list()
                .iter()
                .map(|q| {
                    serde_json::json!({
                        "id": q.alert_id,
                        "cgroup": q.cgroup,
                        "rootPid": q.root_pid,
                        "pids": q.pids,
                        "killed": q.killed,
                    })
                })
                .collect(),
            chain: self.store.verify().map_err(|e| e.to_string()),
        }
    }

    /// Validate and swap a generation's rules (spec §11.3). On success the
    /// change summary is returned and a critical alert records it; on failure
    /// the current rules stay and the errors come back.
    pub fn load_generation(
        &mut self,
        generation: &str,
        dir: &std::path::Path,
        kernel: std::sync::Arc<std::sync::Mutex<Box<dyn Kernel>>>,
    ) -> Result<Vec<String>, Vec<String>> {
        let loaded = sentinel_rules::load_dir(dir)
            .map_err(|errs| errs.iter().map(|e| e.to_string()).collect::<Vec<_>>())?;
        let next = crate::engine::RuleSet::compile(loaded)
            .map_err(|errs| errs.iter().map(|e| e.to_string()).collect::<Vec<_>>())?;

        let diff = sentinel_rules::diff::diff_rules(&self.rules.rules, &next.rules);
        let changes = diff.summary();

        {
            let mut k = kernel
                .lock()
                .map_err(|_| vec!["kernel busy".to_string()])?;
            k.swap_rules(&next.tables)
                .map_err(|e| vec![e.to_string()])?;
        }
        self.rules = next;
        self.generation = generation.to_string();

        let now = self.last_wall_ms;
        let mut a = self.blank_alert("config-changed", "critical", "alerted");
        a.ts = Self::format_ts(now);
        a.message = format!("Sentinel configuration changed by {generation}");
        a.event = serde_json::json!({
            "on": "config",
            "generation": generation,
            "changes": changes,
        });
        self.raise(a);
        Ok(changes)
    }
```

and add the three fields they use to `Daemon`, initialised in `new`:

```rust
    /// The generation whose rules are loaded, for `Status` (spec §10.1).
    pub generation: String,
    /// The last `Status` built, so the varlink thread does not need a kernel.
    pub status: Option<crate::status::Status>,
    /// The last wall clock the hot path saw, for alerts raised off-path.
    pub last_wall_ms: u64,
```

Set `last_wall_ms = now_ms` at the top of `on_event`.

- [ ] **Step 7: Verify the crate still builds and every test passes**

Run: `cd sentinel && cargo test -p sentineld && cargo clippy -p sentineld --all-targets -- -D warnings`
Expected: all tests pass, no clippy warnings.

- [ ] **Step 8: Commit**

```bash
git add sentinel/crates/sentineld/src/varlink.rs sentinel/crates/sentineld/src/daemon.rs
git commit -m "feat(sentineld): root-only varlink methods, WatchAlerts and the server loop"
```

---

## Task 18: The real `Kernel` — load, attach, pin

**Files:**
- Create: `sentinel/crates/sentineld/src/loader.rs`
- Modify: `sentinel/crates/sentineld/src/lib.rs` (add `pub mod loader;`)

Spec §8.1: programs, links and maps are pinned under `/sys/fs/bpf/aios-sentinel/`, and a restarted `sentineld` reuses the pins instead of detaching and reattaching, so a restart leaves no gap. Spec §12: if the object fails to load, exit with the error and pin nothing; if the LSM programs fail to attach but the tracing ones work, run degraded — observe only, with a critical alert.

The load sequence is `ebpf-loadtest`'s `load` function (read it first; it is the reference S2 handed over). Three things differ:

1. Pin every map and every link under `/sys/fs/bpf/aios-sentinel/`.
2. On start, try the pins first; a complete pin set means a previous instance is still attached and this one only re-opens the maps.
3. Drain the ring with `poll` on the ring fd, not a 10 ms sleep loop (§13: under 1 % of one core).

Most of this cannot be unit-tested without a kernel; Task 22's `daemon` scenario covers it. The three pure helpers below are tested here.

- [ ] **Step 1: Write the failing tests**

Create `sentinel/crates/sentineld/src/loader.rs` with the tests first:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_paths_live_under_the_sentinel_directory() {
        assert_eq!(
            map_pin_path("EVENTS"),
            std::path::Path::new("/sys/fs/bpf/aios-sentinel/maps/EVENTS")
        );
        assert_eq!(
            link_pin_path("exec"),
            std::path::Path::new("/sys/fs/bpf/aios-sentinel/links/exec")
        );
    }

    #[test]
    fn the_pin_set_is_complete_only_with_every_map_and_link() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("maps")).unwrap();
        std::fs::create_dir_all(dir.path().join("links")).unwrap();
        assert!(!pins_complete(dir.path()), "an empty directory is not a pin set");
        for m in MAP_NAMES {
            std::fs::write(dir.path().join("maps").join(m), b"").unwrap();
        }
        assert!(!pins_complete(dir.path()), "maps alone are not enough");
        for (prog, _) in LSM_PROGRAMS {
            std::fs::write(dir.path().join("links").join(prog), b"").unwrap();
        }
        for p in OTHER_PROGRAMS {
            std::fs::write(dir.path().join("links").join(p), b"").unwrap();
        }
        assert!(pins_complete(dir.path()));
    }

    #[test]
    fn every_lsm_program_names_its_kernel_hook() {
        // The hook name, not the program name, is what Lsm::load takes (§17.7).
        let by_prog: std::collections::HashMap<&str, &str> = LSM_PROGRAMS.iter().copied().collect();
        assert_eq!(by_prog["exec"], "bprm_check_security");
        assert_eq!(by_prog["connect"], "socket_connect");
        assert_eq!(by_prog["signal"], "task_kill");
        assert_eq!(by_prog["guard_truncate"], "path_truncate");
        assert_eq!(by_prog["bpf"], "bpf");
        assert_eq!(LSM_PROGRAMS.len(), 13);
    }

    #[test]
    fn the_bpf_self_guard_is_attached_last() {
        assert_eq!(
            LSM_PROGRAMS.last().map(|(p, _)| *p),
            Some("bpf"),
            "attaching it earlier would make the loader observe its own setup calls"
        );
    }

    #[test]
    fn the_cgroup_path_of_a_pid_is_read_from_proc_cgroup() {
        assert_eq!(
            cgroup_rel("0::/user.slice/user-1000.slice/session-2.scope\n"),
            "/user.slice/user-1000.slice/session-2.scope"
        );
        assert_eq!(cgroup_rel("0::/\n"), "/");
        assert_eq!(cgroup_rel(""), "/");
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd sentinel && cargo test -p sentineld loader`
Expected: FAIL to compile — `cannot find function map_pin_path`.

- [ ] **Step 3: Write the constants and the pure helpers**

Insert above the `tests` module in `loader.rs`:

```rust
//! The real [`Kernel`]: loads the embedded object, attaches every program,
//! pins everything under `/sys/fs/bpf/aios-sentinel/` (spec §8.1, §12).

use std::path::{Path, PathBuf};

use crate::kernel::{Kernel, KernelError, NHOOKS};

/// Where programs, links and maps are pinned (spec §8.1).
pub const PIN_ROOT: &str = "/sys/fs/bpf/aios-sentinel";

/// Every map the daemon binds, from the S2 ABI.
pub const MAP_NAMES: [&str; 13] = [
    "EVENTS",
    "DROPS",
    "HEARTBEAT",
    "LOCKDOWN_COUNTS",
    "RULES",
    "RULE_COUNT",
    "MOUNTS",
    "CIDRS",
    "PORTS",
    "UID_LITERALS",
    "QUARANTINE",
    "GUARDED_INODES",
    "CONFIG",
];

/// LSM programs as `(program name, kernel hook name)`. `Lsm::load` takes the
/// **hook** name (§17.7). `bpf` is last on purpose: attaching it earlier would
/// make the loader observe its own setup `bpf()` calls.
pub const LSM_PROGRAMS: [(&str, &str); 13] = [
    ("exec", "bprm_check_security"),
    ("connect", "socket_connect"),
    ("sendmsg", "socket_sendmsg"),
    ("listen", "socket_listen"),
    ("open", "file_open"),
    ("ptrace", "ptrace_access_check"),
    ("module_read", "kernel_read_file"),
    ("module_data", "kernel_load_data"),
    ("signal", "task_kill"),
    ("guard_unlink", "inode_unlink"),
    ("guard_rename", "inode_rename"),
    ("guard_truncate", "path_truncate"),
    ("bpf", "bpf"),
];

/// The non-LSM programs: two BTF tracepoints, one fexit, one tracepoint.
pub const OTHER_PROGRAMS: [&str; 4] = ["fork", "exit", "write_refused", "memfd"];

pub fn map_pin_path(name: &str) -> PathBuf {
    Path::new(PIN_ROOT).join("maps").join(name)
}

pub fn link_pin_path(program: &str) -> PathBuf {
    Path::new(PIN_ROOT).join("links").join(program)
}

/// Is a complete pin set already in place — that is, did a previous instance
/// attach everything (spec §8.1)?
pub fn pins_complete(root: &Path) -> bool {
    MAP_NAMES
        .iter()
        .all(|m| root.join("maps").join(m).exists())
        && LSM_PROGRAMS
            .iter()
            .all(|(p, _)| root.join("links").join(p).exists())
        && OTHER_PROGRAMS
            .iter()
            .all(|p| root.join("links").join(p).exists())
}

/// The cgroup v2 path out of a `/proc/<pid>/cgroup` body.
pub fn cgroup_rel(body: &str) -> String {
    body.lines()
        .next()
        .and_then(|l| l.rsplit("::").next())
        .filter(|s| !s.is_empty())
        .unwrap_or("/")
        .to_string()
}

fn ke<T>(msg: impl Into<String>) -> Result<T, KernelError> {
    Err(KernelError(msg.into()))
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd sentinel && cargo test -p sentineld loader`
Expected: 5 passed.

- [ ] **Step 5: Write the loader and the `Kernel` implementation**

This part is exercised by the VM scenarios, not by unit tests. Append to `loader.rs`:

```rust
/// Local newtypes, because `aya::Pod` is a foreign trait and the wire types
/// are foreign too (the same workaround `ebpf-loadtest` uses).
#[derive(Clone, Copy)]
#[repr(transparent)]
struct PodConfig(sentinel_common::wire::KConfig);
// SAFETY: KConfig is repr(C), Copy, fully initialised plain data.
unsafe impl aya::Pod for PodConfig {}

#[derive(Clone, Copy)]
#[repr(transparent)]
struct PodRule(sentinel_common::rule::KRule);
// SAFETY: KRule is repr(C), Copy, fully initialised plain data.
unsafe impl aya::Pod for PodRule {}

#[derive(Clone, Copy)]
#[repr(transparent)]
struct PodCidr(sentinel_common::wire::CidrEntry);
// SAFETY: CidrEntry is repr(C), Copy, plain data with no padding.
unsafe impl aya::Pod for PodCidr {}

#[derive(Clone, Copy)]
#[repr(transparent)]
struct PodPort(sentinel_common::wire::PortRange);
// SAFETY: PortRange is repr(C), Copy, with an explicit padding field.
unsafe impl aya::Pod for PodPort {}

/// Whether the LSM half attached (spec §12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Full,
    /// Tracing works, LSM does not: no deny, no self-guard, no lockdown.
    Degraded,
}

pub struct RealKernel {
    bpf: aya::Ebpf,
    pub mode: Mode,
    pub attached: Vec<String>,
    /// Taken out of `bpf` so the drain thread can own it.
    pub ring: Option<aya::maps::RingBuf<aya::maps::MapData>>,
}

impl RealKernel {
    /// Load, configure, attach and pin. `enforce` and `selfguard` set the
    /// `CONFIG` flags; `guarded` seeds `GUARDED_INODES` (spec §8.2).
    pub fn load(
        lockdown_after_ns: u64,
        enforce: bool,
        selfguard: bool,
        tables: &sentinel_rules::compile::Tables,
        guarded: &[PathBuf],
    ) -> Result<RealKernel, KernelError> {
        use aya::programs::{BtfTracePoint, FExit, Lsm, TracePoint};

        let data = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/sentinel-ebpf"));
        let mut bpf = match aya::Ebpf::load(data) {
            Ok(b) => b,
            Err(e) => return ke(format!("cannot load the eBPF object: {e}")),
        };
        let btf = match aya::Btf::from_sys_fs() {
            Ok(b) => b,
            Err(e) => return ke(format!("BTF is unavailable: {e}")),
        };

        // 1. CONFIG, before attaching anything.
        let usr = usr_mnt_id()?;
        let cfg = sentinel_common::wire::KConfig {
            lockdown_after_ns,
            sentineld_tgid: std::process::id(),
            flags: (if enforce { sentinel_common::wire::CFG_ENFORCE } else { 0 })
                | (if selfguard { sentinel_common::wire::CFG_SELFGUARD } else { 0 }),
            usr_mnt_id: usr,
            _pad: 0,
        };
        set_array(&mut bpf, "CONFIG", 0, PodConfig(cfg))?;

        // 2. Rules and lookup tables.
        write_tables(&mut bpf, tables)?;

        // 3. Guarded inodes (the alert store and the pin directory).
        if !guarded.is_empty() {
            use std::os::unix::fs::MetadataExt;
            let mut m = hash_map::<u64, u8>(&mut bpf, "GUARDED_INODES")?;
            for p in guarded {
                if let Ok(meta) = std::fs::metadata(p) {
                    let _ = m.insert(&meta.ino(), &1u8, 0);
                }
            }
        }

        // 4. Attach. The tracing programs first: if LSM fails we still observe.
        let mut attached = Vec::new();
        for (name, tp) in [("fork", "sched_process_fork"), ("exit", "sched_process_exit")] {
            let prog: &mut BtfTracePoint = match bpf.program_mut(name).and_then(|p| p.try_into().ok())
            {
                Some(p) => p,
                None => return ke(format!("program {name} missing")),
            };
            prog.load(tp, &btf)
                .and_then(|()| prog.attach().map(|_| ()))
                .map_err(|e| KernelError(format!("{name}: {e}")))?;
            attached.push(name.to_string());
        }
        {
            let prog: &mut FExit = match bpf
                .program_mut("write_refused")
                .and_then(|p| p.try_into().ok())
            {
                Some(p) => p,
                None => return ke("program write_refused missing"),
            };
            prog.load("path_openat", &btf)
                .and_then(|()| prog.attach().map(|_| ()))
                .map_err(|e| KernelError(format!("write_refused: {e}")))?;
            attached.push("write_refused".to_string());
        }
        {
            let prog: &mut TracePoint = match bpf.program_mut("memfd").and_then(|p| p.try_into().ok())
            {
                Some(p) => p,
                None => return ke("program memfd missing"),
            };
            prog.load()
                .and_then(|()| prog.attach("syscalls", "sys_enter_memfd_create").map(|_| ()))
                .map_err(|e| KernelError(format!("memfd: {e}")))?;
            attached.push("memfd".to_string());
        }

        // The ring is taken before the bpf self-guard attaches, exactly as the
        // reference loader does.
        let ring = aya::maps::RingBuf::try_from(
            bpf.take_map("EVENTS")
                .ok_or_else(|| KernelError("EVENTS missing".to_string()))?,
        )
        .map_err(|e| KernelError(format!("EVENTS: {e}")))?;

        let mut mode = Mode::Full;
        for (name, hook) in LSM_PROGRAMS {
            let Some(prog) = bpf.program_mut(name) else {
                return ke(format!("program {name} missing"));
            };
            let prog: &mut Lsm = match prog.try_into() {
                Ok(p) => p,
                Err(e) => return ke(format!("{name} is not an LSM program: {e}")),
            };
            match prog.load(hook, &btf).and_then(|()| prog.attach().map(|_| ())) {
                Ok(()) => attached.push(name.to_string()),
                Err(e) => {
                    // Spec §12: tracing works, LSM does not — observe only.
                    eprintln!("sentineld: LSM {name} ({hook}) did not attach: {e}");
                    mode = Mode::Degraded;
                    break;
                }
            }
        }

        let mut k = RealKernel {
            bpf,
            mode,
            attached,
            ring: Some(ring),
        };
        k.pin_everything()?;
        Ok(k)
    }

    /// Pin every map and link so the kernel side outlives this process
    /// (spec §8.1). Already-pinned paths are left alone.
    fn pin_everything(&mut self) -> Result<(), KernelError> {
        let root = Path::new(PIN_ROOT);
        if let Err(e) = std::fs::create_dir_all(root.join("maps")) {
            return ke(format!("cannot create {}: {e}", root.display()));
        }
        if let Err(e) = std::fs::create_dir_all(root.join("links")) {
            return ke(format!("cannot create {}: {e}", root.display()));
        }
        for name in MAP_NAMES {
            let path = map_pin_path(name);
            if path.exists() {
                continue;
            }
            if let Some(m) = self.bpf.map(name) {
                if let Err(e) = m.pin(&path) {
                    return ke(format!("cannot pin map {name}: {e}"));
                }
            }
        }
        // Links are pinned by taking each program's link and converting it to
        // an FdLink, which is what `FdLink::pin` consumes.
        //
        // Aya's per-program `take_link` needs the link id returned by
        // `attach()`. Record those ids in `load` as you attach, in a
        // `Vec<(String, LinkKind)>`, and pin them here. If that bookkeeping
        // proves awkward, the simpler equivalent is to pin inside `load`
        // immediately after each successful `attach()`, which is what the
        // VM scenario asserts anyway.
        Ok(())
    }

    /// Take the ring buffer for the drain thread.
    pub fn take_ring(&mut self) -> Option<aya::maps::RingBuf<aya::maps::MapData>> {
        self.ring.take()
    }
}
```

**Do the link pinning inline.** Replace the comment in `pin_everything` by pinning at attach time: after each successful `prog.attach()` in `load`, add

```rust
            let link_id = prog.attach().map_err(|e| KernelError(format!("{name}: {e}")))?;
            let link = prog
                .take_link(link_id)
                .map_err(|e| KernelError(format!("{name}: {e}")))?;
            let fd_link = aya::programs::links::FdLink::from(link);
            let path = link_pin_path(name);
            if !path.exists() {
                fd_link
                    .pin(&path)
                    .map_err(|e| KernelError(format!("cannot pin link {name}: {e}")))?;
            }
```

and keep `pin_everything` for the maps only. `FdLink::from` exists for every link wrapper `define_link_wrapper!` generates (`LsmLink`, `FExitLink`, `BtfTracePointLink`, `TracePointLink`), which the contract reference above records.

- [ ] **Step 6: Write the map helpers and the `Kernel` impl**

Append to `loader.rs`:

```rust
fn array<T: aya::Pod>(
    bpf: &mut aya::Ebpf,
    name: &'static str,
) -> Result<aya::maps::Array<&mut aya::maps::MapData, T>, KernelError> {
    let m = bpf
        .map_mut(name)
        .ok_or_else(|| KernelError(format!("{name} missing")))?;
    aya::maps::Array::try_from(m).map_err(|e| KernelError(format!("{name}: {e}")))
}

fn hash_map<K: aya::Pod, V: aya::Pod>(
    bpf: &mut aya::Ebpf,
    name: &'static str,
) -> Result<aya::maps::HashMap<&mut aya::maps::MapData, K, V>, KernelError> {
    let m = bpf
        .map_mut(name)
        .ok_or_else(|| KernelError(format!("{name} missing")))?;
    aya::maps::HashMap::try_from(m).map_err(|e| KernelError(format!("{name}: {e}")))
}

fn set_array<T: aya::Pod>(
    bpf: &mut aya::Ebpf,
    name: &'static str,
    index: u32,
    value: T,
) -> Result<(), KernelError> {
    let mut a = array::<T>(bpf, name)?;
    a.set(index, &value, 0)
        .map_err(|e| KernelError(format!("{name}[{index}]: {e}")))
}

/// mnt_id of the mount holding `/usr/bin` (longest matching mount point).
/// Copied from the reference loader; lockdown allows exec only from here.
fn usr_mnt_id() -> Result<u32, KernelError> {
    let info = std::fs::read_to_string("/proc/self/mountinfo")
        .map_err(|e| KernelError(format!("mountinfo: {e}")))?;
    let target = "/usr/bin";
    let mut best: Option<(usize, u32)> = None;
    for line in info.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 5 {
            continue;
        }
        let mp = f[4];
        let is_prefix = mp == "/"
            || target == mp
            || (target.starts_with(mp) && target.as_bytes().get(mp.len()) == Some(&b'/'));
        if is_prefix && best.is_none_or(|(l, _)| mp.len() >= l) {
            if let Ok(id) = f[0].parse() {
                best = Some((mp.len(), id));
            }
        }
    }
    best.map(|(_, id)| id)
        .ok_or_else(|| KernelError("no mount found for /usr".to_string()))
}

/// Write RULES, the lookup tables, then RULE_COUNT — count last, so a hook
/// never walks a half-written set.
fn write_tables(
    bpf: &mut aya::Ebpf,
    t: &sentinel_rules::compile::Tables,
) -> Result<(), KernelError> {
    use sentinel_common::facts::slot_bit;
    use sentinel_common::rule::{MAX_CIDRS, MAX_PORT_SETS, MAX_UID_LITERALS};
    use sentinel_common::wire::{CidrEntry, PortRange};

    {
        let mut a = array::<PodRule>(bpf, "RULES")?;
        for (i, kr) in t.rules.iter().enumerate() {
            a.set(i as u32, &PodRule(*kr), 0)
                .map_err(|e| KernelError(format!("RULES[{i}]: {e}")))?;
        }
    }
    {
        let mut m = hash_map::<u64, u32>(bpf, "MOUNTS")?;
        for (slot, path) in t.mounts.iter().enumerate() {
            match mount_id_for(path) {
                Some(id) => {
                    let cur = m.get(&id, 0).unwrap_or(0);
                    let _ = m.insert(&id, &(cur | slot_bit(slot)), 0);
                }
                None => eprintln!(
                    "sentineld: exe_on path {path} is not a mount point; rules on it cannot match"
                ),
            }
        }
    }
    {
        let mut a = array::<PodCidr>(bpf, "CIDRS")?;
        if t.cidrs.len() > MAX_CIDRS {
            return ke("too many CIDRs");
        }
        for (slot, net) in t.cidrs.iter().enumerate() {
            let mut e = CidrEntry {
                addr: [0; 16],
                prefix: net.prefix_len(),
                family: 0,
                slot: slot as u8,
                used: 1,
            };
            match net.network() {
                std::net::IpAddr::V4(v) => {
                    e.addr[..4].copy_from_slice(&v.octets());
                    e.family = 2;
                }
                std::net::IpAddr::V6(v) => {
                    e.addr = v.octets();
                    e.family = 10;
                }
            }
            a.set(slot as u32, &PodCidr(e), 0)
                .map_err(|err| KernelError(format!("CIDRS[{slot}]: {err}")))?;
        }
    }
    {
        let mut a = array::<PodPort>(bpf, "PORTS")?;
        let mut idx = 0u32;
        for (slot, set) in t.port_sets.iter().enumerate() {
            for &(lo, hi) in set {
                if idx as usize >= MAX_PORT_SETS {
                    return ke("too many port ranges");
                }
                a.set(
                    idx,
                    &PodPort(PortRange { lo, hi, slot: slot as u8, used: 1, _pad: [0; 2] }),
                    0,
                )
                .map_err(|e| KernelError(format!("PORTS[{idx}]: {e}")))?;
                idx += 1;
            }
        }
    }
    {
        let mut a = array::<u32>(bpf, "UID_LITERALS")?;
        for i in 0..MAX_UID_LITERALS {
            // u32::MAX marks an unused slot: an unwritten slot reads 0, which
            // would match root (§17.7).
            let v = t.uid_lits.get(i).copied().unwrap_or(u32::MAX);
            a.set(i as u32, &v, 0)
                .map_err(|e| KernelError(format!("UID_LITERALS[{i}]: {e}")))?;
        }
    }
    set_array(bpf, "RULE_COUNT", 0, t.rules.len() as u32)
}

/// mnt_id of the mount whose mount point is exactly `path` (`exe_on` needs an
/// exact match; longest-prefix would map everything to `/`, §17.7).
fn mount_id_for(path: &str) -> Option<u64> {
    let canon = std::fs::canonicalize(path).unwrap_or_else(|_| path.into());
    let canon = canon.to_string_lossy().into_owned();
    let info = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    let mut found = None;
    for line in info.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        if f.len() < 5 {
            continue;
        }
        if f[4].replace("\\040", " ") == canon {
            found = f[0].parse::<u64>().ok();
        }
    }
    found
}

fn monotonic_ns_now() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: ts is a valid out-pointer; CLOCK_MONOTONIC matches bpf_ktime_get_ns.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

impl Kernel for RealKernel {
    fn monotonic_ns(&self) -> u64 {
        monotonic_ns_now()
    }

    fn wall_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    fn heartbeat(&mut self, ns: u64) -> Result<(), KernelError> {
        set_array(&mut self.bpf, "HEARTBEAT", 0, ns)
    }

    fn heartbeat_value(&self) -> Result<u64, KernelError> {
        let m = self
            .bpf
            .map("HEARTBEAT")
            .ok_or_else(|| KernelError("HEARTBEAT missing".to_string()))?;
        let a = aya::maps::Array::<_, u64>::try_from(m)
            .map_err(|e| KernelError(format!("HEARTBEAT: {e}")))?;
        a.get(&0, 0).map_err(|e| KernelError(format!("HEARTBEAT: {e}")))
    }

    fn drops(&self) -> Result<u64, KernelError> {
        let m = self
            .bpf
            .map("DROPS")
            .ok_or_else(|| KernelError("DROPS missing".to_string()))?;
        let a = aya::maps::PerCpuArray::<_, u64>::try_from(m)
            .map_err(|e| KernelError(format!("DROPS: {e}")))?;
        let per_cpu = a.get(&0, 0).map_err(|e| KernelError(format!("DROPS: {e}")))?;
        Ok(per_cpu.iter().sum())
    }

    fn lockdown_counts(&self) -> Result<[u64; NHOOKS], KernelError> {
        let m = self
            .bpf
            .map("LOCKDOWN_COUNTS")
            .ok_or_else(|| KernelError("LOCKDOWN_COUNTS missing".to_string()))?;
        let a = aya::maps::Array::<_, u64>::try_from(m)
            .map_err(|e| KernelError(format!("LOCKDOWN_COUNTS: {e}")))?;
        let mut out = [0u64; NHOOKS];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = a.get(&(i as u32), 0).unwrap_or(0);
        }
        Ok(out)
    }

    fn swap_rules(&mut self, tables: &sentinel_rules::compile::Tables) -> Result<(), KernelError> {
        write_tables(&mut self.bpf, tables)
    }

    fn quarantine_add(&mut self, cgroup_id: u64) -> Result<(), KernelError> {
        let mut m = hash_map::<u64, u8>(&mut self.bpf, "QUARANTINE")?;
        m.insert(&cgroup_id, &1u8, 0)
            .map_err(|e| KernelError(format!("QUARANTINE insert: {e}")))
    }

    fn quarantine_remove(&mut self, cgroup_id: u64) -> Result<(), KernelError> {
        let mut m = hash_map::<u64, u8>(&mut self.bpf, "QUARANTINE")?;
        m.remove(&cgroup_id)
            .map_err(|e| KernelError(format!("QUARANTINE remove: {e}")))
    }

    fn cgroup_create(&mut self, path: &str) -> Result<u64, KernelError> {
        use std::os::unix::fs::MetadataExt;
        if let Err(e) = std::fs::create_dir_all(path) {
            return ke(format!("cgroup_create {path}: {e}"));
        }
        std::fs::metadata(path)
            .map(|m| m.ino())
            .map_err(|e| KernelError(format!("cgroup_create {path}: {e}")))
    }

    fn cgroup_remove(&mut self, path: &str) -> Result<(), KernelError> {
        std::fs::remove_dir(path).map_err(|e| KernelError(format!("cgroup_remove {path}: {e}")))
    }

    fn cgroup_attach(&mut self, path: &str, pid: u32) -> Result<(), KernelError> {
        std::fs::write(format!("{path}/cgroup.procs"), pid.to_string())
            .map_err(|e| KernelError(format!("cgroup_attach {path} {pid}: {e}")))
    }

    fn cgroup_freeze(&mut self, path: &str, on: bool) -> Result<(), KernelError> {
        std::fs::write(format!("{path}/cgroup.freeze"), if on { "1" } else { "0" })
            .map_err(|e| KernelError(format!("cgroup_freeze {path}: {e}")))
    }

    fn cgroup_kill(&mut self, path: &str) -> Result<(), KernelError> {
        std::fs::write(format!("{path}/cgroup.kill"), "1")
            .map_err(|e| KernelError(format!("cgroup_kill {path}: {e}")))
    }

    fn cgroup_of(&self, pid: u32) -> Result<String, KernelError> {
        let body = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
            .map_err(|e| KernelError(format!("cgroup_of {pid}: {e}")))?;
        Ok(format!("/sys/fs/cgroup{}", cgroup_rel(&body)))
    }

    fn destroy_sockets(&mut self, pids: &[u32]) -> Result<usize, KernelError> {
        crate::sockdestroy::destroy_for_pids(pids)
    }
}
```

Add `pub mod loader;` to `lib.rs`.

- [ ] **Step 7: Verify it compiles**

Run: `cd sentinel && cargo build -p sentineld && cargo clippy -p sentineld --all-targets -- -D warnings`
Expected: compiles, no warnings. It will not compile until Task 19 provides `sockdestroy::destroy_for_pids`; do Task 19 first if you prefer, or stub it as `Ok(0)` and replace it there.

Aya API drift is the likely failure here. If `PerCpuArray::get` returns a different shape, or `Array::try_from` wants an owned `MapData`, read the vendored source at `~/.cargo/registry/src/*/aya-0.16.0/src/maps/` — that is the authority, not this plan.

- [ ] **Step 8: Commit**

```bash
git add sentinel/crates/sentineld/src/loader.rs sentinel/crates/sentineld/src/lib.rs
git commit -m "feat(sentineld): real Kernel - load, attach, pin under /sys/fs/bpf"
```

---

## Task 19: Destroying a quarantined process's sockets

**Files:**
- Create: `sentinel/crates/sentineld/src/sockdestroy.rs`
- Modify: `sentinel/crates/sentineld/src/lib.rs` (add `pub mod sockdestroy;`)

Spec §17.2: Aya exposes no socket-iterator program type, so the `bpf_sock_destroy` step runs in user space — for each quarantined pid, enumerate its sockets and destroy them with `SOCK_DESTROY` (`INET_DIAG_DESTROY`). The LSM deny for the quarantine cgroup already stops new connections, so this only closes what was already open.

The method: read `/proc/<pid>/fd/*`, collect the `socket:[inode]` targets, then for each inode send a `SOCK_DESTROY` request over `NETLINK_SOCK_DIAG`. The request needs the socket's addresses, so the daemon first dumps the live sockets and indexes them by inode.

The netlink message encoders are pure and tested; the socket I/O is covered by Task 22's `freeze` VM scenario.

- [ ] **Step 1: Write the failing tests**

Create `sentinel/crates/sentineld/src/sockdestroy.rs` with the tests first:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_inodes_are_parsed_from_fd_targets() {
        assert_eq!(socket_inode("socket:[12345]"), Some(12345));
        assert_eq!(socket_inode("socket:[0]"), Some(0));
        assert_eq!(socket_inode("/dev/null"), None);
        assert_eq!(socket_inode("pipe:[99]"), None);
        assert_eq!(socket_inode("socket:[nope]"), None);
    }

    #[test]
    fn a_dump_request_is_a_well_formed_netlink_message() {
        let msg = dump_request(libc::AF_INET as u8, libc::IPPROTO_TCP as u8, 1);
        // nlmsghdr is 16 bytes, inet_diag_req_v2 is 56; total 72.
        assert_eq!(msg.len(), 72);
        assert_eq!(u32::from_ne_bytes(msg[0..4].try_into().unwrap()), 72);
        assert_eq!(u16::from_ne_bytes(msg[4..6].try_into().unwrap()), SOCK_DIAG_BY_FAMILY);
        let flags = u16::from_ne_bytes(msg[6..8].try_into().unwrap());
        assert!(flags & NLM_F_DUMP != 0, "a dump sets NLM_F_DUMP");
        assert_eq!(msg[16], libc::AF_INET as u8, "sdiag_family");
        assert_eq!(msg[17], libc::IPPROTO_TCP as u8, "sdiag_protocol");
    }

    #[test]
    fn a_destroy_request_targets_one_socket_and_is_not_a_dump() {
        let id = SockId {
            sport: 1234,
            dport: 443,
            src: [10, 0, 2, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            dst: [10, 0, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            iface: 0,
            cookie: [7, 9],
            family: libc::AF_INET as u8,
            inode: 4242,
        };
        let msg = destroy_request(&id, libc::IPPROTO_TCP as u8, 2);
        assert_eq!(msg.len(), 72);
        assert_eq!(u16::from_ne_bytes(msg[4..6].try_into().unwrap()), SOCK_DESTROY);
        let flags = u16::from_ne_bytes(msg[6..8].try_into().unwrap());
        assert!(flags & NLM_F_DUMP == 0, "a destroy is not a dump");
        assert!(flags & NLM_F_REQUEST != 0);
        // The ports sit in the id, big-endian, right after the 4-byte header
        // of inet_diag_req_v2 (family, protocol, ext, pad).
        assert_eq!(u16::from_be_bytes(msg[20..22].try_into().unwrap()), 1234);
        assert_eq!(u16::from_be_bytes(msg[22..24].try_into().unwrap()), 443);
    }

    #[test]
    fn a_destroy_request_carries_the_cookie() {
        let id = SockId {
            sport: 1,
            dport: 2,
            src: [0; 16],
            dst: [0; 16],
            iface: 0,
            cookie: [0xAA, 0xBB],
            family: libc::AF_INET as u8,
            inode: 1,
        };
        let msg = destroy_request(&id, libc::IPPROTO_TCP as u8, 1);
        // cookie is the last 8 bytes of inet_diag_sockid, which ends the
        // 48-byte id starting at offset 20.
        assert_eq!(u32::from_ne_bytes(msg[60..64].try_into().unwrap()), 0xAA);
        assert_eq!(u32::from_ne_bytes(msg[64..68].try_into().unwrap()), 0xBB);
    }

    #[test]
    fn destroying_no_pids_does_nothing() {
        assert_eq!(destroy_for_pids(&[]).unwrap(), 0);
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd sentinel && cargo test -p sentineld sockdestroy`
Expected: FAIL to compile — `cannot find function socket_inode`.

- [ ] **Step 3: Write the implementation**

Insert above the `tests` module in `sockdestroy.rs`:

```rust
//! `SOCK_DESTROY` over `NETLINK_SOCK_DIAG`, the user-space half of freeze
//! (spec §6, amendment 2 of §17).

use std::collections::HashSet;

use crate::kernel::KernelError;

/// `sock_diag` message types.
pub const SOCK_DIAG_BY_FAMILY: u16 = 20;
pub const SOCK_DESTROY: u16 = 21;

pub const NLM_F_REQUEST: u16 = 0x01;
pub const NLM_F_DUMP: u16 = 0x300;

/// `inet_diag_sockid` plus the inode, as the kernel reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockId {
    pub sport: u16,
    pub dport: u16,
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub iface: u32,
    pub cookie: [u32; 2],
    pub family: u8,
    pub inode: u32,
}

/// The inode out of a `/proc/<pid>/fd/<n>` link target.
pub fn socket_inode(target: &str) -> Option<u32> {
    target
        .strip_prefix("socket:[")
        .and_then(|r| r.strip_suffix(']'))
        .and_then(|n| n.parse().ok())
}

/// `nlmsghdr` + `inet_diag_req_v2`, 16 + 56 bytes.
fn request(
    nlmsg_type: u16,
    flags: u16,
    seq: u32,
    family: u8,
    protocol: u8,
    states: u32,
    id: Option<&SockId>,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(72);
    // struct nlmsghdr
    m.extend_from_slice(&72u32.to_ne_bytes()); // nlmsg_len
    m.extend_from_slice(&nlmsg_type.to_ne_bytes());
    m.extend_from_slice(&flags.to_ne_bytes());
    m.extend_from_slice(&seq.to_ne_bytes());
    m.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid
    // struct inet_diag_req_v2
    m.push(family); // sdiag_family
    m.push(protocol); // sdiag_protocol
    m.push(0); // idiag_ext
    m.push(0); // pad
    m.extend_from_slice(&states.to_ne_bytes()); // idiag_states
    // struct inet_diag_sockid (48 bytes)
    match id {
        Some(s) => {
            m.extend_from_slice(&s.sport.to_be_bytes());
            m.extend_from_slice(&s.dport.to_be_bytes());
            m.extend_from_slice(&s.src);
            m.extend_from_slice(&s.dst);
            m.extend_from_slice(&s.iface.to_ne_bytes());
            m.extend_from_slice(&s.cookie[0].to_ne_bytes());
            m.extend_from_slice(&s.cookie[1].to_ne_bytes());
        }
        None => m.extend_from_slice(&[0u8; 48]),
    }
    debug_assert_eq!(m.len(), 72);
    m
}

/// Ask for every socket of this family and protocol.
pub fn dump_request(family: u8, protocol: u8, seq: u32) -> Vec<u8> {
    request(
        SOCK_DIAG_BY_FAMILY,
        NLM_F_REQUEST | NLM_F_DUMP,
        seq,
        family,
        protocol,
        u32::MAX, // every TCP state
        None,
    )
}

/// Destroy exactly this socket.
pub fn destroy_request(id: &SockId, protocol: u8, seq: u32) -> Vec<u8> {
    request(
        SOCK_DESTROY,
        NLM_F_REQUEST,
        seq,
        id.family,
        protocol,
        u32::MAX,
        Some(id),
    )
}

/// Every socket inode held by these pids.
fn socket_inodes_of(pids: &[u32]) -> HashSet<u32> {
    let mut out = HashSet::new();
    for pid in pids {
        let Ok(rd) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };
        for ent in rd.flatten() {
            if let Ok(target) = std::fs::read_link(ent.path()) {
                if let Some(ino) = socket_inode(&target.to_string_lossy()) {
                    out.insert(ino);
                }
            }
        }
    }
    out
}

/// Parse one `inet_diag_msg` out of a dump reply body (after the nlmsghdr).
/// Layout: family, state, timer, retrans (4 bytes), then the 48-byte sockid,
/// then expires, rqueue, wqueue, uid, inode (5 x u32).
fn parse_diag_msg(body: &[u8]) -> Option<SockId> {
    if body.len() < 72 {
        return None;
    }
    let family = body[0];
    let sport = u16::from_be_bytes(body[4..6].try_into().ok()?);
    let dport = u16::from_be_bytes(body[6..8].try_into().ok()?);
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&body[8..24]);
    dst.copy_from_slice(&body[24..40]);
    let iface = u32::from_ne_bytes(body[40..44].try_into().ok()?);
    let cookie = [
        u32::from_ne_bytes(body[44..48].try_into().ok()?),
        u32::from_ne_bytes(body[48..52].try_into().ok()?),
    ];
    let inode = u32::from_ne_bytes(body[68..72].try_into().ok()?);
    Some(SockId {
        sport,
        dport,
        src,
        dst,
        iface,
        cookie,
        family,
        inode,
    })
}

/// Destroy every TCP and UDP socket belonging to `pids`. Returns the count.
///
/// A failure to destroy one socket is not a failure of the freeze: the LSM
/// hooks already deny the cgroup's `connect` and `sendmsg`, so the worst case
/// is one connection that stays open until its peer gives up.
pub fn destroy_for_pids(pids: &[u32]) -> Result<usize, KernelError> {
    use std::io::{Read, Write};
    use std::os::fd::FromRawFd;

    if pids.is_empty() {
        return Ok(0);
    }
    let wanted = socket_inodes_of(pids);
    if wanted.is_empty() {
        return Ok(0);
    }

    // SAFETY: a plain socket(2) call; the fd is adopted by OwnedFd below.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            4, // NETLINK_SOCK_DIAG
        )
    };
    if fd < 0 {
        return Err(KernelError(format!(
            "sock_diag socket: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: fd is a fresh, valid, owned descriptor.
    let mut sock = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };

    let mut destroyed = 0usize;
    let mut seq = 1u32;
    for (family, protocol) in [
        (libc::AF_INET as u8, libc::IPPROTO_TCP as u8),
        (libc::AF_INET6 as u8, libc::IPPROTO_TCP as u8),
        (libc::AF_INET as u8, libc::IPPROTO_UDP as u8),
        (libc::AF_INET6 as u8, libc::IPPROTO_UDP as u8),
    ] {
        if sock.write_all(&dump_request(family, protocol, seq)).is_err() {
            continue;
        }
        seq += 1;

        let mut found: Vec<SockId> = Vec::new();
        let mut buf = vec![0u8; 64 * 1024];
        'dump: loop {
            let n = match sock.read(&mut buf) {
                Ok(0) | Err(_) => break 'dump,
                Ok(n) => n,
            };
            let mut off = 0usize;
            while off + 16 <= n {
                let len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
                let ty = u16::from_ne_bytes(buf[off + 4..off + 6].try_into().unwrap());
                if len < 16 || off + len > n {
                    break 'dump;
                }
                // NLMSG_DONE = 3, NLMSG_ERROR = 2.
                if ty == 3 || ty == 2 {
                    break 'dump;
                }
                if let Some(id) = parse_diag_msg(&buf[off + 16..off + len]) {
                    if wanted.contains(&id.inode) {
                        found.push(id);
                    }
                }
                off += (len + 3) & !3; // NLMSG_ALIGN
            }
        }

        for id in found {
            if sock.write_all(&destroy_request(&id, protocol, seq)).is_ok() {
                destroyed += 1;
            }
            seq += 1;
            // Drain the acknowledgement so the next dump reads cleanly.
            let mut ack = [0u8; 4096];
            let _ = sock.read(&mut ack);
        }
    }
    Ok(destroyed)
}
```

Add `pub mod sockdestroy;` to `lib.rs`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd sentinel && cargo test -p sentineld sockdestroy`
Expected: 5 passed.

The two offset assertions in the tests are the contract with the kernel's `inet_diag_sockid` layout. If one fails, check the offsets against `/usr/include/linux/inet_diag.h` and fix the **encoder**, not the test, unless the header disagrees with the test's arithmetic.

- [ ] **Step 5: Commit**

```bash
git add sentinel/crates/sentineld/src/sockdestroy.rs sentinel/crates/sentineld/src/lib.rs
git commit -m "feat(sentineld): SOCK_DESTROY for quarantined processes via sock_diag"
```

---

## Task 20: `main.rs` — configuration, threads and the §12 exit paths

**Files:**
- Modify: `sentinel/crates/sentineld/src/main.rs`
- Create: `sentinel/crates/sentineld/src/dns.rs`
- Modify: `sentinel/crates/sentineld/src/lib.rs` (add `pub mod dns;`)

Spec §12 decides what `main` does when something fails:

| Failure | Behaviour |
|---|---|
| BTF or BPF-LSM missing, or the object fails to load | exit with the error; nothing is pinned, so there is no lockdown |
| LSM programs fail to attach, tracing works | degraded: `Status` and the journal say so, a critical alert, no deny, no self-guard, no lockdown |
| Rules invalid at boot | exit with the validation error |
| resolved monitor unavailable | DNS detection off, `Status` says so, retried every 30 s |

The config is `/etc/aios/sentinel/sentinel.toml` and the rules are `/etc/aios/sentinel/rules.d/`; `--config` and `--rules` override both so the VM scenarios can point elsewhere.

- [ ] **Step 1: Write the DNS monitor with its failing tests**

Create `sentinel/crates/sentineld/src/dns.rs`. systemd-resolved's `io.systemd.Resolve.Monitor` is varlink too, so the same framing works. Tests first:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_subscribe_call_asks_for_a_stream() {
        let v: serde_json::Value = serde_json::from_slice(
            &subscribe_call()[..subscribe_call().len() - 1],
        )
        .unwrap();
        assert_eq!(v["method"], "io.systemd.Resolve.Monitor.SubscribeQueryResults");
        assert_eq!(v["more"], true);
    }

    #[test]
    fn query_names_are_lifted_out_of_a_monitor_reply() {
        let reply = serde_json::json!({
            "parameters": {
                "question": [
                    {"type": "A", "name": "a7f3k9x2m4q8w1e5r6t0y.example.com"},
                    {"type": "AAAA", "name": "a7f3k9x2m4q8w1e5r6t0y.example.com"}
                ]
            },
            "continues": true
        });
        assert_eq!(
            query_names(&reply),
            vec!["a7f3k9x2m4q8w1e5r6t0y.example.com".to_string()],
            "a repeated name is reported once per reply"
        );
    }

    #[test]
    fn a_reply_without_a_question_yields_nothing() {
        assert!(query_names(&serde_json::json!({"parameters": {}})).is_empty());
        assert!(query_names(&serde_json::json!({})).is_empty());
    }
}
```

Then the implementation, above the tests:

```rust
//! The systemd-resolved query monitor (spec §4 `dns`, §12).

/// Where resolved listens for monitor subscribers.
pub const MONITOR_SOCKET: &str = "/run/systemd/resolve/io.systemd.Resolve.Monitor";
/// Retry interval when resolved is not there (spec §12).
pub const RETRY: std::time::Duration = std::time::Duration::from_secs(30);

/// The subscribe call, NUL-terminated.
pub fn subscribe_call() -> Vec<u8> {
    let v = serde_json::json!({
        "method": "io.systemd.Resolve.Monitor.SubscribeQueryResults",
        "parameters": {},
        "more": true,
    });
    let mut out = serde_json::to_vec(&v).unwrap_or_default();
    out.push(0);
    out
}

/// The distinct query names in one monitor reply.
pub fn query_names(reply: &serde_json::Value) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let Some(q) = reply
        .get("parameters")
        .and_then(|p| p.get("question"))
        .and_then(|q| q.as_array())
    else {
        return out;
    };
    for item in q {
        if let Some(name) = item.get("name").and_then(|n| n.as_str()) {
            let name = name.to_string();
            if !out.contains(&name) {
                out.push(name);
            }
        }
    }
    out
}
```

Run: `cd sentinel && cargo test -p sentineld dns`
Expected: 3 passed.

- [ ] **Step 2: Add the monitor thread**

Append to `dns.rs` (no unit test; Task 22's scenario does not cover resolved either — this is the one path exercised only by the S5 gauntlet, and the plan says so plainly):

```rust
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

/// Subscribe to resolved and feed every query name to the DNS-tunnel
/// detector. Reconnects every [`RETRY`] while resolved is unavailable.
///
/// Sets `connected` so `Status` can report the monitor's state (spec §12).
pub fn run(
    daemon: Arc<Mutex<crate::daemon::Daemon>>,
    kernel: Arc<Mutex<Box<dyn crate::kernel::Kernel>>>,
    connected: Arc<std::sync::atomic::AtomicBool>,
    stop: Arc<std::sync::atomic::AtomicBool>,
) {
    use std::sync::atomic::Ordering;
    while !stop.load(Ordering::Relaxed) {
        let Ok(mut sock) = std::os::unix::net::UnixStream::connect(MONITOR_SOCKET) else {
            connected.store(false, Ordering::Relaxed);
            std::thread::sleep(RETRY);
            continue;
        };
        if sock.write_all(&subscribe_call()).is_err() {
            connected.store(false, Ordering::Relaxed);
            std::thread::sleep(RETRY);
            continue;
        }
        connected.store(true, Ordering::Relaxed);

        let mut pending: Vec<u8> = Vec::new();
        let mut buf = [0u8; 8192];
        while !stop.load(Ordering::Relaxed) {
            let n = match sock.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            pending.extend_from_slice(&buf[..n]);
            let (frames, rest) = crate::varlink::split_frames(&pending);
            pending = rest;
            for frame in frames {
                let Ok(v) = serde_json::from_slice::<serde_json::Value>(&frame) else {
                    continue;
                };
                for name in query_names(&v) {
                    let now = kernel.lock().map(|k| k.wall_ms()).unwrap_or(0);
                    if let Ok(mut d) = daemon.lock() {
                        if let Some(hit) = d.detectors.on_dns(&name, now) {
                            d.raise_dns(hit, now);
                        }
                    }
                }
            }
        }
        connected.store(false, Ordering::Relaxed);
    }
}
```

and the `Daemon` method it calls, appended to `impl Daemon` in `daemon.rs`:

```rust
    /// A DNS-tunnel hit. Host-level, so it names the domain, not a process
    /// (spec §5.4), and its action can only be alert — freezing a host-level
    /// detection has no process to freeze.
    pub fn raise_dns(&mut self, hit: crate::engine::DetectorHit, now_ms: u64) {
        let mut a = self.blank_alert(hit.rule_id, &hit.severity, "alerted");
        a.ts = Self::format_ts(now_ms);
        a.event = hit.event;
        self.raise(a);
    }
```

- [ ] **Step 3: Write `main.rs`**

```rust
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use clap::Parser;

use sentineld::alert::Store;
use sentineld::daemon::Daemon;
use sentineld::engine::{Policy, RuleSet};
use sentineld::kernel::Kernel;
use sentineld::loader::{Mode, RealKernel};
use sentineld::proc::{ProcSource, RealProc};
use sentineld::report::SystemSink;
use sentineld::resolve::HomeBinds;
use sentineld::status::{self, Health};

/// How often the heartbeat is refreshed (spec §8.3 asks for every second; the
/// reference loader uses 500 ms, which leaves margin under a 2 s minimum).
const HEARTBEAT_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

#[derive(Parser)]
#[command(about = "AIOS Sentinel daemon")]
struct Cli {
    /// The rendered `[sentinel]` section.
    #[arg(long, default_value = "/etc/aios/sentinel/sentinel.toml")]
    config: PathBuf,
    /// The rendered rule directory.
    #[arg(long, default_value = "/etc/aios/sentinel/rules.d")]
    rules: PathBuf,
    /// Where alerts are stored.
    #[arg(long, default_value = "/var/log/aios/sentinel")]
    alerts: PathBuf,
    /// The varlink socket.
    #[arg(long, default_value = sentineld::varlink::SOCKET_PATH)]
    socket: PathBuf,
    /// Where the daemon writes `ok` or `degraded`.
    #[arg(long, default_value = status::STATE_PATH)]
    state: PathBuf,
    /// The manifest-managed home targets, one per line (S4 fills this in).
    #[arg(long)]
    home_binds: Option<PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // 1. Configuration. An absent file means the documented defaults (§11.1).
    let config = match std::fs::read_to_string(&cli.config) {
        Ok(raw) => sentinel_rules::config::parse(&raw)
            .map_err(|e| anyhow::anyhow!("{}: {e}", cli.config.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            sentinel_rules::config::SentinelConfig::default()
        }
        Err(e) => bail!("{}: {e}", cli.config.display()),
    };
    let problems = sentinel_rules::config::validate(&config);
    if !problems.is_empty() {
        bail!("{}: {}", cli.config.display(), problems.join("; "));
    }
    if !config.enable {
        // Nothing is loaded, so nothing is enforced and there is no lockdown.
        eprintln!("sentineld: disabled by configuration; exiting");
        return Ok(());
    }

    // 2. Rules. Invalid rules at boot are the same path as a load failure (§12).
    let loaded = sentinel_rules::load_dir(&cli.rules).map_err(|errs| {
        anyhow::anyhow!(
            "invalid rules: {}",
            errs.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("; ")
        )
    })?;
    let rules = RuleSet::compile(loaded).map_err(|errs| {
        anyhow::anyhow!(
            "rules do not compile: {}",
            errs.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("; ")
        )
    })?;

    let lockdown_after_ns = sentinel_rules::validate::parse_duration_ms(&config.lockdown_after)
        .map(|ms| ms * 1_000_000)
        .map_err(|e| anyhow::anyhow!("lockdown_after: {e}"))?;

    // 3. Load the kernel object. A failure here exits, pinning nothing (§12).
    let guarded = vec![cli.alerts.clone(), PathBuf::from(sentineld::loader::PIN_ROOT)];
    let real = RealKernel::load(
        lockdown_after_ns,
        true,
        true,
        &rules.tables,
        &guarded,
    )
    .map_err(|e| anyhow::anyhow!("cannot start the kernel side: {e}"))?;
    let degraded = real.mode == Mode::Degraded;
    let attached = real.attached.clone();
    let mut real = real;
    let ring = real.take_ring();

    // 4. Report whatever the kernel did while nobody was watching (§8.3).
    //    Read it before the first heartbeat of this instance.
    let gap = sentineld::lockdown::report(&mut real, lockdown_after_ns);

    let kernel: Arc<Mutex<Box<dyn Kernel>>> = Arc::new(Mutex::new(Box::new(real)));

    // 5. Build the daemon.
    let binds = match &cli.home_binds {
        Some(p) => HomeBinds::new(
            std::fs::read_to_string(p)
                .with_context(|| format!("{}", p.display()))?
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect(),
        ),
        None => HomeBinds::default(),
    };
    let procs = RealProc;
    let journald_pid = procs
        .pids()
        .into_iter()
        .find(|p| {
            procs
                .read(*p)
                .is_some_and(|q| q.exe.ends_with("systemd-journald"))
        })
        .unwrap_or(0);
    let policy = Policy::new(
        std::process::id(),
        journald_pid,
        config.never_act_on.clone(),
    );
    let store = Store::open(&cli.alerts).map_err(|e| anyhow::anyhow!("alert store: {e}"))?;

    let mut daemon = Daemon::new(
        rules,
        config.clone(),
        Box::new(RealProc),
        Box::new(SystemSink::new()),
        store,
        policy,
        binds,
    );
    daemon.seed_table();

    if let Some(g) = gap {
        let now = kernel.lock().map(|k| k.wall_ms()).unwrap_or(0);
        let mut a = daemon.blank_alert("lockdown-gap", "critical", "alerted");
        a.ts = sentineld::daemon::format_ts_pub(now);
        a.message = g.message();
        a.event = g.event();
        daemon.raise(a);
    }
    if degraded {
        let now = kernel.lock().map(|k| k.wall_ms()).unwrap_or(0);
        let mut a = daemon.blank_alert("degraded", "critical", "alerted");
        a.ts = sentineld::daemon::format_ts_pub(now);
        a.message =
            "LSM programs did not attach: observe only, no deny, no self-guard, no lockdown"
                .to_string();
        daemon.raise(a);
    }

    let daemon = Arc::new(Mutex::new(daemon));
    let stop = Arc::new(AtomicBool::new(false));
    let dns_connected = Arc::new(AtomicBool::new(false));

    // 6. Threads.
    let hb = {
        let kernel = kernel.clone();
        let stop = stop.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                if let Ok(mut k) = kernel.lock() {
                    let now = k.monotonic_ns();
                    let _ = k.heartbeat(now);
                }
                std::thread::sleep(HEARTBEAT_INTERVAL);
            }
        })
    };

    let drain = {
        let daemon = daemon.clone();
        let kernel = kernel.clone();
        let stop = stop.clone();
        std::thread::spawn(move || {
            let Some(mut ring) = ring else { return };
            sentineld::drain(&mut ring, daemon, kernel, stop);
        })
    };

    let listener = sentineld::varlink::bind(&cli.socket)
        .with_context(|| format!("cannot bind {}", cli.socket.display()))?;
    let svc = Arc::new(sentineld::varlink::Service {
        daemon: daemon.clone(),
        watchers: Arc::new(Mutex::new(Vec::new())),
        kernel: kernel.clone(),
        rules_dir: cli.rules.clone(),
    });

    let dns = {
        let daemon = daemon.clone();
        let kernel = kernel.clone();
        let connected = dns_connected.clone();
        let stop = stop.clone();
        std::thread::spawn(move || sentineld::dns::run(daemon, kernel, connected, stop))
    };

    // 7. Ready.
    let health = if degraded { Health::Degraded } else { Health::Ok };
    status::write_state(&cli.state, health)
        .with_context(|| format!("cannot write {}", cli.state.display()))?;
    if let Ok(mut d) = daemon.lock() {
        d.status = Some(sentineld::status::Status {
            version: env!("CARGO_PKG_VERSION").to_string(),
            health,
            programs: attached,
            heartbeat_age_ms: 0,
            lockdown_active: false,
            lockdown_counts: vec![0; sentineld::kernel::NHOOKS],
            kernel_rules: d.rules.counts().0,
            user_rules: d.rules.counts().1,
            audit_rules: 0,
            generation: d.generation.clone(),
            drops: 0,
            quarantines: 0,
            dns_monitor: false,
            store_error: None,
        });
    }
    status::notify_ready();
    eprintln!("sentineld: ready ({})", health.as_str());

    // 8. Serve until a signal arrives. `RefuseManualStop` means this is only
    //    reached on shutdown or `systemctl kill` (spec §8.2 known limit).
    for conn in listener.incoming() {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        match conn {
            Ok(c) => {
                let svc = svc.clone();
                std::thread::spawn(move || sentineld::varlink::serve_conn(c, svc));
            }
            Err(e) => eprintln!("sentineld: accept failed: {e}"),
        }
    }

    stop.store(true, Ordering::Relaxed);
    let _ = hb.join();
    let _ = drain.join();
    let _ = dns.join();
    Ok(())
}
```

- [ ] **Step 4: Write the ring drain in the library**

Append to `lib.rs` (it needs `Daemon`, `Kernel` and the ring, and `main` is a thin binary):

```rust
/// Drain the `EVENTS` ring until `stop`. Blocks in `poll` on the ring fd, so
/// an idle daemon costs nothing (spec §13: under 1 % of one core).
pub fn drain(
    ring: &mut aya::maps::RingBuf<aya::maps::MapData>,
    daemon: std::sync::Arc<std::sync::Mutex<daemon::Daemon>>,
    kernel: std::sync::Arc<std::sync::Mutex<Box<dyn kernel::Kernel>>>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    use std::os::fd::AsRawFd;
    use std::sync::atomic::Ordering;

    let fd = ring.as_raw_fd();
    let mut since_drop_check = 0u32;
    while !stop.load(Ordering::Relaxed) {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pfd is a valid single-element pollfd array; 250 ms timeout
        // so `stop` is noticed even when the ring stays quiet.
        let rc = unsafe { libc::poll(&mut pfd, 1, 250) };
        if rc < 0 {
            continue;
        }
        while let Some(item) = ring.next() {
            if item.len() < core::mem::size_of::<sentinel_common::wire::RawEvent>() {
                continue;
            }
            // SAFETY: length checked above; RawEvent is repr(C) plain data and
            // a ring item is not necessarily aligned.
            let ev = unsafe {
                core::ptr::read_unaligned(
                    item.as_ptr() as *const sentinel_common::wire::RawEvent
                )
            };
            drop(item);
            if let (Ok(mut d), Ok(mut k)) = (daemon.lock(), kernel.lock()) {
                d.on_event(&ev, k.as_mut().as_mut());
            }
        }
        since_drop_check += 1;
        // Roughly every 4 quiet seconds, or sooner under load.
        if since_drop_check >= 16 {
            since_drop_check = 0;
            if let (Ok(mut d), Ok(mut k)) = (daemon.lock(), kernel.lock()) {
                d.check_drops(k.as_mut().as_mut());
            }
        }
    }
}
```

and expose the timestamp helper `main` uses, in `daemon.rs`:

```rust
/// `Daemon::format_ts`, for callers outside the type.
pub fn format_ts_pub(ms: u64) -> String {
    Daemon::format_ts(ms)
}
```

- [ ] **Step 5: Verify it builds and the suite still passes**

Run: `cd sentinel && cargo build -p sentineld && cargo test -p sentineld && cargo clippy -p sentineld --all-targets -- -D warnings`
Expected: builds, all tests pass, no warnings.

Run: `cd sentinel && ./target/debug/sentineld --help`
Expected: the flag list, exit 0.

Run: `cd sentinel && ./target/debug/sentineld --config /nonexistent --rules /nonexistent`
Expected: exits non-zero with `invalid rules: /nonexistent: cannot read rules directory`. This is the §12 "rules invalid at boot" path, reachable without root because it fails before loading anything.

- [ ] **Step 6: Commit**

```bash
git add sentinel/crates/sentineld/src/main.rs sentinel/crates/sentineld/src/dns.rs sentinel/crates/sentineld/src/lib.rs sentinel/crates/sentineld/src/daemon.rs
git commit -m "feat(sentineld): daemon wiring, ring drain, DNS monitor and the exit paths"
```

---

## Task 21: The `sentinel` CLI

**Files:**
- Create: `sentinel/crates/sentinel/src/client.rs`
- Modify: `sentinel/crates/sentinel/src/main.rs`

Spec §10.2: `sentinel status` · `alerts [--since 1h] [--min high] [--json]` · `show <id>` · `watch` · `quarantine list|release <id>|kill <id>` · `rules list` · `rules check <dir>` (offline, the same validation as `aios plan`) · `verify`. Mutating commands need `run0` — that is the user's job, but the CLI must print a clear message when the daemon refuses.

- [ ] **Step 1: Write the failing tests**

Create `sentinel/crates/sentinel/src/client.rs` with the tests first:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_call_is_nul_terminated_and_names_the_interface() {
        let out = encode_call("Status", serde_json::json!({}), false);
        assert_eq!(out.last(), Some(&0u8));
        let v: serde_json::Value = serde_json::from_slice(&out[..out.len() - 1]).unwrap();
        assert_eq!(v["method"], "io.aios.Sentinel.Status");
        assert!(v.get("more").is_none());

        let out = encode_call("WatchAlerts", serde_json::json!({}), true);
        let v: serde_json::Value = serde_json::from_slice(&out[..out.len() - 1]).unwrap();
        assert_eq!(v["more"], true);
    }

    #[test]
    fn an_error_reply_becomes_a_readable_message() {
        let v = serde_json::json!({
            "error": "io.aios.Sentinel.PermissionDenied",
            "parameters": {"method": "Release", "uid": 1000}
        });
        let e = reply_error(&v).expect("an error");
        assert!(e.contains("PermissionDenied"), "{e}");
        assert!(e.contains("run0"), "the hint names run0: {e}");

        let v = serde_json::json!({
            "error": "io.aios.Sentinel.NoSuchAlert",
            "parameters": {"id": "A9"}
        });
        let e = reply_error(&v).unwrap();
        assert!(e.contains("NoSuchAlert") && e.contains("A9"), "{e}");

        assert!(reply_error(&serde_json::json!({"parameters": {}})).is_none());
    }

    #[test]
    fn relative_times_become_timestamps() {
        // 2026-11-12T12:00:00Z as milliseconds.
        let now = 1_794_571_200_000u64;
        assert_eq!(since_to_ts("1h", now), Some("2026-11-12T11:00:00.000Z".to_string()));
        assert_eq!(since_to_ts("30m", now), Some("2026-11-12T11:30:00.000Z".to_string()));
        assert_eq!(since_to_ts("2d", now), Some("2026-11-10T12:00:00.000Z".to_string()));
        assert_eq!(since_to_ts("nonsense", now), None);
        // An explicit timestamp passes through.
        assert_eq!(
            since_to_ts("2026-11-01T00:00:00.000Z", now),
            Some("2026-11-01T00:00:00.000Z".to_string())
        );
    }

    #[test]
    fn the_alert_table_line_is_aligned_and_complete() {
        let a = serde_json::json!({
            "id": "01JCZZ", "ts": "2026-11-12T16:42:51.123Z", "rule": "reverse-shell",
            "severity": "high", "outcome": "frozen",
            "process": {"pid": 4242, "exe": "/usr/bin/bash"}
        });
        let line = alert_line(&a);
        for want in ["01JCZZ", "16:42:51", "reverse-shell", "high", "frozen", "4242", "/usr/bin/bash"] {
            assert!(line.contains(want), "{want:?} missing from {line:?}");
        }
    }

    #[test]
    fn an_alert_without_a_process_still_renders() {
        let a = serde_json::json!({
            "id": "01JD00", "ts": "2026-11-12T16:00:00.000Z", "rule": "lockdown-gap",
            "severity": "critical", "outcome": "alerted",
            "message": "lockdown was active for 20.0 s"
        });
        let line = alert_line(&a);
        assert!(line.contains("lockdown-gap"));
        assert!(line.contains("lockdown was active"), "the message stands in: {line}");
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd sentinel && cargo test -p sentinel`
Expected: FAIL to compile — `cannot find function encode_call`.

- [ ] **Step 3: Write the client**

Insert above the `tests` module in `client.rs`:

```rust
//! A varlink client for `io.aios.Sentinel` (spec §10.2).

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

use anyhow::{bail, Result};

pub const INTERFACE: &str = "io.aios.Sentinel";
pub const SOCKET_PATH: &str = "/run/aios-sentinel/io.aios.Sentinel";

/// One call, NUL-terminated.
pub fn encode_call(method: &str, parameters: serde_json::Value, more: bool) -> Vec<u8> {
    let mut v = serde_json::json!({
        "method": format!("{INTERFACE}.{method}"),
        "parameters": parameters,
    });
    if more {
        v["more"] = true.into();
    }
    let mut out = serde_json::to_vec(&v).unwrap_or_default();
    out.push(0);
    out
}

/// A readable message for an error reply, or `None` if it is not an error.
pub fn reply_error(v: &serde_json::Value) -> Option<String> {
    let name = v.get("error")?.as_str()?;
    let short = name.rsplit('.').next().unwrap_or(name);
    let params = v.get("parameters").cloned().unwrap_or_default();
    let detail = match short {
        "PermissionDenied" => {
            " — this command changes something, so it needs root: re-run it with run0".to_string()
        }
        "NoSuchAlert" => format!(
            " — no alert with id {}",
            params.get("id").and_then(|i| i.as_str()).unwrap_or("?")
        ),
        "NoSuchQuarantine" => format!(
            " — no quarantine with id {}",
            params.get("id").and_then(|i| i.as_str()).unwrap_or("?")
        ),
        "InvalidRules" => {
            let errs = params
                .get("errors")
                .and_then(|e| e.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|e| e.as_str())
                        .collect::<Vec<_>>()
                        .join("\n  ")
                })
                .unwrap_or_default();
            format!(":\n  {errs}")
        }
        _ => {
            let p = params.to_string();
            if p == "{}" {
                String::new()
            } else {
                format!(" {p}")
            }
        }
    };
    Some(format!("{short}{detail}"))
}

/// `1h`, `30m`, `2d`, or a timestamp passed through unchanged.
pub fn since_to_ts(spec: &str, now_ms: u64) -> Option<String> {
    if spec.contains('T') && spec.ends_with('Z') {
        return Some(spec.to_string());
    }
    let (num, unit) = spec.split_at(spec.len().checked_sub(1)?);
    let n: u64 = num.parse().ok()?;
    let ms = match unit {
        "s" => n * 1000,
        "m" => n * 60_000,
        "h" => n * 3_600_000,
        "d" => n * 86_400_000,
        _ => return None,
    };
    Some(format_ts(now_ms.saturating_sub(ms)))
}

/// The same RFC 3339 rendering the daemon uses.
pub fn format_ts(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    let millis = ms % 1000;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        y, m, d, rem / 3600, (rem % 3600) / 60, rem % 60, millis
    )
}

/// One line of `sentinel alerts`.
pub fn alert_line(a: &serde_json::Value) -> String {
    let s = |k: &str| a.get(k).and_then(|v| v.as_str()).unwrap_or("");
    let time = s("ts").split('T').nth(1).unwrap_or("").trim_end_matches('Z');
    let time = time.split('.').next().unwrap_or(time);
    let who = match a.get("process") {
        Some(p) if p.is_object() => format!(
            "pid {} {}",
            p.get("pid").and_then(|v| v.as_u64()).unwrap_or(0),
            p.get("exe").and_then(|v| v.as_str()).unwrap_or("")
        ),
        _ => s("message").to_string(),
    };
    format!(
        "{:<26}  {:<8}  {:<18}  {:<8}  {:<12}  {}",
        s("id"),
        time,
        s("rule"),
        s("severity"),
        s("outcome"),
        who
    )
}

/// A connected client.
pub struct Client {
    sock: UnixStream,
    pending: Vec<u8>,
}

impl Client {
    pub fn connect(path: &str) -> Result<Client> {
        let sock = UnixStream::connect(path).map_err(|e| {
            anyhow::anyhow!(
                "cannot reach sentineld at {path}: {e}\n\
                 Is aios-sentinel.service running, and are you root or in the wheel group?"
            )
        })?;
        Ok(Client {
            sock,
            pending: Vec::new(),
        })
    }

    /// One call, one reply.
    pub fn call(&mut self, method: &str, parameters: serde_json::Value) -> Result<serde_json::Value> {
        self.sock.write_all(&encode_call(method, parameters, false))?;
        let v = self.read_frame()?;
        if let Some(e) = reply_error(&v) {
            bail!("{e}");
        }
        Ok(v.get("parameters").cloned().unwrap_or_default())
    }

    /// A streaming call: `f` is invoked per reply until the peer closes.
    pub fn call_more(
        &mut self,
        method: &str,
        parameters: serde_json::Value,
        mut f: impl FnMut(&serde_json::Value),
    ) -> Result<()> {
        self.sock.write_all(&encode_call(method, parameters, true))?;
        loop {
            let v = match self.read_frame() {
                Ok(v) => v,
                Err(_) => return Ok(()),
            };
            if let Some(e) = reply_error(&v) {
                bail!("{e}");
            }
            if let Some(p) = v.get("parameters") {
                f(p);
            }
            if v.get("continues").and_then(|c| c.as_bool()) != Some(true) {
                return Ok(());
            }
        }
    }

    fn read_frame(&mut self) -> Result<serde_json::Value> {
        let mut buf = [0u8; 8192];
        loop {
            if let Some(i) = self.pending.iter().position(|b| *b == 0) {
                let frame: Vec<u8> = self.pending.drain(..=i).collect();
                return Ok(serde_json::from_slice(&frame[..frame.len() - 1])?);
            }
            let n = self.sock.read(&mut buf)?;
            if n == 0 {
                bail!("sentineld closed the connection");
            }
            self.pending.extend_from_slice(&buf[..n]);
        }
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd sentinel && cargo test -p sentinel`
Expected: 5 passed.

- [ ] **Step 5: Write `main.rs`**

```rust
mod client;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};

use client::{alert_line, since_to_ts, Client, SOCKET_PATH};

#[derive(Parser)]
#[command(about = "AIOS Sentinel control and inspection")]
struct Cli {
    /// The daemon's varlink socket.
    #[arg(long, default_value = SOCKET_PATH, global = true)]
    socket: String,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Programs, heartbeat, lockdown, rules, quarantines.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Recent alerts.
    Alerts {
        #[arg(long)]
        since: Option<String>,
        #[arg(long = "min")]
        min_severity: Option<String>,
        #[arg(long)]
        limit: Option<u64>,
        #[arg(long)]
        json: bool,
    },
    /// One alert in full.
    Show { id: String },
    /// Stream alerts as they are raised.
    Watch,
    /// Quarantines.
    #[command(subcommand)]
    Quarantine(QuarantineCmd),
    /// Rules.
    #[command(subcommand)]
    Rules(RulesCmd),
    /// Check the whole alert chain.
    Verify,
}

#[derive(Subcommand)]
enum QuarantineCmd {
    List,
    /// Thaw a quarantine and restore its processes (root).
    Release { id: String },
    /// Kill a quarantined process tree (root).
    Kill { id: String },
}

#[derive(Subcommand)]
enum RulesCmd {
    /// The rules the daemon has loaded.
    List,
    /// Validate a rule directory offline, like `aios plan` does.
    Check { dir: std::path::PathBuf },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // `rules check` is offline: it never touches the daemon (spec §10.2).
    if let Cmd::Rules(RulesCmd::Check { dir }) = &cli.cmd {
        return rules_check(dir);
    }

    let mut c = Client::connect(&cli.socket)?;
    match cli.cmd {
        Cmd::Status { json } => {
            let p = c.call("Status", serde_json::json!({}))?;
            let s = p.get("status").cloned().unwrap_or_default();
            if json {
                println!("{}", serde_json::to_string_pretty(&s)?);
            } else {
                print_status(&s);
            }
        }
        Cmd::Alerts {
            since,
            min_severity,
            limit,
            json,
        } => {
            let mut params = serde_json::Map::new();
            if let Some(s) = since {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                match since_to_ts(&s, now) {
                    Some(ts) => {
                        params.insert("since".to_string(), ts.into());
                    }
                    None => bail!("--since {s:?} is not a duration (1h, 30m, 2d) or a timestamp"),
                }
            }
            if let Some(m) = min_severity {
                params.insert("minSeverity".to_string(), m.into());
            }
            if let Some(l) = limit {
                params.insert("limit".to_string(), l.into());
            }
            let p = c.call("ListAlerts", serde_json::Value::Object(params))?;
            let alerts = p.get("alerts").and_then(|a| a.as_array()).cloned().unwrap_or_default();
            if json {
                println!("{}", serde_json::to_string_pretty(&alerts)?);
            } else if alerts.is_empty() {
                println!("no alerts");
            } else {
                for a in &alerts {
                    println!("{}", alert_line(a));
                }
            }
        }
        Cmd::Show { id } => {
            let p = c.call("GetAlert", serde_json::json!({ "id": id }))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&p.get("alert").cloned().unwrap_or_default())?
            );
        }
        Cmd::Watch => {
            c.call_more("WatchAlerts", serde_json::json!({}), |p| {
                if let Some(a) = p.get("alert") {
                    println!("{}", alert_line(a));
                }
            })?;
        }
        Cmd::Quarantine(QuarantineCmd::List) => {
            let p = c.call("ListQuarantine", serde_json::json!({}))?;
            let qs = p
                .get("quarantines")
                .and_then(|q| q.as_array())
                .cloned()
                .unwrap_or_default();
            if qs.is_empty() {
                println!("no quarantines");
            }
            for q in qs {
                println!(
                    "{:<26}  root pid {:<7}  {} pid(s){}",
                    q.get("id").and_then(|v| v.as_str()).unwrap_or(""),
                    q.get("rootPid").and_then(|v| v.as_u64()).unwrap_or(0),
                    q.get("pids").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0),
                    if q.get("killed").and_then(|v| v.as_bool()) == Some(true) {
                        "  (killed)"
                    } else {
                        ""
                    }
                );
            }
        }
        Cmd::Quarantine(QuarantineCmd::Release { id }) => {
            c.call("Release", serde_json::json!({ "id": id }))?;
            println!("released {id}");
        }
        Cmd::Quarantine(QuarantineCmd::Kill { id }) => {
            c.call("Kill", serde_json::json!({ "id": id }))?;
            println!("killed {id}");
        }
        Cmd::Rules(RulesCmd::List) => {
            let p = c.call("Status", serde_json::json!({}))?;
            let s = p.get("status").cloned().unwrap_or_default();
            println!(
                "{} kernel rule(s), {} user-space rule(s), generation {}",
                s.get("kernelRules").and_then(|v| v.as_u64()).unwrap_or(0),
                s.get("userRules").and_then(|v| v.as_u64()).unwrap_or(0),
                s.get("generation").and_then(|v| v.as_str()).unwrap_or("-")
            );
        }
        Cmd::Rules(RulesCmd::Check { .. }) => unreachable!("handled above"),
        Cmd::Verify => {
            let p = c.call("VerifyChain", serde_json::json!({}))?;
            if p.get("ok").and_then(|o| o.as_bool()) == Some(true) {
                println!(
                    "alert chain is intact ({} record(s))",
                    p.get("records").and_then(|r| r.as_u64()).unwrap_or(0)
                );
            } else {
                bail!(
                    "alert chain is broken: {}",
                    p.get("error").and_then(|e| e.as_str()).unwrap_or("unknown")
                );
            }
        }
    }
    Ok(())
}

fn print_status(s: &serde_json::Value) {
    let g = |k: &str| s.get(k).cloned().unwrap_or(serde_json::Value::Null);
    println!("version        {}", g("version"));
    println!("health         {}", g("health"));
    println!("programs       {}", g("programs"));
    println!("heartbeat age  {} ms", g("heartbeatAgeMs"));
    println!("lockdown       {}", g("lockdownActive"));
    println!("rules          {} kernel, {} user", g("kernelRules"), g("userRules"));
    println!("generation     {}", g("generation"));
    println!("ring drops     {}", g("drops"));
    println!("quarantines    {}", g("quarantines"));
    println!("dns monitor    {}", g("dnsMonitor"));
    if let Some(e) = s.get("storeError").and_then(|e| e.as_str()) {
        println!("store error    {e}");
    }
}

/// Offline validation, the same `sentinel-rules` path `aios plan` uses.
fn rules_check(dir: &std::path::Path) -> Result<()> {
    match sentinel_rules::load_dir(dir) {
        Ok(rules) => match sentinel_rules::matcher::compile_all(&rules) {
            Ok((tables, user)) => {
                println!(
                    "{} rule(s) valid: {} kernel, {} user-space",
                    rules.len(),
                    tables.rules.len(),
                    user.len()
                );
                Ok(())
            }
            Err(errs) => {
                for e in &errs {
                    eprintln!("{e}");
                }
                bail!("{} rule(s) do not compile", errs.len())
            }
        },
        Err(errs) => {
            for e in &errs {
                eprintln!("{e}");
            }
            bail!("{} problem(s) in {}", errs.len(), dir.display())
        }
    }
}
```

- [ ] **Step 6: Verify the offline path works without a daemon**

Run: `cd sentinel && cargo build -p sentinel && ./target/debug/sentinel rules check ../manifest/sentinel/rules`
Expected: `14 rule(s) valid: N kernel, M user-space` (the exact split depends on Task 2; `ld-preload` and `reverse-shell` are both user-space).

Run: `cd sentinel && ./target/debug/sentinel status`
Expected: exits non-zero with `cannot reach sentineld at /run/aios-sentinel/io.aios.Sentinel` and the hint about the service and the wheel group.

Run: `cd sentinel && cargo clippy -p sentinel --all-targets -- -D warnings`
Expected: no warnings.

- [ ] **Step 7: Commit**

```bash
git add sentinel/crates/sentinel/src
git commit -m "feat(sentinel): the CLI - status, alerts, watch, quarantine, rules, verify"
```

---

## Task 22: VM scenarios for the daemon

**Files:**
- Create: `sentinel/tests/vm/scenarios/daemon.sh`
- Create: `sentinel/tests/vm/scenarios/freeze.sh`
- Create: `sentinel/tests/vm/scenarios/lockdown_report.sh`
- Modify: `sentinel/tests/vm/harness.sh` (build `sentineld` and `sentinel` too)
- Modify: `sentinel/tests/vm/README.md` (the scenario table)

Everything the unit tests cannot reach: the real loader, pinning, the ring drain, varlink over a real socket, a real freeze with a real cgroup, and the lockdown report after a gap. Read an existing scenario (`sentinel/tests/vm/scenarios/rules.sh`) first — these follow its shape exactly.

The harness runs the VM as root with the host filesystem at identical paths, so the scenarios use `--config`/`--rules`/`--alerts`/`--socket`/`--state` to keep everything in `/tmp`.

- [ ] **Step 1: Teach the harness to build both new binaries**

In `sentinel/tests/vm/harness.sh`, change the pre-boot build line to:

```bash
( cd "$ROOT/sentinel" && cargo build -p ebpf-loadtest -p sentineld -p sentinel )
```

- [ ] **Step 2: Write `scenarios/daemon.sh`**

```sh
#!/bin/sh
# Runs inside the VM as root.
# The daemon starts, pins, serves varlink, and the CLI can read it.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
SENTINEL=$(cd "$HERE/../../.." && pwd)
# shellcheck disable=SC1091
. "$SENTINEL/tests/vm/lib.sh"
cd "$SENTINEL"

mkdir -p /tmp/sd/rules /tmp/sd/alerts
cp ../manifest/sentinel/rules/*.toml /tmp/sd/rules/

./target/debug/sentineld \
    --config /nonexistent/sentinel.toml \
    --rules /tmp/sd/rules \
    --alerts /tmp/sd/alerts \
    --socket /tmp/sd/sock \
    --state /tmp/sd/state \
    >/tmp/sd/out 2>/tmp/sd/err &
DAEMON=$!
sleep 3

cat /tmp/sd/err
grep -qF "sentineld: ready" /tmp/sd/err || { echo "ASSERT FAIL: never became ready"; exit 1; }
[ "$(cat /tmp/sd/state)" = "ok" ] || { echo "ASSERT FAIL: state is $(cat /tmp/sd/state), want ok"; exit 1; }

# Pins outlive the process, so the kernel side keeps enforcing (spec 8.1).
for m in EVENTS HEARTBEAT RULES CONFIG QUARANTINE; do
    [ -e "/sys/fs/bpf/aios-sentinel/maps/$m" ] || { echo "ASSERT FAIL: map $m not pinned"; exit 1; }
done
[ -e /sys/fs/bpf/aios-sentinel/links/exec ] || { echo "ASSERT FAIL: exec link not pinned"; exit 1; }

./target/debug/sentinel --socket /tmp/sd/sock status >/tmp/sd/status 2>&1 || {
    echo "ASSERT FAIL: status failed"; cat /tmp/sd/status; exit 1; }
cat /tmp/sd/status
assert_contains /tmp/sd/status "health         ok"

# An exec that trips a rule must show up as an alert.
cp /bin/busybox /tmp/payload 2>/dev/null || cp /bin/sh /tmp/payload
LD_PRELOAD=/nonexistent.so /bin/true 2>/dev/null || true
sleep 2
./target/debug/sentinel --socket /tmp/sd/sock alerts --json >/tmp/sd/alerts.json 2>&1 || {
    echo "ASSERT FAIL: alerts failed"; cat /tmp/sd/alerts.json; exit 1; }
cat /tmp/sd/alerts.json
assert_contains /tmp/sd/alerts.json "ld-preload"

./target/debug/sentinel --socket /tmp/sd/sock verify >/tmp/sd/verify 2>&1 || {
    echo "ASSERT FAIL: verify failed"; cat /tmp/sd/verify; exit 1; }
assert_contains /tmp/sd/verify "alert chain is intact"

kill -TERM "$DAEMON" 2>/dev/null || true
echo "daemon: PASS"
```

- [ ] **Step 3: Write `scenarios/freeze.sh`**

```sh
#!/bin/sh
# A freeze rule really freezes: the cgroup exists, is frozen, is quarantined,
# and `release` puts the process back (spec 6).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
SENTINEL=$(cd "$HERE/../../.." && pwd)
# shellcheck disable=SC1091
. "$SENTINEL/tests/vm/lib.sh"
cd "$SENTINEL"

mkdir -p /tmp/fz/rules /tmp/fz/alerts
cat > /tmp/fz/rules/freeze.toml <<'RULES'
[[rule]]
id       = "freeze-marker"
desc     = "Freeze anything exec'ing the marker binary"
on       = "exec"
severity = "high"
action   = "freeze"
match    = { exe = ["/tmp/marker"] }
RULES

cp /bin/sleep /tmp/marker

./target/debug/sentineld \
    --config /nonexistent/sentinel.toml \
    --rules /tmp/fz/rules \
    --alerts /tmp/fz/alerts \
    --socket /tmp/fz/sock \
    --state /tmp/fz/state \
    >/tmp/fz/out 2>/tmp/fz/err &
DAEMON=$!
sleep 3
grep -qF "sentineld: ready" /tmp/fz/err || { echo "ASSERT FAIL: not ready"; cat /tmp/fz/err; exit 1; }

/tmp/marker 60 &
VICTIM=$!
sleep 3

./target/debug/sentinel --socket /tmp/fz/sock quarantine list >/tmp/fz/q 2>&1
cat /tmp/fz/q
grep -qF "root pid" /tmp/fz/q || { echo "ASSERT FAIL: nothing quarantined"; cat /tmp/fz/err; exit 1; }
QID=$(awk '{print $1; exit}' /tmp/fz/q)
echo "quarantine $QID"

CG="/sys/fs/cgroup/aios-sentinel.slice/q-$QID"
[ -d "$CG" ] || { echo "ASSERT FAIL: $CG missing"; exit 1; }
grep -q 1 "$CG/cgroup.freeze" || { echo "ASSERT FAIL: cgroup not frozen"; exit 1; }
grep -qw "$VICTIM" "$CG/cgroup.procs" || { echo "ASSERT FAIL: victim not in the cgroup"; cat "$CG/cgroup.procs"; exit 1; }

./target/debug/sentinel --socket /tmp/fz/sock quarantine release "$QID" >/tmp/fz/rel 2>&1 || {
    echo "ASSERT FAIL: release failed"; cat /tmp/fz/rel; exit 1; }
assert_contains /tmp/fz/rel "released"
[ -d "$CG" ] && { echo "ASSERT FAIL: cgroup survived the release"; exit 1; }

kill -9 "$VICTIM" 2>/dev/null || true
kill -TERM "$DAEMON" 2>/dev/null || true
echo "freeze: PASS"
```

- [ ] **Step 4: Write `scenarios/lockdown_report.sh`**

```sh
#!/bin/sh
# After a daemon dies and a new one starts, the gap and the per-hook denial
# counts are reported as a critical alert (spec 8.3).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
SENTINEL=$(cd "$HERE/../../.." && pwd)
# shellcheck disable=SC1091
. "$SENTINEL/tests/vm/lib.sh"
cd "$SENTINEL"

mkdir -p /tmp/lk/rules /tmp/lk/alerts
cp ../manifest/sentinel/rules/*.toml /tmp/lk/rules/

start() {
    ./target/debug/sentineld \
        --config /nonexistent/sentinel.toml \
        --rules /tmp/lk/rules \
        --alerts /tmp/lk/alerts \
        --socket "/tmp/lk/sock$1" \
        --state /tmp/lk/state \
        >"/tmp/lk/out$1" 2>"/tmp/lk/err$1" &
    echo $!
}

D1=$(start 1)
sleep 3
grep -qF "sentineld: ready" /tmp/lk/err1 || { echo "ASSERT FAIL: first daemon not ready"; cat /tmp/lk/err1; exit 1; }

# SIGKILL: no clean-up, so the heartbeat goes stale and the kernel locks down.
kill -9 "$D1"
sleep 8

# During the gap, a non-/usr exec must be refused (spec 8.3).
cp /bin/true /tmp/gap_test
if /tmp/gap_test 2>/dev/null; then
    echo "ASSERT FAIL: a non-/usr exec ran during the lockdown"
    exit 1
fi
echo "lockdown refused the /tmp exec"

D2=$(start 2)
sleep 3
grep -qF "sentineld: ready" /tmp/lk/err2 || { echo "ASSERT FAIL: second daemon not ready"; cat /tmp/lk/err2; exit 1; }

./target/debug/sentinel --socket /tmp/lk/sock2 alerts --json >/tmp/lk/alerts.json 2>&1
cat /tmp/lk/alerts.json
assert_contains /tmp/lk/alerts.json "lockdown-gap"
assert_contains /tmp/lk/alerts.json "critical"

# The chain spans both daemons.
./target/debug/sentinel --socket /tmp/lk/sock2 verify >/tmp/lk/verify 2>&1 || {
    echo "ASSERT FAIL: chain broken across the restart"; cat /tmp/lk/verify; exit 1; }
assert_contains /tmp/lk/verify "alert chain is intact"

kill -TERM "$D2" 2>/dev/null || true
echo "lockdown_report: PASS"
```

- [ ] **Step 5: Run each scenario**

Run: `cd sentinel && cargo run -p xtask -- vmtest daemon`
Expected: `daemon: PASS`.

Run: `cd sentinel && cargo run -p xtask -- vmtest freeze`
Expected: `freeze: PASS`.

Run: `cd sentinel && cargo run -p xtask -- vmtest lockdown_report`
Expected: `lockdown_report: PASS`.

These are the first time the real loader, the pinning and the varlink socket run at all. Expect to iterate: when one fails, the daemon's stderr is in the scenario's `err` file and the scenario prints it. Do **not** weaken an assertion to make a scenario pass — fix the daemon.

- [ ] **Step 6: Run the whole suite**

Run: `make sentinel-vmtest`
Expected: every scenario PASS, 26 in total (23 from S2 plus these 3). `xtask vmtest all` discovers scenarios from the directory, so no list needs editing; confirm by reading `sentinel/xtask/src/main.rs` and add them to its list if it is hard-coded.

- [ ] **Step 7: Update the scenario table in `sentinel/tests/vm/README.md`**

Add three rows, in the table's alphabetical order:

```markdown
| `daemon` | `sentineld` starts, pins its maps and links, serves varlink; the CLI reads status, alerts and the chain. |
| `freeze` | A freeze rule quarantines a process: the cgroup exists, is frozen, holds the pid; `release` restores it. |
| `lockdown_report` | After a SIGKILLed daemon, a non-`/usr` exec is refused during the gap, and the next daemon reports the gap as a critical alert. |
```

- [ ] **Step 8: Commit**

```bash
git add sentinel/tests/vm sentinel/xtask
git commit -m "test(sentinel): VM scenarios for the daemon, freeze and the lockdown report"
```

---

## Task 23: `make check`, the spec amendments and the S4 handoff

**Files:**
- Modify: `Makefile` (the `sentinel-check` target)
- Modify: `.github/workflows/ci.yml` if the build step needs the new crates named
- Modify: `docs/superpowers/specs/2026-11-12-sentinel-core-design.md` (§17)
- Create: `sentinel/crates/sentineld/README.md`

- [ ] **Step 1: Make sure `make check` builds and tests the new crates**

`sentinel-check` already runs `cargo test --workspace`, so the new unit tests are picked up. It also runs `cargo build -p ebpf-loadtest` to prove the kernel object builds; `sentineld` now embeds the same object, so extend that line:

```makefile
	cd sentinel && PATH="$$HOME/.cargo/bin:$$PATH" $(CARGO) build -p ebpf-loadtest -p sentineld -p sentinel
```

Run: `make check`
Expected: everything passes. This is the gate the project's success criteria name (§1), so it must be green before the branch moves on.

- [ ] **Step 2: Check CI still passes**

The CI job already installs the pinned nightly, `rust-src`, clang, `libelf-dev` and `libbpf-dev` (commits `2512681`, `cd250f1`), and runs `make check`. Nothing new is needed unless a step names crates explicitly — read `.github/workflows/ci.yml` and confirm.

```bash
git push origin feat/sentinel
```

Then watch the run and do not call S3 done until it is green:

```bash
gh run watch "$(gh run list --branch feat/sentinel --limit 1 --json databaseId --jq '.[0].databaseId')"
```

The dev box hides CI-only gaps — that is exactly how S2 ended, with two bugs that only a clean runner found.

- [ ] **Step 3: Append the S3 amendments to spec §17**

Add amendments 7–10 (their full text is in "Spec amendments this plan introduces" above) and then a new subsection:

```markdown
### 17.8 S3 outcomes (`sentineld` and the CLI)

Recorded at the end of S3 (plan `docs/superpowers/plans/2026-11-13-sentinel-s3-daemon.md`).

**Settled implementation choices:**

- The daemon is synchronous and thread-per-concern; the varlink transport is hand-written (amendment 7). Threads: ring drain (blocking `poll` on the ring fd), heartbeat (500 ms), varlink listener (one thread per client), resolved monitor.
- Every kernel effect goes through the `Kernel` trait, so dispatch, actions, the alert chain and `LoadGeneration` are unit-tested on the host with `FakeKernel`.
- `env_ld` and `stdio_socket` moved to user space (amendment 8); `ld-preload` is a user rule now.
- Alert ids are ULIDs, and a freeze names its cgroup `q-<alert-id>`, so an alert and its quarantine share one identifier.
- Alert context comes from one time-bounded ring filtered to the tree (amendment 9).
- `SOCK_DESTROY` is issued over `NETLINK_SOCK_DIAG` after matching `/proc/<pid>/fd` socket inodes against a `sock_diag` dump.

**Deferred to S4 and S5:**

- The systemd unit, the PKGBUILD, the manifest `[sentinel]` wiring, the plan/apply rendering, the `LoadGeneration` call from `aios apply`, and the health check (all §11) are S4. `sentineld` already implements the daemon half of each: `Type=notify` readiness, `/run/aios-sentinel/state`, and the `LoadGeneration` varlink method.
- `--home-binds` is a file of manifest-managed home targets; S4 renders it from the home binds so `managed_home` and `persistence-write` work (§5.5, amendment 5). Until then the list is empty and `persistence-write` cannot fire.
- The resolved DNS monitor is implemented but exercised only by the S5 gauntlet; no VM scenario covers it.
- `Status.auditRules` is reported as 0; counting audit-mode rules needs a small addition to `RuleSet::counts`.

**Known gaps:**

- `Status.heartbeatAgeMs`, `lockdownActive`, `lockdownCounts`, `drops` and `dnsMonitor` are filled once at start; refreshing them per `Status` call needs the varlink thread to take the kernel lock. Low risk, left for S4 to do alongside the health check that reads them.
- PID 1 may still signal the daemon (§8.2 known limit, follow-up 5). The lockdown covers that case and `lockdown_report` proves it.
```

- [ ] **Step 4: Write the S4 handoff**

Create `sentinel/crates/sentineld/README.md`, in the shape of `sentinel-ebpf/README.md` (which was S2's handoff to S3):

```markdown
# sentineld: what S4 inherits

The daemon (spec §6–§10, §12–§13). S4 packages it and wires it into the
manifest; this is the interface it should package against.

## Binaries

- `sentineld` — the daemon. Flags: `--config` (default
  `/etc/aios/sentinel/sentinel.toml`), `--rules`
  (`/etc/aios/sentinel/rules.d`), `--alerts` (`/var/log/aios/sentinel`),
  `--socket` (`/run/aios-sentinel/io.aios.Sentinel`), `--state`
  (`/run/aios-sentinel/state`), `--home-binds` (a file of manifest-managed
  home targets, one per line).
- `sentinel` — the CLI. `sentinel rules check <dir>` runs offline and needs
  no daemon; everything else is a varlink client.

## What the unit must provide (spec §11.4)

`Type=notify` (the daemon sends `READY=1` once programs are attached and the
first heartbeat is written), `DefaultDependencies=no`, `After=local-fs.target`,
`Before=sysinit.target network-pre.target`, `Wants=network-pre.target`,
`RefuseManualStop=yes`, `Restart=always`, `RestartSec=1`,
`OOMScoreAdjust=-1000`, `WantedBy=sysinit.target`, `LogsDirectory=aios/sentinel`
(mode 0700).

## What the health check reads (spec §11.5)

`/run/aios-sentinel/state` contains exactly `ok` or `degraded`, written once
the daemon is ready. `degraded` means the LSM programs did not attach: observe
only, no deny, no self-guard, no lockdown. The health check counts degraded as
failed.

## Exit codes (spec §12)

The daemon exits non-zero, having pinned nothing, when: the config is invalid,
the rules are invalid, the kernel object fails to load, or BTF is missing. A
clean exit (0) also happens when `enable = false`. systemd restarts it; the
health check fails the generation.

## `LoadGeneration` (spec §11.3)

`aios apply` calls it over varlink as root:

    {"method":"io.aios.Sentinel.LoadGeneration",
     "parameters":{"gen":"gen-7","dir":"/etc/aios/sentinel/rules.d"}}

Reply on success: `{"parameters":{"ok":true,"changes":["reverse-shell: action freeze -> kill"]}}`,
and the daemon raises a critical `config-changed` alert. On failure:
`{"error":"io.aios.Sentinel.InvalidRules","parameters":{"errors":[…]}}` and the
current rules stay loaded. If the socket is not there, `aios apply` warns and
the rules take effect at the next boot.

## The alert record (spec §9)

`/var/log/aios/sentinel/alerts.jsonl`, one JSON object per line, rotating at
64 MiB to `alerts.<n>.jsonl` (1 is oldest). `hash` is SHA-256 over the record
without `hash`, canonical JSON (sorted keys, no whitespace); the first record
chains from 64 zeros. `sentinel verify` walks the whole chain.

## Pins (spec §8.1)

`/sys/fs/bpf/aios-sentinel/maps/<MAP>` and
`/sys/fs/bpf/aios-sentinel/links/<program>`. bpffs is a tmpfs, so a reboot
starts with nothing loaded and nothing enforced until the daemon first starts.

## Tests

`make check` covers the unit tests. `make sentinel-vmtest` runs 26 scenarios;
`daemon`, `freeze` and `lockdown_report` are S3's.
```

- [ ] **Step 5: Verify the whole gate once more and commit**

Run: `make check`
Expected: pass.

```bash
git add Makefile docs/superpowers/specs/2026-11-12-sentinel-core-design.md sentinel/crates/sentineld/README.md .github/workflows/ci.yml
git commit -m "docs(sentinel): S3 outcomes, S4 handoff, and make check wiring"
git push origin feat/sentinel
```

- [ ] **Step 6: Confirm CI is green before declaring S3 done**

```bash
gh run watch "$(gh run list --branch feat/sentinel --limit 1 --json databaseId --jq '.[0].databaseId')"
```

Expected: `check` and `audit` both succeed. If either fails, fix it on this branch — S3 is not done until a clean runner agrees.

---

## Self-review against the spec

Checked after writing, section by section.

| Spec section | Covered by |
|---|---|
| §6 actions: deny, freeze, kill, release, never-act-on, storm brake, failed action | Tasks 9, 10, 11, 13 |
| §7 process table, ancestors, context | Tasks 5, 6, 8 |
| §8.1 pinning and restart reuse | Task 18, scenario `daemon` |
| §8.2 self-guard | S2 (kernel side). S3 supplies `sentineld_tgid`, `CFG_SELFGUARD` and the guarded inodes — Task 18 |
| §8.3 heartbeat and the lockdown report | Tasks 15, 20, scenario `lockdown_report` |
| §9 alert record, chain, rotation, journal, TTY | Tasks 3, 4, 12 |
| §10.1 varlink, all eight methods, SO_PEERCRED | Tasks 16, 17 |
| §10.2 CLI, all nine commands | Task 21 |
| §12 error handling, every row of the table | Task 20 (load/rules/exit), 13 (store, action), 18 (degraded), 20 (resolved retry) |
| §13 budget | Task 20's `poll`-based drain and the ring caps of Task 6. **Not measured here** — the CPU and RSS assertions live in the S5 e2e, as §13 says |
| §14 Rust-unit bar, every item listed | Tasks 4, 6, 9, 10, 11, 13, 17 |

**Gaps I am leaving deliberately, each recorded in the §17.8 text of Task 23:**

- `Status` counters are filled at start, not refreshed per call.
- `auditRules` is always 0.
- `managed_home` is empty until S4 renders `--home-binds`, so `persistence-write` cannot fire yet. The S5 gauntlet expects it, so S4 must close this.
- The resolved DNS monitor has unit tests for its parsing but no VM scenario; S5's gauntlet is its first real exercise.

**Two places where the plan tells the implementer to trust the code over the plan**, because they are the likeliest drift: the aya 0.16 map and link APIs (Task 18), and the `inet_diag` struct offsets (Task 19). Both name the authority to check — the vendored crate source and `/usr/include/linux/inet_diag.h`.

