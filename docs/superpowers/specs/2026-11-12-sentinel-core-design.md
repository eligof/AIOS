# AIOS Sub-project 2a — Sentinel Core Design

Date: 2026-11-12
Status: Approved section by section during brainstorming (scope, actions, prevention, rule format, tamper resistance, test bar, approach, and design sections 1–4).
Parent: `2026-11-03-aios-vision.md` (§4 Sentinel preview). Builds on `2026-11-03-base-iso-design.md`.

## 1. Goal

An always-on host defense daemon, `sentineld`, that detects remote access trojans and intrusions on an AIOS host with eBPF, can stop them in the kernel before they act, and protects itself from being killed or blinded.

1. **See:** process execution, network connects and listeners, access to camera, microphone and input devices, ptrace, module and BPF loads, DNS queries.
2. **Decide:** declarative rules in the manifest, plus built-in detectors for C2 beacons and DNS tunnels.
3. **Act:** per rule, `alert`, `deny` (BPF-LSM refuses the syscall), `freeze` (quarantine cgroup, network cut) or `kill`.
4. **Resist tampering:** a root process can't kill, ptrace or blind `sentineld` within a boot. If it stops anyway, the kernel falls back to a narrow lockdown until it returns.
5. **Report:** a tamper-evident local alert log, the journal, the TTY, and a varlink API for the later Cockpit.

Sentinel data never leaves the machine (vision §2).

**Success criteria (v0.1):**

- `make check` passes without root, now including the `sentinel/` workspace (unit tests, clippy, the kernel crate's build).
- `make e2e` still passes (a)–(g) of the Base ISO spec with Sentinel enabled, and the Sentinel e2e (§14) passes: every gauntlet technique is detected with the expected rule and outcome, the Sliver implant is caught, every tamper attempt is refused or ends in lockdown, and a benign workload raises no alert of severity `medium` or above.

**Out of scope (later Sentinel specs):**

- **2b `rat-check` sweep:** persistence baseline/diff of `/persist`, `/home` and the manifest, YARA-X, abuse.ch IOC feeds, the cross-view hidden-process check, running processes whose executable was deleted after start.
- **2c interactive:** app-firewall prompts for new outbound connections and live HUD indicators. Both need the Cockpit (sub-project 3).
- **2d AI triage:** local-model incident summaries and multi-event correlation (sequences). Lands with the agent runtime (sub-project 4).
- Screencast detection (needs the compositor), per-process DNS attribution.

## 2. Threat model

- **In scope:** code running on the host as the user or as root, delivered by any means (phishing download, malicious package, exploited service, physical USB): reverse and bind shells, fileless loaders, C2 implants that beacon, keyloggers and input injectors, camera and microphone spying, process injection, BPF rootkits, attempts to stop or blind Sentinel.
- **Guarantee within one boot:** while Sentinel is enabled in the booted generation, no process, root included, can stop `sentineld`, detach its programs, load its own tracing or LSM BPF programs, or edit its alert log, without either being refused (critical alert) or triggering the lockdown (§8.3).
- **Across reboots:** root can change the manifest and run `aios apply`, the legitimate path for any system change. Sentinel raises a critical alert whenever a newly built generation changes Sentinel's configuration (§11.3), and the next boot of the old generation still has the old rules.
- **Not in scope:** a kernel exploit (an attacker in ring 0 wins), firmware and pre-boot attacks (Secure Boot and the TPM cover those, Base ISO §5.1), and hardware keyloggers.

## 3. Architecture

```
manifest repo (git)                                  generation /etc (read-only snapshot)
 [sentinel] + sentinel/rules/*.toml ── plan/apply ──▶ /etc/aios/sentinel/{sentinel.toml,rules.d/}
                                                         │ at boot, or LoadGeneration after apply
 kernel (pinned in /sys/fs/bpf/aios-sentinel/)           ▼
 ┌ sentinel-ebpf (Aya) ──────────────────────┐ ringbuf ┌ sentineld (root, Rust) ──────────────┐
 │ observe: exec/fork/exit, connect, listen, │ ──────▶ │ process table (events + /proc scan)  │
 │          sensitive opens, ptrace, bpf, …  │         │ rule engine: kernel tables + user    │
 │ enforce: LSM deny for kernel-side rules   │ ◀────── │ detectors: beacon, DNS tunnel        │
 │ guard:   LSM self-guard                   │  maps   │ actions: freeze / kill / net cut     │
 │ heartbeat check ⇒ lockdown                │         │ alert store (hash-chained JSONL)     │
 └───────────────────────────────────────────┘         │ varlink io.aios.Sentinel             │
 systemd-resolved Monitor (varlink) ── query names ───▶ └──────────┬───────────────────────────┘
                                             `sentinel` CLI · journal · TTY broadcast · Cockpit (later)
```

### 3.1 Code layout (`sentinel/`, its own Cargo workspace)

A separate workspace, because the kernel crate needs a nightly toolchain and the `bpfel-unknown-none` target, which the `aios-cli` workspace must not pick up.

| Crate | Purpose | Depends on |
|---|---|---|
| `sentinel-common` | `no_std` event structs, map keys and values, flags shared by kernel and user space | — |
| `sentinel-ebpf` | The Aya kernel programs (§4, §8). Nightly, `bpf-linker`, CO-RE via BTF, so one object runs on `linux-cachyos` and `linux-cachyos-lts` | `sentinel-common`, `aya-ebpf` |
| `sentinel-rules` | TOML schema, validation, compilation into kernel tables and user-space matchers. Pure: no I/O, no clock | `sentinel-common` |
| `sentinel-detect` | Beacon and DNS-tunnel detectors. Pure, time passed in | — |
| `sentineld` | The daemon: loads and pins programs, reads the ring buffer, keeps the process table, runs rules and detectors, acts, stores alerts, serves varlink. The kernel object is embedded at build time | all of the above, `aya`, `tokio`, a varlink crate (`zlink` or equivalent) |
| `sentinel` | The CLI, a varlink client; `rules check` validates offline | `sentinel-common`, `sentinel-rules` |
| `xtask` | Builds the kernel object, then the user-space crates | — |

`aios-cli` path-depends on `sentinel-rules` so `aios plan` validates rules before anything is built (§11.2).

The kernel side is Rust (Aya). If one program can't be expressed in Aya, that program alone may be written in C and loaded with libbpf-rs; the plan must name it and say why.

## 4. Sensors

One BPF ring buffer (8 MiB) carries fixed-size events defined in `sentinel-common`. A per-CPU drop counter counts events the ring buffer refused; `sentineld` reports any increase as a `sensor-overflow` alert (flooding the sensor is a blinding technique).

| Event | Hook | Captured | Filtered in the kernel |
|---|---|---|---|
| `exec` | `tp_btf/sched_process_exec`, LSM `bprm_check_security` | pid, ppid, uid/euid, cgroup id, exe path, first 256 bytes of argv, flags: `memfd`, `deleted` (link count 0), `outside_usr` (the file's mount is not the read-only `/usr`), `stdio_socket` (fd 0, 1 or 2 is a socket), `env_ld` (`LD_PRELOAD` or `LD_LIBRARY_PATH` in the first 4 KiB of the new environment) | — |
| `fork`, `exit` | `tp_btf/sched_process_fork`, `sched_process_exit` | pid, ppid, exit code | — |
| `connect` | LSM `socket_connect` | pid, family, protocol, destination address and port | AF_UNIX and loopback skipped |
| `listen` | LSM `socket_listen` | pid, local address and port | AF_UNIX skipped |
| `open` | LSM `file_open` | pid, path, access mode, device class | Only device classes (camera: V4L2 major 81; mic: ALSA capture PCMs `/dev/snd/pcmC*D*c`; input: evdev major 13; `uinput`; `hidraw`) and Sentinel's own files |
| `write_refused` | `fexit/do_filp_open` returning `-EROFS` with write intent | pid, path as passed, dirfd; `sentineld` resolves it against the process's cwd or dirfd | Only `-EROFS` with `O_WRONLY`, `O_RDWR`, `O_CREAT` or `O_TRUNC`. A write to a read-only bind (the manifest-managed home targets of Base ISO §4.4) fails in the VFS before any LSM hook runs, so `file_open` never sees it |
| `memfd` | tracepoint `syscalls/sys_enter_memfd_create` | pid, name, flags | — |
| `ptrace` | LSM `ptrace_access_check` (also covers `/proc/<pid>/mem` and `process_vm_*`) | tracer, tracee, mode | Self-access skipped |
| `module` | LSM `kernel_read_file`, `kernel_load_data` | pid, file, type | Module loads only |
| `bpf` | LSM `bpf`, `bpf_prog_load` | pid, command, program type | — |
| `signal` | LSM `task_kill` | sender, target, signal | Only signals to `sentineld` |
| `dns` | systemd-resolved `io.systemd.Resolve.Monitor` (varlink, user space) | query name, type, response code | Host-level: no pid in v0.1 |

At start, `sentineld` builds the process table from `/proc`, then keeps it up to date from `exec`, `fork` and `exit`. Each entry keeps its ancestor chain, unit (from the cgroup) and the last 20 events of its tree for alert context. Raw events live only in memory, in a ring of about five minutes, and are never written to disk.

## 5. Rules

### 5.1 Location and format

Rules are TOML files in the manifest repo, under the directory `[sentinel] rules` names (default `sentinel/rules/`). `aios apply` renders them into the generation as `/etc/aios/sentinel/rules.d/*.toml`, so they are versioned, reviewed through `aios plan`, and rolled back with the generation.

```toml
[[rule]]
id       = "exec-memfd"                  # unique, [a-z0-9-]+
desc     = "Fileless execution from a memfd"
on       = "exec"                        # exec | connect | listen | open | write_refused | memfd | ptrace | module
severity = "critical"                    # info | low | medium | high | critical
action   = "deny"                        # alert | deny | freeze | kill
mode     = "enforce"                     # enforce | audit (default enforce)
match    = { exe_memfd = true }

[[rule]]
id       = "reverse-shell"
on       = "exec"
severity = "high"
action   = "freeze"
match    = { exe = ["/usr/bin/{bash,sh,zsh,dash}", "/usr/bin/python3*"], stdio_socket = true }
except   = { ancestors = ["/usr/bin/sshd"] }
```

- `match`: every listed predicate must hold. A list value matches if any element does.
- `except`: the rule does not fire if any listed predicate holds.
- `window = { count = 5, within = "60s", by = "exe" }` (optional): fire only when `count` matching events with the same `by` key (`exe`, `uid`, `unit` or `dest`) occur within `within`. Windows make a rule user-space only (§5.3).
- `mode = "audit"`: the action is not taken. The alert says what would have happened (`outcome = "would-deny"` and so on). New rules can be trialed this way.
- Rule files that fail to parse, unknown keys, duplicate ids, predicates that don't apply to the rule's `on`, empty matches, and globs that don't compile are errors.

### 5.2 Predicates

| Predicate | Applies to | Meaning | Kernel-evaluable |
|---|---|---|---|
| `exe_memfd`, `exe_deleted`, `exe_outside_usr`, `stdio_socket`, `env_ld` | exec | The flags of §4 | yes |
| `exe_on` | exec | The executable lives on one of these mount points (matched by mount identity, not path text, so symlinks and renames can't dodge it) | yes |
| `uid` | all | Real uid, or a list, or `"user"` (≥ 1000) / `"system"` (< 1000) | yes |
| `dest` | connect | CIDR list | yes |
| `port` | connect, listen | Port list or ranges | yes |
| `listen_scope` | listen | `non-loopback` | yes |
| `device` | open | `camera`, `mic`, `input`, `uinput`, `hidraw` | yes |
| `ptrace_target` | ptrace | `other-uid`, `non-descendant`, `any` | yes |
| `exe` | all | Glob on the resolved executable path | no |
| `argv` | exec | Glob on the joined argv | no |
| `parent`, `ancestors` | all | Glob on the parent's / any ancestor's executable | no |
| `unit` | all | Glob on the systemd unit of the process's cgroup | no |
| `path` | open, write_refused | Glob on the opened path | no |

### 5.3 Kernel rules and user-space rules

`deny` must be decided synchronously inside the LSM hook. So:

- A rule whose `match` and `except` use only kernel-evaluable predicates and has no `window` is a **kernel rule**. `sentinel-rules` compiles it into map entries the hook programs evaluate. A kernel rule may have any action.
- Every other rule is a **user-space rule**, evaluated by `sentineld` on the event. Its action may be `alert`, `freeze` or `kill`. `action = "deny"` on a user-space rule is a validation error that names the predicate that needs user space.

Kernel rules also emit their event with the verdict, so the alert carries full context from user space.

### 5.4 Built-in detectors

Configured in `[sentinel.beacon]` and `[sentinel.dns_tunnel]` (§11.1). Each has a `severity` and an `action` (`alert`, `freeze` or `kill`; default `alert`).

- **beacon:** per (executable, destination address, port), the intervals between connects over a sliding hour. Fires when there are at least `min_connects` (default 6) and the coefficient of variation of the intervals is at most `max_cov` (default 0.2, so up to about 20 % jitter is still periodic). `allow` lists destinations (CIDRs) and executables that are never reported (NTP, mirror checks, the resolver).
- **dns_tunnel:** per registered domain (public-suffix aware), from the resolved monitor: labels at least `label_len` long (default 20) with Shannon entropy above `entropy` bits per character (default 3.5), or more than `unique_per_min` distinct subdomains per minute (default 30). Host-level: the alert names the domain, not a process.

### 5.5 Default rule pack

Shipped in the default manifest as `sentinel/rules/default.toml` (copied by the installer like the rest of the defaults).

| id | on | match (except) | action | mode | severity |
|---|---|---|---|---|---|
| `exec-memfd` | exec | `exe_memfd` | deny | enforce | critical |
| `exec-deleted` | exec | `exe_deleted` | deny | enforce | high |
| `exec-shm` | exec | `exe_on = ["/dev/shm"]` | deny | enforce | high |
| `exec-tmp` | exec | `exe_on = ["/tmp", "/var/tmp"]` | deny | audit | medium |
| `reverse-shell` | exec | shells and interpreters with `stdio_socket` (ancestors `sshd`) | freeze | enforce | high |
| `ld-preload` | exec | `env_ld` | alert | — | medium |
| `ptrace-other` | ptrace | `ptrace_target = "non-descendant"` (exe: debuggers `/usr/bin/{gdb,lldb,strace}`) | alert | — | high |
| `camera-open` | open | `device = "camera"` | alert | — | low |
| `mic-open` | open | `device = "mic"` (exe: `pipewire`, `wireplumber`) | alert | — | low |
| `input-read` | open | `device = "input"` (exe: `systemd-logind`, the compositor once there is one) | alert | — | high |
| `uinput-open` | open | `device = "uinput"` | alert | — | high |
| `module-load` | module | any | alert | — | medium |
| `user-listener` | listen | `uid = "user"`, `listen_scope = "non-loopback"` | alert | — | medium |
| `persistence-write` | write_refused | `path` is one of the manifest-managed home targets (Base ISO §4.4; `sentineld` fills the list from the rendered home binds) | alert | — | medium |

`kernel.yama.ptrace_scope = 1` (Base ISO §5.2) already limits ptrace to descendants for non-root; `ptrace-other` catches root and the debugger exceptions.

## 6. Actions

- **deny:** the LSM hook returns `-EPERM`. The event carries the verdict and becomes an alert with `outcome = "denied"`.
- **freeze:** `sentineld` takes the process and all its descendants from the process table, creates `/sys/fs/cgroup/aios-sentinel.slice/q-<alert-id>/`, writes each pid to its `cgroup.procs`, rescans until no new descendant appears, and sets `cgroup.freeze = 1`. The cgroup id goes into the `quarantine` map: LSM `socket_connect` and `socket_sendmsg` deny for it, and its existing TCP and UDP sockets are destroyed (`bpf_sock_destroy` from a socket iterator). The original cgroup of each process is recorded. A sibling process can't thaw it, unlike `SIGSTOP`.
- **kill:** the same move, then `cgroup.kill = 1`, which kills the tree atomically even while it forks.
- **release** (`sentinel quarantine release <id>`, root): unfreeze, remove from the `quarantine` map, move the processes back to their recorded cgroups. **kill** (`sentinel quarantine kill <id>`): `cgroup.kill = 1`.
- **Never acted on:** PID 1, `sentineld`, `systemd-journald`, kernel threads, and units matching `never_act_on`. A rule that hits one alerts with `outcome = "suppressed"`.
- **Storm brake:** more than 5 automatic freezes or kills within a minute (configurable) and further hits only alert (`outcome = "braked"`), with a critical alert when the brake engages. A bad rule can't freeze the whole system.
- A failed action (a write to the cgroup filesystem fails, say) is a critical alert naming the error. The process is then neither frozen nor killed.

## 7. Process table and context

`sentineld` resolves for each event: executable path, argv, uid, unit (parsed from the cgroup path), parent and ancestor chain up to PID 1. User-space rules and detectors see the resolved event. Alerts include the ancestor chain and the last 20 events of the process tree (connects, opens, execs) as context.

## 8. Self-guard and lockdown

### 8.1 Pinning and lifetime

Programs, links and maps are pinned under `/sys/fs/bpf/aios-sentinel/`. A restarted `sentineld` reuses the pins instead of detaching and reattaching, so a restart leaves no gap. bpffs is a tmpfs: every reboot starts with nothing loaded, and nothing is enforced before `sentineld` first starts.

### 8.2 Self-guard (always on while Sentinel is enabled)

| Hook | Refuses |
|---|---|
| `task_kill` | Any user-sent signal to `sentineld`'s threads, except from PID 1 and from `sentineld` itself (kernel-generated signals don't pass this hook) |
| `ptrace_access_check` | `PTRACE_MODE_ATTACH` on `sentineld` from anyone; `PTRACE_MODE_READ` (`/proc/<pid>/exe`, `environ`, `mem` reads) except from PID 1 and `systemd-journald`, which read process metadata for the journal |
| `bpf`, `bpf_prog_load` | Loading programs of type kprobe, tracepoint, raw tracepoint, tracing (fentry/fexit/iter), LSM, perf event or extension, except by `sentineld`, PID 1 (systemd's `RestrictFileSystems=` is an LSM program) and the executables in `bpf_loaders`. Cgroup and socket-filter programs stay allowed for everyone (systemd's `IPAddressDeny=`, `DevicePolicy=`, socket filters). Also any `BPF_LINK_DETACH`, `BPF_*_GET_FD_BY_ID` or map update aimed at Sentinel's objects from another process |
| `file_open`, `inode_unlink`, `inode_rename`, `path_truncate` | Writing, renaming, truncating or unlinking anything under `/sys/fs/bpf/aios-sentinel/` or `/var/log/aios/sentinel/`, except by `sentineld` |

Every refusal is a critical alert with the actor's process tree. The unit adds `RefuseManualStop=yes`, `Restart=always`, `RestartSec=1` and `OOMScoreAdjust=-1000` (§11.4).

**Known limit:** PID 1 may still signal `sentineld` (`systemctl kill`). The lockdown covers that case.

### 8.3 Heartbeat lockdown

- `sentineld` writes the monotonic clock (ns, the clock `bpf_ktime_get_ns` reads) into the `heartbeat` map every second.
- Every enforcement hook first checks `ktime - heartbeat > lockdown_after` (default 5 s, allowed 2–30 s). No BPF timer is involved: the check runs lazily on each hook call.
- While stale, the lockdown is on:
  - `socket_connect` is denied for everything but AF_UNIX and loopback;
  - `bprm_check_security` is denied for executables not on the read-only `/usr`.
  - `/usr` programs still run, so a TTY login and recovery work. Self-guard and kernel rules stay in force.
- Lockdown denials are counted per hook in a pinned map. The next `sentineld` reports the gap's length and the counts as a critical alert, then resumes the heartbeat, which ends the lockdown.
- Before the first heartbeat of a boot there is no lockdown (nothing is loaded). If `sentineld` keeps crashing until systemd's start limit, the lockdown stays on for the rest of that boot. Recovery: reboot, and boot the previous generation if the new one's rules are at fault. The health check (§11.5) already makes that automatic for a generation whose Sentinel never starts.

## 9. Alerts

```json
{"id":"01JC…","ts":"2026-11-12T16:42:51.123Z","rule":"reverse-shell","severity":"high",
 "action":"freeze","mode":"enforce","outcome":"frozen",
 "process":{"pid":4242,"exe":"/usr/bin/bash","argv":"bash -i","uid":1000,"unit":"session-2.scope"},
 "ancestors":[{"pid":4100,"exe":"/home/user/Downloads/x"},{"pid":1,"exe":"/usr/lib/systemd/systemd"}],
 "event":{"on":"exec","stdio_socket":true},"context":[…],
 "prev_hash":"9f2c…","hash":"51ab…"}
```

- `id` is a ULID. `hash` = SHA-256 over the record without `hash`, in canonical JSON (sorted keys, no whitespace), which includes `prev_hash`. The first record of a fresh store chains from 64 zeros.
- Store: `/var/log/aios/sentinel/alerts.jsonl` (`/var/log` is persistent, Base ISO §2). It rotates at 64 MiB to `alerts.<n>.jsonl`, and the new file's first record chains from the old file's last hash. `sentinel verify` checks the whole chain. Self-guard keeps other writers out (§8.2).
- Journal: each alert is also logged (`SYSLOG_IDENTIFIER=sentineld`, `PRIORITY` from severity: critical 2, high 3, medium 4, low 5, info 6, `AIOS_SENTINEL_ALERT=<id>`).
- `high` and `critical` alerts are also written to every logged-in TTY (wall-style). The Cockpit replaces this later.

## 10. Interfaces

### 10.1 varlink `io.aios.Sentinel`

Socket `/run/aios-sentinel/io.aios.Sentinel`. The peer's credentials (`SO_PEERCRED`) decide access: root and the `wheel` group may read, only root may change anything.

| Method | Access | |
|---|---|---|
| `Status` | read | Version, programs attached, heartbeat age, lockdown state and counts, rules loaded (by kind and mode), loaded generation, ring buffer drops, quarantines |
| `ListAlerts(since?, min_severity?, limit?)`, `GetAlert(id)` | read | |
| `WatchAlerts` | read | Streams new alerts (`more: true`); the Cockpit's feed |
| `ListQuarantine` | read | |
| `Release(id)`, `Kill(id)` | root | §6 |
| `LoadGeneration(gen, files)` | root | §11.3 |
| `VerifyChain` | read | §9 |

### 10.2 CLI `sentinel`

`sentinel status` · `sentinel alerts [--since 1h] [--min high] [--json]` · `sentinel show <id>` · `sentinel watch` · `sentinel quarantine list|release <id>|kill <id>` · `sentinel rules list` · `sentinel rules check <dir>` (offline, the same validation as `aios plan`) · `sentinel verify`. Mutating commands need `run0`.

## 11. Base ISO integration

### 11.1 Manifest

```toml
[sentinel]
enable         = true
rules          = "sentinel/rules"      # directory in the manifest repo
lockdown_after = "5s"
storm_brake    = 5                      # automatic freezes/kills per minute
never_act_on   = ["systemd-*.service", "dbus-broker.service"]
bpf_loaders    = []                     # executables that may load tracing/LSM BPF besides sentineld

[sentinel.beacon]
min_connects = 6
max_cov      = 0.2
allow        = ["9.9.9.9/32", "149.112.112.112/32", "1.1.1.1/32"]

[sentinel.dns_tunnel]
label_len      = 20
entropy        = 3.5
unique_per_min = 30
```

The section is optional. Without it, Sentinel is enabled with these defaults. `aios-manifest` validates the section; `sentinel-rules` validates the rule files.

### 11.2 `aios plan`

Rule validation errors fail the plan like any manifest error. The diff prints a Sentinel summary: rules added, removed and changed, naming changed fields (`reverse-shell: action freeze → kill`), and any change to the `[sentinel]` section. Disabling Sentinel (`enable = false`) prints a warning, like `lockdown = "none"` does.

### 11.3 `aios apply` and rendering

- The renderer writes `/etc/aios/sentinel/sentinel.toml` (the `[sentinel]` section, resolved with defaults) and copies the rule files to `/etc/aios/sentinel/rules.d/`. Both are managed files of the generation.
- After a generation is built, `aios apply` calls `LoadGeneration(gen, files)` with those files as read from the new generation. `sentineld` validates them; if valid it swaps the kernel tables and user-space rules atomically, records the generation, and raises a critical alert "Sentinel configuration changed by gen-N (manifest commit X)" with the diff summary. If invalid it keeps the current rules, alerts, and returns the error, which `aios apply` prints as a warning (the generation is still built). If `sentineld` isn't running, `aios apply` warns and the rules take effect at the next boot.
- `enable = false` and changes to `lockdown_after` take effect only after a reboot into that generation; the apply-time alert still fires.

### 11.4 Package and unit

- `packaging/aios-sentinel/PKGBUILD` builds the workspace (`cargo xtask build --release`) and installs `/usr/bin/sentineld`, `/usr/bin/sentinel` and `/usr/lib/systemd/system/aios-sentinel.service`. Added to the Makefile `PACKAGES` and to the AIOS core package set; the unit joins the services AIOS always enables.
- Build host needs: the nightly toolchain pinned by `sentinel/rust-toolchain.toml` (with `rust-src`) and `bpf-linker` at a pinned version. `make tools` installs both without root (`rustup toolchain install`, `cargo install --locked`).
- `aios-sentinel.service`: `Type=notify` (ready once programs are attached and the first heartbeat is written), `DefaultDependencies=no`, `After=local-fs.target`, `Before=sysinit.target network-pre.target`, `Wants=network-pre.target`, `RefuseManualStop=yes`, `Restart=always`, `RestartSec=1`, `OOMScoreAdjust=-1000`, `WantedBy=sysinit.target`. Starting before the network and before any login means a home-directory autostart is watched from its first instruction.
- `/var/log/aios/sentinel/` is created by the unit (`LogsDirectory=aios/sentinel`, mode 0700).

### 11.5 Health check

`aios-health.sh` gains one check: when `/etc/aios/sentinel/sentinel.toml` has `enable = true`, `aios-sentinel.service` must be active and `/run/aios-sentinel/state` must read `ok` (`sentineld` writes `ok` or `degraded` there once it is ready, §12). `aios-health.service` is ordered `After=aios-sentinel.service`. A generation whose Sentinel can't start (bad rules, failed program load) therefore fails its health check, and the existing three-boot fallback (Base ISO §3) returns to the previous generation.

## 12. Error handling

| Failure | Behaviour |
|---|---|
| BTF or BPF-LSM missing, or the kernel object fails to load | `sentineld` exits with the verifier or loader error. Nothing is pinned, so there is no lockdown. systemd retries; the health check fails the generation (§11.5) |
| LSM programs fail to attach, tracing programs work | Degraded observe-only mode: `Status` and the journal say so, a critical alert is raised, no `deny`, no self-guard, no lockdown. The health check counts degraded as failed |
| Rules invalid at boot (can't pass `aios plan`, but a hand-edited runtime `/etc` could) | Exit with the validation error; same path as a load failure |
| Rules invalid at `LoadGeneration` | Keep the current rules, alert, return the error (§11.3) |
| Ring buffer full | Events dropped in the kernel, counted, `sensor-overflow` alert. Kernel rules and self-guard are unaffected (they decide in the hook) |
| User space falls behind | Oldest context events are dropped first; the kernel is never blocked |
| Action fails | Critical alert with the error (§6) |
| Alert store can't be written (disk full) | Alerts still go to the journal and the TTY; `Status` reports the store as failing; critical alert once the store works again |
| resolved monitor unavailable | DNS detection off, `Status` says so, retried every 30 s |

## 13. Resource budget

Measured on the e2e VM (4 GiB RAM) after the gauntlet: `sentineld` idle CPU below 1 % of one core averaged over 60 s, RSS at most 64 MiB, ring buffer 8 MiB, context ring at most 32 MiB. The e2e asserts the CPU and RSS limits.

## 14. Testing

| Layer | Tooling | What |
|---|---|---|
| Rust unit | `cargo test` in `sentinel/` (no root) | `sentinel-rules`: every validation error, kernel/user classification, compilation into map entries, match semantics on synthetic events, `except` and `window`. `sentinel-detect`: beacon on synthetic timelines (periodic, jittered, random, too few), DNS entropy and rate. `sentineld` logic behind a `Kernel` trait (maps, ring buffer, cgroupfs) with a fake, as `aios-exec` does with its `Runner`: process table upkeep, rule dispatch, freeze/kill/release sequences, storm brake, protected processes, `LoadGeneration` swap and rejection, heartbeat writes, alert chain, rotation and `verify` |
| Kernel build | `cargo xtask build` in `make check` | The kernel object builds; the verifier only runs in the VM |
| `aios-cli` | existing golden tests | `[sentinel]` validation, rule-file validation through `sentinel-rules`, plan diff summary, rendered `/etc/aios/sentinel/`, the `LoadGeneration` call after apply (fake runner) |
| Shell | bats | `aios-health.sh` with Sentinel enabled/disabled, active/inactive/degraded |
| E2E | `tests/e2e/test_sentinel.py`, same VM run, after the Base ISO tests | below |

**E2E gauntlet.** The harness builds a read-only CD-ROM image (xorriso) holding the gauntlet scripts, small test payloads and a Sliver implant, and attaches it to the VM. Each technique runs as the test user unless noted, and the test then asserts the alert (rule id, outcome) through `sentinel alerts --json`:

| Technique | Expected |
|---|---|
| memfd loader (`memfd_create` + `fexecve`) | `exec-memfd`, denied |
| Binary copied to `/dev/shm` and run | `exec-shm`, denied |
| Binary run from `/tmp` | `exec-tmp`, would-deny, still runs |
| Unlinked `O_TMPFILE` executed through `/proc/self/fd` | `exec-deleted`, denied |
| `bash -i` with stdio on a TCP socket to the host (`/dev/tcp`), and a Python pty shell | `reverse-shell`, frozen; quarantine cgroup frozen; `release` and `kill` work |
| `LD_PRELOAD=… /usr/bin/true` | `ld-preload` |
| Root ptrace attach to an unrelated process | `ptrace-other` |
| Open `/dev/input/event*` (QEMU adds a virtio keyboard), `/dev/uinput` | `input-read`, `uinput-open` |
| Listener on `0.0.0.0` as the user | `user-listener` |
| Write attempt on `~/.bashrc` (a read-only bind the user can't dodge, Base ISO §4.4) | `persistence-write` |
| Script that connects to the host every 5 s ± 10 % | beacon detector |
| 50 high-entropy subdomain lookups | dns_tunnel detector |
| **Sliver** implant (beacon mode, mTLS to `sliver-server` on the host via QEMU user networking, 5 s interval), run from `/tmp` | `exec-tmp` (would-deny) and the beacon detector, both within 2 minutes |
| Tamper as root: `kill -9 $(pidof sentineld)` | refused, critical alert |
| Tamper: load a kprobe program (a static test loader on the image) | refused, critical alert |
| Tamper: `systemctl stop aios-sentinel` | refused by systemd (`RefuseManualStop`) |
| Tamper: write to `/var/log/aios/sentinel/alerts.jsonl` | refused |
| Tamper: `systemctl kill -s SIGKILL aios-sentinel` | during the gap: a connect to the host and running a binary from `/home` both fail; after the restart: lockdown alert with both counts; `sentinel verify` passes |
| Benign workload before the gauntlet: `aios apply` of a package, `git clone` of the manifest repo, `usbguard list-rules`, `journalctl`, `man` | no alert of severity `medium` or above |
| Budget | CPU and RSS within §13 |

The Sliver server is a pinned release (version and SHA-256 in the Makefile, fetched by `make tools` into `build/tools/`). The harness starts it on a free port and generates the implant through its operator interface before the VM boots.

## 15. Repository layout additions

```
AIOS/
├─ sentinel/                     Cargo workspace (§3.1), rust-toolchain.toml, xtask/
├─ manifest/sentinel/rules/      default.toml (§5.5)
├─ packaging/aios-sentinel/      PKGBUILD
├─ base/aios-health.sh           + Sentinel check (§11.5)
└─ tests/e2e/                    test_sentinel.py, gauntlet/ (scripts, payload sources, image builder)
```

## 16. Follow-ups (tracked, not blocking v0.1)

1. 2b `rat-check` sweep, 2c firewall prompts and HUD, 2d AI triage and correlation (§1).
2. Per-process DNS attribution (hook the resolver's peer, or parse DNS in `socket_sendmsg`).
3. Screencast and screenshot detection once the compositor exists.
4. Multi-event sequence rules (`exec` then `connect` then `open camera`).
5. PID 1 signals to `sentineld` (§8.2 known limit): a systemd drop-in can't stop `systemctl kill`; a tighter answer needs knowing in the hook whether the system is shutting down.
6. Signing `aios-sentinel` together with repo signing (Base ISO follow-up #2): until then a root compromise can plant a modified package in `/persist/aios/repo` for the next apply, which the apply-time alert would show.
