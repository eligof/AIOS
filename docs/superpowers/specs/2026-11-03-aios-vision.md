# AIOS — Vision and Cross-Cutting Decisions

Date: 2026-11-03
Status: Approved during brainstorming
Working name: AIOS (final name TBD)

## 1. What AIOS is

AIOS is a personal, AI-driven, security-focused Linux distribution with a cyberpunk "cockpit" interface. It aims to do what Kali, Parrot and BlackArch do (offensive tooling) plus blue-team defense, while also being a safe, hardened daily driver.

Existing AI security tooling (HexStrike AI, Kali MCP server, PentAGI, PentestGPT) wraps an LLM around a tool dump on an otherwise unchanged OS. AIOS puts the security and AI properties into the OS itself.

**Core idea: "host is blue, ops are red."**

- **Host (HOME):** hardened, immutable-by-default daily driver that defends itself (Sentinel).
- **Ops:** each engagement runs in an isolated, scope-locked sandbox with its own network namespace, credentials, knowledge graph and audit trail. Offensive tools never run on the host.
- **Purple link:** findings from ops feed host defense.

## 2. Decisions

| Topic | Decision |
|---|---|
| Mission | Purple team (offense + defense) and hardened daily driver |
| v1 audience | The author only (personal daily driver). Share publicly later |
| Base | Custom Arch-based ISO (archiso) from day one, developed and tested in a KVM VM |
| NixOS-style security | Implemented on Arch by AIOS itself: generations (read-only btrfs snapshots of `/usr` + `/etc`), impermanent root, declarative manifest, atomic apply, boot-menu rollback |
| Packages | pacman + CachyOS repos (x86-64-v3) on the host. Flatpak for daily apps, distrobox/podman for dev envs, BlackArch containers for ops tools |
| Kernel | `linux-cachyos` with AIOS hardening; `linux-cachyos-lts` as fallback |
| Desktop paradigm | "Cockpit": fixed mission-control layout (knowledge graph left, apps/terminals center, agent + Sentinel feed right, audit timeline bottom). Always on. HOME = blue cockpit (left pane maps this machine), OP = red cockpit (target graph). Focus-mode hotkey collapses side panes to a slim HUD |
| Model policy | Local by default (Ollama). Sentinel and HOME data never leave the machine. A cloud strategist (e.g. Claude) is opt-in per op, behind a redaction layer (mask IPs, creds, client names; remap on return). Every cloud call is audited |
| Model tiers | Tier 0: local 2B/4B (always on, private). Tier 1: local 9B+ when hardware allows. Tier 2: cloud strategist, opt-in per op. The OS detects hardware and picks a tier. The author's laptop (RTX 2050 4 GB VRAM, 16 GB RAM) is the baseline target |
| Agent autonomy | T0 read-only: automatic. T1 active in-scope: automatic within a per-op rate/time budget, confirm beyond it. T2 exploitation: explicit per-action approval. T3 destructive/out-of-scope: always blocked, kernel-enforced. HOME: Sentinel may auto-isolate a process on high confidence; system changes only via an approved manifest diff |
| Privilege model | Privileged daemons (Sentinel, scope enforcer, manifest applier, audit log) in Rust. Agent runtime unprivileged, in Python, talking to daemons only via a defined IPC (varlink or D-Bus). The AI requests; daemons decide |
| Shell tech | Cockpit v1 in Quickshell (QML) on a Wayland compositor. A custom Smithay compositor is a possible v2 if compositor-level enforcement is needed |

## 3. Sub-projects and build order

Built foundation-first. Each layer is useful on its own.

| Order | Sub-project | Scope |
|---|---|---|
| 1 | **Base ISO** | archiso profile, installer, hardening, generations, impermanence, manifest + `aios` CLI |
| 2 | **Sentinel** | eBPF collectors, persistence baseline/diff, privacy watch (cam/mic/screen/input), YARA-X, IOC feeds, `rat-check`, incident correlation, local-model triage |
| 3 | **Cockpit shell** | Quickshell panes, HOME/OP contexts, focus mode, cyberpunk theme |
| 4 | **Agent runtime** | Model router, MCP tool interface, T0–T3 policy engine, approvals, hash-chained audit log, redaction |
| 5 | **Ops engine** | Op lifecycle, netns + eBPF/nftables scope enforcer, BlackArch toolset containers, knowledge graph, parsers, reports |

Each sub-project gets its own spec, plan and implementation cycle. The spec for sub-project 1 is `2026-11-03-base-iso-design.md`.

## 4. Sentinel preview (sub-project 2, recorded for continuity)

RAT detection on the host:

- **C2:** per-process `connect()` tracing via eBPF, beacon/jitter detection, DNS tunneling (entropy), app firewall prompts on new outbound connections.
- **Shell:** shells with socket stdin, odd parent chains, execution from `/tmp`/`/dev/shm`, deleted executables, `memfd` (fileless) execution.
- **Persistence:** with impermanence, only `/persist`, `/home` and `/var/log` survive reboot, so Sentinel baselines and diffs those plus the manifest.
- **Spying:** access to `/dev/input`, camera, mic and screencast, with live HUD indicators.
- **Hiding:** cross-view process check (`/proc` vs `ps` vs eBPF), `LD_PRELOAD` hooks.
- **Signatures:** YARA-X plus abuse.ch IOC feeds.
- **Reuse:** Tetragon or Falco, osquery (the AI writes SQL against system state), YARA-X, OpenSnitch.
- **Modes:** always-on daemon, and an on-demand `rat-check` deep sweep ending in an AI-written report.

## 5. Non-goals for v1

- Public distribution, a graphical installer, broad hardware certification.
- Building our own C2/RAT. Red-team C2 uses existing frameworks (Sliver, Mythic) inside scope-locked op sandboxes.
- Replacing pacman with Nix.
