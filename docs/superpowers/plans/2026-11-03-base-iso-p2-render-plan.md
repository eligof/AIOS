# Base ISO — Phase 2: Renderers + Planner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add two pure-logic crates on top of Phase 1. `aios-render` renders every file `aios apply` writes into a generation's `/etc`: the kernel cmdline, `fstab`, the two `tmpfiles.d` files, hostname/locale/vconsole/localtime, `loader.conf`, the managed-files list, and the merged `passwd`/`group`/`shadow`/`gshadow`. `aios-plan` defines the `SystemProbe` trait, computes the desired `/etc` state, and diffs it with the booted generation into the `Plan` that `aios plan` prints.

**Architecture:** Both crates join the `aios-cli/` workspace under `crates/`. `aios-render` is pure functions from `aios_manifest::Manifest` plus a `RenderCtx` to `String`. `aios-plan` builds a `BTreeMap<path, EtcEntry>` of the desired `/etc` from the renderers and the manifest repo, then compares it with the booted generation through the `SystemProbe` trait. Tests use an in-memory `FakeProbe` and a tempdir repo. No code in this phase runs a command, writes outside a tempdir or needs root. Phase 3 (`aios-exec`, the `aios` binary) supplies the real probe and writes these files into `@etc-cand`.

**Tech Stack:** Rust 2021 (rustup toolchain in `~/.cargo`), path dependencies on `aios-manifest` and `aios-gen`, `tempfile` 3 (dev only, from the workspace). No new external crates: the planner compares file bytes directly, so `sha2` is not needed.

**Spec:** `docs/superpowers/specs/2026-11-03-base-iso-design.md`, §2–§4. The relevant parts are §3 steps 3 and 9–10 (cmdline, fstab, tmpfiles), §4.1 (manifest), §4.2 (`aios plan`), §4.3 steps 5–7 (render, users, services), §4.4 (managed home paths), §4.5 (crate layout), §5.3–§5.4 (hardening cmdline, lockdown warning).

**Depends on:** Phase 1 (`docs/superpowers/plans/2026-11-03-base-iso-p1-core-crates.md`), complete and green. This plan uses exactly these Phase 1 APIs:
- `aios_manifest`: `parse`, `Manifest` (`system`, `kernel`, `services`, `files`, `persist`, `users`), `Lockdown::{Integrity, None}`, `FileEntry::{source, symlink, mode_or_default}`, `User::{uid, groups, shell, home}`, `Manifest::package_set`.
- `aios_gen`: `GenId` (`Display` as 4 digits, `usr_subvol`), `gen_from_cmdline`.

**Environment note for every task:** Rust is installed via rustup without PATH changes. Start every shell with:
```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/eli/Development/AIOS
```

**GateGuard note:** a local hook blocks the *first* Write/Edit of each new file, and the first Bash call, until you state some facts: callers/importers, that no existing file serves the purpose, data schema if any, and the user's instruction. Answer briefly in text and retry the same call. The user's instruction is: "finish this project, use skills and subagents".

**Conventions for this phase:**
- Tests are integration tests in each crate's `tests/` directory (public API only), one file per module. Shared fixtures live in `tests/common/mod.rs`, which starts with `#![allow(dead_code)]` because each test binary uses a different subset.
- Golden outputs are inline string constants in the tests (spec §4.5 says "golden files under `tests/golden/`"). This has the same effect, and the expected text sits next to the assertion.
- Expected counts are per test binary. `cargo test -p <crate> --test <name>` prints exactly one `test result:` line for that binary.
- Every code block is rustfmt-clean as written. If `cargo fmt --all -- --check` still reports a diff, run `cargo fmt --all` and continue; formatting never changes behavior.

---

## File Structure

```
aios-cli/Cargo.toml                                   workspace: add crates/aios-render, crates/aios-plan
aios-cli/Cargo.lock                                   committed (gains the two path crates)
aios-cli/crates/aios-render/Cargo.toml
aios-cli/crates/aios-render/src/lib.rs                module list + re-exports
aios-cli/crates/aios-render/src/ctx.rs                RenderCtx
aios-cli/crates/aios-render/src/cmdline.rs            cmdline()
aios-cli/crates/aios-render/src/home.rs               HomeBind, home_binds()
aios-cli/crates/aios-render/src/fstab.rs              fstab(), fstab_escape()
aios-cli/crates/aios-render/src/tmpfiles.rs           persist_tmpfiles(), home_tmpfiles(), persist_dirs()
aios-cli/crates/aios-render/src/simple.rs             hostname(), locale_conf(), locale_gen(), vconsole_conf(), localtime_target(), loader_conf()
aios-cli/crates/aios-render/src/managed.rs            managed_list(), parse_managed_list()
aios-cli/crates/aios-render/src/users.rs              PasswdEntry, GroupEntry, ShadowEntry, GshadowEntry, UserDb, UserFiles, UserDbError
aios-cli/crates/aios-render/src/merge.rs              merge_users(), MANAGED_IDS
aios-cli/crates/aios-render/tests/common/mod.rs       MANIFEST fixture, manifest(), manifest_from(), ctx()
aios-cli/crates/aios-render/tests/cmdline.rs
aios-cli/crates/aios-render/tests/home.rs
aios-cli/crates/aios-render/tests/fstab.rs            includes the exact fstab golden
aios-cli/crates/aios-render/tests/tmpfiles.rs
aios-cli/crates/aios-render/tests/simple.rs
aios-cli/crates/aios-render/tests/managed.rs
aios-cli/crates/aios-render/tests/users_db.rs         parse/render with Arch fixture lines
aios-cli/crates/aios-render/tests/users_merge.rs      merge golden + error cases
aios-cli/crates/aios-plan/Cargo.toml
aios-cli/crates/aios-plan/src/lib.rs                  module list + re-exports
aios-cli/crates/aios-plan/src/probe.rs                SystemProbe, EtcEntry, UnitState, ProbeError
aios-cli/crates/aios-plan/src/desired.rs              Inputs, PlanError, desired_etc(), MANAGED_FILES, GENERATION_TOML
aios-cli/crates/aios-plan/src/plan.rs                 ChangeKind, EtcChange, UnitChange, Plan, build_plan(), Display
aios-cli/crates/aios-plan/tests/common/mod.rs         MANIFEST, Fixture (tempdir repo), FakeProbe
aios-cli/crates/aios-plan/tests/desired.rs
aios-cli/crates/aios-plan/tests/plan.rs
```

---
### Task 1: Scaffold `aios-render`, `RenderCtx` and the kernel cmdline

**Files:**
- Modify: `aios-cli/Cargo.toml` (workspace members)
- Create: `aios-cli/crates/aios-render/Cargo.toml`, `aios-cli/crates/aios-render/src/lib.rs`, `aios-cli/crates/aios-render/src/ctx.rs`, `aios-cli/crates/aios-render/src/cmdline.rs`
- Test: `aios-cli/crates/aios-render/tests/common/mod.rs`, `aios-cli/crates/aios-render/tests/cmdline.rs`

- [ ] **Step 1: Check the baseline**

Run: `make check`
Expected: passes, with `aios-manifest` and `aios-gen` tests all `ok`. If `aios-cli/crates/aios-gen/src/id.rs` doesn't exist, Phase 1 isn't finished: stop and report BLOCKED.

Known Phase 1 lint issue: with the installed nightly clippy, `parse_subvol` exactly as written in the Phase 1 plan fails `clippy::question_mark` (`this block may be rewritten with the ? operator`, `crates/aios-gen/src/id.rs`). If that is the only failure, replace the function in `aios-cli/crates/aios-gen/src/id.rs` with the version below (same behavior; the `id.rs` tests still pass), re-run `make check`, and commit it as `fix(gen): satisfy clippy::question_mark in parse_subvol`. Any other failure means Phase 1 isn't finished: stop and report BLOCKED.

```rust
/// Parse `@usr-gen-NNNN` / `@etc-gen-NNNN`.
pub fn parse_subvol(name: &str) -> Option<(SubvolKind, GenId)> {
    let (kind, rest) = if let Some(rest) = name.strip_prefix("@usr-gen-") {
        (SubvolKind::Usr, rest)
    } else {
        (SubvolKind::Etc, name.strip_prefix("@etc-gen-")?)
    };
    rest.parse().ok().map(|id| (kind, id))
}
```

- [ ] **Step 2: Add the crate to the workspace**

`aios-cli/Cargo.toml`:
```toml
[workspace]
resolver = "2"
members = ["crates/aios-manifest", "crates/aios-gen", "crates/aios-render"]

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "GPL-3.0-or-later"
publish = false

[workspace.dependencies]
serde = { version = "1", features = ["derive"] }
toml = "0.8"
tempfile = "3"
```

`aios-cli/crates/aios-render/Cargo.toml`:
```toml
[package]
name = "aios-render"
description = "Pure renderers for the files AIOS writes into a generation's /etc"
version.workspace = true
edition.workspace = true
license.workspace = true
publish.workspace = true

[dependencies]
aios-manifest = { path = "../aios-manifest" }
aios-gen = { path = "../aios-gen" }
```

`aios-cli/crates/aios-render/src/lib.rs`:
```rust
//! Pure renderers for the files AIOS writes into a generation's `/etc`.
```

- [ ] **Step 3: Write the shared test fixture**

The manifest is Phase 1's `VALID` plus a console token in `extra_cmdline`, two persisted files and a second supplementary group. Its persist directories are deliberately unsorted, so the tests prove that manifest order is kept.

`aios-cli/crates/aios-render/tests/common/mod.rs`:
```rust
//! Shared fixtures. Each test binary uses a different subset, hence the `allow`.
#![allow(dead_code)]

use aios_gen::GenId;
use aios_manifest::{parse, Manifest};
use aios_render::RenderCtx;

/// Phase 1's VALID manifest plus a console token, persisted files and a second group.
pub const MANIFEST: &str = r#"[system]
hostname = "nightcity"
timezone = "Asia/Jerusalem"
locale = "en_US.UTF-8"
keymap = "us"

[kernel]
default = "linux-cachyos"
fallback = "linux-cachyos-lts"
lockdown = "integrity"
extra_cmdline = ["console=ttyS0,115200"]

[packages]
install = ["base", "zsh", "git"]

[services]
enable = ["NetworkManager"]

[files]
"/etc/nftables.conf" = { source = "files/nftables.conf", mode = "0600" }
"/etc/pacman.d/hooks/90-mkinitcpio-install.hook" = { symlink = "/dev/null" }

[persist]
directories = ["/var/lib/NetworkManager", "/var/cache/pacman/pkg"]
files = ["/etc/machine-id", "/var/lib/systemd/random-seed"]

[users.eli]
uid = 1000
groups = ["wheel", "video"]
shell = "/usr/bin/zsh"

[users.eli.home]
".zshrc" = "home/eli/zshrc"
".config/autostart/" = "home/eli/autostart/"
"#;

/// `/usr/lib/aios/cmdline-hardening` (spec §5.3), with its trailing newline.
pub const HARDENING: &str = "init_on_alloc=1 init_on_free=1 slab_nomerge page_alloc.shuffle=1 randomize_kstack_offset=on vsyscall=none debugfs=off lsm=landlock,lockdown,yama,integrity,apparmor,bpf quiet\n";

pub fn manifest() -> Manifest {
    manifest_from(MANIFEST)
}

pub fn manifest_from(raw: &str) -> Manifest {
    parse(raw).expect("fixture manifest parses")
}

pub fn ctx() -> RenderCtx {
    RenderCtx {
        gen: GenId(7),
        luks_uuid: "0b6c2e7f-5d0a-4c2e-9a71-3f1d2c4b5a69".to_string(),
        esp_uuid: "7A1B-2C3D".to_string(),
        hardening_cmdline: HARDENING.to_string(),
    }
}
```

- [ ] **Step 4: Write the failing tests**

`aios-cli/crates/aios-render/tests/cmdline.rs`:
```rust
mod common;

use aios_gen::{gen_from_cmdline, GenId};
use aios_render::cmdline;
use common::{ctx, manifest, manifest_from, MANIFEST};

#[test]
fn full_cmdline_in_spec_order() {
    let expected = "rd.luks.name=0b6c2e7f-5d0a-4c2e-9a71-3f1d2c4b5a69=aios \
root=/dev/mapper/aios \
rootflags=subvol=@root-live,compress=zstd \
rw \
mount.usr=/dev/mapper/aios \
mount.usrflags=subvol=@usr-gen-0007,ro,compress=zstd \
aios.gen=0007 \
init_on_alloc=1 init_on_free=1 slab_nomerge page_alloc.shuffle=1 \
randomize_kstack_offset=on vsyscall=none debugfs=off \
lsm=landlock,lockdown,yama,integrity,apparmor,bpf quiet \
lockdown=integrity \
console=ttyS0,115200\n";
    assert_eq!(cmdline(&manifest(), &ctx()), expected);
}

#[test]
fn lockdown_none_adds_no_lockdown_token() {
    let m = manifest_from(&MANIFEST.replace("lockdown = \"integrity\"", "lockdown = \"none\""));
    let line = cmdline(&m, &ctx());
    assert!(!line.contains("lockdown=integrity"), "got {line}");
    assert!(
        line.ends_with(" quiet console=ttyS0,115200\n"),
        "got {line}"
    );
}

#[test]
fn whitespace_is_normalized_to_single_spaces() {
    let mut c = ctx();
    c.hardening_cmdline = "  quiet\n\tslab_nomerge  \n".to_string();
    let m = manifest_from(&MANIFEST.replace(
        "extra_cmdline = [\"console=ttyS0,115200\"]",
        "extra_cmdline = [\"a=1  b=2\", \"\"]",
    ));
    let line = cmdline(&m, &c);
    assert!(
        line.ends_with(" aios.gen=0007 quiet slab_nomerge lockdown=integrity a=1 b=2\n"),
        "got {line:?}"
    );
    assert!(!line.contains("  "), "double space in {line:?}");
    assert_eq!(line.matches('\n').count(), 1);
}

#[test]
fn generation_drives_usr_subvolume_and_gen_token() {
    let mut c = ctx();
    c.gen = GenId(12);
    let line = cmdline(&manifest(), &c);
    assert!(line.contains(" mount.usrflags=subvol=@usr-gen-0012,ro,compress=zstd "));
    assert_eq!(gen_from_cmdline(&line), Some(GenId(12)));
}
```

- [ ] **Step 5: Run the tests to verify they fail**

Run: `cd aios-cli && cargo test -p aios-render --test cmdline`
Expected: compile errors `unresolved import aios_render::RenderCtx` and `unresolved import aios_render::cmdline`.

- [ ] **Step 6: Implement `ctx.rs` and `cmdline.rs`**

`aios-cli/crates/aios-render/src/ctx.rs`:
```rust
use aios_gen::GenId;

/// Machine facts the renderers need beyond the manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderCtx {
    /// The generation being rendered (`aios.gen=`, `@usr-gen-NNNN`, fstab header).
    pub gen: GenId,
    /// UUID of the LUKS2 partition, for `rd.luks.name=`.
    pub luks_uuid: String,
    /// Volume id of the FAT32 ESP, for the `/efi` fstab line.
    pub esp_uuid: String,
    /// Content of `/usr/lib/aios/cmdline-hardening`: whitespace-separated tokens.
    pub hardening_cmdline: String,
}
```

`aios-cli/crates/aios-render/src/cmdline.rs`:
```rust
use crate::RenderCtx;
use aios_manifest::{Lockdown, Manifest};

/// Kernel command line baked into every UKI (`/etc/kernel/cmdline`, spec §3 step 3).
///
/// One line: the AIOS root/usr tokens, the hardening tokens, `lockdown=integrity` when
/// enabled, then `kernel.extra_cmdline`. Tokens are joined by single spaces.
pub fn cmdline(m: &Manifest, ctx: &RenderCtx) -> String {
    let gen = ctx.gen;
    let mut tokens: Vec<String> = vec![
        format!("rd.luks.name={}=aios", ctx.luks_uuid),
        "root=/dev/mapper/aios".to_string(),
        "rootflags=subvol=@root-live,compress=zstd".to_string(),
        "rw".to_string(),
        "mount.usr=/dev/mapper/aios".to_string(),
        format!(
            "mount.usrflags=subvol={},ro,compress=zstd",
            gen.usr_subvol()
        ),
        format!("aios.gen={gen}"),
    ];
    tokens.extend(ctx.hardening_cmdline.split_whitespace().map(str::to_string));
    if m.kernel.lockdown == Lockdown::Integrity {
        tokens.push("lockdown=integrity".to_string());
    }
    tokens.extend(
        m.kernel
            .extra_cmdline
            .iter()
            .flat_map(|entry| entry.split_whitespace())
            .map(str::to_string),
    );
    format!("{}\n", tokens.join(" "))
}
```

- [ ] **Step 7: Replace `lib.rs`**

`aios-cli/crates/aios-render/src/lib.rs`:
```rust
//! Pure renderers for the files AIOS writes into a generation's `/etc`.
//!
//! Nothing here touches the system: every function maps a manifest (plus a
//! [`RenderCtx`]) to text.

mod cmdline;
mod ctx;

pub use cmdline::cmdline;
pub use ctx::RenderCtx;
```

- [ ] **Step 8: Run the tests to verify they pass**

Run: `cd aios-cli && cargo test -p aios-render --test cmdline`
Expected: `test result: ok. 4 passed`.

- [ ] **Step 9: Lint**

Run: `make check`
Expected: `cargo fmt --check` prints nothing, clippy prints no warnings, and every test binary reports `test result: ok`. If fmt complains, run `cargo fmt --all` in `aios-cli/` and re-run.

- [ ] **Step 10: Commit**

```bash
cd /home/eli/Development/AIOS
git add aios-cli/
git commit -m "feat(render): scaffold aios-render with RenderCtx and kernel cmdline"
```

---
### Task 2: Managed home binds and `fstab`

**Files:**
- Create: `aios-cli/crates/aios-render/src/home.rs`, `aios-cli/crates/aios-render/src/fstab.rs`
- Modify: `aios-cli/crates/aios-render/src/lib.rs` (full content below)
- Test: `aios-cli/crates/aios-render/tests/home.rs`, `aios-cli/crates/aios-render/tests/fstab.rs`

`home_binds` is the single source of truth for `[users.<u>.home]`. `fstab`, `home_tmpfiles` (Task 3) and `desired_etc` (Task 6) all use it.

- [ ] **Step 1: Write the failing tests**

`aios-cli/crates/aios-render/tests/home.rs`:
```rust
mod common;

use aios_render::{home_binds, HomeBind};
use common::{manifest, manifest_from, MANIFEST};

#[test]
fn fixture_binds_in_key_order() {
    assert_eq!(
        home_binds(&manifest()),
        vec![
            HomeBind {
                user: "eli".to_string(),
                uid: 1000,
                target: "/home/eli/.config/autostart".to_string(),
                bind_source: "/etc/aios/home/eli/.config/autostart".to_string(),
                repo_source: "home/eli/autostart".to_string(),
                is_dir: true,
            },
            HomeBind {
                user: "eli".to_string(),
                uid: 1000,
                target: "/home/eli/.zshrc".to_string(),
                bind_source: "/etc/aios/home/eli/.zshrc".to_string(),
                repo_source: "home/eli/zshrc".to_string(),
                is_dir: false,
            },
        ]
    );
}

#[test]
fn users_in_name_order_then_keys() {
    let raw = format!(
        "{MANIFEST}\n[users.ada]\nuid = 1001\nshell = \"/usr/bin/bash\"\n\n[users.ada.home]\n\".profile\" = \"home/ada/profile\"\n\".local/bin/\" = \"home/ada/bin/\"\n"
    );
    let order: Vec<(String, String)> = home_binds(&manifest_from(&raw))
        .into_iter()
        .map(|b| (b.user, b.target))
        .collect();
    let expected = [
        ("ada", "/home/ada/.local/bin"),
        ("ada", "/home/ada/.profile"),
        ("eli", "/home/eli/.config/autostart"),
        ("eli", "/home/eli/.zshrc"),
    ]
    .map(|(u, t)| (u.to_string(), t.to_string()));
    assert_eq!(order, expected);
}

#[test]
fn no_users_no_binds() {
    let raw = MANIFEST.split("[users.eli]").next().unwrap();
    assert!(home_binds(&manifest_from(raw)).is_empty());
}
```

`GOLDEN` is the exact `/etc/fstab` for the shared fixture at generation 7.

`aios-cli/crates/aios-render/tests/fstab.rs`:
```rust
mod common;

use aios_render::{fstab, fstab_escape};
use common::{ctx, manifest, manifest_from, MANIFEST};

const GOLDEN: &str = "\
# Generated by aios for generation 0007. Do not edit: /etc is reset at every boot.
/dev/mapper/aios /persist btrfs subvol=@persist,compress=zstd,noatime 0 0
/dev/mapper/aios /home btrfs subvol=@home,compress=zstd,noatime 0 0
/dev/mapper/aios /var/log btrfs subvol=@log,compress=zstd,noatime 0 0
UUID=7A1B-2C3D /efi vfat noauto,x-systemd.automount,umask=0077 0 2
/persist/var/lib/NetworkManager /var/lib/NetworkManager none bind,x-systemd.requires-mounts-for=/persist 0 0
/persist/var/cache/pacman/pkg /var/cache/pacman/pkg none bind,x-systemd.requires-mounts-for=/persist 0 0
/etc/aios/home/eli/.config/autostart /home/eli/.config/autostart none bind,ro,x-systemd.requires-mounts-for=/home 0 0
/etc/aios/home/eli/.zshrc /home/eli/.zshrc none bind,ro,x-systemd.requires-mounts-for=/home 0 0
";

#[test]
fn golden_fixture() {
    assert_eq!(fstab(&manifest(), &ctx()), GOLDEN);
}

#[test]
fn escape_rules() {
    assert_eq!(fstab_escape("/a b\tc\\d\ne"), "/a\\040b\\011c\\134d\\012e");
    assert_eq!(fstab_escape("/plain/path"), "/plain/path");
}

#[test]
fn paths_with_spaces_are_escaped_in_lines() {
    let m = manifest_from(&MANIFEST.replace(
        "\".zshrc\" = \"home/eli/zshrc\"",
        "\"Notes/My File.txt\" = \"home/eli/notes.txt\"",
    ));
    let text = fstab(&m, &ctx());
    let line = "/etc/aios/home/eli/Notes/My\\040File.txt /home/eli/Notes/My\\040File.txt none bind,ro,x-systemd.requires-mounts-for=/home 0 0\n";
    assert!(text.contains(line), "got:\n{text}");
}

#[test]
fn without_persist_or_users_only_base_mounts() {
    let raw = MANIFEST.split("[persist]").next().unwrap();
    let text = fstab(&manifest_from(raw), &ctx());
    assert_eq!(text.lines().count(), 5, "got:\n{text}");
    assert!(text.ends_with("umask=0077 0 2\n"));
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd aios-cli && cargo test -p aios-render --test home --test fstab`
Expected: compile errors `unresolved imports aios_render::home_binds, aios_render::HomeBind` and `unresolved imports aios_render::fstab, aios_render::fstab_escape`.

- [ ] **Step 3: Implement `home.rs`**

`aios-cli/crates/aios-render/src/home.rs`:
```rust
use aios_manifest::Manifest;

/// One read-only bind mount of a manifest-managed path into a home directory (spec §4.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeBind {
    pub user: String,
    pub uid: u32,
    /// Mount point: `/home/<user>/<rel>`, no trailing slash.
    pub target: String,
    /// The generation's copy of the source: `/etc/aios/home/<user>/<rel>`, no trailing slash.
    pub bind_source: String,
    /// Source relative to the manifest repo, trailing slash trimmed.
    pub repo_source: String,
    /// The manifest key ends with `/`.
    pub is_dir: bool,
}

/// Every `[users.<u>.home]` entry, ordered by user name, then by key.
pub fn home_binds(m: &Manifest) -> Vec<HomeBind> {
    m.users
        .iter()
        .flat_map(|(user, u)| {
            u.home.iter().map(move |(key, source)| {
                let rel = key.trim_end_matches('/');
                HomeBind {
                    user: user.clone(),
                    uid: u.uid,
                    target: format!("/home/{user}/{rel}"),
                    bind_source: format!("/etc/aios/home/{user}/{rel}"),
                    repo_source: source.trim_end_matches('/').to_string(),
                    is_dir: key.ends_with('/'),
                }
            })
        })
        .collect()
}
```

- [ ] **Step 4: Implement `fstab.rs`**

Fields are separated by single spaces. Paths go through `fstab_escape`. Beyond the spec's space, tab and backslash, it also escapes newline (`\012`), so a path can never inject a second fstab line.

`aios-cli/crates/aios-render/src/fstab.rs`:
```rust
use crate::{home_binds, RenderCtx};
use aios_manifest::Manifest;

/// Escape a path for one fstab field: space, tab, newline and backslash become octal escapes.
pub fn fstab_escape(p: &str) -> String {
    let mut out = String::with_capacity(p.len());
    for c in p.chars() {
        match c {
            ' ' => out.push_str("\\040"),
            '\t' => out.push_str("\\011"),
            '\n' => out.push_str("\\012"),
            '\\' => out.push_str("\\134"),
            c => out.push(c),
        }
    }
    out
}

/// `/etc/fstab` for a generation (spec §3 step 9, §4.4).
pub fn fstab(m: &Manifest, ctx: &RenderCtx) -> String {
    let mut lines = vec![format!(
        "# Generated by aios for generation {}. Do not edit: /etc is reset at every boot.",
        ctx.gen
    )];
    for (mount_point, subvol) in [
        ("/persist", "@persist"),
        ("/home", "@home"),
        ("/var/log", "@log"),
    ] {
        lines.push(format!(
            "/dev/mapper/aios {mount_point} btrfs subvol={subvol},compress=zstd,noatime 0 0"
        ));
    }
    lines.push(format!(
        "UUID={} /efi vfat noauto,x-systemd.automount,umask=0077 0 2",
        ctx.esp_uuid
    ));
    for dir in &m.persist.directories {
        let dir = fstab_escape(dir);
        lines.push(format!(
            "/persist{dir} {dir} none bind,x-systemd.requires-mounts-for=/persist 0 0"
        ));
    }
    for bind in home_binds(m) {
        lines.push(format!(
            "{} {} none bind,ro,x-systemd.requires-mounts-for=/home 0 0",
            fstab_escape(&bind.bind_source),
            fstab_escape(&bind.target)
        ));
    }
    let mut out = lines.join("\n");
    out.push('\n');
    out
}
```

- [ ] **Step 5: Replace `lib.rs`**

`aios-cli/crates/aios-render/src/lib.rs`:
```rust
//! Pure renderers for the files AIOS writes into a generation's `/etc`.
//!
//! Nothing here touches the system: every function maps a manifest (plus a
//! [`RenderCtx`]) to text.

mod cmdline;
mod ctx;
mod fstab;
mod home;

pub use cmdline::cmdline;
pub use ctx::RenderCtx;
pub use fstab::{fstab, fstab_escape};
pub use home::{home_binds, HomeBind};
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cd aios-cli && cargo test -p aios-render --test home --test fstab`
Expected: `fstab`: `test result: ok. 4 passed`; `home`: `test result: ok. 3 passed`.

- [ ] **Step 7: Lint**

Run: `make check`
Expected: `cargo fmt --check` prints nothing, clippy prints no warnings, and every test binary reports `test result: ok`. If fmt complains, run `cargo fmt --all` in `aios-cli/` and re-run.

- [ ] **Step 8: Commit**

```bash
cd /home/eli/Development/AIOS
git add aios-cli/
git commit -m "feat(render): home bind mounts and fstab"
```

---
### Task 3: `tmpfiles.d`, simple system files and the managed-files list

**Files:**
- Create: `aios-cli/crates/aios-render/src/tmpfiles.rs`, `aios-cli/crates/aios-render/src/simple.rs`, `aios-cli/crates/aios-render/src/managed.rs`
- Modify: `aios-cli/crates/aios-render/src/lib.rs` (full content below)
- Test: `aios-cli/crates/aios-render/tests/tmpfiles.rs`, `aios-cli/crates/aios-render/tests/simple.rs`, `aios-cli/crates/aios-render/tests/managed.rs`

- [ ] **Step 1: Write the failing tests**

`aios-cli/crates/aios-render/tests/tmpfiles.rs`:
```rust
mod common;

use aios_render::{home_tmpfiles, persist_dirs, persist_tmpfiles};
use common::{manifest, manifest_from, MANIFEST};

const HEADER: &str = "# Generated by aios. Do not edit: /etc is reset at every boot.\n";
const FILES_LINE: &str = "files = [\"/etc/machine-id\", \"/var/lib/systemd/random-seed\"]";

#[test]
fn persist_tmpfiles_links_each_file_into_persist() {
    let expected = format!(
        "{HEADER}L+ /etc/machine-id - - - - /persist/etc/machine-id\n\
         L+ /var/lib/systemd/random-seed - - - - /persist/var/lib/systemd/random-seed\n"
    );
    assert_eq!(persist_tmpfiles(&manifest()), expected);
}

#[test]
fn home_tmpfiles_creates_file_targets_only() {
    let expected = format!("{HEADER}f /home/eli/.zshrc 0644 eli eli -\n");
    assert_eq!(home_tmpfiles(&manifest()), expected);
}

#[test]
fn empty_lists_render_header_only() {
    let raw = MANIFEST.replace(FILES_LINE, "files = []");
    let m = manifest_from(raw.split("[users.eli]").next().unwrap());
    assert_eq!(persist_tmpfiles(&m), HEADER);
    assert_eq!(home_tmpfiles(&m), HEADER);
}

#[test]
fn persist_dirs_cover_directories_and_file_parents() {
    assert_eq!(
        persist_dirs(&manifest()),
        [
            "/persist/etc",
            "/persist/var/cache/pacman/pkg",
            "/persist/var/lib/NetworkManager",
            "/persist/var/lib/systemd",
        ]
    );
}

#[test]
fn persist_dirs_handle_top_level_files_and_duplicates() {
    let raw = MANIFEST.replace(
        FILES_LINE,
        "files = [\"/etc/machine-id\", \"/etc/adjtime\", \"/top-level\"]",
    );
    assert_eq!(
        persist_dirs(&manifest_from(&raw)),
        [
            "/persist",
            "/persist/etc",
            "/persist/var/cache/pacman/pkg",
            "/persist/var/lib/NetworkManager",
        ]
    );
}
```

`aios-cli/crates/aios-render/tests/simple.rs`:
```rust
mod common;

use aios_render::{
    hostname, loader_conf, locale_conf, locale_gen, localtime_target, vconsole_conf,
};
use common::{manifest, manifest_from, MANIFEST};

#[test]
fn system_files() {
    let m = manifest();
    assert_eq!(hostname(&m), "nightcity\n");
    assert_eq!(locale_conf(&m), "LANG=en_US.UTF-8\n");
    assert_eq!(vconsole_conf(&m), "KEYMAP=us\n");
    assert_eq!(localtime_target(&m), "/usr/share/zoneinfo/Asia/Jerusalem");
}

#[test]
fn locale_gen_variants() {
    let with = |locale: &str| locale_gen(&manifest_from(&MANIFEST.replace("en_US.UTF-8", locale)));
    assert_eq!(with("en_US.UTF-8"), "en_US.UTF-8 UTF-8\n");
    assert_eq!(with("he_IL.UTF-8"), "he_IL.UTF-8 UTF-8\n");
    assert_eq!(with("C.UTF-8"), "");
    assert_eq!(with("en_US"), "en_US\n");
}

#[test]
fn loader_conf_boots_newest_cachyos_generation() {
    assert_eq!(
        loader_conf(),
        "default aios-gen-*-cachyos*\ntimeout 3\neditor no\n"
    );
}
```

`managed.rs` needs no manifest, so it doesn't include `mod common;`.

`aios-cli/crates/aios-render/tests/managed.rs`:
```rust
use aios_render::{managed_list, parse_managed_list};

#[test]
fn sorted_unique_one_path_per_line() {
    let paths = [
        "/etc/fstab".to_string(),
        "/etc/aios/managed-files".to_string(),
        "/etc/fstab".to_string(),
        "/etc/hostname".to_string(),
    ];
    assert_eq!(
        managed_list(&paths),
        "/etc/aios/managed-files\n/etc/fstab\n/etc/hostname\n"
    );
}

#[test]
fn empty_list_is_empty_text() {
    assert_eq!(managed_list(&[]), "");
}

#[test]
fn parse_round_trips_and_skips_blank_lines() {
    assert_eq!(
        parse_managed_list("/etc/b\n\n/etc/a\n/etc/b\n"),
        ["/etc/a", "/etc/b"]
    );
    let paths = ["/etc/x".to_string(), "/etc/a b".to_string()];
    assert_eq!(
        parse_managed_list(&managed_list(&paths)),
        ["/etc/a b", "/etc/x"]
    );
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd aios-cli && cargo test -p aios-render --test tmpfiles --test simple --test managed`
Expected: compile errors `unresolved imports aios_render::home_tmpfiles, ...`, `unresolved imports aios_render::hostname, ...` and `unresolved imports aios_render::managed_list, aios_render::parse_managed_list`.

- [ ] **Step 3: Implement `tmpfiles.rs`**

`persist_dirs` is for the executor (Phase 3). It returns what `mkdir -p` must create under `/persist` before the binds and symlinks work. It is sorted and deduplicated, and a top-level file such as `/foo` yields `/persist`.

`aios-cli/crates/aios-render/src/tmpfiles.rs`:
```rust
use crate::home_binds;
use aios_manifest::Manifest;
use std::collections::BTreeSet;

const HEADER: &str = "# Generated by aios. Do not edit: /etc is reset at every boot.\n";

/// `/etc/tmpfiles.d/aios-persist.conf`: each declared persistent file becomes a symlink
/// into `/persist` (spec §3 step 10).
pub fn persist_tmpfiles(m: &Manifest) -> String {
    let mut out = String::from(HEADER);
    for file in &m.persist.files {
        out.push_str(&format!("L+ {file} - - - - /persist{file}\n"));
    }
    out
}

/// `/etc/tmpfiles.d/aios-home.conf`: an empty, user-owned target for each file bind,
/// so the read-only bind has a mount point (spec §4.4).
pub fn home_tmpfiles(m: &Manifest) -> String {
    let mut out = String::from(HEADER);
    for bind in home_binds(m).iter().filter(|b| !b.is_dir) {
        out.push_str(&format!(
            "f {} 0644 {} {} -\n",
            bind.target, bind.user, bind.user
        ));
    }
    out
}

/// Directories under `/persist` that must exist for the binds and symlinks to work:
/// each persistent directory plus the parent of each persistent file. Sorted, unique.
pub fn persist_dirs(m: &Manifest) -> Vec<String> {
    let mut dirs = BTreeSet::new();
    for dir in &m.persist.directories {
        dirs.insert(format!("/persist{dir}"));
    }
    for file in &m.persist.files {
        let parent = file.rfind('/').map_or("", |i| &file[..i]);
        dirs.insert(format!("/persist{parent}"));
    }
    dirs.into_iter().collect()
}
```

- [ ] **Step 4: Implement `simple.rs`**

`aios-cli/crates/aios-render/src/simple.rs`:
```rust
use aios_manifest::Manifest;

/// `/etc/hostname`.
pub fn hostname(m: &Manifest) -> String {
    format!("{}\n", m.system.hostname)
}

/// `/etc/locale.conf`.
pub fn locale_conf(m: &Manifest) -> String {
    format!("LANG={}\n", m.system.locale)
}

/// `/etc/locale.gen` for `locale-gen`. Empty for `C.UTF-8`, which glibc has built in.
pub fn locale_gen(m: &Manifest) -> String {
    let locale = &m.system.locale;
    if locale == "C.UTF-8" {
        String::new()
    } else if locale.ends_with(".UTF-8") {
        format!("{locale} UTF-8\n")
    } else {
        format!("{locale}\n")
    }
}

/// `/etc/vconsole.conf`.
pub fn vconsole_conf(m: &Manifest) -> String {
    format!("KEYMAP={}\n", m.system.keymap)
}

/// Target of the `/etc/localtime` symlink.
pub fn localtime_target(m: &Manifest) -> String {
    format!("/usr/share/zoneinfo/{}", m.system.timezone)
}

/// ESP `/loader/loader.conf`: the newest `cachyos` generation boots by default (spec §3 step 2).
pub fn loader_conf() -> String {
    "default aios-gen-*-cachyos*\ntimeout 3\neditor no\n".to_string()
}
```

- [ ] **Step 5: Implement `managed.rs`**

`parse_managed_list` is the inverse of `managed_list`. The planner uses it to read the booted generation's `/etc/aios/managed-files`.

`aios-cli/crates/aios-render/src/managed.rs`:
```rust
use std::collections::BTreeSet;

/// Content of `/etc/aios/managed-files`: sorted, unique, one path per line.
pub fn managed_list(paths: &[String]) -> String {
    let unique: BTreeSet<&str> = paths.iter().map(String::as_str).collect();
    unique.into_iter().map(|p| format!("{p}\n")).collect()
}

/// The paths in a `/etc/aios/managed-files`, sorted and unique. Blank lines are skipped.
pub fn parse_managed_list(text: &str) -> Vec<String> {
    let unique: BTreeSet<&str> = text.lines().filter(|l| !l.is_empty()).collect();
    unique.into_iter().map(str::to_string).collect()
}
```

- [ ] **Step 6: Replace `lib.rs`**

`aios-cli/crates/aios-render/src/lib.rs`:
```rust
//! Pure renderers for the files AIOS writes into a generation's `/etc`.
//!
//! Nothing here touches the system: every function maps a manifest (plus a
//! [`RenderCtx`]) to text.

mod cmdline;
mod ctx;
mod fstab;
mod home;
mod managed;
mod simple;
mod tmpfiles;

pub use cmdline::cmdline;
pub use ctx::RenderCtx;
pub use fstab::{fstab, fstab_escape};
pub use home::{home_binds, HomeBind};
pub use managed::{managed_list, parse_managed_list};
pub use simple::{hostname, loader_conf, locale_conf, locale_gen, localtime_target, vconsole_conf};
pub use tmpfiles::{home_tmpfiles, persist_dirs, persist_tmpfiles};
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cd aios-cli && cargo test -p aios-render --test tmpfiles --test simple --test managed`
Expected: `managed`: `test result: ok. 3 passed`; `simple`: `test result: ok. 3 passed`; `tmpfiles`: `test result: ok. 5 passed`.

- [ ] **Step 8: Lint**

Run: `make check`
Expected: `cargo fmt --check` prints nothing, clippy prints no warnings, and every test binary reports `test result: ok`. If fmt complains, run `cargo fmt --all` in `aios-cli/` and re-run.

- [ ] **Step 9: Commit**

```bash
cd /home/eli/Development/AIOS
git add aios-cli/
git commit -m "feat(render): tmpfiles.d, system files and managed-files list"
```

---
### Task 4: Account database parse and render

**Files:**
- Create: `aios-cli/crates/aios-render/src/users.rs`
- Modify: `aios-cli/crates/aios-render/src/lib.rs` (full content below)
- Test: `aios-cli/crates/aios-render/tests/users_db.rs`

Formats (one entry per line, `:`-separated):
- `passwd`: exactly 7 fields. The password field is ignored on parse and rendered as `x`.
- `group`: exactly 4 fields. The password field is rendered as `x`, members are comma-separated.
- `shadow`: at least 2 fields. Fields 3 onward are kept verbatim in `rest`.
- `gshadow`: exactly 4 fields.

Empty member names (`a,,b,`) are dropped. Blank lines are skipped but still counted, so error line numbers match the file. An empty name or a non-numeric uid/gid is `Malformed`.

- [ ] **Step 1: Write the failing tests**

The fixture lines are real Arch entries (`base` + systemd).

`aios-cli/crates/aios-render/tests/users_db.rs`:
```rust
use aios_render::{GroupEntry, GshadowEntry, PasswdEntry, ShadowEntry, UserDb, UserDbError};

const PASSWD: &str = "root:x:0:0::/root:/usr/bin/bash
bin:x:1:1::/:/usr/bin/nologin
nobody:x:65534:65534:Kernel Overflow User:/:/usr/bin/nologin
eli:x:1000:1000::/home/eli:/usr/bin/zsh
";
const GROUP: &str = "root:x:0:root
wheel:x:998:eli
video:x:985:eli
nobody:x:65534:
eli:x:1000:
";
const SHADOW: &str = "root:!*:20000::::::
bin:!*:20000::::::
nobody:!*:20000::::::
eli:$y$j9T$salt$hash:20100:0:99999:7:::
";
const GSHADOW: &str = "root:::root
wheel:!*::eli
video:!*::eli
nobody:!*::
eli:!*::
";

fn db() -> UserDb {
    UserDb::parse(PASSWD, GROUP, SHADOW, GSHADOW).expect("fixture parses")
}

#[test]
fn parses_arch_entries() {
    let db = db();
    assert_eq!(db.passwd.len(), 4);
    assert_eq!(
        db.passwd[2],
        PasswdEntry {
            name: "nobody".to_string(),
            uid: 65534,
            gid: 65534,
            gecos: "Kernel Overflow User".to_string(),
            home: "/".to_string(),
            shell: "/usr/bin/nologin".to_string(),
        }
    );
    assert_eq!(
        db.group[1],
        GroupEntry {
            name: "wheel".to_string(),
            gid: 998,
            members: vec!["eli".to_string()],
        }
    );
    assert!(db.group[3].members.is_empty());
    assert_eq!(
        db.shadow[3],
        ShadowEntry {
            name: "eli".to_string(),
            hash: "$y$j9T$salt$hash".to_string(),
            rest: "20100:0:99999:7:::".to_string(),
        }
    );
    assert_eq!(
        db.gshadow[0],
        GshadowEntry {
            name: "root".to_string(),
            password: String::new(),
            admins: vec![],
            members: vec!["root".to_string()],
        }
    );
}

#[test]
fn render_reproduces_canonical_text() {
    let files = db().render();
    assert_eq!(files.passwd, PASSWD);
    assert_eq!(files.group, GROUP);
    assert_eq!(files.shadow, SHADOW);
    assert_eq!(files.gshadow, GSHADOW);
}

#[test]
fn parse_of_render_is_identity() {
    let db = db();
    let files = db.render();
    let again = UserDb::parse(&files.passwd, &files.group, &files.shadow, &files.gshadow);
    assert_eq!(again, Ok(db));
}

#[test]
fn passwd_password_field_is_rendered_as_x() {
    let db = UserDb::parse("root:*:0:0::/root:/usr/bin/bash\n", "", "", "").unwrap();
    assert_eq!(db.render().passwd, "root:x:0:0::/root:/usr/bin/bash\n");
}

#[test]
fn member_lists_drop_empty_names() {
    let db = UserDb::parse("", "video:x:985:eli,,ada,\n", "", "video:!*:eli,:ada,,\n").unwrap();
    assert_eq!(db.group[0].members, ["eli", "ada"]);
    assert_eq!(db.gshadow[0].admins, ["eli"]);
    assert_eq!(db.gshadow[0].members, ["ada"]);
}

#[test]
fn blank_lines_are_skipped_but_still_counted() {
    let db = UserDb::parse("\nroot:x:0:0::/root:/usr/bin/bash\n\n", "", "", "").unwrap();
    assert_eq!(db.passwd.len(), 1);
    let err = UserDb::parse("root:x:0:0::/root:/usr/bin/bash\n\nbroken\n", "", "", "");
    assert_eq!(
        err,
        Err(UserDbError::Malformed {
            file: "passwd",
            line: 3
        })
    );
}

#[test]
fn malformed_entries_name_file_and_line() {
    let cases = [
        (UserDb::parse("root:x:0:0::/root\n", "", "", ""), "passwd"),
        (
            UserDb::parse("root:x:zero:0::/root:/bin/sh\n", "", "", ""),
            "passwd",
        ),
        (
            UserDb::parse(":x:0:0::/root:/bin/sh\n", "", "", ""),
            "passwd",
        ),
        (UserDb::parse("", "wheel:x:998\n", "", ""), "group"),
        (UserDb::parse("", "wheel:x:-1:\n", "", ""), "group"),
        (UserDb::parse("", "", "root\n", ""), "shadow"),
        (
            UserDb::parse("", "", "", "wheel:!*::eli:extra\n"),
            "gshadow",
        ),
    ];
    for (result, file) in cases {
        assert_eq!(result, Err(UserDbError::Malformed { file, line: 1 }));
    }
}

#[test]
fn error_messages() {
    let cases = [
        (
            UserDbError::Malformed {
                file: "group",
                line: 4,
            },
            "/etc/group:4: malformed entry",
        ),
        (
            UserDbError::MissingGroup {
                user: "eli".to_string(),
                group: "docker".to_string(),
            },
            "user \"eli\": group \"docker\" does not exist",
        ),
        (
            UserDbError::NameConflict("dbus".to_string()),
            "user \"dbus\": name is already used by a system account or group",
        ),
        (
            UserDbError::MissingHash("eli".to_string()),
            "user \"eli\": no password hash (run `aios passwd eli`)",
        ),
        (
            UserDbError::InvalidHash("eli".to_string()),
            "user \"eli\": password hash is empty or contains ':' or a newline",
        ),
    ];
    for (err, text) in cases {
        assert_eq!(err.to_string(), text);
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd aios-cli && cargo test -p aios-render --test users_db`
Expected: compile error `unresolved imports aios_render::GroupEntry, aios_render::GshadowEntry, aios_render::PasswdEntry, ...`.

- [ ] **Step 3: Implement `users.rs`**

`aios-cli/crates/aios-render/src/users.rs`:
```rust
use std::fmt;

/// One `/etc/passwd` line. The password field is always rendered as `x`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswdEntry {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub gecos: String,
    pub home: String,
    pub shell: String,
}

/// One `/etc/group` line. The password field is always rendered as `x`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupEntry {
    pub name: String,
    pub gid: u32,
    pub members: Vec<String>,
}

/// One `/etc/shadow` line. `rest` is fields 3 to 9 verbatim
/// (`lastchg:min:max:warn:inactive:expire:reserved`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowEntry {
    pub name: String,
    pub hash: String,
    pub rest: String,
}

/// One `/etc/gshadow` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GshadowEntry {
    pub name: String,
    pub password: String,
    pub admins: Vec<String>,
    pub members: Vec<String>,
}

/// The four account databases, each in file order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UserDb {
    pub passwd: Vec<PasswdEntry>,
    pub group: Vec<GroupEntry>,
    pub shadow: Vec<ShadowEntry>,
    pub gshadow: Vec<GshadowEntry>,
}

/// Rendered contents of `/etc/passwd`, `/etc/group`, `/etc/shadow` and `/etc/gshadow`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserFiles {
    pub passwd: String,
    pub group: String,
    pub shadow: String,
    pub gshadow: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserDbError {
    /// Wrong field count, empty name or non-numeric id. `file` is `passwd`, `group`,
    /// `shadow` or `gshadow`; `line` is 1-based.
    Malformed { file: &'static str, line: usize },
    /// A declared user lists a group that does not exist after merging.
    MissingGroup { user: String, group: String },
    /// A declared user's name is taken by a system account or group.
    NameConflict(String),
    /// No password hash was supplied for a declared user.
    MissingHash(String),
    /// The hash is empty or contains `:` or a newline.
    InvalidHash(String),
}

impl fmt::Display for UserDbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UserDbError::Malformed { file, line } => {
                write!(f, "/etc/{file}:{line}: malformed entry")
            }
            UserDbError::MissingGroup { user, group } => {
                write!(f, "user {user:?}: group {group:?} does not exist")
            }
            UserDbError::NameConflict(name) => write!(
                f,
                "user {name:?}: name is already used by a system account or group"
            ),
            UserDbError::MissingHash(name) => write!(
                f,
                "user {name:?}: no password hash (run `aios passwd {name}`)"
            ),
            UserDbError::InvalidHash(name) => write!(
                f,
                "user {name:?}: password hash is empty or contains ':' or a newline"
            ),
        }
    }
}

impl std::error::Error for UserDbError {}

impl UserDb {
    /// Parse the four files. Empty lines are skipped (but still counted for line numbers).
    pub fn parse(
        passwd: &str,
        group: &str,
        shadow: &str,
        gshadow: &str,
    ) -> Result<UserDb, UserDbError> {
        Ok(UserDb {
            passwd: parse_lines(passwd, "passwd", parse_passwd)?,
            group: parse_lines(group, "group", parse_group)?,
            shadow: parse_lines(shadow, "shadow", parse_shadow)?,
            gshadow: parse_lines(gshadow, "gshadow", parse_gshadow)?,
        })
    }

    /// One line per entry, each ending in a newline.
    pub fn render(&self) -> UserFiles {
        UserFiles {
            passwd: self
                .passwd
                .iter()
                .map(|e| {
                    format!(
                        "{}:x:{}:{}:{}:{}:{}\n",
                        e.name, e.uid, e.gid, e.gecos, e.home, e.shell
                    )
                })
                .collect(),
            group: self
                .group
                .iter()
                .map(|e| format!("{}:x:{}:{}\n", e.name, e.gid, e.members.join(",")))
                .collect(),
            shadow: self
                .shadow
                .iter()
                .map(|e| format!("{}:{}:{}\n", e.name, e.hash, e.rest))
                .collect(),
            gshadow: self
                .gshadow
                .iter()
                .map(|e| {
                    format!(
                        "{}:{}:{}:{}\n",
                        e.name,
                        e.password,
                        e.admins.join(","),
                        e.members.join(",")
                    )
                })
                .collect(),
        }
    }
}

fn parse_lines<T>(
    text: &str,
    file: &'static str,
    parse: fn(&[&str]) -> Option<T>,
) -> Result<Vec<T>, UserDbError> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split(':').collect();
        let entry = parse(&fields).ok_or(UserDbError::Malformed { file, line: i + 1 })?;
        out.push(entry);
    }
    Ok(out)
}

fn parse_passwd(fields: &[&str]) -> Option<PasswdEntry> {
    let [name, _password, uid, gid, gecos, home, shell] = fields else {
        return None;
    };
    Some(PasswdEntry {
        name: non_empty(name)?,
        uid: uid.parse().ok()?,
        gid: gid.parse().ok()?,
        gecos: gecos.to_string(),
        home: home.to_string(),
        shell: shell.to_string(),
    })
}

fn parse_group(fields: &[&str]) -> Option<GroupEntry> {
    let [name, _password, gid, members] = fields else {
        return None;
    };
    Some(GroupEntry {
        name: non_empty(name)?,
        gid: gid.parse().ok()?,
        members: split_list(members),
    })
}

fn parse_shadow(fields: &[&str]) -> Option<ShadowEntry> {
    let [name, hash, rest @ ..] = fields else {
        return None;
    };
    Some(ShadowEntry {
        name: non_empty(name)?,
        hash: hash.to_string(),
        rest: rest.join(":"),
    })
}

fn parse_gshadow(fields: &[&str]) -> Option<GshadowEntry> {
    let [name, password, admins, members] = fields else {
        return None;
    };
    Some(GshadowEntry {
        name: non_empty(name)?,
        password: password.to_string(),
        admins: split_list(admins),
        members: split_list(members),
    })
}

fn non_empty(name: &str) -> Option<String> {
    (!name.is_empty()).then(|| name.to_string())
}

fn split_list(list: &str) -> Vec<String> {
    list.split(',')
        .filter(|m| !m.is_empty())
        .map(str::to_string)
        .collect()
}
```

- [ ] **Step 4: Replace `lib.rs`**

`aios-cli/crates/aios-render/src/lib.rs`:
```rust
//! Pure renderers for the files AIOS writes into a generation's `/etc`.
//!
//! Nothing here touches the system: every function maps a manifest (plus a
//! [`RenderCtx`]) to text.

mod cmdline;
mod ctx;
mod fstab;
mod home;
mod managed;
mod simple;
mod tmpfiles;
mod users;

pub use cmdline::cmdline;
pub use ctx::RenderCtx;
pub use fstab::{fstab, fstab_escape};
pub use home::{home_binds, HomeBind};
pub use managed::{managed_list, parse_managed_list};
pub use simple::{hostname, loader_conf, locale_conf, locale_gen, localtime_target, vconsole_conf};
pub use tmpfiles::{home_tmpfiles, persist_dirs, persist_tmpfiles};
pub use users::{
    GroupEntry, GshadowEntry, PasswdEntry, ShadowEntry, UserDb, UserDbError, UserFiles,
};
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd aios-cli && cargo test -p aios-render --test users_db`
Expected: `test result: ok. 8 passed`.

- [ ] **Step 6: Lint**

Run: `make check`
Expected: `cargo fmt --check` prints nothing, clippy prints no warnings, and every test binary reports `test result: ok`. If fmt complains, run `cargo fmt --all` in `aios-cli/` and re-run.

- [ ] **Step 7: Commit**

```bash
cd /home/eli/Development/AIOS
git add aios-cli/
git commit -m "feat(render): parse and render passwd/group/shadow/gshadow"
```

---
### Task 5: Merge declared users into the account files

**Files:**
- Create: `aios-cli/crates/aios-render/src/merge.rs`
- Modify: `aios-cli/crates/aios-render/src/lib.rs` (full content below)
- Test: `aios-cli/crates/aios-render/tests/users_merge.rs`

Rules (spec §4.3 step 6). Managed ids are `1000..=59999`. D is the set of declared user names. R is the set of names of dropped passwd entries.
- **passwd:** keep unmanaged-uid entries in file order. If a kept entry has a declared user's name, that's `NameConflict`. Drop managed-uid entries; their names form R. Append the declared users in name order as `name:x:uid:uid::/home/name:shell`.
- **group:** keep unmanaged-gid groups. A kept group with a declared user's name is also `NameConflict`, because the primary group would otherwise exist twice. Drop managed-gid groups. Append each declared user's primary group (`gid = uid`, no members). Strip R ∪ D from every member list, then append each declared user (name order) to the groups it lists. A listed group that doesn't exist is `MissingGroup`.
- **shadow:** keep entries for kept passwd names, with root's hash set to `!*` (its `rest` stays). Each declared user's hash comes from `hashes`. A missing hash is `MissingHash`. An empty hash, or one containing `:` or `\n`, is `InvalidHash`. If the old entry has the same hash, its `rest` is kept; otherwise `rest = "<today_days>:0:99999:7:::"`. Re-planning on a later day therefore changes nothing.
- **gshadow:** rebuilt from the merged groups. Each group reuses the old entry's password and admins (else `!*` and none). Its members always equal the group's members.

The merge is idempotent: `merge(merge(db)) == merge(db)`. That is what makes `aios plan` print "no changes" on a freshly installed system (spec §1 success criterion (c)).

- [ ] **Step 1: Write the failing tests**

The booted generation has the Arch system accounts plus `eli` (declared) and `bob` (no longer declared). The manifest declares `eli` and `ada`, and `ada` reuses bob's uid 1001.

`aios-cli/crates/aios-render/tests/users_merge.rs`:
```rust
mod common;

use aios_manifest::Manifest;
use aios_render::{merge_users, UserDb, UserDbError, UserFiles};
use common::{manifest_from, MANIFEST};
use std::collections::BTreeMap;

/// The booted generation: Arch system accounts, plus eli and a stale user bob.
const PASSWD: &str = "root:x:0:0::/root:/usr/bin/bash
bin:x:1:1::/:/usr/bin/nologin
daemon:x:2:2::/:/usr/bin/nologin
dbus:x:81:81:System Message Bus:/:/usr/bin/nologin
systemd-network:x:982:982:systemd Network Management:/:/usr/bin/nologin
nobody:x:65534:65534:Kernel Overflow User:/:/usr/bin/nologin
eli:x:1000:1000::/home/eli:/usr/bin/bash
bob:x:1001:1001::/home/bob:/usr/bin/bash
";
const GROUP: &str = "root:x:0:root
bin:x:1:daemon
daemon:x:2:bin
wheel:x:998:bob,eli
video:x:985:eli,bob
audio:x:984:bob
dbus:x:81:
systemd-network:x:982:
nobody:x:65534:
eli:x:1000:
bob:x:1001:
";
const SHADOW: &str = "root:$6$oldroot$hash:20000::::::
bin:!*:20000::::::
daemon:!*:20000::::::
dbus:!*:20000::::::
systemd-network:!*:20000::::::
nobody:!*:20000::::::
eli:$y$j9T$eli$old:20100:0:99999:7:::
bob:$y$j9T$bob$hash:20200:0:99999:7:::
";
const GSHADOW: &str = "root:::root
bin:::daemon
daemon:::bin
wheel:!*::bob,eli
video:!*::eli,bob
audio:!*::bob
dbus:!*::
systemd-network:!*::
nobody:!*::
eli:!*::
bob:!*::
";

/// 2026-11-03 in days since the epoch.
const TODAY: u64 = 20760;

fn db() -> UserDb {
    UserDb::parse(PASSWD, GROUP, SHADOW, GSHADOW).expect("fixture parses")
}

/// The common manifest (eli: wheel, video) plus ada (uid 1001, video), who reuses bob's uid.
fn two_users() -> Manifest {
    manifest_from(&format!(
        "{MANIFEST}\n[users.ada]\nuid = 1001\ngroups = [\"video\"]\nshell = \"/usr/bin/bash\"\n"
    ))
}

fn hashes(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(user, hash)| (user.to_string(), hash.to_string()))
        .collect()
}

fn default_hashes() -> BTreeMap<String, String> {
    hashes(&[("ada", "$y$j9T$ada$new"), ("eli", "$y$j9T$eli$old")])
}

fn merged() -> UserFiles {
    merge_users(&two_users(), &db(), &default_hashes(), TODAY)
        .expect("merge succeeds")
        .render()
}

#[test]
fn golden_merge() {
    let files = merged();
    assert_eq!(
        files.passwd,
        "root:x:0:0::/root:/usr/bin/bash
bin:x:1:1::/:/usr/bin/nologin
daemon:x:2:2::/:/usr/bin/nologin
dbus:x:81:81:System Message Bus:/:/usr/bin/nologin
systemd-network:x:982:982:systemd Network Management:/:/usr/bin/nologin
nobody:x:65534:65534:Kernel Overflow User:/:/usr/bin/nologin
ada:x:1001:1001::/home/ada:/usr/bin/bash
eli:x:1000:1000::/home/eli:/usr/bin/zsh
"
    );
    assert_eq!(
        files.group,
        "root:x:0:root
bin:x:1:daemon
daemon:x:2:bin
wheel:x:998:eli
video:x:985:ada,eli
audio:x:984:
dbus:x:81:
systemd-network:x:982:
nobody:x:65534:
ada:x:1001:
eli:x:1000:
"
    );
    assert_eq!(
        files.shadow,
        "root:!*:20000::::::
bin:!*:20000::::::
daemon:!*:20000::::::
dbus:!*:20000::::::
systemd-network:!*:20000::::::
nobody:!*:20000::::::
ada:$y$j9T$ada$new:20760:0:99999:7:::
eli:$y$j9T$eli$old:20100:0:99999:7:::
"
    );
    assert_eq!(
        files.gshadow,
        "root:::root
bin:::daemon
daemon:::bin
wheel:!*::eli
video:!*::ada,eli
audio:!*::
dbus:!*::
systemd-network:!*::
nobody:!*::
ada:!*::
eli:!*::
"
    );
}

#[test]
fn stale_managed_user_is_removed_everywhere() {
    let files = merged();
    for text in [&files.passwd, &files.group, &files.shadow, &files.gshadow] {
        assert!(!text.contains("bob"), "bob left in:\n{text}");
    }
}

#[test]
fn root_is_locked_and_keeps_its_aging_fields() {
    let files = merged();
    assert!(files.shadow.starts_with("root:!*:20000::::::\n"));
}

#[test]
fn changed_hash_updates_lastchg() {
    let new = hashes(&[("ada", "$y$j9T$ada$new"), ("eli", "$y$j9T$eli$new")]);
    let files = merge_users(&two_users(), &db(), &new, TODAY)
        .unwrap()
        .render();
    assert!(files
        .shadow
        .contains("\neli:$y$j9T$eli$new:20760:0:99999:7:::\n"));
}

#[test]
fn unchanged_hash_is_stable_across_days() {
    let first = merge_users(&two_users(), &db(), &default_hashes(), TODAY).unwrap();
    let later = merge_users(&two_users(), &first, &default_hashes(), TODAY + 30).unwrap();
    assert_eq!(later, first);
}

#[test]
fn merge_is_idempotent() {
    let once = merge_users(&two_users(), &db(), &default_hashes(), TODAY).unwrap();
    let twice = merge_users(&two_users(), &once, &default_hashes(), TODAY).unwrap();
    assert_eq!(twice, once);
}

#[test]
fn empty_database_gets_declared_users() {
    let m = manifest_from(&MANIFEST.replace("groups = [\"wheel\", \"video\"]", "groups = []"));
    let files = merge_users(&m, &UserDb::default(), &hashes(&[("eli", "$y$h")]), TODAY)
        .unwrap()
        .render();
    assert_eq!(files.passwd, "eli:x:1000:1000::/home/eli:/usr/bin/zsh\n");
    assert_eq!(files.group, "eli:x:1000:\n");
    assert_eq!(files.shadow, "eli:$y$h:20760:0:99999:7:::\n");
    assert_eq!(files.gshadow, "eli:!*::\n");
}

#[test]
fn missing_group_is_an_error() {
    let m = manifest_from(&MANIFEST.replace("[\"wheel\", \"video\"]", "[\"wheel\", \"docker\"]"));
    let err = merge_users(&m, &db(), &default_hashes(), TODAY).unwrap_err();
    assert_eq!(
        err,
        UserDbError::MissingGroup {
            user: "eli".to_string(),
            group: "docker".to_string()
        }
    );
}

#[test]
fn missing_hash_is_an_error() {
    let err = merge_users(
        &two_users(),
        &db(),
        &hashes(&[("eli", "$y$j9T$eli$old")]),
        TODAY,
    )
    .unwrap_err();
    assert_eq!(err, UserDbError::MissingHash("ada".to_string()));
}

#[test]
fn invalid_hashes_are_errors() {
    for bad in ["", "$y$a:b", "$y$ab\n"] {
        let err = merge_users(
            &two_users(),
            &db(),
            &hashes(&[("ada", bad), ("eli", "$y$j9T$eli$old")]),
            TODAY,
        )
        .unwrap_err();
        assert_eq!(
            err,
            UserDbError::InvalidHash("ada".to_string()),
            "hash {bad:?}"
        );
    }
}

#[test]
fn declared_name_of_a_system_user_conflicts() {
    let m = manifest_from(&format!(
        "{MANIFEST}\n[users.dbus]\nuid = 1005\nshell = \"/usr/bin/bash\"\n"
    ));
    let hs = hashes(&[("dbus", "$y$d"), ("eli", "$y$j9T$eli$old")]);
    let err = merge_users(&m, &db(), &hs, TODAY).unwrap_err();
    assert_eq!(err, UserDbError::NameConflict("dbus".to_string()));
}

#[test]
fn declared_name_of_a_system_group_conflicts() {
    let m = manifest_from(&format!(
        "{MANIFEST}\n[users.audio]\nuid = 1005\nshell = \"/usr/bin/bash\"\n"
    ));
    let hs = hashes(&[("audio", "$y$a"), ("eli", "$y$j9T$eli$old")]);
    let err = merge_users(&m, &db(), &hs, TODAY).unwrap_err();
    assert_eq!(err, UserDbError::NameConflict("audio".to_string()));
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd aios-cli && cargo test -p aios-render --test users_merge`
Expected: compile error `unresolved import aios_render::merge_users`.

- [ ] **Step 3: Implement `merge.rs`**

`aios-cli/crates/aios-render/src/merge.rs`:
```rust
use crate::{GroupEntry, GshadowEntry, PasswdEntry, ShadowEntry, UserDb, UserDbError};
use aios_manifest::Manifest;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::RangeInclusive;

/// uids and gids AIOS owns. Anything outside (system accounts, `nobody`) is kept as
/// packages created it.
pub const MANAGED_IDS: RangeInclusive<u32> = 1000..=59999;

/// Password field of a locked account.
const LOCKED: &str = "!*";

/// Merge the manifest's users into the account files of a generation (spec §4.3 step 6).
///
/// - Entries with an unmanaged id are kept in file order; managed ones are dropped.
/// - Declared users and their primary groups (gid = uid) are appended in name order.
/// - Supplementary memberships of dropped and declared users are rebuilt from the manifest.
/// - root is locked (`!*`).
///
/// `hashes` maps each declared user to the hash from `secrets/passwd/<user>`, trailing newline
/// already trimmed. `today_days` (days since the epoch) becomes `lastchg` only when a hash
/// changes, so planning on a later day renders identical files.
pub fn merge_users(
    m: &Manifest,
    db: &UserDb,
    hashes: &BTreeMap<String, String>,
    today_days: u64,
) -> Result<UserDb, UserDbError> {
    let declared: BTreeSet<&str> = m.users.keys().map(String::as_str).collect();

    let mut removed: BTreeSet<&str> = BTreeSet::new();
    let mut kept: BTreeSet<&str> = BTreeSet::new();
    let mut passwd = Vec::new();
    for entry in &db.passwd {
        if MANAGED_IDS.contains(&entry.uid) {
            removed.insert(&entry.name);
        } else if declared.contains(entry.name.as_str()) {
            return Err(UserDbError::NameConflict(entry.name.clone()));
        } else {
            kept.insert(&entry.name);
            passwd.push(entry.clone());
        }
    }
    for (name, user) in &m.users {
        passwd.push(PasswdEntry {
            name: name.clone(),
            uid: user.uid,
            gid: user.uid,
            gecos: String::new(),
            home: format!("/home/{name}"),
            shell: user.shell.clone(),
        });
    }

    let mut group = Vec::new();
    for entry in &db.group {
        if MANAGED_IDS.contains(&entry.gid) {
            continue;
        }
        if declared.contains(entry.name.as_str()) {
            return Err(UserDbError::NameConflict(entry.name.clone()));
        }
        group.push(entry.clone());
    }
    for (name, user) in &m.users {
        group.push(GroupEntry {
            name: name.clone(),
            gid: user.uid,
            members: Vec::new(),
        });
    }
    for entry in &mut group {
        entry.members.retain(|member| {
            !removed.contains(member.as_str()) && !declared.contains(member.as_str())
        });
    }
    for (name, user) in &m.users {
        for wanted in &user.groups {
            let entry = group
                .iter_mut()
                .find(|g| g.name == *wanted)
                .ok_or_else(|| UserDbError::MissingGroup {
                    user: name.clone(),
                    group: wanted.clone(),
                })?;
            if !entry.members.contains(name) {
                entry.members.push(name.clone());
            }
        }
    }

    let mut shadow = Vec::new();
    for entry in &db.shadow {
        if !kept.contains(entry.name.as_str()) {
            continue;
        }
        let mut entry = entry.clone();
        if entry.name == "root" {
            entry.hash = LOCKED.to_string();
        }
        shadow.push(entry);
    }
    for name in m.users.keys() {
        let hash = hashes
            .get(name)
            .ok_or_else(|| UserDbError::MissingHash(name.clone()))?;
        if hash.is_empty() || hash.contains(':') || hash.contains('\n') {
            return Err(UserDbError::InvalidHash(name.clone()));
        }
        let rest = match db.shadow.iter().find(|s| s.name == *name) {
            Some(old) if old.hash == *hash => old.rest.clone(),
            _ => format!("{today_days}:0:99999:7:::"),
        };
        shadow.push(ShadowEntry {
            name: name.clone(),
            hash: hash.clone(),
            rest,
        });
    }

    let gshadow = group
        .iter()
        .map(|g| {
            let old = db.gshadow.iter().find(|s| s.name == g.name);
            GshadowEntry {
                name: g.name.clone(),
                password: old.map_or_else(|| LOCKED.to_string(), |o| o.password.clone()),
                admins: old.map(|o| o.admins.clone()).unwrap_or_default(),
                members: g.members.clone(),
            }
        })
        .collect();

    Ok(UserDb {
        passwd,
        group,
        shadow,
        gshadow,
    })
}
```

- [ ] **Step 4: Replace `lib.rs`**

`aios-cli/crates/aios-render/src/lib.rs`:
```rust
//! Pure renderers for the files AIOS writes into a generation's `/etc`.
//!
//! Nothing here touches the system: every function maps a manifest (plus a
//! [`RenderCtx`]) to text.

mod cmdline;
mod ctx;
mod fstab;
mod home;
mod managed;
mod merge;
mod simple;
mod tmpfiles;
mod users;

pub use cmdline::cmdline;
pub use ctx::RenderCtx;
pub use fstab::{fstab, fstab_escape};
pub use home::{home_binds, HomeBind};
pub use managed::{managed_list, parse_managed_list};
pub use merge::{merge_users, MANAGED_IDS};
pub use simple::{hostname, loader_conf, locale_conf, locale_gen, localtime_target, vconsole_conf};
pub use tmpfiles::{home_tmpfiles, persist_dirs, persist_tmpfiles};
pub use users::{
    GroupEntry, GshadowEntry, PasswdEntry, ShadowEntry, UserDb, UserDbError, UserFiles,
};
```

- [ ] **Step 5: Run the crate's tests**

Run: `cd aios-cli && cargo test -p aios-render`
Expected, one `test result: ok` line per binary: `cmdline` 4, `fstab` 4, `home` 3, `managed` 3, `simple` 3, `tmpfiles` 5, `users_db` 8, `users_merge` 12 (42 total). The lib unit tests and doc-tests report `0 passed`.

- [ ] **Step 6: Lint**

Run: `make check`
Expected: `cargo fmt --check` prints nothing, clippy prints no warnings, and every test binary reports `test result: ok`. If fmt complains, run `cargo fmt --all` in `aios-cli/` and re-run.

- [ ] **Step 7: Commit**

```bash
cd /home/eli/Development/AIOS
git add aios-cli/
git commit -m "feat(render): merge declared users into the account files"
```

---
### Task 6: Scaffold `aios-plan`: probe types and the desired `/etc`

**Files:**
- Modify: `aios-cli/Cargo.toml` (workspace members)
- Create: `aios-cli/crates/aios-plan/Cargo.toml`, `aios-cli/crates/aios-plan/src/lib.rs`, `aios-cli/crates/aios-plan/src/probe.rs`, `aios-cli/crates/aios-plan/src/desired.rs`
- Test: `aios-cli/crates/aios-plan/tests/common/mod.rs`, `aios-cli/crates/aios-plan/tests/desired.rs`

`desired_etc` returns every `/etc` entry aios writes into a generation:
- `[files]`: the repo source's bytes with the manifest mode (octal), or a `Symlink`.
- Generated, mode 0644: `/etc/fstab`, `/etc/hostname`, `/etc/locale.conf`, `/etc/locale.gen` (only if non-empty), `/etc/vconsole.conf`, `/etc/kernel/cmdline`, `/etc/tmpfiles.d/aios-persist.conf`, `/etc/tmpfiles.d/aios-home.conf`.
- `/etc/localtime`: a `Symlink` to the zoneinfo file.
- Accounts: `/etc/passwd` and `/etc/group` (0644), `/etc/shadow` and `/etc/gshadow` (0600), merged into the probe's current files. A file missing from the probe counts as empty text.
- Home bind sources: a file bind's source with its repo permission bits (`& 0o777`), or each regular file under a directory bind's source, walked recursively and sorted.
- `/etc/aios/managed-files`: every key in the map, itself included, `/etc/aios/generation.toml` excluded.

On a path clash, a later source in the list above wins over `[files]`. So `[files]` can never override `/etc/fstab` or `/etc/shadow`.

- [ ] **Step 1: Add the crate to the workspace**

`aios-cli/Cargo.toml`:
```toml
[workspace]
resolver = "2"
members = [
    "crates/aios-manifest",
    "crates/aios-gen",
    "crates/aios-render",
    "crates/aios-plan",
]

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "GPL-3.0-or-later"
publish = false

[workspace.dependencies]
serde = { version = "1", features = ["derive"] }
toml = "0.8"
tempfile = "3"
```

`aios-gen` is a dev-dependency only: the tests build a `RenderCtx`, which holds a `GenId`.

`aios-cli/crates/aios-plan/Cargo.toml`:
```toml
[package]
name = "aios-plan"
description = "Diff the AIOS manifest against the booted generation"
version.workspace = true
edition.workspace = true
license.workspace = true
publish.workspace = true

[dependencies]
aios-manifest = { path = "../aios-manifest" }
aios-render = { path = "../aios-render" }

[dev-dependencies]
aios-gen = { path = "../aios-gen" }
tempfile.workspace = true
```

`aios-cli/crates/aios-plan/src/lib.rs`:
```rust
//! Compare the manifest with the booted generation: what would `aios apply` change?
```

- [ ] **Step 2: Write the shared test fixture**

`Fixture` owns a tempdir manifest repo whose files have explicit modes (0644, 0755, 0700). `FakeProbe` is an in-memory booted generation. `FakeProbe::base()` holds only pacstrap's account files. `FakeProbe::synced(&fx)` feeds `desired_etc`'s output back into the probe, with the manifest's packages and unit states, so it models a generation built from exactly this fixture.

`aios-cli/crates/aios-plan/tests/common/mod.rs`:
```rust
//! Shared planner fixtures. Each test binary uses a different subset, hence the `allow`.
#![allow(dead_code)]

use aios_gen::GenId;
use aios_manifest::{parse, Manifest};
use aios_plan::{desired_etc, EtcEntry, Inputs, ProbeError, SystemProbe, UnitState};
use aios_render::RenderCtx;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tempfile::TempDir;

pub const MANIFEST: &str = r#"[system]
hostname = "nightcity"
timezone = "Asia/Jerusalem"
locale = "en_US.UTF-8"
keymap = "us"

[kernel]
default = "linux-cachyos"
fallback = "linux-cachyos-lts"
lockdown = "integrity"
extra_cmdline = []

[packages]
install = ["base", "zsh", "git"]

[services]
enable = ["NetworkManager", "fwupd-refresh.timer"]
disable = ["bluetooth"]
mask = ["sshd.socket"]

[files]
"/etc/nftables.conf" = { source = "files/nftables.conf", mode = "0600" }
"/etc/pacman.d/hooks/90-mkinitcpio-install.hook" = { symlink = "/dev/null" }

[persist]
directories = ["/var/lib/NetworkManager", "/var/cache/pacman/pkg"]
files = []

[users.eli]
uid = 1000
groups = ["wheel"]
shell = "/usr/bin/zsh"

[users.eli.home]
".zshrc" = "home/eli/zshrc"
".local/bin/" = "home/eli/bin/"
"#;

/// Account files as pacstrap leaves them, before aios merges users.
pub const BASE_PASSWD: &str = "root:x:0:0::/root:/usr/bin/bash
nobody:x:65534:65534:Kernel Overflow User:/:/usr/bin/nologin
";
pub const BASE_GROUP: &str = "root:x:0:root\nwheel:x:998:\nnobody:x:65534:\n";
pub const BASE_SHADOW: &str = "root:*:20000::::::\nnobody:!*:20000::::::\n";
pub const BASE_GSHADOW: &str = "root:::root\nwheel:!*::\nnobody:!*::\n";

/// 2026-11-03 in days since the epoch.
pub const TODAY: u64 = 20760;
pub const ELI_HASH: &str = "$y$j9T$salt$hash";

/// A manifest repo in a tempdir plus everything else `Inputs` borrows.
pub struct Fixture {
    pub repo: TempDir,
    pub manifest: Manifest,
    pub ctx: RenderCtx,
    pub hashes: BTreeMap<String, String>,
}

impl Fixture {
    pub fn inputs(&self) -> Inputs<'_> {
        Inputs {
            manifest: &self.manifest,
            repo_root: self.repo.path(),
            ctx: &self.ctx,
            hashes: &self.hashes,
            today_days: TODAY,
        }
    }
}

pub fn fixture() -> Fixture {
    fixture_with(MANIFEST)
}

/// Repo layout: files/nftables.conf, home/eli/zshrc, home/eli/bin/{hello, lib/util.sh}.
pub fn fixture_with(raw: &str) -> Fixture {
    let repo = TempDir::new().unwrap();
    write(repo.path(), "files/nftables.conf", "flush ruleset\n", 0o644);
    write(repo.path(), "home/eli/zshrc", "# zshrc\n", 0o644);
    write(
        repo.path(),
        "home/eli/bin/hello",
        "#!/bin/sh\necho hello\n",
        0o755,
    );
    write(
        repo.path(),
        "home/eli/bin/lib/util.sh",
        "util() { :; }\n",
        0o700,
    );
    Fixture {
        repo,
        manifest: parse(raw).expect("fixture manifest parses"),
        ctx: RenderCtx {
            gen: GenId(1),
            luks_uuid: "0b6c2e7f-5d0a-4c2e-9a71-3f1d2c4b5a69".to_string(),
            esp_uuid: "7A1B-2C3D".to_string(),
            hardening_cmdline: "init_on_alloc=1 quiet\n".to_string(),
        },
        hashes: BTreeMap::from([("eli".to_string(), ELI_HASH.to_string())]),
    }
}

pub fn write(root: &Path, rel: &str, content: &str, mode: u32) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, content).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
}

pub fn text_file(text: &str, mode: u32) -> EtcEntry {
    EtcEntry::File {
        content: text.as_bytes().to_vec(),
        mode,
    }
}

/// In-memory booted generation. Unknown units are `NotFound`.
#[derive(Debug, Clone, Default)]
pub struct FakeProbe {
    pub packages: BTreeSet<String>,
    pub etc: BTreeMap<String, EtcEntry>,
    pub units: BTreeMap<String, UnitState>,
    /// When set, every call fails with this message.
    pub fail: Option<String>,
}

impl FakeProbe {
    /// A booted system with only pacstrap's account files in `/etc`.
    pub fn base() -> FakeProbe {
        let mut probe = FakeProbe::default();
        for (path, text, mode) in [
            ("/etc/passwd", BASE_PASSWD, 0o644),
            ("/etc/group", BASE_GROUP, 0o644),
            ("/etc/shadow", BASE_SHADOW, 0o600),
            ("/etc/gshadow", BASE_GSHADOW, 0o600),
        ] {
            probe.etc.insert(path.to_string(), text_file(text, mode));
        }
        probe
    }

    /// A booted generation built from exactly this fixture: the planner must see no changes.
    pub fn synced(fx: &Fixture) -> FakeProbe {
        let mut probe = FakeProbe::base();
        probe.etc = desired_etc(&fx.inputs(), &probe).expect("desired state renders");
        probe.packages = fx.manifest.package_set().into_iter().collect();
        let services = &fx.manifest.services;
        for (units, state) in [
            (&services.enable, UnitState::Enabled),
            (&services.disable, UnitState::Disabled),
            (&services.mask, UnitState::Masked),
        ] {
            for unit in units {
                let name = if unit.contains('.') {
                    unit.clone()
                } else {
                    format!("{unit}.service")
                };
                probe.units.insert(name, state);
            }
        }
        probe
    }

    fn check(&self) -> Result<(), ProbeError> {
        match &self.fail {
            Some(message) => Err(ProbeError(message.clone())),
            None => Ok(()),
        }
    }
}

impl SystemProbe for FakeProbe {
    fn explicit_packages(&self) -> Result<BTreeSet<String>, ProbeError> {
        self.check()?;
        Ok(self.packages.clone())
    }

    fn etc_entry(&self, path: &str) -> Result<Option<EtcEntry>, ProbeError> {
        self.check()?;
        Ok(self.etc.get(path).cloned())
    }

    fn unit_state(&self, unit: &str) -> Result<UnitState, ProbeError> {
        self.check()?;
        Ok(self.units.get(unit).copied().unwrap_or(UnitState::NotFound))
    }
}
```

- [ ] **Step 3: Write the failing tests**

`aios-cli/crates/aios-plan/tests/desired.rs`:
```rust
mod common;

use aios_plan::{desired_etc, EtcEntry, PlanError, MANAGED_FILES};
use aios_render::{cmdline, fstab, managed_list, UserDbError};
use common::{fixture, fixture_with, text_file, FakeProbe, ELI_HASH, MANIFEST};

#[test]
fn desired_has_every_managed_path() {
    let fx = fixture();
    let desired = desired_etc(&fx.inputs(), &FakeProbe::base()).unwrap();
    let paths: Vec<&str> = desired.keys().map(String::as_str).collect();
    assert_eq!(
        paths,
        [
            "/etc/aios/home/eli/.local/bin/hello",
            "/etc/aios/home/eli/.local/bin/lib/util.sh",
            "/etc/aios/home/eli/.zshrc",
            "/etc/aios/managed-files",
            "/etc/fstab",
            "/etc/group",
            "/etc/gshadow",
            "/etc/hostname",
            "/etc/kernel/cmdline",
            "/etc/locale.conf",
            "/etc/locale.gen",
            "/etc/localtime",
            "/etc/nftables.conf",
            "/etc/pacman.d/hooks/90-mkinitcpio-install.hook",
            "/etc/passwd",
            "/etc/shadow",
            "/etc/tmpfiles.d/aios-home.conf",
            "/etc/tmpfiles.d/aios-persist.conf",
            "/etc/vconsole.conf",
        ]
    );
}

#[test]
fn files_entries_carry_content_manifest_mode_and_symlinks() {
    let fx = fixture();
    let d = desired_etc(&fx.inputs(), &FakeProbe::base()).unwrap();
    assert_eq!(d["/etc/nftables.conf"], text_file("flush ruleset\n", 0o600));
    assert_eq!(
        d["/etc/pacman.d/hooks/90-mkinitcpio-install.hook"],
        EtcEntry::Symlink("/dev/null".to_string())
    );
}

#[test]
fn generated_files_come_from_the_renderers() {
    let fx = fixture();
    let d = desired_etc(&fx.inputs(), &FakeProbe::base()).unwrap();
    assert_eq!(
        d["/etc/fstab"],
        text_file(&fstab(&fx.manifest, &fx.ctx), 0o644)
    );
    assert_eq!(
        d["/etc/kernel/cmdline"],
        text_file(&cmdline(&fx.manifest, &fx.ctx), 0o644)
    );
    assert_eq!(d["/etc/hostname"], text_file("nightcity\n", 0o644));
    assert_eq!(
        d["/etc/locale.gen"],
        text_file("en_US.UTF-8 UTF-8\n", 0o644)
    );
    assert_eq!(
        d["/etc/localtime"],
        EtcEntry::Symlink("/usr/share/zoneinfo/Asia/Jerusalem".to_string())
    );
}

#[test]
fn locale_gen_is_omitted_for_c_utf8() {
    let fx = fixture_with(&MANIFEST.replace("en_US.UTF-8", "C.UTF-8"));
    let d = desired_etc(&fx.inputs(), &FakeProbe::base()).unwrap();
    assert!(!d.contains_key("/etc/locale.gen"));
    assert_eq!(d["/etc/locale.conf"], text_file("LANG=C.UTF-8\n", 0o644));
}

#[test]
fn account_files_merge_declared_users_into_the_probe_state() {
    let fx = fixture();
    let d = desired_etc(&fx.inputs(), &FakeProbe::base()).unwrap();
    assert_eq!(
        d["/etc/passwd"],
        text_file(
            "root:x:0:0::/root:/usr/bin/bash\n\
             nobody:x:65534:65534:Kernel Overflow User:/:/usr/bin/nologin\n\
             eli:x:1000:1000::/home/eli:/usr/bin/zsh\n",
            0o644
        )
    );
    assert_eq!(
        d["/etc/group"],
        text_file(
            "root:x:0:root\nwheel:x:998:eli\nnobody:x:65534:\neli:x:1000:\n",
            0o644
        )
    );
    let shadow =
        format!("root:!*:20000::::::\nnobody:!*:20000::::::\neli:{ELI_HASH}:20760:0:99999:7:::\n");
    assert_eq!(d["/etc/shadow"], text_file(&shadow, 0o600));
    assert_eq!(
        d["/etc/gshadow"],
        text_file("root:::root\nwheel:!*::eli\nnobody:!*::\neli:!*::\n", 0o600)
    );
}

#[test]
fn absent_account_files_mean_empty_databases() {
    let fx = fixture_with(&MANIFEST.replace("groups = [\"wheel\"]", "groups = []"));
    let d = desired_etc(&fx.inputs(), &FakeProbe::default()).unwrap();
    assert_eq!(
        d["/etc/passwd"],
        text_file("eli:x:1000:1000::/home/eli:/usr/bin/zsh\n", 0o644)
    );
    assert_eq!(d["/etc/group"], text_file("eli:x:1000:\n", 0o644));
}

#[test]
fn home_sources_copy_files_and_walk_directories() {
    let fx = fixture();
    let d = desired_etc(&fx.inputs(), &FakeProbe::base()).unwrap();
    assert_eq!(
        d["/etc/aios/home/eli/.zshrc"],
        text_file("# zshrc\n", 0o644)
    );
    assert_eq!(
        d["/etc/aios/home/eli/.local/bin/hello"],
        text_file("#!/bin/sh\necho hello\n", 0o755)
    );
    assert_eq!(
        d["/etc/aios/home/eli/.local/bin/lib/util.sh"],
        text_file("util() { :; }\n", 0o700)
    );
}

#[test]
fn managed_files_lists_every_path_including_itself() {
    let fx = fixture();
    let d = desired_etc(&fx.inputs(), &FakeProbe::base()).unwrap();
    let paths: Vec<String> = d.keys().cloned().collect();
    assert!(paths.iter().any(|p| p == MANAGED_FILES));
    assert_eq!(d[MANAGED_FILES], text_file(&managed_list(&paths), 0o644));
}

#[test]
fn bad_mode_is_an_error() {
    let fx = fixture_with(&MANIFEST.replace("mode = \"0600\"", "mode = \"0999\""));
    let err = desired_etc(&fx.inputs(), &FakeProbe::base()).unwrap_err();
    assert_eq!(
        err,
        PlanError::BadMode {
            path: "/etc/nftables.conf".to_string(),
            mode: "0999".to_string()
        }
    );
    assert_eq!(
        err.to_string(),
        "file \"/etc/nftables.conf\": invalid mode \"0999\""
    );
}

#[test]
fn missing_source_is_an_io_error() {
    let fx = fixture_with(&MANIFEST.replace("files/nftables.conf", "files/missing.conf"));
    match desired_etc(&fx.inputs(), &FakeProbe::base()).unwrap_err() {
        PlanError::Io { path, .. } => assert!(path.ends_with("files/missing.conf"), "got {path}"),
        other => panic!("expected PlanError::Io, got {other:?}"),
    }
}

#[test]
fn account_parse_errors_propagate() {
    let fx = fixture();
    let mut probe = FakeProbe::base();
    probe
        .etc
        .insert("/etc/passwd".to_string(), text_file("broken\n", 0o644));
    assert_eq!(
        desired_etc(&fx.inputs(), &probe).unwrap_err(),
        PlanError::Users(UserDbError::Malformed {
            file: "passwd",
            line: 1
        })
    );
}
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `cd aios-cli && cargo test -p aios-plan --test desired`
Expected: compile errors `unresolved imports aios_plan::desired_etc, aios_plan::EtcEntry, aios_plan::Inputs, ...` (from `common/mod.rs`) and `unresolved imports aios_plan::desired_etc, aios_plan::EtcEntry, aios_plan::PlanError, aios_plan::MANAGED_FILES`.

- [ ] **Step 5: Implement `probe.rs`**

`aios-cli/crates/aios-plan/src/probe.rs`:
```rust
use std::collections::BTreeSet;
use std::fmt;

/// One entry of a generation's `/etc`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EtcEntry {
    /// A regular file and its permission bits (`st_mode & 0o7777`).
    File { content: Vec<u8>, mode: u32 },
    /// A symlink and its target.
    Symlink(String),
}

/// `systemctl is-enabled` result, reduced to what the planner compares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitState {
    Enabled,
    Disabled,
    Masked,
    Static,
    NotFound,
}

impl UnitState {
    /// The `systemctl is-enabled` spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            UnitState::Enabled => "enabled",
            UnitState::Disabled => "disabled",
            UnitState::Masked => "masked",
            UnitState::Static => "static",
            UnitState::NotFound => "not-found",
        }
    }
}

impl fmt::Display for UnitState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A probe call failed (command error, unreadable snapshot, ...).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeError(pub String);

impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ProbeError {}

/// Read-only view of the booted generation. The real implementation lives in a later phase;
/// tests use an in-memory fake.
pub trait SystemProbe {
    /// `pacman -Qqe` of the booted generation.
    fn explicit_packages(&self) -> Result<BTreeSet<String>, ProbeError>;
    /// An entry of the booted `@etc-gen-N` snapshot (not the live `/etc`). `None` if absent.
    fn etc_entry(&self, path: &str) -> Result<Option<EtcEntry>, ProbeError>;
    /// Enablement state of a unit in the booted generation.
    fn unit_state(&self, unit: &str) -> Result<UnitState, ProbeError>;
}
```

- [ ] **Step 6: Implement `desired.rs`**

`aios-cli/crates/aios-plan/src/desired.rs`:
```rust
use crate::{EtcEntry, ProbeError, SystemProbe};
use aios_manifest::Manifest;
use aios_render::{
    cmdline, fstab, home_binds, home_tmpfiles, hostname, locale_conf, locale_gen, localtime_target,
    managed_list, merge_users, persist_tmpfiles, vconsole_conf, RenderCtx, UserDb, UserDbError,
};
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Lists every `/etc` path aios wrote into a generation, itself included.
pub const MANAGED_FILES: &str = "/etc/aios/managed-files";
/// Written by the executor for each generation; never part of the desired state.
pub const GENERATION_TOML: &str = "/etc/aios/generation.toml";

/// Everything the planner needs besides the probe.
pub struct Inputs<'a> {
    pub manifest: &'a Manifest,
    /// Root of the manifest repo (holds `files/` and `home/`).
    pub repo_root: &'a Path,
    pub ctx: &'a RenderCtx,
    /// User name -> password hash, trailing newline trimmed.
    pub hashes: &'a BTreeMap<String, String>,
    /// Days since the epoch, for shadow `lastchg`.
    pub today_days: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    Users(UserDbError),
    Probe(ProbeError),
    Io { path: String, message: String },
    BadMode { path: String, mode: String },
}

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlanError::Users(e) => write!(f, "{e}"),
            PlanError::Probe(e) => write!(f, "probe failed: {e}"),
            PlanError::Io { path, message } => write!(f, "{path}: {message}"),
            PlanError::BadMode { path, mode } => {
                write!(f, "file {path:?}: invalid mode {mode:?}")
            }
        }
    }
}

impl std::error::Error for PlanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PlanError::Users(e) => Some(e),
            PlanError::Probe(e) => Some(e),
            PlanError::Io { .. } | PlanError::BadMode { .. } => None,
        }
    }
}

impl From<UserDbError> for PlanError {
    fn from(e: UserDbError) -> Self {
        PlanError::Users(e)
    }
}

impl From<ProbeError> for PlanError {
    fn from(e: ProbeError) -> Self {
        PlanError::Probe(e)
    }
}

/// Every `/etc` entry aios writes into a generation built from `inputs`.
///
/// Later sources win on a path clash: `[files]`, then generated files, then account files,
/// then home bind sources, then `managed-files`. The account files merge the declared users
/// into the probe's current `passwd`/`group`/`shadow`/`gshadow` (absent = empty).
pub fn desired_etc(
    inputs: &Inputs,
    probe: &dyn SystemProbe,
) -> Result<BTreeMap<String, EtcEntry>, PlanError> {
    let m = inputs.manifest;
    let ctx = inputs.ctx;
    let mut out = BTreeMap::new();

    for (path, entry) in &m.files {
        let value = match (&entry.source, &entry.symlink) {
            (_, Some(target)) => EtcEntry::Symlink(target.clone()),
            (Some(source), None) => EtcEntry::File {
                content: read(&inputs.repo_root.join(source))?,
                mode: parse_mode(path, entry.mode_or_default())?,
            },
            (None, None) => {
                return Err(PlanError::Io {
                    path: path.clone(),
                    message: "neither source nor symlink is set".to_string(),
                })
            }
        };
        out.insert(path.clone(), value);
    }

    let generated = [
        ("/etc/fstab", fstab(m, ctx)),
        ("/etc/hostname", hostname(m)),
        ("/etc/locale.conf", locale_conf(m)),
        ("/etc/locale.gen", locale_gen(m)),
        ("/etc/vconsole.conf", vconsole_conf(m)),
        ("/etc/kernel/cmdline", cmdline(m, ctx)),
        ("/etc/tmpfiles.d/aios-persist.conf", persist_tmpfiles(m)),
        ("/etc/tmpfiles.d/aios-home.conf", home_tmpfiles(m)),
    ];
    for (path, text) in generated {
        // Only locale.gen can be empty (C.UTF-8); an empty render means "don't write it".
        if !text.is_empty() {
            out.insert(path.to_string(), file(text.into_bytes(), 0o644));
        }
    }
    out.insert(
        "/etc/localtime".to_string(),
        EtcEntry::Symlink(localtime_target(m)),
    );

    let db = UserDb::parse(
        &etc_text(probe, "/etc/passwd")?,
        &etc_text(probe, "/etc/group")?,
        &etc_text(probe, "/etc/shadow")?,
        &etc_text(probe, "/etc/gshadow")?,
    )?;
    let users = merge_users(m, &db, inputs.hashes, inputs.today_days)?.render();
    for (path, text, mode) in [
        ("/etc/passwd", users.passwd, 0o644),
        ("/etc/group", users.group, 0o644),
        ("/etc/shadow", users.shadow, 0o600),
        ("/etc/gshadow", users.gshadow, 0o600),
    ] {
        out.insert(path.to_string(), file(text.into_bytes(), mode));
    }

    for bind in home_binds(m) {
        let source = inputs.repo_root.join(&bind.repo_source);
        if bind.is_dir {
            for (rel, entry) in walk(&source)? {
                out.insert(format!("{}/{rel}", bind.bind_source), entry);
            }
        } else {
            out.insert(bind.bind_source.clone(), repo_file(&source)?);
        }
    }

    let mut paths: Vec<String> = out
        .keys()
        .filter(|p| p.as_str() != GENERATION_TOML)
        .cloned()
        .collect();
    paths.push(MANAGED_FILES.to_string());
    out.insert(
        MANAGED_FILES.to_string(),
        file(managed_list(&paths).into_bytes(), 0o644),
    );
    Ok(out)
}

fn file(content: Vec<u8>, mode: u32) -> EtcEntry {
    EtcEntry::File { content, mode }
}

fn io_error(path: &Path, e: impl fmt::Display) -> PlanError {
    PlanError::Io {
        path: path.display().to_string(),
        message: e.to_string(),
    }
}

fn read(path: &Path) -> Result<Vec<u8>, PlanError> {
    fs::read(path).map_err(|e| io_error(path, e))
}

/// A manifest-repo file as it will be copied: content plus permission bits.
fn repo_file(path: &Path) -> Result<EtcEntry, PlanError> {
    let meta = fs::metadata(path).map_err(|e| io_error(path, e))?;
    Ok(file(read(path)?, meta.permissions().mode() & 0o777))
}

/// Every regular file below `dir` as (`/`-separated relative path, entry), sorted by path.
fn walk(dir: &Path) -> Result<Vec<(String, EtcEntry)>, PlanError> {
    let mut out = Vec::new();
    walk_into(dir, "", &mut out)?;
    Ok(out)
}

fn walk_into(dir: &Path, prefix: &str, out: &mut Vec<(String, EtcEntry)>) -> Result<(), PlanError> {
    let mut entries = fs::read_dir(dir)
        .and_then(|it| it.collect::<Result<Vec<_>, _>>())
        .map_err(|e| io_error(dir, e))?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let name = entry.file_name().to_string_lossy().into_owned();
        let rel = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let path = entry.path();
        let kind = entry.file_type().map_err(|e| io_error(&path, e))?;
        if kind.is_dir() {
            walk_into(&path, &rel, out)?;
        } else if kind.is_file() {
            out.push((rel, repo_file(&path)?));
        }
    }
    Ok(())
}

/// `"0644"` -> `0o644`. Accepts 3 or 4 octal digits, like manifest validation.
fn parse_mode(path: &str, mode: &str) -> Result<u32, PlanError> {
    let bad = || PlanError::BadMode {
        path: path.to_string(),
        mode: mode.to_string(),
    };
    if !(3..=4).contains(&mode.len()) || !mode.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
        return Err(bad());
    }
    u32::from_str_radix(mode, 8).map_err(|_| bad())
}

/// Text of an account file in the probe; an absent file is empty.
fn etc_text(probe: &dyn SystemProbe, path: &str) -> Result<String, PlanError> {
    match probe.etc_entry(path)? {
        None => Ok(String::new()),
        Some(EtcEntry::File { content, .. }) => {
            String::from_utf8(content).map_err(|e| PlanError::Io {
                path: path.to_string(),
                message: e.to_string(),
            })
        }
        Some(EtcEntry::Symlink(target)) => Err(PlanError::Io {
            path: path.to_string(),
            message: format!("is a symlink to {target}, expected a regular file"),
        }),
    }
}
```

- [ ] **Step 7: Replace `lib.rs`**

`aios-cli/crates/aios-plan/src/lib.rs`:
```rust
//! Compare the manifest with the booted generation: what would `aios apply` change?
//!
//! All system access goes through [`SystemProbe`], so every test runs without root.

mod desired;
mod probe;

pub use desired::{desired_etc, Inputs, PlanError, GENERATION_TOML, MANAGED_FILES};
pub use probe::{EtcEntry, ProbeError, SystemProbe, UnitState};
```

- [ ] **Step 8: Run the tests to verify they pass**

Run: `cd aios-cli && cargo test -p aios-plan --test desired`
Expected: `test result: ok. 11 passed`.

- [ ] **Step 9: Lint**

Run: `make check`
Expected: `cargo fmt --check` prints nothing, clippy prints no warnings, and every test binary reports `test result: ok`. If fmt complains, run `cargo fmt --all` in `aios-cli/` and re-run.

- [ ] **Step 10: Commit**

```bash
cd /home/eli/Development/AIOS
git add aios-cli/
git commit -m "feat(plan): SystemProbe trait and desired /etc state"
```

---
### Task 7: `build_plan` and the human-readable plan

**Files:**
- Create: `aios-cli/crates/aios-plan/src/plan.rs`
- Modify: `aios-cli/crates/aios-plan/src/lib.rs` (full content below)
- Test: `aios-cli/crates/aios-plan/tests/plan.rs`

Rules:
- **Packages:** add = `package_set()` − `explicit_packages()`, remove = the reverse. Both sorted.
- **`/etc`:** each desired path is `Add` if the probe lacks it and `Modify` if content, mode or symlink target differ. Each path in the booted `/etc/aios/managed-files` that is no longer desired is `Remove`. Sorted by path.
- **Units:** a name without `.` gets `.service`. `enable` wants `enabled`, `disable` wants `disabled` and `mask` wants `masked`. For a unit listed twice, `mask` beats `disable`, which beats `enable`. `static` satisfies `enable` (spec); `static` and `not-found` satisfy `disable`, since a unit that can't be enabled is already "not enabled". Sorted by unit name.
- **Warnings:** `kernel.lockdown = "none": unsigned kernel modules can be loaded` when lockdown is off. `Plan::is_empty()` ignores warnings.
- **Display:** sections `packages:` (`  + name` lines, then `  - name`), `/etc:` (`  + path` / `  ~ path` / `  - path`), `services:` (`  unit: from -> to`, lowercase `systemctl is-enabled` names), then `warning: ...` lines. Empty sections are omitted. An empty plan prints `no changes` followed by any warnings.

- [ ] **Step 1: Write the failing tests**

`aios-cli/crates/aios-plan/tests/plan.rs`:
```rust
mod common;

use aios_plan::{
    build_plan, ChangeKind, EtcChange, Plan, PlanError, ProbeError, UnitChange, UnitState,
};
use common::{fixture, fixture_with, text_file, FakeProbe, MANIFEST};
use std::collections::BTreeMap;

fn change(path: &str, kind: ChangeKind) -> EtcChange {
    EtcChange {
        path: path.to_string(),
        kind,
    }
}

fn unit(name: &str, from: UnitState, to: UnitState) -> UnitChange {
    UnitChange {
        unit: name.to_string(),
        from,
        to,
    }
}

#[test]
fn empty_probe_adds_everything() {
    let fx = fixture_with(&MANIFEST.replace("groups = [\"wheel\"]", "groups = []"));
    let plan = build_plan(&fx.inputs(), &FakeProbe::default()).unwrap();
    assert_eq!(plan.packages_add, fx.manifest.package_set());
    assert!(plan.packages_remove.is_empty());
    assert_eq!(plan.etc_changes.len(), 19);
    assert!(plan.etc_changes.iter().all(|c| c.kind == ChangeKind::Add));
    assert!(plan.etc_changes.windows(2).all(|w| w[0].path < w[1].path));
    assert_eq!(
        plan.unit_changes,
        [
            unit(
                "NetworkManager.service",
                UnitState::NotFound,
                UnitState::Enabled
            ),
            unit(
                "fwupd-refresh.timer",
                UnitState::NotFound,
                UnitState::Enabled
            ),
            unit("sshd.socket", UnitState::NotFound, UnitState::Masked),
        ]
    );
}

#[test]
fn synced_probe_has_no_changes() {
    let fx = fixture();
    let plan = build_plan(&fx.inputs(), &FakeProbe::synced(&fx)).unwrap();
    assert!(plan.is_empty(), "unexpected plan:\n{plan}");
    assert_eq!(plan.to_string(), "no changes\n");
}

#[test]
fn synced_probe_stays_clean_on_a_later_day() {
    let fx = fixture();
    let probe = FakeProbe::synced(&fx);
    let mut inputs = fx.inputs();
    inputs.today_days += 30;
    assert!(build_plan(&inputs, &probe).unwrap().is_empty());
}

#[test]
fn content_change_is_modify() {
    let fx = fixture();
    let mut probe = FakeProbe::synced(&fx);
    probe.etc.insert(
        "/etc/nftables.conf".to_string(),
        text_file("old ruleset\n", 0o600),
    );
    let plan = build_plan(&fx.inputs(), &probe).unwrap();
    assert_eq!(
        plan.etc_changes,
        [change("/etc/nftables.conf", ChangeKind::Modify)]
    );
}

#[test]
fn mode_change_is_modify() {
    let fx = fixture();
    let mut probe = FakeProbe::synced(&fx);
    probe.etc.insert(
        "/etc/nftables.conf".to_string(),
        text_file("flush ruleset\n", 0o644),
    );
    let plan = build_plan(&fx.inputs(), &probe).unwrap();
    assert_eq!(
        plan.etc_changes,
        [change("/etc/nftables.conf", ChangeKind::Modify)]
    );
}

#[test]
fn dropped_file_is_removed_via_managed_files() {
    let probe = FakeProbe::synced(&fixture());
    let fx = fixture_with(&MANIFEST.replace(
        "\"/etc/pacman.d/hooks/90-mkinitcpio-install.hook\" = { symlink = \"/dev/null\" }\n",
        "",
    ));
    let plan = build_plan(&fx.inputs(), &probe).unwrap();
    assert_eq!(
        plan.etc_changes,
        [
            change("/etc/aios/managed-files", ChangeKind::Modify),
            change(
                "/etc/pacman.d/hooks/90-mkinitcpio-install.hook",
                ChangeKind::Remove
            ),
        ]
    );
}

#[test]
fn package_differences_are_sorted() {
    let fx = fixture();
    let mut probe = FakeProbe::synced(&fx);
    probe.packages.remove("zsh");
    probe.packages.insert("vim".to_string());
    probe.packages.insert("nano".to_string());
    let plan = build_plan(&fx.inputs(), &probe).unwrap();
    assert_eq!(plan.packages_add, ["zsh"]);
    assert_eq!(plan.packages_remove, ["nano", "vim"]);
    assert!(plan.etc_changes.is_empty());
}

#[test]
fn unit_changes_sorted_with_service_suffix_and_static_as_enabled() {
    let fx = fixture();
    let mut probe = FakeProbe::synced(&fx);
    probe.units = BTreeMap::from([
        ("NetworkManager.service".to_string(), UnitState::Disabled),
        ("fwupd-refresh.timer".to_string(), UnitState::Static),
        ("bluetooth.service".to_string(), UnitState::Enabled),
        ("sshd.socket".to_string(), UnitState::Disabled),
    ]);
    let plan = build_plan(&fx.inputs(), &probe).unwrap();
    assert_eq!(
        plan.unit_changes,
        [
            unit(
                "NetworkManager.service",
                UnitState::Disabled,
                UnitState::Enabled
            ),
            unit("bluetooth.service", UnitState::Enabled, UnitState::Disabled),
            unit("sshd.socket", UnitState::Disabled, UnitState::Masked),
        ]
    );
}

#[test]
fn disable_is_satisfied_by_static_or_missing_units() {
    let fx = fixture();
    let mut probe = FakeProbe::synced(&fx);
    probe
        .units
        .insert("bluetooth.service".to_string(), UnitState::Static);
    assert!(build_plan(&fx.inputs(), &probe)
        .unwrap()
        .unit_changes
        .is_empty());
    probe.units.remove("bluetooth.service");
    assert!(build_plan(&fx.inputs(), &probe)
        .unwrap()
        .unit_changes
        .is_empty());
}

#[test]
fn mask_beats_disable_beats_enable() {
    let probe = FakeProbe::synced(&fixture());
    let fx = fixture_with(&MANIFEST.replace(
        "disable = [\"bluetooth\"]",
        "disable = [\"bluetooth\", \"NetworkManager\", \"sshd.socket\"]",
    ));
    let plan = build_plan(&fx.inputs(), &probe).unwrap();
    assert_eq!(
        plan.unit_changes,
        [unit(
            "NetworkManager.service",
            UnitState::Enabled,
            UnitState::Disabled
        )]
    );
}

#[test]
fn lockdown_none_warns_without_dirtying_the_plan() {
    let fx = fixture_with(&MANIFEST.replace("lockdown = \"integrity\"", "lockdown = \"none\""));
    let plan = build_plan(&fx.inputs(), &FakeProbe::synced(&fx)).unwrap();
    assert!(plan.is_empty());
    assert_eq!(
        plan.warnings,
        ["kernel.lockdown = \"none\": unsigned kernel modules can be loaded"]
    );
    assert_eq!(
        plan.to_string(),
        "no changes\nwarning: kernel.lockdown = \"none\": unsigned kernel modules can be loaded\n"
    );
}

#[test]
fn switching_lockdown_modifies_the_kernel_cmdline() {
    let probe = FakeProbe::synced(&fixture());
    let fx = fixture_with(&MANIFEST.replace("lockdown = \"integrity\"", "lockdown = \"none\""));
    let plan = build_plan(&fx.inputs(), &probe).unwrap();
    assert_eq!(
        plan.etc_changes,
        [change("/etc/kernel/cmdline", ChangeKind::Modify)]
    );
}

#[test]
fn display_lists_every_section_in_order() {
    let plan = Plan {
        packages_add: vec!["tree".to_string()],
        packages_remove: vec!["nano".to_string()],
        etc_changes: vec![
            change("/etc/fstab", ChangeKind::Modify),
            change("/etc/issue", ChangeKind::Add),
            change("/etc/old.conf", ChangeKind::Remove),
        ],
        unit_changes: vec![unit("sshd.service", UnitState::Enabled, UnitState::Masked)],
        warnings: vec!["something to know".to_string()],
    };
    assert_eq!(
        plan.to_string(),
        "packages:
  + tree
  - nano
/etc:
  ~ /etc/fstab
  + /etc/issue
  - /etc/old.conf
services:
  sshd.service: enabled -> masked
warning: something to know
"
    );
}

#[test]
fn display_omits_empty_sections() {
    let plan = Plan {
        unit_changes: vec![unit("a.service", UnitState::NotFound, UnitState::Enabled)],
        ..Plan::default()
    };
    assert!(!plan.is_empty());
    assert_eq!(
        plan.to_string(),
        "services:\n  a.service: not-found -> enabled\n"
    );
}

#[test]
fn probe_errors_propagate() {
    let fx = fixture();
    let probe = FakeProbe {
        fail: Some("pacman exited 1".to_string()),
        ..FakeProbe::default()
    };
    assert_eq!(
        build_plan(&fx.inputs(), &probe).unwrap_err(),
        PlanError::Probe(ProbeError("pacman exited 1".to_string()))
    );
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd aios-cli && cargo test -p aios-plan --test plan`
Expected: compile error `unresolved imports aios_plan::build_plan, aios_plan::ChangeKind, aios_plan::EtcChange, aios_plan::Plan, aios_plan::UnitChange`.

- [ ] **Step 3: Implement `plan.rs`**

`aios-cli/crates/aios-plan/src/plan.rs`:
```rust
use crate::{desired_etc, EtcEntry, Inputs, PlanError, SystemProbe, UnitState, MANAGED_FILES};
use aios_manifest::Lockdown;
use aios_render::parse_managed_list;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Printed whenever the manifest turns kernel lockdown off (spec §5.4).
pub const LOCKDOWN_NONE_WARNING: &str =
    "kernel.lockdown = \"none\": unsigned kernel modules can be loaded";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    Add,
    Modify,
    Remove,
}

impl ChangeKind {
    fn marker(self) -> char {
        match self {
            ChangeKind::Add => '+',
            ChangeKind::Modify => '~',
            ChangeKind::Remove => '-',
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EtcChange {
    pub path: String,
    pub kind: ChangeKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitChange {
    pub unit: String,
    pub from: UnitState,
    pub to: UnitState,
}

/// What `aios apply` would change relative to the booted generation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Plan {
    pub packages_add: Vec<String>,
    pub packages_remove: Vec<String>,
    pub etc_changes: Vec<EtcChange>,
    pub unit_changes: Vec<UnitChange>,
    pub warnings: Vec<String>,
}

impl Plan {
    /// True when there is nothing to apply. Warnings don't count.
    pub fn is_empty(&self) -> bool {
        self.packages_add.is_empty()
            && self.packages_remove.is_empty()
            && self.etc_changes.is_empty()
            && self.unit_changes.is_empty()
    }
}

/// Diff the manifest against the booted generation.
///
/// - Packages: the manifest's package set against `pacman -Qqe`.
/// - `/etc`: [`desired_etc`] against the booted snapshot; paths listed in its
///   `managed-files` that are no longer desired are removals.
/// - Units: `enable`/`disable`/`mask`, with `mask` beating `disable` beating `enable` for a
///   unit listed twice. `static` satisfies `enable`; `static` and `not-found` satisfy `disable`.
pub fn build_plan(inputs: &Inputs, probe: &dyn SystemProbe) -> Result<Plan, PlanError> {
    let m = inputs.manifest;

    let want: BTreeSet<String> = m.package_set().into_iter().collect();
    let have = probe.explicit_packages()?;
    let packages_add = want.difference(&have).cloned().collect();
    let packages_remove = have.difference(&want).cloned().collect();

    let desired = desired_etc(inputs, probe)?;
    let mut etc_changes = Vec::new();
    for (path, entry) in &desired {
        let kind = match probe.etc_entry(path)? {
            None => Some(ChangeKind::Add),
            Some(current) if current != *entry => Some(ChangeKind::Modify),
            Some(_) => None,
        };
        if let Some(kind) = kind {
            etc_changes.push(EtcChange {
                path: path.clone(),
                kind,
            });
        }
    }
    if let Some(EtcEntry::File { content, .. }) = probe.etc_entry(MANAGED_FILES)? {
        for path in parse_managed_list(&String::from_utf8_lossy(&content)) {
            if !desired.contains_key(&path) {
                etc_changes.push(EtcChange {
                    path,
                    kind: ChangeKind::Remove,
                });
            }
        }
    }
    etc_changes.sort_by(|a, b| a.path.cmp(&b.path));

    let services = &m.services;
    let mut wanted: BTreeMap<String, UnitState> = BTreeMap::new();
    for (units, state) in [
        (&services.enable, UnitState::Enabled),
        (&services.disable, UnitState::Disabled),
        (&services.mask, UnitState::Masked),
    ] {
        for unit in units {
            wanted.insert(unit_name(unit), state);
        }
    }
    let mut unit_changes = Vec::new();
    for (unit, to) in wanted {
        let from = probe.unit_state(&unit)?;
        if !satisfied(from, to) {
            unit_changes.push(UnitChange { unit, from, to });
        }
    }

    let mut warnings = Vec::new();
    if m.kernel.lockdown == Lockdown::None {
        warnings.push(LOCKDOWN_NONE_WARNING.to_string());
    }

    Ok(Plan {
        packages_add,
        packages_remove,
        etc_changes,
        unit_changes,
        warnings,
    })
}

/// `NetworkManager` -> `NetworkManager.service`. Names with a type suffix are kept.
fn unit_name(name: &str) -> String {
    if name.contains('.') {
        name.to_string()
    } else {
        format!("{name}.service")
    }
}

fn satisfied(from: UnitState, to: UnitState) -> bool {
    from == to
        || matches!(
            (to, from),
            (UnitState::Enabled, UnitState::Static)
                | (UnitState::Disabled, UnitState::Static | UnitState::NotFound)
        )
}

impl fmt::Display for Plan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            writeln!(f, "no changes")?;
        }
        if !self.packages_add.is_empty() || !self.packages_remove.is_empty() {
            writeln!(f, "packages:")?;
            for name in &self.packages_add {
                writeln!(f, "  + {name}")?;
            }
            for name in &self.packages_remove {
                writeln!(f, "  - {name}")?;
            }
        }
        if !self.etc_changes.is_empty() {
            writeln!(f, "/etc:")?;
            for change in &self.etc_changes {
                writeln!(f, "  {} {}", change.kind.marker(), change.path)?;
            }
        }
        if !self.unit_changes.is_empty() {
            writeln!(f, "services:")?;
            for change in &self.unit_changes {
                writeln!(f, "  {}: {} -> {}", change.unit, change.from, change.to)?;
            }
        }
        for warning in &self.warnings {
            writeln!(f, "warning: {warning}")?;
        }
        Ok(())
    }
}
```

- [ ] **Step 4: Replace `lib.rs`**

`aios-cli/crates/aios-plan/src/lib.rs`:
```rust
//! Compare the manifest with the booted generation: what would `aios apply` change?
//!
//! All system access goes through [`SystemProbe`], so every test runs without root.

mod desired;
mod plan;
mod probe;

pub use desired::{desired_etc, Inputs, PlanError, GENERATION_TOML, MANAGED_FILES};
pub use plan::{build_plan, ChangeKind, EtcChange, Plan, UnitChange, LOCKDOWN_NONE_WARNING};
pub use probe::{EtcEntry, ProbeError, SystemProbe, UnitState};
```

- [ ] **Step 5: Run the crate's tests**

Run: `cd aios-cli && cargo test -p aios-plan`
Expected: `desired`: `test result: ok. 11 passed`; `plan`: `test result: ok. 15 passed` (26 total). The lib unit tests and doc-tests report `0 passed`.

- [ ] **Step 6: Lint**

Run: `make check`
Expected: `cargo fmt --check` prints nothing, clippy prints no warnings, and every test binary reports `test result: ok`. If fmt complains, run `cargo fmt --all` in `aios-cli/` and re-run.

- [ ] **Step 7: Commit**

```bash
cd /home/eli/Development/AIOS
git add aios-cli/
git commit -m "feat(plan): build_plan diff and human-readable output"
```

---
### Task 8: `make check` gate for Phase 2

**Files:** none expected. A fix is committed only if a step below finds a problem.

- [ ] **Step 1: Full check**

Run: `make check`
Expected: fmt and clippy print no diagnostics. `cargo test --workspace` reports `test result: ok` for every binary, and these counts for the Phase 2 binaries:

| Crate | Binary | Passed |
|---|---|---|
| aios-render | `cmdline` | 4 |
| aios-render | `fstab` | 4 |
| aios-render | `home` | 3 |
| aios-render | `managed` | 3 |
| aios-render | `simple` | 3 |
| aios-render | `tmpfiles` | 5 |
| aios-render | `users_db` | 8 |
| aios-render | `users_merge` | 12 |
| aios-plan | `desired` | 11 |
| aios-plan | `plan` | 15 |

That makes 42 for `aios-render` and 26 for `aios-plan`. The Phase 1 crates keep whatever counts Phase 1 ended with.

- [ ] **Step 2: Prove the new crates are pure**

Run: `cd /home/eli/Development/AIOS && grep -rnE "std::process|Command::new|set_permissions|fs::write|remove_file" aios-cli/crates/aios-render/src aios-cli/crates/aios-plan/src`
Expected: no output (grep exits 1 when nothing matches; that is the pass condition). Neither crate runs commands or writes files. `aios-plan` only reads the manifest repo, and the tests write only inside `TempDir`.

Run: `cd /home/eli/Development/AIOS && grep -rn "std::fs" aios-cli/crates/aios-render/src`
Expected: no output (exit status 1). `aios-render` doesn't touch the filesystem at all.

- [ ] **Step 3: Tests run unprivileged**

Run: `id -u`
Expected: a non-zero uid. Step 1 has already passed as this user, so no test needs root.

- [ ] **Step 4: Commit (only if Steps 1–3 required a change)**

```bash
cd /home/eli/Development/AIOS
git status --short
```
Expected: no output after Task 7's commit. If a fix was needed, commit it:
```bash
git add aios-cli/
git commit -m "chore: phase 2 make check fixes"
```

---

## Contracts for Phase 3 (`aios-exec`, `aios` binary)

These follow from the Phase 2 code. The Phase 3 plan must honor them.

1. **`aios plan` renders with the booted generation's id.** `RenderCtx.gen` appears in the fstab header and the kernel cmdline (`aios.gen=`, `@usr-gen-NNNN`). `plan` must pass `ctx.gen = booted`, or those two files always differ. `apply` renders with `N+1`.
2. **`hashes`** holds the content of `secrets/passwd/<user>` with the trailing newline trimmed. `merge_users` rejects any remaining `\n`.
3. **`today_days`** is `SystemTime::now()` in whole days since the epoch (UTC).
4. **The real `SystemProbe`** reads `etc_entry` from the booted `@etc-gen-N` snapshot (not the live `/etc`), returning `st_mode & 0o7777` for files. `explicit_packages` is `pacman -Qqe` of the booted generation. `unit_state` maps `systemctl --root=<booted snapshot> is-enabled` onto `UnitState`, at least: `enabled`/`enabled-runtime` → `Enabled`; `disabled` → `Disabled`; `masked`/`masked-runtime` → `Masked`; `static`/`indirect`/`generated`/`transient` → `Static`; `not-found` → `NotFound`. Phase 3 decides the remaining spellings (`alias`, `linked`, `bad`).
5. **When writing `desired_etc` output into `@etc-cand`**, the executor sets owner/group from `[files]` (`owner_or_default`/`group_or_default`; `EtcEntry` carries no owner, so the planner does not see owner-only changes). It deletes every `Remove` path. It writes `/etc/aios/generation.toml` itself.
6. **The executor creates directories the map cannot express:** each `persist_dirs()` entry under the `/persist` subvolume, and `bind_source` for every directory `HomeBind` (an empty repo directory yields no map entries but still needs its bind source).
7. **The executor also** runs `locale-gen` in the chroot when `/etc/locale.gen` is present, enables the AIOS core units (`aios-health.service`; `systemd-bless-boot.service` comes in via `boot-complete.target`) in addition to the manifest units, and the installer writes `loader_conf()` to the ESP.

---

## Self-review

- **Spec coverage:**

  | Spec item | Task | Tests |
  |---|---|---|
  | §3 step 3 cmdline: root/usr tokens, `aios.gen`, hardening (§5.3), extra cmdline | 1 | `full_cmdline_in_spec_order`, `whitespace_is_normalized_to_single_spaces`, `generation_drives_usr_subvolume_and_gen_token` |
  | §5.3 `lockdown=integrity` only when enabled | 1 | `full_cmdline_in_spec_order`, `lockdown_none_adds_no_lockdown_token` |
  | §3 step 9 fstab: `/persist`, `/home`, `/var/log` subvols, `/efi` automount, persist dir binds in manifest order | 2 | `golden_fixture`, `without_persist_or_users_only_base_mounts` |
  | §4.4 read-only home binds in fstab, path escaping | 2 | `golden_fixture`, `paths_with_spaces_are_escaped_in_lines`, `escape_rules`, `fixture_binds_in_key_order`, `users_in_name_order_then_keys` |
  | §3 step 10 persistent files as `L+` symlinks | 3 | `persist_tmpfiles_links_each_file_into_persist` |
  | §4.4 empty user-owned file targets via tmpfiles | 3 | `home_tmpfiles_creates_file_targets_only` |
  | §4.3 step 5 hostname, locale.conf, locale.gen, vconsole.conf, localtime | 3 | `system_files`, `locale_gen_variants` |
  | §3 step 2 / §6.2 step 10 `loader.conf` | 3 | `loader_conf_boots_newest_cachyos_generation` |
  | §4.3 step 5 home sources copied to `/etc/aios/home/<user>/…` | 6 | `home_sources_copy_files_and_walk_directories` |
  | §4.3 step 6 users: system kept, stale removed, declared created, primary group, supplementary groups, root locked, hash from secrets | 4, 5 | `parses_arch_entries`, `render_reproduces_canonical_text`, `golden_merge`, `stale_managed_user_is_removed_everywhere`, `root_is_locked_and_keeps_its_aging_fields`, `empty_database_gets_declared_users`, error tests |
  | Shadow stable across days (plan stays clean) | 5, 7 | `unchanged_hash_is_stable_across_days`, `changed_hash_updates_lastchg`, `synced_probe_stays_clean_on_a_later_day` |
  | §4.2 `aios plan`: packages vs `pacman -Qqe` | 7 | `package_differences_are_sorted`, `empty_probe_adds_everything` |
  | §4.2 files, users, persist, home and cmdline changes (all are `/etc` entries) | 6, 7 | `desired_has_every_managed_path`, `content_change_is_modify`, `mode_change_is_modify`, `switching_lockdown_modifies_the_kernel_cmdline`, `dropped_file_is_removed_via_managed_files` |
  | §4.2 services | 7 | `unit_changes_sorted_with_service_suffix_and_static_as_enabled`, `disable_is_satisfied_by_static_or_missing_units`, `mask_beats_disable_beats_enable` |
  | §4.2 "no changes" / §1 success (c) | 5, 7 | `merge_is_idempotent`, `synced_probe_has_no_changes` |
  | §5.4 warning when `lockdown = "none"` | 7 | `lockdown_none_warns_without_dirtying_the_plan` |
  | §4.1 mode is 3–4 octal digits (defensive re-check) | 6 | `bad_mode_is_an_error` |
  | §4.5 `aios-render` golden tests, `aios-plan` fake probe, no root | 1–8 | inline goldens, `FakeProbe`, Task 8 Steps 2–3 |

- **Decisions made where the spec is silent:**
  - Goldens are inline constants instead of `tests/golden/` files.
  - `fstab_escape` also escapes newline (`\012`).
  - `extra_cmdline` entries are split on whitespace, and empty ones are dropped.
  - The tmpfiles header has no generation number, because its functions take only the manifest.
  - `persist_dirs` is sorted and deduplicated.
  - `merge_users` lives in `merge.rs` and also exports `MANAGED_IDS`.
  - A declared name equal to a kept system group is `NameConflict`.
  - An empty account name is `Malformed`.
  - Units listed twice: mask beats disable, which beats enable.
  - `static` and `not-found` satisfy `disable`.
  - Generated files win over `[files]` on a path clash.
  - Account files that are symlinks or not UTF-8 are `PlanError::Io`.
  - The directory walk skips symlinks.
- **Known limits, left to later phases:**
  - `tmpfiles.d` lines are not escaped, so paths containing whitespace or `%` would break them. A validation rule rejecting such persist and home paths is the simplest fix (Phase 3 or a Phase 1 follow-up).
  - Owner/group-only changes in `[files]` are invisible to the planner (contract 5).
- **Placeholder scan:** every step has complete code or an exact command. No "TBD" or "similar to Task N".
- **Type consistency:**
  - `RenderCtx`, `HomeBind`, `UserDb` and `UserDbError` are defined once in `aios-render` and used unchanged by `aios-plan`.
  - `EtcEntry`, `UnitState`, `ProbeError`, `Inputs` and `PlanError` are defined once in `aios-plan`.
  - Phase 1 APIs are used exactly as that plan defines them (see "Depends on").
