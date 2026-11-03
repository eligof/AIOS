# Base ISO — Phase 1: Workspace + Core Crates Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create the Rust workspace for the `aios` CLI with two pure-logic crates: `aios-manifest` (parse and validate `manifest.toml`) and `aios-gen` (generation ids, subvolume names, UKI file names with boot counters, generation metadata, GC selection).

**Architecture:** Cargo workspace at `aios-cli/`, with crates under `aios-cli/crates/`. No crate in this phase touches the system, so every test runs without root. A top-level `Makefile` exposes `make check` (fmt, clippy -D warnings, tests). Later phases add `aios-render`, `aios-plan`, `aios-exec` and the `aios` binary on top of these types.

**Tech Stack:** Rust 2021 (rustup toolchain in `~/.cargo`), `serde` 1, `toml` 0.8, `tempfile` 3 (dev only).

**Spec:** `docs/superpowers/specs/2026-11-03-base-iso-design.md`, §2 (naming, metadata), §3 (UKI counters), §4.1 (manifest + validation rules), §4.5 (crate layout).

**Environment note for every task:** Rust is installed via rustup without PATH changes. Start every shell with:
```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/eli/Development/AIOS
```

**GateGuard note:** a local hook blocks the *first* Write/Edit of each new file, and the first Bash call, until you state some facts: callers/importers, that no existing file serves the purpose, data schema if any, and the user's instruction. Answer briefly in text and retry the same call. The user's instruction is: "finish this project, use skills and subagents".

---

## File Structure

```
Makefile                                         make check (fmt, clippy, test)
README.md                                        project overview + dev commands
aios-cli/Cargo.toml                              workspace
aios-cli/Cargo.lock                              committed
aios-cli/crates/aios-manifest/Cargo.toml
aios-cli/crates/aios-manifest/src/lib.rs         ManifestError, parse(), load(), re-exports
aios-cli/crates/aios-manifest/src/model.rs       Manifest types, CORE_PACKAGES, KNOWN_KERNELS, package_set()
aios-cli/crates/aios-manifest/src/locate.rs      locate(), offset_to_line_col()
aios-cli/crates/aios-manifest/src/validate.rs    ValidationEnv, validate()
aios-cli/crates/aios-manifest/tests/common/mod.rs   VALID fixture manifest (shared)
aios-cli/crates/aios-manifest/tests/manifest.rs  parse/model tests
aios-cli/crates/aios-manifest/tests/validate.rs  validation tests with tempdir fixtures
aios-cli/crates/aios-gen/Cargo.toml
aios-cli/crates/aios-gen/src/lib.rs              re-exports
aios-cli/crates/aios-gen/src/id.rs               GenId, MAX_GEN, SubvolKind, parse_subvol, list_complete, next_id, gen_from_cmdline
aios-cli/crates/aios-gen/src/uki.rs              Flavor, Counter, UkiName
aios-cli/crates/aios-gen/src/meta.rs             GenerationMeta
aios-cli/crates/aios-gen/src/gc.rs               gc_select
```

---

### Task 1: Workspace scaffold and `make check`

**Files:**
- Create: `Makefile`, `README.md`, `aios-cli/Cargo.toml`
- Create: `aios-cli/crates/aios-manifest/Cargo.toml`, `aios-cli/crates/aios-manifest/src/lib.rs`
- Create: `aios-cli/crates/aios-gen/Cargo.toml`, `aios-cli/crates/aios-gen/src/lib.rs`

- [ ] **Step 1: Check the toolchain**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo --version && cargo clippy --version && cargo fmt --version`
Expected: three version lines. If `cargo` is missing, stop and report BLOCKED.

- [ ] **Step 2: Create the workspace manifest**

`aios-cli/Cargo.toml`:
```toml
[workspace]
resolver = "2"
members = ["crates/aios-manifest", "crates/aios-gen"]

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

- [ ] **Step 3: Create the two crate manifests and empty libs**

`aios-cli/crates/aios-manifest/Cargo.toml`:
```toml
[package]
name = "aios-manifest"
description = "Parse and validate the AIOS system manifest"
version.workspace = true
edition.workspace = true
license.workspace = true
publish.workspace = true

[dependencies]
serde.workspace = true
toml.workspace = true

[dev-dependencies]
tempfile.workspace = true
```

`aios-cli/crates/aios-manifest/src/lib.rs`:
```rust
//! Parse and validate the AIOS system manifest (`manifest.toml`).
```

`aios-cli/crates/aios-gen/Cargo.toml`:
```toml
[package]
name = "aios-gen"
description = "AIOS generation naming, UKI boot-counter names, metadata and GC policy"
version.workspace = true
edition.workspace = true
license.workspace = true
publish.workspace = true

[dependencies]
serde.workspace = true
toml.workspace = true
```

`aios-cli/crates/aios-gen/src/lib.rs`:
```rust
//! AIOS generations: ids, subvolume names, UKI file names, metadata and GC policy.
```

- [ ] **Step 4: Create the Makefile**

`Makefile` (recipe lines start with a TAB character):
```make
export PATH := $(HOME)/.cargo/bin:$(PATH)
CARGO ?= cargo

.PHONY: check rust-check

check: rust-check

rust-check:
	cd aios-cli && $(CARGO) fmt --all -- --check
	cd aios-cli && $(CARGO) clippy --workspace --all-targets -- -D warnings
	cd aios-cli && $(CARGO) test --workspace
```

- [ ] **Step 5: Create the README**

`README.md`:
````markdown
# AIOS

A personal, AI-driven, security-focused Linux distribution (Arch-based) with
NixOS-style guarantees: read-only generations, an impermanent root, and a
declarative manifest as the only way to change the system.

- Vision: `docs/superpowers/specs/2026-11-03-aios-vision.md`
- Base ISO design: `docs/superpowers/specs/2026-11-03-base-iso-design.md`
- Plans: `docs/superpowers/plans/`

## Development

```bash
make check   # fmt + clippy + unit tests, no root needed
```
````

- [ ] **Step 6: Verify the scaffold**

Run: `make check`
Expected: fmt and clippy print no diagnostics. Tests show `test result: ok. 0 passed` per crate. `aios-cli/Cargo.lock` is created.

- [ ] **Step 7: Commit**

```bash
git add Makefile README.md aios-cli/
git commit -m "build: scaffold aios-cli workspace and make check"
```

---

### Task 2: `aios-manifest` model, parse and error locations

**Files:**
- Create: `aios-cli/crates/aios-manifest/src/model.rs`, `aios-cli/crates/aios-manifest/src/locate.rs`
- Modify: `aios-cli/crates/aios-manifest/src/lib.rs`
- Test: `aios-cli/crates/aios-manifest/tests/common/mod.rs`, `aios-cli/crates/aios-manifest/tests/manifest.rs`

- [ ] **Step 1: Write the shared fixture**

`aios-cli/crates/aios-manifest/tests/common/mod.rs`:
```rust
/// A manifest that passes every validation rule given the tempdir layout built in `validate.rs`.
pub const VALID: &str = r#"[system]
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
enable = ["NetworkManager"]

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
".config/autostart/" = "home/eli/autostart/"
"#;
```

- [ ] **Step 2: Write the failing tests**

`aios-cli/crates/aios-manifest/tests/manifest.rs`:
```rust
mod common;

use aios_manifest::{locate, offset_to_line_col, parse, Lockdown};
use common::VALID;

#[test]
fn parses_valid_manifest() {
    let m = parse(VALID).expect("valid manifest parses");
    assert_eq!(m.system.hostname, "nightcity");
    assert_eq!(m.kernel.default, "linux-cachyos");
    assert_eq!(m.kernel.fallback.as_deref(), Some("linux-cachyos-lts"));
    assert_eq!(m.kernel.lockdown, Lockdown::Integrity);
    assert_eq!(m.files["/etc/nftables.conf"].mode_or_default(), "0600");
    assert_eq!(
        m.files["/etc/pacman.d/hooks/90-mkinitcpio-install.hook"].symlink.as_deref(),
        Some("/dev/null")
    );
    assert_eq!(m.users["eli"].uid, 1000);
    assert_eq!(m.users["eli"].home[".zshrc"], "home/eli/zshrc");
}

#[test]
fn defaults_apply_for_optional_fields() {
    let raw = r#"[system]
hostname = "h"
timezone = "UTC"
locale = "C.UTF-8"
keymap = "us"

[kernel]
default = "linux"
"#;
    let m = parse(raw).unwrap();
    assert_eq!(m.kernel.lockdown, Lockdown::Integrity);
    assert!(m.kernel.fallback.is_none());
    assert!(m.packages.install.is_empty());
    assert!(m.files.is_empty());
    assert!(m.users.is_empty());
}

#[test]
fn lockdown_none_parses() {
    let raw = VALID.replace("lockdown = \"integrity\"", "lockdown = \"none\"");
    assert_eq!(parse(&raw).unwrap().kernel.lockdown, Lockdown::None);
}

#[test]
fn file_entry_defaults() {
    let m = parse(VALID).unwrap();
    let hook = &m.files["/etc/pacman.d/hooks/90-mkinitcpio-install.hook"];
    assert_eq!(hook.mode_or_default(), "0644");
    assert_eq!(hook.owner_or_default(), "root");
    assert_eq!(hook.group_or_default(), "root");
}

#[test]
fn package_set_is_core_plus_kernels_plus_install_sorted_dedup() {
    let m = parse(VALID).unwrap();
    let set = m.package_set();
    for p in ["base", "aios-cli", "aios-base", "linux-cachyos", "linux-cachyos-lts", "zsh", "git"] {
        assert!(set.contains(&p.to_string()), "missing {p}");
    }
    let mut sorted = set.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(set, sorted, "package_set must be sorted and deduplicated");
    assert_eq!(set.iter().filter(|p| *p == "base").count(), 1);
}

#[test]
fn unknown_key_is_parse_error_with_location() {
    let raw = VALID.replace("keymap = \"us\"", "keymap = \"us\"\nkeymapp = \"de\"");
    let err = parse(&raw).unwrap_err();
    assert_eq!(err.line, 6, "error should point at the unknown key line, got {err}");
    assert!(err.message.contains("unknown field"), "got: {}", err.message);
    assert!(err.to_string().starts_with("manifest.toml:6:"), "got: {err}");
}

#[test]
fn missing_required_field_is_error() {
    let err = parse("[system]\nhostname = \"h\"\n").unwrap_err();
    assert!(err.message.contains("missing field"), "got: {}", err.message);
}

#[test]
fn locate_finds_first_occurrence_one_based() {
    let raw = "a = 1\nb = \"/etc/x\"\n";
    assert_eq!(locate(raw, "\"/etc/x\""), (2, 5));
    assert_eq!(locate(raw, "a"), (1, 1));
    assert_eq!(locate(raw, "zzz"), (1, 1));
}

#[test]
fn offset_to_line_col_is_one_based() {
    let raw = "ab\ncd\n";
    assert_eq!(offset_to_line_col(raw, 0), (1, 1));
    assert_eq!(offset_to_line_col(raw, 1), (1, 2));
    assert_eq!(offset_to_line_col(raw, 3), (2, 1));
    assert_eq!(offset_to_line_col(raw, 4), (2, 2));
    assert_eq!(offset_to_line_col(raw, 999), (3, 1));
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cd aios-cli && cargo test -p aios-manifest`
Expected: compile error, `unresolved imports aios_manifest::locate` (and similar).

- [ ] **Step 4: Implement `model.rs`**

`aios-cli/crates/aios-manifest/src/model.rs`:
```rust
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

/// Packages AIOS always installs, whatever the manifest says (spec §4.6).
pub const CORE_PACKAGES: &[&str] = &[
    "base",
    "aios-cli",
    "aios-base",
    "btrfs-progs",
    "cryptsetup",
    "tpm2-tss",
    "sbctl",
    "systemd-ukify",
    "mkinitcpio",
    "nftables",
    "usbguard",
    "apparmor",
    "zram-generator",
    "fwupd",
    "polkit",
];

/// Kernel packages the manifest may name in `[kernel]`.
pub const KNOWN_KERNELS: &[&str] = &["linux-cachyos", "linux-cachyos-lts", "linux", "linux-lts"];

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub system: System,
    pub kernel: Kernel,
    #[serde(default)]
    pub packages: Packages,
    #[serde(default)]
    pub services: Services,
    #[serde(default)]
    pub files: BTreeMap<String, FileEntry>,
    #[serde(default)]
    pub persist: Persist,
    #[serde(default)]
    pub users: BTreeMap<String, User>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct System {
    pub hostname: String,
    pub timezone: String,
    pub locale: String,
    pub keymap: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Lockdown {
    #[default]
    Integrity,
    None,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Kernel {
    pub default: String,
    #[serde(default)]
    pub fallback: Option<String>,
    #[serde(default)]
    pub lockdown: Lockdown,
    #[serde(default)]
    pub extra_cmdline: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Packages {
    #[serde(default)]
    pub install: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Services {
    #[serde(default)]
    pub enable: Vec<String>,
    #[serde(default)]
    pub disable: Vec<String>,
    #[serde(default)]
    pub mask: Vec<String>,
}

/// One managed file under `/etc`. Exactly one of `source` or `symlink` must be set.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileEntry {
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub symlink: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub group: Option<String>,
}

impl FileEntry {
    pub fn mode_or_default(&self) -> &str {
        self.mode.as_deref().unwrap_or("0644")
    }

    pub fn owner_or_default(&self) -> &str {
        self.owner.as_deref().unwrap_or("root")
    }

    pub fn group_or_default(&self) -> &str {
        self.group.as_deref().unwrap_or("root")
    }
}

#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Persist {
    #[serde(default)]
    pub directories: Vec<String>,
    #[serde(default)]
    pub files: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub uid: u32,
    #[serde(default)]
    pub groups: Vec<String>,
    pub shell: String,
    /// Home-relative target path -> manifest-repo-relative source. A trailing `/` marks a directory.
    #[serde(default)]
    pub home: BTreeMap<String, String>,
}

impl Manifest {
    /// Full explicit package set: core + kernels + `[packages].install`, sorted and deduplicated.
    pub fn package_set(&self) -> Vec<String> {
        let mut set: BTreeSet<String> = CORE_PACKAGES.iter().map(|p| p.to_string()).collect();
        set.insert(self.kernel.default.clone());
        if let Some(fallback) = &self.kernel.fallback {
            set.insert(fallback.clone());
        }
        set.extend(self.packages.install.iter().cloned());
        set.into_iter().collect()
    }
}
```

- [ ] **Step 5: Implement `locate.rs`**

`aios-cli/crates/aios-manifest/src/locate.rs`:
```rust
/// 1-based `(line, col)` of the first occurrence of `needle` in `raw`, or `(1, 1)` if absent.
pub fn locate(raw: &str, needle: &str) -> (usize, usize) {
    for (i, line) in raw.lines().enumerate() {
        if let Some(col) = line.find(needle) {
            return (i + 1, col + 1);
        }
    }
    (1, 1)
}

/// 1-based `(line, col)` of a byte offset into `raw`. Offsets past the end clamp to the end.
pub fn offset_to_line_col(raw: &str, offset: usize) -> (usize, usize) {
    let offset = offset.min(raw.len());
    let before = &raw[..offset];
    let line = before.matches('\n').count() + 1;
    let col = match before.rfind('\n') {
        Some(nl) => offset - nl - 1,
        None => offset,
    };
    (line, col + 1)
}
```

- [ ] **Step 6: Implement `lib.rs` (error type, `parse`)**

`aios-cli/crates/aios-manifest/src/lib.rs`:
```rust
//! Parse and validate the AIOS system manifest (`manifest.toml`).

mod locate;
mod model;

pub use locate::{locate, offset_to_line_col};
pub use model::*;

use std::fmt;

/// A manifest problem with a 1-based location in `manifest.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestError {
    pub line: usize,
    pub col: usize,
    pub message: String,
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "manifest.toml:{}:{}: {}", self.line, self.col, self.message)
    }
}

impl std::error::Error for ManifestError {}

/// Parse manifest text. Unknown keys and type errors fail here, with the TOML location.
pub fn parse(raw: &str) -> Result<Manifest, ManifestError> {
    toml::from_str(raw).map_err(|e| {
        let (line, col) = e
            .span()
            .map(|span| offset_to_line_col(raw, span.start))
            .unwrap_or((1, 1));
        ManifestError {
            line,
            col,
            message: e.message().to_string(),
        }
    })
}
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cd aios-cli && cargo test -p aios-manifest`
Expected: `test result: ok. 9 passed`.
If `unknown_key_is_parse_error_with_location` fails on the line number, print the error and look at where `toml` puts the span for unknown fields. The test's intent: the error is reported on the `keymapp` line (line 6). If `toml` reports the enclosing table instead, compute the location by `locate(raw, <unknown key name>)`. Parse the key name from the message ``unknown field `keymapp` ``. Keep the test unchanged.

- [ ] **Step 8: Commit**

```bash
cd /home/eli/Development/AIOS
git add aios-cli/
git commit -m "feat(manifest): manifest model, parse with TOML error locations"
```

---

### Task 3: `aios-manifest` validation rules

**Files:**
- Create: `aios-cli/crates/aios-manifest/src/validate.rs`
- Modify: `aios-cli/crates/aios-manifest/src/lib.rs` (full content below)
- Test: `aios-cli/crates/aios-manifest/tests/validate.rs`

- [ ] **Step 1: Write the failing tests**

`aios-cli/crates/aios-manifest/tests/validate.rs`:
```rust
mod common;

use aios_manifest::{load, parse, validate, ValidationEnv};
use common::VALID;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

/// Temp layout: repo/{files/nftables.conf, home/eli/zshrc, home/eli/autostart/},
/// secrets/passwd/eli, zoneinfo/Asia/Jerusalem.
fn env() -> (TempDir, ValidationEnv) {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let repo = root.join("repo");
    fs::create_dir_all(repo.join("files")).unwrap();
    fs::write(repo.join("files/nftables.conf"), "flush ruleset\n").unwrap();
    fs::create_dir_all(repo.join("home/eli/autostart")).unwrap();
    fs::write(repo.join("home/eli/zshrc"), "# zshrc\n").unwrap();
    fs::create_dir_all(root.join("secrets/passwd")).unwrap();
    fs::write(root.join("secrets/passwd/eli"), "$y$j9T$hash\n").unwrap();
    fs::create_dir_all(root.join("zoneinfo/Asia")).unwrap();
    fs::write(root.join("zoneinfo/Asia/Jerusalem"), "TZif").unwrap();
    let env = ValidationEnv {
        repo_root: repo,
        secrets_dir: root.join("secrets"),
        zoneinfo_dir: root.join("zoneinfo"),
    };
    (tmp, env)
}

fn errors(raw: &str) -> Vec<String> {
    let (_tmp, env) = env();
    let m = parse(raw).expect("fixture must parse");
    validate(&m, raw, &env).into_iter().map(|e| e.to_string()).collect()
}

fn assert_error(raw: &str, needle: &str) {
    let errs = errors(raw);
    assert!(
        errs.iter().any(|e| e.contains(needle)),
        "expected an error containing {needle:?}, got {errs:#?}"
    );
}

#[test]
fn valid_manifest_has_no_errors() {
    assert_eq!(errors(VALID), Vec::<String>::new());
}

#[test]
fn load_reads_parses_and_validates() {
    let (tmp, env) = env();
    let path = tmp.path().join("manifest.toml");
    fs::write(&path, VALID).unwrap();
    assert!(load(&path, &env).is_ok());
    fs::write(&path, VALID.replace("uid = 1000", "uid = 5")).unwrap();
    let errs = load(&path, &env).unwrap_err();
    assert!(errs[0].message.contains("outside 1000-59999"), "got {errs:?}");
}

#[test]
fn load_missing_file_is_error() {
    let (_tmp, env) = env();
    let errs = load(Path::new("/nonexistent/manifest.toml"), &env).unwrap_err();
    assert!(errs[0].message.contains("cannot read"));
}

#[test]
fn file_outside_etc_rejected() {
    let raw = VALID.replace("\"/etc/nftables.conf\" =", "\"/usr/lib/x\" =");
    assert_error(&raw, "only paths under /etc are allowed");
}

#[test]
fn file_with_parent_dir_rejected() {
    let raw = VALID.replace("\"/etc/nftables.conf\" =", "\"/etc/../usr/x\" =");
    assert_error(&raw, "only paths under /etc are allowed");
}

#[test]
fn file_with_both_source_and_symlink_rejected() {
    let raw = VALID.replace(
        "{ symlink = \"/dev/null\" }",
        "{ symlink = \"/dev/null\", source = \"files/nftables.conf\" }",
    );
    assert_error(&raw, "set exactly one of source or symlink");
}

#[test]
fn file_with_neither_source_nor_symlink_rejected() {
    let raw = VALID.replace("{ symlink = \"/dev/null\" }", "{ mode = \"0644\" }");
    assert_error(&raw, "set exactly one of source or symlink");
}

#[test]
fn missing_source_rejected() {
    let raw = VALID.replace("files/nftables.conf", "files/missing.conf");
    assert_error(&raw, "source \"files/missing.conf\" not found");
}

#[test]
fn bad_mode_rejected() {
    let raw = VALID.replace("mode = \"0600\"", "mode = \"0999\"");
    assert_error(&raw, "invalid mode \"0999\"");
}

#[test]
fn error_location_points_at_offending_key() {
    let raw = VALID.replace("mode = \"0600\"", "mode = \"rw\"");
    let errs = errors(&raw);
    let line = raw.lines().position(|l| l.contains("/etc/nftables.conf")).unwrap() + 1;
    assert!(errs[0].starts_with(&format!("manifest.toml:{line}:")), "got {errs:?}");
}

#[test]
fn persist_relative_path_rejected() {
    let raw = VALID.replace("\"/var/lib/NetworkManager\"", "\"var/lib/nm\"");
    assert_error(&raw, "must be absolute without '..'");
}

#[test]
fn persist_under_usr_rejected() {
    let raw = VALID.replace("\"/var/lib/NetworkManager\"", "\"/usr/share/x\"");
    assert_error(&raw, "may not be under /usr");
}

#[test]
fn persist_under_home_rejected() {
    let raw = VALID.replace("\"/var/lib/NetworkManager\"", "\"/home/eli\"");
    assert_error(&raw, "may not be under /home");
}

#[test]
fn persist_overlap_rejected() {
    let raw = VALID.replace(
        "directories = [\"/var/lib/NetworkManager\", \"/var/cache/pacman/pkg\"]",
        "directories = [\"/var/lib\", \"/var/lib/NetworkManager\"]",
    );
    assert_error(&raw, "overlap");
}

#[test]
fn persist_prefix_without_component_boundary_is_not_overlap() {
    let raw = VALID.replace(
        "directories = [\"/var/lib/NetworkManager\", \"/var/cache/pacman/pkg\"]",
        "directories = [\"/var/lib/foo\", \"/var/lib/foobar\"]",
    );
    assert_eq!(errors(&raw), Vec::<String>::new());
}

#[test]
fn home_absolute_target_rejected() {
    let raw = VALID.replace("\".zshrc\" =", "\"/etc/zshrc\" =");
    assert_error(&raw, "must be relative inside the home directory");
}

#[test]
fn home_parent_target_rejected() {
    let raw = VALID.replace("\".zshrc\" =", "\"../other/.zshrc\" =");
    assert_error(&raw, "must be relative inside the home directory");
}

#[test]
fn home_kind_mismatch_rejected() {
    let raw = VALID.replace("\".zshrc\" =", "\".zshrc.d/\" =");
    assert_error(&raw, "needs a directory at \"home/eli/zshrc\"");
}

#[test]
fn home_missing_source_rejected() {
    let raw = VALID.replace("home/eli/zshrc", "home/eli/nope");
    assert_error(&raw, "needs a file at \"home/eli/nope\"");
}

#[test]
fn uid_out_of_range_rejected() {
    let raw = VALID.replace("uid = 1000", "uid = 60000");
    assert_error(&raw, "outside 1000-59999");
}

#[test]
fn duplicate_uid_rejected() {
    let raw = format!("{VALID}\n[users.bob]\nuid = 1000\nshell = \"/bin/sh\"\n");
    assert_error(&raw, "already used by");
}

#[test]
fn missing_password_hash_rejected() {
    let raw = format!("{VALID}\n[users.bob]\nuid = 1001\nshell = \"/bin/sh\"\n");
    assert_error(&raw, "missing password hash secrets/passwd/bob");
}

#[test]
fn invalid_username_rejected() {
    let raw = VALID
        .replace("[users.eli]", "[users.Eli]")
        .replace("[users.eli.home]", "[users.Eli.home]");
    assert_error(&raw, "invalid user name \"Eli\"");
}

#[test]
fn unknown_kernel_rejected() {
    let raw = VALID.replace("default = \"linux-cachyos\"", "default = \"linux-zen\"");
    assert_error(&raw, "unknown kernel \"linux-zen\"");
}

#[test]
fn fallback_equal_to_default_rejected() {
    let raw = VALID.replace("fallback = \"linux-cachyos-lts\"", "fallback = \"linux-cachyos\"");
    assert_error(&raw, "fallback kernel must differ from default");
}

#[test]
fn unknown_timezone_rejected() {
    let raw = VALID.replace("Asia/Jerusalem", "Mars/Olympus");
    assert_error(&raw, "unknown timezone \"Mars/Olympus\"");
}

#[test]
fn timezone_traversal_rejected() {
    let raw = VALID.replace("Asia/Jerusalem", "../../etc/passwd");
    assert_error(&raw, "unknown timezone");
}

#[test]
fn invalid_hostname_rejected() {
    let raw = VALID.replace("hostname = \"nightcity\"", "hostname = \"Night_City\"");
    assert_error(&raw, "invalid hostname \"Night_City\"");
}

#[test]
fn collects_multiple_errors() {
    let raw = VALID
        .replace("uid = 1000", "uid = 1")
        .replace("Asia/Jerusalem", "Nope/Nope");
    assert!(errors(&raw).len() >= 2);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd aios-cli && cargo test -p aios-manifest --test validate`
Expected: compile error, `unresolved imports aios_manifest::validate, aios_manifest::ValidationEnv, aios_manifest::load`.

- [ ] **Step 3: Implement `validate.rs`**

`aios-cli/crates/aios-manifest/src/validate.rs`:
```rust
use crate::{locate, Manifest, ManifestError, KNOWN_KERNELS};
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

/// Where validation looks for files the manifest refers to.
#[derive(Debug, Clone)]
pub struct ValidationEnv {
    /// Root of the manifest git repo (holds `files/` and `home/`).
    pub repo_root: PathBuf,
    /// `/persist/aios/secrets` (holds `passwd/<user>`).
    pub secrets_dir: PathBuf,
    /// `/usr/share/zoneinfo`.
    pub zoneinfo_dir: PathBuf,
}

/// Check every semantic rule from spec §4.1. Returns all problems found (empty = valid).
pub fn validate(m: &Manifest, raw: &str, env: &ValidationEnv) -> Vec<ManifestError> {
    let mut v = Validator {
        raw,
        errors: Vec::new(),
    };
    v.system(m, env);
    v.kernel(m);
    v.files(m, env);
    v.persist(m);
    v.users(m, env);
    v.errors
}

struct Validator<'a> {
    raw: &'a str,
    errors: Vec<ManifestError>,
}

impl Validator<'_> {
    fn err(&mut self, needle: &str, message: String) {
        let (line, col) = locate(self.raw, needle);
        self.errors.push(ManifestError { line, col, message });
    }

    fn system(&mut self, m: &Manifest, env: &ValidationEnv) {
        let host = &m.system.hostname;
        if !valid_hostname(host) {
            self.err("hostname", format!("invalid hostname {host:?}"));
        }
        let tz = &m.system.timezone;
        if !is_safe_relative(tz) || !env.zoneinfo_dir.join(tz).is_file() {
            self.err("timezone", format!("unknown timezone {tz:?}"));
        }
    }

    fn kernel(&mut self, m: &Manifest) {
        let known = KNOWN_KERNELS.join(", ");
        let default = &m.kernel.default;
        if !KNOWN_KERNELS.contains(&default.as_str()) {
            self.err(
                "default",
                format!("unknown kernel {default:?} (expected one of: {known})"),
            );
        }
        if let Some(fallback) = &m.kernel.fallback {
            if !KNOWN_KERNELS.contains(&fallback.as_str()) {
                self.err(
                    "fallback",
                    format!("unknown kernel {fallback:?} (expected one of: {known})"),
                );
            }
            if fallback == default {
                self.err(
                    "fallback",
                    "fallback kernel must differ from default".to_string(),
                );
            }
        }
    }

    fn files(&mut self, m: &Manifest, env: &ValidationEnv) {
        for (path, entry) in &m.files {
            let needle = format!("\"{path}\"");
            if !path.starts_with("/etc/") || has_parent(path) {
                self.err(
                    &needle,
                    format!("file {path:?}: only paths under /etc are allowed"),
                );
            }
            match (&entry.source, &entry.symlink) {
                (Some(_), Some(_)) | (None, None) => self.err(
                    &needle,
                    format!("file {path:?}: set exactly one of source or symlink"),
                ),
                (Some(src), None) => {
                    if !is_safe_relative(src) || !env.repo_root.join(src).is_file() {
                        self.err(
                            &needle,
                            format!("file {path:?}: source {src:?} not found in manifest repo"),
                        );
                    }
                }
                (None, Some(_)) => {}
            }
            if let Some(mode) = &entry.mode {
                if !valid_mode(mode) {
                    self.err(&needle, format!("file {path:?}: invalid mode {mode:?}"));
                }
            }
        }
    }

    fn persist(&mut self, m: &Manifest) {
        let all: Vec<&String> = m
            .persist
            .directories
            .iter()
            .chain(m.persist.files.iter())
            .collect();
        for p in &all {
            let needle = format!("\"{p}\"");
            if !p.starts_with('/') || has_parent(p) {
                self.err(
                    &needle,
                    format!("persist path {p:?} must be absolute without '..'"),
                );
                continue;
            }
            for forbidden in ["/usr", "/persist", "/home"] {
                if is_under(p, forbidden) {
                    self.err(
                        &needle,
                        format!("persist path {p:?} may not be under {forbidden}"),
                    );
                }
            }
        }
        for (i, a) in all.iter().enumerate() {
            for b in all.iter().skip(i + 1) {
                if is_under(a, b) || is_under(b, a) {
                    self.err(
                        &format!("\"{b}\""),
                        format!("persist paths {a:?} and {b:?} overlap"),
                    );
                }
            }
        }
    }

    fn users(&mut self, m: &Manifest, env: &ValidationEnv) {
        let mut seen: BTreeMap<u32, &str> = BTreeMap::new();
        for (name, user) in &m.users {
            let needle = format!("[users.{name}]");
            if !valid_username(name) {
                self.err(&needle, format!("invalid user name {name:?}"));
            }
            if !(1000..=59999).contains(&user.uid) {
                self.err(
                    &needle,
                    format!("user {name:?}: uid {} outside 1000-59999", user.uid),
                );
            }
            if let Some(other) = seen.insert(user.uid, name) {
                self.err(
                    &needle,
                    format!("user {name:?}: uid {} already used by {other:?}", user.uid),
                );
            }
            if !env.secrets_dir.join("passwd").join(name).is_file() {
                self.err(
                    &needle,
                    format!(
                        "user {name:?}: missing password hash secrets/passwd/{name} (run `aios passwd {name}`)"
                    ),
                );
            }
            for (target, src) in &user.home {
                let hneedle = format!("\"{target}\"");
                if target.is_empty() || target.starts_with('/') || has_parent(target) {
                    self.err(
                        &hneedle,
                        format!(
                            "user {name:?}: home entry {target:?} must be relative inside the home directory"
                        ),
                    );
                    continue;
                }
                let want_dir = target.ends_with('/');
                let kind = if want_dir { "directory" } else { "file" };
                let ok = is_safe_relative(src) && {
                    let source = env.repo_root.join(src);
                    if want_dir {
                        source.is_dir()
                    } else {
                        source.is_file()
                    }
                };
                if !ok {
                    self.err(
                        &hneedle,
                        format!("user {name:?}: home entry {target:?} needs a {kind} at {src:?}"),
                    );
                }
            }
        }
    }
}

fn has_parent(p: &str) -> bool {
    Path::new(p).components().any(|c| c == Component::ParentDir)
}

fn is_safe_relative(p: &str) -> bool {
    !p.is_empty() && !p.starts_with('/') && !has_parent(p)
}

/// True if `p` equals `base` or lies below it, compared component by component.
fn is_under(p: &str, base: &str) -> bool {
    Path::new(p).starts_with(Path::new(base))
}

fn valid_mode(mode: &str) -> bool {
    (3..=4).contains(&mode.len()) && mode.chars().all(|c| ('0'..='7').contains(&c))
}

fn valid_hostname(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 63
        && !h.starts_with('-')
        && !h.ends_with('-')
        && h.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

fn valid_username(n: &str) -> bool {
    let mut chars = n.chars();
    let first_ok = matches!(chars.next(), Some(c) if c.is_ascii_lowercase() || c == '_');
    first_ok
        && n.len() <= 32
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}
```

- [ ] **Step 4: Replace `lib.rs` with the full version**

`aios-cli/crates/aios-manifest/src/lib.rs`:
```rust
//! Parse and validate the AIOS system manifest (`manifest.toml`).

mod locate;
mod model;
mod validate;

pub use locate::{locate, offset_to_line_col};
pub use model::*;
pub use validate::{validate, ValidationEnv};

use std::fmt;
use std::path::Path;

/// A manifest problem with a 1-based location in `manifest.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestError {
    pub line: usize,
    pub col: usize,
    pub message: String,
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "manifest.toml:{}:{}: {}", self.line, self.col, self.message)
    }
}

impl std::error::Error for ManifestError {}

/// Parse manifest text. Unknown keys and type errors fail here, with the TOML location.
pub fn parse(raw: &str) -> Result<Manifest, ManifestError> {
    toml::from_str(raw).map_err(|e| {
        let (line, col) = e
            .span()
            .map(|span| offset_to_line_col(raw, span.start))
            .unwrap_or((1, 1));
        ManifestError {
            line,
            col,
            message: e.message().to_string(),
        }
    })
}

/// Read, parse and validate a manifest file. Returns every problem found.
pub fn load(path: &Path, env: &ValidationEnv) -> Result<Manifest, Vec<ManifestError>> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        vec![ManifestError {
            line: 1,
            col: 1,
            message: format!("cannot read {}: {e}", path.display()),
        }]
    })?;
    let manifest = parse(&raw).map_err(|e| vec![e])?;
    let errors = validate(&manifest, &raw, env);
    if errors.is_empty() {
        Ok(manifest)
    } else {
        Err(errors)
    }
}
```

If Task 2 Step 7 needed a fallback location for unknown keys, keep that logic in `parse`.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd aios-cli && cargo test -p aios-manifest`
Expected: `manifest.rs` 9 passed and `validate.rs` 29 passed.

- [ ] **Step 6: Lint**

Run: `make check`
Expected: no fmt diff, no clippy warnings, all tests pass. If fmt complains, run `cargo fmt --all` in `aios-cli/` and re-run.

- [ ] **Step 7: Commit**

```bash
cd /home/eli/Development/AIOS
git add aios-cli/
git commit -m "feat(manifest): validation rules with locations, load()"
```

---

### Task 4: `aios-gen` generation ids, subvolumes, cmdline

**Files:**
- Create: `aios-cli/crates/aios-gen/src/id.rs`
- Modify: `aios-cli/crates/aios-gen/src/lib.rs`

- [ ] **Step 1: Write the failing tests and wire the module**

`aios-cli/crates/aios-gen/src/id.rs` (tests only for now; the implementation goes above them in Step 3):
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_is_zero_padded() {
        assert_eq!(GenId(7).to_string(), "0007");
        assert_eq!(GenId(1234).to_string(), "1234");
    }

    #[test]
    fn subvolume_names() {
        assert_eq!(GenId(7).usr_subvol(), "@usr-gen-0007");
        assert_eq!(GenId(7).etc_subvol(), "@etc-gen-0007");
    }

    #[test]
    fn parse_requires_four_digits_and_nonzero() {
        assert_eq!("0007".parse::<GenId>(), Ok(GenId(7)));
        assert!("7".parse::<GenId>().is_err());
        assert!("00007".parse::<GenId>().is_err());
        assert!("0000".parse::<GenId>().is_err());
        assert!("00a7".parse::<GenId>().is_err());
        assert!("+007".parse::<GenId>().is_err());
    }

    #[test]
    fn parse_subvol_names() {
        assert_eq!(parse_subvol("@usr-gen-0003"), Some((SubvolKind::Usr, GenId(3))));
        assert_eq!(parse_subvol("@etc-gen-0012"), Some((SubvolKind::Etc, GenId(12))));
        assert_eq!(parse_subvol("@usr-cand"), None);
        assert_eq!(parse_subvol("@home"), None);
        assert_eq!(parse_subvol("@usr-gen-12"), None);
    }

    #[test]
    fn list_complete_needs_both_halves() {
        let subvols = [
            "@blank",
            "@usr-gen-0001",
            "@etc-gen-0001",
            "@usr-gen-0002",
            "@etc-gen-0003",
            "@usr-gen-0003",
            "@home",
        ];
        assert_eq!(list_complete(&subvols), vec![GenId(1), GenId(3)]);
    }

    #[test]
    fn next_id_is_max_plus_one() {
        assert_eq!(next_id(&[]), Some(GenId(1)));
        assert_eq!(next_id(&[GenId(1), GenId(5), GenId(3)]), Some(GenId(6)));
        assert_eq!(next_id(&[GenId(MAX_GEN)]), None);
    }

    #[test]
    fn gen_from_cmdline_finds_token() {
        let cmdline = "rd.luks.name=x=aios root=/dev/mapper/aios aios.gen=0042 quiet";
        assert_eq!(gen_from_cmdline(cmdline), Some(GenId(42)));
        assert_eq!(gen_from_cmdline("quiet splash"), None);
        assert_eq!(gen_from_cmdline("aios.gen=42"), None);
        assert_eq!(gen_from_cmdline("xaios.gen=0042"), None);
    }
}
```

`aios-cli/crates/aios-gen/src/lib.rs`:
```rust
//! AIOS generations: ids, subvolume names, UKI file names, metadata and GC policy.

mod id;

pub use id::{gen_from_cmdline, list_complete, next_id, parse_subvol, GenId, SubvolKind, MAX_GEN};
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd aios-cli && cargo test -p aios-gen`
Expected: compile errors, `cannot find type GenId` / unresolved imports.

- [ ] **Step 3: Implement (insert above the `#[cfg(test)]` block in `id.rs`)**

```rust
use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

/// Generation number. Displayed zero-padded to 4 digits so lexical order equals numeric order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GenId(pub u32);

/// Highest representable generation (4 digits).
pub const MAX_GEN: u32 = 9999;

impl GenId {
    pub fn usr_subvol(self) -> String {
        format!("@usr-gen-{self}")
    }

    pub fn etc_subvol(self) -> String {
        format!("@etc-gen-{self}")
    }
}

impl fmt::Display for GenId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}", self.0)
    }
}

impl FromStr for GenId {
    type Err = String;

    /// Accepts exactly four ASCII digits with a value of at least 1.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 4 || !s.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!("generation id must be 4 digits, got {s:?}"));
        }
        let n: u32 = s
            .parse()
            .map_err(|e| format!("bad generation id {s:?}: {e}"))?;
        if n == 0 {
            return Err("generation id 0000 is not valid".to_string());
        }
        Ok(GenId(n))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubvolKind {
    Usr,
    Etc,
}

/// Parse `@usr-gen-NNNN` / `@etc-gen-NNNN`.
pub fn parse_subvol(name: &str) -> Option<(SubvolKind, GenId)> {
    let (kind, rest) = if let Some(rest) = name.strip_prefix("@usr-gen-") {
        (SubvolKind::Usr, rest)
    } else if let Some(rest) = name.strip_prefix("@etc-gen-") {
        (SubvolKind::Etc, rest)
    } else {
        return None;
    };
    rest.parse().ok().map(|id| (kind, id))
}

/// Generations whose `@usr-gen` and `@etc-gen` subvolumes both exist, ascending.
pub fn list_complete<S: AsRef<str>>(subvols: &[S]) -> Vec<GenId> {
    let mut usr = BTreeSet::new();
    let mut etc = BTreeSet::new();
    for name in subvols {
        match parse_subvol(name.as_ref()) {
            Some((SubvolKind::Usr, id)) => {
                usr.insert(id);
            }
            Some((SubvolKind::Etc, id)) => {
                etc.insert(id);
            }
            None => {}
        }
    }
    usr.intersection(&etc).copied().collect()
}

/// Next generation id (max + 1), or `None` once `MAX_GEN` is used.
pub fn next_id(existing: &[GenId]) -> Option<GenId> {
    let next = existing.iter().map(|g| g.0).max().unwrap_or(0) + 1;
    (next <= MAX_GEN).then_some(GenId(next))
}

/// The generation named by an `aios.gen=NNNN` token on a kernel cmdline.
pub fn gen_from_cmdline(cmdline: &str) -> Option<GenId> {
    cmdline
        .split_whitespace()
        .find_map(|token| token.strip_prefix("aios.gen="))
        .and_then(|value| value.parse().ok())
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd aios-cli && cargo test -p aios-gen`
Expected: `test result: ok. 7 passed`.

- [ ] **Step 5: Commit**

```bash
cd /home/eli/Development/AIOS
git add aios-cli/
git commit -m "feat(gen): generation ids, subvolume names, cmdline parsing"
```

---

### Task 5: `aios-gen` UKI names with boot counters

**Files:**
- Create: `aios-cli/crates/aios-gen/src/uki.rs`
- Modify: `aios-cli/crates/aios-gen/src/lib.rs`

Background (systemd boot counting): a file `NAME+LEFT[-DONE].efi` has LEFT tries left and DONE tries used. systemd-boot decrements on each attempt. `systemd-bless-boot` renames it to `NAME.efi` after a good boot. LEFT = 0 means "bad". The boot entry id is the file name without the counter.

- [ ] **Step 1: Write the failing tests and wire the module**

`aios-cli/crates/aios-gen/src/uki.rs` (tests only for now):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::GenId;

    #[test]
    fn fresh_name_has_three_tries() {
        let uki = UkiName::fresh(GenId(7), Flavor::Main);
        assert_eq!(uki.file_name(), "aios-gen-0007-cachyos+3.efi");
        assert_eq!(uki.entry_id(), "aios-gen-0007-cachyos.efi");
        assert!(!uki.is_bad());
    }

    #[test]
    fn fallback_flavor_token() {
        let uki = UkiName::fresh(GenId(7), Flavor::Fallback);
        assert_eq!(uki.file_name(), "aios-gen-0007-lts+3.efi");
    }

    #[test]
    fn parse_counted_names() {
        let u = UkiName::parse("aios-gen-0042-cachyos+1-2.efi").unwrap();
        assert_eq!(u.gen, GenId(42));
        assert_eq!(u.flavor, Flavor::Main);
        assert_eq!(u.counter, Some(Counter { left: 1, done: 2 }));
        assert_eq!(u.file_name(), "aios-gen-0042-cachyos+1-2.efi");

        let u = UkiName::parse("aios-gen-0042-lts+3.efi").unwrap();
        assert_eq!(u.counter, Some(Counter { left: 3, done: 0 }));
        assert_eq!(u.file_name(), "aios-gen-0042-lts+3.efi");
    }

    #[test]
    fn parse_blessed_name() {
        let u = UkiName::parse("aios-gen-0042-cachyos.efi").unwrap();
        assert_eq!(u.counter, None);
        assert_eq!(u.file_name(), "aios-gen-0042-cachyos.efi");
        assert!(!u.is_bad());
    }

    #[test]
    fn zero_left_is_bad() {
        let u = UkiName::parse("aios-gen-0042-cachyos+0-3.efi").unwrap();
        assert!(u.is_bad());
        assert_eq!(u.entry_id(), "aios-gen-0042-cachyos.efi");
    }

    #[test]
    fn parse_rejects_foreign_names() {
        for name in [
            "systemd-bootx64.efi",
            "aios-gen-42-cachyos.efi",
            "aios-gen-0042-zen.efi",
            "aios-gen-0042-cachyos+x.efi",
            "aios-gen-0042-cachyos+1-.efi",
            "aios-gen-0042-cachyos",
            "arch-linux.efi",
        ] {
            assert_eq!(UkiName::parse(name), None, "{name} should not parse");
        }
    }
}
```

`aios-cli/crates/aios-gen/src/lib.rs`:
```rust
//! AIOS generations: ids, subvolume names, UKI file names, metadata and GC policy.

mod id;
mod uki;

pub use id::{gen_from_cmdline, list_complete, next_id, parse_subvol, GenId, SubvolKind, MAX_GEN};
pub use uki::{Counter, Flavor, UkiName};
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd aios-cli && cargo test -p aios-gen`
Expected: compile errors, `cannot find type UkiName` (and similar).

- [ ] **Step 3: Implement (insert above the tests in `uki.rs`)**

```rust
use crate::GenId;

/// Which kernel a UKI boots. Tokens match `loader.conf` (`default aios-gen-*-cachyos*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    /// The manifest's `kernel.default`.
    Main,
    /// The manifest's `kernel.fallback`.
    Fallback,
}

impl Flavor {
    pub fn token(self) -> &'static str {
        match self {
            Flavor::Main => "cachyos",
            Flavor::Fallback => "lts",
        }
    }

    fn from_token(token: &str) -> Option<Self> {
        match token {
            "cachyos" => Some(Flavor::Main),
            "lts" => Some(Flavor::Fallback),
            _ => None,
        }
    }
}

/// systemd boot-assessment counter: `+LEFT[-DONE]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counter {
    pub left: u32,
    pub done: u32,
}

/// A UKI file name on the ESP: `aios-gen-NNNN-<flavor>[+LEFT[-DONE]].efi`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UkiName {
    pub gen: GenId,
    pub flavor: Flavor,
    pub counter: Option<Counter>,
}

impl UkiName {
    /// Name for a newly built generation: three boot tries.
    pub fn fresh(gen: GenId, flavor: Flavor) -> Self {
        UkiName {
            gen,
            flavor,
            counter: Some(Counter { left: 3, done: 0 }),
        }
    }

    fn base(&self) -> String {
        format!("aios-gen-{}-{}", self.gen, self.flavor.token())
    }

    pub fn file_name(&self) -> String {
        match self.counter {
            None => format!("{}.efi", self.base()),
            Some(Counter { left, done: 0 }) => format!("{}+{left}.efi", self.base()),
            Some(Counter { left, done }) => format!("{}+{left}-{done}.efi", self.base()),
        }
    }

    /// Boot loader entry id: the file name without the counter.
    pub fn entry_id(&self) -> String {
        format!("{}.efi", self.base())
    }

    /// systemd-boot treats an entry with no tries left as bad.
    pub fn is_bad(&self) -> bool {
        matches!(self.counter, Some(Counter { left: 0, .. }))
    }

    pub fn parse(file_name: &str) -> Option<Self> {
        let stem = file_name.strip_suffix(".efi")?;
        let rest = stem.strip_prefix("aios-gen-")?;
        let (gen_str, rest) = rest.split_once('-')?;
        let gen: GenId = gen_str.parse().ok()?;
        let (flavor_str, counter) = match rest.split_once('+') {
            Some((flavor, counter)) => (flavor, Some(parse_counter(counter)?)),
            None => (rest, None),
        };
        let flavor = Flavor::from_token(flavor_str)?;
        Some(UkiName {
            gen,
            flavor,
            counter,
        })
    }
}

fn parse_counter(s: &str) -> Option<Counter> {
    let digits = |v: &str| -> Option<u32> {
        if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        v.parse().ok()
    };
    match s.split_once('-') {
        Some((left, done)) => Some(Counter {
            left: digits(left)?,
            done: digits(done)?,
        }),
        None => Some(Counter {
            left: digits(s)?,
            done: 0,
        }),
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd aios-cli && cargo test -p aios-gen`
Expected: `test result: ok. 13 passed`.

- [ ] **Step 5: Commit**

```bash
cd /home/eli/Development/AIOS
git add aios-cli/
git commit -m "feat(gen): UKI file names with systemd boot counters"
```

---

### Task 6: `aios-gen` metadata and GC selection

**Files:**
- Create: `aios-cli/crates/aios-gen/src/meta.rs`, `aios-cli/crates/aios-gen/src/gc.rs`
- Modify: `aios-cli/crates/aios-gen/src/lib.rs`

- [ ] **Step 1: Write the failing tests and wire the modules**

`aios-cli/crates/aios-gen/src/meta.rs` (tests only for now):
```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> GenerationMeta {
        GenerationMeta {
            id: 7,
            parent: 6,
            created: "2026-11-03T21:14:05Z".to_string(),
            manifest_commit: "3f9c2a1".to_string(),
            kernels: vec![
                "linux-cachyos 7.3.0-4".to_string(),
                "linux-cachyos-lts 6.18.55-2".to_string(),
            ],
            package_set_sha256: "ab".repeat(32),
        }
    }

    #[test]
    fn round_trips_through_toml() {
        let meta = sample();
        let text = meta.to_toml();
        assert!(text.contains("id = 7"));
        assert!(text.contains("created = \"2026-11-03T21:14:05Z\""));
        assert_eq!(GenerationMeta::from_toml(&text).unwrap(), meta);
    }

    #[test]
    fn rejects_unknown_fields() {
        let text = format!("{}extra = 1\n", sample().to_toml());
        assert!(GenerationMeta::from_toml(&text).is_err());
    }

    #[test]
    fn gen_id_accessor() {
        assert_eq!(sample().gen_id(), crate::GenId(7));
    }
}
```

`aios-cli/crates/aios-gen/src/gc.rs` (tests only for now):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::GenId;

    fn ids(v: &[u32]) -> Vec<GenId> {
        v.iter().map(|&n| GenId(n)).collect()
    }

    #[test]
    fn keeps_newest_k() {
        let gens = ids(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(gc_select(&gens, 5, &[]), ids(&[2, 3]));
    }

    #[test]
    fn never_deletes_gen_one() {
        let gens = ids(&[1, 2, 3]);
        assert_eq!(gc_select(&gens, 1, &[]), ids(&[2]));
    }

    #[test]
    fn never_deletes_protected() {
        let gens = ids(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(gc_select(&gens, 2, &ids(&[3, 5])), ids(&[2, 4, 6]));
    }

    #[test]
    fn nothing_to_delete_when_few_gens() {
        assert!(gc_select(&ids(&[1, 2]), 5, &[]).is_empty());
        assert!(gc_select(&[], 5, &[]).is_empty());
    }

    #[test]
    fn handles_unsorted_and_duplicate_input() {
        let gens = ids(&[8, 2, 5, 2, 7, 3]);
        assert_eq!(gc_select(&gens, 2, &[]), ids(&[2, 3, 5]));
    }

    #[test]
    fn keep_zero_still_respects_protection() {
        let gens = ids(&[1, 2, 3]);
        assert_eq!(gc_select(&gens, 0, &ids(&[3])), ids(&[2]));
    }
}
```

`aios-cli/crates/aios-gen/src/lib.rs`:
```rust
//! AIOS generations: ids, subvolume names, UKI file names, metadata and GC policy.

mod gc;
mod id;
mod meta;
mod uki;

pub use gc::gc_select;
pub use id::{gen_from_cmdline, list_complete, next_id, parse_subvol, GenId, SubvolKind, MAX_GEN};
pub use meta::GenerationMeta;
pub use uki::{Counter, Flavor, UkiName};
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd aios-cli && cargo test -p aios-gen`
Expected: compile errors, `cannot find type GenerationMeta`, `cannot find function gc_select`.

- [ ] **Step 3: Implement `meta.rs` (insert above its tests)**

```rust
use crate::GenId;
use serde::{Deserialize, Serialize};

/// Contents of `/etc/aios/generation.toml` inside each `@etc-gen-NNNN` (spec §2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationMeta {
    pub id: u32,
    /// Parent generation id, 0 for gen-1.
    pub parent: u32,
    /// RFC 3339 UTC timestamp, e.g. `2026-11-03T21:14:05Z`.
    pub created: String,
    /// Git commit of the manifest repo that produced this generation.
    pub manifest_commit: String,
    /// `"<package> <version>"` for each kernel in the generation.
    pub kernels: Vec<String>,
    /// sha256 (hex) of the sorted `pacman -Qq` output.
    pub package_set_sha256: String,
}

impl GenerationMeta {
    pub fn gen_id(&self) -> GenId {
        GenId(self.id)
    }

    pub fn to_toml(&self) -> String {
        toml::to_string(self).expect("GenerationMeta contains only TOML-representable fields")
    }

    pub fn from_toml(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }
}
```

- [ ] **Step 4: Implement `gc.rs` (insert above its tests)**

```rust
use crate::GenId;

/// Generations to delete, ascending. Keeps the newest `keep`, every id in `protected`,
/// and gen-1 (the install baseline).
pub fn gc_select(gens: &[GenId], keep: usize, protected: &[GenId]) -> Vec<GenId> {
    let mut sorted = gens.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let cutoff = sorted.len().saturating_sub(keep);
    sorted
        .into_iter()
        .take(cutoff)
        .filter(|g| g.0 != 1 && !protected.contains(g))
        .collect()
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd aios-cli && cargo test -p aios-gen`
Expected: `test result: ok. 22 passed`.

- [ ] **Step 6: Full check and commit**

Run: `make check`
Expected: clean fmt, no clippy warnings, all tests pass (aios-manifest 9 + 29, aios-gen 22).

```bash
cd /home/eli/Development/AIOS
git add aios-cli/
git commit -m "feat(gen): generation metadata and GC selection"
```

---

## Self-review

- **Spec coverage, §4.1 validation rules:**

  | Rule | Test |
  |---|---|
  | unknown keys | `unknown_key_is_parse_error_with_location` |
  | files outside /etc | `file_outside_etc_rejected`, `file_with_parent_dir_rejected` |
  | source/symlink | `file_with_both_source_and_symlink_rejected`, `file_with_neither_source_nor_symlink_rejected` |
  | mode | `bad_mode_rejected` |
  | persist absolute / `..` / under | `persist_relative_path_rejected`, `persist_under_usr_rejected`, `persist_under_home_rejected` |
  | persist overlap | `persist_overlap_rejected`, plus the component-boundary negative case |
  | home path | `home_absolute_target_rejected`, `home_parent_target_rejected` |
  | missing source / kind mismatch | `missing_source_rejected`, `home_missing_source_rejected`, `home_kind_mismatch_rejected` |
  | UID range / duplicate | `uid_out_of_range_rejected`, `duplicate_uid_rejected` |
  | missing secret | `missing_password_hash_rejected` |
  | kernel set | `unknown_kernel_rejected`, `fallback_equal_to_default_rejected` |
  | timezone | `unknown_timezone_rejected`, `timezone_traversal_rejected` |

  Hostname and username rules were added as safe extras.
- **Spec coverage, §2/§3:** zero-padded ids, subvolume names, next id with the 9999 cap, metadata fields, UKI names with counters, entry id, bad detection, GC protections (booted/default via `protected`, gen-1 always).
- **Deferred to Phase 2/3 plans (written against this code):** renderers, planner, exec, CLI.
