# Sentinel S4: Base ISO integration — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A generation carries its Sentinel configuration: the manifest's `[sentinel]` section and rule files are validated at plan time, rendered into the generation, loaded into the running daemon by `aios apply`, and a generation whose Sentinel cannot start fails its health check.

**Architecture:** `aios-manifest` gains a `[sentinel]` section modelled on `sentinel_rules::config::SentinelConfig` and validates it — and the rule files — through `sentinel-rules` directly, so `aios plan` reports exactly what the daemon would. `aios-render` gains one module that renders `sentinel.toml` and the rule copies; `aios-plan` reports the diff; `aios-exec` calls `LoadGeneration` over a new `sentinel-client` crate shared with the S3 CLI. Packaging adds `aios-sentinel` (binaries + unit) and `aios-health.sh` gains one check.

**Tech Stack:** Rust (aios-cli workspace, stable; sentinel workspace, pinned nightly), `sentinel-rules` as a cross-workspace path dependency, varlink over a Unix socket, PKGBUILD/makepkg, systemd, bats + pytest e2e, virtme-ng VM scenarios.

**Spec:** `docs/superpowers/specs/2026-11-12-sentinel-core-design.md` §11, with the three settled choices in §17.9. Read both before Task 1.

---

## Status of this plan

**Tasks 1–2 are written. Tasks 3–14 are listed under "Remaining tasks" with
their scope and files, and still need to be written out in full before they are
executed.** They are deliberately not stubbed inside the task format: a task in
this plan means complete code and commands, and a half-written task invites an
executor to improvise. Write them against the verified contract reference below
— those APIs were read off the tree, not remembered.

---

## Shared contract reference

Verified against the tree at commit `03fd017`. Quote these rather than guessing.

### sentinel-rules (the validator `aios-manifest` links)

`sentinel/crates/sentinel-rules`, builds on stable (`cargo +stable check -p sentinel-rules`
passes — the crate does not need sentinel's pinned nightly):

```rust
// config.rs
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
impl Default for SentinelConfig { /* the §11.1 defaults */ }
pub fn parse(raw: &str) -> Result<SentinelConfig, String>;
pub fn validate(c: &SentinelConfig) -> Vec<String>;   // empty == valid

pub struct Beacon { pub min_connects: u32, pub max_cov: f64, pub allow: Vec<String>,
                    pub severity: String, pub action: String }
pub struct DnsTunnel { pub label_len: u32, pub entropy: f64, pub unique_per_min: u32,
                       pub severity: String, pub action: String }

// lib.rs
pub fn load_dir(dir: &Path) -> Result<Vec<Rule>, Vec<RuleError>>;
// diff.rs
pub fn diff_rules(old: &[Rule], new: &[Rule]) -> RuleSetDiff;
impl RuleSetDiff { pub fn summary(&self) -> Vec<String> }  // "+ id", "- id", "id: action freeze -> kill"
// matcher.rs
pub fn compile_all(rules: &[Rule]) -> Result<(Tables, Vec<UserRule>), Vec<RuleError>>;
```

`RuleError` has `file: String`, `rule: Option<String>`, `message: String` and implements `Display`.

### aios-manifest

`aios-cli/crates/aios-manifest/src/model.rs:29`. **`Manifest` is
`#[serde(deny_unknown_fields)]`, so a manifest carrying `[sentinel]` fails to
parse today** — Task 1 is what makes it loadable at all:

```rust
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub system: System,
    pub kernel: Kernel,
    #[serde(default)] pub packages: Packages,
    #[serde(default)] pub services: Services,
    #[serde(default)] pub files: BTreeMap<String, FileEntry>,
    #[serde(default)] pub persist: Persist,
    #[serde(default)] pub users: BTreeMap<String, User>,
}
```

### aios-render

Modules are **pure functions** returning file content, taking `&Manifest`
(`aios-cli/crates/aios-render/src/simple.rs` is the pattern to copy):

```rust
use aios_manifest::Manifest;
/// `/etc/hostname`.
pub fn hostname(m: &Manifest) -> String { format!("{}\n", m.system.hostname) }
```

`managed.rs` owns the managed-file list: `pub fn managed_list(paths: &[String]) -> String`
and `pub fn parse_managed_list(text: &str) -> Result<Vec<String>, ManagedListError>`.

### aios-plan

`aios-cli/crates/aios-plan/src/desired.rs` builds the desired `/etc` map from the
manifest plus `repo_root`; `plan.rs` holds the result:

```rust
pub const MANAGED_FILES: &str = "/etc/aios/managed-files";
pub struct Inputs<'a> { pub manifest: &'a Manifest, pub repo_root: &'a Path, /* ctx */ }

pub struct Plan {
    pub packages_add: Vec<String>,
    pub packages_remove: Vec<String>,
    pub etc_changes: Vec<EtcChange>,   // EtcChange { path: String, kind: ChangeKind }
    pub unit_changes: Vec<UnitChange>,
    pub warnings: Vec<String>,
}
```

Rendered Sentinel files are ordinary `etc_changes` entries and join `MANAGED_FILES`.
The §11.2 rule summary is a new `Plan` field (Task 5), not a warning.

### The daemon side S3 already shipped (do not re-implement)

- `sentineld` flags: `--config`, `--rules`, `--alerts`, `--socket`, `--state`,
  `--home-binds`, `--no-enforce`, `--no-selfguard`.
- `LoadGeneration` and the three replies §11.3 distinguishes:
  `{"method":"io.aios.Sentinel.LoadGeneration","parameters":{"gen":"gen-7","dir":"/etc/aios/sentinel/rules.d"}}`
  → `{"parameters":{"ok":true,"changes":[...]}}`, or
  `{"error":"io.aios.Sentinel.InvalidRules","parameters":{"errors":[...]}}`, or
  the socket is absent.
- Socket: `/run/aios-sentinel/io.aios.Sentinel`, mode 0660 group `wheel`,
  root-only for `LoadGeneration`. State file: `/run/aios-sentinel/state`,
  exactly `ok` or `degraded`.
- The client to extract in Task 7 is `sentinel/crates/sentinel/src/client.rs`
  (`encode_call`, `reply_error`, `Client::{connect, call, call_more}`), with its
  tests in the same file.
- Full handoff: `sentinel/crates/sentineld/README.md`.

---

## File structure

| File | Responsibility |
|---|---|
| `aios-cli/crates/aios-manifest/src/sentinel.rs` (create) | The `[sentinel]` section: a thin wrapper over `sentinel_rules::config::SentinelConfig` plus its validation |
| `aios-cli/crates/aios-manifest/src/model.rs` (modify) | `pub sentinel: Option<Sentinel>` on `Manifest` |
| `aios-cli/crates/aios-manifest/Cargo.toml` (modify) | Path dependency on `sentinel-rules` |
| `aios-cli/crates/aios-render/src/sentinel.rs` (create) | `sentinel_toml(m) -> String` and the rule-file copy list |
| `aios-cli/crates/aios-plan/src/desired.rs` (modify) | Sentinel files in the desired `/etc` map and in `MANAGED_FILES` |
| `aios-cli/crates/aios-plan/src/plan.rs` (modify) | `sentinel_changes: Vec<String>` and the `enable = false` warning |
| `sentinel/crates/sentinel-client/` (create) | The varlink client, shared by the CLI and `aios-exec` |
| `sentinel/crates/sentinel/src/client.rs` (modify) | Depend on the shared crate; keep the CLI's own error phrasing |
| `aios-cli/crates/aios-exec/src/sentinel.rs` (create) | `LoadGeneration` after the generation is built, with §11.3's three outcomes |
| `packaging/aios-sentinel/PKGBUILD` (create) | Builds the sentinel workspace, installs both binaries and the unit |
| `packaging/aios-sentinel/aios-sentinel.service` (create) | §11.4's unit, plus the bpffs ordering S3's handoff flagged |
| `base/aios-health.sh` (modify) | One check: unit active and `/run/aios-sentinel/state` reads `ok` |
| `base/aios-health.service` (modify) | `After=aios-sentinel.service` |
| `Makefile` (modify) | `aios-sentinel` in `PACKAGES`; `make tools` installs the nightly and `bpf-linker` |
| `tests/e2e/` (modify) | Rendered-file and health-check coverage |
| `sentinel/tests/vm/scenarios/apply_generation.sh` (create) | apply → `LoadGeneration` → alert, in a VM |

---

## Task 1: The `[sentinel]` manifest section

**Files:**
- Create: `aios-cli/crates/aios-manifest/src/sentinel.rs`
- Modify: `aios-cli/crates/aios-manifest/src/model.rs:29-42` (add the field), `aios-cli/crates/aios-manifest/src/lib.rs` (add `pub mod sentinel;` and the re-export), `aios-cli/crates/aios-manifest/Cargo.toml`
- Test: in `aios-cli/crates/aios-manifest/src/sentinel.rs`

Spec §11.1 and §17.9 decision 1. The section is optional: absent means Sentinel
is enabled with the documented defaults. The inner type is
`sentinel_rules::config::SentinelConfig`, so the section has exactly one
definition and `aios plan` validates what the daemon will read.

- [ ] **Step 1: Add the dependency**

In `aios-cli/crates/aios-manifest/Cargo.toml`, under `[dependencies]`:

```toml
sentinel-rules = { path = "../../../sentinel/crates/sentinel-rules" }
```

- [ ] **Step 2: Verify the dependency resolves on this workspace's toolchain**

Run: `cd aios-cli && cargo check -p aios-manifest`
Expected: compiles. `sentinel-rules` is plain Rust and was checked on stable; if
it fails here, stop and report rather than vendoring a copy of the config type.

- [ ] **Step 3: Write the failing tests**

Create `aios-cli/crates/aios-manifest/src/sentinel.rs`:

```rust
//! The manifest's `[sentinel]` section (spec §11.1, amendment §17.9).

use serde::Deserialize;

/// The `[sentinel]` section. Absent from a manifest means
/// [`Sentinel::default`] — Sentinel enabled with the §11.1 defaults.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sentinel {
    #[serde(flatten)]
    pub config: sentinel_rules::config::SentinelConfig,
}

impl Default for Sentinel {
    fn default() -> Sentinel {
        Sentinel {
            config: sentinel_rules::config::SentinelConfig::default(),
        }
    }
}

impl Sentinel {
    /// Problems with the section, in the shape `aios plan` prints. Empty is valid.
    pub fn problems(&self) -> Vec<String> {
        sentinel_rules::config::validate(&self.config)
            .into_iter()
            .map(|p| format!("[sentinel]: {p}"))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absent_section_means_the_documented_defaults() {
        let s = Sentinel::default();
        assert!(s.config.enable);
        assert_eq!(s.config.lockdown_after, "5s");
        assert_eq!(s.config.storm_brake, 5);
        assert_eq!(s.config.rules, "sentinel/rules");
        assert!(s.problems().is_empty());
    }

    #[test]
    fn the_section_parses_the_spec_example() {
        let raw = r#"
enable         = true
rules          = "sentinel/rules"
lockdown_after = "5s"
storm_brake    = 5
never_act_on   = ["systemd-*.service", "dbus-broker.service"]
bpf_loaders    = []

[beacon]
min_connects = 6
max_cov      = 0.2
allow        = ["9.9.9.9/32"]

[dns_tunnel]
label_len      = 20
entropy        = 3.5
unique_per_min = 30
"#;
        let s: Sentinel = toml::from_str(raw).expect("parses");
        assert_eq!(s.config.beacon.min_connects, 6);
        assert_eq!(s.config.dns_tunnel.label_len, 20);
        assert!(s.problems().is_empty());
    }

    #[test]
    fn an_unknown_key_is_rejected() {
        let e = toml::from_str::<Sentinel>("enabel = true\n").expect_err("typo rejected");
        assert!(
            e.to_string().contains("enabel") || e.to_string().contains("unknown"),
            "the error names the typo: {e}"
        );
    }

    #[test]
    fn a_bad_duration_is_a_problem_not_a_parse_error() {
        let s: Sentinel = toml::from_str("lockdown_after = \"5 fortnights\"\n").expect("parses");
        let p = s.problems();
        assert_eq!(p.len(), 1, "{p:?}");
        assert!(p[0].starts_with("[sentinel]: "), "{p:?}");
        assert!(p[0].contains("lockdown_after"), "{p:?}");
    }
}
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `cd aios-cli && cargo test -p aios-manifest sentinel`
Expected: FAIL to compile — ``file not found for module `sentinel` `` until
Step 5 declares the module.

- [ ] **Step 5: Declare the module and put the field on `Manifest`**

In `aios-cli/crates/aios-manifest/src/lib.rs`, beside the existing module
declarations:

```rust
pub mod sentinel;
pub use sentinel::Sentinel;
```

In `aios-cli/crates/aios-manifest/src/model.rs`, inside `pub struct Manifest`,
after the `users` field:

```rust
    #[serde(default)]
    pub sentinel: Option<Sentinel>,
```

and add `use crate::sentinel::Sentinel;` to that file's imports.

`Option` rather than `#[serde(default)] Sentinel`, because §11.2 prints a
warning for `enable = false` and the planner has to tell "the manifest said
nothing" from "the manifest asked for the defaults explicitly" when it reports
section changes.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cd aios-cli && cargo test -p aios-manifest sentinel`
Expected: 4 passed.

- [ ] **Step 7: Check that a manifest carrying the section now loads at all**

Run: `cd aios-cli && cargo test -p aios-manifest`
Expected: the whole crate's tests pass, including the existing manifest
fixtures. `deny_unknown_fields` on `Manifest` is what made `[sentinel]` a parse
error before this task; if an existing fixture test fails, it is asserting that
rejection and its expectation is what changes.

- [ ] **Step 8: Commit**

```bash
git add aios-cli/crates/aios-manifest/Cargo.toml aios-cli/crates/aios-manifest/src/sentinel.rs aios-cli/crates/aios-manifest/src/model.rs aios-cli/crates/aios-manifest/src/lib.rs aios-cli/Cargo.lock
git commit -m "feat(aios-manifest): the [sentinel] manifest section"
```

---

## Task 2: Rule-file validation at plan time

**Files:**
- Modify: `aios-cli/crates/aios-manifest/src/sentinel.rs` (add the loader)
- Test: in the same file

Spec §11.2: "Rule validation errors fail the plan like any manifest error." The
rules live in a directory of the manifest repo named by `sentinel.rules`
(default `sentinel/rules`), so validation needs the repo root.

- [ ] **Step 1: Write the failing tests**

Append inside the `tests` module of `aios-cli/crates/aios-manifest/src/sentinel.rs`:

```rust
    #[test]
    fn a_valid_rule_directory_loads() {
        let dir = tempfile::tempdir().unwrap();
        let rules = dir.path().join("sentinel/rules");
        std::fs::create_dir_all(&rules).unwrap();
        std::fs::write(
            rules.join("pack.toml"),
            "[[rule]]\nid = \"x\"\non = \"exec\"\nseverity = \"low\"\n\
             action = \"alert\"\nmatch = { exe_memfd = true }\n",
        )
        .unwrap();

        let s = Sentinel::default();
        let loaded = s.load_rules(dir.path()).expect("valid rules load");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, "x");
    }

    #[test]
    fn an_invalid_rule_fails_with_the_validators_own_message() {
        let dir = tempfile::tempdir().unwrap();
        let rules = dir.path().join("sentinel/rules");
        std::fs::create_dir_all(&rules).unwrap();
        std::fs::write(
            rules.join("pack.toml"),
            "[[rule]]\nid = \"x\"\non = \"exec\"\nseverity = \"low\"\n\
             action = \"alert\"\nmatch = { nope = true }\n",
        )
        .unwrap();

        let errs = Sentinel::default()
            .load_rules(dir.path())
            .expect_err("rejected");
        assert_eq!(errs.len(), 1, "{errs:?}");
        assert!(errs[0].contains("pack.toml"), "names the file: {errs:?}");
        assert!(errs[0].contains("nope"), "names the predicate: {errs:?}");
    }

    #[test]
    fn a_missing_rule_directory_is_an_error_naming_the_path() {
        let dir = tempfile::tempdir().unwrap();
        let errs = Sentinel::default()
            .load_rules(dir.path())
            .expect_err("rejected");
        assert!(
            errs.iter().any(|e| e.contains("sentinel/rules")),
            "names the configured directory: {errs:?}"
        );
    }

    #[test]
    fn a_disabled_sentinel_still_validates_its_rules() {
        // enable = false takes effect at the next boot (§11.3); shipping a
        // generation whose rules do not compile would arm a trap for whoever
        // re-enables it.
        let dir = tempfile::tempdir().unwrap();
        let rules = dir.path().join("sentinel/rules");
        std::fs::create_dir_all(&rules).unwrap();
        std::fs::write(rules.join("pack.toml"), "[[rule]]\nid = \"x\"\n").unwrap();
        let mut s = Sentinel::default();
        s.config.enable = false;
        assert!(s.load_rules(dir.path()).is_err());
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd aios-cli && cargo test -p aios-manifest sentinel`
Expected: FAIL to compile — ``no method named `load_rules` ``.

- [ ] **Step 3: Write the implementation**

Add to `impl Sentinel` in `aios-cli/crates/aios-manifest/src/sentinel.rs`:

```rust
    /// The rule directory inside the manifest repo, as configured.
    pub fn rules_dir(&self, repo_root: &std::path::Path) -> std::path::PathBuf {
        repo_root.join(&self.config.rules)
    }

    /// Load and validate the rule files. `Err` holds one message per problem,
    /// in the shape `aios plan` prints; the strings come from `sentinel-rules`,
    /// so they match what `sentineld` would report for the same files
    /// (§17.9 decision 1).
    pub fn load_rules(
        &self,
        repo_root: &std::path::Path,
    ) -> Result<Vec<sentinel_rules::model::Rule>, Vec<String>> {
        let dir = self.rules_dir(repo_root);
        if !dir.is_dir() {
            return Err(vec![format!(
                "[sentinel] rules: {} is not a directory",
                self.config.rules
            )]);
        }
        sentinel_rules::load_dir(&dir).map_err(|errs| {
            errs.iter()
                .map(|e| format!("[sentinel] rules: {e}"))
                .collect()
        })
    }
```

- [ ] **Step 4: Confirm the dev-dependency the tests need**

Run: `cd aios-cli && grep -A4 '\[dev-dependencies\]' crates/aios-manifest/Cargo.toml`
Expected: `tempfile` appears. If it does not, add `tempfile.workspace = true`
under `[dev-dependencies]`.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd aios-cli && cargo test -p aios-manifest sentinel`
Expected: 8 passed.

- [ ] **Step 6: Commit**

```bash
git add aios-cli/crates/aios-manifest/src/sentinel.rs aios-cli/crates/aios-manifest/Cargo.toml
git commit -m "feat(aios-manifest): validate the Sentinel rule files at plan time"
```

---

## Remaining tasks

Each line is one task still to be written out in the format above — files, a
failing test with real code, the run command and its expected output, the
implementation, the verification, the commit. Scope and files are settled; the
code is not yet written.

- **Task 3: Wire the section into manifest loading.** The crate's top-level
  `load`/`validate` path calls `Sentinel::problems` and `load_rules`, so a bad
  section or a bad rule fails like any other manifest error. Files:
  `aios-cli/crates/aios-manifest/src/lib.rs` and wherever that crate's existing
  `validate` collects problems.
- **Task 4: Render `sentinel.toml` and the rule list.** Create
  `aios-cli/crates/aios-render/src/sentinel.rs` with
  `sentinel_toml(m: &Manifest) -> String` (the section resolved with defaults,
  which is what `sentineld --config` reads) and a function listing the rule
  files to copy. Pure functions, `simple.rs` pattern, unit-tested on content.
- **Task 5: The `aios plan` Sentinel summary.** `Plan` gains
  `sentinel_changes: Vec<String>`, filled from
  `sentinel_rules::diff::diff_rules(...).summary()` plus the changed
  `[sentinel]` fields, and a warning when `enable = false` (§11.2, mirroring
  `lockdown = "none"`). Files: `aios-cli/crates/aios-plan/src/{plan.rs,desired.rs}`
  and the CLI's plan printer.
- **Task 6: Sentinel files in the desired state.** `desired.rs` puts
  `/etc/aios/sentinel/sentinel.toml` and each `/etc/aios/sentinel/rules.d/*.toml`
  into the desired `/etc` map and therefore into `MANAGED_FILES`, so drift and
  removal behave like every other managed file.
- **Task 7: Extract `sentinel-client`.** New crate
  `sentinel/crates/sentinel-client` holding the framing and `Client` from
  `sentinel/crates/sentinel/src/client.rs`, with that file's tests moving with
  it; the CLI keeps `reply_error`'s human phrasing and depends on the crate. No
  behaviour change — the S3 CLI tests must still pass unmodified.
- **Task 8: `LoadGeneration` from `aios apply`.** New
  `aios-cli/crates/aios-exec/src/sentinel.rs`, called once the generation is
  built, handling §11.3's three outcomes distinctly: rules rejected (warn,
  naming the errors, generation still built), daemon absent (warn, rules take
  effect next boot), success (print the change summary). Unit-tested against a
  fake socket. `enable = false` and `lockdown_after` changes also warn that they
  need a reboot.
- **Task 9: The systemd unit.** `packaging/aios-sentinel/aios-sentinel.service`
  with §11.4's directives verbatim, plus `LogsDirectory=aios/sentinel` (0700)
  and the bpffs dependency the S3 handoff flagged (`sys-fs-bpf.mount`), checked
  with `systemd-analyze verify` the way `make check` already checks the other
  units.
- **Task 10: The package.** `packaging/aios-sentinel/PKGBUILD` building the
  sentinel workspace and installing `/usr/bin/sentineld`, `/usr/bin/sentinel`
  and the unit; `aios-sentinel` added to the Makefile `PACKAGES` and to the core
  package set; `make tools` installs the pinned nightly with `rust-src` and
  `bpf-linker`.
- **Task 11: The health check.** `base/aios-health.sh` gains the §11.5 check
  (when `enable = true`, unit active **and** `/run/aios-sentinel/state` reads
  `ok`), and `base/aios-health.service` gains `After=aios-sentinel.service`.
  Covered by the existing bats harness.
- **Task 12: e2e coverage.** The rendered files appear in a generation with the
  right content and mode, `MANAGED_FILES` lists them, and a manifest with a
  broken rule fails `aios plan` with the validator's message.
- **Task 13: A VM scenario for apply.**
  `sentinel/tests/vm/scenarios/apply_generation.sh`: daemon running, rules
  changed, `LoadGeneration` called, the daemon swaps and raises the critical
  `config-changed` alert; an invalid set is rejected while the old rules stay
  loaded.
- **Task 14: `make check`, spec amendments and the S5 handoff.** Extend the gate
  to the new package, record S4's outcomes as §17.10, and write what the S5
  gauntlet inherits.

---

## Self-review against the spec

| Spec section | Covered by |
|---|---|
| §11.1 manifest section: optional, defaults, validated | Tasks 1, 3 |
| §11.2 plan fails on rule errors; Sentinel summary; `enable = false` warning | Tasks 2, 5 |
| §11.3 renderer writes both files, managed files, `LoadGeneration` with three outcomes, reboot-only fields | Tasks 4, 6, 8 |
| §11.4 PKGBUILD, binaries, unit directives, build-host tools, log directory | Tasks 9, 10 |
| §11.5 health check and its ordering | Task 11 |
| §17.9 decisions 1–3 | Tasks 1–2 (linked validator), 7–8 (shared client), the single-stage scope of this plan |

**Known gap in this document:** Tasks 3–14 are scoped but not written out.
Write them before executing them.
