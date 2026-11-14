# Sentinel S4: Base ISO integration — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A generation carries its Sentinel configuration: the manifest's `[sentinel]` section and rule files are validated at plan time, rendered into the generation, loaded into the running daemon by `aios apply`, and a generation whose Sentinel cannot start fails its health check.

**Architecture:** `aios-manifest` gains a `[sentinel]` section modelled on `sentinel_rules::config::SentinelConfig` and validates it — and the rule files — through `sentinel-rules` directly, so `aios plan` reports exactly what the daemon would. `aios-render` gains one module that renders `sentinel.toml` and the rule copies; `aios-plan` reports the diff; `aios-exec` calls `LoadGeneration` over a new `sentinel-client` crate shared with the S3 CLI. Packaging adds `aios-sentinel` (binaries + unit) and `aios-health.sh` gains one check.

**Tech Stack:** Rust (aios-cli workspace, stable; sentinel workspace, pinned nightly), `sentinel-rules` as a cross-workspace path dependency, varlink over a Unix socket, PKGBUILD/makepkg, systemd, bats + pytest e2e, virtme-ng VM scenarios.

**Spec:** `docs/superpowers/specs/2026-11-12-sentinel-core-design.md` §11, with the three settled choices in §17.9. Read both before Task 1.

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
The §11.2 rule summary is a new `Plan` field (Task 6), not a warning.

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
| `aios-cli/crates/aios-exec/src/apply/sentinel.rs` (create) | `LoadGeneration` after the generation is built, with §11.3's three outcomes |
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

## Task 3: Wire the section into manifest validation

**Files:**
- Modify: `aios-cli/crates/aios-manifest/src/validate.rs:75-87` (call the new check) and the `Validator` impl in the same file
- Test: in `aios-cli/crates/aios-manifest/src/validate.rs`'s existing `tests` module

Spec §11.2: a bad `[sentinel]` section or a rule file that does not validate
fails the plan like any other manifest error. `validate` already returns every
problem as a `ManifestError { line, col, message }` positioned with the
`locate_*` helpers; Sentinel joins that list, so the CLI needs no new path.

- [ ] **Step 1: Write the failing tests**

Append inside the `tests` module of `aios-cli/crates/aios-manifest/src/validate.rs`.
Match the fixtures the module already uses for `env`; if it has a helper that
builds a `ValidationEnv` over a tempdir, call that instead of repeating this:

```rust
    /// A manifest whose only interesting part is its `[sentinel]` section.
    fn with_sentinel(section: &str) -> String {
        format!(
            "[system]\nhostname = \"h\"\ntimezone = \"UTC\"\n\
             locale = \"C.UTF-8\"\nkeymap = \"us\"\n\n\
             [kernel]\npackage = \"linux\"\n\n{section}"
        )
    }

    #[test]
    fn a_bad_sentinel_field_is_a_manifest_error() {
        let raw = with_sentinel("[sentinel]\nlockdown_after = \"5 fortnights\"\n");
        let m: Manifest = crate::parse(&raw).expect("parses");
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("sentinel/rules")).unwrap();
        let env = ValidationEnv {
            repo_root: dir.path().to_path_buf(),
            secrets_dir: dir.path().join("secrets"),
            zoneinfo_dir: dir.path().join("zoneinfo"),
        };
        let errs = validate(&m, &raw, &env);
        let hit = errs
            .iter()
            .find(|e| e.message.contains("lockdown_after"))
            .unwrap_or_else(|| panic!("no sentinel error in {errs:?}"));
        assert!(hit.line > 1, "the error points at the section: {hit:?}");
    }

    #[test]
    fn a_rule_file_that_does_not_validate_is_a_manifest_error() {
        let raw = with_sentinel("[sentinel]\n");
        let m: Manifest = crate::parse(&raw).expect("parses");
        let dir = tempfile::tempdir().unwrap();
        let rules = dir.path().join("sentinel/rules");
        std::fs::create_dir_all(&rules).unwrap();
        std::fs::write(
            rules.join("pack.toml"),
            "[[rule]]\nid = \"x\"\non = \"exec\"\nseverity = \"low\"\n\
             action = \"alert\"\nmatch = { nope = true }\n",
        )
        .unwrap();
        let env = ValidationEnv {
            repo_root: dir.path().to_path_buf(),
            secrets_dir: dir.path().join("secrets"),
            zoneinfo_dir: dir.path().join("zoneinfo"),
        };
        let errs = validate(&m, &raw, &env);
        assert!(
            errs.iter().any(|e| e.message.contains("nope")),
            "the validator's own message reaches the plan: {errs:?}"
        );
    }

    #[test]
    fn a_manifest_without_a_sentinel_section_validates_its_default_rules() {
        // Absent section means enabled with defaults (§11.1), and the default
        // rules directory must therefore exist in the repo.
        let raw = with_sentinel("");
        let m: Manifest = crate::parse(&raw).expect("parses");
        let dir = tempfile::tempdir().unwrap();
        let env = ValidationEnv {
            repo_root: dir.path().to_path_buf(),
            secrets_dir: dir.path().join("secrets"),
            zoneinfo_dir: dir.path().join("zoneinfo"),
        };
        let errs = validate(&m, &raw, &env);
        assert!(
            errs.iter().any(|e| e.message.contains("sentinel/rules")),
            "a missing default rule directory is reported: {errs:?}"
        );
    }

    #[test]
    fn a_valid_section_and_rule_set_adds_no_errors() {
        let raw = with_sentinel("[sentinel]\nstorm_brake = 3\n");
        let m: Manifest = crate::parse(&raw).expect("parses");
        let dir = tempfile::tempdir().unwrap();
        let rules = dir.path().join("sentinel/rules");
        std::fs::create_dir_all(&rules).unwrap();
        std::fs::write(
            rules.join("pack.toml"),
            "[[rule]]\nid = \"x\"\non = \"exec\"\nseverity = \"low\"\n\
             action = \"alert\"\nmatch = { exe_memfd = true }\n",
        )
        .unwrap();
        let env = ValidationEnv {
            repo_root: dir.path().to_path_buf(),
            secrets_dir: dir.path().join("secrets"),
            zoneinfo_dir: dir.path().join("zoneinfo"),
        };
        let errs = validate(&m, &raw, &env);
        assert!(
            !errs.iter().any(|e| e.message.contains("sentinel")),
            "{errs:?}"
        );
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd aios-cli && cargo test -p aios-manifest sentinel`
Expected: the four new tests fail — no Sentinel problem appears in `errs`,
because `validate` does not look at the section yet.

- [ ] **Step 3: Write the implementation**

In `aios-cli/crates/aios-manifest/src/validate.rs`, add the call at the end of
`validate`'s existing sequence:

```rust
    v.users(m, env);
    v.sentinel(m, env);
    v.errors
```

and add the method to `impl Validator<'_>`, beside `files`:

```rust
    /// The `[sentinel]` section and its rule files (spec §11.1, §11.2). An
    /// absent section means the defaults, which still name a rule directory,
    /// so the rules are validated either way.
    fn sentinel(&mut self, m: &Manifest, env: &ValidationEnv) {
        let s = m.sentinel.clone().unwrap_or_default();
        let pos = locate_section(self.raw, &["sentinel"]);

        for problem in s.problems() {
            self.err(pos, problem);
        }
        if let Err(problems) = s.load_rules(&env.repo_root) {
            // One error per problem, so `aios plan` lists them all rather than
            // making the user fix them one build at a time.
            for problem in problems {
                self.err(pos, problem);
            }
        }
    }
```

`locate_section` takes a slice and falls back to `(1, 1)` when the section is
absent, which is the right position for "your manifest did not mention
Sentinel and its default rule directory is missing".

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd aios-cli && cargo test -p aios-manifest`
Expected: all pass, the four new ones included.

Existing manifest fixtures now need a `sentinel/rules` directory in their test
repo root, or they will gain a "not a directory" error. If a fixture fails that
way, create the directory in the fixture — do not weaken the check, because
§11.1's defaults really do point at `sentinel/rules`.

- [ ] **Step 5: Commit**

```bash
git add aios-cli/crates/aios-manifest/src/validate.rs
git commit -m "feat(aios-manifest): fail the plan on a bad [sentinel] section or rules"
```

---

## Task 4: Render `sentinel.toml`

**Files:**
- Create: `aios-cli/crates/aios-render/src/sentinel.rs`
- Modify: `aios-cli/crates/aios-render/src/lib.rs` (add `mod sentinel;` and re-export), `aios-cli/crates/aios-render/Cargo.toml`
- Test: in `aios-cli/crates/aios-render/src/sentinel.rs`

Spec §11.3: the renderer writes `/etc/aios/sentinel/sentinel.toml` — the
section resolved with defaults, which is exactly what `sentineld --config`
reads. Pure function returning the content, like every other module here.

- [ ] **Step 1: Add the dependency**

In `aios-cli/crates/aios-render/Cargo.toml`, under `[dependencies]`:

```toml
sentinel-rules = { path = "../../../sentinel/crates/sentinel-rules" }
toml.workspace = true
```

`toml` only if it is not already a dependency of this crate; check first with
`grep '^toml' aios-cli/crates/aios-render/Cargo.toml`.

- [ ] **Step 2: Write the failing tests**

Create `aios-cli/crates/aios-render/src/sentinel.rs`:

```rust
//! `/etc/aios/sentinel/sentinel.toml` (spec §11.3).

use aios_manifest::Manifest;

/// Where the daemon reads its configuration.
pub const SENTINEL_TOML: &str = "/etc/aios/sentinel/sentinel.toml";
/// Where the daemon reads its rules.
pub const RULES_DIR: &str = "/etc/aios/sentinel/rules.d";

/// `/etc/aios/sentinel/sentinel.toml`: the `[sentinel]` section resolved with
/// the §11.1 defaults. An absent section renders the defaults, so the file is
/// always present and `sentineld` never has to guess.
pub fn sentinel_toml(m: &Manifest) -> String {
    let s = m.sentinel.clone().unwrap_or_default();
    // Serialised from the same type the daemon parses, so a field added to
    // SentinelConfig cannot be silently dropped on the way to disk.
    let body = toml::to_string_pretty(&s.config)
        .unwrap_or_else(|e| panic!("the [sentinel] section must serialise: {e}"));
    format!("# Written by aios. Do not edit.\n{body}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(sentinel: &str) -> Manifest {
        let raw = format!(
            "[system]\nhostname = \"h\"\ntimezone = \"UTC\"\n\
             locale = \"C.UTF-8\"\nkeymap = \"us\"\n\n\
             [kernel]\npackage = \"linux\"\n\n{sentinel}"
        );
        aios_manifest::parse(&raw).expect("parses")
    }

    #[test]
    fn an_absent_section_renders_the_defaults() {
        let out = sentinel_toml(&manifest(""));
        assert!(out.starts_with("# Written by aios. Do not edit.\n"));
        assert!(out.contains("enable = true"), "{out}");
        assert!(out.contains("lockdown_after = \"5s\""), "{out}");
        assert!(out.contains("storm_brake = 5"), "{out}");
    }

    #[test]
    fn the_rendered_file_is_what_the_daemon_parses() {
        // The round trip is the point: this file is sentineld's --config.
        let out = sentinel_toml(&manifest("[sentinel]\nstorm_brake = 3\n"));
        let parsed = sentinel_rules::config::parse(&out).expect("the daemon can read it");
        assert_eq!(parsed.storm_brake, 3);
        assert!(parsed.enable);
        assert!(
            sentinel_rules::config::validate(&parsed).is_empty(),
            "and it validates"
        );
    }

    #[test]
    fn a_disabled_sentinel_renders_enable_false() {
        let out = sentinel_toml(&manifest("[sentinel]\nenable = false\n"));
        assert!(out.contains("enable = false"), "{out}");
        let parsed = sentinel_rules::config::parse(&out).unwrap();
        assert!(!parsed.enable);
    }

    #[test]
    fn the_detector_tables_survive_the_round_trip() {
        let out = sentinel_toml(&manifest(
            "[sentinel]\n\n[sentinel.beacon]\nmin_connects = 9\n\n\
             [sentinel.dns_tunnel]\nlabel_len = 30\n",
        ));
        let parsed = sentinel_rules::config::parse(&out).unwrap();
        assert_eq!(parsed.beacon.min_connects, 9);
        assert_eq!(parsed.dns_tunnel.label_len, 30);
    }
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cd aios-cli && cargo test -p aios-render sentinel`
Expected: FAIL to compile — ``file not found for module `sentinel` ``.

- [ ] **Step 4: Make `SentinelConfig` serialisable**

`sentinel_rules::config::SentinelConfig` derives `Deserialize` only. In
`sentinel/crates/sentinel-rules/src/config.rs`, add `Serialize` to the derive
on `SentinelConfig`, `Beacon` and `DnsTunnel`:

```rust
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct SentinelConfig {
```

and make sure that file's `use serde::...` line imports both:

```rust
use serde::{Deserialize, Serialize};
```

Run: `cd sentinel && cargo test -p sentinel-rules config`
Expected: the crate's existing config tests still pass.

- [ ] **Step 5: Declare the module**

In `aios-cli/crates/aios-render/src/lib.rs`, beside the other module
declarations and re-exports:

```rust
mod sentinel;
pub use sentinel::{sentinel_toml, RULES_DIR, SENTINEL_TOML};
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cd aios-cli && cargo test -p aios-render sentinel`
Expected: 4 passed.

- [ ] **Step 7: Commit**

```bash
git add aios-cli/crates/aios-render/src/sentinel.rs aios-cli/crates/aios-render/src/lib.rs aios-cli/crates/aios-render/Cargo.toml aios-cli/Cargo.lock sentinel/crates/sentinel-rules/src/config.rs
git commit -m "feat(aios-render): render /etc/aios/sentinel/sentinel.toml"
```

---

## Task 5: Sentinel files in the desired state

**Files:**
- Modify: `aios-cli/crates/aios-plan/src/desired.rs:145-207` (the generated-file block and the rule copies)
- Test: in `aios-cli/crates/aios-plan/src/desired.rs`'s `tests` module

Spec §11.3: both the config and the rule files are managed files of the
generation. `MANAGED_FILES` is built from the keys of the desired map, so
inserting them is all it takes for drift and removal to behave like every
other managed file — no separate bookkeeping.

- [ ] **Step 1: Write the failing tests**

Append inside the `tests` module of `aios-cli/crates/aios-plan/src/desired.rs`.
Use whatever helper that module already has for building `Inputs` and a probe;
the names below assume `desired_etc(inputs, probe)` is the function under test
and that the module has a `fixture()` helper — adapt to what is there rather
than adding a second fixture:

```rust
    #[test]
    fn the_sentinel_config_and_rules_are_managed_files() {
        let (inputs, probe, repo) = fixture();
        let rules = repo.join("sentinel/rules");
        std::fs::create_dir_all(&rules).unwrap();
        std::fs::write(
            rules.join("default.toml"),
            "[[rule]]\nid = \"x\"\non = \"exec\"\nseverity = \"low\"\n\
             action = \"alert\"\nmatch = { exe_memfd = true }\n",
        )
        .unwrap();

        let out = desired_etc(&inputs, &probe).expect("renders");

        assert!(
            out.contains_key("/etc/aios/sentinel/sentinel.toml"),
            "the config is rendered"
        );
        assert!(
            out.contains_key("/etc/aios/sentinel/rules.d/default.toml"),
            "each rule file is copied: {:?}",
            out.keys().collect::<Vec<_>>()
        );

        let managed = match out.get(MANAGED_FILES).expect("managed list") {
            EtcEntry::File { content, .. } => String::from_utf8(content.clone()).unwrap(),
            other => panic!("managed-files is not a file: {other:?}"),
        };
        assert!(managed.contains("/etc/aios/sentinel/sentinel.toml"), "{managed}");
        assert!(managed.contains("/etc/aios/sentinel/rules.d/default.toml"), "{managed}");
    }

    #[test]
    fn a_rule_file_is_copied_byte_for_byte() {
        let (inputs, probe, repo) = fixture();
        let rules = repo.join("sentinel/rules");
        std::fs::create_dir_all(&rules).unwrap();
        let body = "[[rule]]\nid = \"keep\"\non = \"exec\"\nseverity = \"low\"\n\
                    action = \"alert\"\nmatch = { exe_memfd = true }\n";
        std::fs::write(rules.join("keep.toml"), body).unwrap();

        let out = desired_etc(&inputs, &probe).expect("renders");
        match out.get("/etc/aios/sentinel/rules.d/keep.toml").unwrap() {
            EtcEntry::File { content, mode } => {
                assert_eq!(String::from_utf8(content.clone()).unwrap(), body);
                assert_eq!(*mode, 0o644);
            }
            other => panic!("not a file: {other:?}"),
        }
    }

    #[test]
    fn a_disabled_sentinel_still_renders_its_files() {
        // enable = false only takes effect at the next boot (§11.3), and the
        // daemon in this generation still reads both paths.
        let (mut inputs, probe, repo) = fixture();
        std::fs::create_dir_all(repo.join("sentinel/rules")).unwrap();
        let mut m = inputs.manifest.clone();
        m.sentinel = Some(aios_manifest::Sentinel {
            config: sentinel_rules::config::SentinelConfig {
                enable: false,
                ..Default::default()
            },
        });
        inputs.manifest = &m;

        let out = desired_etc(&inputs, &probe).expect("renders");
        assert!(out.contains_key("/etc/aios/sentinel/sentinel.toml"));
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd aios-cli && cargo test -p aios-plan sentinel`
Expected: FAIL — the keys are missing from the desired map.

- [ ] **Step 3: Write the implementation**

In `aios-cli/crates/aios-plan/src/desired.rs`, add `sentinel_toml`,
`SENTINEL_TOML` and `RULES_DIR` to the `aios_render` import list, then add
`sentinel.toml` to the `generated` array:

```rust
        ("/etc/tmpfiles.d/aios-home.conf", home_tmpfiles(m)),
        (SENTINEL_TOML, sentinel_toml(m)),
```

and copy the rule files in, after the `home_binds` loop and before
`out.remove(PKGDIRS_CONF)`:

```rust
    // The rule files, copied from the manifest repo (§11.3). Validation
    // already ran in aios-manifest, so a file that fails to read here is a
    // repo that changed under us, which is a plan error like any other.
    let sentinel = m.sentinel.clone().unwrap_or_default();
    let rules_src = in_repo(inputs.repo_root, &sentinel.config.rules)?;
    for (rel, entry) in walk(&rules_src)? {
        out.insert(format!("{RULES_DIR}/{rel}"), entry);
    }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd aios-cli && cargo test -p aios-plan`
Expected: all pass. Existing fixtures that have no `sentinel/rules` directory
will now fail in `in_repo`; add the directory to those fixtures, which is what
a real manifest repo has.

- [ ] **Step 5: Commit**

```bash
git add aios-cli/crates/aios-plan/src/desired.rs
git commit -m "feat(aios-plan): Sentinel config and rules are managed files"
```

---

## Task 6: The `aios plan` Sentinel summary

**Files:**
- Modify: `aios-cli/crates/aios-plan/src/plan.rs:44-49` (the `Plan` struct), `aios-cli/crates/aios-plan/src/plan.rs:164` (`impl fmt::Display for Plan`), and wherever `Plan` is built in that file
- Test: in `aios-cli/crates/aios-plan/src/plan.rs`'s `tests` module

Spec §11.2: the diff prints a Sentinel summary — rules added, removed and
changed, naming changed fields — plus any change to the `[sentinel]` section,
and a warning when Sentinel is disabled. The rule lines come from
`sentinel_rules::diff::diff_rules(...).summary()`, so `aios plan` and the
daemon's own `config-changed` alert word them identically.

- [ ] **Step 1: Write the failing tests**

Append inside the `tests` module of `aios-cli/crates/aios-plan/src/plan.rs`:

```rust
    use sentinel_rules::model::Rule;

    fn rule(id: &str, action: &str) -> Rule {
        let raw = format!(
            "[[rule]]\nid = \"{id}\"\non = \"exec\"\nseverity = \"low\"\n\
             action = \"{action}\"\nmatch = {{ exe_memfd = true }}\n"
        );
        sentinel_rules::model::parse(&raw).expect("parses").rule.remove(0)
    }

    #[test]
    fn the_summary_names_added_removed_and_changed_rules() {
        let old = vec![rule("gone", "alert"), rule("changed", "freeze")];
        let new = vec![rule("changed", "kill"), rule("added", "alert")];
        let lines = sentinel_summary(&old, &new);
        assert!(lines.iter().any(|l| l == "+ added"), "{lines:?}");
        assert!(lines.iter().any(|l| l == "- gone"), "{lines:?}");
        assert!(
            lines.iter().any(|l| l.contains("changed") && l.contains("freeze") && l.contains("kill")),
            "a changed field is named: {lines:?}"
        );
    }

    #[test]
    fn an_unchanged_rule_set_summarises_to_nothing() {
        let same = vec![rule("x", "alert")];
        assert!(sentinel_summary(&same, &same).is_empty());
    }

    #[test]
    fn a_changed_section_field_is_reported() {
        let old = sentinel_rules::config::SentinelConfig::default();
        let new = sentinel_rules::config::SentinelConfig {
            storm_brake: 9,
            ..Default::default()
        };
        let lines = sentinel_config_summary(&old, &new);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("storm_brake"), "{lines:?}");
        assert!(lines[0].contains('5') && lines[0].contains('9'), "{lines:?}");
    }

    #[test]
    fn disabling_sentinel_is_a_warning() {
        let off = sentinel_rules::config::SentinelConfig {
            enable: false,
            ..Default::default()
        };
        let w = sentinel_warnings(&off);
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(
            w[0].contains("Sentinel") && w[0].contains("reboot"),
            "it says what is lost and when: {w:?}"
        );
        assert!(sentinel_warnings(&Default::default()).is_empty());
    }

    #[test]
    fn the_summary_prints_under_its_own_heading() {
        let mut p = Plan::default();
        p.sentinel_changes = vec!["+ added".to_string(), "x: action alert -> kill".to_string()];
        let text = p.to_string();
        assert!(text.contains("Sentinel:"), "{text}");
        assert!(text.contains("+ added"), "{text}");
        assert!(text.contains("x: action alert -> kill"), "{text}");
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd aios-cli && cargo test -p aios-plan sentinel`
Expected: FAIL to compile — ``cannot find function `sentinel_summary` `` and
``no field `sentinel_changes` ``.

- [ ] **Step 3: Write the implementation**

In `aios-cli/crates/aios-plan/src/plan.rs`, add the field to `Plan`:

```rust
pub struct Plan {
    pub packages_add: Vec<String>,
    pub packages_remove: Vec<String>,
    pub etc_changes: Vec<EtcChange>,
    pub unit_changes: Vec<UnitChange>,
    pub warnings: Vec<String>,
    /// Rule and `[sentinel]` changes, in the wording the daemon's own
    /// `config-changed` alert uses (spec §11.2).
    pub sentinel_changes: Vec<String>,
}
```

Update every construction of `Plan` in the crate to set it (an empty `Vec` where
there is nothing to say), and add the three helpers:

```rust
/// Rule changes between two rule sets, worded as the daemon words them.
pub fn sentinel_summary(
    old: &[sentinel_rules::model::Rule],
    new: &[sentinel_rules::model::Rule],
) -> Vec<String> {
    sentinel_rules::diff::diff_rules(old, new).summary()
}

/// Changed `[sentinel]` fields, one line each.
pub fn sentinel_config_summary(
    old: &sentinel_rules::config::SentinelConfig,
    new: &sentinel_rules::config::SentinelConfig,
) -> Vec<String> {
    let mut out = Vec::new();
    let mut field = |name: &str, a: String, b: String| {
        if a != b {
            out.push(format!("[sentinel] {name}: {a} -> {b}"));
        }
    };
    field("enable", old.enable.to_string(), new.enable.to_string());
    field("rules", old.rules.clone(), new.rules.clone());
    field(
        "lockdown_after",
        old.lockdown_after.clone(),
        new.lockdown_after.clone(),
    );
    field(
        "storm_brake",
        old.storm_brake.to_string(),
        new.storm_brake.to_string(),
    );
    field(
        "never_act_on",
        old.never_act_on.join(","),
        new.never_act_on.join(","),
    );
    field(
        "bpf_loaders",
        old.bpf_loaders.join(","),
        new.bpf_loaders.join(","),
    );
    if old.beacon != new.beacon {
        out.push("[sentinel.beacon]: changed".to_string());
    }
    if old.dns_tunnel != new.dns_tunnel {
        out.push("[sentinel.dns_tunnel]: changed".to_string());
    }
    out
}

/// The §11.2 warning for a disabled Sentinel, worded like `lockdown = "none"`.
pub fn sentinel_warnings(c: &sentinel_rules::config::SentinelConfig) -> Vec<String> {
    if c.enable {
        return Vec::new();
    }
    vec![
        "Sentinel is disabled: no exec, network, device or BPF monitoring, \
         and no quarantine. Takes effect after a reboot into this generation."
            .to_string(),
    ]
}
```

In `impl fmt::Display for Plan`, print the section after the unit changes and
before the warnings:

```rust
        if !self.sentinel_changes.is_empty() {
            writeln!(f, "Sentinel:")?;
            for line in &self.sentinel_changes {
                writeln!(f, "  {line}")?;
            }
        }
```

If `Plan` has no `Default` impl, derive one (`#[derive(Debug, Default, ...)]`)
so the display test can build an otherwise-empty plan.

- [ ] **Step 4: Fill the field where the plan is built**

Wherever the planner compares current and desired state, set
`sentinel_changes` to `sentinel_summary(old_rules, new_rules)` followed by
`sentinel_config_summary(old_config, new_config)`, and extend `warnings` with
`sentinel_warnings(&new_config)`. The old rules and config come from the booted
generation's `/etc/aios/sentinel/` (read through the probe, like the other
current-state reads); when they cannot be read — a first apply, or Sentinel
newly added — treat the old side as empty and the summary becomes all
additions.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd aios-cli && cargo test -p aios-plan`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add aios-cli/crates/aios-plan/src/plan.rs
git commit -m "feat(aios-plan): Sentinel summary and the disabled warning"
```

---

## Task 7: Extract `sentinel-client`

**Files:**
- Create: `sentinel/crates/sentinel-client/Cargo.toml`, `sentinel/crates/sentinel-client/src/lib.rs`
- Modify: `sentinel/Cargo.toml` (workspace members), `sentinel/crates/sentinel/src/client.rs`, `sentinel/crates/sentinel/Cargo.toml`
- Test: the tests move from `sentinel/crates/sentinel/src/client.rs` into the new crate

Spec §17.9 decision 2. The framing and the call loop move into their own crate
so `aios-exec` and the CLI speak one implementation of the wire format. This is
a refactor: **no behaviour changes**, and the moved tests must pass unaltered
except for their module path.

- [ ] **Step 1: Create the crate with the moved tests**

Create `sentinel/crates/sentinel-client/Cargo.toml`:

```toml
[package]
name = "sentinel-client"
description = "varlink client for io.aios.Sentinel"
version.workspace = true
edition.workspace = true
license.workspace = true
publish.workspace = true

[dependencies]
anyhow.workspace = true
serde_json.workspace = true
```

Create `sentinel/crates/sentinel-client/src/lib.rs` holding, verbatim from
`sentinel/crates/sentinel/src/client.rs`: `INTERFACE`, `SOCKET_PATH`,
`encode_call`, `Client` with `connect`, `call`, `call_more` and `read_frame`,
plus a `reply_error_name` helper split out of the CLI's `reply_error`:

```rust
//! A varlink client for `io.aios.Sentinel` (spec §10.2, amendment §17.9).
//!
//! The wire format lives here, not in a caller: `aios apply` and the
//! `sentinel` CLI both speak it, and a change to the framing that reached only
//! one of them would be a protocol split between a daemon and its own tools.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

use anyhow::{bail, Result};

pub const INTERFACE: &str = "io.aios.Sentinel";
pub const SOCKET_PATH: &str = "/run/aios-sentinel/io.aios.Sentinel";

/// The short error name of a reply, or `None` when it is not an error.
/// Callers map it to their own wording: the CLI advises `run0`, `aios apply`
/// turns it into a warning (§11.3).
pub fn reply_error_name(v: &serde_json::Value) -> Option<String> {
    let full = v.get("error")?.as_str()?;
    Some(full.rsplit('.').next().unwrap_or(full).to_string())
}
```

followed by the `encode_call` and `Client` definitions copied from the CLI
file, and the tests from that file that cover them — `a_call_is_nul_terminated_and_names_the_interface`
moves as is, and add one for the new helper:

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
    fn the_error_name_is_the_last_component() {
        let v = serde_json::json!({"error": "io.aios.Sentinel.InvalidRules",
                                   "parameters": {"errors": ["x"]}});
        assert_eq!(reply_error_name(&v).as_deref(), Some("InvalidRules"));
        assert_eq!(reply_error_name(&serde_json::json!({"parameters": {}})), None);
    }
}
```

- [ ] **Step 2: Add the crate to the workspace and run its tests**

In `sentinel/Cargo.toml`, add `"crates/sentinel-client"` to `members`, and add
to the workspace dependency table:

```toml
sentinel-client = { path = "crates/sentinel-client" }
```

Run: `cd sentinel && cargo test -p sentinel-client`
Expected: 2 passed.

- [ ] **Step 3: Point the CLI at the crate**

In `sentinel/crates/sentinel/Cargo.toml`, add `sentinel-client.workspace = true`.

In `sentinel/crates/sentinel/src/client.rs`, delete the moved items and re-export
what `main.rs` imports, keeping the CLI-only formatting in place:

```rust
//! CLI-side wrapper over `sentinel-client` (spec §10.2).

pub use sentinel_client::{encode_call, Client, INTERFACE, SOCKET_PATH};

/// A readable message for an error reply, or `None` if it is not an error.
/// The wording is the CLI's: a person is reading it.
pub fn reply_error(v: &serde_json::Value) -> Option<String> {
    let short = sentinel_client::reply_error_name(v)?;
    let params = v.get("parameters").cloned().unwrap_or_default();
    let detail = match short.as_str() {
        "PermissionDenied" => {
            " — this command changes something, so it needs root: re-run it with run0".to_string()
        }
        // ... the remaining arms unchanged from the S3 version ...
        _ => {
            let p = params.to_string();
            if p == "{}" { String::new() } else { format!(" {p}") }
        }
    };
    Some(format!("{short}{detail}"))
}
```

Keep `since_to_ts`, `format_ts` and `alert_line` in this file: they are output
formatting, not protocol, and `aios apply` has no use for them.

- [ ] **Step 4: Run the CLI's tests to prove the refactor changed nothing**

Run: `cd sentinel && cargo test -p sentinel`
Expected: the S3 tests still pass — `an_error_reply_becomes_a_readable_message`,
`relative_times_become_timestamps`, `the_alert_table_line_is_aligned_and_complete`
and the rest, unmodified. If one needed editing to pass, the refactor changed
behaviour and that is a bug, not a test to update.

- [ ] **Step 5: Verify both binaries still build and the gate is green**

Run: `cd sentinel && cargo build -p sentinel -p sentineld && cargo clippy --workspace --all-targets -- -D warnings`
Expected: builds, no warnings.

- [ ] **Step 6: Commit**

```bash
git add sentinel/Cargo.toml sentinel/Cargo.lock sentinel/crates/sentinel-client sentinel/crates/sentinel/Cargo.toml sentinel/crates/sentinel/src/client.rs
git commit -m "refactor(sentinel): extract sentinel-client from the CLI"
```

---

## Task 8: `LoadGeneration` from `aios apply`

**Files:**
- Create: `aios-cli/crates/aios-exec/src/apply/sentinel.rs`
- Modify: `aios-cli/crates/aios-exec/src/apply/mod.rs` (declare the module and call it), `aios-cli/crates/aios-exec/Cargo.toml`
- Test: in `aios-cli/crates/aios-exec/src/apply/sentinel.rs`

Spec §11.3. The call happens after the generation is committed, so every failure
here is a warning on `ApplyOutcome` — the same "after_commit" rule
`apply/finalize.rs` already follows for `bootctl` and the UKI. The three
outcomes stay distinct, which is why §17.9 chose a typed client over a
shell-out.

- [ ] **Step 1: Add the dependency**

In `aios-cli/crates/aios-exec/Cargo.toml`, under `[dependencies]`:

```toml
sentinel-client = { path = "../../../sentinel/crates/sentinel-client" }
```

- [ ] **Step 2: Write the failing tests**

Create `aios-cli/crates/aios-exec/src/apply/sentinel.rs`:

```rust
//! Telling the running daemon about a new generation (spec §11.3).

use std::path::Path;

/// What `LoadGeneration` did, for the apply report.
#[derive(Debug, Clone, PartialEq)]
pub enum Loaded {
    /// The daemon swapped the rules; the lines are its change summary.
    Swapped(Vec<String>),
    /// The daemon rejected them and kept the rules it had.
    Rejected(Vec<String>),
    /// No daemon answered: the rules take effect at the next boot.
    NotRunning(String),
}

impl Loaded {
    /// The warnings this outcome adds to the apply report. A swap is not a
    /// warning: it is what was asked for.
    pub fn warnings(&self) -> Vec<String> {
        match self {
            Loaded::Swapped(_) => Vec::new(),
            Loaded::Rejected(errors) => vec![format!(
                "sentineld rejected the new rules and kept the running set: {}",
                errors.join("; ")
            )],
            Loaded::NotRunning(why) => vec![format!(
                "sentineld is not reachable ({why}); the new rules take effect at the next boot"
            )],
        }
    }
}

/// Call `LoadGeneration` on `socket` for generation `gen` and rule directory
/// `dir`.
pub fn load_generation(socket: &Path, generation: &str, dir: &Path) -> Loaded {
    let mut c = match sentinel_client::Client::connect(&socket.to_string_lossy()) {
        Ok(c) => c,
        Err(e) => return Loaded::NotRunning(e.to_string()),
    };
    let params = serde_json::json!({
        "gen": generation,
        "dir": dir.to_string_lossy(),
    });
    match c.call_raw("LoadGeneration", params) {
        Ok(v) => {
            if let Some(name) = sentinel_client::reply_error_name(&v) {
                let errors = v
                    .get("parameters")
                    .and_then(|p| p.get("errors"))
                    .and_then(|e| e.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|e| e.as_str().map(str::to_string))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_else(|| vec![name]);
                return Loaded::Rejected(errors);
            }
            let changes = v
                .get("parameters")
                .and_then(|p| p.get("changes"))
                .and_then(|c| c.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|c| c.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            Loaded::Swapped(changes)
        }
        Err(e) => Loaded::NotRunning(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;

    /// A daemon that answers one call with `reply`, then closes.
    fn fake_daemon(path: std::path::PathBuf, reply: serde_json::Value) {
        std::thread::spawn(move || {
            let l = UnixListener::bind(&path).expect("bind");
            if let Ok((mut s, _)) = l.accept() {
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf);
                let mut out = serde_json::to_vec(&reply).unwrap();
                out.push(0);
                let _ = s.write_all(&out);
            }
        });
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    #[test]
    fn a_successful_swap_returns_the_change_summary_and_no_warning() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("sock");
        fake_daemon(
            sock.clone(),
            serde_json::json!({"parameters": {"ok": true,
                "changes": ["+ exec-shm", "reverse-shell: action freeze -> kill"]}}),
        );
        let out = load_generation(&sock, "gen-7", dir.path());
        assert_eq!(
            out,
            Loaded::Swapped(vec![
                "+ exec-shm".to_string(),
                "reverse-shell: action freeze -> kill".to_string()
            ])
        );
        assert!(out.warnings().is_empty(), "a swap is not a warning");
    }

    #[test]
    fn rejected_rules_warn_and_name_the_errors() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("sock");
        fake_daemon(
            sock.clone(),
            serde_json::json!({"error": "io.aios.Sentinel.InvalidRules",
                "parameters": {"errors": ["default.toml: rule x: unknown predicate `nope`"]}}),
        );
        let out = load_generation(&sock, "gen-7", dir.path());
        match &out {
            Loaded::Rejected(errs) => assert!(errs[0].contains("unknown predicate"), "{errs:?}"),
            other => panic!("expected Rejected, got {other:?}"),
        }
        let w = out.warnings();
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("kept the running set"), "{w:?}");
    }

    #[test]
    fn an_absent_daemon_warns_about_the_next_boot() {
        let dir = tempfile::tempdir().unwrap();
        let out = load_generation(&dir.path().join("nothing-here"), "gen-7", dir.path());
        match &out {
            Loaded::NotRunning(_) => {}
            other => panic!("expected NotRunning, got {other:?}"),
        }
        let w = out.warnings();
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("next boot"), "{w:?}");
    }

    #[test]
    fn a_reply_with_neither_changes_nor_error_is_still_a_swap() {
        // The daemon may report no changes; that is success, not a failure.
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("sock");
        fake_daemon(sock.clone(), serde_json::json!({"parameters": {"ok": true}}));
        assert_eq!(
            load_generation(&sock, "gen-7", dir.path()),
            Loaded::Swapped(Vec::new())
        );
    }
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cd aios-cli && cargo test -p aios-exec sentinel`
Expected: FAIL to compile — ``no method named `call_raw` `` on
`sentinel_client::Client`.

- [ ] **Step 4: Add `call_raw` to the shared client**

`Client::call` turns an error reply into `Err`, which collapses "rules
rejected" and "no daemon" into one case; §11.3 needs them apart. Add the raw
form beside it in `sentinel/crates/sentinel-client/src/lib.rs`:

```rust
    /// One call, returning the reply as it came — an error reply included.
    /// `call` is the convenience wrapper that turns those into `Err`; a caller
    /// that must distinguish an error reply from a dead socket uses this.
    pub fn call_raw(
        &mut self,
        method: &str,
        parameters: serde_json::Value,
    ) -> Result<serde_json::Value> {
        self.sock
            .write_all(&encode_call(method, parameters, false))?;
        self.read_frame()
    }
```

and a test for it in that crate:

```rust
    #[test]
    fn call_raw_hands_back_an_error_reply_instead_of_failing() {
        // Covered end to end by aios-exec's tests; this pins the contract that
        // an error reply is Ok(_), not Err(_).
        let v = serde_json::json!({"error": "io.aios.Sentinel.InvalidRules"});
        assert!(reply_error_name(&v).is_some());
    }
```

Run: `cd sentinel && cargo test -p sentinel-client`
Expected: 3 passed.

- [ ] **Step 5: Run the aios-exec tests to verify they pass**

Run: `cd aios-cli && cargo test -p aios-exec sentinel`
Expected: 4 passed.

- [ ] **Step 6: Call it from apply, after the commit**

In `aios-cli/crates/aios-exec/src/apply/mod.rs`, declare the module beside the
other apply submodules:

```rust
mod sentinel;
```

and call it where the generation is already committed — immediately after the
`Finalize` step's warnings are collected, so a rejected rule set cannot abort a
generation that is already installed:

```rust
    // §11.3: tell the running daemon about the generation we just built. Any
    // failure here is a warning, like everything else after the commit point.
    let loaded = sentinel::load_generation(
        std::path::Path::new(sentinel_client::SOCKET_PATH),
        &format!("gen-{gen}"),
        std::path::Path::new("/etc/aios/sentinel/rules.d"),
    );
    for line in loaded.warnings() {
        run.warnings.push(line);
    }
    if let sentinel::Loaded::Swapped(changes) = &loaded {
        for line in changes {
            eprintln!("aios: sentinel: {line}");
        }
    }
```

Skip the call when the generation's `sentinel.toml` has `enable = false`: there
is no daemon to tell, and §11.3 says the change takes effect at the next boot
anyway. Read it with `sentinel_rules::config::parse` from the candidate root.

- [ ] **Step 7: Verify the whole workspace still passes**

Run: `cd aios-cli && cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings`
Expected: all pass, no warnings.

- [ ] **Step 8: Commit**

```bash
git add aios-cli/crates/aios-exec/src/apply/sentinel.rs aios-cli/crates/aios-exec/src/apply/mod.rs aios-cli/crates/aios-exec/Cargo.toml aios-cli/Cargo.lock sentinel/crates/sentinel-client/src/lib.rs
git commit -m "feat(aios-exec): call LoadGeneration after a generation is built"
```

---

## Task 9: The systemd unit

**Files:**
- Create: `packaging/aios-sentinel/aios-sentinel.service`
- Modify: `Makefile` (the `unit-check` list in `check`)
- Test: `systemd-analyze verify`, through the existing `unit-check` step

Spec §11.4, plus the bpffs dependency the S3 handoff recorded: the daemon pins
under `/sys/fs/bpf` and exits if it is not mounted.

- [ ] **Step 1: Write the unit**

Create `packaging/aios-sentinel/aios-sentinel.service`:

```ini
# AIOS Sentinel (spec §11.4). Starts before the network and before any login,
# so a home-directory autostart is watched from its first instruction.
#
# RefuseManualStop: stopping the daemon is what the kernel-side lockdown exists
# to punish (§8.3). `systemctl kill` is the documented escape.

[Unit]
Description=AIOS: Sentinel runtime security
DefaultDependencies=no
After=local-fs.target sys-fs-bpf.mount
Requires=sys-fs-bpf.mount
Before=sysinit.target network-pre.target
Wants=network-pre.target
RefuseManualStop=yes

[Service]
Type=notify
ExecStart=/usr/bin/sentineld
Restart=always
RestartSec=1
OOMScoreAdjust=-1000
LogsDirectory=aios/sentinel
LogsDirectoryMode=0700

[Install]
WantedBy=sysinit.target
```

`Requires=sys-fs-bpf.mount`, not just `After=`: without bpffs the daemon cannot
pin and exits non-zero (§12), and a dependency failure is a clearer report than
a restart loop.

- [ ] **Step 2: Add it to the unit verification `make check` already runs**

In the `Makefile`'s `check` target, the `unit-check` step copies units into
`build/unit-check/` and runs `systemd-analyze verify` over them. Add the new
unit to both the `cp` list and the `systemd-analyze verify` arguments, beside
`base/aios-health.service`.

- [ ] **Step 3: Verify**

Run: `make check 2>&1 | grep -A3 unit-check`
Expected: no output naming `build/unit-check/aios-sentinel.service` — the step
prints only problems in our own units, and `make check` exits 0.

- [ ] **Step 4: Commit**

```bash
git add packaging/aios-sentinel/aios-sentinel.service Makefile
git commit -m "feat(packaging): the aios-sentinel systemd unit"
```

---

## Task 10: The `aios-sentinel` package

**Files:**
- Create: `packaging/aios-sentinel/PKGBUILD`
- Modify: `Makefile:160` (`PACKAGES`), the `tools` target, and the AIOS core package set
- Test: `make repo` builds it

Spec §11.4. Follow `packaging/aios-cli/PKGBUILD` exactly for the version
function, the `RUSTFLAGS` replacement and the `!lto !debug` options; the one
difference is the toolchain, because the eBPF object needs the pinned nightly
and `bpf-linker`.

- [ ] **Step 1: Write the PKGBUILD**

Create `packaging/aios-sentinel/PKGBUILD`:

```bash
# aios-sentinel: the Sentinel daemon and CLI (spec §6–§10, §11.4). Built from this
# repository's sentinel workspace by `make repo`.

pkgname=aios-sentinel
pkgver=0.1.0.r54.g99f3fda
pkgrel=1
pkgdesc="AIOS Sentinel: eBPF runtime security daemon and its CLI"
arch=(x86_64)
license=(GPL-3.0-or-later)
depends=(systemd)
# The kernel object is built by an aya-build build script, so the pinned nightly
# and bpf-linker must already be on the build host: `make tools` installs both.
makedepends=(cargo rustup clang llvm libbpf)
options=(!lto !debug)

_root="${AIOS_SRC_ROOT:-$(realpath "$startdir/../..")}"

pkgver() {
  printf '0.1.0.r%s.g%s' \
    "$(git -C "$_root" rev-list --count HEAD)" \
    "$(git -C "$_root" rev-parse --short HEAD)"
}

prepare() {
  [[ -d $_root/sentinel ]] || { error "run from packaging/<pkg> inside the AIOS repo"; return 1; }
  cd "$_root/sentinel"
  cargo fetch --locked
}

build() {
  cd "$_root/sentinel"
  # As in aios-cli: RUSTFLAGS is replaced, not appended to, so CachyOS's
  # target-cpu=native does not leak into a package meant to run anywhere.
  export RUSTFLAGS="-C target-cpu=x86-64 -C opt-level=3 \
--remap-path-prefix=$HOME=/home/builder \
--remap-path-prefix=$_root=/build/aios"
  export CFLAGS="${CFLAGS//-march=native/-march=x86-64}"
  export CXXFLAGS="${CXXFLAGS//-march=native/-march=x86-64}"
  export CARGO_TARGET_DIR="$srcdir/target"
  cargo build --release --frozen -p sentineld -p sentinel
}

package() {
  install -Dm755 "$srcdir/target/release/sentineld" "$pkgdir/usr/bin/sentineld"
  install -Dm755 "$srcdir/target/release/sentinel" "$pkgdir/usr/bin/sentinel"
  install -Dm644 "$startdir/aios-sentinel.service" \
    "$pkgdir/usr/lib/systemd/system/aios-sentinel.service"
}
```

The binaries are built with `-p sentineld -p sentinel` rather than
`cargo xfeature build`: `sentineld`'s build script already compiles and embeds
the kernel object (spec amendment 3), so a plain `cargo build --release` is the
whole build.

- [ ] **Step 2: Add the package to the Makefile and the core set**

In `Makefile:160`:

```makefile
PACKAGES := aios-base aios-cli aios-sentinel
```

Add `aios-sentinel` to the AIOS core package set the installer/manifest
installs, next to `aios-cli`, and make `make tools` install what the build
needs:

```makefile
	rustup toolchain install "$$(sed -n 's/^channel = "\(.*\)"/\1/p' sentinel/rust-toolchain.toml)" \
	    --component rust-src
	cargo install --locked bpf-linker
```

- [ ] **Step 3: Build the package**

Run: `make repo 2>&1 | tail -20`
Expected: `aios-sentinel-*.pkg.tar.zst` is built and added to the repo
alongside `aios-base` and `aios-cli`.

- [ ] **Step 4: Check what landed in it**

Run: `tar -tf build/repo/aios-sentinel-*.pkg.tar.zst | grep -E 'usr/bin|systemd'`
Expected: `usr/bin/sentineld`, `usr/bin/sentinel`,
`usr/lib/systemd/system/aios-sentinel.service`.

- [ ] **Step 5: Commit**

```bash
git add packaging/aios-sentinel/PKGBUILD Makefile
git commit -m "feat(packaging): the aios-sentinel package"
```

---

## Task 11: The health check

**Files:**
- Modify: `base/aios-health.sh`, `base/aios-health.service`
- Test: the existing bats suite for `aios-health.sh`

Spec §11.5: when `/etc/aios/sentinel/sentinel.toml` has `enable = true`, the
unit must be active **and** `/run/aios-sentinel/state` must read `ok`. The
script already takes `AIOS_*` environment overrides so the suite can run it
without the real system; the new check follows that convention.

- [ ] **Step 1: Write the failing tests**

In the bats file that covers `aios-health.sh`, add:

```bash
@test "sentinel: an enabled daemon that is active and ok passes" {
    printf 'enable = true\n' > "$BATS_TEST_TMPDIR/sentinel.toml"
    printf 'ok' > "$BATS_TEST_TMPDIR/state"
    printf '#!/bin/sh\nexit 0\n' > "$BATS_TEST_TMPDIR/systemctl"
    chmod +x "$BATS_TEST_TMPDIR/systemctl"
    run env AIOS_SENTINEL_CONF="$BATS_TEST_TMPDIR/sentinel.toml" \
            AIOS_SENTINEL_STATE="$BATS_TEST_TMPDIR/state" \
            AIOS_SYSTEMCTL="$BATS_TEST_TMPDIR/systemctl" \
            "$HEALTH"
    [ "$status" -eq 0 ]
}

@test "sentinel: degraded fails the generation" {
    printf 'enable = true\n' > "$BATS_TEST_TMPDIR/sentinel.toml"
    printf 'degraded' > "$BATS_TEST_TMPDIR/state"
    printf '#!/bin/sh\nexit 0\n' > "$BATS_TEST_TMPDIR/systemctl"
    chmod +x "$BATS_TEST_TMPDIR/systemctl"
    run env AIOS_SENTINEL_CONF="$BATS_TEST_TMPDIR/sentinel.toml" \
            AIOS_SENTINEL_STATE="$BATS_TEST_TMPDIR/state" \
            AIOS_SYSTEMCTL="$BATS_TEST_TMPDIR/systemctl" \
            "$HEALTH"
    [ "$status" -eq 1 ]
    [[ "$output" == *degraded* ]]
}

@test "sentinel: an inactive unit fails even when the state file says ok" {
    printf 'enable = true\n' > "$BATS_TEST_TMPDIR/sentinel.toml"
    printf 'ok' > "$BATS_TEST_TMPDIR/state"
    printf '#!/bin/sh\nexit 3\n' > "$BATS_TEST_TMPDIR/systemctl"
    chmod +x "$BATS_TEST_TMPDIR/systemctl"
    run env AIOS_SENTINEL_CONF="$BATS_TEST_TMPDIR/sentinel.toml" \
            AIOS_SENTINEL_STATE="$BATS_TEST_TMPDIR/state" \
            AIOS_SYSTEMCTL="$BATS_TEST_TMPDIR/systemctl" \
            "$HEALTH"
    [ "$status" -eq 1 ]
}

@test "sentinel: a missing state file fails an enabled Sentinel" {
    printf 'enable = true\n' > "$BATS_TEST_TMPDIR/sentinel.toml"
    printf '#!/bin/sh\nexit 0\n' > "$BATS_TEST_TMPDIR/systemctl"
    chmod +x "$BATS_TEST_TMPDIR/systemctl"
    run env AIOS_SENTINEL_CONF="$BATS_TEST_TMPDIR/sentinel.toml" \
            AIOS_SENTINEL_STATE="$BATS_TEST_TMPDIR/missing" \
            AIOS_SYSTEMCTL="$BATS_TEST_TMPDIR/systemctl" \
            "$HEALTH"
    [ "$status" -eq 1 ]
}

@test "sentinel: a disabled Sentinel is not checked at all" {
    printf 'enable = false\n' > "$BATS_TEST_TMPDIR/sentinel.toml"
    printf '#!/bin/sh\nexit 3\n' > "$BATS_TEST_TMPDIR/systemctl"
    chmod +x "$BATS_TEST_TMPDIR/systemctl"
    run env AIOS_SENTINEL_CONF="$BATS_TEST_TMPDIR/sentinel.toml" \
            AIOS_SENTINEL_STATE="$BATS_TEST_TMPDIR/missing" \
            AIOS_SYSTEMCTL="$BATS_TEST_TMPDIR/systemctl" \
            "$HEALTH"
    [ "$status" -eq 0 ]
}

@test "sentinel: no config file means no check" {
    # A generation built before Sentinel existed, or one that never rendered it.
    printf '#!/bin/sh\nexit 3\n' > "$BATS_TEST_TMPDIR/systemctl"
    chmod +x "$BATS_TEST_TMPDIR/systemctl"
    run env AIOS_SENTINEL_CONF="$BATS_TEST_TMPDIR/absent.toml" \
            AIOS_SENTINEL_STATE="$BATS_TEST_TMPDIR/missing" \
            AIOS_SYSTEMCTL="$BATS_TEST_TMPDIR/systemctl" \
            "$HEALTH"
    [ "$status" -eq 0 ]
}
```

Set the other `AIOS_*` overrides these tests need (`AIOS_CMDLINE_FILE`,
`AIOS_GEN_FILE`, `AIOS_FINDMNT`) the way the existing tests in that file do, so
only the Sentinel check decides the outcome.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `make check 2>&1 | grep -E "not ok .*sentinel"`
Expected: the new cases fail — the script does not look at Sentinel yet, so the
`degraded` and inactive-unit cases exit 0.

- [ ] **Step 3: Write the implementation**

In `base/aios-health.sh`, add the overrides to the header comment:

```sh
#   AIOS_SENTINEL_CONF  sentinel config     (default /etc/aios/sentinel/sentinel.toml)
#   AIOS_SENTINEL_STATE sentinel state file (default /run/aios-sentinel/state)
#   AIOS_SYSTEMCTL      systemctl           (default systemctl)
```

and add the check, after the existing ones so a Sentinel problem never masks a
subvolume or generation mismatch:

```sh
SENTINEL_CONF="${AIOS_SENTINEL_CONF:-/etc/aios/sentinel/sentinel.toml}"
SENTINEL_STATE="${AIOS_SENTINEL_STATE:-/run/aios-sentinel/state}"
SYSTEMCTL="${AIOS_SYSTEMCTL:-systemctl}"

# Sentinel (spec §11.5). Only when this generation enabled it: a generation
# that never rendered the file, or set enable = false, has nothing to check.
if [ -f "$SENTINEL_CONF" ] && grep -qE '^[[:space:]]*enable[[:space:]]*=[[:space:]]*true' "$SENTINEL_CONF"; then
    "$SYSTEMCTL" is-active --quiet aios-sentinel.service \
        || fail "aios-sentinel.service is not active"
    [ -r "$SENTINEL_STATE" ] || fail "$SENTINEL_STATE is missing"
    state=$(cat "$SENTINEL_STATE")
    [ "$state" = ok ] || fail "sentineld reports $state"
fi
```

`degraded` fails deliberately: it means the LSM programs did not attach, so the
generation enforces nothing (§12), and §11.5 counts that as a failed health
check so the three-boot fallback returns to the previous generation.

- [ ] **Step 4: Order the units**

In `base/aios-health.service`, add `aios-sentinel.service` to `After=`:

```ini
After=local-fs.target aios-sentinel.service
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `make check`
Expected: every bats case passes, the six new ones included, and the unit
verification still reports nothing.

- [ ] **Step 6: Commit**

```bash
git add base/aios-health.sh base/aios-health.service
git commit -m "feat(base): health check for an enabled Sentinel"
```

---

## Task 12: End-to-end coverage of the rendered generation

**Files:**
- Modify: `tests/e2e/test_e2e.py`
- Test: that file

The e2e suite builds a generation from a manifest and inspects it. Three facts
matter: the files are there with the right content, `MANAGED_FILES` lists them,
and a broken rule fails `aios plan` with the validator's own message.

- [ ] **Step 1: Write the failing tests**

Add to `tests/e2e/test_e2e.py`, following the fixtures that file already uses
for a manifest repo and an applied generation:

```python
def test_sentinel_files_are_rendered_into_the_generation(applied_generation):
    """§11.3: both the config and the rules are managed files."""
    etc = applied_generation.etc
    conf = etc / "aios/sentinel/sentinel.toml"
    assert conf.is_file(), "sentinel.toml is rendered"
    body = conf.read_text()
    assert "enable = true" in body
    assert body.startswith("# Written by aios. Do not edit.")

    rules = etc / "aios/sentinel/rules.d"
    assert rules.is_dir(), "the rules directory is rendered"
    assert any(rules.glob("*.toml")), f"rule files were copied: {list(rules.iterdir())}"

    managed = (etc / "aios/managed-files").read_text()
    assert "/etc/aios/sentinel/sentinel.toml" in managed
    for f in rules.glob("*.toml"):
        assert f"/etc/aios/sentinel/rules.d/{f.name}" in managed


def test_a_broken_rule_fails_the_plan(manifest_repo, aios):
    """§11.2: rule validation errors fail the plan like any manifest error."""
    rules = manifest_repo / "sentinel/rules"
    rules.mkdir(parents=True, exist_ok=True)
    (rules / "bad.toml").write_text(
        '[[rule]]\nid = "x"\non = "exec"\nseverity = "low"\n'
        'action = "alert"\nmatch = { nope = true }\n'
    )
    out = aios("plan", expect_rc=1)
    assert "nope" in out, out
    assert "bad.toml" in out, out


def test_the_plan_summarises_a_changed_rule(manifest_repo, aios):
    """§11.2: the summary names the changed field, as the daemon words it."""
    rules = manifest_repo / "sentinel/rules"
    rules.mkdir(parents=True, exist_ok=True)
    (rules / "pack.toml").write_text(
        '[[rule]]\nid = "r"\non = "exec"\nseverity = "high"\n'
        'action = "freeze"\nmatch = { exe_memfd = true }\n'
    )
    aios("apply")
    (rules / "pack.toml").write_text(
        '[[rule]]\nid = "r"\non = "exec"\nseverity = "high"\n'
        'action = "kill"\nmatch = { exe_memfd = true }\n'
    )
    out = aios("plan")
    assert "Sentinel:" in out, out
    assert "r: action freeze -> kill" in out, out
```

Adapt the fixture names to the ones in that file (`aios(...)` standing for
however it invokes the binary and captures output).

- [ ] **Step 2: Run them to verify they fail**

Run: `build/venv/bin/pytest -q tests/e2e/test_e2e.py -k sentinel`
Expected: failures — the generation has no `aios/sentinel/` yet if Tasks 4–6
are not merged, and the plan prints no Sentinel section.

- [ ] **Step 3: Make them pass**

No new production code: Tasks 4, 5 and 6 are what these assert. If a test fails
after those are in, fix the implementation — these are the spec's own words.

- [ ] **Step 4: Run the suite**

Run: `build/venv/bin/pytest -q tests/e2e/test_e2e.py`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add tests/e2e/test_e2e.py
git commit -m "test(e2e): the rendered Sentinel generation and the plan summary"
```

---

## Task 13: A VM scenario for apply

**Files:**
- Create: `sentinel/tests/vm/scenarios/apply_generation.sh`
- Modify: `sentinel/tests/vm/README.md` (the scenario table)
- Test: `cargo run -p xtask -- vmtest apply_generation`

The only place the whole §11.3 round trip runs: a live daemon, a rule change,
`LoadGeneration` over the real socket, the swap, the critical alert, and a
rejected set leaving the running rules alone. Follow
`sentinel/tests/vm/scenarios/daemon.sh` for the shape.

- [ ] **Step 1: Write the scenario**

Create `sentinel/tests/vm/scenarios/apply_generation.sh`:

```sh
#!/bin/sh
# Runs inside the VM as root.
# LoadGeneration swaps a valid rule set, alerts about it, and refuses an
# invalid one while the running rules stay loaded (spec 11.3).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
SENTINEL=$(cd "$HERE/../../.." && pwd)
# shellcheck disable=SC1091
. "$SENTINEL/tests/vm/lib.sh"
cd "$SENTINEL"

# virtme boots without bpffs; systemd mounts it in production (spec 8.1).
grep -q " /sys/fs/bpf " /proc/mounts || mount -t bpf bpffs /sys/fs/bpf

mkdir -p /tmp/ap/rules /tmp/ap/alerts
cat > /tmp/ap/rules/pack.toml <<'RULES'
[[rule]]
id       = "r"
desc     = "before the swap"
on       = "exec"
severity = "high"
action   = "freeze"
match    = { exe = ["/tmp/never-run"] }
RULES

./target/debug/sentineld \
    --config /nonexistent/sentinel.toml \
    --rules /tmp/ap/rules \
    --alerts /tmp/ap/alerts \
    --socket /tmp/ap/sock \
    --state /tmp/ap/state \
    >/tmp/ap/out 2>/tmp/ap/err &
DAEMON=$!
sleep 3
grep -qF "sentineld: ready" /tmp/ap/err || { echo "ASSERT FAIL: not ready"; cat /tmp/ap/err; exit 1; }

# A valid change: the action moves from freeze to kill.
cat > /tmp/ap/rules/pack.toml <<'RULES'
[[rule]]
id       = "r"
desc     = "after the swap"
on       = "exec"
severity = "high"
action   = "kill"
match    = { exe = ["/tmp/never-run"] }
RULES

printf '{"method":"io.aios.Sentinel.LoadGeneration","parameters":{"gen":"gen-7","dir":"/tmp/ap/rules"}}\0' \
    | socat -t5 - UNIX-CONNECT:/tmp/ap/sock >/tmp/ap/reply1 2>/dev/null \
    || { echo "ASSERT FAIL: LoadGeneration call failed"; exit 1; }
tr -d '\0' < /tmp/ap/reply1
assert_contains /tmp/ap/reply1 '"ok":true'
assert_contains /tmp/ap/reply1 'action freeze -> kill'

# The swap is a critical alert naming the generation (spec 11.3).
./target/debug/sentinel --socket /tmp/ap/sock alerts --json >/tmp/ap/alerts.json 2>&1
assert_contains /tmp/ap/alerts.json "config-changed"
assert_contains /tmp/ap/alerts.json "gen-7"
assert_contains /tmp/ap/alerts.json "critical"

# An invalid set is refused and the running rules stay.
cat > /tmp/ap/rules/pack.toml <<'RULES'
[[rule]]
id       = "r"
on       = "exec"
severity = "high"
action   = "kill"
match    = { nope = true }
RULES

printf '{"method":"io.aios.Sentinel.LoadGeneration","parameters":{"gen":"gen-8","dir":"/tmp/ap/rules"}}\0' \
    | socat -t5 - UNIX-CONNECT:/tmp/ap/sock >/tmp/ap/reply2 2>/dev/null || true
tr -d '\0' < /tmp/ap/reply2
assert_contains /tmp/ap/reply2 "InvalidRules"
assert_contains /tmp/ap/reply2 "nope"

./target/debug/sentinel --socket /tmp/ap/sock status >/tmp/ap/status 2>&1
cat /tmp/ap/status
grep -qF "generation     gen-7" /tmp/ap/status \
    || { echo "ASSERT FAIL: the rejected generation was recorded"; cat /tmp/ap/status; exit 1; }

kill -TERM "$DAEMON" 2>/dev/null || true
echo "apply_generation: PASS"
```

If `socat` is not in the VM, call the method with
`./target/debug/sentinel --socket /tmp/ap/sock load-generation gen-7 /tmp/ap/rules`
and add that subcommand to the CLI in this task — a root-only wrapper over
`sentinel_client::Client::call_raw`, which also gives operators a way to reload
by hand. Check first: `command -v socat`.

- [ ] **Step 2: Make it executable and run it**

Run:

```bash
chmod +x sentinel/tests/vm/scenarios/apply_generation.sh
cd sentinel && cargo run -q -p xtask -- vmtest apply_generation
```

Expected: `apply_generation: PASS`.

The log for a VM run must live outside `/tmp` — the guest mounts its own, and
content written to a shared-fs path disappears mid-run. Redirect to `$HOME` if
you capture it.

- [ ] **Step 3: Add the row to the scenario table**

In `sentinel/tests/vm/README.md`, in alphabetical order:

```markdown
| `apply_generation` | `LoadGeneration` swaps a valid rule set and alerts about it; an invalid set is refused and the running rules stay loaded. |
```

- [ ] **Step 4: Run the whole suite**

Run: `cd sentinel && cargo run -q -p xtask -- vmtest all`
Expected: `27/27 scenarios passed`.

- [ ] **Step 5: Commit**

```bash
git add sentinel/tests/vm/scenarios/apply_generation.sh sentinel/tests/vm/README.md
git commit -m "test(sentinel): VM scenario for LoadGeneration from a generation"
```

---

## Task 14: `make check`, the spec amendments and the S5 handoff

**Files:**
- Modify: `Makefile` (the `check` target), `docs/superpowers/specs/2026-11-12-sentinel-core-design.md` (§17.10)
- Create: `docs/superpowers/plans/` nothing new; the handoff goes in the spec

- [ ] **Step 1: Make the gate cover the new crates**

`make check` runs `cargo test --workspace` in both workspaces, so the new unit
tests are already in. Confirm the `aios-cli` side still builds the release
binary and that the sentinel side builds the two binaries the package installs:

Run: `make check`
Expected: exits 0.

- [ ] **Step 2: Record S4's outcomes as §17.10**

Append to §17 of the spec, after §17.9, in the shape §17.8 used: what S4
settled, what S5 inherits, and what is still missing. Cover at least:

- The `[sentinel]` section is `Option<Sentinel>` on `Manifest`, wrapping
  `sentinel_rules::config::SentinelConfig`, so the section has one definition.
- Rule validation happens in `aios-manifest`'s `Validator`, so errors are
  positioned `ManifestError`s like any other manifest problem.
- `sentinel.toml` is rendered from the same type the daemon parses, and the
  renderer's test asserts the round trip.
- `MANAGED_FILES` lists the Sentinel files because the desired map's keys build
  it; no separate bookkeeping was added.
- `LoadGeneration` runs after the commit point, so all three §11.3 outcomes are
  warnings on `ApplyOutcome` rather than apply failures.
- `sentinel-client` is the only implementation of the wire format.
- Anything that turned out differently from this plan, with the evidence —
  the S3 amendments are the model: record what the VM or the gate proved, not
  what was expected.

- [ ] **Step 3: Write what S5 inherits**

The S5 gauntlet needs to know: the unit and package names, that
`/run/aios-sentinel/state` is what the health check reads, that a `degraded`
generation fails health and rolls back, that the DNS monitor has no VM coverage
and is exercised for the first time in S5, and that §13's CPU and RSS budgets
are still unmeasured. Put it in §17.10 rather than a separate file, as §11.5's
check and the unit are now the whole interface.

- [ ] **Step 4: Commit and push**

```bash
git add Makefile docs/superpowers/specs/2026-11-12-sentinel-core-design.md
git commit -m "docs(sentinel): S4 outcomes, the S5 handoff and make check wiring"
git push origin feat/sentinel
```

- [ ] **Step 5: Confirm CI is green before declaring S4 done**

```bash
gh run watch "$(gh run list --branch feat/sentinel --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
```

Expected: `check` and `audit` both succeed. S4 is not done until a clean runner
agrees — the dev box hides CI-only gaps, which is how S2 and S3 both ended.

---

## Self-review against the spec

| Spec section | Covered by |
|---|---|
| §11.1 manifest section: optional, defaults, validated | Tasks 1, 3 |
| §11.2 plan fails on rule errors; Sentinel summary; `enable = false` warning | Tasks 2, 3, 6 |
| §11.3 renderer writes both files, managed files, `LoadGeneration` with three outcomes, reboot-only fields | Tasks 4, 5, 8 |
| §11.4 PKGBUILD, binaries, unit directives, build-host tools, log directory | Tasks 9, 10 |
| §11.5 health check and its ordering | Task 11 |
| §14 testing bar: unit, e2e, VM | Tasks 12, 13 |
| §11.4 `make check` and CI green before done | Task 14 |
| §17.9 decisions 1–3 | Tasks 1–2 (linked validator), 7–8 (shared client), the single-stage scope of this plan |

All fourteen tasks are written. The APIs quoted in the contract reference and
in each task were read off the tree at `03fd017`, not remembered; where a task
tells you to adapt to a fixture or helper that already exists in the file you
are editing, it says so explicitly rather than inventing a name.
