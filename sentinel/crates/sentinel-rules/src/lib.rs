//! Sentinel rules: parse TOML, validate, classify kernel vs user space,
//! compile to kernel tables and user-space matchers, diff rule sets.
//!
//! Pure: no I/O except `load_dir`, no clock. Builds on stable so `aios-cli`
//! can path-depend on it (S4).

pub mod classify;
pub mod compile;
pub mod config;
pub mod diff;
pub mod matcher;
pub mod model;
pub mod window;

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
                errors.push(RuleError {
                    file: name,
                    rule: None,
                    message: format!("cannot read: {e}"),
                });
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
            Err(msg) => errors.push(RuleError {
                file: name,
                rule: None,
                message: msg,
            }),
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
pub use validate::parse_duration_ms;
pub use validate::{parse_action, parse_mode, parse_on};
