//! Parse and validate the AIOS system manifest (`manifest.toml`).

mod locate;
mod model;
mod validate;

pub use locate::{locate, locate_key, locate_section, locate_value, offset_to_line_col};
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
        write!(
            f,
            "manifest.toml:{}:{}: {}",
            self.line, self.col, self.message
        )
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
