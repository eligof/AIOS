use std::collections::BTreeSet;
use std::fmt;

/// Content of `/etc/aios/managed-files`: sorted, unique, one path per line.
pub fn managed_list(paths: &[String]) -> String {
    let unique: BTreeSet<&str> = paths.iter().map(String::as_str).collect();
    unique.into_iter().map(|p| format!("{p}\n")).collect()
}

/// A line of `/etc/aios/managed-files` that is not an absolute path under `/etc/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedListError {
    /// 1-based line number.
    pub line: usize,
    pub entry: String,
}

impl fmt::Display for ManagedListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "line {}: {:?} is not an absolute path under /etc/",
            self.line, self.entry
        )
    }
}

impl std::error::Error for ManagedListError {}

/// The paths in a `/etc/aios/managed-files`, sorted and unique. Blank lines are skipped.
///
/// Every other line must start with `/etc/` and contain no control character and no `..`
/// component, so a tampered list cannot make aios remove anything outside `/etc`.
pub fn parse_managed_list(text: &str) -> Result<Vec<String>, ManagedListError> {
    let mut unique = BTreeSet::new();
    for (i, line) in text.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        if !valid_entry(line) {
            return Err(ManagedListError {
                line: i + 1,
                entry: line.to_string(),
            });
        }
        unique.insert(line);
    }
    Ok(unique.into_iter().map(str::to_string).collect())
}

fn valid_entry(line: &str) -> bool {
    line.starts_with("/etc/")
        && line.len() > "/etc/".len()
        && !line.chars().any(char::is_control)
        && !line.split('/').any(|c| c == "..")
}
