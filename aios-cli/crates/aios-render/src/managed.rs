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
