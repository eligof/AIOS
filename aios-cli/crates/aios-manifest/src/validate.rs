use crate::{locate_key, locate_section, locate_value, Manifest, ManifestError, KNOWN_KERNELS};
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
    fn err(&mut self, (line, col): (usize, usize), message: String) {
        self.errors.push(ManifestError { line, col, message });
    }

    fn system(&mut self, m: &Manifest, env: &ValidationEnv) {
        let host = &m.system.hostname;
        if !valid_hostname(host) {
            self.err(
                locate_key(self.raw, "system", "hostname"),
                format!("invalid hostname {host:?}"),
            );
        }
        let tz = &m.system.timezone;
        if !is_safe_relative(tz) || !env.zoneinfo_dir.join(tz).is_file() {
            self.err(
                locate_key(self.raw, "system", "timezone"),
                format!("unknown timezone {tz:?}"),
            );
        }
    }

    fn kernel(&mut self, m: &Manifest) {
        let known = KNOWN_KERNELS.join(", ");
        let default = &m.kernel.default;
        if !KNOWN_KERNELS.contains(&default.as_str()) {
            self.err(
                locate_key(self.raw, "kernel", "default"),
                format!("unknown kernel {default:?} (expected one of: {known})"),
            );
        }
        if let Some(fallback) = &m.kernel.fallback {
            if !KNOWN_KERNELS.contains(&fallback.as_str()) {
                self.err(
                    locate_key(self.raw, "kernel", "fallback"),
                    format!("unknown kernel {fallback:?} (expected one of: {known})"),
                );
            }
            if fallback == default {
                self.err(
                    locate_key(self.raw, "kernel", "fallback"),
                    "fallback kernel must differ from default".to_string(),
                );
            }
        }
    }

    fn files(&mut self, m: &Manifest, env: &ValidationEnv) {
        for (path, entry) in &m.files {
            let pos = locate_key(self.raw, "files", &format!("\"{path}\""));
            if !path.starts_with("/etc/") || path.ends_with('/') || has_parent(path) {
                self.err(
                    pos,
                    format!("file {path:?}: only paths under /etc are allowed"),
                );
            }
            match (&entry.source, &entry.symlink) {
                (Some(_), Some(_)) | (None, None) => self.err(
                    pos,
                    format!("file {path:?}: set exactly one of source or symlink"),
                ),
                (Some(src), None) => {
                    if !is_safe_relative(src) || !env.repo_root.join(src).is_file() {
                        self.err(
                            pos,
                            format!("file {path:?}: source {src:?} not found in manifest repo"),
                        );
                    } else if escapes_repo(&env.repo_root, src) {
                        self.err(
                            pos,
                            format!(
                                "file {path:?}: source {src:?} resolves outside the manifest repo"
                            ),
                        );
                    }
                }
                (None, Some(_)) => {}
            }
            if let Some(mode) = &entry.mode {
                if !valid_mode(mode) {
                    self.err(pos, format!("file {path:?}: invalid mode {mode:?}"));
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
            let pos = locate_value(self.raw, "persist", &format!("\"{p}\""));
            if !p.starts_with('/') || has_parent(p) {
                self.err(
                    pos,
                    format!("persist path {p:?} must be absolute without '..'"),
                );
                continue;
            }
            if Path::new(p.as_str()).components().count() == 1 {
                self.err(
                    pos,
                    format!("persist path {p:?} may not be the root directory"),
                );
                continue;
            }
            for forbidden in ["/usr", "/persist", "/home"] {
                if is_under(p, forbidden) {
                    self.err(
                        pos,
                        format!("persist path {p:?} may not be under {forbidden}"),
                    );
                }
            }
        }
        for (i, a) in all.iter().enumerate() {
            for b in all.iter().skip(i + 1) {
                if is_under(a, b) || is_under(b, a) {
                    self.err(
                        locate_value(self.raw, "persist", &format!("\"{b}\"")),
                        format!("persist paths {a:?} and {b:?} overlap"),
                    );
                }
            }
        }
    }

    fn users(&mut self, m: &Manifest, env: &ValidationEnv) {
        let mut seen: BTreeMap<u32, &str> = BTreeMap::new();
        for (name, user) in &m.users {
            let home_section = format!("users.{name}.home");
            let pos = locate_section(self.raw, &[&format!("users.{name}"), &home_section]);
            if !valid_username(name) {
                self.err(pos, format!("invalid user name {name:?}"));
            }
            if !(1000..=59999).contains(&user.uid) {
                self.err(
                    pos,
                    format!("user {name:?}: uid {} outside 1000-59999", user.uid),
                );
            }
            if let Some(other) = seen.insert(user.uid, name) {
                self.err(
                    pos,
                    format!("user {name:?}: uid {} already used by {other:?}", user.uid),
                );
            }
            if !env.secrets_dir.join("passwd").join(name).is_file() {
                self.err(
                    pos,
                    format!(
                        "user {name:?}: missing password hash secrets/passwd/{name} (run `aios passwd {name}`)"
                    ),
                );
            }
            for (target, src) in &user.home {
                let hpos = locate_key(self.raw, &home_section, &format!("\"{target}\""));
                if target.is_empty() || target.starts_with('/') || has_parent(target) {
                    self.err(
                        hpos,
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
                        hpos,
                        format!("user {name:?}: home entry {target:?} needs a {kind} at {src:?}"),
                    );
                } else if escapes_repo(&env.repo_root, src) {
                    self.err(
                        hpos,
                        format!(
                            "user {name:?}: home entry {target:?} resolves outside the manifest repo"
                        ),
                    );
                }
            }
        }
    }
}

/// True if `repo_root/src` resolves (through symlinks) to somewhere outside `repo_root`.
/// Unresolvable paths count as escaping.
fn escapes_repo(repo_root: &Path, src: &str) -> bool {
    match (
        std::fs::canonicalize(repo_root),
        std::fs::canonicalize(repo_root.join(src)),
    ) {
        (Ok(root), Ok(resolved)) => !resolved.starts_with(root),
        _ => true,
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
        && h.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

fn valid_username(n: &str) -> bool {
    let mut chars = n.chars();
    let first_ok = matches!(chars.next(), Some(c) if c.is_ascii_lowercase() || c == '_');
    first_ok
        && n.len() <= 32
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}
