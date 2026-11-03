use crate::{locate_key, locate_section, locate_value, Manifest, ManifestError, KNOWN_KERNELS};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

/// Files aios renders into every generation's `/etc` (spec §4.3 step 5). Persisting one would
/// shadow the rendered copy.
const GENERATED_ETC: &[&str] = &[
    "/etc/passwd",
    "/etc/group",
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/fstab",
    "/etc/hostname",
    "/etc/locale.conf",
    "/etc/locale.gen",
    "/etc/vconsole.conf",
    "/etc/localtime",
    "/etc/kernel/cmdline",
    "/etc/tmpfiles.d/aios-persist.conf",
    "/etc/tmpfiles.d/aios-home.conf",
];

/// Mount points and runtime trees a persist bind may not equal or sit under.
/// `/bin`, `/sbin`, `/lib`, `/lib64` and the pacman database are symlinks into (or live on) the
/// read-only `/usr`, so binding over them would reach it.
const SYSTEM_TREES: &[&str] = &[
    "/efi",
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/tmp",
    "/var/log",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/var/lib/pacman",
];

/// Kernel parameters aios puts on the command line itself (`aios-render`'s `cmdline` and the
/// hardening file). `kernel.extra_cmdline` may not set them again.
const RESERVED_CMDLINE_KEYS: &[&str] = &[
    "root",
    "rootflags",
    "rw",
    "ro",
    "mount.usr",
    "mount.usrflags",
    "rd.luks.name",
    "aios.gen",
    "lockdown",
    "lsm",
    "init",
    "rdinit",
    "systemd.debug_shell",
    "rd.systemd.debug_shell",
    "apparmor",
    "security",
];

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
        let locale = &m.system.locale;
        if !ascii_word(locale, "_.@-") {
            self.err(
                locate_key(self.raw, "system", "locale"),
                format!("invalid locale {locale:?}"),
            );
        }
        let keymap = &m.system.keymap;
        if !ascii_word(keymap, "_.-") {
            self.err(
                locate_key(self.raw, "system", "keymap"),
                format!("invalid keymap {keymap:?}"),
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
        for t in &m.kernel.extra_cmdline {
            let pos = locate_value(self.raw, "kernel", &format!("\"{t}\""));
            if t.is_empty() || t.chars().any(|c| is_space_or_control(c) || c == '"') {
                self.err(
                    pos,
                    format!("extra_cmdline token {t:?} must be a single word"),
                );
            } else if is_reserved_cmdline_key(cmdline_key(t)) {
                self.err(
                    pos,
                    format!("extra_cmdline token {t:?} overrides a parameter AIOS sets"),
                );
            }
        }
    }

    fn files(&mut self, m: &Manifest, env: &ValidationEnv) {
        for (path, entry) in &m.files {
            let pos = locate_key(self.raw, "files", &format!("\"{path}\""));
            if has_forbidden_path_char(path) {
                self.err(
                    pos,
                    format!("file {path:?}: contains a forbidden character"),
                );
            }
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
            if has_forbidden_path_char(p) {
                self.err(
                    pos,
                    format!("persist path {p:?} contains a forbidden character"),
                );
            }
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
            if let Some(other) = managed_conflict(p, m) {
                self.err(
                    pos,
                    format!("persist path {p:?} conflicts with {other:?}, which aios manages"),
                );
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
            if !valid_shell(&user.shell) {
                self.err(
                    pos,
                    format!("user {name:?}: invalid shell {:?}", user.shell),
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
            let mut targets: BTreeSet<&str> = BTreeSet::new();
            let mut keys: Vec<(&str, &str)> = Vec::new();
            for (target, src) in &user.home {
                let hpos = locate_key(self.raw, &home_section, &format!("\"{target}\""));
                if has_forbidden_path_char(target) {
                    self.err(
                        hpos,
                        format!(
                            "user {name:?}: home entry {target:?} contains a forbidden character"
                        ),
                    );
                }
                if !valid_home_key(target) {
                    self.err(
                        hpos,
                        format!(
                            "user {name:?}: home entry {target:?} must be relative inside the home directory"
                        ),
                    );
                    continue;
                }
                let trimmed = target.strip_suffix('/').unwrap_or(target);
                keys.push((trimmed, target));
                if !targets.insert(trimmed) {
                    self.err(
                        hpos,
                        format!("user {name:?}: duplicate home entry {target:?}"),
                    );
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
            for (inner, inner_key) in &keys {
                for (outer, outer_key) in &keys {
                    if inner != outer && is_under(inner, outer) {
                        let hpos = locate_key(self.raw, &home_section, &format!("\"{inner_key}\""));
                        self.err(
                            hpos,
                            format!(
                                "user {name:?}: home entry {inner_key:?} is inside home entry {outer_key:?}"
                            ),
                        );
                    }
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

/// The aios-managed path `p` (a persist path) equals, contains or lies under, if any.
/// `/etc` itself only conflicts when equal, so `/etc/<subdir>` can still be persisted.
fn managed_conflict(p: &str, m: &Manifest) -> Option<String> {
    if Path::new(p) == Path::new("/etc") {
        return Some("/etc".to_string());
    }
    let managed = GENERATED_ETC
        .iter()
        .copied()
        .chain(["/etc/aios", "/etc/systemd/system"])
        .chain(m.files.keys().map(String::as_str));
    for other in managed {
        if is_under(p, other) || is_under(other, p) {
            return Some(other.to_string());
        }
    }
    SYSTEM_TREES
        .iter()
        .find(|tree| is_under(p, tree))
        .map(|tree| tree.to_string())
}

/// Characters that would split or reinterpret a path in fstab, tmpfiles.d or a unit file:
/// whitespace, control characters, `%` (specifiers), `\` (escapes) and quotes.
fn has_forbidden_path_char(p: &str) -> bool {
    p.chars()
        .any(|c| is_space_or_control(c) || matches!(c, '%' | '\\' | '"' | '\''))
}

fn is_space_or_control(c: char) -> bool {
    c.is_whitespace() || c.is_control()
}

/// Non-empty, and every char is ASCII alphanumeric or one of `extra`.
fn ascii_word(s: &str, extra: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || extra.contains(c))
}

/// An absolute path usable as the last `/etc/passwd` field.
fn valid_shell(shell: &str) -> bool {
    shell.starts_with('/') && !shell.chars().any(|c| c == ':' || is_space_or_control(c))
}

/// Relative, with only real components: no empty, `.` or `..` parts. One trailing `/`
/// (the directory marker) is allowed.
fn valid_home_key(key: &str) -> bool {
    let rel = key.strip_suffix('/').unwrap_or(key);
    !key.starts_with('/') && rel.split('/').all(|c| !matches!(c, "" | "." | ".."))
}

/// True if `key` is in [`RESERVED_CMDLINE_KEYS`]; the kernel treats `-` and `_` in names alike.
fn is_reserved_cmdline_key(key: &str) -> bool {
    let key = key.replace('-', "_");
    RESERVED_CMDLINE_KEYS
        .iter()
        .any(|reserved| reserved.replace('-', "_") == key)
}

/// The parameter name of a cmdline token: the text before the first `=`, or the whole token.
fn cmdline_key(token: &str) -> &str {
    token.split_once('=').map_or(token, |(key, _)| key)
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
