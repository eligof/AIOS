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
use std::path::{Path, PathBuf};

/// Lists every `/etc` path aios wrote into a generation, itself included.
pub const MANAGED_FILES: &str = "/etc/aios/managed-files";
/// Written by the executor for each generation; never part of the desired state.
pub const GENERATION_TOML: &str = "/etc/aios/generation.toml";

/// Everything the planner needs besides the probe.
pub struct Inputs<'a> {
    pub manifest: &'a Manifest,
    /// Root of the manifest repo (holds `files/` and `home/`).
    pub repo_root: &'a Path,
    /// Machine facts for the renderers. `ctx.gen` is the generation the files are rendered
    /// for, and `/etc/fstab` and `/etc/kernel/cmdline` embed it: pass the booted generation
    /// for `aios plan` and N+1 for `aios apply`. Planning with any other value shows both
    /// files as Modify even when nothing changed.
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
    Io {
        path: String,
        message: String,
    },
    BadMode {
        path: String,
        mode: String,
    },
    /// A home source directory contains a symlink (at `path`).
    SymlinkInSource {
        path: String,
    },
    /// A `[files]` or home source resolves to somewhere outside the manifest repo.
    OutsideRepo {
        path: String,
    },
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
            PlanError::SymlinkInSource { path } => {
                write!(
                    f,
                    "{path}: symlinks are not allowed in a home source directory"
                )
            }
            PlanError::OutsideRepo { path } => {
                write!(f, "{path}: resolves outside the manifest repo")
            }
        }
    }
}

impl std::error::Error for PlanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PlanError::Users(e) => Some(e),
            PlanError::Probe(e) => Some(e),
            PlanError::Io { .. }
            | PlanError::BadMode { .. }
            | PlanError::SymlinkInSource { .. }
            | PlanError::OutsideRepo { .. } => None,
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
/// into the probe's current `passwd`/`group`/`shadow`/`gshadow` (absent = empty, though a
/// passwd without root fails).
///
/// Every `[files]` and home source must resolve inside the repo ([`PlanError::OutsideRepo`]),
/// and a home source directory may not contain symlinks ([`PlanError::SymlinkInSource`]) or
/// file names that aren't UTF-8 ([`PlanError::Io`]). Validation checks the first already;
/// this is the second line of defence.
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
                content: read(&in_repo(inputs.repo_root, source)?)?,
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
        let source = in_repo(inputs.repo_root, &bind.repo_source)?;
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

/// `repo_root/rel` with every symlink resolved, which must lie inside the resolved `repo_root`.
/// Reading through the resolved path narrows, but does not close, the window for a symlink swap.
fn in_repo(repo_root: &Path, rel: &str) -> Result<PathBuf, PlanError> {
    let root = fs::canonicalize(repo_root).map_err(|e| io_error(repo_root, e))?;
    let path = repo_root.join(rel);
    let resolved = fs::canonicalize(&path).map_err(|e| io_error(&path, e))?;
    if !resolved.starts_with(&root) {
        return Err(PlanError::OutsideRepo {
            path: path.display().to_string(),
        });
    }
    Ok(resolved)
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
/// A symlink, a non-UTF-8 name or a name with a control character anywhere below `dir` is an error.
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
        let path = entry.path();
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| io_error(&path, "file name is not valid UTF-8"))?;
        if name.chars().any(char::is_control) {
            return Err(io_error(&path, "file name contains a control character"));
        }
        let rel = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let kind = entry.file_type().map_err(|e| io_error(&path, e))?;
        if kind.is_symlink() {
            return Err(PlanError::SymlinkInSource {
                path: path.display().to_string(),
            });
        } else if kind.is_dir() {
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
