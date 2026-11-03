use super::{with_top, BootState};
use crate::{CommandRunner, ExecError, Layout};
use aios_gen::GenId;
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// `aios status` (spec §4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub booted: Option<GenId>,
    pub default: Option<GenId>,
    pub bad: Vec<GenId>,
    /// `None` when the booted generation is unknown.
    pub drift: Option<Drift>,
}

/// Regular files and symlinks in the live `/etc` that differ from `@etc-gen-<booted>`:
/// runtime edits a reboot will discard. Paths are absolute (`/etc/...`), sorted.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Drift {
    pub added: Vec<String>,
    pub modified: Vec<String>,
    pub removed: Vec<String>,
    /// Entries that could not be read, with the error. Not compared.
    pub skipped: Vec<String>,
}

impl Drift {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.modified.is_empty() && self.removed.is_empty()
    }
}

/// Boot state plus drift. Mounts the top level read-only while comparing.
pub fn status(runner: &dyn CommandRunner, layout: &Layout) -> Result<Status, ExecError> {
    let state = BootState::read(layout)?;
    let drift = match state.booted {
        Some(gen) => Some(with_top(runner, layout, true, |top| {
            drift(&layout.live_etc, &top.subvol(&gen.etc_subvol()))
        })?),
        None => None,
    };
    Ok(Status {
        booted: state.booted,
        default: state.default_gen(),
        bad: state.bad(),
        drift,
    })
}

#[derive(Debug)]
enum Node {
    File(PathBuf, u32),
    Link(PathBuf),
}

/// Compare the live `/etc` with a generation's snapshot. `/etc/aios/generation.toml` is
/// ignored; directories and special files are not compared.
pub fn drift(live: &Path, snapshot: &Path) -> Result<Drift, ExecError> {
    if !snapshot.is_dir() {
        return Err(ExecError(format!("{} is missing", snapshot.display())));
    }
    let mut d = Drift::default();
    let live_nodes = scan(live, &mut d.skipped);
    let snap_nodes = scan(snapshot, &mut d.skipped);
    for (rel, node) in &live_nodes {
        let path = format!("/etc/{rel}");
        match snap_nodes.get(rel) {
            None => d.added.push(path),
            Some(old) => match differs(node, old) {
                Ok(true) => d.modified.push(path),
                Ok(false) => {}
                Err(e) => d.skipped.push(format!("{path}: {e}")),
            },
        }
    }
    for rel in snap_nodes.keys() {
        if !live_nodes.contains_key(rel) {
            d.removed.push(format!("/etc/{rel}"));
        }
    }
    Ok(d)
}

fn scan(root: &Path, skipped: &mut Vec<String>) -> BTreeMap<String, Node> {
    let mut nodes = BTreeMap::new();
    for entry in WalkDir::new(root).min_depth(1).follow_links(false) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                skipped.push(e.to_string());
                continue;
            }
        };
        let Ok(rel) = entry.path().strip_prefix(root) else {
            continue;
        };
        let rel = rel.to_string_lossy().into_owned();
        if rel == "aios/generation.toml" {
            continue;
        }
        let kind = entry.file_type();
        let node = if kind.is_symlink() {
            Node::Link(entry.path().to_path_buf())
        } else if kind.is_file() {
            match entry.metadata() {
                Ok(meta) => Node::File(entry.path().to_path_buf(), meta.permissions().mode()),
                Err(e) => {
                    skipped.push(e.to_string());
                    continue;
                }
            }
        } else {
            continue;
        };
        nodes.insert(rel, node);
    }
    nodes
}

fn differs(a: &Node, b: &Node) -> std::io::Result<bool> {
    Ok(match (a, b) {
        (Node::Link(a), Node::Link(b)) => fs::read_link(a)? != fs::read_link(b)?,
        (Node::File(a, mode_a), Node::File(b, mode_b)) => {
            mode_a != mode_b || fs::read(a)? != fs::read(b)?
        }
        _ => true,
    })
}

fn show(gen: Option<GenId>) -> String {
    gen.map_or_else(|| "unknown".to_string(), |g| format!("gen-{g}"))
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "booted:  {}", show(self.booted))?;
        writeln!(f, "default: {}", show(self.default))?;
        let bad: Vec<String> = self.bad.iter().map(|g| format!("gen-{g}")).collect();
        let bad = if bad.is_empty() {
            "none".to_string()
        } else {
            bad.join(", ")
        };
        writeln!(f, "bad:     {bad}")?;
        match &self.drift {
            None => writeln!(f, "drift:   unknown (no aios.gen= on the kernel cmdline)")?,
            Some(d) if d.is_empty() => writeln!(f, "drift:   none")?,
            Some(d) => {
                writeln!(f, "drift (discarded at the next boot):")?;
                for (marker, paths) in [('+', &d.added), ('~', &d.modified), ('-', &d.removed)] {
                    for path in paths {
                        writeln!(f, "  {marker} {path}")?;
                    }
                }
            }
        }
        for item in self.drift.iter().flat_map(|d| &d.skipped) {
            writeln!(f, "note: skipped {item}")?;
        }
        Ok(())
    }
}
