use super::{with_top, BootState};
use crate::runner::escape_unprintable;
use crate::sys::{O_NOFOLLOW, O_NONBLOCK};
use crate::{CommandRunner, ExecError, Layout};
use aios_gen::GenId;
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, Metadata};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// The largest file drift reads. Two larger files of the same size are skipped with a
/// note; a size difference is drift whatever the size.
pub const DRIFT_READ_MAX: u64 = 16 << 20;

/// `aios status` (spec §4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub booted: Option<GenId>,
    pub default: Option<GenId>,
    pub bad: Vec<GenId>,
    /// `None` when the booted generation is unknown.
    pub drift: Option<Drift>,
}

/// How the live `/etc` differs from `@etc-gen-<booted>`: runtime edits a reboot will
/// discard. Paths are absolute (`/etc/...`, a directory with a trailing `/`), sorted, and
/// unescaped: `Display` escapes them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Drift {
    /// Only in the live `/etc`.
    pub added: Vec<String>,
    /// In both, but different.
    pub modified: Vec<Modified>,
    /// Only in the snapshot.
    pub removed: Vec<String>,
    /// Entries that could not be compared, with the reason.
    pub skipped: Vec<String>,
}

/// A path in both trees and what differs, snapshot first: `size differs`, `content
/// differs`, `target differs` (a symlink), `mode 0644 -> 0600`, `owner 0:0 -> 1000:1000`
/// (uid:gid) or a changed type (`file -> symlink`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Modified {
    pub path: String,
    pub what: Vec<String>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    File,
    Dir,
    Symlink,
    /// A FIFO, socket or device node: compared by mode and owner, never opened.
    Special,
}

impl Kind {
    fn of(meta: &Metadata) -> Kind {
        let t = meta.file_type();
        if t.is_symlink() {
            Kind::Symlink
        } else if t.is_dir() {
            Kind::Dir
        } else if t.is_file() {
            Kind::File
        } else {
            Kind::Special
        }
    }

    fn name(self) -> &'static str {
        match self {
            Kind::File => "file",
            Kind::Dir => "directory",
            Kind::Symlink => "symlink",
            Kind::Special => "special file",
        }
    }
}

/// One entry as the walk saw it (`lstat`).
#[derive(Debug, Clone)]
struct Node {
    path: PathBuf,
    kind: Kind,
    /// `st_mode & 0o7777`.
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
}

/// Compare the live `/etc` with a generation's snapshot, the top directory included.
/// `/etc/aios/generation.toml` is ignored. Type, owner and mode (not for a symlink) are
/// compared from `lstat`; then a symlink's target, and a regular file's size and, if the
/// sizes match, its bytes, read through a descriptor that is a regular file (see
/// [`read_regular`]).
pub fn drift(live: &Path, snapshot: &Path) -> Result<Drift, ExecError> {
    if !snapshot.is_dir() {
        return Err(ExecError(format!("{} is missing", snapshot.display())));
    }
    let mut d = Drift::default();
    let live_nodes = scan(live, &mut d.skipped);
    let snap_nodes = scan(snapshot, &mut d.skipped);
    for (rel, node) in &live_nodes {
        let path = shown(rel, node.kind);
        match snap_nodes.get(rel) {
            None => d.added.push(path),
            Some(old) => match compare(node, old) {
                Ok(what) if what.is_empty() => {}
                Ok(what) => d.modified.push(Modified { path, what }),
                Err(reason) => d.skipped.push(format!("{path}: {reason}")),
            },
        }
    }
    for (rel, node) in &snap_nodes {
        if !live_nodes.contains_key(rel) {
            d.removed.push(shown(rel, node.kind));
        }
    }
    Ok(d)
}

/// `/etc/<rel>`, with a trailing `/` for a directory.
fn shown(rel: &Path, kind: Kind) -> String {
    let mut path = Path::new("/etc").join(rel).to_string_lossy().into_owned();
    if kind == Kind::Dir {
        path.push('/');
    }
    path
}

/// Every entry below `root` and `root` itself (as the empty path), by relative path.
/// Symlinks are never followed, except a symlink at `root` itself.
fn scan(root: &Path, skipped: &mut Vec<String>) -> BTreeMap<PathBuf, Node> {
    let mut nodes = BTreeMap::new();
    for entry in WalkDir::new(root).follow_links(false) {
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
        if rel == Path::new("aios/generation.toml") {
            continue;
        }
        let meta = match entry.metadata() {
            Ok(meta) => meta,
            Err(e) => {
                skipped.push(e.to_string());
                continue;
            }
        };
        let node = Node {
            path: entry.path().to_path_buf(),
            kind: Kind::of(&meta),
            mode: meta.mode() & 0o7777,
            uid: meta.uid(),
            gid: meta.gid(),
            size: meta.len(),
        };
        nodes.insert(rel.to_path_buf(), node);
    }
    nodes
}

/// What differs between the live node and the snapshot's (empty: nothing). `Err` with
/// the reason when it can't be told.
fn compare(live: &Node, snap: &Node) -> Result<Vec<String>, String> {
    if live.kind != snap.kind {
        return Ok(vec![format!(
            "{} -> {}",
            snap.kind.name(),
            live.kind.name()
        )]);
    }
    let mut what = Vec::new();
    if live.kind != Kind::Symlink && live.mode != snap.mode {
        what.push(format!("mode {:04o} -> {:04o}", snap.mode, live.mode));
    }
    if (live.uid, live.gid) != (snap.uid, snap.gid) {
        what.push(format!(
            "owner {}:{} -> {}:{}",
            snap.uid, snap.gid, live.uid, live.gid
        ));
    }
    match live.kind {
        Kind::Symlink => {
            let target = |n: &Node| fs::read_link(&n.path).map_err(|e| e.to_string());
            if target(live)? != target(snap)? {
                what.push("target differs".to_string());
            }
        }
        Kind::File if live.size != snap.size => what.push("size differs".to_string()),
        Kind::File if live.size > DRIFT_READ_MAX => {
            return Err(format!(
                "larger than {} MiB, contents not compared",
                DRIFT_READ_MAX >> 20
            ))
        }
        Kind::File => {
            let read = |n: &Node| read_regular(&n.path).map_err(|e| e.to_string());
            if read(live)? != read(snap)? {
                what.push("content differs".to_string());
            }
        }
        Kind::Dir | Kind::Special => {}
    }
    Ok(what)
}

/// The bytes of the regular file at `path`, read through one descriptor: opened without
/// following a symlink or waiting on a FIFO (`O_NOFOLLOW | O_NONBLOCK`), then `fstat`ed,
/// so what is read is what was checked. Anything but a regular file of at most
/// [`DRIFT_READ_MAX`] bytes is an error.
fn read_regular(path: &Path) -> io::Result<Vec<u8>> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    let too_large = || io::Error::other(format!("larger than {} MiB", DRIFT_READ_MAX >> 20));
    if meta.len() > DRIFT_READ_MAX {
        return Err(too_large());
    }
    let mut bytes = Vec::new();
    file.take(DRIFT_READ_MAX + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > DRIFT_READ_MAX {
        return Err(too_large());
    }
    Ok(bytes)
}

fn show(gen: Option<GenId>) -> String {
    gen.map_or_else(|| "unknown".to_string(), |g| format!("gen-{g}"))
}

impl fmt::Display for Status {
    /// Every path and note is escaped (`escape_unprintable`): a file name can't forge a
    /// line.
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
                for path in &d.added {
                    writeln!(f, "  + {}", escape_unprintable(path))?;
                }
                for m in &d.modified {
                    let what = escape_unprintable(&m.what.join(", "));
                    writeln!(f, "  ~ {} ({what})", escape_unprintable(&m.path))?;
                }
                for path in &d.removed {
                    writeln!(f, "  - {}", escape_unprintable(path))?;
                }
            }
        }
        for item in self.drift.iter().flat_map(|d| &d.skipped) {
            writeln!(f, "note: skipped {}", escape_unprintable(item))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{compare, read_regular, Kind, Node};
    use std::path::PathBuf;

    fn node(kind: Kind, mode: u32, uid: u32, gid: u32) -> Node {
        Node {
            path: PathBuf::from("/nonexistent"),
            kind,
            mode,
            uid,
            gid,
            size: 0,
        }
    }

    /// Tests can't chown, so owner changes are shown on nodes as the walk would see them.
    #[test]
    fn owner_and_group_changes_are_drift_for_every_kind() {
        for kind in [Kind::Dir, Kind::Special] {
            let what = compare(&node(kind, 0o755, 1000, 0), &node(kind, 0o755, 0, 0)).unwrap();
            assert_eq!(what, ["owner 0:0 -> 1000:0"], "{kind:?}");
            let what = compare(&node(kind, 0o700, 0, 10), &node(kind, 0o755, 0, 0)).unwrap();
            assert_eq!(what, ["mode 0755 -> 0700", "owner 0:0 -> 0:10"], "{kind:?}");
        }
        assert!(
            compare(&node(Kind::Dir, 0o755, 0, 0), &node(Kind::Dir, 0o755, 0, 0))
                .unwrap()
                .is_empty()
        );
    }

    /// The walk saw a regular file; by the time it is read it may be something else.
    #[test]
    fn reading_never_follows_a_symlink_or_waits_on_a_fifo() {
        let dir = tempfile::tempdir().unwrap();
        let (file, link, fifo) = (
            dir.path().join("file"),
            dir.path().join("link"),
            dir.path().join("fifo"),
        );
        std::fs::write(&file, "data").unwrap();
        std::os::unix::fs::symlink(&file, &link).unwrap();
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(made.success());
        assert_eq!(read_regular(&file).unwrap(), b"data");
        let err = read_regular(&link).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(40), "ELOOP: {err}");
        assert_eq!(
            read_regular(&fifo).unwrap_err().to_string(),
            "not a regular file"
        );
    }
}
