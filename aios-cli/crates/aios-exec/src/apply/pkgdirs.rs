use super::{Mode, Run};
use crate::runner::escape_unprintable;
use crate::{etcfs, read_etc_entry, ExecError};
use aios_plan::{EtcEntry, PKGDIRS_CONF};
use aios_render::{parse_pkgdirs_tmpfiles, pkgdirs_tmpfiles, PackagePath};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, Metadata};
use std::io::ErrorKind;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

/// Trees the next boot has without `@root-cand`: the generation (`/usr`, `/etc`), the
/// persistent subvolumes (`/persist`, `/home`, and `/var/log`, which the candidate binds
/// while packages install, so what they write there stays), `/boot` (read only while the
/// UKIs are built), and the API file systems and tmpfs mounts that start out empty on any
/// system.
const KEPT_TREES: [&str; 12] = [
    "/usr", "/etc", "/boot", "/persist", "/home", "/var/log", "/proc", "/sys", "/dev", "/run",
    "/tmp", "/efi",
];

/// Where a path leads below a root, never following a symlink.
enum Found {
    Missing,
    /// A parent is a symlink: the path lives wherever that points.
    BelowLink,
    Here(Metadata),
}

impl Run<'_> {
    /// Spec §4.3 step 5: every boot starts from a copy of `@blank`, so a package's
    /// directories and symlinks outside the generation and the persistent trees would be
    /// gone. `aios-pkgdirs.conf` recreates them at boot, with the mode, owner and target
    /// they have in the candidate. A package's regular file there can't be recreated: each
    /// becomes a warning. Paths `@blank` provides (or leads elsewhere through its links) and
    /// declared persistent files are left out.
    ///
    /// apply's candidate root is a fresh snapshot of `@blank`, holding only what this
    /// transaction installed. A path some package still owns but the candidate lacks keeps
    /// the booted generation's line (its package was installed by an earlier generation).
    pub(super) fn write_pkgdirs(&mut self, etc: &Path) -> Result<(), ExecError> {
        let listed = self.chroot(&["pacman", "-Qlq"], &[])?.stdout_text();
        let previous = self.previous_pkgdirs()?;
        let blank = self.ctx.layout.subvol("@blank");
        let persisted = &self.ctx.manifest.persist.files;
        let mut paths = Vec::new();
        let unique: BTreeSet<&str> = listed
            .lines()
            .map(|line| line.trim_end_matches('/'))
            .collect();
        for path in unique {
            let Some(rel) = relative(path) else { continue };
            if KEPT_TREES.iter().any(|tree| at_or_under(path, tree))
                || persisted.iter().any(|file| file == path)
                || !matches!(find(&blank, rel)?, Found::Missing)
            {
                continue;
            }
            let cand = &self.ctx.layout.cand;
            let Found::Here(meta) = find(cand, rel)? else {
                paths.extend(previous.get(path).cloned());
                continue;
            };
            let target = if meta.file_type().is_symlink() {
                let full = cand.join(rel);
                let target = fs::read_link(&full).map_err(|e| ExecError::io(&full, e))?;
                target.to_str().map(str::to_string)
            } else {
                None
            };
            let path = path.to_string();
            if meta.is_dir() {
                paths.push(PackagePath::Dir {
                    path,
                    mode: meta.permissions().mode() & 0o7777,
                    uid: meta.uid(),
                    gid: meta.gid(),
                });
            } else if let Some(target) = target {
                paths.push(PackagePath::Symlink { path, target });
            } else {
                // A regular file, or a symlink tmpfiles can't name the target of.
                self.warnings.push(format!(
                    "package file {} lives outside /usr and /etc and is lost at every boot",
                    escape_unprintable(&path)
                ));
            }
        }
        let entry = EtcEntry::File {
            content: pkgdirs_tmpfiles(&paths).into_bytes(),
            mode: 0o644,
        };
        etcfs::write(etc, PKGDIRS_CONF, &entry)
    }

    /// The booted generation's `aios-pkgdirs.conf`, by path (apply only; none if absent).
    fn previous_pkgdirs(&self) -> Result<BTreeMap<String, PackagePath>, ExecError> {
        let Mode::Apply { booted } = self.ctx.mode else {
            return Ok(BTreeMap::new());
        };
        let booted_etc = self.ctx.layout.subvol(&booted.etc_subvol());
        Ok(
            match read_etc_entry(&booted_etc, PKGDIRS_CONF).map_err(|e| ExecError(e.0))? {
                Some(EtcEntry::File { content, .. }) => {
                    parse_pkgdirs_tmpfiles(&String::from_utf8_lossy(&content))
                }
                _ => BTreeMap::new(),
            },
        )
    }
}

/// `/a/b` -> `a/b`; `None` for the root itself, a relative path or one with an empty, `.`
/// or `..` component.
fn relative(path: &str) -> Option<&str> {
    path.strip_prefix('/')
        .filter(|rel| rel.split('/').all(|c| !matches!(c, "" | "." | "..")))
}

/// `path` is `tree` or lies below it.
fn at_or_under(path: &str, tree: &str) -> bool {
    path.strip_prefix(tree)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// Look up `rel` below `root` one component at a time, so no symlink is ever followed.
fn find(root: &Path, rel: &str) -> Result<Found, ExecError> {
    let parts: Vec<&str> = rel.split('/').collect();
    let mut full = root.to_path_buf();
    for (i, part) in parts.iter().enumerate() {
        full.push(part);
        let meta = match fs::symlink_metadata(&full) {
            Ok(meta) => meta,
            Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => {
                return Ok(Found::Missing)
            }
            Err(e) => return Err(ExecError::io(&full, e)),
        };
        if i + 1 == parts.len() {
            return Ok(Found::Here(meta));
        }
        if meta.file_type().is_symlink() {
            return Ok(Found::BelowLink);
        }
        if !meta.is_dir() {
            return Ok(Found::Missing);
        }
    }
    Ok(Found::Missing)
}
