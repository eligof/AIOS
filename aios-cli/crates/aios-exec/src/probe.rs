use crate::{run_ok, Cmd, CommandRunner, Output};
use aios_plan::{EtcEntry, ProbeError, SystemProbe, UnitState};
use std::collections::BTreeSet;
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// The real [`SystemProbe`]: a generation's `/etc` read from a directory (the booted
/// `top/@etc-gen-N` snapshot, or the candidate's `cand/etc`), packages and units through
/// the runner.
pub struct DirProbe<'a> {
    /// The directory standing in for `/etc`.
    pub etc_root: PathBuf,
    pub runner: &'a dyn CommandRunner,
    /// `None`: ask the running system (`pacman -Qqe`, `systemctl is-enabled`).
    /// `Some(root)`: ask a candidate root (`arch-chroot ROOT pacman -Qqe`,
    /// `systemctl --root=ROOT is-enabled`).
    pub root: Option<PathBuf>,
}

impl<'a> DirProbe<'a> {
    pub fn new(
        etc_root: impl Into<PathBuf>,
        runner: &'a dyn CommandRunner,
        root: Option<PathBuf>,
    ) -> DirProbe<'a> {
        DirProbe {
            etc_root: etc_root.into(),
            runner,
            root,
        }
    }
}

impl SystemProbe for DirProbe<'_> {
    fn explicit_packages(&self) -> Result<BTreeSet<String>, ProbeError> {
        let cmd = match &self.root {
            None => Cmd::new("pacman").arg("-Qqe"),
            Some(root) => Cmd::new("arch-chroot")
                .arg_path(root)
                .args(["pacman", "-Qqe"]),
        };
        let out = run_ok(self.runner, &cmd).map_err(|e| ProbeError(e.to_string()))?;
        Ok(out
            .stdout_text()
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect())
    }

    fn etc_entry(&self, path: &str) -> Result<Option<EtcEntry>, ProbeError> {
        read_etc_entry(&self.etc_root, path)
    }

    fn unit_state(&self, unit: &str) -> Result<UnitState, ProbeError> {
        let mut cmd = Cmd::new("systemctl");
        if let Some(root) = &self.root {
            cmd = cmd.arg(format!("--root={}", root.display()));
        }
        let cmd = cmd.args(["is-enabled", unit]);
        let out = self
            .runner
            .run(&cmd)
            .map_err(|e| ProbeError(e.to_string()))?;
        parse_unit_state(unit, &out)
    }
}

/// `/etc/<rel>` read from `etc_root/<rel>`: a symlink's target, or a file's bytes and
/// `st_mode & 0o7777`. `None` when absent. Directories and special files are errors.
pub fn read_etc_entry(etc_root: &Path, path: &str) -> Result<Option<EtcEntry>, ProbeError> {
    let rel = path
        .strip_prefix("/etc/")
        .filter(|rel| rel.split('/').all(|c| !matches!(c, "" | "." | "..")))
        .ok_or_else(|| ProbeError(format!("{path}: not a path below /etc")))?;
    let full = etc_root.join(rel);
    let failed = |e: std::io::Error| ProbeError(format!("{}: {e}", full.display()));
    let meta = match fs::symlink_metadata(&full) {
        Ok(meta) => meta,
        Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => {
            return Ok(None)
        }
        Err(e) => return Err(failed(e)),
    };
    if meta.file_type().is_symlink() {
        let target = fs::read_link(&full).map_err(failed)?;
        Ok(Some(EtcEntry::Symlink(
            target.to_string_lossy().into_owned(),
        )))
    } else if meta.is_file() {
        Ok(Some(EtcEntry::File {
            content: fs::read(&full).map_err(failed)?,
            mode: meta.permissions().mode() & 0o7777,
        }))
    } else {
        Err(ProbeError(format!(
            "{}: not a regular file or symlink",
            full.display()
        )))
    }
}

/// Map `systemctl is-enabled UNIT` onto [`UnitState`]. `linked` units are not enabled, so
/// they count as `Disabled`; `bad` and unknown answers are errors.
pub fn parse_unit_state(unit: &str, out: &Output) -> Result<UnitState, ProbeError> {
    let stdout = out.stdout_text();
    let word = stdout.lines().next().unwrap_or("").trim();
    let state = match word {
        "enabled" | "enabled-runtime" => UnitState::Enabled,
        "disabled" | "linked" | "linked-runtime" => UnitState::Disabled,
        "masked" | "masked-runtime" => UnitState::Masked,
        "static" | "indirect" | "generated" | "transient" | "alias" => UnitState::Static,
        "not-found" => UnitState::NotFound,
        "" if out.status == 4 || out.stderr_text().contains("Failed to get unit file state") => {
            UnitState::NotFound
        }
        other => {
            return Err(ProbeError(format!(
                "systemctl is-enabled {unit}: unexpected answer {other:?} (exit status {})",
                out.status
            )))
        }
    };
    Ok(state)
}
