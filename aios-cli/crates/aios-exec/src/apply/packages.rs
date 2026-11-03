use super::{lines, mkdir, Mode, Run};
use crate::{run_ok, status_error, Cmd, ExecError, Layout};
use std::fs;
use std::path::{Path, PathBuf};

impl Run<'_> {
    /// Apply: full upgrade to the package set, remove what left it, mark the set explicit,
    /// remove orphans. Bootstrap: `pacstrap` the set into the empty candidate.
    pub(super) fn packages(&mut self) -> Result<(), ExecError> {
        let set = self.ctx.manifest.package_set();
        match self.ctx.mode {
            Mode::Apply { .. } => self.upgrade(&set),
            Mode::Bootstrap => self.pacstrap(&set),
        }
    }

    fn upgrade(&self, set: &[String]) -> Result<(), ExecError> {
        self.chroot(&["pacman", "-Syu", "--needed", "--noconfirm"], set)?;
        let explicit = lines(&self.chroot(&["pacman", "-Qqe"], &[])?.stdout_text());
        let removed: Vec<String> = explicit.into_iter().filter(|p| !set.contains(p)).collect();
        if !removed.is_empty() {
            self.chroot(&["pacman", "-Rns", "--noconfirm"], &removed)?;
        }
        self.chroot(&["pacman", "-D", "--asexplicit"], set)?;
        let orphans = self.orphans()?;
        if !orphans.is_empty() {
            self.chroot(&["pacman", "-Rns", "--noconfirm"], &orphans)?;
        }
        Ok(())
    }

    /// `pacman -Qdtq`, which exits 1 when there are none.
    fn orphans(&self) -> Result<Vec<String>, ExecError> {
        let cmd = self.chroot_cmd(&["pacman", "-Qdtq"]);
        let out = self.ctx.runner.run(&cmd)?;
        match out.status {
            0 => Ok(lines(&out.stdout_text())),
            1 if out.stdout.is_empty() => Ok(Vec::new()),
            _ => Err(status_error(&cmd, &out)),
        }
    }

    fn pacstrap(&self, set: &[String]) -> Result<(), ExecError> {
        let l = self.ctx.layout;
        let conf = pacstrap_conf_path(l);
        let text = pacstrap_conf(&self.manifest_pacman_conf()?, &l.cand);
        fs::write(&conf, text).map_err(|e| ExecError::io(&conf, e))?;
        // `var/lib/pacman` (from @blank) links to `../../usr/lib/pacman`; pacstrap's
        // `mkdir -p` fails on a dangling link.
        mkdir(&l.cand.join("usr/lib/pacman"))?;
        let cmd = Cmd::new("pacstrap")
            .arg("-C")
            .arg_path(&conf)
            .arg_path(&l.cand);
        run_ok(self.ctx.runner, &cmd.args(set.iter().cloned())).map(drop)
    }

    fn manifest_pacman_conf(&self) -> Result<String, ExecError> {
        let source = self
            .ctx
            .manifest
            .files
            .get("/etc/pacman.conf")
            .and_then(|entry| entry.source.as_ref())
            .ok_or_else(|| {
                ExecError::new("bootstrap needs a [files] \"/etc/pacman.conf\" entry with a source")
            })?;
        let path = self.ctx.layout.config.join(source);
        fs::read_to_string(&path).map_err(|e| ExecError::io(&path, e))
    }

    /// Bootstrap only: a fresh keyring in the new root, trusting Arch and CachyOS.
    pub(super) fn keyring(&mut self) -> Result<(), ExecError> {
        self.chroot(&["pacman-key", "--init"], &[])?;
        self.chroot(&["pacman-key", "--populate", "archlinux", "cachyos"], &[])?;
        Ok(())
    }
}

/// Next to the candidate mount point, e.g. `/run/aios/aios-pacstrap.conf`. It is left in
/// place (tmpfs) for inspection.
fn pacstrap_conf_path(l: &Layout) -> PathBuf {
    l.cand.with_file_name("aios-pacstrap.conf")
}

/// The manifest's `pacman.conf` for the host-side `pacstrap`:
/// - `DBPath` and `LogFile` are dropped, so both default to paths inside the new root
///   (`var/lib/pacman` there links into `/usr`, spec §2);
/// - `file:///persist/` servers point at the candidate's bind of the local repo, since the
///   installer host has no `/persist`.
fn pacstrap_conf(text: &str, cand: &Path) -> String {
    let repo = format!("file://{}/persist/", cand.display());
    text.lines()
        .filter(|line| {
            let key = line.split('=').next().unwrap_or("").trim();
            key != "DBPath" && key != "LogFile"
        })
        .map(|line| format!("{}\n", line.replace("file:///persist/", &repo)))
        .collect()
}
