use super::{lines, mkdir, Mode, Run};
use crate::{etcfs, read_etc_entry, run_ok, status_error, Cmd, ExecError, Layout};
use aios_plan::EtcEntry;
use std::fs;
use std::path::{Path, PathBuf};

/// Hooks pacstrap must not run, masked in the empty candidate's `/etc` while it does:
/// mkinitcpio's, which would build throwaway initramfs images (aios builds its own for the
/// UKIs), and sbctl's, whose `sbctl sign-all` finds no keys in the candidate and fails.
/// `zz-sbctl.hook` is the name sbctl's Makefile installs the hook under.
const PACSTRAP_MASKS: [&str; 3] = [
    "/etc/pacman.d/hooks/90-mkinitcpio-install.hook",
    "/etc/pacman.d/hooks/60-mkinitcpio-remove.hook",
    "/etc/pacman.d/hooks/zz-sbctl.hook",
];

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

    /// Package names always follow `--`, so none can be read as an option (the manifest
    /// rejects a leading `-` too, but installed names come from `pacman -Qqe`/`-Qdtq`).
    fn upgrade(&self, set: &[String]) -> Result<(), ExecError> {
        self.chroot(&["pacman", "-Syu", "--needed", "--noconfirm", "--"], set)?;
        let explicit = lines(&self.chroot(&["pacman", "-Qqe"], &[])?.stdout_text());
        let removed: Vec<String> = explicit.into_iter().filter(|p| !set.contains(p)).collect();
        if !removed.is_empty() {
            self.chroot(&["pacman", "-Rns", "--noconfirm", "--"], &removed)?;
        }
        self.chroot(&["pacman", "-D", "--asexplicit", "--"], set)?;
        let orphans = self.orphans()?;
        if !orphans.is_empty() {
            self.chroot(&["pacman", "-Rns", "--noconfirm", "--"], &orphans)?;
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

    /// `pacstrap` into the empty candidate root, with the database in the candidate's `/usr`
    /// (see [`pacstrap_conf`]) and the hooks in [`PACSTRAP_MASKS`] masked while it runs.
    /// The root is empty, not `@blank`: pacman would refuse to install `filesystem` and
    /// `pacman` over `@blank`'s `bin`, `lib`, ... and `var/lib/pacman` symlinks, which no
    /// package in an empty database owns yet ("exists in filesystem").
    fn pacstrap(&self, set: &[String]) -> Result<(), ExecError> {
        let l = self.ctx.layout;
        let conf = pacstrap_conf_path(l);
        let text = pacstrap_conf(&self.manifest_pacman_conf()?, &l.cand);
        fs::write(&conf, text).map_err(|e| ExecError::io(&conf, e))?;
        mkdir(&l.cand.join("usr/lib/pacman"))?;
        let etc = l.cand.join("etc");
        let mask = EtcEntry::Symlink("/dev/null".to_string());
        for path in PACSTRAP_MASKS {
            etcfs::write(&etc, path, &mask)?;
        }
        // No `--` before the packages: pacstrap would pass it to pacman as a package name.
        // The manifest validator rejects package names with a leading `-` instead.
        // pacstrap runs `pacman -b ROOT/var/lib/pacman/` unless it copies the config (-P),
        // and that beats the config's DBPath. It passes what follows the root on to pacman
        // after its own options, so this `--dbpath` wins.
        let cmd = Cmd::new("pacstrap")
            .arg("-C")
            .arg_path(&conf)
            .arg_path(&l.cand)
            .arg(format!("--dbpath={}/usr/lib/pacman/", l.cand.display()));
        run_ok(self.ctx.runner, &cmd.args(set.iter().cloned()))?;
        // A mask the manifest doesn't declare was only for pacstrap.
        let files = &self.ctx.manifest.files;
        for path in PACSTRAP_MASKS.iter().filter(|p| !files.contains_key(**p)) {
            let entry = read_etc_entry(&etc, path).map_err(|e| ExecError(e.0))?;
            if entry.as_ref() == Some(&mask) {
                etcfs::remove(&etc, path)?;
            }
        }
        Ok(())
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

/// The manifest's `pacman.conf` for the host-side `pacstrap`. pacman takes `DBPath` and
/// `HookDir` from the config as they are, not below `--root`, so:
/// - `DBPath` names the candidate's `/usr/lib/pacman/`, where the database lives (spec §2),
///   and `HookDir` the candidate's `/etc/pacman.d/hooks/`, so the masks there apply and none
///   of the installer's own hooks run. Both go right after `[options]` (added at the top if
///   missing) and replace any the manifest sets.
/// - `LogFile` is dropped, so it defaults to the new root's `var/log/pacman.log`.
/// - `file:///persist/` servers point at the candidate's bind of the local repo, since the
///   installer host has no `/persist`.
fn pacstrap_conf(text: &str, cand: &Path) -> String {
    let repo = format!("file://{}/persist/", cand.display());
    let options = format!(
        "DBPath = {0}/usr/lib/pacman/\nHookDir = {0}/etc/pacman.d/hooks/\n",
        cand.display()
    );
    let mut out = String::new();
    let mut placed = false;
    for line in text.lines() {
        let key = line.split('=').next().unwrap_or("").trim();
        if matches!(key, "DBPath" | "HookDir" | "LogFile") {
            continue;
        }
        out.push_str(&line.replace("file:///persist/", &repo));
        out.push('\n');
        if !placed && line.trim() == "[options]" {
            out.push_str(&options);
            placed = true;
        }
    }
    if placed {
        out
    } else {
        format!("[options]\n{options}{out}")
    }
}

#[cfg(test)]
mod tests {
    use super::pacstrap_conf;
    use std::path::Path;

    const CAND: &str = "/run/aios/cand";
    const OPTIONS: &str = "DBPath = /run/aios/cand/usr/lib/pacman/\n\
                           HookDir = /run/aios/cand/etc/pacman.d/hooks/\n";

    #[test]
    fn database_and_hooks_come_from_the_candidate() {
        let text = "# c\n[options]\nDBPath = /usr/lib/pacman/\nHookDir=/etc/pacman.d/hooks/\n\
                    LogFile = /var/log/pacman.log\nHoldPkg = pacman\n\
                    [aios-local]\nServer = file:///persist/aios/repo\n";
        assert_eq!(
            pacstrap_conf(text, Path::new(CAND)),
            format!(
                "# c\n[options]\n{OPTIONS}HoldPkg = pacman\n\
                 [aios-local]\nServer = file:///run/aios/cand/persist/aios/repo\n"
            )
        );
    }

    #[test]
    fn without_options_a_section_is_added_first() {
        let text = "[core]\nInclude = /etc/pacman.d/mirrorlist\n";
        assert_eq!(
            pacstrap_conf(text, Path::new(CAND)),
            format!("[options]\n{OPTIONS}{text}")
        );
    }
}
