use super::{mkdir, Mode, Run, ETC_CAND, ROOT_CAND, USR_CAND};
use crate::ops::read_ukis;
use crate::{btrfs, run_ok, Cmd, ExecError};
use aios_gen::GenId;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

impl Run<'_> {
    /// Spec §4.3 steps 11–12. The UKIs are first copied to the ESP under a `.tmp` name,
    /// which systemd-boot ignores, because they live in the candidate tree that is unmounted
    /// next. They get their real names only after the subvolume renames are on disk
    /// (`btrfs filesystem sync`), so a bootable UKI never exists without its subvolumes, even
    /// after a power loss. Renaming the main UKI is the commit point: from then on gen-N+1
    /// boots, so whatever fails after it is a warning (`after_commit`).
    pub(super) fn finalize(&mut self) -> Result<(), ExecError> {
        let (runner, l) = (self.ctx.runner, self.ctx.layout);
        let uki_dir = l.uki_dir();
        mkdir(&uki_dir)?;
        remove_ukis_of(&uki_dir, self.gen)?;
        for name in &self.ukis {
            let tmp = uki_dir.join(format!("{}.tmp", name.file_name()));
            self.esp_tmp.push(tmp.clone());
            copy_synced(&self.built_uki(name), &tmp)?;
        }
        btrfs::umount_recursive(runner, &l.cand)?;
        self.cand_mounted = false;
        for name in [USR_CAND, ETC_CAND] {
            btrfs::set_readonly(runner, &l.subvol(name))?;
        }
        rename(&l.subvol(USR_CAND), &l.subvol(&self.gen.usr_subvol()))?;
        rename(&l.subvol(ETC_CAND), &l.subvol(&self.gen.etc_subvol()))?;
        btrfs::filesystem_sync(runner, &l.top)?;
        // `uki` builds the main UKI first.
        let main = self
            .esp_tmp
            .first()
            .cloned()
            .ok_or_else(|| ExecError::new("no UKI was built"))?;
        rename(&main, &main.with_extension(""))?;
        let rest = self.esp_tmp.split_off(1);
        self.esp_tmp.clear();
        self.after_commit(&rest);
        Ok(())
    }

    /// The rest of finalize, once gen-N+1 is installed: rename the other UKIs, fsync the
    /// ESP directory, then (apply) `bootctl set-default ""`, which only moves the default
    /// to an entry that is on disk; delete `@root-cand` and unmount the top level. Each
    /// failure becomes a warning (spec §7); a failed fsync also skips `bootctl`.
    fn after_commit(&mut self, rest: &[PathBuf]) {
        let (runner, l, gen) = (self.ctx.runner, self.ctx.layout, self.gen);
        let mut warnings = Vec::new();
        // `rest` holds the copies of `ukis[1..]`, in order.
        let mut missing = Vec::new();
        for (tmp, name) in rest.iter().zip(&self.ukis[1..]) {
            if let Err(e) = rename(tmp, &tmp.with_extension("")) {
                warnings.push(format!("{e}; gen-{gen} is installed without this UKI"));
                missing.push(name.clone());
                if let Err(e) = fs::remove_file(tmp) {
                    warnings.push(ExecError::io(tmp, e).to_string());
                }
            }
        }
        self.ukis.retain(|name| !missing.contains(name));
        match runner.sync_dir(&l.uki_dir()) {
            Err(e) => warnings.push(format!("{e}; the boot default is unchanged")),
            Ok(()) if matches!(self.ctx.mode, Mode::Apply { .. }) => {
                let bootctl = Cmd::new("bootctl").args(["set-default", ""]);
                if let Err(e) = run_ok(runner, &bootctl) {
                    warnings.push(format!("{e}; `{bootctl}` makes gen-{gen} the default"));
                }
            }
            Ok(()) => {}
        }
        if let Err(e) = btrfs::delete_recursive(runner, &l.subvol(ROOT_CAND)) {
            warnings.push(format!("{e}; the next boot deletes {ROOT_CAND}"));
        }
        if self.top_mounted {
            match btrfs::umount(runner, &l.top) {
                Ok(()) => self.top_mounted = false,
                Err(e) => warnings.push(e.to_string()),
            }
        }
        self.warnings.extend(warnings);
    }
}

/// Remove every UKI of `gen` in `dir`, whatever its flavor or boot counter. `gen` has no
/// subvolumes yet (it is one past the newest), so these are left from a generation whose
/// subvolumes are gone, and one could share the new UKI's entry id.
fn remove_ukis_of(dir: &Path, gen: GenId) -> Result<(), ExecError> {
    for uki in read_ukis(dir)?.iter().filter(|u| u.name.gen == gen) {
        let path = dir.join(&uki.file);
        fs::remove_file(&path).map_err(|e| ExecError::io(&path, e))?;
    }
    Ok(())
}

fn rename(from: &Path, to: &Path) -> Result<(), ExecError> {
    fs::rename(from, to).map_err(|e| {
        ExecError(format!(
            "rename {} to {}: {e}",
            from.display(),
            to.display()
        ))
    })
}

/// Copy without carrying permission bits (the ESP is FAT) and flush to disk.
fn copy_synced(from: &Path, to: &Path) -> Result<(), ExecError> {
    let mut src = File::open(from).map_err(|e| ExecError::io(from, e))?;
    let mut dst = File::create(to).map_err(|e| ExecError::io(to, e))?;
    io::copy(&mut src, &mut dst).map_err(|e| ExecError::io(to, e))?;
    dst.sync_all().map_err(|e| ExecError::io(to, e))
}
