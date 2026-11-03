use super::{mkdir, Mode, Run, ETC_CAND, ROOT_CAND, USR_CAND};
use crate::{btrfs, run_ok, Cmd, ExecError};
use std::fs::{self, File};
use std::io;
use std::path::Path;

impl Run<'_> {
    /// Spec §4.3 steps 11–12. The UKIs are first copied to the ESP under a `.tmp` name,
    /// which systemd-boot ignores, because they live in the candidate tree that is unmounted
    /// next. They get their real names only after the subvolume renames, so a bootable UKI
    /// never exists without its subvolumes.
    pub(super) fn finalize(&mut self) -> Result<(), ExecError> {
        let (runner, l) = (self.ctx.runner, self.ctx.layout);
        let uki_dir = l.uki_dir();
        mkdir(&uki_dir)?;
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
        for tmp in self.esp_tmp.clone() {
            rename(&tmp, &tmp.with_extension(""))?;
        }
        self.esp_tmp.clear();
        if let Mode::Apply { .. } = self.ctx.mode {
            run_ok(runner, &Cmd::new("bootctl").args(["set-default", ""]))?;
        }
        btrfs::delete_recursive(runner, &l.subvol(ROOT_CAND))?;
        if self.top_mounted {
            btrfs::umount(runner, &l.top)?;
            self.top_mounted = false;
        }
        Ok(())
    }
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
