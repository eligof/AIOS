use super::{with_top, BootState};
use crate::{btrfs, CommandRunner, ExecError, Layout};
use aios_gen::{gc_select, list_complete, GenId};
use std::fs;

/// `aios gc`: mount the top level, delete old generations, unmount.
pub fn gc(
    runner: &dyn CommandRunner,
    layout: &Layout,
    keep: usize,
) -> Result<Vec<GenId>, ExecError> {
    with_top(runner, layout, false, |top| gc_mounted(runner, top, keep))
}

/// Delete generations beyond the newest `keep`, never the booted one, the default (the
/// `bootctl` override and the newest good one) or gen-1. A generation's UKIs go first, and
/// the ESP directory is fsynced before its subvolumes are deleted, so no UKI outlives them
/// even after a power loss; a `btrfs filesystem sync` makes the deletes durable. Needs the
/// top level mounted. Returns the deleted ids, ascending.
pub fn gc_mounted(
    runner: &dyn CommandRunner,
    layout: &Layout,
    keep: usize,
) -> Result<Vec<GenId>, ExecError> {
    let state = BootState::read(layout)?;
    let gens = list_complete(&btrfs::list_names(&layout.top)?);
    let protected: Vec<GenId> = [state.booted, state.default_override, state.newest]
        .into_iter()
        .flatten()
        .collect();
    let doomed = gc_select(&gens, keep, &protected);
    for gen in &doomed {
        let ukis: Vec<_> = state.ukis.iter().filter(|u| u.name.gen == *gen).collect();
        for uki in &ukis {
            let path = layout.uki_dir().join(&uki.file);
            fs::remove_file(&path).map_err(|e| ExecError::io(&path, e))?;
        }
        if !ukis.is_empty() {
            runner.sync_dir(&layout.uki_dir())?;
        }
        for subvol in [gen.usr_subvol(), gen.etc_subvol()] {
            btrfs::delete_recursive(runner, &layout.subvol(&subvol))?;
        }
    }
    if !doomed.is_empty() {
        btrfs::filesystem_sync(runner, &layout.top)?;
    }
    Ok(doomed)
}
