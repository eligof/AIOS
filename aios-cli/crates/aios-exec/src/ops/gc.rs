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
    with_top(runner, layout, false, || gc_mounted(runner, layout, keep))
}

/// Delete generations beyond the newest `keep`, never the booted one, the default (the
/// `bootctl` override and the newest good one) or gen-1. A generation's UKIs go first, then
/// its subvolumes, so no UKI outlives them. Needs the top level mounted. Returns the
/// deleted ids, ascending.
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
        for uki in state.ukis.iter().filter(|u| u.name.gen == *gen) {
            let path = layout.uki_dir().join(&uki.file);
            fs::remove_file(&path).map_err(|e| ExecError::io(&path, e))?;
        }
        for subvol in [gen.usr_subvol(), gen.etc_subvol()] {
            btrfs::delete_recursive(runner, &layout.subvol(&subvol))?;
        }
    }
    Ok(doomed)
}
