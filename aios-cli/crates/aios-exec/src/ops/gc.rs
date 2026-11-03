use super::{with_top, BootState};
use crate::{btrfs, CommandRunner, ExecError, Layout};
use aios_gen::{gc_select, list_complete, parse_subvol, Flavor, GenId};
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
/// `bootctl` override and the newest good one) or gen-1. Also delete every incomplete
/// generation except the booted one: an `@usr-gen-N` without its `@etc-gen-N` or the other
/// way round, and UKIs without both. None of them can boot, so a UKI of one never counts as
/// the newest good one either. A generation's UKIs go first, and the ESP directory is
/// fsynced before its subvolumes are deleted, so no UKI outlives them even after a power
/// loss; a `btrfs filesystem sync` makes the deletes durable. Needs the top level mounted.
/// Returns every generation something was deleted of, ascending.
pub fn gc_mounted(
    runner: &dyn CommandRunner,
    layout: &Layout,
    keep: usize,
) -> Result<Vec<GenId>, ExecError> {
    let state = BootState::read(layout)?;
    let names = btrfs::list_names(&layout.top)?;
    let complete = list_complete(&names);
    let newest = state
        .ukis
        .iter()
        .filter(|u| u.name.flavor == Flavor::Main && !u.name.is_bad())
        .map(|u| u.name.gen)
        .filter(|gen| complete.contains(gen))
        .max();
    let protected: Vec<GenId> = [state.booted, state.default_override, newest]
        .into_iter()
        .flatten()
        .collect();
    let mut doomed = gc_select(&complete, keep, &protected);
    let incomplete = names
        .iter()
        .filter_map(|name| parse_subvol(name).map(|(_, gen)| gen))
        .chain(state.ukis.iter().map(|u| u.name.gen))
        .filter(|gen| !complete.contains(gen) && Some(*gen) != state.booted);
    doomed.extend(incomplete);
    doomed.sort();
    doomed.dedup();
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
