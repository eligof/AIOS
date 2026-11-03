use super::{with_top, BootState};
use crate::{btrfs, CommandRunner, ExecError, Layout};
use aios_gen::{gc_select, list_complete, parse_subvol, Flavor, GenId};
use std::fs;

/// Where gc runs, which decides the generation it must spare as booted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GcMode {
    /// On a running AIOS system (`aios gc`, apply's ESP-space gc): the generation
    /// `aios.gen=` names is booted. Without one, gc refuses to delete anything.
    Running,
    /// `aios bootstrap`'s ESP-space gc, on a target nothing has booted from yet.
    Bootstrap,
}

/// `aios gc`: mount the top level, delete old generations, unmount.
pub fn gc(
    runner: &dyn CommandRunner,
    layout: &Layout,
    keep: usize,
) -> Result<Vec<GenId>, ExecError> {
    with_top(runner, layout, false, |top| {
        gc_mounted(runner, top, keep, GcMode::Running)
    })
}

/// Delete generations beyond the newest `keep`, never the booted one, the default (the
/// `bootctl` override and the newest good one) or gen-1. Also delete every incomplete
/// generation except the booted one: an `@usr-gen-N` without its `@etc-gen-N` or the other
/// way round, and UKIs without both. None of them can boot, so a UKI of one never counts as
/// the newest good one either. A generation's UKIs go first, and the ESP directory is
/// fsynced before its subvolumes are deleted, so no UKI outlives them even after a power
/// loss; a `btrfs filesystem sync` makes the deletes durable. Needs the top level mounted.
/// Returns every generation something was deleted of, ascending. In [`GcMode::Running`]
/// it refuses when the booted generation is unknown, and in [`GcMode::Bootstrap`] there
/// is none to spare.
pub fn gc_mounted(
    runner: &dyn CommandRunner,
    layout: &Layout,
    keep: usize,
    mode: GcMode,
) -> Result<Vec<GenId>, ExecError> {
    let state = BootState::read(layout)?;
    let booted = match mode {
        GcMode::Running => Some(state.booted.ok_or_else(|| {
            ExecError::new("cannot determine the booted generation; refusing to garbage-collect")
        })?),
        GcMode::Bootstrap => None,
    };
    let names = btrfs::list_names(&layout.top)?;
    let complete = list_complete(&names);
    let newest = state
        .ukis
        .iter()
        .filter(|u| u.name.flavor == Flavor::Main && !u.name.is_bad())
        .map(|u| u.name.gen)
        .filter(|gen| complete.contains(gen))
        .max();
    let protected: Vec<GenId> = [booted, state.default_override, newest]
        .into_iter()
        .flatten()
        .collect();
    let mut doomed = gc_select(&complete, keep, &protected);
    let incomplete = names
        .iter()
        .filter_map(|name| parse_subvol(name).map(|(_, gen)| gen))
        .chain(state.ukis.iter().map(|u| u.name.gen))
        .filter(|gen| !complete.contains(gen) && Some(*gen) != booted);
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
