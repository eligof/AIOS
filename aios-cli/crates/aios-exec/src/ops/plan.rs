use super::with_top;
use crate::MachineFacts;
use crate::{days_since_epoch, read_hashes, CommandRunner, DirProbe, ExecError, Layout};
use aios_gen::gen_from_cmdline;
use aios_manifest::Manifest;
use aios_plan::{build_plan, Inputs, Plan};
use std::fs;
use std::time::SystemTime;

/// `aios plan`: diff the manifest against the booted generation. Its `/etc` comes from the
/// `@etc-gen-<booted>` snapshot (top level mounted read-only meanwhile), packages and units
/// from the running system. Renders with the booted generation's id, so a generation built
/// from this exact manifest shows "no changes".
pub fn plan(
    runner: &dyn CommandRunner,
    layout: &Layout,
    manifest: &Manifest,
    facts: &MachineFacts,
    now: SystemTime,
) -> Result<Plan, ExecError> {
    let cmdline = fs::read_to_string(&layout.proc_cmdline)
        .map_err(|e| ExecError::io(&layout.proc_cmdline, e))?;
    let booted = gen_from_cmdline(&cmdline).ok_or_else(|| {
        ExecError::new(
            "cannot tell the booted generation: no single aios.gen= on the kernel cmdline",
        )
    })?;
    let ctx = facts.render_ctx(booted)?;
    let hashes = read_hashes(layout, manifest)?;
    with_top(runner, layout, true, |top| {
        let snapshot = top.subvol(&booted.etc_subvol());
        if !snapshot.is_dir() {
            return Err(ExecError(format!("{} is missing", snapshot.display())));
        }
        let probe = DirProbe::new(snapshot, runner, None);
        let inputs = Inputs {
            manifest,
            repo_root: &layout.config,
            ctx: &ctx,
            hashes: &hashes,
            today_days: days_since_epoch(now),
        };
        build_plan(&inputs, &probe).map_err(|e| ExecError(e.to_string()))
    })
}
