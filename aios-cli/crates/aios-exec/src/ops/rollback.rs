use super::read_ukis;
use crate::{run_ok, Cmd, CommandRunner, ExecError, Layout};
use aios_gen::{Flavor, GenId};

/// Make generation `gen` the default boot entry (`bootctl set-default`, spec §4.2). Needs
/// its main-kernel UKI on the ESP. Returns the entry id. No subvolume is touched.
pub fn rollback(
    runner: &dyn CommandRunner,
    layout: &Layout,
    gen: GenId,
) -> Result<String, ExecError> {
    let entry = read_ukis(&layout.uki_dir())?
        .into_iter()
        .find(|u| u.name.gen == gen && u.name.flavor == Flavor::Main)
        .map(|u| u.name.entry_id())
        .ok_or_else(|| ExecError(format!("no boot entry for gen-{gen}")))?;
    run_ok(runner, &Cmd::new("bootctl").args(["set-default", &entry]))?;
    Ok(entry)
}
