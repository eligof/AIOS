use super::{read_ukis, with_top};
use crate::{run_ok, Cmd, CommandRunner, ExecError, Layout};
use aios_gen::{Flavor, GenId, UkiName};

/// Make generation `gen` the default boot entry (`bootctl set-default`, spec §4.2). Needs
/// its main-kernel UKI on the ESP, not marked bad (its boot counter ran out) unless
/// `force`, and both of its subvolumes, which are checked with the top level mounted
/// read-only. Returns the entry id. No subvolume is touched.
pub fn rollback(
    runner: &dyn CommandRunner,
    layout: &Layout,
    gen: GenId,
    force: bool,
) -> Result<String, ExecError> {
    let mains: Vec<UkiName> = read_ukis(&layout.uki_dir())?
        .into_iter()
        .map(|u| u.name)
        .filter(|name| name.gen == gen && name.flavor == Flavor::Main)
        .collect();
    let entry = mains
        .first()
        .map(UkiName::entry_id)
        .ok_or_else(|| ExecError(format!("no boot entry for gen-{gen}")))?;
    if !force && mains.iter().any(UkiName::is_bad) {
        return Err(ExecError(format!(
            "gen-{gen} is marked bad (its boot tries ran out); use --force to boot it anyway"
        )));
    }
    with_top(runner, layout, true, |top| {
        for name in [gen.usr_subvol(), gen.etc_subvol()] {
            if !top.subvol(&name).is_dir() {
                return Err(ExecError(format!(
                    "gen-{gen} is not installed: {name} is missing"
                )));
            }
        }
        Ok(())
    })?;
    run_ok(runner, &Cmd::new("bootctl").args(["set-default", &entry]))?;
    Ok(entry)
}
