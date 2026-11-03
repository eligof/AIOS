use super::{read_ukis, with_top};
use crate::{run_ok, Cmd, CommandRunner, ExecError, Layout};
use aios_gen::{Flavor, GenId, UkiName};
use std::fs;
use std::io::ErrorKind;

/// Make generation `gen` the default boot entry (`bootctl set-default`, spec §4.2). Needs
/// its main-kernel UKI on the ESP, not marked bad (its boot counter ran out) unless
/// `force`, and both of its subvolumes, which are checked with the top level mounted
/// read-only: each must be a subvolume itself, not a symlink to one or a plain directory.
/// Returns the entry id. No subvolume is touched.
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
            let path = top.subvol(&name);
            let problem = match fs::symlink_metadata(&path) {
                Ok(meta) if meta.file_type().is_symlink() => "is a symlink, not a subvolume",
                Ok(meta) if !runner.is_subvolume_root(&meta) => "is not a subvolume",
                Ok(_) => continue,
                Err(e) if e.kind() == ErrorKind::NotFound => "is missing",
                Err(e) => return Err(ExecError::io(&path, e)),
            };
            return Err(ExecError(format!(
                "gen-{gen} is not installed: {name} {problem}"
            )));
        }
        Ok(())
    })?;
    run_ok(runner, &Cmd::new("bootctl").args(["set-default", &entry]))?;
    Ok(entry)
}
