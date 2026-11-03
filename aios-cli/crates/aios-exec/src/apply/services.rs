use super::Run;
use crate::{run_ok, unit_file_name, Cmd, ExecError};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// Units AIOS always enables (spec §4.3 step 7). `systemd-bless-boot.service` comes in
/// through `boot-complete.target`.
const CORE_UNITS: &[&str] = &["aios-health.service"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Want {
    Enable,
    Disable,
    Mask,
}

impl Run<'_> {
    /// `systemctl --root=<cand>` with one call per verb. A unit listed twice follows the
    /// planner: mask beats disable beats enable. Units that are masked but now wanted
    /// enabled or disabled are unmasked first, and `disable` skips units with no unit file
    /// (the planner treats them as already disabled).
    pub(super) fn services(&mut self) -> Result<(), ExecError> {
        let s = &self.ctx.manifest.services;
        let cand = &self.ctx.layout.cand;
        let mut wanted = BTreeMap::new();
        for (units, want) in [
            (&s.enable, Want::Enable),
            (&s.disable, Want::Disable),
            (&s.mask, Want::Mask),
        ] {
            for unit in units {
                wanted.insert(unit_file_name(unit), want);
            }
        }
        for unit in CORE_UNITS {
            wanted.insert(unit.to_string(), Want::Enable);
        }
        let select = |keep: &dyn Fn(&str, Want) -> bool| -> Vec<String> {
            wanted
                .iter()
                .filter(|(unit, want)| keep(unit, **want))
                .map(|(unit, _)| unit.clone())
                .collect()
        };
        let calls = [
            (
                "unmask",
                select(&|u, w| w != Want::Mask && is_masked(cand, u)),
            ),
            ("enable", select(&|_, w| w == Want::Enable)),
            (
                "disable",
                select(&|u, w| w == Want::Disable && has_unit_file(cand, u)),
            ),
            ("mask", select(&|_, w| w == Want::Mask)),
        ];
        for (verb, units) in calls {
            if !units.is_empty() {
                let cmd = Cmd::new("systemctl")
                    .arg(format!("--root={}", cand.display()))
                    .arg(verb)
                    .args(units);
                run_ok(self.ctx.runner, &cmd)?;
            }
        }
        Ok(())
    }
}

fn mask_link(path: &Path) -> bool {
    fs::read_link(path).is_ok_and(|target| target == Path::new("/dev/null"))
}

/// `etc/systemd/system/<unit>` is a symlink to `/dev/null`.
fn is_masked(cand: &Path, unit: &str) -> bool {
    mask_link(&cand.join("etc/systemd/system").join(unit))
}

/// The candidate has a unit file for `unit` (or, for `name@instance.type`, its template),
/// not counting mask links.
fn has_unit_file(cand: &Path, unit: &str) -> bool {
    let mut names = vec![unit.to_string()];
    if let Some((name, rest)) = unit.split_once('@') {
        if let Some((_, kind)) = rest.rsplit_once('.') {
            names.push(format!("{name}@.{kind}"));
        }
    }
    names.iter().any(|name| {
        ["etc/systemd/system", "usr/lib/systemd/system"]
            .iter()
            .map(|dir| cand.join(dir).join(name))
            .any(|path| fs::symlink_metadata(&path).is_ok() && !mask_link(&path))
    })
}
