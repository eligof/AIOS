use crate::{desired_etc, EtcEntry, Inputs, PlanError, SystemProbe, UnitState, MANAGED_FILES};
use aios_manifest::Lockdown;
use aios_render::parse_managed_list;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Printed whenever the manifest turns kernel lockdown off (spec §5.4).
pub const LOCKDOWN_NONE_WARNING: &str =
    "kernel.lockdown = \"none\": unsigned kernel modules can be loaded";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    Add,
    Modify,
    Remove,
}

impl ChangeKind {
    fn marker(self) -> char {
        match self {
            ChangeKind::Add => '+',
            ChangeKind::Modify => '~',
            ChangeKind::Remove => '-',
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EtcChange {
    pub path: String,
    pub kind: ChangeKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitChange {
    pub unit: String,
    pub from: UnitState,
    pub to: UnitState,
}

/// What `aios apply` would change relative to the booted generation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Plan {
    pub packages_add: Vec<String>,
    pub packages_remove: Vec<String>,
    pub etc_changes: Vec<EtcChange>,
    pub unit_changes: Vec<UnitChange>,
    pub warnings: Vec<String>,
}

impl Plan {
    /// True when there is nothing to apply. Warnings don't count.
    pub fn is_empty(&self) -> bool {
        self.packages_add.is_empty()
            && self.packages_remove.is_empty()
            && self.etc_changes.is_empty()
            && self.unit_changes.is_empty()
    }
}

/// Diff the manifest against the booted generation.
///
/// - Packages: the manifest's package set against `pacman -Qqe`.
/// - `/etc`: [`desired_etc`] against the booted snapshot; paths listed in its
///   `managed-files` that are no longer desired are removals.
/// - Units: `enable`/`disable`/`mask`, with `mask` beating `disable` beating `enable` for a
///   unit listed twice. `static` satisfies `enable`; `static` and `not-found` satisfy `disable`.
pub fn build_plan(inputs: &Inputs, probe: &dyn SystemProbe) -> Result<Plan, PlanError> {
    let m = inputs.manifest;

    let want: BTreeSet<String> = m.package_set().into_iter().collect();
    let have = probe.explicit_packages()?;
    let packages_add = want.difference(&have).cloned().collect();
    let packages_remove = have.difference(&want).cloned().collect();

    let desired = desired_etc(inputs, probe)?;
    let mut etc_changes = Vec::new();
    for (path, entry) in &desired {
        let kind = match probe.etc_entry(path)? {
            None => Some(ChangeKind::Add),
            Some(current) if current != *entry => Some(ChangeKind::Modify),
            Some(_) => None,
        };
        if let Some(kind) = kind {
            etc_changes.push(EtcChange {
                path: path.clone(),
                kind,
            });
        }
    }
    if let Some(EtcEntry::File { content, .. }) = probe.etc_entry(MANAGED_FILES)? {
        for path in parse_managed_list(&String::from_utf8_lossy(&content)) {
            if !desired.contains_key(&path) {
                etc_changes.push(EtcChange {
                    path,
                    kind: ChangeKind::Remove,
                });
            }
        }
    }
    etc_changes.sort_by(|a, b| a.path.cmp(&b.path));

    let services = &m.services;
    let mut wanted: BTreeMap<String, UnitState> = BTreeMap::new();
    for (units, state) in [
        (&services.enable, UnitState::Enabled),
        (&services.disable, UnitState::Disabled),
        (&services.mask, UnitState::Masked),
    ] {
        for unit in units {
            wanted.insert(unit_name(unit), state);
        }
    }
    let mut unit_changes = Vec::new();
    for (unit, to) in wanted {
        let from = probe.unit_state(&unit)?;
        if !satisfied(from, to) {
            unit_changes.push(UnitChange { unit, from, to });
        }
    }

    let mut warnings = Vec::new();
    if m.kernel.lockdown == Lockdown::None {
        warnings.push(LOCKDOWN_NONE_WARNING.to_string());
    }

    Ok(Plan {
        packages_add,
        packages_remove,
        etc_changes,
        unit_changes,
        warnings,
    })
}

/// `NetworkManager` -> `NetworkManager.service`. Names with a type suffix are kept.
fn unit_name(name: &str) -> String {
    if name.contains('.') {
        name.to_string()
    } else {
        format!("{name}.service")
    }
}

fn satisfied(from: UnitState, to: UnitState) -> bool {
    from == to
        || matches!(
            (to, from),
            (UnitState::Enabled, UnitState::Static)
                | (UnitState::Disabled, UnitState::Static | UnitState::NotFound)
        )
}

impl fmt::Display for Plan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            writeln!(f, "no changes")?;
        }
        if !self.packages_add.is_empty() || !self.packages_remove.is_empty() {
            writeln!(f, "packages:")?;
            for name in &self.packages_add {
                writeln!(f, "  + {name}")?;
            }
            for name in &self.packages_remove {
                writeln!(f, "  - {name}")?;
            }
        }
        if !self.etc_changes.is_empty() {
            writeln!(f, "/etc:")?;
            for change in &self.etc_changes {
                writeln!(f, "  {} {}", change.kind.marker(), change.path)?;
            }
        }
        if !self.unit_changes.is_empty() {
            writeln!(f, "services:")?;
            for change in &self.unit_changes {
                writeln!(f, "  {}: {} -> {}", change.unit, change.from, change.to)?;
            }
        }
        for warning in &self.warnings {
            writeln!(f, "warning: {warning}")?;
        }
        Ok(())
    }
}
