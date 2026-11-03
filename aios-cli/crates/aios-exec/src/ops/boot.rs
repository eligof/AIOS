use crate::{parse_efivar_utf16, ExecError, Layout};
use aios_gen::{gen_from_cmdline, Flavor, GenId, UkiName};
use std::fs;
use std::io::ErrorKind;
use std::path::Path;

/// One UKI on the ESP: its file name and what it parses to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EspUki {
    pub file: String,
    pub name: UkiName,
}

/// What booted and what will boot next, from the cmdline, the ESP and the EFI variables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootState {
    /// `aios.gen=` of the running kernel.
    pub booted: Option<GenId>,
    /// The `bootctl set-default` override (`LoaderEntryDefault`), if it names an aios UKI.
    pub default_override: Option<GenId>,
    /// Newest generation with a main-kernel UKI that isn't bad: what `loader.conf` picks.
    pub newest: Option<GenId>,
    /// Every aios UKI on the ESP, by file name.
    pub ukis: Vec<EspUki>,
}

impl BootState {
    pub fn read(layout: &Layout) -> Result<BootState, ExecError> {
        let booted = fs::read_to_string(&layout.proc_cmdline)
            .ok()
            .and_then(|cmdline| gen_from_cmdline(&cmdline));
        let default_override = fs::read(layout.loader_entry_default())
            .ok()
            .and_then(|bytes| parse_efivar_utf16(&bytes))
            .and_then(|entry| UkiName::parse(&entry))
            .map(|uki| uki.gen);
        let ukis = read_ukis(&layout.uki_dir())?;
        let newest = ukis
            .iter()
            .filter(|u| u.name.flavor == Flavor::Main && !u.name.is_bad())
            .map(|u| u.name.gen)
            .max();
        Ok(BootState {
            booted,
            default_override,
            newest,
            ukis,
        })
    }

    /// The generation the next boot picks: the override, else the newest good one.
    pub fn default_gen(&self) -> Option<GenId> {
        self.default_override.or(self.newest)
    }

    /// Generations with a UKI whose boot counter ran out, ascending.
    pub fn bad(&self) -> Vec<GenId> {
        let mut bad: Vec<GenId> = self
            .ukis
            .iter()
            .filter(|u| u.name.is_bad())
            .map(|u| u.name.gen)
            .collect();
        bad.sort();
        bad.dedup();
        bad
    }
}

/// The aios UKIs in `dir`, sorted by file name. A missing directory has none.
pub fn read_ukis(dir: &Path) -> Result<Vec<EspUki>, ExecError> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(ExecError::io(dir, e)),
    };
    let mut ukis = Vec::new();
    for entry in entries {
        let file = entry
            .map_err(|e| ExecError::io(dir, e))?
            .file_name()
            .to_string_lossy()
            .into_owned();
        if let Some(name) = UkiName::parse(&file) {
            ukis.push(EspUki { file, name });
        }
    }
    ukis.sort_by(|a, b| a.file.cmp(&b.file));
    Ok(ukis)
}
