use crate::sentinel::Sentinel;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

/// Packages AIOS always installs, whatever the manifest says (spec §4.6).
pub const CORE_PACKAGES: &[&str] = &[
    "base",
    "aios-cli",
    "aios-base",
    "btrfs-progs",
    "cryptsetup",
    "dosfstools",
    "tpm2-tss",
    "sbctl",
    "systemd-ukify",
    "mkinitcpio",
    "nftables",
    "usbguard",
    "apparmor",
    "zram-generator",
    "fwupd",
    "polkit",
];

/// Kernel packages the manifest may name in `[kernel]`.
pub const KNOWN_KERNELS: &[&str] = &["linux-cachyos", "linux-cachyos-lts", "linux", "linux-lts"];

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub system: System,
    pub kernel: Kernel,
    #[serde(default)]
    pub packages: Packages,
    #[serde(default)]
    pub services: Services,
    #[serde(default)]
    pub files: BTreeMap<String, FileEntry>,
    #[serde(default)]
    pub persist: Persist,
    #[serde(default)]
    pub users: BTreeMap<String, User>,
    /// `Option`, not a defaulted value: §11.2 warns when Sentinel is disabled,
    /// and the planner has to tell "the manifest said nothing" from "the
    /// manifest asked for the defaults explicitly".
    #[serde(default)]
    pub sentinel: Option<Sentinel>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct System {
    pub hostname: String,
    pub timezone: String,
    pub locale: String,
    pub keymap: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Lockdown {
    #[default]
    Integrity,
    None,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Kernel {
    pub default: String,
    #[serde(default)]
    pub fallback: Option<String>,
    #[serde(default)]
    pub lockdown: Lockdown,
    #[serde(default)]
    pub extra_cmdline: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Packages {
    #[serde(default)]
    pub install: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Services {
    #[serde(default)]
    pub enable: Vec<String>,
    #[serde(default)]
    pub disable: Vec<String>,
    #[serde(default)]
    pub mask: Vec<String>,
}

/// One managed file under `/etc`. Exactly one of `source` or `symlink` must be set.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileEntry {
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub symlink: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub group: Option<String>,
}

impl FileEntry {
    pub fn mode_or_default(&self) -> &str {
        self.mode.as_deref().unwrap_or("0644")
    }

    pub fn owner_or_default(&self) -> &str {
        self.owner.as_deref().unwrap_or("root")
    }

    pub fn group_or_default(&self) -> &str {
        self.group.as_deref().unwrap_or("root")
    }
}

#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Persist {
    #[serde(default)]
    pub directories: Vec<String>,
    #[serde(default)]
    pub files: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub uid: u32,
    #[serde(default)]
    pub groups: Vec<String>,
    pub shell: String,
    /// Home-relative target path -> manifest-repo-relative source. A trailing `/` marks a directory.
    #[serde(default)]
    pub home: BTreeMap<String, String>,
}

impl Manifest {
    /// Full explicit package set: core + kernels + `[packages].install`, sorted and deduplicated.
    pub fn package_set(&self) -> Vec<String> {
        let mut set: BTreeSet<String> = CORE_PACKAGES.iter().map(|p| p.to_string()).collect();
        set.insert(self.kernel.default.clone());
        if let Some(fallback) = &self.kernel.fallback {
            set.insert(fallback.clone());
        }
        set.extend(self.packages.install.iter().cloned());
        set.into_iter().collect()
    }
}
