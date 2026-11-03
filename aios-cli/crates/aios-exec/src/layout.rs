use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// GUID of the systemd-boot loader interface EFI variables.
const LOADER_GUID: &str = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f";

/// Every path aios reads or writes. `from_env` lets tests point all of them at a tempdir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    /// btrfs top level (`subvolid=5`) mount point. `AIOS_TOP`, default `/run/aios/top`.
    pub top: PathBuf,
    /// Candidate root during apply/bootstrap. `AIOS_CAND`, default `/run/aios/cand`.
    pub cand: PathBuf,
    /// ESP mount point. `AIOS_ESP`, default `/efi`.
    pub esp: PathBuf,
    /// Manifest git repo. `AIOS_CONFIG`, default `/persist/aios/config`.
    pub config: PathBuf,
    /// Secrets (`passwd/<user>`). `AIOS_SECRETS`, default `/persist/aios/secrets`.
    pub secrets: PathBuf,
    /// The `@persist` subvolume. `AIOS_PERSIST`, default `/persist`.
    pub persist: PathBuf,
    /// The `@home` subvolume. `AIOS_HOME`, default `/home`.
    pub home: PathBuf,
    /// The `@log` subvolume. `AIOS_LOG`, default `/var/log`.
    pub log: PathBuf,
    /// The running system's `/etc`, for drift. `AIOS_LIVE_ETC`, default `/etc`.
    pub live_etc: PathBuf,
    /// Kernel cmdline. `AIOS_CMDLINE`, default `/proc/cmdline`.
    pub proc_cmdline: PathBuf,
    /// efivarfs. `AIOS_EFIVARS`, default `/sys/firmware/efi/efivars`.
    pub efivars: PathBuf,
    /// flock file. `AIOS_LOCK`, default `/run/aios.lock`.
    pub lock: PathBuf,
    /// Unlocked LUKS device holding btrfs. `AIOS_DEVICE`, default `/dev/mapper/aios`.
    pub device: PathBuf,
}

impl Layout {
    /// The production layout, with any `AIOS_*` override from the environment.
    pub fn from_env() -> Layout {
        Layout::from_vars(|name| std::env::var_os(name))
    }

    /// Like `from_env`, reading variables through `var`.
    pub fn from_vars(var: impl Fn(&str) -> Option<OsString>) -> Layout {
        let path = |name: &str, default: &str| var(name).map_or_else(|| default.into(), Into::into);
        Layout {
            top: path("AIOS_TOP", "/run/aios/top"),
            cand: path("AIOS_CAND", "/run/aios/cand"),
            esp: path("AIOS_ESP", "/efi"),
            config: path("AIOS_CONFIG", "/persist/aios/config"),
            secrets: path("AIOS_SECRETS", "/persist/aios/secrets"),
            persist: path("AIOS_PERSIST", "/persist"),
            home: path("AIOS_HOME", "/home"),
            log: path("AIOS_LOG", "/var/log"),
            live_etc: path("AIOS_LIVE_ETC", "/etc"),
            proc_cmdline: path("AIOS_CMDLINE", "/proc/cmdline"),
            efivars: path("AIOS_EFIVARS", "/sys/firmware/efi/efivars"),
            lock: path("AIOS_LOCK", "/run/aios.lock"),
            device: path("AIOS_DEVICE", "/dev/mapper/aios"),
        }
    }

    /// Every path below `root` (named like its field), except `device`.
    pub fn under(root: &Path) -> Layout {
        Layout {
            top: root.join("top"),
            cand: root.join("cand"),
            esp: root.join("esp"),
            config: root.join("config"),
            secrets: root.join("secrets"),
            persist: root.join("persist"),
            home: root.join("home"),
            log: root.join("log"),
            live_etc: root.join("live-etc"),
            proc_cmdline: root.join("cmdline"),
            efivars: root.join("efivars"),
            lock: root.join("aios.lock"),
            device: PathBuf::from("/dev/mapper/aios"),
        }
    }

    pub fn manifest_path(&self) -> PathBuf {
        self.config.join("manifest.toml")
    }

    /// A subvolume in the top level, e.g. `@usr-gen-0007`.
    pub fn subvol(&self, name: &str) -> PathBuf {
        self.top.join(name)
    }

    /// Where UKIs live on the ESP.
    pub fn uki_dir(&self) -> PathBuf {
        self.esp.join("EFI/Linux")
    }

    /// The `LoaderEntryDefault` EFI variable (`bootctl set-default`).
    pub fn loader_entry_default(&self) -> PathBuf {
        self.efivars
            .join(format!("LoaderEntryDefault-{LOADER_GUID}"))
    }

    /// Local pacman repo, bound into the candidate at `/persist/aios/repo`.
    pub fn repo(&self) -> PathBuf {
        self.persist.join("aios/repo")
    }

    /// Persisted pacman cache, bound into the candidate.
    pub fn pkg_cache(&self) -> PathBuf {
        self.persist.join("var/cache/pacman/pkg")
    }

    /// `secrets/passwd/<user>`.
    pub fn passwd_secret(&self, user: &str) -> PathBuf {
        self.secrets.join("passwd").join(user)
    }

    /// Map an absolute `/persist/...` path onto `persist`.
    pub fn persist_path(&self, abs: &str) -> PathBuf {
        let rel = abs.strip_prefix("/persist").unwrap_or(abs);
        self.persist.join(rel.trim_start_matches('/'))
    }
}
