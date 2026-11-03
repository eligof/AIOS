//! Shared planner fixtures. Each test binary uses a different subset, hence the `allow`.
#![allow(dead_code)]

use aios_gen::GenId;
use aios_manifest::{parse, Manifest};
use aios_plan::{desired_etc, EtcEntry, Inputs, ProbeError, SystemProbe, UnitState};
use aios_render::RenderCtx;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tempfile::TempDir;

pub const MANIFEST: &str = r#"[system]
hostname = "nightcity"
timezone = "Asia/Jerusalem"
locale = "en_US.UTF-8"
keymap = "us"

[kernel]
default = "linux-cachyos"
fallback = "linux-cachyos-lts"
lockdown = "integrity"
extra_cmdline = []

[packages]
install = ["base", "zsh", "git"]

[services]
enable = ["NetworkManager", "fwupd-refresh.timer"]
disable = ["bluetooth"]
mask = ["sshd.socket"]

[files]
"/etc/nftables.conf" = { source = "files/nftables.conf", mode = "0600" }
"/etc/pacman.d/hooks/90-mkinitcpio-install.hook" = { symlink = "/dev/null" }

[persist]
directories = ["/var/lib/NetworkManager", "/var/cache/pacman/pkg"]
files = []

[users.eli]
uid = 1000
groups = ["wheel"]
shell = "/usr/bin/zsh"

[users.eli.home]
".zshrc" = "home/eli/zshrc"
".local/bin/" = "home/eli/bin/"
"#;

/// Account files as pacstrap leaves them, before aios merges users.
pub const BASE_PASSWD: &str = "root:x:0:0::/root:/usr/bin/bash
nobody:x:65534:65534:Kernel Overflow User:/:/usr/bin/nologin
";
pub const BASE_GROUP: &str = "root:x:0:root\nwheel:x:998:\nnobody:x:65534:\n";
pub const BASE_SHADOW: &str = "root:*:20000::::::\nnobody:!*:20000::::::\n";
pub const BASE_GSHADOW: &str = "root:::root\nwheel:!*::\nnobody:!*::\n";

/// 2026-11-03 in days since the epoch.
pub const TODAY: u64 = 20760;
pub const ELI_HASH: &str = "$y$j9T$salt$hash";

/// A manifest repo in a tempdir plus everything else `Inputs` borrows.
pub struct Fixture {
    pub repo: TempDir,
    pub manifest: Manifest,
    pub ctx: RenderCtx,
    pub hashes: BTreeMap<String, String>,
}

impl Fixture {
    pub fn inputs(&self) -> Inputs<'_> {
        Inputs {
            manifest: &self.manifest,
            repo_root: self.repo.path(),
            ctx: &self.ctx,
            hashes: &self.hashes,
            today_days: TODAY,
        }
    }
}

pub fn fixture() -> Fixture {
    fixture_with(MANIFEST)
}

/// Repo layout: files/nftables.conf, home/eli/zshrc, home/eli/bin/{hello, lib/util.sh}.
pub fn fixture_with(raw: &str) -> Fixture {
    let repo = TempDir::new().unwrap();
    write(repo.path(), "files/nftables.conf", "flush ruleset\n", 0o644);
    write(repo.path(), "home/eli/zshrc", "# zshrc\n", 0o644);
    write(
        repo.path(),
        "home/eli/bin/hello",
        "#!/bin/sh\necho hello\n",
        0o755,
    );
    write(
        repo.path(),
        "home/eli/bin/lib/util.sh",
        "util() { :; }\n",
        0o700,
    );
    Fixture {
        repo,
        manifest: parse(raw).expect("fixture manifest parses"),
        ctx: RenderCtx {
            gen: GenId(1),
            luks_uuid: "0b6c2e7f-5d0a-4c2e-9a71-3f1d2c4b5a69".to_string(),
            esp_uuid: "7A1B-2C3D".to_string(),
            hardening_cmdline: "init_on_alloc=1 quiet\n".to_string(),
        },
        hashes: BTreeMap::from([("eli".to_string(), ELI_HASH.to_string())]),
    }
}

pub fn write(root: &Path, rel: &str, content: &str, mode: u32) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, content).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
}

pub fn text_file(text: &str, mode: u32) -> EtcEntry {
    EtcEntry::File {
        content: text.as_bytes().to_vec(),
        mode,
    }
}

/// In-memory booted generation. Unknown units are `NotFound`.
#[derive(Debug, Clone, Default)]
pub struct FakeProbe {
    pub packages: BTreeSet<String>,
    pub etc: BTreeMap<String, EtcEntry>,
    pub units: BTreeMap<String, UnitState>,
    /// When set, every call fails with this message.
    pub fail: Option<String>,
}

impl FakeProbe {
    /// A booted system with only pacstrap's account files in `/etc`.
    pub fn base() -> FakeProbe {
        let mut probe = FakeProbe::default();
        for (path, text, mode) in [
            ("/etc/passwd", BASE_PASSWD, 0o644),
            ("/etc/group", BASE_GROUP, 0o644),
            ("/etc/shadow", BASE_SHADOW, 0o600),
            ("/etc/gshadow", BASE_GSHADOW, 0o600),
        ] {
            probe.etc.insert(path.to_string(), text_file(text, mode));
        }
        probe
    }

    /// A booted generation built from exactly this fixture: the planner must see no changes.
    pub fn synced(fx: &Fixture) -> FakeProbe {
        let mut probe = FakeProbe::base();
        probe.etc = desired_etc(&fx.inputs(), &probe).expect("desired state renders");
        probe.packages = fx.manifest.package_set().into_iter().collect();
        let services = &fx.manifest.services;
        for (units, state) in [
            (&services.enable, UnitState::Enabled),
            (&services.disable, UnitState::Disabled),
            (&services.mask, UnitState::Masked),
        ] {
            for unit in units {
                let name = if unit.contains('.') {
                    unit.clone()
                } else {
                    format!("{unit}.service")
                };
                probe.units.insert(name, state);
            }
        }
        probe
    }

    fn check(&self) -> Result<(), ProbeError> {
        match &self.fail {
            Some(message) => Err(ProbeError(message.clone())),
            None => Ok(()),
        }
    }
}

impl SystemProbe for FakeProbe {
    fn explicit_packages(&self) -> Result<BTreeSet<String>, ProbeError> {
        self.check()?;
        Ok(self.packages.clone())
    }

    fn etc_entry(&self, path: &str) -> Result<Option<EtcEntry>, ProbeError> {
        self.check()?;
        Ok(self.etc.get(path).cloned())
    }

    fn unit_state(&self, unit: &str) -> Result<UnitState, ProbeError> {
        self.check()?;
        Ok(self.units.get(unit).copied().unwrap_or(UnitState::NotFound))
    }
}
