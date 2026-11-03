//! Shared fixtures: a whole machine in a tempdir plus a scripted `FakeRunner`. Each test
//! binary uses a different subset, hence the `allow`.
#![allow(dead_code)]

use aios_exec::StepError;
use aios_exec::{apply, ApplyCtx, ApplyOutcome, FakeRunner, Layout, MachineFacts, Mode, Output};
use aios_gen::GenId;
use aios_manifest::{parse, Manifest};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
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
"/etc/pacman.conf" = { source = "files/pacman.conf" }
"/etc/nftables.conf" = { source = "files/nftables.conf", mode = "0600" }
"/etc/usbguard/usbguard-daemon.conf" = { source = "files/usbguard-daemon.conf", mode = "0600", group = "wheel" }
"/etc/pacman.d/hooks/90-mkinitcpio-install.hook" = { symlink = "/dev/null" }

[persist]
directories = ["/var/lib/NetworkManager", "/var/cache/pacman/pkg"]
files = ["/etc/machine-id"]

[users.eli]
uid = 1000
groups = ["wheel"]
shell = "/usr/bin/zsh"

[users.eli.home]
".zshrc" = "home/eli/zshrc"
".config/autostart/" = "home/eli/autostart/"
".ssh/authorized_keys" = "home/eli/authorized_keys"
"#;

pub const PACMAN_CONF: &str = "[options]
DBPath       = /usr/lib/pacman/
CacheDir     = /var/cache/pacman/pkg/
LogFile      = /var/log/pacman.log
SigLevel     = Required DatabaseOptional

[aios-local]
SigLevel = Optional TrustAll
Server = file:///persist/aios/repo

[core]
Include = /etc/pacman.d/mirrorlist
";

pub const LUKS_UUID: &str = "0b6c2e7f-5d0a-4c2e-9a71-3f1d2c4b5a69";
pub const ESP_UUID: &str = "7A1B-2C3D";
pub const HARDENING: &str = "init_on_alloc=1 quiet\n";
pub const ELI_HASH: &str = "$y$j9T$salt$hash";
pub const BOOTED: GenId = GenId(7);
/// What `pacman -Q <kernels>` prints in the candidate.
pub const KERNELS: &str = "linux-cachyos 7.3.0-4\nlinux-cachyos-lts 6.18.55-2\n";
/// What `pacman -Qq` prints in the candidate (deliberately unsorted).
pub const ALL_PACKAGES: &str = "zsh\nbase\nlinux-cachyos\n";

/// 2026-11-03T21:14:05Z.
pub fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_793_740_445)
}

pub fn facts() -> MachineFacts {
    MachineFacts {
        hardening_cmdline: HARDENING.to_string(),
        luks_uuid: LUKS_UUID.to_string(),
        esp_uuid: ESP_UUID.to_string(),
    }
}

/// The cmdline gen-7 booted with.
pub fn booted_cmdline() -> String {
    format!("rd.luks.name={LUKS_UUID}=aios root=/dev/mapper/aios rw aios.gen=0007 quiet\n")
}

pub fn write(path: &Path, content: &str, mode: u32) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

pub fn mkdir(path: &Path) {
    fs::create_dir_all(path).unwrap();
}

/// A machine in a tempdir. `runner` emulates subvolumes as directories and answers the
/// queries apply makes. The candidate tree (`cand/`) is pre-populated with what the
/// package manager would have left there: account files, kernel modules, a unit file, and
/// the UKIs `ukify` would build.
pub struct Fixture {
    pub dir: TempDir,
    pub layout: Layout,
    pub manifest: Manifest,
    pub facts: MachineFacts,
    pub runner: FakeRunner,
    pub mode: Mode,
    /// Owner `check_trusted_dirs` requires: whoever runs the tests.
    pub trusted_uid: u32,
}

impl Fixture {
    /// An installed machine that booted gen-7; gen-6 and gen-7 exist. Apply builds gen-8.
    pub fn booted() -> Fixture {
        let fx = Fixture::machine(MANIFEST, Mode::Apply { booted: BOOTED }, GenId(8));
        let l = &fx.layout;
        for gen in ["0006", "0007"] {
            mkdir(&l.subvol(&format!("@usr-gen-{gen}")));
            mkdir(&l.subvol(&format!("@etc-gen-{gen}")));
            write(
                &l.uki_dir().join(format!("aios-gen-{gen}-cachyos.efi")),
                "old",
                0o644,
            );
        }
        write(&l.proc_cmdline, &booted_cmdline(), 0o644);
        // gen-7 managed a file this manifest no longer has.
        write(
            &l.cand.join("etc/aios/managed-files"),
            "/etc/old.conf\n",
            0o644,
        );
        write(&l.cand.join("etc/old.conf"), "old\n", 0o644);
        fx
    }

    /// An installer target: the top level holds only `@blank`. Bootstrap builds gen-1.
    pub fn fresh() -> Fixture {
        let fx = Fixture::machine(MANIFEST, Mode::Bootstrap, GenId(1));
        write(
            &fx.layout.proc_cmdline,
            "archisobasedir=arch quiet\n",
            0o644,
        );
        fx
    }

    fn machine(manifest: &str, mode: Mode, gen: GenId) -> Fixture {
        let dir = TempDir::new().unwrap();
        let layout = Layout::under(dir.path());
        let l = &layout;
        write(&l.manifest_path(), manifest, 0o644);
        write(&l.config.join("files/pacman.conf"), PACMAN_CONF, 0o644);
        write(
            &l.config.join("files/nftables.conf"),
            "flush ruleset\n",
            0o644,
        );
        write(
            &l.config.join("files/usbguard-daemon.conf"),
            "RuleFile=x\n",
            0o644,
        );
        write(&l.config.join("home/eli/zshrc"), "# zshrc\n", 0o644);
        write(&l.config.join("home/eli/authorized_keys"), "", 0o644);
        write(
            &l.config.join("home/eli/autostart/hello.desktop"),
            "[Desktop Entry]\n",
            0o644,
        );
        write(&l.passwd_secret("eli"), &format!("{ELI_HASH}\n"), 0o600);
        fs::set_permissions(&l.config, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&l.secrets, fs::Permissions::from_mode(0o700)).unwrap();
        mkdir(&l.subvol("@blank"));
        mkdir(&l.home);
        mkdir(&l.esp);
        let etc = l.cand.join("etc");
        write(
            &etc.join("passwd"),
            "root:x:0:0::/root:/usr/bin/bash\n",
            0o644,
        );
        write(&etc.join("group"), "root:x:0:root\nwheel:x:998:\n", 0o644);
        write(&etc.join("shadow"), "root:*:20000::::::\n", 0o600);
        write(&etc.join("gshadow"), "root:::root\nwheel:!*::\n", 0o600);
        let modules = l.cand.join("usr/lib/modules");
        write(
            &modules.join("7.3.0-4-cachyos/pkgbase"),
            "linux-cachyos\n",
            0o644,
        );
        write(
            &modules.join("6.18.55-2-cachyos-lts/pkgbase"),
            "linux-cachyos-lts\n",
            0o644,
        );
        mkdir(&modules.join("6.1.0-old/kernel"));
        write(
            &l.cand.join("usr/lib/systemd/system/bluetooth.service"),
            "[Unit]\n",
            0o644,
        );
        for flavor in ["cachyos", "lts"] {
            let uki = format!("var/tmp/aios/aios-gen-{gen}-{flavor}.efi");
            write(&l.cand.join(uki), &format!("UKI {flavor}"), 0o644);
        }
        let manifest = parse(manifest).expect("fixture manifest parses");
        let mut runner = FakeRunner::new();
        let cand = l.cand.display().to_string();
        let explicit = format!("{}\nnano\n", manifest.package_set().join("\n"));
        runner
            .emulate_subvolumes()
            .emulate_top_mounts(&l.top)
            .respond(&git(&l.config, &["rev-parse"]), Output::ok("3f9c2a1\n"))
            .respond(
                &["arch-chroot", &cand, "pacman", "-Qqe"],
                Output::ok(explicit),
            )
            .respond(
                &["arch-chroot", &cand, "pacman", "-Qdtq"],
                Output::ok("libnano\n"),
            )
            .respond(&["arch-chroot", &cand, "pacman", "-Q"], Output::ok(KERNELS))
            .respond(
                &["arch-chroot", &cand, "pacman", "-Qq"],
                Output::ok(ALL_PACKAGES),
            )
            .respond(&["df"], Output::ok("     Avail\n2000000000\n"));
        Fixture {
            trusted_uid: fs::metadata(dir.path()).unwrap().uid(),
            facts: facts(),
            manifest,
            runner,
            mode,
            layout,
            dir,
        }
    }

    /// Replace the manifest (written to the repo too).
    pub fn set_manifest(&mut self, raw: &str) {
        write(&self.layout.manifest_path(), raw, 0o644);
        self.manifest = parse(raw).expect("test manifest parses");
    }

    pub fn ctx(&self) -> ApplyCtx<'_> {
        ApplyCtx {
            runner: &self.runner,
            layout: &self.layout,
            manifest: &self.manifest,
            facts: &self.facts,
            now: now(),
            mode: self.mode,
            trusted_uid: self.trusted_uid,
        }
    }

    pub fn run(&self) -> Result<ApplyOutcome, StepError> {
        apply(&self.ctx())
    }

    /// The calls so far, with paths written as `{top}`, `{cand}`, ... (see `expand`).
    pub fn calls(&self) -> Vec<String> {
        let mut calls = self.runner.calls();
        for (key, value) in self.placeholders() {
            for call in &mut calls {
                *call = call.replace(&value, key);
            }
        }
        calls
    }

    /// `{top}`, `{cand}`, `{config}`, `{persist}`, `{log}`, `{home}`, `{esp}`, `{ro}`
    /// (where readers mount the top level) and `{run}` (the tempdir root) replaced by
    /// their paths; `{set}` by the package set. One entry per non-empty line.
    pub fn expand(&self, text: &str) -> Vec<String> {
        let set = self.manifest.package_set().join(" ");
        text.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(|l| l.replace("{set}", &set))
            .collect()
    }

    /// Longest paths first, so `{top}` never eats part of `{cand}`.
    fn placeholders(&self) -> Vec<(&'static str, String)> {
        let l = &self.layout;
        let mut pairs = vec![
            ("{top}", l.top.display().to_string()),
            ("{cand}", l.cand.display().to_string()),
            ("{config}", l.config.display().to_string()),
            ("{persist}", l.persist.display().to_string()),
            ("{log}", l.log.display().to_string()),
            ("{home}", l.home.display().to_string()),
            ("{esp}", l.esp.display().to_string()),
            ("{run}", self.dir.path().display().to_string()),
            ("{ro}", l.ro_top().display().to_string()),
        ];
        pairs.sort_by_key(|(_, path)| std::cmp::Reverse(path.len()));
        pairs
    }

    /// Calls made after the first call starting with `failing` (placeholder form).
    pub fn calls_after(&self, failing: &str) -> Vec<String> {
        let calls = self.calls();
        let at = calls
            .iter()
            .position(|c| c.starts_with(failing))
            .unwrap_or_else(|| panic!("no call starts with {failing:?} in {calls:#?}"));
        calls[at + 1..].to_vec()
    }

    /// No candidate subvolume is left in the top level.
    pub fn assert_no_candidates(&self) {
        for name in ["@usr-cand", "@etc-cand", "@root-cand"] {
            assert!(!self.layout.subvol(name).exists(), "{name} left behind");
        }
    }
}

/// `git -C CONFIG <the -c options aios always passes> ARGS...`, as a `respond` prefix.
pub fn git<'a>(config: &'a Path, args: &[&'a str]) -> Vec<&'a str> {
    let config = config.to_str().expect("tempdir paths are UTF-8");
    let mut argv = vec!["git", "-C", config];
    argv.extend([
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "commit.gpgsign=false",
    ]);
    argv.extend(args);
    argv
}

/// The cleanup after a failure once the candidate tree is mounted (apply mode).
pub const CLEANUP_MOUNTED: &str = "
umount -R {cand}
btrfs subvolume show {top}/@usr-cand
btrfs subvolume delete --recursive {top}/@usr-cand
btrfs subvolume show {top}/@etc-cand
btrfs subvolume delete --recursive {top}/@etc-cand
btrfs subvolume show {top}/@root-cand
btrfs subvolume delete --recursive {top}/@root-cand
umount {top}
";
