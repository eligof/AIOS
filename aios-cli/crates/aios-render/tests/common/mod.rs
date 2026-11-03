//! Shared fixtures. Each test binary uses a different subset, hence the `allow`.
#![allow(dead_code)]

use aios_gen::GenId;
use aios_manifest::{parse, Manifest};
use aios_render::RenderCtx;

/// Phase 1's VALID manifest plus a console token, persisted files and a second group.
pub const MANIFEST: &str = r#"[system]
hostname = "nightcity"
timezone = "Asia/Jerusalem"
locale = "en_US.UTF-8"
keymap = "us"

[kernel]
default = "linux-cachyos"
fallback = "linux-cachyos-lts"
lockdown = "integrity"
extra_cmdline = ["console=ttyS0,115200"]

[packages]
install = ["base", "zsh", "git"]

[services]
enable = ["NetworkManager"]

[files]
"/etc/nftables.conf" = { source = "files/nftables.conf", mode = "0600" }
"/etc/pacman.d/hooks/90-mkinitcpio-install.hook" = { symlink = "/dev/null" }

[persist]
directories = ["/var/lib/NetworkManager", "/var/cache/pacman/pkg"]
files = ["/etc/machine-id", "/var/lib/systemd/random-seed"]

[users.eli]
uid = 1000
groups = ["wheel", "video"]
shell = "/usr/bin/zsh"

[users.eli.home]
".zshrc" = "home/eli/zshrc"
".config/autostart/" = "home/eli/autostart/"
"#;

/// `/usr/lib/aios/cmdline-hardening` (spec §5.3), with its trailing newline.
pub const HARDENING: &str = "init_on_alloc=1 init_on_free=1 slab_nomerge page_alloc.shuffle=1 randomize_kstack_offset=on vsyscall=none debugfs=off lsm=landlock,lockdown,yama,integrity,apparmor,bpf quiet\n";

pub fn manifest() -> Manifest {
    manifest_from(MANIFEST)
}

pub fn manifest_from(raw: &str) -> Manifest {
    parse(raw).expect("fixture manifest parses")
}

pub fn ctx() -> RenderCtx {
    RenderCtx {
        gen: GenId(7),
        luks_uuid: "0b6c2e7f-5d0a-4c2e-9a71-3f1d2c4b5a69".to_string(),
        esp_uuid: "7A1B-2C3D".to_string(),
        hardening_cmdline: HARDENING.to_string(),
    }
}
