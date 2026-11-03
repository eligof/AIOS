# AIOS Sub-project 1 — Base ISO Design

Date: 2026-11-03
Status: Sections 1–2 approved section by section during brainstorming. Sections 3–11 were written by Claude under the user's `/goal` delegation ("finish this project") using the recommended defaults.
Parent: `2026-11-03-aios-vision.md`

## 1. Goal

A bootable Arch-based ISO that installs AIOS onto a disk, giving a hardened host with NixOS-style guarantees:

1. **Generations:** the system (`/usr` + `/etc`) exists only as numbered, read-only btrfs snapshots.
2. **Impermanence:** every boot starts from an empty root. Only declared state survives.
3. **One way to change the system:** edit `manifest.toml`, review `aios plan`, run `aios apply`. That builds a new generation without touching the running system.
4. **Rollback:** any older generation is bootable. A generation that fails its health check falls back automatically.
5. **Hardened by default:** Secure Boot with own keys, signed UKIs, LUKS2 + TPM2, kernel hardening, deny-inbound firewall, USBGuard.

**Success criteria (v0.1):**

- `make check` (Rust + shell unit tests, unit verification) passes without root.
- `make iso` builds the ISO. It needs root and is run by the developer.
- `make e2e` installs unattended into a QEMU VM (OVMF Secure Boot firmware + swtpm), boots gen-1 over the serial console, and asserts:
  - (a) Files written at runtime to `/etc/aios-e2e`, `/var/tmp/aios-e2e` and `/root/aios-e2e` are gone after reboot. Writing to `/usr` fails with EROFS.
  - (b) Files in `/persist` and `/home/<user>` survive reboot.
  - (c) `aios plan` reports "no changes" on a fresh install.
  - (d) After adding a package (`tree`) to the manifest, `aios apply --yes` + reboot boots gen-2, where `tree` exists.
  - (e) `aios rollback 1` + reboot boots gen-1, where `tree` does not exist.
  - (f) A gen-3 built with the test-only cmdline flag `aios.test.fail_health=1` fails its health check. After 3 boots the machine is back on the previous good gen.
  - (g) After the test user replaces `~/.ssh/authorized_keys` with a symlink to `/etc/nftables.conf` and reboots: `findmnt /etc/nftables.conf` shows no bind, nftables loads, and the symlinked path is not mounted over its target. This guards the §4.4 symlink-redirect limit.

**Out of scope:** Sentinel, Cockpit, agent runtime, ops engine (sub-projects 2–5). Graphical installer. Offline install. Desktop environment beyond a TTY (see §8).

## 2. Disk layout

```
GPT
├─ p1  ESP, FAT32, 2 GiB, mounted at /efi (noauto, x-systemd.automount, umask=0077)
│      /EFI/systemd/systemd-bootx64.efi        (signed)
│      /EFI/BOOT/BOOTX64.EFI                   (signed copy)
│      /EFI/Linux/aios-gen-0007-cachyos+3.efi  (signed UKI, boot counter)
│      /EFI/Linux/aios-gen-0007-lts+3.efi
│      /loader/loader.conf
└─ p2  LUKS2 ("aios") → btrfs, label "aios", mount option compress=zstd
       @blank           empty root skeleton (read-only), cloned at every boot
       @root-live       this boot's root (recreated from @blank at boot)
       @usr-gen-NNNN    read-only, one per generation
       @etc-gen-NNNN    read-only, one per generation
       @etc-live        this boot's /etc (rw clone of @etc-gen-N, recreated at boot)
       @usr-cand, @etc-cand, @root-cand   transient, exist only during apply/bootstrap
       @persist         declared persistent state
       @home            persistent home
       @log             /var/log (journal, pacman.log)
```

- **`@blank` skeleton:**
  - Top-level dirs: `usr etc persist home efi proc sys dev run tmp var var/log var/lib var/cache var/tmp root`.
  - Arch merged-usr symlinks: `bin → usr/bin`, `sbin → usr/bin`, `lib → usr/lib`, `lib64 → usr/lib`.
  - `var/lib/pacman → ../../usr/lib/pacman`.
- **pacman DB lives inside /usr:** the `var/lib/pacman` symlink in every assembled root, plus `DBPath = /usr/lib/pacman/` in `pacman.conf`. Packages and their DB are therefore always snapshotted together, and tools that hardcode `/var/lib/pacman` keep working. `CacheDir` is `/var/cache/pacman/pkg/` (persisted). `LogFile` is `/var/log/pacman.log`.
- **Generation number:** a zero-padded 4-digit integer, so lexical sort equals numeric sort. Next N = max(existing `@usr-gen-*`) + 1. Gen-1 is created by the installer.
- **Generation metadata** lives at `/etc/aios/generation.toml` inside each `@etc-gen-N`:

```toml
id = 7
parent = 6                          # 0 for gen-1
created = "2026-11-03T21:14:05Z"    # RFC 3339, UTC
manifest_commit = "3f9c2a1"         # git commit of the manifest repo at apply time
kernels = ["linux-cachyos 7.3.0-4", "linux-cachyos-lts 6.18.55-2"]
package_set_sha256 = "…"            # sha256 of sorted `pacman -Qq` output
```

## 3. Boot flow

1. UEFI Secure Boot verifies signed systemd-boot, which verifies the signed UKI.
2. **Entry selection:**
   - systemd-boot auto-discovers the UKIs in `/EFI/Linux`.
   - `loader.conf` has `default aios-gen-*-cachyos*`. systemd-boot sorts matching entries so the highest version comes first, which means the newest gen boots by default.
   - Boot counting comes from the `+3` filename suffix. Entries whose counter has reached 0 are sorted last as "bad".
   - `aios rollback N` overrides the default via the `LoaderEntryDefault` EFI variable (`bootctl set-default`). `aios apply` clears that override (`bootctl set-default ""`) so the newest gen wins again.
   - The fallback behavior is validated by e2e (f).
3. The UKI cmdline (baked in and signed) is:
   `rd.luks.name=<LUKS-UUID>=aios root=/dev/mapper/aios rootflags=subvol=@root-live,compress=zstd rw mount.usr=/dev/mapper/aios mount.usrflags=subvol=@usr-gen-NNNN,ro,compress=zstd aios.gen=NNNN <hardening cmdline §5.3> <manifest kernel.extra_cmdline>`
4. The initrd is mkinitcpio, systemd-based: `HOOKS=(base systemd autodetect microcode modconf kms keyboard sd-vconsole block sd-encrypt filesystems aios)`.
5. `systemd-cryptsetup@aios` unlocks LUKS: TPM2 + PIN, or passphrase, or recovery key.
6. `aios-root.service` runs in the initrd (`After=cryptsetup.target`, `Before=sysroot.mount`, `DefaultDependencies=no`) and executes `/usr/lib/aios/initrd/aios-root.sh`:
   - Parses `aios.gen=` from `/proc/cmdline`. If it's absent, or any `aios.gen=` value isn't a 4-digit generation (empty and `0000` included, even next to a valid one), it fails with "aios: no generation on cmdline". Conflicting values fail too.
   - Mounts the btrfs top level (`subvolid=5`) at `/run/aios/top`.
   - If `@usr-gen-N` or `@etc-gen-N` is missing, it fails with "aios: generation N missing — pick another boot entry".
   - If `@blank` is missing, it fails with "aios: @blank missing — reinstall required" before deleting anything.
   - Deletes `@root-live` and `@etc-live` if present, plus stale `@usr-cand`, `@etc-cand` and `@root-cand` left by a power loss mid-apply.
     - Each must be a subvolume (`btrfs subvolume show`). Otherwise it fails with "aios: <name> exists but is not a subvolume".
     - Deletion is `btrfs subvolume delete --recursive`, which also removes nested subvolumes (systemd creates `/var/lib/machines` and `/var/lib/portables` as subvolumes). Subvolume names are never parsed.
   - Snapshots `@blank → @root-live` (rw) and `@etc-gen-N → @etc-live` (rw).
   - Unmounts the top level. If that fails, it retries with `umount -l`, because `/run` survives switch-root.

   If the unit fails, `sysroot.mount` and `initrd-root-fs.target` fail, and `emergency.target` starts. The initrd's root account is locked, so no emergency shell opens and the boot stops there. Recovery is choosing another boot entry or booting the ISO.
7. `sysroot.mount` mounts `@root-live`. The systemd fstab-generator mounts `/sysroot/usr` from `mount.usr=` (ro).
8. `sysroot-etc.mount` (initrd unit, `After=sysroot.mount`) mounts `@etc-live` at `/sysroot/etc`. The mount is Required: the hook links it into `initrd-fs.target.requires/`, so a failed mount fails `initrd-fs.target` and the boot stops (as in step 6) rather than continuing with the empty `/etc` from `@blank`.
9. switch-root. Real systemd mounts the rest from `/etc/fstab`, which `aios apply` generates:
   - `/persist`, `/home`, `/var/log` as subvolumes.
   - `/efi` with `noauto,x-systemd.automount,umask=0077`.
   - A bind mount `/persist<path> → <path>` for every declared persistent directory (`bind,x-systemd.requires-mounts-for=/persist`).
   - Read-only bind mounts for managed home paths (§4.4).
10. Declared persistent **files** become symlinks via `tmpfiles.d` (`L+ <path> - - - - /persist<path>`). Bind-mounting files is fragile.
11. `aios-health.service` (`Type=oneshot`, `RequiredBy=boot-complete.target`, `Before=boot-complete.target`) runs `/usr/lib/aios/aios-health.sh`, which checks:
    - `/usr` is mounted read-only from subvolume `@usr-gen-<aios.gen>`.
    - `/etc` is mounted from `@etc-live`.
    - Both are read with `findmnt -fno OPTIONS -M`, which matches the exact mount point and takes its first mount, so a mount stacked on top can't break the match.
    - `/persist`, `/home` and `/var/log` are mounted.
    - The `/etc/aios/generation.toml` id equals `aios.gen`.
    - `aios.test.fail_health=1` is absent from the cmdline. This test-only flag forces failure.

    On success `systemd-bless-boot.service` removes the counter. On failure the entry stays counted, and after 3 tries systemd-boot boots the next entry.

**Effect:** any runtime write outside `/persist`, `/home` and `/var/log` disappears at reboot. That covers `/etc/systemd`, `/etc/ld.so.preload`, cron, `/root`, `/var/tmp` and `/var/lib/*` (except declared paths). `/usr` is read-only.

## 4. Manifest and the `aios` CLI

### 4.1 Manifest location and format

- The manifest repo lives at `/persist/aios/config/`, a git repo.
- `manifest.toml` is the single entry point. File contents referenced by the manifest live under `files/` and `home/`.
- Secrets never live in the repo. They go in `/persist/aios/secrets/` (root, 0700). Example: `passwd/<user>` holds one yescrypt hash line.

```toml
[system]
hostname = "nightcity"
timezone = "Asia/Jerusalem"
locale   = "en_US.UTF-8"
keymap   = "us"

[kernel]
default   = "linux-cachyos"
fallback  = "linux-cachyos-lts"     # optional
lockdown  = "integrity"             # "integrity" | "none"  (§5.4)
extra_cmdline = []                  # appended after the AIOS hardening cmdline

[packages]
# Explicit package set. AIOS always adds its core set (§4.6).
install = ["base", "linux-firmware", "intel-ucode", "networkmanager", "flatpak", "zsh", "git", "neovim"]

[services]
enable  = ["NetworkManager", "systemd-resolved", "nftables", "usbguard", "fwupd-refresh.timer", "apparmor"]
disable = []
mask    = []

[files]
# Only paths under /etc are allowed. mode defaults to "0644", owner/group to "root".
# A `symlink` value instead of `source` creates a symlink.
"/etc/nftables.conf" = { source = "files/nftables.conf", mode = "0600" }
"/etc/pacman.d/hooks/90-mkinitcpio-install.hook" = { symlink = "/dev/null" }

[persist]
directories = [
  "/var/lib/NetworkManager", "/etc/NetworkManager/system-connections",
  "/var/lib/bluetooth", "/var/lib/flatpak", "/var/lib/systemd",
  "/var/lib/sbctl", "/var/lib/fwupd", "/var/lib/usbguard",
  "/var/lib/containers", "/var/cache/pacman/pkg",
]
files = []

[users.eli]
uid    = 1000
groups = ["wheel", "video", "audio", "input"]
shell  = "/usr/bin/zsh"

[users.eli.home]
# Read-only bind mounts into /home/eli. Sources are relative to the manifest repo.
# A trailing "/" marks a directory. This is the default set (§4.4).
".zshrc"                         = "home/eli/zshrc"
".zshenv"                        = "home/eli/zshenv"
".zprofile"                      = "home/eli/zprofile"
".zlogin"                        = "home/eli/zlogin"
".zlogout"                       = "home/eli/zlogout"
".profile"                       = "home/eli/profile"
".bashrc"                        = "home/eli/bashrc"
".bash_profile"                  = "home/eli/bash_profile"
".bash_logout"                   = "home/eli/bash_logout"
".ssh/authorized_keys"           = "home/eli/authorized_keys"
".ssh/authorized_keys2"          = "home/eli/authorized_keys2"
".ssh/rc"                        = "home/eli/ssh-rc"
".config/autostart/"             = "home/eli/autostart/"
".config/systemd/user/"          = "home/eli/systemd-user/"
".config/systemd/user.control/"  = "home/eli/systemd-user-control/"
".local/share/systemd/user/"     = "home/eli/local-share-systemd-user/"
".config/environment.d/"         = "home/eli/environment.d/"
".local/bin/"                    = "home/eli/bin/"
```

**Validation:** `aios plan` and `aios apply` refuse to run, citing `manifest.toml:line:col`, if any of these hold:
- Unknown keys anywhere.
- `[files]` paths outside `/etc`, or an entry with both or neither of `source`/`symlink`.
- `mode` that isn't 3–4 octal digits.
- Persist paths that aren't absolute, contain `..`, overlap each other, or sit under `/usr`, `/persist` or `/home`.
- Persist paths that equal `/etc`; equal, contain or sit under a file aios generates, `/etc/aios` or a `[files]` path; or equal or sit under `/efi`, `/proc`, `/sys`, `/dev`, `/run`, `/tmp` or `/var/log`.
- Persist paths or home-managed paths containing whitespace, a control character, `%`, `\`, `"` or `'`.
- A home-managed path that's absolute or has an empty, `.` or `..` component, or two of a user's paths that differ only by the trailing `/`.
- A missing source file, or a directory/file kind mismatch.
- A duplicate UID, or a UID outside 1000–59999.
- A user with no `secrets/passwd/<user>`.
- `kernel.default` not in the known kernel set (`linux-cachyos`, `linux-cachyos-lts`, `linux`, `linux-lts`).
- `timezone` not present under `/usr/share/zoneinfo`.
- A shell that isn't absolute or contains `:`, whitespace or a control character.
- `locale` outside `[A-Za-z0-9_.@-]+`, or `keymap` outside `[A-Za-z0-9_.-]+`.
- An `extra_cmdline` entry that isn't a single word (empty, whitespace, control character or `"`), or that sets a parameter AIOS sets itself (`root`, `rootflags`, `rw`, `ro`, `mount.usr`, `mount.usrflags`, `rd.luks.name`, `aios.gen`, `lockdown`, `lsm`, `init`).

### 4.2 Commands

| Command | Behavior |
|---|---|
| `aios plan` | Validate the manifest. Compare it with the booted generation and print a diff: packages added/removed (against `pacman -Qqe`), files changed (sha256 of the manifest source vs `@etc-gen-N` content), services, users, persist entries, home-managed entries, cmdline. Prints "no changes" and exits 0 when clean |
| `aios apply [--yes]` | Show the plan and ask for confirmation unless `--yes`. Build gen N+1 (§4.3). This is also a full system upgrade (`-Syu`), because Arch doesn't support partial upgrades. Never modifies the running system except the ESP and the manifest repo commit. Prints "reboot to activate gen-N+1" |
| `aios status` | Show booted gen, default gen and gens that failed to boot. Show runtime drift: files in `/etc` that differ from `@etc-gen-<booted>` (a reboot will discard them) |
| `aios gen list` | List generations: id, created, manifest commit, kernels, boot state (booted / default / bad) |
| `aios rollback <N>` | `bootctl set-default aios-gen-NNNN-cachyos.efi` (with the counter suffix stripped from the match). Next reboot boots N. No snapshots are touched |
| `aios gc [--keep K]` | Delete old generations, default K = 5. Never deletes the booted gen, the default/rollback target or gen-1. Removes `@usr-gen-N`, `@etc-gen-N` and the gen's UKIs |
| `aios passwd <user>` | Prompt twice for a password. Write a yescrypt hash (via `mkpasswd -m yescrypt` or the `crypt` API) to `secrets/passwd/<user>`. Takes effect from the next `aios apply` |
| `aios secureboot enroll` | If `sbctl status` reports Setup Mode, run `sbctl enroll-keys --microsoft`. Otherwise print how to enter Setup Mode in firmware. Exits non-zero if not enrolled |
| `aios tpm enroll` | Requires Secure Boot enabled (`bootctl status`). Runs `systemd-cryptenroll --tpm2-device=auto --tpm2-with-pin=yes --tpm2-pcrs=7 /dev/disk/by-uuid/<LUKS-UUID>`. Passphrase and recovery slots are kept |
| `aios bootstrap --target <top> --esp <esp> --manifest <path>` | Installer-only. Builds gen-1 inside an already created btrfs top level mounted at `<top>`. Same steps as apply, except step 2 creates empty candidates and step 4 uses `pacstrap` |

All mutating commands require root (run via `run0`). They take an exclusive `flock` on `/run/aios.lock`, and each step logs to stderr and the journal (`SYSLOG_IDENTIFIER=aios`).

### 4.3 Apply algorithm

Each step aborts on failure. Abort deletes the candidate subvolumes and candidate root, releases the lock and exits non-zero naming the step. The booted generation is never modified.

1. Acquire the lock. Validate the manifest. If the manifest repo is dirty, `git commit -am "aios: manifest for gen-<N+1>"`. Record `HEAD` as `manifest_commit`. Mount the btrfs top level (`subvolid=5`) at `/run/aios/top`.
2. Delete stale `@*-cand`. Snapshot `@usr-gen-N → @usr-cand` and `@etc-gen-N → @etc-cand` (rw), plus `@blank → @root-cand` (rw).
3. Assemble the candidate root at `/run/aios/cand` = `@root-cand`, with these mounted into it:
   - `@usr-cand` at `usr`
   - `@etc-cand` at `etc`
   - binds of `/var/cache/pacman/pkg` and `/var/log`
4. Packages:
   - `arch-chroot /run/aios/cand pacman -Syu --needed --noconfirm <install set>`
   - `pacman -Rns --noconfirm <removed set>` (if any)
   - `pacman -D --asexplicit <install set>`
   - Remove orphans: `pacman -Qdtq`, piped to `pacman -Rns --noconfirm` if non-empty.
   - The mkinitcpio pacman hooks are masked via `[files]` symlinks to `/dev/null`, so pacman never writes `/boot` or the ESP.
5. Render config into `@etc-cand`:
   - `[files]` entries, with mode, owner and symlinks.
   - `hostname`, `locale.conf` (plus `locale-gen` in the chroot), `vconsole.conf`, the `localtime` symlink.
   - `fstab` (§3 step 9).
   - `tmpfiles.d/aios-persist.conf` and `tmpfiles.d/aios-home.conf`. The latter creates each user's home (`0700`) and the directories between it and each managed home path (`0700` under `~/.ssh`, else `0755`), owned by the user. Paths are tmpfiles-escaped.
   - Home-managed sources copied to `/etc/aios/home/<user>/…`, the bind sources.
   - `kernel/cmdline`.
   - `aios/generation.toml`.
6. Users: merge declared users into the candidate's `passwd`/`group`/`shadow`/`gshadow`.
   - Entries with uid < 1000 or ≥ 60000 (system and `nobody`) are kept as packages created them.
   - Declared users are created or updated with uid, primary group (same name, gid = uid), supplementary groups and shell. Their shadow hash comes from `secrets/passwd/<user>`.
   - Undeclared entries in 1000–59999 are removed.
   - The root shadow hash is set to `!*` (locked).
7. Services: `systemctl --root=/run/aios/cand enable|disable|mask` per the manifest, plus AIOS core units (`aios-health.service`, `systemd-bless-boot.service` via `boot-complete.target`).
8. UKIs, for each kernel (default → flavor `cachyos`, fallback → flavor `lts`), in the chroot:
   - `mkinitcpio -k <ver> -g /var/tmp/aios/initramfs-<flavor>.img`
   - `ukify build --linux=/usr/lib/modules/<ver>/vmlinuz --initrd=/boot/intel-ucode.img (if present) --initrd=/var/tmp/aios/initramfs-<flavor>.img --cmdline=@/etc/kernel/cmdline --os-release=@/usr/lib/os-release --output=/var/tmp/aios/aios-gen-<N+1>-<flavor>.efi`
   - The cmdline file carries `aios.gen=<N+1>` and `subvol=@usr-gen-<N+1>`.
   - The microcode image lands in the candidate's ephemeral `/boot`, which is fine because it lives in `@root-cand`.
9. Sign each UKI on the host with `sbctl sign <cand>/var/tmp/aios/<uki>` (keys in persisted `/var/lib/sbctl`), then `sbctl verify` it.
10. ESP space: if free space < 1.2 × total UKI size, run gc. If it's still short, abort.
11. Finalize, in this order:
    - Unmount the candidate tree.
    - `btrfs property set -ts @usr-cand ro true`, same for `@etc-cand`.
    - `mv @usr-cand @usr-gen-<N+1>` and `@etc-cand → @etc-gen-<N+1>` (rename in the top level).
    - Copy the UKIs to `/efi/EFI/Linux/aios-gen-<N+1>-<flavor>+3.efi`.
    - `bootctl set-default ""`.
    - Delete `@root-cand`.
12. Unmount the top level and release the lock.

**Crash safety:** before step 11 nothing visible has changed. In step 11 the subvolume rename happens before the UKI copy, so a UKI never exists without its subvolumes. A gen subvolume without a UKI is harmless; `aios gc` removes it. Stale candidates are removed at the next boot (§3 step 6) or the next apply.

### 4.4 Managed home paths

- Each `[users.<u>.home]` entry becomes an `fstab` line `/etc/aios/home/<u>/<path> /home/<u>/<path> none bind,ro,nofail,x-systemd.requires-mounts-for=/home 0 0`. `nofail`: a user who deletes or replaces a target can't drop the next boot into emergency mode.
- systemd creates missing mount points itself: a directory for a directory source, an empty file for a file source (`apply` never touches `/home`; only `bootstrap` creates `@home/<u>`, 0700, owned by the user). Either may leave root-owned parents. `tmpfiles.d` then fixes the owner and mode of the home and of every parent directory of a target (`d /home/<u>/<dir> 0755 <u> <u> -`; `0700` for the home and under `~/.ssh`). It never names a target: after the first boot each is a read-only bind, and a `d` or `f` line on it would fail with EROFS.
- **Default set** (the §4.1 example), each closing one vector:
  - Shell startup and logout: `.zshenv`, `.zprofile`, `.zshrc`, `.zlogin`, `.zlogout` (zsh), and `.profile`, `.bash_profile`, `.bashrc`, `.bash_logout` (sh and bash). The defaults are minimal; `.bash_profile` sources `.profile` and `.bashrc`.
  - SSH: `.ssh/authorized_keys`, `.ssh/authorized_keys2` (both empty) and `.ssh/rc` (comment only; sshd runs it at every login).
  - XDG autostart: `.config/autostart/`.
  - systemd user units: `.config/systemd/user/`, `.config/systemd/user.control/` and `.local/share/systemd/user/`, the per-user unit directories in `~` on the user manager's search path.
  - User session environment: `.config/environment.d/`.
  - PATH shims: `.local/bin/`.
- **Effect:** a user-level RAT can't add autostart entries, user units, shell startup hooks, `~/.local/bin` shims or SSH keys. To change these, edit the manifest.
- **Known limit, nested targets can be bypassed at runtime:** a target below a user-owned directory, such as `.ssh/authorized_keys` or `.config/autostart/`, can be dodged until the next reboot. The user can rename the parent directory, which moves the mount with it, and recreate it unprotected (`mv ~/.ssh ~/.x && mkdir ~/.ssh`). Direct children of the home, like `.zshrc`, can't be dodged this way, because a mount point can't be renamed or removed. A user-planted symlink at a target path could also redirect the bind at boot, and `nofail` would hide that failure. v0.1 mitigation: e2e test (g) checks that a planted symlink target doesn't redirect the bind. Fix: follow-up #7.
- **Known limit, other autostart vectors:** these also exist, such as compositor configs, `.desktop` overrides, editor plugins, and `~/.config/systemd/user.conf`, whose `DefaultEnvironment=` reaches every user unit. They're added to the manifest defaults when the Cockpit picks the compositor (follow-up #5). Sentinel watches the rest of `/home`.

### 4.5 Code structure (Rust workspace `aios-cli/`)

| Crate | Purpose | Tested by |
|---|---|---|
| `aios-manifest` | Types, TOML parse (serde + `toml` spans), validation (every rule in §4.1) | Fixture manifests: one valid, one per invalid rule |
| `aios-gen` | Generation id/subvolume/UKI naming, counter parsing (`+3`, `+1-2`), metadata TOML, listing, next id, GC selection | Pure unit tests |
| `aios-render` | Pure renderers: fstab, tmpfiles, cmdline, passwd/group/shadow/gshadow merge, loader.conf | Golden files under `tests/golden/` |
| `aios-plan` | `SystemProbe` trait (booted gen, installed explicit packages, `/etc` file hashes, enabled units), observed state, `Plan` diff, human-readable rendering | Unit tests with a fake probe |
| `aios-exec` | `CommandRunner` trait (real: `std::process::Command`; fake: records argv, returns scripted results) and the step sequences for apply, bootstrap, rollback, gc, secureboot, tpm | Golden argv-sequence tests, plus a failure injected at each step asserting the cleanup sequence |
| `aios` (bin) | clap CLI, flock, logging, config of paths. The paths are fixed in release builds | CLI tests using the fake runner (`test-hooks` builds) |

All system interaction goes through `CommandRunner` and `SystemProbe`, so no unit test needs root.

**Test overrides exist only in test builds.** The environment overrides the CLI tests use (`AIOS_TOP`, `AIOS_ESP`, `AIOS_CONFIG`, `AIOS_SECRETS` and the other `Layout` paths, `AIOS_ZONEINFO`, `AIOS_HARDENING_CMDLINE_FILE`, `AIOS_FAKE_RUNNER`, `AIOS_TEST_PASSWORD`) are read through a single function that only builds with the `test-hooks` cargo feature consult. The feature is off by default, so a shipped `aios` reads no `AIOS_*` variable and can't be pointed at a fake runner or another manifest repo. The CLI tests require the feature, and `make check` runs them with `--all-features`. It then builds the release binary (`cargo build --release --locked -p aios`) and fails if the string `AIOS_FAKE_RUNNER` is in it.

`RealRunner` gives each child a clean environment (`PATH=/usr/bin`, `LC_ALL=C`, `TERM` passed through) and `/dev/null` as stdin, and captures stdout and stderr. A command marked interactive (`systemd-cryptenroll` for `aios tpm enroll`) inherits all three streams instead, so it can prompt.

### 4.6 AIOS packages

**`aios-cli`**
- Ships `/usr/bin/aios`.
- Depends on `btrfs-progs arch-install-scripts mkinitcpio systemd-ukify sbctl git whois` (`whois` provides `mkpasswd`).

**`aios-base`** (configs live in `/usr` so they're package-owned and immutable):
- `/usr/lib/sysctl.d/90-aios-hardening.conf` (§5.2)
- `/usr/lib/aios/cmdline-hardening` (§5.3)
- `/usr/lib/initcpio/install/aios`. It adds `aios-root.service`, `sysroot-etc.mount`, `/usr/lib/aios/initrd/aios-root.sh` and `btrfs` to the initrd, and enables both units in the initrd.
- `/usr/lib/systemd/system/aios-health.service` and `/usr/lib/aios/aios-health.sh`
- `/usr/lib/NetworkManager/conf.d/90-aios-privacy.conf`: `wifi.cloned-mac-address=stable`, `ethernet.cloned-mac-address=stable`, `wifi.scan-rand-mac-address=yes`, `ipv6.ip6-privacy=2`.
- `/usr/lib/systemd/resolved.conf.d/90-aios-dot.conf`: `DNS=9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net 1.1.1.1#cloudflare-dns.com`, `DNSOverTLS=yes`, `DNSSEC=allow-downgrade`.
- `/usr/lib/systemd/zram-generator.conf`: `zram-size = min(ram / 2, 8192)`, `compression-algorithm = zstd`.
- `/usr/share/aios/defaults/manifest/`: the default manifest repo (`manifest.toml`, `files/`, `home/`). The installer copies it.
- The default manifest's `[files]` includes:
  - `/etc/pacman.conf` (`DBPath = /usr/lib/pacman/`, CachyOS repos).
  - `/etc/mkinitcpio.conf`.
  - Mask symlinks for `90-mkinitcpio-install.hook` and `60-mkinitcpio-remove.hook`.
  - `/etc/nftables.conf`.
  - `/etc/usbguard/usbguard-daemon.conf`.
- AIOS core package set, always added: `base aios-cli aios-base btrfs-progs cryptsetup tpm2-tss sbctl systemd-ukify mkinitcpio nftables usbguard apparmor zram-generator fwupd polkit` + the manifest kernels.

**Packaging:**
- PKGBUILDs live in `packaging/aios-cli/` and `packaging/aios-base/`.
- `make repo` builds them with `makepkg` (no root) and creates `build/repo/aios-local.db.tar.gz` via `repo-add`.
- The ISO uses this repo. The installer copies it to `/persist/aios/repo`, and the installed `pacman.conf` points `[aios-local]` at `file:///persist/aios/repo`. In the candidate chroot that's a bind of the same path. `[aios-local]` is the last repo in `pacman.conf`, so a package dropped into it can never shadow a signed one. `aios-cli` and `aios-base` come only from this unsigned repo, so a runtime root compromise could persist by planting packages in `/persist/aios/repo` until follow-up #2 (repo signing) lands.
- The repo is unsigned (`SigLevel = Optional TrustAll`) for v0.1, because it's built locally on the same machine. Signing the repo is follow-up #2.

## 5. Hardening

### 5.1 Boot chain and disk
- **Secure Boot with own keys:**
  - `sbctl create-keys` runs at install, with keys in `/var/lib/sbctl` (persisted).
  - If firmware is in Setup Mode, the installer enrolls with `--microsoft`. Microsoft keys stay because GPU option ROMs need them.
  - Otherwise the summary points to `aios secureboot enroll`.
- systemd-boot, the fallback `BOOTX64.EFI` and every UKI are signed.
- **LUKS2** uses argon2id. At install: a passphrase plus a generated recovery key (`systemd-cryptenroll --recovery-key`, printed once).
- **TPM2 + PIN** comes after Secure Boot enrollment: `aios tpm enroll`, binding PCR 7.

### 5.2 sysctl (`90-aios-hardening.conf`)
```
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.yama.ptrace_scope = 1
kernel.kexec_load_disabled = 1
kernel.perf_event_paranoid = 3
kernel.sysrq = 0
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.tcp_syncookies = 1
```
Unprivileged user namespaces stay enabled, because Flatpak, bubblewrap and rootless podman need them. This is a documented trade-off.

### 5.3 Kernel cmdline (`cmdline-hardening`)
`init_on_alloc=1 init_on_free=1 slab_nomerge page_alloc.shuffle=1 randomize_kstack_offset=on vsyscall=none debugfs=off lsm=landlock,lockdown,yama,integrity,apparmor,bpf quiet`

The renderer adds `lockdown=integrity` when `kernel.lockdown = "integrity"`, and nothing when it's `"none"`.

### 5.4 Lockdown and out-of-tree modules (NVIDIA)

**The problem:** `lockdown=integrity` rejects unsigned kernel modules. The kernel trusts only its build-time signing key (plus MOK via shim). Our sbctl db key is *not* trusted for modules.

**v0.1 policy:**
- **Default `kernel.lockdown = "integrity"`.** Used in the VM and on machines without out-of-tree modules.
- **Laptop with NVIDIA (RTX 2050):** first check whether CachyOS's prebuilt `linux-cachyos-nvidia-open` modules carry the kernel build signature (`modinfo -F signer nvidia`).
  - If they do, lockdown works with NVIDIA.
  - If not, set `lockdown = "none"` for that machine and track signed NVIDIA modules as follow-up #1. Options: own-key kernel build, or shim + MOK.
- `aios plan` prints a warning whenever `lockdown = "none"`.

### 5.5 Other host hardening
- **Root and privilege:**
  - The root account is locked.
  - `sudo` is not installed. Admin is `run0` via polkit, with wheel as admin per Arch's default polkit rules.
- **Network:** `nftables.conf` (default `/etc/nftables.conf` from the manifest):
  - `input` policy `drop`, accepting loopback, `ct state established,related`, ICMP/ICMPv6 essentials (echo-reply, unreachable, time-exceeded, NDP, MLD listener query per RFC 4890) and DHCPv6 client.
  - `forward` policy `drop`.
  - `output` policy `accept`. The app firewall comes with Sentinel.
  - **Trade-off, containers and VMs:** `forward` policy `drop` blocks the NAT that rootful podman and libvirt set up. The ruleset starts with `flush ruleset`, so restarting `nftables.service` also wipes the tables netavark and libvirt added at runtime. Rootless podman (slirp4netns/pasta) is unaffected. Users who need rootful NAT add forward rules in their `files/nftables.conf`.
- **Network trade-offs** (follow-up #6):
  - Strict reverse-path filtering (`rp_filter = 1`, §5.2) drops asymmetrically routed packets, which can break multi-homed hosts and some VPN setups.
  - Strict DNS over TLS (`DNSOverTLS=yes`, §4.6) can't reach a captive portal's local resolver, so captive-portal networks need DoT relaxed until login.
  - The DoT resolvers are IPv4 only, so IPv6-only networks have no DNS.
- **USBGuard:**
  - `usbguard-daemon.conf`: `RuleFile=/var/lib/usbguard/rules.conf` (persisted), `ImplicitPolicyTarget=block`, `PresentDevicePolicy=apply-policy`, `InsertedDevicePolicy=apply-policy`, `IPCAllowedUsers=root`, `IPCAllowedGroups=` (empty).
  - Only root may use the daemon's IPC. Every policy change therefore goes through `run0` and its polkit prompt, and a process running as a wheel user can't allow a device on its own.
  - The installer writes `usbguard generate-policy` output, which allows devices present at install.
  - The installer then appends `block with-interface one-of { 03:*:* }` followed by `allow`, so new HID devices are blocked and other new devices are allowed.
  - Approve a device with `run0 usbguard allow-device -p <id>`.
- **AppArmor** is enabled via `lsm=` and `apparmor.service`, with packaged profiles enforced.
- **Swap:** zram only. No disk swap, no hibernation.
- **Firmware:** `fwupd-refresh.timer`.

## 6. ISO and installer

### 6.1 archiso profile (`iso/`)
- Copied from `/usr/share/archiso/configs/releng/` and modified.
- `profiledef.sh`: `iso_name="aios"`, `iso_label="AIOS_<YYYYMM>"`, `bootmodes=('uefi.systemd-boot.esp' 'uefi.systemd-boot.eltorito')`. UEFI only.
- `pacman.conf`: `core`, `extra`, the CachyOS repos, and `[aios-local]` → `file://<repo>/build/repo`. `make iso` generates it from a template with the absolute path.
- `packages.x86_64`: the releng list plus `arch-install-scripts sbctl btrfs-progs cryptsetup gptfdisk tpm2-tools git usbguard whois aios-cli aios-base`.
- `airootfs/usr/local/bin/aios-install` and `airootfs/usr/local/lib/aios-install/*.sh`.
- `efiboot/loader/entries/03-aios-serial.conf`: same as the default entry plus `console=ttyS0,115200`.
- `airootfs/etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf`: root autologin on the live ISO only.
- The build repo is copied into the ISO at `airootfs/opt/aios-repo/`, so the installer can seed `/persist/aios/repo` without network.
- `make iso` runs `sudo mkarchiso -v -w work/ -o out/ iso/`. The developer runs it.

### 6.2 `aios-install` (bash, `set -euo pipefail`, shellcheck-clean, helpers in `lib/` unit-tested with bats)

**Modes:**
- **Interactive:** prompts for disk, hostname, username, user password, LUKS passphrase and timezone.
- **Unattended:** `--config <file>`, or automatically when `/sys/firmware/qemu_fw_cfg/by_name/opt/aios/install.conf/raw` exists.
  - `KEY=value` lines: `DISK HOSTNAME USERNAME USER_PASSWORD LUKS_PASSPHRASE TIMEZONE WIPE EXTRA_CMDLINE`.
  - Values are parsed by a whitelist parser, never `source`d.

**Steps:**
1. Preflight:
   - `/sys/firmware/efi` exists.
   - `DISK` is a whole block device and isn't the live medium (`/run/archiso/bootmnt` source).
   - Network: `curl -sI https://geo.mirror.pkgbuild.com`.
   - x86-64-v3 detection (`/lib/ld-linux-x86-64.so.2 --help` lists "x86-64-v3 (supported, searched)"). If v3 isn't supported, the v3 CachyOS repos are dropped from the generated `pacman.conf`.
2. Confirm the wipe. Interactive mode requires typing the disk path; unattended mode requires `WIPE=yes`.
3. Partition: `sgdisk --zap-all`, then `-n1:0:+2G -t1:EF00 -n2:0:0 -t2:8309`. Then `mkfs.fat -F32 -n EFI`.
4. `cryptsetup luksFormat --type luks2 --pbkdf argon2id` (passphrase from stdin), then `cryptsetup open … aios`. `systemd-cryptenroll --recovery-key`, with the key printed and saved nowhere.
5. `mkfs.btrfs -L aios /dev/mapper/aios`. Mount the top level and create `@blank` (skeleton §2, then `btrfs property set -ts … ro true`), `@persist`, `@home` and `@log`.
6. Copy `/usr/share/aios/defaults/manifest` to `@persist/aios/config`, substituting hostname, username, timezone and `EXTRA_CMDLINE`. Then `git init`, commit "aios: initial manifest". Write the yescrypt hash of `USER_PASSWORD` to `@persist/aios/secrets/passwd/<user>` (0600). Copy `/opt/aios-repo` to `@persist/aios/repo`.
7. Mount the ESP at `/mnt/aios-esp`.
8. Secure Boot keys:
   - Bind `@persist/var/lib/sbctl` to the live system's `/var/lib/sbctl`.
   - `sbctl create-keys`.
   - Then `aios bootstrap` (step 9) can sign.
9. `aios bootstrap --target /mnt/aios-top --esp /mnt/aios-esp --manifest /mnt/aios-top/@persist/aios/config/manifest.toml`.
   - Before pacstrap, it imports and locally signs the CachyOS key into the candidate keyring. The fingerprint is pinned in `installer/lib/keys.sh`, taken from the build host at ISO build time by `make iso`.
10. `bootctl install --esp-path=/mnt/aios-esp`. Write `loader.conf` (`default aios-gen-*-cachyos*`, `timeout 3`, `editor no`). Sign `systemd-bootx64.efi` and `BOOTX64.EFI` with `sbctl sign -s`.
11. If `sbctl status` reports Setup Mode, run `sbctl enroll-keys --microsoft`.
12. Write the USBGuard rules to `@persist/var/lib/usbguard/rules.conf` (§5.5).
13. Unmount everything, `cryptsetup close aios`, and print the summary: the recovery key reminder, `aios secureboot enroll` (if not enrolled) and `aios tpm enroll`. Exit 0, then reboot when unattended.

## 7. Error handling summary

| Failure | Behavior |
|---|---|
| Invalid manifest | `plan`/`apply` refuse with `manifest.toml:line:col: <reason>`. Nothing changes |
| Any apply step fails | Candidates and the candidate root are deleted, the lock is released, and the command exits non-zero with `aios: step <name> failed: <detail>`. The booted gen is untouched |
| Power loss mid-apply | Stale `@*-cand` subvolumes are removed by `aios-root.service` at next boot and by the next apply |
| ESP full | Auto-gc respecting protected gens. If still short, abort before finalizing |
| UKI signing or verification fails | Abort before finalizing. No unsigned UKI is copied to the ESP |
| Gen fails health check | Not blessed. After 3 tries systemd-boot boots the next entry. `aios status` lists it as bad |
| Generation subvolume missing at boot | `aios-root.service` fails with a clear message and the boot stops. The initrd's root account is locked, so no emergency shell opens. Recovery: choose another boot entry (the menu still lists other gens) or boot the ISO |
| `@blank` missing, or a live/candidate name that isn't a subvolume, at boot | `aios-root.service` fails before deleting anything, with the same recovery |
| `@etc-live` fails to mount in the initrd | `sysroot-etc.mount` is required by `initrd-fs.target`, so the boot stops, with the same recovery |
| Concurrent `aios` commands | The second exits 1: "another aios operation is running" |
| Runtime edits to `/etc` | Allowed, but discarded at reboot. `aios status` lists them |
| Installer step fails | Stop with the step name. Leave LUKS closed if it was opened, unmount everything (trap). The disk is left in an undefined state and the user re-runs the installer |

## 8. Session for v0.1

The Base ISO includes no desktop. The Cockpit sub-project picks the compositor. The default manifest boots to a TTY login (plus serial console via `EXTRA_CMDLINE` in e2e). Daily-driving starts after Sentinel + Cockpit.

## 9. Testing

| Layer | Tooling | What |
|---|---|---|
| Rust unit/golden | `cargo test --workspace` | Manifest validation (each rule), gen naming/counter/GC, renderers (golden files), planner diff, argv sequences for apply/bootstrap/rollback/gc/secureboot/tpm with the fake runner, cleanup on a failure injected at every step |
| Shell | `shellcheck`, `bats` | `aios-root.sh` with a fake `btrfs`/`mount`/`umount` on PATH (with failure injection) and a fake `/proc/cmdline` (env override): normal boot, missing gen, missing `@blank`, no or invalid gen on cmdline, stale candidates, nested subvolumes (including one named like a top-level subvolume), a non-subvolume at a live name, and mount/snapshot/unmount failures. `aios-health.sh` with fake `findmnt` (including stacked mounts) and cmdline. Installer `lib/` helpers: config parser (rejects unknown keys and shell metacharacters), disk validation, v3 detection parsing |
| Units | `systemd-analyze verify` | `aios-root.service`, `sysroot-etc.mount`, `aios-health.service` |
| Packaging | `makepkg` in `make repo`, `namcap` if available | PKGBUILDs build |
| E2E | `make e2e`: pytest harness in `tests/e2e/`, QEMU (`-enable-kvm -cpu host -m 4G`), OVMF `OVMF_CODE.secboot.4m.fd` + a copy of the vars, `swtpm` socket TPM 2.0, a 20 GiB qcow2 | Boots the ISO with the fw_cfg install config, drives the serial console via a unix socket: install → reboot → LUKS passphrase → log in as the test user → assertions (a)–(g) from §1. Needs `out/aios-*.iso` |

`make check` = `cargo test --all-features` + `cargo clippy -D warnings` (with and without features) + the release-binary check for test hooks (§4.5) + shellcheck + bats + `systemd-analyze verify`. It needs no root and no VM.

## 10. Repository layout

```
AIOS/
├─ Makefile                 check | repo | iso | vm | e2e | clean
├─ aios-cli/                Rust workspace (§4.5)
├─ initrd/                  aios-root.sh, aios-root.service, sysroot-etc.mount, install/aios hook
├─ base/                    aios-base payload (sysctl, cmdline, NM, resolved, zram, health)
├─ manifest/                default manifest repo (manifest.toml, files/, home/)
├─ packaging/               PKGBUILDs: aios-cli, aios-base
├─ iso/                     archiso profile
├─ installer/               aios-install + lib/
├─ tests/                   bats/, e2e/, fixtures/, golden/
└─ docs/superpowers/        specs/, plans/
```

## 11. Open follow-ups (tracked, not blocking v0.1)

1. Signed NVIDIA modules under lockdown (§5.4).
2. Signed `aios-local` repo.
3. "Block USB while locked" (Cockpit).
4. Offline install from the ISO's local repo.
5. Managed home paths for the compositor chosen by the Cockpit, plus `~/.config/systemd/user.conf` (§4.4).
6. Network trade-offs (§5.5): a manifest switch for loose `rp_filter` on multi-homed/VPN hosts, a captive-portal flow under strict DoT, IPv6 DoT resolvers, and opt-in forward rules for rootful container/VM NAT.
7. Replace the fstab home binds with a root oneshot run before `user@.service`. For each target it:
   - resolves the path with `openat2(RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH)`;
   - re-creates a missing or replaced parent directory;
   - bind-mounts through the file descriptor (`move_mount`);
   - reports any failure to the journal and to `aios status`;
   - re-checks at every user login, closing the rename bypass (§4.4).
8. Read manifest sources from the git objects at `manifest_commit` instead of the working tree. This closes the check-then-read race, and guarantees that `apply` builds exactly what `plan` showed.
