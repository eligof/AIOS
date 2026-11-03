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
  - (g) `~/.ssh/authorized_keys` starts out as a read-only bind. The test user then replaces it with a symlink to `/etc/nftables.conf` and reboots. Afterwards `findmnt /etc/nftables.conf` shows no bind and nftables loads. The bind's mount unit has failed, because systemd refuses the path (`not canonical` in the journal), and `~/.ssh/authorized_keys2` is still a read-only bind. This guards the §4.4 symlink-redirect limit.

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
   - If `@usr-gen-N`, `@etc-gen-N` or `@blank` is a symlink, even a dangling one, it fails with "aios: <name> is a symlink, not a subvolume" before deleting anything: btrfs resolves the path, so the boot would use another subvolume's content.
   - If `@usr-gen-N` or `@etc-gen-N` is missing, it fails with "aios: generation N missing — pick another boot entry".
   - If `@blank` is missing, it fails with "aios: @blank missing — reinstall required" before deleting anything.
   - Deletes `@root-live` and `@etc-live` if present, plus stale `@usr-cand`, `@etc-cand` and `@root-cand` left by a power loss mid-apply.
     - A symlink there, even a dangling one, fails with "aios: <name> is a symlink, not a subvolume": btrfs resolves the path, so deleting through the link would delete its target.
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
| `aios apply [--yes] [--upgrade]` | Show the plan and ask for confirmation unless `--yes`. Build gen N+1 (§4.3). This is also a full system upgrade (`-Syu`), because Arch doesn't support partial upgrades. Never modifies the running system except the ESP and the manifest repo commit. Prints "reboot to activate gen-N+1". When the plan shows no changes, it exits 0 without building. With `--upgrade` it builds anyway, printing `upgrading: no manifest changes` first: a full `pacman -Syu` with the same manifest |
| `aios status` | Show booted gen, default gen and gens that failed to boot. Show runtime drift, which a reboot will discard: entries of `/etc` (directories and `/etc` itself included) that were added, removed or changed compared with `@etc-gen-<booted>`, with what changed: type, mode, owner (uid:gid), a symlink's target, a device node's number, a file's size or, at equal sizes, its bytes (xattrs, ACLs and hard links are not compared). A file is read through one descriptor opened with `O_NOFOLLOW \| O_NONBLOCK` and checked with `fstat` to be a regular file; FIFOs, sockets and devices are never opened. Files over 16 MiB are compared by size only (equal sizes get a note). An entry that can't be compared gets a note, and then no drift reads `none found in what could be compared`, not `none`. Control characters in printed paths are escaped |
| `aios gen list` | List generations: id, created, manifest commit, kernels, boot state (booted / default / bad) |
| `aios rollback <N> [--force]` | `bootctl set-default aios-gen-NNNN-cachyos.efi` (with the counter suffix stripped from the match). Next reboot boots N. Refuses when N's main UKI is marked bad (no boot tries left) unless `--force`, and when `@usr-gen-N` or `@etc-gen-N` is missing or isn't a subvolume itself (a symlink, or a directory without the subvolume root inode), checked with the top level mounted read-only. No snapshots are touched |
| `aios gc [--keep K]` | Delete old generations, default K = 5. Never deletes the booted gen, the default/rollback target or gen-1. Refuses (`cannot determine the booted generation; refusing to garbage-collect`) when the cmdline names no booted gen, and fails when `LoaderEntryDefault` exists but can't be read or decoded (a missing or empty one, or one naming no aios UKI, means no aios override). Removes `@usr-gen-N`, `@etc-gen-N` and the gen's UKIs: the UKIs first, then an fsync of `EFI/Linux`, then the subvolumes, then `btrfs filesystem sync`. Also removes every incomplete gen except the booted one (an `@usr-gen-N` without `@etc-gen-N` or the other way round, and UKIs without both); a UKI of one never counts as the newest good gen |
| `aios passwd <user>` | Prompt twice for a password. Write a yescrypt hash (via `mkpasswd -m yescrypt` or the `crypt` API) to `secrets/passwd/<user>`. Takes effect from the next `aios apply` |
| `aios secureboot enroll` | If `sbctl status` reports Secure Boot already enabled, print "Secure Boot is already enabled" and exit 0. If it reports Setup Mode, run `sbctl enroll-keys --microsoft`. Otherwise print how to enter Setup Mode in firmware. Exits non-zero if not enrolled |
| `aios tpm enroll` | Requires Secure Boot enabled and out of Setup Mode (`sbctl status`), and a canonical LUKS UUID in `rd.luks.name=`. Runs `systemd-cryptenroll --tpm2-device=auto --tpm2-with-pin=yes --tpm2-pcrs=7 --wipe-slot=tpm2 /dev/disk/by-uuid/<LUKS-UUID>` on the terminal, where it prompts for the passphrase and the PIN. A re-run replaces the TPM2 slot (systemd enrolls the new slot first and never wipes it). Passphrase and recovery slots are kept |
| `aios bootstrap --target <top> --esp <esp> --manifest <path> --luks-uuid <uuid>` | Installer-only. Builds gen-1 inside an already created btrfs top level mounted at `<top>`. Same steps as apply, except step 2 creates empty candidates and step 4 uses `pacstrap`. Loads the manifest file `<path>` (any file name); its directory is the manifest repo. A bare file name without a directory is refused |

All mutating commands require root (run via `run0`). They take an exclusive `flock` on `/run/aios.lock`, and each step logs to stderr and the journal (`SYSLOG_IDENTIFIER=aios`). Every command that mounts the top level (`apply`, `bootstrap`, `gc`, `rollback`, and the read-only `plan`, `status` and `gen list`) first moves into a private mount namespace (`unshare(CLONE_NEWNS)`, then `/` made a recursive slave): what it mounts never appears in the host's namespace and goes away with the process, even if it is killed, while host mounts such as the `/efi` automount still propagate in. If that fails, the command aborts. The read-only commands take a shared lock, so several can run at once. Each mounts the top level read-only at its own `/run/aios/ro.<pid>` and removes the directory again, even if it fails. If the directory can't be removed once unmounted (`EBUSY`, say), that is a warning (`aios: warning: cannot remove …`), and the command's outcome stands. A SIGKILL can leave the empty directory behind, but never the mount.

### 4.3 Apply algorithm

Each step aborts on failure (or panic). Abort unmounts and deletes the candidate subvolumes and candidate root, releases the lock and exits non-zero naming the step. The booted generation is never modified. Nothing is deleted before step 2 starts, so a bootstrap that refuses its target (it already holds generations) leaves that target alone. If the candidate tree won't unmount, its subvolumes are kept and the next boot deletes them.

1. Acquire the lock and enter the private mount namespace (§4.2). Check ownership: the manifest repo, its `.git` and `.git/config` (where present) and the secrets directory must be owned by root and not group- or world-writable. None of them may be a symlink, and `.git` may not be a `gitdir:` file. Validate the manifest. If the manifest repo is dirty (`git status --porcelain`), run `git add -A`, then `git commit --no-verify -m "aios: manifest for gen-<N+1>"`. Record `HEAD` (`git rev-parse --short HEAD`) as `manifest_commit`. git runs as root, so every git call gets the environment `GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_ATTR_NOSYSTEM=1 GIT_CEILING_DIRECTORIES=<the repo's parent>` and the options `--attr-source=<the empty tree> -c core.attributesFile=/dev/null -c core.hooksPath=/dev/null -c core.fsmonitor=false -c commit.gpgsign=false` (`--attr-source` needs git ≥ 2.42; the empty tree is that of a SHA-1 repo, which `git init` makes). git then reads no system or global config, and never uses a repo above the manifest repo (without its `.git`, git fails). It reads no attributes from the work tree's `.gitattributes` or from a system or global attributes file; `.git/info/attributes` still applies. A filter, diff or merge driver runs only if a config entry defines it, and the only config left is the root-owned `.git/config` (with anything it includes) and these options. No hook, fsmonitor or signing program runs. Mount the btrfs top level (`subvolid=5`) at `/run/aios/top`, then `mount --make-rprivate /run/aios/top`, so the candidate binds made from it don't join its peer group.
2. If something is still mounted at `/run/aios/cand` (`mountpoint -q`, left by a run that crashed outside a private namespace), `umount -R` it. Delete stale `@*-cand`: a symlink, or anything that isn't a directory with the subvolume root inode (256) and passes `btrfs subvolume show`, is an error. Snapshot `@usr-gen-N → @usr-cand` and `@etc-gen-N → @etc-cand` (rw), plus `@blank → @root-cand` (rw). A snapshot or create whose destination exists (even as a dangling symlink) is refused, because btrfs would put it inside an existing directory.
3. Assemble the candidate root at `/run/aios/cand` = `@root-cand`, with these mounted into it:
   - `@usr-cand` at `usr`
   - `@etc-cand` at `etc`
   - binds of `/var/cache/pacman/pkg` and `/var/log`
4. Packages (operands always follow `--`, here and for `systemctl` and `chown`; `pacstrap` can't take one, so it relies on the manifest's ban on a leading `-`):
   - `arch-chroot /run/aios/cand pacman -Syu --needed --noconfirm -- <install set>`
   - `pacman -Rns --noconfirm -- <removed set>` (if any)
   - `pacman -D --asexplicit -- <install set>`
   - Remove orphans: `pacman -Qdtq`, piped to `pacman -Rns --noconfirm --` if non-empty.
   - The mkinitcpio pacman hooks are masked via `[files]` symlinks to `/dev/null`, so pacman never writes `/boot` or the ESP.
5. Render config into `@etc-cand`:
   - `[files]` entries, with mode, owner and symlinks. An entry with an owner is written without its setuid/setgid bits, chowned (`chown -h` in the chroot), and only then given its full mode, through a descriptor that never follows a symlink: chown clears those bits, and the file is never setuid root in between.
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
7. Services: `systemctl --root=/run/aios/cand enable|disable|mask -- <units>` per the manifest, plus AIOS core units (`aios-health.service`, `systemd-bless-boot.service` via `boot-complete.target`).
8. UKIs, for each kernel (default → flavor `cachyos`, fallback → flavor `lts`), in the chroot:
   - `mkinitcpio -k <ver> -g /var/tmp/aios/initramfs-<flavor>.img`
   - `ukify build --linux=/usr/lib/modules/<ver>/vmlinuz --initrd=/boot/intel-ucode.img (if present) --initrd=/var/tmp/aios/initramfs-<flavor>.img --cmdline=@/etc/kernel/cmdline --os-release=@/usr/lib/os-release --output=/var/tmp/aios/aios-gen-<N+1>-<flavor>.efi`
   - The cmdline file carries `aios.gen=<N+1>` and `subvol=@usr-gen-<N+1>`.
   - The microcode image lands in the candidate's ephemeral `/boot`, which is fine because it lives in `@root-cand`.
9. Sign each UKI on the host with `sbctl sign <cand>/var/tmp/aios/<uki>` (keys in persisted `/var/lib/sbctl`). A signing failure aborts the apply before anything reaches the ESP. There is no separate verify step: upstream `sbctl verify FILE` exits 0 for an unsigned file too, so it would prove nothing (§11 item 9). If an unsigned UKI still reached the ESP, it is caught at boot: with Secure Boot enabled the firmware refuses to start it, and boot counting (§3) moves on to the next entry once its tries run out.
10. ESP space: if free space < 1.2 × total UKI size, run gc (`--keep 5`). If it's still short, abort. In bootstrap nothing has booted from the target yet, so this gc has no booted gen to spare and runs without one.
11. Finalize, in this order:
    - Remove any `aios-gen-<N+1>-*.efi` already on the ESP, whatever its counter (left by a gen whose subvolumes are gone), then copy the UKIs to `/efi/EFI/Linux/aios-gen-<N+1>-<flavor>+3.efi.tmp` (fsynced; systemd-boot ignores `.tmp`).
    - Unmount the candidate tree.
    - `btrfs property set -ts @usr-cand ro true`, same for `@etc-cand`.
    - `mv @usr-cand @usr-gen-<N+1>` and `@etc-cand → @etc-gen-<N+1>` (rename in the top level).
    - `btrfs filesystem sync /run/aios/top`: the renames are on disk.
    - Rename the main UKI from `.tmp`. **This is the commit point**: from here on gen-N+1 boots, so every later failure is a warning (§7), not a failed step.
    - Rename the fallback UKI from `.tmp`, then fsync `/efi/EFI/Linux`.
    - `bootctl set-default ""` (apply only, and only if the fsync worked).
    - Delete `@root-cand`.
12. Unmount the top level and release the lock.

**Crash safety:** before step 11 nothing visible has changed. In step 11 the subvolume renames are synced to disk before any UKI gets its bootable name, so a UKI never exists without its subvolumes, even after a power loss; and the ESP directory is synced before the boot default moves, so it only moves to an entry that is on disk. A gen subvolume without a UKI is harmless; `aios gc` removes it once it falls out of `--keep`, or at once if it is half a pair. Stale candidates are removed at the next boot (§3 step 6) or the next apply.

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

**Test overrides exist only in test builds.** The environment overrides the CLI tests use (`AIOS_TOP`, `AIOS_ESP`, `AIOS_CONFIG`, `AIOS_SECRETS` and the other `Layout` paths, `AIOS_ZONEINFO`, `AIOS_HARDENING_CMDLINE_FILE`, `AIOS_FAKE_RUNNER`, `AIOS_TEST_PASSWORD`) are read through a single function, which consults the environment only in builds with the `test-hooks` cargo feature. The feature is off by default, so a shipped `aios` reads no `AIOS_*` variable and can't be pointed at a fake runner or another manifest repo. The CLI tests require the feature, and `make check` runs them with `--all-features`. It then builds the release binary (`cargo build --release --locked -p aios`) and fails if it is empty or holds any `AIOS_` string at all, which would mean an override leaked in: `grep -q AIOS_` must exit 1 (no match), so a read error fails too. `make release-check` runs that check on a binary already built.

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
- `profiledef.sh`: `iso_name="aios"`, `iso_label="AIOS_<YYYYMM>"`, `bootmodes=('uefi.systemd-boot')` (archiso 86 merged the ESP and El Torito modes into one). UEFI only.
- `pacman.conf`: `core`, `extra`, the CachyOS repos, and `[aios-local]` → `file://<repo>/build/repo`. `make iso-build` generates it from `iso/pacman.conf.in` with the absolute path. `[cachyos]` only provides the keyring and the mirrorlists.
- `packages.x86_64`: the releng list plus `arch-install-scripts sbctl btrfs-progs cryptsetup gptfdisk tpm2-tools git usbguard whois aios-cli aios-base cachyos-keyring cachyos-mirrorlist cachyos-v3-mirrorlist`. Bootstrap needs the CachyOS keyring and mirrorlists on the live system.
- `airootfs/usr/local/bin/aios-install` and `airootfs/usr/local/lib/aios-install/*.sh`.
- `efiboot/loader/entries/`: `01-aios-linux.conf` (default), `03-aios-serial.conf` (the same plus `console=ttyS0,115200`; the second menu entry) and `04-aios-memtest86+x64.conf`. releng's speech entry is dropped.
- `airootfs/etc/systemd/system/aios-install-auto.service` runs `aios-install --auto`:
  - `ConditionVirtualization=vm`, so it never starts on real hardware.
  - `After=… pacman-init.service`, so the keyring check (§6.2 step 1) sees the populated keyring.
  - stdout and stderr go to `journal+console`, with `LogRateLimitIntervalSec=0` so journald drops no installer line.
- `airootfs/etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf`: root autologin on the live ISO only.
- The build repo is copied into the ISO at `airootfs/opt/aios-repo/`, so the installer can seed `/persist/aios/repo` without network.
- `iso/build-profile.sh` assembles `iso-build/` without root:
  - It writes its `.aios-iso-build` marker right after creating the directory, and only ever replaces a directory that has the marker. A run that failed half way can be repeated.
  - It accepts the keys file only as `make keys` writes it: comment lines plus exactly one `AIOS_CACHYOS_KEYS="<fingerprints>"` line, since the installer sources it as root.
- `make iso` writes `iso-build/` without root (the profile, `pacman.conf`, the installer, `/opt/aios-repo`, `keys.sh`), clears `build/iso-work`, then runs `sudo mkarchiso -v -w build/iso-work -o out iso-build/`. The developer runs it.
  - `make iso SUDO=` builds unprivileged (archiso ≥ 89). mkarchiso then leaves files owned by the user's subordinate IDs, so the work directory is cleared with `unshare --map-auto --map-root-user rm -rf --one-file-system`. This needs `/etc/subuid` and `/etc/subgid` ranges for the user.
  - If clearing fails, make prints a hint and stops: "Device or resource busy" means an interrupted build left mounts under `build/iso-work`, to be unmounted with `umount -R`. `make clean-iso` clears the work directory the same way.

### 6.2 `aios-install` (bash, `set -euo pipefail`, shellcheck-clean, helpers in `lib/` unit-tested with bats)

**Modes:**
- **Interactive:** prompts for disk, hostname, username, user password, LUKS passphrase and timezone.
- **Unattended:** `--config <file>`, or automatically when `/sys/firmware/qemu_fw_cfg/by_name/opt/aios/install.conf/raw` exists. `--auto` (the ISO's `aios-install-auto.service`) installs from that fw_cfg file, and exits 0 when there is none.
  - `KEY=value` lines: `DISK HOSTNAME USERNAME USER_PASSWORD LUKS_PASSPHRASE TIMEZONE WIPE EXTRA_CMDLINE`.
  - Values are parsed by a whitelist parser, never `source`d. `EXTRA_CMDLINE` words may only hold letters, digits and `. _ , : = / + -`. There's no `@`, so no word can carry a manifest placeholder.
  - A `--config` file that group or others can read gets a warning. The summary says to delete the file.
- **`--dry-run`:** prints the commands that would change the system and runs only the read-only queries. Queries about what those commands would have created are skipped: the new partitions aren't checked, and the LUKS UUID is the placeholder `00000000-0000-0000-0000-000000000000`. So a dry run also works on a real machine.
- **Secrets:**
  - They reach programs only on stdin, never in argv, the log or the dry-run output.
  - The installer refuses to run under xtrace (`bash -x`, `SHELLOPTS=xtrace`).
  - It unsets the user password once it is hashed (step 1), and the LUKS passphrase after step 4.

**Steps:**
1. Preflight. Everything that can fail without touching the disk fails here:
   - `/sys/firmware/efi` exists and `/dev/mapper/aios` doesn't. `/mnt/aios-top`, `/efi` and `/var/lib/sbctl` aren't mount points yet.
   - `DISK` is a whole, writable block device of at least 16 GiB with no mounted filesystem.
   - `DISK` isn't the live medium. The `/run/archiso/bootmnt` source's device stack is walked down with `lsblk -nrso NAME,TYPE`, so a medium on a partition or a device-mapper target (Ventoy) still protects the disk below it.
   - Nothing holds `DISK`: `lsblk` lists no child other than partitions, and `/sys/class/block/<dev>/holders` is empty for the disk and every partition. Otherwise it stops with `<disk> is in use by <holder> (LVM/MD/dm); deactivate it first`.
   - The disk's `diskseq` (`/sys/class/block/<dev>/diskseq`), model, serial and size are recorded.
   - Network: `curl -fsI` (HTTP errors fail too) to `https://geo.mirror.pkgbuild.com`, and to `cachyos.db` on the first `https` `Server` of `/etc/pacman.d/cachyos-mirrorlist`.
   - x86-64-v3 detection (`/lib/ld-linux-x86-64.so.2 --help` lists "x86-64-v3 (supported, searched)"). If v3 isn't supported, the v3 CachyOS repos are dropped from the generated `pacman.conf`.
   - The live keyring trusts exactly the pinned CachyOS keys (step 9).
   - The filled-in manifest (and, without v3, the stripped `pacman.conf`), the yescrypt hash of `USER_PASSWORD` (`mkpasswd`) and the `usbguard generate-policy` output are made now and kept in memory. Steps 6 and 12 write them.
2. Confirm the wipe:
   - It shows the recorded model, serial, size and diskseq, and `lsblk -o NAME,SIZE,FSTYPE,LABEL,MODEL <disk>`.
   - Interactive mode requires typing the disk path; unattended mode requires `WIPE=yes`.
3. Partition:
   - Re-read the diskseq. If another disk now has the name, stop with `disk changed since validation`, before anything is written.
   - `wipefs -a`, `sgdisk --zap-all`, then `-n1:0:+2G -t1:EF00 -n2:0:0 -t2:8309`.
   - `udevadm settle`, then `blockdev --rereadpt`. While udev still has a new partition open the re-read fails with EBUSY, so it is tried up to five times; after that the failure is fatal.
   - `udevadm settle` again. Then exactly partitions 1 and 2 must exist.
   - `wipefs -a` on both new partitions, so an old signature inside them (a LUKS header, a btrfs superblock) can't confuse blkid.
   - `mkfs.fat -F32 -n EFI`.
4. Encrypt:
   - `cryptsetup luksFormat --type luks2 --pbkdf argon2id` (passphrase from stdin), then `cryptsetup open … aios`.
   - `systemd-cryptenroll --recovery-key`, with the key printed and saved nowhere.
   - On a terminal (but not with `--auto`), wait for Enter: `Press Enter after writing down the recovery key`.
5. `mkfs.btrfs -L aios /dev/mapper/aios`. Mount the top level and create `@blank` (skeleton §2, then `btrfs property set -ts … ro true`), `@persist`, `@home` and `@log`.
6. Copy `/usr/share/aios/defaults/manifest` to `@persist/aios/config`, substituting hostname, username, timezone and `EXTRA_CMDLINE`. Then `git init`, commit "aios: initial manifest". Write the yescrypt hash from step 1 to `@persist/aios/secrets/passwd/<user>` (0600). Copy `/opt/aios-repo` to `@persist/aios/repo`.
7. Mount the ESP at `/efi` on the live system, where the installed system mounts it too.
8. Secure Boot keys:
   - Bind `@persist/var/lib/sbctl` to the live system's `/var/lib/sbctl`.
   - `sbctl create-keys`.
   - Then `aios bootstrap` (step 9) can sign.
9. `aios bootstrap --target /mnt/aios-top --esp /efi --manifest /mnt/aios-top/@persist/aios/config/manifest.toml --luks-uuid <uuid>`.
   - It takes `--luks-uuid` (from `cryptsetup luksUUID`). Its pacstrap verifies with, and copies, the live keyring. So step 1 checks that this keyring trusts exactly the CachyOS keys pinned in `installer/lib/keys.sh`, which `make keys` (part of `make iso`) generates from the build host's keyring.
10. `bootctl install --esp-path=/efi`. Write `loader.conf` (`default aios-gen-*-cachyos*`, `timeout 3`, `editor no`). Sign `systemd-bootx64.efi` and `BOOTX64.EFI` with `sbctl sign -s`. With the ESP at `/efi`, the paths sbctl saves in its database (`/efi/EFI/...`, kept in `@persist`) are the ones the installed system re-signs.
11. If `sbctl status` reports Setup Mode, run `sbctl enroll-keys --microsoft`. If that fails, the install still completes, and the summary points to `aios secureboot enroll`.
12. Write the USBGuard rules from step 1 to `@persist/var/lib/usbguard/rules.conf` (§5.5).
13. Finish:
   - Unmount everything and `cryptsetup close aios`.
   - Print the summary: the recovery key reminder, `aios secureboot enroll` (if not enrolled), `aios tpm enroll`, and for `--config`, deleting the config file.
   - Exit 0. Only `--auto` reboots. Otherwise the summary says to remove the install medium and reboot.

**Failure cleanup** (the EXIT trap, §7):
- Each mount, and the LUKS open, is tracked before its command runs.
- The trap runs without errexit and ignores further INT, TERM and SIGPIPE. A closed, read-only or broken-pipe stderr doesn't stop it.
- It unmounts the tracked mounts newest first with `umount -R` (lazily if busy), each only if `mountpoint -q` says it's mounted. The step 1 mount point check makes sure the trap never unmounts something this run didn't mount.
- Then, if `/dev/mapper/aios` exists, it unmounts everything else mounted from it, deepest first (`findmnt -rno TARGET -S /dev/mapper/aios`), and closes it.
- It names the failed step, and says whether the disk was changed yet (it is from step 3 on). A failure after step 13 has unmounted everything (the reboot, say) leaves AIOS installed, and the trap says so.

## 7. Error handling summary

| Failure | Behavior |
|---|---|
| Invalid manifest | `plan`/`apply` refuse with `manifest.toml:line:col: <reason>`. Nothing changes |
| Any apply step fails | Candidates and the candidate root are deleted, the lock is released, and the command exits non-zero with `aios: step <name> failed: <detail>`. The booted gen is untouched. A panic cleans up the same way. If the candidate tree won't unmount, its subvolumes are kept for the next boot to delete |
| A failure after the commit point (§4.3 step 11: fallback UKI rename, ESP fsync, `bootctl set-default ""`, deleting `@root-cand`, unmounting the top level) | gen-N+1 is installed, so the command prints `aios: warning: <detail>` for each and exits 0. A failed fsync also skips `bootctl`, leaving the boot default as it was |
| `aios bootstrap` on a target that already holds generations | Refused in step `mount-top`, before anything is run on or deleted from the target |
| Power loss mid-apply | Stale `@*-cand` subvolumes are removed by `aios-root.service` at next boot and by the next apply |
| ESP full | Auto-gc respecting protected gens. If still short, abort before finalizing |
| UKI signing fails | Abort before finalizing. No UKI is copied to the ESP. There is no verify step (§4.3 step 9): an unsigned UKI that reached the ESP anyway doesn't start under Secure Boot, and boot counting falls back to the next entry |
| Gen fails health check | Not blessed. After 3 tries systemd-boot boots the next entry. `aios status` lists it as bad |
| Generation subvolume missing at boot | `aios-root.service` fails with a clear message and the boot stops. The initrd's root account is locked, so no emergency shell opens. Recovery: choose another boot entry (the menu still lists other gens) or boot the ISO |
| `@blank` missing, a symlink at `@blank` or at the generation's names, or a live/candidate name that isn't a subvolume, at boot | `aios-root.service` fails before deleting anything, with the same recovery |
| `@etc-live` fails to mount in the initrd | `sysroot-etc.mount` is required by `initrd-fs.target`, so the boot stops, with the same recovery |
| Concurrent `aios` commands | The second exits 1: "another aios operation is running" |
| Runtime edits to `/etc` | Allowed, but discarded at reboot. `aios status` lists them |
| Installer step fails | Stop with the step name. The trap unmounts what the run mounted and anything else on `/dev/mapper/aios`, then closes LUKS (§6.2). Before step 3 nothing on the disk has changed. From step 3 on, the disk is left in an undefined state and the user re-runs the installer |

## 8. Session for v0.1

The Base ISO includes no desktop. The Cockpit sub-project picks the compositor. The default manifest boots to a TTY login (plus serial console via `EXTRA_CMDLINE` in e2e). Daily-driving starts after Sentinel + Cockpit.

## 9. Testing

| Layer | Tooling | What |
|---|---|---|
| Rust unit/golden | `cargo test --workspace` | Manifest validation (each rule), gen naming/counter/GC, renderers (golden files), planner diff, argv sequences for apply/bootstrap/rollback/gc/secureboot/tpm with the fake runner, cleanup on a failure injected at every step |
| Shell | `shellcheck`, `bats` | `aios-root.sh` with a fake `btrfs`/`mount`/`umount` on PATH (with failure injection) and a fake `/proc/cmdline` (env override): normal boot, missing gen, missing `@blank`, no or invalid gen on cmdline, stale candidates, nested subvolumes (including one named like a top-level subvolume), a non-subvolume or a symlink (also dangling) at a live or candidate name, a symlink (also dangling) at `@usr-gen-N`, `@etc-gen-N` or `@blank`, and mount/snapshot/unmount failures. The fake `btrfs` resolves symlinks the way btrfs-progs does, so a missing check would delete the link's target. `aios-health.sh` with fake `findmnt` (including stacked mounts) and cmdline. The installer's tests are listed below the table |
| Units | `systemd-analyze verify` | `aios-root.service`, `sysroot-etc.mount`, `aios-health.service`, the ISO's `aios-install-auto.service` |
| Packaging | `makepkg` in `make repo`, `namcap` if available | PKGBUILDs build |
| E2E | `make e2e`: pytest harness in `tests/e2e/`, QEMU (`-enable-kvm -cpu host -m 4G`), OVMF `OVMF_CODE.secboot.4m.fd` + a copy of the vars, `swtpm` socket TPM 2.0, a 20 GiB qcow2 | Boots the ISO once, with the fw_cfg install config and `-no-reboot`, so QEMU exits when the installer reboots. Then it powers on from the disk alone, without the CD-ROM, fw_cfg or `-no-reboot` (the ISO's `--auto` would install again), and keeps the vars copy, the swtpm state, the disk and `-cpu host`. Later reboots are guest reboots. It drives the serial console via a unix socket: install → reboot → LUKS passphrase → log in as the test user → assertions (a)–(g) from §1. An install wait fails at once on `aios-install: error: …` or the trap's `step N (name) failed`, quoting the line. A failed run keeps the disk and TPM state in `build/e2e/`, and `--keep-vm` keeps them after a pass too. Also, since only a real root run exercises it, the private mount namespace (§4.2): during and after an `aios apply` (and after one killed with SIGKILL mid-build), `findmnt` in the host namespace shows nothing under `/run/aios`; the apply still reaches the ESP through the `/efi` automount; a second apply after the killed one succeeds. Needs `out/aios-*.iso` |

The installer's bats tests use fake `lsblk`, `findmnt`, `mountpoint` and `curl`, and a fake sysfs:
- **`lib/` helpers:**
  - the config parser (rejects unknown keys, shell metacharacters and `@` in `EXTRA_CMDLINE`);
  - disk validation (holders, the live medium's device stack, diskseq, exactly two new partitions);
  - the network probes and v3 detection parsing;
  - the partition table re-read, retried while busy;
  - the cleanup: newest first, then the mapping's other mounts deepest first, with a closed, read-only or broken-pipe stderr, and through a second interrupt.
- **`aios-install` itself, in dry-run mode:**
  - golden command lists (virtio and NVMe disks, a path with spaces) and the exact read-only queries;
  - a failure injected at a step;
  - a disk that changes before the wipe;
  - the reboot rule, and the Enter prompt on a terminal (under `script`);
  - the passwords unset once used.
- **The ISO and the Makefile:** `make iso-check` checks the profile without building it. `tests/bats/makefile.bats` runs the `make iso` cleanup and the venv rule with fake tools.

`make check` = `cargo test --all-features` + `cargo clippy -D warnings` (with and without features) + the release-binary check for test hooks (§4.5) + shellcheck + bats + `systemd-analyze verify` + the e2e harness's unit tests (`make e2e-unit`). It needs no root and no VM. Without a system pytest, `make tools` installs a hash-pinned one into `build/venv/`. The venv is keyed on the Python minor version (`build/venv.python`), so a Python upgrade rebuilds it.

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
9. Check each signature after `sbctl sign` (§4.3 step 9): run `sbctl verify --json` and require `is_signed` for the UKI, since plain `sbctl verify FILE` exits 0 for an unsigned file.
