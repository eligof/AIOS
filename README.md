# AIOS

A personal, AI-driven, security-focused Linux distribution (Arch-based) with
NixOS-style guarantees: read-only generations, an impermanent root, and a
declarative manifest as the only way to change the system.

- Vision: `docs/superpowers/specs/2026-11-03-aios-vision.md`
- Base ISO design: `docs/superpowers/specs/2026-11-03-base-iso-design.md`
- Plans: `docs/superpowers/plans/`

## Development

```bash
make check      # Rust, shellcheck, bats, systemd-analyze verify, e2e harness unit tests; no root
make tools      # fetch pinned shellcheck, bats (build/tools/) and pytest (build/venv/) if missing
make repo       # build aios-base and aios-cli into build/repo/ (local pacman repo); no root needed
make iso-check  # check the archiso profile in iso/ without building it; no root needed
```

## Building and testing the ISO

Build on a CachyOS host (or any Arch host whose pacman keyring trusts the CachyOS key).
Only `make iso` uses root, and it asks `sudo` for the commands that need it.

### Prerequisites

```bash
sudo pacman -S --needed archiso arch-install-scripts sbctl swtpm systemd-ukify python-pytest
```

- archiso 91 or 92 (or newer) is expected; `make iso SUDO=` needs 89 or newer.
- `make e2e` also needs QEMU with OVMF Secure Boot firmware and read-write access to `/dev/kvm`.
- `python-pytest` is optional: `make tools` builds a pinned pytest in `build/venv/` instead.

### Steps

1. `make tools` fetches the pinned shellcheck and bats into `build/tools/` and builds the
   pytest venv if needed. Run it once; it needs the network.
2. `make check` runs everything that needs no root and no VM: Rust fmt, clippy and tests,
   shellcheck, the bats suites, `systemd-analyze verify`, and the e2e harness unit tests.
3. `make repo` builds `aios-cli` and `aios-base` into `build/repo/` (the local pacman repo
   the ISO and the installed system use). makepkg runs on copies of the PKGBUILDs in
   `build/pkgbuild/`, so the tracked files are never rewritten.
4. `make iso` first runs `make repo` (every time, so the ISO never ships packages older
   than the checkout), then builds `out/aios-YYYY.MM.DD-x86_64.iso`. Run it as yourself, not as
   `sudo make iso`: it writes `iso-build/` without root, then runs
   `sudo mkarchiso -v -w build/iso-work -o out iso-build/`. For an unprivileged archiso build
   (needs `/etc/subuid` and `/etc/subgid` ranges for your user) use `make iso SUDO=`.
5. `make e2e` installs the newest `out/aios-*.iso` into a QEMU VM (KVM, OVMF Secure Boot in
   Setup Mode, swtpm) unattended and checks spec section 1 (a) to (g) over the serial console.
   It needs no root. Expect about an hour, and a download of about 2 GB (packages for the
   installed system, fetched inside the VM). The VM disk is a sparse 20 GiB file in
   `build/e2e/`. For the first run use `make e2e E2E_ARGS=--keep-vm`, so the disk survives a
   pass too and you can boot it by hand. Without `--keep-vm`, the disk and TPM state are
   deleted only when every e2e test passed; a failed, partial or Ctrl-C'd run keeps them.
6. `make clean-iso` removes `iso-build/` and `build/iso-work/`.

### Logs

Everything the VM printed on its serial console is in `build/e2e/serial.log`. The installer prints its
steps and errors on the console.

### If a step fails

- `make tools` or `make check`: read the first failing tool's output; a missing tool is
  named (install it, or run `make tools`).
- `make iso` stops at "different device" or "Device or resource busy" from `rm`: an
  interrupted build left mounts under `build/iso-work`. Run `findmnt -R build/iso-work`,
  then `umount -R` each one, and run make again. "Permission denied" means the directory
  was built in the other mode: clear it with the same mode that built it (sudo, or
  `SUDO=` for unprivileged).
- `make e2e` fails or times out: read `build/e2e/serial.log` from the bottom. The VM disk
  and TPM state stay in `build/e2e/` so you can inspect them. Delete `build/e2e/` to start
  from scratch.
- The installer says the package mirrors are unreachable: check the network of the live
  system (Wi-Fi: `iwctl`) and run `aios-install` again. A failed install unmounts and closes
  LUKS; the installer says whether the disk was changed.

### Installing on real hardware

`aios-install` erases a whole disk. Be careful:

- Back up everything on the machine first.
- Try the ISO in a VM (`make e2e`, or boot it in QEMU by hand) before the real machine.
- Write the LUKS recovery key down when the installer prints it. It is shown once and
  stored nowhere else.
- Boot the stick with Secure Boot in Setup Mode. If the installer could not enroll the keys,
  boot AIOS and run `run0 aios secureboot enroll`. Once Secure Boot is on, bind the disk to
  the TPM with `run0 aios tpm enroll`.
- NVIDIA: the default `lockdown = "integrity"` rejects unsigned kernel modules. Check
  whether your NVIDIA modules are signed (spec section 5.4) before relying on it; otherwise
  the machine needs `lockdown = "none"` in its manifest, and `aios plan` warns about that.

## Daily use

The manifest lives in `/persist/aios/config/` (a git repo). Change it, then:

| Command | What it does |
|---|---|
| `aios plan` | Show what `apply` would change compared with the booted generation |
| `run0 aios apply` | Build the next generation from the manifest (`--yes` skips the question) |
| `run0 aios apply --upgrade` | Build a new generation even without manifest changes: a full `pacman -Syu` |
| `run0 aios rollback N` | Boot generation N at the next reboot (`--force` for one marked bad) |
| `run0 aios gc` | Delete old generations (`--keep N`, default 5) |
| `aios status` | Booted, default and bad generations, and runtime changes to `/etc` |
| `run0 aios passwd USER` | Set a user's password; used from the next `apply` |

Reboot to boot a new generation. A generation that fails to boot three times is marked bad
and the system falls back to the previous one.

## Layout

- `aios-cli/`: Rust workspace for the `aios` command
- `initrd/`: `aios-root.sh`, its initrd units and the `aios` mkinitcpio hook
- `base/`: the `aios-base` payload (hardening, health check, network and swap defaults)
- `manifest/`: the default manifest repo the installer copies
- `packaging/`: PKGBUILDs for `aios-cli` and `aios-base`
- `installer/`: `aios-install` and its `lib/` (copied into the ISO), `gen-keys.sh`
- `iso/`: the archiso profile (UEFI, systemd-boot) and `build-profile.sh`
- `tests/bats/`: shell tests with fake `btrfs`, `mount`, `umount`, `findmnt` and installer tools
- `tests/e2e/`: the QEMU end-to-end harness (pytest)

## Packages

- `aios-cli`: the `aios` binary, installed to `/usr/bin/aios`
- `aios-base`: hardening config, initrd hook and units, boot health check, and the default
  manifest under `/usr/share/aios/defaults/manifest/`

`make repo` builds both into `build/repo/`, with the database `aios-local.db.tar.gz`.

## License

AIOS is licensed under the GNU General Public License v3.0 or later. See `LICENSE`.
