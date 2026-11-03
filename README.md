# AIOS

A personal, AI-driven, security-focused Linux distribution (Arch-based) with
NixOS-style guarantees: read-only generations, an impermanent root, and a
declarative manifest as the only way to change the system.

- Vision: `docs/superpowers/specs/2026-11-03-aios-vision.md`
- Base ISO design: `docs/superpowers/specs/2026-11-03-base-iso-design.md`
- Plans: `docs/superpowers/plans/`

## Development

```bash
make check   # Rust fmt/clippy/tests, shellcheck, bats, systemd-analyze verify; no root needed
make tools   # fetch pinned shellcheck and bats into build/tools/ if they are not installed
make repo    # build aios-base and aios-cli into build/repo/ (local pacman repo); no root needed
```

## Layout

- `aios-cli/`: Rust workspace for the `aios` command
- `initrd/`: `aios-root.sh`, its initrd units and the `aios` mkinitcpio hook
- `base/`: the `aios-base` payload (hardening, health check, network and swap defaults)
- `manifest/`: the default manifest repo the installer copies
- `packaging/`: PKGBUILDs for `aios-cli` and `aios-base`
- `tests/bats/`: shell tests with fake `btrfs`, `mount`, `umount` and `findmnt`

## Packages

- `aios-cli`: the `aios` binary, installed to `/usr/bin/aios`
- `aios-base`: hardening config, initrd hook and units, boot health check, and the default
  manifest under `/usr/share/aios/defaults/manifest/`

`make repo` builds both into `build/repo/`, with the database `aios-local.db.tar.gz`.
