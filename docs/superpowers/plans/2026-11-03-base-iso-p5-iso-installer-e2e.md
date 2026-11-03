# Base ISO — Phase 5: ISO Profile, Installer, E2E Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the pieces that turn the packages into an installable, tested system:
- `aios-install`, the bash installer of spec §6.2, with a dry-run mode
- the archiso profile `iso/` (UEFI only, systemd-boot), plus `make iso-build`, `iso`, `iso-check` and `clean-iso`
- the QEMU end-to-end harness `tests/e2e/`, which installs the ISO unattended and checks spec §1 (a)–(g), plus `make e2e` and `make e2e-unit`

`make check` grows the installer and profile bats suites, the live ISO's unit in `systemd-analyze verify`, and the harness's pytest unit tests.

**Architecture:**
- **Installer.** `installer/aios-install` orchestrates steps 1–13 through small libraries in `installer/lib/`.
  - Every command that changes the disk or the live system goes through `run_cmd`, `run_stdin` (secrets on stdin) or `run_write`.
  - With `AIOS_INSTALL_DRYRUN=1` (`--dry-run`) those print `DRYRUN <command>` and change nothing. Read-only queries (`lsblk`, `sbctl status`, `mkpasswd`, …) still run.
  - bats tests every library with fakes. It then runs the whole installer in dry-run mode against a fake machine and compares the ordered command list to a golden list.
- **Profile.** `iso/` is archiso's releng profile (archiso 92) cut down to UEFI + systemd-boot, plus the AIOS pieces.
  - `iso/build-profile.sh` (no root) assembles `iso-build/`: the profile, `pacman.conf` with the absolute `build/repo` path, the installer, `/opt/aios-repo`, and `keys.sh`.
  - `keys.sh` holds the CachyOS key fingerprints that `installer/gen-keys.sh` pins from the build host's keyring.
  - Only `mkarchiso` needs root.
- **Live ISO.** `aios-install-auto.service` runs `aios-install --auto`. In a VM that has the fw_cfg file `opt/aios/install.conf`, that is an unattended install with a reboot at the end. Without it, the command exits at once.
- **Harness.** `vm.py` runs swtpm and QEMU as the user. `serial.py` drives the serial console through a unix socket, with expect-style matching and a sentinel protocol for command results.
  - The unit tests play the guest with a fake console thread.
  - `test_e2e.py` needs a built ISO and swtpm, and is skipped without them. `make e2e` fails instead of reporting a skip as a pass.

**Tech Stack:** bash 5.3, bats-core 1.11.1, shellcheck 0.10.0, archiso 92 (`uefi.systemd-boot` boot mode), systemd 262 units, pacman 7.1 (`pacman-conf`, `pacman -Sp`), GnuPG 2.4, Python 3.14 with pytest 9.2.0 (system `python-pytest`, or a hash-pinned venv), QEMU with KVM (q35, OVMF `OVMF_CODE.secboot.4m.fd`), swtpm.

**Spec:** `docs/superpowers/specs/2026-11-03-base-iso-design.md`:
- §1: success criteria, e2e assertions (a)–(g)
- §2: the `@blank` skeleton
- §3: boot flow, boot counting
- §4.2: `aios bootstrap`
- §5.1, §5.5: Secure Boot, LUKS, USBGuard
- §6.1: the ISO profile
- §6.2: the installer
- §7: installer failure handling
- §9: the E2E row

**Depends on:** Phases 1–4, all merged (HEAD `a8c3edd` when this plan was written):
- `aios bootstrap` (Phase 3)
- the default manifest and the `aios-base` payload (Phase 4)
- `make repo` → `build/repo/aios-local.db.tar.gz` (Phase 4 Task 7)

Phase 5 changes no Rust code. `make check` still runs the Rust suites.

**Phase 3 contracts this plan relies on** (from "Contracts for Phase 4/5" in `2026-11-03-base-iso-p3-exec-cli.md`, which is authoritative):
- **CLI:** `aios bootstrap --target <top> --esp <esp> --manifest <path> --luks-uuid <uuid>`. It needs root. It loads the `--manifest` file it is given, and that file's directory is the manifest repo (`a8c3edd`).
- **Exit codes:** 0 success, 1 any operational error, 2 invalid manifest only. The installer reports the code in its failure line.
- **Output** the harness matches:
  - bootstrap prints `gen-0001 built in <target>`
  - `aios plan` prints `no changes` when clean
  - `aios apply` prints `reboot to activate gen-NNNN`
  - step failures print `aios: step <name> failed: <detail>`
- **What bootstrap expects from the installer (contract 7)**, and where this plan provides it:

  | Contract | Installer step |
  |---|---|
  | Top level mounted at `--target` with `@blank` (the §2 skeleton, read-only, including `var/lib/pacman → ../../usr/lib/pacman`), `@persist`, `@home` and `@log`, and no generations. Bootstrap never mounts or unmounts the top level | 5 |
  | ESP mounted at `--esp` | 7 |
  | `--luks-uuid` from `cryptsetup luksUUID <partition>` | 4 (passed in 9) |
  | `@persist/aios/config` is a git repo with a commit, root-owned, not group/world-writable (0755). `@persist/aios/secrets` and `passwd/` are 0700, and `passwd/<user>` is one yescrypt line, 0600 (contract 6) | 6 |
  | `@persist/aios/repo` holds the local repo. Bootstrap binds it into the candidate itself, so the live system needs no `/persist` | 6 |
  | `/var/lib/sbctl` on the live system is a bind of `@persist/var/lib/sbctl`, because `sbctl sign` runs on the host | 8 |
  | Every `Include =` file the manifest's `pacman.conf` names exists on the live system (the CachyOS mirrorlists) | the ISO package list (Task 6) |
  | The live pacman keyring trusts the CachyOS key, because pacstrap verifies with it and copies it. Bootstrap then runs `pacman-key --populate archlinux cachyos` in the candidate | preflight (step 1) checks the pinned fingerprints |
  | After bootstrap, the installer runs `bootctl install`, writes `loader_conf()` to the ESP and signs systemd-boot. Bootstrap never calls `bootctl` | 10 |
  | Bootstrap creates `@home/<user>` (0700, owned by the user) and the persist directories | not repeated by the installer |
- **Paths:** `/persist/aios/config/manifest.toml`, and the UKIs `/EFI/Linux/aios-gen-NNNN-{cachyos,lts}+3.efi`.

**Environment note for every task:** Rust is installed via rustup without PATH changes. Start every shell with:
```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/eli/Development/AIOS
```
- **No root.** The user has no passwordless sudo, so never run `sudo`. Steps marked **USER RUNS** are for the user. The executing agent only checks their results afterwards, or stops with the handoff in Task 9.
- **zsh.** The Bash tool runs zsh, which does not word-split an unquoted `$var`. Every snippet below either avoids that or wraps itself in `bash -c`. Everything that matters lives in scripts and bats files anyway.
- **Test tools.** `shellcheck` and `bats` come from `make tools` (`build/tools/`, already present). pytest comes from the system `python-pytest`, or, from Task 7 on, from a venv that `make tools` builds in `build/venv/` from hash-pinned wheels. The venv needs the network once.
- **Space.** `/tmp` is a small tmpfs. The e2e VM lives in `build/e2e/` (a sparse 20 GiB qcow2), never in `/tmp`.

**Tools that may be missing** (the user was asked to install `archiso`, `arch-install-scripts`, `sbctl`, `swtpm`, `systemd-ukify` and `python-pytest`):

| Tool | Used by | If missing |
|---|---|---|
| `python-pytest` | `make e2e-unit`, `make e2e` | `make tools` creates `build/venv` (`python3 -m venv` + `pip install --require-hashes -r tests/e2e/requirements.txt`) |
| `archiso` (`mkarchiso`) | `make iso` (USER RUNS) | `make iso-check` covers the profile statically; the build is the user's step |
| `swtpm` | `make e2e` | `test_e2e.py` is skipped with "swtpm is not installed (pacman -S swtpm)"; `make e2e` fails with that line |
| `arch-install-scripts`, `sbctl`, `systemd-ukify` | the ISO and the installed system, not the build host's tests | nothing to do: the installer tests fake them, and the ISO gets them from its package list |
| `pacman-conf`, `pacman`, `gpg` | profile and keyring tests | each such test skips with a message |

**GateGuard note:** a local hook blocks the *first* Write/Edit of each new file, and the first Bash call, until you state some facts:
- callers/importers
- that no existing file serves the purpose
- data schema if any
- the user's instruction

Answer briefly in text and retry the same call. A second gate fires on any Bash command containing `rm -rf` (or other destructive words such as `truncate` or `git checkout --`, even inside a heredoc). For that one, list the files the command modifies or deletes, give a one-line rollback, and quote the instruction, then retry. The user's instruction is: "finish this project, use skills and subagents".

**Verified while writing this plan.** Every file below was created in a scratch copy of this repo at HEAD `a8c3edd` and run on this host:
- **shellcheck** 0.10.0 is clean, including `-x` on the installer.
- **bats:** all 117 tests pass (40 existing, 77 new), and each new file fails as stated before its implementation exists.
- **pytest** 9.2.0, from a venv built from `tests/e2e/requirements.txt`: the 19 harness unit tests pass, and `test_e2e.py` reports 7 skips with their reasons.
- **Units:** `systemd-analyze verify` prints nothing for the four units.
- **Rust:** the full `make check` passes, including HEAD's `rust-check`, which this plan does not change.
- **Plan replay:** a final round trip rebuilt everything from this document's text alone.
  - It extracted all 59 files, which are byte-identical to the scratch files.
  - It ran the `chmod` steps and the Task 6 symlink script on a clean `git archive` of HEAD.
  - It then ran `make keys tools shell-check bats-check unit-check e2e-unit iso-check`, and all passed. `make tools` built the venv.
  - Task 7's intermediate unit-test file passed its 17 tests, and the fail-first states of Tasks 7 and 8 failed as stated.
- **Real inputs:** `iso/build-profile.sh` assembled a profile from the real `build/repo` (Phase 4's `make repo` at `99f3fda`) and the real `make keys` output. With that profile's `pacman.conf`, the full ISO package list resolves with `pacman -Sp` against freshly synced private databases (`fakeroot pacman -Sy --dbpath …`, the way `checkupdates` does it). That includes `aios-cli` and `aios-base` from `[aios-local]` and all their dependencies.
- **QEMU:** the harness's own `qemu_argv`, minus the TPM because swtpm is not installed here, booted OVMF's Secure Boot firmware under KVM. The harness's `Serial` read OVMF's `BdsDxe` lines through the unix socket. With the empty disk, OVMF offered no network boot (`romfile=`). The argv with a CD-ROM attached starts too.
- **Against real tools:**
  - systemd-boot's source: a digit key selects that menu entry, and auto entries come after the sorted loader entries.
  - systemd-cryptsetup's prompt text: `Please enter passphrase or recovery key for disk …`.
  - `systemd-cryptenroll --unlock-key-file`.
  - pkttyagent's `==== AUTHENTICATION COMPLETE ====`.
  - `bootctl status`'s `Secure Boot: … (setup)` line.

Not verified: `mkarchiso`, the installer on a real disk, swtpm and the full e2e run. They need root or tools this host lacks, so they are the user's steps in Task 9.

If an expected output differs, that is a real difference in your environment. Investigate it (superpowers:systematic-debugging) instead of editing a test until it passes.

**Spec corrections** (Task 9 writes them into the spec):
1. **§6.1 boot modes.** archiso 86 replaced the ESP/El Torito systemd-boot modes with the single `uefi.systemd-boot`, so the profile uses `bootmodes=('uefi.systemd-boot')`.
2. **§6.1 `make iso`.** It first generates `iso-build/` (no root), then runs `sudo mkarchiso -v -w build/iso-work -o out iso-build/`.
3. **§6.1 packages.** The list adds `cachyos-keyring`, `cachyos-mirrorlist` and `cachyos-v3-mirrorlist`. Phase 3 contract 7 needs them on the live system.
4. **§6.1 boot entries.** releng's speech entry and its services are dropped. The menu is `01-aios-linux.conf` (default), `03-aios-serial.conf` and `04-aios-memtest86+x64.conf`.
5. **§6.2 unattended mode.** "Automatically" means `aios-install --auto`, run by the live ISO's `aios-install-auto.service`. It needs `qemu_fw_cfg`, which it loads first.
6. **§6.2 step 9, the keyring.** Bootstrap populates the candidate keyring from `cachyos-keyring` (Phase 3). So the pin moves to the installer's preflight: the live keyring must trust exactly the CachyOS keys pinned in `installer/lib/keys.sh`. `make keys` generates that file and it is not committed.
7. **§6.2 step 11.** A failed `sbctl enroll-keys` is a warning, not a failed install. The summary then points to `aios secureboot enroll`.

---

## File Structure

```
Makefile                                   + installer/iso/e2e lists; keys, iso-build, iso, iso-check, clean-iso, e2e-unit, e2e; pytest venv
.gitignore                                 + iso-build/, installer/lib/keys.sh, .pytest_cache/
README.md                                  + "Building and testing the ISO"
installer/aios-install                     the installer: steps 1-13, --config/--auto/--dry-run (755)
installer/gen-keys.sh                      writes lib/keys.sh from the host keyring (755, not on the ISO)
installer/lib/common.sh                    log, die, step, run_cmd, run_stdin, run_write (dry-run)
installer/lib/config.sh                    whitelist KEY=value parser, validators, fw_cfg discovery
installer/lib/disk.sh                      partition names, live medium, disk validation
installer/lib/cpu.sh                       x86-64-v3 detection, pacman.conf v3 strip
installer/lib/manifest.sh                  placeholder substitution, home template rename
installer/lib/skeleton.sh                  the @blank skeleton (spec §2)
installer/lib/secrets.sh                   yescrypt hash via mkpasswd
installer/lib/usbguard.sh                  rules.conf composition (spec §5.5)
installer/lib/boot.sh                      loader.conf, sbctl Setup Mode check
installer/lib/keyring.sh                   trusted CachyOS fingerprints, pin check
installer/lib/cleanup.sh                   mount tracking, cleanup, the EXIT trap
installer/lib/keys.sh                      GENERATED by make keys (gitignored)
iso/profiledef.sh                          iso_name=aios, bootmodes=(uefi.systemd-boot)
iso/packages.x86_64                        releng list + AIOS additions
iso/pacman.conf.in                         core, extra, cachyos, aios-local (@AIOS_REPO@)
iso/build-profile.sh                       builds iso-build/ (755, not copied into it)
iso/efiboot/loader/loader.conf             default 01-aios-linux.conf
iso/efiboot/loader/entries/01-aios-linux.conf
iso/efiboot/loader/entries/03-aios-serial.conf          + console=ttyS0,115200
iso/efiboot/loader/entries/04-aios-memtest86+x64.conf
iso/airootfs/...                           live system overlay (22 files, 15 symlinks, see Task 6)
tests/bats/fakes/installer                 multi-call fake: lsblk findmnt gpg mkpasswd cryptsetup sbctl usbguard curl modprobe (755)
tests/bats/installer-config.bats           19 tests
tests/bats/installer-disk.bats             13 tests
tests/bats/installer-target.bats           14 tests
tests/bats/installer-keys.bats              9 tests
tests/bats/installer-dryrun.bats           12 tests
tests/bats/iso-profile.bats                10 tests (= make iso-check)
tests/e2e/__init__.py                      package marker (so serial.py never shadows pyserial)
tests/e2e/requirements.txt                 hash-pinned pytest 9.2.0 and its 4 dependencies
tests/e2e/vm.py                            QEMU/swtpm argv, install config, requirements, Vm
tests/e2e/serial.py                        Serial (expect), sentinel protocol, Shell, boot/LUKS/login helpers
tests/e2e/conftest.py                      incremental steps, --keep-vm
tests/e2e/test_harness_unit.py             19 tests (part of make check)
tests/e2e/test_e2e.py                      7 ordered steps: install, (a)-(g)
```

**On the ISO** (Task 6 checks the generated profile):

| Source | ISO path |
|---|---|
| `installer/aios-install` | `/usr/local/bin/aios-install` (755, via `file_permissions`) |
| `installer/lib/*.sh` + `keys.sh` | `/usr/local/lib/aios-install/` (644) |
| `build/repo/` | `/opt/aios-repo/` (seeds `@persist/aios/repo`) |
| `iso/airootfs/etc/systemd/system/aios-install-auto.service` | enabled in `multi-user.target.wants` |
| `aios-base` (package) | `/usr/share/aios/defaults/manifest/`, `/usr/lib/aios/cmdline-hardening` (read by bootstrap on the live system) |

**On the target disk** (spec §2, written by the installer):

| Path | Mode | Step |
|---|---|---|
| GPT: p1 ESP FAT32 2 GiB (`EF00`), p2 LUKS2 (`8309`) | | 3 |
| LUKS2 argon2id, passphrase + recovery key, mapping `aios` | | 4 |
| btrfs `aios`: `@blank` (skeleton, ro), `@persist`, `@home`, `@log` | | 5 |
| `@persist/aios/config/` (manifest repo, one commit "aios: initial manifest") | 0755, root | 6 |
| `@persist/aios/secrets/passwd/<user>` | 0700/0700/0600 | 6 |
| `@persist/aios/repo/` | root | 6 |
| `@persist/var/lib/sbctl/` (keys from `sbctl create-keys`) | 0700 | 8 |
| gen-1 (`aios bootstrap`), ESP `EFI/Linux/*.efi` | | 9 |
| ESP `EFI/systemd/systemd-bootx64.efi`, `EFI/BOOT/BOOTX64.EFI` (signed), `loader/loader.conf` | | 10 |
| `@persist/var/lib/usbguard/rules.conf` | 0600 | 12 |

---

### Task 1: Installer foundation: the command wrappers and the install config

**Files:**
- Create: `installer/lib/common.sh`, `installer/lib/config.sh`
- Test: `tests/bats/installer-config.bats`
- Modify: `Makefile` (the lists)

How it works:
- `run_cmd` is the spec's "run wrapper". It is not called `run`, because the bats tests source the libraries, and bats' own `run` would be shadowed.
- **Quoting.** `quote_cmd` prints plain words as they are and single-quotes anything else (`${arg@Q}`), so the dry-run text is identical on every bash. bash's `printf %q` escapes commas, which would make `subvolid=5\,compress=zstd`.
- **Secrets.** `run_stdin DATA CMD…` pipes `DATA` without a newline: `cryptsetup --key-file -` reads its key verbatim. Its log and dry-run lines end in `<secret`, never in the data.
- **Failure hook.** Dry-run mode fails exactly those commands whose text is listed in `$AIOS_INSTALL_DRYRUN_FAILS`. That lets Task 5 test the failure trap without touching anything.
- **Config parsing.** `parse_config` is a whitelist parser.
  - The value is everything after the first `=`, verbatim. Nothing is sourced or evaluated.
  - Unknown, malformed and duplicate keys are all reported, with their line numbers.
- **Validation.**
  - The values that reach commands, paths or the manifest (DISK, HOSTNAME, USERNAME, TIMEZONE, EXTRA_CMDLINE) must match strict patterns, so shell metacharacters, quotes and whitespace can never get through. The hostname and user name rules are the manifest's (`aios-manifest` `valid_hostname`/`valid_username`).
  - The two secrets accept any printable text, since they only ever reach a program on stdin. They may not contain control characters, and the LUKS passphrase needs 8 or more characters.
  - EXTRA_CMDLINE may not set a parameter AIOS sets itself. A test compares the list with `RESERVED_CMDLINE_KEYS` in `aios-manifest`.

- [ ] **Step 1: Write the failing tests**

`tests/bats/installer-config.bats`:
```bash
#!/usr/bin/env bats
# installer/lib/common.sh and config.sh: command wrappers, config parsing and validation
# (spec §6.2, §9).
# Literal $ and backticks in single quotes are test data; bats runs each test in a subshell.
# shellcheck disable=SC2016,SC2030,SC2031

setup() {
    LIB="$BATS_TEST_DIRNAME/../../installer/lib"
    # shellcheck source=/dev/null
    source "$LIB/common.sh"
    # shellcheck source=/dev/null
    source "$LIB/config.sh"
    CONF="$BATS_TEST_TMPDIR/install.conf"
    export AIOS_ZONEINFO="$BATS_TEST_TMPDIR/zoneinfo"
    mkdir -p "$AIOS_ZONEINFO/Asia"
    : >"$AIOS_ZONEINFO/UTC"
    : >"$AIOS_ZONEINFO/Asia/Jerusalem"
    export AIOS_PASSWD_FILE="$BATS_TEST_TMPDIR/passwd"
    printf '%s\n' 'root:x:0:0::/root:/bin/bash' 'alpm:x:946:946::/:/usr/bin/nologin' >"$AIOS_PASSWD_FILE"
    unset AIOS_INSTALL_DRYRUN AIOS_INSTALL_DRYRUN_FAILS
}

# good_config: a complete unattended config.
good_config() {
    cat >"$CONF" <<'EOF'
# e2e install config
DISK=/dev/vda
HOSTNAME=aios-e2e
USERNAME=tester
USER_PASSWORD=pa ss$;&|`x`
LUKS_PASSPHRASE=correct horse battery
TIMEZONE=Asia/Jerusalem
WIPE=yes
EXTRA_CMDLINE=console=ttyS0,115200 aios.test.fail_health=1
EOF
}

@test "run_cmd prints the quoted command in dry-run mode and runs nothing" {
    export AIOS_INSTALL_DRYRUN=1

    run run_cmd touch "$BATS_TEST_TMPDIR/a file"

    [ "$status" -eq 0 ]
    [ "$output" = "DRYRUN touch '$BATS_TEST_TMPDIR/a file'" ]
    [ ! -e "$BATS_TEST_TMPDIR/a file" ]
}

@test "run_cmd logs and runs the command otherwise" {
    run run_cmd touch "$BATS_TEST_TMPDIR/made"

    [ "$status" -eq 0 ]
    [ "$output" = "aios-install: + touch $BATS_TEST_TMPDIR/made" ]
    [ -f "$BATS_TEST_TMPDIR/made" ]
}

@test "run_stdin feeds the secret without a newline and never prints it" {
    run run_stdin 's3cret pass' sh -c 'cat >"$1"' _ "$BATS_TEST_TMPDIR/key"

    [ "$status" -eq 0 ]
    [ "$(od -An -c "$BATS_TEST_TMPDIR/key" | tr -s ' ')" = " s 3 c r e t p a s s" ]
    [[ "$output" != *s3cret* ]]

    export AIOS_INSTALL_DRYRUN=1
    run run_stdin 's3cret pass' cryptsetup open --key-file - /dev/vda2 aios
    [ "$output" = "DRYRUN cryptsetup open --key-file - /dev/vda2 aios <secret" ]
}

@test "run_write writes stdin with the mode, and only prints in dry-run mode" {
    printf 'hash\n' | run_write "$BATS_TEST_TMPDIR/secret" 0600

    [ "$(cat "$BATS_TEST_TMPDIR/secret")" = hash ]
    [ "$(stat -c %a "$BATS_TEST_TMPDIR/secret")" = 600 ]

    export AIOS_INSTALL_DRYRUN=1
    run run_write "$BATS_TEST_TMPDIR/other" 0644 <<<"content"
    [ "$output" = "DRYRUN write $BATS_TEST_TMPDIR/other 0644" ]
    [ ! -e "$BATS_TEST_TMPDIR/other" ]
}

@test "the dry-run failure hook fails exactly the listed command" {
    export AIOS_INSTALL_DRYRUN=1 AIOS_INSTALL_DRYRUN_FAILS="$BATS_TEST_TMPDIR/fails"
    echo "mkfs.btrfs -L aios /dev/mapper/aios" >"$AIOS_INSTALL_DRYRUN_FAILS"

    run run_cmd mkfs.btrfs -L aios /dev/mapper/aios
    [ "$status" -eq 1 ]
    run run_cmd mkfs.fat -F32 -n EFI /dev/vda1
    [ "$status" -eq 0 ]
}

@test "a complete config parses verbatim" {
    good_config

    parse_config "$CONF"

    [ "${CFG[DISK]}" = /dev/vda ]
    [ "${CFG[USER_PASSWORD]}" = 'pa ss$;&|`x`' ]
    [ "${CFG[LUKS_PASSPHRASE]}" = "correct horse battery" ]
    [ "${CFG[EXTRA_CMDLINE]}" = "console=ttyS0,115200 aios.test.fail_health=1" ]
    [ "${#CFG[@]}" -eq 8 ]
}

@test "comments, blank lines and CRLF line ends are accepted" {
    printf '# c\r\n\r\nDISK=/dev/vda\r\nHOSTNAME=h' >"$CONF"

    parse_config "$CONF"

    [ "${CFG[DISK]}" = /dev/vda ]
    [ "${CFG[HOSTNAME]}" = h ]
}

@test "unknown, malformed and duplicate keys are rejected with their line" {
    printf '%s\n' 'DISK=/dev/vda' 'ROOT_PASSWORD=x' 'hostname=h' ' DISK=/dev/sda' 'DISK=/dev/sdb' >"$CONF"

    run parse_config "$CONF"

    [ "$status" -eq 1 ]
    [[ "$output" == *"$CONF:2: unknown key ROOT_PASSWORD"* ]]
    [[ "$output" == *"$CONF:3: expected KEY=value"* ]]
    [[ "$output" == *"$CONF:4: expected KEY=value"* ]]
    [[ "$output" == *"$CONF:5: duplicate key DISK"* ]]
}

@test "the config is never executed or expanded" {
    cd "$BATS_TEST_TMPDIR"
    printf '%s\n' 'touch pwned1' 'HOSTNAME=$(touch pwned2)' 'DISK=`touch pwned3`' >"$CONF"

    run parse_config "$CONF"

    [ "$status" -eq 1 ]
    [ ! -e pwned1 ] && [ ! -e pwned2 ] && [ ! -e pwned3 ]
    parse_config <(printf 'HOSTNAME=$(touch pwned2)\n')
    [ "${CFG[HOSTNAME]}" = '$(touch pwned2)' ]
    [ ! -e pwned2 ]
}

@test "a complete config validates, with defaults for TIMEZONE and EXTRA_CMDLINE" {
    good_config
    parse_config "$CONF"
    validate_config 1

    grep -v -e '^TIMEZONE=' -e '^EXTRA_CMDLINE=' "$CONF" >"$CONF.min"
    parse_config "$CONF.min"
    validate_config 1
    [ "${CFG[TIMEZONE]}" = UTC ]
    [ "${CFG[EXTRA_CMDLINE]}" = "" ]
}

@test "missing required keys are all reported" {
    printf '%s\n' 'DISK=/dev/vda' 'WIPE=yes' >"$CONF"
    parse_config "$CONF"

    run validate_config 1

    [ "$status" -eq 1 ]
    [[ "$output" == *"HOSTNAME is missing"* ]]
    [[ "$output" == *"USERNAME is missing"* ]]
    [[ "$output" == *"USER_PASSWORD is missing"* ]]
    [[ "$output" == *"LUKS_PASSPHRASE is missing"* ]]
}

@test "shell metacharacters and whitespace are rejected in every non-secret value" {
    local key bad value
    for key in DISK HOSTNAME USERNAME TIMEZONE EXTRA_CMDLINE; do
        for bad in '$(id)' '`id`' 'a;b' 'a&b' 'a|b' 'a>b' "a'b" 'a"b' 'a\b' 'a*' 'a b'; do
            [ "$key" = EXTRA_CMDLINE ] && [ "$bad" = 'a b' ] && continue
            value=$bad
            [ "$key" = DISK ] && value="/dev/$bad"
            good_config
            grep -v "^$key=" "$CONF" >"$CONF.x"
            printf '%s=%s\n' "$key" "$value" >>"$CONF.x"
            parse_config "$CONF.x"
            run validate_config 1
            [ "$status" -eq 1 ] || { echo "accepted $key=$value"; return 1; }
        done
    done
}

@test "hostname and user name follow the manifest rules" {
    run valid_hostname nightcity
    [ "$status" -eq 0 ]
    for bad in NightCity -lead trail- "$(printf 'a%.0s' {1..64})" ""; do
        run valid_hostname "$bad"
        [ "$status" -eq 1 ]
    done

    run valid_username _svc-1
    [ "$status" -eq 0 ]
    for bad in Eli 1eli "$(printf 'a%.0s' {1..33})" root nobody alpm; do
        run valid_username "$bad"
        [ "$status" -eq 1 ]
    done
    [[ "$output" == *"USERNAME alpm is a system account"* ]]
}

@test "the time zone must exist in the zone database" {
    run valid_timezone Asia/Jerusalem
    [ "$status" -eq 0 ]
    run valid_timezone Mars/Olympus
    [ "$status" -eq 1 ]
    [[ "$output" == *"TIMEZONE Mars/Olympus is not in"* ]]
    run valid_timezone ../../etc/passwd
    [ "$status" -eq 1 ]
}

@test "secrets accept any printable text but no control characters, LUKS needs 8" {
    run valid_secret USER_PASSWORD 'x $;`|' 1
    [ "$status" -eq 0 ]
    run valid_secret USER_PASSWORD "$(printf 'a\tb')" 1
    [ "$status" -eq 1 ]
    run valid_secret LUKS_PASSPHRASE 1234567 8
    [ "$status" -eq 1 ]
    [[ "$output" == *"LUKS_PASSPHRASE must be at least 8 characters"* ]]
}

@test "EXTRA_CMDLINE refuses parameters AIOS sets itself" {
    run valid_extra_cmdline "console=ttyS0,115200 quiet aios.test.fail_health=1"
    [ "$status" -eq 0 ]
    for bad in root=/dev/sda rw aios.gen=0002 rd.luks.name=x systemd.debug-shell mount.usrflags=ro lsm=bpf; do
        run valid_extra_cmdline "quiet $bad"
        [ "$status" -eq 1 ]
        [[ "$output" == *"sets a parameter AIOS sets itself"* ]]
    done
}

@test "the reserved parameter list matches aios-manifest" {
    src="$BATS_TEST_DIRNAME/../../aios-cli/crates/aios-manifest/src/validate.rs"
    rust=$(sed -n '/^const RESERVED_CMDLINE_KEYS/,/^];/p' "$src" | grep -o '"[^"]*"' | tr -d '"' | sort)

    [ -n "$rust" ]
    [ "$(printf '%s\n' "${AIOS_RESERVED_CMDLINE_KEYS[@]}" | sort)" = "$rust" ]
}

@test "an unattended install needs WIPE=yes exactly" {
    for wipe in no YES "" "yes "; do
        good_config
        sed -i "s/^WIPE=.*/WIPE=$wipe/" "$CONF"
        parse_config "$CONF"
        run validate_config 1
        [ "$status" -eq 1 ]
        [[ "$output" == *"erases DISK only with WIPE=yes"* ]]
    done
    run validate_config 0
    [ "$status" -eq 0 ]
}

@test "the fw_cfg install config is found under sysfs" {
    export AIOS_FWCFG_DIR="$BATS_TEST_TMPDIR/fw_cfg"

    run fwcfg_config
    [ "$status" -eq 0 ]
    [ "$output" = "" ]

    mkdir -p "$AIOS_FWCFG_DIR/by_name/opt/aios/install.conf"
    good_config
    cp "$CONF" "$AIOS_FWCFG_DIR/by_name/opt/aios/install.conf/raw"
    run fwcfg_config
    [ "$output" = "$AIOS_FWCFG_DIR/by_name/opt/aios/install.conf/raw" ]
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `build/tools/bats-core/bin/bats tests/bats/installer-config.bats`
Expected: `1..19`, then 19 `not ok` lines, each with `` `source "$LIB/common.sh"' failed `` and `…/installer/lib/common.sh: No such file or directory`.

- [ ] **Step 3: Write `common.sh`**

`installer/lib/common.sh`:
```bash
# shellcheck shell=bash
# common.sh: logging, step tracking and the command wrappers of aios-install (spec §6.2, §7).
#
# Every command that changes the disk or the live system goes through run_cmd, run_stdin
# or run_write. (It is not called "run": that would shadow bats' run in the tests.) With
# AIOS_INSTALL_DRYRUN=1 they print one "DRYRUN <command>" line on stdout and change
# nothing. Read-only queries (lsblk, sbctl status, mkpasswd, ...) always run.
#
# Test hook, dry-run only: a command whose DRYRUN text (without the "DRYRUN " prefix) is
# a line of the file $AIOS_INSTALL_DRYRUN_FAILS fails with status 1.

# The current step, for the failure message of on_exit (cleanup.sh).
# shellcheck disable=SC2034
AIOS_STEP=0
# shellcheck disable=SC2034
AIOS_STEP_NAME=start

log() {
    printf 'aios-install: %s\n' "$*" >&2
}

die() {
    log "error: $*"
    exit 1
}

# step N NAME: start step N of 13 (spec §6.2). A failure names the current step.
step() {
    # shellcheck disable=SC2034
    AIOS_STEP=$1
    # shellcheck disable=SC2034
    AIOS_STEP_NAME=$2
    log "step $1/13: $2"
}

dry_run() {
    [[ ${AIOS_INSTALL_DRYRUN:-0} == 1 ]]
}

# quote_cmd ARGS...: the command line as one string. Plain words stay as they are; any
# other argument is single-quoted (${arg@Q}), so the text is the same on every bash.
quote_cmd() {
    local out="" arg
    for arg in "$@"; do
        if [[ $arg =~ ^[A-Za-z0-9_./:=,@%+-]+$ ]]; then
            out+="${out:+ }$arg"
        else
            out+="${out:+ }${arg@Q}"
        fi
    done
    printf '%s' "$out"
}

# dry_print TEXT: print "DRYRUN TEXT"; fail if the test hook lists TEXT.
dry_print() {
    printf 'DRYRUN %s\n' "$1"
    if [[ -n ${AIOS_INSTALL_DRYRUN_FAILS:-} && -f $AIOS_INSTALL_DRYRUN_FAILS ]] &&
        grep -qxF -- "$1" "$AIOS_INSTALL_DRYRUN_FAILS"; then
        return 1
    fi
    return 0
}

# run_cmd CMD ARGS...: run a command that changes the system.
run_cmd() {
    local line
    line=$(quote_cmd "$@")
    if dry_run; then
        dry_print "$line"
        return
    fi
    log "+ $line"
    "$@"
}

# run_stdin DATA CMD ARGS...: like run_cmd, with DATA (a secret) on stdin, without a newline.
# DATA is never printed or logged.
run_stdin() {
    local data=$1 line
    shift
    line=$(quote_cmd "$@")
    if dry_run; then
        dry_print "$line <secret"
        return
    fi
    log "+ $line <secret"
    printf '%s' "$data" | "$@"
}

# run_write PATH [MODE]: write stdin to PATH, with MODE if given. The content is not logged.
run_write() {
    local path=$1 mode=${2:-}
    if dry_run; then
        cat >/dev/null
        dry_print "write $path${mode:+ $mode}"
        return
    fi
    log "+ write $path${mode:+ $mode}"
    if [[ -n $mode ]]; then
        install -m "$mode" /dev/stdin "$path"
    else
        cat >"$path"
    fi
}
```

- [ ] **Step 4: Write `config.sh`**

`installer/lib/config.sh`:
```bash
# shellcheck shell=bash
# config.sh: the install config and its validation (spec §6.2).
#
# Unattended configs are KEY=value lines. Blank lines and lines starting with "#" are
# ignored, and a trailing CR is dropped. The value is everything after the first "=",
# verbatim: no quotes, no expansion. The file is parsed with a whitelist and is never
# sourced or evaluated.
#
# Values that end up in commands, paths or the manifest (everything except the two
# secrets) must match a strict pattern, so they can never carry shell metacharacters,
# quotes or whitespace. Secrets may hold any printable character: they only ever reach a
# program on stdin.
#
# Environment overrides (tests only):
#   AIOS_FWCFG_DIR    qemu_fw_cfg sysfs dir  (default /sys/firmware/qemu_fw_cfg)
#   AIOS_ZONEINFO     time zone database     (default /usr/share/zoneinfo)
#   AIOS_PASSWD_FILE  accounts the live system already has (default /etc/passwd)

AIOS_CONFIG_KEYS=(DISK HOSTNAME USERNAME USER_PASSWORD LUKS_PASSPHRASE TIMEZONE WIPE EXTRA_CMDLINE)
AIOS_FWCFG_NAME=opt/aios/install.conf

# Kernel parameters AIOS sets itself. Keep in sync with RESERVED_CMDLINE_KEYS in
# aios-cli/crates/aios-manifest/src/validate.rs (a bats test compares the two).
AIOS_RESERVED_CMDLINE_KEYS=(root rootflags rw ro mount.usr mount.usrflags rd.luks.name aios.gen
    lockdown lsm init rdinit systemd.debug_shell rd.systemd.debug_shell apparmor security)

declare -gA CFG=()

is_config_key() {
    local k
    for k in "${AIOS_CONFIG_KEYS[@]}"; do
        [[ $1 == "$k" ]] && return 0
    done
    return 1
}

# parse_config FILE: fill CFG from FILE. Reports every problem, then returns 1 if any.
parse_config() {
    local file=$1 line key n=0 errors=0
    CFG=()
    if [[ ! -r $file ]]; then
        log "error: cannot read $file"
        return 1
    fi
    while IFS= read -r line || [[ -n $line ]]; do
        n=$((n + 1))
        line=${line%$'\r'}
        [[ -z $line || $line == \#* ]] && continue
        if [[ ! $line =~ ^([A-Z_]+)=(.*)$ ]]; then
            log "error: $file:$n: expected KEY=value"
            errors=$((errors + 1))
            continue
        fi
        key=${BASH_REMATCH[1]}
        if ! is_config_key "$key"; then
            log "error: $file:$n: unknown key $key"
            errors=$((errors + 1))
        elif [[ -v CFG[$key] ]]; then
            log "error: $file:$n: duplicate key $key"
            errors=$((errors + 1))
        else
            CFG[$key]=${BASH_REMATCH[2]}
        fi
    done <"$file"
    ((errors == 0))
}

valid_disk_path() {
    if [[ ! $1 =~ ^/dev/[A-Za-z0-9][A-Za-z0-9/_.:-]*$ || $1 == *..* ]]; then
        log "error: DISK must be a /dev path made of letters, digits and / _ . : - (got ${1@Q})"
        return 1
    fi
}

valid_hostname() {
    if [[ ! $1 =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]]; then
        log "error: HOSTNAME must be 1-63 lowercase letters, digits or -, not starting or ending with - (got ${1@Q})"
        return 1
    fi
}

# Same rule as the manifest's user names (aios-manifest valid_username).
valid_username_pattern() {
    if [[ ! $1 =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
        log "error: USERNAME must start with a lowercase letter or _, then up to 31 lowercase letters, digits, _ or - (got ${1@Q})"
        return 1
    fi
}

# The user must not collide with an account the packages create (root, system users).
valid_username() {
    valid_username_pattern "$1" || return 1
    if [[ $1 == root || $1 == nobody ]] || grep -q "^$1:" "${AIOS_PASSWD_FILE:-/etc/passwd}"; then
        log "error: USERNAME $1 is a system account"
        return 1
    fi
}

valid_timezone_name() {
    if [[ ! $1 =~ ^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)*$ ]]; then
        log "error: TIMEZONE must look like Region/City (got ${1@Q})"
        return 1
    fi
}

valid_timezone() {
    valid_timezone_name "$1" || return 1
    if [[ ! -f ${AIOS_ZONEINFO:-/usr/share/zoneinfo}/$1 ]]; then
        log "error: TIMEZONE $1 is not in ${AIOS_ZONEINFO:-/usr/share/zoneinfo}"
        return 1
    fi
}

# valid_secret NAME VALUE MINLEN: non-empty, at least MINLEN characters, no control characters.
valid_secret() {
    if ((${#2} < $3)); then
        log "error: $1 must be at least $3 characters"
        return 1
    fi
    if [[ $2 =~ [[:cntrl:]] ]]; then
        log "error: $1 must not contain control characters"
        return 1
    fi
}

is_reserved_cmdline_key() {
    local key=${1//-/_} r
    for r in "${AIOS_RESERVED_CMDLINE_KEYS[@]}"; do
        [[ $key == "${r//-/_}" ]] && return 0
    done
    return 1
}

# valid_extra_cmdline WORDS: space-separated kernel parameters the manifest may append.
valid_extra_cmdline() {
    local -a words
    local w
    read -ra words <<<"$1"
    for w in "${words[@]}"; do
        if [[ ! $w =~ ^[A-Za-z0-9._,:=/+@-]+$ ]]; then
            log "error: EXTRA_CMDLINE word ${w@Q} may only hold letters, digits and . _ , : = / + @ -"
            return 1
        fi
        if is_reserved_cmdline_key "${w%%=*}"; then
            log "error: EXTRA_CMDLINE word $w sets a parameter AIOS sets itself"
            return 1
        fi
    done
}

# validate_config UNATTENDED: apply defaults, then check every value. UNATTENDED=1 also
# requires WIPE=yes. Reports every problem, then returns 1 if any.
validate_config() {
    local unattended=$1 key errors=0
    : "${CFG[TIMEZONE]:=UTC}"
    : "${CFG[EXTRA_CMDLINE]:=}"
    : "${CFG[WIPE]:=}"
    for key in DISK HOSTNAME USERNAME USER_PASSWORD LUKS_PASSPHRASE; do
        if [[ -z ${CFG[$key]:-} ]]; then
            log "error: $key is missing"
            errors=$((errors + 1))
        fi
    done
    ((errors == 0)) || return 1
    valid_disk_path "${CFG[DISK]}" || errors=$((errors + 1))
    valid_hostname "${CFG[HOSTNAME]}" || errors=$((errors + 1))
    valid_username "${CFG[USERNAME]}" || errors=$((errors + 1))
    valid_timezone "${CFG[TIMEZONE]}" || errors=$((errors + 1))
    valid_extra_cmdline "${CFG[EXTRA_CMDLINE]}" || errors=$((errors + 1))
    valid_secret USER_PASSWORD "${CFG[USER_PASSWORD]}" 1 || errors=$((errors + 1))
    valid_secret LUKS_PASSPHRASE "${CFG[LUKS_PASSPHRASE]}" 8 || errors=$((errors + 1))
    if [[ $unattended == 1 && ${CFG[WIPE]} != yes ]]; then
        log "error: an unattended install erases DISK only with WIPE=yes"
        errors=$((errors + 1))
    fi
    ((errors == 0))
}

# fwcfg_config: print the QEMU fw_cfg install config path if the VM has one.
fwcfg_config() {
    local raw="${AIOS_FWCFG_DIR:-/sys/firmware/qemu_fw_cfg}/by_name/$AIOS_FWCFG_NAME/raw"
    if [[ -r $raw ]]; then
        printf '%s\n' "$raw"
    fi
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `build/tools/bats-core/bin/bats tests/bats/installer-config.bats`
Expected: `1..19` and 19 `ok` lines.

- [ ] **Step 6: Add the files to the Makefile lists**

In `Makefile`, replace the block that starts with `# What the shell and unit checks cover.` and ends with the `UNITS :=` line with this. Continuation lines start with a TAB, as everywhere in the Makefile:
```make
# What the shell and unit checks cover. installer/lib/keys.sh is generated (make keys).
INSTALLER_LIBS := installer/lib/common.sh installer/lib/config.sh
SH_SCRIPTS := initrd/aios-root.sh base/aios-health.sh
BASH_SCRIPTS := initrd/install/aios tests/bats/fakes/btrfs tests/bats/fakes/record \
	tests/bats/fakes/findmnt $(INSTALLER_LIBS)
BATS_FILES := tests/bats/aios-root.bats tests/bats/install-hook.bats tests/bats/aios-health.bats \
	tests/bats/installer-config.bats
UNITS := initrd/aios-root.service initrd/sysroot-etc.mount base/aios-health.service
```
`INSTALLER_LIBS` must come before `BASH_SCRIPTS`: `:=` expands at once, so a later definition would leave the list empty.

- [ ] **Step 7: shellcheck and the full gate**

Run: `make shell-check`
Expected: make echoes the two shellcheck commands, the second now ending in `… installer/lib/common.sh installer/lib/config.sh tests/bats/aios-root.bats … tests/bats/installer-config.bats`. There are no diagnostics, and the exit status is 0.

Run: `make check`
Expected: passes. bats prints `1..59` (40 existing + 19), all `ok`.

- [ ] **Step 8: Commit**

```bash
git add Makefile installer/lib/common.sh installer/lib/config.sh tests/bats/installer-config.bats
git commit -m "feat(installer): command wrappers and the whitelist install config parser"
```

---

### Task 2: The target disk and the CPU level

**Files:**
- Create: `installer/lib/disk.sh`, `installer/lib/cpu.sh`
- Test: `tests/bats/fakes/installer`, `tests/bats/installer-disk.bats`
- Modify: `Makefile` (the lists)

How it works:
- **One multi-call fake.** `tests/bats/fakes/installer` is linked under the name of each read-only tool the installer queries (`lsblk`, `findmnt`, `gpg`, `mkpasswd`, `cryptsetup luksUUID`, `sbctl status --json`, `usbguard generate-policy`, `curl`, `modprobe`). It appends every call to `$CALLS` and answers from files under `$FAKE_SYS`. Tasks 3–5 reuse it.
- **Disk checks.** `validate_disk` refuses, in this order:
  - anything that is not a whole disk (`lsblk TYPE`)
  - the disk holding the live medium (the source of `/run/archiso/bootmnt`, or its parent disk)
  - a read-only disk
  - a disk with mounted filesystems
  - a disk smaller than 16 GiB
- **x86-64-v3.** `cpu_supports_v3` reads glibc's `ld-linux-x86-64.so.2 --help`, which ends with the hwcaps list (`x86-64-v3 (supported, searched)`).
- **v3 strip.** `strip_v3` drops the `# BEGIN v3` … `# END v3` regions of `pacman.conf`, which Phase 4 put around the v3 `Architecture` line and the three v3 repos. Unbalanced markers fail, where a plain `sed` range would silently drop the rest of the file.

- [ ] **Step 1: Write the fake**

`tests/bats/fakes/installer`:
```bash
#!/usr/bin/env bash
# Multi-call fake for the installer tests, linked under the name of the command it fakes.
# Every call is appended to $CALLS as "<name> <args>". Answers come from $FAKE_SYS:
#   lsblk      -o COLUMN ... DEV   prints $FAKE_SYS/blk/<DEV without /dev/>/<COLUMN>
#                                  (exit 32 "not a block device" if that dir is missing)
#   findmnt    ... MOUNTPOINT      prints $FAKE_SYS/mnt<MOUNTPOINT> (the SOURCE), else exit 1
#   gpg        ...                 prints $FAKE_SYS/gpg.out (a --with-colons listing)
#   mkpasswd   ...                 reads the password from stdin, appends it to
#                                  $FAKE_SYS/mkpasswd.stdin, prints a fixed yescrypt hash
#   cryptsetup luksUUID DEV        prints $FAKE_SYS/luks-uuid
#   sbctl      status --json       prints $FAKE_SYS/sbctl-status.json
#   usbguard   generate-policy     prints $FAKE_SYS/usbguard-policy
#   curl, modprobe                 exit with $FAKE_SYS/<name>.rc (default 0)
set -euo pipefail

name=${0##*/}
echo "$name $*" >>"$CALLS"

case "$name" in
    lsblk)
        column=""
        prev=""
        for arg in "$@"; do
            case "$prev" in -o | -*o) column=$arg ;; esac
            prev=$arg
        done
        dev=${!#}
        dir="$FAKE_SYS/blk/${dev#/dev/}"
        if [ ! -d "$dir" ]; then
            echo "lsblk: $dev: not a block device" >&2
            exit 32
        fi
        cat "$dir/$column"
        ;;
    findmnt)
        file="$FAKE_SYS/mnt${!#}"
        [ -f "$file" ] || exit 1
        cat "$file"
        ;;
    gpg)
        [ -f "$FAKE_SYS/gpg.out" ] || exit 2
        cat "$FAKE_SYS/gpg.out"
        ;;
    mkpasswd)
        cat >>"$FAKE_SYS/mkpasswd.stdin"
        echo "\$y\$j9T\$fakesalt\$fakehashfakehashfakehashfakehashfake0"
        ;;
    cryptsetup)
        [ "$1" = luksUUID ] || { echo "fake cryptsetup: unsupported: $*" >&2; exit 2; }
        cat "$FAKE_SYS/luks-uuid"
        ;;
    sbctl)
        [ "$*" = "status --json" ] || { echo "fake sbctl: unsupported: $*" >&2; exit 2; }
        cat "$FAKE_SYS/sbctl-status.json"
        ;;
    usbguard)
        [ "$*" = generate-policy ] || { echo "fake usbguard: unsupported: $*" >&2; exit 2; }
        cat "$FAKE_SYS/usbguard-policy"
        ;;
    curl | modprobe)
        exit "$(cat "$FAKE_SYS/$name.rc" 2>/dev/null || echo 0)"
        ;;
    *)
        echo "fake installer tool: unknown name $name" >&2
        exit 2
        ;;
esac
```

Run: `chmod 755 tests/bats/fakes/installer`

- [ ] **Step 2: Write the failing tests**

`tests/bats/installer-disk.bats`:
```bash
#!/usr/bin/env bats
# installer/lib/disk.sh and cpu.sh: target disk validation, x86-64-v3 detection and the
# pacman.conf v3 strip (spec §6.2 steps 1 and 3, §9).

setup() {
    LIB="$BATS_TEST_DIRNAME/../../installer/lib"
    # shellcheck source=/dev/null
    source "$LIB/common.sh"
    # shellcheck source=/dev/null
    source "$LIB/disk.sh"
    # shellcheck source=/dev/null
    source "$LIB/cpu.sh"
    BIN="$BATS_TEST_TMPDIR/bin"
    mkdir -p "$BIN"
    ln -s "$BATS_TEST_DIRNAME/fakes/installer" "$BIN/lsblk"
    ln -s "$BATS_TEST_DIRNAME/fakes/installer" "$BIN/findmnt"
    PATH="$BIN:$PATH"
    export FAKE_SYS="$BATS_TEST_TMPDIR/sys" CALLS="$BATS_TEST_TMPDIR/calls"
    mkdir -p "$FAKE_SYS"
    : >"$CALLS"
    GIB=$((1024 * 1024 * 1024))
    blk vda disk $((20 * GIB)) 0 "" ""
    blk sr0 rom $((1 * GIB)) 1 "/run/archiso/bootmnt" ""
    live /dev/sr0
    PACMAN_CONF="$BATS_TEST_DIRNAME/../../manifest/files/pacman.conf"
}

# blk NAME TYPE SIZE RO MOUNTPOINTS PKNAME: a fake block device /dev/NAME.
blk() {
    local d="$FAKE_SYS/blk/$1"
    mkdir -p "$d"
    printf '%s\n' "$2" >"$d/TYPE"
    printf '%s\n' "$3" >"$d/SIZE"
    printf '%s\n' "$4" >"$d/RO"
    printf '%s\n' "$5" >"$d/MOUNTPOINTS"
    printf '%s\n' "$6" >"$d/PKNAME"
}

# live SOURCE: the archiso boot medium is mounted from SOURCE.
live() {
    mkdir -p "$FAKE_SYS/mnt/run/archiso"
    printf '%s\n' "$1" >"$FAKE_SYS/mnt/run/archiso/bootmnt"
}

# ldso OUTPUT: a fake dynamic loader whose --help prints OUTPUT.
ldso() {
    export AIOS_LDSO="$BATS_TEST_TMPDIR/ld.so"
    printf '#!/bin/sh\ncat <<"EOF"\n%s\nEOF\n' "$1" >"$AIOS_LDSO"
    chmod +x "$AIOS_LDSO"
}

@test "partition names follow the kernel's naming" {
    [ "$(part_path /dev/vda 1)" = /dev/vda1 ]
    [ "$(part_path /dev/sda 2)" = /dev/sda2 ]
    [ "$(part_path /dev/nvme0n1 1)" = /dev/nvme0n1p1 ]
    [ "$(part_path /dev/mmcblk0 2)" = /dev/mmcblk0p2 ]
}

@test "a whole, unmounted 20 GiB disk is accepted" {
    run validate_disk /dev/vda

    [ "$status" -eq 0 ]
    [ "$output" = "" ]
}

@test "partitions, optical drives and missing devices are refused" {
    blk vda1 part $((20 * GIB)) 0 "" vda

    run validate_disk /dev/vda1
    [ "$status" -eq 1 ]
    [ "$output" = "aios-install: error: /dev/vda1 is a part, not a whole disk" ]

    run validate_disk /dev/sr0
    [ "$status" -eq 1 ]

    run validate_disk /dev/vdz
    [ "$status" -eq 1 ]
    [ "$output" = "aios-install: error: /dev/vdz is not a block device" ]
}

@test "the disk holding the live medium is refused" {
    blk sdb disk $((32 * GIB)) 0 "" ""
    live /dev/sdb1
    blk sdb1 part $((2 * GIB)) 0 "/run/archiso/bootmnt" sdb

    run validate_disk /dev/sdb

    [ "$status" -eq 1 ]
    [ "$output" = "aios-install: error: /dev/sdb holds the live medium this system booted from" ]
}

@test "a live medium written to the whole disk is refused too" {
    blk sdc disk $((32 * GIB)) 0 "" ""
    live /dev/sdc

    run validate_disk /dev/sdc

    [ "$status" -eq 1 ]
    [[ "$output" == *"holds the live medium"* ]]
}

@test "a disk with mounted filesystems is refused" {
    blk vdb disk $((20 * GIB)) 0 "$(printf '\n/mnt/data\n')" ""

    run validate_disk /dev/vdb

    [ "$status" -eq 1 ]
    [[ "$output" == *"/dev/vdb has mounted filesystems: "*"/mnt/data"* ]]
}

@test "read-only and small disks are refused" {
    blk vdc disk $((20 * GIB)) 1 "" ""
    run validate_disk /dev/vdc
    [ "$status" -eq 1 ]
    [ "$output" = "aios-install: error: /dev/vdc is read-only" ]

    blk vdd disk $((8 * GIB)) 0 "" ""
    run validate_disk /dev/vdd
    [ "$status" -eq 1 ]
    [ "$output" = "aios-install: error: /dev/vdd has 8 GiB, AIOS needs at least 16 GiB" ]
}

@test "x86-64-v3 is detected from the loader's hwcaps list" {
    ldso "$(printf 'Subdirectories of glibc-hwcaps directories, in priority order:\n  x86-64-v4\n  x86-64-v3 (supported, searched)\n  x86-64-v2 (supported, searched)')"
    cpu_supports_v3

    ldso "$(printf 'Subdirectories of glibc-hwcaps directories, in priority order:\n  x86-64-v4 (supported, searched)\n  x86-64-v3 (supported, searched)\n  x86-64-v2 (supported, searched)')"
    cpu_supports_v3
}

@test "a v2-only CPU, odd output or a failing loader count as no v3" {
    ldso "$(printf 'Subdirectories of glibc-hwcaps directories, in priority order:\n  x86-64-v4\n  x86-64-v3\n  x86-64-v2 (supported, searched)')"
    run cpu_supports_v3
    [ "$status" -eq 1 ]

    ldso "  x86-64-v3 (supported, searched) maybe"
    run cpu_supports_v3
    [ "$status" -eq 1 ]

    export AIOS_LDSO=/bin/false
    run cpu_supports_v3
    [ "$status" -eq 1 ]
}

@test "the host's real loader answers (either way)" {
    [ -x /lib/ld-linux-x86-64.so.2 ] || skip "no /lib/ld-linux-x86-64.so.2"
    unset AIOS_LDSO
    run cpu_supports_v3
    [ "$status" -eq 0 ] || [ "$status" -eq 1 ]
}

@test "strip_v3 removes the v3 architecture and repos from the default pacman.conf" {
    run strip_v3 <"$PACMAN_CONF"

    [ "$status" -eq 0 ]
    [ "$(grep -c -e x86_64_v3 -e cachyos-v3-mirrorlist -e '^# BEGIN v3$' -e '^# END v3$' <<<"$output")" -eq 0 ]
    [ "$(grep '^\[' <<<"$output" | paste -sd' ')" = "[options] [cachyos] [core] [extra] [aios-local]" ]
    [ "$(grep -c '^Architecture = x86_64$' <<<"$output")" -eq 1 ]
    [ "$(diff <(strip_v3 <"$PACMAN_CONF") <(sed '/^# BEGIN v3$/,/^# END v3$/d' "$PACMAN_CONF") && echo same)" = same ]
}

@test "pacman reads the stripped config as generic x86_64 (if pacman-conf is installed)" {
    command -v pacman-conf >/dev/null || skip "pacman-conf not installed"
    mkdir -p "$BATS_TEST_TMPDIR/db"
    strip_v3 <"$PACMAN_CONF" | sed "s|^DBPath .*|DBPath = $BATS_TEST_TMPDIR/db/|" >"$BATS_TEST_TMPDIR/generic.conf"

    [ "$(pacman-conf -c "$BATS_TEST_TMPDIR/generic.conf" Architecture)" = x86_64 ]
    [ "$(pacman-conf -c "$BATS_TEST_TMPDIR/generic.conf" --repo-list | paste -sd' ')" = "cachyos core extra aios-local" ]
}

@test "unbalanced v3 markers fail instead of dropping the rest of the file" {
    run strip_v3 <<<"$(printf 'a\n# BEGIN v3\nb\n')"
    [ "$status" -eq 1 ]
    [[ "$output" == *"# BEGIN v3 is never closed"* ]]

    run strip_v3 <<<"$(printf 'a\n# END v3\nb\n')"
    [ "$status" -eq 1 ]
    [[ "$output" == *"line 2: # END v3 without # BEGIN v3"* ]]

    run strip_v3 <<<"$(printf '# BEGIN v3\n# BEGIN v3\n# END v3\n')"
    [ "$status" -eq 1 ]
    [[ "$output" == *"line 2: nested # BEGIN v3"* ]]
}
```

- [ ] **Step 3: Run them to verify they fail**

Run: `build/tools/bats-core/bin/bats tests/bats/installer-disk.bats`
Expected: `1..13`, then 13 `not ok` lines, each with `` `source "$LIB/disk.sh"' failed `` and `No such file or directory`.

- [ ] **Step 4: Write `disk.sh` and `cpu.sh`**

`installer/lib/disk.sh`:
```bash
# shellcheck shell=bash
# disk.sh: the target disk (spec §6.2 steps 1 and 3).
#
# Environment overrides (tests only):
#   AIOS_LIVE_MNT  where archiso mounts the boot medium (default /run/archiso/bootmnt)

AIOS_MIN_DISK_BYTES=$((16 * 1024 * 1024 * 1024))

# part_path DISK N: partition N of DISK (/dev/vda -> /dev/vda1, /dev/nvme0n1 -> /dev/nvme0n1p1).
part_path() {
    if [[ $1 =~ [0-9]$ ]]; then
        printf '%sp%s\n' "$1" "$2"
    else
        printf '%s%s\n' "$1" "$2"
    fi
}

# live_medium_disk: the whole disk the live system booted from, or nothing (copytoram, PXE).
live_medium_disk() {
    local src parent
    src=$(findmnt -nro SOURCE "${AIOS_LIVE_MNT:-/run/archiso/bootmnt}") || return 0
    [[ -n $src ]] || return 0
    parent=$(lsblk -ndro PKNAME "$src" 2>/dev/null) || parent=""
    if [[ -n $parent ]]; then
        printf '/dev/%s\n' "$parent"
    else
        printf '%s\n' "$src"
    fi
}

# validate_disk DISK: DISK is a whole, writable disk of at least 16 GiB that holds neither
# the live medium nor any mounted filesystem.
validate_disk() {
    local disk=$1 type ro size mounts
    if ! type=$(lsblk -ndro TYPE "$disk" 2>/dev/null); then
        log "error: $disk is not a block device"
        return 1
    fi
    if [[ $type != disk ]]; then
        log "error: $disk is a $type, not a whole disk"
        return 1
    fi
    if [[ $disk == "$(live_medium_disk)" ]]; then
        log "error: $disk holds the live medium this system booted from"
        return 1
    fi
    ro=$(lsblk -ndro RO "$disk")
    if [[ $ro != 0 ]]; then
        log "error: $disk is read-only"
        return 1
    fi
    mounts=$(lsblk -nro MOUNTPOINTS "$disk")
    if [[ -n ${mounts//[[:space:]]/} ]]; then
        log "error: $disk has mounted filesystems: $(printf '%s' "$mounts" | tr -s '\n' ' ')"
        return 1
    fi
    size=$(lsblk -ndbro SIZE "$disk")
    if ((size < AIOS_MIN_DISK_BYTES)); then
        log "error: $disk has $((size / 1024 / 1024 / 1024)) GiB, AIOS needs at least 16 GiB"
        return 1
    fi
}
```

`installer/lib/cpu.sh`:
```bash
# shellcheck shell=bash
# cpu.sh: x86-64-v3 detection and the v3 parts of pacman.conf (spec §6.2 step 1).
#
# Environment overrides (tests only):
#   AIOS_LDSO  the dynamic loader (default /lib/ld-linux-x86-64.so.2)

# cpu_supports_v3: true if glibc's loader lists x86-64-v3 as supported. Its --help ends with
#   Subdirectories of glibc-hwcaps directories, in priority order:
#     x86-64-v4
#     x86-64-v3 (supported, searched)
cpu_supports_v3() {
    local out
    out=$("${AIOS_LDSO:-/lib/ld-linux-x86-64.so.2}" --help 2>/dev/null) || return 1
    grep -qE '^[[:space:]]*x86-64-v3 \(supported(, searched)?\)[[:space:]]*$' <<<"$out"
}

# strip_v3: copy pacman.conf from stdin to stdout without its "# BEGIN v3" ... "# END v3"
# regions (the v3 Architecture line and the CachyOS v3 repos). Unbalanced markers fail.
strip_v3() {
    awk '
        /^# BEGIN v3$/ {
            if (inside) { printf "strip_v3: line %d: nested # BEGIN v3\n", NR > "/dev/stderr"; bad = 1; exit 1 }
            inside = 1; next
        }
        /^# END v3$/ {
            if (!inside) { printf "strip_v3: line %d: # END v3 without # BEGIN v3\n", NR > "/dev/stderr"; bad = 1; exit 1 }
            inside = 0; next
        }
        !inside { print }
        END {
            if (inside && !bad) { print "strip_v3: # BEGIN v3 is never closed" > "/dev/stderr"; exit 1 }
        }
    '
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `build/tools/bats-core/bin/bats tests/bats/installer-disk.bats`
Expected: `1..13`, all `ok`.
- Test 10 runs this host's real loader and accepts either answer.
- Test 12 skips only without `pacman-conf`. It checks that pacman reads the stripped file as `Architecture` `x86_64` with the repos `cachyos core extra aios-local`.

- [ ] **Step 6: Extend the Makefile lists**

Replace the same block with:
```make
# What the shell and unit checks cover. installer/lib/keys.sh is generated (make keys).
INSTALLER_LIBS := installer/lib/common.sh installer/lib/config.sh installer/lib/disk.sh \
	installer/lib/cpu.sh
SH_SCRIPTS := initrd/aios-root.sh base/aios-health.sh
BASH_SCRIPTS := initrd/install/aios tests/bats/fakes/btrfs tests/bats/fakes/record \
	tests/bats/fakes/findmnt tests/bats/fakes/installer $(INSTALLER_LIBS)
BATS_FILES := tests/bats/aios-root.bats tests/bats/install-hook.bats tests/bats/aios-health.bats \
	tests/bats/installer-config.bats tests/bats/installer-disk.bats
UNITS := initrd/aios-root.service initrd/sysroot-etc.mount base/aios-health.service
```

- [ ] **Step 7: The full gate**

Run: `make check`
Expected: passes. shellcheck is silent, and bats prints `1..72`, all `ok`.

- [ ] **Step 8: Commit (with the executable bit)**

```bash
git add Makefile installer/lib/disk.sh installer/lib/cpu.sh tests/bats/fakes/installer tests/bats/installer-disk.bats
git ls-files -s tests/bats/fakes/installer
```
Expected: the line starts with `100755`.

```bash
git commit -m "feat(installer): disk validation, x86-64-v3 detection and the pacman.conf v3 strip"
```

---

### Task 3: What the installer writes to the target

**Files:**
- Create: `installer/lib/manifest.sh`, `installer/lib/skeleton.sh`, `installer/lib/secrets.sh`, `installer/lib/usbguard.sh`, `installer/lib/boot.sh`
- Test: `tests/bats/installer-target.bats`
- Modify: `Makefile` (the lists)

How it works:
- **Manifest.** `render_manifest` fills the four placeholders of Phase 4's template with bash parameter expansion, never `sed`, so a value is never a regex or a replacement pattern.
  - `@EXTRA_CMDLINE@` becomes a TOML string-list body (`"a", "b"`).
  - `patsub_replacement` is switched off: since bash 5.2 an `&` in a replacement means the matched text.
  - A placeholder it does not know fails.
  - A test checks the output against the same substitution as the Rust `default_manifest` test. Another checks that, after `rename_home_template`, all 18 home sources the manifest names exist with the right kind.
- **`@blank` skeleton.** `skeleton_entries` is the §2 list as data, with the modes of Arch's `filesystem` package (`tmp` and `var/tmp` 1777, `root` 0750, `proc` and `sys` 0555). A test compares it word for word with the spec text.
- **Password hash.** `hash_password` makes the same call as `aios passwd` (Phase 3, `ops/passwd.rs`): `mkpasswd -m yescrypt -s`, with the password and a newline on stdin. It applies the same check: the hash starts with `$y$` and holds no `:`.
- **USBGuard.** `usbguard_rules` composes the rule file of §5.5. usbguard uses the first rule that matches, so the order matters: the present devices, then `block with-interface one-of { 03:*:* }`, then `allow`. A policy line that is not an `allow` rule fails.
- **loader.conf.** `loader_conf` is the text of `aios_render::loader_conf()`, and a test compares the two. Bootstrap leaves `loader.conf` to the installer (contract 7).

- [ ] **Step 1: Write the failing tests**

`tests/bats/installer-target.bats`:
```bash
#!/usr/bin/env bats
# installer/lib/{manifest,skeleton,secrets,usbguard,boot}.sh: what the installer writes to
# the target (spec §2, §4.1, §5.5, §6.2 steps 5, 6, 10-12, §9).
# Literal $ in single quotes is test data; bats runs each test in a subshell.
# shellcheck disable=SC2016,SC2030,SC2031

setup() {
    ROOT="$BATS_TEST_DIRNAME/../.."
    LIB="$ROOT/installer/lib"
    for f in common config manifest skeleton secrets usbguard boot; do
        # shellcheck source=/dev/null
        source "$LIB/$f.sh"
    done
    TEMPLATE="$ROOT/manifest/manifest.toml"
    BIN="$BATS_TEST_TMPDIR/bin"
    mkdir -p "$BIN"
    ln -s "$BATS_TEST_DIRNAME/fakes/installer" "$BIN/mkpasswd"
    PATH="$BIN:$PATH"
    export FAKE_SYS="$BATS_TEST_TMPDIR/sys" CALLS="$BATS_TEST_TMPDIR/calls"
    mkdir -p "$FAKE_SYS"
    : >"$CALLS"
    unset AIOS_INSTALL_DRYRUN
}

@test "EXTRA_CMDLINE becomes a TOML string-list body" {
    [ "$(toml_string_list "")" = "" ]
    [ "$(toml_string_list "console=ttyS0,115200")" = '"console=ttyS0,115200"' ]
    [ "$(toml_string_list "quiet  console=ttyS0,115200")" = '"quiet", "console=ttyS0,115200"' ]
}

@test "the default manifest is filled in exactly like the Rust default_manifest test" {
    run render_manifest aios-e2e tester UTC "console=ttyS0,115200" <"$TEMPLATE"

    [ "$status" -eq 0 ]
    expected=$(sed -e 's/@HOSTNAME@/aios-e2e/g' -e 's/@USERNAME@/tester/g' -e 's/@TIMEZONE@/UTC/g' \
        -e 's/@EXTRA_CMDLINE@/"console=ttyS0,115200"/g' "$TEMPLATE")
    [ "$output" = "$expected" ]
    [[ "$output" == *'hostname = "aios-e2e"'* ]]
    [[ "$output" == *'extra_cmdline = ["console=ttyS0,115200"]'* ]]
    [[ "$output" == *'[users.tester.home]'* ]]
    [[ ! "$output" =~ @[A-Z_]+@ ]]
}

@test "an empty EXTRA_CMDLINE renders an empty list, and the trailing newline is kept" {
    render_manifest h tester Asia/Jerusalem "" <"$TEMPLATE" >"$BATS_TEST_TMPDIR/m.toml"

    grep -q '^extra_cmdline = \[\] ' "$BATS_TEST_TMPDIR/m.toml"
    [ "$(tail -c 1 "$BATS_TEST_TMPDIR/m.toml" | od -An -c | tr -d ' ')" = '\n' ]
    [ "$(wc -l <"$BATS_TEST_TMPDIR/m.toml")" -eq "$(wc -l <"$TEMPLATE")" ]
}

@test "invalid values and unknown placeholders are refused" {
    run render_manifest NightCity tester UTC "" <"$TEMPLATE"
    [ "$status" -eq 1 ]
    run render_manifest h Tester UTC "" <"$TEMPLATE"
    [ "$status" -eq 1 ]
    run render_manifest h tester "../x" "" <"$TEMPLATE"
    [ "$status" -eq 1 ]
    run render_manifest h tester UTC "root=/dev/sda" <"$TEMPLATE"
    [ "$status" -eq 1 ]

    run render_manifest h tester UTC "" <<<'hostname = "@HOSTNAME@" # @ROOTPW@'
    [ "$status" -eq 1 ]
    [[ "$output" == *"unknown placeholder @ROOTPW@"* ]]
}

@test "after the rename, every home source the manifest names exists" {
    cp -r "$ROOT/manifest" "$BATS_TEST_TMPDIR/config"
    cfg="$BATS_TEST_TMPDIR/config"

    rename_home_template "$cfg" tester
    render_manifest h tester UTC "" <"$TEMPLATE" >"$cfg/manifest.toml"

    [ ! -e "$cfg/home/@USERNAME@" ]
    sources=$(sed -n 's/^"[^"]*" *= *"\(home\/[^"]*\)"$/\1/p' "$cfg/manifest.toml")
    [ "$(wc -l <<<"$sources")" -eq 18 ]
    while IFS= read -r src; do
        case $src in
            home/tester/*/) [ -d "$cfg/$src" ] || { echo "missing dir $src"; return 1; } ;;
            home/tester/*) [ -f "$cfg/$src" ] || { echo "missing file $src"; return 1; } ;;
            *) echo "source outside home/tester: $src"; return 1 ;;
        esac
    done <<<"$sources"
}

@test "the @blank skeleton has the spec's directories, modes and links" {
    blank="$BATS_TEST_TMPDIR/blank"
    mkdir "$blank"

    blank_skeleton "$blank" 2>/dev/null

    for d in usr etc persist home efi dev run var var/log var/lib var/cache; do
        [ "$(stat -c %a "$blank/$d")" = 755 ] || { echo "bad $d"; return 1; }
    done
    [ "$(stat -c %a "$blank/proc")" = 555 ]
    [ "$(stat -c %a "$blank/sys")" = 555 ]
    [ "$(stat -c %a "$blank/tmp")" = 1777 ]
    [ "$(stat -c %a "$blank/var/tmp")" = 1777 ]
    [ "$(stat -c %a "$blank/root")" = 750 ]
    [ "$(readlink "$blank/bin")" = usr/bin ]
    [ "$(readlink "$blank/sbin")" = usr/bin ]
    [ "$(readlink "$blank/lib")" = usr/lib ]
    [ "$(readlink "$blank/lib64")" = usr/lib ]
    [ "$(readlink "$blank/var/lib/pacman")" = ../../usr/lib/pacman ]
    [ "$(find "$blank" -mindepth 1 | wc -l)" -eq 21 ]
}

@test "the skeleton matches spec §2 word for word" {
    spec="$ROOT/docs/superpowers/specs/2026-11-03-base-iso-design.md"
    dirs=$(sed -n 's/^  - Top-level dirs: `\(.*\)`\.$/\1/p' "$spec" | tr ' ' '\n')
    links=$(grep -o '`[a-z0-9/][a-z0-9/]* → [a-z./][a-z./]*`' "$spec" | tr -d '`' | sed 's/ → / /' | sort)

    [ -n "$dirs" ]
    [ "$(skeleton_entries | awk '$1 == "dir" { print $3 }')" = "$dirs" ]
    [ "$(skeleton_entries | awk '$1 == "link" { print $3, $2 }' | sort)" = "$links" ]
}

@test "in dry-run mode the skeleton is one command per entry" {
    export AIOS_INSTALL_DRYRUN=1

    run blank_skeleton /mnt/aios-top/@blank

    [ "$status" -eq 0 ]
    [ "${#lines[@]}" -eq 21 ]
    [ "${lines[0]}" = "DRYRUN install -d -m 0755 /mnt/aios-top/@blank/usr" ]
    [ "${lines[9]}" = "DRYRUN install -d -m 1777 /mnt/aios-top/@blank/tmp" ]
    [ "${lines[20]}" = "DRYRUN ln -s ../../usr/lib/pacman /mnt/aios-top/@blank/var/lib/pacman" ]
}

@test "the password reaches mkpasswd on stdin and the yescrypt hash comes back" {
    run hash_password 'pa ss$;&|'

    [ "$status" -eq 0 ]
    [ "$output" = '$y$j9T$fakesalt$fakehashfakehashfakehashfakehashfake0' ]
    [ "$(cat "$CALLS")" = "mkpasswd -m yescrypt -s" ]
    [ "$(cat "$FAKE_SYS/mkpasswd.stdin")" = 'pa ss$;&|' ]
    [ "$(wc -l <"$FAKE_SYS/mkpasswd.stdin")" -eq 1 ]
}

@test "a failing mkpasswd or a hash that is not yescrypt is refused" {
    printf '#!/bin/sh\necho "\\$6\\$salt\\$sha512"\n' >"$BIN/mkpasswd.sha"
    chmod +x "$BIN/mkpasswd.sha"
    rm "$BIN/mkpasswd"
    ln -s "$BIN/mkpasswd.sha" "$BIN/mkpasswd"
    run hash_password x
    [ "$status" -eq 1 ]
    [[ "$output" == *"printed an unexpected hash"* ]]

    rm "$BIN/mkpasswd"
    ln -s /bin/false "$BIN/mkpasswd"
    run hash_password x
    [ "$status" -eq 1 ]
    [[ "$output" == *"mkpasswd -m yescrypt -s failed"* ]]
}

@test "USBGuard rules: present devices, then block new HID, then allow the rest" {
    policy='allow id 1d6b:0002 serial "0000:00:14.0" name "xHCI Host Controller" with-interface 09:00:00
allow id 046d:c52b serial "" name "USB Receiver" with-interface { 03:01:01 03:01:02 }'

    run usbguard_rules "$policy"

    [ "$status" -eq 0 ]
    [ "${#lines[@]}" -eq 8 ]
    [ "${lines[1]}" = 'allow id 1d6b:0002 serial "0000:00:14.0" name "xHCI Host Controller" with-interface 09:00:00' ]
    [ "${lines[2]}" = 'allow id 046d:c52b serial "" name "USB Receiver" with-interface { 03:01:01 03:01:02 }' ]
    [ "${lines[5]}" = "block with-interface one-of { 03:*:* }" ]
    [ "${lines[7]}" = "allow" ]
    [ "$(grep -vc '^#' <<<"$output")" -eq 4 ]
}

@test "USBGuard rules without present devices, and a policy that is not all allow rules" {
    run usbguard_rules ""
    [ "$status" -eq 0 ]
    [ "$(grep -v '^#' <<<"$output" | paste -sd'|')" = "block with-interface one-of { 03:*:* }|allow" ]

    run usbguard_rules 'block id 1234:5678'
    [ "$status" -eq 1 ]
    [[ "$output" == *"not an allow rule: block id 1234:5678"* ]]
}

@test "loader.conf matches aios_render::loader_conf" {
    rust=$(sed -n '/^pub fn loader_conf/,/^}/p' "$ROOT/aios-cli/crates/aios-render/src/simple.rs" |
        sed -n 's/^ *"\(.*\)"\.to_string()$/\1/p')

    [ -n "$rust" ]
    [ "$(loader_conf)" = "$(printf '%b' "$rust")" ]
}

@test "Setup Mode is read from sbctl status --json" {
    sbctl_setup_mode '{"installed":true,"guid":"x","setup_mode":true,"secure_boot":false,"vendors":[]}'
    sbctl_setup_mode '{ "setup_mode" : true }'
    run sbctl_setup_mode '{"installed":true,"setup_mode":false,"secure_boot":true}'
    [ "$status" -eq 1 ]
    run sbctl_setup_mode ''
    [ "$status" -eq 1 ]
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `build/tools/bats-core/bin/bats tests/bats/installer-target.bats`
Expected: `1..14`, then 14 `not ok` lines, each with `` `source "$LIB/$f.sh"' failed `` and `…/installer/lib/manifest.sh: No such file or directory`.

- [ ] **Step 3: Write the five libraries**

`installer/lib/manifest.sh`:
```bash
# shellcheck shell=bash
# manifest.sh: fill in the default manifest template (spec §6.2 step 6, Phase 4 Task 6).
# The template's placeholders are @HOSTNAME@, @USERNAME@, @TIMEZONE@ and @EXTRA_CMDLINE@
# (a TOML string-list body, possibly empty). Its home/@USERNAME@/ directory is renamed.

# toml_string_list WORDS: "a b" -> "a", "b". The words are validated kernel parameters,
# so they hold no quote or backslash to escape.
toml_string_list() {
    local -a words
    local out="" w
    read -ra words <<<"$1"
    for w in "${words[@]}"; do
        out+="${out:+, }\"$w\""
    done
    printf '%s' "$out"
}

# render_manifest HOSTNAME USERNAME TIMEZONE EXTRA_CMDLINE: the template on stdin, filled in,
# on stdout. Fails on an invalid value or a placeholder it does not know.
render_manifest() {
    local host=$1 user=$2 tz=$3 cmdline=$4 tpl list
    valid_hostname "$host" || return 1
    valid_username_pattern "$user" || return 1
    valid_timezone_name "$tz" || return 1
    valid_extra_cmdline "$cmdline" || return 1
    list=$(toml_string_list "$cmdline")
    tpl=$(
        cat
        printf x
    )
    tpl=${tpl%x}
    # bash 5.2+ would otherwise expand "&" in a replacement to the matched text.
    shopt -u patsub_replacement 2>/dev/null || true
    tpl=${tpl//@HOSTNAME@/"$host"}
    tpl=${tpl//@USERNAME@/"$user"}
    tpl=${tpl//@TIMEZONE@/"$tz"}
    tpl=${tpl//@EXTRA_CMDLINE@/"$list"}
    if [[ $tpl =~ @[A-Z_]+@ ]]; then
        log "error: manifest template: unknown placeholder ${BASH_REMATCH[0]}"
        return 1
    fi
    printf '%s' "$tpl"
}

# rename_home_template CONFIG USERNAME: CONFIG/home/@USERNAME@ -> CONFIG/home/USERNAME.
rename_home_template() {
    run_cmd mv "$1/home/@USERNAME@" "$1/home/$2"
}
```

`installer/lib/skeleton.sh`:
```bash
# shellcheck shell=bash
# skeleton.sh: the @blank root skeleton (spec §2), cloned to @root-live at every boot.

# skeleton_entries: one entry per line, "dir MODE PATH" or "link TARGET PATH", in creation
# order. The modes are those of Arch's filesystem package.
skeleton_entries() {
    cat <<'EOF'
dir 0755 usr
dir 0755 etc
dir 0755 persist
dir 0755 home
dir 0755 efi
dir 0555 proc
dir 0555 sys
dir 0755 dev
dir 0755 run
dir 1777 tmp
dir 0755 var
dir 0755 var/log
dir 0755 var/lib
dir 0755 var/cache
dir 1777 var/tmp
dir 0750 root
link usr/bin bin
link usr/bin sbin
link usr/lib lib
link usr/lib lib64
link ../../usr/lib/pacman var/lib/pacman
EOF
}

# blank_skeleton DIR: create the skeleton inside DIR (the new @blank subvolume).
blank_skeleton() {
    local kind arg path
    while read -r kind arg path; do
        case $kind in
            dir) run_cmd install -d -m "$arg" "$1/$path" ;;
            link) run_cmd ln -s "$arg" "$1/$path" ;;
        esac
    done < <(skeleton_entries)
}
```

`installer/lib/secrets.sh`:
```bash
# shellcheck shell=bash
# secrets.sh: the user's password hash for secrets/passwd/<user> (spec §4.1, §6.2 step 6).

# hash_password PASSWORD: print the yescrypt hash. Same call and check as `aios passwd`:
# mkpasswd -m yescrypt -s, with the password and a newline on stdin.
hash_password() {
    local hash
    if ! hash=$(printf '%s\n' "$1" | mkpasswd -m yescrypt -s); then
        log "error: mkpasswd -m yescrypt -s failed"
        return 1
    fi
    if [[ $hash != \$y\$* || $hash == *:* || $hash == *$'\n'* ]]; then
        log "error: mkpasswd -m yescrypt -s printed an unexpected hash"
        return 1
    fi
    printf '%s\n' "$hash"
}
```

`installer/lib/usbguard.sh`:
```bash
# shellcheck shell=bash
# usbguard.sh: the USBGuard rule file (spec §5.5, §6.2 step 12). usbguard uses the first
# rule that matches, so: the devices present at install are allowed, then any new device
# with a HID interface (keyboard, mouse, BadUSB) is blocked, then everything else is allowed.

# usbguard_rules POLICY: rules.conf for POLICY, the output of `usbguard generate-policy`.
# Every POLICY line must be an allow rule.
usbguard_rules() {
    local line
    while IFS= read -r line; do
        if [[ -n $line && $line != "allow "* ]]; then
            log "error: usbguard generate-policy printed a rule that is not an allow rule: $line"
            return 1
        fi
    done <<<"$1"
    printf '%s\n' "# Written by aios-install (spec §5.5). Devices present at install:"
    if [[ -n $1 ]]; then
        printf '%s\n' "$1"
    fi
    printf '%s\n' "# New devices with a HID interface are blocked; approve one with" \
        "# run0 usbguard allow-device -p <id>." \
        "block with-interface one-of { 03:*:* }" \
        "# Every other new device is allowed." \
        "allow"
}
```

`installer/lib/boot.sh`:
```bash
# shellcheck shell=bash
# boot.sh: the ESP loader.conf and the Secure Boot setup-mode check (spec §6.2 steps 10-11).

# loader_conf: the ESP /loader/loader.conf. Same text as aios_render::loader_conf()
# (a bats test compares the two): the newest cachyos generation boots by default.
loader_conf() {
    printf '%s\n' 'default aios-gen-*-cachyos*' 'timeout 3' 'editor no'
}

# sbctl_setup_mode JSON: true if `sbctl status --json` reports Setup Mode.
sbctl_setup_mode() {
    [[ $1 =~ \"setup_mode\"[[:space:]]*:[[:space:]]*true ]]
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `build/tools/bats-core/bin/bats tests/bats/installer-target.bats`
Expected: `1..14`, all `ok`.

- [ ] **Step 5: Extend the Makefile lists**

Replace the same block with:
```make
# What the shell and unit checks cover. installer/lib/keys.sh is generated (make keys).
INSTALLER_LIBS := installer/lib/common.sh installer/lib/config.sh installer/lib/disk.sh \
	installer/lib/cpu.sh installer/lib/manifest.sh installer/lib/skeleton.sh \
	installer/lib/secrets.sh installer/lib/usbguard.sh installer/lib/boot.sh
SH_SCRIPTS := initrd/aios-root.sh base/aios-health.sh
BASH_SCRIPTS := initrd/install/aios tests/bats/fakes/btrfs tests/bats/fakes/record \
	tests/bats/fakes/findmnt tests/bats/fakes/installer $(INSTALLER_LIBS)
BATS_FILES := tests/bats/aios-root.bats tests/bats/install-hook.bats tests/bats/aios-health.bats \
	tests/bats/installer-config.bats tests/bats/installer-disk.bats \
	tests/bats/installer-target.bats
UNITS := initrd/aios-root.service initrd/sysroot-etc.mount base/aios-health.service
```

- [ ] **Step 6: The full gate**

Run: `make check`
Expected: passes. bats prints `1..86`, all `ok`.

- [ ] **Step 7: Commit**

```bash
git add Makefile installer/lib/manifest.sh installer/lib/skeleton.sh installer/lib/secrets.sh \
  installer/lib/usbguard.sh installer/lib/boot.sh tests/bats/installer-target.bats
git commit -m "feat(installer): manifest rendering, @blank skeleton, password hash, USBGuard rules, loader.conf"
```

---
### Task 4: The pinned CachyOS key, `make keys`, and the failure cleanup

**Files:**
- Create: `installer/lib/keyring.sh`, `installer/gen-keys.sh`, `installer/lib/cleanup.sh`
- Test: `tests/bats/installer-keys.bats`
- Modify: `Makefile` (lists, `shell-check`, `keys`), `.gitignore`

How it works:
- **The pin.** `trusted_key_fprs UID` lists the primary-key fingerprints for `admin@cachyos.org` that the pacman keyring trusts fully (gpg validity `f` or `u`), never subkeys. On this host that is `882DCFE48E2051D48E2562ABF3B607488DB35A47`.
  - The build host's `/etc/pacman.d/gnupg` is world-readable, so `make keys` needs no root. gpg prints `trustdb not writable`, which the script discards.
  - `gen-keys.sh` writes `installer/lib/keys.sh` atomically, and fails when there is no such key.
  - `keys.sh` is generated and gitignored. Only the ISO carries a copy.
- **The check.** `check_cachyos_keys` runs in the installer's preflight, before anything is erased. The live keyring that pacstrap will verify with, and copy (Phase 3 contract 7), must trust exactly the pinned set. That keyring is populated by archiso's `pacman-init.service` from the ISO's `cachyos-keyring`. A missing key, an extra key and an empty pin all fail.
- **Cleanup.** `mount_tracked` remembers each mount point. On failure, `cleanup` (from the EXIT trap `on_exit`) unmounts them newest first, falls back to `umount -l`, then closes the LUKS mapping when `luks_opened` was called, and only warns about problems. `on_exit` names the failed step and keeps the exit status (spec §7). After a success, step 13 calls `cleanup` itself.

- [ ] **Step 1: Write the failing tests**

`tests/bats/installer-keys.bats`:
```bash
#!/usr/bin/env bats
# installer/lib/keyring.sh, installer/gen-keys.sh and installer/lib/cleanup.sh: the pinned
# CachyOS key and the failure cleanup (spec §6.2 step 9, §7, §9).

FPR=882DCFE48E2051D48E2562ABF3B607488DB35A47
OTHER=0123456789ABCDEF0123456789ABCDEF01234567

setup() {
    ROOT="$BATS_TEST_DIRNAME/../.."
    LIB="$ROOT/installer/lib"
    for f in common keyring cleanup; do
        # shellcheck source=/dev/null
        source "$LIB/$f.sh"
    done
    BIN="$BATS_TEST_TMPDIR/bin"
    mkdir -p "$BIN"
    ln -s "$BATS_TEST_DIRNAME/fakes/installer" "$BIN/gpg"
    for n in mount umount cryptsetup; do
        ln -s "$BATS_TEST_DIRNAME/fakes/record" "$BIN/$n"
    done
    PATH="$BIN:$PATH"
    export FAKE_SYS="$BATS_TEST_TMPDIR/sys" CALLS="$BATS_TEST_TMPDIR/calls"
    mkdir -p "$FAKE_SYS"
    : >"$CALLS"
    unset AIOS_INSTALL_DRYRUN FAILS
}

# key VALIDITY FPR: one primary key in gpg's --with-colons format, with a subkey.
key() {
    printf 'pub:%s:3072:1:%s:1628554460:::-:::scSC::::::23::0:\n' "$1" "${2: -16}"
    printf 'fpr:::::::::%s:\n' "$2"
    printf 'uid:%s::::1691645607::05DE::CachyOS <admin@cachyos.org>::::::::::0:\n' "$1"
    printf 'sub:e:3072:1:9B71BE9D397982C5:1628554460:1691626460:::::e::::::23:\n'
    printf 'fpr:::::::::9149495EB47A04A82FF0BA6F9B71BE9D397982C5:\n'
}

@test "only fully trusted primary keys count, never subkeys" {
    { key f "$FPR"; key r "$OTHER"; key e 1111111111111111111111111111111111111111; key - 2222222222222222222222222222222222222222; } >"$FAKE_SYS/gpg.out"

    run trusted_key_fprs admin@cachyos.org

    [ "$status" -eq 0 ]
    [ "$output" = "$FPR" ]
    [ "$(cat "$CALLS")" = "gpg --homedir /etc/pacman.d/gnupg --batch --no-permission-warning --with-colons --list-keys -- admin@cachyos.org" ]
}

@test "gen-keys.sh pins the trusted key into a sourceable keys.sh" {
    { key u "$FPR"; key f "$OTHER"; } >"$FAKE_SYS/gpg.out"

    run "$ROOT/installer/gen-keys.sh" "$BATS_TEST_TMPDIR/keys.sh"

    [ "$status" -eq 0 ]
    [ "$output" = "gen-keys.sh: pinned $OTHER $FPR in $BATS_TEST_TMPDIR/keys.sh" ]
    # shellcheck source=/dev/null
    source "$BATS_TEST_TMPDIR/keys.sh"
    [ "$AIOS_CACHYOS_KEYS" = "$OTHER $FPR" ]
    [ ! -e "$BATS_TEST_TMPDIR/keys.sh.tmp" ]
}

@test "gen-keys.sh fails without a trusted key and keeps no partial file" {
    key r "$FPR" >"$FAKE_SYS/gpg.out"

    run "$ROOT/installer/gen-keys.sh" "$BATS_TEST_TMPDIR/keys.sh"
    [ "$status" -eq 1 ]
    [[ "$output" == *"trusts no key for admin@cachyos.org"* ]]
    [ ! -e "$BATS_TEST_TMPDIR/keys.sh" ]

    rm "$FAKE_SYS/gpg.out"
    run "$ROOT/installer/gen-keys.sh" "$BATS_TEST_TMPDIR/keys.sh"
    [ "$status" -eq 1 ]
}

@test "gen-keys.sh reads the build host's real keyring (if it has CachyOS)" {
    rm "$BIN/gpg"
    command -v gpg >/dev/null || skip "gpg not installed"
    trusted_key_fprs admin@cachyos.org | grep -q . || skip "this host's pacman keyring has no CachyOS key"

    run "$ROOT/installer/gen-keys.sh" "$BATS_TEST_TMPDIR/keys.sh"

    [ "$status" -eq 0 ]
    grep -Eqx 'AIOS_CACHYOS_KEYS="[0-9A-F]{40}( [0-9A-F]{40})*"' "$BATS_TEST_TMPDIR/keys.sh"
}

@test "the live keyring must trust exactly the pinned keys" {
    key f "$FPR" >"$FAKE_SYS/gpg.out"
    check_cachyos_keys "$FPR"

    run check_cachyos_keys "$OTHER"
    [ "$status" -eq 1 ]
    [[ "$output" == *"trusts the CachyOS keys [$FPR], but this ISO pinned [$OTHER]"* ]]

    { key f "$FPR"; key f "$OTHER"; } >"$FAKE_SYS/gpg.out"
    run check_cachyos_keys "$FPR"
    [ "$status" -eq 1 ]

    run check_cachyos_keys ""
    [ "$status" -eq 1 ]
    [[ "$output" == *"no pinned CachyOS key"* ]]
}

@test "cleanup unmounts newest first, then closes LUKS, then has nothing left to do" {
    mount_tracked -t btrfs -o subvolid=5 /dev/mapper/aios /mnt/aios-top 2>/dev/null
    luks_opened
    mount_tracked -o umask=0077 /dev/vda1 /mnt/aios-esp 2>/dev/null
    mount_tracked --bind /mnt/aios-top/@persist/var/lib/sbctl /var/lib/sbctl 2>/dev/null
    : >"$CALLS"

    cleanup 2>/dev/null
    cleanup 2>/dev/null

    diff - "$CALLS" <<'EOF'
umount /var/lib/sbctl
umount /mnt/aios-esp
umount /mnt/aios-top
cryptsetup close aios
EOF
}

@test "a busy mount is lazily unmounted, and a failed close is only a warning" {
    export FAILS="$BATS_TEST_TMPDIR/fails"
    printf '%s\n' "umount /mnt/aios-top" "cryptsetup close aios" >"$FAILS"
    mount_tracked /dev/mapper/aios /mnt/aios-top 2>/dev/null
    luks_opened
    : >"$CALLS"

    run cleanup

    [ "$status" -eq 0 ]
    [ "$(paste -sd'|' "$CALLS")" = "umount /mnt/aios-top|umount -l /mnt/aios-top|cryptsetup close aios" ]
    [[ "$output" == *"warning: could not close the LUKS mapping aios"* ]]
}

@test "the exit trap names the failed step, cleans up and keeps the status" {
    run bash -c '
        for f in common cleanup; do . "$1/$f.sh"; done
        trap on_exit EXIT
        step 7 esp
        mount_tracked /dev/vda1 /mnt/aios-esp
        exit 3
    ' _ "$LIB"

    [ "$status" -eq 3 ]
    [[ "$output" == *"step 7 (esp) failed (exit 3)"* ]]
    [ "$(tail -n 1 "$CALLS")" = "umount /mnt/aios-esp" ]
}

@test "the exit trap does nothing after a success" {
    run bash -c '
        for f in common cleanup; do . "$1/$f.sh"; done
        trap on_exit EXIT
        step 13 finish
        mount_tracked /dev/vda1 /mnt/aios-esp
        cleanup
    ' _ "$LIB"

    [ "$status" -eq 0 ]
    [[ "$output" != *failed* ]]
    [ "$(grep -c '^umount ' "$CALLS")" -eq 1 ]
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `build/tools/bats-core/bin/bats tests/bats/installer-keys.bats`
Expected: `1..9`, then 9 `not ok` lines, each with `` `source "$LIB/$f.sh"' failed `` and `…/installer/lib/keyring.sh: No such file or directory`.

- [ ] **Step 3: Write the libraries and the generator**

`installer/lib/keyring.sh`:
```bash
# shellcheck shell=bash
# keyring.sh: the CachyOS repository signing key (spec §6.2 step 9, Phase 3 contract 7).
# `aios bootstrap` runs pacstrap on the live system, which verifies packages with (and
# copies) the live pacman keyring. So before anything is erased, the installer checks that
# the live keyring trusts exactly the CachyOS keys pinned in keys.sh at ISO build time.
#
# Environment overrides (tests only):
#   AIOS_PACMAN_GNUPG  the pacman keyring (default /etc/pacman.d/gnupg)

AIOS_CACHYOS_UID=admin@cachyos.org

# trusted_key_fprs UID: fingerprints of the primary keys for UID that the pacman keyring
# trusts fully (validity f or u), one per line. Revoked, expired and untrusted keys and all
# subkeys are left out.
trusted_key_fprs() {
    {
        gpg --homedir "${AIOS_PACMAN_GNUPG:-/etc/pacman.d/gnupg}" --batch --no-permission-warning \
            --with-colons --list-keys -- "$1" 2>/dev/null || true
    } | awk -F: '
        $1 == "pub" { want = ($2 == "f" || $2 == "u"); next }
        $1 == "fpr" && want { print $10; want = 0; next }
        $1 == "sub" { want = 0 }
    '
}

# check_cachyos_keys PINNED: PINNED (space-separated fingerprints) must be exactly the set of
# CachyOS keys the live keyring trusts.
check_cachyos_keys() {
    local pinned live
    pinned=$(tr ' ' '\n' <<<"$1" | sed '/^$/d' | sort -u)
    if [[ -z $pinned ]]; then
        log "error: no pinned CachyOS key (keys.sh is empty)"
        return 1
    fi
    live=$(trusted_key_fprs "$AIOS_CACHYOS_UID" | sort -u)
    if [[ $live != "$pinned" ]]; then
        log "error: the live pacman keyring trusts the CachyOS keys [$(paste -sd' ' <<<"$live")]," \
            "but this ISO pinned [$(paste -sd' ' <<<"$pinned")]. Wait for pacman-init.service," \
            "or rebuild the ISO."
        return 1
    fi
}
```

`installer/lib/cleanup.sh`:
```bash
# shellcheck shell=bash
# cleanup.sh: undo the live-system state on exit (spec §7): unmount what this run mounted,
# newest first, then close the LUKS mapping. The disk itself is left as it is; the user
# runs the installer again.

AIOS_MOUNTS=()
AIOS_LUKS_OPEN=0

# mount_tracked MOUNT-ARGS... TARGET: mount, and remember TARGET (the last argument).
mount_tracked() {
    run_cmd mount "$@"
    AIOS_MOUNTS+=("${!#}")
}

# luks_opened: the "aios" mapping is open from now on.
luks_opened() {
    AIOS_LUKS_OPEN=1
}

# cleanup: unmount and close everything. Never fails; problems are warnings.
cleanup() {
    local i target
    for ((i = ${#AIOS_MOUNTS[@]} - 1; i >= 0; i--)); do
        target=${AIOS_MOUNTS[i]}
        run_cmd umount "$target" || run_cmd umount -l "$target" ||
            log "warning: could not unmount $target"
    done
    AIOS_MOUNTS=()
    if ((AIOS_LUKS_OPEN)); then
        run_cmd cryptsetup close aios || log "warning: could not close the LUKS mapping aios"
        AIOS_LUKS_OPEN=0
    fi
}

# on_exit: the EXIT trap. On failure: name the step, clean up, keep the exit status.
on_exit() {
    local rc=$?
    trap - EXIT
    if ((rc != 0)); then
        log "step $AIOS_STEP ($AIOS_STEP_NAME) failed (exit $rc)"
        cleanup
        log "the disk is left in an undefined state: fix the problem and run aios-install again"
    fi
    exit "$rc"
}
```

`installer/gen-keys.sh`:
```bash
#!/usr/bin/env bash
# gen-keys.sh OUT: pin the CachyOS repository signing keys that this build host's pacman
# keyring trusts into OUT (installer/lib/keys.sh), for the installer's keyring check (spec
# §6.2 step 9). Run by `make keys`, which `make iso` runs. Needs no root: the keyring is
# world-readable.
#
# Environment overrides (tests only): AIOS_PACMAN_GNUPG (see lib/keyring.sh).
set -euo pipefail

here=$(dirname "$(readlink -f "$0")")
# shellcheck source=lib/keyring.sh
. "$here/lib/keyring.sh"

out=${1:?usage: gen-keys.sh OUT}
mapfile -t fprs < <(trusted_key_fprs "$AIOS_CACHYOS_UID" | sort -u)

if ((${#fprs[@]} == 0)); then
    echo "gen-keys.sh: ${AIOS_PACMAN_GNUPG:-/etc/pacman.d/gnupg} trusts no key for $AIOS_CACHYOS_UID." \
        "Install cachyos-keyring and run: sudo pacman-key --populate cachyos" >&2
    exit 1
fi
for fpr in "${fprs[@]}"; do
    if [[ ! $fpr =~ ^[0-9A-F]{40}$ ]]; then
        echo "gen-keys.sh: unexpected fingerprint ${fpr@Q}" >&2
        exit 1
    fi
done

{
    echo "# shellcheck shell=bash"
    echo "# Generated by installer/gen-keys.sh from the build host's pacman keyring. Do not edit."
    echo "# The CachyOS repository signing keys the live keyring must trust (lib/keyring.sh)."
    echo "# shellcheck disable=SC2034"
    echo "AIOS_CACHYOS_KEYS=\"${fprs[*]}\""
} >"$out.tmp"
mv "$out.tmp" "$out"
echo "gen-keys.sh: pinned ${fprs[*]} in $out"
```

Run: `chmod 755 installer/gen-keys.sh`

- [ ] **Step 4: Run the tests to verify they pass**

Run: `build/tools/bats-core/bin/bats tests/bats/installer-keys.bats`
Expected: `1..9`, all `ok`. Test 4 reads this host's real keyring. It is skipped only on a host without gpg or without a CachyOS key.

- [ ] **Step 5: Makefile: lists, the `-x` shellcheck line, `make keys`**

Replace the lists block with:
```make
# What the shell and unit checks cover. installer/lib/keys.sh is generated (make keys).
INSTALLER_LIBS := installer/lib/common.sh installer/lib/config.sh installer/lib/disk.sh \
	installer/lib/cpu.sh installer/lib/manifest.sh installer/lib/skeleton.sh \
	installer/lib/secrets.sh installer/lib/usbguard.sh installer/lib/boot.sh \
	installer/lib/keyring.sh installer/lib/cleanup.sh
# Scripts that source the installer libraries; shellcheck follows the sources (-x).
INSTALLER_SCRIPTS := installer/gen-keys.sh
SH_SCRIPTS := initrd/aios-root.sh base/aios-health.sh
BASH_SCRIPTS := initrd/install/aios tests/bats/fakes/btrfs tests/bats/fakes/record \
	tests/bats/fakes/findmnt tests/bats/fakes/installer $(INSTALLER_LIBS)
BATS_FILES := tests/bats/aios-root.bats tests/bats/install-hook.bats tests/bats/aios-health.bats \
	tests/bats/installer-config.bats tests/bats/installer-disk.bats \
	tests/bats/installer-target.bats tests/bats/installer-keys.bats
UNITS := initrd/aios-root.service initrd/sysroot-etc.mount base/aios-health.service
```

Replace the `shell-check` target with this. The third line resolves `# shellcheck source=lib/…` relative to each script (`-P SCRIPTDIR`):
```make
shell-check: tools
	$(SHELLCHECK) -s sh $(SH_SCRIPTS)
	$(SHELLCHECK) -s bash $(BASH_SCRIPTS) $(BATS_FILES)
	$(SHELLCHECK) -s bash -x -P SCRIPTDIR $(INSTALLER_SCRIPTS)
```

Add `keys` to the `.PHONY` line:
```make
.PHONY: check rust-check shell-check bats-check unit-check tools repo keys
```

Append after the `repo` target:
```make

# The CachyOS signing keys this host's pacman keyring trusts, pinned for the installer.
keys:
	installer/gen-keys.sh installer/lib/keys.sh
```

- [ ] **Step 6: Ignore the generated file, run `make keys`**

Append to `.gitignore`:
```text
installer/lib/keys.sh
```

Run: `make keys && cat installer/lib/keys.sh && git status --short installer/`
Expected:
```
installer/gen-keys.sh installer/lib/keys.sh
gen-keys.sh: pinned 882DCFE48E2051D48E2562ABF3B607488DB35A47 in installer/lib/keys.sh
# shellcheck shell=bash
# Generated by installer/gen-keys.sh from the build host's pacman keyring. Do not edit.
# The CachyOS repository signing keys the live keyring must trust (lib/keyring.sh).
# shellcheck disable=SC2034
AIOS_CACHYOS_KEYS="882DCFE48E2051D48E2562ABF3B607488DB35A47"
?? installer/gen-keys.sh
?? installer/lib/cleanup.sh
?? installer/lib/keyring.sh
```
`keys.sh` does not appear because it is ignored. Another build host may pin another fingerprint. One that has no CachyOS key fails with `trusts no key for admin@cachyos.org`.

- [ ] **Step 7: The full gate**

Run: `make check`
Expected: passes. shellcheck prints three commands and no diagnostics. bats prints `1..95`, all `ok`.

- [ ] **Step 8: Commit**

```bash
git add Makefile .gitignore installer/gen-keys.sh installer/lib/keyring.sh installer/lib/cleanup.sh \
  tests/bats/installer-keys.bats
git ls-files -s installer/gen-keys.sh
```
Expected: the line starts with `100755`.

```bash
git commit -m "feat(installer): pinned CachyOS key check, make keys, and the failure cleanup trap"
```

---

### Task 5: `aios-install`, steps 1–13, and its dry-run golden test

**Files:**
- Create: `installer/aios-install`
- Test: `tests/bats/installer-dryrun.bats`
- Modify: `Makefile` (the lists)

The steps (spec §6.2, reconciled with the Phase 3 contracts):

| Step | Commands (dry-run text) | Notes |
|---|---|---|
| 1 preflight | queries only | config parsed and validated; UEFI; `/dev/mapper/aios` not open; root; tools; `validate_disk`; `curl -sI https://geo.mirror.pkgbuild.com`; v3; `check_cachyos_keys`; default manifest and `/opt/aios-repo` present |
| 2 confirm | none | unattended: `WIPE=yes` (validated in step 1); interactive: type the disk path |
| 3 partition | `sgdisk --zap-all`, `sgdisk -n1:0:+2G -t1:EF00 -n2:0:0 -t2:8309`, `udevadm settle`, `mkfs.fat -F32 -n EFI` | |
| 4 encrypt | `cryptsetup luksFormat --type luks2 --pbkdf argon2id --batch-mode --key-file -`, `cryptsetup open`, `systemd-cryptenroll --unlock-key-file=/dev/stdin --recovery-key` | passphrase on stdin; the recovery key is printed once; `cryptsetup luksUUID` for step 9 |
| 5 btrfs | `mkfs.btrfs -L aios`, mount `subvolid=5,compress=zstd` at `/mnt/aios-top`, `@blank` + skeleton + `ro`, `@persist @home @log` | contract 7 |
| 6 manifest | copy defaults to `@persist/aios/config`, `chown -R 0:0`, `chmod -R u=rwX,go=rX`, rename `home/@USERNAME@`, write `manifest.toml` (and the stripped `pacman.conf` without v3), `git init/add/commit`, secrets 0700/0600, copy `/opt/aios-repo` | contract 6 |
| 7 esp | mount `umask=0077` at `/mnt/aios-esp` | |
| 8 secureboot-keys | `@persist/var/lib/sbctl` (0700) bound on `/var/lib/sbctl`, `sbctl create-keys` | |
| 9 bootstrap | `aios bootstrap --target /mnt/aios-top --esp /mnt/aios-esp --manifest …/config/manifest.toml --luks-uuid <uuid>` | exit 2 = invalid manifest |
| 10 bootloader | `bootctl install --esp-path=/mnt/aios-esp`, write `loader/loader.conf`, `sbctl sign -s` both systemd-boot binaries | |
| 11 enroll | `sbctl enroll-keys --microsoft` in Setup Mode | a failure is a warning (spec correction 7) |
| 12 usbguard | `rules.conf` 0600 from `usbguard generate-policy` | |
| 13 finish | unmount newest first, `cryptsetup close aios`, summary, `systemctl reboot` when unattended | |

Entry points:
- `--config FILE`: unattended.
- No arguments: unattended from the fw_cfg file if the VM has one, otherwise interactive.
- `--auto` (the live ISO service): loads `qemu_fw_cfg`, then installs unattended if the fw_cfg file exists, or exits 0.
- `--dry-run`: sets `AIOS_INSTALL_DRYRUN=1`.

How the test works:
- **The fake machine.** `$FAKE_SYS` describes it:
  - a 20 GiB `/dev/vda`, with the live medium on `/dev/sr0`
  - a keyring that trusts the pinned key
  - firmware in Setup Mode
  - one USB controller
  - a fake loader that reports v3
- **Tools.** The read-only tools are the Task 2 fake. Every other tool the installer needs (`sgdisk`, `mount`, `git`, `install`, `cp`, …) is linked to Phase 4's `record` fake. So the second test can show that dry-run mode ran nothing but the 12 queries. Because `cp` is faked too, the tests write their own files with redirections.
- **Golden list.** The first test compares every `DRYRUN` line with the golden list, in order.
- **Failure hook.** The failure tests list one command in `$AIOS_INSTALL_DRYRUN_FAILS` and check what the trap prints afterwards.
- **No stdin.** `install_dry` runs the installer with stdin from `/dev/null`, so a stray prompt fails the test instead of hanging it.

- [ ] **Step 1: Write the failing tests**

`tests/bats/installer-dryrun.bats`:
```bash
#!/usr/bin/env bats
# installer/aios-install end to end in dry-run mode (spec §6.2, §7, §9): the ordered list of
# commands that change the system, what actually runs (read-only queries only), the failure
# trap, and the unattended/interactive/--auto entry points.
# bats sets $stderr for `run --separate-stderr`; each test runs in a subshell.
# shellcheck disable=SC2030,SC2031,SC2154

bats_require_minimum_version 1.5.0

setup() {
    ROOT="$BATS_TEST_DIRNAME/../.."
    SCRIPT="$ROOT/installer/aios-install"
    T="$BATS_TEST_TMPDIR"
    FPR=882DCFE48E2051D48E2562ABF3B607488DB35A47

    # The libraries, plus a keys.sh like `make keys` writes.
    mkdir -p "$T/lib"
    cp "$ROOT"/installer/lib/*.sh "$T/lib/"
    printf 'AIOS_CACHYOS_KEYS="%s"\n' "$FPR" >"$T/lib/keys.sh"

    # The fake machine: a 20 GiB /dev/vda, the live medium on /dev/sr0, a CachyOS-trusting
    # keyring, firmware in Setup Mode, one USB controller, a v3 CPU.
    export FAKE_SYS="$T/sys" CALLS="$T/calls"
    : >"$CALLS"
    blk vda disk $((20 * 1024 * 1024 * 1024)) 0 ""
    blk sr0 rom 1073741824 1 /run/archiso/bootmnt
    mkdir -p "$FAKE_SYS/mnt/run/archiso"
    echo /dev/sr0 >"$FAKE_SYS/mnt/run/archiso/bootmnt"
    keyring "$FPR"
    echo 0b2a3c4d-1111-4222-8333-944455556666 >"$FAKE_SYS/luks-uuid"
    setup_mode true
    echo 'allow id 1d6b:0002 serial "0000:00:04.0" name "xHCI Host Controller" with-interface 09:00:00' \
        >"$FAKE_SYS/usbguard-policy"
    printf '#!/bin/sh\necho "  x86-64-v3 (supported, searched)"\n' >"$T/ld.so"
    chmod +x "$T/ld.so"

    mkdir -p "$T/efi" "$T/repo" "$T/zoneinfo"
    : >"$T/repo/aios-local.db.tar.gz"
    : >"$T/zoneinfo/UTC"
    export AIOS_INSTALL_LIB="$T/lib" AIOS_INSTALL_DRYRUN=1 AIOS_EFI_DIR="$T/efi"
    export AIOS_DEFAULTS="$ROOT/manifest" AIOS_LIVE_REPO="$T/repo" AIOS_ZONEINFO="$T/zoneinfo"
    export AIOS_PASSWD_FILE=/dev/null AIOS_LDSO="$T/ld.so" AIOS_FWCFG_DIR="$T/fw_cfg"
    unset AIOS_INSTALL_DRYRUN_FAILS
    DEFAULTS=$AIOS_DEFAULTS LIVE_REPO=$AIOS_LIVE_REPO

    cat >"$T/install.conf" <<'EOF'
DISK=/dev/vda
HOSTNAME=aios-e2e
USERNAME=tester
USER_PASSWORD=e2e-user-pass
LUKS_PASSPHRASE=e2e-luks-passphrase
TIMEZONE=UTC
WIPE=yes
EXTRA_CMDLINE=console=ttyS0,115200
EOF

    # Queries answer from $FAKE_SYS. Every other tool is `record`: dry-run must never call it.
    # (So the tests below write files with redirections, not with cp.)
    mkdir -p "$T/bin"
    for n in lsblk findmnt gpg mkpasswd cryptsetup sbctl usbguard curl modprobe; do
        ln -s "$BATS_TEST_DIRNAME/fakes/installer" "$T/bin/$n"
    done
    for n in sgdisk udevadm mkfs.fat systemd-cryptenroll mkfs.btrfs btrfs mount umount git aios \
        bootctl install cp mv chown chmod; do
        ln -s "$BATS_TEST_DIRNAME/fakes/record" "$T/bin/$n"
    done
    PATH="$T/bin:$PATH"
}

blk() {
    local d="$FAKE_SYS/blk/$1"
    mkdir -p "$d"
    printf '%s\n' "$2" >"$d/TYPE"
    printf '%s\n' "$3" >"$d/SIZE"
    printf '%s\n' "$4" >"$d/RO"
    printf '%s\n' "$5" >"$d/MOUNTPOINTS"
    printf '\n' >"$d/PKNAME"
}

keyring() {
    printf 'pub:f:3072:1:%s:1628554460:::m:::scSC::::::23::0:\nfpr:::::::::%s:\nuid:f::::1691645607::05DE::CachyOS <admin@cachyos.org>::::::::::0:\n' \
        "${1: -16}" "$1" >"$FAKE_SYS/gpg.out"
}

setup_mode() {
    echo "{\"installed\":true,\"guid\":\"x\",\"setup_mode\":$1,\"secure_boot\":false,\"vendors\":[]}" \
        >"$FAKE_SYS/sbctl-status.json"
}

# install_dry ARGS...: run the installer (no stdin, so a stray prompt fails instead of
# hanging); DRY holds its DRYRUN lines, LOG its stderr.
install_dry() {
    run --separate-stderr "$SCRIPT" "$@" </dev/null
    DRY=$(grep '^DRYRUN ' <<<"$output" | sed 's/^DRYRUN //' || true)
    LOG=$stderr
}

# The commands of an unattended install on a v3 CPU in Setup Mode, in order.
golden() {
    cat <<EOF
sgdisk --zap-all /dev/vda
sgdisk -n1:0:+2G -t1:EF00 -n2:0:0 -t2:8309 /dev/vda
udevadm settle
mkfs.fat -F32 -n EFI /dev/vda1
cryptsetup luksFormat --type luks2 --pbkdf argon2id --batch-mode --key-file - /dev/vda2 <secret
cryptsetup open --key-file - /dev/vda2 aios <secret
systemd-cryptenroll --unlock-key-file=/dev/stdin --recovery-key /dev/vda2 <secret
mkfs.btrfs -L aios /dev/mapper/aios
mkdir -p /mnt/aios-top
mount -t btrfs -o subvolid=5,compress=zstd /dev/mapper/aios /mnt/aios-top
btrfs subvolume create /mnt/aios-top/@blank
install -d -m 0755 /mnt/aios-top/@blank/usr
install -d -m 0755 /mnt/aios-top/@blank/etc
install -d -m 0755 /mnt/aios-top/@blank/persist
install -d -m 0755 /mnt/aios-top/@blank/home
install -d -m 0755 /mnt/aios-top/@blank/efi
install -d -m 0555 /mnt/aios-top/@blank/proc
install -d -m 0555 /mnt/aios-top/@blank/sys
install -d -m 0755 /mnt/aios-top/@blank/dev
install -d -m 0755 /mnt/aios-top/@blank/run
install -d -m 1777 /mnt/aios-top/@blank/tmp
install -d -m 0755 /mnt/aios-top/@blank/var
install -d -m 0755 /mnt/aios-top/@blank/var/log
install -d -m 0755 /mnt/aios-top/@blank/var/lib
install -d -m 0755 /mnt/aios-top/@blank/var/cache
install -d -m 1777 /mnt/aios-top/@blank/var/tmp
install -d -m 0750 /mnt/aios-top/@blank/root
ln -s usr/bin /mnt/aios-top/@blank/bin
ln -s usr/bin /mnt/aios-top/@blank/sbin
ln -s usr/lib /mnt/aios-top/@blank/lib
ln -s usr/lib /mnt/aios-top/@blank/lib64
ln -s ../../usr/lib/pacman /mnt/aios-top/@blank/var/lib/pacman
btrfs property set -ts /mnt/aios-top/@blank ro true
btrfs subvolume create /mnt/aios-top/@persist
btrfs subvolume create /mnt/aios-top/@home
btrfs subvolume create /mnt/aios-top/@log
install -d -m 0755 /mnt/aios-top/@persist/aios
cp -a $DEFAULTS /mnt/aios-top/@persist/aios/config
chown -R 0:0 /mnt/aios-top/@persist/aios/config
chmod -R u=rwX,go=rX /mnt/aios-top/@persist/aios/config
mv /mnt/aios-top/@persist/aios/config/home/@USERNAME@ /mnt/aios-top/@persist/aios/config/home/tester
write /mnt/aios-top/@persist/aios/config/manifest.toml 0644
git -C /mnt/aios-top/@persist/aios/config init -q -b main
git -C /mnt/aios-top/@persist/aios/config add -A
git -C /mnt/aios-top/@persist/aios/config -c user.name=aios -c user.email=aios@localhost commit -q -m 'aios: initial manifest'
install -d -m 0700 /mnt/aios-top/@persist/aios/secrets /mnt/aios-top/@persist/aios/secrets/passwd
write /mnt/aios-top/@persist/aios/secrets/passwd/tester 0600
cp -a $LIVE_REPO /mnt/aios-top/@persist/aios/repo
mkdir -p /mnt/aios-esp
mount -o umask=0077 /dev/vda1 /mnt/aios-esp
install -d -m 0700 /mnt/aios-top/@persist/var/lib/sbctl
mkdir -p /var/lib/sbctl
mount --bind /mnt/aios-top/@persist/var/lib/sbctl /var/lib/sbctl
sbctl create-keys
aios bootstrap --target /mnt/aios-top --esp /mnt/aios-esp --manifest /mnt/aios-top/@persist/aios/config/manifest.toml --luks-uuid 0b2a3c4d-1111-4222-8333-944455556666
bootctl install --esp-path=/mnt/aios-esp
write /mnt/aios-esp/loader/loader.conf
sbctl sign -s /mnt/aios-esp/EFI/systemd/systemd-bootx64.efi
sbctl sign -s /mnt/aios-esp/EFI/BOOT/BOOTX64.EFI
sbctl enroll-keys --microsoft
install -d -m 0700 /mnt/aios-top/@persist/var/lib/usbguard
write /mnt/aios-top/@persist/var/lib/usbguard/rules.conf 0600
umount /var/lib/sbctl
umount /mnt/aios-esp
umount /mnt/aios-top
cryptsetup close aios
systemctl reboot
EOF
}

@test "an unattended install runs the 13 steps' commands in order" {
    install_dry --config "$T/install.conf"

    [ "$status" -eq 0 ]
    diff <(golden) - <<<"$DRY"
}

@test "dry-run mode only runs read-only queries" {
    install_dry --config "$T/install.conf"

    [ "$status" -eq 0 ]
    diff - "$CALLS" <<'EOF'
lsblk -ndro TYPE /dev/vda
findmnt -nro SOURCE /run/archiso/bootmnt
lsblk -ndro PKNAME /dev/sr0
lsblk -ndro RO /dev/vda
lsblk -nro MOUNTPOINTS /dev/vda
lsblk -ndbro SIZE /dev/vda
curl -sI --max-time 20 --retry 3 --retry-connrefused https://geo.mirror.pkgbuild.com
gpg --homedir /etc/pacman.d/gnupg --batch --no-permission-warning --with-colons --list-keys -- admin@cachyos.org
cryptsetup luksUUID /dev/vda2
mkpasswd -m yescrypt -s
sbctl status --json
usbguard generate-policy
EOF
}

@test "the log names each step, ends with the summary and never shows a secret" {
    install_dry --config "$T/install.conf"

    for n in $(seq 1 13); do
        grep -q "^aios-install: step $n/13: " <<<"$LOG" || { echo "no step $n"; return 1; }
    done
    [[ "$LOG" == *"installation complete: /dev/vda holds AIOS generation 1 for tester@aios-e2e"* ]]
    [[ "$LOG" == *"Secure Boot keys are enrolled"* ]]
    [[ "$LOG$output" != *e2e-user-pass* ]]
    [[ "$LOG$output" != *e2e-luks-passphrase* ]]
}

@test "on a CPU without x86-64-v3 the stripped pacman.conf is written too" {
    printf '#!/bin/sh\necho "  x86-64-v3"\n' >"$T/ld.so"

    install_dry --config "$T/install.conf"

    [ "$status" -eq 0 ]
    [[ "$LOG" == *"the CPU lacks x86-64-v3"* ]]
    manifest=$(grep -n '^write .*/config/manifest.toml 0644$' <<<"$DRY" | cut -d: -f1)
    pacman=$(grep -n '^write .*/config/files/pacman.conf 0644$' <<<"$DRY" | cut -d: -f1)
    init=$(grep -n ' init -q -b main$' <<<"$DRY" | cut -d: -f1)
    [ "$((manifest + 1))" -eq "$pacman" ]
    [ "$((pacman + 1))" -eq "$init" ]
    [ "$(wc -l <<<"$DRY")" -eq "$(($(golden | wc -l) + 1))" ]
}

@test "outside Setup Mode no keys are enrolled and the summary says what to do" {
    setup_mode false

    install_dry --config "$T/install.conf"

    [ "$status" -eq 0 ]
    [[ "$DRY" != *"enroll-keys"* ]]
    [[ "$LOG" == *"Secure Boot keys are NOT enrolled"*"run0 aios secureboot enroll"* ]]
}

@test "a failing step is named, then everything is unmounted newest first and LUKS closed" {
    export AIOS_INSTALL_DRYRUN_FAILS="$T/fails"
    golden | grep '^aios bootstrap ' >"$AIOS_INSTALL_DRYRUN_FAILS"

    install_dry --config "$T/install.conf"

    [ "$status" -eq 1 ]
    [[ "$LOG" == *"step 9 (bootstrap) failed (exit 1)"* ]]
    [ "$(sed -n '/^aios bootstrap /,$p' <<<"$DRY" | tail -n +2)" = "$(printf '%s\n' \
        'umount /var/lib/sbctl' 'umount /mnt/aios-esp' 'umount /mnt/aios-top' 'cryptsetup close aios')" ]
}

@test "a failure after LUKS opens but before any mount only closes LUKS" {
    export AIOS_INSTALL_DRYRUN_FAILS="$T/fails"
    echo "mkfs.btrfs -L aios /dev/mapper/aios" >"$AIOS_INSTALL_DRYRUN_FAILS"

    install_dry --config "$T/install.conf"

    [ "$status" -eq 1 ]
    [[ "$LOG" == *"step 5 (btrfs) failed"* ]]
    [ "$(tail -n 2 <<<"$DRY")" = "$(printf '%s\n' 'mkfs.btrfs -L aios /dev/mapper/aios' 'cryptsetup close aios')" ]
}

@test "a failure before LUKS opens leaves nothing to clean up" {
    export AIOS_INSTALL_DRYRUN_FAILS="$T/fails"
    echo "mkfs.fat -F32 -n EFI /dev/vda1" >"$AIOS_INSTALL_DRYRUN_FAILS"

    install_dry --config "$T/install.conf"

    [ "$status" -eq 1 ]
    [[ "$LOG" == *"step 3 (partition) failed"* ]]
    [ "$(tail -n 1 <<<"$DRY")" = "mkfs.fat -F32 -n EFI /dev/vda1" ]
}

@test "preflight problems stop the install before the disk is touched" {
    sed -i 's/^WIPE=yes$/WIPE=no/' "$T/install.conf"
    install_dry --config "$T/install.conf"
    [ "$status" -eq 1 ]
    [ -z "$DRY" ]
    [[ "$LOG" == *"erases DISK only with WIPE=yes"* ]]

    sed -i 's/^WIPE=no$/WIPE=yes/' "$T/install.conf"
    keyring 0123456789ABCDEF0123456789ABCDEF01234567
    install_dry --config "$T/install.conf"
    [ "$status" -eq 1 ]
    [ -z "$DRY" ]
    [[ "$LOG" == *"the live pacman keyring trusts the CachyOS keys [0123456789ABCDEF0123456789ABCDEF01234567]"* ]]

    keyring "$FPR"
    echo 6 >"$FAKE_SYS/curl.rc"
    install_dry --config "$T/install.conf"
    [ "$status" -eq 1 ]
    [ -z "$DRY" ]
    [[ "$LOG" == *"no network"* ]]
    [[ "$LOG" == *"step 1 (preflight) failed"* ]]
}

@test "--auto installs from the fw_cfg config, and exits 0 without one" {
    install_dry --auto
    [ "$status" -eq 0 ]
    [ -z "$DRY" ]
    [[ "$LOG" == *"no fw_cfg install config (opt/aios/install.conf)"* ]]
    grep -qx 'modprobe -q qemu_fw_cfg' "$CALLS"

    mkdir -p "$AIOS_FWCFG_DIR/by_name/opt/aios/install.conf"
    cat "$T/install.conf" >"$AIOS_FWCFG_DIR/by_name/opt/aios/install.conf/raw"
    install_dry --auto
    [ "$status" -eq 0 ]
    [[ "$LOG" == *"unattended install from $AIOS_FWCFG_DIR/by_name/opt/aios/install.conf/raw"* ]]
    diff <(golden) - <<<"$DRY"
}

@test "without arguments the fw_cfg config is used when present" {
    mkdir -p "$AIOS_FWCFG_DIR/by_name/opt/aios/install.conf"
    cat "$T/install.conf" >"$AIOS_FWCFG_DIR/by_name/opt/aios/install.conf/raw"

    install_dry

    [ "$status" -eq 0 ]
    diff <(golden) - <<<"$DRY"
}

@test "interactive mode asks for each value and needs the disk path typed back" {
    answers=$'/dev/vda\naios-e2e\ntester\ne2e-user-pass\ne2e-user-pass\ne2e-luks-passphrase\ne2e-luks-passphrase\nUTC\n'

    run --separate-stderr "$SCRIPT" <<<"${answers}/dev/vda"
    [ "$status" -eq 0 ]
    diff <(golden | sed '$d') <(grep '^DRYRUN ' <<<"$output" | sed 's/^DRYRUN //')

    run --separate-stderr "$SCRIPT" <<<"${answers}yes"
    [ "$status" -eq 1 ]
    [[ "$stderr" == *"not confirmed; nothing was changed"* ]]
    [[ "$output" != *DRYRUN* ]]
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `build/tools/bats-core/bin/bats tests/bats/installer-dryrun.bats`
Expected: `1..12` and 12 `not ok` lines. Without the script, `run` reports status 127.

- [ ] **Step 3: Write the installer**

`installer/aios-install`:
```bash
#!/usr/bin/env bash
# aios-install: install AIOS onto a whole disk from the AIOS live ISO (spec §6.2). Root only.
#
#   aios-install                interactive, unless the VM has a fw_cfg install config
#   aios-install --config FILE  unattended, from a KEY=value file (lib/config.sh)
#   aios-install --auto         the live ISO's aios-install-auto.service: unattended from the
#                               fw_cfg config if the VM has one, otherwise exit 0
#   aios-install --dry-run ...  print the commands that would change the system, run none
#
# Steps (spec §6.2): 1 preflight, 2 confirm, 3 partition, 4 encrypt, 5 btrfs, 6 manifest,
# 7 esp, 8 secureboot-keys, 9 bootstrap, 10 bootloader, 11 enroll, 12 usbguard, 13 finish.
# A failing step unmounts everything and closes LUKS (lib/cleanup.sh).
#
# Environment overrides (tests only): AIOS_INSTALL_LIB (default /usr/local/lib/aios-install),
# AIOS_EFI_DIR (/sys/firmware/efi), AIOS_DEFAULTS (/usr/share/aios/defaults/manifest),
# AIOS_LIVE_REPO (/opt/aios-repo), and those of the libraries.
set -euo pipefail

LIB=${AIOS_INSTALL_LIB:-/usr/local/lib/aios-install}
# shellcheck source=lib/common.sh
. "$LIB/common.sh"
# shellcheck source=lib/config.sh
. "$LIB/config.sh"
# shellcheck source=lib/disk.sh
. "$LIB/disk.sh"
# shellcheck source=lib/cpu.sh
. "$LIB/cpu.sh"
# shellcheck source=lib/manifest.sh
. "$LIB/manifest.sh"
# shellcheck source=lib/skeleton.sh
. "$LIB/skeleton.sh"
# shellcheck source=lib/secrets.sh
. "$LIB/secrets.sh"
# shellcheck source=lib/usbguard.sh
. "$LIB/usbguard.sh"
# shellcheck source=lib/boot.sh
. "$LIB/boot.sh"
# shellcheck source=lib/keyring.sh
. "$LIB/keyring.sh"
# shellcheck source=lib/cleanup.sh
. "$LIB/cleanup.sh"
# Generated at ISO build time by installer/gen-keys.sh (make keys).
# shellcheck source=/dev/null
. "$LIB/keys.sh"

DEFAULTS=${AIOS_DEFAULTS:-/usr/share/aios/defaults/manifest}
LIVE_REPO=${AIOS_LIVE_REPO:-/opt/aios-repo}
TOP=/mnt/aios-top
ESP=/mnt/aios-esp
TOOLS=(sgdisk udevadm mkfs.fat cryptsetup systemd-cryptenroll mkfs.btrfs btrfs mount umount
    lsblk findmnt git mkpasswd gpg sbctl aios bootctl usbguard curl install cp mv chown chmod)

usage() {
    sed -n '2,8s/^# \{0,1\}//p' "$0"
}

# ask NAME PROMPT: read one line into CFG[NAME]. Prompts go to stderr; answers come from stdin.
ask() {
    local answer
    printf '%s: ' "$2" >&2
    IFS= read -r answer || die "no answer for $1"
    CFG[$1]=$answer
}

# ask_secret NAME PROMPT: read a secret twice, without echo on a terminal.
ask_secret() {
    local a b
    printf '%s: ' "$2" >&2
    IFS= read -rs a || die "no answer for $1"
    printf '\n%s (again): ' "$2" >&2
    IFS= read -rs b || die "no answer for $1"
    printf '\n' >&2
    [[ $a == "$b" ]] || die "the two $1 entries differ"
    CFG[$1]=$a
}

prompt_config() {
    log "disks:"
    lsblk -dpno NAME,SIZE,TYPE,MODEL | awk '$3 == "disk"' >&2 || true
    ask DISK "Disk to erase and install AIOS on (for example /dev/nvme0n1)"
    ask HOSTNAME "Hostname"
    ask USERNAME "User name"
    ask_secret USER_PASSWORD "Password for ${CFG[USERNAME]}"
    ask_secret LUKS_PASSPHRASE "Disk encryption passphrase (at least 8 characters)"
    ask TIMEZONE "Time zone [UTC]"
}

require_tools() {
    local t missing=()
    for t in "${TOOLS[@]}"; do
        command -v "$t" >/dev/null || missing+=("$t")
    done
    ((${#missing[@]} == 0)) || die "missing tools: ${missing[*]}"
}

summary() {
    log "installation complete: $DISK holds AIOS generation 1 for ${CFG[USERNAME]}@${CFG[HOSTNAME]}"
    log "the LUKS recovery key printed in step 4 is the only copy: keep it somewhere safe"
    if ((ENROLLED)); then
        log "Secure Boot keys are enrolled: the firmware now boots only images signed by AIOS (or Microsoft)"
    else
        log "Secure Boot keys are NOT enrolled: put the firmware in Setup Mode, boot AIOS, then run: run0 aios secureboot enroll"
    fi
    log "once Secure Boot is on, bind the disk to the TPM: run0 aios tpm enroll"
}

main() {
    local config="" auto=0 unattended=0
    while (($#)); do
        case $1 in
            --config)
                [[ $# -ge 2 ]] || die "--config needs a file"
                config=$2
                shift 2
                ;;
            --auto) auto=1 && shift ;;
            --dry-run) export AIOS_INSTALL_DRYRUN=1 && shift ;;
            -h | --help) usage && exit 0 ;;
            *) usage >&2 && exit 1 ;;
        esac
    done
    trap on_exit EXIT
    trap 'exit 130' INT TERM

    if ((auto)); then
        modprobe -q qemu_fw_cfg 2>/dev/null || true
        config=$(fwcfg_config)
        if [[ -z $config ]]; then
            log "no fw_cfg install config ($AIOS_FWCFG_NAME); run aios-install by hand"
            exit 0
        fi
    elif [[ -z $config ]]; then
        config=$(fwcfg_config)
    fi

    step 1 preflight
    if [[ -n $config ]]; then
        unattended=1
        log "unattended install from $config"
        parse_config "$config" || die "invalid install config $config"
    else
        prompt_config
    fi
    validate_config "$unattended" || die "invalid install config"
    [[ -d ${AIOS_EFI_DIR:-/sys/firmware/efi} ]] || die "not booted in UEFI mode"
    [[ ! -e /dev/mapper/aios ]] || die "the LUKS mapping aios is already open (cryptsetup close aios)"
    dry_run || ((EUID == 0)) || die "aios-install must run as root"
    require_tools
    DISK=$(readlink -f -- "${CFG[DISK]}")
    validate_disk "$DISK" || die "unusable disk $DISK"
    ESP_PART=$(part_path "$DISK" 1)
    ROOT_PART=$(part_path "$DISK" 2)
    curl -sI --max-time 20 --retry 3 --retry-connrefused https://geo.mirror.pkgbuild.com >/dev/null ||
        die "no network: https://geo.mirror.pkgbuild.com is unreachable (Wi-Fi: iwctl)"
    if cpu_supports_v3; then
        V3=1
        log "the CPU supports x86-64-v3: the CachyOS v3 repos stay enabled"
    else
        V3=0
        log "the CPU lacks x86-64-v3: the CachyOS v3 repos are removed from pacman.conf"
    fi
    check_cachyos_keys "${AIOS_CACHYOS_KEYS:-}" || die "untrusted package keyring"
    [[ -f $DEFAULTS/manifest.toml ]] || die "no default manifest in $DEFAULTS (aios-base)"
    [[ -f $LIVE_REPO/aios-local.db.tar.gz ]] || die "no local package repo in $LIVE_REPO"

    step 2 confirm
    if ((unattended)); then
        log "WIPE=yes: erasing $DISK"
    else
        local answer
        printf 'Everything on %s will be erased. Type %s to continue: ' "$DISK" "$DISK" >&2
        IFS= read -r answer || answer=""
        [[ $answer == "$DISK" ]] || die "not confirmed; nothing was changed"
    fi

    step 3 partition
    run_cmd sgdisk --zap-all "$DISK"
    run_cmd sgdisk -n1:0:+2G -t1:EF00 -n2:0:0 -t2:8309 "$DISK"
    run_cmd udevadm settle
    run_cmd mkfs.fat -F32 -n EFI "$ESP_PART"

    step 4 encrypt
    local luks=${CFG[LUKS_PASSPHRASE]}
    run_stdin "$luks" cryptsetup luksFormat --type luks2 --pbkdf argon2id --batch-mode \
        --key-file - "$ROOT_PART"
    run_stdin "$luks" cryptsetup open --key-file - "$ROOT_PART" aios
    luks_opened
    log "recovery key (shown only now, stored nowhere: write it down):"
    run_stdin "$luks" systemd-cryptenroll --unlock-key-file=/dev/stdin --recovery-key "$ROOT_PART"
    LUKS_UUID=$(cryptsetup luksUUID "$ROOT_PART")
    [[ $LUKS_UUID =~ ^[0-9a-f-]{36}$ ]] || die "unexpected LUKS UUID ${LUKS_UUID@Q}"

    step 5 btrfs
    run_cmd mkfs.btrfs -L aios /dev/mapper/aios
    run_cmd mkdir -p "$TOP"
    mount_tracked -t btrfs -o subvolid=5,compress=zstd /dev/mapper/aios "$TOP"
    run_cmd btrfs subvolume create "$TOP/@blank"
    blank_skeleton "$TOP/@blank"
    run_cmd btrfs property set -ts "$TOP/@blank" ro true
    local sv
    for sv in @persist @home @log; do
        run_cmd btrfs subvolume create "$TOP/$sv"
    done

    step 6 manifest
    local config_dir=$TOP/@persist/aios/config secrets=$TOP/@persist/aios/secrets text
    run_cmd install -d -m 0755 "$TOP/@persist/aios"
    run_cmd cp -a "$DEFAULTS" "$config_dir"
    run_cmd chown -R 0:0 "$config_dir"
    run_cmd chmod -R u=rwX,go=rX "$config_dir"
    rename_home_template "$config_dir" "${CFG[USERNAME]}"
    text=$(render_manifest "${CFG[HOSTNAME]}" "${CFG[USERNAME]}" "${CFG[TIMEZONE]}" \
        "${CFG[EXTRA_CMDLINE]}" <"$DEFAULTS/manifest.toml")
    printf '%s\n' "$text" | run_write "$config_dir/manifest.toml" 0644
    if ((!V3)); then
        text=$(strip_v3 <"$DEFAULTS/files/pacman.conf")
        printf '%s\n' "$text" | run_write "$config_dir/files/pacman.conf" 0644
    fi
    run_cmd git -C "$config_dir" init -q -b main
    run_cmd git -C "$config_dir" add -A
    run_cmd git -C "$config_dir" -c user.name=aios -c user.email=aios@localhost \
        commit -q -m "aios: initial manifest"
    run_cmd install -d -m 0700 "$secrets" "$secrets/passwd"
    text=$(hash_password "${CFG[USER_PASSWORD]}")
    printf '%s\n' "$text" | run_write "$secrets/passwd/${CFG[USERNAME]}" 0600
    run_cmd cp -a "$LIVE_REPO" "$TOP/@persist/aios/repo"

    step 7 esp
    run_cmd mkdir -p "$ESP"
    mount_tracked -o umask=0077 "$ESP_PART" "$ESP"

    step 8 secureboot-keys
    run_cmd install -d -m 0700 "$TOP/@persist/var/lib/sbctl"
    run_cmd mkdir -p /var/lib/sbctl
    mount_tracked --bind "$TOP/@persist/var/lib/sbctl" /var/lib/sbctl
    run_cmd sbctl create-keys

    step 9 bootstrap
    run_cmd aios bootstrap --target "$TOP" --esp "$ESP" --manifest "$config_dir/manifest.toml" \
        --luks-uuid "$LUKS_UUID"

    step 10 bootloader
    run_cmd bootctl install --esp-path="$ESP"
    loader_conf | run_write "$ESP/loader/loader.conf"
    run_cmd sbctl sign -s "$ESP/EFI/systemd/systemd-bootx64.efi"
    run_cmd sbctl sign -s "$ESP/EFI/BOOT/BOOTX64.EFI"

    step 11 enroll
    ENROLLED=0
    local sb_status
    sb_status=$(sbctl status --json) || sb_status=""
    if sbctl_setup_mode "$sb_status"; then
        if run_cmd sbctl enroll-keys --microsoft; then
            ENROLLED=1
        else
            log "warning: sbctl enroll-keys failed; enroll later with: run0 aios secureboot enroll"
        fi
    else
        log "the firmware is not in Secure Boot Setup Mode; keys are not enrolled"
    fi

    step 12 usbguard
    local policy
    policy=$(usbguard generate-policy)
    text=$(usbguard_rules "$policy")
    run_cmd install -d -m 0700 "$TOP/@persist/var/lib/usbguard"
    printf '%s\n' "$text" | run_write "$TOP/@persist/var/lib/usbguard/rules.conf" 0600

    step 13 finish
    cleanup
    summary
    if ((unattended)); then
        log "rebooting into AIOS"
        run_cmd systemctl reboot
    fi
}

main "$@"
```

Run: `chmod 755 installer/aios-install`

- [ ] **Step 4: Run the tests to verify they pass**

Run: `build/tools/bats-core/bin/bats tests/bats/installer-dryrun.bats`
Expected: `1..12`, all `ok`.

- [ ] **Step 5: Try it by hand**

Run: `AIOS_INSTALL_LIB=installer/lib installer/aios-install --help`
Expected (exit 0):
```
aios-install: install AIOS onto a whole disk from the AIOS live ISO (spec §6.2). Root only.

  aios-install                interactive, unless the VM has a fw_cfg install config
  aios-install --config FILE  unattended, from a KEY=value file (lib/config.sh)
  aios-install --auto         the live ISO's aios-install-auto.service: unattended from the
                              fw_cfg config if the VM has one, otherwise exit 0
  aios-install --dry-run ...  print the commands that would change the system, run none
```
`AIOS_INSTALL_LIB` is needed because the default is the ISO path `/usr/local/lib/aios-install`. `keys.sh` must exist from Task 4 Step 6.

- [ ] **Step 6: Extend the lists**

In the lists block, change the `INSTALLER_SCRIPTS` and `BATS_FILES` lines to:
```make
INSTALLER_SCRIPTS := installer/aios-install installer/gen-keys.sh
```
```make
BATS_FILES := tests/bats/aios-root.bats tests/bats/install-hook.bats tests/bats/aios-health.bats \
	tests/bats/installer-config.bats tests/bats/installer-disk.bats \
	tests/bats/installer-target.bats tests/bats/installer-keys.bats \
	tests/bats/installer-dryrun.bats
```

- [ ] **Step 7: The full gate**

Run: `make check`
Expected: passes. The third shellcheck command is `build/tools/shellcheck -s bash -x -P SCRIPTDIR installer/aios-install installer/gen-keys.sh`, with no diagnostics. bats prints `1..107`, all `ok`.

- [ ] **Step 8: Commit**

```bash
git add Makefile installer/aios-install tests/bats/installer-dryrun.bats
git ls-files -s installer/aios-install
```
Expected: `100755`.

```bash
git commit -m "feat(installer): aios-install steps 1-13 with dry-run mode and a golden test"
```

---

### Task 6: The archiso profile and `make iso-build`, `iso`, `iso-check`, `clean-iso`

**Files:**
- Create: `iso/profiledef.sh`, `iso/packages.x86_64`, `iso/pacman.conf.in`, `iso/build-profile.sh`, `iso/efiboot/loader/loader.conf`, `iso/efiboot/loader/entries/{01-aios-linux,03-aios-serial,04-aios-memtest86+x64}.conf`, and the `iso/airootfs/` files and symlinks below
- Test: `tests/bats/iso-profile.bats`
- Modify: `Makefile` (lists, ISO targets), `.gitignore`

How it is built:
- **Releng content.** The releng files were taken from archiso's `configs/releng` at its 92 release, the version in Arch's repos today. The host has no `/usr/share/archiso`, so the plan carries every file in full. Unchanged from releng:
  - the package list (as its first section)
  - `mkinitcpio.conf.d/archiso.conf` (no `kms` hook since archiso 92)
  - `pacman-init.service` with `etc-pacman.d-gnupg.mount`
  - the networkd, resolved, journald and logind drop-ins, the two pacman hooks, `passwd`/`shadow`, the tty1 autologin and `wait-for-only-one-interface.conf`
- **Releng items left out:** BIOS/syslinux/GRUB; the speech entry and its services; sshd, ModemManager, the VM guest daemons and cloud-init enablement; `choose-mirror`, `Installation_guide` and `.automated_script.sh`.
- **AIOS changes:**
  - `bootmodes=('uefi.systemd-boot')`, `iso_name=aios`, `install_dir=aios`
  - the boot entries: `03-aios-serial.conf` is the default entry plus `console=ttyS0,115200`, and memtest moves to `04`
  - `aios-install-auto.service`
  - root autologin on `ttyS0`
  - `motd`, `hostname` and `/root/.zlogin` (which also keeps zsh's new-user wizard away)
- **The serial entry is second.** systemd-boot sorts loader entries by `sort-key` and appends auto entries (EFI shell, firmware setup) after them, so the serial entry is entry 2. The e2e harness presses `2`, and a unit test checks the position (Task 8).
- **`pacman.conf.in`.** Arch's core and extra come first, so the live system gets Arch's packages. `[cachyos]` contributes only `cachyos-keyring` and the two mirrorlists (the 3 packages the resolution test counts). `Architecture = x86_64` keeps the ISO generic. `[aios-local]` is last and unsigned (spec §4.6).
- **`iso/build-profile.sh`.** It copies only the profile files, so neither it nor `pacman.conf.in` ends up in `iso-build/`. It replaces an existing output only if that output carries its `.aios-iso-build` marker, so it can never `rm -rf` anything else.
- **Fresh work dir.** `make iso` deletes `build/iso-work` first. mkarchiso skips steps whose marker files survive in the work dir, so a leftover work dir would keep a stale build. `--one-file-system` keeps that `rm` off any mount an interrupted build left behind.

- [ ] **Step 1: Write the failing tests**

`tests/bats/iso-profile.bats`:
```bash
#!/usr/bin/env bats
# iso/: the archiso profile and build-profile.sh, checked without building (spec §6.1, §9).
# This file is `make iso-check`.
# shellcheck disable=SC2016

FPR=882DCFE48E2051D48E2562ABF3B607488DB35A47

setup() {
    ROOT="$BATS_TEST_DIRNAME/../.."
    ISO="$ROOT/iso"
    AIR="$ISO/airootfs"
    ENTRIES="$ISO/efiboot/loader/entries"
    # A fake local repo and keys file for build-profile.sh.
    REPO="$BATS_TEST_TMPDIR/repo"
    mkdir -p "$REPO"
    : >"$REPO/aios-base-0.1.0-1-any.pkg.tar.zst"
    : >"$REPO/aios-local.db.tar.gz"
    ln -s aios-local.db.tar.gz "$REPO/aios-local.db"
    KEYS="$BATS_TEST_TMPDIR/keys.sh"
    printf 'AIOS_CACHYOS_KEYS="%s"\n' "$FPR" >"$KEYS"
    OUT="$BATS_TEST_TMPDIR/iso-build"
}

# packages: the package list without comments and blank lines.
packages() {
    sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "$ISO/packages.x86_64"
}

# option FILE KEY: the value of KEY in a systemd-boot entry or loader.conf.
option() {
    sed -n "s/^$2[[:space:]]\{1,\}//p" "$1"
}

@test "profiledef.sh: AIOS names, UEFI systemd-boot only" {
    run bash -c 'declare -A file_permissions=(); . "$1"; printf "%s\n" "$iso_name" "$install_dir" "${bootmodes[*]}" "$pacman_conf" "$iso_label"; printf "%s\n" "${!file_permissions[@]}" | sort' _ "$ISO/profiledef.sh"

    [ "$status" -eq 0 ]
    [ "${lines[0]}" = aios ]
    [ "${lines[1]}" = aios ]
    [ "${lines[2]}" = uefi.systemd-boot ]
    [ "${lines[3]}" = pacman.conf ]
    [[ "${lines[4]}" =~ ^AIOS_[0-9]{6}$ ]]
    [ "${lines[5]}" = /etc/shadow ]
    [ "${lines[6]}" = /root ]
    [ "${lines[7]}" = /usr/local/bin/aios-install ]
}

@test "the package list is releng plus the AIOS additions, without duplicates" {
    [ -z "$(packages | sort | uniq -d)" ]
    for p in base linux mkinitcpio mkinitcpio-archiso edk2-shell memtest86+-efi iwd zsh \
        arch-install-scripts sbctl btrfs-progs cryptsetup gptfdisk tpm2-tools git usbguard whois \
        aios-cli aios-base cachyos-keyring cachyos-mirrorlist cachyos-v3-mirrorlist; do
        packages | grep -qx -- "$p" || { echo "missing $p"; return 1; }
    done
}

@test "the boot entries: default, serial console, memtest" {
    [ "$(cd "$ENTRIES" && ls)" = "$(printf '%s\n' 01-aios-linux.conf 03-aios-serial.conf '04-aios-memtest86+x64.conf')" ]
    [ "$(option "$ISO/efiboot/loader/loader.conf" default)" = 01-aios-linux.conf ]
    for e in 01-aios-linux.conf 03-aios-serial.conf; do
        [[ "$(option "$ENTRIES/$e" options)" == "archisobasedir=%INSTALL_DIR% archisosearchuuid=%ARCHISO_UUID% %KERNEL_PARAMS%"* ]]
        [ "$(option "$ENTRIES/$e" linux)" = "/%INSTALL_DIR%/boot/%ARCH%/vmlinuz-linux" ]
        [ "$(option "$ENTRIES/$e" initrd)" = "/%INSTALL_DIR%/boot/%ARCH%/initramfs-linux.img" ]
    done
    [ "$(option "$ENTRIES/03-aios-serial.conf" options)" = "$(option "$ENTRIES/01-aios-linux.conf" options) console=ttyS0,115200" ]
    [ "$(cat "$ENTRIES"/*.conf | option /dev/stdin sort-key | paste -sd' ')" = "01 03 04" ]
}

@test "the live system: autologin on tty1 and ttyS0, the auto-install unit enabled" {
    for f in etc/hostname etc/motd etc/passwd etc/shadow root/.zlogin \
        etc/systemd/system/getty@tty1.service.d/autologin.conf \
        etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf \
        etc/systemd/system/aios-install-auto.service etc/systemd/system/pacman-init.service; do
        [ -f "$AIR/$f" ] || { echo "missing $f"; return 1; }
    done
    grep -qx 'ExecStart=-/usr/bin/agetty --noreset --noclear --autologin root --keep-baud 115200,57600,38400,9600 - ${TERM}' \
        "$AIR/etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf"
    grep -qx 'ExecStart=/usr/local/bin/aios-install --auto' "$AIR/etc/systemd/system/aios-install-auto.service"
    [ "$(readlink "$AIR/etc/systemd/system/multi-user.target.wants/aios-install-auto.service")" = ../aios-install-auto.service ]
    [ "$(readlink "$AIR/etc/systemd/system/multi-user.target.wants/pacman-init.service")" = ../pacman-init.service ]
    [ "$(cat "$AIR/etc/hostname")" = aios-live ]
}

@test "every airootfs symlink is absolute or stays inside /etc/systemd/system" {
    while IFS= read -r link; do
        target=$(readlink "$link")
        case $target in
            /*) ;;
            ../*.service) [[ $link == */etc/systemd/system/*.wants/* ]] && [ -f "$(dirname "$link")/$target" ] ;;
            *) echo "unexpected relative link $link -> $target"; return 1 ;;
        esac
    done < <(find "$AIR" -type l)
    [ "$(find "$AIR" -type l | wc -l)" -eq 15 ]
}

@test "pacman.conf.in: core, extra, cachyos, then the unsigned aios-local repo last" {
    [ "$(grep -c '@AIOS_REPO@' "$ISO/pacman.conf.in")" -eq 1 ]
    grep -qx 'Server = file://@AIOS_REPO@' "$ISO/pacman.conf.in"
    [ "$(grep '^\[' "$ISO/pacman.conf.in" | paste -sd' ')" = "[options] [core] [extra] [cachyos] [aios-local]" ]
    [ "$(sed -n '/^\[aios-local\]/,$p' "$ISO/pacman.conf.in" | grep -c '^SigLevel = Optional TrustAll$')" -eq 1 ]
    grep -qx 'Architecture = x86_64' "$ISO/pacman.conf.in"
}

@test "build-profile.sh assembles the complete profile" {
    run "$ISO/build-profile.sh" "$OUT" "$REPO" "$KEYS"

    [ "$status" -eq 0 ]
    [ -f "$OUT/.aios-iso-build" ]
    [ ! -e "$OUT/pacman.conf.in" ] && [ ! -e "$OUT/build-profile.sh" ]
    grep -qx "Server = file://$(readlink -f "$REPO")" "$OUT/pacman.conf"
    [ "$(grep -c '@AIOS_REPO@' "$OUT/pacman.conf")" -eq 0 ]
    [ "$(stat -c %a "$OUT/airootfs/usr/local/bin/aios-install")" = 755 ]
    cmp "$ROOT/installer/aios-install" "$OUT/airootfs/usr/local/bin/aios-install"
    for f in "$ROOT"/installer/lib/*.sh; do
        [ "$(basename "$f")" = keys.sh ] && continue
        cmp "$f" "$OUT/airootfs/usr/local/lib/aios-install/$(basename "$f")"
    done
    cmp "$KEYS" "$OUT/airootfs/usr/local/lib/aios-install/keys.sh"
    [ "$(readlink "$OUT/airootfs/opt/aios-repo/aios-local.db")" = aios-local.db.tar.gz ]
    [ -f "$OUT/airootfs/opt/aios-repo/aios-base-0.1.0-1-any.pkg.tar.zst" ]
    diff -r "$ISO/efiboot" "$OUT/efiboot"
    [ "$(readlink "$OUT/airootfs/etc/resolv.conf")" = /run/systemd/resolve/stub-resolv.conf ]
}

@test "build-profile.sh rebuilds its own output but never touches anything else" {
    "$ISO/build-profile.sh" "$OUT" "$REPO" "$KEYS"
    : >"$OUT/stale"
    "$ISO/build-profile.sh" "$OUT" "$REPO" "$KEYS"
    [ ! -e "$OUT/stale" ]

    mkdir "$BATS_TEST_TMPDIR/mine"
    : >"$BATS_TEST_TMPDIR/mine/precious"
    run "$ISO/build-profile.sh" "$BATS_TEST_TMPDIR/mine" "$REPO" "$KEYS"
    [ "$status" -eq 1 ]
    [[ "$output" == *"exists but was not made by build-profile.sh"* ]]
    [ -f "$BATS_TEST_TMPDIR/mine/precious" ]
}

@test "build-profile.sh needs the local repo and a pinned key" {
    run "$ISO/build-profile.sh" "$OUT" "$BATS_TEST_TMPDIR/norepo" "$KEYS"
    [ "$status" -eq 1 ]
    [[ "$output" == *"run make repo first"* ]]

    : >"$KEYS"
    run "$ISO/build-profile.sh" "$OUT" "$REPO" "$KEYS"
    [ "$status" -eq 1 ]
    [[ "$output" == *"pins no CachyOS key: run make keys"* ]]
    [ ! -e "$OUT" ]
}

@test "every package resolves in the build host's sync databases (except aios-*)" {
    command -v pacman >/dev/null || skip "pacman not installed"
    db=$(pacman-conf DBPath)
    for r in core extra cachyos; do
        [ -f "$db/sync/$r.db" ] || skip "the host has no synced $r database"
    done
    sed '/^\[aios-local\]/,$d' "$ISO/pacman.conf.in" >"$BATS_TEST_TMPDIR/pacman.conf"
    mapfile -t pkgs < <(packages | grep -vx -e aios-base -e aios-cli)

    run pacman -Sp --config "$BATS_TEST_TMPDIR/pacman.conf" --print-format '%r %n' "${pkgs[@]}"

    [ "$status" -eq 0 ] || { echo "$output"; echo "(stale host databases give false misses)"; return 1; }
    [ "$(grep -c '^cachyos ' <<<"$output")" -eq 3 ]
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `build/tools/bats-core/bin/bats tests/bats/iso-profile.bats`
Expected: `1..10` and 10 `not ok` lines, for missing files under `iso/`.

- [ ] **Step 3: The profile's own files**

`iso/profiledef.sh`:
```bash
#!/usr/bin/env bash
# shellcheck disable=SC2034
# AIOS live and install medium (spec §6.1): archiso's releng profile (archiso 92), UEFI only,
# booted by systemd-boot. `make iso-build` turns this directory into iso-build/.

iso_name="aios"
iso_label="AIOS_$(date --date="@${SOURCE_DATE_EPOCH:-$(date +%s)}" +%Y%m)"
iso_publisher="AIOS"
iso_application="AIOS live and install medium"
iso_version="$(date --date="@${SOURCE_DATE_EPOCH:-$(date +%s)}" +%Y.%m.%d)"
install_dir="aios"
bootmodes=('uefi.systemd-boot')
pacman_conf="pacman.conf"
airootfs_image_type="squashfs"
airootfs_image_tool_options=('-comp' 'xz' '-Xbcj' 'x86' '-b' '1M' '-Xdict-size' '1M')
file_permissions=(
  ["/etc/shadow"]="0:0:400"
  ["/root"]="0:0:750"
  ["/usr/local/bin/aios-install"]="0:0:755"
)
```

`iso/packages.x86_64`:
```text
# archiso releng (archiso 92), unchanged:
alsa-utils
amd-ucode
arch-install-scripts
archinstall
b43-fwcutter
base
bcachefs-tools
bind
bolt
brltty
btrfs-progs
clonezilla
cloud-init
cryptsetup
darkhttpd
ddrescue
dhcpcd
diffutils
dmidecode
dmraid
dnsmasq
dosfstools
e2fsprogs
edk2-shell
efibootmgr
espeakup
ethtool
exfatprogs
f2fs-tools
fatresize
foot-terminfo
fsarchiver
ghostty-terminfo
gpart
gpm
gptfdisk
grml-zsh-config
grub
hdparm
hyperv
intel-ucode
irssi
iw
iwd
jfsutils
kitty-terminfo
kmscon-terminfo
ldns
less
lftp
libfido2
libusb-compat
linux
linux-firmware
linux-firmware-marvell
livecd-sounds
lsscsi
lvm2
lynx
man-db
man-pages
mc
mdadm
memtest86+
memtest86+-efi
mkinitcpio
mkinitcpio-archiso
mkinitcpio-nfs-utils
mmc-utils
modemmanager
mtools
nano
nbd
ndisc6
nfs-utils
nilfs-utils
nmap
ntfsprogs
nvme-cli
open-iscsi
open-vm-tools
openconnect
openpgp-card-tools
openssh
openvpn
partclone
parted
partimage
pcsclite
ppp
pptpclient
pv
qemu-guest-agent
refind
reflector
rsync
rxvt-unicode-terminfo
screen
sdparm
sequoia-sq
sg3_utils
smartmontools
sof-firmware
squashfs-tools
sudo
syslinux
systemd-resolvconf
tcpdump
terminus-font
testdisk
tmux
tpm2-tools
tpm2-tss
udftools
usb_modeswitch
usbmuxd
usbutils
vim
virtualbox-guest-utils-nox
vpnc
wireless-regdb
wireless_tools
wpa_supplicant
wvdial
xdg-utils
xfsprogs
xl2tpd
zsh

# AIOS (spec §6.1). arch-install-scripts, btrfs-progs, cryptsetup, gptfdisk and tpm2-tools
# are in the releng list above. The CachyOS keyring and mirrorlists are what
# `aios bootstrap` needs on the live system (Phase 3 contract 7).
aios-base
aios-cli
cachyos-keyring
cachyos-mirrorlist
cachyos-v3-mirrorlist
git
sbctl
usbguard
whois
```

`iso/pacman.conf.in`:
```ini
# pacman.conf for building the AIOS ISO (spec §6.1). `make iso-build` writes it to
# iso-build/pacman.conf, with the absolute path of build/repo in the aios-local Server line.
# The build host's keyring must trust the Arch and CachyOS keys (a CachyOS host does).
#
# Arch's core and extra come first, so the live system gets Arch's packages. [cachyos] is
# only there for cachyos-keyring and the mirrorlists, and its packages are generic x86_64,
# so the ISO boots on any x86_64 CPU. [aios-local] is last and unsigned (spec §4.6).

[options]
HoldPkg      = pacman glibc
Architecture = x86_64
ParallelDownloads = 5
SigLevel          = Required DatabaseOptional
LocalFileSigLevel = Optional

[core]
Include = /etc/pacman.d/mirrorlist

[extra]
Include = /etc/pacman.d/mirrorlist

[cachyos]
Include = /etc/pacman.d/cachyos-mirrorlist

[aios-local]
SigLevel = Optional TrustAll
Server = file://@AIOS_REPO@
```

`iso/efiboot/loader/loader.conf`:
```text
timeout 15
default 01-aios-linux.conf
beep on
```

`iso/efiboot/loader/entries/01-aios-linux.conf`:
```text
title    AIOS install medium (%ARCH%, UEFI)
sort-key 01
linux    /%INSTALL_DIR%/boot/%ARCH%/vmlinuz-linux
initrd   /%INSTALL_DIR%/boot/%ARCH%/initramfs-linux.img
options  archisobasedir=%INSTALL_DIR% archisosearchuuid=%ARCHISO_UUID% %KERNEL_PARAMS%
```

`iso/efiboot/loader/entries/03-aios-serial.conf`:
```text
title    AIOS install medium (%ARCH%, UEFI, serial console)
sort-key 03
linux    /%INSTALL_DIR%/boot/%ARCH%/vmlinuz-linux
initrd   /%INSTALL_DIR%/boot/%ARCH%/initramfs-linux.img
options  archisobasedir=%INSTALL_DIR% archisosearchuuid=%ARCHISO_UUID% %KERNEL_PARAMS% console=ttyS0,115200
```

`iso/efiboot/loader/entries/04-aios-memtest86+x64.conf`:
```text
title    Memtest86+
sort-key 04
efi      /boot/memtest86+/memtest86x64.efi
architecture x64
```

`iso/build-profile.sh`:
```bash
#!/usr/bin/env bash
# build-profile.sh OUT REPO KEYS: assemble the archiso profile that mkarchiso builds (spec
# §6.1), without root. Run by `make iso-build`.
#   OUT   the profile to create (iso-build/). An existing OUT is replaced only if this
#         script made it (it holds the .aios-iso-build marker).
#   REPO  the local package repo (build/repo/ from `make repo`)
#   KEYS  the pinned CachyOS keys (installer/lib/keys.sh from `make keys`)
# OUT gets this profile (without pacman.conf.in and this script), pacman.conf with the
# absolute REPO path, the installer and its libraries, and a copy of REPO in /opt/aios-repo.
set -euo pipefail

here=$(dirname "$(readlink -f "$0")")
root=$(dirname "$here")
usage="usage: build-profile.sh OUT REPO KEYS"
out=${1:?$usage}
repo=${2:?$usage}
keys=${3:?$usage}
marker=.aios-iso-build

fail() {
    echo "build-profile.sh: $*" >&2
    exit 1
}

[[ -f $repo/aios-local.db.tar.gz ]] || fail "no $repo/aios-local.db.tar.gz: run make repo first"
repo=$(readlink -f "$repo")
[[ $repo =~ ^/[A-Za-z0-9._/+-]+$ ]] || fail "the repo path $repo has characters pacman.conf cannot hold"
grep -Eqx 'AIOS_CACHYOS_KEYS="[0-9A-F]{40}( [0-9A-F]{40})*"' "$keys" 2>/dev/null ||
    fail "$keys pins no CachyOS key: run make keys"
if [[ -e $out || -L $out ]]; then
    [[ -f $out/$marker ]] || fail "$out exists but was not made by build-profile.sh; not touching it"
    rm -rf -- "$out"
fi

mkdir -p "$out"
cp -a "$here/profiledef.sh" "$here/packages.x86_64" "$here/efiboot" "$here/airootfs" "$out/"
sed "s|@AIOS_REPO@|$repo|" "$here/pacman.conf.in" >"$out/pacman.conf"
lib=$out/airootfs/usr/local/lib/aios-install
install -D -m 0755 "$root/installer/aios-install" "$out/airootfs/usr/local/bin/aios-install"
install -d -m 0755 "$lib"
install -m 0644 "$root"/installer/lib/*.sh "$lib/"
install -m 0644 "$keys" "$lib/keys.sh"
install -d -m 0755 "$out/airootfs/opt/aios-repo"
cp -a "$repo/." "$out/airootfs/opt/aios-repo/"
: >"$out/$marker"
echo "build-profile.sh: profile ready in $out (repo $repo)"
```

Run: `chmod 755 iso/build-profile.sh`

- [ ] **Step 4: The live system: AIOS files**

`iso/airootfs/etc/systemd/system/aios-install-auto.service`:
```ini
# AIOS live ISO only (spec §6.2): install unattended when the VM provides the QEMU fw_cfg
# file opt/aios/install.conf (the e2e harness does). Without it, `aios-install --auto`
# exits 0 at once. The installer's output goes to the console (the serial console when the
# serial boot entry is used).

[Unit]
Description=AIOS: unattended install from the QEMU fw_cfg config
Wants=network-online.target
After=network-online.target time-sync.target pacman-init.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/aios-install --auto
StandardInput=null
StandardOutput=journal+console
StandardError=journal+console
TimeoutStartSec=infinity

[Install]
WantedBy=multi-user.target
```

`iso/airootfs/etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf`:
```ini
# AIOS live ISO only (spec §6.1): log root in on the serial console, as on tty1.
[Service]
ExecStart=
ExecStart=-/usr/bin/agetty --noreset --noclear --autologin root --keep-baud 115200,57600,38400,9600 - ${TERM}
```

`iso/airootfs/etc/motd` (it ends with an empty line):
```text
AIOS live medium. Nothing is installed yet.

  aios-install                  install AIOS; asks for the disk to erase and the settings
  aios-install --config FILE    unattended install from KEY=value lines (see the script)
  iwctl                         connect to Wi-Fi first when there is no Ethernet

The installer erases the whole disk you choose.

```

`iso/airootfs/etc/hostname`:
```text
aios-live
```

`iso/airootfs/root/.zlogin`:
```zsh
# AIOS live medium. (A ~/.zlogin also keeps zsh's new-user wizard away.)
print -P '%BRun aios-install to install AIOS.%b'
```

- [ ] **Step 5: The live system: files kept from releng (archiso 92)**

`iso/airootfs/etc/locale.conf`:
```ini
LANG=C.UTF-8
```

`iso/airootfs/etc/passwd`:
```text
root:x:0:0:root:/root:/usr/bin/zsh
```

`iso/airootfs/etc/shadow`:
```text
root::14871::::::
```

`iso/airootfs/etc/mkinitcpio.conf.d/archiso.conf`:
```bash
HOOKS=(base udev microcode modconf memdisk archiso archiso_loop_mnt archiso_pxe_common archiso_pxe_nbd archiso_pxe_http archiso_pxe_nfs block filesystems keyboard)
COMPRESSION="xz"
COMPRESSION_OPTIONS=(-9e)
```

`iso/airootfs/etc/pacman.d/hooks/uncomment-mirrors.hook`:
```ini
# remove from airootfs!
[Trigger]
Operation = Install
Operation = Upgrade
Type = Package
Target = pacman-mirrorlist

[Action]
Description = Uncommenting HTTPS mirrors in /etc/pacman.d/mirrorlist...
When = PostTransaction
Depends = pacman-mirrorlist
Depends = sed
Exec = /usr/bin/sed -E -i 's/#(Server = https:)/\1/g' /etc/pacman.d/mirrorlist
```

`iso/airootfs/etc/pacman.d/hooks/zzzz99-remove-custom-hooks-from-airootfs.hook`:
```ini
# remove from airootfs!
# As a workaround for https://bugs.archlinux.org/task/49347 , remove pacman hooks specific to the ISO build process.
# If not, they would be used when pacstrap is run in the live environment.

[Trigger]
Operation = Install
Operation = Upgrade
Operation = Remove
Type = Package
Target = *

[Action]
Description = Work around FS#49347 by removing custom pacman hooks that are only required during ISO build...
When = PostTransaction
Depends = sh
Depends = coreutils
Depends = grep
Exec = /bin/sh -c "rm -- $(grep -Frl 'remove from airootfs' /etc/pacman.d/hooks/)"
```

`iso/airootfs/etc/systemd/journald.conf.d/volatile-storage.conf`:
```ini
[Journal]
Storage=volatile
```

`iso/airootfs/etc/systemd/logind.conf.d/do-not-suspend.conf`:
```ini
[Login]
HandleSuspendKey=ignore
HandleHibernateKey=ignore
HandleLidSwitch=ignore
```

`iso/airootfs/etc/systemd/network/20-ethernet.network`:
```ini
[Match]
Type=ether
# Exclude virtual Ethernet interfaces
Kind=!*

[Link]
RequiredForOnline=routable

[Network]
DHCP=yes
MulticastDNS=yes

# systemd-networkd does not set per-interface-type default route metrics
# https://github.com/systemd/systemd/issues/17698
# Explicitly set route metric, so that Ethernet is preferred over Wi-Fi and Wi-Fi is preferred over mobile broadband.
# Use values from NetworkManager. From nm_device_get_route_metric_default in
# https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/blob/main/src/core/devices/nm-device.c
[DHCPv4]
RouteMetric=100

[IPv6AcceptRA]
RouteMetric=100
```

`iso/airootfs/etc/systemd/network/20-wlan.network`:
```ini
[Match]
Type=wlan

[Link]
RequiredForOnline=routable

[Network]
DHCP=yes
MulticastDNS=yes

# systemd-networkd does not set per-interface-type default route metrics
# https://github.com/systemd/systemd/issues/17698
# Explicitly set route metric, so that Ethernet is preferred over Wi-Fi and Wi-Fi is preferred over mobile broadband.
# Use values from NetworkManager. From nm_device_get_route_metric_default in
# https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/blob/main/src/core/devices/nm-device.c
[DHCPv4]
RouteMetric=600

[IPv6AcceptRA]
RouteMetric=600
```

`iso/airootfs/etc/systemd/network/20-wwan.network`:
```ini
[Match]
Type=wwan

[Link]
RequiredForOnline=routable

[Network]
DHCP=yes

# systemd-networkd does not set per-interface-type default route metrics
# https://github.com/systemd/systemd/issues/17698
# Explicitly set route metric, so that Ethernet is preferred over Wi-Fi and Wi-Fi is preferred over mobile broadband.
# Use values from NetworkManager. From nm_device_get_route_metric_default in
# https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/blob/main/src/core/devices/nm-device.c
[DHCPv4]
RouteMetric=700

[IPv6AcceptRA]
RouteMetric=700
```

`iso/airootfs/etc/systemd/networkd.conf.d/ipv6-privacy-extensions.conf`:
```ini
[Network]
IPv6PrivacyExtensions=yes
```

`iso/airootfs/etc/systemd/resolved.conf.d/archiso.conf`:
```bash
# Default systemd-resolved configuration for archiso

[Resolve]
MulticastDNS=yes
```

`iso/airootfs/etc/systemd/system/etc-pacman.d-gnupg.mount`:
```ini
[Unit]
Description=Temporary /etc/pacman.d/gnupg directory

[Mount]
What=tmpfs
Where=/etc/pacman.d/gnupg
Type=tmpfs
Options=mode=0755,noswap
```

`iso/airootfs/etc/systemd/system/pacman-init.service`:
```ini
[Unit]
Description=Initializes Pacman keyring
Requires=etc-pacman.d-gnupg.mount
After=etc-pacman.d-gnupg.mount time-sync.target
BindsTo=etc-pacman.d-gnupg.mount
Before=archlinux-keyring-wkd-sync.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/pacman-key --init
ExecStart=/usr/bin/pacman-key --populate

[Install]
WantedBy=multi-user.target
```

`iso/airootfs/etc/systemd/system/getty@tty1.service.d/autologin.conf`:
```ini
[Service]
ExecStart=
ExecStart=-/usr/bin/agetty --noreset --noclear --autologin root - ${TERM}
```

`iso/airootfs/etc/systemd/system/systemd-networkd-wait-online.service.d/wait-for-only-one-interface.conf`:
```ini
# Allow systemd-networkd-wait-online to succeed with one interface, otherwise, if multiple network interfaces exist,
# network-online.target gets needlessly delayed.
# See https://wiki.archlinux.org/title/systemd-networkd#systemd-networkd-wait-online
[Service]
ExecStart=
ExecStart=/usr/lib/systemd/systemd-networkd-wait-online --any
```

- [ ] **Step 6: The live system: symlinks**

These are releng's links, minus the services left out, plus `aios-install-auto.service`. Run this in bash:
```bash
bash -euc '
cd iso/airootfs
ln -s /usr/share/zoneinfo/UTC etc/localtime
ln -s /run/systemd/resolve/stub-resolv.conf etc/resolv.conf
mkdir -p etc/systemd/system-generators
ln -s /dev/null etc/systemd/system-generators/systemd-gpt-auto-generator
cd etc/systemd/system
mkdir -p multi-user.target.wants network-online.target.wants sockets.target.wants sysinit.target.wants
ln -s /usr/lib/systemd/system/systemd-networkd.service dbus-org.freedesktop.network1.service
ln -s /usr/lib/systemd/system/systemd-resolved.service dbus-org.freedesktop.resolve1.service
ln -s /usr/lib/systemd/system/systemd-timesyncd.service dbus-org.freedesktop.timesync1.service
ln -s ../aios-install-auto.service multi-user.target.wants/aios-install-auto.service
ln -s ../pacman-init.service multi-user.target.wants/pacman-init.service
ln -s /usr/lib/systemd/system/iwd.service multi-user.target.wants/iwd.service
ln -s /usr/lib/systemd/system/systemd-networkd.service multi-user.target.wants/systemd-networkd.service
ln -s /usr/lib/systemd/system/systemd-resolved.service multi-user.target.wants/systemd-resolved.service
ln -s /usr/lib/systemd/system/systemd-networkd-wait-online.service network-online.target.wants/systemd-networkd-wait-online.service
ln -s /usr/lib/systemd/system/systemd-networkd.socket sockets.target.wants/systemd-networkd.socket
ln -s /usr/lib/systemd/system/systemd-time-wait-sync.service sysinit.target.wants/systemd-time-wait-sync.service
ln -s /usr/lib/systemd/system/systemd-timesyncd.service sysinit.target.wants/systemd-timesyncd.service
'
find iso/airootfs -type l | wc -l; find iso/airootfs -type f | wc -l
```
Expected: `15` and `22`.

- [ ] **Step 7: Run the tests to verify they pass**

Run: `build/tools/bats-core/bin/bats tests/bats/iso-profile.bats`
Expected: `1..10`, all `ok`. Test 10 resolves the whole package list, except `aios-*`, against this host's sync databases. A miss there usually means stale host databases, not a bad list.

- [ ] **Step 8: Makefile: lists and the ISO targets**

Replace the lists block with the final one:
```make
# What the shell and unit checks cover. installer/lib/keys.sh is generated (make keys).
INSTALLER_LIBS := installer/lib/common.sh installer/lib/config.sh installer/lib/disk.sh \
	installer/lib/cpu.sh installer/lib/manifest.sh installer/lib/skeleton.sh \
	installer/lib/secrets.sh installer/lib/usbguard.sh installer/lib/boot.sh \
	installer/lib/keyring.sh installer/lib/cleanup.sh
# Scripts that source the installer libraries; shellcheck follows the sources (-x).
INSTALLER_SCRIPTS := installer/aios-install installer/gen-keys.sh
SH_SCRIPTS := initrd/aios-root.sh base/aios-health.sh
BASH_SCRIPTS := initrd/install/aios tests/bats/fakes/btrfs tests/bats/fakes/record \
	tests/bats/fakes/findmnt tests/bats/fakes/installer iso/profiledef.sh iso/build-profile.sh \
	$(INSTALLER_LIBS)
BATS_FILES := tests/bats/aios-root.bats tests/bats/install-hook.bats tests/bats/aios-health.bats \
	tests/bats/installer-config.bats tests/bats/installer-disk.bats \
	tests/bats/installer-target.bats tests/bats/installer-keys.bats \
	tests/bats/installer-dryrun.bats tests/bats/iso-profile.bats
UNITS := initrd/aios-root.service initrd/sysroot-etc.mount base/aios-health.service \
	iso/airootfs/etc/systemd/system/aios-install-auto.service

# The ISO (spec §6.1): iso/ is the profile, iso-build/ the generated copy mkarchiso builds.
ISO_BUILD := iso-build
ISO_WORK := build/iso-work
ISO_OUT := out
```

Add `SUDO ?= sudo` after the `CARGO ?= cargo` line, and change the `.PHONY` line to:
```make
.PHONY: check rust-check shell-check bats-check unit-check tools repo keys iso-build iso \
	iso-check clean-iso
```

Append after the `keys` target:
```make

# The profile mkarchiso builds: iso/ plus pacman.conf, the installer and build/repo.
iso-build: keys
	iso/build-profile.sh $(ISO_BUILD) build/repo installer/lib/keys.sh

# Needs root: run `make iso` yourself (not `sudo make iso`); it asks sudo for the two root
# commands. archiso >= 89 can also build unprivileged: `make iso SUDO=`.
iso: iso-build
	$(SUDO) rm -rf --one-file-system $(ISO_WORK)
	$(SUDO) mkarchiso -v -w $(ISO_WORK) -o $(ISO_OUT) $(ISO_BUILD)/

# Static profile checks, no build and no root.
iso-check: tools
	$(BATS) tests/bats/iso-profile.bats

clean-iso:
	rm -rf $(ISO_BUILD)
	if [ -e $(ISO_WORK) ]; then $(SUDO) rm -rf --one-file-system $(ISO_WORK); fi
```

Append to `.gitignore`:
```text
iso-build/
```

- [ ] **Step 9: Check the targets without root**

Run: `make iso-check`
Expected: `build/tools/bats-core/bin/bats tests/bats/iso-profile.bats`, then `1..10`, all `ok`.

Run: `make unit-check`
Expected: the `cp` line now lists `iso/airootfs/etc/systemd/system/aios-install-auto.service`. `systemd-analyze verify` prints nothing.

Run: `make -n iso | tail -2`
Expected (dry run, nothing executed):
```
sudo rm -rf --one-file-system build/iso-work
sudo mkarchiso -v -w build/iso-work -o out iso-build/
```

Run: `test -f build/repo/aios-local.db.tar.gz && make iso-build && grep '^Server = file://' iso-build/pacman.conf && ls iso-build/airootfs/opt/aios-repo | grep -c 'pkg.tar.zst$'`
Expected:
- the `keys` output from Task 4
- `build-profile.sh: profile ready in iso-build (repo /home/eli/Development/AIOS/build/repo)`
- `Server = file:///home/eli/Development/AIOS/build/repo`
- `2`

Without `build/repo`, run `make repo` first (Phase 4, no root, several minutes). `iso-build/` is ignored.

- [ ] **Step 10: The full gate**

Run: `make check`
Expected: passes. bats prints `1..117`, all `ok`. `systemd-analyze verify` checks four units.

- [ ] **Step 11: Commit (modes and symlinks)**

```bash
git add Makefile .gitignore iso/ tests/bats/iso-profile.bats
git ls-files -s iso/build-profile.sh | cut -c1-6; git ls-files -s iso | grep -c '^120000'
```
Expected: `100755` and `15`.

```bash
git commit -m "feat(iso): archiso profile (UEFI, systemd-boot), build-profile.sh and the ISO make targets"
git status --short --untracked-files=all | grep -E 'iso|installer' || echo "nothing left over"
```
Expected: `nothing left over`. `iso-build/` and `installer/lib/keys.sh` are ignored.

- [ ] **Step 12: USER RUNS: build the ISO (needs root; the agent does not run it)**

Run by the user, after `sudo pacman -S --needed archiso` (archiso 91 or later, for `%KERNEL_PARAMS%`):
```bash
make repo   # only if build/repo is missing or older than the last commit
make iso    # not `sudo make iso`; sudo prompts for the work-dir cleanup and mkarchiso
```
Expected: mkarchiso ends with `[mkarchiso] INFO: Done! … out/aios-YYYY.MM.DD-x86_64.iso`. The agent checks it afterwards with `ls -l out/aios-*.iso`, which shows a root-owned, world-readable file of roughly 1.5 GB. If it isn't there yet, go on: Tasks 7–8 do not need it, and Task 9 hands this step off.

---
### Task 7: The e2e harness: QEMU, swtpm and the serial console, with unit tests in `make check`

**Files:**
- Create: `tests/e2e/__init__.py`, `tests/e2e/requirements.txt`, `tests/e2e/vm.py`, `tests/e2e/serial.py`
- Test: `tests/e2e/test_harness_unit.py` (17 tests here, 2 more in Task 8)
- Modify: `Makefile` (pytest, venv, `e2e-unit`, `check`), `.gitignore`

How it works:
- **Package.** `tests/e2e/` is a package (`__init__.py`), so pytest imports `e2e.serial`, never a top-level `serial` that would clash with pyserial.
- **pytest source.** `PYTEST` is the system `python3 -m pytest` when that imports, otherwise `build/venv/bin/pytest`. `make tools` builds the venv from `requirements.txt`: pytest 9.2.0 and its four dependencies, as wheels with sha256 hashes (`pip --require-hashes --only-binary=:all:`). `-p no:cacheprovider` keeps `.pytest_cache/` out of the tree.
- **`vm.py`** has the pure parts, which are unit-tested, and a thin `Vm` that runs them.
  - **QEMU** (spec §9):
    - `-enable-kvm -machine q35,smm=on -cpu host -m 4G`
    - OVMF's Secure Boot code read-only, plus a per-run copy of `OVMF_VARS.4m.fd` (Setup Mode)
    - `cfi.pflash01` `secure=on`, which the SMM build needs
    - swtpm on a socket chardev with `tpm-tis`
    - the virtio qcow2 (20G, `bootindex=0`), the ISO as `ide-cd` (`bootindex=1`), so the empty disk falls through to the ISO, and the installed disk boots first afterwards
    - `-fw_cfg name=opt/aios/install.conf,file=…`
    - the serial port on a unix socket with `wait=on`, so no early output is lost
    - `-nographic -monitor none`
    - a NIC without an option ROM: OVMF refuses the unsigned iPXE ROM once keys are enrolled
  - **swtpm:** `swtpm socket --tpm2 … --terminate`, so it exits with QEMU.
  - **`render_install_conf`** writes the installer's `KEY=value` file. A unit test feeds the e2e config to the installer's own bash parser.
  - **`missing_requirements`** names every missing piece (tools, firmware, `/dev/kvm`, the ISO, socket path length). `python3 -m e2e.vm` prints the same list, and Task 8's `make e2e` uses it.
- **`serial.py`.**
  - `Serial` keeps the raw transcript and a cleaned text, without escape sequences, CR or control characters. It reassembles escape sequences and UTF-8 characters split across reads.
  - `expect` searches after the previous match, times out with the last output in the message, and raises `SerialClosed` when QEMU goes away.
  - `Shell` runs one command at a time with the sentinel protocol. The typed line only ever contains `%s`, so an echoed command never looks like a result.
- **Boot and login helpers.**
  - `choose_boot_entry` waits for a title in systemd-boot's menu, presses the entry's digit, then Enter.
  - `unlock_luks` answers `Please enter passphrase or recovery key for disk aios:`.
  - `login_root_shell` logs in on the getty. The root account is locked (spec §4.3 step 6), so it then runs `exec bash --norc --noprofile --noediting` and `run0 bash …`, answers polkit's `Password:`, and turns echo and prompts off.

- [ ] **Step 1: pytest: requirements and the venv rule**

`tests/e2e/requirements.txt`:
```text
# pytest for `make e2e-unit` and `make e2e` when the system has no python-pytest.
# `make tools` installs exactly these wheels into build/venv (pip --require-hashes).
iniconfig==2.3.1 \
    --hash=sha256:9121e2c1fdb355232495be3194c8dfe87ccc2d5dee45947b78e68f499790d7a7
packaging==26.3 \
    --hash=sha256:d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c
pluggy==1.7.0 \
    --hash=sha256:7dd7b0d8832ba3cb632c306926ded123429211b83641b35dc5c41ad2d34f9bec
pygments==2.21.0 \
    --hash=sha256:2363c69b61c4a97c838da3b130dcd6468f4848992b21a82f2a63ec34377137d9
pytest==9.2.0 \
    --hash=sha256:07acdcf88ec174f907dc01af70bf52d49b014bbab03faeeade31c96b18c2e588
```

In `Makefile`, add after `CARGO ?= cargo`:
```make
PYTHON ?= python3
```
Add after the `BATS ?=` line:
```make
# pytest: the system module when installed, otherwise a venv that `make tools` creates in
# build/venv/ from the hash-pinned tests/e2e/requirements.txt.
PYTEST ?= $(shell $(PYTHON) -c 'import pytest' 2>/dev/null && echo '$(PYTHON) -m pytest' || echo build/venv/bin/pytest)
```
Replace the `tools:` line with:
```make
tools: $(SHELLCHECK) $(BATS) $(filter build/venv/bin/pytest,$(PYTEST))
```
Add this rule after the `build/tools/bats-core/bin/bats` rule:
```make

build/venv/bin/pytest: tests/e2e/requirements.txt
	$(PYTHON) -m venv build/venv
	build/venv/bin/pip install -q --require-hashes --only-binary=:all: -r tests/e2e/requirements.txt
	touch $@
```

Append to `.gitignore`:
```text
.pytest_cache/
```

Run: `make tools`
Expected without a system pytest:
- `python3 -m venv build/venv`
- the `pip install …` line (pip may add a `[notice]` about a newer pip)
- `touch build/venv/bin/pytest`

With `python-pytest` installed, it prints nothing for pytest. Then:

Run: `bash -c 'p=$(make -s --eval "print-pytest: ; @echo \$(PYTEST)" print-pytest); echo "$p"; $p --version'`
Expected: `build/venv/bin/pytest` (or `python3 -m pytest`), then `pytest 9.2.0` (or the system version).

- [ ] **Step 2: Write the failing tests**

`tests/e2e/__init__.py`:
```python
"""AIOS end-to-end harness (spec §9): QEMU + swtpm + serial console, driven by pytest."""
```

`tests/e2e/test_harness_unit.py`:
```python
"""Unit tests of the e2e harness (spec §9): no VM, no root. A thread plays the guest's serial
console on a unix socket. Part of `make check` (make e2e-unit)."""

from __future__ import annotations

import os
import re
import socket
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable

import pytest

from .serial import (
    Serial,
    SerialClosed,
    SerialTimeout,
    Shell,
    choose_boot_entry,
    login_root_shell,
    parse_result,
    strip_ansi,
    unlock_luks,
    wrap_command,
)
from .vm import (
    E2E_INSTALL,
    FW_CFG_NAME,
    REPO,
    VmConfig,
    find_iso,
    missing_requirements,
    qemu_argv,
    render_install_conf,
    swtpm_argv,
)

SENTINEL_LINE = re.compile(
    r"printf '__AIOS_E2E_BEGIN_%s__\\n' (\d+); \{ (.*) ; \} 2>&1; "
    r"printf '__AIOS_E2E_END_%s_%s__\\n' \1 \"\$\?\"$"
)


class FakeConsole:
    """The guest side of the serial socket. Sends `banner` (a list of byte chunks, with
    `gap` seconds between them), then answers each line the harness sends (terminated by
    CR) with on_line(line), and records everything it received."""

    def __init__(
        self,
        path: Path,
        banner: list[bytes] = (),
        on_line: Callable[[str], bytes] | None = None,
        gap: float = 0.0,
        close_after_banner: bool = False,
    ):
        self.path = path
        self.banner = list(banner)
        self.on_line = on_line or (lambda line: b"")
        self.gap = gap
        self.close_after_banner = close_after_banner
        self.received = b""
        self.lines: list[str] = []
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(str(path))
        self._server.listen(1)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        conn, _ = self._server.accept()
        with conn:
            for chunk in self.banner:
                conn.sendall(chunk)
                time.sleep(self.gap)
            if self.close_after_banner:
                return
            buffer = b""
            conn.settimeout(5)
            while True:
                try:
                    data = conn.recv(4096)
                except (TimeoutError, OSError):
                    return
                if not data:
                    return
                self.received += data
                buffer += data
                while b"\r" in buffer:
                    line, buffer = buffer.split(b"\r", 1)
                    text = line.decode()
                    self.lines.append(text)
                    reply = self.on_line(text)
                    if reply:
                        conn.sendall(reply)

    def join(self) -> None:
        self._thread.join(timeout=10)
        self._server.close()


def shell_replies(results: dict[str, tuple[int, str]]) -> Callable[[str], bytes]:
    """on_line for a fake root shell: answers sentinel lines from `results` (command ->
    (status, output)); other lines get no answer."""

    def reply(line: str) -> bytes:
        match = SENTINEL_LINE.match(line)
        if not match:
            return b""
        n, cmd = match.group(1), match.group(2)
        rc, out = results.get(cmd, (127, f"bash: {cmd}: command not found\n"))
        return f"__AIOS_E2E_BEGIN_{n}__\r\n{out}__AIOS_E2E_END_{n}_{rc}__\r\n".encode()

    return reply


@pytest.fixture
def sock_path(tmp_path: Path) -> Path:
    return tmp_path / "serial.sock"


def connect(path: Path, **kw) -> Serial:
    return Serial.connect(path, timeout=5, **kw)


def option(argv: list[str], flag: str) -> list[str]:
    """Every value that follows `flag` in argv."""
    return [argv[i + 1] for i, a in enumerate(argv) if a == flag]


# --- vm.py -----------------------------------------------------------------------------


def test_qemu_argv_has_kvm_secure_boot_tpm_disk_cdrom_fw_cfg_and_serial(tmp_path: Path) -> None:
    cfg = VmConfig(workdir=tmp_path, iso=Path("/out/aios-2026.11.03-x86_64.iso"))

    argv = qemu_argv(cfg)

    assert argv[0] == "qemu-system-x86_64"
    assert "-enable-kvm" in argv and "-nographic" in argv
    assert option(argv, "-cpu") == ["host"]
    assert option(argv, "-m") == ["4G"]
    assert option(argv, "-machine") == ["q35,smm=on"]
    assert "driver=cfi.pflash01,property=secure,value=on" in option(argv, "-global")
    assert option(argv, "-drive")[:2] == [
        "if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd",
        f"if=pflash,format=raw,unit=1,file={tmp_path}/OVMF_VARS.4m.fd",
    ]
    assert f"socket,id=chrtpm,path={tmp_path}/tpm/swtpm.sock" in option(argv, "-chardev")
    assert option(argv, "-tpmdev") == ["emulator,id=tpm0,chardev=chrtpm"]
    devices = option(argv, "-device")
    assert "tpm-tis,tpmdev=tpm0" in devices
    assert "virtio-blk-pci,drive=disk0,bootindex=0" in devices
    assert "ide-cd,drive=cd0,bootindex=1" in devices
    assert f"if=none,id=disk0,format=qcow2,file={tmp_path}/disk.qcow2" in option(argv, "-drive")
    assert option(argv, "-fw_cfg") == [f"name={FW_CFG_NAME},file={tmp_path}/install.conf"]
    assert FW_CFG_NAME == "opt/aios/install.conf"
    assert f"socket,id=serial0,path={tmp_path}/serial.sock,server=on,wait=on" in option(argv, "-chardev")
    assert option(argv, "-serial") == ["chardev:serial0"]
    assert option(argv, "-monitor") == ["none"]


def test_qemu_argv_without_an_iso_has_no_cdrom_and_refuses_commas(tmp_path: Path) -> None:
    argv = qemu_argv(VmConfig(workdir=tmp_path, iso=None))
    assert not any("cd0" in a for a in argv)

    with pytest.raises(ValueError, match="may not contain ','"):
        qemu_argv(VmConfig(workdir=tmp_path / "a,b", iso=None))


def test_swtpm_is_a_tpm2_socket_that_exits_with_qemu(tmp_path: Path) -> None:
    argv = swtpm_argv(VmConfig(workdir=tmp_path, iso=None))

    assert argv[:3] == ["swtpm", "socket", "--tpm2"]
    assert option(argv, "--tpmstate") == [f"dir={tmp_path}/tpm"]
    assert option(argv, "--ctrl") == [f"type=unixio,path={tmp_path}/tpm/swtpm.sock"]
    assert "--terminate" in argv


def test_the_install_config_is_rendered_in_order_and_checked() -> None:
    text = render_install_conf(E2E_INSTALL)

    assert text.splitlines()[0] == "DISK=/dev/vda"
    assert "EXTRA_CMDLINE=console=ttyS0,115200\n" in text
    assert "WIPE=yes\n" in text
    with pytest.raises(ValueError, match="unknown install keys"):
        render_install_conf({"ROOT_PASSWORD": "x"})
    with pytest.raises(ValueError, match="line break"):
        render_install_conf({"HOSTNAME": "a\nWIPE=yes"})


def test_the_e2e_config_passes_the_installers_own_parser(tmp_path: Path) -> None:
    conf = tmp_path / "install.conf"
    conf.write_text(render_install_conf(E2E_INSTALL))
    (tmp_path / "zoneinfo").mkdir()
    (tmp_path / "zoneinfo" / "UTC").write_text("")
    lib = REPO / "installer" / "lib"
    script = 'for f in common config; do . "$1/$f.sh"; done; parse_config "$2" && validate_config 1'

    proc = subprocess.run(
        ["bash", "-c", script, "_", str(lib), str(conf)],
        env={**os.environ, "AIOS_ZONEINFO": str(tmp_path / "zoneinfo"), "AIOS_PASSWD_FILE": "/dev/null"},
        capture_output=True,
        text=True,
    )

    assert proc.returncode == 0, proc.stderr


def test_missing_requirements_name_each_missing_piece(tmp_path: Path) -> None:
    code, vars_ = tmp_path / "CODE.fd", tmp_path / "VARS.fd"
    iso = tmp_path / "aios.iso"
    kvm = tmp_path / "kvm"
    for f in (code, vars_, iso, kvm):
        f.write_text("")
    cfg = VmConfig(workdir=tmp_path, iso=iso, ovmf_code=code, ovmf_vars=vars_, kvm=kvm)

    assert missing_requirements(cfg, which=lambda tool: f"/usr/bin/{tool}") == []
    missing = missing_requirements(
        VmConfig(workdir=tmp_path, iso=None, ovmf_code=tmp_path / "none.fd", ovmf_vars=vars_, kvm=tmp_path / "nokvm"),
        which=lambda tool: None if tool == "swtpm" else f"/usr/bin/{tool}",
    )
    assert missing == [
        "swtpm is not installed (pacman -S swtpm)",
        f"{tmp_path}/none.fd is missing (pacman -S edk2-ovmf)",
        f"{tmp_path}/nokvm is not readable and writable",
        "no out/aios-*.iso: build it first (make iso)",
    ]


def test_a_workdir_too_long_for_unix_sockets_is_reported(tmp_path: Path) -> None:
    deep = tmp_path / ("d" * 100)
    cfg = VmConfig(workdir=deep, iso=None)

    assert missing_requirements(cfg, which=lambda tool: tool)[-1] == (
        f"{deep} is too long for unix socket paths: set AIOS_E2E_DIR to a shorter one"
    )


def test_find_iso_takes_the_newest(tmp_path: Path) -> None:
    assert find_iso(tmp_path) is None
    old, new = tmp_path / "aios-2026.10.01-x86_64.iso", tmp_path / "aios-2026.11.03-x86_64.iso"
    old.write_text("")
    new.write_text("")
    os.utime(old, (1, 1))
    (tmp_path / "other.iso").write_text("")

    assert find_iso(tmp_path) == new


# --- serial.py -------------------------------------------------------------------------


def test_strip_ansi_keeps_only_the_text() -> None:
    raw = "\x1b]0;title\x07\x1b[1;36mtester@aios-e2e\x1b[0m \x1b(B\x1b7~\x1b8 %\r\n\x1b[?25lok\x1bc\tx"

    assert strip_ansi(raw) == "tester@aios-e2e ~ %\nok\tx"


def test_escapes_and_utf8_split_across_reads_are_reassembled(sock_path: Path) -> None:
    console = FakeConsole(sock_path, [b"Please enter \x1b[1", b";31mpass\xf0\x9f", b"\x94\x90phrase\x1b", b"[0m for disk aios:"])
    serial = connect(sock_path)

    serial.expect(r"for disk aios:", 5)

    assert serial.text == "Please enter pass\U0001f510phrase for disk aios:"
    serial.close()
    console.join()


def test_expect_matches_across_chunks_and_moves_past_each_match(sock_path: Path) -> None:
    console = FakeConsole(sock_path, [b"aios-e2e lo", b"gin: \n", b"aios-e2e login: \n"], gap=0.05)
    serial = connect(sock_path)

    first = serial.expect(r"login: ", 5)
    second = serial.expect(r"login: ", 5)

    assert first.start() < second.start()
    with pytest.raises(SerialTimeout):
        serial.expect(r"login: ", 0.3)
    serial.close()
    console.join()


def test_a_timeout_is_prompt_and_shows_the_last_output(sock_path: Path) -> None:
    console = FakeConsole(sock_path, [b"Booting AIOS\r\nsomething else\r\n"])
    serial = connect(sock_path)

    started = time.monotonic()
    with pytest.raises(SerialTimeout) as err:
        serial.expect(r"login: ", 0.5)

    assert time.monotonic() - started < 3
    assert "something else" in str(err.value)
    serial.close()
    console.join()


def test_a_closed_console_raises_serial_closed(sock_path: Path) -> None:
    console = FakeConsole(sock_path, [b"Power down.\r\n"], close_after_banner=True)
    serial = connect(sock_path)

    with pytest.raises(SerialClosed, match="Power down"):
        serial.expect(r"login: ", 5)
    console.join()


def test_the_transcript_keeps_the_raw_bytes(sock_path: Path, tmp_path: Path) -> None:
    raw = b"\x1b[2J\x1b[HAIOS\r\n"
    console = FakeConsole(sock_path, [raw])
    serial = connect(sock_path, transcript=tmp_path / "serial.log")

    serial.expect(r"AIOS", 5)
    serial.close()
    console.join()

    assert (tmp_path / "serial.log").read_bytes() == raw


def test_wrap_and_parse_the_sentinel_protocol() -> None:
    line = wrap_command("cat /etc/hostname", 7)
    assert line == (
        "printf '__AIOS_E2E_BEGIN_%s__\\n' 7; { cat /etc/hostname ; } 2>&1; "
        "printf '__AIOS_E2E_END_%s_%s__\\n' 7 \"$?\""
    )
    echoed = line + "\n"
    assert parse_result(echoed, 7) is None
    assert parse_result(echoed + "__AIOS_E2E_BEGIN_7__\naios-e2e\n__AIOS_E2E_END_7_0__\n", 7) == (0, "aios-e2e")
    assert parse_result("__AIOS_E2E_BEGIN_8__\n__AIOS_E2E_END_8_1__\n", 8) == (1, "")
    assert parse_result("__AIOS_E2E_BEGIN_9__\nhalf", 9) is None
    with pytest.raises(ValueError):
        wrap_command("echo a\necho b", 1)


def test_shell_runs_numbered_commands_and_returns_status_and_output(sock_path: Path) -> None:
    console = FakeConsole(
        sock_path,
        on_line=shell_replies({
            "cat /etc/hostname": (0, "aios-e2e\r\n"),
            "touch /usr/x": (1, "touch: cannot touch '/usr/x': Read-only file system\r\n"),
        }),
    )
    shell = Shell(connect(sock_path))

    assert shell.check("cat /etc/hostname") == "aios-e2e"
    result = shell.run("touch /usr/x")
    assert (result.rc, result.output) == (1, "touch: cannot touch '/usr/x': Read-only file system")
    with pytest.raises(AssertionError, match="exited 127"):
        shell.check("tree")
    assert [SENTINEL_LINE.match(l).group(1) for l in console.lines] == ["1", "2", "3"]
    shell.serial.close()
    console.join()


def test_boot_menu_luks_and_login_are_answered_in_order(sock_path: Path) -> None:
    setup = "stty -echo; PS1=; PS2=; export SYSTEMD_PAGER= SYSTEMD_COLORS=0 PAGER=cat"
    # Each answer the harness types gets the next prompt as the reply.
    script = iter([
        b"\x1b[0m\xf0\x9f\x94\x90 Please enter passphrase or recovery key for disk aios: ",  # "2" + Enter
        b"\r\naios-e2e login: ",  # after the passphrase
        b"Password: ",  # after the user name
        b"\x1b[36mtester@aios-e2e\x1b[39m ~ % ",  # after the password: zsh
        b"",  # after exec bash
        b"==== AUTHENTICATING FOR org.freedesktop.systemd1.manage-units ====\r\nPassword: ",
        b"==== AUTHENTICATION COMPLETE ====\r\n",  # after the password for run0
    ])
    replies = shell_replies({setup: (0, "")})

    def on_line(line: str) -> bytes:
        return replies(line) if SENTINEL_LINE.match(line) else next(script)

    console = FakeConsole(sock_path, [b"  AIOS install medium (x86_64, UEFI, serial console)\r\n"], on_line=on_line)
    serial = connect(sock_path)

    choose_boot_entry(serial, "AIOS install medium (x86_64, UEFI, serial console)", "2", 5)
    unlock_luks(serial, "e2e-luks-passphrase", 5)
    shell = login_root_shell(serial, "tester", "e2e-user-pass", "aios-e2e", 5)

    assert console.lines[:7] == [
        "2",
        "e2e-luks-passphrase",
        "tester",
        "e2e-user-pass",
        "exec bash --norc --noprofile --noediting",
        "run0 bash --norc --noprofile --noediting",
        "e2e-user-pass",
    ]
    assert shell.count == 1
    serial.close()
    console.join()
```

- [ ] **Step 3: Run them to verify they fail**

Add the target to `Makefile`, after `unit-check`:
```make

# The e2e harness's own tests: no VM, no root (spec §9).
e2e-unit: tools
	$(PYTEST) -p no:cacheprovider -q tests/e2e/test_harness_unit.py
```

Run: `make e2e-unit`
Expected: a collection error, `ModuleNotFoundError: No module named 'e2e.serial'`, then `1 error`. make ends with `Error 2`.

- [ ] **Step 4: Write `vm.py` and `serial.py`**

`tests/e2e/vm.py`:
```python
"""QEMU + swtpm for the AIOS end-to-end test (spec §9).

The VM boots OVMF's Secure Boot firmware with a fresh copy of the variable store (Setup
Mode), a swtpm TPM 2.0, a 20 GiB virtio disk (/dev/vda in the guest) and the ISO as a
CD-ROM. The install config reaches the guest as the fw_cfg file opt/aios/install.conf, and
the serial console is a unix socket the harness connects to. Nothing here needs root.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .serial import Serial

REPO = Path(__file__).resolve().parents[2]
OVMF_DIR = Path("/usr/share/edk2/x64")
FW_CFG_NAME = "opt/aios/install.conf"
# Longest unix socket path (sockaddr_un.sun_path is 108 bytes with the NUL).
UNIX_PATH_MAX = 107
# The installer's config keys, in its order (installer/lib/config.sh).
INSTALL_KEYS = (
    "DISK",
    "HOSTNAME",
    "USERNAME",
    "USER_PASSWORD",
    "LUKS_PASSPHRASE",
    "TIMEZONE",
    "WIPE",
    "EXTRA_CMDLINE",
)
# The unattended install the e2e test runs.
E2E_INSTALL = {
    "DISK": "/dev/vda",
    "HOSTNAME": "aios-e2e",
    "USERNAME": "tester",
    "USER_PASSWORD": "e2e-user-pass",
    "LUKS_PASSPHRASE": "e2e-luks-passphrase",
    "TIMEZONE": "UTC",
    "WIPE": "yes",
    "EXTRA_CMDLINE": "console=ttyS0,115200",
}


@dataclass(frozen=True)
class VmConfig:
    """Where the VM's files live and how big it is."""

    workdir: Path
    iso: Path | None
    ovmf_code: Path = OVMF_DIR / "OVMF_CODE.secboot.4m.fd"
    ovmf_vars: Path = OVMF_DIR / "OVMF_VARS.4m.fd"
    memory: str = "4G"
    cpus: int = 4
    disk_size: str = "20G"
    qemu: str = "qemu-system-x86_64"
    swtpm: str = "swtpm"
    kvm: Path = Path("/dev/kvm")

    @property
    def disk(self) -> Path:
        return self.workdir / "disk.qcow2"

    @property
    def vars(self) -> Path:
        return self.workdir / "OVMF_VARS.4m.fd"

    @property
    def serial_socket(self) -> Path:
        return self.workdir / "serial.sock"

    @property
    def tpm_dir(self) -> Path:
        return self.workdir / "tpm"

    @property
    def tpm_socket(self) -> Path:
        return self.tpm_dir / "swtpm.sock"

    @property
    def install_conf(self) -> Path:
        return self.workdir / "install.conf"

    @property
    def transcript(self) -> Path:
        return self.workdir / "serial.log"


def _opt(path: Path) -> str:
    """A path for a QEMU -opt value: a comma would start the next option."""
    text = str(path)
    if "," in text:
        raise ValueError(f"QEMU option paths may not contain ',': {text}")
    return text


def qemu_argv(cfg: VmConfig) -> list[str]:
    """The QEMU command line (spec §9)."""
    argv = [
        cfg.qemu,
        "-name", "aios-e2e",
        "-enable-kvm",
        "-machine", "q35,smm=on",
        "-cpu", "host",
        "-smp", str(cfg.cpus),
        "-m", cfg.memory,
        # OVMF's Secure Boot build needs SMM and a secure flash for its variable store.
        "-global", "driver=cfi.pflash01,property=secure,value=on",
        "-global", "ICH9-LPC.disable_s3=1",
        "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={_opt(cfg.ovmf_code)}",
        "-drive", f"if=pflash,format=raw,unit=1,file={_opt(cfg.vars)}",
        "-chardev", f"socket,id=chrtpm,path={_opt(cfg.tpm_socket)}",
        "-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
        "-device", "tpm-tis,tpmdev=tpm0",
        "-drive", f"if=none,id=disk0,format=qcow2,file={_opt(cfg.disk)}",
        "-device", "virtio-blk-pci,drive=disk0,bootindex=0",
    ]
    if cfg.iso is not None:
        argv += [
            "-drive", f"if=none,id=cd0,media=cdrom,readonly=on,format=raw,file={_opt(cfg.iso)}",
            "-device", "ide-cd,drive=cd0,bootindex=1",
        ]
    argv += [
        # No option ROM: OVMF would refuse the unsigned iPXE ROM once keys are enrolled.
        "-netdev", "user,id=net0",
        "-device", "virtio-net-pci,netdev=net0,romfile=",
        "-device", "virtio-rng-pci",
        "-fw_cfg", f"name={FW_CFG_NAME},file={_opt(cfg.install_conf)}",
        # wait=on: QEMU starts the guest only once the harness is connected.
        "-chardev", f"socket,id=serial0,path={_opt(cfg.serial_socket)},server=on,wait=on",
        "-serial", "chardev:serial0",
        "-nographic",
        "-monitor", "none",
        "-parallel", "none",
    ]
    return argv


def swtpm_argv(cfg: VmConfig) -> list[str]:
    """swtpm as a TPM 2.0 socket device; it exits when QEMU disconnects."""
    return [
        cfg.swtpm, "socket", "--tpm2",
        "--tpmstate", f"dir={cfg.tpm_dir}",
        "--ctrl", f"type=unixio,path={cfg.tpm_socket}",
        "--terminate",
        "--log", f"file={cfg.workdir / 'swtpm.log'},level=1",
    ]


def render_install_conf(values: dict[str, str]) -> str:
    """KEY=value lines for the installer's whitelist parser."""
    unknown = set(values) - set(INSTALL_KEYS)
    if unknown:
        raise ValueError(f"unknown install keys: {sorted(unknown)}")
    lines = []
    for key in INSTALL_KEYS:
        if key not in values:
            continue
        value = values[key]
        if any(c in value for c in "\n\r\0"):
            raise ValueError(f"{key} holds a line break or NUL")
        lines.append(f"{key}={value}\n")
    return "".join(lines)


def find_iso(out_dir: Path) -> Path | None:
    """The newest out/aios-*.iso, or None."""
    isos = sorted(out_dir.glob("aios-*.iso"), key=lambda p: p.stat().st_mtime)
    return isos[-1] if isos else None


def missing_requirements(
    cfg: VmConfig, which: Callable[[str], str | None] = shutil.which
) -> list[str]:
    """Why the e2e test cannot run here (empty when it can)."""
    missing = []
    for tool, package in ((cfg.qemu, "qemu-system-x86"), ("qemu-img", "qemu-img"), (cfg.swtpm, "swtpm")):
        if which(tool) is None:
            missing.append(f"{tool} is not installed (pacman -S {package})")
    for firmware in (cfg.ovmf_code, cfg.ovmf_vars):
        if not firmware.is_file():
            missing.append(f"{firmware} is missing (pacman -S edk2-ovmf)")
    if not os.access(cfg.kvm, os.R_OK | os.W_OK):
        missing.append(f"{cfg.kvm} is not readable and writable")
    if cfg.iso is None or not cfg.iso.is_file():
        missing.append("no out/aios-*.iso: build it first (make iso)")
    if max(len(os.fsencode(p)) for p in (cfg.serial_socket, cfg.tpm_socket)) > UNIX_PATH_MAX:
        missing.append(f"{cfg.workdir} is too long for unix socket paths: set AIOS_E2E_DIR to a shorter one")
    return missing


def default_config() -> VmConfig:
    """The e2e VM: build/e2e/ (or $AIOS_E2E_DIR) and the newest out/aios-*.iso (or
    $AIOS_E2E_ISO)."""
    workdir = Path(os.environ.get("AIOS_E2E_DIR", REPO / "build" / "e2e"))
    iso_env = os.environ.get("AIOS_E2E_ISO")
    iso = Path(iso_env) if iso_env else find_iso(REPO / "out")
    return VmConfig(workdir=workdir, iso=iso)


def _wait_for(path: Path, timeout: float, what: str) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists():
        if time.monotonic() > deadline:
            raise TimeoutError(f"{what} did not create {path} within {timeout:.0f}s")
        time.sleep(0.1)


class Vm:
    """A fresh VM: prepare() creates the disk, the variable store and the config, start()
    runs swtpm and QEMU and connects to the serial console."""

    def __init__(self, cfg: VmConfig):
        self.cfg = cfg
        self.qemu: subprocess.Popen | None = None
        self.swtpm: subprocess.Popen | None = None
        self.serial: Serial | None = None

    def prepare(self, install: dict[str, str]) -> None:
        cfg = self.cfg
        cfg.workdir.mkdir(parents=True, exist_ok=True)
        for old in (cfg.disk, cfg.vars, cfg.serial_socket, cfg.install_conf, cfg.transcript):
            old.unlink(missing_ok=True)
        shutil.rmtree(cfg.tpm_dir, ignore_errors=True)
        cfg.tpm_dir.mkdir()
        subprocess.run(
            ["qemu-img", "create", "-q", "-f", "qcow2", str(cfg.disk), cfg.disk_size], check=True
        )
        shutil.copyfile(cfg.ovmf_vars, cfg.vars)
        cfg.install_conf.write_text(render_install_conf(install))

    def start(self) -> Serial:
        cfg = self.cfg
        with open(cfg.workdir / "swtpm.out", "ab") as out:
            self.swtpm = subprocess.Popen(swtpm_argv(cfg), stdin=subprocess.DEVNULL, stdout=out, stderr=out)
        _wait_for(cfg.tpm_socket, 10, "swtpm")
        with open(cfg.workdir / "qemu.out", "ab") as out:
            self.qemu = subprocess.Popen(qemu_argv(cfg), stdin=subprocess.DEVNULL, stdout=out, stderr=out)
        self.serial = Serial.connect(cfg.serial_socket, transcript=cfg.transcript, timeout=30)
        return self.serial

    def stop(self) -> None:
        if self.serial is not None:
            self.serial.close()
        for proc in (self.qemu, self.swtpm):
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()

    def __enter__(self) -> Vm:
        return self

    def __exit__(self, *exc) -> None:
        self.stop()


if __name__ == "__main__":
    # `make e2e` runs this first, so a missing tool fails loudly instead of skipping.
    problems = missing_requirements(default_config())
    for problem in problems:
        print(f"make e2e: {problem}", file=sys.stderr)
    sys.exit(1 if problems else 0)
```

`tests/e2e/serial.py`:
```python
"""Expect-style driving of the VM's serial console over QEMU's unix socket (spec §9).

`Serial` keeps two views of what the guest printed: the raw bytes in a transcript file,
and `text`, decoded and stripped of terminal escape sequences and carriage returns, which
`expect` searches. `Shell` runs one command at a time with a sentinel protocol:

    printf '__AIOS_E2E_BEGIN_%s__\\n' 7; { CMD ; } 2>&1; printf '__AIOS_E2E_END_%s_%s__\\n' 7 "$?"

The typed line itself only ever holds `%s`, so an echoed command can never look like a
result. The login helpers get from a LUKS prompt to a root bash with echo off.
"""

from __future__ import annotations

import codecs
import re
import select
import socket
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

# OSC (title etc.), CSI (colors, cursor), charset designation, then any other 2-byte escape.
_ESCAPE = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]|\x1b[()*+][0-9A-Za-z]|\x1b[0-~]")
# An escape sequence cut off at the end of a chunk.
_PARTIAL = re.compile(r"\x1b(?:\][^\x07\x1b]*|\[[0-?]*[ -/]*|[()*+])?$")
# Control characters except tab and newline (this drops CR and stray ESC).
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def strip_ansi(text: str) -> str:
    """Text without escape sequences, carriage returns or other control characters."""
    return _CONTROL.sub("", _ESCAPE.sub("", text))


class SerialTimeout(AssertionError):
    """The expected text did not appear in time."""


class SerialClosed(AssertionError):
    """QEMU closed the serial socket (the VM is gone)."""


class Serial:
    """One connection to the guest's serial console."""

    def __init__(
        self,
        sock: socket.socket,
        transcript: Path | None = None,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._sock = sock
        self._sock.setblocking(False)
        self._decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self._partial = ""
        self._clock = clock
        self._log = open(transcript, "ab") if transcript else None
        self.text = ""
        self.pos = 0

    @classmethod
    def connect(cls, path: Path, transcript: Path | None = None, timeout: float = 30.0) -> Serial:
        """Connect to QEMU's serial socket, retrying until it exists."""
        deadline = time.monotonic() + timeout
        while True:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                sock.connect(str(path))
                return cls(sock, transcript)
            except (FileNotFoundError, ConnectionRefusedError):
                sock.close()
                if time.monotonic() > deadline:
                    raise SerialTimeout(f"no serial console at {path} after {timeout:.0f}s") from None
                time.sleep(0.1)

    def _feed(self, data: bytes) -> None:
        if self._log:
            self._log.write(data)
            self._log.flush()
        chunk = self._partial + self._decoder.decode(data)
        partial = _PARTIAL.search(chunk)
        cut = partial.start() if partial else len(chunk)
        self._partial = chunk[cut:]
        self.text += strip_ansi(chunk[:cut])

    def _read(self, timeout: float) -> None:
        ready, _, _ = select.select([self._sock], [], [], max(0.0, timeout))
        if not ready:
            return
        data = self._sock.recv(65536)
        if not data:
            raise SerialClosed(f"the serial console closed; last output:\n{self.tail()}")
        self._feed(data)

    def expect(self, pattern: str | re.Pattern[str], timeout: float) -> re.Match[str]:
        """Wait for `pattern` in the text after the previous match, and move past it."""
        rx = re.compile(pattern) if isinstance(pattern, str) else pattern
        deadline = self._clock() + timeout
        while True:
            match = rx.search(self.text, self.pos)
            if match:
                self.pos = match.end()
                return match
            left = deadline - self._clock()
            if left <= 0:
                raise SerialTimeout(
                    f"no {rx.pattern!r} within {timeout:.0f}s; last output:\n{self.tail()}"
                )
            self._read(min(left, 0.5))

    def tail(self, chars: int = 3000) -> str:
        return self.text[-chars:]

    def send(self, text: str) -> None:
        self._sock.sendall(text.encode())

    def sendline(self, text: str) -> None:
        self.send(text + "\r")

    def close(self) -> None:
        self._sock.close()
        if self._log:
            self._log.close()
            self._log = None


def wrap_command(cmd: str, n: int) -> str:
    """The line that runs `cmd` as command number `n` of the sentinel protocol."""
    if any(c in cmd for c in "\n\r"):
        raise ValueError("a command must be one line")
    return (
        f"printf '__AIOS_E2E_BEGIN_%s__\\n' {n}; {{ {cmd} ; }} 2>&1; "
        f"printf '__AIOS_E2E_END_%s_%s__\\n' {n} \"$?\""
    )


def result_pattern(n: int) -> re.Pattern[str]:
    return re.compile(rf"__AIOS_E2E_BEGIN_{n}__\n(.*?)__AIOS_E2E_END_{n}_(\d+)__", re.S)


def parse_result(text: str, n: int) -> tuple[int, str] | None:
    """(exit status, output) of command `n` in `text`, or None if it has not finished."""
    match = result_pattern(n).search(text)
    if not match:
        return None
    return int(match.group(2)), match.group(1).rstrip("\n")


@dataclass(frozen=True)
class Result:
    rc: int
    output: str


class Shell:
    """A shell on the serial console that runs commands with the sentinel protocol."""

    def __init__(self, serial: Serial):
        self.serial = serial
        self.count = 0

    def run(self, cmd: str, timeout: float = 120) -> Result:
        self.count += 1
        self.serial.sendline(wrap_command(cmd, self.count))
        match = self.serial.expect(result_pattern(self.count), timeout)
        return Result(int(match.group(2)), match.group(1).rstrip("\n"))

    def check(self, cmd: str, timeout: float = 120) -> str:
        """Run `cmd`; it must exit 0. Returns its output."""
        result = self.run(cmd, timeout)
        if result.rc != 0:
            raise AssertionError(f"`{cmd}` exited {result.rc}:\n{result.output}")
        return result.output

    def send_only(self, cmd: str) -> None:
        """Type `cmd` without waiting for a result (reboot)."""
        self.serial.sendline(cmd)


def choose_boot_entry(serial: Serial, title: str, key: str, timeout: float) -> None:
    """In the systemd-boot menu, wait for the entry `title`, then select entry `key` and boot."""
    serial.expect(re.escape(title), timeout)
    time.sleep(0.5)
    serial.send(key)
    time.sleep(0.5)
    serial.send("\r")


def unlock_luks(serial: Serial, passphrase: str, timeout: float) -> None:
    """Answer systemd-cryptsetup's prompt in the initrd. With the recovery key enrolled it
    reads "Please enter passphrase or recovery key for disk aios:"."""
    serial.expect(r"Please enter [a-z ]+ for disk ", timeout)
    time.sleep(0.5)
    serial.sendline(passphrase)


def login_root_shell(serial: Serial, user: str, password: str, hostname: str, timeout: float) -> Shell:
    """Log in as `user` on the getty, then `run0` a root bash with echo and prompts off.
    The root account itself is locked (spec §4.3 step 6), so root goes through polkit."""
    serial.expect(rf"{re.escape(hostname)} login: ", timeout)
    serial.sendline(user)
    serial.expect(r"Password: ", 60)
    serial.sendline(password)
    serial.expect(rf"{re.escape(user)}@{re.escape(hostname)}", 60)
    serial.sendline("exec bash --norc --noprofile --noediting")
    serial.sendline("run0 bash --norc --noprofile --noediting")
    serial.expect(r"Password: ", 60)
    serial.sendline(password)
    serial.expect(r"AUTHENTICATION COMPLETE", 60)
    shell = Shell(serial)
    shell.check("stty -echo; PS1=; PS2=; export SYSTEMD_PAGER= SYSTEMD_COLORS=0 PAGER=cat", 60)
    return shell
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `make e2e-unit`
Expected: `17 passed`, in about 3 s.

Run: `(cd tests && python3 -m e2e.vm); echo "rc=$?"`
Expected on this host before the ISO exists:
```
make e2e: swtpm is not installed (pacman -S swtpm)
make e2e: no out/aios-*.iso: build it first (make iso)
rc=1
```
The swtpm line is gone once swtpm is installed.

- [ ] **Step 6: Put the harness tests in `make check`**

Change the `check:` line and the `.PHONY` line to:
```make
.PHONY: check rust-check shell-check bats-check unit-check e2e-unit tools repo keys iso-build \
	iso iso-check clean-iso

check: rust-check shell-check bats-check unit-check e2e-unit
```

Run: `make check`
Expected: passes, ending with `17 passed`.

- [ ] **Step 7: Commit**

```bash
git add Makefile .gitignore tests/e2e/__init__.py tests/e2e/requirements.txt tests/e2e/vm.py \
  tests/e2e/serial.py tests/e2e/test_harness_unit.py
git status --short tests/
```
Expected: five `A` lines, one per file under `tests/e2e/`, and no `__pycache__` (it is ignored).

```bash
git commit -m "test(e2e): QEMU, swtpm and serial-console harness, unit-tested in make check"
```

---

### Task 8: The end-to-end flow: unattended install and spec §1 (a)–(g), `make e2e`

**Files:**
- Create: `tests/e2e/conftest.py`, `tests/e2e/test_e2e.py`
- Modify: `tests/e2e/test_harness_unit.py` (2 tests appended), `Makefile` (`e2e`)

The flow:
- **One VM.** All steps share one module-scoped VM, and the `incremental` marker xfails the rest once a step fails. Each boot goes LUKS → login → root bash. Reboots are `systemctl reboot` from that shell; QEMU reboots in place, and the serial socket stays connected.

| Test | Boot | Checks |
|---|---|---|
| `test_01` | ISO, serial entry (key `2`) | the installer runs from fw_cfg: `step 1/13`, `gen-0001 built in /mnt/aios-top`, `installation complete`, `rebooting into AIOS` |
| `test_02` | gen-1 | (c) `aios plan` exits 0 with `no changes`; also gen 1, `aios-health` active, `bootctl status` shows `Secure Boot: enabled (user)` |
| `test_03` | gen-1, then reboot to gen-1 | (a) `/etc`, `/var/tmp`, `/root` files gone, `touch /usr/…` fails with `Read-only file system`; (b) `/persist` and `/home/tester` files survive; (g) set-up: the user moves `~/.ssh` away and plants `~/.ssh/authorized_keys → /etc/nftables.conf` (spec §4.4) |
| `test_04` | same boot | (g) `findmnt /etc/nftables.conf` finds nothing, nothing is mounted at the symlink path, `nftables` is active with `policy drop`, and `/etc/nftables.conf` matches the manifest's file |
| `test_05` | gen-2 | (d) `tree` added with `sed`, `aios apply --yes` prints `reboot to activate gen-0002`, gen 2 has `tree` |
| `test_06` | gen-1 | (e) `aios rollback 1`, gen 1 has no `tree` |
| `test_07` | gen-3 ×3, then gen-2 | (f) `aios.test.fail_health=1` added to `extra_cmdline`, apply prints `gen-0003`; three boots of gen 3 with `aios-health` failed; the fourth boot is gen 2 |

Notes:
- **(f) lands on gen-2.** That is the newest blessed generation. systemd-boot sorts a gen-3 with no tries left after everything else, and the `default aios-gen-*-cachyos*` glob then picks gen-2. `apply` cleared test_06's `bootctl set-default` override (spec §3 step 2).
- **The two `sed` edits** are written against the installed manifest's exact text: Phase 4's template, filled in by the installer. The appended unit test runs them on such a copy and checks that each matches exactly once.
- **Timeouts:** install 90 min, apply 60 min, boot 10 min. Everything the VM printed goes to `build/e2e/serial.log`. QEMU's and swtpm's own output goes to `qemu.out` and `swtpm.out`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/e2e/test_harness_unit.py`, after two blank lines:
```python
# --- test_e2e.py: the boot menu position and the manifest edits it relies on -------------

from .test_e2e import ADD_FAIL_HEALTH, ADD_TREE, ISO_SERIAL_KEY, ISO_SERIAL_TITLE, MANIFEST  # noqa: E402


def test_the_serial_entry_is_the_second_in_the_iso_boot_menu() -> None:
    entries = REPO / "iso" / "efiboot" / "loader" / "entries"
    keys = {}
    for entry in entries.glob("*.conf"):
        text = entry.read_text()
        keys[re.search(r"^sort-key\s+(\S+)", text, re.M).group(1)] = re.search(
            r"^title\s+(.*)$", text, re.M
        ).group(1)
    titles = [keys[k] for k in sorted(keys)]

    assert titles[int(ISO_SERIAL_KEY) - 1].replace("%ARCH%", "x86_64") == ISO_SERIAL_TITLE


def test_the_manifest_edits_apply_once_to_the_installed_manifest(tmp_path: Path) -> None:
    template = (REPO / "manifest" / "manifest.toml").read_text()
    manifest = tmp_path / "manifest.toml"
    manifest.write_text(
        template.replace("@HOSTNAME@", "aios-e2e")
        .replace("@USERNAME@", "tester")
        .replace("@TIMEZONE@", "UTC")
        .replace("@EXTRA_CMDLINE@", '"console=ttyS0,115200"')
    )

    for edit, expected in (
        (ADD_TREE, '"tree",'),
        (ADD_FAIL_HEALTH, '"aios.test.fail_health=1"]'),
    ):
        cmd = edit.replace(MANIFEST, str(manifest))
        subprocess.run(["sh", "-c", cmd], check=True)
        assert manifest.read_text().count(expected) == 1, cmd
```

Run: `make e2e-unit`
Expected: a collection error, `ModuleNotFoundError: No module named 'e2e.test_e2e'`, then `1 error`, and `Error 2`.

- [ ] **Step 2: Write `conftest.py` and `test_e2e.py`**

`tests/e2e/conftest.py`:
```python
"""pytest setup for tests/e2e: ordered e2e steps and the --keep-vm option."""

from __future__ import annotations

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--keep-vm",
        action="store_true",
        help="leave build/e2e (disk, firmware variables, transcript) for inspection",
    )


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers", "incremental: later tests in the module xfail once one test fails"
    )


def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo) -> None:
    if "incremental" in item.keywords and call.excinfo is not None and call.when == "call":
        item.parent._aios_failed = item.name  # type: ignore[attr-defined]


def pytest_runtest_setup(item: pytest.Item) -> None:
    if "incremental" in item.keywords:
        failed = getattr(item.parent, "_aios_failed", None)
        if failed is not None:
            pytest.xfail(f"an earlier step failed: {failed}")
```

`tests/e2e/test_e2e.py`:
```python
"""The AIOS end-to-end test (spec §1 assertions (a)-(g), §9): install the ISO unattended into a
QEMU VM with OVMF Secure Boot firmware and swtpm, then drive gen-1, gen-2, a rollback and a
failing gen-3 over the serial console. Skipped unless out/aios-*.iso and the VM tools exist.
Run it with `make e2e` (about an hour; it downloads the packages). The transcript of
everything the VM printed is build/e2e/serial.log.

The steps share one VM and run in order; after a failure the rest xfail.
"""

from __future__ import annotations

import shutil

import pytest

from .serial import Serial, Shell, choose_boot_entry, login_root_shell, unlock_luks
from .vm import E2E_INSTALL, Vm, default_config, missing_requirements

USER = E2E_INSTALL["USERNAME"]
HOST = E2E_INSTALL["HOSTNAME"]
PASSWORD = E2E_INSTALL["USER_PASSWORD"]
LUKS = E2E_INSTALL["LUKS_PASSPHRASE"]

# The ISO's serial-console boot entry: its title, and its position in the systemd-boot menu
# (a unit test checks both against iso/efiboot/loader/entries).
ISO_SERIAL_TITLE = "AIOS install medium (x86_64, UEFI, serial console)"
ISO_SERIAL_KEY = "2"

MANIFEST = "/persist/aios/config/manifest.toml"
# (d): add tree to the package list. (f): the test-only cmdline flag that fails aios-health.
ADD_TREE = f"sed -i 's/^  \"pacman-contrib\",$/  \"pacman-contrib\", \"tree\",/' {MANIFEST}"
ADD_FAIL_HEALTH = (
    f"sed -i 's/^extra_cmdline = \\[\"console=ttyS0,115200\"\\]/"
    f"extra_cmdline = [\"console=ttyS0,115200\", \"aios.test.fail_health=1\"]/' {MANIFEST}"
)

INSTALL_TIMEOUT = 90 * 60
BOOT_TIMEOUT = 10 * 60
APPLY_TIMEOUT = 60 * 60

CONFIG = default_config()

pytestmark = [
    pytest.mark.incremental,
    pytest.mark.skipif(
        bool(missing_requirements(CONFIG)),
        reason="; ".join(missing_requirements(CONFIG)) or "ready",
    ),
]


class Machine:
    """The VM plus the root shell of the current boot."""

    def __init__(self, vm: Vm, serial: Serial):
        self.vm = vm
        self.serial = serial
        self.shell: Shell | None = None

    def boot(self) -> Shell:
        """From power-on or reboot: unlock LUKS, log in, return the root shell."""
        unlock_luks(self.serial, LUKS, BOOT_TIMEOUT)
        self.shell = login_root_shell(self.serial, USER, PASSWORD, HOST, BOOT_TIMEOUT)
        return self.shell

    def reboot(self) -> Shell:
        assert self.shell is not None
        self.shell.send_only("systemctl reboot")
        return self.boot()

    def gen(self) -> int:
        """The booted generation, from aios.gen= on the kernel cmdline."""
        assert self.shell is not None
        out = self.shell.check("tr ' ' '\\n' </proc/cmdline | sed -n 's/^aios\\.gen=//p'")
        return int(out)

    def as_user(self, cmd: str) -> str:
        """Run `cmd` as the test user. runuser keeps root's $HOME, so use absolute paths."""
        assert self.shell is not None
        return self.shell.check(f"runuser -u {USER} -- sh -c '{cmd}'")


@pytest.fixture(scope="module")
def machine(request: pytest.FixtureRequest):
    vm = Vm(CONFIG)
    vm.prepare(E2E_INSTALL)
    serial = vm.start()
    yield Machine(vm, serial)
    vm.stop()
    if not request.config.getoption("--keep-vm"):
        CONFIG.disk.unlink(missing_ok=True)
        shutil.rmtree(CONFIG.tpm_dir, ignore_errors=True)


def test_01_unattended_install_from_the_iso(machine: Machine) -> None:
    """The serial boot entry, then aios-install from the fw_cfg config, then the reboot."""
    choose_boot_entry(machine.serial, ISO_SERIAL_TITLE, ISO_SERIAL_KEY, BOOT_TIMEOUT)
    machine.serial.expect(r"aios-install: step 1/13: preflight", BOOT_TIMEOUT)
    machine.serial.expect(r"gen-0001 built in /mnt/aios-top", INSTALL_TIMEOUT)
    machine.serial.expect(r"aios-install: installation complete", 10 * 60)
    machine.serial.expect(r"aios-install: rebooting into AIOS", 60)


def test_02_gen1_boots_with_secure_boot_and_plan_is_clean(machine: Machine) -> None:
    """(c) aios plan reports no changes on a fresh install. Also: gen-1 is booted, healthy,
    and Secure Boot is on with the installer's keys."""
    shell = machine.boot()

    assert machine.gen() == 1
    assert shell.check("systemctl is-active aios-health.service") == "active"
    assert "enabled (user)" in shell.check("bootctl status 2>/dev/null | grep -i 'secure boot'")
    plan = shell.run("aios plan", 300)
    assert plan.rc == 0, plan.output
    assert "no changes" in plan.output


def test_03_runtime_state_is_ephemeral_and_declared_state_persists(machine: Machine) -> None:
    """(a) runtime writes to /etc, /var/tmp and /root vanish at reboot, /usr is read-only;
    (b) /persist and /home survive; (g, part 1) plant a symlink where ~/.ssh/authorized_keys
    is bind-mounted, by moving the protected ~/.ssh away (spec §4.4)."""
    shell = machine.shell
    assert shell is not None
    shell.check("echo e2e | tee /etc/aios-e2e /var/tmp/aios-e2e /root/aios-e2e /persist/aios-e2e")
    machine.as_user(f"echo e2e > /home/{USER}/aios-e2e")
    erofs = shell.run("touch /usr/aios-e2e")
    assert erofs.rc != 0
    assert "Read-only file system" in erofs.output
    machine.as_user(
        f"cd /home/{USER} && mv .ssh .ssh-moved && mkdir -m 0700 .ssh"
        " && ln -s /etc/nftables.conf .ssh/authorized_keys"
    )

    shell = machine.reboot()

    assert machine.gen() == 1
    for gone in ("/etc/aios-e2e", "/var/tmp/aios-e2e", "/root/aios-e2e"):
        assert shell.run(f"test -e {gone}").rc == 1, f"{gone} survived the reboot"
    assert shell.check("cat /persist/aios-e2e") == "e2e"
    assert shell.check(f"cat /home/{USER}/aios-e2e") == "e2e"


def test_04_a_planted_symlink_does_not_redirect_the_home_bind(machine: Machine) -> None:
    """(g) findmnt shows no mount on /etc/nftables.conf, nftables loaded the real ruleset,
    and nothing is mounted at the symlink path."""
    shell = machine.shell
    assert shell is not None

    assert shell.run("findmnt -n /etc/nftables.conf").rc == 1
    assert shell.run(f"findmnt -rno TARGET | grep -Fx /home/{USER}/.ssh/authorized_keys").rc == 1
    assert shell.check("systemctl is-active nftables.service") == "active"
    assert "policy drop" in shell.check("nft list chain inet filter input")
    # The managed file is intact (sha256sum: base has no cmp).
    assert shell.check("sha256sum </etc/nftables.conf") == shell.check(
        "sha256sum </persist/aios/config/files/nftables.conf"
    )


def test_05_apply_builds_gen2_with_a_new_package(machine: Machine) -> None:
    """(d) after adding tree to the manifest, aios apply --yes + reboot boots gen-2 with tree."""
    shell = machine.shell
    assert shell is not None
    shell.check(ADD_TREE)
    assert "reboot to activate gen-0002" in shell.check("aios apply --yes", APPLY_TIMEOUT)

    shell = machine.reboot()

    assert machine.gen() == 2
    shell.check("command -v tree")


def test_06_rollback_boots_gen1_without_the_package(machine: Machine) -> None:
    """(e) aios rollback 1 + reboot boots gen-1, where tree does not exist."""
    shell = machine.shell
    assert shell is not None
    shell.check("aios rollback 1")

    shell = machine.reboot()

    assert machine.gen() == 1
    assert shell.run("command -v tree").rc == 1


def test_07_a_failing_generation_falls_back_after_three_boots(machine: Machine) -> None:
    """(f) gen-3 with aios.test.fail_health=1 fails its health check on each of 3 boots; the
    next boot is the previous good generation (gen-2, the newest blessed one)."""
    shell = machine.shell
    assert shell is not None
    shell.check(ADD_FAIL_HEALTH)
    assert "reboot to activate gen-0003" in shell.check("aios apply --yes", APPLY_TIMEOUT)

    for attempt in range(1, 4):
        shell = machine.reboot()
        assert machine.gen() == 3, f"boot {attempt} after the apply"
        assert shell.run("systemctl is-failed aios-health.service").output == "failed"

    shell = machine.reboot()

    assert machine.gen() == 2
    assert shell.check("systemctl is-active aios-health.service") == "active"
```

- [ ] **Step 3: Run the unit tests to verify they pass**

Run: `make e2e-unit`
Expected: `19 passed`.

- [ ] **Step 4: The e2e module skips cleanly without an ISO or swtpm**

Run: `bash -c '$(make -s --eval "print-pytest: ; @echo \$(PYTEST)" print-pytest) -p no:cacheprovider -rs tests/e2e/test_e2e.py | tail -2'`
Expected (this host before the ISO and swtpm exist):
```
SKIPPED [1] tests/e2e/test_e2e.py:…: swtpm is not installed (pacman -S swtpm); no out/aios-*.iso: build it first (make iso)
============================== 7 skipped in 0.0…s ==============================
```

- [ ] **Step 5: `make e2e`**

Append to `Makefile`:
```make

# Install the newest out/aios-*.iso into a VM and run spec §1 (a)-(g). No root, about an
# hour. E2E_ARGS=--keep-vm keeps the VM disk in build/e2e/ afterwards.
E2E_ARGS ?=
e2e: tools
	cd tests && $(PYTHON) -m e2e.vm
	$(PYTEST) -p no:cacheprovider -v -rs tests/e2e/test_e2e.py $(E2E_ARGS)
```

Change the `.PHONY` line to:
```make
.PHONY: check rust-check shell-check bats-check unit-check e2e-unit tools repo keys iso-build \
	iso iso-check clean-iso e2e
```

Run: `make e2e; echo "rc=$?"`
Expected while the ISO or swtpm is missing: the two `make e2e: …` lines from Task 7 Step 5, `make: *** [Makefile:…: e2e] Error 1`, `rc=2`. It never reports a pass with every test skipped.

- [ ] **Step 6: The full gate and commit**

Run: `make check`
Expected: passes, ending with `19 passed`.

```bash
git add Makefile tests/e2e/conftest.py tests/e2e/test_e2e.py tests/e2e/test_harness_unit.py
git commit -m "test(e2e): unattended install and spec §1 (a)-(g) over the serial console, make e2e"
```

- [ ] **Step 7: Run the e2e test, if the ISO and swtpm exist (no root)**

Run: `ls out/aios-*.iso && command -v swtpm`. If both print a path, start `make e2e` in the background: it takes about an hour and downloads about 2 GB.

Expected: `7 passed`. While it runs, `tail -f build/e2e/serial.log` shows the guest.

If either is missing, skip this step. Task 9 hands it to the user.

---

### Task 9: README, spec corrections, final gate and handoff

**Files:**
- Modify: `README.md` (full content below), `docs/superpowers/specs/2026-11-03-base-iso-design.md` (seven corrections)

- [ ] **Step 1: The README**

`README.md`:
````markdown
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

The ISO is built on a CachyOS host (or any Arch host whose pacman keyring trusts the
CachyOS key). Only `make iso` needs root, and it asks `sudo` for the two commands that do.

1. Install the build and test tools once:
   ```bash
   sudo pacman -S --needed archiso arch-install-scripts sbctl swtpm systemd-ukify python-pytest
   ```
   QEMU and OVMF (`qemu-system-x86_64`, `/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd`) and
   read-write access to `/dev/kvm` are needed for step 4. `python-pytest` is optional:
   `make tools` installs a pinned pytest into `build/venv/` instead.
2. Build the local package repo: `make repo` (no root).
3. Build the ISO: `make iso`. Run it as yourself, not as `sudo make iso`. It writes
   `iso-build/` without root: the profile from `iso/`, `pacman.conf` pointing at
   `build/repo`, the installer, a copy of the repo for `/opt/aios-repo`, and the CachyOS key
   fingerprint pinned from your keyring (`make keys`). Then it runs
   `sudo mkarchiso -v -w build/iso-work -o out iso-build/`. The result is
   `out/aios-YYYY.MM.DD-x86_64.iso`. With archiso 89 or later and an `/etc/subuid` entry for
   your user, `make iso SUDO=` builds without root.
4. Test it end to end: `make e2e` (no root, about an hour, downloads about 2 GB). It boots the
   ISO in QEMU with KVM, OVMF Secure Boot firmware in Setup Mode and a swtpm TPM, installs
   unattended from a fw_cfg config, and checks spec §1 (a)–(g) over the serial console.
   Everything the VM printed is in `build/e2e/serial.log`. `make e2e E2E_ARGS=--keep-vm`
   keeps the VM disk.
5. Install on a machine: write the ISO to a USB stick, boot it (Secure Boot in Setup Mode,
   or off), and run `aios-install`. It asks for the disk, hostname, user, passwords and time
   zone, and prints the LUKS recovery key once. After the first boot run
   `run0 aios secureboot enroll` if the installer could not enroll the keys, then
   `run0 aios tpm enroll`.
6. Clean up: `make clean-iso` removes `iso-build/` and the root-owned `build/iso-work/`
   (through `sudo`).

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
````

- [ ] **Step 2: Write the spec corrections into the spec**

In `docs/superpowers/specs/2026-11-03-base-iso-design.md`, make these replacements (use the Edit tool; each old text is one line):

1. §6.1 `profiledef.sh`: replace `` `bootmodes=('uefi.systemd-boot.esp' 'uefi.systemd-boot.eltorito')`. UEFI only. `` with `` `bootmodes=('uefi.systemd-boot')` (archiso 86 merged the ESP and El Torito modes into one). UEFI only. ``
2. §6.1 `pacman.conf`: replace `` `make iso` generates it from a template with the absolute path. `` with `` `make iso-build` generates it from `iso/pacman.conf.in` with the absolute path. `[cachyos]` only provides the keyring and the mirrorlists. ``
3. §6.1 packages: replace `` `arch-install-scripts sbctl btrfs-progs cryptsetup gptfdisk tpm2-tools git usbguard whois aios-cli aios-base`. `` with `` `arch-install-scripts sbctl btrfs-progs cryptsetup gptfdisk tpm2-tools git usbguard whois aios-cli aios-base cachyos-keyring cachyos-mirrorlist cachyos-v3-mirrorlist`. Bootstrap needs the CachyOS keyring and mirrorlists on the live system. ``
4. §6.1 serial entry: replace `` - `efiboot/loader/entries/03-aios-serial.conf`: same as the default entry plus `console=ttyS0,115200`. `` with `` - `efiboot/loader/entries/`: `01-aios-linux.conf` (default), `03-aios-serial.conf` (the same plus `console=ttyS0,115200`; the second menu entry) and `04-aios-memtest86+x64.conf`. releng's speech entry is dropped. `airootfs/etc/systemd/system/aios-install-auto.service` runs `aios-install --auto`. ``
5. §6.1 `make iso`: replace `` - `make iso` runs `sudo mkarchiso -v -w work/ -o out/ iso/`. The developer runs it. `` with `` - `make iso` writes `iso-build/` without root (the profile, `pacman.conf`, the installer, `/opt/aios-repo`, `keys.sh`), then runs `sudo mkarchiso -v -w build/iso-work -o out iso-build/`. The developer runs it. ``
6. §6.2 step 9: replace `` - Before pacstrap, it imports and locally signs the CachyOS key into the candidate keyring. The fingerprint is pinned in `installer/lib/keys.sh`, taken from the build host at ISO build time by `make iso`. `` with `` - It takes `--luks-uuid` (from `cryptsetup luksUUID`). Its pacstrap verifies with, and copies, the live keyring. So step 1 checks that this keyring trusts exactly the CachyOS keys pinned in `installer/lib/keys.sh`, which `make keys` (part of `make iso`) generates from the build host's keyring. ``
7. §6.2 step 11: replace `` 11. If `sbctl status` reports Setup Mode, run `sbctl enroll-keys --microsoft`. `` with `` 11. If `sbctl status` reports Setup Mode, run `sbctl enroll-keys --microsoft`. If that fails, the install still completes, and the summary points to `aios secureboot enroll`. ``

If an old text is not found, the spec changed since this plan was written. Make the same correction in the current wording and say so in the commit message.

- [ ] **Step 3: Compare the Makefile with the final version**

After Tasks 1–8 the Makefile must read exactly:
```make
export PATH := $(HOME)/.cargo/bin:$(PATH)
CARGO ?= cargo
PYTHON ?= python3
SUDO ?= sudo

# Shell test tools: the system copies when installed, otherwise pinned copies that
# `make tools` fetches into build/tools/ (no root needed).
SHELLCHECK_VERSION := v0.10.0
SHELLCHECK_SHA256 := 6c881ab0698e4e6ea235245f22832860544f17ba386442fe7e9d629f8cbedf87
BATS_VERSION := v1.11.1
BATS_COMMIT := b640ec3cf2c7c9cfc9e6351479261186f76eeec8
SHELLCHECK ?= $(shell command -v shellcheck || echo build/tools/shellcheck)
BATS ?= $(shell command -v bats || echo build/tools/bats-core/bin/bats)
# pytest: the system module when installed, otherwise a venv that `make tools` creates in
# build/venv/ from the hash-pinned tests/e2e/requirements.txt.
PYTEST ?= $(shell $(PYTHON) -c 'import pytest' 2>/dev/null && echo '$(PYTHON) -m pytest' || echo build/venv/bin/pytest)

# What the shell and unit checks cover. installer/lib/keys.sh is generated (make keys).
INSTALLER_LIBS := installer/lib/common.sh installer/lib/config.sh installer/lib/disk.sh \
	installer/lib/cpu.sh installer/lib/manifest.sh installer/lib/skeleton.sh \
	installer/lib/secrets.sh installer/lib/usbguard.sh installer/lib/boot.sh \
	installer/lib/keyring.sh installer/lib/cleanup.sh
# Scripts that source the installer libraries; shellcheck follows the sources (-x).
INSTALLER_SCRIPTS := installer/aios-install installer/gen-keys.sh
SH_SCRIPTS := initrd/aios-root.sh base/aios-health.sh
BASH_SCRIPTS := initrd/install/aios tests/bats/fakes/btrfs tests/bats/fakes/record \
	tests/bats/fakes/findmnt tests/bats/fakes/installer iso/profiledef.sh iso/build-profile.sh \
	$(INSTALLER_LIBS)
BATS_FILES := tests/bats/aios-root.bats tests/bats/install-hook.bats tests/bats/aios-health.bats \
	tests/bats/installer-config.bats tests/bats/installer-disk.bats \
	tests/bats/installer-target.bats tests/bats/installer-keys.bats \
	tests/bats/installer-dryrun.bats tests/bats/iso-profile.bats
UNITS := initrd/aios-root.service initrd/sysroot-etc.mount base/aios-health.service \
	iso/airootfs/etc/systemd/system/aios-install-auto.service

# The ISO (spec §6.1): iso/ is the profile, iso-build/ the generated copy mkarchiso builds.
ISO_BUILD := iso-build
ISO_WORK := build/iso-work
ISO_OUT := out

.PHONY: check rust-check shell-check bats-check unit-check e2e-unit tools repo keys iso-build \
	iso iso-check clean-iso e2e

check: rust-check shell-check bats-check unit-check e2e-unit

# The CLI tests need the `test-hooks` feature (AIOS_* overrides, AIOS_FAKE_RUNNER), hence
# --all-features. The shipped configuration (no features) is linted too, and its release
# binary must not contain the test hooks.
rust-check:
	cd aios-cli && $(CARGO) fmt --all -- --check
	cd aios-cli && $(CARGO) clippy --workspace --all-targets --all-features -- -D warnings
	cd aios-cli && $(CARGO) clippy --workspace -- -D warnings
	cd aios-cli && $(CARGO) test --workspace --all-features
	cd aios-cli && $(CARGO) build --release --locked -p aios
	test -s aios-cli/target/release/aios
	! grep -q AIOS_FAKE_RUNNER aios-cli/target/release/aios

shell-check: tools
	$(SHELLCHECK) -s sh $(SH_SCRIPTS)
	$(SHELLCHECK) -s bash $(BASH_SCRIPTS) $(BATS_FILES)
	$(SHELLCHECK) -s bash -x -P SCRIPTDIR $(INSTALLER_SCRIPTS)

bats-check: tools
	$(BATS) $(BATS_FILES)

# Verify copies of the units with ExecStart= pointed at /usr/bin/true, so the host does
# not need /usr/lib/aios/. systemd-analyze verify exits 0 on warnings such as unknown
# keys, so any output at all fails the target.
unit-check:
	rm -rf build/unit-check
	mkdir -p build/unit-check
	cp $(UNITS) build/unit-check/
	sed -i 's|^ExecStart=.*|ExecStart=/usr/bin/true|' build/unit-check/*.service
	out=$$(systemd-analyze verify $(addprefix build/unit-check/,$(notdir $(UNITS))) 2>&1); \
	rc=$$?; \
	if [ $$rc -ne 0 ] || [ -n "$$out" ]; then printf '%s\n' "$$out"; exit 1; fi

# The e2e harness's own tests: no VM, no root (spec §9).
e2e-unit: tools
	$(PYTEST) -p no:cacheprovider -q tests/e2e/test_harness_unit.py

tools: $(SHELLCHECK) $(BATS) $(filter build/venv/bin/pytest,$(PYTEST))

build/tools/shellcheck:
	mkdir -p build/tools
	curl -fsSL -o build/tools/shellcheck.tar.xz \
		https://github.com/koalaman/shellcheck/releases/download/$(SHELLCHECK_VERSION)/shellcheck-$(SHELLCHECK_VERSION).linux.x86_64.tar.xz
	echo "$(SHELLCHECK_SHA256)  build/tools/shellcheck.tar.xz" | sha256sum -c -
	tar -xJf build/tools/shellcheck.tar.xz -C build/tools --strip-components=1 \
		shellcheck-$(SHELLCHECK_VERSION)/shellcheck
	rm build/tools/shellcheck.tar.xz

build/tools/bats-core/bin/bats:
	mkdir -p build/tools
	git clone --depth 1 --branch $(BATS_VERSION) https://github.com/bats-core/bats-core build/tools/bats-core
	test "$$(git -C build/tools/bats-core rev-parse HEAD)" = $(BATS_COMMIT)

build/venv/bin/pytest: tests/e2e/requirements.txt
	$(PYTHON) -m venv build/venv
	build/venv/bin/pip install -q --require-hashes --only-binary=:all: -r tests/e2e/requirements.txt
	touch $@

# Local pacman repo with aios-base and aios-cli (spec §4.6). No root: makepkg -d skips
# the dependency check, so the build host needs cargo but not the runtime depends.
repo:
	rm -rf build/repo build/makepkg
	mkdir -p build/repo build/makepkg
	cd packaging/aios-base && PKGDEST=$(CURDIR)/build/repo BUILDDIR=$(CURDIR)/build/makepkg \
		makepkg -f -d --noconfirm
	cd packaging/aios-cli && PKGDEST=$(CURDIR)/build/repo BUILDDIR=$(CURDIR)/build/makepkg \
		makepkg -f -d --noconfirm
	repo-add build/repo/aios-local.db.tar.gz build/repo/*.pkg.tar.zst
	if command -v namcap >/dev/null; then namcap build/repo/*.pkg.tar.zst; fi

# The CachyOS signing keys this host's pacman keyring trusts, pinned for the installer.
keys:
	installer/gen-keys.sh installer/lib/keys.sh

# The profile mkarchiso builds: iso/ plus pacman.conf, the installer and build/repo.
iso-build: keys
	iso/build-profile.sh $(ISO_BUILD) build/repo installer/lib/keys.sh

# Needs root: run `make iso` yourself (not `sudo make iso`); it asks sudo for the two root
# commands. archiso >= 89 can also build unprivileged: `make iso SUDO=`.
iso: iso-build
	$(SUDO) rm -rf --one-file-system $(ISO_WORK)
	$(SUDO) mkarchiso -v -w $(ISO_WORK) -o $(ISO_OUT) $(ISO_BUILD)/

# Static profile checks, no build and no root.
iso-check: tools
	$(BATS) tests/bats/iso-profile.bats

clean-iso:
	rm -rf $(ISO_BUILD)
	if [ -e $(ISO_WORK) ]; then $(SUDO) rm -rf --one-file-system $(ISO_WORK); fi

# Install the newest out/aios-*.iso into a VM and run spec §1 (a)-(g). No root, about an
# hour. E2E_ARGS=--keep-vm keeps the VM disk in build/e2e/ afterwards.
E2E_ARGS ?=
e2e: tools
	cd tests && $(PYTHON) -m e2e.vm
	$(PYTEST) -p no:cacheprovider -v -rs tests/e2e/test_e2e.py $(E2E_ARGS)
```

Run: `grep -cP '^\t' Makefile; make -n check | head -3`
Expected: `59` (the recipe and continuation lines start with a TAB), then:
```
cd aios-cli && cargo fmt --all -- --check
cd aios-cli && cargo clippy --workspace --all-targets --all-features -- -D warnings
cd aios-cli && cargo clippy --workspace -- -D warnings
```

- [ ] **Step 4: The full gate from clean build dirs**

Run: `rm -rf build/unit-check iso-build && make check && make iso-check`
Expected:
- `make check` passes:
  - HEAD's `rust-check`: no fmt diff, no clippy warnings with or without features, the Rust suites pass, and the release binary carries no test hooks
  - three shellcheck commands without diagnostics
  - bats `1..117` all `ok`
  - `systemd-analyze verify` silent for four units
  - `19 passed`
- `make iso-check` prints `1..10`, all `ok`.

- [ ] **Step 5: Independent review**

Use superpowers:requesting-code-review to dispatch a reviewer subagent over `git diff <phase-5 base>..HEAD`. Point it at spec §1, §2, §5.5, §6, §7 and §9, and at "Contracts for Phase 4/5" in the Phase 3 plan. Ask it to focus on these risks:
- **Secrets:** they reach programs only on stdin, never argv, logs or the dry-run output.
- **The config parser:** it never evaluates its input.
- **The cleanup trap:** its order, and that it cannot leave LUKS open.
- **The disk guard:** the live medium can never be erased.
- **The ISO pacman.conf:** repo order and SigLevel.
- **The harness:** its expect/timeout logic.

Fix blocking findings tests-first, then re-run Step 4.

- [ ] **Step 6: Commit**

```bash
git add README.md docs/superpowers/specs/2026-11-03-base-iso-design.md
git commit -m "docs: building and testing the ISO; spec corrections from phase 5"
git log --oneline | head -9
```
Expected: the nine Phase 5 commits on top of `a8c3edd` (or later).

- [ ] **Step 7: Handoff to the user (USER RUNS)**

Stop here and report BLOCKED-ON-USER with this checklist, unless Task 6 Step 12 and Task 8 Step 7 already ran:

1. Install the tools (root):
   ```bash
   sudo pacman -S --needed archiso arch-install-scripts sbctl swtpm systemd-ukify python-pytest
   ```
2. Build the local repo from the current commit (no root): `make repo`
3. Build the ISO: `make iso`. It asks for the sudo password. Run it as yourself, not as `sudo make iso`. Expected: `out/aios-YYYY.MM.DD-x86_64.iso`.
4. Run the end-to-end test (no root, about an hour): `make e2e`. Expected: `7 passed`. On a failure, `build/e2e/serial.log` has the whole console transcript, and the failing step's message holds the last 3000 characters of it. `make e2e E2E_ARGS=--keep-vm` keeps the disk for inspection.

After steps 1–3 the agent can run step 4 itself, since it needs no root.

---

## Self-review

- **Spec coverage:**

  | Spec | What | Task |
  |---|---|---|
  | §1 `make iso` | `make iso` = `iso-build` (no root) + `sudo mkarchiso -v -w build/iso-work -o out iso-build/` | 6 |
  | §1 `make e2e` (a)–(g) | `test_e2e.py` test_02–07 (table in Task 8) | 8 |
  | §2 `@blank` skeleton | `skeleton.sh`, compared with the spec text | 3, 5 |
  | §5.1 Secure Boot keys, enrollment in Setup Mode, signed systemd-boot | steps 8, 10, 11; e2e test_02 | 5, 8 |
  | §5.1 LUKS2 argon2id, recovery key | step 4 | 5 |
  | §5.5 USBGuard rules (present, block HID, allow) | `usbguard.sh`, step 12 | 3, 5 |
  | §6.1 profiledef, pacman.conf template, packages, entries (serial), airootfs (installer, serial autologin, `/opt/aios-repo`, motd) | `iso/`, `build-profile.sh`, `iso-profile.bats` | 6 |
  | §6.2 modes: interactive, `--config`, fw_cfg (automatic) | `aios-install`, `config.sh`, `aios-install-auto.service` | 1, 5, 6 |
  | §6.2 whitelist parser, never sourced | `parse_config`; "never executed or expanded" test | 1 |
  | §6.2 step 1 preflight (EFI, whole disk, not the live medium, network, v3) | `validate_disk`, `cpu_supports_v3`, preflight | 2, 5 |
  | §6.2 steps 2–13 | `aios-install`; golden dry-run sequence | 5 |
  | §6.2 placeholders, home rename, yescrypt secret | `manifest.sh`, `secrets.sh` | 3 |
  | §6.2 pinned CachyOS key in `installer/lib/keys.sh`, generated at ISO build time, non-empty check | `gen-keys.sh`, `make keys`, `check_cachyos_keys` | 4 |
  | §7 installer failure: name the step, unmount, close LUKS | `cleanup.sh` `on_exit`; dry-run failure tests | 4, 5 |
  | §9 shell row (installer `lib/`: parser, disk, v3) | the five `installer-*.bats` files | 1–5 |
  | §9 E2E row (KVM, OVMF secboot + vars copy, swtpm, 20 GiB qcow2, fw_cfg, serial socket) | `vm.py`, `serial.py`, `test_e2e.py` | 7, 8 |

- **Beyond the brief** (each one is called out in its task):
  - **Installer:**
    - `run_cmd` instead of `run`, which would shadow bats' `run`
    - deterministic quoting instead of `printf %q`
    - `run_stdin`, so secrets never appear in argv, logs or dry-run output
    - the dry-run failure hook
    - `--auto` and `aios-install-auto.service`
    - refusing a disk with mounts, a read-only disk or one under 16 GiB
    - refusing an already-open `aios` mapping
    - `chown`/`chmod` of the copied manifest repo, for contract 6
    - an enrollment failure is a warning
  - **Keys:** an exact-set keyring check, made in preflight, before anything is erased.
  - **Profile:** the releng items left out (BIOS, speech, sshd, VM guest daemons), memtest as entry `04`, and `make iso` deleting a stale work dir.
  - **Harness:**
    - the package layout, which avoids a pyserial clash
    - `make e2e` refusing to report a skip as a pass
    - the socket-path length check
    - Secure Boot checked in test_02
    - `--keep-vm` / `E2E_ARGS`
    - a hash-pinned venv instead of a plain `pip install pytest`
  - **Drift checks:** bats tests compare the installer with `aios-manifest` (reserved cmdline keys), `aios-render` (`loader_conf`) and the spec (the skeleton). A pytest compares the harness with `iso/efiboot` (menu position) and the default manifest (the `sed` edits).
- **What the first real `make e2e` will tell us.** These parts are checked against the tools' sources or binaries on this host, but they never ran together:
  - OVMF + sbctl enrollment from the live ISO, then `bootctl status` reporting `enabled (user)`
  - systemd-boot's menu over the serial console (press `2`)
  - run0's polkit prompt on a serial getty
  - the timing of a full pacstrap

  When a step fails, its message carries the last 3000 characters of the console, and `build/e2e/serial.log` has everything. Fix with superpowers:systematic-debugging, not by loosening a check.
- **Environment overrides.** The installer honors its `AIOS_*` test overrides in production too. Since `a8c3edd` the shipped `aios` binary reads no `AIOS_*` variable (spec §4.5), but the two differ: the installer is a root-run script on the live medium, so its caller already controls its environment. Its overrides only redirect inputs, plus the dry-run failure hook, which works only in dry-run mode. The bootstrap child it starts is a release `aios`, which ignores them all.
- **Placeholder scan:** every file's full content is in its step, and every command lists its expected output. The only host-dependent outputs are named as such: the pinned fingerprint, the pytest source, and paths under `/home/eli/Development/AIOS`.
- **Type and name consistency:**
  - The fw_cfg name `opt/aios/install.conf` is the same in `config.sh`, `vm.py` and the profile's service.
  - The serial entry's title and key are the same in `test_e2e.py` and `iso/efiboot`, which a test checks.
  - The installer's `KEY`s are `AIOS_CONFIG_KEYS` in bash and `INSTALL_KEYS` in Python, in the same order.
  - The env overrides in the scripts match the tests: `AIOS_INSTALL_LIB`, `AIOS_INSTALL_DRYRUN(_FAILS)`, `AIOS_EFI_DIR`, `AIOS_DEFAULTS`, `AIOS_LIVE_REPO`, `AIOS_FWCFG_DIR`, `AIOS_ZONEINFO`, `AIOS_PASSWD_FILE`, `AIOS_LDSO`, `AIOS_LIVE_MNT`, `AIOS_PACMAN_GNUPG`, `AIOS_E2E_DIR`, `AIOS_E2E_ISO`.
  - The Makefile lists match the created files.
- **Deferred:**
  - **TPM and Secure Boot follow-ups:** the first boot after a failed enrollment, and `aios tpm enroll` (both manual, per spec §5.1).
  - **systemd-boot updates:** a newer systemd in a later generation would leave systemd-boot unsigned if something ran `bootctl update`. Nothing does today; signing on update is Phase 3 territory.
  - **Offline install** (spec follow-up #4).
