# Base ISO — Phase 4: initrd, Health Check, Base Payload, Default Manifest, Packaging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship everything that runs outside the `aios` binary:
- the initrd script and units that rebuild `@root-live`/`@etc-live` at every boot
- the boot health check
- the `aios-base` configuration payload
- the default manifest repo
- PKGBUILDs for `aios-cli` and `aios-base`, plus `make repo` to build the local pacman repo

`make check` grows shellcheck, bats and `systemd-analyze verify`.

**Architecture:**
- The shell scripts are POSIX `sh` with env overrides (`AIOS_CMDLINE_FILE`, `AIOS_TOP`, `AIOS_FINDMNT`, …). bats drives them against fake `btrfs`/`mount`/`umount`/`findmnt` executables, so no test needs root, a block device or btrfs.
- The initrd units live on the host under `/usr/lib/aios/initrd/`, outside every unit search path. Only the `aios` mkinitcpio hook copies them into the initrd and enables them there.
- The default manifest is a template whose placeholders the installer fills. One Rust integration test in `aios-manifest` proves the filled-in result passes every Phase 1 validation rule.
- Both packages build from this working tree with `makepkg -d` (no root, no source tarballs).

**Tech Stack:** POSIX sh (busybox ash in the initrd, bash-as-sh on the host), bash, bats-core 1.11.1, shellcheck 0.10.0, systemd 262 units, mkinitcpio 42 install hook API, makepkg/repo-add (pacman 7.1), Rust (one integration test, Phase 1 API only).

**Spec:** `docs/superpowers/specs/2026-11-03-base-iso-design.md`:
- §2: `@blank` skeleton, pacman DB in `/usr`
- §3: boot flow, `aios-root.service`, `sysroot-etc.mount`, `aios-health`
- §4.1: manifest format
- §4.4: managed home paths
- §4.6: packages, `aios-base` payload, default manifest
- §5: hardening contents
- §9: testing
- §10: repo layout

**Depends on:**
- Phase 1 (merged: `aios-manifest`, `aios-gen`).
- Phase 2 (`aios-render`, merged while this plan was written) reads `base/cmdline-hardening`. Task 5 cross-checks the two.
- Task 7 also needs Phase 3: the binary crate `aios-cli/crates/aios` producing `aios`.
- Phase 4 changes no Rust crate except adding `aios-cli/crates/aios-manifest/tests/default_manifest.rs`.

**Environment note for every task:** Rust is installed via rustup without PATH changes. Start every shell with:
```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/eli/Development/AIOS
```
- No task needs root. The user has no passwordless sudo, so never run `sudo`.
- `shellcheck` and `bats` may be missing. `make tools` (Task 1) fetches pinned copies into `build/tools/`, which is gitignored.
- `/bin/sh` on this host is bash. `shellcheck -s sh` is what keeps `aios-root.sh` and `aios-health.sh` portable to busybox ash in the initrd. The `base` hook provides `sh awk sort cat mkdir printf sed head [`, and mount/umount come from util-linux.

**GateGuard note:** a local hook blocks the *first* Write/Edit of each new file, and the first Bash call, until you state some facts:
- callers/importers
- that no existing file serves the purpose
- data schema if any
- the user's instruction

Answer briefly in text and retry the same call. A second gate fires on any Bash command containing `rm -rf`, even inside a heredoc. For that one, list the files the command modifies or deletes, give a one-line rollback, and quote the instruction, then retry. The user's instruction is: "finish this project, use skills and subagents".

**Verified while writing this plan:** every file below was created in a scratch copy of this repo and run on this host:
- shellcheck 0.10.0 is clean.
- All 21 bats tests pass, and they fail as stated before the implementation exists.
- `systemd-analyze verify` prints nothing.
- The Rust test passes against the real Phase 1 code (`cargo fmt --check` and clippy clean).
- `make repo` builds both packages. `aios-cli` was built against a stand-in `aios` bin crate because Phase 3 was not merged yet.
- A final round trip rebuilt the repo from this document's text alone, on top of HEAD `4a1c4a4` (Phase 2 merged). It extracted every file, ran the `chmod`/`.keep` steps, then `make check`, `make repo` and the Task 7 checks. All passed.

If an expected output differs, that is a real difference in your environment. Investigate it (superpowers:systematic-debugging) instead of editing a test until it passes.

**`make check` before Task 4:** Task 1 writes the final Makefile, whose file lists name files that Tasks 2–4 create. Until Task 4 lands, the full `make check` fails at `shell-check` with "does not exist". Tasks 2 and 3 therefore run the narrowed targets shown in their steps, using command-line overrides such as `make bats-check BATS_FILES=tests/bats/aios-root.bats`. From Task 4 on, plain `make check` must pass.

---

## File Structure

```
Makefile                                      check = rust + shell + bats + units; tools; repo
.gitignore                                    + packaging/*/{src,pkg}/ and stray packages
README.md                                     development commands, layout
initrd/aios-root.sh                           initrd: recreate @root-live/@etc-live for aios.gen=N
initrd/aios-root.service                      initrd unit: runs aios-root.sh before sysroot.mount
initrd/sysroot-etc.mount                      initrd unit: mounts @etc-live at /sysroot/etc
initrd/install/aios                           mkinitcpio install hook (build + help)
base/aios-health.sh                           boot health check
base/aios-health.service                      oneshot, RequiredBy=boot-complete.target
base/sysctl.d/90-aios-hardening.conf          spec §5.2
base/cmdline-hardening                        spec §5.3, without lockdown=
base/NetworkManager/conf.d/90-aios-privacy.conf   MAC randomization, IPv6 privacy
base/resolved.conf.d/90-aios-dot.conf         DNS over TLS
base/zram-generator.conf                      zram swap
manifest/manifest.toml                        default manifest template (@HOSTNAME@ @USERNAME@ @TIMEZONE@ @EXTRA_CMDLINE@)
manifest/files/pacman.conf                    DBPath in /usr, aios-local + CachyOS + Arch repos
manifest/files/mkinitcpio.conf                MODULES=(btrfs), spec §3 HOOKS
manifest/files/nftables.conf                  deny inbound/forward, allow outbound
manifest/files/usbguard-daemon.conf           spec §5.5
manifest/home/@USERNAME@/zshrc
manifest/home/@USERNAME@/profile
manifest/home/@USERNAME@/authorized_keys      empty
manifest/home/@USERNAME@/autostart/.keep
manifest/home/@USERNAME@/systemd-user/.keep
manifest/home/@USERNAME@/environment.d/.keep
manifest/home/@USERNAME@/environment.d/10-aios.conf
manifest/home/@USERNAME@/bin/.keep
packaging/aios-cli/PKGBUILD                   /usr/bin/aios from aios-cli/
packaging/aios-base/PKGBUILD                  base/, initrd/, manifest/ into /usr
tests/bats/fakes/btrfs                        fake btrfs: subvolumes are dirs with a .subvol marker
tests/bats/fakes/record                       fake mount/umount: record the call
tests/bats/fakes/findmnt                      fake findmnt driven by files under $FAKE_MOUNTS
tests/bats/aios-root.bats                     10 tests
tests/bats/install-hook.bats                  2 tests
tests/bats/aios-health.bats                   11 tests
aios-cli/crates/aios-manifest/tests/default_manifest.rs   4 tests
```

**Installed layout** (Task 7 checks it against the built package):

| Repo file | Installed path (mode) |
|---|---|
| `base/sysctl.d/90-aios-hardening.conf` | `/usr/lib/sysctl.d/90-aios-hardening.conf` |
| `base/cmdline-hardening` | `/usr/lib/aios/cmdline-hardening` |
| `base/aios-health.sh` | `/usr/lib/aios/aios-health.sh` (755) |
| `base/aios-health.service` | `/usr/lib/systemd/system/aios-health.service` |
| `base/NetworkManager/conf.d/90-aios-privacy.conf` | `/usr/lib/NetworkManager/conf.d/90-aios-privacy.conf` |
| `base/resolved.conf.d/90-aios-dot.conf` | `/usr/lib/systemd/resolved.conf.d/90-aios-dot.conf` |
| `base/zram-generator.conf` | `/usr/lib/systemd/zram-generator.conf` |
| `initrd/aios-root.sh` | `/usr/lib/aios/initrd/aios-root.sh` (755) |
| `initrd/aios-root.service`, `initrd/sysroot-etc.mount` | `/usr/lib/aios/initrd/` (inside the initrd: `/usr/lib/systemd/system/`) |
| `initrd/install/aios` | `/usr/lib/initcpio/install/aios` |
| `manifest/` | `/usr/share/aios/defaults/manifest/` (dirs 755, files 644, `.keep` files kept) |
| `aios-cli` target `aios` | `/usr/bin/aios` (755) |

---

### Task 1: Test tools and the extended `make check`

**Files:**
- Modify: `Makefile` (full new content below)

- [ ] **Step 1: Check the host tools**

Run: `systemd-analyze --version | head -1; command -v makepkg repo-add fakeroot curl git sha256sum tar`
Expected: `systemd 262 (262.1-1-arch)` (or a later 262.x), then seven paths. If `systemd-analyze` or `makepkg` is missing, stop and report BLOCKED.

- [ ] **Step 2: Replace the Makefile**

The pinned hashes were taken from the real downloads:
- `SHELLCHECK_SHA256` is the sha256 of `shellcheck-v0.10.0.linux.x86_64.tar.xz`.
- `BATS_COMMIT` is the commit behind tag `v1.11.1`.

`unit-check` copies the units, rewrites `ExecStart=` to `/usr/bin/true` so the host doesn't need `/usr/lib/aios/`, and runs plain `systemd-analyze verify`. No extra flags are needed:
- systemd 262 accepts the initrd-only references (`sysroot.mount`, `initrd-fs.target`, `dev-mapper-aios.device`) without complaint.
- The units carry no `Documentation=`, so `--man` has nothing to check.
- `verify` runs no generators unless asked to with `--generators=yes`.

`verify` exits 0 even when it warns about an unknown key, so the target fails on *any* output.

`Makefile` (recipe lines start with a TAB character):
```make
export PATH := $(HOME)/.cargo/bin:$(PATH)
CARGO ?= cargo

# Shell test tools: the system copies when installed, otherwise pinned copies that
# `make tools` fetches into build/tools/ (no root needed).
SHELLCHECK_VERSION := v0.10.0
SHELLCHECK_SHA256 := 6c881ab0698e4e6ea235245f22832860544f17ba386442fe7e9d629f8cbedf87
BATS_VERSION := v1.11.1
BATS_COMMIT := b640ec3cf2c7c9cfc9e6351479261186f76eeec8
SHELLCHECK ?= $(shell command -v shellcheck || echo build/tools/shellcheck)
BATS ?= $(shell command -v bats || echo build/tools/bats-core/bin/bats)

# What the shell and unit checks cover.
SH_SCRIPTS := initrd/aios-root.sh base/aios-health.sh
BASH_SCRIPTS := initrd/install/aios tests/bats/fakes/btrfs tests/bats/fakes/record \
	tests/bats/fakes/findmnt
BATS_FILES := tests/bats/aios-root.bats tests/bats/install-hook.bats tests/bats/aios-health.bats
UNITS := initrd/aios-root.service initrd/sysroot-etc.mount base/aios-health.service

.PHONY: check rust-check shell-check bats-check unit-check tools repo

check: rust-check shell-check bats-check unit-check

rust-check:
	cd aios-cli && $(CARGO) fmt --all -- --check
	cd aios-cli && $(CARGO) clippy --workspace --all-targets -- -D warnings
	cd aios-cli && $(CARGO) test --workspace

shell-check: tools
	$(SHELLCHECK) -s sh $(SH_SCRIPTS)
	$(SHELLCHECK) -s bash $(BASH_SCRIPTS) $(BATS_FILES)

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

tools: $(SHELLCHECK) $(BATS)

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
```

- [ ] **Step 3: Fetch the tools**

Run: `make tools`
Expected on first run: `curl` downloads the tarball, `build/tools/shellcheck.tar.xz: OK` from `sha256sum -c`, `tar` extracts it, and `git clone` fetches `bats-core`. The `test "$(git … rev-parse HEAD)" = b640ec3…` line passes silently. A tool that is already installed system-wide is not fetched. When both are installed, the output is `make: Nothing to be done for 'tools'.`

- [ ] **Step 4: Confirm which tools `make` will use**

Run: `make -s --eval 'print-tools: ; @echo $(SHELLCHECK) $(BATS)' print-tools`
Expected: `build/tools/shellcheck build/tools/bats-core/bin/bats` (or `/usr/bin/…` for system copies).

Run: `build/tools/shellcheck --version | sed -n 2p; build/tools/bats-core/bin/bats --version`
Expected: `version: 0.10.0` and `Bats 1.11.1`. Skip whichever tool is a system copy.

- [ ] **Step 5: Rust checks still pass, the new targets are wired**

Run: `make rust-check`
Expected: as before: no fmt diff, no clippy warnings, all tests pass.

Run: `make -n shell-check bats-check unit-check | head -4`
Expected (dry run, nothing executed):
```
build/tools/shellcheck -s sh initrd/aios-root.sh base/aios-health.sh
build/tools/shellcheck -s bash initrd/install/aios tests/bats/fakes/btrfs tests/bats/fakes/record tests/bats/fakes/findmnt tests/bats/aios-root.bats tests/bats/install-hook.bats tests/bats/aios-health.bats
build/tools/bats-core/bin/bats tests/bats/aios-root.bats tests/bats/install-hook.bats tests/bats/aios-health.bats
rm -rf build/unit-check
```

Run: `git status --short`
Expected: ` M Makefile` only. `build/` is ignored.

- [ ] **Step 6: Commit**

```bash
git add Makefile
git commit -m "build: make tools; shellcheck, bats and unit verify in make check"
```

---

### Task 2: `aios-root.sh` with bats tests

**Files:**
- Create: `initrd/aios-root.sh`
- Test: `tests/bats/fakes/btrfs`, `tests/bats/fakes/record`, `tests/bats/aios-root.bats`

How the fakes work:
- A "subvolume" is a directory under `$AIOS_TOP` containing a `.subvol` marker file.
- The fake `btrfs` appends every call to `$CALLS`. It handles three subcommands:
  - `snapshot SRC DST`: `mkdir` plus `cp -a`.
  - `delete P`: `rm -rf`. Like real btrfs, it refuses when `P` still contains a nested subvolume, so a wrong deletion order fails the script, not just the order assertion.
  - `list -o P`: prints `ID n gen n top level n path <rel>` for every nested marker.
- `record` is installed as both `mount` and `umount`. It only appends `<name> <args>` to `$CALLS`.
- The test's `setup()` symlinks the fakes into `$BATS_TEST_TMPDIR/bin` and prepends that directory to `PATH`.

- [ ] **Step 1: Write the fakes**

`tests/bats/fakes/btrfs`:
```bash
#!/usr/bin/env bash
# Fake btrfs for tests/bats/aios-root.bats.
# A "subvolume" is a directory under $AIOS_TOP that contains a .subvol marker file.
# Every call is appended to $CALLS as one line: "btrfs <args>".
set -euo pipefail

echo "btrfs $*" >>"$CALLS"

is_subvol() {
    [ -f "$1/.subvol" ]
}

# Subvolumes strictly below $1, as paths relative to $AIOS_TOP, sorted.
nested_subvols() {
    find "$1" -mindepth 2 -name .subvol | sort | while IFS= read -r marker; do
        rel=${marker%/.subvol}
        printf '%s\n' "${rel#"$AIOS_TOP"/}"
    done
}

[ "${1:-}" = subvolume ] || { echo "fake btrfs: unsupported: $*" >&2; exit 2; }
case "${2:-}" in
    snapshot)
        src=$3 dst=$4
        is_subvol "$src" || { echo "ERROR: not a subvolume: $src" >&2; exit 1; }
        [ ! -e "$dst" ] || { echo "ERROR: target path already exists: $dst" >&2; exit 1; }
        mkdir "$dst"
        cp -a "$src/." "$dst/"
        echo "Create a snapshot of '$src' in '$dst'"
        ;;
    delete)
        target=$3
        is_subvol "$target" || { echo "ERROR: not a subvolume: $target" >&2; exit 1; }
        if [ -n "$(nested_subvols "$target")" ]; then
            echo "ERROR: Could not destroy subvolume/snapshot: Directory not empty" >&2
            exit 1
        fi
        rm -rf "$target"
        echo "Delete subvolume '$target'"
        ;;
    list)
        [ "${3:-}" = -o ] || { echo "fake btrfs: only 'list -o PATH' is supported" >&2; exit 2; }
        id=300
        nested_subvols "$4" | while IFS= read -r rel; do
            id=$((id + 1))
            echo "ID $id gen 10 top level 5 path $rel"
        done
        ;;
    *)
        echo "fake btrfs: unsupported: $*" >&2
        exit 2
        ;;
esac
```

`tests/bats/fakes/record`:
```bash
#!/usr/bin/env bash
# Fake mount/umount for tests/bats/aios-root.bats: records "<name> <args>" in $CALLS and succeeds.
set -euo pipefail

echo "${0##*/} $*" >>"$CALLS"
```

Run: `chmod 755 tests/bats/fakes/btrfs tests/bats/fakes/record`

- [ ] **Step 2: Write the failing tests**

`tests/bats/aios-root.bats`:
```bash
#!/usr/bin/env bats
# initrd/aios-root.sh against fake btrfs/mount/umount (spec §3 step 6, §9).

setup() {
    SCRIPT="$BATS_TEST_DIRNAME/../../initrd/aios-root.sh"
    FAKES="$BATS_TEST_DIRNAME/fakes"
    BIN="$BATS_TEST_TMPDIR/bin"
    mkdir -p "$BIN"
    ln -s "$FAKES/btrfs" "$BIN/btrfs"
    ln -s "$FAKES/record" "$BIN/mount"
    ln -s "$FAKES/record" "$BIN/umount"
    PATH="$BIN:$PATH"

    export AIOS_TOP="$BATS_TEST_TMPDIR/top"
    export AIOS_CMDLINE_FILE="$BATS_TEST_TMPDIR/cmdline"
    export AIOS_DEVICE=/dev/mapper/fake-aios
    export CALLS="$BATS_TEST_TMPDIR/calls"
    : >"$CALLS"

    mkdir -p "$AIOS_TOP"
    subvol @blank
    mkdir -p "$AIOS_TOP/@blank/etc" "$AIOS_TOP/@blank/usr" "$AIOS_TOP/@blank/persist"
    subvol @usr-gen-0007
    subvol @etc-gen-0007
    mkdir -p "$AIOS_TOP/@etc-gen-0007/aios"
    echo "id = 7" >"$AIOS_TOP/@etc-gen-0007/aios/generation.toml"
    cmdline "root=/dev/mapper/aios rootflags=subvol=@root-live aios.gen=0007 quiet"
}

# subvol NAME: create a fake subvolume at $AIOS_TOP/NAME.
subvol() {
    mkdir -p "$AIOS_TOP/$1"
    : >"$AIOS_TOP/$1/.subvol"
}

cmdline() {
    printf '%s\n' "$*" >"$AIOS_CMDLINE_FILE"
}

# called LINE: LINE appears verbatim in $CALLS.
called() {
    grep -qxF -- "$1" "$CALLS" || { echo "not called: $1" >&2; cat "$CALLS" >&2; return 1; }
}

# call_index LINE: 1-based position of LINE in $CALLS.
call_index() {
    grep -nxF -- "$1" "$CALLS" | cut -d: -f1
}

@test "normal boot recreates @root-live and @etc-live and deletes the stale ones" {
    subvol @root-live
    touch "$AIOS_TOP/@root-live/runtime-junk"
    subvol @etc-live
    touch "$AIOS_TOP/@etc-live/runtime-edit"

    run "$SCRIPT"

    [ "$status" -eq 0 ]
    called "mount -t btrfs -o subvolid=5 /dev/mapper/fake-aios $AIOS_TOP"
    called "btrfs subvolume delete $AIOS_TOP/@root-live"
    called "btrfs subvolume delete $AIOS_TOP/@etc-live"
    called "btrfs subvolume snapshot $AIOS_TOP/@blank $AIOS_TOP/@root-live"
    called "btrfs subvolume snapshot $AIOS_TOP/@etc-gen-0007 $AIOS_TOP/@etc-live"
    [ "$(tail -n 1 "$CALLS")" = "umount $AIOS_TOP" ]
    [ "$(grep -c "^umount " "$CALLS")" -eq 1 ]
    [ -d "$AIOS_TOP/@root-live/etc" ]
    [ ! -e "$AIOS_TOP/@root-live/runtime-junk" ]
    [ -f "$AIOS_TOP/@etc-live/aios/generation.toml" ]
    [ ! -e "$AIOS_TOP/@etc-live/runtime-edit" ]
    [ -f "$AIOS_TOP/@usr-gen-0007/.subvol" ]
    [ -f "$AIOS_TOP/@etc-gen-0007/.subvol" ]
    [[ "$output" == *"aios: generation 0007 ready"* ]]
}

@test "first boot without live subvolumes deletes nothing" {
    run "$SCRIPT"

    [ "$status" -eq 0 ]
    [ "$(grep -c ' delete ' "$CALLS")" -eq 0 ]
    [ -f "$AIOS_TOP/@root-live/.subvol" ]
    [ -f "$AIOS_TOP/@etc-live/.subvol" ]
}

@test "stale candidates from an interrupted apply are deleted" {
    subvol @usr-cand
    subvol @etc-cand
    subvol @root-cand

    run "$SCRIPT"

    [ "$status" -eq 0 ]
    called "btrfs subvolume delete $AIOS_TOP/@usr-cand"
    called "btrfs subvolume delete $AIOS_TOP/@etc-cand"
    called "btrfs subvolume delete $AIOS_TOP/@root-cand"
    [ ! -e "$AIOS_TOP/@usr-cand" ]
    [ ! -e "$AIOS_TOP/@etc-cand" ]
    [ ! -e "$AIOS_TOP/@root-cand" ]
}

@test "nested subvolumes are deleted before their parent" {
    subvol @root-live
    subvol @root-live/var/lib/machines
    subvol @root-live/var/lib/machines/inner
    subvol @root-live/var/lib/portables

    run "$SCRIPT"

    [ "$status" -eq 0 ]
    inner=$(call_index "btrfs subvolume delete $AIOS_TOP/@root-live/var/lib/machines/inner")
    machines=$(call_index "btrfs subvolume delete $AIOS_TOP/@root-live/var/lib/machines")
    portables=$(call_index "btrfs subvolume delete $AIOS_TOP/@root-live/var/lib/portables")
    parent=$(call_index "btrfs subvolume delete $AIOS_TOP/@root-live")
    [ -n "$inner" ]
    [ -n "$machines" ]
    [ -n "$portables" ]
    [ -n "$parent" ]
    [ "$inner" -lt "$machines" ]
    [ "$machines" -lt "$parent" ]
    [ "$portables" -lt "$parent" ]
    [ ! -e "$AIOS_TOP/@root-live/var" ]
}

@test "missing generation fails with a clear message and still unmounts" {
    cmdline "root=/dev/mapper/aios aios.gen=0008"

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [[ "$output" == *"aios: generation 0008 missing — pick another boot entry"* ]]
    [ "$(grep -c ' snapshot ' "$CALLS")" -eq 0 ]
    [ "$(tail -n 1 "$CALLS")" = "umount $AIOS_TOP" ]
}

@test "half a generation (no @etc-gen-N) counts as missing" {
    subvol @usr-gen-0008
    cmdline "aios.gen=0008"

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [[ "$output" == *"aios: generation 0008 missing — pick another boot entry"* ]]
}

@test "no aios.gen on the cmdline fails before mounting" {
    cmdline "root=/dev/mapper/aios quiet"

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [[ "$output" == *"aios: no generation on cmdline"* ]]
    [ ! -s "$CALLS" ]
}

@test "aios.gen=42 (not 4 digits) fails" {
    cmdline "aios.gen=42"

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [[ "$output" == *"aios: no generation on cmdline"* ]]
    [ ! -s "$CALLS" ]
}

@test "aios.gen=0000 fails" {
    cmdline "aios.gen=0000"

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [[ "$output" == *"aios: no generation on cmdline"* ]]
    [ ! -s "$CALLS" ]
}

@test "conflicting aios.gen values fail before mounting" {
    cmdline "aios.gen=0007 quiet aios.gen=0008"

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [[ "$output" == *"aios: conflicting aios.gen= values on cmdline"* ]]
    [ ! -s "$CALLS" ]
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `make bats-check BATS_FILES=tests/bats/aios-root.bats`
Expected: `1..10`, then ten `not ok` lines, plus `BW01` warnings that the script "exited with code 127, indicating 'Command not found'". make ends with `Error 1`.

- [ ] **Step 4: Implement `aios-root.sh`**

Design points:
- **Recursive deletion.** `delete_subvol` recurses into every nested subvolume that `btrfs subvolume list -o` reports, deepest first (`sort -r`). That covers both readings of `-o` (direct children only, or all descendants). systemd creates `/var/lib/machines` and `/var/lib/portables` as subvolumes inside `@root-live`, so this case is real.
- **Subshell function body.** The body is a subshell `( … )`, so the recursion's variables stay local without the non-POSIX `local`. Its `exit 0` leaves only that call.
- **Trap scope.** The EXIT trap is set only after a successful mount. Subshells don't inherit it, so the top level is unmounted exactly once, at script exit. The tests assert this.
- **Cmdline parsing.** `set -f` around the word split stops a `*` on the cmdline from globbing. Conflicting `aios.gen=` values fail (identical repeats are fine). This matches `aios_gen::gen_from_cmdline`, so the initrd, the health check and the `aios` CLI always agree on the booted generation.

`initrd/aios-root.sh`:
```sh
#!/bin/sh
# aios-root.sh: runs in the initrd via aios-root.service, before sysroot.mount (spec §3 step 6).
# Recreates @root-live from @blank and @etc-live from @etc-gen-N for the generation named by
# aios.gen=N, after deleting stale live subvolumes and leftover apply candidates.
#
# Environment overrides (tests only):
#   AIOS_CMDLINE_FILE  kernel cmdline        (default /proc/cmdline)
#   AIOS_DEVICE        unlocked LUKS device  (default /dev/mapper/aios)
#   AIOS_TOP           btrfs top-level mount (default /run/aios/top)
set -eu

CMDLINE_FILE="${AIOS_CMDLINE_FILE:-/proc/cmdline}"
DEVICE="${AIOS_DEVICE:-/dev/mapper/aios}"
TOP="${AIOS_TOP:-/run/aios/top}"

log() {
    printf 'aios: %s\n' "$*" >&2
}

die() {
    log "$*"
    exit 1
}

# Print the 4-digit generation from aios.gen= (repeats must agree), or fail.
generation_from_cmdline() {
    [ -r "$CMDLINE_FILE" ] || die "cannot read $CMDLINE_FILE"
    cmdline=$(cat "$CMDLINE_FILE")
    found=""
    set -f
    for arg in $cmdline; do
        case "$arg" in
            aios.gen=*)
                value="${arg#aios.gen=}"
                if [ -n "$found" ] && [ "$found" != "$value" ]; then
                    set +f
                    die "conflicting aios.gen= values on cmdline"
                fi
                found="$value"
                ;;
        esac
    done
    set +f
    case "$found" in
        0000) die "no generation on cmdline" ;;
        [0-9][0-9][0-9][0-9]) printf '%s\n' "$found" ;;
        *) die "no generation on cmdline" ;;
    esac
}

# delete_subvol NAME: delete $TOP/NAME (if present) and every subvolume nested inside it.
# `btrfs subvolume list -o` prints paths relative to the top level in its last field.
# Children are handled deepest first (`sort -r`), recursively, because btrfs refuses to
# delete a subvolume that still contains another one (systemd creates
# /var/lib/machines and /var/lib/portables as subvolumes inside @root-live).
# The body is a subshell so the recursion's variables stay local.
delete_subvol() (
    target="$TOP/$1"
    [ -d "$target" ] || exit 0
    btrfs subvolume list -o "$target" | awk '{ print $NF }' | sort -r |
        while IFS= read -r nested; do
            if [ -n "$nested" ]; then
                delete_subvol "$nested"
            fi
        done
    log "deleting $1"
    btrfs subvolume delete "$target"
)

gen=$(generation_from_cmdline)
log "preparing generation $gen"

mkdir -p "$TOP"
mount -t btrfs -o subvolid=5 "$DEVICE" "$TOP"
trap 'umount "$TOP" || log "warning: could not unmount $TOP"' EXIT

if [ ! -d "$TOP/@usr-gen-$gen" ] || [ ! -d "$TOP/@etc-gen-$gen" ]; then
    die "generation $gen missing — pick another boot entry"
fi

for stale in @root-live @etc-live @usr-cand @etc-cand @root-cand; do
    delete_subvol "$stale"
done

log "snapshot @blank -> @root-live"
btrfs subvolume snapshot "$TOP/@blank" "$TOP/@root-live"
log "snapshot @etc-gen-$gen -> @etc-live"
btrfs subvolume snapshot "$TOP/@etc-gen-$gen" "$TOP/@etc-live"
log "generation $gen ready"
```

Run: `chmod 755 initrd/aios-root.sh`

- [ ] **Step 5: Run the tests to verify they pass**

Run: `make bats-check BATS_FILES=tests/bats/aios-root.bats`
Expected: `1..10` and ten `ok` lines.

- [ ] **Step 6: shellcheck**

Run: `make shell-check SH_SCRIPTS=initrd/aios-root.sh BASH_SCRIPTS="tests/bats/fakes/btrfs tests/bats/fakes/record" BATS_FILES=tests/bats/aios-root.bats`
Expected: make echoes the two shellcheck commands and nothing else (no diagnostics), exit 0.

- [ ] **Step 7: Commit (with executable bits)**

```bash
git add initrd/aios-root.sh tests/bats/fakes/btrfs tests/bats/fakes/record tests/bats/aios-root.bats
git ls-files -s initrd/aios-root.sh tests/bats/fakes/btrfs tests/bats/fakes/record
```
Expected: all three lines start with `100755`. If any shows `100644`, run `chmod 755` on it and `git add` again.

```bash
git commit -m "feat(initrd): aios-root.sh rebuilds live subvolumes at boot, with bats tests"
```

---

### Task 3: initrd units, mkinitcpio hook, unit verification

**Files:**
- Create: `initrd/aios-root.service`, `initrd/sysroot-etc.mount`, `initrd/install/aios`
- Test: `tests/bats/install-hook.bats`

How the pieces fit:
- **Hook.** The hook copies the units from `/usr/lib/aios/initrd/` into the initrd's `/usr/lib/systemd/system/`. It enables them with the same `add_symlink` pattern as Arch's own `ostree` hook (absolute target, a `.requires/` or `.wants/` directory). systemd honours those directories for `sysroot.mount` even though that unit is generated at boot by `systemd-fstab-generator` from `root=`.
- **Emergency shell.** A failing `aios-root.service` fails `sysroot.mount` and then `initrd-root-fs.target`. That target has `OnFailure=emergency.target`, which gives spec §3's emergency shell with no extra directives.
- **Extra ordering.** `sysroot-etc.mount` adds one directive beyond the spec's list: `Before=initrd-parse-etc.service`. `systemd-sysroot-fstab-check` then always reads the generation's `/etc/fstab`, never the empty `/etc` from `@blank`. There is no ordering cycle: `initrd-parse-etc.service` runs after `initrd-root-fs.target` and before `initrd-fs.target`.

- [ ] **Step 1: Write the failing hook test**

The test sources the hook in a bash subshell with mkinitcpio's `add_*` functions replaced by recorders. This is exactly how mkinitcpio calls `build()`.

`tests/bats/install-hook.bats`:
```bash
#!/usr/bin/env bats
# initrd/install/aios: what the mkinitcpio hook puts into the initrd (spec §3, §4.6).

setup() {
    HOOK="$BATS_TEST_DIRNAME/../../initrd/install/aios"
}

# Source the hook with mkinitcpio's add_* functions replaced by recorders, then call $1.
hook() {
    bash -c '
        add_binary() { echo "add_binary $*"; }
        add_file() { echo "add_file $*"; }
        add_symlink() { echo "add_symlink $*"; }
        . "$1"
        "$2"
    ' _ "$HOOK" "$1"
}

@test "build adds btrfs, the script, both units and their initrd enablement" {
    run hook build

    [ "$status" -eq 0 ]
    [ "${#lines[@]}" -eq 6 ]
    [ "${lines[0]}" = "add_binary btrfs" ]
    [ "${lines[1]}" = "add_file /usr/lib/aios/initrd/aios-root.sh /usr/lib/aios/initrd/aios-root.sh 755" ]
    [ "${lines[2]}" = "add_file /usr/lib/aios/initrd/aios-root.service /usr/lib/systemd/system/aios-root.service" ]
    [ "${lines[3]}" = "add_file /usr/lib/aios/initrd/sysroot-etc.mount /usr/lib/systemd/system/sysroot-etc.mount" ]
    [ "${lines[4]}" = "add_symlink /usr/lib/systemd/system/sysroot.mount.requires/aios-root.service /usr/lib/systemd/system/aios-root.service" ]
    [ "${lines[5]}" = "add_symlink /usr/lib/systemd/system/initrd-fs.target.wants/sysroot-etc.mount /usr/lib/systemd/system/sysroot-etc.mount" ]
}

@test "help explains the hook" {
    run hook help

    [ "$status" -eq 0 ]
    [[ "$output" == *"aios.gen="* ]]
    [[ "$output" == *"systemd hook"* ]]
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `make bats-check BATS_FILES=tests/bats/install-hook.bats`
Expected: `1..2`, then:
- `not ok 1`, with `` `[ "$status" -eq 0 ]' failed `` and a `BW01` warning that `hook build` exited with code 127.
- `not ok 2`, with `` `[[ "$output" == *"aios.gen="* ]]' failed ``. Without the hook, `help` resolves to bash's builtin, so the status check passes but the output check fails.

- [ ] **Step 3: Write the hook**

The argument forms match mkinitcpio 42's `/usr/lib/initcpio/functions`:
- `add_file SRC [DEST] [MODE]`
- `add_symlink NAME [TARGET]`

shellcheck needs no SC2034/SC2154 disables. To shellcheck the `add_*` helpers are just undefined functions, and the hook reads no mkinitcpio globals.

`initrd/install/aios` (mode 644, sourced by mkinitcpio):
```bash
#!/bin/bash
# mkinitcpio install hook "aios" (spec §3 steps 4-8). Needs the systemd hook before it.
# The units live on the host under /usr/lib/aios/initrd/, outside the host's unit path,
# so only the initrd ever loads them.

build() {
    add_binary btrfs

    add_file /usr/lib/aios/initrd/aios-root.sh /usr/lib/aios/initrd/aios-root.sh 755
    add_file /usr/lib/aios/initrd/aios-root.service /usr/lib/systemd/system/aios-root.service
    add_file /usr/lib/aios/initrd/sysroot-etc.mount /usr/lib/systemd/system/sysroot-etc.mount

    add_symlink /usr/lib/systemd/system/sysroot.mount.requires/aios-root.service \
        /usr/lib/systemd/system/aios-root.service
    add_symlink /usr/lib/systemd/system/initrd-fs.target.wants/sysroot-etc.mount \
        /usr/lib/systemd/system/sysroot-etc.mount
}

help() {
    cat <<HELPEOF
Prepares the AIOS generation named by aios.gen= on the kernel cmdline: recreates
@root-live from @blank and @etc-live from @etc-gen-N, deletes stale apply
candidates, and mounts @etc-live at /sysroot/etc. Requires the systemd hook.
HELPEOF
}
```

- [ ] **Step 4: Run the hook test to verify it passes**

Run: `make bats-check BATS_FILES="tests/bats/aios-root.bats tests/bats/install-hook.bats"`
Expected: `1..12`, all `ok`.

- [ ] **Step 5: Write the two initrd units**

`initrd/aios-root.service`:
```ini
# Initrd only (spec §3 step 6). aios-base installs this file in /usr/lib/aios/initrd/,
# outside the host's unit path. The "aios" mkinitcpio hook copies it into the initrd and
# links it into sysroot.mount.requires/. If it fails, sysroot.mount and then
# initrd-root-fs.target fail, and that target's OnFailure=emergency.target opens the
# emergency shell.

[Unit]
Description=AIOS: prepare @root-live and @etc-live for the booted generation
DefaultDependencies=no
ConditionPathExists=/etc/initrd-release
Requires=dev-mapper-aios.device
After=dev-mapper-aios.device cryptsetup.target
Before=sysroot.mount

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/lib/aios/initrd/aios-root.sh
StandardOutput=journal+console
```

`initrd/sysroot-etc.mount`:
```ini
# Initrd only (spec §3 step 8): this boot's /etc. aios-base installs this file in
# /usr/lib/aios/initrd/. The "aios" mkinitcpio hook copies it into the initrd and links
# it into initrd-fs.target.wants/. The device and /sysroot dependencies are implicit.
# It is ordered before initrd-parse-etc.service so that service reads the generation's
# /etc/fstab rather than the empty /etc from @blank.

[Unit]
Description=AIOS: mount @etc-live at /sysroot/etc
DefaultDependencies=no
Requires=aios-root.service
After=sysroot.mount aios-root.service
Before=initrd-fs.target initrd-parse-etc.service

[Mount]
What=/dev/mapper/aios
Where=/sysroot/etc
Type=btrfs
Options=subvol=@etc-live,compress=zstd
```

- [ ] **Step 6: Verify the units**

Run: `make unit-check UNITS="initrd/aios-root.service initrd/sysroot-etc.mount"`
Expected: make echoes its commands:
```
rm -rf build/unit-check
mkdir -p build/unit-check
cp initrd/aios-root.service initrd/sysroot-etc.mount build/unit-check/
sed -i 's|^ExecStart=.*|ExecStart=/usr/bin/true|' build/unit-check/*.service
out=$(systemd-analyze verify build/unit-check/aios-root.service build/unit-check/sysroot-etc.mount 2>&1); \
rc=$?; \
if [ $rc -ne 0 ] || [ -n "$out" ]; then printf '%s\n' "$out"; exit 1; fi
```
`systemd-analyze` itself prints nothing, and the exit status is 0.

The `ExecStart` rewrite is needed. Without it, `verify` prints `aios-root.service: Command /usr/lib/aios/initrd/aios-root.sh is not executable: No such file or directory` and exits 1.

- [ ] **Step 7: Prove that `unit-check` catches warnings**

```bash
mkdir -p build/neg
sed 's/^After=/Afterr=/' initrd/aios-root.service > build/neg/aios-root.service
make unit-check UNITS=build/neg/aios-root.service
```
Expected: `…/build/unit-check/aios-root.service:…: Unknown key 'Afterr' in section [Unit], ignoring.` followed by `make: *** [Makefile:…: unit-check] Error 1`. `build/` is ignored, so nothing needs cleaning.

- [ ] **Step 8: shellcheck**

Run: `make shell-check SH_SCRIPTS=initrd/aios-root.sh BASH_SCRIPTS="initrd/install/aios tests/bats/fakes/btrfs tests/bats/fakes/record" BATS_FILES="tests/bats/aios-root.bats tests/bats/install-hook.bats"`
Expected: no diagnostics, exit 0.

- [ ] **Step 9: Commit**

```bash
git add initrd/aios-root.service initrd/sysroot-etc.mount initrd/install/aios tests/bats/install-hook.bats
git commit -m "feat(initrd): aios-root.service, sysroot-etc.mount and the aios mkinitcpio hook"
```

---

### Task 4: `aios-health` check, unit and bats tests

**Files:**
- Create: `base/aios-health.sh`, `base/aios-health.service`
- Test: `tests/bats/fakes/findmnt`, `tests/bats/aios-health.bats`

How the fake works:
- The fake `findmnt` treats mount point `M` as mounted when the file `$FAKE_MOUNTS/M` exists, for example `$FAKE_MOUNTS/var/log`.
- The file holds the `OPTIONS` column in the kernel's format, `…,subvol=/@usr-gen-0007`, with a leading slash.
- The script reaches it through `AIOS_FINDMNT`, so `PATH` is left alone.

Option matching is per comma-separated token, so:
- `errors=remount-ro` does not count as `ro`.
- `@usr-gen-00070` does not count as `@usr-gen-0007`.

The id comparison strips leading zeros with parameter expansion. `$((0008))` would be an invalid octal number in POSIX sh.

- [ ] **Step 1: Write the fake findmnt**

`tests/bats/fakes/findmnt`:
```bash
#!/usr/bin/env bash
# Fake findmnt for tests/bats/aios-health.bats.
# Mount point M counts as mounted when the file $FAKE_MOUNTS/M exists (e.g. $FAKE_MOUNTS/var/log).
# The file holds M's OPTIONS column. Supported forms:
#   findmnt -no OPTIONS M   prints the options
#   findmnt -n M            prints a findmnt-style row
# Both exit 1 when M is not mounted, like the real findmnt.
set -euo pipefail

target=""
for target in "$@"; do :; done
file="$FAKE_MOUNTS$target"
[ -f "$file" ] || exit 1

if [ "$#" -eq 3 ] && [ "$1" = -no ] && [ "$2" = OPTIONS ]; then
    cat "$file"
elif [ "$#" -eq 2 ] && [ "$1" = -n ]; then
    printf '%s /dev/mapper/aios btrfs %s\n' "$target" "$(cat "$file")"
else
    echo "fake findmnt: unsupported: $*" >&2
    exit 2
fi
```

Run: `chmod 755 tests/bats/fakes/findmnt`

- [ ] **Step 2: Write the failing tests**

`tests/bats/aios-health.bats`:
```bash
#!/usr/bin/env bats
# base/aios-health.sh against a fake findmnt (spec §3 step 11, §9).

BTRFS_OPTS="relatime,compress=zstd:3,ssd,discard=async,space_cache=v2"

setup() {
    SCRIPT="$BATS_TEST_DIRNAME/../../base/aios-health.sh"
    export AIOS_FINDMNT="$BATS_TEST_DIRNAME/fakes/findmnt"
    export FAKE_MOUNTS="$BATS_TEST_TMPDIR/mounts"
    export AIOS_CMDLINE_FILE="$BATS_TEST_TMPDIR/cmdline"
    export AIOS_GEN_FILE="$BATS_TEST_TMPDIR/generation.toml"

    mkdir -p "$FAKE_MOUNTS/var"
    mnt /usr "ro,$BTRFS_OPTS,subvolid=261,subvol=/@usr-gen-0007"
    mnt /etc "rw,$BTRFS_OPTS,subvolid=263,subvol=/@etc-live"
    mnt /persist "rw,$BTRFS_OPTS,subvolid=257,subvol=/@persist"
    mnt /home "rw,$BTRFS_OPTS,subvolid=258,subvol=/@home"
    mnt /var/log "rw,$BTRFS_OPTS,subvolid=259,subvol=/@log"
    cmdline "root=/dev/mapper/aios mount.usrflags=subvol=@usr-gen-0007,ro,compress=zstd aios.gen=0007 quiet"
    gen_file 7
}

# mnt MOUNTPOINT OPTIONS: make the fake findmnt report MOUNTPOINT as mounted.
mnt() {
    printf '%s\n' "$2" >"$FAKE_MOUNTS$1"
}

unmnt() {
    rm -f "$FAKE_MOUNTS$1"
}

cmdline() {
    printf '%s\n' "$*" >"$AIOS_CMDLINE_FILE"
}

gen_file() {
    cat >"$AIOS_GEN_FILE" <<TOML
id = $1
parent = 6
created = "2026-11-03T21:14:05Z"
manifest_commit = "3f9c2a1"
kernels = ["linux-cachyos 7.3.0-4"]
package_set_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
TOML
}

@test "healthy generation passes" {
    run "$SCRIPT"

    [ "$status" -eq 0 ]
    [ "$output" = "aios-health: generation 0007 is healthy" ]
}

@test "/usr mounted read-write fails" {
    mnt /usr "rw,$BTRFS_OPTS,subvolid=261,subvol=/@usr-gen-0007"

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [[ "$output" == "aios-health: /usr is not mounted read-only"* ]]
}

@test "/usr from another generation fails" {
    mnt /usr "ro,$BTRFS_OPTS,subvolid=260,subvol=/@usr-gen-0006"

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [[ "$output" == "aios-health: /usr is not subvolume @usr-gen-0007"* ]]
}

@test "/usr subvolume match is exact, not a prefix" {
    mnt /usr "ro,$BTRFS_OPTS,subvolid=262,subvol=/@usr-gen-00070"

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [[ "$output" == "aios-health: /usr is not subvolume @usr-gen-0007"* ]]
}

@test "/etc not from @etc-live fails" {
    mnt /etc "rw,$BTRFS_OPTS,subvolid=262,subvol=/@etc-gen-0007"

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [[ "$output" == "aios-health: /etc is not subvolume @etc-live"* ]]
}

@test "missing /persist fails" {
    unmnt /persist

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [ "$output" = "aios-health: /persist is not mounted" ]
}

@test "missing /var/log fails" {
    unmnt /var/log

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [ "$output" = "aios-health: /var/log is not mounted" ]
}

@test "generation.toml id mismatch fails" {
    gen_file 6

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [ "$output" = "aios-health: $AIOS_GEN_FILE has id 6 but the cmdline says aios.gen=0007" ]
}

@test "aios.test.fail_health=1 forces failure" {
    cmdline "root=/dev/mapper/aios aios.gen=0007 aios.test.fail_health=1"

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [ "$output" = "aios-health: forced failure (aios.test.fail_health=1 on the cmdline)" ]
}

@test "no aios.gen on the cmdline fails" {
    cmdline "root=/dev/mapper/aios quiet"

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [ "$output" = "aios-health: no generation on cmdline" ]
}

@test "conflicting aios.gen values fail" {
    cmdline "aios.gen=0007 aios.gen=0008"

    run "$SCRIPT"

    [ "$status" -eq 1 ]
    [ "$output" = "aios-health: conflicting aios.gen= values on cmdline" ]
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `make bats-check BATS_FILES=tests/bats/aios-health.bats`
Expected: `1..11`, eleven `not ok` lines, `BW01` warnings about exit code 127, then `Error 1`.

- [ ] **Step 4: Implement `aios-health.sh`**

`base/aios-health.sh`:
```sh
#!/bin/sh
# aios-health.sh: boot health check for the booted generation (spec §3 step 11).
# Run by aios-health.service, which boot-complete.target requires. Exit 0 lets
# systemd-bless-boot mark the boot entry good. Exit 1 leaves the boot counter running,
# so after 3 failed boots systemd-boot falls back to the previous entry.
#
# Environment overrides (tests only):
#   AIOS_CMDLINE_FILE  kernel cmdline         (default /proc/cmdline)
#   AIOS_GEN_FILE      generation metadata    (default /etc/aios/generation.toml)
#   AIOS_FINDMNT       findmnt executable     (default findmnt)
set -eu

CMDLINE_FILE="${AIOS_CMDLINE_FILE:-/proc/cmdline}"
GEN_FILE="${AIOS_GEN_FILE:-/etc/aios/generation.toml}"
FINDMNT="${AIOS_FINDMNT:-findmnt}"

fail() {
    printf 'aios-health: %s\n' "$*" >&2
    exit 1
}

# has_opt OPTIONS WANT: true if the comma-separated mount OPTIONS contain WANT exactly.
has_opt() {
    case ",$1," in
        *",$2,"*) return 0 ;;
        *) return 1 ;;
    esac
}

# strip_zeros DIGITS: "0007" -> "7", "0000" -> "0".
strip_zeros() {
    n=$1
    while [ "${n#0}" != "$n" ] && [ -n "${n#0}" ]; do
        n=${n#0}
    done
    printf '%s\n' "$n"
}

[ -r "$CMDLINE_FILE" ] || fail "cannot read $CMDLINE_FILE"
cmdline=$(cat "$CMDLINE_FILE")
gen=""
forced=no
set -f
for arg in $cmdline; do
    case "$arg" in
        aios.gen=*)
            value="${arg#aios.gen=}"
            if [ -n "$gen" ] && [ "$gen" != "$value" ]; then
                fail "conflicting aios.gen= values on cmdline"
            fi
            gen="$value"
            ;;
        aios.test.fail_health=1) forced=yes ;;
    esac
done
set +f

[ "$forced" = no ] || fail "forced failure (aios.test.fail_health=1 on the cmdline)"

case "$gen" in
    [0-9][0-9][0-9][0-9]) ;;
    *) fail "no generation on cmdline" ;;
esac

usr_opts=$("$FINDMNT" -no OPTIONS /usr) || fail "/usr is not mounted"
has_opt "$usr_opts" ro || fail "/usr is not mounted read-only ($usr_opts)"
has_opt "$usr_opts" "subvol=/@usr-gen-$gen" ||
    fail "/usr is not subvolume @usr-gen-$gen ($usr_opts)"

etc_opts=$("$FINDMNT" -no OPTIONS /etc) || fail "/etc is not mounted"
has_opt "$etc_opts" "subvol=/@etc-live" || fail "/etc is not subvolume @etc-live ($etc_opts)"

for mountpoint in /persist /home /var/log; do
    "$FINDMNT" -n "$mountpoint" >/dev/null || fail "$mountpoint is not mounted"
done

[ -r "$GEN_FILE" ] || fail "cannot read $GEN_FILE"
id=$(sed -n 's/^id[[:space:]]*=[[:space:]]*\([0-9][0-9]*\)[[:space:]]*$/\1/p' "$GEN_FILE" | head -n 1)
[ -n "$id" ] || fail "no id in $GEN_FILE"
[ "$(strip_zeros "$id")" = "$(strip_zeros "$gen")" ] ||
    fail "$GEN_FILE has id $id but the cmdline says aios.gen=$gen"

printf 'aios-health: generation %s is healthy\n' "$gen"
```

Run: `chmod 755 base/aios-health.sh`

- [ ] **Step 5: Run the tests to verify they pass**

Run: `make bats-check BATS_FILES=tests/bats/aios-health.bats`
Expected: `1..11`, all `ok`.

- [ ] **Step 6: Write the unit**

`base/aios-health.service`:
```ini
# Boot health check (spec §3 step 11). `aios apply` enables it in every generation.
# boot-complete.target requires it, so systemd-bless-boot marks the boot entry good only
# when the check passes. Otherwise the boot counter keeps running and systemd-boot falls
# back after 3 tries.

[Unit]
Description=AIOS: generation health check
After=local-fs.target
Before=boot-complete.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/lib/aios/aios-health.sh

[Install]
RequiredBy=boot-complete.target
```

- [ ] **Step 7: Full shell and unit checks (every listed file now exists)**

Run: `make shell-check bats-check unit-check`
Expected:
- shellcheck prints no diagnostics.
- bats prints `1..23` and 23 `ok` lines: `aios-root.bats` 1–10, `install-hook.bats` 11–12, `aios-health.bats` 13–23.
- `systemd-analyze verify` prints nothing.
- The exit status is 0.

Run: `make check`
Expected: passes. This is the first time the full gate is green.

- [ ] **Step 8: Commit**

```bash
git add base/aios-health.sh base/aios-health.service tests/bats/fakes/findmnt tests/bats/aios-health.bats
git ls-files -s base/aios-health.sh tests/bats/fakes/findmnt
```
Expected: both lines start with `100755`.

```bash
git commit -m "feat(base): aios-health boot check and unit, with bats tests"
```

---

### Task 5: `aios-base` payload

**Files:**
- Create: `base/sysctl.d/90-aios-hardening.conf`, `base/cmdline-hardening`, `base/NetworkManager/conf.d/90-aios-privacy.conf`, `base/resolved.conf.d/90-aios-dot.conf`, `base/zram-generator.conf`

These are data files, so there is nothing to test first. Each step below checks a file against the spec or against the program that reads it, all without root.

- [ ] **Step 1: sysctl (spec §5.2)**

`base/sysctl.d/90-aios-hardening.conf`:
```ini
# AIOS kernel hardening (spec §5.2). Shipped by aios-base in /usr/lib/sysctl.d/.
# Unprivileged user namespaces stay enabled: Flatpak, bubblewrap and rootless podman
# need them (documented trade-off).

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

Check that it matches the spec block exactly and that every key exists on this kernel:
````bash
awk '/^### 5.2/{f=1;next} f&&/^```/{n++; if(n==2) exit; next} f&&n==1' \
  docs/superpowers/specs/2026-11-03-base-iso-design.md \
  | diff - <(grep -E '^[a-z]' base/sysctl.d/90-aios-hardening.conf) && echo "matches §5.2"
grep -E '^[a-z]' base/sysctl.d/90-aios-hardening.conf | while read -r key _; do
  [ -e "/proc/sys/$(printf '%s' "$key" | tr . /)" ] || echo "missing: $key"
done
````
Expected: `matches §5.2`, and no `missing:` lines.

- [ ] **Step 2: Hardening cmdline (spec §5.3)**

The file is a single line with no comments, so consumers can append it verbatim. The renderer adds `lockdown=integrity` itself (§5.3), so the file must not contain it.

`base/cmdline-hardening`:
```text
init_on_alloc=1 init_on_free=1 slab_nomerge page_alloc.shuffle=1 randomize_kstack_offset=on vsyscall=none debugfs=off lsm=landlock,lockdown,yama,integrity,apparmor,bpf quiet
```

Run: `wc -l < base/cmdline-hardening; grep -c 'lockdown=' base/cmdline-hardening; sed -n 's/^\x60\(init_on_alloc.*\)\x60$/\1/p' docs/superpowers/specs/2026-11-03-base-iso-design.md | diff - base/cmdline-hardening && echo "matches §5.3"`
Expected: `1`, `0`, `matches §5.3`.

Phase 2's renderer takes this file's content as `RenderCtx.hardening_cmdline` (whitespace-separated tokens), and its test fixture `HARDENING` mirrors it. Check that the two agree:

Run: `sed -n 's/^pub const HARDENING: &str = "\(.*\)\\n";$/\1/p' aios-cli/crates/aios-render/tests/common/mod.rs | diff - base/cmdline-hardening && echo "matches the aios-render fixture"`
Expected: `matches the aios-render fixture`. On a mismatch, the spec §5.3 line is the authority. Report the drift instead of editing Phase 2's fixture, because Phase 4 must not change other crates.

- [ ] **Step 3: NetworkManager privacy (spec §4.6)**

`wifi.scan-rand-mac-address` is a `[device]` setting. The other three are connection defaults, so they go in `[connection]`.

`base/NetworkManager/conf.d/90-aios-privacy.conf`:
```ini
# AIOS network privacy defaults (spec §4.6). Shipped by aios-base in
# /usr/lib/NetworkManager/conf.d/. See NetworkManager.conf(5).

[device]
# Random MAC address while scanning for Wi-Fi networks.
wifi.scan-rand-mac-address=yes

[connection]
# Per-network stable MAC address: not the hardware address, but stable per connection.
wifi.cloned-mac-address=stable
ethernet.cloned-mac-address=stable
# Prefer temporary IPv6 addresses (RFC 4941).
ipv6.ip6-privacy=2
```

Check how NetworkManager itself merges it. `--system-config-dir` is the flag for `/usr/lib/NetworkManager/conf.d`, and the command needs no root. The paths must be absolute, because NetworkManager silently ignores a relative config dir:
```bash
mkdir -p build/nm/empty && : > build/nm/NetworkManager.conf
NetworkManager --print-config --config="$PWD/build/nm/NetworkManager.conf" \
  --config-dir="$PWD/build/nm/empty" --system-config-dir="$PWD/base/NetworkManager/conf.d" \
  | grep -vE '^#|^$'
```
Expected:
```
[main]
configure-and-quit=no
[logging]
[device]
wifi.scan-rand-mac-address=yes
[connection]
wifi.cloned-mac-address=stable
ethernet.cloned-mac-address=stable
ipv6.ip6-privacy=2
```
If `NetworkManager` is not installed on the build host, skip this check.

- [ ] **Step 4: systemd-resolved DNS over TLS (spec §4.6)**

`base/resolved.conf.d/90-aios-dot.conf`:
```ini
# AIOS DNS defaults (spec §4.6): DNS over TLS to Quad9, Cloudflare as backup.
# Shipped by aios-base in /usr/lib/systemd/resolved.conf.d/. See resolved.conf(5).

[Resolve]
DNS=9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net 1.1.1.1#cloudflare-dns.com
DNSOverTLS=yes
DNSSEC=allow-downgrade
```

Run: `grep -cE '^(DNS=9\.9\.9\.9#dns\.quad9\.net 149\.112\.112\.112#dns\.quad9\.net 1\.1\.1\.1#cloudflare-dns\.com|DNSOverTLS=yes|DNSSEC=allow-downgrade)$' base/resolved.conf.d/90-aios-dot.conf`
Expected: `3`.

- [ ] **Step 5: zram (spec §4.6, §5.5)**

`base/zram-generator.conf`:
```ini
# AIOS swap (spec §5.5): zram only, no disk swap, no hibernation.
# Shipped by aios-base in /usr/lib/systemd/. See zram-generator.conf(5).

[zram0]
zram-size = min(ram / 2, 8192)
compression-algorithm = zstd
```

Check it with the real generator against a fake root with 16 GB of RAM (`ZRAM_GENERATOR_ROOT` is the generator's own test hook):
```bash
rm -rf build/zram && mkdir -p build/zram/root/usr/lib/systemd build/zram/root/proc build/zram/out
cp base/zram-generator.conf build/zram/root/usr/lib/systemd/
printf 'MemTotal:       16000000 kB\n' > build/zram/root/proc/meminfo
: > build/zram/root/proc/cmdline
ZRAM_GENERATOR_ROOT=$PWD/build/zram/root /usr/lib/systemd/system-generators/zram-generator build/zram/out 2>&1 | grep Creating
```
Expected: `Creating unit file dev-zram0.swap (/dev/zram0 with 7812MB)`. That is 15625 MB / 2, under the 8192 MB cap. If the generator is not installed, skip this check.

- [ ] **Step 6: Commit**

```bash
git add base/sysctl.d base/cmdline-hardening base/NetworkManager base/resolved.conf.d base/zram-generator.conf
git commit -m "feat(base): hardening sysctl and cmdline, NM privacy, DNS over TLS, zram"
```

---

### Task 6: Default manifest repo and its validity test

**Files:**
- Create: `manifest/manifest.toml`, `manifest/files/{pacman.conf,mkinitcpio.conf,nftables.conf,usbguard-daemon.conf}`
- Create: `manifest/home/@USERNAME@/{zshrc,profile,authorized_keys}`, `manifest/home/@USERNAME@/{autostart,systemd-user,environment.d,bin}/.keep`, `manifest/home/@USERNAME@/environment.d/10-aios.conf`
- Test: `aios-cli/crates/aios-manifest/tests/default_manifest.rs`

How the template works:
- `manifest.toml` stays a template until the installer runs. `[users.@USERNAME@]` and `extra_cmdline = [@EXTRA_CMDLINE@]` are not valid TOML yet.
- The installer (spec §6.2 step 6) substitutes `@HOSTNAME@`, `@USERNAME@` and `@TIMEZONE@`. It replaces `@EXTRA_CMDLINE@` with a TOML string-list body, which may be empty. It also renames `home/@USERNAME@/`.
- The test performs the same substitution and calls only Phase 1 API: `parse`, `validate`, `ValidationEnv`, `Manifest::package_set`, and the public fields.

Two additions go beyond the listed `[files]` entries:
- **`/etc/resolv.conf` symlink to the resolved stub.** The `filesystem` package owns a plain `/etc/resolv.conf`, and systemd's `L! /etc/resolv.conf` tmpfiles line never replaces an existing file. Without the symlink, NetworkManager writes the DHCP servers into it and DNS over TLS (Task 5) is silently bypassed.
- **`pacman.conf` architecture lines.** They are split as `Architecture = x86_64` plus `Architecture = x86_64_v3` inside a `# BEGIN v3`/`# END v3` region. pacman accumulates repeated `Architecture` lines, so the parsed value is `x86_64 x86_64_v3`, exactly as specified. The installer's strip then removes the v3 architecture together with the v3 repos. Without this split, stripping would either leave `x86_64_v3` allowed on a CPU without v3, or remove the line entirely, and an unset `Architecture` disables pacman's architecture check altogether.

- [ ] **Step 1: Write the failing test**

`aios-cli/crates/aios-manifest/tests/default_manifest.rs`:
```rust
//! The default manifest shipped in aios-base (`manifest/` at the repo root) must be
//! valid once the installer has substituted its placeholders (spec §4.6, §6.2 step 6).

use aios_manifest::{parse, validate, Manifest, ValidationEnv};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const PLACEHOLDERS: [&str; 4] = ["@HOSTNAME@", "@USERNAME@", "@TIMEZONE@", "@EXTRA_CMDLINE@"];

fn default_manifest_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../manifest")
}

fn template() -> String {
    let path = default_manifest_dir().join("manifest.toml");
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// The installer's substitution (spec §6.2 step 6). `extra_cmdline` is a TOML string list body.
fn substitute(template: &str, extra_cmdline: &str) -> String {
    template
        .replace("@HOSTNAME@", "testhost")
        .replace("@USERNAME@", "tester")
        .replace("@TIMEZONE@", "UTC")
        .replace("@EXTRA_CMDLINE@", extra_cmdline)
}

fn copy_tree(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap();
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &to);
        } else {
            fs::copy(entry.path(), &to).unwrap();
        }
    }
}

/// Tempdir laid out like a fresh install: repo/{files, home/tester}, secrets/passwd/tester,
/// zoneinfo/UTC.
fn installed_env() -> (TempDir, ValidationEnv) {
    let src = default_manifest_dir();
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let repo = root.join("repo");
    copy_tree(&src.join("files"), &repo.join("files"));
    copy_tree(&src.join("home/@USERNAME@"), &repo.join("home/tester"));
    fs::create_dir_all(root.join("secrets/passwd")).unwrap();
    fs::write(root.join("secrets/passwd/tester"), "$y$j9T$hash\n").unwrap();
    fs::create_dir_all(root.join("zoneinfo")).unwrap();
    fs::write(root.join("zoneinfo/UTC"), "TZif").unwrap();
    let env = ValidationEnv {
        repo_root: repo,
        secrets_dir: root.join("secrets"),
        zoneinfo_dir: root.join("zoneinfo"),
    };
    (tmp, env)
}

fn parse_ok(raw: &str) -> Manifest {
    parse(raw).unwrap_or_else(|e| panic!("default manifest does not parse: {e}"))
}

#[test]
fn template_contains_every_placeholder() {
    let raw = template();
    for p in PLACEHOLDERS {
        assert!(raw.contains(p), "manifest.toml lacks placeholder {p}");
    }
}

#[test]
fn default_manifest_is_valid_after_substitution() {
    let (_tmp, env) = installed_env();
    let raw = substitute(&template(), "\"console=ttyS0,115200\"");
    let m = parse_ok(&raw);
    let errors: Vec<String> = validate(&m, &raw, &env)
        .iter()
        .map(|e| e.to_string())
        .collect();
    assert_eq!(errors, Vec::<String>::new());
    assert_eq!(m.system.hostname, "testhost");
    assert_eq!(m.system.timezone, "UTC");
    assert_eq!(
        m.kernel.extra_cmdline,
        vec!["console=ttyS0,115200".to_string()]
    );
    assert_eq!(m.users["tester"].uid, 1000);
    assert_eq!(m.files["/etc/nftables.conf"].mode_or_default(), "0600");
    assert_eq!(
        m.files["/etc/usbguard/usbguard-daemon.conf"].mode_or_default(),
        "0600"
    );
    assert!(m.services.enable.contains(&"systemd-timesyncd".to_string()));
}

#[test]
fn empty_extra_cmdline_parses() {
    let m = parse_ok(&substitute(&template(), ""));
    assert!(m.kernel.extra_cmdline.is_empty());
}

#[test]
fn default_package_set_has_cachyos_keyring_and_aios_base() {
    let m = parse_ok(&substitute(&template(), ""));
    let set = m.package_set();
    for p in [
        "cachyos-keyring",
        "aios-base",
        "aios-cli",
        "linux-cachyos",
        "linux-cachyos-lts",
    ] {
        assert!(
            set.contains(&p.to_string()),
            "package set lacks {p}: {set:?}"
        );
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `(cd aios-cli && cargo test -p aios-manifest --test default_manifest)`
Expected: `test result: FAILED. 0 passed; 4 failed`. The panics name the missing `…/aios-manifest/../../../manifest/…` paths, for example `cannot read …/manifest/manifest.toml: No such file or directory (os error 2)`.

- [ ] **Step 3: Write `manifest.toml`**

`manifest/manifest.toml`:
```toml
# AIOS system manifest: the only way to change this system (spec §4).
# Edit, review with `aios plan`, build a new generation with `aios apply`, reboot.
#
# This is the default shipped in aios-base (/usr/share/aios/defaults/manifest/).
# The installer copies it to /persist/aios/config/ and replaces @HOSTNAME@,
# @USERNAME@ and @TIMEZONE@, and @EXTRA_CMDLINE@ with a TOML string list body
# (possibly empty). Until then this file is a template, not valid TOML.

[system]
hostname = "@HOSTNAME@"
timezone = "@TIMEZONE@"
locale   = "en_US.UTF-8"
keymap   = "us"

[kernel]
default       = "linux-cachyos"
fallback      = "linux-cachyos-lts"
lockdown      = "integrity"            # "integrity" | "none" (spec §5.4)
extra_cmdline = [@EXTRA_CMDLINE@]      # appended after the AIOS hardening cmdline

[packages]
# AIOS always adds its core set (aios-cli, aios-base, btrfs-progs, cryptsetup, ...)
# and the kernels above.
install = [
  "base", "linux-firmware", "intel-ucode", "amd-ucode",
  "networkmanager", "zsh", "git", "neovim", "flatpak",
  "cachyos-keyring", "cachyos-mirrorlist", "cachyos-v3-mirrorlist",
  "pacman-contrib",
]

[services]
enable = [
  "NetworkManager", "systemd-resolved", "systemd-timesyncd", "nftables",
  "usbguard", "fwupd-refresh.timer", "apparmor",
]
disable = []
mask    = []

[files]
# Only paths under /etc. mode defaults to "0644", owner/group to "root".
"/etc/pacman.conf"                   = { source = "files/pacman.conf" }
"/etc/mkinitcpio.conf"               = { source = "files/mkinitcpio.conf" }
"/etc/nftables.conf"                 = { source = "files/nftables.conf", mode = "0600" }
"/etc/usbguard/usbguard-daemon.conf" = { source = "files/usbguard-daemon.conf", mode = "0600" }
# `aios apply` builds the initramfs and UKIs itself; pacman must never write /boot or the ESP.
"/etc/pacman.d/hooks/90-mkinitcpio-install.hook" = { symlink = "/dev/null" }
"/etc/pacman.d/hooks/60-mkinitcpio-remove.hook"  = { symlink = "/dev/null" }
# Route all lookups through systemd-resolved (DNS over TLS, 90-aios-dot.conf). The
# `filesystem` package ships a plain /etc/resolv.conf, which NetworkManager would fill
# with the DHCP servers instead.
"/etc/resolv.conf" = { symlink = "/run/systemd/resolve/stub-resolv.conf" }

[persist]
# Everything else outside /persist, /home and /var/log is gone after a reboot.
directories = [
  "/var/lib/NetworkManager", "/etc/NetworkManager/system-connections",
  "/var/lib/bluetooth", "/var/lib/flatpak", "/var/lib/systemd",
  "/var/lib/sbctl", "/var/lib/fwupd", "/var/lib/usbguard",
  "/var/lib/containers", "/var/cache/pacman/pkg",
]
files = []

[users.@USERNAME@]
uid    = 1000
groups = ["wheel", "video", "audio", "input"]
shell  = "/usr/bin/zsh"

[users.@USERNAME@.home]
# Read-only bind mounts into the home directory (spec §4.4). A trailing "/" marks a directory.
".zshrc"                 = "home/@USERNAME@/zshrc"
".profile"               = "home/@USERNAME@/profile"
".config/autostart/"     = "home/@USERNAME@/autostart/"
".config/systemd/user/"  = "home/@USERNAME@/systemd-user/"
".config/environment.d/" = "home/@USERNAME@/environment.d/"
".local/bin/"            = "home/@USERNAME@/bin/"
".ssh/authorized_keys"   = "home/@USERNAME@/authorized_keys"
```

- [ ] **Step 4: Write the managed `/etc` files**

`manifest/files/pacman.conf`:
```ini
# /etc/pacman.conf: managed by AIOS through the manifest's [files] section.
# Edit manifest/files/pacman.conf in /persist/aios/config, then `aios apply`.
#
# The package database lives inside /usr (DBPath), so packages and their database
# are always snapshotted together in @usr-gen-N (spec §2).
#
# The installer deletes every "# BEGIN v3" ... "# END v3" region when the CPU does
# not support x86-64-v3, which leaves Architecture = x86_64 and the generic repos.

[options]
DBPath       = /usr/lib/pacman/
CacheDir     = /var/cache/pacman/pkg/
LogFile      = /var/log/pacman.log
HookDir      = /etc/pacman.d/hooks/
HoldPkg      = pacman glibc
Architecture = x86_64
# BEGIN v3
Architecture = x86_64_v3
# END v3
CheckSpace
VerbosePkgLists
ParallelDownloads = 5
DownloadUser = alpm
SigLevel          = Required DatabaseOptional
LocalFileSigLevel = Optional

# Local repo with aios-cli and aios-base, built by `make repo` and seeded by the
# installer. Unsigned for v0.1 (spec §4.6, follow-up #2).
[aios-local]
SigLevel = Optional TrustAll
Server = file:///persist/aios/repo

# BEGIN v3
[cachyos-v3]
Include = /etc/pacman.d/cachyos-v3-mirrorlist

[cachyos-core-v3]
Include = /etc/pacman.d/cachyos-v3-mirrorlist

[cachyos-extra-v3]
Include = /etc/pacman.d/cachyos-v3-mirrorlist
# END v3

[cachyos]
Include = /etc/pacman.d/cachyos-mirrorlist

[core]
Include = /etc/pacman.d/mirrorlist

[extra]
Include = /etc/pacman.d/mirrorlist
```

`manifest/files/mkinitcpio.conf`:
```bash
# /etc/mkinitcpio.conf: managed by AIOS through the manifest's [files] section.
# `aios apply` runs mkinitcpio in the candidate chroot and packs the result into a
# signed UKI (spec §4.3 step 8). The pacman mkinitcpio hooks are masked.
#
# "aios" (from aios-base) must come after systemd and sd-encrypt: it adds
# aios-root.service and sysroot-etc.mount to the initrd (spec §3).

MODULES=(btrfs)
BINARIES=()
FILES=()
HOOKS=(base systemd autodetect microcode modconf kms keyboard sd-vconsole block sd-encrypt filesystems aios)
COMPRESSION="zstd"
```

`manifest/files/nftables.conf`:
```nft
#!/usr/bin/nft -f
# /etc/nftables.conf: managed by AIOS through the manifest's [files] section (mode 0600).
# Inbound and forwarded traffic is dropped unless listed here. Outbound is allowed;
# per-application outbound control comes with Sentinel (spec §5.5).

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;

        iif "lo" accept
        ct state established,related accept
        ct state invalid drop

        # ICMP essentials. Echo requests (being pinged) stay dropped.
        meta l4proto icmp icmp type { echo-reply, destination-unreachable, time-exceeded } accept

        # ICMPv6 essentials, including NDP. IPv6 does not work without these (RFC 4890).
        meta l4proto ipv6-icmp icmpv6 type {
            echo-reply, destination-unreachable, packet-too-big, time-exceeded,
            parameter-problem, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert
        } accept

        # DHCPv6 client: server/relay replies to our link-local address.
        ip6 daddr fe80::/64 udp sport 547 udp dport 546 accept
    }

    chain forward {
        type filter hook forward priority filter; policy drop;
    }

    chain output {
        type filter hook output priority filter; policy accept;
    }
}
```

The usbguard keys not named in spec §5.5 use usbguard 1.1's upstream defaults. The exception is `AuditFilePath`, which points straight into the always-mounted `/var/log` instead of a `/var/log/usbguard/` subdirectory that might not exist in the `@log` subvolume.

`manifest/files/usbguard-daemon.conf`:
```ini
# /etc/usbguard/usbguard-daemon.conf: managed by AIOS through the manifest's [files]
# section (mode 0600; usbguard refuses group/world-readable config). See
# usbguard-daemon.conf(5). Policy (spec §5.5): devices present at install are allowed,
# new HID devices are blocked, other new devices are allowed. Approve a device with
# `usbguard allow-device -p <id>`.

# Rules written by the installer; /var/lib/usbguard is persisted.
RuleFile=/var/lib/usbguard/rules.conf
RuleFolder=/etc/usbguard/rules.d/

# Devices that match no rule are blocked.
ImplicitPolicyTarget=block

# Apply the rules to devices present at daemon start and to devices inserted later.
PresentDevicePolicy=apply-policy
PresentControllerPolicy=keep
InsertedDevicePolicy=apply-policy

# New devices start deauthorized until the daemon decides.
AuthorizedDefault=none
RestoreControllerDeviceState=false
DeviceManagerBackend=uevent

# Only root and wheel (the run0 admins) may talk to the daemon.
IPCAllowedUsers=root
IPCAllowedGroups=wheel
IPCAccessControlFiles=/etc/usbguard/IPCAccessControl.d/

DeviceRulesWithPort=false

# Audit trail in the persistent /var/log (its own subvolume, always mounted).
AuditBackend=FileAudit
AuditFilePath=/var/log/usbguard-audit.log
HidePII=false
```

- [ ] **Step 5: Write the home template**

`manifest/home/@USERNAME@/zshrc`:
```zsh
# ~/.zshrc: managed by AIOS, bind-mounted read-only. Change it in the manifest repo
# (/persist/aios/config/home/<user>/zshrc), then `aios apply` and reboot.

HISTFILE=~/.zsh_history
HISTSIZE=10000
SAVEHIST=10000
setopt hist_ignore_all_dups hist_ignore_space share_history

typeset -U path
path=(~/.local/bin $path)
export PATH

PROMPT='%F{cyan}%n@%m%f %F{blue}%~%f %# '
```

`manifest/home/@USERNAME@/profile`:
```sh
# ~/.profile: managed by AIOS, bind-mounted read-only. Read by sh-compatible login shells.

case ":$PATH:" in
    *":$HOME/.local/bin:"*) ;;
    *) PATH="$HOME/.local/bin:$PATH" ;;
esac
export PATH
export EDITOR=nvim
```

`manifest/home/@USERNAME@/environment.d/10-aios.conf`:
```ini
# systemd user-session environment, managed by AIOS. See environment.d(5).
EDITOR=nvim
```

Create the empty files. `authorized_keys` starts empty, and each `.keep` lets git track the otherwise empty managed directories:
```bash
: > 'manifest/home/@USERNAME@/authorized_keys'
for d in autostart systemd-user environment.d bin; do
  mkdir -p "manifest/home/@USERNAME@/$d"
  : > "manifest/home/@USERNAME@/$d/.keep"
done
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `(cd aios-cli && cargo test -p aios-manifest --test default_manifest)`
Expected: `test result: ok. 4 passed`.

- [ ] **Step 7: Check the managed files with their real consumers (no root)**

pacman parses the config and the v3 strip behaves as intended. `pacman-conf` insists that `DBPath` exists, so point it at a scratch dir:
```bash
mkdir -p build/pacman-conf/db
sed "s|^DBPath .*|DBPath = $PWD/build/pacman-conf/db/|" manifest/files/pacman.conf > build/pacman-conf/v3.conf
pacman-conf -c build/pacman-conf/v3.conf Architecture; pacman-conf -c build/pacman-conf/v3.conf --repo-list | paste -sd' '
pacman-conf -c build/pacman-conf/v3.conf -r aios-local Server
sed '/^# BEGIN v3$/,/^# END v3$/d' build/pacman-conf/v3.conf > build/pacman-conf/generic.conf
pacman-conf -c build/pacman-conf/generic.conf Architecture; pacman-conf -c build/pacman-conf/generic.conf --repo-list | paste -sd' '
```
Expected:
```
x86_64
x86_64_v3
aios-local cachyos-v3 cachyos-core-v3 cachyos-extra-v3 cachyos core extra
file:///persist/aios/repo
x86_64
aios-local cachyos core extra
```

nftables accepts the ruleset. `unshare -rn` gives an unprivileged user plus network namespace:

Run: `unshare -rn nft -c -f manifest/files/nftables.conf && echo "nftables ok"`
Expected: `nftables ok`. If `unshare` reports `Operation not permitted` (unprivileged user namespaces disabled), skip this check and note it.

mkinitcpio sources its config as bash, and the shell snippets parse:

Run: `bash -n manifest/files/mkinitcpio.conf && zsh -n 'manifest/home/@USERNAME@/zshrc' && build/tools/shellcheck -s sh 'manifest/home/@USERNAME@/profile' && echo "syntax ok"` (use the shellcheck path from Task 1 Step 4)
Expected: `syntax ok`.

- [ ] **Step 8: Full check and commit**

Run: `make check`
Expected: passes. `default_manifest.rs` shows 4 passed, and the other aios-manifest suites are unchanged.

```bash
git add manifest/ aios-cli/crates/aios-manifest/tests/default_manifest.rs
git status --short manifest/ | wc -l
```
Expected: `13` (13 files, including four `.keep` and the empty `authorized_keys`).

```bash
git commit -m "feat(manifest): default manifest repo with a validity test"
```

---

### Task 7: PKGBUILDs and `make repo`

**Depends on Phase 3.** `aios-cli` builds `cargo build --release --locked -p aios`, so it needs the binary crate `aios-cli/crates/aios`, its workspace membership and its `Cargo.lock` entries.

**Files:**
- Create: `packaging/aios-base/PKGBUILD`, `packaging/aios-cli/PKGBUILD`
- Modify: `.gitignore`

About the PKGBUILDs:
- Both build from the working tree through `_root="$(realpath "$startdir/../..")"`, with no `source=()`.
- `make repo` sets `BUILDDIR`, so `src/` and `pkg/` normally land in `build/makepkg/`. The `.gitignore` entries cover running `makepkg` by hand inside `packaging/*/`.
- **CPU target.** CachyOS's `/etc/makepkg.conf.d/rust.conf` sets `RUSTFLAGS="-C opt-level=3 -C target-cpu=native"`, and `makepkg.conf` sets `-march=native`. The `aios-cli` `build()` therefore overrides both, so the binary runs on any x86_64 machine, not just the build host. The release profile is already `opt-level=3`.

- [ ] **Step 1: Check the Phase 3 prerequisite**

Run: `test -d aios-cli/crates/aios && grep -q 'crates/aios"' aios-cli/Cargo.toml && echo "phase 3 present"`
Expected: `phase 3 present`. Otherwise stop and report BLOCKED: "Task 7 needs Phase 3 (aios-cli/crates/aios)". Tasks 1–6 do not depend on it.

Run: `command -v makepkg repo-add fakeroot`
Expected: three paths.

- [ ] **Step 2: Ignore packaging leftovers**

Append to `.gitignore`:
```
packaging/*/src/
packaging/*/pkg/
packaging/*/*.pkg.tar.*
```

`.gitignore` (full content after the change):
```text
.superpowers/
target/
build/
out/
work/
*.qcow2
*.iso
__pycache__/
packaging/*/src/
packaging/*/pkg/
packaging/*/*.pkg.tar.*
```

- [ ] **Step 3: Write the aios-base PKGBUILD**

`packaging/aios-base/PKGBUILD`:
```bash
# aios-base: the AIOS configuration payload (spec §4.6). Configs live in /usr, so they
# are package-owned and immutable. Built from this repository by `make repo`.

pkgname=aios-base
pkgver=0.1.0
pkgrel=1
pkgdesc="AIOS base payload: hardening config, initrd hook, boot health check, default manifest"
arch=(any)
license=(GPL-3.0-or-later)
depends=(btrfs-progs systemd mkinitcpio)

_root="$(realpath "$startdir/../..")"

package() {
  local lib="$pkgdir/usr/lib"

  install -Dm644 "$_root/base/sysctl.d/90-aios-hardening.conf" \
    "$lib/sysctl.d/90-aios-hardening.conf"
  install -Dm644 "$_root/base/cmdline-hardening" "$lib/aios/cmdline-hardening"
  install -Dm755 "$_root/base/aios-health.sh" "$lib/aios/aios-health.sh"
  install -Dm644 "$_root/base/aios-health.service" "$lib/systemd/system/aios-health.service"
  install -Dm644 "$_root/base/NetworkManager/conf.d/90-aios-privacy.conf" \
    "$lib/NetworkManager/conf.d/90-aios-privacy.conf"
  install -Dm644 "$_root/base/resolved.conf.d/90-aios-dot.conf" \
    "$lib/systemd/resolved.conf.d/90-aios-dot.conf"
  install -Dm644 "$_root/base/zram-generator.conf" "$lib/systemd/zram-generator.conf"

  # Initrd pieces. The units stay outside the host's unit path; the mkinitcpio hook
  # copies them into the initrd's /usr/lib/systemd/system/.
  install -Dm755 "$_root/initrd/aios-root.sh" "$lib/aios/initrd/aios-root.sh"
  install -Dm644 "$_root/initrd/aios-root.service" "$lib/aios/initrd/aios-root.service"
  install -Dm644 "$_root/initrd/sysroot-etc.mount" "$lib/aios/initrd/sysroot-etc.mount"
  install -Dm644 "$_root/initrd/install/aios" "$lib/initcpio/install/aios"

  # Default manifest repo, copied by the installer. The whole tree is copied
  # recursively so dotfiles and the .keep files (which keep empty managed home
  # directories) are preserved without hand-listing each file.
  local defaults="$pkgdir/usr/share/aios/defaults"
  install -dm755 "$defaults"
  cp -a "$_root/manifest" "$defaults/manifest"
  chmod -R u=rwX,go=rX "$defaults/manifest"
}
```

- [ ] **Step 4: Write the aios-cli PKGBUILD**

`packaging/aios-cli/PKGBUILD`:
```bash
# aios-cli: the `aios` command (spec §4.2, §4.6). Built from this repository's Rust
# workspace by `make repo`.

pkgname=aios-cli
pkgver=0.1.0
pkgrel=1
pkgdesc="AIOS system manager: declarative manifest, generations, rollback"
arch=(x86_64)
license=(GPL-3.0-or-later)
depends=(btrfs-progs arch-install-scripts mkinitcpio systemd-ukify sbctl git whois)
makedepends=(cargo)
options=(!lto !debug)

_root="$(realpath "$startdir/../..")"

build() {
  cd "$_root/aios-cli"
  # CachyOS's makepkg.conf targets the build host's CPU (-C target-cpu=native,
  # -march=native). The package must run on any x86_64 machine.
  export RUSTFLAGS="-C target-cpu=x86-64"
  export CFLAGS="${CFLAGS//-march=native/-march=x86-64}"
  export CXXFLAGS="${CXXFLAGS//-march=native/-march=x86-64}"
  export CARGO_TARGET_DIR="$srcdir/target"
  cargo build --release --locked -p aios
}

package() {
  install -Dm755 "$srcdir/target/release/aios" "$pkgdir/usr/bin/aios"
}
```

- [ ] **Step 5: Lint the PKGBUILDs**

Run: `(cd packaging/aios-base && makepkg --printsrcinfo) && (cd packaging/aios-cli && makepkg --printsrcinfo)`
Expected:
```
pkgbase = aios-base
	pkgdesc = AIOS base payload: hardening config, initrd hook, boot health check, default manifest
	pkgver = 0.1.0
	pkgrel = 1
	arch = any
	license = GPL-3.0-or-later
	depends = btrfs-progs
	depends = systemd
	depends = mkinitcpio

pkgname = aios-base
pkgbase = aios-cli
	pkgdesc = AIOS system manager: declarative manifest, generations, rollback
	pkgver = 0.1.0
	pkgrel = 1
	arch = x86_64
	license = GPL-3.0-or-later
	makedepends = cargo
	depends = btrfs-progs
	depends = arch-install-scripts
	depends = mkinitcpio
	depends = systemd-ukify
	depends = sbctl
	depends = git
	depends = whois
	options = !lto
	options = !debug

pkgname = aios-cli
```

- [ ] **Step 6: Build the repo**

Run: `make repo`
Expected, in order:
- `==> Making package: aios-base 0.1.0-1 …`, `==> WARNING: Skipping dependency checks.`, `==> Finished making: aios-base 0.1.0-1 …`
- the same for `aios-cli`, with cargo's `Finished \`release\` profile [optimized]` in between
- repo-add's `Adding package 'build/repo/aios-base-0.1.0-1-any.pkg.tar.zst'`, `Adding package 'build/repo/aios-cli-0.1.0-1-x86_64.pkg.tar.zst'`, `Creating updated database file 'build/repo/aios-local.db.tar.gz'`

`namcap` runs only if it is installed. Its warnings are advisory.

Run: `ls build/repo`
Expected:
```
aios-base-0.1.0-1-any.pkg.tar.zst
aios-cli-0.1.0-1-x86_64.pkg.tar.zst
aios-local.db
aios-local.db.tar.gz
aios-local.files
aios-local.files.tar.gz
```

- [ ] **Step 7: Check the aios-base contents**

```bash
tar -tf build/repo/aios-base-*.pkg.tar.zst | grep -v '/$' | grep -v '^\.' | LC_ALL=C sort > build/aios-base.files
diff - build/aios-base.files <<'EOF' && echo "aios-base contents ok"
usr/lib/NetworkManager/conf.d/90-aios-privacy.conf
usr/lib/aios/aios-health.sh
usr/lib/aios/cmdline-hardening
usr/lib/aios/initrd/aios-root.service
usr/lib/aios/initrd/aios-root.sh
usr/lib/aios/initrd/sysroot-etc.mount
usr/lib/initcpio/install/aios
usr/lib/sysctl.d/90-aios-hardening.conf
usr/lib/systemd/resolved.conf.d/90-aios-dot.conf
usr/lib/systemd/system/aios-health.service
usr/lib/systemd/zram-generator.conf
usr/share/aios/defaults/manifest/files/mkinitcpio.conf
usr/share/aios/defaults/manifest/files/nftables.conf
usr/share/aios/defaults/manifest/files/pacman.conf
usr/share/aios/defaults/manifest/files/usbguard-daemon.conf
usr/share/aios/defaults/manifest/home/@USERNAME@/authorized_keys
usr/share/aios/defaults/manifest/home/@USERNAME@/authorized_keys2
usr/share/aios/defaults/manifest/home/@USERNAME@/autostart/.keep
usr/share/aios/defaults/manifest/home/@USERNAME@/bash_logout
usr/share/aios/defaults/manifest/home/@USERNAME@/bash_profile
usr/share/aios/defaults/manifest/home/@USERNAME@/bashrc
usr/share/aios/defaults/manifest/home/@USERNAME@/bin/.keep
usr/share/aios/defaults/manifest/home/@USERNAME@/environment.d/.keep
usr/share/aios/defaults/manifest/home/@USERNAME@/environment.d/10-aios.conf
usr/share/aios/defaults/manifest/home/@USERNAME@/local-share-systemd-user/.keep
usr/share/aios/defaults/manifest/home/@USERNAME@/profile
usr/share/aios/defaults/manifest/home/@USERNAME@/ssh-rc
usr/share/aios/defaults/manifest/home/@USERNAME@/systemd-user-control/.keep
usr/share/aios/defaults/manifest/home/@USERNAME@/systemd-user/.keep
usr/share/aios/defaults/manifest/home/@USERNAME@/zlogin
usr/share/aios/defaults/manifest/home/@USERNAME@/zlogout
usr/share/aios/defaults/manifest/home/@USERNAME@/zprofile
usr/share/aios/defaults/manifest/home/@USERNAME@/zshenv
usr/share/aios/defaults/manifest/home/@USERNAME@/zshrc
usr/share/aios/defaults/manifest/manifest.toml
EOF
tar -tvf build/repo/aios-base-*.pkg.tar.zst | grep -E 'aios-root\.sh|aios-health\.sh|install/aios$' | awk '{print $1, $2, $6}'
```
Expected: `aios-base contents ok`, then:
```
-rwxr-xr-x root/root usr/lib/aios/aios-health.sh
-rwxr-xr-x root/root usr/lib/aios/initrd/aios-root.sh
-rw-r--r-- root/root usr/lib/initcpio/install/aios
```

- [ ] **Step 8: Check the aios-cli package and the repo database**

```bash
tar -tf build/repo/aios-cli-*.pkg.tar.zst | grep -v '^\.'
tar -xOf build/repo/aios-cli-*.pkg.tar.zst .PKGINFO | grep -E '^(arch|depend) '
tar -xOf build/repo/aios-cli-*.pkg.tar.zst usr/bin/aios > build/aios && chmod +x build/aios && build/aios --help | head -3
tar -tzf build/repo/aios-local.db.tar.gz | LC_ALL=C sort
```
Expected:
- the package lists `usr/`, `usr/bin/`, `usr/bin/aios`
- `.PKGINFO` shows `arch = x86_64` and seven `depend =` lines (`btrfs-progs arch-install-scripts mkinitcpio systemd-ukify sbctl git whois`)
- the start of Phase 3's clap help (`Usage: aios …`)
- the repo database lists `aios-base-0.1.0-1/`, `aios-base-0.1.0-1/desc`, `aios-cli-0.1.0-1/`, `aios-cli-0.1.0-1/desc`

- [ ] **Step 9: Working tree is clean apart from the new files**

Run: `git status --short`
Expected: exactly:
```
 M .gitignore
?? packaging/
```
`packaging/aios-*/` contain only `PKGBUILD`, and `build/` is ignored.

- [ ] **Step 10: Commit**

```bash
git add .gitignore packaging/aios-base/PKGBUILD packaging/aios-cli/PKGBUILD
git commit -m "build: aios-cli and aios-base PKGBUILDs, make repo"
```

---

### Task 8: Final gate

**Files:**
- Modify: `README.md` (full content below)

- [ ] **Step 1: Update the README**

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
````

- [ ] **Step 2: Full check from a clean build directory**

Run: `rm -rf build/unit-check build/repo build/makepkg && make check && make repo`
Expected:
- `make check` passes: no fmt diff, no clippy warnings, all Rust suites pass (`default_manifest.rs` 4 passed), shellcheck silent, bats `1..23` all `ok`, `systemd-analyze verify` silent.
- `make repo` ends with `Creating updated database file 'build/repo/aios-local.db.tar.gz'`.

- [ ] **Step 3: Independent review**

Use superpowers:requesting-code-review to dispatch a reviewer subagent over `git diff <phase-4 base>..HEAD`. Point it at spec §2, §3, §4.6, §5 and §9. Ask it to focus on these risks:
- initrd ordering
- busybox portability of the two `sh` scripts
- nftables and usbguard semantics
- package paths versus the hook's paths

Fix blocking findings with tests first, then re-run Step 2.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: README development commands and layout"
git log --oneline | head -8
```
Expected: the eight Phase 4 commits on top of the Phase 3 history.

---

## Self-review

- **Spec coverage:**

  | Spec | What | Task |
  |---|---|---|
  | §2 | `@blank` is cloned to `@root-live` every boot. `DBPath = /usr/lib/pacman/`, `CacheDir`, `LogFile` | 2, 6 |
  | §3 step 4 | `HOOKS=(… sd-encrypt filesystems aios)`, `MODULES=(btrfs)` | 6 |
  | §3 step 6 | `aios-root.sh`: parse `aios.gen`, mount top level, missing-gen message, delete live/candidate subvolumes, snapshots, unmount. `aios-root.service` ordering. Emergency shell via `initrd-root-fs.target` `OnFailure=` | 2, 3 |
  | §3 step 8 | `sysroot-etc.mount` into `initrd-fs.target.wants/` | 3 |
  | §3 step 11 | `aios-health.sh` checks (ro `/usr` from `@usr-gen-N`, `/etc` from `@etc-live`, `/persist` `/home` `/var/log`, id, `fail_health`). `RequiredBy=boot-complete.target` | 4 |
  | §4.1 | default manifest: `[system] [kernel] [packages] [services] [files] [persist] [users]`, all Phase 1 rules pass | 6 |
  | §4.4 | the seven managed home entries, with sources that exist and match their kind | 6 |
  | §4.6 aios-cli | `/usr/bin/aios`, depends `btrfs-progs arch-install-scripts mkinitcpio systemd-ukify sbctl git whois` | 7 |
  | §4.6 aios-base | sysctl, cmdline, initcpio hook, health unit and script, NM, resolved, zram, `/usr/share/aios/defaults/manifest/` | 4, 5, 7 |
  | §4.6 packaging | `make repo` → `build/repo/aios-local.db.tar.gz`. `[aios-local]` `SigLevel = Optional TrustAll`, `file:///persist/aios/repo` | 6, 7 |
  | §5.2 | sysctl file, diffed against the spec block | 5 |
  | §5.3 | cmdline file, diffed against the spec line, no `lockdown=` | 5 |
  | §5.5 | nftables (drop input/forward, accept output, lo, established, ICMP/ICMPv6 + NDP, DHCPv6). usbguard (`RuleFile`, `ImplicitPolicyTarget=block`, apply-policy, `IPCAllowedGroups=wheel`). zram only | 5, 6 |
  | §9 shell | bats for `aios-root.sh` (normal boot, stale candidates, nested subvolume, missing gen, no gen, `42`, `0000`) and `aios-health.sh` (healthy, `/usr` rw, wrong subvol, `/etc` not live, missing `/persist`, id mismatch, forced failure, no gen). shellcheck | 2, 4 |
  | §9 units | `systemd-analyze verify` of the three units, failing on any output | 1, 3, 4 |
  | §9 packaging | `makepkg` in `make repo`, `namcap` if available | 7 |
  | §9 `make check` | cargo + clippy + shellcheck + bats + verify, no root | 1, 4, 8 |
  | §10 | `initrd/ base/ manifest/ packaging/ tests/bats/` | all |

- **Beyond the brief (each called out in its task):**
  - `install-hook.bats`
  - extra bats cases: first boot, half a generation, exact subvol match, `/var/log`
  - `Before=initrd-parse-etc.service`
  - the `/etc/resolv.conf` stub symlink
  - split `Architecture` lines inside the v3 markers
  - `AuditFilePath` directly in `/var/log`
  - the CPU-target override in the `aios-cli` PKGBUILD
  - sha256 and commit pinning in `make tools`
  - optional `namcap`
  - the README
- **Placeholder scan:** every file's full content is in its step, and every command lists its expected output. The only output that depends on Phase 3 is `aios --help`.
- **Type and name consistency:**
  - Env overrides match between the scripts and the tests: `AIOS_CMDLINE_FILE`, `AIOS_DEVICE`, `AIOS_TOP`, `AIOS_GEN_FILE`, `AIOS_FINDMNT`.
  - The paths the hook copies from (`/usr/lib/aios/initrd/*`) are the paths the aios-base PKGBUILD installs to (Task 7 Step 7).
  - The Makefile lists match the created files.
  - The Rust test uses only `parse`, `validate`, `ValidationEnv`, `Manifest`, `package_set`, `mode_or_default` and public fields from Phase 1.
- **Deferred:**
  - the installer's placeholder substitution and v3 strip (installer phase)
  - Phase 3's executor reading `/usr/lib/aios/cmdline-hardening` from the candidate and enabling `aios-health.service` per generation
  - the signed `aios-local` repo (follow-up #2)
