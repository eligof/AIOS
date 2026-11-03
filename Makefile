export PATH := $(HOME)/.cargo/bin:$(PATH)
CARGO ?= cargo
SUDO ?= sudo
PYTHON ?= python3

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
	installer/lib/network.sh installer/lib/cpu.sh installer/lib/manifest.sh \
	installer/lib/skeleton.sh installer/lib/secrets.sh installer/lib/usbguard.sh \
	installer/lib/boot.sh installer/lib/keyring.sh installer/lib/cleanup.sh
# Scripts that source the installer libraries; shellcheck follows the sources (-x).
INSTALLER_SCRIPTS := installer/aios-install installer/gen-keys.sh
SH_SCRIPTS := initrd/aios-root.sh base/aios-health.sh
BASH_SCRIPTS := initrd/install/aios tests/bats/fakes/btrfs tests/bats/fakes/record \
	tests/bats/fakes/findmnt tests/bats/fakes/installer iso/profiledef.sh iso/build-profile.sh \
	$(INSTALLER_LIBS)
BATS_FILES := tests/bats/aios-root.bats tests/bats/install-hook.bats tests/bats/aios-health.bats \
	tests/bats/installer-config.bats tests/bats/installer-disk.bats \
	tests/bats/installer-target.bats tests/bats/installer-keys.bats \
	tests/bats/installer-dryrun.bats tests/bats/iso-profile.bats tests/bats/makefile.bats
UNITS := initrd/aios-root.service initrd/sysroot-etc.mount base/aios-health.service \
	iso/airootfs/etc/systemd/system/aios-install-auto.service

# The ISO (spec §6.1): iso/ is the profile, iso-build/ the generated copy mkarchiso builds.
ISO_BUILD := iso-build
ISO_WORK := build/iso-work
ISO_OUT := out
# Clear the work directory: with sudo, or with SUDO= in a user namespace, as unprivileged
# mkarchiso leaves files owned by the user's subordinate ids (/etc/subuid) that only a
# namespace mapping them can delete. rm fails with EBUSY on mounts an interrupted build left.
ISO_RM_WORK = $(if $(SUDO),$(SUDO),unshare --map-auto --map-root-user) rm -rf --one-file-system \
	$(ISO_WORK) || { \
	echo 'If rm said "Device or resource busy", an interrupted build left mounts under $(ISO_WORK).'; \
	echo 'Unmount them with "$(strip $(SUDO) umount -R) MOUNTPOINT" (findmnt lists them), then run make again.'; \
	exit 1; } >&2

.PHONY: check rust-check release-check shell-check bats-check unit-check e2e-unit tools repo \
	keys iso-build iso iso-check clean-iso e2e FORCE

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
	$(check-release-bin)

# The shipped binary reads no AIOS_* variable at all, so any AIOS_ string in it means an
# override leaked into the release build. Only grep's "no match" (status 1) passes: a read
# error (2) proves nothing. `make release-check` checks a binary already built.
RELEASE_BIN ?= aios-cli/target/release/aios
define check-release-bin
	test -s $(RELEASE_BIN)
	grep -q AIOS_ $(RELEASE_BIN); rc=$$?; [ $$rc -eq 1 ] || { \
		echo "$(RELEASE_BIN): grep -q AIOS_ exited $$rc (0: an AIOS_ string is in it)" >&2; \
		exit 1; }
endef

release-check:
	$(check-release-bin)

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

# The venv is keyed on the Python minor version: build/venv.python holds it and changes only
# when the version does, so a Python upgrade rebuilds the venv from scratch.
build/venv.python: FORCE
	+@mkdir -p $(@D)
	+@v=$$($(PYTHON) -c 'import sys;print(sys.version_info[:2])') && \
		{ [ "$$v" = "$$(cat $@ 2>/dev/null)" ] || echo "$$v" >$@; }

build/venv/bin/pytest: build/venv.python tests/e2e/requirements.txt
	rm -rf build/venv
	$(PYTHON) -m venv build/venv
	build/venv/bin/pip install -q --require-hashes --only-binary=:all: -r tests/e2e/requirements.txt
	touch $@

FORCE:

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
	$(ISO_RM_WORK)
	$(SUDO) mkarchiso -v -w $(ISO_WORK) -o $(ISO_OUT) $(ISO_BUILD)/

# Static profile checks, no build and no root.
iso-check: tools
	$(BATS) tests/bats/iso-profile.bats

clean-iso:
	rm -rf $(ISO_BUILD)
	if [ -e $(ISO_WORK) ]; then $(ISO_RM_WORK); fi

# Install the newest out/aios-*.iso into a VM and run spec §1 (a)-(g). No root, about an
# hour. A failed run keeps the VM disk in build/e2e/; E2E_ARGS=--keep-vm keeps it after a pass too.
E2E_ARGS ?=
e2e: tools
	cd tests && $(PYTHON) -m e2e.vm
	$(PYTEST) -p no:cacheprovider -v -rs tests/e2e/test_e2e.py $(E2E_ARGS)
