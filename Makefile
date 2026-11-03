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
	! grep -qE 'AIOS_(FAKE_RUNNER|TEST_PASSWORD)' aios-cli/target/release/aios

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
