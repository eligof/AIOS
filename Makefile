export PATH := $(HOME)/.cargo/bin:$(PATH)
CARGO ?= cargo

.PHONY: check rust-check

check: rust-check

rust-check:
	cd aios-cli && $(CARGO) fmt --all -- --check
	cd aios-cli && $(CARGO) clippy --workspace --all-targets -- -D warnings
	cd aios-cli && $(CARGO) test --workspace
