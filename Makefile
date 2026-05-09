# Build / install / test convenience targets.
#
# Default install location is ~/.local/bin (already on the typical macOS
# PATH). Override with INSTALL_ROOT=/usr/local etc.

INSTALL_ROOT ?= $(HOME)/.local
INSTALL_BIN   := $(INSTALL_ROOT)/bin/ephemwork

.PHONY: build test install update uninstall fmt clippy

build:
	cargo build --workspace

test:
	cargo test --workspace

# Install (or reinstall) the laptop CLI into $(INSTALL_ROOT)/bin.
# `--force` overwrites any prior copy. Cargo reuses ./target so subsequent
# installs are incremental.
install:
	cargo install --path . --root $(INSTALL_ROOT) --force
	@echo ""
	@echo "Installed: $(INSTALL_BIN)"
	@command -v ephemwork >/dev/null 2>&1 \
	 && echo "ephemwork is on PATH." \
	 || echo "WARNING: $(INSTALL_ROOT)/bin is not on your PATH."

# Alias so re-running after a code change reads naturally.
update: install

uninstall:
	rm -f $(INSTALL_BIN)
	@echo "Removed $(INSTALL_BIN)"

fmt:
	cargo fmt --all

clippy:
	cargo clippy --workspace --all-targets -- -D warnings
