# Build / install / test convenience targets.
#
# Default install location is ~/.local/bin (already on the typical macOS
# PATH). Override with INSTALL_ROOT=/usr/local etc.

INSTALL_ROOT ?= $(HOME)/.local
INSTALL_BIN   := $(INSTALL_ROOT)/bin/ephemwork

BASTION_TARGET := aarch64-unknown-linux-musl
BASTION_BIN    := target/$(BASTION_TARGET)/release/ephemwork-bastion-server

.PHONY: build test install update uninstall fmt clippy bastion-binary bastion-upload

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

# Cross-compile the bastion-server for Linux arm64 (the t4g.nano host).
# Uses cargo-zigbuild because cross 0.2.5 has an Apple Silicon bug.
# Requires `brew install zig` and `cargo install --locked cargo-zigbuild`.
bastion-binary:
	cargo zigbuild --release --target $(BASTION_TARGET) -p ephemwork-bastion-server
	@echo "Built: $(BASTION_BIN)"

# Upload the bastion-server binary to the per-project S3 bucket the
# bastion's user-data downloads from. Override BUCKET / KEY / PROFILE
# to target a different deployment, e.g.:
#   make bastion-upload BUCKET=other-ops PROFILE=other-aws
BUCKET  ?= motocred-ephemwork-ops
KEY     ?= ephemwork-bastion-server
PROFILE ?= motocred
REGION  ?= us-east-1

bastion-upload: bastion-binary
	aws s3 cp $(BASTION_BIN) s3://$(BUCKET)/$(KEY) \
	  --profile $(PROFILE) --region $(REGION)
	@echo "Uploaded: s3://$(BUCKET)/$(KEY)"
