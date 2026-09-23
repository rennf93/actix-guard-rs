.PHONY: install test lint fix bump-version clean

# Install the workspace (adapter crate plus the example apps)
install:
	cargo build --workspace

# Run the test suite (adapter units, example apps, doc tests)
test:
	cargo test --workspace

# Lint: format check + clippy with warnings denied (mirrors CI)
lint:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets -- -D warnings

# Auto-fix formatting and clippy suggestions where possible
fix:
	cargo fmt --all
	cargo clippy --workspace --all-targets --fix --allow-dirty

# Bump the adapter version across the files that must stay in sync:
#   make bump-version VERSION=1.0.1
bump-version:
ifndef VERSION
	$(error VERSION is required. Usage: make bump-version VERSION=x.y.z)
endif
	python3 .github/scripts/bump_version.py $(VERSION)

# Clean build artifacts
clean:
	cargo clean
