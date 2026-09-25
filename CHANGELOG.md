# Changelog

All notable changes to this project.

## [1.0.0] - 2026-09-24

### Added

- First stable release of `actix-guard-rs` 1.0.0: application-layer security middleware for actix-web, powered by `guard-core-engine` 4.0.4 (17/17 checks parity with guard-core 4.0.4, binary-noise gates)
- `GuardTransform` middleware: one engine call per request view (path, query string, headers, buffered body), 403/413/500 fail-secure responses with the ecosystem JSON `detail` shape, configurable body cap (default: engine full-scan cap), request rebuilding around the buffered payload, `catch_unwind` panic recovery
- Example apps: `examples/simple_app` and `examples/advanced_app` with Dockerfiles and docker-compose smoke stacks
- Dockerized live smoke workflow (`.github/workflows/live-smoke.yml`): compose run of `simple_app` with curl assertions of real engine behavior (XSS block, traversal block, 413 body cap, passthrough)
- Upstream drift guard (`.github/workflows/upstream-drift.yml`): daily test suite run against `guard-core-rs@master`
- Security audit workflow (`cargo deny`), release gate (fmt/clippy/test at tag on stable and MSRV 1.92, tag/version consistency), automated crates.io publish on GitHub release via `CARGO_REGISTRY_TOKEN`
- `Makefile` (`install`, `test`, `lint`, `fix`, `bump-version`, `clean`) and `.github/scripts/bump_version.py` (stdlib-only version bump across the crate, example pins, `Cargo.lock`, and a CHANGELOG scaffold)

### Changed

- `guard-core-engine` dependency pinned to the published 4.0.4 release (path dep kept for local builds and CI against a sibling `guard-core-rs` checkout)

## [Unreleased]

### Changed

- 403/413/500 short-circuit responses now carry the bare message (`Suspicious activity detected`, `Payload too large`, `Security check failed`) as `text/plain; charset=utf-8`, matching the Python family's block-response convention, instead of the JSON `{"detail":"..."}` shape
