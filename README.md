# actix-guard-rs

Application-layer security middleware for [actix-web](https://github.com/actix/actix-web). Part of the [guard ecosystem](https://github.com/rennf93).

**Status:** Scaffold. Reserved namespace; implementation pending. See [guard-core-rs](https://github.com/rennf93/guard-core-rs) for the reference engine and roadmap.

## About

The guard ecosystem provides application-layer API security middleware across multiple languages and frameworks:

- **Python**: [fastapi-guard](https://github.com/rennf93/fastapi-guard), [flaskapi-guard](https://github.com/rennf93/flaskapi-guard), [dj-api-guard](https://github.com/rennf93/dj-api-guard), [tornado-api-guard](https://github.com/rennf93/tornado-api-guard)
- **TypeScript**: guard-core-ts with adapters for Express, Fastify, Hono, NestJS
- **Rust**: guard-core-rs (in development) with adapters for tower, axum, actix-web, rocket

## Development

This repo is a CI-governed scaffold: no engine integration yet, no dependencies.

- MSRV: 1.92 (matches guard-core-rs)
- Planned integration surface: actix-web `Transform` + `Service` middleware (see the crate docs in `src/lib.rs`)

```bash
cargo check
cargo test
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
```

CI (`.github/workflows/ci.yml`) runs the same checks on stable plus an MSRV 1.92 job.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
