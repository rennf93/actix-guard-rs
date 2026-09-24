# actix-guard-rs

Application-layer security middleware for [actix-web](https://github.com/actix/actix-web) 4, powered by the [guard-core-rs](https://github.com/rennf93/guard-core-rs) detection engine. Part of the [guard ecosystem](https://github.com/rennf93).

Docs: <https://rennf93.github.io/actix-guard-rs/>

**Status:** Released. Version 1.0.0, published to crates.io. `GuardTransform` and `GuardService` are working actix-web middleware, screened by the engine.

## About

The guard ecosystem provides application-layer API security middleware across multiple languages and frameworks:

- **Python**: [fastapi-guard](https://github.com/rennf93/fastapi-guard), [flaskapi-guard](https://github.com/rennf93/flaskapi-guard), [djapi-guard](https://github.com/rennf93/djapi-guard), [tornadoapi-guard](https://github.com/rennf93/tornadoapi-guard)
- **TypeScript**: guard-core-ts with adapters for Express, Fastify, Hono, NestJS
- **Rust**: [guard-core-rs](https://github.com/rennf93/guard-core-rs) with adapters for [tower](https://github.com/rennf93/tower-guard-rs), [axum](https://github.com/rennf93/axum-guard-rs), [actix-web](https://github.com/rennf93/actix-guard-rs) (this repo), and [rocket](https://github.com/rennf93/rocket-guard-rs)

Per the ecosystem boundary rules, this crate holds framework glue only: every detection decision comes from the engine.

## Usage

```rust
use actix_guard_rs::{default_config, GuardTransform};
use actix_web::{App, HttpServer};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .wrap(GuardTransform::new(default_config()))
            .route("/", actix_web::web::to(|| async { "ok" }))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
```

The full crate documentation is in [`src/lib.rs`](src/lib.rs) (build it with `cargo doc --open`).

## What it inspects

One engine call per request view, mirroring the mapping used by the sibling adapters:

| Request part | Engine context | Notes |
|---|---|---|
| Path | `url_path` | Skipped for `/` |
| Query string | `query_param` | Skipped when empty |
| Header values | `header` | Skips `sec-*` and the negotiation/routing headers (`Host`, `User-Agent`, `Accept`, `Accept-Encoding`, `Connection`, `Origin`, `Referer`) |
| Body | `request_body` | Buffered first, capped |

The HTTP method is not fed to the engine: the engine's `detect(content, context, config)` takes content plus a context, and the reference adapters do not scan the method either.

## Responses

| Situation | Status | Body |
|---|---|---|
| Engine flags a view | `403 Forbidden` | `{"detail":"Suspicious activity detected"}` |
| Body exceeds the cap | `413 Payload Too Large` | `{"detail":"Payload too large"}` |
| Body read error or engine panic | `500 Internal Server Error` | `{"detail":"Security check failed"}` |

The bodies mirror the ecosystem's JSON `detail` error shape (same as the Python and TypeScript adapters), but the adapter is deliberately **fail-secure**: unlike the TypeScript adapters, whose check pipeline logs and skips on error, any failure to complete the security check answers `500`, never an uninspected passthrough.

Engine panics are caught with `catch_unwind` on the worker thread, so a detected panic still produces a response instead of unwinding out of the request future. `panic = "abort"` in the release profile disables that recovery.

## Body cap

Request bodies are buffered so the engine can inspect them, and the buffer is bounded. The cap defaults to the engine's full-scan cap (`DetectConfig::max_full_scan_bytes`, 262 144 bytes in the ecosystem default) and is configurable:

```rust
let transform = actix_guard_rs::GuardTransform::with_defaults()
    .with_body_cap(1_048_576);
```

A body larger than the cap is rejected with `413` rather than forwarded unscanned: the engine would only ever see a truncated prefix, which would be a bypass vector.

## Request rebuilding

actix Web consumes a request's payload as it is read, so the middleware buffers the body and hands the next service a rebuilt `ServiceRequest` (`into_parts`, buffer under the cap, `from_parts` around the buffered bytes). The wrapped service observes the request exactly as the client sent it, body included. The next service is shared through an `Rc`: actix Web builds its service tree per worker on single-threaded event loops, so this is free and never crosses threads.

## Engine dependency

The Cargo.toml pins `guard-core-engine` 4.0.4, published to crates.io, and also carries a path pointing at the engine crate inside a sibling `guard-core-rs` checkout (`../guard-core-rs/crates/guard-core-engine`) so local builds and CI compile the engine from source; consumers installing the crate from the registry resolve the engine normally. CI checks out `rennf93/guard-core-rs` (see [`.github/workflows/ci.yml`](.github/workflows/ci.yml)), mirroring the sibling adapter pattern in `tower-guard-rs`.

The engine crate is `guard-core-engine` rather than the `guard-core-rs` facade because the facade currently re-exports only `compiler`, `preprocessor`, and `semantic`; `detect` (the entry point this adapter uses) is not re-exported there yet.

## Development

- MSRV: 1.92 (matches guard-core-rs); edition 2024
- Requires a sibling `guard-core-rs` checkout at `../guard-core-rs`

```bash
cargo check --all-targets
cargo test
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
```

CI (`.github/workflows/ci.yml`) runs the same checks on stable plus an MSRV 1.92 job, checking out `guard-core-rs` first so the path dependency resolves.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
