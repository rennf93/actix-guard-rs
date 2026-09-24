# Installation

## Requirements

- Rust 1.92 or later (the crate uses edition 2024)
- actix-web 4

## Add the crate

```bash
cargo add actix-guard-rs
```

or add it to your `Cargo.toml` directly:

```toml
[dependencies]
actix-guard-rs = "1.0.0"
actix-web = "4"
```

`actix-guard-rs` `1.0.0` depends on `guard-core-engine` `4.0.4`, the published
detection engine crate. The adapter's version pin stays in lockstep with the
published engine release.

## Verify the installation

A minimal program that wires the middleware and serves one route:

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

With the server running:

```bash
curl -i http://127.0.0.1:8080/
curl -i 'http://127.0.0.1:8080/?cmd=$(whoami)'
```

The first request answers `200 OK`; the second is blocked by the engine with
`403 Forbidden` and a `{"detail":"Suspicious activity detected"}` body.

## Building from source

The repository itself consumes the engine as a local path dependency on a
sibling `guard-core-rs` checkout (see the repository README), so building the
repository workspace locally requires that checkout to exist. Downstream
applications that depend on the published crate are not affected: crates.io
resolves `guard-core-engine` automatically.
