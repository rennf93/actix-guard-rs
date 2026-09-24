# API reference

The public surface of `actix_guard_rs` `1.0.0`. The full crate documentation
is also in `src/lib.rs` (build it with `cargo doc --open`).

## Middleware

### `GuardTransform`

The actix-web middleware entry point. `GuardTransform` implements
`Transform<ServiceRequest>`; register it with
`App::wrap` (or a `web::scope`'s `wrap`) so every request routed after it is
screened before it reaches the wrapped service.

```rust
use actix_guard_rs::{default_config, GuardTransform};
use actix_web::{App, web};

let app = App::new().wrap(GuardTransform::new(default_config())).route(
    "/",
    web::to(|| async { "ok" }),
);
```

Constructors and builders:

| Method | Description |
|---|---|
| `GuardTransform::new(config: DetectConfig)` | Build a transform from an engine `DetectConfig`. The body buffering cap starts at `config.max_full_scan_bytes` |
| `GuardTransform::with_defaults()` | Build a transform with `default_config()` |
| `.with_body_cap(body_cap: usize)` | Replace the body buffering cap, in bytes. A body larger than the cap is rejected with `413`. A cap of `0` rejects every request that carries a non-empty body |

The transform clones into a per-worker `GuardService`; actix Web builds its
service tree per worker on single-threaded event loops, and the wrapped
service is shared through an `Rc`, so this never crosses threads.

### `GuardService`

The `Service` produced by `GuardTransform`. It screens a `ServiceRequest` by
running one engine call per request view and, on a clean pass, hands the next
service a rebuilt request whose body is byte-identical to what the client
sent (actix Web consumes the payload as it is read, so the middleware buffers
it under the cap and rebuilds the request).

## Configuration

### `default_config()`

Returns the reference default `DetectConfig`. The engine's `DetectConfig`
carries no `Default` impl, so the adapter pins the ecosystem defaults here;
they are the values the engine conformance corpus records:

| Knob | Value |
|---|---|
| `max_content_length` | `10_000` |
| `max_full_scan_bytes` | `262_144` |
| `preserve_attack_patterns` | `true` |
| `semantic_threshold` | `0.7` |
| `threat_score_threshold` | `1.0` |

### `DetectConfig`

Re-exported from `guard_core_engine::detect`. Fields:

| Field | Type | Meaning |
|---|---|---|
| `max_content_length` | `usize` | Semantic budget and truncation budget |
| `max_full_scan_bytes` | `usize` | Preprocessor full-scan cap (also the default body cap) |
| `preserve_attack_patterns` | `bool` | Keep attack patterns in the processed view |
| `semantic_threshold` | `f64` | Semantic analysis threshold |
| `threat_score_threshold` | `f64` | Threat score threshold for a verdict |

A custom configuration:

```rust
use actix_guard_rs::DetectConfig;

let config = DetectConfig {
    max_content_length: 10_000,
    max_full_scan_bytes: 262_144,
    preserve_attack_patterns: true,
    semantic_threshold: 0.7,
    threat_score_threshold: 1.0,
};
```

## Behavior

### What it inspects

One engine call per request view:

| Request part | Engine context | Notes |
|---|---|---|
| Path | `url_path` | Skipped for `/` |
| Query string | `query_param` | Skipped when empty |
| Header values | `header` | Skips `sec-*` and the negotiation/routing headers (`Host`, `User-Agent`, `Accept`, `Accept-Encoding`, `Connection`, `Origin`, `Referer`) |
| Body | `request_body` | Buffered first, capped |

The HTTP method is not scanned.

### Responses

| Situation | Status | Body |
|---|---|---|
| Engine flags a view | `403 Forbidden` | `{"detail":"Suspicious activity detected"}` |
| Body exceeds the cap | `413 Payload Too Large` | `{"detail":"Payload too large"}` |
| Body read error or engine panic | `500 Internal Server Error` | `{"detail":"Security check failed"}` |

The adapter is fail-secure: any failure to complete the security check
answers `500`, never an uninspected passthrough. Engine panics are caught
with `catch_unwind` on the worker thread (note that `panic = "abort"` in a
release profile disables that recovery).

### Constants

Re-exported refusal message bodies:

| Constant | Value |
|---|---|
| `BLOCKED_MESSAGE` | `"Suspicious activity detected"` |
| `OVERSIZE_MESSAGE` | `"Payload too large"` |
| `FAILURE_MESSAGE` | `"Security check failed"` |

### Engine re-exports

`DetectConfig`, `DetectVerdict`, and `Threat` are re-exported from
`guard_core_engine::detect`. A `DetectVerdict` carries `is_threat`, a
`threat_score`, and the list of `Threat` findings (regex or semantic).
