//! # actix-guard-rs
//!
//! Application-layer security middleware for
//! [Actix Web](https://github.com/actix/actix-web) 4, powered by the
//! [guard-core-rs](https://github.com/rennf93/guard-core-rs) detection
//! engine. Part of the [Guard ecosystem](https://github.com/rennf93).
//!
//! ## Status: implemented (v0.1.0)
//!
//! [`GuardTransform`] is a working [`Transform`]
//! factory and [`GuardService`] a working [`Service`] over `ServiceRequest`.
//! The engine is
//! wired in through `guard-core-engine` (a path dependency until the engine
//! is tagged and published). Per the ecosystem boundary rules, this adapter
//! holds framework glue only: every detection decision comes from the engine.
//!
//! ## What it inspects
//!
//! One engine call per request view, mirroring the mapping used by the
//! sibling adapters (`tower-guard-rs`, `guard-core-ts`):
//!
//! | Request part | Engine context | Notes |
//! |---|---|---|
//! | Path | `url_path` | Skipped for `/` |
//! | Query string | `query_param` | Skipped when empty |
//! | Header values | `header` | Skips `sec-*` and hop-by-hop/negotiation headers (see `EXCLUDED_HEADERS` in `src/service.rs`) |
//! | Body | `request_body` | Buffered first, capped (see below) |
//!
//! The HTTP method is not fed to the engine: the engine's `detect` signature
//! takes content plus a context, and the reference adapters do not scan the
//! method either.
//!
//! ## Body cap
//!
//! Request bodies are buffered so the engine can inspect them, and the
//! buffer is bounded by [`GuardTransform::with_body_cap`]. It defaults to the
//! engine's full-scan cap (`DetectConfig::max_full_scan_bytes`, 262,144 bytes
//! in the ecosystem default). A request whose body exceeds the cap is
//! rejected with `413 Payload Too Large` rather than forwarded unscanned: the
//! engine would only ever see a truncated prefix, which would be a bypass
//! vector.
//!
//! ## Request rebuilding
//!
//! actix Web consumes a request's payload as it is read, so a body-inspecting
//! middleware must hand the next service a rebuilt request. The canonical
//! pattern used here:
//!
//! 1. Split the `ServiceRequest` with
//!    [`ServiceRequest::into_parts`](actix_web::dev::ServiceRequest::into_parts)
//!    into an `HttpRequest` and its `Payload`.
//! 2. Poll the payload to completion under the cap (`Payload` is `Unpin` and
//!    implements `Stream`, so a `poll_fn` loop buffers it without extra
//!    stream-utility dependencies).
//! 3. Rebuild with
//!    [`ServiceRequest::from_parts`](actix_web::dev::ServiceRequest::from_parts)
//!    around a fresh `Payload` built from the buffered bytes (actix Web's
//!    `HttpMessage::set_payload` would land in the same place, but the owning
//!    split/rebuild keeps the buffering future self-contained).
//!
//! The inner service therefore observes the request exactly as the client
//! sent it, body included.
//!
//! ## Responses
//!
//! | Situation | Status | Body |
//! |---|---|---|
//! | The IP gate denies the client IP (blacklisted, or a non-empty whitelist matches neither the IP nor an exemption) | `403 Forbidden` | `Forbidden` |
//! | Engine flags a view | `400 Bad Request` | `Suspicious activity detected` |
//! | Body exceeds the cap | `413 Payload Too Large` | `Payload too large` |
//! | Body read error or engine panic | `500 Internal Server Error` | `Security check failed` |
//!
//! The IP gate is optional (`GuardTransform::with_ip_gate`); when it is
//! configured, `exempt_ips` (like a whitelist match) only sets the skip state
//! on the request, never a deny path of its own - the exempt-vs-whitelist
//! contract in the engine's `ip_gate` module. The Rust family ships no rate
//! limiter, user-agent filter, cloud-provider blocker, or violation counter
//! yet, so there is nothing for the flag to skip; detection always scans
//! every request, exempt or not, per the contract.
//!
//! These bodies follow the ecosystem's plain-text convention (the bare
//! message, `text/plain; charset=utf-8`, same as the Python family) but
//! the adapter is deliberately **fail-secure**, unlike the TypeScript
//! adapters whose check pipeline logs and skips on error: any failure to
//! complete the security check results in `500`, never in an uninspected
//! passthrough.
//!
//! A panic is caught with [`std::panic::catch_unwind`] on the worker thread,
//! so the default panic hook still prints. `panic = "abort"` in the release
//! profile disables that recovery, because the process dies before the guard
//! can respond.
//!
//! ## Example
//!
//! ```
//! use actix_guard_rs::{default_config, GuardTransform};
//! use actix_web::{test, web, App, HttpResponse};
//!
//! # let runtime = actix_web::rt::System::new();
//! # runtime.block_on(async {
//! let service = test::init_service(
//!     App::new()
//!         .wrap(GuardTransform::new(default_config()))
//!         .route("/", web::post().to(|| async { HttpResponse::Ok().finish() })),
//! )
//! .await;
//!
//! // Benign traffic passes through untouched.
//! let request = test::TestRequest::post()
//!     .uri("/")
//!     .set_payload("benign body")
//!     .to_request();
//! let response = test::call_service(&service, request).await;
//! assert_eq!(response.status(), actix_web::http::StatusCode::OK);
//!
//! // Attack traffic is blocked by the engine.
//! let request = test::TestRequest::get()
//!     .uri("/files/../../etc/passwd")
//!     .to_request();
//! let response = test::call_service(&service, request).await;
//! assert_eq!(response.status(), actix_web::http::StatusCode::BAD_REQUEST);
//! # });
//! ```

mod response;
mod service;

use actix_web::Error;
use actix_web::body::MessageBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
pub use guard_core_engine::detect::{DetectConfig, DetectVerdict, Threat};
pub use guard_core_engine::ip_gate::{
    IpGateConfig, IpGateDecision, IpGateDenial, IpGateError, IpGateVerdict,
};

pub use crate::response::{BLOCKED_MESSAGE, FAILURE_MESSAGE, FORBIDDEN_MESSAGE, OVERSIZE_MESSAGE};
pub use crate::service::GuardService;

/// Reference default detection configuration.
///
/// The engine's [`DetectConfig`] carries no `Default` impl, so the adapter
/// pins the ecosystem defaults here. They are the values the conformance
/// corpus records for the reference implementation:
///
/// | Knob | Value |
/// |---|---|
/// | `max_content_length` | `10_000` |
/// | `max_full_scan_bytes` | `262_144` |
/// | `preserve_attack_patterns` | `true` |
/// | `semantic_threshold` | `0.7` |
/// | `threat_score_threshold` | `1.0` |
/// | `binary_min_run_length` | `16` |
///
/// # Example
///
/// ```
/// let config = actix_guard_rs::default_config();
/// let transform = actix_guard_rs::GuardTransform::new(config);
/// # let _ = transform;
/// ```
#[must_use]
pub const fn default_config() -> DetectConfig {
    DetectConfig {
        max_content_length: 10_000,
        max_full_scan_bytes: 262_144,
        preserve_attack_patterns: true,
        semantic_threshold: 0.7,
        threat_score_threshold: 1.0,
        binary_min_run_length: 16,
    }
}

/// Engine entry point stored in the transform.
///
/// Indirection exists so unit tests can substitute a panicking detector and
/// exercise the fail-secure path; production builds always store
/// [`guard_core_engine::detect::detect`].
pub(crate) type DetectFn = fn(&str, &str, &DetectConfig) -> DetectVerdict;

/// Screens actix Web requests with the Guard engine before they reach the
/// wrapped service.
///
/// Register it with [`App::wrap`](actix_web::App::wrap):
///
/// ```ignore
/// App::new().wrap(GuardTransform::new(default_config()))
/// ```
///
/// The compiled example in the crate docs shows the full setup.
///
/// The transform applies to every request routed after it. Wrapped services
/// are shared through an `Rc` (see [`GuardService`]); actix Web builds its
/// service tree per worker, so this is free and never crosses threads.
#[derive(Debug, Clone)]
pub struct GuardTransform {
    config: DetectConfig,
    body_cap: usize,
    ip_gate: Option<IpGateConfig>,
    detect_fn: DetectFn,
}

impl GuardTransform {
    /// Build a transform from an engine [`DetectConfig`].
    ///
    /// The body buffering cap starts at `config.max_full_scan_bytes`, and no
    /// IP gate is configured (one can be added with
    /// [`GuardTransform::with_ip_gate`]).
    #[must_use]
    pub fn new(config: DetectConfig) -> Self {
        Self {
            config,
            body_cap: config.max_full_scan_bytes,
            ip_gate: None,
            detect_fn: guard_core_engine::detect::detect,
        }
    }

    /// Build a transform with [`default_config`].
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(default_config())
    }

    /// Replace the body buffering cap, in bytes.
    ///
    /// A body larger than the cap is rejected with `413 Payload Too Large`.
    /// A cap of `0` rejects every request that carries a non-empty body.
    ///
    /// # Example
    ///
    /// ```
    /// let transform = actix_guard_rs::GuardTransform::with_defaults()
    ///     // Reject bodies larger than 1 MiB with 413 instead of buffering more.
    ///     .with_body_cap(1_048_576);
    /// # let _ = transform;
    /// ```
    #[must_use]
    pub fn with_body_cap(mut self, body_cap: usize) -> Self {
        self.body_cap = body_cap;
        self
    }

    /// Install the global IP gate: a `whitelist`/`blacklist`/`exempt_ips`
    /// config built with [`IpGateConfig::new`] (which fails closed on an
    /// invalid entry).
    ///
    /// The gate runs before body buffering and before detection: an IP on the
    /// `blacklist` is denied with `403 Forbidden`, and so is any IP when a
    /// non-empty `whitelist` matches neither it nor an `exempt_ips` entry. A
    /// passed request gets the gate's [`IpGateDecision`] inserted into the
    /// request extensions, so downstream handlers can read the skip state
    /// (`is_whitelisted` / `is_exempt`). The client IP is the request's peer
    /// address; a request without one is not attributed and goes through
    /// detection unconditionally - detection still screens every request,
    /// exempt or not.
    ///
    /// # Example
    ///
    /// ```
    /// use actix_guard_rs::{GuardTransform, IpGateConfig};
    ///
    /// let gate = IpGateConfig::new(
    ///     [] as [&str; 0],
    ///     ["203.0.113.9"],
    ///     ["198.51.100.0/28"],
    /// )
    /// .expect("valid lists");
    /// let transform = GuardTransform::new(actix_guard_rs::default_config()).with_ip_gate(gate);
    /// # let _ = transform;
    /// ```
    #[must_use]
    pub fn with_ip_gate(mut self, ip_gate: IpGateConfig) -> Self {
        self.ip_gate = Some(ip_gate);
        self
    }

    pub(crate) const fn config(&self) -> &DetectConfig {
        &self.config
    }

    pub(crate) const fn body_cap(&self) -> usize {
        self.body_cap
    }

    pub(crate) const fn ip_gate(&self) -> Option<&IpGateConfig> {
        self.ip_gate.as_ref()
    }

    pub(crate) const fn detect_fn(&self) -> DetectFn {
        self.detect_fn
    }

    /// Substitute the detector. Test-only: exercises the fail-secure path.
    #[cfg(test)]
    pub(crate) fn with_detect_fn(mut self, detect_fn: DetectFn) -> Self {
        self.detect_fn = detect_fn;
        self
    }
}

impl<S, B> Transform<S, ServiceRequest> for GuardTransform
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse;
    type Error = Error;
    type InitError = ();
    type Transform = GuardService<S>;
    type Future = std::future::Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        std::future::ready(Ok(GuardService::new(service, self.clone())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_matches_corpus_knobs() {
        let config = default_config();
        assert_eq!(config.max_content_length, 10_000);
        assert_eq!(config.max_full_scan_bytes, 262_144);
        assert!(config.preserve_attack_patterns);
        assert!((config.semantic_threshold - 0.7).abs() < f64::EPSILON);
        assert!((config.threat_score_threshold - 1.0).abs() < f64::EPSILON);
        assert_eq!(config.binary_min_run_length, 16);
    }

    #[test]
    fn body_cap_defaults_to_full_scan_cap_and_is_overridable() {
        let transform = GuardTransform::new(default_config());
        assert_eq!(transform.body_cap(), 262_144);
        let transform = transform.with_body_cap(1024);
        assert_eq!(transform.body_cap(), 1024);
    }
}
