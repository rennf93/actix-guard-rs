//! # actix-guard-rs
//!
//! Application-layer security middleware for
//! [Actix Web](https://github.com/actix/actix-web), part of the
//! [Guard ecosystem](https://github.com/rennf93).
//!
//! ## Status: scaffold
//!
//! This crate is an intentionally minimal scaffold. The Guard Rust engine
//! ([guard-core-rs](https://github.com/rennf93/guard-core-rs)) is not yet a
//! published, consumable crate, so there is no integration code here yet.
//! What this scaffold establishes is package metadata, CI governance, and
//! the integration contract documented below, so the engine can be wired in
//! with minimal friction.
//!
//! Per the ecosystem boundary rules, adapter crates hold all framework glue
//! and no security logic: detection, rate limiting, and IP policy live in
//! the engine, never here.
//!
//! ## Planned integration: `Transform` + `Service`
//!
//! Actix Web middleware is built from two cooperating pieces, both defined
//! by `actix-service` and re-exported through `actix-web`:
//!
//! 1. A factory type implementing `Transform`. Actix Web calls
//!    `Transform::new_transform` once per worker to turn the factory into
//!    the per-connection middleware service.
//! 2. The middleware service itself, implementing `Service`. Its `call`
//!    receives each `ServiceRequest`, runs the Guard pipeline (IP
//!    reputation, rate limiting, penetration-attempt detection, security
//!    headers), and either short-circuits with a Guard-generated error
//!    response or forwards to the wrapped service, inspecting the
//!    `ServiceResponse` on the way out.
//!
//! The adapter will expose the factory roughly as follows (illustrative
//! only; the engine API does not exist yet):
//!
//! ```ignore
//! // Ignored on purpose: actix-web and actix-service are not dependencies
//! // of this scaffold, so this example cannot compile yet. It documents the
//! // shape the integration will take.
//! use actix_service::Service;
//! use actix_web::body::MessageBody;
//! use actix_web::dev::{ServiceRequest, ServiceResponse, Transform};
//!
//! pub struct Guard {
//!     // engine configuration
//! }
//!
//! pub struct GuardMiddleware<S> {
//!     next: S,
//! }
//!
//! impl<S, B> Transform<S, ServiceRequest> for Guard
//! where
//!     S: Service<ServiceRequest, Response = ServiceResponse<B>> + 'static,
//!     B: MessageBody,
//! {
//!     type Response = ServiceResponse<B>;
//!     type Error = S::Error;
//!     type InitError = ();
//!     type Transform = GuardMiddleware<S>;
//!     type Future = std::future::Ready<Result<Self::Transform, Self::InitError>>;
//!
//!     fn new_transform(&self, service: S) -> Self::Future {
//!         std::future::ready(Ok(GuardMiddleware { next: service }))
//!     }
//! }
//! ```
//!
//! The `Service` implementation for `GuardMiddleware` (not shown) is where
//! request inspection and short-circuiting happen.
//!
//! ## Placeholder API
//!
//! [`add`] exists only so the scaffold has a testable public symbol while
//! the real API surface is designed. It will be removed when the engine
//! integration lands.

/// Placeholder smoke-test symbol for the scaffold.
///
/// It exists only so the crate has a testable public item while the real
/// API surface is designed; it will be removed when the engine integration
/// lands.
///
/// # Example
///
/// ```
/// assert_eq!(actix_guard_rs::add(2, 2), 4);
/// ```
pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
