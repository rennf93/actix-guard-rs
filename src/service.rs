//! The middleware service: body buffering, view scanning, dispatching.

use crate::GuardTransform;
use crate::response;
use actix_web::body::MessageBody;
use actix_web::dev::{Payload, Service, ServiceRequest, ServiceResponse};
use actix_web::{Error, HttpRequest};
use bytes::{Bytes, BytesMut};
use futures_core::Stream;
use std::future::{Future, poll_fn};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

/// Header names that are never scanned, mirroring the TypeScript adapters'
/// `EXCLUDED_HEADERS` (plus every `sec-*` header).
///
/// Negotiation and routing headers carry attacker-influenced-but-expected
/// values (`Accept`, `User-Agent`, ...) whose scanning costs false positives
/// without buying coverage: a payload smuggled into them must still survive
/// the path, query, and body views.
const EXCLUDED_HEADERS: &[&str] = &[
    "host",
    "user-agent",
    "accept",
    "accept-encoding",
    "connection",
    "origin",
    "referer",
];

/// An actix Web middleware that screens requests through the Guard engine
/// before forwarding them to the next service.
///
/// Built by [`GuardTransform::new_transform`](actix_web::dev::Transform::new_transform).
/// The next service is shared through an [`Rc`]: the body has to be buffered
/// and scanned before the inner service can be called with the rebuilt
/// request, so the scanning future must own it, and the services actix Web
/// hands to a middleware are not `Clone`. actix Web builds its service tree
/// per worker (single-threaded event loops), so the `Rc` costs nothing and
/// never crosses threads.
pub struct GuardService<S> {
    next: Rc<S>,
    transform: GuardTransform,
}

impl<S> GuardService<S> {
    pub(crate) fn new(next: S, transform: GuardTransform) -> Self {
        Self {
            next: Rc::new(next),
            transform,
        }
    }
}

impl<S> Clone for GuardService<S> {
    fn clone(&self) -> Self {
        Self {
            next: Rc::clone(&self.next),
            transform: self.transform.clone(),
        }
    }
}

impl<S: std::fmt::Debug> std::fmt::Debug for GuardService<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuardService")
            .field("next", &self.next)
            .field("transform", &self.transform)
            .finish()
    }
}

/// Why a request body could not be fully buffered.
enum BufferFailure {
    /// The body exceeded the buffering cap; reading stopped early.
    TooLarge,
    /// The body stream errored mid-read. The underlying error is dropped on
    /// purpose: it is body-transport noise (client abort, socket reset), not
    /// a security signal, and it must not leak into the `500` response.
    Read,
}

/// The outcome of scanning one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScanOutcome {
    /// No view tripped the engine.
    Clean,
    /// At least one view was flagged as a threat.
    Threat,
    /// The engine panicked; fail secure.
    Failed,
}

impl<S, B> Service<ServiceRequest> for GuardService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.next.poll_ready(cx)
    }

    fn call(&self, request: ServiceRequest) -> Self::Future {
        let next = Rc::clone(&self.next);
        let transform = self.transform.clone();
        Box::pin(async move {
            let (request, payload) = request.into_parts();
            let buffered = match buffer_body(payload, transform.body_cap()).await {
                Ok(buffered) => buffered,
                Err(BufferFailure::TooLarge) => return Ok(response::oversize(request)),
                Err(BufferFailure::Read) => return Ok(response::failure(request)),
            };
            match scan_request(&request, buffered.as_ref(), &transform) {
                ScanOutcome::Clean => {
                    // actix Web consumes the payload while buffering, so the
                    // request the next service sees is rebuilt around the
                    // buffered bytes (see the crate docs on request rebuilding).
                    let rebuilt = ServiceRequest::from_parts(
                        request,
                        Payload::from(buffered.unwrap_or_default()),
                    );
                    next.call(rebuilt)
                        .await
                        .map(ServiceResponse::map_into_boxed_body)
                }
                ScanOutcome::Threat => Ok(response::blocked(request)),
                ScanOutcome::Failed => Ok(response::failure(request)),
            }
        })
    }
}

/// Buffer a request body up to `cap` bytes.
///
/// `Ok(None)` means the body was empty. The payload is polled directly
/// (`Payload` is `Unpin` and implements `Stream`) so no extra stream utility
/// crate is needed for a single `next()`.
async fn buffer_body(mut payload: Payload, cap: usize) -> Result<Option<Bytes>, BufferFailure> {
    let mut buffered = BytesMut::new();
    while let Some(chunk) = poll_fn(|cx| Pin::new(&mut payload).poll_next(cx)).await {
        let chunk = chunk.map_err(|_error| BufferFailure::Read)?;
        if buffered.len() + chunk.len() > cap {
            return Err(BufferFailure::TooLarge);
        }
        buffered.extend_from_slice(&chunk);
    }
    Ok(if buffered.is_empty() {
        None
    } else {
        Some(buffered.freeze())
    })
}

/// Run the engine over every request view, recovering from engine panics.
///
/// The engine's `detect` is total by signature, so the only failure mode is a
/// panic. Catching it here keeps the worker alive and lets the guard answer
/// `500` instead of unwinding out of the request future.
fn scan_request(
    request: &HttpRequest,
    body: Option<&Bytes>,
    transform: &GuardTransform,
) -> ScanOutcome {
    match catch_unwind(AssertUnwindSafe(|| scan_views(request, body, transform))) {
        Ok(true) => ScanOutcome::Threat,
        Ok(false) => ScanOutcome::Clean,
        Err(_) => ScanOutcome::Failed,
    }
}

/// One engine call per view, in the documented order: path, query, headers,
/// body. The first view the engine flags wins.
fn scan_views(request: &HttpRequest, body: Option<&Bytes>, transform: &GuardTransform) -> bool {
    let path = request.path();
    if path != "/" && flagged(transform, path, "url_path") {
        return true;
    }

    let query = request.query_string();
    if !query.is_empty() && flagged(transform, query, "query_param") {
        return true;
    }

    for (name, value) in request.headers() {
        if is_excluded_header(name.as_str()) {
            continue;
        }
        // Opaque (non-ASCII) header values cannot be represented as `&str`.
        // They are skipped rather than guessed at, mirroring the string-typed
        // header maps the TypeScript adapters hand to the engine.
        let Ok(value) = value.to_str() else {
            continue;
        };
        if flagged(transform, value, "header") {
            return true;
        }
    }

    if let Some(bytes) = body {
        let text = String::from_utf8_lossy(bytes);
        if !text.trim().is_empty() && flagged(transform, &text, "request_body") {
            return true;
        }
    }

    false
}

/// One engine call: `true` when the engine flags the content.
fn flagged(transform: &GuardTransform, content: &str, view: &str) -> bool {
    (transform.detect_fn())(content, view, transform.config()).is_threat
}

fn is_excluded_header(name: &str) -> bool {
    name.starts_with("sec-") || EXCLUDED_HEADERS.contains(&name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BLOCKED_MESSAGE, FAILURE_MESSAGE, default_config};
    use actix_web::body::MessageBody;
    use actix_web::dev::Transform;
    use actix_web::error::PayloadError;
    use actix_web::test::TestRequest;
    use actix_web::{Error, HttpResponse};
    use guard_core_engine::detect::{DetectConfig, DetectVerdict};

    fn panicking_detect(_content: &str, _context: &str, _config: &DetectConfig) -> DetectVerdict {
        panic!("engine exploded");
    }

    async fn guarded(transform: GuardTransform) -> GuardService<OkService> {
        transform
            .new_transform(OkService)
            .await
            .expect("infallible")
    }

    fn body_text(response: ServiceResponse) -> String {
        let bytes = response.into_body().try_into_bytes().expect("bytes");
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[actix_web::test]
    async fn engine_panic_is_recovered_as_a_500() {
        let guard =
            guarded(GuardTransform::new(default_config()).with_detect_fn(panicking_detect)).await;
        let request = TestRequest::post()
            .uri("/hello")
            .set_payload("ping")
            .to_srv_request();

        let response = guard.call(request).await.expect("response");
        assert_eq!(response.status(), 500);
        assert_eq!(
            body_text(response),
            format!(r#"{{"detail":"{FAILURE_MESSAGE}"}}"#)
        );
    }

    #[actix_web::test]
    async fn scan_views_reports_threat_through_catch_unwind() {
        let transform = GuardTransform::new(default_config());
        let request = TestRequest::default()
            .uri("/files/../../etc/passwd")
            .to_http_request();
        assert_eq!(
            scan_request(&request, None, &transform),
            ScanOutcome::Threat,
            "traversal path should be flagged"
        );
    }

    #[actix_web::test]
    async fn empty_body_is_not_scanned_and_still_forwarded() {
        let guard = guarded(GuardTransform::new(default_config())).await;
        let request = TestRequest::get().uri("/hello").to_srv_request();
        let response = guard.call(request).await.expect("response");
        assert_eq!(response.status(), 200);
    }

    #[actix_web::test]
    async fn blocked_response_body_reports_the_documented_message() {
        let guard = guarded(GuardTransform::new(default_config())).await;
        let request = TestRequest::get()
            .uri("/files/../../etc/passwd")
            .to_srv_request();
        let response = guard.call(request).await.expect("response");
        assert_eq!(response.status(), 403);
        assert_eq!(
            body_text(response),
            format!(r#"{{"detail":"{BLOCKED_MESSAGE}"}}"#)
        );
    }

    #[actix_web::test]
    async fn body_read_error_fails_secure_with_500() {
        let guard = guarded(GuardTransform::new(default_config())).await;
        let mut request = TestRequest::post().uri("/api/items").to_srv_request();
        request.set_payload(Payload::Stream {
            payload: Box::pin(FailingStream { yielded: false }),
        });

        let response = guard.call(request).await.expect("response");
        assert_eq!(response.status(), 500);
        assert_eq!(
            body_text(response),
            format!(r#"{{"detail":"{FAILURE_MESSAGE}"}}"#)
        );
    }

    #[actix_web::test]
    async fn a_body_at_the_cap_is_forwarded() {
        let guard = guarded(GuardTransform::new(default_config()).with_body_cap(4)).await;
        let request = TestRequest::post()
            .uri("/api/items")
            .set_payload("abcd")
            .to_srv_request();
        let response = guard.call(request).await.expect("response");
        assert_eq!(response.status(), 200);
    }

    #[test]
    fn excluded_headers_cover_the_negotiation_set_and_sec_prefix() {
        for name in [
            "host",
            "user-agent",
            "accept",
            "accept-encoding",
            "connection",
        ] {
            assert!(is_excluded_header(name), "{name} should be excluded");
        }
        for name in ["sec-fetch-site", "sec-ch-ua", "sec-websocket-key"] {
            assert!(is_excluded_header(name), "{name} should be excluded");
        }
        for name in ["cookie", "authorization", "content-type", "x-api-key"] {
            assert!(!is_excluded_header(name), "{name} should be scanned");
        }
    }

    /// A body that yields one frame, then errors.
    struct FailingStream {
        yielded: bool,
    }

    impl Stream for FailingStream {
        type Item = Result<Bytes, PayloadError>;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            if self.yielded {
                return Poll::Ready(Some(Err(PayloadError::EncodingCorrupted)));
            }
            self.yielded = true;
            Poll::Ready(Some(Ok(Bytes::from_static(b"hi"))))
        }
    }

    /// The inner service used by the unit tests: answers `200` with an empty
    /// body, and never inspects the request. It is only reachable on the
    /// benign paths these tests exercise.
    #[derive(Clone)]
    struct OkService;

    impl Service<ServiceRequest> for OkService {
        type Response = ServiceResponse;
        type Error = Error;
        type Future = std::future::Ready<Result<ServiceResponse, Error>>;

        fn poll_ready(&self, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&self, request: ServiceRequest) -> Self::Future {
            std::future::ready(Ok(request.into_response(HttpResponse::Ok().finish())))
        }
    }
}
