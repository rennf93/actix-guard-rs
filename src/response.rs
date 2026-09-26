//! Short-circuit responses emitted by the guard.

use actix_web::dev::ServiceResponse;
use actix_web::http::StatusCode;
use actix_web::http::header::{CONTENT_TYPE, RETRY_AFTER};
use actix_web::{HttpRequest, HttpResponse};

/// Detail message carried by the `400 Bad Request` block response.
pub const BLOCKED_MESSAGE: &str = "Suspicious activity detected";

/// Detail message carried by the IP gate's `403 Forbidden` response.
pub const FORBIDDEN_MESSAGE: &str = "Forbidden";

/// Detail message carried by the ban stage's `403 Forbidden` response.
pub const BANNED_MESSAGE: &str = "IP address banned";

/// Detail message carried by the `403 Forbidden` response when a detected
/// threat crossed an auto-ban threshold and the ban fired on this request.
pub const ACTIVITY_BANNED_MESSAGE: &str = "IP has been banned";

/// Detail message carried by the `429 Too Many Requests` response.
pub const RATE_LIMITED_MESSAGE: &str = "Too many requests";

/// Detail message carried by the `413 Payload Too Large` response.
pub const OVERSIZE_MESSAGE: &str = "Payload too large";

/// Detail message carried by the fail-secure `500` response.
pub const FAILURE_MESSAGE: &str = "Security check failed";

pub(crate) fn blocked(request: HttpRequest) -> ServiceResponse {
    plain_text(request, StatusCode::BAD_REQUEST, BLOCKED_MESSAGE)
}

pub(crate) fn forbidden(request: HttpRequest) -> ServiceResponse {
    plain_text(request, StatusCode::FORBIDDEN, FORBIDDEN_MESSAGE)
}

/// The ban stage's denial: a live ban on the client IP.
pub(crate) fn banned_ip(request: HttpRequest) -> ServiceResponse {
    plain_text(request, StatusCode::FORBIDDEN, BANNED_MESSAGE)
}

/// The auto-ban engine's denial: the detected threat crossed a threshold and
/// the ban fired on this very request.
pub(crate) fn activity_banned(request: HttpRequest) -> ServiceResponse {
    plain_text(request, StatusCode::FORBIDDEN, ACTIVITY_BANNED_MESSAGE)
}

/// The rate limiter's denial, carrying `Retry-After: <window seconds>` the
/// way the references do.
pub(crate) fn rate_limited(request: HttpRequest, retry_after: u64) -> ServiceResponse {
    let response = HttpResponse::build(StatusCode::TOO_MANY_REQUESTS)
        .insert_header((CONTENT_TYPE, "text/plain; charset=utf-8"))
        .insert_header((RETRY_AFTER, retry_after.to_string()))
        .body(RATE_LIMITED_MESSAGE);
    ServiceResponse::new(request, response)
}

pub(crate) fn oversize(request: HttpRequest) -> ServiceResponse {
    plain_text(request, StatusCode::PAYLOAD_TOO_LARGE, OVERSIZE_MESSAGE)
}

pub(crate) fn failure(request: HttpRequest) -> ServiceResponse {
    plain_text(request, StatusCode::INTERNAL_SERVER_ERROR, FAILURE_MESSAGE)
}

/// The ecosystem's error shape: the bare message as the body,
/// `text/plain; charset=utf-8` (same as the Python family).
fn plain_text(request: HttpRequest, status: StatusCode, message: &'static str) -> ServiceResponse {
    let response = HttpResponse::build(status)
        .insert_header((CONTENT_TYPE, "text/plain; charset=utf-8"))
        .body(message);
    ServiceResponse::new(request, response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::body::MessageBody;
    use bytes::Bytes;

    fn test_request() -> HttpRequest {
        actix_web::test::TestRequest::default().to_http_request()
    }

    #[test]
    fn blocked_response_shape() {
        let response = blocked(test_request());
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .expect("content type")
                .to_str()
                .expect("ascii"),
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            response.into_body().try_into_bytes().expect("bytes"),
            Bytes::from_static(b"Suspicious activity detected")
        );
    }

    #[test]
    fn forbidden_response_shape() {
        let response = forbidden(test_request());
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .expect("content type")
                .to_str()
                .expect("ascii"),
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            response.into_body().try_into_bytes().expect("bytes"),
            Bytes::from_static(b"Forbidden")
        );
    }

    #[test]
    fn banned_response_shape() {
        let response = banned_ip(test_request());
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response.into_body().try_into_bytes().expect("bytes"),
            Bytes::from_static(b"IP address banned")
        );
    }

    #[test]
    fn activity_banned_response_shape() {
        let response = activity_banned(test_request());
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response.into_body().try_into_bytes().expect("bytes"),
            Bytes::from_static(b"IP has been banned")
        );
    }

    #[test]
    fn rate_limited_response_shape_carries_retry_after() {
        let response = rate_limited(test_request(), 90);
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response
                .headers()
                .get(RETRY_AFTER)
                .expect("retry after")
                .to_str()
                .expect("ascii"),
            "90"
        );
        assert_eq!(
            response.into_body().try_into_bytes().expect("bytes"),
            Bytes::from_static(b"Too many requests")
        );
    }

    #[test]
    fn oversize_response_shape() {
        let response = oversize(test_request());
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .expect("content type")
                .to_str()
                .expect("ascii"),
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            response.into_body().try_into_bytes().expect("bytes"),
            Bytes::from_static(b"Payload too large")
        );
    }

    #[test]
    fn failure_response_shape() {
        let response = failure(test_request());
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .expect("content type")
                .to_str()
                .expect("ascii"),
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            response.into_body().try_into_bytes().expect("bytes"),
            Bytes::from_static(b"Security check failed")
        );
    }
}
