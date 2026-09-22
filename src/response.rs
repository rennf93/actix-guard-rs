//! Short-circuit responses emitted by the guard.

use actix_web::dev::ServiceResponse;
use actix_web::http::StatusCode;
use actix_web::http::header::CONTENT_TYPE;
use actix_web::{HttpRequest, HttpResponse};
use bytes::Bytes;

/// Detail message carried by the `403 Forbidden` block response.
pub const BLOCKED_MESSAGE: &str = "Suspicious activity detected";

/// Detail message carried by the `413 Payload Too Large` response.
pub const OVERSIZE_MESSAGE: &str = "Payload too large";

/// Detail message carried by the fail-secure `500` response.
pub const FAILURE_MESSAGE: &str = "Security check failed";

pub(crate) fn blocked(request: HttpRequest) -> ServiceResponse {
    json(request, StatusCode::FORBIDDEN, BLOCKED_MESSAGE)
}

pub(crate) fn oversize(request: HttpRequest) -> ServiceResponse {
    json(request, StatusCode::PAYLOAD_TOO_LARGE, OVERSIZE_MESSAGE)
}

pub(crate) fn failure(request: HttpRequest) -> ServiceResponse {
    json(request, StatusCode::INTERNAL_SERVER_ERROR, FAILURE_MESSAGE)
}

/// The ecosystem's JSON error shape: a `detail` field, `application/json`.
fn json(request: HttpRequest, status: StatusCode, detail: &'static str) -> ServiceResponse {
    let body = Bytes::from(format!(r#"{{"detail":"{detail}"}}"#));
    let response = HttpResponse::build(status)
        .insert_header((CONTENT_TYPE, "application/json"))
        .body(body);
    ServiceResponse::new(request, response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::body::MessageBody;

    fn test_request() -> HttpRequest {
        actix_web::test::TestRequest::default().to_http_request()
    }

    #[test]
    fn blocked_response_shape() {
        let response = blocked(test_request());
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .expect("content type")
                .to_str()
                .expect("ascii"),
            "application/json"
        );
        assert_eq!(
            response.into_body().try_into_bytes().expect("bytes"),
            Bytes::from_static(br#"{"detail":"Suspicious activity detected"}"#)
        );
    }

    #[test]
    fn oversize_response_shape() {
        let response = oversize(test_request());
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn failure_response_shape() {
        let response = failure(test_request());
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            response.into_body().try_into_bytes().expect("bytes"),
            Bytes::from_static(br#"{"detail":"Security check failed"}"#)
        );
    }
}
